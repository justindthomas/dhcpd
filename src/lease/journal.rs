//! v4 lease store — append-only journal + periodic snapshot.
//!
//! On-disk layout under `<lease_db_dir>`:
//!
//! ```text
//! leases-v4.snapshot   # LeaseSet serialized with bincode (periodically rewritten)
//! leases-v4.journal    # sequence of JournalEntry records, each length-prefixed u32 BE
//! ```
//!
//! Startup sequence:
//!   1. Load snapshot (or empty set).
//!   2. Replay journal entries on top.
//!   3. If journal > `COMPACT_THRESHOLD_BYTES`, write a fresh
//!      snapshot and truncate the journal.
//!   4. Open the journal for append.
//!
//! Every `LeaseStoreV4` mutation appends a journal record and
//! fsyncs the file before returning to the caller. This gives us
//! write-ahead-log semantics — if we crash after sending an OFFER
//! but before fsyncing, we'd have handed out a lease we don't
//! remember. The mitigation is: call `bind()` and its fsync
//! *before* writing the OFFER to the wire.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::DhcpdError;
use crate::packet::v4::client_id::ClientId;

/// Maximum journal size before we trigger startup compaction.
/// Every bound lease fits in ~120 bytes so ~8MB is roughly 65k
/// bind events — more than enough headroom between restarts.
const COMPACT_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;

const SNAPSHOT_FILENAME: &str = "leases-v4.snapshot";
const JOURNAL_FILENAME: &str = "leases-v4.journal";

/// Lease lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseState {
    /// Lease is active and allocated to the client.
    Bound,
    /// Client sent a RELEASE. IP returns to pool when the lease is
    /// reaped on the next periodic sweep.
    Released,
    /// Client sent a DECLINE. IP is quarantined for ~30 min before
    /// reuse (RFC 2131 §3.1).
    Declined,
    /// Lease expired without renewal.
    Expired,
}

/// A v4 lease entry. The key is `client_id`; `ip` is a secondary
/// index maintained by `LeaseStoreV4` for pool-conflict checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub client_id: Vec<u8>,
    pub ip: Ipv4Addr,
    /// Ethernet MAC from the client's BOOTP chaddr. Informational;
    /// key is client_id.
    pub mac: [u8; 6],
    pub hostname: Option<String>,
    /// Time the lease was first granted (seconds since UNIX_EPOCH).
    pub granted_unix: u64,
    /// Time the lease expires (seconds since UNIX_EPOCH).
    pub expires_unix: u64,
    pub state: LeaseState,
}

impl Lease {
    /// Returns true if `now` is past the expiry timestamp.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() >= self.expires_unix)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseSet {
    entries: Vec<Lease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum JournalEntry {
    Bind(Lease),
    Release { client_id: Vec<u8> },
    Decline { client_id: Vec<u8> },
    Expire { client_id: Vec<u8> },
}

/// In-memory v4 lease store backed by an append-only journal plus
/// periodic snapshot. Single-writer: the daemon owns exactly one
/// instance; concurrent mutation is a bug.
pub struct LeaseStoreV4 {
    by_client: HashMap<Vec<u8>, Lease>,
    /// IP -> client_id index, maintained alongside `by_client` so
    /// we can answer "is this IP free?" without scanning.
    by_ip: HashMap<Ipv4Addr, Vec<u8>>,
    journal_path: PathBuf,
    snapshot_path: PathBuf,
    journal: File,
}

impl LeaseStoreV4 {
    /// Open the lease store under `dir`, creating files + directory
    /// as needed. Replays any journal on top of the snapshot. If
    /// the journal is past the compaction threshold, rewrite the
    /// snapshot and truncate.
    pub fn open(dir: &Path) -> Result<Self, DhcpdError> {
        std::fs::create_dir_all(dir).map_err(|e| {
            DhcpdError::Lease(format!("create {}: {}", dir.display(), e))
        })?;

        let snapshot_path = dir.join(SNAPSHOT_FILENAME);
        let journal_path = dir.join(JOURNAL_FILENAME);

        // 1. Load snapshot.
        let mut by_client: HashMap<Vec<u8>, Lease> = HashMap::new();
        let mut by_ip: HashMap<Ipv4Addr, Vec<u8>> = HashMap::new();
        if snapshot_path.exists() {
            let bytes = std::fs::read(&snapshot_path)
                .map_err(|e| DhcpdError::Lease(format!("read snapshot: {}", e)))?;
            let set: LeaseSet = bincode::deserialize(&bytes)
                .map_err(|e| DhcpdError::Lease(format!("decode snapshot: {}", e)))?;
            for lease in set.entries {
                by_ip.insert(lease.ip, lease.client_id.clone());
                by_client.insert(lease.client_id.clone(), lease);
            }
            tracing::info!(
                leases = by_client.len(),
                path = %snapshot_path.display(),
                "loaded v4 lease snapshot"
            );
        }

        // 2. Replay journal.
        let replayed_bytes = if journal_path.exists() {
            replay_journal(&journal_path, &mut by_client, &mut by_ip)?
        } else {
            0
        };

        // 3. Compact if journal is large.
        let needs_compact = replayed_bytes > COMPACT_THRESHOLD_BYTES;

        // Open the journal for append (truncate if we compacted).
        let journal_opts = {
            let mut o = OpenOptions::new();
            o.create(true).append(true);
            if needs_compact {
                // Will truncate after we write the new snapshot.
            }
            o
        };
        let journal = journal_opts.open(&journal_path).map_err(|e| {
            DhcpdError::Lease(format!("open journal {}: {}", journal_path.display(), e))
        })?;

        let mut store = LeaseStoreV4 {
            by_client,
            by_ip,
            journal_path: journal_path.clone(),
            snapshot_path: snapshot_path.clone(),
            journal,
        };

        if needs_compact {
            tracing::info!(
                journal_bytes = replayed_bytes,
                "compacting v4 lease journal"
            );
            store.compact()?;
            // Re-open journal after truncate.
            store.journal = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&store.journal_path)
                .map_err(|e| DhcpdError::Lease(format!("reopen journal: {}", e)))?;
        }
        Ok(store)
    }

    /// Record a new or renewed binding. The lease is written to the
    /// journal and fsynced before returning — callers rely on that
    /// ordering so an OFFER sent after `bind()` returns is durable.
    pub fn bind(&mut self, lease: Lease) -> Result<(), DhcpdError> {
        // If another client held this IP, drop its index first.
        if let Some(existing_cid) = self.by_ip.get(&lease.ip).cloned() {
            if existing_cid != lease.client_id {
                self.by_client.remove(&existing_cid);
            }
        }
        self.by_ip.insert(lease.ip, lease.client_id.clone());
        self.by_client.insert(lease.client_id.clone(), lease.clone());
        self.append(&JournalEntry::Bind(lease))
    }

    /// Mark a lease as released — the IP returns to the pool on the
    /// next reap. No-op if we don't have a lease for `cid`.
    pub fn release(&mut self, cid: &ClientId) -> Result<(), DhcpdError> {
        if let Some(existing) = self.by_client.get_mut(cid.as_bytes()) {
            existing.state = LeaseState::Released;
        }
        self.append(&JournalEntry::Release {
            client_id: cid.as_bytes().to_vec(),
        })
    }

    /// Mark a lease as declined (IP quarantine).
    pub fn decline(&mut self, cid: &ClientId) -> Result<(), DhcpdError> {
        if let Some(existing) = self.by_client.get_mut(cid.as_bytes()) {
            existing.state = LeaseState::Declined;
        }
        self.append(&JournalEntry::Decline {
            client_id: cid.as_bytes().to_vec(),
        })
    }

    /// Mark a lease as expired.
    pub fn expire(&mut self, cid: &ClientId) -> Result<(), DhcpdError> {
        if let Some(existing) = self.by_client.get_mut(cid.as_bytes()) {
            existing.state = LeaseState::Expired;
        }
        self.append(&JournalEntry::Expire {
            client_id: cid.as_bytes().to_vec(),
        })
    }

    /// Look up a lease by client-id.
    pub fn get(&self, cid: &ClientId) -> Option<&Lease> {
        self.by_client.get(cid.as_bytes())
    }

    /// Which client (if any) currently has `ip`? Used by allocators
    /// to skip IPs that are already bound. A lease in `Released` or
    /// `Expired` state still indexes its IP here; allocators check
    /// the state.
    pub fn holder_of(&self, ip: Ipv4Addr) -> Option<&Lease> {
        self.by_ip
            .get(&ip)
            .and_then(|cid| self.by_client.get(cid))
    }

    /// Iterate all leases.
    pub fn iter(&self) -> impl Iterator<Item = &Lease> {
        self.by_client.values()
    }

    /// Count of leases in all states.
    pub fn len(&self) -> usize {
        self.by_client.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_client.is_empty()
    }

    /// Rewrite the snapshot from the current in-memory state and
    /// truncate the journal. Typically called at startup after a
    /// large journal is detected, but the caller can also schedule
    /// it periodically.
    pub fn compact(&mut self) -> Result<(), DhcpdError> {
        let set = LeaseSet {
            entries: self.by_client.values().cloned().collect(),
        };
        let bytes = bincode::serialize(&set)
            .map_err(|e| DhcpdError::Lease(format!("encode snapshot: {}", e)))?;
        let tmp_path = self.snapshot_path.with_extension("snapshot.tmp");
        {
            let mut f = File::create(&tmp_path)
                .map_err(|e| DhcpdError::Lease(format!("create tmp snapshot: {}", e)))?;
            f.write_all(&bytes)
                .map_err(|e| DhcpdError::Lease(format!("write snapshot: {}", e)))?;
            f.sync_all()
                .map_err(|e| DhcpdError::Lease(format!("sync snapshot: {}", e)))?;
        }
        std::fs::rename(&tmp_path, &self.snapshot_path).map_err(|e| {
            DhcpdError::Lease(format!(
                "rename {} -> {}: {}",
                tmp_path.display(),
                self.snapshot_path.display(),
                e
            ))
        })?;
        // Truncate the journal. We keep the existing fd valid by
        // opening a fresh handle with O_TRUNC, then replacing.
        let fresh = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.journal_path)
            .map_err(|e| DhcpdError::Lease(format!("truncate journal: {}", e)))?;
        fresh.sync_all()
            .map_err(|e| DhcpdError::Lease(format!("sync journal truncate: {}", e)))?;
        self.journal = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .map_err(|e| DhcpdError::Lease(format!("reopen journal: {}", e)))?;
        Ok(())
    }

    fn append(&mut self, entry: &JournalEntry) -> Result<(), DhcpdError> {
        let bytes = bincode::serialize(entry)
            .map_err(|e| DhcpdError::Lease(format!("encode journal entry: {}", e)))?;
        let len = bytes.len() as u32;
        self.journal
            .write_all(&len.to_be_bytes())
            .map_err(|e| DhcpdError::Lease(format!("journal write len: {}", e)))?;
        self.journal
            .write_all(&bytes)
            .map_err(|e| DhcpdError::Lease(format!("journal write body: {}", e)))?;
        self.journal
            .sync_data()
            .map_err(|e| DhcpdError::Lease(format!("journal fsync: {}", e)))?;
        Ok(())
    }
}

fn replay_journal(
    path: &Path,
    by_client: &mut HashMap<Vec<u8>, Lease>,
    by_ip: &mut HashMap<Ipv4Addr, Vec<u8>>,
) -> Result<u64, DhcpdError> {
    let f = File::open(path)
        .map_err(|e| DhcpdError::Lease(format!("open journal for replay: {}", e)))?;
    let len = f
        .metadata()
        .map_err(|e| DhcpdError::Lease(format!("stat journal: {}", e)))?
        .len();
    let mut reader = BufReader::new(f);
    let mut consumed: u64 = 0;
    let mut applied = 0usize;
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                return Err(DhcpdError::Lease(format!("journal read: {}", e)));
            }
        }
        let entry_len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; entry_len];
        if let Err(e) = reader.read_exact(&mut body) {
            tracing::warn!(
                error = %e,
                "truncated journal entry at offset {} — discarding tail",
                consumed,
            );
            break;
        }
        consumed += 4 + entry_len as u64;
        let entry: JournalEntry = match bincode::deserialize(&body) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "skipping undecodable journal entry");
                continue;
            }
        };
        apply_entry(entry, by_client, by_ip);
        applied += 1;
    }
    tracing::info!(applied, journal_bytes = consumed, total = len, "replayed journal");
    Ok(consumed)
}

fn apply_entry(
    entry: JournalEntry,
    by_client: &mut HashMap<Vec<u8>, Lease>,
    by_ip: &mut HashMap<Ipv4Addr, Vec<u8>>,
) {
    match entry {
        JournalEntry::Bind(lease) => {
            // If another client previously held this IP, drop its
            // index entry so the new binding wins cleanly.
            if let Some(existing_cid) = by_ip.get(&lease.ip).cloned() {
                if existing_cid != lease.client_id {
                    by_client.remove(&existing_cid);
                }
            }
            by_ip.insert(lease.ip, lease.client_id.clone());
            by_client.insert(lease.client_id.clone(), lease);
        }
        JournalEntry::Release { client_id } => {
            if let Some(l) = by_client.get_mut(&client_id) {
                l.state = LeaseState::Released;
            }
        }
        JournalEntry::Decline { client_id } => {
            if let Some(l) = by_client.get_mut(&client_id) {
                l.state = LeaseState::Declined;
            }
        }
        JournalEntry::Expire { client_id } => {
            if let Some(l) = by_client.get_mut(&client_id) {
                l.state = LeaseState::Expired;
            }
        }
    }
}

#[allow(dead_code)]
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    fn sample_lease(cid: &[u8], ip: [u8; 4]) -> Lease {
        Lease {
            client_id: cid.to_vec(),
            ip: Ipv4Addr::from(ip),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            hostname: Some("client".into()),
            granted_unix: 1_700_000_000,
            expires_unix: 1_700_003_600,
            state: LeaseState::Bound,
        }
    }

    #[test]
    fn bind_then_reopen_recovers() {
        let dir = tempdir().unwrap();
        {
            let mut store = LeaseStoreV4::open(dir.path()).unwrap();
            store.bind(sample_lease(&[1, 2, 3, 4, 5, 6], [10, 0, 0, 5])).unwrap();
        }
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let cid = ClientId(vec![1, 2, 3, 4, 5, 6]);
        let l = store.get(&cid).unwrap();
        assert_eq!(l.ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(l.state, LeaseState::Bound);
    }

    #[test]
    fn release_transitions_state_persistently() {
        let dir = tempdir().unwrap();
        {
            let mut store = LeaseStoreV4::open(dir.path()).unwrap();
            store.bind(sample_lease(&[1, 2, 3, 4, 5, 6], [10, 0, 0, 5])).unwrap();
            store.release(&ClientId(vec![1, 2, 3, 4, 5, 6])).unwrap();
        }
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let l = store.get(&ClientId(vec![1, 2, 3, 4, 5, 6])).unwrap();
        assert_eq!(l.state, LeaseState::Released);
    }

    #[test]
    fn decline_transitions_state_persistently() {
        let dir = tempdir().unwrap();
        {
            let mut store = LeaseStoreV4::open(dir.path()).unwrap();
            store.bind(sample_lease(&[1, 2, 3, 4, 5, 6], [10, 0, 0, 5])).unwrap();
            store.decline(&ClientId(vec![1, 2, 3, 4, 5, 6])).unwrap();
        }
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let l = store.get(&ClientId(vec![1, 2, 3, 4, 5, 6])).unwrap();
        assert_eq!(l.state, LeaseState::Declined);
    }

    #[test]
    fn by_ip_index_is_consistent() {
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        store.bind(sample_lease(&[1, 1, 1, 1, 1, 1], [10, 0, 0, 5])).unwrap();
        let held = store.holder_of(Ipv4Addr::new(10, 0, 0, 5));
        assert!(held.is_some());
        assert_eq!(held.unwrap().client_id, vec![1, 1, 1, 1, 1, 1]);
        assert!(store.holder_of(Ipv4Addr::new(10, 0, 0, 6)).is_none());
    }

    #[test]
    fn rebinding_same_client_same_ip_replaces() {
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        let mut l = sample_lease(&[1, 2, 3, 4, 5, 6], [10, 0, 0, 5]);
        store.bind(l.clone()).unwrap();
        l.expires_unix += 3600;
        store.bind(l.clone()).unwrap();
        assert_eq!(store.len(), 1);
        let got = store.get(&ClientId(vec![1, 2, 3, 4, 5, 6])).unwrap();
        assert_eq!(got.expires_unix, 1_700_003_600 + 3600);
    }

    #[test]
    fn rebinding_different_client_same_ip_evicts_old() {
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        store.bind(sample_lease(&[1, 1, 1, 1, 1, 1], [10, 0, 0, 5])).unwrap();
        store.bind(sample_lease(&[2, 2, 2, 2, 2, 2], [10, 0, 0, 5])).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get(&ClientId(vec![1, 1, 1, 1, 1, 1])).is_none());
        assert!(store.get(&ClientId(vec![2, 2, 2, 2, 2, 2])).is_some());
    }

    #[test]
    fn compaction_preserves_state_and_truncates_journal() {
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        // Create a bunch of binds + some releases.
        for i in 0..20u8 {
            store.bind(sample_lease(&[i; 6], [10, 0, 0, i + 10])).unwrap();
        }
        for i in 0..5u8 {
            store.release(&ClientId(vec![i; 6])).unwrap();
        }
        let journal_size_before = std::fs::metadata(dir.path().join(JOURNAL_FILENAME))
            .unwrap()
            .len();
        assert!(journal_size_before > 0);

        store.compact().unwrap();

        // After compaction the journal should be 0 bytes.
        let journal_size_after = std::fs::metadata(dir.path().join(JOURNAL_FILENAME))
            .unwrap()
            .len();
        assert_eq!(journal_size_after, 0);

        // The snapshot exists and the state is preserved.
        assert!(dir.path().join(SNAPSHOT_FILENAME).exists());
        drop(store);
        let reopened = LeaseStoreV4::open(dir.path()).unwrap();
        assert_eq!(reopened.len(), 20);
        let released = reopened.get(&ClientId(vec![0; 6])).unwrap();
        assert_eq!(released.state, LeaseState::Released);
    }

    #[test]
    fn is_expired_checks_timestamp() {
        let l = sample_lease(&[1; 6], [10, 0, 0, 1]);
        // Lease is valid until 1_700_003_600. At that second and beyond, expired.
        let now = UNIX_EPOCH + Duration::from_secs(1_700_003_600);
        assert!(l.is_expired(now));
        let earlier = UNIX_EPOCH + Duration::from_secs(1_700_003_599);
        assert!(!l.is_expired(earlier));
    }
}
