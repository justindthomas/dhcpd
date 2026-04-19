//! DHCPv6 lease store — append-only journal + snapshot.
//!
//! Leases are keyed by `(DUID, IAID)` for IA_NA (and will be keyed
//! the same way for IA_PD in Phase 4, with a discriminator). A
//! client can hold multiple IAIDs (one per interface), each with
//! its own IA_NA address.
//!
//! On-disk layout under `<lease_db_dir>`:
//!
//! ```text
//! leases-v6.snapshot
//! leases-v6.journal
//! server-duid        (persistent DUID-LLT generated at first startup)
//! ```

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::DhcpdError;
use crate::packet::v6::duid::Duid;

const COMPACT_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;

const SNAPSHOT_FILENAME: &str = "leases-v6.snapshot";
const JOURNAL_FILENAME: &str = "leases-v6.journal";
pub const SERVER_DUID_FILENAME: &str = "server-duid";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseStateV6 {
    Bound,
    Released,
    Declined,
    Expired,
}

/// An IA_NA binding. IA_PD gets its own variant in Phase 4 — we
/// already provision the discriminator so the journal format
/// doesn't need to break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseV6 {
    pub duid: Vec<u8>,
    pub iaid: u32,
    pub kind: IaKind,
    pub address: Ipv6Addr,
    pub prefix_len: u8,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub granted_unix: u64,
    pub expires_unix: u64,
    pub state: LeaseStateV6,
    /// Only meaningful for IA_PD delegations via direct path; see
    /// Phase 4. For IA_NA this is always `false`.
    pub via_relay: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IaKind {
    Na,
    Pd,
}

/// Key for the in-memory index. IA_NA allows multiple addresses
/// per IAID (RFC 8415 §21.4), but v1 binds one address per IAID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct V6Key {
    pub duid: Vec<u8>,
    pub iaid: u32,
    pub kind: IaKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseSet {
    entries: Vec<LeaseV6>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum JournalEntry {
    Bind(LeaseV6),
    Release(V6Key),
    Decline(V6Key),
    Expire(V6Key),
}

pub struct LeaseStoreV6 {
    by_key: HashMap<V6Key, LeaseV6>,
    by_address: HashMap<Ipv6Addr, V6Key>,
    journal_path: PathBuf,
    snapshot_path: PathBuf,
    journal: File,
}

impl LeaseStoreV6 {
    /// Open the store under `dir`, replaying any journal on top of
    /// the snapshot. Compacts if the journal is large.
    pub fn open(dir: &Path) -> Result<Self, DhcpdError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| DhcpdError::Lease(format!("create {}: {}", dir.display(), e)))?;

        let snapshot_path = dir.join(SNAPSHOT_FILENAME);
        let journal_path = dir.join(JOURNAL_FILENAME);

        let mut by_key: HashMap<V6Key, LeaseV6> = HashMap::new();
        let mut by_address: HashMap<Ipv6Addr, V6Key> = HashMap::new();
        if snapshot_path.exists() {
            let bytes = std::fs::read(&snapshot_path)
                .map_err(|e| DhcpdError::Lease(format!("read v6 snapshot: {}", e)))?;
            let set: LeaseSet = bincode::deserialize(&bytes)
                .map_err(|e| DhcpdError::Lease(format!("decode v6 snapshot: {}", e)))?;
            for lease in set.entries {
                let key = V6Key {
                    duid: lease.duid.clone(),
                    iaid: lease.iaid,
                    kind: lease.kind,
                };
                by_address.insert(lease.address, key.clone());
                by_key.insert(key, lease);
            }
            tracing::info!(
                leases = by_key.len(),
                path = %snapshot_path.display(),
                "loaded v6 lease snapshot"
            );
        }

        let replayed_bytes = if journal_path.exists() {
            replay_journal(&journal_path, &mut by_key, &mut by_address)?
        } else {
            0
        };

        let needs_compact = replayed_bytes > COMPACT_THRESHOLD_BYTES;

        let journal = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_path)
            .map_err(|e| DhcpdError::Lease(format!("open v6 journal: {}", e)))?;

        let mut store = LeaseStoreV6 {
            by_key,
            by_address,
            journal_path,
            snapshot_path,
            journal,
        };

        if needs_compact {
            tracing::info!("compacting v6 lease journal");
            store.compact()?;
            store.journal = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&store.journal_path)
                .map_err(|e| DhcpdError::Lease(format!("reopen v6 journal: {}", e)))?;
        }
        Ok(store)
    }

    pub fn bind(&mut self, lease: LeaseV6) -> Result<(), DhcpdError> {
        let key = V6Key {
            duid: lease.duid.clone(),
            iaid: lease.iaid,
            kind: lease.kind,
        };
        // If the IP is held by another client, evict.
        if let Some(existing_key) = self.by_address.get(&lease.address).cloned() {
            if existing_key != key {
                self.by_key.remove(&existing_key);
            }
        }
        self.by_address.insert(lease.address, key.clone());
        self.by_key.insert(key, lease.clone());
        self.append(&JournalEntry::Bind(lease))
    }

    pub fn release(&mut self, key: &V6Key) -> Result<(), DhcpdError> {
        if let Some(lease) = self.by_key.get_mut(key) {
            lease.state = LeaseStateV6::Released;
        }
        self.append(&JournalEntry::Release(key.clone()))
    }

    pub fn decline(&mut self, key: &V6Key) -> Result<(), DhcpdError> {
        if let Some(lease) = self.by_key.get_mut(key) {
            lease.state = LeaseStateV6::Declined;
        }
        self.append(&JournalEntry::Decline(key.clone()))
    }

    pub fn expire(&mut self, key: &V6Key) -> Result<(), DhcpdError> {
        if let Some(lease) = self.by_key.get_mut(key) {
            lease.state = LeaseStateV6::Expired;
        }
        self.append(&JournalEntry::Expire(key.clone()))
    }

    pub fn get(&self, key: &V6Key) -> Option<&LeaseV6> {
        self.by_key.get(key)
    }

    pub fn holder_of(&self, address: Ipv6Addr) -> Option<&LeaseV6> {
        self.by_address
            .get(&address)
            .and_then(|k| self.by_key.get(k))
    }

    pub fn iter(&self) -> impl Iterator<Item = &LeaseV6> {
        self.by_key.values()
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    pub fn compact(&mut self) -> Result<(), DhcpdError> {
        let set = LeaseSet {
            entries: self.by_key.values().cloned().collect(),
        };
        let bytes = bincode::serialize(&set)
            .map_err(|e| DhcpdError::Lease(format!("encode v6 snapshot: {}", e)))?;
        let tmp_path = self.snapshot_path.with_extension("snapshot.tmp");
        {
            let mut f = File::create(&tmp_path)
                .map_err(|e| DhcpdError::Lease(format!("create tmp v6 snapshot: {}", e)))?;
            f.write_all(&bytes)
                .map_err(|e| DhcpdError::Lease(format!("write v6 snapshot: {}", e)))?;
            f.sync_all()
                .map_err(|e| DhcpdError::Lease(format!("sync v6 snapshot: {}", e)))?;
        }
        std::fs::rename(&tmp_path, &self.snapshot_path).map_err(|e| {
            DhcpdError::Lease(format!(
                "rename v6 snapshot: {}",
                e
            ))
        })?;
        let fresh = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.journal_path)
            .map_err(|e| DhcpdError::Lease(format!("truncate v6 journal: {}", e)))?;
        fresh.sync_all()
            .map_err(|e| DhcpdError::Lease(format!("sync v6 journal truncate: {}", e)))?;
        self.journal = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .map_err(|e| DhcpdError::Lease(format!("reopen v6 journal: {}", e)))?;
        Ok(())
    }

    fn append(&mut self, entry: &JournalEntry) -> Result<(), DhcpdError> {
        let bytes = bincode::serialize(entry)
            .map_err(|e| DhcpdError::Lease(format!("encode v6 journal entry: {}", e)))?;
        let len = bytes.len() as u32;
        self.journal
            .write_all(&len.to_be_bytes())
            .map_err(|e| DhcpdError::Lease(format!("v6 journal write len: {}", e)))?;
        self.journal
            .write_all(&bytes)
            .map_err(|e| DhcpdError::Lease(format!("v6 journal write body: {}", e)))?;
        self.journal
            .sync_data()
            .map_err(|e| DhcpdError::Lease(format!("v6 journal fsync: {}", e)))?;
        Ok(())
    }
}

fn replay_journal(
    path: &Path,
    by_key: &mut HashMap<V6Key, LeaseV6>,
    by_address: &mut HashMap<Ipv6Addr, V6Key>,
) -> Result<u64, DhcpdError> {
    let f = File::open(path)
        .map_err(|e| DhcpdError::Lease(format!("open v6 journal for replay: {}", e)))?;
    let mut reader = BufReader::new(f);
    let mut consumed: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(DhcpdError::Lease(format!("v6 journal read: {}", e))),
        }
        let entry_len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; entry_len];
        if reader.read_exact(&mut body).is_err() {
            break;
        }
        consumed += 4 + entry_len as u64;
        let entry: JournalEntry = match bincode::deserialize(&body) {
            Ok(e) => e,
            Err(_) => continue,
        };
        apply_entry(entry, by_key, by_address);
    }
    Ok(consumed)
}

fn apply_entry(
    entry: JournalEntry,
    by_key: &mut HashMap<V6Key, LeaseV6>,
    by_address: &mut HashMap<Ipv6Addr, V6Key>,
) {
    match entry {
        JournalEntry::Bind(lease) => {
            let key = V6Key {
                duid: lease.duid.clone(),
                iaid: lease.iaid,
                kind: lease.kind,
            };
            if let Some(existing) = by_address.get(&lease.address).cloned() {
                if existing != key {
                    by_key.remove(&existing);
                }
            }
            by_address.insert(lease.address, key.clone());
            by_key.insert(key, lease);
        }
        JournalEntry::Release(k) => {
            if let Some(l) = by_key.get_mut(&k) {
                l.state = LeaseStateV6::Released;
            }
        }
        JournalEntry::Decline(k) => {
            if let Some(l) = by_key.get_mut(&k) {
                l.state = LeaseStateV6::Declined;
            }
        }
        JournalEntry::Expire(k) => {
            if let Some(l) = by_key.get_mut(&k) {
                l.state = LeaseStateV6::Expired;
            }
        }
    }
}

/// Load the persistent server DUID from `<lease_db>/server-duid`,
/// or generate + persist a fresh DUID-LLT if one doesn't exist.
///
/// `mac` is the ethernet MAC to embed. `hw_type` = 1 for ethernet.
/// Called once at daemon startup.
pub fn load_or_generate_server_duid(
    dir: &Path,
    hw_type: u16,
    mac: [u8; 6],
    now: SystemTime,
) -> Result<Duid, DhcpdError> {
    let path = dir.join(SERVER_DUID_FILENAME);
    if path.exists() {
        let bytes = std::fs::read(&path)
            .map_err(|e| DhcpdError::Lease(format!("read server-duid: {}", e)))?;
        return Ok(Duid::parse(&bytes)?);
    }
    let duid = Duid::new_llt(hw_type, &mac, now);
    // Write atomically (tmp + rename).
    let tmp_path = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp_path)
            .map_err(|e| DhcpdError::Lease(format!("create server-duid tmp: {}", e)))?;
        f.write_all(duid.as_bytes())
            .map_err(|e| DhcpdError::Lease(format!("write server-duid: {}", e)))?;
        f.sync_all()
            .map_err(|e| DhcpdError::Lease(format!("sync server-duid: {}", e)))?;
    }
    std::fs::rename(&tmp_path, &path)
        .map_err(|e| DhcpdError::Lease(format!("rename server-duid: {}", e)))?;
    tracing::info!(duid = %duid.pretty(), "generated new server DUID-LLT");
    Ok(duid)
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
    use tempfile::tempdir;

    fn sample_lease(duid: &[u8], iaid: u32, addr: &str) -> LeaseV6 {
        LeaseV6 {
            duid: duid.to_vec(),
            iaid,
            kind: IaKind::Na,
            address: addr.parse().unwrap(),
            prefix_len: 128,
            preferred_lifetime: 1800,
            valid_lifetime: 3600,
            granted_unix: 1_700_000_000,
            expires_unix: 1_700_003_600,
            state: LeaseStateV6::Bound,
            via_relay: false,
        }
    }

    #[test]
    fn bind_and_recover() {
        let dir = tempdir().unwrap();
        {
            let mut s = LeaseStoreV6::open(dir.path()).unwrap();
            s.bind(sample_lease(&[1, 2, 3], 7, "2001:db8::5")).unwrap();
        }
        let s = LeaseStoreV6::open(dir.path()).unwrap();
        let key = V6Key {
            duid: vec![1, 2, 3],
            iaid: 7,
            kind: IaKind::Na,
        };
        let l = s.get(&key).unwrap();
        assert_eq!(l.address, "2001:db8::5".parse::<Ipv6Addr>().unwrap());
        assert_eq!(l.state, LeaseStateV6::Bound);
    }

    #[test]
    fn release_persists() {
        let dir = tempdir().unwrap();
        let key = V6Key {
            duid: vec![1, 2, 3],
            iaid: 7,
            kind: IaKind::Na,
        };
        {
            let mut s = LeaseStoreV6::open(dir.path()).unwrap();
            s.bind(sample_lease(&[1, 2, 3], 7, "2001:db8::5")).unwrap();
            s.release(&key).unwrap();
        }
        let s = LeaseStoreV6::open(dir.path()).unwrap();
        assert_eq!(s.get(&key).unwrap().state, LeaseStateV6::Released);
    }

    #[test]
    fn holder_of_address_index() {
        let dir = tempdir().unwrap();
        let mut s = LeaseStoreV6::open(dir.path()).unwrap();
        s.bind(sample_lease(&[1, 2, 3], 7, "2001:db8::5")).unwrap();
        let h = s.holder_of("2001:db8::5".parse().unwrap()).unwrap();
        assert_eq!(h.duid, vec![1, 2, 3]);
        assert!(s.holder_of("2001:db8::6".parse().unwrap()).is_none());
    }

    #[test]
    fn rebinding_evicts_old_client() {
        let dir = tempdir().unwrap();
        let mut s = LeaseStoreV6::open(dir.path()).unwrap();
        s.bind(sample_lease(&[1, 1, 1], 1, "2001:db8::5")).unwrap();
        s.bind(sample_lease(&[2, 2, 2], 2, "2001:db8::5")).unwrap();
        assert_eq!(s.len(), 1);
        let key = V6Key {
            duid: vec![2, 2, 2],
            iaid: 2,
            kind: IaKind::Na,
        };
        assert!(s.get(&key).is_some());
    }

    #[test]
    fn compaction_preserves_state() {
        let dir = tempdir().unwrap();
        let mut s = LeaseStoreV6::open(dir.path()).unwrap();
        for i in 0..10u8 {
            s.bind(sample_lease(&[i], i as u32, &format!("2001:db8::{:x}", i + 10)))
                .unwrap();
        }
        s.compact().unwrap();
        drop(s);
        let s = LeaseStoreV6::open(dir.path()).unwrap();
        assert_eq!(s.len(), 10);
    }

    #[test]
    fn server_duid_persists_across_calls() {
        let dir = tempdir().unwrap();
        let now = SystemTime::now();
        let d1 =
            load_or_generate_server_duid(dir.path(), 1, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], now)
                .unwrap();
        // Second call must return the SAME DUID even if `now` shifts.
        let later = now + std::time::Duration::from_secs(7200);
        let d2 =
            load_or_generate_server_duid(dir.path(), 1, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], later)
                .unwrap();
        assert_eq!(d1, d2);
    }
}
