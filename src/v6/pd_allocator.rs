//! DHCPv6 Prefix Delegation allocator.
//!
//! Carves a configured `pd_pool.prefix` (the super-prefix) into
//! `delegated_length`-sized chunks. Each chunk is a candidate
//! delegation for one client (keyed by `(DUID, IAID)` in the lease
//! store).
//!
//! Allocation order:
//!
//! 1. **DUID affinity** — if `(DUID, IAID)` already has a bound
//!    delegation in the store, return the same prefix. Survives
//!    daemon restarts (leases replay from the journal).
//! 2. **Requested prefix** — if the client's IA_PD carries an
//!    IAPrefix with a non-zero prefix, honor it when it's inside
//!    the super-prefix, aligned to `delegated_length`, and free.
//! 3. **Pool scan** — left-to-right walk of the chunk space.
//!
//! Scan is capped at 65k iterations for bounded runtime on very
//! large pools. In practice real deployments delegate a /56 out of
//! a /40..  /36 — tens of thousands of chunks.

use std::net::Ipv6Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::ParsedPdPool;
use crate::error::DhcpdError;
use crate::lease::{IaKind, LeaseStateV6, LeaseStoreV6, LeaseV6, V6Key};
use crate::packet::v6::duid::Duid;

/// Result of a PD allocation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdAllocateResult {
    Available(Ipv6Addr),
    Exhausted,
    /// Requested prefix is unavailable (held by another client).
    Unavailable(Ipv6Addr),
}

/// Upper bound on the scan length to keep allocation O(bounded).
const MAX_SCAN: u128 = 65_536;

pub struct PdAllocator<'a> {
    pub pool: &'a ParsedPdPool,
}

impl<'a> PdAllocator<'a> {
    pub fn new(pool: &'a ParsedPdPool) -> Self {
        Self { pool }
    }

    /// Pick a delegation for `(duid, iaid)`.
    pub fn pick(
        &self,
        duid: &Duid,
        iaid: u32,
        requested: Option<Ipv6Addr>,
        store: &LeaseStoreV6,
    ) -> PdAllocateResult {
        let key = V6Key {
            duid: duid.as_bytes().to_vec(),
            iaid,
            kind: IaKind::Pd,
        };

        // 1. DUID affinity — return the same prefix if we already have one.
        if let Some(existing) = store.get(&key) {
            if self.prefix_in_pool(existing.address)
                && self.available_to(existing.address, &key, store)
            {
                return PdAllocateResult::Available(existing.address);
            }
        }

        // 2. Requested prefix, if client specified one and it aligns.
        if let Some(req) = requested {
            if !req.is_unspecified() {
                if self.is_aligned(req) && self.prefix_in_pool(req) {
                    if self.available_to(req, &key, store) {
                        return PdAllocateResult::Available(req);
                    } else {
                        return PdAllocateResult::Unavailable(req);
                    }
                }
            }
        }

        // 3. Scan.
        let step: u128 = 1u128 << (128u32 - self.pool.delegated_length as u32);
        let start = u128::from(self.pool.prefix);
        let super_size: u128 = 1u128 << (128u32 - self.pool.prefix_len as u32);
        let count = (super_size / step).min(MAX_SCAN);
        let mut cur = start;
        for _ in 0..count {
            let candidate = Ipv6Addr::from(cur);
            if self.available_to(candidate, &key, store) {
                return PdAllocateResult::Available(candidate);
            }
            cur = cur.wrapping_add(step);
        }
        PdAllocateResult::Exhausted
    }

    /// Is `prefix` inside our super-prefix?
    fn prefix_in_pool(&self, prefix: Ipv6Addr) -> bool {
        let super_start = u128::from(self.pool.prefix);
        let super_mask = if self.pool.prefix_len == 0 {
            0u128
        } else {
            (!0u128) << (128 - self.pool.prefix_len as u32)
        };
        (u128::from(prefix) & super_mask) == (super_start & super_mask)
    }

    /// Is `prefix` aligned to a `delegated_length` boundary?
    fn is_aligned(&self, prefix: Ipv6Addr) -> bool {
        let d = self.pool.delegated_length as u32;
        if d == 0 {
            return true;
        }
        if d >= 128 {
            return u128::from(prefix) == u128::from(prefix);
        }
        let host_bits = 128 - d;
        (u128::from(prefix) & ((1u128 << host_bits) - 1)) == 0
    }

    /// Is `prefix` available to `key` (either free, or held by us,
    /// or held in an Expired/Released state)?
    fn available_to(
        &self,
        prefix: Ipv6Addr,
        key: &V6Key,
        store: &LeaseStoreV6,
    ) -> bool {
        let Some(lease) = store.holder_of(prefix) else {
            return true;
        };
        let holder = V6Key {
            duid: lease.duid.clone(),
            iaid: lease.iaid,
            kind: lease.kind,
        };
        if holder == *key {
            return true;
        }
        match lease.state {
            LeaseStateV6::Bound => false,
            LeaseStateV6::Released | LeaseStateV6::Expired => true,
            LeaseStateV6::Declined => false,
        }
    }

    /// Build a LeaseV6 record for a PD delegation.
    pub fn build_lease(
        &self,
        duid: &Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        now: SystemTime,
        via_relay: bool,
    ) -> Result<LeaseV6, DhcpdError> {
        let granted = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| DhcpdError::Allocator(format!("clock went backwards: {}", e)))?;
        Ok(LeaseV6 {
            duid: duid.as_bytes().to_vec(),
            iaid,
            kind: IaKind::Pd,
            address: prefix,
            prefix_len: self.pool.delegated_length,
            preferred_lifetime: self.pool.preferred_lifetime,
            valid_lifetime: self.pool.valid_lifetime,
            granted_unix: granted,
            expires_unix: granted.saturating_add(self.pool.valid_lifetime as u64),
            state: LeaseStateV6::Bound,
            via_relay,
        })
    }

    pub fn t1(&self) -> u32 {
        self.pool.preferred_lifetime / 2
    }

    pub fn t2(&self) -> u32 {
        (self.pool.preferred_lifetime * 4) / 5
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn mk_pool(prefix: &str, len: u8, deleg: u8) -> ParsedPdPool {
        ParsedPdPool {
            name: "residential".into(),
            prefix: prefix.parse().unwrap(),
            prefix_len: len,
            delegated_length: deleg,
            preferred_lifetime: 3600,
            valid_lifetime: 86400,
        }
    }

    fn duid(b: &[u8]) -> Duid {
        Duid(b.to_vec())
    }

    #[test]
    fn picks_first_delegated_prefix() {
        let pool = mk_pool("2001:db8:1000::", 36, 56);
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let a = PdAllocator::new(&pool);
        assert_eq!(
            a.pick(&duid(&[1; 10]), 1, None, &store),
            PdAllocateResult::Available("2001:db8:1000::".parse().unwrap())
        );
    }

    #[test]
    fn duid_affinity_returns_same_prefix() {
        let pool = mk_pool("2001:db8:1000::", 36, 56);
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV6::open(dir.path()).unwrap();
        // Bind an existing PD for our (DUID, IAID) at 2001:db8:1000:ff00::/56.
        store
            .bind(LeaseV6 {
                duid: vec![1; 10],
                iaid: 7,
                kind: IaKind::Pd,
                address: "2001:db8:1000:ff00::".parse().unwrap(),
                prefix_len: 56,
                preferred_lifetime: 3600,
                valid_lifetime: 86400,
                granted_unix: 0,
                expires_unix: u64::MAX,
                state: LeaseStateV6::Bound,
                via_relay: false,
            })
            .unwrap();
        let a = PdAllocator::new(&pool);
        assert_eq!(
            a.pick(&duid(&[1; 10]), 7, None, &store),
            PdAllocateResult::Available(
                "2001:db8:1000:ff00::".parse().unwrap()
            )
        );
    }

    #[test]
    fn requested_prefix_must_align() {
        let pool = mk_pool("2001:db8:1000::", 36, 56);
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let a = PdAllocator::new(&pool);
        // Unaligned request — low bits non-zero at /56 boundary.
        let unaligned: Ipv6Addr = "2001:db8:1000:0001:1234::".parse().unwrap();
        // Must fall through to the pool scan (returning first).
        assert_eq!(
            a.pick(&duid(&[2; 10]), 2, Some(unaligned), &store),
            PdAllocateResult::Available("2001:db8:1000::".parse().unwrap())
        );
    }

    #[test]
    fn requested_aligned_prefix_honored() {
        let pool = mk_pool("2001:db8:1000::", 36, 56);
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let a = PdAllocator::new(&pool);
        let aligned: Ipv6Addr = "2001:db8:1000:ab00::".parse().unwrap();
        assert_eq!(
            a.pick(&duid(&[3; 10]), 3, Some(aligned), &store),
            PdAllocateResult::Available(aligned)
        );
    }

    #[test]
    fn requested_prefix_held_by_other_client_unavailable() {
        let pool = mk_pool("2001:db8:1000::", 36, 56);
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV6::open(dir.path()).unwrap();
        store
            .bind(LeaseV6 {
                duid: vec![9; 10],
                iaid: 99,
                kind: IaKind::Pd,
                address: "2001:db8:1000:1000::".parse().unwrap(),
                prefix_len: 56,
                preferred_lifetime: 3600,
                valid_lifetime: 86400,
                granted_unix: 0,
                expires_unix: u64::MAX,
                state: LeaseStateV6::Bound,
                via_relay: false,
            })
            .unwrap();
        let a = PdAllocator::new(&pool);
        let requested: Ipv6Addr = "2001:db8:1000:1000::".parse().unwrap();
        assert_eq!(
            a.pick(&duid(&[4; 10]), 4, Some(requested), &store),
            PdAllocateResult::Unavailable(requested)
        );
    }

    #[test]
    fn scan_skips_bound_and_returns_next() {
        let pool = mk_pool("2001:db8::", 60, 62); // only 4 chunks: /62 steps of 0x4_0000_0000...0000
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV6::open(dir.path()).unwrap();
        // Block the first chunk.
        store
            .bind(LeaseV6 {
                duid: vec![9; 10],
                iaid: 99,
                kind: IaKind::Pd,
                address: "2001:db8::".parse().unwrap(),
                prefix_len: 62,
                preferred_lifetime: 3600,
                valid_lifetime: 86400,
                granted_unix: 0,
                expires_unix: u64::MAX,
                state: LeaseStateV6::Bound,
                via_relay: false,
            })
            .unwrap();
        let a = PdAllocator::new(&pool);
        // Step at /62 = 64 bits of host. Next chunk = 2001:db8::4:0:0:0.
        let result = a.pick(&duid(&[5; 10]), 5, None, &store);
        if let PdAllocateResult::Available(got) = result {
            assert_ne!(got, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        } else {
            panic!("expected Available, got {:?}", result);
        }
    }

    #[test]
    fn released_prefix_reusable() {
        let pool = mk_pool("2001:db8::", 60, 60); // one chunk
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV6::open(dir.path()).unwrap();
        store
            .bind(LeaseV6 {
                duid: vec![9; 10],
                iaid: 99,
                kind: IaKind::Pd,
                address: "2001:db8::".parse().unwrap(),
                prefix_len: 60,
                preferred_lifetime: 3600,
                valid_lifetime: 86400,
                granted_unix: 0,
                expires_unix: u64::MAX,
                state: LeaseStateV6::Released,
                via_relay: false,
            })
            .unwrap();
        let a = PdAllocator::new(&pool);
        assert_eq!(
            a.pick(&duid(&[6; 10]), 6, None, &store),
            PdAllocateResult::Available("2001:db8::".parse().unwrap())
        );
    }

    #[test]
    fn t1_t2_per_rfc() {
        let pool = mk_pool("2001:db8:1000::", 36, 56);
        let a = PdAllocator::new(&pool);
        assert_eq!(a.t1(), 1800);
        assert_eq!(a.t2(), 2880); // 0.8 * 3600
    }
}
