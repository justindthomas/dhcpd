//! DHCPv6 IA_NA pool allocator.
//!
//! Mirrors the v4 allocator shape. For v6 we key bindings by
//! `(DUID, IAID, IA_NA)` — see [`LeaseStoreV6`]. A client may
//! request a specific address (via the IA_Address sub-option in
//! the IA_NA); we honor the request when the address is free and
//! in the configured pool range.

use std::net::Ipv6Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{DhcpdV6Config, InterfaceV6Config};
use crate::error::DhcpdError;
use crate::lease::{IaKind, LeaseStateV6, LeaseStoreV6, LeaseV6, V6Key};
use crate::packet::v6::duid::Duid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocateResult {
    Available(Ipv6Addr),
    Exhausted,
    Unavailable(Ipv6Addr),
}

pub struct V6Allocator<'a> {
    pub iface: &'a InterfaceV6Config,
    pub global: &'a DhcpdV6Config,
}

impl<'a> V6Allocator<'a> {
    pub fn new(iface: &'a InterfaceV6Config, global: &'a DhcpdV6Config) -> Self {
        Self { iface, global }
    }

    /// Pick an IA_NA address for this client on this interface.
    /// `requested` is the client's preferred address (IA Address
    /// sub-option) if set.
    pub fn pick(
        &self,
        duid: &Duid,
        iaid: u32,
        requested: Option<Ipv6Addr>,
        store: &LeaseStoreV6,
    ) -> AllocateResult {
        let Some(start) = self.iface.pool_start else {
            return AllocateResult::Exhausted;
        };
        let Some(end) = self.iface.pool_end else {
            return AllocateResult::Exhausted;
        };

        let key = V6Key {
            duid: duid.as_bytes().to_vec(),
            iaid,
            kind: IaKind::Na,
        };

        // 1. Existing lease for this (DUID, IAID).
        if let Some(existing) = store.get(&key) {
            if ip_in_range(&existing.address, &start, &end)
                && self.available(existing.address, &key, store)
            {
                return AllocateResult::Available(existing.address);
            }
        }

        // 2. Requested address.
        if let Some(addr) = requested {
            if ip_in_range(&addr, &start, &end) && self.available(addr, &key, store) {
                return AllocateResult::Available(addr);
            }
            if !self.available(addr, &key, store) {
                return AllocateResult::Unavailable(addr);
            }
            // out-of-pool fall through
        }

        // 3. Scan the pool.
        let start_n = u128::from(start);
        let end_n = u128::from(end);
        // Cap scans at 65k to bound runtime on enormous pools.
        // Beyond that, use a stochastic scan (future polish).
        const MAX_SCAN: u128 = 65_536;
        let upper = end_n.min(start_n + MAX_SCAN);
        for n in start_n..=upper {
            let addr = Ipv6Addr::from(n);
            if self.available(addr, &key, store) {
                return AllocateResult::Available(addr);
            }
        }
        AllocateResult::Exhausted
    }

    fn available(&self, addr: Ipv6Addr, key: &V6Key, store: &LeaseStoreV6) -> bool {
        let Some(lease) = store.holder_of(addr) else {
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
            // Phase 3: treat declined v6 leases as not-available
            // indefinitely. Phase 4 polish: add quarantine window.
            LeaseStateV6::Declined => false,
        }
    }

    /// Build an IA_NA lease record for a successful binding.
    pub fn build_lease(
        &self,
        duid: &Duid,
        iaid: u32,
        address: Ipv6Addr,
        now: SystemTime,
        via_relay: bool,
    ) -> Result<LeaseV6, DhcpdError> {
        let preferred = self.global.preferred_lifetime;
        let valid = self.global.valid_lifetime;
        let granted = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| DhcpdError::Allocator(format!("clock went backwards: {}", e)))?;
        Ok(LeaseV6 {
            duid: duid.as_bytes().to_vec(),
            iaid,
            kind: IaKind::Na,
            address,
            prefix_len: 128,
            preferred_lifetime: preferred,
            valid_lifetime: valid,
            granted_unix: granted,
            expires_unix: granted.saturating_add(valid as u64),
            state: LeaseStateV6::Bound,
            via_relay,
        })
    }

    /// T1 (renewal) = 0.5 * preferred_lifetime per RFC 8415 §14.2.
    pub fn t1(&self) -> u32 {
        self.global.preferred_lifetime / 2
    }

    /// T2 (rebinding) = 0.8 * preferred_lifetime per RFC 8415 §14.2.
    pub fn t2(&self) -> u32 {
        (self.global.preferred_lifetime * 4) / 5
    }
}

fn ip_in_range(addr: &Ipv6Addr, start: &Ipv6Addr, end: &Ipv6Addr) -> bool {
    let n = u128::from(*addr);
    n >= u128::from(*start) && n <= u128::from(*end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn mk_iface(start: &str, end: &str) -> InterfaceV6Config {
        InterfaceV6Config {
            name: "lan".into(),
            pool_start: Some(start.parse().unwrap()),
            pool_end: Some(end.parse().unwrap()),
            pd_pool: None,
        }
    }

    fn mk_global() -> DhcpdV6Config {
        DhcpdV6Config {
            preferred_lifetime: 1800,
            valid_lifetime: 3600,
            global_dns_servers: vec![],
            domain_search: vec![],
            pd_pools: vec![],
            interfaces: vec![],
            subnets: vec![],
            install_pd_routes: false,
        }
    }

    fn duid(bytes: &[u8]) -> Duid {
        Duid(bytes.to_vec())
    }

    #[test]
    fn picks_first_in_pool() {
        let iface = mk_iface("2001:db8::10", "2001:db8::20");
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let a = V6Allocator::new(&iface, &global);
        let r = a.pick(&duid(&[1; 10]), 1, None, &store);
        assert_eq!(
            r,
            AllocateResult::Available("2001:db8::10".parse().unwrap())
        );
    }

    #[test]
    fn honors_requested_when_free() {
        let iface = mk_iface("2001:db8::10", "2001:db8::20");
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let a = V6Allocator::new(&iface, &global);
        let r = a.pick(
            &duid(&[1; 10]),
            1,
            Some("2001:db8::15".parse().unwrap()),
            &store,
        );
        assert_eq!(
            r,
            AllocateResult::Available("2001:db8::15".parse().unwrap())
        );
    }

    #[test]
    fn requested_unavailable_rejected() {
        let iface = mk_iface("2001:db8::10", "2001:db8::20");
        let global = mk_global();
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV6::open(dir.path()).unwrap();
        store
            .bind(LeaseV6 {
                duid: vec![9; 10],
                iaid: 99,
                kind: IaKind::Na,
                address: "2001:db8::15".parse().unwrap(),
                prefix_len: 128,
                preferred_lifetime: 1800,
                valid_lifetime: 3600,
                granted_unix: 0,
                expires_unix: u64::MAX,
                state: LeaseStateV6::Bound,
                via_relay: false,
            })
            .unwrap();
        let a = V6Allocator::new(&iface, &global);
        let r = a.pick(
            &duid(&[1; 10]),
            1,
            Some("2001:db8::15".parse().unwrap()),
            &store,
        );
        assert_eq!(
            r,
            AllocateResult::Unavailable("2001:db8::15".parse().unwrap())
        );
    }

    #[test]
    fn honors_existing_lease_on_renew() {
        let iface = mk_iface("2001:db8::10", "2001:db8::20");
        let global = mk_global();
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV6::open(dir.path()).unwrap();
        store
            .bind(LeaseV6 {
                duid: vec![1; 10],
                iaid: 1,
                kind: IaKind::Na,
                address: "2001:db8::18".parse().unwrap(),
                prefix_len: 128,
                preferred_lifetime: 1800,
                valid_lifetime: 3600,
                granted_unix: 0,
                expires_unix: u64::MAX,
                state: LeaseStateV6::Bound,
                via_relay: false,
            })
            .unwrap();
        let a = V6Allocator::new(&iface, &global);
        let r = a.pick(&duid(&[1; 10]), 1, None, &store);
        assert_eq!(
            r,
            AllocateResult::Available("2001:db8::18".parse().unwrap())
        );
    }

    #[test]
    fn exhausted_when_pool_full() {
        let iface = mk_iface("2001:db8::10", "2001:db8::10");
        let global = mk_global();
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV6::open(dir.path()).unwrap();
        store
            .bind(LeaseV6 {
                duid: vec![9; 10],
                iaid: 99,
                kind: IaKind::Na,
                address: "2001:db8::10".parse().unwrap(),
                prefix_len: 128,
                preferred_lifetime: 1800,
                valid_lifetime: 3600,
                granted_unix: 0,
                expires_unix: u64::MAX,
                state: LeaseStateV6::Bound,
                via_relay: false,
            })
            .unwrap();
        let a = V6Allocator::new(&iface, &global);
        let r = a.pick(&duid(&[1; 10]), 1, None, &store);
        assert_eq!(r, AllocateResult::Exhausted);
    }

    #[test]
    fn t1_t2_match_rfc() {
        let iface = mk_iface("2001:db8::10", "2001:db8::20");
        let mut global = mk_global();
        global.preferred_lifetime = 1000;
        let a = V6Allocator::new(&iface, &global);
        assert_eq!(a.t1(), 500);
        assert_eq!(a.t2(), 800);
    }
}
