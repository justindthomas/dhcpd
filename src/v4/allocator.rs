//! DHCPv4 pool + reservation allocator.
//!
//! The allocator is stateless with respect to time-series state —
//! it queries [`LeaseStoreV4`] for holders-of-IP and reservation
//! matches. Decisions:
//!
//!   1. **Reservation.** If the client's MAC (or v6-shaped client-id)
//!      matches a reservation, always use that IP. If the reserved
//!      IP is currently held by a *different* client, that's a
//!      config-time conflict we refuse (documented at startup).
//!      At runtime we evict the stale lease and hand the IP to its
//!      rightful owner.
//!
//!   2. **Existing lease.** If the client already has a Bound or
//!      Expired lease on this interface and the IP is still in
//!      the pool, prefer that IP. Stability across renewals.
//!
//!   3. **Requested IP (Option 50).** If the client asked for a
//!      specific IP, honor it when: (a) it's in the pool, (b) it's
//!      not a reservation for someone else, (c) nobody else is
//!      Bound to it.
//!
//!   4. **Pool scan.** Walk the pool range left-to-right; return
//!      the first IP that's not held (or is only held in a
//!      non-Bound state past quarantine).
//!
//! Declined IPs stay quarantined for [`QUARANTINE_SECS`] from the
//! time of decline. We use `expires_unix` as a proxy for "when the
//! decline happened" — `decline()` leaves the existing expiry
//! untouched but the state flips, so after `expires_unix +
//! QUARANTINE_SECS` the IP is eligible again.

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{DhcpdConfig, InterfaceV4Config};
use crate::error::DhcpdError;
use crate::lease::{Lease, LeaseState, LeaseStoreV4};
use crate::packet::v4::client_id::ClientId;

/// How long a declined IP stays quarantined (RFC 2131 §3.1 uses
/// "some time"; 30 min matches ISC DHCP's default).
pub const QUARANTINE_SECS: u64 = 30 * 60;

/// Result of an allocation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocateResult {
    /// A free IP within the interface pool, available to offer.
    Available(Ipv4Addr),
    /// No IP available — pool exhausted or all quarantined.
    Exhausted,
    /// Requested IP was explicitly unavailable (reservation belongs
    /// to someone else, or another client is bound to it).
    Unavailable(Ipv4Addr),
}

/// Allocator for a single DHCP-serving interface.
pub struct Allocator<'a> {
    pub iface: &'a InterfaceV4Config,
    pub global: &'a DhcpdConfig,
}

impl<'a> Allocator<'a> {
    pub fn new(iface: &'a InterfaceV4Config, global: &'a DhcpdConfig) -> Self {
        Self { iface, global }
    }

    /// Find the IP that belongs to (or should belong to) `cid` on
    /// this interface. `requested` is the Option 50 value from the
    /// client's DISCOVER or REQUEST, if set.
    pub fn pick(
        &self,
        cid: &ClientId,
        mac: Option<[u8; 6]>,
        requested: Option<Ipv4Addr>,
        store: &LeaseStoreV4,
    ) -> AllocateResult {
        let now = now_unix();

        // 1. Reservation match on MAC.
        if let Some(mac) = mac {
            if let Some(res) = self
                .global
                .reservations
                .iter()
                .find(|r| r.hw_address == mac)
            {
                // Return the reservation even if it's outside the
                // configured pool range — reservations often sit
                // in pool gaps deliberately.
                return AllocateResult::Available(res.ip_address);
            }
        }

        // 2. Existing lease for this client.
        if let Some(existing) = store.get(cid) {
            if self.in_pool(existing.ip) && self.ip_available(existing.ip, cid, store, now) {
                return AllocateResult::Available(existing.ip);
            }
        }

        // 3. Requested IP.
        if let Some(ip) = requested {
            if self.in_pool(ip) && self.ip_available(ip, cid, store, now) {
                return AllocateResult::Available(ip);
            } else if !self.ip_available(ip, cid, store, now) {
                return AllocateResult::Unavailable(ip);
            }
            // out-of-pool requested IP falls through to pool scan
        }

        // 4. Pool scan left-to-right.
        let start = u32::from(self.iface.pool_start);
        let end = u32::from(self.iface.pool_end);
        for n in start..=end {
            let ip = Ipv4Addr::from(n);
            if self.is_reserved_elsewhere(ip, mac) {
                continue;
            }
            if self.ip_available(ip, cid, store, now) {
                return AllocateResult::Available(ip);
            }
        }
        AllocateResult::Exhausted
    }

    /// Is this IP inside the interface's configured pool range?
    pub fn in_pool(&self, ip: Ipv4Addr) -> bool {
        let n = u32::from(ip);
        u32::from(self.iface.pool_start) <= n && n <= u32::from(self.iface.pool_end)
    }

    /// True if `ip` is currently available to `cid`: either
    /// unheld, or held by `cid` itself, or held in an expired/
    /// released state past quarantine.
    fn ip_available(
        &self,
        ip: Ipv4Addr,
        cid: &ClientId,
        store: &LeaseStoreV4,
        now: u64,
    ) -> bool {
        let Some(lease) = store.holder_of(ip) else {
            return true;
        };
        if lease.client_id == cid.as_bytes() {
            // Our own lease — always available to us.
            return true;
        }
        match lease.state {
            LeaseState::Bound => false,
            LeaseState::Declined => now >= lease.expires_unix.saturating_add(QUARANTINE_SECS),
            LeaseState::Released => true,
            LeaseState::Expired => true,
        }
    }

    /// Is `ip` reserved for a MAC other than `requesting_mac`?
    fn is_reserved_elsewhere(&self, ip: Ipv4Addr, requesting_mac: Option<[u8; 6]>) -> bool {
        for r in &self.global.reservations {
            if r.ip_address == ip {
                match requesting_mac {
                    Some(mac) => return r.hw_address != mac,
                    None => return true,
                }
            }
        }
        false
    }

    /// Build a canonical [`Lease`] record for a successful binding.
    /// `msg_type`-agnostic: callers use this for both OFFER (not yet
    /// committed) and ACK (committed) — the OFFER path writes a
    /// `Bound` state so a rogue client that skips REQUEST doesn't
    /// leak the IP. A proper "RESERVED" intermediate state is a
    /// future polish item.
    pub fn build_lease(
        &self,
        cid: &ClientId,
        mac: [u8; 6],
        ip: Ipv4Addr,
        hostname: Option<String>,
        now: SystemTime,
    ) -> Result<Lease, DhcpdError> {
        let lease_secs = u64::from(
            self.iface
                .lease_time
                .unwrap_or(self.global.default_lease_time),
        );
        let granted_unix = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| DhcpdError::Allocator(format!("clock went backwards: {}", e)))?;
        Ok(Lease {
            client_id: cid.as_bytes().to_vec(),
            ip,
            mac,
            hostname,
            granted_unix,
            expires_unix: granted_unix.saturating_add(lease_secs),
            state: LeaseState::Bound,
        })
    }

    /// Effective lease time in seconds for this interface.
    pub fn lease_secs(&self) -> u32 {
        self.iface
            .lease_time
            .unwrap_or(self.global.default_lease_time)
            .min(self.global.max_lease_time)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InterfaceV4Config, Reservation4};
    use tempfile::tempdir;

    fn mk_iface(start: [u8; 4], end: [u8; 4]) -> InterfaceV4Config {
        InterfaceV4Config {
            name: "lan".into(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            prefix_len: 24,
            pool_start: Ipv4Addr::from(start),
            pool_end: Ipv4Addr::from(end),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
        }
    }

    fn mk_global(reservations: Vec<Reservation4>) -> DhcpdConfig {
        DhcpdConfig {
            default_lease_time: 3600,
            max_lease_time: 86400,
            authoritative: true,
            global_dns_servers: vec![],
            domain_name: None,
            reservations,
            interfaces: vec![],
            subnets: vec![],
            enabled_interfaces: vec![],
        }
    }

    fn cid(mac: &[u8; 6]) -> ClientId {
        ClientId(mac.to_vec())
    }

    #[test]
    fn picks_first_free_in_pool() {
        let iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global(vec![]);
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let a = Allocator::new(&iface, &global);
        let r = a.pick(&cid(&[1; 6]), Some([1; 6]), None, &store);
        assert_eq!(r, AllocateResult::Available(Ipv4Addr::new(10, 0, 0, 100)));
    }

    #[test]
    fn honors_reservation_over_requested() {
        let iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global(vec![Reservation4 {
            hw_address: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            ip_address: Ipv4Addr::new(10, 0, 0, 5),
            hostname: None,
        }]);
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let a = Allocator::new(&iface, &global);
        let r = a.pick(
            &cid(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Some(Ipv4Addr::new(10, 0, 0, 101)), // asked for something else
            &store,
        );
        // Reservation wins even though it's outside the pool.
        assert_eq!(r, AllocateResult::Available(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn honors_existing_lease_on_renew() {
        let iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global(vec![]);
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        let existing = Lease {
            client_id: vec![1, 1, 1, 1, 1, 1],
            ip: Ipv4Addr::new(10, 0, 0, 107),
            mac: [1, 1, 1, 1, 1, 1],
            hostname: None,
            granted_unix: 0,
            expires_unix: 1_999_999_999,
            state: LeaseState::Bound,
        };
        store.bind(existing).unwrap();
        let a = Allocator::new(&iface, &global);
        let r = a.pick(&cid(&[1; 6]), Some([1; 6]), None, &store);
        assert_eq!(r, AllocateResult::Available(Ipv4Addr::new(10, 0, 0, 107)));
    }

    #[test]
    fn requested_ip_honored_when_free() {
        let iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global(vec![]);
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let a = Allocator::new(&iface, &global);
        let r = a.pick(
            &cid(&[1; 6]),
            Some([1; 6]),
            Some(Ipv4Addr::new(10, 0, 0, 105)),
            &store,
        );
        assert_eq!(r, AllocateResult::Available(Ipv4Addr::new(10, 0, 0, 105)));
    }

    #[test]
    fn requested_ip_rejected_when_held_by_other_client() {
        let iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global(vec![]);
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        store
            .bind(Lease {
                client_id: vec![9; 6],
                ip: Ipv4Addr::new(10, 0, 0, 105),
                mac: [9; 6],
                hostname: None,
                granted_unix: 0,
                expires_unix: 1_999_999_999,
                state: LeaseState::Bound,
            })
            .unwrap();
        let a = Allocator::new(&iface, &global);
        let r = a.pick(
            &cid(&[1; 6]),
            Some([1; 6]),
            Some(Ipv4Addr::new(10, 0, 0, 105)),
            &store,
        );
        assert_eq!(r, AllocateResult::Unavailable(Ipv4Addr::new(10, 0, 0, 105)));
    }

    #[test]
    fn skips_reserved_ip_for_other_mac_during_pool_scan() {
        // Pool 100..103. Reservation at .101 for MAC X. Client Y
        // scans → must skip .101 even though no lease exists.
        let iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 103]);
        let global = mk_global(vec![Reservation4 {
            hw_address: [9; 6],
            ip_address: Ipv4Addr::new(10, 0, 0, 101),
            hostname: None,
        }]);
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let a = Allocator::new(&iface, &global);
        let r = a.pick(&cid(&[1; 6]), Some([1; 6]), None, &store);
        assert_eq!(r, AllocateResult::Available(Ipv4Addr::new(10, 0, 0, 100)));
        // Fill .100. Next scan returns .102, not .101.
        let mut store = store;
        store
            .bind(Lease {
                client_id: vec![1; 6],
                ip: Ipv4Addr::new(10, 0, 0, 100),
                mac: [1; 6],
                hostname: None,
                granted_unix: 0,
                expires_unix: 1_999_999_999,
                state: LeaseState::Bound,
            })
            .unwrap();
        let r = a.pick(&cid(&[2; 6]), Some([2; 6]), None, &store);
        assert_eq!(r, AllocateResult::Available(Ipv4Addr::new(10, 0, 0, 102)));
    }

    #[test]
    fn declined_ip_quarantined_during_pool_scan() {
        let iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 101]);
        let global = mk_global(vec![]);
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        // Fill .100 in Declined state, expiring "now" (so quarantine window active).
        let expires = now_unix();
        store
            .bind(Lease {
                client_id: vec![9; 6],
                ip: Ipv4Addr::new(10, 0, 0, 100),
                mac: [9; 6],
                hostname: None,
                granted_unix: 0,
                expires_unix: expires,
                state: LeaseState::Declined,
            })
            .unwrap();
        let a = Allocator::new(&iface, &global);
        let r = a.pick(&cid(&[1; 6]), Some([1; 6]), None, &store);
        // Should skip .100 and pick .101.
        assert_eq!(r, AllocateResult::Available(Ipv4Addr::new(10, 0, 0, 101)));
    }

    #[test]
    fn pool_exhausted_returns_exhausted() {
        let iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 100]);
        let global = mk_global(vec![]);
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        store
            .bind(Lease {
                client_id: vec![9; 6],
                ip: Ipv4Addr::new(10, 0, 0, 100),
                mac: [9; 6],
                hostname: None,
                granted_unix: 0,
                expires_unix: 1_999_999_999,
                state: LeaseState::Bound,
            })
            .unwrap();
        let a = Allocator::new(&iface, &global);
        let r = a.pick(&cid(&[1; 6]), Some([1; 6]), None, &store);
        assert_eq!(r, AllocateResult::Exhausted);
    }

    #[test]
    fn released_ip_reusable_by_another_client() {
        let iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 100]);
        let global = mk_global(vec![]);
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        store
            .bind(Lease {
                client_id: vec![9; 6],
                ip: Ipv4Addr::new(10, 0, 0, 100),
                mac: [9; 6],
                hostname: None,
                granted_unix: 0,
                expires_unix: 1_999_999_999,
                state: LeaseState::Released,
            })
            .unwrap();
        let a = Allocator::new(&iface, &global);
        let r = a.pick(&cid(&[1; 6]), Some([1; 6]), None, &store);
        assert_eq!(r, AllocateResult::Available(Ipv4Addr::new(10, 0, 0, 100)));
    }

    #[test]
    fn lease_secs_clamped_to_max() {
        let mut iface = mk_iface([10, 0, 0, 100], [10, 0, 0, 200]);
        iface.lease_time = Some(9_999_999);
        let mut global = mk_global(vec![]);
        global.max_lease_time = 7200;
        let a = Allocator::new(&iface, &global);
        assert_eq!(a.lease_secs(), 7200);
    }
}
