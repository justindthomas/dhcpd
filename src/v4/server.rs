//! Glue layer: RX packet → FSM → commit lease → TX reply.
//!
//! The server owns a lease store + an interface→config map and is
//! driven from the daemon's main select loop. It's synchronous-ish
//! — the FSM and lease operations don't block on the network, so
//! we can safely run this on a single tokio task.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::config::{DhcpdConfig, InterfaceV4Config};
use crate::error::DhcpdError;
use crate::io::{RxV4Packet, TxV4Packet};
use crate::lease::LeaseStoreV4;
use crate::packet::v4::message::DhcpMessage;
use crate::v4::fsm::{handle, FsmOutcome, LeaseMutation};

/// A server tied to one dhcpd instance's lease store and
/// config. Per-interface config is looked up by `sw_if_index`.
pub struct V4Server {
    pub store: LeaseStoreV4,
    pub global: DhcpdConfig,
    /// sw_if_index → interface config.
    pub interfaces: HashMap<u32, InterfaceV4Config>,
}

impl V4Server {
    pub fn new(
        store: LeaseStoreV4,
        global: DhcpdConfig,
        interfaces: HashMap<u32, InterfaceV4Config>,
    ) -> Self {
        Self {
            store,
            global,
            interfaces,
        }
    }

    /// Handle a single RX packet. Returns the outbound packet (if
    /// any) after committing any lease mutation the FSM asks for.
    /// The caller is responsible for actually sending the TX.
    pub fn on_rx(&mut self, pkt: &RxV4Packet) -> Result<Option<TxV4Packet>, DhcpdError> {
        let iface = match self.interfaces.get(&pkt.sw_if_index) {
            Some(i) => i.clone(),
            None => {
                tracing::debug!(
                    sw_if_index = pkt.sw_if_index,
                    "DHCP packet on interface without v4 serving config; dropping"
                );
                return Ok(None);
            }
        };

        let msg = match DhcpMessage::decode(&pkt.payload) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "failed to decode DHCP message; dropping");
                return Ok(None);
            }
        };

        let now = SystemTime::now();
        let outcome = handle(&msg, pkt.sw_if_index, pkt.src_addr, &iface, &self.global, &self.store, now)?;
        match outcome {
            FsmOutcome::Reply { tx, commit } => {
                // fsync the lease mutation before returning the tx
                // so the daemon can safely send it.
                self.commit(commit)?;
                Ok(Some(tx))
            }
            FsmOutcome::Silent { commit } => {
                self.commit(commit)?;
                Ok(None)
            }
        }
    }

    fn commit(&mut self, mutation: Option<LeaseMutation>) -> Result<(), DhcpdError> {
        let Some(m) = mutation else {
            return Ok(());
        };
        match m {
            LeaseMutation::Bind(lease) => {
                tracing::info!(
                    ip = %lease.ip,
                    mac = format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        lease.mac[0], lease.mac[1], lease.mac[2],
                        lease.mac[3], lease.mac[4], lease.mac[5]
                    ),
                    expires_unix = lease.expires_unix,
                    "binding lease"
                );
                self.store.bind(lease)?;
            }
            LeaseMutation::Release(cid) => {
                self.store.release(&cid)?;
            }
            LeaseMutation::Decline(cid) => {
                self.store.decline(&cid)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::v4::header::{BootOp, BootpHeader, BOOTP_FLAG_BROADCAST};
    use crate::packet::v4::message::{DhcpMessage, DhcpMessageType};
    use crate::packet::v4::options::DhcpOption;
    use std::net::Ipv4Addr;
    use tempfile::tempdir;

    fn mk_iface() -> InterfaceV4Config {
        InterfaceV4Config {
            name: "lan".into(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            prefix_len: 24,
            pool_start: Ipv4Addr::new(10, 0, 0, 100),
            pool_end: Ipv4Addr::new(10, 0, 0, 110),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            lease_time: None,
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
            domain_name: Some("example.net".into()),
            trust_relay: false,
        }
    }

    fn mk_global() -> DhcpdConfig {
        DhcpdConfig {
            default_lease_time: 3600,
            max_lease_time: 86400,
            authoritative: true,
            global_dns_servers: vec![],
            domain_name: None,
            reservations: vec![],
            interfaces: vec![],
            subnets: vec![],
            enabled_interfaces: vec![],
        }
    }

    fn build_discover_payload(mac: [u8; 6], xid: u32) -> Vec<u8> {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&mac);
        let hdr = BootpHeader {
            op: BootOp::Request,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags: BOOTP_FLAG_BROADCAST,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
        };
        let msg = DhcpMessage {
            header: hdr,
            msg_type: DhcpMessageType::Discover,
            options: vec![DhcpOption::MessageType(1)],
        };
        msg.encode()
    }

    #[test]
    fn on_rx_discover_produces_offer_and_binds_lease() {
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let iface = mk_iface();
        let mut ifaces = HashMap::new();
        ifaces.insert(2, iface.clone());
        let mut server = V4Server::new(store, mk_global(), ifaces);

        let pkt = RxV4Packet {
            sw_if_index: 2,
            src_mac: [1; 6],
            src_addr: Ipv4Addr::UNSPECIFIED,
            dst_addr: Ipv4Addr::BROADCAST,
            payload: build_discover_payload([1; 6], 0xcafe),
        };
        let tx = server.on_rx(&pkt).unwrap().expect("expected offer");
        let reply = DhcpMessage::decode(&tx.payload).unwrap();
        assert_eq!(reply.msg_type, DhcpMessageType::Offer);
        // Lease committed to store.
        assert_eq!(server.store.len(), 1);
    }

    #[test]
    fn on_rx_unknown_interface_drops_silently() {
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let mut server = V4Server::new(store, mk_global(), HashMap::new());
        let pkt = RxV4Packet {
            sw_if_index: 99,
            src_mac: [1; 6],
            src_addr: Ipv4Addr::UNSPECIFIED,
            dst_addr: Ipv4Addr::BROADCAST,
            payload: build_discover_payload([1; 6], 1),
        };
        assert!(server.on_rx(&pkt).unwrap().is_none());
        assert_eq!(server.store.len(), 0);
    }

    #[test]
    fn on_rx_malformed_payload_drops_silently() {
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let iface = mk_iface();
        let mut ifaces = HashMap::new();
        ifaces.insert(2, iface);
        let mut server = V4Server::new(store, mk_global(), ifaces);
        let pkt = RxV4Packet {
            sw_if_index: 2,
            src_mac: [1; 6],
            src_addr: Ipv4Addr::UNSPECIFIED,
            dst_addr: Ipv4Addr::BROADCAST,
            payload: vec![0u8; 30], // too short
        };
        assert!(server.on_rx(&pkt).unwrap().is_none());
    }
}
