//! v6 server glue: RX → FSM → commit lease → TX.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::config::{DhcpdV6Config, InterfaceV6Config};
use crate::error::DhcpdError;
use crate::io::{RxV6Packet, TxV6Packet};
use crate::lease::LeaseStoreV6;
use crate::packet::v6::duid::Duid;
use crate::packet::v6::message::Dhcp6Message;
use crate::v6::fsm::{handle, FsmOutcomeV6, LeaseMutationV6, PdEvent};

pub struct V6Server {
    pub store: LeaseStoreV6,
    pub global: DhcpdV6Config,
    /// sw_if_index → interface config.
    pub interfaces: HashMap<u32, InterfaceV6Config>,
    pub server_duid: Duid,
    /// Optional channel to the PD route installer. `Some(..)` when
    /// `dhcp6_server.install_pd_routes=true`. FSM-emitted PdGranted
    /// events are pushed here for async processing by the installer
    /// task (see [`crate::v6::route_installer`]).
    pub pd_event_tx: Option<tokio::sync::mpsc::UnboundedSender<PdEvent>>,
}

impl V6Server {
    pub fn new(
        store: LeaseStoreV6,
        global: DhcpdV6Config,
        interfaces: HashMap<u32, InterfaceV6Config>,
        server_duid: Duid,
    ) -> Self {
        Self {
            store,
            global,
            interfaces,
            server_duid,
            pd_event_tx: None,
        }
    }

    /// Attach the PD route installer's event channel.
    pub fn with_pd_installer(
        mut self,
        tx: tokio::sync::mpsc::UnboundedSender<PdEvent>,
    ) -> Self {
        self.pd_event_tx = Some(tx);
        self
    }

    pub fn on_rx(&mut self, pkt: &RxV6Packet) -> Result<Option<TxV6Packet>, DhcpdError> {
        let iface = match self.interfaces.get(&pkt.sw_if_index) {
            Some(i) => i.clone(),
            None => {
                tracing::debug!(
                    sw_if_index = pkt.sw_if_index,
                    "v6 DHCP packet on un-configured interface; dropping"
                );
                return Ok(None);
            }
        };
        let msg = match Dhcp6Message::decode(&pkt.payload) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "failed to decode DHCPv6 message; dropping");
                return Ok(None);
            }
        };
        let outcome = handle(
            &msg,
            pkt.sw_if_index,
            pkt.src_addr,
            &iface,
            &self.global,
            &self.server_duid,
            &self.store,
            SystemTime::now(),
        )?;
        match outcome {
            FsmOutcomeV6::Reply {
                tx,
                commit,
                pd_event,
            } => {
                self.commit(commit)?;
                if let Some(ev) = pd_event {
                    if let Some(sender) = &self.pd_event_tx {
                        if let Err(e) = sender.send(ev) {
                            tracing::warn!(
                                error = %e,
                                "PD installer channel closed; event dropped"
                            );
                        }
                    } else {
                        match &ev {
                            PdEvent::Granted(g) => tracing::debug!(
                                prefix = %g.prefix,
                                via_relay = g.via_relay,
                                "PD granted (installer disabled)"
                            ),
                            PdEvent::Revoked(r) => tracing::debug!(
                                prefix = %r.prefix,
                                via_relay = r.via_relay,
                                "PD revoked (installer disabled)"
                            ),
                        }
                    }
                }
                // Fill in the source address from the interface's
                // link-local — caller punt-io path uses it.
                let tx = self.source_fill(tx, pkt.sw_if_index);
                Ok(Some(tx))
            }
            FsmOutcomeV6::Silent { commit } => {
                self.commit(commit)?;
                Ok(None)
            }
        }
    }

    fn commit(&mut self, mutation: Option<LeaseMutationV6>) -> Result<(), DhcpdError> {
        let Some(m) = mutation else {
            return Ok(());
        };
        self.apply(m)
    }

    fn apply(&mut self, m: LeaseMutationV6) -> Result<(), DhcpdError> {
        match m {
            LeaseMutationV6::Bind(lease) => {
                tracing::info!(
                    address = %lease.address,
                    kind = ?lease.kind,
                    preferred = lease.preferred_lifetime,
                    valid = lease.valid_lifetime,
                    via_relay = lease.via_relay,
                    "binding v6 lease"
                );
                self.store.bind(lease)?;
            }
            LeaseMutationV6::Release(key) => {
                self.store.release(&key)?;
            }
            LeaseMutationV6::Decline(key) => {
                self.store.decline(&key)?;
            }
            LeaseMutationV6::Many(ms) => {
                for inner in ms {
                    self.apply(inner)?;
                }
            }
        }
        Ok(())
    }

    /// Fill in the source address from the interface's IPv6
    /// link-local. Callers (FSM `encode_tx`) leave `src_addr` as
    /// UNSPECIFIED to avoid baking interface state into the FSM.
    fn source_fill(&self, tx: TxV6Packet, _sw_if_index: u32) -> TxV6Packet {
        use std::net::Ipv6Addr;
        if tx.src_addr == Ipv6Addr::UNSPECIFIED {
            // The FSM doesn't know the interface's link-local. We
            // could fetch it from vpp_iface but the PuntIo backend
            // fills this in correctly when it has the IoInterface
            // in its own map. For now, leave as UNSPECIFIED and let
            // VPP's own src-address selection do the right thing.
        }
        tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::LeaseStoreV6;
    use crate::packet::v6::duid::Duid;
    use crate::packet::v6::message::{Dhcp6Body, Dhcp6MessageType};
    use crate::packet::v6::options::{Dhcp6Option, IaNa};
    use std::net::Ipv6Addr;
    use tempfile::tempdir;

    fn mk_iface() -> InterfaceV6Config {
        InterfaceV6Config {
            name: "lan".into(),
            pool_start: Some("2001:db8::10".parse().unwrap()),
            pool_end: Some("2001:db8::20".parse().unwrap()),
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

    fn solicit_payload() -> Vec<u8> {
        Dhcp6Message {
            msg_type: Dhcp6MessageType::Solicit,
            body: Dhcp6Body::Client { xid: 1 },
            options: vec![
                Dhcp6Option::ClientId(Duid::parse(&[0, 3, 0, 1, 1, 2, 3, 4, 5, 6]).unwrap()),
                Dhcp6Option::IaNa(IaNa {
                    iaid: 1,
                    t1: 0,
                    t2: 0,
                    addresses: vec![],
                    status: None,
                }),
            ],
        }
        .encode()
    }

    #[test]
    fn on_rx_unknown_iface_drops() {
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let duid = Duid::new_llt(1, &[1, 2, 3, 4, 5, 6], SystemTime::now());
        let mut srv = V6Server::new(store, mk_global(), HashMap::new(), duid);
        let pkt = RxV6Packet {
            sw_if_index: 99,
            src_mac: [0; 6],
            src_addr: "fe80::1".parse().unwrap(),
            dst_addr: Ipv6Addr::UNSPECIFIED,
            payload: solicit_payload(),
        };
        assert!(srv.on_rx(&pkt).unwrap().is_none());
    }

    #[test]
    fn on_rx_solicit_produces_advertise() {
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let duid = Duid::new_llt(1, &[1, 2, 3, 4, 5, 6], SystemTime::now());
        let mut ifaces = HashMap::new();
        ifaces.insert(2, mk_iface());
        let mut srv = V6Server::new(store, mk_global(), ifaces, duid);
        let pkt = RxV6Packet {
            sw_if_index: 2,
            src_mac: [0xaa; 6],
            src_addr: "fe80::1".parse().unwrap(),
            dst_addr: "ff02::1:2".parse().unwrap(),
            payload: solicit_payload(),
        };
        let tx = srv.on_rx(&pkt).unwrap().expect("expected advertise");
        let decoded = Dhcp6Message::decode(&tx.payload).unwrap();
        assert_eq!(decoded.msg_type, Dhcp6MessageType::Advertise);
    }
}
