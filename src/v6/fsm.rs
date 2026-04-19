//! DHCPv6 server FSM (RFC 8415 §18).
//!
//! The FSM consumes a parsed [`Dhcp6Message`], peels any
//! Relay-Forw encapsulation, dispatches on the inner client
//! message type, and returns zero or one [`TxV6Packet`] — wrapped
//! symmetrically in Relay-Repl when the input was relayed.
//!
//! Phase 3 scope: IA_NA lifecycle. Phase 4 adds IA_PD in the
//! same dispatch — the `PdGranted` event surface is reserved but
//! not yet populated.

use std::net::Ipv6Addr;
use std::time::SystemTime;

use crate::config::{DhcpdV6Config, InterfaceV6Config};
use crate::error::DhcpdError;
use crate::io::TxV6Packet;
use crate::lease::{IaKind, LeaseStoreV6, LeaseV6, V6Key};
use crate::packet::v6::duid::Duid;
use crate::packet::v6::header::{
    RelayHeader, DHCP6_CLIENT_PORT, DHCP6_SERVER_PORT,
};
use crate::packet::v6::message::{Dhcp6Body, Dhcp6Message, Dhcp6MessageType};
use crate::packet::v6::options::{
    find_client_id, find_ia_na, find_ia_pd, find_server_id, has_rapid_commit, Dhcp6Option,
    IaAddress, IaNa, IaPd, IaPrefix, StatusCode,
};
use crate::v6::allocator::{AllocateResult, V6Allocator};
use crate::v6::pd_allocator::{PdAllocateResult, PdAllocator};

/// Result of the FSM dispatch.
#[derive(Debug)]
pub enum FsmOutcomeV6 {
    Reply {
        tx: TxV6Packet,
        commit: Option<LeaseMutationV6>,
        /// For PD grants via direct path, the route-installer picks
        /// this up in Phase 4. Phase 3 always emits None.
        pd_event: Option<PdEvent>,
    },
    Silent {
        commit: Option<LeaseMutationV6>,
    },
}

#[derive(Debug)]
pub enum LeaseMutationV6 {
    Bind(LeaseV6),
    Release(V6Key),
    Decline(V6Key),
    /// Composite mutation — applied in order. Used when a single
    /// client message carries both IA_NA and IA_PD.
    Many(Vec<LeaseMutationV6>),
}

/// A PD lifecycle event consumed by the route installer. `Granted`
/// is emitted on a successful delegation (Solicit+Rapid-Commit or
/// Request), `Revoked` on Release. The route installer translates
/// these to ribd `update(Add, ...)` / `update(Remove, ...)`.
///
/// When `via_relay=true`, the installer skips — the relay (L3
/// switch) owns the route for that delegation.
#[derive(Debug, Clone)]
pub enum PdEvent {
    Granted(PdGranted),
    Revoked(PdRevoked),
}

/// Details of a fresh PD grant. `next_hop` is the client's
/// link-local (from the Solicit's source or the innermost relay's
/// peer-address); `ingress_sw_if_index` is the VPP interface the
/// request arrived on.
#[derive(Debug, Clone)]
pub struct PdGranted {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub next_hop: Ipv6Addr,
    pub ingress_sw_if_index: u32,
    pub via_relay: bool,
}

/// Details of a PD revocation. We keep the delegation's `prefix`
/// and `prefix_len` so the installer can build the removal route
/// precisely; `via_relay` signals whether we had previously
/// installed it (Phase 4 rule: direct path only).
#[derive(Debug, Clone)]
pub struct PdRevoked {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub via_relay: bool,
}

/// Dispatch a received DHCPv6 message.
pub fn handle(
    msg: &Dhcp6Message,
    sw_if_index: u32,
    src_addr: Ipv6Addr,
    iface: &InterfaceV6Config,
    global: &DhcpdV6Config,
    server_duid: &Duid,
    store: &LeaseStoreV6,
    now: SystemTime,
) -> Result<FsmOutcomeV6, DhcpdError> {
    // Peel any relay layers. For a non-relayed client message, the
    // relay chain is empty and `inner == msg`.
    let (relays, inner) = msg.peel_relays()?;
    let via_relay = !relays.is_empty();

    // Pool selection. Relayed packets carry `link-address` in the
    // outermost Relay-Forw, which identifies the client's subnet
    // on the relay's client-facing link. Direct packets use the
    // ingress interface's pool.
    let effective = match select_effective_context_v6(&relays, iface, global) {
        Some(eff) => eff,
        None => {
            tracing::warn!(
                cid = ?crate::packet::v6::options::find_client_id(&inner.options),
                "no matching v6 subnet for relayed packet; dropping"
            );
            return Ok(FsmOutcomeV6::Silent { commit: None });
        }
    };
    let iface = &effective;

    // The client's own message type dictates behavior.
    match inner.msg_type {
        Dhcp6MessageType::Solicit => handle_solicit(
            &inner, &relays, sw_if_index, src_addr, iface, global, server_duid, store, now, via_relay,
        ),
        Dhcp6MessageType::Request => handle_request(
            &inner, &relays, sw_if_index, src_addr, iface, global, server_duid, store, now, via_relay,
        ),
        Dhcp6MessageType::Renew | Dhcp6MessageType::Rebind => handle_renew_rebind(
            &inner, &relays, sw_if_index, src_addr, iface, global, server_duid, store, now, via_relay,
        ),
        Dhcp6MessageType::Release => {
            handle_release(&inner, &relays, sw_if_index, src_addr, iface, server_duid, store)
        }
        Dhcp6MessageType::Decline => {
            handle_decline(&inner, &relays, sw_if_index, src_addr, iface, server_duid)
        }
        Dhcp6MessageType::InformationRequest => handle_information_request(
            &inner, &relays, sw_if_index, src_addr, iface, global, server_duid,
        ),
        Dhcp6MessageType::Confirm => handle_confirm(
            &inner, &relays, sw_if_index, src_addr, iface, global, server_duid, store,
        ),
        other => {
            tracing::debug!(
                msg_type = other.name(),
                "v6 server ignoring client message type"
            );
            Ok(FsmOutcomeV6::Silent { commit: None })
        }
    }
}

/// Pick the effective [`InterfaceV6Config`] for a packet. When the
/// packet is relayed, the *outermost* (closest-to-client) relay's
/// `link-address` identifies the client's subnet — look it up in
/// `global.subnets[]` and synthesize an iface config with that pool.
/// When direct, the ingress iface config is used unchanged.
fn select_effective_context_v6(
    relays: &[RelayHeader],
    iface: &InterfaceV6Config,
    global: &DhcpdV6Config,
) -> Option<InterfaceV6Config> {
    // Relay order from `peel_relays` is outer→inner. The outermost
    // (first) relay is the one closest to the server (furthest from
    // the client). The innermost (last) relay has the link-address
    // on the client's own subnet. Per RFC 8415 §18.4, servers use
    // the innermost relay's link-address when it's non-zero.
    let inner_most = relays.last();
    let link_addr = inner_most.map(|h| h.link_address);
    match link_addr {
        Some(a) if !a.is_unspecified() => {
            // Relayed with an explicit link-address. Require a
            // matching subnet — this is symmetric with the v4
            // path's giaddr handling. Falling back to the ingress
            // iface pool would be wrong: that pool is on the
            // uplink, not the client's subnet.
            let subnet = global.find_subnet(a)?;
            Some(InterfaceV6Config {
                name: format!("subnet:{}", subnet.subnet),
                pool_start: Some(subnet.pool_start),
                pool_end: Some(subnet.pool_end),
                pd_pool: iface.pd_pool.clone(),
            })
        }
        _ => Some(iface.clone()),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_solicit(
    inner: &Dhcp6Message,
    relays: &[RelayHeader],
    sw_if_index: u32,
    src_addr: Ipv6Addr,
    iface: &InterfaceV6Config,
    global: &DhcpdV6Config,
    server_duid: &Duid,
    store: &LeaseStoreV6,
    now: SystemTime,
    via_relay: bool,
) -> Result<FsmOutcomeV6, DhcpdError> {
    let Some(client_duid) = find_client_id(&inner.options) else {
        // Clients MUST include a Client-ID; drop.
        return Ok(FsmOutcomeV6::Silent { commit: None });
    };
    let ia_na = find_ia_na(&inner.options);
    let ia_pd = find_ia_pd(&inner.options);
    if ia_na.is_none() && ia_pd.is_none() {
        // Solicit with neither IA_NA nor IA_PD — drop. Clients who
        // want stateless DNS config use Information-Request instead.
        return Ok(FsmOutcomeV6::Silent { commit: None });
    }

    let rapid = has_rapid_commit(&inner.options);
    let reply_type = if rapid {
        Dhcp6MessageType::Reply
    } else {
        Dhcp6MessageType::Advertise
    };
    let commit_now = rapid && reply_type == Dhcp6MessageType::Reply;

    let mut reply_opts: Vec<Dhcp6Option> = vec![
        Dhcp6Option::ClientId(client_duid.clone()),
        Dhcp6Option::ServerId(server_duid.clone()),
    ];
    if !global.global_dns_servers.is_empty() {
        reply_opts.push(Dhcp6Option::DnsServers(global.global_dns_servers.clone()));
    }
    if rapid {
        reply_opts.push(Dhcp6Option::RapidCommit);
    }

    let mut commits: Vec<LeaseMutationV6> = Vec::new();
    let mut pd_event: Option<PdEvent> = None;

    if let Some(ia_na) = ia_na {
        let alloc = V6Allocator::new(iface, global);
        let requested = ia_na.addresses.first().map(|a| a.address);
        let (out_ia, maybe_bind) =
            process_ia_na(&alloc, client_duid, ia_na, requested, store, now, via_relay)?;
        reply_opts.push(Dhcp6Option::IaNa(out_ia));
        if let (true, Some(bind)) = (commit_now, maybe_bind) {
            commits.push(bind);
        }
    }
    if let Some(ia_pd) = ia_pd {
        let requested = ia_pd.prefixes.first().map(|p| p.prefix);
        let (out_ia_pd, maybe_bind, event) = process_ia_pd(
            iface,
            global,
            client_duid,
            ia_pd,
            requested,
            store,
            now,
            via_relay,
            sw_if_index,
            inner_peer_address(relays, src_addr),
        )?;
        reply_opts.push(Dhcp6Option::IaPd(out_ia_pd));
        if commit_now {
            if let Some(bind) = maybe_bind {
                commits.push(bind);
            }
            if let Some(ev) = event {
                pd_event = Some(PdEvent::Granted(ev));
            }
        }
    }

    let reply = build_client_reply(inner, reply_type, reply_opts);
    let tx = encode_tx(reply, relays, sw_if_index, src_addr, iface)?;
    let commit = match commits.len() {
        0 => None,
        1 => Some(commits.into_iter().next().unwrap()),
        _ => Some(LeaseMutationV6::Many(commits)),
    };
    Ok(FsmOutcomeV6::Reply {
        tx,
        commit,
        pd_event,
    })
}

/// Runs the IA_NA allocator and builds the reply option + optional
/// Bind mutation. Factored so Solicit/Request/Renew share one path.
fn process_ia_na(
    alloc: &V6Allocator,
    client_duid: &Duid,
    ia_na: &IaNa,
    requested: Option<Ipv6Addr>,
    store: &LeaseStoreV6,
    now: SystemTime,
    via_relay: bool,
) -> Result<(IaNa, Option<LeaseMutationV6>), DhcpdError> {
    match alloc.pick(client_duid, ia_na.iaid, requested, store) {
        AllocateResult::Available(ip) => {
            let lease = alloc.build_lease(client_duid, ia_na.iaid, ip, now, via_relay)?;
            let ia_addr = IaAddress {
                address: ip,
                preferred_lifetime: alloc.global.preferred_lifetime,
                valid_lifetime: alloc.global.valid_lifetime,
                status: None,
            };
            Ok((
                IaNa {
                    iaid: ia_na.iaid,
                    t1: alloc.t1(),
                    t2: alloc.t2(),
                    addresses: vec![ia_addr],
                    status: None,
                },
                Some(LeaseMutationV6::Bind(lease)),
            ))
        }
        _ => Ok((
            IaNa {
                iaid: ia_na.iaid,
                t1: 0,
                t2: 0,
                addresses: vec![],
                status: Some((StatusCode::NoAddrsAvail, "pool exhausted".into())),
            },
            None,
        )),
    }
}

/// Runs the PD allocator for an IA_PD sub-option. Returns the reply
/// IA_PD, an optional Bind mutation, and a `PdGranted` event for
/// the Phase-4 route installer (only populated for direct-path
/// delegations; relayed delegations set the event's `via_relay`
/// flag and the installer is responsible for honoring it).
#[allow(clippy::too_many_arguments)]
fn process_ia_pd(
    iface: &InterfaceV6Config,
    global: &DhcpdV6Config,
    client_duid: &Duid,
    ia_pd: &IaPd,
    requested: Option<Ipv6Addr>,
    store: &LeaseStoreV6,
    now: SystemTime,
    via_relay: bool,
    ingress_sw_if_index: u32,
    next_hop: Ipv6Addr,
) -> Result<(IaPd, Option<LeaseMutationV6>, Option<PdGranted>), DhcpdError> {
    // Which PD pool? The interface config names it; look up in
    // `global.pd_pools`.
    let pool_name = match &iface.pd_pool {
        Some(n) => n,
        None => {
            // Interface isn't configured for PD — reply
            // NoPrefixAvail.
            return Ok((
                IaPd {
                    iaid: ia_pd.iaid,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: Some((
                        StatusCode::NoPrefixAvail,
                        "PD not configured on this interface".into(),
                    )),
                },
                None,
                None,
            ));
        }
    };
    let pool = match global.pd_pools.iter().find(|p| &p.name == pool_name) {
        Some(p) => p,
        None => {
            tracing::warn!(
                pool = pool_name.as_str(),
                "interface references unknown PD pool; returning NoPrefixAvail"
            );
            return Ok((
                IaPd {
                    iaid: ia_pd.iaid,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: Some((
                        StatusCode::NoPrefixAvail,
                        "unknown PD pool".into(),
                    )),
                },
                None,
                None,
            ));
        }
    };
    let alloc = PdAllocator::new(pool);
    match alloc.pick(client_duid, ia_pd.iaid, requested, store) {
        PdAllocateResult::Available(prefix) => {
            let lease = alloc.build_lease(client_duid, ia_pd.iaid, prefix, now, via_relay)?;
            let out = IaPd {
                iaid: ia_pd.iaid,
                t1: alloc.t1(),
                t2: alloc.t2(),
                prefixes: vec![IaPrefix {
                    preferred_lifetime: pool.preferred_lifetime,
                    valid_lifetime: pool.valid_lifetime,
                    prefix_len: pool.delegated_length,
                    prefix,
                    status: None,
                }],
                status: None,
            };
            let event = PdGranted {
                prefix,
                prefix_len: pool.delegated_length,
                next_hop,
                ingress_sw_if_index,
                via_relay,
            };
            Ok((out, Some(LeaseMutationV6::Bind(lease)), Some(event)))
        }
        _ => Ok((
            IaPd {
                iaid: ia_pd.iaid,
                t1: 0,
                t2: 0,
                prefixes: vec![],
                status: Some((
                    StatusCode::NoPrefixAvail,
                    "PD pool exhausted".into(),
                )),
            },
            None,
            None,
        )),
    }
}

/// Determine the "next hop" IPv6 address for a PD delegation. For
/// direct packets this is the client's source address (its
/// link-local). For relayed packets this is the innermost relay's
/// `peer-address` — which is the client's link-local on the
/// relay's client-facing link.
fn inner_peer_address(relays: &[RelayHeader], src_addr: Ipv6Addr) -> Ipv6Addr {
    relays.last().map(|h| h.peer_address).unwrap_or(src_addr)
}

#[allow(clippy::too_many_arguments)]
fn handle_request(
    inner: &Dhcp6Message,
    relays: &[RelayHeader],
    sw_if_index: u32,
    src_addr: Ipv6Addr,
    iface: &InterfaceV6Config,
    global: &DhcpdV6Config,
    server_duid: &Duid,
    store: &LeaseStoreV6,
    now: SystemTime,
    via_relay: bool,
) -> Result<FsmOutcomeV6, DhcpdError> {
    if !server_id_matches(inner, server_duid) {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    }
    let Some(client_duid) = find_client_id(&inner.options) else {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    };
    let ia_na = find_ia_na(&inner.options);
    let ia_pd = find_ia_pd(&inner.options);
    if ia_na.is_none() && ia_pd.is_none() {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    }

    let mut reply_opts: Vec<Dhcp6Option> = vec![
        Dhcp6Option::ClientId(client_duid.clone()),
        Dhcp6Option::ServerId(server_duid.clone()),
    ];
    if !global.global_dns_servers.is_empty() {
        reply_opts.push(Dhcp6Option::DnsServers(global.global_dns_servers.clone()));
    }
    let mut commits: Vec<LeaseMutationV6> = Vec::new();
    let mut pd_event: Option<PdEvent> = None;

    if let Some(ia_na) = ia_na {
        let alloc = V6Allocator::new(iface, global);
        let requested = ia_na.addresses.first().map(|a| a.address);
        let (out, bind) =
            process_ia_na(&alloc, client_duid, ia_na, requested, store, now, via_relay)?;
        reply_opts.push(Dhcp6Option::IaNa(out));
        if let Some(b) = bind {
            commits.push(b);
        }
    }
    if let Some(ia_pd) = ia_pd {
        let requested = ia_pd.prefixes.first().map(|p| p.prefix);
        let (out, bind, event) = process_ia_pd(
            iface,
            global,
            client_duid,
            ia_pd,
            requested,
            store,
            now,
            via_relay,
            sw_if_index,
            inner_peer_address(relays, src_addr),
        )?;
        reply_opts.push(Dhcp6Option::IaPd(out));
        if let Some(b) = bind {
            commits.push(b);
        }
        if let Some(e) = event {
            pd_event = Some(PdEvent::Granted(e));
        }
    }

    let reply = build_client_reply(inner, Dhcp6MessageType::Reply, reply_opts);
    let tx = encode_tx(reply, relays, sw_if_index, src_addr, iface)?;
    let commit = match commits.len() {
        0 => None,
        1 => Some(commits.into_iter().next().unwrap()),
        _ => Some(LeaseMutationV6::Many(commits)),
    };
    Ok(FsmOutcomeV6::Reply {
        tx,
        commit,
        pd_event,
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_renew_rebind(
    inner: &Dhcp6Message,
    relays: &[RelayHeader],
    sw_if_index: u32,
    src_addr: Ipv6Addr,
    iface: &InterfaceV6Config,
    global: &DhcpdV6Config,
    server_duid: &Duid,
    store: &LeaseStoreV6,
    now: SystemTime,
    via_relay: bool,
) -> Result<FsmOutcomeV6, DhcpdError> {
    // Renew includes our Server-ID. Rebind does not (goes multicast).
    if inner.msg_type == Dhcp6MessageType::Renew && !server_id_matches(inner, server_duid) {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    }
    let Some(client_duid) = find_client_id(&inner.options) else {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    };
    let ia_na = find_ia_na(&inner.options);
    let ia_pd = find_ia_pd(&inner.options);
    if ia_na.is_none() && ia_pd.is_none() {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    }

    let is_rebind = inner.msg_type == Dhcp6MessageType::Rebind;

    let mut reply_opts: Vec<Dhcp6Option> = vec![
        Dhcp6Option::ClientId(client_duid.clone()),
        Dhcp6Option::ServerId(server_duid.clone()),
    ];
    if !global.global_dns_servers.is_empty() {
        reply_opts.push(Dhcp6Option::DnsServers(global.global_dns_servers.clone()));
    }
    let mut commits: Vec<LeaseMutationV6> = Vec::new();

    if let Some(ia_na) = ia_na {
        let key = V6Key {
            duid: client_duid.as_bytes().to_vec(),
            iaid: ia_na.iaid,
            kind: IaKind::Na,
        };
        let alloc = V6Allocator::new(iface, global);
        match store.get(&key) {
            Some(existing) => {
                let lease = alloc.build_lease(
                    client_duid,
                    ia_na.iaid,
                    existing.address,
                    now,
                    via_relay,
                )?;
                let ia_addr = IaAddress {
                    address: existing.address,
                    preferred_lifetime: global.preferred_lifetime,
                    valid_lifetime: global.valid_lifetime,
                    status: None,
                };
                reply_opts.push(Dhcp6Option::IaNa(IaNa {
                    iaid: ia_na.iaid,
                    t1: alloc.t1(),
                    t2: alloc.t2(),
                    addresses: vec![ia_addr],
                    status: None,
                }));
                commits.push(LeaseMutationV6::Bind(lease));
            }
            None => {
                if is_rebind {
                    // RFC 8415 §18.3.5: silently drop Rebind when
                    // we have no binding for this client.
                    return Ok(FsmOutcomeV6::Silent { commit: None });
                }
                reply_opts.push(Dhcp6Option::IaNa(IaNa {
                    iaid: ia_na.iaid,
                    t1: 0,
                    t2: 0,
                    addresses: vec![],
                    status: Some((StatusCode::NoBinding, "no such binding".into())),
                }));
            }
        }
    }
    if let Some(ia_pd) = ia_pd {
        let key = V6Key {
            duid: client_duid.as_bytes().to_vec(),
            iaid: ia_pd.iaid,
            kind: IaKind::Pd,
        };
        match (store.get(&key), iface.pd_pool.as_ref()) {
            (Some(existing), Some(pool_name))
                if global.pd_pools.iter().any(|p| &p.name == pool_name) =>
            {
                let pool = global
                    .pd_pools
                    .iter()
                    .find(|p| &p.name == pool_name)
                    .unwrap();
                let alloc = PdAllocator::new(pool);
                let lease = alloc.build_lease(
                    client_duid,
                    ia_pd.iaid,
                    existing.address,
                    now,
                    via_relay,
                )?;
                reply_opts.push(Dhcp6Option::IaPd(IaPd {
                    iaid: ia_pd.iaid,
                    t1: alloc.t1(),
                    t2: alloc.t2(),
                    prefixes: vec![IaPrefix {
                        preferred_lifetime: pool.preferred_lifetime,
                        valid_lifetime: pool.valid_lifetime,
                        prefix_len: pool.delegated_length,
                        prefix: existing.address,
                        status: None,
                    }],
                    status: None,
                }));
                commits.push(LeaseMutationV6::Bind(lease));
            }
            _ => {
                if is_rebind {
                    return Ok(FsmOutcomeV6::Silent { commit: None });
                }
                reply_opts.push(Dhcp6Option::IaPd(IaPd {
                    iaid: ia_pd.iaid,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: Some((StatusCode::NoBinding, "no such PD binding".into())),
                }));
            }
        }
    }

    let reply = build_client_reply(inner, Dhcp6MessageType::Reply, reply_opts);
    let tx = encode_tx(reply, relays, sw_if_index, src_addr, iface)?;
    let commit = match commits.len() {
        0 => None,
        1 => Some(commits.into_iter().next().unwrap()),
        _ => Some(LeaseMutationV6::Many(commits)),
    };
    Ok(FsmOutcomeV6::Reply {
        tx,
        commit,
        pd_event: None,
    })
}

fn handle_release(
    inner: &Dhcp6Message,
    relays: &[RelayHeader],
    sw_if_index: u32,
    src_addr: Ipv6Addr,
    iface: &InterfaceV6Config,
    server_duid: &Duid,
    store: &LeaseStoreV6,
) -> Result<FsmOutcomeV6, DhcpdError> {
    if !server_id_matches(inner, server_duid) {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    }
    let Some(client_duid) = find_client_id(&inner.options) else {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    };
    let ia_na = find_ia_na(&inner.options);
    let ia_pd = find_ia_pd(&inner.options);
    if ia_na.is_none() && ia_pd.is_none() {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    }

    let mut commits: Vec<LeaseMutationV6> = Vec::new();
    let mut pd_event: Option<PdEvent> = None;

    if let Some(ia_na) = ia_na {
        commits.push(LeaseMutationV6::Release(V6Key {
            duid: client_duid.as_bytes().to_vec(),
            iaid: ia_na.iaid,
            kind: IaKind::Na,
        }));
    }
    if let Some(ia_pd) = ia_pd {
        let key = V6Key {
            duid: client_duid.as_bytes().to_vec(),
            iaid: ia_pd.iaid,
            kind: IaKind::Pd,
        };
        // Emit a Revoked event if we had a binding; the installer
        // uses it to remove the route from ribd. If no binding
        // existed (duplicate Release), the event is skipped.
        if let Some(existing) = store.get(&key) {
            pd_event = Some(PdEvent::Revoked(PdRevoked {
                prefix: existing.address,
                prefix_len: existing.prefix_len,
                via_relay: existing.via_relay,
            }));
        }
        commits.push(LeaseMutationV6::Release(key));
    }

    // RFC 8415 §18.3.7: send Reply with status=Success.
    let opts = vec![
        Dhcp6Option::ClientId(client_duid.clone()),
        Dhcp6Option::ServerId(server_duid.clone()),
        Dhcp6Option::StatusCode(StatusCode::Success, "released".into()),
    ];
    let reply = build_client_reply(inner, Dhcp6MessageType::Reply, opts);
    let tx = encode_tx(reply, relays, sw_if_index, src_addr, iface)?;
    let commit = match commits.len() {
        0 => None,
        1 => Some(commits.into_iter().next().unwrap()),
        _ => Some(LeaseMutationV6::Many(commits)),
    };
    Ok(FsmOutcomeV6::Reply {
        tx,
        commit,
        pd_event,
    })
}

fn handle_decline(
    inner: &Dhcp6Message,
    relays: &[RelayHeader],
    sw_if_index: u32,
    src_addr: Ipv6Addr,
    iface: &InterfaceV6Config,
    server_duid: &Duid,
) -> Result<FsmOutcomeV6, DhcpdError> {
    if !server_id_matches(inner, server_duid) {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    }
    let Some(client_duid) = find_client_id(&inner.options) else {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    };
    let Some(ia_na) = find_ia_na(&inner.options) else {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    };
    let key = V6Key {
        duid: client_duid.as_bytes().to_vec(),
        iaid: ia_na.iaid,
        kind: IaKind::Na,
    };
    let opts = vec![
        Dhcp6Option::ClientId(client_duid.clone()),
        Dhcp6Option::ServerId(server_duid.clone()),
        Dhcp6Option::StatusCode(StatusCode::Success, "declined".into()),
    ];
    let reply = build_client_reply(inner, Dhcp6MessageType::Reply, opts);
    let tx = encode_tx(reply, relays, sw_if_index, src_addr, iface)?;
    Ok(FsmOutcomeV6::Reply {
        tx,
        commit: Some(LeaseMutationV6::Decline(key)),
        pd_event: None,
    })
}

fn handle_information_request(
    inner: &Dhcp6Message,
    relays: &[RelayHeader],
    sw_if_index: u32,
    src_addr: Ipv6Addr,
    iface: &InterfaceV6Config,
    global: &DhcpdV6Config,
    server_duid: &Duid,
) -> Result<FsmOutcomeV6, DhcpdError> {
    // Client-ID is optional for Information-Request.
    let client_duid = find_client_id(&inner.options).cloned();
    let opts = build_reply_options(
        // Client-ID — echo if present. If absent, we still need to
        // send Server-ID. build_reply_options takes &Duid; use a
        // zero-byte placeholder when the client omitted theirs and
        // skip the echo in post-processing.
        client_duid
            .as_ref()
            .unwrap_or(&Duid(vec![0])),
        server_duid,
        None, // no IA_NA in Info-Request reply
        global,
        false,
    );
    let opts = if client_duid.is_none() {
        opts.into_iter()
            .filter(|o| !matches!(o, Dhcp6Option::ClientId(_)))
            .collect()
    } else {
        opts
    };
    let reply = build_client_reply(inner, Dhcp6MessageType::Reply, opts);
    let tx = encode_tx(reply, relays, sw_if_index, src_addr, iface)?;
    Ok(FsmOutcomeV6::Reply {
        tx,
        commit: None,
        pd_event: None,
    })
}

fn handle_confirm(
    inner: &Dhcp6Message,
    relays: &[RelayHeader],
    sw_if_index: u32,
    src_addr: Ipv6Addr,
    iface: &InterfaceV6Config,
    global: &DhcpdV6Config,
    server_duid: &Duid,
    store: &LeaseStoreV6,
) -> Result<FsmOutcomeV6, DhcpdError> {
    // Confirm: client asking "is my address still valid on this link?"
    // RFC 8415 §18.3.3: look at all IAs in the Confirm; if any
    // address matches a known binding on the ingress link, reply
    // Success. Otherwise reply NotOnLink.
    let Some(client_duid) = find_client_id(&inner.options) else {
        return Ok(FsmOutcomeV6::Silent { commit: None });
    };

    let mut on_link = false;
    for opt in &inner.options {
        if let Dhcp6Option::IaNa(ia) = opt {
            for a in &ia.addresses {
                let key = V6Key {
                    duid: client_duid.as_bytes().to_vec(),
                    iaid: ia.iaid,
                    kind: IaKind::Na,
                };
                if store
                    .get(&key)
                    .map(|l| l.address == a.address)
                    .unwrap_or(false)
                {
                    on_link = true;
                    break;
                }
                // Also accept if the address is inside the pool —
                // we still own the subnet.
                if let (Some(start), Some(end)) = (iface.pool_start, iface.pool_end) {
                    let n = u128::from(a.address);
                    if n >= u128::from(start) && n <= u128::from(end) {
                        on_link = true;
                        break;
                    }
                }
            }
        }
        if on_link {
            break;
        }
    }

    let status = if on_link {
        (StatusCode::Success, "on link".into())
    } else {
        (StatusCode::NotOnLink, "not on link".into())
    };
    let opts = vec![
        Dhcp6Option::ClientId(client_duid.clone()),
        Dhcp6Option::ServerId(server_duid.clone()),
        Dhcp6Option::StatusCode(status.0, status.1),
    ];
    let _ = global; // currently unused here; kept for symmetry
    let reply = build_client_reply(inner, Dhcp6MessageType::Reply, opts);
    let tx = encode_tx(reply, relays, sw_if_index, src_addr, iface)?;
    Ok(FsmOutcomeV6::Reply {
        tx,
        commit: None,
        pd_event: None,
    })
}

fn server_id_matches(inner: &Dhcp6Message, server_duid: &Duid) -> bool {
    match find_server_id(&inner.options) {
        Some(d) => d == server_duid,
        None => false,
    }
}

/// Build the standard reply option set: Client-ID echo, Server-ID,
/// IA_NA (if provided), DNS, domain search, and Rapid-Commit if we
/// committed in response to one.
fn build_reply_options(
    client_duid: &Duid,
    server_duid: &Duid,
    ia: Option<IaNa>,
    global: &DhcpdV6Config,
    rapid_commit: bool,
) -> Vec<Dhcp6Option> {
    let mut opts = Vec::with_capacity(8);
    opts.push(Dhcp6Option::ClientId(client_duid.clone()));
    opts.push(Dhcp6Option::ServerId(server_duid.clone()));
    if let Some(ia) = ia {
        opts.push(Dhcp6Option::IaNa(ia));
    }
    if !global.global_dns_servers.is_empty() {
        opts.push(Dhcp6Option::DnsServers(global.global_dns_servers.clone()));
    }
    if rapid_commit {
        opts.push(Dhcp6Option::RapidCommit);
    }
    opts
}

/// Helper: build a Dhcp6Message reply preserving the client's xid.
fn build_client_reply(
    req: &Dhcp6Message,
    msg_type: Dhcp6MessageType,
    options: Vec<Dhcp6Option>,
) -> Dhcp6Message {
    let xid = match &req.body {
        Dhcp6Body::Client { xid } => *xid,
        Dhcp6Body::Relay(_) => 0, // shouldn't happen — caller peels relays first
    };
    Dhcp6Message {
        msg_type,
        body: Dhcp6Body::Client { xid },
        options,
    }
}

/// Wrap `reply` in any required Relay-Repl layers (reversed stack
/// from the original Relay-Forw chain) and encode the final
/// TxV6Packet.
///
/// - Relayed: destination = the innermost relay's source address
///   (i.e., where the request came from). Port 547 → 547.
/// - Direct: destination = the client's link-local source address.
///   Port 547 → 546.
fn encode_tx(
    reply: Dhcp6Message,
    relays: &[RelayHeader],
    sw_if_index: u32,
    src_addr: Ipv6Addr,
    iface: &InterfaceV6Config,
) -> Result<TxV6Packet, DhcpdError> {
    let _ = iface;
    // Build the wrapped reply. Start from the innermost (client)
    // reply and wrap outward through each Relay-Forw → Relay-Repl.
    let mut current = reply.encode();
    // Walk the relay chain from innermost to outermost. `relays`
    // from `peel_relays` is ordered outer→inner, so we iterate in
    // reverse.
    for hdr in relays.iter().rev() {
        let mut wrap_opts = vec![Dhcp6Option::RelayMessage(current.clone())];
        // Echo any Interface-ID / Client-Linklayer-Addr the relay
        // sent us. Phase 3 doesn't propagate those from the relay
        // header options — that's a v1.5 polish item.
        let wrap = Dhcp6Message {
            msg_type: Dhcp6MessageType::RelayRepl,
            body: Dhcp6Body::Relay(RelayHeader {
                msg_type: Dhcp6MessageType::RelayRepl as u8,
                hop_count: hdr.hop_count,
                link_address: hdr.link_address,
                peer_address: hdr.peer_address,
            }),
            options: wrap_opts.drain(..).collect(),
        };
        current = wrap.encode();
    }

    // Destination address. Port selection is the caller's concern
    // (PuntIo::send_v6 always emits to DHCP6_CLIENT_PORT=546 for
    // direct and DHCP6_SERVER_PORT=547 for relayed replies; we keep
    // the logic here as documentation).
    let _relay_port = DHCP6_SERVER_PORT;
    let _client_port = DHCP6_CLIENT_PORT;
    let dst_addr = src_addr;

    Ok(TxV6Packet {
        sw_if_index,
        src_addr: Ipv6Addr::UNSPECIFIED, // caller fills from iface link-local
        dst_addr,
        payload: current,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DhcpdV6Config;
    use crate::packet::v6::header::Dhcp6Header;
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
            global_dns_servers: vec!["2001:4860:4860::8888".parse().unwrap()],
            domain_search: vec![],
            pd_pools: vec![],
            interfaces: vec![],
            subnets: vec![],
            install_pd_routes: false,
        }
    }

    fn server_duid() -> Duid {
        Duid::new_llt(1, &[1, 2, 3, 4, 5, 6], SystemTime::UNIX_EPOCH)
    }

    fn client_duid() -> Duid {
        Duid::parse(&[0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).unwrap()
    }

    fn solicit(xid: u32, requested: Option<Ipv6Addr>) -> Dhcp6Message {
        let ia = IaNa {
            iaid: 42,
            t1: 0,
            t2: 0,
            addresses: requested
                .map(|a| {
                    vec![IaAddress {
                        address: a,
                        preferred_lifetime: 0,
                        valid_lifetime: 0,
                        status: None,
                    }]
                })
                .unwrap_or_default(),
            status: None,
        };
        Dhcp6Message {
            msg_type: Dhcp6MessageType::Solicit,
            body: Dhcp6Body::Client { xid },
            options: vec![
                Dhcp6Option::ClientId(client_duid()),
                Dhcp6Option::IaNa(ia),
                Dhcp6Option::Oro(vec![crate::packet::v6::options::OPT_DNS_SERVERS]),
                Dhcp6Option::ElapsedTime(0),
            ],
        }
    }

    #[test]
    fn solicit_yields_advertise_with_pool_address() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let out = handle(
            &solicit(0xcafe, None),
            2,
            src,
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match out {
            FsmOutcomeV6::Reply {
                tx,
                commit: None, // no commit without Rapid-Commit
                pd_event: None,
            } => {
                let reply = Dhcp6Message::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, Dhcp6MessageType::Advertise);
                let ia = find_ia_na(&reply.options).expect("IA_NA in advertise");
                assert_eq!(ia.addresses.len(), 1);
                assert_eq!(
                    ia.addresses[0].address,
                    "2001:db8::10".parse::<Ipv6Addr>().unwrap()
                );
                // Reply was unicast back to the client's link-local.
                assert_eq!(tx.dst_addr, src);
            }
            other => panic!("expected Advertise, got {:?}", other),
        }
    }

    #[test]
    fn rapid_commit_solicit_yields_reply_and_bind() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let mut msg = solicit(0xbeef, None);
        msg.options.push(Dhcp6Option::RapidCommit);
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match out {
            FsmOutcomeV6::Reply {
                tx,
                commit: Some(LeaseMutationV6::Bind(_)),
                ..
            } => {
                let reply = Dhcp6Message::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, Dhcp6MessageType::Reply);
                assert!(has_rapid_commit(&reply.options));
            }
            other => panic!("expected Reply+Bind, got {:?}", other),
        }
    }

    #[test]
    fn request_matching_server_id_acks() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let mut msg = solicit(1, None);
        msg.msg_type = Dhcp6MessageType::Request;
        msg.options.push(Dhcp6Option::ServerId(sd.clone()));
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match out {
            FsmOutcomeV6::Reply {
                tx,
                commit: Some(LeaseMutationV6::Bind(_)),
                ..
            } => {
                let reply = Dhcp6Message::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, Dhcp6MessageType::Reply);
            }
            other => panic!("expected Reply, got {:?}", other),
        }
    }

    #[test]
    fn request_for_wrong_server_silent() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let other =
            Duid::new_llt(1, &[9, 9, 9, 9, 9, 9], SystemTime::UNIX_EPOCH);
        let mut msg = solicit(1, None);
        msg.msg_type = Dhcp6MessageType::Request;
        msg.options.push(Dhcp6Option::ServerId(other));
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        assert!(matches!(out, FsmOutcomeV6::Silent { commit: None }));
    }

    #[test]
    fn relayed_solicit_returns_relay_repl_wrap() {
        let iface = mk_iface();
        let mut global = mk_global();
        // Configure a subnet that contains the relay's link-address
        // so subnet selection succeeds — this test covers the
        // Relay-Repl wrap shape, not the drop path.
        global.subnets.push(crate::config::Subnet6 {
            subnet: "2001:db8::/64".parse().unwrap(),
            pool_start: "2001:db8::1000".parse().unwrap(),
            pool_end: "2001:db8::ffff".parse().unwrap(),
            preferred_lifetime: None,
            valid_lifetime: None,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();

        let inner_bytes = solicit(0xabc, None).encode();
        let relay_msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::RelayForw,
            body: Dhcp6Body::Relay(RelayHeader {
                msg_type: 12,
                hop_count: 0,
                link_address: "2001:db8::1".parse().unwrap(),
                peer_address: "fe80::cafe".parse().unwrap(),
            }),
            options: vec![
                Dhcp6Option::InterfaceId(b"sw-port-5".to_vec()),
                Dhcp6Option::RelayMessage(inner_bytes),
            ],
        };

        let out = handle(
            &relay_msg,
            2,
            "2001:db8::ffff".parse().unwrap(), // the relay's src addr
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match out {
            FsmOutcomeV6::Reply { tx, .. } => {
                let decoded = Dhcp6Message::decode(&tx.payload).unwrap();
                assert_eq!(decoded.msg_type, Dhcp6MessageType::RelayRepl);
                // The relay header was echoed.
                if let Dhcp6Body::Relay(h) = decoded.body {
                    assert_eq!(h.msg_type, Dhcp6MessageType::RelayRepl as u8);
                    assert_eq!(h.link_address, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                    assert_eq!(
                        h.peer_address,
                        "fe80::cafe".parse::<Ipv6Addr>().unwrap()
                    );
                } else {
                    panic!("expected Relay body");
                }
                // Destination goes back to the relay (unicast), port 547.
                assert_eq!(
                    tx.dst_addr,
                    "2001:db8::ffff".parse::<Ipv6Addr>().unwrap()
                );
            }
            other => panic!("expected Reply, got {:?}", other),
        }
    }

    #[test]
    fn release_emits_reply_and_release_mutation() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let mut msg = solicit(1, Some("2001:db8::15".parse().unwrap()));
        msg.msg_type = Dhcp6MessageType::Release;
        msg.options.push(Dhcp6Option::ServerId(sd.clone()));
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match out {
            FsmOutcomeV6::Reply {
                commit: Some(LeaseMutationV6::Release(_)),
                ..
            } => {}
            other => panic!("expected Release, got {:?}", other),
        }
    }

    #[test]
    fn information_request_yields_reply_without_ia() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::InformationRequest,
            body: Dhcp6Body::Client { xid: 1 },
            options: vec![
                Dhcp6Option::ClientId(client_duid()),
                Dhcp6Option::Oro(vec![crate::packet::v6::options::OPT_DNS_SERVERS]),
            ],
        };
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcomeV6::Reply { tx, .. } = out {
            let reply = Dhcp6Message::decode(&tx.payload).unwrap();
            assert_eq!(reply.msg_type, Dhcp6MessageType::Reply);
            assert!(find_ia_na(&reply.options).is_none());
            // DNS servers from config should be present.
            assert!(reply
                .options
                .iter()
                .any(|o| matches!(o, Dhcp6Option::DnsServers(_))));
        } else {
            panic!("expected Reply");
        }
    }

    #[test]
    fn confirm_returns_notonlink_for_foreign_address() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let mut msg = solicit(1, Some("2001:db9::1".parse().unwrap()));
        msg.msg_type = Dhcp6MessageType::Confirm;
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcomeV6::Reply { tx, .. } = out {
            let reply = Dhcp6Message::decode(&tx.payload).unwrap();
            let status = reply
                .options
                .iter()
                .find_map(|o| match o {
                    Dhcp6Option::StatusCode(s, _) => Some(*s),
                    _ => None,
                })
                .expect("status code");
            assert_eq!(status, StatusCode::NotOnLink);
        } else {
            panic!("expected Reply");
        }
    }

    #[test]
    fn confirm_returns_success_for_in_pool_address() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let mut msg = solicit(1, Some("2001:db8::15".parse().unwrap()));
        msg.msg_type = Dhcp6MessageType::Confirm;
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcomeV6::Reply { tx, .. } = out {
            let reply = Dhcp6Message::decode(&tx.payload).unwrap();
            let status = reply
                .options
                .iter()
                .find_map(|o| match o {
                    Dhcp6Option::StatusCode(s, _) => Some(*s),
                    _ => None,
                })
                .expect("status code");
            assert_eq!(status, StatusCode::Success);
        } else {
            panic!("expected Reply");
        }
    }

    #[test]
    fn renew_for_unknown_client_returns_nobinding() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let mut msg = solicit(1, None);
        msg.msg_type = Dhcp6MessageType::Renew;
        msg.options.push(Dhcp6Option::ServerId(sd.clone()));
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcomeV6::Reply { tx, .. } = out {
            let reply = Dhcp6Message::decode(&tx.payload).unwrap();
            let ia = find_ia_na(&reply.options).unwrap();
            assert_eq!(
                ia.status,
                Some((StatusCode::NoBinding, "no such binding".into()))
            );
        } else {
            panic!("expected Reply");
        }
    }

    #[test]
    fn solicit_with_ia_pd_advertises_prefix_with_pd_event() {
        let mut iface = mk_iface();
        iface.pd_pool = Some("residential".into());
        let mut global = mk_global();
        global.pd_pools.push(crate::config::ParsedPdPool {
            name: "residential".into(),
            prefix: "2001:db8:1000::".parse().unwrap(),
            prefix_len: 36,
            delegated_length: 56,
            preferred_lifetime: 3600,
            valid_lifetime: 86400,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();

        // Solicit carrying just IA_PD.
        let msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::Solicit,
            body: Dhcp6Body::Client { xid: 1 },
            options: vec![
                Dhcp6Option::ClientId(client_duid()),
                Dhcp6Option::IaPd(IaPd {
                    iaid: 7,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: None,
                }),
            ],
        };
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcomeV6::Reply { tx, .. } = out {
            let reply = Dhcp6Message::decode(&tx.payload).unwrap();
            assert_eq!(reply.msg_type, Dhcp6MessageType::Advertise);
            let ia_pd = crate::packet::v6::options::find_ia_pd(&reply.options)
                .expect("IA_PD in advertise");
            assert_eq!(ia_pd.prefixes.len(), 1);
            assert_eq!(
                ia_pd.prefixes[0].prefix,
                "2001:db8:1000::".parse::<Ipv6Addr>().unwrap()
            );
            assert_eq!(ia_pd.prefixes[0].prefix_len, 56);
        } else {
            panic!("expected Advertise");
        }
    }

    #[test]
    fn rapid_commit_solicit_ia_pd_binds_and_emits_event() {
        let mut iface = mk_iface();
        iface.pd_pool = Some("residential".into());
        let mut global = mk_global();
        global.pd_pools.push(crate::config::ParsedPdPool {
            name: "residential".into(),
            prefix: "2001:db8:1000::".parse().unwrap(),
            prefix_len: 36,
            delegated_length: 56,
            preferred_lifetime: 3600,
            valid_lifetime: 86400,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();

        let msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::Solicit,
            body: Dhcp6Body::Client { xid: 2 },
            options: vec![
                Dhcp6Option::ClientId(client_duid()),
                Dhcp6Option::IaPd(IaPd {
                    iaid: 9,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: None,
                }),
                Dhcp6Option::RapidCommit,
            ],
        };
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match out {
            FsmOutcomeV6::Reply {
                commit: Some(LeaseMutationV6::Bind(lease)),
                pd_event: Some(PdEvent::Granted(ev)),
                ..
            } => {
                assert_eq!(lease.kind, crate::lease::IaKind::Pd);
                assert_eq!(lease.prefix_len, 56);
                assert_eq!(ev.prefix_len, 56);
                assert!(!ev.via_relay);
            }
            other => panic!("expected PD Bind + event, got {:?}", other),
        }
    }

    #[test]
    fn solicit_ia_pd_without_configured_pool_returns_noprefixavail() {
        let iface = mk_iface(); // pd_pool = None
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::Solicit,
            body: Dhcp6Body::Client { xid: 3 },
            options: vec![
                Dhcp6Option::ClientId(client_duid()),
                Dhcp6Option::IaPd(IaPd {
                    iaid: 1,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: None,
                }),
            ],
        };
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcomeV6::Reply { tx, .. } = out {
            let reply = Dhcp6Message::decode(&tx.payload).unwrap();
            let ia_pd = crate::packet::v6::options::find_ia_pd(&reply.options).unwrap();
            assert_eq!(
                ia_pd.status.as_ref().map(|(c, _)| *c),
                Some(StatusCode::NoPrefixAvail)
            );
        }
    }

    #[test]
    fn solicit_with_both_ia_na_and_ia_pd_replies_with_both() {
        let mut iface = mk_iface();
        iface.pd_pool = Some("residential".into());
        let mut global = mk_global();
        global.pd_pools.push(crate::config::ParsedPdPool {
            name: "residential".into(),
            prefix: "2001:db8:1000::".parse().unwrap(),
            prefix_len: 36,
            delegated_length: 56,
            preferred_lifetime: 3600,
            valid_lifetime: 86400,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::Solicit,
            body: Dhcp6Body::Client { xid: 4 },
            options: vec![
                Dhcp6Option::ClientId(client_duid()),
                Dhcp6Option::IaNa(IaNa {
                    iaid: 1,
                    t1: 0,
                    t2: 0,
                    addresses: vec![],
                    status: None,
                }),
                Dhcp6Option::IaPd(IaPd {
                    iaid: 2,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: None,
                }),
            ],
        };
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcomeV6::Reply { tx, .. } = out {
            let reply = Dhcp6Message::decode(&tx.payload).unwrap();
            assert!(find_ia_na(&reply.options).is_some());
            assert!(crate::packet::v6::options::find_ia_pd(&reply.options).is_some());
        }
    }

    #[test]
    fn release_of_pd_lease_emits_revoked_event() {
        let mut iface = mk_iface();
        iface.pd_pool = Some("residential".into());
        let mut global = mk_global();
        global.pd_pools.push(crate::config::ParsedPdPool {
            name: "residential".into(),
            prefix: "2001:db8:1000::".parse().unwrap(),
            prefix_len: 36,
            delegated_length: 56,
            preferred_lifetime: 3600,
            valid_lifetime: 86400,
        });
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        // Pre-seed the store with an existing PD binding for the
        // client — Release only meaningfully revokes known bindings.
        store
            .bind(crate::lease::LeaseV6 {
                duid: client_duid().as_bytes().to_vec(),
                iaid: 7,
                kind: crate::lease::IaKind::Pd,
                address: "2001:db8:1000::".parse().unwrap(),
                prefix_len: 56,
                preferred_lifetime: 3600,
                valid_lifetime: 86400,
                granted_unix: 0,
                expires_unix: u64::MAX,
                state: crate::lease::LeaseStateV6::Bound,
                via_relay: false,
            })
            .unwrap();

        let msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::Release,
            body: Dhcp6Body::Client { xid: 1 },
            options: vec![
                Dhcp6Option::ClientId(client_duid()),
                Dhcp6Option::ServerId(sd.clone()),
                Dhcp6Option::IaPd(IaPd {
                    iaid: 7,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: None,
                }),
            ],
        };
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match out {
            FsmOutcomeV6::Reply {
                commit: Some(_),
                pd_event: Some(PdEvent::Revoked(r)),
                ..
            } => {
                assert_eq!(r.prefix, "2001:db8:1000::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(r.prefix_len, 56);
                assert!(!r.via_relay);
            }
            other => panic!("expected Reply + Revoked event, got {:?}", other),
        }
    }

    #[test]
    fn release_of_unknown_pd_emits_no_event() {
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::Release,
            body: Dhcp6Body::Client { xid: 1 },
            options: vec![
                Dhcp6Option::ClientId(client_duid()),
                Dhcp6Option::ServerId(sd.clone()),
                Dhcp6Option::IaPd(IaPd {
                    iaid: 7,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: None,
                }),
            ],
        };
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        // Reply is sent (client always gets Success), but no
        // revocation event since we didn't have a binding.
        match out {
            FsmOutcomeV6::Reply {
                pd_event: None, ..
            } => {}
            other => panic!("expected Reply with no pd_event, got {:?}", other),
        }
    }

    #[test]
    fn request_ia_pd_binds_and_emits_event() {
        let mut iface = mk_iface();
        iface.pd_pool = Some("residential".into());
        let mut global = mk_global();
        global.pd_pools.push(crate::config::ParsedPdPool {
            name: "residential".into(),
            prefix: "2001:db8:1000::".parse().unwrap(),
            prefix_len: 36,
            delegated_length: 56,
            preferred_lifetime: 3600,
            valid_lifetime: 86400,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::Request,
            body: Dhcp6Body::Client { xid: 10 },
            options: vec![
                Dhcp6Option::ClientId(client_duid()),
                Dhcp6Option::ServerId(sd.clone()),
                Dhcp6Option::IaPd(IaPd {
                    iaid: 5,
                    t1: 0,
                    t2: 0,
                    prefixes: vec![],
                    status: None,
                }),
            ],
        };
        let out = handle(
            &msg,
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match out {
            FsmOutcomeV6::Reply {
                commit: Some(LeaseMutationV6::Bind(lease)),
                pd_event: Some(PdEvent::Granted(ev)),
                ..
            } => {
                assert_eq!(lease.kind, crate::lease::IaKind::Pd);
                assert!(!ev.via_relay);
                assert_eq!(ev.prefix_len, 56);
            }
            other => panic!("expected PD Bind, got {:?}", other),
        }
    }

    #[test]
    fn relayed_solicit_no_matching_subnet_drops() {
        // Relay link-address not in any configured subnet → drop
        // (symmetric with v4's giaddr handling).
        let iface = mk_iface();
        let global = mk_global(); // no subnets
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let inner_bytes = solicit(1, None).encode();
        let relay_msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::RelayForw,
            body: Dhcp6Body::Relay(RelayHeader {
                msg_type: 12,
                hop_count: 0,
                link_address: "2001:db8:99::1".parse().unwrap(),
                peer_address: "fe80::1".parse().unwrap(),
            }),
            options: vec![Dhcp6Option::RelayMessage(inner_bytes)],
        };
        let out = handle(
            &relay_msg,
            2,
            "2001:db8:99::ffff".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        assert!(matches!(out, FsmOutcomeV6::Silent { commit: None }));
    }

    #[test]
    fn relayed_solicit_uses_subnet_from_link_address() {
        // Ingress interface pool is 2001:db8::10..20 (uplink).
        // Relay forwards with link-address 2001:db8:cafe::1 which
        // matches a configured subnet 2001:db8:cafe::/64 whose pool
        // is cafe::100..cafe::200. We must offer from the customer
        // subnet, not the uplink pool.
        let iface = mk_iface();
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet6 {
            subnet: "2001:db8:cafe::/64".parse().unwrap(),
            pool_start: "2001:db8:cafe::100".parse().unwrap(),
            pool_end: "2001:db8:cafe::200".parse().unwrap(),
            preferred_lifetime: None,
            valid_lifetime: None,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();

        let inner_bytes = solicit(0xabcd, None).encode();
        let relay_msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::RelayForw,
            body: Dhcp6Body::Relay(RelayHeader {
                msg_type: 12,
                hop_count: 0,
                link_address: "2001:db8:cafe::1".parse().unwrap(),
                peer_address: "fe80::c1".parse().unwrap(),
            }),
            options: vec![Dhcp6Option::RelayMessage(inner_bytes)],
        };
        let out = handle(
            &relay_msg,
            2,
            "2001:db8::ffff".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcomeV6::Reply { tx, .. } = out {
            let relay_repl = Dhcp6Message::decode(&tx.payload).unwrap();
            assert_eq!(relay_repl.msg_type, Dhcp6MessageType::RelayRepl);
            let inner_bytes = crate::packet::v6::options::find_relay_message(&relay_repl.options)
                .expect("inner Relay-Msg");
            let inner = Dhcp6Message::decode(inner_bytes).unwrap();
            let ia = find_ia_na(&inner.options).expect("IA_NA in advertise");
            assert_eq!(ia.addresses.len(), 1);
            assert_eq!(
                ia.addresses[0].address,
                "2001:db8:cafe::100".parse::<Ipv6Addr>().unwrap()
            );
        } else {
            panic!("expected relayed Advertise");
        }
    }

    #[test]
    fn dhcp6_header_encoded_with_xid_preserved() {
        // Sanity: build_client_reply uses the request's xid.
        let iface = mk_iface();
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV6::open(dir.path()).unwrap();
        let sd = server_duid();
        let out = handle(
            &solicit(0xdeadbe, None),
            2,
            "fe80::1".parse().unwrap(),
            &iface,
            &global,
            &sd,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcomeV6::Reply { tx, .. } = out {
            let (hdr, _) = Dhcp6Header::decode(&tx.payload).unwrap();
            assert_eq!(hdr.xid, 0xdeadbe);
        }
    }
}
