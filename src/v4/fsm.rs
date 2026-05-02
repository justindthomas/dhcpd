//! DHCPv4 server state machine (RFC 2131 §4.3).
//!
//! The FSM is stateless per-transaction: we consume a parsed
//! [`DhcpMessage`], consult the allocator and lease store, and
//! return zero or one [`TxV4Packet`] (plus optional side-effect:
//! commit the lease). The caller owns the actual I/O.
//!
//! Classification of REQUEST sub-states (RFC 2131 §4.3.2):
//!
//! | ciaddr | server-id (54) | requested-ip (50) | state      |
//! |--------|----------------|-------------------|------------|
//! | 0      | set            | set               | SELECTING  |
//! | 0      | unset          | set               | INIT-REBOOT|
//! | set    | unset          | unset             | RENEWING or REBINDING |
//!
//! We distinguish RENEWING vs REBINDING by whether the packet
//! arrived unicast to our server address (RENEWING) or broadcast
//! (REBINDING). The packet-path doesn't currently carry that
//! signal, so we treat both the same for Phase 2 — a REBIND-only
//! path will come in a polish pass.

use std::net::Ipv4Addr;
use std::time::SystemTime;

use crate::config::{DhcpdConfig, InterfaceV4Config};
use crate::error::DhcpdError;
use crate::io::TxV4Packet;
use crate::lease::{Lease, LeaseStoreV4};
use crate::packet::v4::client_id::ClientId;
use crate::packet::v4::header::{BootOp, BootpHeader, BOOTP_FLAG_BROADCAST};
use crate::packet::v4::message::{DhcpMessage, DhcpMessageType};
use crate::packet::v4::options::{
    client_requests_v6_only_preferred, find_client_identifier, find_option_82,
    find_requested_ip, find_server_id, DhcpOption,
};
use crate::v4::allocator::{AllocateResult, Allocator};

/// What the caller should do as a result of this packet.
#[derive(Debug)]
pub enum FsmOutcome {
    /// Send this reply, optionally after committing a lease mutation.
    Reply {
        tx: TxV4Packet,
        commit: Option<LeaseMutation>,
    },
    /// No reply (packet ignored or committed state without wire
    /// acknowledgement — e.g. RELEASE).
    Silent {
        commit: Option<LeaseMutation>,
    },
}

/// A lease mutation the caller applies to the lease store before
/// emitting the wire reply (bind) or after (release/decline).
#[derive(Debug)]
pub enum LeaseMutation {
    Bind(Lease),
    Release(ClientId),
    Decline(ClientId),
}

/// Run the server FSM on a received message.
///
/// `rx_src_addr` is the IP source address of the ingress packet (as
/// seen at our socket). For relayed replies we send to this address
/// rather than `giaddr`: it's the return path the relay explicitly
/// chose (RFC 2131 §4.1 points to giaddr, but the packet-source
/// address is what the relay is listening on, and it's always the
/// correct reverse path). For direct clients `rx_src_addr` is just
/// the client's IP (if ciaddr is set) or 0.0.0.0 (first DISCOVER).
///
/// Returns the outcome: a reply packet to send (and optionally a
/// lease mutation to commit beforehand), or Silent when no reply
/// is warranted.
pub fn handle(
    msg: &DhcpMessage,
    sw_if_index: u32,
    rx_src_addr: Ipv4Addr,
    iface: &InterfaceV4Config,
    global: &DhcpdConfig,
    store: &LeaseStoreV4,
    now: SystemTime,
) -> Result<FsmOutcome, DhcpdError> {
    // Extract the client identifier (option 61 preferred, chaddr
    // fallback per RFC 2131 §4.2 / RFC 4361).
    let chaddr_mac = msg.header.ethernet_mac();
    let cid = ClientId::from_packet(find_client_identifier(&msg.options), chaddr_mac);

    // Pool selection: for relayed packets (giaddr != 0), look up
    // the matching subnet; for direct-broadcast use the ingress
    // interface's config. The effective context carries the
    // selected pool + reply options, preserving the server's
    // ingress address for Server-ID regardless of subnet.
    let effective = match select_effective_context(msg, iface, global) {
        Some(eff) => eff,
        None => {
            tracing::warn!(
                giaddr = %msg.header.giaddr,
                cid = %cid.pretty(),
                "no matching subnet for relayed DHCP packet; dropping"
            );
            return Ok(FsmOutcome::Silent { commit: None });
        }
    };
    let allocator = Allocator::new(&effective, global);
    let iface = &effective;

    match msg.msg_type {
        DhcpMessageType::Discover => {
            handle_discover(msg, sw_if_index, rx_src_addr, iface, global, &cid, chaddr_mac, &allocator, store, now)
        }
        DhcpMessageType::Request => {
            handle_request(msg, sw_if_index, rx_src_addr, iface, global, &cid, chaddr_mac, &allocator, store, now)
        }
        DhcpMessageType::Decline => Ok(handle_decline(&cid, msg)),
        DhcpMessageType::Release => Ok(handle_release(&cid)),
        DhcpMessageType::Inform => {
            // Phase 2 v1: ignore INFORM. Phase 5 polish: respond
            // with options but no yiaddr/lease (RFC 2131 §4.4.3).
            Ok(FsmOutcome::Silent { commit: None })
        }
        other => {
            tracing::debug!(
                msg_type = other.name(),
                "server ignoring client message type"
            );
            Ok(FsmOutcome::Silent { commit: None })
        }
    }
}

/// Build the effective interface context for an incoming packet.
///
/// - Direct-broadcast (`giaddr == 0`): use the ingress interface
///   config unchanged.
/// - Relayed (`giaddr != 0`): look up `global.subnets[]` for a
///   subnet containing `giaddr`, or Option 82 sub-option 5
///   link-selection when `iface.trust_relay=true`. If found,
///   synthesize an `InterfaceV4Config` carrying that subnet's
///   pool + reply options but the *server's* ingress address so
///   Server-ID and reply source stay consistent.
/// - Relayed with no match: return `None` — caller drops.
fn select_effective_context(
    msg: &DhcpMessage,
    iface: &InterfaceV4Config,
    global: &DhcpdConfig,
) -> Option<InterfaceV4Config> {
    if msg.header.giaddr.is_unspecified() {
        return Some(iface.clone());
    }
    // Relayed. Option 82 sub-option 5 overrides giaddr only when
    // the ingress interface is configured to trust relays (RFC
    // 3046 §2.1 — honor "authorized agents" only).
    let selector = if iface.trust_relay {
        find_option_82(&msg.options)
            .and_then(|o| o.link_selection)
            .unwrap_or(msg.header.giaddr)
    } else {
        msg.header.giaddr
    };
    let subnet = global.find_subnet(selector)?;
    // v6_only_preferred is read directly off the matched subnet by
    // the v6-only short-circuit (see `find_v6_only_seconds`); we
    // don't need to mirror it onto the synthesized iface.
    Some(InterfaceV4Config {
        name: format!("subnet:{}", subnet.subnet),
        // Server-ID / reply-source comes from the ingress iface —
        // that's where the relay routed the request, and where the
        // reply must return from.
        address: iface.address,
        prefix_len: subnet.subnet.prefix_len(),
        pool_start: subnet.pool_start,
        pool_end: subnet.pool_end,
        gateway: subnet.gateway,
        lease_time: subnet.lease_time,
        dns_servers: subnet.dns_servers.clone(),
        domain_name: subnet.domain_name.clone(),
        trust_relay: subnet.trust_relay,
    })
}

fn handle_discover(
    msg: &DhcpMessage,
    sw_if_index: u32,
    rx_src_addr: Ipv4Addr,
    iface: &InterfaceV4Config,
    global: &DhcpdConfig,
    cid: &ClientId,
    mac: Option<[u8; 6]>,
    allocator: &Allocator,
    store: &LeaseStoreV4,
    now: SystemTime,
) -> Result<FsmOutcome, DhcpdError> {
    // RFC 8925: if the subnet is v6-only-preferred AND the client
    // signaled support via PRL, OFFER with yiaddr=0 + option 108
    // and skip allocation entirely (§3.1: "MUST NOT allocate").
    if let Some(secs) = find_v6_only_seconds(msg, iface, global) {
        tracing::info!(
            cid = %cid.pretty(),
            wait_secs = secs,
            "DISCOVER: v6-only-preferred subnet; sending no-yiaddr OFFER with option 108"
        );
        let reply = build_v6_only_reply(msg, DhcpMessageType::Offer, iface, secs);
        let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
        return Ok(FsmOutcome::Reply { tx, commit: None });
    }
    let requested = find_requested_ip(&msg.options);
    let ip = match allocator.pick(cid, mac, requested, store) {
        AllocateResult::Available(ip) => ip,
        AllocateResult::Unavailable(ip) => {
            tracing::info!(
                cid = %cid.pretty(),
                requested = %ip,
                "DISCOVER: requested IP unavailable, falling through to pool scan"
            );
            // Pool scan already ran inside pick(); Unavailable
            // means the pool_scan also didn't match. Drop.
            return Ok(FsmOutcome::Silent { commit: None });
        }
        AllocateResult::Exhausted => {
            tracing::warn!(
                iface = iface.name.as_str(),
                cid = %cid.pretty(),
                "DISCOVER: pool exhausted; dropping"
            );
            return Ok(FsmOutcome::Silent { commit: None });
        }
    };

    let mac_owned = mac.unwrap_or([0u8; 6]);
    let hostname = msg.options.iter().find_map(|o| match o {
        DhcpOption::HostName(s) => Some(s.clone()),
        _ => None,
    });
    let lease = allocator.build_lease(cid, mac_owned, ip, hostname, now)?;

    let reply = build_reply(
        msg,
        DhcpMessageType::Offer,
        ip,
        iface,
        global,
        allocator.lease_secs(),
    );
    let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);

    Ok(FsmOutcome::Reply {
        tx,
        commit: Some(LeaseMutation::Bind(lease)),
    })
}

fn handle_request(
    msg: &DhcpMessage,
    sw_if_index: u32,
    rx_src_addr: Ipv4Addr,
    iface: &InterfaceV4Config,
    global: &DhcpdConfig,
    cid: &ClientId,
    mac: Option<[u8; 6]>,
    allocator: &Allocator,
    store: &LeaseStoreV4,
    now: SystemTime,
) -> Result<FsmOutcome, DhcpdError> {
    let server_id = find_server_id(&msg.options);
    let requested = find_requested_ip(&msg.options);

    // SELECTING: server-id + requested-ip set, ciaddr == 0.
    // The client is committing to an OFFER. We MUST check that the
    // server-id matches us before replying — otherwise the client
    // picked a different server and we should silently ignore.
    let is_selecting = server_id.is_some()
        && requested.is_some()
        && msg.header.ciaddr.is_unspecified();
    // INIT-REBOOT: no server-id, requested-ip set, ciaddr == 0.
    let is_init_reboot = server_id.is_none()
        && requested.is_some()
        && msg.header.ciaddr.is_unspecified();
    // RENEWING/REBINDING: ciaddr non-zero.
    let is_renewing = !msg.header.ciaddr.is_unspecified();

    if is_selecting {
        let server_id = server_id.unwrap();
        if server_id != iface.address {
            tracing::debug!(
                cid = %cid.pretty(),
                server_id = %server_id,
                self_addr = %iface.address,
                "REQUEST (SELECTING) not for us; ignoring"
            );
            return Ok(FsmOutcome::Silent { commit: None });
        }
        // RFC 8925 §3.2: well-behaved v6-only clients shouldn't
        // REQUEST after a no-yiaddr OFFER, but if one does we ACK
        // with the same yiaddr=0 + option 108 shape so the client
        // still picks up the V6ONLY_WAIT timer.
        if let Some(secs) = find_v6_only_seconds(msg, iface, global) {
            tracing::info!(
                cid = %cid.pretty(),
                wait_secs = secs,
                "REQUEST (SELECTING): v6-only-preferred subnet; ACK with option 108 only"
            );
            let reply = build_v6_only_reply(msg, DhcpMessageType::Ack, iface, secs);
            let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
            return Ok(FsmOutcome::Reply { tx, commit: None });
        }
        let ip = requested.unwrap();
        // Verify this is what the allocator would hand out now —
        // the client might be picking from a stale OFFER, so we
        // re-check. If mismatch, NAK.
        match allocator.pick(cid, mac, Some(ip), store) {
            AllocateResult::Available(got) if got == ip => {
                let mac_owned = mac.unwrap_or([0u8; 6]);
                let hostname = msg.options.iter().find_map(|o| match o {
                    DhcpOption::HostName(s) => Some(s.clone()),
                    _ => None,
                });
                let lease = allocator.build_lease(cid, mac_owned, ip, hostname, now)?;
                let reply = build_reply(
                    msg,
                    DhcpMessageType::Ack,
                    ip,
                    iface,
                    global,
                    allocator.lease_secs(),
                );
                let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
                Ok(FsmOutcome::Reply {
                    tx,
                    commit: Some(LeaseMutation::Bind(lease)),
                })
            }
            _ => {
                tracing::info!(
                    cid = %cid.pretty(),
                    requested = %ip,
                    "REQUEST (SELECTING) IP not allocatable; sending NAK"
                );
                let reply = build_nak(msg, iface, global);
                let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
                Ok(FsmOutcome::Reply { tx, commit: None })
            }
        }
    } else if is_init_reboot {
        // RFC 8925 §3: if the subnet is v6-only-preferred AND the
        // client signaled support via PRL, ACK with yiaddr=0 +
        // option 108 even on INIT-REBOOT — the spec doesn't carve
        // out the rebinding states, and a Mac (or any well-behaved
        // dual-stack client) that signals 108 should pick up the
        // V6ONLY_WAIT timer regardless of which DHCP-state phase
        // it's in. Without this short-circuit, a client whose
        // previous lease pre-dated the v6-only-preferred config
        // would just keep INIT-REBOOTing into its old IP forever.
        if let Some(secs) = find_v6_only_seconds(msg, iface, global) {
            tracing::info!(
                cid = %cid.pretty(),
                wait_secs = secs,
                "REQUEST (INIT-REBOOT): v6-only-preferred subnet; ACK with option 108 only"
            );
            let reply = build_v6_only_reply(msg, DhcpMessageType::Ack, iface, secs);
            let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
            return Ok(FsmOutcome::Reply { tx, commit: None });
        }
        // Client is reclaiming a known binding. If we have a lease
        // for this client matching the requested IP, ACK it;
        // otherwise NAK so the client falls back to DISCOVER.
        let ip = requested.unwrap();
        match store.get(cid) {
            Some(existing) if existing.ip == ip => {
                let mac_owned = mac.unwrap_or([0u8; 6]);
                let lease = allocator.build_lease(
                    cid,
                    mac_owned,
                    ip,
                    existing.hostname.clone(),
                    now,
                )?;
                let reply = build_reply(
                    msg,
                    DhcpMessageType::Ack,
                    ip,
                    iface,
                    global,
                    allocator.lease_secs(),
                );
                let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
                Ok(FsmOutcome::Reply {
                    tx,
                    commit: Some(LeaseMutation::Bind(lease)),
                })
            }
            Some(other) => {
                // Our stored binding differs from the client's
                // requested-ip. If the requested-ip is outside our
                // pool range, it's almost certainly a stale lease
                // from a previous/foreign DHCP server — we are not
                // authoritative for it, so silently drop (same
                // rationale as the unknown-client case: NAK'ing
                // thrashes Android clients that persist their
                // last IP). Only NAK when we are authoritative for
                // the requested-ip (inside our pool).
                if allocator.in_pool(ip) {
                    tracing::info!(
                        cid = %cid.pretty(),
                        requested = %ip,
                        held = %other.ip,
                        "REQUEST (INIT-REBOOT) mismatch within our pool; sending NAK"
                    );
                    let reply = build_nak(msg, iface, global);
                    let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
                    Ok(FsmOutcome::Reply { tx, commit: None })
                } else {
                    tracing::debug!(
                        cid = %cid.pretty(),
                        requested = %ip,
                        held = %other.ip,
                        "REQUEST (INIT-REBOOT) requested-ip outside our pool (stale foreign lease); silently dropping"
                    );
                    Ok(FsmOutcome::Silent { commit: None })
                }
            }
            None => {
                // RFC 2131 §4.3.2: server MUST remain silent when
                // an INIT-REBOOT client is unknown. NAK'ing here
                // can thrash clients that persist their last IP
                // (Android in particular) — they interpret the NAK
                // as "your lease is gone" but keep re-trying the
                // same requested-ip on the next INIT-REBOOT cycle.
                tracing::debug!(
                    cid = %cid.pretty(),
                    requested = %requested.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    "REQUEST (INIT-REBOOT) from unknown client; silently dropping"
                );
                Ok(FsmOutcome::Silent { commit: None })
            }
        }
    } else if is_renewing {
        // RFC 8925 §3.2: a server which is configured to enable
        // IPv6-only Preferred receiving a DHCPREQUEST in the
        // RENEWING or REBINDING states from a client that includes
        // option 108 in its PRL "MUST send a DHCPACK without
        // yiaddr or any other IPv4 configuration parameters
        // except for V6ONLY_WAIT". This is the explicit RFC mandate
        // — the INIT-REBOOT short-circuit above is a defensive
        // mirror of the same idea.
        if let Some(secs) = find_v6_only_seconds(msg, iface, global) {
            tracing::info!(
                cid = %cid.pretty(),
                wait_secs = secs,
                "REQUEST (RENEWING): v6-only-preferred subnet; ACK with option 108 only (RFC 8925 §3.2)"
            );
            let reply = build_v6_only_reply(msg, DhcpMessageType::Ack, iface, secs);
            let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
            return Ok(FsmOutcome::Reply { tx, commit: None });
        }
        let ip = msg.header.ciaddr;
        match store.get(cid) {
            Some(existing) if existing.ip == ip => {
                let mac_owned = mac.unwrap_or([0u8; 6]);
                let lease = allocator.build_lease(
                    cid,
                    mac_owned,
                    ip,
                    existing.hostname.clone(),
                    now,
                )?;
                let reply = build_reply(
                    msg,
                    DhcpMessageType::Ack,
                    ip,
                    iface,
                    global,
                    allocator.lease_secs(),
                );
                let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
                Ok(FsmOutcome::Reply {
                    tx,
                    commit: Some(LeaseMutation::Bind(lease)),
                })
            }
            _ => {
                let reply = build_nak(msg, iface, global);
                let tx = encode_tx(reply, &msg.header, rx_src_addr, iface, sw_if_index);
                Ok(FsmOutcome::Reply { tx, commit: None })
            }
        }
    } else {
        // Malformed REQUEST — drop.
        tracing::debug!(
            cid = %cid.pretty(),
            "REQUEST with unexpected flag combination; dropping"
        );
        Ok(FsmOutcome::Silent { commit: None })
    }
}

fn handle_decline(cid: &ClientId, _msg: &DhcpMessage) -> FsmOutcome {
    tracing::info!(cid = %cid.pretty(), "DECLINE received; quarantining lease");
    FsmOutcome::Silent {
        commit: Some(LeaseMutation::Decline(cid.clone())),
    }
}

fn handle_release(cid: &ClientId) -> FsmOutcome {
    tracing::info!(cid = %cid.pretty(), "RELEASE received; freeing lease");
    FsmOutcome::Silent {
        commit: Some(LeaseMutation::Release(cid.clone())),
    }
}

/// Assemble an OFFER/ACK reply message. Broadcast flag is echoed
/// from the request (RFC 2131 §4.1). Options carry the standard
/// reply set; Option 82 is echoed verbatim per RFC 3046 §2.0.
fn build_reply(
    req: &DhcpMessage,
    msg_type: DhcpMessageType,
    yiaddr: Ipv4Addr,
    iface: &InterfaceV4Config,
    global: &DhcpdConfig,
    lease_secs: u32,
) -> DhcpMessage {
    let mut hdr = req.header.clone();
    hdr.op = BootOp::Reply;
    hdr.yiaddr = yiaddr;
    hdr.siaddr = Ipv4Addr::UNSPECIFIED;
    // Preserve bflag from the request (do not force). VyOS and
    // other "known-good" servers echo the client-set bflag, and
    // SONiC's dhcrelay correctly delivers chaddr-unicast to
    // clients with no IP yet.

    // Option order mirrors ISC/VyOS so brittle relays and clients
    // see a familiar shape: MT, Subnet, Router, DNS, Hostname,
    // Lease, Server-ID, Client-ID, Agent-Info. No T1/T2 — clients
    // compute them from lease-time per RFC 2131 §4.4.5 when absent.
    let mut opts: Vec<DhcpOption> = Vec::with_capacity(16);
    opts.push(DhcpOption::MessageType(msg_type as u8));
    opts.push(DhcpOption::SubnetMask(prefix_to_mask(iface.prefix_len)));
    opts.push(DhcpOption::Router(vec![iface.gateway]));

    let dns: Vec<Ipv4Addr> = if !iface.dns_servers.is_empty() {
        iface.dns_servers.clone()
    } else {
        global.global_dns_servers.clone()
    };
    if !dns.is_empty() {
        opts.push(DhcpOption::DomainNameServer(dns));
    }

    // Echo Hostname from the request when the client sent one
    // (VyOS/ISC do this). Fall back to the global domain.
    if let Some(h) = req.options.iter().find_map(|o| match o {
        DhcpOption::HostName(s) => Some(s.clone()),
        _ => None,
    }) {
        opts.push(DhcpOption::HostName(h));
    }
    if let Some(d) = iface
        .domain_name
        .as_deref()
        .or(global.domain_name.as_deref())
    {
        opts.push(DhcpOption::DomainName(d.to_string()));
    }

    opts.push(DhcpOption::LeaseTime(lease_secs));
    // RFC 5107 §5.2: if the relay inserted Option 82 sub-option 11
    // (Server Identifier Override), use that address as the Server-ID
    // instead of the server's own IP. This makes the client see the
    // relay as the "server," so subsequent unicast messages (renewal,
    // release) flow back through the relay rather than directly to
    // the physical server. Absent the sub-option, use iface.address
    // as usual.
    let server_id = find_option_82(&req.options)
        .and_then(|a| a.server_id_override)
        .unwrap_or(iface.address);
    opts.push(DhcpOption::ServerId(server_id));

    // RFC 6842: echo the client identifier if the client sent one.
    if let Some(c) = find_client_identifier(&req.options) {
        opts.push(DhcpOption::ClientIdentifier(c.to_vec()));
    }
    // RFC 3046 §2.0: echo option 82 verbatim.
    if let Some(agent) = find_option_82(&req.options) {
        opts.push(DhcpOption::RelayAgentInfo(agent.clone()));
    }

    // Strip fields that could leak — sname/file should be empty in
    // replies unless the admin is serving PXE.
    hdr.sname = [0u8; 64];
    hdr.file = [0u8; 128];

    DhcpMessage {
        header: hdr,
        msg_type,
        options: opts,
    }
}

/// Build a DHCPNAK. yiaddr/siaddr/ciaddr are zeroed; broadcast flag
/// is forced on so the client (which can't listen on a unicast IP
/// post-NAK) still hears us.
fn build_nak(req: &DhcpMessage, iface: &InterfaceV4Config, _global: &DhcpdConfig) -> DhcpMessage {
    let mut hdr = req.header.clone();
    hdr.op = BootOp::Reply;
    hdr.ciaddr = Ipv4Addr::UNSPECIFIED;
    hdr.yiaddr = Ipv4Addr::UNSPECIFIED;
    hdr.siaddr = Ipv4Addr::UNSPECIFIED;
    hdr.flags |= BOOTP_FLAG_BROADCAST;
    hdr.sname = [0u8; 64];
    hdr.file = [0u8; 128];
    // Honor server-id-override on NAKs too so the client's Server-ID
    // match (if it checks) and the relay's return-path logic still
    // routes it correctly. Echo Option 82 so encode_tx can see it.
    let agent = find_option_82(&req.options).cloned();
    let server_id = agent
        .as_ref()
        .and_then(|a| a.server_id_override)
        .unwrap_or(iface.address);
    let mut opts = vec![
        DhcpOption::MessageType(DhcpMessageType::Nak as u8),
        DhcpOption::ServerId(server_id),
    ];
    if let Some(a) = agent {
        opts.push(DhcpOption::RelayAgentInfo(a));
    }
    DhcpMessage {
        header: hdr,
        msg_type: DhcpMessageType::Nak,
        options: opts,
    }
}

/// Wrap a DhcpMessage in a TxV4Packet. Destination addressing
/// follows RFC 2131 §4.1:
///
/// - If `giaddr != 0` → reply goes to giaddr:67 (the relay agent).
/// - Else if broadcast flag → 255.255.255.255:68 via broadcast MAC.
/// - Else if ciaddr != 0 → unicast to ciaddr.
/// - Else unicast to yiaddr with chaddr as MAC.
fn encode_tx(
    reply: DhcpMessage,
    req_hdr: &BootpHeader,
    rx_src_addr: Ipv4Addr,
    iface: &InterfaceV4Config,
    sw_if_index: u32,
) -> TxV4Packet {
    let payload = reply.encode();
    // Destination for relayed replies (giaddr non-zero), in priority order:
    //   1. RFC 5107 Option 82 sub-option 11 (server-id-override) —
    //      the relay explicitly told us where to send replies and
    //      what to put in Server-ID. This is the standards-track
    //      way to redirect the return path.
    //   2. The ingress packet's IP source — for relays that don't
    //      speak RFC 5107 but use a non-giaddr source IP (SONiC's
    //      dhcrelay sourcing from Loopback0 when forwarding to a
    //      "remote" server is one example). The source is always
    //      a correct return path by definition.
    //   3. giaddr (RFC 2131 §4.1 default) — traditional same-subnet
    //      relay where source, giaddr, and Server-ID are all the
    //      same SVI.
    // For non-relayed traffic:
    //   - Broadcast flag set → 255.255.255.255:68 via PUNT_L2 bcast.
    //   - Renew (ciaddr set) → unicast to ciaddr:68.
    //   - Fresh binding, bflag clear → yiaddr:68 via PUNT_L2 chaddr.
    let server_id_override = find_option_82(&reply.options)
        .and_then(|a| a.server_id_override);
    let (dst_addr, dst_port, dst_mac, broadcast) = if !req_hdr.giaddr.is_unspecified() {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&req_hdr.chaddr[..6]);
        let dst = server_id_override
            .or_else(|| {
                if rx_src_addr.is_unspecified() {
                    None
                } else {
                    Some(rx_src_addr)
                }
            })
            .unwrap_or(req_hdr.giaddr);
        (dst, 67u16, mac, false)
    } else if req_hdr.broadcast_flag() {
        (Ipv4Addr::BROADCAST, 68u16, [0xff; 6], true)
    } else if !req_hdr.ciaddr.is_unspecified() {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&req_hdr.chaddr[..6]);
        (req_hdr.ciaddr, 68u16, mac, false)
    } else {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&req_hdr.chaddr[..6]);
        (reply.header.yiaddr, 68u16, mac, true)
    };

    TxV4Packet {
        sw_if_index,
        src_addr: iface.address,
        dst_addr,
        dst_port,
        dst_mac,
        broadcast,
        payload,
    }
}

/// RFC 8925: returns the configured V6ONLY_WAIT seconds when the
/// client opted in via PRL (option 55 contains 108) AND a matching
/// subnet has `v6_only_preferred` set. Selector follows the same
/// rules as `select_effective_context`: relayed packets pick the
/// subnet by `giaddr` (or option 82 link-selection when trusted);
/// direct packets pick by the ingress interface's address.
fn find_v6_only_seconds(
    msg: &DhcpMessage,
    iface: &InterfaceV4Config,
    global: &DhcpdConfig,
) -> Option<u32> {
    if !client_requests_v6_only_preferred(&msg.options) {
        return None;
    }
    let selector = if msg.header.giaddr.is_unspecified() {
        iface.address
    } else if iface.trust_relay {
        find_option_82(&msg.options)
            .and_then(|o| o.link_selection)
            .unwrap_or(msg.header.giaddr)
    } else {
        msg.header.giaddr
    };
    global.find_subnet(selector).and_then(|s| s.v6_only_preferred)
}

/// Build a DHCPOFFER/DHCPACK carrying option 108 only — yiaddr is
/// zero, no lease time, no subnet/router/DNS. RFC 8925 §3.1: the
/// server MUST NOT allocate an IPv4 address when sending option 108
/// for a v6-only network. Server-ID, client-id echo, and option 82
/// echo follow the normal reply rules.
fn build_v6_only_reply(
    req: &DhcpMessage,
    msg_type: DhcpMessageType,
    iface: &InterfaceV4Config,
    wait_secs: u32,
) -> DhcpMessage {
    let mut hdr = req.header.clone();
    hdr.op = BootOp::Reply;
    hdr.ciaddr = Ipv4Addr::UNSPECIFIED;
    hdr.yiaddr = Ipv4Addr::UNSPECIFIED;
    hdr.siaddr = Ipv4Addr::UNSPECIFIED;
    hdr.sname = [0u8; 64];
    hdr.file = [0u8; 128];

    let agent = find_option_82(&req.options).cloned();
    let server_id = agent
        .as_ref()
        .and_then(|a| a.server_id_override)
        .unwrap_or(iface.address);
    let mut opts: Vec<DhcpOption> = Vec::with_capacity(5);
    opts.push(DhcpOption::MessageType(msg_type as u8));
    opts.push(DhcpOption::ServerId(server_id));
    opts.push(DhcpOption::V6OnlyPreferred(wait_secs));
    if let Some(c) = find_client_identifier(&req.options) {
        opts.push(DhcpOption::ClientIdentifier(c.to_vec()));
    }
    if let Some(a) = agent {
        opts.push(DhcpOption::RelayAgentInfo(a));
    }

    DhcpMessage {
        header: hdr,
        msg_type,
        options: opts,
    }
}

/// Convert a prefix length (0..=32) into an IPv4 mask.
fn prefix_to_mask(len: u8) -> Ipv4Addr {
    if len == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let shift = 32 - len.min(32);
    let bits = !0u32 << shift;
    Ipv4Addr::from(bits.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Reservation4;
    use crate::packet::v4::header::{BootOp, BOOTP_FLAG_BROADCAST};
    use crate::packet::v4::options::Option82;
    use crate::packet::v4::options::{find_message_type, find_server_id};
    use std::net::Ipv4Addr;
    use tempfile::tempdir;

    fn mk_iface(addr: [u8; 4], start: [u8; 4], end: [u8; 4]) -> InterfaceV4Config {
        InterfaceV4Config {
            name: "lan".into(),
            address: Ipv4Addr::from(addr),
            prefix_len: 24,
            pool_start: Ipv4Addr::from(start),
            pool_end: Ipv4Addr::from(end),
            gateway: Ipv4Addr::from(addr),
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

    fn mk_header(op: BootOp, xid: u32, mac: [u8; 6], flags: u16) -> BootpHeader {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&mac);
        BootpHeader {
            op,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
        }
    }

    fn mk_discover(mac: [u8; 6], xid: u32) -> DhcpMessage {
        DhcpMessage {
            header: mk_header(BootOp::Request, xid, mac, BOOTP_FLAG_BROADCAST),
            msg_type: DhcpMessageType::Discover,
            options: vec![DhcpOption::MessageType(1)],
        }
    }

    fn mk_request_selecting(
        mac: [u8; 6],
        xid: u32,
        server_id: Ipv4Addr,
        requested: Ipv4Addr,
    ) -> DhcpMessage {
        DhcpMessage {
            header: mk_header(BootOp::Request, xid, mac, BOOTP_FLAG_BROADCAST),
            msg_type: DhcpMessageType::Request,
            options: vec![
                DhcpOption::MessageType(3),
                DhcpOption::ServerId(server_id),
                DhcpOption::RequestedIp(requested),
            ],
        }
    }

    #[test]
    fn discover_yields_offer_with_standard_options() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let msg = mk_discover([1; 6], 0xdead);

        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        match outcome {
            FsmOutcome::Reply {
                tx,
                commit: Some(LeaseMutation::Bind(lease)),
            } => {
                assert_eq!(lease.ip, Ipv4Addr::new(10, 0, 0, 100));
                let reply = DhcpMessage::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, DhcpMessageType::Offer);
                assert_eq!(reply.header.yiaddr, Ipv4Addr::new(10, 0, 0, 100));
                assert_eq!(
                    find_server_id(&reply.options),
                    Some(Ipv4Addr::new(10, 0, 0, 1))
                );
                assert!(tx.broadcast);
                assert_eq!(tx.dst_addr, Ipv4Addr::BROADCAST);
            }
            other => panic!("expected Offer+Bind, got {:?}", other),
        }
    }

    #[test]
    fn discover_exhausted_returns_silent() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 100]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        // Block the only pool slot.
        store
            .bind(Lease {
                client_id: vec![9; 6],
                ip: Ipv4Addr::new(10, 0, 0, 100),
                mac: [9; 6],
                hostname: None,
                granted_unix: 0,
                expires_unix: 1_999_999_999,
                state: crate::lease::LeaseState::Bound,
            })
            .unwrap();

        let outcome = handle(
            &mk_discover([1; 6], 1),
            2,
            Ipv4Addr::UNSPECIFIED,
            &iface,
            &global,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        assert!(matches!(outcome, FsmOutcome::Silent { commit: None }));
    }

    #[test]
    fn request_selecting_for_wrong_server_id_silent() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let req = mk_request_selecting(
            [1; 6],
            1,
            Ipv4Addr::new(10, 0, 0, 99), // different server
            Ipv4Addr::new(10, 0, 0, 100),
        );
        let outcome = handle(&req, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        assert!(matches!(outcome, FsmOutcome::Silent { commit: None }));
    }

    #[test]
    fn request_selecting_matches_us_acks() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let req = mk_request_selecting(
            [1; 6],
            1,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 100),
        );
        let outcome = handle(&req, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        match outcome {
            FsmOutcome::Reply {
                tx,
                commit: Some(LeaseMutation::Bind(_)),
            } => {
                let reply = DhcpMessage::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, DhcpMessageType::Ack);
                assert_eq!(reply.header.yiaddr, Ipv4Addr::new(10, 0, 0, 100));
            }
            other => panic!("expected Ack+Bind, got {:?}", other),
        }
    }

    #[test]
    fn request_selecting_ip_unavailable_sends_nak() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        // Fill the requested IP with another client.
        store
            .bind(Lease {
                client_id: vec![9; 6],
                ip: Ipv4Addr::new(10, 0, 0, 100),
                mac: [9; 6],
                hostname: None,
                granted_unix: 0,
                expires_unix: 1_999_999_999,
                state: crate::lease::LeaseState::Bound,
            })
            .unwrap();
        let req = mk_request_selecting(
            [1; 6],
            1,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 100),
        );
        let outcome = handle(&req, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        match outcome {
            FsmOutcome::Reply { tx, commit: None } => {
                let reply = DhcpMessage::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, DhcpMessageType::Nak);
            }
            other => panic!("expected Nak, got {:?}", other),
        }
    }

    #[test]
    fn renewing_known_client_acks() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let mut store = LeaseStoreV4::open(dir.path()).unwrap();
        store
            .bind(Lease {
                client_id: vec![1; 6],
                ip: Ipv4Addr::new(10, 0, 0, 105),
                mac: [1; 6],
                hostname: None,
                granted_unix: 0,
                expires_unix: 1_999_999_999,
                state: crate::lease::LeaseState::Bound,
            })
            .unwrap();

        // RENEW: ciaddr set, no server-id, no requested-ip.
        let mut msg = DhcpMessage {
            header: mk_header(BootOp::Request, 42, [1; 6], 0),
            msg_type: DhcpMessageType::Request,
            options: vec![DhcpOption::MessageType(3)],
        };
        msg.header.ciaddr = Ipv4Addr::new(10, 0, 0, 105);
        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        match outcome {
            FsmOutcome::Reply {
                tx,
                commit: Some(LeaseMutation::Bind(_)),
            } => {
                let reply = DhcpMessage::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, DhcpMessageType::Ack);
                // Renew: broadcast flag was 0 and ciaddr was set, so
                // encode_tx should unicast to ciaddr.
                assert!(!tx.broadcast);
                assert_eq!(tx.dst_addr, Ipv4Addr::new(10, 0, 0, 105));
            }
            other => panic!("expected Ack, got {:?}", other),
        }
    }

    #[test]
    fn release_marks_lease_released() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let msg = DhcpMessage {
            header: mk_header(BootOp::Request, 1, [1; 6], 0),
            msg_type: DhcpMessageType::Release,
            options: vec![DhcpOption::MessageType(7)],
        };
        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        match outcome {
            FsmOutcome::Silent {
                commit: Some(LeaseMutation::Release(cid)),
            } => assert_eq!(cid.as_bytes(), &[1u8; 6]),
            other => panic!("expected Silent+Release, got {:?}", other),
        }
    }

    #[test]
    fn decline_marks_lease_declined() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let msg = DhcpMessage {
            header: mk_header(BootOp::Request, 1, [1; 6], 0),
            msg_type: DhcpMessageType::Decline,
            options: vec![DhcpOption::MessageType(4)],
        };
        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        match outcome {
            FsmOutcome::Silent {
                commit: Some(LeaseMutation::Decline(cid)),
            } => assert_eq!(cid.as_bytes(), &[1u8; 6]),
            other => panic!("expected Silent+Decline, got {:?}", other),
        }
    }

    #[test]
    fn reply_echoes_option_82() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let msg = DhcpMessage {
            header: mk_header(BootOp::Request, 1, [1; 6], BOOTP_FLAG_BROADCAST),
            msg_type: DhcpMessageType::Discover,
            options: vec![
                DhcpOption::MessageType(1),
                DhcpOption::RelayAgentInfo(Option82 {
                    circuit_id: Some(b"port-5".to_vec()),
                    remote_id: Some(b"cpe-007".to_vec()),
                    ..Default::default()
                }),
            ],
        };
        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        if let FsmOutcome::Reply { tx, .. } = outcome {
            let reply = DhcpMessage::decode(&tx.payload).unwrap();
            let agent = reply
                .options
                .iter()
                .find_map(|o| match o {
                    DhcpOption::RelayAgentInfo(a) => Some(a),
                    _ => None,
                })
                .expect("option 82 echoed");
            assert_eq!(agent.circuit_id.as_deref(), Some(b"port-5".as_ref()));
            assert_eq!(agent.remote_id.as_deref(), Some(b"cpe-007".as_ref()));
        } else {
            panic!("expected reply");
        }
    }

    #[test]
    fn reply_echoes_client_identifier() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let global = mk_global();
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let cid_bytes = vec![0xff, 0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04];
        let msg = DhcpMessage {
            header: mk_header(BootOp::Request, 1, [1; 6], BOOTP_FLAG_BROADCAST),
            msg_type: DhcpMessageType::Discover,
            options: vec![
                DhcpOption::MessageType(1),
                DhcpOption::ClientIdentifier(cid_bytes.clone()),
            ],
        };
        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        if let FsmOutcome::Reply { tx, .. } = outcome {
            let reply = DhcpMessage::decode(&tx.payload).unwrap();
            let echoed = reply
                .options
                .iter()
                .find_map(|o| match o {
                    DhcpOption::ClientIdentifier(b) => Some(b.clone()),
                    _ => None,
                })
                .expect("client-id echoed");
            assert_eq!(echoed, cid_bytes);
        } else {
            panic!("expected reply");
        }
    }

    #[test]
    fn prefix_to_mask_boundaries() {
        assert_eq!(prefix_to_mask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix_to_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn relayed_discover_selects_subnet_by_giaddr() {
        // Ingress interface is on 172.16.0.2/24 (the uplink side).
        // A relay at 10.0.1.1 forwards a DISCOVER from the customer
        // subnet 10.0.1.0/24. dhcpd must offer an IP from that
        // subnet's pool, not from the ingress interface's pool.
        let iface = mk_iface([172, 16, 0, 2], [172, 16, 0, 100], [172, 16, 0, 110]);
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "10.0.1.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(10, 0, 1, 100),
            pool_end: Ipv4Addr::new(10, 0, 1, 200),
            gateway: Ipv4Addr::new(10, 0, 1, 1),
            lease_time: Some(7200),
            dns_servers: vec![Ipv4Addr::new(10, 0, 1, 1)],
            domain_name: Some("customer1".into()),
            trust_relay: false,
            v6_only_preferred: None,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        // DISCOVER arriving with giaddr set (relayed).
        let mut msg = mk_discover([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], 0xabcd);
        msg.header.giaddr = Ipv4Addr::new(10, 0, 1, 1);

        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        match outcome {
            FsmOutcome::Reply {
                tx,
                commit: Some(LeaseMutation::Bind(lease)),
            } => {
                assert_eq!(lease.ip, Ipv4Addr::new(10, 0, 1, 100));
                let reply = DhcpMessage::decode(&tx.payload).unwrap();
                assert_eq!(reply.header.yiaddr, Ipv4Addr::new(10, 0, 1, 100));
                // Reply routes back to the relay (giaddr), not the client.
                assert_eq!(tx.dst_addr, Ipv4Addr::new(10, 0, 1, 1));
                assert!(!tx.broadcast);
                // Server-ID is the server's ingress IP, not the relay's.
                use crate::packet::v4::options::find_server_id;
                assert_eq!(
                    find_server_id(&reply.options),
                    Some(Ipv4Addr::new(172, 16, 0, 2))
                );
                // Gateway (Option 3) should come from the subnet config.
                let router = reply
                    .options
                    .iter()
                    .find_map(|o| match o {
                        DhcpOption::Router(r) => Some(r.clone()),
                        _ => None,
                    })
                    .expect("Option 3 Router present");
                assert_eq!(router, vec![Ipv4Addr::new(10, 0, 1, 1)]);
            }
            other => panic!("expected relay-path Offer+Bind, got {:?}", other),
        }
    }

    #[test]
    fn relayed_discover_no_matching_subnet_drops() {
        let iface = mk_iface([172, 16, 0, 2], [172, 16, 0, 100], [172, 16, 0, 110]);
        let global = mk_global(); // no subnets configured
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let mut msg = mk_discover([1; 6], 1);
        msg.header.giaddr = Ipv4Addr::new(10, 0, 99, 1);
        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        assert!(matches!(outcome, FsmOutcome::Silent { commit: None }));
    }

    #[test]
    fn relayed_discover_honors_link_selection_when_trusted() {
        // Relay lives on 10.0.1.1, but inserts Option 82 sub-5
        // link-selection pointing at a different customer subnet
        // 10.0.99.0/24. With trust_relay=true, we pick that subnet.
        let mut iface = mk_iface([172, 16, 0, 2], [172, 16, 0, 100], [172, 16, 0, 110]);
        iface.trust_relay = true;
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "10.0.1.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(10, 0, 1, 100),
            pool_end: Ipv4Addr::new(10, 0, 1, 200),
            gateway: Ipv4Addr::new(10, 0, 1, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: None,
        });
        global.subnets.push(crate::config::Subnet4 {
            subnet: "10.0.99.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(10, 0, 99, 100),
            pool_end: Ipv4Addr::new(10, 0, 99, 200),
            gateway: Ipv4Addr::new(10, 0, 99, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: None,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        let mut msg = mk_discover([0x11; 6], 1);
        msg.header.giaddr = Ipv4Addr::new(10, 0, 1, 1);
        msg.options.push(DhcpOption::RelayAgentInfo(Option82 {
            link_selection: Some(Ipv4Addr::new(10, 0, 99, 1)),
            ..Default::default()
        }));

        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        if let FsmOutcome::Reply {
            commit: Some(LeaseMutation::Bind(lease)),
            ..
        } = outcome
        {
            assert_eq!(lease.ip, Ipv4Addr::new(10, 0, 99, 100));
        } else {
            panic!("expected Offer from link-selection subnet");
        }
    }

    #[test]
    fn relayed_discover_ignores_link_selection_when_untrusted() {
        // Same setup as above but trust_relay=false — we MUST ignore
        // Option 82 sub-5 and use giaddr's subnet.
        let iface = mk_iface([172, 16, 0, 2], [172, 16, 0, 100], [172, 16, 0, 110]);
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "10.0.1.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(10, 0, 1, 100),
            pool_end: Ipv4Addr::new(10, 0, 1, 200),
            gateway: Ipv4Addr::new(10, 0, 1, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: None,
        });
        global.subnets.push(crate::config::Subnet4 {
            subnet: "10.0.99.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(10, 0, 99, 100),
            pool_end: Ipv4Addr::new(10, 0, 99, 200),
            gateway: Ipv4Addr::new(10, 0, 99, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: None,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        let mut msg = mk_discover([0x22; 6], 2);
        msg.header.giaddr = Ipv4Addr::new(10, 0, 1, 1);
        msg.options.push(DhcpOption::RelayAgentInfo(Option82 {
            link_selection: Some(Ipv4Addr::new(10, 0, 99, 1)),
            ..Default::default()
        }));
        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        if let FsmOutcome::Reply {
            commit: Some(LeaseMutation::Bind(lease)),
            ..
        } = outcome
        {
            // giaddr wins — 10.0.1.x, not 10.0.99.x.
            assert_eq!(lease.ip, Ipv4Addr::new(10, 0, 1, 100));
        } else {
            panic!("expected Offer");
        }
    }

    #[test]
    fn reservation_ip_used_in_offer() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let mut global = mk_global();
        global.reservations.push(Reservation4 {
            hw_address: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            ip_address: Ipv4Addr::new(10, 0, 0, 50),
            hostname: Some("printer".into()),
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();
        let outcome = handle(
            &mk_discover([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 1),
            2,
            Ipv4Addr::UNSPECIFIED,
            &iface,
            &global,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        if let FsmOutcome::Reply {
            tx,
            commit: Some(LeaseMutation::Bind(lease)),
        } = outcome
        {
            assert_eq!(lease.ip, Ipv4Addr::new(10, 0, 0, 50));
            let reply = DhcpMessage::decode(&tx.payload).unwrap();
            assert_eq!(reply.header.yiaddr, Ipv4Addr::new(10, 0, 0, 50));
            assert_eq!(find_message_type(&reply.options), Some(2)); // OFFER
        } else {
            panic!("expected reservation offer");
        }
    }

    #[test]
    fn relayed_reply_dst_uses_packet_source_not_giaddr() {
        // When a relay uses a loopback (or any non-giaddr IP) as its
        // UDP/IP source, the packet's source address is the correct
        // return path — giaddr is only the relay's identity on the
        // client VLAN. This is the "asymmetric relay" case: e.g.
        // SONiC switches sourcing from Loopback0 (10.1.0.1) with
        // giaddr set to the Vlan SVI (192.168.20.5). Reply to the
        // packet source so the return path traverses the -iu
        // interface the relay is listening on.
        let iface = mk_iface([172, 16, 0, 2], [172, 16, 0, 100], [172, 16, 0, 110]);
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "192.168.20.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(192, 168, 20, 100),
            pool_end: Ipv4Addr::new(192, 168, 20, 200),
            gateway: Ipv4Addr::new(192, 168, 20, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: None,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        let mut msg = mk_discover([1; 6], 0xabc);
        msg.header.giaddr = Ipv4Addr::new(192, 168, 20, 5);

        let rx_src = Ipv4Addr::new(10, 1, 0, 1);
        let outcome = handle(&msg, 2, rx_src, &iface, &global, &store, SystemTime::now()).unwrap();
        if let FsmOutcome::Reply { tx, .. } = outcome {
            assert_eq!(tx.dst_addr, rx_src, "reply should target the rx IP source");
            assert_eq!(tx.dst_port, 67, "relay reply always lands on port 67");
        } else {
            panic!("expected Reply");
        }
    }

    #[test]
    fn rfc5107_server_id_override_sets_server_id_and_dst() {
        // When a relay inserts Option 82 sub-option 11 (server-id-
        // override), the server MUST use it as both the Server-ID
        // option value AND the reply destination. This supersedes
        // both giaddr and the rx_src_addr heuristic.
        let iface = mk_iface([172, 16, 0, 2], [172, 16, 0, 100], [172, 16, 0, 110]);
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "192.168.20.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(192, 168, 20, 100),
            pool_end: Ipv4Addr::new(192, 168, 20, 200),
            gateway: Ipv4Addr::new(192, 168, 20, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: None,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        let override_ip = Ipv4Addr::new(172, 20, 0, 99);
        let mut msg = mk_discover([3; 6], 0xabe);
        msg.header.giaddr = Ipv4Addr::new(192, 168, 20, 5);
        msg.options.push(DhcpOption::RelayAgentInfo(Option82 {
            server_id_override: Some(override_ip),
            ..Default::default()
        }));

        // Even with a non-zero rx_src_addr, the override wins.
        let rx_src = Ipv4Addr::new(10, 1, 0, 1);
        let outcome = handle(&msg, 2, rx_src, &iface, &global, &store, SystemTime::now()).unwrap();
        if let FsmOutcome::Reply { tx, .. } = outcome {
            assert_eq!(tx.dst_addr, override_ip, "reply dst must be server-id-override");
            let reply = DhcpMessage::decode(&tx.payload).unwrap();
            assert_eq!(
                find_server_id(&reply.options),
                Some(override_ip),
                "Server-ID in reply must be server-id-override"
            );
        } else {
            panic!("expected Reply");
        }
    }

    #[test]
    fn v6_only_subnet_with_prl_108_offers_no_yiaddr_with_option_108() {
        // Direct-broadcast: ingress iface 10.0.0.1/24 sits inside a
        // subnet flagged v6_only_preferred = 1800. Client sends
        // DISCOVER with PRL containing 108 → expect OFFER with
        // yiaddr=0.0.0.0 and option 108 = 1800, and no lease commit.
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "10.0.0.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(10, 0, 0, 100),
            pool_end: Ipv4Addr::new(10, 0, 0, 110),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: Some(1800),
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        let mut msg = mk_discover([0xaa; 6], 0xfeed);
        msg.options
            .push(DhcpOption::ParamRequestList(vec![1, 3, 6, 108]));

        let outcome = handle(
            &msg,
            2,
            Ipv4Addr::UNSPECIFIED,
            &iface,
            &global,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match outcome {
            FsmOutcome::Reply { tx, commit: None } => {
                let reply = DhcpMessage::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, DhcpMessageType::Offer);
                assert_eq!(reply.header.yiaddr, Ipv4Addr::UNSPECIFIED);
                let secs = reply
                    .options
                    .iter()
                    .find_map(|o| match o {
                        DhcpOption::V6OnlyPreferred(s) => Some(*s),
                        _ => None,
                    })
                    .expect("option 108 in reply");
                assert_eq!(secs, 1800);
                // Lease store untouched.
                assert_eq!(store.len(), 0);
                // Server-ID still our address so the client can match
                // any later messages it may send.
                assert_eq!(
                    find_server_id(&reply.options),
                    Some(Ipv4Addr::new(10, 0, 0, 1))
                );
            }
            other => panic!("expected v6-only OFFER, got {:?}", other),
        }
    }

    #[test]
    fn v6_only_subnet_without_prl_108_falls_through_to_normal_offer() {
        // Same v6-only subnet as above, but the client doesn't list
        // 108 in its PRL — fall back to a normal v4 lease.
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "10.0.0.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(10, 0, 0, 100),
            pool_end: Ipv4Addr::new(10, 0, 0, 110),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: Some(1800),
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        let mut msg = mk_discover([0xbb; 6], 0xbeef);
        // PRL without 108 — legacy v4 client.
        msg.options
            .push(DhcpOption::ParamRequestList(vec![1, 3, 6, 51]));

        let outcome = handle(
            &msg,
            2,
            Ipv4Addr::UNSPECIFIED,
            &iface,
            &global,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match outcome {
            FsmOutcome::Reply {
                tx,
                commit: Some(LeaseMutation::Bind(_)),
            } => {
                let reply = DhcpMessage::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, DhcpMessageType::Offer);
                assert_eq!(reply.header.yiaddr, Ipv4Addr::new(10, 0, 0, 100));
                assert!(!reply
                    .options
                    .iter()
                    .any(|o| matches!(o, DhcpOption::V6OnlyPreferred(_))));
            }
            other => panic!("expected normal Offer+Bind, got {:?}", other),
        }
    }

    #[test]
    fn v6_only_relayed_discover_uses_giaddr_subnet() {
        // Relayed: ingress iface is 172.16.0.2 (uplink); the relayed
        // DISCOVER carries giaddr=192.168.20.5 inside a v6-only
        // subnet. Reply should be no-yiaddr ACK with option 108 and
        // route back to the relay (giaddr) on port 67.
        let iface = mk_iface([172, 16, 0, 2], [172, 16, 0, 100], [172, 16, 0, 110]);
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "192.168.20.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(192, 168, 20, 100),
            pool_end: Ipv4Addr::new(192, 168, 20, 200),
            gateway: Ipv4Addr::new(192, 168, 20, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: Some(600),
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        let mut msg = mk_discover([0xcc; 6], 0x1234);
        msg.header.giaddr = Ipv4Addr::new(192, 168, 20, 5);
        msg.options
            .push(DhcpOption::ParamRequestList(vec![1, 3, 6, 108]));

        let outcome = handle(
            &msg,
            2,
            Ipv4Addr::UNSPECIFIED,
            &iface,
            &global,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match outcome {
            FsmOutcome::Reply { tx, commit: None } => {
                assert_eq!(tx.dst_addr, Ipv4Addr::new(192, 168, 20, 5));
                assert_eq!(tx.dst_port, 67);
                let reply = DhcpMessage::decode(&tx.payload).unwrap();
                assert_eq!(reply.header.yiaddr, Ipv4Addr::UNSPECIFIED);
                let secs = reply
                    .options
                    .iter()
                    .find_map(|o| match o {
                        DhcpOption::V6OnlyPreferred(s) => Some(*s),
                        _ => None,
                    })
                    .expect("option 108 in reply");
                assert_eq!(secs, 600);
            }
            other => panic!("expected relayed v6-only OFFER, got {:?}", other),
        }
    }

    #[test]
    fn v6_only_selecting_request_acks_with_option_108() {
        let iface = mk_iface([10, 0, 0, 1], [10, 0, 0, 100], [10, 0, 0, 110]);
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "10.0.0.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(10, 0, 0, 100),
            pool_end: Ipv4Addr::new(10, 0, 0, 110),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: Some(900),
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        let mut req = mk_request_selecting(
            [0xdd; 6],
            1,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 100),
        );
        req.options
            .push(DhcpOption::ParamRequestList(vec![1, 3, 6, 108]));

        let outcome = handle(
            &req,
            2,
            Ipv4Addr::UNSPECIFIED,
            &iface,
            &global,
            &store,
            SystemTime::now(),
        )
        .unwrap();
        match outcome {
            FsmOutcome::Reply { tx, commit: None } => {
                let reply = DhcpMessage::decode(&tx.payload).unwrap();
                assert_eq!(reply.msg_type, DhcpMessageType::Ack);
                assert_eq!(reply.header.yiaddr, Ipv4Addr::UNSPECIFIED);
                assert!(reply
                    .options
                    .iter()
                    .any(|o| matches!(o, DhcpOption::V6OnlyPreferred(900))));
            }
            other => panic!("expected v6-only ACK, got {:?}", other),
        }
    }

    #[test]
    fn relayed_reply_falls_back_to_giaddr_when_rx_src_unspecified() {
        // Backwards-compat: if the caller doesn't thread through a
        // real packet source (rx_src=0.0.0.0), use giaddr per RFC
        // 2131 §4.1. Keeps existing tests honest and preserves
        // behavior when handle() is called synthetically.
        let iface = mk_iface([172, 16, 0, 2], [172, 16, 0, 100], [172, 16, 0, 110]);
        let mut global = mk_global();
        global.subnets.push(crate::config::Subnet4 {
            subnet: "192.168.20.0/24".parse().unwrap(),
            pool_start: Ipv4Addr::new(192, 168, 20, 100),
            pool_end: Ipv4Addr::new(192, 168, 20, 200),
            gateway: Ipv4Addr::new(192, 168, 20, 1),
            lease_time: None,
            dns_servers: vec![],
            domain_name: None,
            trust_relay: false,
            v6_only_preferred: None,
        });
        let dir = tempdir().unwrap();
        let store = LeaseStoreV4::open(dir.path()).unwrap();

        let mut msg = mk_discover([2; 6], 0xabd);
        msg.header.giaddr = Ipv4Addr::new(192, 168, 20, 5);

        let outcome = handle(&msg, 2, Ipv4Addr::UNSPECIFIED, &iface, &global, &store, SystemTime::now()).unwrap();
        if let FsmOutcome::Reply { tx, .. } = outcome {
            assert_eq!(tx.dst_addr, Ipv4Addr::new(192, 168, 20, 5));
        } else {
            panic!("expected Reply");
        }
    }
}
