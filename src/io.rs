//! Packet I/O traits for dhcpd.
//!
//! Phase 1 ships the traits and the `IoInterface` wiring type. Real
//! packet processing lands in Phase 2 (v4) and Phase 3 (v6). The
//! actual punt-socket implementation is in [`crate::io_punt`].
//!
//! The `raw` backend (AF_PACKET on the LCP TAP) was originally
//! planned as a fallback if VPP's punt couldn't deliver broadcast
//! DHCPDISCOVER. Phase 0 testing (2026-04-16) confirmed punt works
//! for both broadcast and unicast, so the raw fallback is unlikely
//! to ship. Trait is kept so we can add it later without touching
//! callers if VPP regresses.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Metadata about a DHCP-serving interface. Built once at startup
/// from the config + VPP interface/address dumps, then indexed by
/// `sw_if_index` for packet RX/TX dispatch.
#[derive(Debug, Clone)]
pub struct IoInterface {
    pub sw_if_index: u32,
    pub name: String,
    pub mac_address: [u8; 6],
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv4_prefix_len: u8,
    pub ipv6_link_local: Option<Ipv6Addr>,
}

/// An RX DHCPv4 packet, after punt framing + eth/ip/udp headers have
/// been stripped. Phase 2 wires this up.
#[derive(Debug, Clone)]
pub struct RxV4Packet {
    pub sw_if_index: u32,
    pub src_mac: [u8; 6],
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    /// DHCP body (BOOTP header + options), starting at op=1/2.
    pub payload: Vec<u8>,
}

/// An RX DHCPv6 packet. Phase 3 wires this up.
#[derive(Debug, Clone)]
pub struct RxV6Packet {
    pub sw_if_index: u32,
    pub src_mac: [u8; 6],
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
    /// DHCPv6 message (msg-type + transaction-id + options).
    pub payload: Vec<u8>,
}

/// An outbound DHCPv4 packet. `broadcast` controls whether the
/// `io_punt` backend wraps via `PUNT_L2` (ff:ff:ff:ff:ff:ff dst MAC,
/// bypasses unicast FIB) or `PUNT_IP4_ROUTED` (ip4-lookup, normal
/// unicast). Phase 2 wires this up.
#[derive(Debug, Clone)]
pub struct TxV4Packet {
    pub sw_if_index: u32,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    /// UDP destination port. Per RFC 2131 §4.1:
    ///   - 67 (server port) when replying to a relay (giaddr set)
    ///   - 68 (client port) when replying directly to a client
    pub dst_port: u16,
    /// L2 destination MAC. Only consulted when `broadcast = true` or
    /// when the unicast reply needs a specific chaddr (e.g. replying
    /// to a DHCPREQUEST pre-bind-confirmation).
    pub dst_mac: [u8; 6],
    pub broadcast: bool,
    pub payload: Vec<u8>,
}

/// An outbound DHCPv6 packet. Phase 3 wires this up.
#[derive(Debug, Clone)]
pub struct TxV6Packet {
    pub sw_if_index: u32,
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
    pub payload: Vec<u8>,
}
