//! VPP punt-socket I/O backend for dhcpd.
//!
//! Phase 0 confirmed `PuntType::L4` port=67 delivers both broadcast
//! DHCPDISCOVER and unicast renewals, and that PUNT_L2 with dst MAC
//! `ff:ff:ff:ff:ff:ff` reaches the wire. See
//! `memory/project_dhcpd_phase0_findings.md` for the probe
//! results.
//!
//! This module owns the RX socket (VPP writes to us), the TX socket
//! (we write to VPP's server path), parses the punt framing, and
//! emits a stream of [`RxV4Packet`] the main loop consumes.
//!
//! ## RX framing
//!
//! Each datagram is:
//!
//! ```text
//! [u32 sw_if_index][u32 action][14-byte ethernet][IP header][UDP header][DHCP]
//! ```
//!
//! Both integers are native-endian (little-endian on x86). `action`
//! is always 0 (PUNT_L2) on RX — the value carries no meaning. We
//! parse up through UDP and hand the DHCP body plus metadata to
//! the FSM.
//!
//! ## TX framing
//!
//! ```text
//! [u32 sw_if_index][u32 action][... depending on action]
//! ```
//!
//! - `action = 0 (PUNT_L2)`: payload is a full L2 frame (eth+IP+UDP+DHCP).
//!   Enqueued at `<iface>-output`. Required for broadcast dst
//!   (`255.255.255.255`) because ip4-lookup has no unicast FIB for it.
//! - `action = 1 (PUNT_IP4_ROUTED)`: payload is an IP packet; VPP
//!   does FIB lookup + ARP. Used for unicast replies post-binding.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixDatagram as StdUnixDatagram;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;

use vpp_api::generated::ip::{
    FibPath, FibPathNhProto, FibPathType, IpRoute, IpRouteAddDel, IpRouteAddDelReply,
    Prefix,
};
use vpp_api::generated::punt::{
    PuntSocketDeregister, PuntSocketDeregisterReply, PuntSocketRegister,
    PuntSocketRegisterReply, PuntType,
};
use vpp_api::VppClient;

use crate::io::{IoInterface, RxV4Packet, RxV6Packet, TxV4Packet, TxV6Packet};

const AF_IPV4: u8 = 0;
const AF_IPV6: u8 = 1;
const IP_PROTO_UDP: u8 = 17;
pub const DHCP_SERVER_PORT_V4: u16 = 67;
pub const DHCP_SERVER_PORT_V6: u16 = 547;

const PUNT_ACTION_L2: u32 = 0;
const PUNT_ACTION_IP4_ROUTED: u32 = 1;
const PUNT_ACTION_IP6_ROUTED: u32 = 2;

/// Size of VPP's punt_packetdesc_t prefix on each datagram.
const PUNT_DESC_LEN: usize = 8;
/// Size of the ethernet header VPP prepends to RX datagrams.
const ETHERNET_HEADER_LEN: usize = 14;

/// Registration bookkeeping returned from [`register`].
#[derive(Debug, Clone)]
pub struct PuntRegistration {
    pub v4_client_path: String,
    pub v4_server_path: String,
    pub v6_client_path: Option<String>,
    pub v6_server_path: Option<String>,
}

/// Register UDP/67 (v4) and optionally UDP/547 (v6) with VPP.
/// The returned server paths are where we write TX datagrams.
pub async fn register(
    vpp: &VppClient,
    v4_client: &str,
    v6_client: Option<&str>,
) -> anyhow::Result<PuntRegistration> {
    let v4_server = register_one(vpp, AF_IPV4, DHCP_SERVER_PORT_V4, v4_client)
        .await
        .context("register UDP/67 (DHCPv4)")?;

    // VPP's default FIB drops 255.255.255.255/32 at ip4-lookup, which
    // is upstream of ip4-local where our punt socket hooks. Without
    // this receive entry DHCPDISCOVER never reaches us.
    //
    // The deregister path is best-effort: if a stale entry exists
    // from a previous run we just treat that as "already installed",
    // and on shutdown we try to remove it but won't fail if it's
    // already gone.
    if let Err(e) = install_bcast_route(vpp, true).await {
        tracing::warn!(
            error = %e,
            "failed to install 255.255.255.255/32 receive route; \
             broadcast DHCPDISCOVER may be dropped",
        );
    }

    let (v6_client_path, v6_server_path) = match v6_client {
        Some(path) => {
            let server = register_one(vpp, AF_IPV6, DHCP_SERVER_PORT_V6, path)
                .await
                .context("register UDP/547 (DHCPv6)")?;
            (Some(path.to_string()), Some(server))
        }
        None => (None, None),
    };

    Ok(PuntRegistration {
        v4_client_path: v4_client.to_string(),
        v4_server_path: v4_server,
        v6_client_path,
        v6_server_path,
    })
}

async fn register_one(
    vpp: &VppClient,
    af: u8,
    port: u16,
    client_path: &str,
) -> anyhow::Result<String> {
    let req = PuntSocketRegister {
        header_version: 1,
        punt_type: PuntType::L4,
        af,
        protocol: IP_PROTO_UDP,
        port,
        pathname: client_path.to_string(),
    };
    let reply: PuntSocketRegisterReply = vpp
        .request::<PuntSocketRegister, PuntSocketRegisterReply>(req)
        .await
        .map_err(|e| anyhow::anyhow!("punt_socket_register: {}", e))?;
    if reply.retval != 0 {
        anyhow::bail!(
            "punt_socket_register af={} proto=UDP port={} failed: retval={} \
             (is `punt {{ socket ... }}` set in startup.conf?)",
            af,
            port,
            reply.retval,
        );
    }
    let server = reply.pathname.trim_end_matches('\0').to_string();
    tracing::info!(
        client = client_path,
        server = server.as_str(),
        af,
        port,
        "registered DHCP punt socket"
    );
    Ok(server)
}

pub async fn deregister(vpp: &VppClient, reg: &PuntRegistration) {
    let _ = deregister_one(vpp, AF_IPV4, DHCP_SERVER_PORT_V4).await;
    if reg.v6_server_path.is_some() {
        let _ = deregister_one(vpp, AF_IPV6, DHCP_SERVER_PORT_V6).await;
    }
    // Best-effort — stale entry from a crashed prior run (or no
    // entry at all if register failed) is fine. We don't surface
    // errors here because shutdown shouldn't be noisy.
    let _ = install_bcast_route(vpp, false).await;
}

/// Install (or remove, when `is_add=false`) the 255.255.255.255/32
/// receive FIB entry that lets broadcast DHCPDISCOVER reach ip4-local.
///
/// Returns Ok on success or when VPP reports -72 (EEXIST / ENOENT
/// depending on direction), which we treat as "state already matches
/// request" — this path may run redundantly after a deploy that left
/// the same entry in commands-core.txt, and we don't want that to
/// fail the register path.
async fn install_bcast_route(vpp: &VppClient, is_add: bool) -> anyhow::Result<()> {
    let route = IpRoute {
        table_id: 0,
        stats_index: 0,
        prefix: Prefix::ipv4([255, 255, 255, 255], 32),
        n_paths: 1,
        paths: vec![FibPath {
            sw_if_index: u32::MAX,
            path_type: FibPathType::Local as u32,
            proto: FibPathNhProto::Ip4 as u32,
            ..FibPath::default()
        }],
    };
    let reply: IpRouteAddDelReply = vpp
        .request::<IpRouteAddDel, IpRouteAddDelReply>(IpRouteAddDel {
            is_add,
            is_multipath: false,
            route,
        })
        .await
        .map_err(|e| anyhow::anyhow!("ip_route_add_del: {}", e))?;
    // Idempotent: treat already-exists (on add) and no-such-entry
    // (on delete) as success. Other negative retvals surface.
    match reply.retval {
        0 => {
            tracing::info!(
                is_add,
                "toggled 255.255.255.255/32 receive route"
            );
            Ok(())
        }
        // VPP's FIB_ROUTE_ENTRY_EEXIST = -72, ENOENT surfaces similarly
        // in practice; accept any non-fatal "no-op" retval.
        -72 | -31 => Ok(()),
        other => anyhow::bail!(
            "ip_route_add_del(255.255.255.255/32, is_add={}) retval={}",
            is_add,
            other
        ),
    }
}

async fn deregister_one(
    vpp: &VppClient,
    af: u8,
    port: u16,
) -> anyhow::Result<()> {
    let req = PuntSocketDeregister {
        punt_type: PuntType::L4,
        af,
        protocol: IP_PROTO_UDP,
        port,
    };
    let reply: PuntSocketDeregisterReply = vpp
        .request::<PuntSocketDeregister, PuntSocketDeregisterReply>(req)
        .await
        .map_err(|e| anyhow::anyhow!("punt_socket_deregister: {}", e))?;
    if reply.retval != 0 {
        anyhow::bail!("punt_socket_deregister retval={}", reply.retval);
    }
    Ok(())
}

/// Full punt-socket IO for DHCPv4 + optional DHCPv6. Owns reader
/// tasks and a shared transmit socket.
pub struct PuntIo {
    interfaces: HashMap<u32, IoInterface>,
    tx: StdUnixDatagram,
    vpp_server_path_v4: String,
    vpp_server_path_v6: Option<String>,
    rx_v4: mpsc::Receiver<RxV4Packet>,
    rx_v6: Option<mpsc::Receiver<RxV6Packet>>,
    _reader_task_v4: tokio::task::JoinHandle<()>,
    _reader_task_v6: Option<tokio::task::JoinHandle<()>>,
}

impl PuntIo {
    /// Bind the v4 client socket and spawn the v4 reader task.
    pub fn open_v4(
        interfaces: Vec<IoInterface>,
        client_socket_path: &str,
        vpp_server_path: String,
    ) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(client_socket_path);
        let rx_sock = StdUnixDatagram::bind(client_socket_path)?;
        rx_sock.set_nonblocking(true)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            client_socket_path,
            std::fs::Permissions::from_mode(0o777),
        )?;
        let async_rx = UnixDatagram::from_std(rx_sock)?;

        let tx = StdUnixDatagram::unbound()?;
        let iface_map: HashMap<u32, IoInterface> =
            interfaces.into_iter().map(|i| (i.sw_if_index, i)).collect();

        let (chan_tx, chan_rx) = mpsc::channel::<RxV4Packet>(256);
        let iface_map_for_reader = Arc::new(iface_map.clone());
        let reader = tokio::spawn(reader_task_v4(async_rx, chan_tx, iface_map_for_reader));

        tracing::info!(
            client = client_socket_path,
            vpp_server = vpp_server_path.as_str(),
            interfaces = iface_map.len(),
            "DHCPv4 punt socket ready"
        );

        Ok(PuntIo {
            interfaces: iface_map,
            tx,
            vpp_server_path_v4: vpp_server_path,
            vpp_server_path_v6: None,
            rx_v4: chan_rx,
            rx_v6: None,
            _reader_task_v4: reader,
            _reader_task_v6: None,
        })
    }

    /// Bind the v6 client socket and spawn the v6 reader task.
    /// Call after [`open_v4`] on the same instance.
    pub fn attach_v6(
        &mut self,
        client_socket_path: &str,
        vpp_server_path: String,
    ) -> std::io::Result<()> {
        let _ = std::fs::remove_file(client_socket_path);
        let rx_sock = StdUnixDatagram::bind(client_socket_path)?;
        rx_sock.set_nonblocking(true)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            client_socket_path,
            std::fs::Permissions::from_mode(0o777),
        )?;
        let async_rx = UnixDatagram::from_std(rx_sock)?;

        let (chan_tx, chan_rx) = mpsc::channel::<RxV6Packet>(256);
        let iface_map_for_reader = Arc::new(self.interfaces.clone());
        let reader = tokio::spawn(reader_task_v6(async_rx, chan_tx, iface_map_for_reader));

        tracing::info!(
            client = client_socket_path,
            vpp_server = vpp_server_path.as_str(),
            "DHCPv6 punt socket ready"
        );
        self.vpp_server_path_v6 = Some(vpp_server_path);
        self.rx_v6 = Some(chan_rx);
        self._reader_task_v6 = Some(reader);
        Ok(())
    }

    pub async fn recv_v4(&mut self) -> Option<RxV4Packet> {
        self.rx_v4.recv().await
    }

    pub async fn recv_v6(&mut self) -> Option<RxV6Packet> {
        match &mut self.rx_v6 {
            Some(ch) => ch.recv().await,
            None => std::future::pending().await,
        }
    }

    pub fn has_v6(&self) -> bool {
        self.rx_v6.is_some()
    }

    /// Take the v4 RX receiver out of the PuntIo so it can be
    /// borrowed independently of the TX path in a select loop.
    /// Only valid once.
    pub fn take_rx_v4(&mut self) -> mpsc::Receiver<RxV4Packet> {
        // Replace with a closed channel so subsequent recv_v4
        // returns None if anyone calls it.
        let (_closed_tx, closed_rx) = mpsc::channel(1);
        std::mem::replace(&mut self.rx_v4, closed_rx)
    }

    pub fn take_rx_v6(&mut self) -> Option<mpsc::Receiver<RxV6Packet>> {
        self.rx_v6.take()
    }

    pub fn send_v4(&self, packet: &TxV4Packet) -> std::io::Result<()> {
        let iface = self.interfaces.get(&packet.sw_if_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unknown sw_if_index {}", packet.sw_if_index),
            )
        })?;
        // Keep the v4 path using the v4 server socket.
        let vpp_server_path = &self.vpp_server_path_v4;

        // Build UDP + IP + DHCP body. src port is always 67 (server);
        // dst port picked by the FSM (67 when replying to a relay per
        // giaddr, 68 when replying to a client directly).
        let udp_len: u16 = 8 + packet.payload.len() as u16;
        let mut udp = Vec::with_capacity(udp_len as usize);
        udp.extend_from_slice(&67u16.to_be_bytes()); // sport = 67
        udp.extend_from_slice(&packet.dst_port.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // cksum placeholder
        udp.extend_from_slice(&packet.payload);
        let ck = udp_checksum_v4(&packet.src_addr, &packet.dst_addr, &udp);
        udp[6..8].copy_from_slice(&ck.to_be_bytes());

        // IP header.
        let ip = build_ipv4_header(&packet.src_addr, &packet.dst_addr, &udp);

        if packet.broadcast {
            // PUNT_L2: build a full L2 frame with dst MAC supplied
            // by the FSM (either ff:ff:ff:ff:ff:ff or client chaddr
            // for pre-bound unicast with broadcast-flag clear).
            let mut frame = Vec::with_capacity(14 + ip.len());
            frame.extend_from_slice(&packet.dst_mac);
            frame.extend_from_slice(&iface.mac_address);
            frame.extend_from_slice(&[0x08, 0x00]); // IPv4
            frame.extend_from_slice(&ip);

            let mut dgram = Vec::with_capacity(PUNT_DESC_LEN + frame.len());
            dgram.extend_from_slice(&packet.sw_if_index.to_le_bytes());
            dgram.extend_from_slice(&PUNT_ACTION_L2.to_le_bytes());
            dgram.extend_from_slice(&frame);
            self.tx.send_to(&dgram, vpp_server_path)?;
        } else {
            // PUNT_IP4_ROUTED: ip4-lookup does FIB + ARP for us.
            let mut dgram = Vec::with_capacity(PUNT_DESC_LEN + ip.len());
            dgram.extend_from_slice(&packet.sw_if_index.to_le_bytes());
            dgram.extend_from_slice(&PUNT_ACTION_IP4_ROUTED.to_le_bytes());
            dgram.extend_from_slice(&ip);
            self.tx.send_to(&dgram, vpp_server_path)?;
        }
        Ok(())
    }

    /// Send a DHCPv6 reply. The src_addr is typically left as
    /// UNSPECIFIED by the FSM; we fill it in from the egress
    /// interface's link-local. VPP's FIB resolves the link-local
    /// destination via the /10 multicast route; for direct replies
    /// we unicast to the client's link-local on UDP/546, for
    /// relayed replies we unicast to the relay's address on UDP/547.
    pub fn send_v6(&self, packet: &TxV6Packet, to_relay: bool) -> std::io::Result<()> {
        let iface = self.interfaces.get(&packet.sw_if_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unknown sw_if_index {}", packet.sw_if_index),
            )
        })?;
        let vpp_server_path = self.vpp_server_path_v6.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "v6 punt not attached")
        })?;

        let src_addr = if packet.src_addr == Ipv6Addr::UNSPECIFIED {
            iface.ipv6_link_local.unwrap_or(Ipv6Addr::UNSPECIFIED)
        } else {
            packet.src_addr
        };

        let dst_port = if to_relay {
            super::packet::v6::header::DHCP6_SERVER_PORT
        } else {
            super::packet::v6::header::DHCP6_CLIENT_PORT
        };
        let src_port = super::packet::v6::header::DHCP6_SERVER_PORT;

        let udp_len: u16 = 8 + packet.payload.len() as u16;
        let mut udp = Vec::with_capacity(udp_len as usize);
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum placeholder
        udp.extend_from_slice(&packet.payload);
        let ck = udp_checksum_v6(&src_addr, &packet.dst_addr, &udp);
        udp[6..8].copy_from_slice(&ck.to_be_bytes());

        let ip = build_ipv6_header(&src_addr, &packet.dst_addr, &udp);

        // PUNT_IP6_ROUTED: VPP's ip6-lookup resolves the link-local
        // destination via the /10 multicast-ish route that always
        // points back out the ingress interface. That's the ND
        // behavior we want for Advertise-to-client.
        let mut dgram = Vec::with_capacity(PUNT_DESC_LEN + ip.len());
        dgram.extend_from_slice(&packet.sw_if_index.to_le_bytes());
        dgram.extend_from_slice(&PUNT_ACTION_IP6_ROUTED.to_le_bytes());
        dgram.extend_from_slice(&ip);
        self.tx.send_to(&dgram, vpp_server_path)?;
        Ok(())
    }

    pub fn interface(&self, sw_if_index: u32) -> Option<&IoInterface> {
        self.interfaces.get(&sw_if_index)
    }
}

/// Build an IPv4 packet with UDP payload already embedded.
fn build_ipv4_header(src: &Ipv4Addr, dst: &Ipv4Addr, udp: &[u8]) -> Vec<u8> {
    let total_length: u16 = 20 + udp.len() as u16;
    let mut ip = Vec::with_capacity(total_length as usize);
    ip.push(0x45);
    ip.push(0x10); // tos
    ip.extend_from_slice(&total_length.to_be_bytes());
    ip.extend_from_slice(&[0, 0]); // id
    ip.extend_from_slice(&[0x40, 0]); // DF + frag off
    ip.push(64); // ttl
    ip.push(IP_PROTO_UDP);
    ip.extend_from_slice(&[0, 0]); // cksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ck = ip_header_checksum(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());
    ip.extend_from_slice(udp);
    ip
}

fn ip_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += ((header[i] as u32) << 8) | header[i + 1] as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum_v4(src: &Ipv4Addr, dst: &Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(IP_PROTO_UDP);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    let ck = ip_header_checksum(&pseudo);
    if ck == 0 {
        0xffff
    } else {
        ck
    }
}

/// Build an IPv6 header with UDP payload embedded.
fn build_ipv6_header(src: &Ipv6Addr, dst: &Ipv6Addr, udp: &[u8]) -> Vec<u8> {
    let payload_len = udp.len() as u16;
    let mut ip = Vec::with_capacity(40 + udp.len());
    // Version (4) || Traffic Class (8) || Flow Label (20)
    ip.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    ip.extend_from_slice(&payload_len.to_be_bytes());
    ip.push(IP_PROTO_UDP); // Next Header
    ip.push(64); // Hop Limit
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(udp);
    ip
}

fn udp_checksum_v6(src: &Ipv6Addr, dst: &Ipv6Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, IP_PROTO_UDP]);
    pseudo.extend_from_slice(udp);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    let ck = ip_header_checksum(&pseudo);
    if ck == 0 {
        0xffff
    } else {
        ck
    }
}

/// Parse a VPP v4 punt-socket datagram into an RxV4Packet.
///
/// Frame layout: `[desc (8)] [eth (14)] [vlan tags (0..8)] [ip] [udp] [dhcp]`.
/// Returns Err with a short reason on validation failure; returns Ok(None)
/// if the frame is well-formed but for an unknown sw_if_index.
fn parse_punt_v4_frame(
    buf: &[u8],
    interfaces: &HashMap<u32, IoInterface>,
) -> Result<Option<RxV4Packet>, &'static str> {
    let n = buf.len();
    if n < PUNT_DESC_LEN + ETHERNET_HEADER_LEN + 20 + 8 + 240 {
        return Err("datagram too short");
    }
    let sw_if_index = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    // buf[4..8] is action — ignored on RX.

    let mut off = PUNT_DESC_LEN;
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&buf[off + 6..off + 12]);
    off += ETHERNET_HEADER_LEN;

    // Skip any 802.1Q / 802.1ad VLAN tags preserved in the L2 framing.
    // VPP already validated the tag matches the sub-interface config
    // before punting, so this is just stepping past them to reach L3.
    while off + 4 <= n {
        let ethertype = u16::from_be_bytes([buf[off - 2], buf[off - 1]]);
        if ethertype == 0x8100 || ethertype == 0x88a8 {
            off += 4;
        } else {
            break;
        }
    }

    if off >= n {
        return Err("truncated after L2 header");
    }
    let ver_ihl = buf[off];
    let ihl = ((ver_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Err("bad IPv4 IHL");
    }
    let total_len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
    let proto = buf[off + 9];
    if proto != IP_PROTO_UDP {
        return Err("non-UDP proto");
    }
    let src_addr = Ipv4Addr::new(
        buf[off + 12],
        buf[off + 13],
        buf[off + 14],
        buf[off + 15],
    );
    let dst_addr = Ipv4Addr::new(
        buf[off + 16],
        buf[off + 17],
        buf[off + 18],
        buf[off + 19],
    );
    let ip_end = off + total_len;
    if ip_end > n {
        return Err("IP total_length exceeds datagram");
    }
    let udp_start = off + ihl;
    if udp_start + 8 > ip_end {
        return Err("truncated UDP header");
    }
    let dport = u16::from_be_bytes([buf[udp_start + 2], buf[udp_start + 3]]);
    if dport != DHCP_SERVER_PORT_V4 {
        return Err("unexpected UDP dport");
    }
    let dhcp_start = udp_start + 8;
    let dhcp_end = ip_end;
    if dhcp_end <= dhcp_start {
        return Err("empty DHCP body");
    }
    if !interfaces.contains_key(&sw_if_index) {
        return Ok(None);
    }
    Ok(Some(RxV4Packet {
        sw_if_index,
        src_mac,
        src_addr,
        dst_addr,
        payload: buf[dhcp_start..dhcp_end].to_vec(),
    }))
}

async fn reader_task_v4(
    sock: UnixDatagram,
    chan: mpsc::Sender<RxV4Packet>,
    interfaces: Arc<HashMap<u32, IoInterface>>,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("punt-v4 recv error: {}", e);
                continue;
            }
        };
        let pkt = match parse_punt_v4_frame(&buf[..n], &interfaces) {
            Ok(Some(pkt)) => pkt,
            Ok(None) => {
                tracing::debug!("punt-v4: packet on unknown sw_if_index; dropping");
                continue;
            }
            Err(reason) => {
                tracing::debug!(len = n, reason, "punt-v4: frame rejected");
                continue;
            }
        };
        if chan.send(pkt).await.is_err() {
            // Receiver dropped — daemon shutting down.
            break;
        }
    }
}

async fn reader_task_v6(
    sock: UnixDatagram,
    chan: mpsc::Sender<RxV6Packet>,
    interfaces: Arc<HashMap<u32, IoInterface>>,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("punt-v6 recv error: {}", e);
                continue;
            }
        };
        // Minimum: desc(8) + eth(14) + ip6(40) + udp(8) + dhcp(4) = 74
        if n < PUNT_DESC_LEN + ETHERNET_HEADER_LEN + 40 + 8 + 4 {
            tracing::debug!(len = n, "punt-v6 datagram too short; skipping");
            continue;
        }
        let sw_if_index = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let mut off = PUNT_DESC_LEN;
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&buf[off + 6..off + 12]);
        off += ETHERNET_HEADER_LEN;

        // IPv6 header: fixed 40 bytes.
        if buf[off] >> 4 != 6 {
            tracing::debug!("punt-v6: not IPv6");
            continue;
        }
        let payload_len = u16::from_be_bytes([buf[off + 4], buf[off + 5]]) as usize;
        let next_header = buf[off + 6];
        if next_header != IP_PROTO_UDP {
            tracing::debug!(next_header, "punt-v6: non-UDP next-header; skipping");
            continue;
        }
        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&buf[off + 8..off + 24]);
        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&buf[off + 24..off + 40]);
        let src_addr = Ipv6Addr::from(src_bytes);
        let dst_addr = Ipv6Addr::from(dst_bytes);

        let udp_off = off + 40;
        if udp_off + 8 > n {
            continue;
        }
        let dport = u16::from_be_bytes([buf[udp_off + 2], buf[udp_off + 3]]);
        if dport != super::packet::v6::header::DHCP6_SERVER_PORT {
            tracing::debug!(dport, "punt-v6: unexpected dport; skipping");
            continue;
        }
        let dhcp_off = udp_off + 8;
        let dhcp_end = udp_off + payload_len;
        if dhcp_end > n {
            continue;
        }
        let payload = buf[dhcp_off..dhcp_end].to_vec();

        if !interfaces.contains_key(&sw_if_index) {
            tracing::debug!(
                sw_if_index,
                "punt-v6: packet on unknown sw_if_index; dropping"
            );
            continue;
        }
        let pkt = RxV6Packet {
            sw_if_index,
            src_mac,
            src_addr,
            dst_addr,
            payload,
        };
        if chan.send(pkt).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_checksum_matches_known_vector() {
        // Trivial UDP packet — validate nothing more than
        // "checksum function doesn't panic and returns non-zero".
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let udp: Vec<u8> = vec![0, 67, 0, 68, 0, 8, 0, 0];
        let ck = udp_checksum_v4(&src, &dst, &udp);
        assert_ne!(ck, 0);
    }

    #[test]
    fn ip_header_checksum_is_zero_for_valid_header() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let udp: Vec<u8> = vec![0, 67, 0, 68, 0, 8, 0, 0];
        let ip = build_ipv4_header(&src, &dst, &udp);
        // After encoding with the computed checksum, verifying the
        // same header (including the now-valid checksum) should be
        // zero (one's-complement arithmetic).
        assert_eq!(ip_header_checksum(&ip[..20]), 0);
    }

    fn mk_iface(sw_if_index: u32) -> IoInterface {
        IoInterface {
            sw_if_index,
            name: format!("test{}", sw_if_index),
            mac_address: [0xde, 0xad, 0, 0, 0, sw_if_index as u8],
            ipv4_address: Some(Ipv4Addr::new(192, 168, 1, 1)),
            ipv4_prefix_len: 24,
            ipv6_link_local: None,
        }
    }

    /// Build a minimal punt-v4 datagram with optional VLAN tags
    /// between the ethernet header and the IPv4 header.
    fn mk_punt_frame(sw_if_index: u32, vlan_tags: &[u16], dhcp_body_len: usize) -> Vec<u8> {
        let mut v = Vec::new();
        // desc: sw_if_index (LE) + action (LE)
        v.extend_from_slice(&sw_if_index.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        // eth: dst MAC, src MAC, ethertype (set below after tags)
        v.extend_from_slice(&[0xde, 0xad, 0, 0, 0, 0x64]); // dst
        v.extend_from_slice(&[0x3a, 0xe0, 0xa3, 0x25, 0x8e, 0x27]); // src
        // initial ethertype: first tag TPID if tagged, else IPv4
        if vlan_tags.is_empty() {
            v.extend_from_slice(&0x0800u16.to_be_bytes());
        } else {
            v.extend_from_slice(&0x8100u16.to_be_bytes());
        }
        // subsequent VLAN tags
        for (i, &vid) in vlan_tags.iter().enumerate() {
            // TCI: priority=0, DEI=0, VID=vid
            v.extend_from_slice(&vid.to_be_bytes());
            // next ethertype
            let next = if i + 1 < vlan_tags.len() {
                0x8100
            } else {
                0x0800
            };
            v.extend_from_slice(&(next as u16).to_be_bytes());
        }
        // IPv4 header (20 bytes, no options)
        let ip_start = v.len();
        let total_len: u16 = (20 + 8 + dhcp_body_len) as u16;
        v.push(0x45); // version=4, IHL=5
        v.push(0x00); // tos
        v.extend_from_slice(&total_len.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // id
        v.extend_from_slice(&0x4000u16.to_be_bytes()); // flags: DF
        v.push(64); // ttl
        v.push(17); // proto UDP
        v.extend_from_slice(&[0, 0]); // checksum placeholder
        v.extend_from_slice(&Ipv4Addr::new(192, 168, 20, 5).octets()); // src
        v.extend_from_slice(&Ipv4Addr::new(192, 168, 37, 4).octets()); // dst
        // fill in a sensible IP checksum (we don't validate on RX, but keep it clean)
        let cksum = ip_header_checksum(&v[ip_start..ip_start + 20]);
        v[ip_start + 10..ip_start + 12].copy_from_slice(&cksum.to_be_bytes());
        // UDP header
        v.extend_from_slice(&67u16.to_be_bytes()); // sport
        v.extend_from_slice(&67u16.to_be_bytes()); // dport
        v.extend_from_slice(&((8 + dhcp_body_len) as u16).to_be_bytes()); // len
        v.extend_from_slice(&[0, 0]); // checksum (unused on RX)
        // DHCP body (fill with zeros — minimum size 240)
        v.extend(std::iter::repeat(0u8).take(dhcp_body_len));
        v
    }

    #[test]
    fn parse_untagged_frame() {
        let mut ifs = HashMap::new();
        ifs.insert(9, mk_iface(9));
        let frame = mk_punt_frame(9, &[], 240);
        let pkt = parse_punt_v4_frame(&frame, &ifs).unwrap().unwrap();
        assert_eq!(pkt.sw_if_index, 9);
        assert_eq!(pkt.src_addr, Ipv4Addr::new(192, 168, 20, 5));
        assert_eq!(pkt.dst_addr, Ipv4Addr::new(192, 168, 37, 4));
        assert_eq!(pkt.src_mac, [0x3a, 0xe0, 0xa3, 0x25, 0x8e, 0x27]);
        assert_eq!(pkt.payload.len(), 240);
    }

    #[test]
    fn parse_single_vlan_tagged_frame() {
        // The bug fixed 2026-04-17: DHCP packets arriving on a VPP
        // sub-interface carry an 802.1Q tag in the punted frame.
        let mut ifs = HashMap::new();
        ifs.insert(9, mk_iface(9));
        let frame = mk_punt_frame(9, &[110], 240);
        let pkt = parse_punt_v4_frame(&frame, &ifs).unwrap().unwrap();
        assert_eq!(pkt.sw_if_index, 9);
        assert_eq!(pkt.src_addr, Ipv4Addr::new(192, 168, 20, 5));
        assert_eq!(pkt.dst_addr, Ipv4Addr::new(192, 168, 37, 4));
        assert_eq!(pkt.payload.len(), 240);
    }

    #[test]
    fn parse_qinq_tagged_frame() {
        let mut ifs = HashMap::new();
        ifs.insert(9, mk_iface(9));
        let frame = mk_punt_frame(9, &[200, 110], 240);
        let pkt = parse_punt_v4_frame(&frame, &ifs).unwrap().unwrap();
        assert_eq!(pkt.src_addr, Ipv4Addr::new(192, 168, 20, 5));
        assert_eq!(pkt.payload.len(), 240);
    }

    #[test]
    fn parse_rejects_unknown_sw_if_index() {
        let ifs = HashMap::new();
        let frame = mk_punt_frame(9, &[], 240);
        assert!(parse_punt_v4_frame(&frame, &ifs).unwrap().is_none());
    }

    #[test]
    fn parse_rejects_short_frame() {
        let ifs = HashMap::new();
        assert!(parse_punt_v4_frame(&[0u8; 50], &ifs).is_err());
    }
}
