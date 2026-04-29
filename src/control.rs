//! Unix-socket query protocol for `dhcpd query`.
//!
//! Line-delimited JSON: each request is one JSON object tagged by
//! `command`; each response is one JSON line. Follows the bgpd /
//! ospfd pattern.
//!
//! Phase 1 commands:
//! - `status` — daemon version, v4/v6 enabled, interface count,
//!   control socket path
//! - `interfaces` — per-interface view (name, sw_if_index, MAC,
//!   addresses, pool, PD pool name)
//!
//! Lease/pool queries land in Phase 2 (`Leases`) and Phase 4
//! (`PdDelegations`) per the plan.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::io::IoInterface;
use crate::v4::server::V4Server;
use crate::v6::server::V6Server;

pub const DEFAULT_CONTROL_SOCKET: &str = "/run/dhcpd.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlRequest {
    Status,
    Interfaces,
    Leases,
    Pools,
    /// `dhcp_server.subnets[]` view — pool, gateway, options,
    /// `v6_only_preferred` (RFC 8925).
    Subnets,
    /// Admin-initiated release — frees the lease for `client_id`.
    /// `client_id` is hex-encoded (lowercase, ':'-separated bytes
    /// or tight hex) to avoid embedding raw bytes in JSON strings.
    ReleaseLease { client_id: String },
    Leases6,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    Status(StatusReply),
    Interfaces(InterfacesReply),
    Leases(LeasesReply),
    Pools(PoolsReply),
    Subnets(SubnetsReply),
    ReleaseLease(ReleaseReply),
    Leases6(Leases6Reply),
    Error { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReply {
    pub version: String,
    pub v4_enabled: bool,
    pub v6_enabled: bool,
    /// Interfaces with explicit per-interface pool config (legacy
    /// `interfaces[].dhcp_server_enabled: true` path). Serve
    /// direct-broadcast clients on their own subnet.
    pub v4_interface_count: usize,
    /// Interfaces listed in `dhcp_server.interfaces[]` — ingress-only
    /// opt-in for relayed DHCP. Pool is resolved via giaddr →
    /// `dhcp_server.subnets[]`.
    pub v4_relay_interface_count: usize,
    pub v6_interface_count: usize,
    pub pd_pool_count: usize,
    pub reservation_count: usize,
    pub control_socket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfacesReply {
    pub interfaces: Vec<InterfaceStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub name: String,
    pub sw_if_index: u32,
    pub mac_address: String,
    pub ipv4_address: Option<String>,
    pub ipv4_prefix_len: u8,
    pub ipv6_link_local: Option<String>,
    /// DHCPv4 pool range for this interface, if v4 serving is enabled.
    pub v4_pool: Option<PoolRange4>,
    /// True if this interface is opted in via `dhcp_server.interfaces[]`
    /// (ingress-only, pool comes from `dhcp_server.subnets[]`). Mutually
    /// exclusive with `v4_pool` — a given interface is either direct-
    /// serving or relay-ingress, never both.
    pub v4_relay_ingress: bool,
    /// DHCPv6 IA_NA pool, if v6 serving is enabled.
    pub v6_pool: Option<PoolRange6>,
    /// PD pool name referenced by v6 serving on this interface, if any.
    pub v6_pd_pool: Option<String>,
    /// V6ONLY_WAIT seconds (RFC 8925, option 108) inherited from the
    /// matching `dhcp_server.subnets[]` entry that contains this
    /// interface's IPv4 address. `None` when no subnet covers it or
    /// the subnet doesn't opt in.
    pub v6_only_preferred: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolRange4 {
    pub start: String,
    pub end: String,
    pub gateway: String,
    pub lease_time: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolRange6 {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeasesReply {
    pub leases: Vec<LeaseRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRow {
    pub client_id: String,
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub granted_unix: u64,
    pub expires_unix: u64,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolsReply {
    pub pools: Vec<PoolRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolRow {
    pub interface: String,
    pub start: String,
    pub end: String,
    pub total: u32,
    pub used: u32,
    pub free: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetsReply {
    pub subnets: Vec<SubnetRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetRow {
    pub subnet: String,
    pub pool_start: String,
    pub pool_end: String,
    pub gateway: String,
    pub lease_time: Option<u32>,
    pub dns_servers: Vec<String>,
    pub domain_name: Option<String>,
    pub trust_relay: bool,
    /// V6ONLY_WAIT seconds (RFC 8925, option 108). `None` disables
    /// the v6-only short-circuit for clients on this subnet.
    pub v6_only_preferred: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseReply {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leases6Reply {
    pub leases: Vec<Lease6Row>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease6Row {
    pub duid: String,
    pub iaid: u32,
    pub kind: String,
    pub address: String,
    pub prefix_len: u8,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub state: String,
    pub via_relay: bool,
}

/// Shared state the control task consults. The daemon keeps this
/// up-to-date with the latest interface + config view; control
/// handlers read a lock without touching the packet path.
///
/// When packet handling is live, `v4_server` is `Some`; control
/// handlers for `Leases`/`Pools`/`ReleaseLease` grab a lock on it
/// briefly to snapshot state.
#[derive(Clone)]
pub struct ControlSnapshot {
    #[doc(hidden)]
    pub v4_relay_interface_names: Vec<String>,
    pub version: String,
    pub v4_enabled: bool,
    pub v6_enabled: bool,
    pub interfaces: Vec<IoInterface>,
    pub v4_iface_configs: Vec<crate::config::InterfaceV4Config>,
    /// Snapshot of `dhcp_server.subnets[]`. Refreshed at startup and
    /// on SIGHUP reload — the v4 server's live `global.subnets` is
    /// the source of truth, but this mirror lets the `Interfaces`
    /// query surface per-interface `v6_only_preferred` without
    /// taking a v4_server lock.
    pub v4_subnets: Vec<crate::config::Subnet4>,
    pub v6_iface_configs: Vec<crate::config::InterfaceV6Config>,
    pub pd_pool_count: usize,
    pub reservation_count: usize,
    pub control_socket: String,
    /// Live reference to the v4 server. `None` when v4 is disabled
    /// or before the daemon has spun it up.
    pub v4_server: Option<Arc<Mutex<V4Server>>>,
    /// Live reference to the v6 server.
    pub v6_server: Option<Arc<Mutex<V6Server>>>,
}

impl Default for ControlSnapshot {
    fn default() -> Self {
        ControlSnapshot {
            version: env!("CARGO_PKG_VERSION").to_string(),
            v4_enabled: false,
            v6_enabled: false,
            interfaces: Vec::new(),
            v4_iface_configs: Vec::new(),
            v4_subnets: Vec::new(),
            v6_iface_configs: Vec::new(),
            v4_relay_interface_names: Vec::new(),
            pd_pool_count: 0,
            reservation_count: 0,
            control_socket: DEFAULT_CONTROL_SOCKET.to_string(),
            v4_server: None,
            v6_server: None,
        }
    }
}

/// Spawn the control listener. Removes any stale socket first.
pub async fn serve(
    socket_path: &str,
    snapshot: Arc<Mutex<ControlSnapshot>>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    // Make the socket readable by anyone — clients may run as a
    // different uid.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))?;
    tracing::info!(socket = %socket_path, "dhcpd control listener ready");
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let snap = snapshot.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_one(stream, snap).await {
                            tracing::warn!("control client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("control listener accept failed: {}", e);
                    break;
                }
            }
        }
    });
    Ok(handle)
}

async fn handle_one(
    stream: UnixStream,
    snapshot: Arc<Mutex<ControlSnapshot>>,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    let response = match serde_json::from_str::<ControlRequest>(line.trim()) {
        Ok(req) => handle_request(req, &snapshot).await,
        Err(e) => ControlResponse::Error {
            error: format!("invalid request: {}", e),
        },
    };
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    write_half.write_all(&bytes).await?;
    Ok(())
}

async fn handle_request(
    req: ControlRequest,
    snapshot: &Arc<Mutex<ControlSnapshot>>,
) -> ControlResponse {
    let snap = snapshot.lock().await;
    match req {
        ControlRequest::Status => ControlResponse::Status(build_status(&snap)),
        ControlRequest::Interfaces => ControlResponse::Interfaces(InterfacesReply {
            interfaces: snap
                .interfaces
                .iter()
                .map(|i| build_iface_status(i, &snap))
                .collect(),
        }),
        ControlRequest::Leases => {
            let Some(srv) = snap.v4_server.clone() else {
                return ControlResponse::Error {
                    error: "v4 server not running".into(),
                };
            };
            drop(snap);
            let srv = srv.lock().await;
            let leases = srv
                .store
                .iter()
                .map(|l| LeaseRow {
                    client_id: pretty_cid(&l.client_id),
                    ip: l.ip.to_string(),
                    mac: format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        l.mac[0], l.mac[1], l.mac[2], l.mac[3], l.mac[4], l.mac[5]
                    ),
                    hostname: l.hostname.clone(),
                    granted_unix: l.granted_unix,
                    expires_unix: l.expires_unix,
                    state: format!("{:?}", l.state),
                })
                .collect();
            ControlResponse::Leases(LeasesReply { leases })
        }
        ControlRequest::Subnets => {
            // Read straight off the snapshot mirror — same shape the
            // FSM consults at packet time. No v4_server lock needed.
            let subnets = snap
                .v4_subnets
                .iter()
                .map(|s| SubnetRow {
                    subnet: s.subnet.to_string(),
                    pool_start: s.pool_start.to_string(),
                    pool_end: s.pool_end.to_string(),
                    gateway: s.gateway.to_string(),
                    lease_time: s.lease_time,
                    dns_servers: s.dns_servers.iter().map(|a| a.to_string()).collect(),
                    domain_name: s.domain_name.clone(),
                    trust_relay: s.trust_relay,
                    v6_only_preferred: s.v6_only_preferred,
                })
                .collect();
            ControlResponse::Subnets(SubnetsReply { subnets })
        }
        ControlRequest::Pools => {
            let Some(srv) = snap.v4_server.clone() else {
                return ControlResponse::Error {
                    error: "v4 server not running".into(),
                };
            };
            drop(snap);
            let srv = srv.lock().await;
            let mut pools = Vec::new();
            for iface in srv.interfaces.values() {
                let start_n = u32::from(iface.pool_start);
                let end_n = u32::from(iface.pool_end);
                let total = end_n.saturating_sub(start_n).saturating_add(1);
                let used = srv
                    .store
                    .iter()
                    .filter(|l| {
                        let n = u32::from(l.ip);
                        n >= start_n
                            && n <= end_n
                            && matches!(
                                l.state,
                                crate::lease::LeaseState::Bound
                                    | crate::lease::LeaseState::Declined
                            )
                    })
                    .count() as u32;
                let free = total.saturating_sub(used);
                pools.push(PoolRow {
                    interface: iface.name.clone(),
                    start: iface.pool_start.to_string(),
                    end: iface.pool_end.to_string(),
                    total,
                    used,
                    free,
                });
            }
            ControlResponse::Pools(PoolsReply { pools })
        }
        ControlRequest::Leases6 => {
            let Some(srv) = snap.v6_server.clone() else {
                return ControlResponse::Error {
                    error: "v6 server not running".into(),
                };
            };
            drop(snap);
            let srv = srv.lock().await;
            let leases = srv
                .store
                .iter()
                .map(|l| Lease6Row {
                    duid: hex_colon(&l.duid),
                    iaid: l.iaid,
                    kind: format!("{:?}", l.kind),
                    address: l.address.to_string(),
                    prefix_len: l.prefix_len,
                    preferred_lifetime: l.preferred_lifetime,
                    valid_lifetime: l.valid_lifetime,
                    state: format!("{:?}", l.state),
                    via_relay: l.via_relay,
                })
                .collect();
            ControlResponse::Leases6(Leases6Reply { leases })
        }
        ControlRequest::ReleaseLease { client_id } => {
            let Some(srv) = snap.v4_server.clone() else {
                return ControlResponse::Error {
                    error: "v4 server not running".into(),
                };
            };
            drop(snap);
            let bytes = match parse_cid(&client_id) {
                Ok(b) => b,
                Err(e) => {
                    return ControlResponse::Error {
                        error: format!("invalid client_id: {}", e),
                    }
                }
            };
            let cid = crate::packet::v4::client_id::ClientId(bytes);
            let mut srv = srv.lock().await;
            let found = srv.store.get(&cid).is_some();
            if !found {
                return ControlResponse::ReleaseLease(ReleaseReply {
                    ok: false,
                    message: "no lease with that client_id".into(),
                });
            }
            match srv.store.release(&cid) {
                Ok(()) => ControlResponse::ReleaseLease(ReleaseReply {
                    ok: true,
                    message: "released".into(),
                }),
                Err(e) => ControlResponse::Error {
                    error: format!("release: {}", e),
                },
            }
        }
    }
}

fn pretty_cid(bytes: &[u8]) -> String {
    crate::packet::v4::client_id::ClientId(bytes.to_vec()).pretty()
}

fn hex_colon(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        write!(s, "{:02x}", b).ok();
    }
    s
}

fn parse_cid(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| *c != ':').collect();
    if cleaned.len() % 2 != 0 {
        return Err("client_id must be an even number of hex digits".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn build_status(snap: &ControlSnapshot) -> StatusReply {
    StatusReply {
        version: snap.version.clone(),
        v4_enabled: snap.v4_enabled,
        v6_enabled: snap.v6_enabled,
        v4_interface_count: snap.v4_iface_configs.len(),
        v4_relay_interface_count: snap.v4_relay_interface_names.len(),
        v6_interface_count: snap.v6_iface_configs.len(),
        pd_pool_count: snap.pd_pool_count,
        reservation_count: snap.reservation_count,
        control_socket: snap.control_socket.clone(),
    }
}

fn build_iface_status(iface: &IoInterface, snap: &ControlSnapshot) -> InterfaceStatus {
    let v4_pool = snap
        .v4_iface_configs
        .iter()
        .find(|c| c.name == iface.name)
        .map(|c| PoolRange4 {
            start: c.pool_start.to_string(),
            end: c.pool_end.to_string(),
            gateway: c.gateway.to_string(),
            lease_time: c.lease_time,
        });
    let v6_cfg = snap.v6_iface_configs.iter().find(|c| c.name == iface.name);
    let v6_pool = v6_cfg.and_then(|c| match (c.pool_start, c.pool_end) {
        (Some(s), Some(e)) => Some(PoolRange6 {
            start: s.to_string(),
            end: e.to_string(),
        }),
        _ => None,
    });
    let v6_pd_pool = v6_cfg.and_then(|c| c.pd_pool.clone());
    // RFC 8925: when a configured subnet contains the iface's IPv4
    // address and has `v6_only_preferred`, surface it here so an
    // operator running `dhcpd query interfaces` sees the v6-only
    // policy without having to cross-reference the subnets list.
    let v6_only_preferred = iface.ipv4_address.and_then(|addr| {
        snap.v4_subnets
            .iter()
            .filter(|s| s.subnet.contains(&addr))
            .max_by_key(|s| s.subnet.prefix_len())
            .and_then(|s| s.v6_only_preferred)
    });
    InterfaceStatus {
        name: iface.name.clone(),
        sw_if_index: iface.sw_if_index,
        mac_address: format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            iface.mac_address[0],
            iface.mac_address[1],
            iface.mac_address[2],
            iface.mac_address[3],
            iface.mac_address[4],
            iface.mac_address[5],
        ),
        ipv4_address: iface.ipv4_address.map(|a| a.to_string()),
        ipv4_prefix_len: iface.ipv4_prefix_len,
        ipv6_link_local: iface.ipv6_link_local.map(|a| a.to_string()),
        v4_pool,
        v4_relay_ingress: snap
            .v4_relay_interface_names
            .iter()
            .any(|n| n == &iface.name),
        v6_pool,
        v6_pd_pool,
        v6_only_preferred,
    }
}

/// Client-side helper: connect to the daemon's control socket, send
/// a request, decode the reply. Matches the ospfd helper of the
/// same name.
pub async fn client_request(
    socket_path: &str,
    req: &ControlRequest,
) -> std::io::Result<ControlResponse> {
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let json = serde_json::to_string(req)
        .map_err(|e| std::io::Error::other(format!("encode: {}", e)))?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await?;

    if let Some(line) = lines.next_line().await? {
        serde_json::from_str::<ControlResponse>(&line)
            .map_err(|e| std::io::Error::other(format!("decode: {}", e)))
    } else {
        Err(std::io::Error::other("empty response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_with_snake_case_command() {
        let s = serde_json::to_string(&ControlRequest::Status).unwrap();
        assert_eq!(s, "{\"command\":\"status\"}");
        let s = serde_json::to_string(&ControlRequest::Interfaces).unwrap();
        assert_eq!(s, "{\"command\":\"interfaces\"}");
        let s = serde_json::to_string(&ControlRequest::Subnets).unwrap();
        assert_eq!(s, "{\"command\":\"subnets\"}");
    }

    #[test]
    fn subnets_reply_round_trip() {
        let r = ControlResponse::Subnets(SubnetsReply {
            subnets: vec![SubnetRow {
                subnet: "10.0.20.0/24".into(),
                pool_start: "10.0.20.100".into(),
                pool_end: "10.0.20.200".into(),
                gateway: "10.0.20.1".into(),
                lease_time: Some(7200),
                dns_servers: vec!["10.0.20.1".into()],
                domain_name: Some("v6only.example".into()),
                trust_relay: false,
                v6_only_preferred: Some(1800),
            }],
        });
        let s = serde_json::to_string(&r).unwrap();
        let back: ControlResponse = serde_json::from_str(&s).unwrap();
        match back {
            ControlResponse::Subnets(reply) => {
                assert_eq!(reply.subnets.len(), 1);
                assert_eq!(reply.subnets[0].v6_only_preferred, Some(1800));
            }
            other => panic!("expected Subnets, got {:?}", other),
        }
    }

    #[test]
    fn status_reply_round_trip() {
        let r = ControlResponse::Status(StatusReply {
            version: "0.1.0".into(),
            v4_enabled: true,
            v6_enabled: false,
            v4_interface_count: 1,
            v4_relay_interface_count: 0,
            v6_interface_count: 0,
            pd_pool_count: 0,
            reservation_count: 0,
            control_socket: "/run/dhcpd.sock".into(),
        });
        let s = serde_json::to_string(&r).unwrap();
        let back: ControlResponse = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ControlResponse::Status(_)));
    }
}
