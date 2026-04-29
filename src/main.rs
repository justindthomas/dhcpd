//! dhcpd — DHCPv4 + DHCPv6 with VPP punt integration.
//!
//! Phase 2: DHCPv4 is live. Phase 3 will add v6. Pipeline:
//!
//! ```text
//! VPP punt socket (UDP/67)
//!   → PuntIo::recv_v4
//!   → V4Server::on_rx   (parse, FSM, commit lease)
//!   → PuntIo::send_v4   (PUNT_L2 or PUNT_IP4_ROUTED)
//!   → client
//! ```
//!
//! Usage:
//!   dhcpd --config /etc/dhcpd/config.yaml
//!   dhcpd query status
//!   dhcpd query interfaces
//!   dhcpd query leases
//!   dhcpd query pools
//!   dhcpd query release-lease --client-id aa:bb:cc:dd:ee:ff

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use dhcpd::config::{DhcpdConfig, DhcpdV6Config, InterfaceV4Config};
use dhcpd::io::IoInterface;
use dhcpd::control::{
    self, ControlRequest, ControlResponse, ControlSnapshot, DEFAULT_CONTROL_SOCKET,
};
use dhcpd::io_punt::{self, PuntIo};
use dhcpd::lease::{journal6, LeaseStoreV4, LeaseStoreV6};
use dhcpd::v4::server::V4Server;
use dhcpd::v6::route_installer;
use dhcpd::v6::server::V6Server;
use dhcpd::vpp_iface;

const DEFAULT_LEASE_DB: &str = "/var/lib/dhcpd";

enum Command {
    Run(RunArgs),
    Query(QueryArgs),
}

struct RunArgs {
    config_path: PathBuf,
    vpp_api_socket: String,
    control_socket: String,
    lease_db: PathBuf,
    io_backend: IoBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IoBackend {
    Punt,
    Raw,
}

struct QueryArgs {
    control_socket: String,
    request: ControlRequest,
    output: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!("Usage:");
    eprintln!(
        "  dhcpd [--config PATH] [--vpp-api SOCKET] [--control-socket PATH] \
         [--lease-db DIR] [--io punt|raw]"
    );
    eprintln!(
        "  dhcpd query <status|interfaces|leases|pools|subnets|release-lease> \
         [-o text|json] [--control-socket PATH] [--client-id MAC]"
    );
    std::process::exit(code);
}

fn parse_args() -> Command {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        print_usage_and_exit(1);
    }
    let mut args = raw.into_iter().peekable();
    if let Some(first) = args.peek() {
        if first == "query" {
            args.next();
            return Command::Query(parse_query_args(args));
        }
    }
    let mut run = RunArgs {
        config_path: PathBuf::from("/etc/dhcpd/config.yaml"),
        vpp_api_socket: vpp_api::client::DEFAULT_API_SOCKET.to_string(),
        control_socket: DEFAULT_CONTROL_SOCKET.to_string(),
        lease_db: PathBuf::from(DEFAULT_LEASE_DB),
        io_backend: IoBackend::Punt,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                run.config_path = PathBuf::from(args.next().expect("--config requires a path"));
            }
            "--vpp-api" => {
                run.vpp_api_socket = args.next().expect("--vpp-api requires a socket path");
            }
            "--control-socket" => {
                run.control_socket = args.next().expect("--control-socket requires a path");
            }
            "--lease-db" => {
                run.lease_db = PathBuf::from(args.next().expect("--lease-db requires a path"));
            }
            "--io" => {
                let v = args.next().expect("--io requires 'punt' or 'raw'");
                run.io_backend = match v.as_str() {
                    "punt" => IoBackend::Punt,
                    "raw" => IoBackend::Raw,
                    other => {
                        eprintln!("Unknown --io value: {} (expected punt|raw)", other);
                        print_usage_and_exit(1);
                    }
                };
            }
            "--help" | "-h" => print_usage_and_exit(0),
            other => {
                eprintln!("Unknown argument: {}", other);
                print_usage_and_exit(1);
            }
        }
    }
    Command::Run(run)
}

fn parse_query_args<I: Iterator<Item = String>>(mut args: I) -> QueryArgs {
    let subject = args.next().unwrap_or_else(|| {
        eprintln!(
            "query requires a subject (status, interfaces, leases, pools, subnets, release-lease)"
        );
        print_usage_and_exit(1);
    });

    let mut control_socket = DEFAULT_CONTROL_SOCKET.to_string();
    let mut client_id: Option<String> = None;
    let mut output = OutputFormat::Text;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--control-socket" => {
                control_socket = args.next().expect("--control-socket requires a path");
            }
            "--client-id" => {
                client_id = Some(args.next().expect("--client-id requires a value"));
            }
            "-o" | "--output" => {
                let v = args.next().expect("-o/--output requires 'text' or 'json'");
                output = match v.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    other => {
                        eprintln!("Unknown output format: {} (expected text|json)", other);
                        print_usage_and_exit(1);
                    }
                };
            }
            other => {
                eprintln!("Unknown query argument: {}", other);
                print_usage_and_exit(1);
            }
        }
    }

    let request = match subject.as_str() {
        "status" => ControlRequest::Status,
        "interfaces" => ControlRequest::Interfaces,
        "leases" => ControlRequest::Leases,
        "leases6" => ControlRequest::Leases6,
        "pools" => ControlRequest::Pools,
        "subnets" => ControlRequest::Subnets,
        "release-lease" => {
            let cid = client_id.unwrap_or_else(|| {
                eprintln!("release-lease requires --client-id");
                print_usage_and_exit(1);
            });
            ControlRequest::ReleaseLease { client_id: cid }
        }
        other => {
            eprintln!("Unknown query subject: {}", other);
            print_usage_and_exit(1);
        }
    };

    QueryArgs {
        control_socket,
        request,
        output,
    }
}

fn acquire_instance_lock(control_socket: &str) -> anyhow::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let lock_path = format!("{}.lock", control_socket);
    if let Some(parent) = std::path::Path::new(&lock_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o644)
        .open(&lock_path)
        .map_err(|e| anyhow::anyhow!("failed to open lock file {}: {}", lock_path, e))?;

    let fd = lock_file.as_raw_fd();
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            anyhow::bail!(
                "another dhcpd is already running (lock {} held). \
                 For queries against a live daemon use `dhcpd query ...` instead.",
                lock_path
            );
        }
        anyhow::bail!("flock({}): {}", lock_path, err);
    }

    use std::io::{Seek, SeekFrom, Write};
    let mut f = lock_file;
    f.seek(SeekFrom::Start(0)).ok();
    let _ = f.set_len(0);
    writeln!(&mut f, "{}", std::process::id()).ok();
    f.flush().ok();
    Ok(f)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    match parse_args() {
        Command::Run(args) => run_daemon(args).await,
        Command::Query(args) => run_query(args).await,
    }
}

async fn run_query(args: QueryArgs) -> anyhow::Result<()> {
    let response = control::client_request(&args.control_socket, &args.request)
        .await
        .map_err(|e| anyhow::anyhow!("control request failed: {}", e))?;
    match args.output {
        OutputFormat::Text => print_response(&response),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n - 1])
    }
}

/// Peek a DHCPv6 datagram to determine whether it's a relayed
/// message. Used so the TX path can pick the correct destination
/// port without re-parsing the full message. Returns false on any
/// decode error — the FSM's output of that RX will be Silent anyway.
fn peek_is_relayed(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    // RelayForw = 12.
    buf[0] == 12
}


fn print_response(resp: &ControlResponse) {
    match resp {
        ControlResponse::Status(s) => {
            println!("Version:               {}", s.version);
            println!("DHCPv4 enabled:        {}", s.v4_enabled);
            println!("DHCPv6 enabled:        {}", s.v6_enabled);
            let v4_total = s.v4_interface_count + s.v4_relay_interface_count;
            println!(
                "DHCPv4 interfaces:     {} ({} direct, {} relay)",
                v4_total, s.v4_interface_count, s.v4_relay_interface_count
            );
            println!("DHCPv6 interfaces:     {}", s.v6_interface_count);
            println!("PD pools:              {}", s.pd_pool_count);
            println!("Reservations:          {}", s.reservation_count);
            println!("Control socket:        {}", s.control_socket);
        }
        ControlResponse::Interfaces(r) => {
            if r.interfaces.is_empty() {
                println!("No DHCP interfaces.");
                return;
            }
            println!(
                "{:<12} {:<4} {:<17} {:<18} {:<28} {:<8} {:<10} {}",
                "Name", "idx", "MAC", "IPv4", "Pool", "PD", "V6Only", "LinkLocal"
            );
            for i in &r.interfaces {
                let addr = i
                    .ipv4_address
                    .as_ref()
                    .map(|a| format!("{}/{}", a, i.ipv4_prefix_len))
                    .unwrap_or_else(|| "-".into());
                let pool = match (&i.v4_pool, i.v4_relay_ingress) {
                    (Some(p), _) => format!("{}..{}", p.start, p.end),
                    (None, true) => "(relay ingress)".into(),
                    (None, false) => "-".into(),
                };
                let pd = i.v6_pd_pool.clone().unwrap_or_else(|| "-".into());
                let v6only = i
                    .v6_only_preferred
                    .map(|s| format!("{}s", s))
                    .unwrap_or_else(|| "-".into());
                let ll = i.ipv6_link_local.clone().unwrap_or_else(|| "-".into());
                println!(
                    "{:<12} {:<4} {:<17} {:<18} {:<28} {:<8} {:<10} {}",
                    i.name, i.sw_if_index, i.mac_address, addr, pool, pd, v6only, ll
                );
            }
        }
        ControlResponse::Subnets(r) => {
            if r.subnets.is_empty() {
                println!("No subnets.");
                return;
            }
            println!(
                "{:<18} {:<16} {:<16} {:<14} {:<8} {:<6} {:<8} {}",
                "Subnet", "Pool start", "Pool end", "Gateway", "Lease", "Trust", "V6Only", "DNS"
            );
            for s in &r.subnets {
                let lease = s
                    .lease_time
                    .map(|t| format!("{}s", t))
                    .unwrap_or_else(|| "-".into());
                let v6only = s
                    .v6_only_preferred
                    .map(|t| format!("{}s", t))
                    .unwrap_or_else(|| "-".into());
                let dns = if s.dns_servers.is_empty() {
                    "-".into()
                } else {
                    s.dns_servers.join(",")
                };
                println!(
                    "{:<18} {:<16} {:<16} {:<14} {:<8} {:<6} {:<8} {}",
                    s.subnet,
                    s.pool_start,
                    s.pool_end,
                    s.gateway,
                    lease,
                    if s.trust_relay { "yes" } else { "no" },
                    v6only,
                    dns,
                );
            }
        }
        ControlResponse::Leases(r) => {
            if r.leases.is_empty() {
                println!("No leases.");
                return;
            }
            println!(
                "{:<22} {:<16} {:<17} {:<12} {:<10} {}",
                "Client-ID", "IP", "MAC", "State", "Expires", "Hostname"
            );
            for l in &r.leases {
                let expires_in = l.expires_unix as i64
                    - std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0) as i64;
                println!(
                    "{:<22} {:<16} {:<17} {:<12} {:<10} {}",
                    l.client_id,
                    l.ip,
                    l.mac,
                    l.state,
                    format!("{}s", expires_in),
                    l.hostname.as_deref().unwrap_or("-")
                );
            }
        }
        ControlResponse::Pools(r) => {
            if r.pools.is_empty() {
                println!("No pools.");
                return;
            }
            println!(
                "{:<12} {:<16} {:<16} {:<6} {:<6} {}",
                "Interface", "Pool start", "Pool end", "Total", "Used", "Free"
            );
            for p in &r.pools {
                println!(
                    "{:<12} {:<16} {:<16} {:<6} {:<6} {}",
                    p.interface, p.start, p.end, p.total, p.used, p.free
                );
            }
        }
        ControlResponse::ReleaseLease(r) => {
            if r.ok {
                println!("OK: {}", r.message);
            } else {
                eprintln!("error: {}", r.message);
                std::process::exit(1);
            }
        }
        ControlResponse::Leases6(r) => {
            if r.leases.is_empty() {
                println!("No v6 leases.");
                return;
            }
            println!(
                "{:<32} {:<10} {:<4} {:<40} {:<10} {:<6} {}",
                "DUID", "Kind", "IAID", "Address", "State", "Relay", "Pref/Valid"
            );
            for l in &r.leases {
                println!(
                    "{:<32} {:<10} {:<4} {:<40} {:<10} {:<6} {}/{}",
                    truncate(&l.duid, 30),
                    l.kind,
                    l.iaid,
                    format!("{}/{}", l.address, l.prefix_len),
                    l.state,
                    if l.via_relay { "yes" } else { "no" },
                    l.preferred_lifetime,
                    l.valid_lifetime,
                );
            }
        }
        ControlResponse::Error { error } => {
            eprintln!("error: {}", error);
            std::process::exit(1);
        }
    }
}

async fn run_daemon(args: RunArgs) -> anyhow::Result<()> {
    // Honour NO_COLOR — keeps ANSI escapes out of impd-captured
    // stderr → journald.
    tracing_subscriber::fmt()
        .with_ansi(std::env::var_os("NO_COLOR").is_none())
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,dhcpd=info")),
        )
        .init();

    tracing::info!(
        config = %args.config_path.display(),
        vpp_api = %args.vpp_api_socket,
        control = %args.control_socket,
        lease_db = %args.lease_db.display(),
        io = ?args.io_backend,
        "dhcpd starting"
    );

    let _lock = acquire_instance_lock(&args.control_socket)?;

    std::fs::create_dir_all(&args.lease_db).map_err(|e| {
        anyhow::anyhow!(
            "failed to create lease-db {}: {}",
            args.lease_db.display(),
            e
        )
    })?;

    // Load config.
    let v4_cfg = DhcpdConfig::load(&args.config_path)
        .map_err(|e| anyhow::anyhow!("load v4 config: {}", e))?;
    let v6_cfg = DhcpdV6Config::load(&args.config_path)
        .map_err(|e| anyhow::anyhow!("load v6 config: {}", e))?;
    if v4_cfg.is_none() && v6_cfg.is_none() {
        anyhow::bail!(
            "neither dhcp_server.enabled nor dhcp6_server.enabled is true in {}",
            args.config_path.display()
        );
    }
    if let Some(v4) = &v4_cfg {
        tracing::info!(
            interfaces = v4.interfaces.len(),
            reservations = v4.reservations.len(),
            "loaded DHCPv4 config"
        );
    }
    if let Some(v6) = &v6_cfg {
        tracing::info!(
            interfaces = v6.interfaces.len(),
            pd_pools = v6.pd_pools.len(),
            "loaded DHCPv6 config"
        );
    }

    // Collect interface names we want to serve. Sources, in order:
    //   1. `interfaces[].dhcp_server_enabled: true` — full per-interface
    //      config (pool_start, pool_end, etc.) for direct-broadcast.
    //   2. `dhcp_server.interfaces: [name, ...]` — ingress-only opt-in
    //      for relay-landing (pool comes from `dhcp_server.subnets[]`).
    //   3. Mirror of the above two for DHCPv6.
    // An empty combined list is a configuration error — dhcpd can
    // only serve DHCP on interfaces it's been explicitly pointed at.
    let mut wanted_names: Vec<String> = Vec::new();
    if let Some(v4) = &v4_cfg {
        for i in &v4.interfaces {
            if !wanted_names.contains(&i.name) {
                wanted_names.push(i.name.clone());
            }
        }
        for n in &v4.enabled_interfaces {
            if !wanted_names.contains(n) {
                wanted_names.push(n.clone());
            }
        }
    }
    if let Some(v6) = &v6_cfg {
        for i in &v6.interfaces {
            if !wanted_names.contains(&i.name) {
                wanted_names.push(i.name.clone());
            }
        }
    }
    if wanted_names.is_empty() {
        anyhow::bail!(
            "no DHCP-serving interfaces: enable via `dhcp_server.interfaces: [...]` \
             or per-interface `dhcp_server_enabled: true`"
        );
    }

    // Connect to VPP + discover interfaces.
    tracing::info!(socket = %args.vpp_api_socket, "connecting to VPP");
    let vpp = vpp_api::VppClient::connect(&args.vpp_api_socket)
        .await
        .map_err(|e| anyhow::anyhow!("connect to VPP {}: {}", args.vpp_api_socket, e))?;
    let interfaces = vpp_iface::discover(&vpp, &wanted_names).await?;
    if interfaces.is_empty() {
        anyhow::bail!(
            "none of the configured DHCP interfaces ({:?}) are admin-up in VPP",
            wanted_names
        );
    }
    for i in &interfaces {
        tracing::info!(
            iface = i.name.as_str(),
            sw_if_index = i.sw_if_index,
            v4 = ?i.ipv4_address,
            "discovered DHCP interface"
        );
    }

    // Register punt sockets.
    let punt_io = if args.io_backend == IoBackend::Punt {
        let runtime_dir = std::path::Path::new(&args.control_socket)
            .parent()
            .map(|p| p.join("dhcpd"))
            .unwrap_or_else(|| std::path::PathBuf::from("/run/dhcpd"));
        let _ = std::fs::create_dir_all(&runtime_dir);
        let v4_client = runtime_dir.join("punt-v4.sock");
        let v6_client = if v6_cfg.is_some() {
            Some(runtime_dir.join("punt-v6.sock"))
        } else {
            None
        };
        let _ = std::fs::remove_file(&v4_client);
        if let Some(p) = &v6_client {
            let _ = std::fs::remove_file(p);
        }
        let reg = io_punt::register(
            &vpp,
            v4_client.to_str().unwrap(),
            v6_client.as_deref().and_then(|p| p.to_str()),
        )
        .await?;
        let mut io = PuntIo::open_v4(
            interfaces.clone(),
            v4_client.to_str().unwrap(),
            reg.v4_server_path.clone(),
        )
        .map_err(|e| anyhow::anyhow!("open v4 punt io: {}", e))?;
        if let (Some(client), Some(server)) = (v6_client.as_ref(), reg.v6_server_path.as_ref()) {
            io.attach_v6(client.to_str().unwrap(), server.clone())
                .map_err(|e| anyhow::anyhow!("attach v6 punt io: {}", e))?;
        }
        Some((io, reg))
    } else {
        tracing::warn!(
            "--io raw selected; this backend is not yet implemented. Use --io punt."
        );
        None
    };

    // Build the v4 server (if v4 is enabled).
    //
    // Interface opt-in: an interface serves DHCPv4 if EITHER
    //   (a) there's an explicit `interfaces[].dhcp_server_enabled:
    //       true` entry with a full per-interface pool config
    //       (direct-broadcast serving on its own subnet), OR
    //   (b) its name is listed in `dhcp_server.interfaces: [...]`
    //       (relay-landing / ingress-only opt-in — pool comes from
    //       `dhcp_server.subnets[]` via giaddr lookup).
    // Interfaces not opted in are IGNORED — ingress DHCP on them is
    // dropped. This is the safe default; operators must opt in
    // explicitly per interface to avoid leasing addresses on an
    // unintended VLAN.
    let v4_server = if let Some(v4_cfg) = &v4_cfg {
        let mut iface_map = HashMap::new();
        for iface in &interfaces {
            // (a) Explicit per-interface config with pool.
            if let Some(cfg) = v4_cfg.interfaces.iter().find(|c| c.name == iface.name) {
                iface_map.insert(iface.sw_if_index, cfg.clone());
                continue;
            }
            // (b) Ingress-only opt-in for relay landing.
            if v4_cfg.enabled_interfaces.iter().any(|n| n == &iface.name) {
                let Some(addr) = iface.ipv4_address else {
                    tracing::warn!(
                        iface = iface.name.as_str(),
                        "dhcp_server.interfaces lists an interface with no IPv4 address; skipping"
                    );
                    continue;
                };
                iface_map.insert(
                    iface.sw_if_index,
                    dhcpd::config::InterfaceV4Config {
                        name: iface.name.clone(),
                        address: addr,
                        prefix_len: iface.ipv4_prefix_len,
                        // Empty pool — direct-broadcast allocation is
                        // blocked here. The FSM's subnet-match handles
                        // giaddr-relayed DISCOVERs via `subnets[]`.
                        pool_start: Ipv4Addr::BROADCAST,
                        pool_end: Ipv4Addr::UNSPECIFIED,
                        gateway: addr,
                        lease_time: None,
                        dns_servers: vec![],
                        domain_name: None,
                        trust_relay: false,
                    },
                );
            }
        }
        let store = LeaseStoreV4::open(&args.lease_db)
            .map_err(|e| anyhow::anyhow!("open lease store: {}", e))?;
        let server = V4Server::new(store, v4_cfg.clone(), iface_map);
        Some(Arc::new(Mutex::new(server)))
    } else {
        None
    };

    // Build the v6 server (if v6 is enabled).
    let v6_server = if let Some(v6_cfg) = &v6_cfg {
        let mut iface_map = HashMap::new();
        let mut first_mac: Option<[u8; 6]> = None;
        for iface in &interfaces {
            if let Some(cfg) = v6_cfg.interfaces.iter().find(|c| c.name == iface.name) {
                iface_map.insert(iface.sw_if_index, cfg.clone());
                if first_mac.is_none() {
                    first_mac = Some(iface.mac_address);
                }
            }
        }
        let store = LeaseStoreV6::open(&args.lease_db)
            .map_err(|e| anyhow::anyhow!("open v6 lease store: {}", e))?;
        let mac = first_mac.ok_or_else(|| {
            anyhow::anyhow!("no v6-serving interface has a MAC — cannot build server DUID")
        })?;
        let server_duid = journal6::load_or_generate_server_duid(
            &args.lease_db,
            1, // ethernet hw type
            mac,
            std::time::SystemTime::now(),
        )?;
        tracing::info!(duid = %server_duid.pretty(), "v6 server DUID ready");
        let mut server = V6Server::new(store, v6_cfg.clone(), iface_map, server_duid);
        if v6_cfg.install_pd_routes {
            let tx = route_installer::spawn(route_installer::DEFAULT_RIB_SOCKET);
            server = server.with_pd_installer(tx);
            tracing::info!(
                rib = route_installer::DEFAULT_RIB_SOCKET,
                "PD route installer spawned"
            );
        }
        Some(Arc::new(Mutex::new(server)))
    } else {
        None
    };

    // Build the control snapshot (includes a ref to v4 server).
    let snapshot = Arc::new(Mutex::new(ControlSnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        v4_enabled: v4_cfg.is_some(),
        v6_enabled: v6_cfg.is_some(),
        interfaces: interfaces.clone(),
        v4_iface_configs: v4_cfg
            .as_ref()
            .map(|c| c.interfaces.clone())
            .unwrap_or_default(),
        v4_subnets: v4_cfg
            .as_ref()
            .map(|c| c.subnets.clone())
            .unwrap_or_default(),
        v4_relay_interface_names: v4_cfg
            .as_ref()
            .map(|c| c.enabled_interfaces.clone())
            .unwrap_or_default(),
        v6_iface_configs: v6_cfg
            .as_ref()
            .map(|c| c.interfaces.clone())
            .unwrap_or_default(),
        pd_pool_count: v6_cfg.as_ref().map(|c| c.pd_pools.len()).unwrap_or(0),
        reservation_count: v4_cfg.as_ref().map(|c| c.reservations.len()).unwrap_or(0),
        control_socket: args.control_socket.clone(),
        v4_server: v4_server.clone(),
        v6_server: v6_server.clone(),
    }));

    let control_handle = control::serve(&args.control_socket, snapshot.clone())
        .await
        .map_err(|e| anyhow::anyhow!("control socket bind: {}", e))?;

    tracing::info!("dhcpd ready; awaiting DHCP packets");

    // Main select loop.
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("install SIGTERM handler: {}", e))?;
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| anyhow::anyhow!("install SIGINT handler: {}", e))?;
    let mut sighup = signal(SignalKind::hangup())
        .map_err(|e| anyhow::anyhow!("install SIGHUP handler: {}", e))?;

    let mut punt_io = punt_io;
    // Split receivers off the PuntIo so they can be awaited
    // independently of the TX-owning PuntIo (single-mutable-borrow
    // constraint).
    let (mut rx_v4, mut rx_v6_opt) = match punt_io.as_mut() {
        Some((io, _)) => (Some(io.take_rx_v4()), io.take_rx_v6()),
        None => (None, None),
    };

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, shutting down");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received, shutting down");
                break;
            }
            maybe_rx = async {
                match rx_v4.as_mut() {
                    Some(r) => r.recv().await,
                    None => std::future::pending().await,
                }
            }, if rx_v4.is_some() => {
                let Some(rx) = maybe_rx else {
                    tracing::warn!("v4 punt rx channel closed; shutting down");
                    break;
                };
                if let Some(srv) = v4_server.as_ref() {
                    let mut srv = srv.lock().await;
                    match srv.on_rx(&rx) {
                        Ok(Some(tx)) => {
                            if let Some((io, _)) = punt_io.as_ref() {
                                if let Err(e) = io.send_v4(&tx) {
                                    tracing::warn!(error = %e, "v4 punt send failed");
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "v4 FSM error");
                        }
                    }
                }
            }
            maybe_rx6 = async {
                match rx_v6_opt.as_mut() {
                    Some(r) => r.recv().await,
                    None => std::future::pending().await,
                }
            }, if rx_v6_opt.is_some() => {
                let Some(rx) = maybe_rx6 else {
                    tracing::warn!("v6 punt rx channel closed; shutting down");
                    break;
                };
                if let Some(srv) = v6_server.as_ref() {
                    let is_relay = peek_is_relayed(&rx.payload);
                    let mut srv = srv.lock().await;
                    match srv.on_rx(&rx) {
                        Ok(Some(tx)) => {
                            if let Some((io, _)) = punt_io.as_ref() {
                                if let Err(e) = io.send_v6(&tx, is_relay) {
                                    tracing::warn!(error = %e, "v6 punt send failed");
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "v6 FSM error");
                        }
                    }
                }
            }
            _ = sighup.recv() => {
                tracing::info!(
                    path = %args.config_path.display(),
                    "SIGHUP: reloading config"
                );
                reload_config(
                    &args.config_path,
                    &interfaces,
                    v4_server.as_ref(),
                    v6_server.as_ref(),
                    &snapshot,
                )
                .await;
            }
        }
    }

    // Cleanup.
    control_handle.abort();
    if let Some((_, reg)) = &punt_io {
        io_punt::deregister(&vpp, reg).await;
    }
    let _ = std::fs::remove_file(&args.control_socket);

    Ok(())
}

/// Re-read the YAML config and hot-apply pool / reservation /
/// subnet / per-interface changes to the live V4/V6 servers
/// without dropping in-memory lease state. Called from the main
/// loop's SIGHUP branch.
///
/// Out of scope for hot-reload (logged as "restart required"):
/// - toggling `dhcp_server.enabled` / `dhcp6_server.enabled`
///   (would require spinning up punt sockets, lease store, DUID)
/// - adding or removing serving interfaces (would require
///   re-discovering from VPP and rebuilding iface maps against new
///   sw_if_index values — restart is the safer path)
/// - toggling `install_pd_routes` (would require spawning or
///   tearing down the route-installer task)
async fn reload_config(
    config_path: &std::path::Path,
    interfaces: &[IoInterface],
    v4_server: Option<&Arc<Mutex<V4Server>>>,
    v6_server: Option<&Arc<Mutex<V6Server>>>,
    snapshot: &Arc<Mutex<ControlSnapshot>>,
) {
    let new_v4 = match DhcpdConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "reload failed: v4 config parse; keeping prior config");
            return;
        }
    };
    let new_v6 = match DhcpdV6Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "reload failed: v6 config parse; keeping prior config");
            return;
        }
    };

    // v4 reload
    if let Some(srv) = v4_server {
        let mut server = srv.lock().await;
        match &new_v4 {
            Some(v4_cfg) => {
                // Build the same iface_map that startup does: first
                // from per-interface pool entries, then from the
                // relay-ingress opt-in list.
                let mut iface_map = HashMap::new();
                for iface in interfaces {
                    if let Some(cfg) = v4_cfg.interfaces.iter().find(|c| c.name == iface.name) {
                        iface_map.insert(iface.sw_if_index, cfg.clone());
                        continue;
                    }
                    if v4_cfg.enabled_interfaces.iter().any(|n| n == &iface.name) {
                        let Some(addr) = iface.ipv4_address else {
                            continue;
                        };
                        iface_map.insert(
                            iface.sw_if_index,
                            InterfaceV4Config {
                                name: iface.name.clone(),
                                address: addr,
                                prefix_len: iface.ipv4_prefix_len,
                                pool_start: Ipv4Addr::BROADCAST,
                                pool_end: Ipv4Addr::UNSPECIFIED,
                                gateway: addr,
                                lease_time: None,
                                dns_servers: vec![],
                                domain_name: None,
                                trust_relay: false,
                            },
                        );
                    }
                }
                let prev_iface_count = server.interfaces.len();
                server.global = v4_cfg.clone();
                server.interfaces = iface_map;
                tracing::info!(
                    prev_ifaces = prev_iface_count,
                    new_ifaces = server.interfaces.len(),
                    reservations = v4_cfg.reservations.len(),
                    "v4 reload applied"
                );
            }
            None => {
                tracing::warn!(
                    "reload: dhcp_server block missing/disabled in new config, \
                     but v4 was running — restart required to fully stop"
                );
            }
        }
    } else if new_v4.is_some() {
        tracing::warn!(
            "reload: dhcp_server is enabled in new config but was off at startup — \
             restart required to bring v4 online"
        );
    }

    // v6 reload — preserve server_duid (persistent identity) and
    // pd_event_tx (route installer channel).
    if let Some(srv) = v6_server {
        let mut server = srv.lock().await;
        match &new_v6 {
            Some(v6_cfg) => {
                let mut iface_map = HashMap::new();
                for iface in interfaces {
                    if let Some(cfg) = v6_cfg.interfaces.iter().find(|c| c.name == iface.name) {
                        iface_map.insert(iface.sw_if_index, cfg.clone());
                    }
                }
                let prev_install_pd = server.global.install_pd_routes;
                if prev_install_pd != v6_cfg.install_pd_routes {
                    tracing::warn!(
                        old = prev_install_pd,
                        new = v6_cfg.install_pd_routes,
                        "reload: install_pd_routes change requires restart; ignoring"
                    );
                }
                let prev_iface_count = server.interfaces.len();
                server.global = v6_cfg.clone();
                server.interfaces = iface_map;
                tracing::info!(
                    prev_ifaces = prev_iface_count,
                    new_ifaces = server.interfaces.len(),
                    pd_pools = v6_cfg.pd_pools.len(),
                    "v6 reload applied"
                );
            }
            None => {
                tracing::warn!(
                    "reload: dhcp6_server block missing/disabled in new config, \
                     but v6 was running — restart required to fully stop"
                );
            }
        }
    } else if new_v6.is_some() {
        tracing::warn!(
            "reload: dhcp6_server is enabled in new config but was off at startup — \
             restart required to bring v6 online"
        );
    }

    // Refresh the control snapshot's config-derived fields so
    // `dhcpd query status` / `interfaces` report post-reload state.
    {
        let mut s = snapshot.lock().await;
        s.v4_iface_configs = new_v4
            .as_ref()
            .map(|c| c.interfaces.clone())
            .unwrap_or_default();
        s.v4_subnets = new_v4
            .as_ref()
            .map(|c| c.subnets.clone())
            .unwrap_or_default();
        s.v4_relay_interface_names = new_v4
            .as_ref()
            .map(|c| c.enabled_interfaces.clone())
            .unwrap_or_default();
        s.v6_iface_configs = new_v6
            .as_ref()
            .map(|c| c.interfaces.clone())
            .unwrap_or_default();
        s.pd_pool_count = new_v6.as_ref().map(|c| c.pd_pools.len()).unwrap_or(0);
        s.reservation_count = new_v4.as_ref().map(|c| c.reservations.len()).unwrap_or(0);
    }
}
