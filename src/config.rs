//! DHCP daemon configuration — reads the DHCP-relevant fields from
//! `/etc/dhcpd/config.yaml`. We define our own minimal serde
//! structs for just the fields we need, matching the "partial
//! deserializer" pattern established by ospfd/config.rs.
//!
//! The schema intentionally uses `dhcp_server` / `dhcp6_server` /
//! `dhcp6_pd_pool` names, NOT `dhcp` / `dhcp6` / `dhcp6_pd` — the
//! latter describe the router as a *client* (WAN-side DHCP, PD
//! requestor) and have been in the tree for a while. The server
//! fields are disjoint to avoid any rename cascade.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;

/// Top-level router config — we only deserialize the fields we need.
#[derive(Debug, Default, Deserialize)]
pub struct RouterConfig {
    /// DHCPv4 server block. YAML key: `dhcp_server:` — disjoint from
    /// the per-interface `dhcp: true/false` client flag.
    #[serde(default)]
    pub dhcp_server: DhcpConfig,
    /// DHCPv6 server block. YAML key: `dhcp6_server:`.
    #[serde(default)]
    pub dhcp6_server: Dhcp6Config,
    #[serde(default)]
    pub interfaces: Vec<InterfaceConfig>,
    #[serde(default)]
    pub loopbacks: Vec<LoopbackConfig>,
}

/// Global DHCPv4 server config block.
///
/// Preferred configuration shape:
///
/// ```yaml
/// dhcp_server:
///   enabled: true
///   authoritative: true
///   default_lease_time: 86400
///   interfaces: [lan.110, bvi100]   # opt-in list (ingress/serving)
///   subnets:
///     - subnet: 192.168.20.0/24
///       pool_start: 192.168.20.100
///       pool_end:   192.168.20.199
///       gateway:    192.168.20.1
///       dns_servers: [8.8.8.8]
/// ```
///
/// Per-interface `dhcp_server_enabled: true` with inline
/// `dhcp_server_pool_start`/`_end`/etc. is DEPRECATED — it
/// still loads (with a warning), but operators should migrate
/// to the subnets-plus-opt-in form above.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct DhcpConfig {
    #[serde(default)]
    pub enabled: bool,
    pub default_lease_time: Option<u32>,
    pub max_lease_time: Option<u32>,
    #[serde(default)]
    pub authoritative: bool,
    #[serde(default)]
    pub global_dns_servers: Vec<String>,
    pub domain_name: Option<String>,
    #[serde(default)]
    pub reservations: Vec<Dhcp4Reservation>,
    /// Explicit subnet pools — used for relayed DHCPv4 (`giaddr != 0`).
    /// For direct-broadcast, per-interface `dhcp_server_*` fields
    /// still apply. FSM selects via `giaddr` (or Option 82 link-
    /// selection when `trust_relay=true`).
    #[serde(default)]
    pub subnets: Vec<Dhcp4SubnetRaw>,
    /// Names of VPP interfaces where DHCPv4 service is enabled.
    /// DHCP packets (ingress) are accepted only on listed interfaces;
    /// outbound replies may still egress anywhere (routing decides).
    /// Empty list = no interfaces serve DHCPv4. This is the "safe
    /// default" — operators must opt in explicitly per interface to
    /// avoid accidentally leasing addresses on an unintended VLAN.
    /// Matches VPP interface names (e.g. "loop100", "lan.110").
    #[serde(default)]
    pub interfaces: Vec<String>,
}

/// YAML shape for a subnet entry. Fields are strings at this layer;
/// parsing into `Subnet4` happens in `DhcpdConfig::load`.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Dhcp4SubnetRaw {
    pub subnet: String,       // CIDR
    pub pool_start: String,
    pub pool_end: String,
    #[serde(default)]
    pub gateway: Option<String>,  // defaults to first host IP of subnet
    #[serde(default)]
    pub lease_time: Option<u32>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub domain_name: Option<String>,
    #[serde(default)]
    pub trust_relay: bool,
    /// RFC 8925 V6ONLY_WAIT in seconds. When set, clients on this
    /// subnet that signal option 108 in their PRL receive a
    /// no-yiaddr DHCPOFFER carrying option 108 — they disable IPv4
    /// for the configured duration. Clients that do NOT request
    /// option 108 still get a normal IPv4 lease.
    #[serde(default)]
    pub v6_only_preferred: Option<u32>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Dhcp4Reservation {
    pub hw_address: String,
    pub ip_address: String,
    #[serde(default)]
    pub hostname: Option<String>,
}

/// Global DHCPv6 server config block.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Dhcp6Config {
    #[serde(default)]
    pub enabled: bool,
    pub preferred_lifetime: Option<u32>,
    pub valid_lifetime: Option<u32>,
    #[serde(default)]
    pub global_dns_servers: Vec<String>,
    #[serde(default)]
    pub domain_search: Vec<String>,
    #[serde(default)]
    pub pd_pools: Vec<Dhcp6PdPool>,
    /// Explicit subnet pools for relayed DHCPv6. FSM selects via
    /// the Relay-Forw `link-address`. Direct-path still uses the
    /// per-interface `dhcp6_server_*` fields.
    #[serde(default)]
    pub subnets: Vec<Dhcp6SubnetRaw>,
    /// When true, push a route for each PD delegation to ribd.
    /// Only applies to direct-path delegations — relayed
    /// delegations are expected to be routed by the relay (L3
    /// switch) and this flag is a no-op for them. Default false
    /// (operators opt in when deploying on a platform where the
    /// server IS the forwarding plane).
    #[serde(default)]
    pub install_pd_routes: bool,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Dhcp6SubnetRaw {
    pub subnet: String,       // CIDR
    pub pool_start: String,
    pub pool_end: String,
    #[serde(default)]
    pub preferred_lifetime: Option<u32>,
    #[serde(default)]
    pub valid_lifetime: Option<u32>,
}

/// A Prefix Delegation pool that per-interface configs can reference
/// by name.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Dhcp6PdPool {
    pub name: String,
    pub prefix: String,
    pub delegated_length: u8,
    pub preferred_lifetime: Option<u32>,
    pub valid_lifetime: Option<u32>,
}

/// An IPv4 address on a sub-interface.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Ipv4AddressConfig {
    pub address: String,
    pub prefix: u8,
}

/// An IPv4 address on a loopback (uses cidr field).
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Ipv4CidrConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub prefix: Option<u8>,
}

/// Sub-interface (DHCP-relevant fields).
#[derive(Debug, Default, Deserialize, Clone)]
pub struct InterfaceConfig {
    pub name: Option<String>,
    #[serde(default)]
    pub ipv4: Vec<Ipv4AddressConfig>,
    // DHCPv4 server — DEPRECATED (2026-04-17). These per-interface
    // pool fields duplicate `dhcp_server.subnets[]` + opt-in via
    // `dhcp_server.interfaces[]`. The legacy path still parses and
    // warns at load; new configs should use the composed form.
    pub dhcp_server_enabled: Option<bool>,
    pub dhcp_server_pool_start: Option<String>,
    pub dhcp_server_pool_end: Option<String>,
    pub dhcp_server_gateway: Option<String>,
    pub dhcp_server_lease_time: Option<u32>,
    #[serde(default)]
    pub dhcp_server_dns_servers: Vec<String>,
    pub dhcp_server_domain_name: Option<String>,
    #[serde(default)]
    pub dhcp_server_trust_relay: bool,
    // DHCPv6 server
    pub dhcp6_server_enabled: Option<bool>,
    pub dhcp6_server_pool_start: Option<String>,
    pub dhcp6_server_pool_end: Option<String>,
    pub dhcp6_server_pd_pool: Option<String>,
}

/// Loopback interface (DHCP-relevant fields — none today; loopbacks
/// don't serve DHCP, but we keep the type so the deserializer is
/// symmetric and future-proof for e.g. info-request-only listeners).
#[derive(Debug, Default, Deserialize, Clone)]
pub struct LoopbackConfig {
    pub name: Option<String>,
    #[serde(default)]
    pub ipv4: Vec<Ipv4CidrConfig>,
}

/// Parsed, validated per-interface DHCPv4 server configuration.
#[derive(Debug, Clone)]
pub struct InterfaceV4Config {
    pub name: String,
    /// First IPv4 address configured on the interface. Used as the
    /// default server-id, default gateway, and pool subnet anchor
    /// when the more specific fields below aren't set.
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub gateway: Ipv4Addr,
    /// Per-interface lease time override. `None` means fall through
    /// to `DhcpdConfig::default_lease_time`.
    pub lease_time: Option<u32>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    /// Whether Option 82 sub-option 5 link-selection is honored for
    /// subnet selection. Defaults false — RFC 3046 §2.1 "authorized
    /// agents only". Set true only for server-behind-relay topologies.
    pub trust_relay: bool,
}

/// Parsed, validated per-interface DHCPv6 server configuration.
#[derive(Debug, Clone)]
pub struct InterfaceV6Config {
    pub name: String,
    pub pool_start: Option<Ipv6Addr>,
    pub pool_end: Option<Ipv6Addr>,
    /// Name of the PD pool in [`DhcpdV6Config::pd_pools`] that this
    /// interface delegates from. `None` disables PD on this interface.
    pub pd_pool: Option<String>,
}

/// Parsed reservation entry.
#[derive(Debug, Clone)]
pub struct Reservation4 {
    pub hw_address: [u8; 6],
    pub ip_address: Ipv4Addr,
    pub hostname: Option<String>,
}

/// Parsed PD pool entry.
#[derive(Debug, Clone)]
pub struct ParsedPdPool {
    pub name: String,
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub delegated_length: u8,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}

/// A parsed relay-capable subnet entry for DHCPv4. Carries the
/// subnet CIDR plus the same reply-options fields an
/// [`InterfaceV4Config`] holds, so a relayed DISCOVER can be
/// answered without an interface on the client's subnet.
#[derive(Debug, Clone)]
pub struct Subnet4 {
    pub subnet: Ipv4Net,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub lease_time: Option<u32>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub trust_relay: bool,
    /// RFC 8925 V6ONLY_WAIT in seconds for clients on this subnet
    /// that signal option 108 in their PRL. `None` disables the
    /// behavior; clients always get a normal v4 lease.
    pub v6_only_preferred: Option<u32>,
}

/// A parsed subnet entry for DHCPv6.
#[derive(Debug, Clone)]
pub struct Subnet6 {
    pub subnet: Ipv6Net,
    pub pool_start: Ipv6Addr,
    pub pool_end: Ipv6Addr,
    pub preferred_lifetime: Option<u32>,
    pub valid_lifetime: Option<u32>,
}

/// Abstracted "pool source" — either a direct-broadcast interface
/// or an explicit relay-subnet entry. The FSM and allocator work
/// uniformly against this view.
#[derive(Debug, Clone)]
pub enum PoolSource4<'a> {
    Interface(&'a InterfaceV4Config),
    Subnet(&'a Subnet4),
}

impl<'a> PoolSource4<'a> {
    pub fn pool_start(&self) -> Ipv4Addr {
        match self {
            PoolSource4::Interface(i) => i.pool_start,
            PoolSource4::Subnet(s) => s.pool_start,
        }
    }
    pub fn pool_end(&self) -> Ipv4Addr {
        match self {
            PoolSource4::Interface(i) => i.pool_end,
            PoolSource4::Subnet(s) => s.pool_end,
        }
    }
    pub fn gateway(&self) -> Ipv4Addr {
        match self {
            PoolSource4::Interface(i) => i.gateway,
            PoolSource4::Subnet(s) => s.gateway,
        }
    }
    pub fn prefix_len(&self) -> u8 {
        match self {
            PoolSource4::Interface(i) => i.prefix_len,
            PoolSource4::Subnet(s) => s.subnet.prefix_len(),
        }
    }
    pub fn lease_time(&self) -> Option<u32> {
        match self {
            PoolSource4::Interface(i) => i.lease_time,
            PoolSource4::Subnet(s) => s.lease_time,
        }
    }
    pub fn dns_servers(&self) -> &[Ipv4Addr] {
        match self {
            PoolSource4::Interface(i) => &i.dns_servers,
            PoolSource4::Subnet(s) => &s.dns_servers,
        }
    }
    pub fn domain_name(&self) -> Option<&str> {
        match self {
            PoolSource4::Interface(i) => i.domain_name.as_deref(),
            PoolSource4::Subnet(s) => s.domain_name.as_deref(),
        }
    }
    pub fn trust_relay(&self) -> bool {
        match self {
            PoolSource4::Interface(i) => i.trust_relay,
            PoolSource4::Subnet(s) => s.trust_relay,
        }
    }
    /// A descriptive label for logs.
    pub fn label(&self) -> String {
        match self {
            PoolSource4::Interface(i) => format!("iface:{}", i.name),
            PoolSource4::Subnet(s) => format!("subnet:{}", s.subnet),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PoolSource6<'a> {
    Interface(&'a InterfaceV6Config),
    Subnet(&'a Subnet6),
}

impl<'a> PoolSource6<'a> {
    pub fn pool_start(&self) -> Option<Ipv6Addr> {
        match self {
            PoolSource6::Interface(i) => i.pool_start,
            PoolSource6::Subnet(s) => Some(s.pool_start),
        }
    }
    pub fn pool_end(&self) -> Option<Ipv6Addr> {
        match self {
            PoolSource6::Interface(i) => i.pool_end,
            PoolSource6::Subnet(s) => Some(s.pool_end),
        }
    }
    pub fn preferred_lifetime(&self) -> Option<u32> {
        match self {
            PoolSource6::Interface(_) => None,
            PoolSource6::Subnet(s) => s.preferred_lifetime,
        }
    }
    pub fn valid_lifetime(&self) -> Option<u32> {
        match self {
            PoolSource6::Interface(_) => None,
            PoolSource6::Subnet(s) => s.valid_lifetime,
        }
    }
    pub fn label(&self) -> String {
        match self {
            PoolSource6::Interface(i) => format!("iface:{}", i.name),
            PoolSource6::Subnet(s) => format!("subnet:{}", s.subnet),
        }
    }
}

/// Parsed, validated DHCPv4 daemon configuration.
#[derive(Debug, Clone)]
pub struct DhcpdConfig {
    pub default_lease_time: u32,
    pub max_lease_time: u32,
    pub authoritative: bool,
    pub global_dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub reservations: Vec<Reservation4>,
    pub interfaces: Vec<InterfaceV4Config>,
    pub subnets: Vec<Subnet4>,
    /// Names of VPP interfaces opted into DHCPv4 service via
    /// `dhcp_server.interfaces: [...]`. Interfaces NOT in this list
    /// (and not in `interfaces` above) are ignored — ingress DHCP
    /// on them is dropped. Empty list = no relay-mode opt-in.
    pub enabled_interfaces: Vec<String>,
}

/// Parsed, validated DHCPv6 daemon configuration.
#[derive(Debug, Clone)]
pub struct DhcpdV6Config {
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub global_dns_servers: Vec<Ipv6Addr>,
    pub domain_search: Vec<String>,
    pub pd_pools: Vec<ParsedPdPool>,
    pub interfaces: Vec<InterfaceV6Config>,
    pub subnets: Vec<Subnet6>,
    /// When true, PD delegations granted via direct path push a
    /// route to ribd (see `v6::route_installer`). No-op for
    /// relayed delegations.
    pub install_pd_routes: bool,
}

impl DhcpdConfig {
    /// Load DHCPv4 server config from YAML. Returns `Ok(None)` when
    /// `dhcp.enabled` is absent or false — the caller decides what
    /// to do in that case (typically: run v6-only, or exit).
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let contents = std::fs::read_to_string(path)?;
        let cfg: RouterConfig = serde_yaml::from_str(&contents)?;
        if !cfg.dhcp_server.enabled {
            return Ok(None);
        }

        let default_lease_time = cfg.dhcp_server.default_lease_time.unwrap_or(3600);
        let max_lease_time = cfg.dhcp_server.max_lease_time.unwrap_or(86400);
        if default_lease_time > max_lease_time {
            anyhow::bail!(
                "default_lease_time ({}) > max_lease_time ({})",
                default_lease_time,
                max_lease_time
            );
        }

        let global_dns_servers = parse_ipv4_list(&cfg.dhcp_server.global_dns_servers, "global_dns_servers")?;

        let mut reservations = Vec::new();
        for r in &cfg.dhcp_server.reservations {
            let hw = parse_mac(&r.hw_address)
                .map_err(|e| anyhow::anyhow!("reservation {}: {}", r.hw_address, e))?;
            let ip: Ipv4Addr = r
                .ip_address
                .parse()
                .map_err(|e| anyhow::anyhow!("reservation ip {}: {}", r.ip_address, e))?;
            reservations.push(Reservation4 {
                hw_address: hw,
                ip_address: ip,
                hostname: r.hostname.clone(),
            });
        }
        // Duplicate-reservation guard.
        for i in 0..reservations.len() {
            for j in (i + 1)..reservations.len() {
                if reservations[i].ip_address == reservations[j].ip_address {
                    anyhow::bail!(
                        "duplicate reservation IP {} in dhcp.reservations",
                        reservations[i].ip_address
                    );
                }
            }
        }

        let mut interfaces = Vec::new();
        for iface in &cfg.interfaces {
            if !iface.dhcp_server_enabled.unwrap_or(false) {
                continue;
            }
            let name = iface
                .name
                .clone()
                .ok_or_else(|| anyhow::anyhow!("interface with dhcp_server_enabled missing name"))?;
            // Deprecated as of 2026-04-17 — the per-interface pool
            // config duplicates `dhcp_server.subnets[]`. Migrate to:
            //   dhcp_server:
            //     subnets:
            //       - subnet: <iface-subnet-cidr>
            //         pool_start: <...>
            //         pool_end: <...>
            //         gateway: <...>
            //     interfaces: [<this-iface-name>]
            // The new form composes cleanly (one pool, many serving
            // interfaces) and matches the relay-landing shape.
            tracing::warn!(
                iface = name.as_str(),
                "interfaces[].dhcp_server_enabled is DEPRECATED. Move the pool to \
                 dhcp_server.subnets[] and add the interface name to \
                 dhcp_server.interfaces[]. The legacy path still works today but will \
                 be removed in a future release."
            );
            let first = iface.ipv4.first().ok_or_else(|| {
                anyhow::anyhow!("interface {} has dhcp_server_enabled but no ipv4 address", name)
            })?;
            let address: Ipv4Addr = first
                .address
                .parse()
                .map_err(|e| anyhow::anyhow!("interface {}: {}", name, e))?;
            let prefix_len = first.prefix;
            let pool_start: Ipv4Addr = iface
                .dhcp_server_pool_start
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("interface {} missing dhcp_server_pool_start", name))?
                .parse()
                .map_err(|e| anyhow::anyhow!("interface {} pool_start: {}", name, e))?;
            let pool_end: Ipv4Addr = iface
                .dhcp_server_pool_end
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("interface {} missing dhcp_server_pool_end", name))?
                .parse()
                .map_err(|e| anyhow::anyhow!("interface {} pool_end: {}", name, e))?;
            if u32::from(pool_start) > u32::from(pool_end) {
                anyhow::bail!("interface {} pool_start > pool_end", name);
            }
            let gateway: Ipv4Addr = match &iface.dhcp_server_gateway {
                Some(g) => g
                    .parse()
                    .map_err(|e| anyhow::anyhow!("interface {} gateway: {}", name, e))?,
                None => address,
            };
            let dns_servers =
                parse_ipv4_list(&iface.dhcp_server_dns_servers, "dhcp_server_dns_servers")?;
            interfaces.push(InterfaceV4Config {
                name,
                address,
                prefix_len,
                pool_start,
                pool_end,
                gateway,
                lease_time: iface.dhcp_server_lease_time,
                dns_servers,
                domain_name: iface.dhcp_server_domain_name.clone(),
                trust_relay: iface.dhcp_server_trust_relay,
            });
        }

        let mut subnets = Vec::new();
        for raw in &cfg.dhcp_server.subnets {
            let subnet: Ipv4Net = raw
                .subnet
                .parse()
                .map_err(|e| anyhow::anyhow!("dhcp_server.subnets[].subnet '{}': {}", raw.subnet, e))?;
            let pool_start: Ipv4Addr = raw
                .pool_start
                .parse()
                .map_err(|e| anyhow::anyhow!("subnet {} pool_start: {}", raw.subnet, e))?;
            let pool_end: Ipv4Addr = raw
                .pool_end
                .parse()
                .map_err(|e| anyhow::anyhow!("subnet {} pool_end: {}", raw.subnet, e))?;
            if u32::from(pool_start) > u32::from(pool_end) {
                anyhow::bail!("subnet {} pool_start > pool_end", raw.subnet);
            }
            if !subnet.contains(&pool_start) || !subnet.contains(&pool_end) {
                anyhow::bail!(
                    "subnet {}: pool {}..{} not inside subnet",
                    raw.subnet,
                    pool_start,
                    pool_end
                );
            }
            let gateway: Ipv4Addr = match &raw.gateway {
                Some(g) => g
                    .parse()
                    .map_err(|e| anyhow::anyhow!("subnet {} gateway: {}", raw.subnet, e))?,
                None => {
                    // Default to first host IP (subnet.network() + 1).
                    let n = u32::from(subnet.network());
                    Ipv4Addr::from(n.saturating_add(1))
                }
            };
            let dns_servers = parse_ipv4_list(&raw.dns_servers, "subnets[].dns_servers")?;
            // RFC 8925 §3.5: clients clamp values < 300 to 300. Warn
            // and clamp at config load so reply traffic is honest
            // about what the client will actually do.
            let v6_only_preferred = raw.v6_only_preferred.map(|secs| {
                if secs < crate::packet::v4::options::MIN_V6ONLY_WAIT {
                    tracing::warn!(
                        subnet = %raw.subnet,
                        configured = secs,
                        clamped = crate::packet::v4::options::MIN_V6ONLY_WAIT,
                        "v6_only_preferred below RFC 8925 minimum; clamping"
                    );
                    crate::packet::v4::options::MIN_V6ONLY_WAIT
                } else {
                    secs
                }
            });
            subnets.push(Subnet4 {
                subnet,
                pool_start,
                pool_end,
                gateway,
                lease_time: raw.lease_time,
                dns_servers,
                domain_name: raw.domain_name.clone(),
                trust_relay: raw.trust_relay,
                v6_only_preferred,
            });
        }
        // Duplicate-subnet guard (exact-match CIDR).
        for i in 0..subnets.len() {
            for j in (i + 1)..subnets.len() {
                if subnets[i].subnet == subnets[j].subnet {
                    anyhow::bail!(
                        "duplicate subnet {} in dhcp_server.subnets",
                        subnets[i].subnet
                    );
                }
            }
        }

        Ok(Some(DhcpdConfig {
            default_lease_time,
            max_lease_time,
            authoritative: cfg.dhcp_server.authoritative,
            global_dns_servers,
            domain_name: cfg.dhcp_server.domain_name.clone(),
            reservations,
            interfaces,
            subnets,
            enabled_interfaces: cfg.dhcp_server.interfaces.clone(),
        }))
    }
}

impl DhcpdConfig {
    /// Look up the subnet pool for a given IP (the client's subnet
    /// identifier — either `giaddr` or Option 82 link-selection).
    /// Returns the most-specific matching subnet (longest prefix).
    pub fn find_subnet(&self, addr: Ipv4Addr) -> Option<&Subnet4> {
        self.subnets
            .iter()
            .filter(|s| s.subnet.contains(&addr))
            .max_by_key(|s| s.subnet.prefix_len())
    }
}

impl DhcpdV6Config {
    /// Load DHCPv6 server config from YAML. Returns `Ok(None)` when
    /// `dhcp6.enabled` is absent or false.
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let contents = std::fs::read_to_string(path)?;
        let cfg: RouterConfig = serde_yaml::from_str(&contents)?;
        if !cfg.dhcp6_server.enabled {
            return Ok(None);
        }

        let preferred_lifetime = cfg.dhcp6_server.preferred_lifetime.unwrap_or(3600);
        let valid_lifetime = cfg.dhcp6_server.valid_lifetime.unwrap_or(86400);
        if preferred_lifetime > valid_lifetime {
            anyhow::bail!(
                "dhcp6.preferred_lifetime ({}) > valid_lifetime ({})",
                preferred_lifetime,
                valid_lifetime
            );
        }

        let global_dns_servers = parse_ipv6_list(&cfg.dhcp6_server.global_dns_servers, "dhcp6.global_dns_servers")?;

        let mut pd_pools = Vec::new();
        for p in &cfg.dhcp6_server.pd_pools {
            let (addr_s, len_s) = p
                .prefix
                .split_once('/')
                .ok_or_else(|| anyhow::anyhow!("pd pool {}: prefix must be CIDR", p.name))?;
            let prefix: Ipv6Addr = addr_s
                .parse()
                .map_err(|e| anyhow::anyhow!("pd pool {}: {}", p.name, e))?;
            let prefix_len: u8 = len_s
                .parse()
                .map_err(|e| anyhow::anyhow!("pd pool {}: {}", p.name, e))?;
            if p.delegated_length <= prefix_len || p.delegated_length > 128 {
                anyhow::bail!(
                    "pd pool {}: delegated_length {} must be > prefix length {} and <= 128",
                    p.name,
                    p.delegated_length,
                    prefix_len
                );
            }
            pd_pools.push(ParsedPdPool {
                name: p.name.clone(),
                prefix,
                prefix_len,
                delegated_length: p.delegated_length,
                preferred_lifetime: p.preferred_lifetime.unwrap_or(preferred_lifetime),
                valid_lifetime: p.valid_lifetime.unwrap_or(valid_lifetime),
            });
        }
        // Duplicate name guard.
        for i in 0..pd_pools.len() {
            for j in (i + 1)..pd_pools.len() {
                if pd_pools[i].name == pd_pools[j].name {
                    anyhow::bail!("duplicate pd_pool name {}", pd_pools[i].name);
                }
            }
        }

        let mut interfaces = Vec::new();
        for iface in &cfg.interfaces {
            if !iface.dhcp6_server_enabled.unwrap_or(false) {
                continue;
            }
            let name = iface
                .name
                .clone()
                .ok_or_else(|| anyhow::anyhow!("interface with dhcp6_server_enabled missing name"))?;
            let pool_start = match &iface.dhcp6_server_pool_start {
                Some(s) => Some(
                    s.parse::<Ipv6Addr>()
                        .map_err(|e| anyhow::anyhow!("interface {} pool_start: {}", name, e))?,
                ),
                None => None,
            };
            let pool_end = match &iface.dhcp6_server_pool_end {
                Some(s) => Some(
                    s.parse::<Ipv6Addr>()
                        .map_err(|e| anyhow::anyhow!("interface {} pool_end: {}", name, e))?,
                ),
                None => None,
            };
            if let (Some(a), Some(b)) = (pool_start, pool_end) {
                if u128::from(a) > u128::from(b) {
                    anyhow::bail!("interface {} dhcp6 pool_start > pool_end", name);
                }
            }
            if let Some(pd_pool_name) = &iface.dhcp6_server_pd_pool {
                if !pd_pools.iter().any(|p| &p.name == pd_pool_name) {
                    anyhow::bail!(
                        "interface {}: dhcp6_server_pd_pool '{}' not found",
                        name,
                        pd_pool_name
                    );
                }
            }
            interfaces.push(InterfaceV6Config {
                name,
                pool_start,
                pool_end,
                pd_pool: iface.dhcp6_server_pd_pool.clone(),
            });
        }

        let mut subnets = Vec::new();
        for raw in &cfg.dhcp6_server.subnets {
            let subnet: Ipv6Net = raw
                .subnet
                .parse()
                .map_err(|e| anyhow::anyhow!("dhcp6_server.subnets[].subnet '{}': {}", raw.subnet, e))?;
            let pool_start: Ipv6Addr = raw
                .pool_start
                .parse()
                .map_err(|e| anyhow::anyhow!("subnet {} pool_start: {}", raw.subnet, e))?;
            let pool_end: Ipv6Addr = raw
                .pool_end
                .parse()
                .map_err(|e| anyhow::anyhow!("subnet {} pool_end: {}", raw.subnet, e))?;
            if u128::from(pool_start) > u128::from(pool_end) {
                anyhow::bail!("subnet {} pool_start > pool_end", raw.subnet);
            }
            if !subnet.contains(&pool_start) || !subnet.contains(&pool_end) {
                anyhow::bail!(
                    "subnet {}: pool {}..{} not inside subnet",
                    raw.subnet,
                    pool_start,
                    pool_end
                );
            }
            subnets.push(Subnet6 {
                subnet,
                pool_start,
                pool_end,
                preferred_lifetime: raw.preferred_lifetime,
                valid_lifetime: raw.valid_lifetime,
            });
        }
        for i in 0..subnets.len() {
            for j in (i + 1)..subnets.len() {
                if subnets[i].subnet == subnets[j].subnet {
                    anyhow::bail!(
                        "duplicate subnet {} in dhcp6_server.subnets",
                        subnets[i].subnet
                    );
                }
            }
        }

        Ok(Some(DhcpdV6Config {
            preferred_lifetime,
            valid_lifetime,
            global_dns_servers,
            domain_search: cfg.dhcp6_server.domain_search.clone(),
            pd_pools,
            interfaces,
            subnets,
            install_pd_routes: cfg.dhcp6_server.install_pd_routes,
        }))
    }
}

impl DhcpdV6Config {
    /// Find the subnet entry containing `addr` (a relay's
    /// `link-address`). Returns the most-specific match.
    pub fn find_subnet(&self, addr: Ipv6Addr) -> Option<&Subnet6> {
        self.subnets
            .iter()
            .filter(|s| s.subnet.contains(&addr))
            .max_by_key(|s| s.subnet.prefix_len())
    }
}

fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("expected 6 colon-separated bytes in MAC, got '{}'", s);
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16)
            .map_err(|e| anyhow::anyhow!("bad MAC byte '{}': {}", p, e))?;
    }
    Ok(out)
}

fn parse_ipv4_list(strings: &[String], field: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
    let mut out = Vec::with_capacity(strings.len());
    for s in strings {
        let a: Ipv4Addr = s
            .parse()
            .map_err(|e| anyhow::anyhow!("{}: bad address '{}': {}", field, s, e))?;
        out.push(a);
    }
    Ok(out)
}

fn parse_ipv6_list(strings: &[String], field: &str) -> anyhow::Result<Vec<Ipv6Addr>> {
    let mut out = Vec::with_capacity(strings.len());
    for s in strings {
        let a: Ipv6Addr = s
            .parse()
            .map_err(|e| anyhow::anyhow!("{}: bad address '{}': {}", field, s, e))?;
        out.push(a);
    }
    Ok(out)
}
