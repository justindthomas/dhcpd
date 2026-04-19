//! Tests that the YAML → DhcpdConfig / DhcpdV6Config parser
//! accepts the real schema shape and catches common mistakes.

use std::io::Write;
use tempfile::NamedTempFile;

use dhcpd::config::{DhcpdConfig, DhcpdV6Config};

fn write_yaml(contents: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn v4_disabled_returns_none() {
    let f = write_yaml("dhcp_server:\n  enabled: false\n");
    let cfg = DhcpdConfig::load(f.path()).unwrap();
    assert!(cfg.is_none());
}

#[test]
fn v4_basic_pool_parses() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
  default_lease_time: 7200
  max_lease_time: 86400
  authoritative: true
  global_dns_servers: [1.1.1.1, 8.8.8.8]
  domain_name: example.net
  reservations:
    - hw_address: "aa:bb:cc:dd:ee:ff"
      ip_address: 10.0.0.10
      hostname: printer

interfaces:
  - name: lan
    ipv4:
      - address: 10.0.0.1
        prefix: 24
    dhcp_server_enabled: true
    dhcp_server_pool_start: 10.0.0.100
    dhcp_server_pool_end:   10.0.0.200
    dhcp_server_lease_time: 1800
    dhcp_server_dns_servers: [10.0.0.1]
    dhcp_server_domain_name: home.example.net
"#,
    );
    let cfg = DhcpdConfig::load(f.path()).unwrap().unwrap();
    assert_eq!(cfg.default_lease_time, 7200);
    assert_eq!(cfg.max_lease_time, 86400);
    assert!(cfg.authoritative);
    assert_eq!(cfg.global_dns_servers.len(), 2);
    assert_eq!(cfg.domain_name.as_deref(), Some("example.net"));
    assert_eq!(cfg.reservations.len(), 1);
    assert_eq!(cfg.reservations[0].hw_address, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(cfg.interfaces.len(), 1);
    let iface = &cfg.interfaces[0];
    assert_eq!(iface.name, "lan");
    assert_eq!(iface.pool_start.to_string(), "10.0.0.100");
    assert_eq!(iface.pool_end.to_string(), "10.0.0.200");
    assert_eq!(iface.gateway.to_string(), "10.0.0.1"); // defaults to interface addr
    assert_eq!(iface.lease_time, Some(1800));
    assert_eq!(iface.dns_servers.len(), 1);
    assert_eq!(iface.domain_name.as_deref(), Some("home.example.net"));
    assert!(!iface.trust_relay);
}

#[test]
fn v4_pool_reversed_is_rejected() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
interfaces:
  - name: lan
    ipv4:
      - address: 10.0.0.1
        prefix: 24
    dhcp_server_enabled: true
    dhcp_server_pool_start: 10.0.0.200
    dhcp_server_pool_end:   10.0.0.100
"#,
    );
    let err = DhcpdConfig::load(f.path()).unwrap_err();
    assert!(err.to_string().contains("pool_start > pool_end"), "got: {}", err);
}

#[test]
fn v4_default_gt_max_rejected() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
  default_lease_time: 90000
  max_lease_time: 86400
"#,
    );
    let err = DhcpdConfig::load(f.path()).unwrap_err();
    assert!(err.to_string().contains("default_lease_time"), "got: {}", err);
}

#[test]
fn v4_duplicate_reservation_rejected() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
  reservations:
    - hw_address: "aa:bb:cc:dd:ee:01"
      ip_address: 10.0.0.10
    - hw_address: "aa:bb:cc:dd:ee:02"
      ip_address: 10.0.0.10
"#,
    );
    let err = DhcpdConfig::load(f.path()).unwrap_err();
    assert!(err.to_string().contains("duplicate reservation"), "got: {}", err);
}

#[test]
fn v4_missing_pool_rejected() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
interfaces:
  - name: lan
    ipv4:
      - address: 10.0.0.1
        prefix: 24
    dhcp_server_enabled: true
"#,
    );
    let err = DhcpdConfig::load(f.path()).unwrap_err();
    assert!(err.to_string().contains("dhcp_server_pool_start"), "got: {}", err);
}

#[test]
fn v4_interface_without_address_rejected() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
interfaces:
  - name: lan
    ipv4: []
    dhcp_server_enabled: true
    dhcp_server_pool_start: 10.0.0.100
    dhcp_server_pool_end:   10.0.0.200
"#,
    );
    let err = DhcpdConfig::load(f.path()).unwrap_err();
    assert!(err.to_string().contains("no ipv4 address"), "got: {}", err);
}

#[test]
fn v6_disabled_returns_none() {
    let f = write_yaml("dhcp6_server:\n  enabled: false\n");
    let cfg = DhcpdV6Config::load(f.path()).unwrap();
    assert!(cfg.is_none());
}

#[test]
fn v6_pd_pool_parses() {
    let f = write_yaml(
        r#"
dhcp6_server:
  enabled: true
  preferred_lifetime: 3600
  valid_lifetime: 86400
  global_dns_servers:
    - "2001:4860:4860::8888"
  domain_search: [example.net]
  pd_pools:
    - name: residential
      prefix: "2001:db8:1000::/36"
      delegated_length: 56

interfaces:
  - name: lan
    dhcp6_server_enabled: true
    dhcp6_server_pool_start: "2001:db8::100"
    dhcp6_server_pool_end:   "2001:db8::ffff"
    dhcp6_server_pd_pool: residential
"#,
    );
    let cfg = DhcpdV6Config::load(f.path()).unwrap().unwrap();
    assert_eq!(cfg.preferred_lifetime, 3600);
    assert_eq!(cfg.valid_lifetime, 86400);
    assert_eq!(cfg.global_dns_servers.len(), 1);
    assert_eq!(cfg.domain_search, vec!["example.net".to_string()]);
    assert_eq!(cfg.pd_pools.len(), 1);
    let pool = &cfg.pd_pools[0];
    assert_eq!(pool.name, "residential");
    assert_eq!(pool.prefix_len, 36);
    assert_eq!(pool.delegated_length, 56);
    // Lifetimes default to the global values when the pool omits them.
    assert_eq!(pool.preferred_lifetime, 3600);
    assert_eq!(pool.valid_lifetime, 86400);
    assert_eq!(cfg.interfaces.len(), 1);
    assert_eq!(cfg.interfaces[0].pd_pool.as_deref(), Some("residential"));
}

#[test]
fn v6_pd_pool_delegated_shorter_than_prefix_rejected() {
    let f = write_yaml(
        r#"
dhcp6_server:
  enabled: true
  pd_pools:
    - name: bad
      prefix: "2001:db8:1000::/60"
      delegated_length: 56
"#,
    );
    let err = DhcpdV6Config::load(f.path()).unwrap_err();
    assert!(err.to_string().contains("delegated_length"), "got: {}", err);
}

#[test]
fn v6_iface_references_unknown_pd_pool_rejected() {
    let f = write_yaml(
        r#"
dhcp6_server:
  enabled: true
  pd_pools:
    - name: residential
      prefix: "2001:db8:1000::/36"
      delegated_length: 56

interfaces:
  - name: lan
    dhcp6_server_enabled: true
    dhcp6_server_pd_pool: nonexistent
"#,
    );
    let err = DhcpdV6Config::load(f.path()).unwrap_err();
    assert!(err.to_string().contains("not found"), "got: {}", err);
}

#[test]
fn v4_interfaces_opt_in_list_parses() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
  interfaces: [lan.110, bvi100]
  subnets:
    - subnet: 192.168.20.0/24
      pool_start: 192.168.20.100
      pool_end:   192.168.20.199
"#,
    );
    let cfg = DhcpdConfig::load(f.path()).unwrap().unwrap();
    assert_eq!(cfg.enabled_interfaces, vec!["lan.110", "bvi100"]);
    assert_eq!(cfg.subnets.len(), 1);
    // No per-interface (legacy) entries since the new form is used.
    assert!(cfg.interfaces.is_empty());
}

#[test]
fn v4_interfaces_opt_in_default_empty() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
  subnets:
    - subnet: 192.168.20.0/24
      pool_start: 192.168.20.100
      pool_end:   192.168.20.199
"#,
    );
    let cfg = DhcpdConfig::load(f.path()).unwrap().unwrap();
    assert!(cfg.enabled_interfaces.is_empty());
}

#[test]
fn v4_subnets_relay_pools_parse() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
  subnets:
    - subnet: 10.0.1.0/24
      pool_start: 10.0.1.100
      pool_end:   10.0.1.200
      gateway:    10.0.1.1
      lease_time: 7200
      dns_servers: [10.0.1.1, 10.0.1.2]
      domain_name: customer1
      trust_relay: true
    - subnet: 10.0.2.0/24
      pool_start: 10.0.2.100
      pool_end:   10.0.2.200
"#,
    );
    let cfg = DhcpdConfig::load(f.path()).unwrap().unwrap();
    assert_eq!(cfg.subnets.len(), 2);
    let s0 = &cfg.subnets[0];
    assert_eq!(s0.subnet.to_string(), "10.0.1.0/24");
    assert_eq!(s0.gateway.to_string(), "10.0.1.1");
    assert_eq!(s0.lease_time, Some(7200));
    assert_eq!(s0.dns_servers.len(), 2);
    assert!(s0.trust_relay);
    let s1 = &cfg.subnets[1];
    // Gateway defaults to .1 of subnet when omitted.
    assert_eq!(s1.gateway.to_string(), "10.0.2.1");
    assert_eq!(s1.lease_time, None);
}

#[test]
fn v4_subnet_pool_outside_subnet_rejected() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
  subnets:
    - subnet: 10.0.1.0/24
      pool_start: 10.0.1.100
      pool_end:   10.0.2.200
"#,
    );
    let err = DhcpdConfig::load(f.path()).unwrap_err();
    assert!(err.to_string().contains("not inside subnet"), "got: {}", err);
}

#[test]
fn v6_subnets_relay_pools_parse() {
    let f = write_yaml(
        r#"
dhcp6_server:
  enabled: true
  subnets:
    - subnet: "2001:db8:1::/64"
      pool_start: "2001:db8:1::100"
      pool_end:   "2001:db8:1::ffff"
      preferred_lifetime: 3600
      valid_lifetime: 86400
"#,
    );
    let cfg = DhcpdV6Config::load(f.path()).unwrap().unwrap();
    assert_eq!(cfg.subnets.len(), 1);
    assert_eq!(cfg.subnets[0].subnet.to_string(), "2001:db8:1::/64");
    assert_eq!(cfg.subnets[0].preferred_lifetime, Some(3600));
}

#[test]
fn v6_preferred_gt_valid_rejected() {
    let f = write_yaml(
        r#"
dhcp6_server:
  enabled: true
  preferred_lifetime: 90000
  valid_lifetime: 86400
"#,
    );
    let err = DhcpdV6Config::load(f.path()).unwrap_err();
    assert!(err.to_string().contains("preferred_lifetime"), "got: {}", err);
}

#[test]
fn both_families_coexist() {
    let f = write_yaml(
        r#"
dhcp_server:
  enabled: true
dhcp6_server:
  enabled: true
  pd_pools:
    - name: pool1
      prefix: "2001:db8::/40"
      delegated_length: 56
interfaces:
  - name: lan
    ipv4:
      - address: 10.0.0.1
        prefix: 24
    dhcp_server_enabled: true
    dhcp_server_pool_start: 10.0.0.100
    dhcp_server_pool_end:   10.0.0.200
    dhcp6_server_enabled: true
    dhcp6_server_pd_pool: pool1
"#,
    );
    let v4 = DhcpdConfig::load(f.path()).unwrap().unwrap();
    let v6 = DhcpdV6Config::load(f.path()).unwrap().unwrap();
    assert_eq!(v4.interfaces.len(), 1);
    assert_eq!(v6.interfaces.len(), 1);
    assert_eq!(v4.interfaces[0].name, "lan");
    assert_eq!(v6.interfaces[0].name, "lan");
}
