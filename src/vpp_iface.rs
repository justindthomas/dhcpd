//! VPP interface + address discovery for dhcpd.
//!
//! Builds the daemon's per-interface `IoInterface` view from
//! `SwInterfaceDump` + `IpAddressDump` + (later) the v6 link-local
//! getter, intersected with the DHCPv4/v6 server enable flags from
//! the config. Matches the ospfd startup discovery pattern.

use std::net::{Ipv4Addr, Ipv6Addr};

use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
use vpp_api::generated::ip::{
    AddressFamily, IpAddressDetails, IpAddressDump,
    SwInterfaceIp6GetLinkLocalAddress, SwInterfaceIp6GetLinkLocalAddressReply,
};
use vpp_api::VppClient;

use crate::io::IoInterface;

/// Discover VPP interfaces matching the daemon's needs. If
/// `wanted_names` is non-empty, only interfaces in that list are
/// returned. If it's empty, all admin-up interfaces with at least
/// one IPv4 address or an IPv6 link-local are returned — used for
/// pure-subnets (relay-only) deployments where the reply interface
/// is a BVI or loopback not listed in the YAML `interfaces[]`.
pub async fn discover(
    vpp: &VppClient,
    wanted_names: &[String],
) -> anyhow::Result<Vec<IoInterface>> {
    let ifaces: Vec<SwInterfaceDetails> = vpp
        .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
        .await
        .map_err(|e| anyhow::anyhow!("sw_interface_dump: {}", e))?;

    let permissive = wanted_names.is_empty();

    // Index parent MACs by sw_if_index so sub-interfaces (whose own
    // l2_address field is often all-zeros) can inherit from the
    // physical / super interface they belong to.
    let mac_by_sw_if: std::collections::HashMap<u32, [u8; 6]> = ifaces
        .iter()
        .map(|vi| (vi.sw_if_index, vi.l2_address))
        .collect();

    let mut out = Vec::new();
    for vi in &ifaces {
        let name = vi.interface_name.trim_end_matches('\0').to_string();
        if !permissive && !wanted_names.iter().any(|w| w == &name) {
            continue;
        }
        if !vi.flags.is_admin_up() {
            if !permissive {
                tracing::warn!(
                    iface = name.as_str(),
                    sw_if_index = vi.sw_if_index,
                    "configured DHCP interface is admin-down — skipping"
                );
            }
            continue;
        }
        // Skip local0 and the like — they have no useful addresses.
        if permissive && name == "local0" {
            continue;
        }

        // MAC: prefer the interface's own l2_address. If it's all
        // zeros (typical for VLAN sub-interfaces whose super is a
        // physical NIC), fall back to the super interface's MAC.
        let is_zero = vi.l2_address == [0u8; 6];
        let parent_mac = if is_zero && vi.sup_sw_if_index != vi.sw_if_index {
            mac_by_sw_if.get(&vi.sup_sw_if_index).copied()
        } else {
            None
        };
        let mut mac = [0u8; 6];
        if let Some(p) = parent_mac {
            mac.copy_from_slice(&p[..6]);
        } else {
            mac.copy_from_slice(&vi.l2_address[..6]);
        }

        // v4 addresses
        let v4_addrs: Vec<IpAddressDetails> = vpp
            .dump::<IpAddressDump, IpAddressDetails>(IpAddressDump {
                sw_if_index: vi.sw_if_index,
                is_ipv6: false,
            })
            .await
            .unwrap_or_default();
        let (ipv4_address, ipv4_prefix_len) = match v4_addrs.first() {
            Some(d) if d.prefix.af == AddressFamily::Ipv4 => {
                let octets = [
                    d.prefix.address[0],
                    d.prefix.address[1],
                    d.prefix.address[2],
                    d.prefix.address[3],
                ];
                (Some(Ipv4Addr::from(octets)), d.prefix.len)
            }
            _ => (None, 0),
        };

        // v6 link-local (VPP has a dedicated getter; regular
        // IpAddressDump returns only non-link-local v6 addresses).
        let ipv6_link_local = fetch_link_local(vpp, vi.sw_if_index).await;

        // Interfaces with no IPv4 address AND no IPv6 link-local
        // can't serve DHCP — they can't source replies, can't
        // respond to Server-ID lookups, and for most relay topologies
        // the relay needs a reachable IP to forward to. Skip them
        // regardless of whether they were explicitly opted-in;
        // log a warning so operators notice the misconfiguration.
        if ipv4_address.is_none() && ipv6_link_local.is_none() {
            if !permissive {
                tracing::warn!(
                    iface = name.as_str(),
                    sw_if_index = vi.sw_if_index,
                    "opted-in DHCP interface has no IP address — skipping"
                );
            }
            continue;
        }

        out.push(IoInterface {
            sw_if_index: vi.sw_if_index,
            name,
            mac_address: mac,
            ipv4_address,
            ipv4_prefix_len,
            ipv6_link_local,
        });
    }

    Ok(out)
}

async fn fetch_link_local(vpp: &VppClient, sw_if_index: u32) -> Option<Ipv6Addr> {
    let req = SwInterfaceIp6GetLinkLocalAddress { sw_if_index };
    match vpp
        .request::<SwInterfaceIp6GetLinkLocalAddress, SwInterfaceIp6GetLinkLocalAddressReply>(req)
        .await
    {
        Ok(reply) if reply.retval == 0 => {
            if reply.ip == [0u8; 16] {
                None
            } else {
                Some(Ipv6Addr::from(reply.ip))
            }
        }
        _ => None,
    }
}
