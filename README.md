# dhcpd

DHCPv4 + DHCPv6 (including IA_PD prefix delegation) daemon that integrates directly with [VPP](https://fd.io) via punt sockets.

Runs in a VPP-hosted network namespace. VPP punts UDP/67 (v4) and UDP/546/547 (v6) to the daemon's Unix socket; the daemon parses, runs the server FSM, and punts responses back through VPP (`PUNT_L2` for broadcast DISCOVER/OFFER, `PUNT_IP4_ROUTED` for unicast renewals). Leases are persisted to disk and replayed on restart.

## Build

```sh
cargo build --release
```

Depends on [`vpp-api`](https://github.com/justindthomas/vpp-api) and [`ribd-client`](https://github.com/justindthomas/ribd) (for pushing IA_PD-delegated prefixes into the RIB).

## Run

```sh
dhcpd --config /etc/dhcpd/config.yaml
```

Flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--config PATH` | `/etc/dhcpd/config.yaml` | Config file |
| `--vpp-api SOCKET` | `/run/vpp/api.sock` | VPP binary API socket |
| `--control-socket PATH` | `/run/dhcpd.sock` | Unix socket for `query` subcommands |
| `--lease-db DIR` | `/var/lib/dhcpd` | Lease persistence directory |
| `--io punt\|raw` | `punt` | Packet I/O backend |

## Query a running daemon

```sh
dhcpd query status
dhcpd query interfaces
dhcpd query leases
dhcpd query pools
dhcpd query release-lease --client-id aa:bb:cc:dd:ee:ff
```

## Configuration reload

`SIGHUP` re-reads the config file and hot-applies changes to pools, subnets, reservations, per-interface DNS/gateway/lease-time, and the DHCPv6 PD pool list. In-memory lease state is preserved across reload. Changes that require a full restart (logged as warnings on reload): toggling `dhcp_server.enabled` / `dhcp6_server.enabled`, adding or removing serving interfaces, and toggling `install_pd_routes`.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

If the AGPL's obligations are incompatible with your use, commercial licenses are available. See [CONTRIBUTING.md](CONTRIBUTING.md).
