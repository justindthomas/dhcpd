//! Optional PD route installer.
//!
//! When `dhcp6_server.install_pd_routes: true` is set, this module
//! spawns a tokio task that consumes [`PdGranted`] events from the
//! v6 FSM and pushes matching routes into ribd via the
//! incremental `update(Add, ...)` API.
//!
//! **Scope.** Only direct-path delegations are installed —
//! relayed delegations set `via_relay=true` on the event and are
//! silently skipped here, because in that deployment shape the
//! L3 relay owns the route (the delegated prefix's nexthop is the
//! CPE's link-local on the relay's client-facing interface, which
//! this server has no path to).
//!
//! **Lifecycle.** Phase 4 only handles the grant direction. A PD
//! release doesn't currently revoke the route; the route stays
//! until the daemon restarts and the installer re-bootstraps from
//! the lease store (future polish: wire a `PdRevoked` event on
//! release, or periodically reconcile the installer's view against
//! the store).
//!
//! **Source + AD.** PD routes are pushed as `Source::Static`
//! (admin distance 1). A dedicated `Source::DhcpPd` variant would
//! let operators tune AD per-family, but adding it means touching
//! ribd-proto and every consumer — deferred.

use std::path::Path;
use std::time::Duration;

use ribd_client::connect_with_retry;
use ribd_proto::{Action, NextHop, Prefix, Route, Source};
use tokio::sync::mpsc;

use crate::v6::fsm::{PdEvent, PdGranted, PdRevoked};

/// Spawn the installer task. Returns a sender the FSM glue pushes
/// events into. The task loops forever, reconnecting to ribd with
/// backoff on transient failures.
pub fn spawn(
    rib_socket_path: impl AsRef<Path>,
) -> mpsc::UnboundedSender<PdEvent> {
    let (tx, rx) = mpsc::unbounded_channel::<PdEvent>();
    let rib_path = rib_socket_path.as_ref().to_path_buf();
    tokio::spawn(async move {
        run(rib_path, rx).await;
    });
    tx
}

async fn run(rib_path: std::path::PathBuf, mut rx: mpsc::UnboundedReceiver<PdEvent>) {
    let rib_path_str = rib_path.to_string_lossy().into_owned();
    let mut conn = match connect_with_retry(
        &rib_path_str,
        "dhcpd",
        Duration::from_secs(30),
    )
    .await
    {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(
                error = %e,
                rib = rib_path_str.as_str(),
                "PD route installer: initial ribd connect failed; will reconnect on first event"
            );
            None
        }
    };

    while let Some(event) = rx.recv().await {
        // Build the action + route from the event. Relayed
        // delegations are skipped — the relay owns the route.
        let (action, route) = match &event {
            PdEvent::Granted(g) => {
                if g.via_relay {
                    tracing::debug!(
                        prefix = %g.prefix,
                        "PD granted via relay — route install skipped"
                    );
                    continue;
                }
                (Action::Add, build_pd_grant_route(g))
            }
            PdEvent::Revoked(r) => {
                if r.via_relay {
                    tracing::debug!(
                        prefix = %r.prefix,
                        "PD revoked for relayed delegation — route removal skipped"
                    );
                    continue;
                }
                (Action::Delete, build_pd_revoke_route(r))
            }
        };

        if conn.is_none() {
            conn = match connect_with_retry(
                &rib_path_str,
                "dhcpd",
                Duration::from_secs(10),
            )
            .await
            {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "PD route installer: ribd reconnect failed; dropping event"
                    );
                    continue;
                }
            };
        }

        match conn.as_mut().unwrap().update(action, route.clone()).await {
            Ok(()) => {
                tracing::info!(
                    action = ?action,
                    prefix = %route.prefix,
                    "PD route applied to ribd"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "PD route install failed; dropping and tearing down conn"
                );
                conn = None;
            }
        }
    }
}

fn build_pd_grant_route(event: &PdGranted) -> Route {
    Route {
        prefix: Prefix::v6(event.prefix, event.prefix_len),
        source: Source::DhcpPd,
        next_hops: vec![NextHop::v6(event.next_hop, event.ingress_sw_if_index)],
        metric: 0,
        tag: 0,
        admin_distance: None,
    }
}

/// Build a matching `Route` for a Revoke event. ribd matches
/// on `(prefix, source)` so we only need to fill those — the rest
/// of the Route fields are ignored by `update(Remove, ...)`. We
/// populate a placeholder next-hop so the `Display` impl still
/// works for the info log.
fn build_pd_revoke_route(event: &PdRevoked) -> Route {
    Route {
        prefix: Prefix::v6(event.prefix, event.prefix_len),
        source: Source::DhcpPd,
        next_hops: vec![],
        metric: 0,
        tag: 0,
        admin_distance: None,
    }
}

/// Default `/run/ribd.sock` — the path ospfd and bgpd
/// use. Overridable via daemon CLI flag (TODO — not wired yet).
pub const DEFAULT_RIB_SOCKET: &str = "/run/ribd.sock";

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn sample_event() -> PdGranted {
        PdGranted {
            prefix: "2001:db8:1000::".parse().unwrap(),
            prefix_len: 56,
            next_hop: "fe80::1".parse().unwrap(),
            ingress_sw_if_index: 7,
            via_relay: false,
        }
    }

    #[test]
    fn grant_route_shape() {
        let ev = sample_event();
        let r = build_pd_grant_route(&ev);
        assert_eq!(r.source, Source::DhcpPd);
        assert_eq!(r.prefix.len, 56);
        assert_eq!(r.prefix.af, ribd_proto::Af::V6);
        assert_eq!(r.next_hops.len(), 1);
        assert_eq!(r.next_hops[0].sw_if_index, 7);
        // DhcpPd admin distance defaults to 2 (just above Static=1).
        assert_eq!(r.effective_admin_distance(), 2);
    }

    #[test]
    fn revoke_route_shape() {
        let r = build_pd_revoke_route(&PdRevoked {
            prefix: "2001:db8:1000::".parse().unwrap(),
            prefix_len: 56,
            via_relay: false,
        });
        assert_eq!(r.source, Source::DhcpPd);
        assert_eq!(r.prefix.len, 56);
        // No next-hop needed for removal — ribd keys on (prefix, source).
        assert!(r.next_hops.is_empty());
    }

    #[test]
    fn grant_prefix_bytes_preserved() {
        let ev = sample_event();
        let r = build_pd_grant_route(&ev);
        let expected: Ipv6Addr = "2001:db8:1000::".parse().unwrap();
        assert_eq!(r.prefix.addr, expected.octets());
    }
}
