//! dhcpd — DHCPv4 + DHCPv6 server.
//!
//! Exposes modules as a library so examples and integration tests can reuse
//! config parsing, the control protocol, and the I/O traits. Packet codecs,
//! FSMs, allocators, and the lease store are staged in for Phase 2+ and
//! will appear under `packet/`, `v4/`, `v6/`, and `lease/` submodules.

pub mod config;
pub mod control;
pub mod error;
pub mod io;
pub mod io_punt;
pub mod lease;
pub mod packet;
pub mod v4;
pub mod v6;
pub mod vpp_iface;
