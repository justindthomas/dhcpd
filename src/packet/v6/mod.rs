//! DHCPv6 wire format (RFC 8415 consolidated).
//!
//! Scope for Phase 3:
//! - Client ↔ server header (msg-type + transaction-id).
//! - Relay header (msg-type + hop-count + link-addr + peer-addr)
//!   and nested Relay-Msg option decoding.
//! - Options: Client-ID, Server-ID, IA_NA, IA_Address, ORO,
//!   Elapsed-Time, Status-Code, Rapid-Commit, Preference, DNS
//!   Servers (RFC 3646), Domain List (RFC 3646), Relay-Msg,
//!   Interface-ID, Client-FQDN (RFC 4704), Client-Linklayer-Addr
//!   (RFC 6939), SOL_MAX_RT, INF_MAX_RT.
//! - DUID codec — LLT / EN / LL / UUID parse; LLT generate for
//!   the server's own identifier.
//!
//! Phase 4 adds IA_PD (25) and IAPrefix (26).

pub mod duid;
pub mod header;
pub mod message;
pub mod options;

pub use duid::{Duid, DuidType};
pub use header::{
    Dhcp6Header, RelayHeader, DHCP6_CLIENT_HEADER_LEN, DHCP6_RELAY_HEADER_LEN,
    DHCP6_SERVER_PORT, DHCP6_CLIENT_PORT, ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
};
pub use message::{Dhcp6Message, Dhcp6MessageType};
pub use options::{
    Dhcp6Option, IaAddress, IaNa, IaPd, IaPrefix, StatusCode,
};
