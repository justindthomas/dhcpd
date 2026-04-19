//! DHCPv4 / BOOTP wire format.
//!
//! RFC 2131 header + magic cookie + options framing.
//! RFC 2132 standard options.
//! RFC 3046 Option 82 relay agent information.
//! RFC 3442 classless static routes (Option 121).
//! RFC 4361 + 6842 client-identifier handling.

pub mod client_id;
pub mod header;
pub mod message;
pub mod options;

pub use client_id::ClientId;
pub use header::{BootOp, BootpHeader, DHCP_MAGIC_COOKIE};
pub use message::{DhcpMessage, DhcpMessageType};
pub use options::{DhcpOption, Option82, RouteEntry, DECODE_END_OF_OPTIONS};
