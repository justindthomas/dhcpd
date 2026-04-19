//! DHCPv4 server logic.
//!
//! - `allocator` — pool + reservation allocator with DECLINE quarantine.
//! - `fsm` — RFC 2131 §4.3 server state machine.
//! - `server` — glue: receives RxV4Packet, dispatches to FSM,
//!   persists leases, emits TxV4Packet.

pub mod allocator;
pub mod fsm;
pub mod server;
