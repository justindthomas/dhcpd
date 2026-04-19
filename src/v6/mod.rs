//! DHCPv6 server logic.
//!
//! - `allocator` — IA_NA pool allocator.
//! - `fsm` — RFC 8415 §18 server state machine for Phase 3 (IA_NA).
//! - `server` — glue: RxV6Packet → FSM → lease commit → TxV6Packet.
//!
//! Phase 4 will add `pd_allocator` and IA_PD handling in `fsm`.

pub mod allocator;
pub mod fsm;
pub mod pd_allocator;
pub mod route_installer;
pub mod server;
