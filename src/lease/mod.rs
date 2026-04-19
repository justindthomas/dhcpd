//! DHCP lease store.
//!
//! v1: append-only bincode journal (`leases-v4.journal`) with a
//! periodic snapshot (`leases-v4.snapshot`). On startup the daemon
//! loads the snapshot then replays any journal entries recorded
//! after it. Every mutation fsyncs the journal before returning.
//! Once the journal grows past a threshold we compact by writing
//! a fresh snapshot and truncating the journal.
//!
//! See `journal.rs` for the v4 implementation. v6/PD stores will
//! live in `journal6.rs` (Phase 3/4).

pub mod journal;
pub mod journal6;

pub use journal::{Lease, LeaseState, LeaseStoreV4};
pub use journal6::{IaKind, LeaseStateV6, LeaseStoreV6, LeaseV6, V6Key};
