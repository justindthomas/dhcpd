//! DHCP packet codecs.
//!
//! v4 codec lives under [`v4`] and implements RFC 2131 + 2132 +
//! 3046 + 3442 + 4361 + 6842. v6 codec lands in Phase 3 under
//! `packet/v6/`.

pub mod v4;
pub mod v6;
