//! DHCP Unique Identifier (DUID) codec — RFC 8415 §11.
//!
//! DUIDs come in four flavors:
//!
//!   - **DUID-LLT** (type 1) — link-layer address + time. The type
//!     we generate for our server identifier at first startup.
//!   - **DUID-EN** (type 2) — enterprise number + opaque vendor bytes.
//!   - **DUID-LL** (type 3) — link-layer address only.
//!   - **DUID-UUID** (type 4) — 128-bit UUID (RFC 6355).
//!
//! We only need to *generate* DUID-LLT (our server); client DUIDs
//! are echoed as opaque bytes. For debugging, [`Duid`] preserves
//! the type + raw bytes so the query surface can render it.

use std::time::SystemTime;

use crate::error::DhcpdError;

/// DUID type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DuidType {
    Llt = 1,
    En = 2,
    Ll = 3,
    Uuid = 4,
}

impl DuidType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(DuidType::Llt),
            2 => Some(DuidType::En),
            3 => Some(DuidType::Ll),
            4 => Some(DuidType::Uuid),
            _ => None,
        }
    }
}

/// A DUID as raw wire bytes. Most consumers (lease store, reply
/// echo, logs) only need the bytes; parsing the type is optional.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Duid(pub Vec<u8>);

impl Duid {
    /// Return the DUID's type field (first 2 bytes big-endian),
    /// or `None` if the DUID is empty or not a recognized type.
    pub fn duid_type(&self) -> Option<DuidType> {
        if self.0.len() < 2 {
            return None;
        }
        DuidType::from_u16(u16::from_be_bytes([self.0[0], self.0[1]]))
    }

    /// Generate a DUID-LLT for this server. `hw_type` = 1 for
    /// ethernet (IANA ARPHRD type). `mac` is the 6-byte MAC of
    /// the interface whose MAC we're embedding. `now` is used for
    /// the time field — seconds since Jan 1, 2000 UTC (RFC 8415
    /// §11.2).
    pub fn new_llt(hw_type: u16, mac: &[u8; 6], now: SystemTime) -> Self {
        // Seconds between Unix epoch and DUID epoch (Jan 1 2000 UTC):
        // 30 years of Unix time = 946_684_800 seconds.
        const DUID_EPOCH_UNIX: u64 = 946_684_800;
        let duid_time = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().saturating_sub(DUID_EPOCH_UNIX) as u32)
            .unwrap_or(0);

        let mut bytes = Vec::with_capacity(14);
        bytes.extend_from_slice(&(DuidType::Llt as u16).to_be_bytes());
        bytes.extend_from_slice(&hw_type.to_be_bytes());
        bytes.extend_from_slice(&duid_time.to_be_bytes());
        bytes.extend_from_slice(mac);
        Duid(bytes)
    }

    /// Parse raw bytes into a DUID. Validates length bounds (2..=128)
    /// but does not deeply validate subtype fields — RFC 8415 §11.1
    /// treats unknown types as opaque bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, DhcpdError> {
        if bytes.is_empty() {
            return Err(DhcpdError::Parse("DUID cannot be empty".into()));
        }
        if bytes.len() > 128 {
            return Err(DhcpdError::Parse(format!(
                "DUID too long: {} bytes (max 128)",
                bytes.len()
            )));
        }
        Ok(Duid(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Human-readable form. Always shown as `type:hex` pairs.
    pub fn pretty(&self) -> String {
        if self.0.is_empty() {
            return "<empty>".into();
        }
        use std::fmt::Write;
        let mut s = String::with_capacity(self.0.len() * 3);
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                s.push(':');
            }
            write!(s, "{:02x}", b).ok();
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn llt_generation_produces_expected_prefix() {
        // Jan 1 2000 UTC is DUID epoch. Verify time = 0 when now = Jan 1 2000.
        let epoch_2000 = UNIX_EPOCH + Duration::from_secs(946_684_800);
        let d = Duid::new_llt(1, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], epoch_2000);
        // type=1 (LLT) || hw_type=1 || time=0 || mac
        assert_eq!(
            d.as_bytes(),
            &[
                0, 1, 0, 1, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ]
        );
    }

    #[test]
    fn llt_time_field_increases_with_time() {
        let t0 = UNIX_EPOCH + Duration::from_secs(946_684_800);
        let t1 = t0 + Duration::from_secs(3600);
        let d0 = Duid::new_llt(1, &[0; 6], t0);
        let d1 = Duid::new_llt(1, &[0; 6], t1);
        let t0_bytes = &d0.as_bytes()[4..8];
        let t1_bytes = &d1.as_bytes()[4..8];
        assert_eq!(t0_bytes, &[0, 0, 0, 0]);
        assert_eq!(t1_bytes, &[0, 0, 0x0e, 0x10]); // 3600 seconds
    }

    #[test]
    fn duid_parse_accepts_valid() {
        let d = Duid::parse(&[0, 1, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(d.duid_type(), Some(DuidType::Llt));
    }

    #[test]
    fn duid_parse_rejects_empty() {
        assert!(Duid::parse(&[]).is_err());
    }

    #[test]
    fn duid_parse_rejects_over_max() {
        let big = vec![0u8; 129];
        assert!(Duid::parse(&big).is_err());
    }

    #[test]
    fn pretty_renders_colon_hex() {
        let d = Duid(vec![0, 1, 0, 1]);
        assert_eq!(d.pretty(), "00:01:00:01");
    }

    #[test]
    fn equality_is_bytewise() {
        let a = Duid(vec![1, 2, 3]);
        let b = Duid(vec![1, 2, 3]);
        let c = Duid(vec![1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
