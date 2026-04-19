//! Client identifier handling (RFC 4361 + RFC 6842).
//!
//! The client-id is the identifier used to key lease state. Precedence:
//!
//! 1. If the client sends Option 61 (Client Identifier) — use it.
//!    The bytes are opaque; RFC 6842 mandates we echo it verbatim
//!    in every reply to that client.
//! 2. Otherwise fall back to the BOOTP `chaddr` (first `hlen` bytes)
//!    per RFC 2131 §4.2.
//!
//! RFC 4361 recommends type=255 (IAID + DUID) client-ids so v4 and
//! v6 bindings can share a DUID. We don't impose that format — we
//! treat option 61 as opaque bytes — but our lease store keys are
//! bytes, so v4/v6 alignment is available to clients that choose it.

/// An opaque client identifier — either the Option-61 body or the
/// derived chaddr fallback.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientId(pub Vec<u8>);

impl ClientId {
    /// Build a client-id from Option 61 bytes (preferred) or fall
    /// back to the ethernet MAC from the BOOTP header.
    pub fn from_packet(option_61: Option<&[u8]>, ethernet_mac: Option<[u8; 6]>) -> Self {
        match option_61 {
            Some(b) if !b.is_empty() => ClientId(b.to_vec()),
            _ => {
                let mac = ethernet_mac.unwrap_or([0u8; 6]);
                // For the fallback form RFC 2131 §4.2 describes the
                // key as `chaddr` itself (no type prefix). Keep that
                // shape so legacy and modern clients hash equal when
                // the modern client sends a chaddr-shaped Option 61.
                ClientId(mac.to_vec())
            }
        }
    }

    /// Human-readable form (for logs).
    pub fn pretty(&self) -> String {
        if self.0.is_empty() {
            return "<empty>".into();
        }
        // If the bytes look like 6 octets, render as a MAC.
        if self.0.len() == 6 {
            return format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
            );
        }
        // If the first byte is a known hardware type and the rest is 6
        // bytes, it's chaddr with a type prefix — render as type/MAC.
        if self.0.len() == 7 && self.0[0] == 1 {
            return format!(
                "01:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6]
            );
        }
        // Generic hex.
        let mut s = String::with_capacity(self.0.len() * 3);
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                s.push(':');
            }
            use std::fmt::Write;
            write!(s, "{:02x}", b).ok();
        }
        s
    }

    /// Returns the raw bytes, useful for echoing Option 61 per RFC 6842.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_61_preferred_over_mac() {
        let opt = vec![1, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let cid = ClientId::from_packet(Some(&opt), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(cid.as_bytes(), opt.as_slice());
    }

    #[test]
    fn falls_back_to_mac_when_no_option_61() {
        let cid = ClientId::from_packet(None, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(cid.as_bytes(), &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn empty_option_61_falls_back() {
        let cid = ClientId::from_packet(Some(&[]), Some([1, 2, 3, 4, 5, 6]));
        assert_eq!(cid.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn pretty_renders_mac() {
        let cid = ClientId(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(cid.pretty(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn pretty_renders_typed_mac() {
        let cid = ClientId(vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(cid.pretty(), "01:aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn pretty_handles_arbitrary_length() {
        let cid = ClientId(vec![0xff, 0, 1, 2, 3, 4]);
        assert_eq!(cid.pretty(), "ff:00:01:02:03:04");
    }

    #[test]
    fn clientid_equality_key() {
        let a = ClientId::from_packet(Some(&[1, 2, 3, 4, 5, 6, 7]), None);
        let b = ClientId::from_packet(Some(&[1, 2, 3, 4, 5, 6, 7]), Some([9, 9, 9, 9, 9, 9]));
        assert_eq!(a, b);
    }
}
