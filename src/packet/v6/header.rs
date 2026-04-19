//! DHCPv6 header formats (RFC 8415 §8 for client messages, §9 for relay).
//!
//! Client/server messages:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    msg-type   |           transaction-id (3 bytes)            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              options                          .
//! .                              (variable)                       .
//! ```
//!
//! Relay messages (Relay-Forw, Relay-Repl):
//! ```text
//! |    msg-type   |  hop-count    |                                |
//! |                         link-address (16 octets)               |
//! |                         peer-address (16 octets)               |
//! |                              options                           .
//! ```

use std::net::Ipv6Addr;

use crate::error::DhcpdError;

/// Client/server header length in bytes (msg-type + 3-byte xid).
pub const DHCP6_CLIENT_HEADER_LEN: usize = 4;
/// Relay header length (msg-type + hop-count + 16 + 16).
pub const DHCP6_RELAY_HEADER_LEN: usize = 34;

pub const DHCP6_SERVER_PORT: u16 = 547;
pub const DHCP6_CLIENT_PORT: u16 = 546;

/// `ff02::1:2` — the multicast group relay agents and servers
/// listen on. Clients Solicit / InfoRequest here.
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x0001, 0x0002);

/// Parsed client/server header. 24-bit transaction-id packed into
/// the low 24 bits of `xid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dhcp6Header {
    pub msg_type: u8,
    pub xid: u32,
}

/// Parsed relay header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayHeader {
    pub msg_type: u8,
    pub hop_count: u8,
    pub link_address: Ipv6Addr,
    pub peer_address: Ipv6Addr,
}

impl Dhcp6Header {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.msg_type);
        // 24-bit xid in network order.
        buf.push(((self.xid >> 16) & 0xff) as u8);
        buf.push(((self.xid >> 8) & 0xff) as u8);
        buf.push((self.xid & 0xff) as u8);
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), DhcpdError> {
        if buf.len() < DHCP6_CLIENT_HEADER_LEN {
            return Err(DhcpdError::Parse(format!(
                "dhcp6 client header too short: {}",
                buf.len()
            )));
        }
        let msg_type = buf[0];
        let xid =
            ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32);
        Ok((Dhcp6Header { msg_type, xid }, &buf[4..]))
    }
}

impl RelayHeader {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.msg_type);
        buf.push(self.hop_count);
        buf.extend_from_slice(&self.link_address.octets());
        buf.extend_from_slice(&self.peer_address.octets());
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), DhcpdError> {
        if buf.len() < DHCP6_RELAY_HEADER_LEN {
            return Err(DhcpdError::Parse(format!(
                "dhcp6 relay header too short: {}",
                buf.len()
            )));
        }
        let msg_type = buf[0];
        let hop_count = buf[1];
        let mut link = [0u8; 16];
        link.copy_from_slice(&buf[2..18]);
        let mut peer = [0u8; 16];
        peer.copy_from_slice(&buf[18..34]);
        Ok((
            RelayHeader {
                msg_type,
                hop_count,
                link_address: Ipv6Addr::from(link),
                peer_address: Ipv6Addr::from(peer),
            },
            &buf[34..],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_header_round_trip() {
        let h = Dhcp6Header {
            msg_type: 1, // Solicit
            xid: 0xabcdef,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(buf, vec![1, 0xab, 0xcd, 0xef]);
        let (back, rest) = Dhcp6Header::decode(&buf).unwrap();
        assert_eq!(back, h);
        assert!(rest.is_empty());
    }

    #[test]
    fn relay_header_round_trip() {
        let h = RelayHeader {
            msg_type: 12, // Relay-Forw
            hop_count: 3,
            link_address: "2001:db8::1".parse().unwrap(),
            peer_address: "fe80::1".parse().unwrap(),
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(buf.len(), DHCP6_RELAY_HEADER_LEN);
        let (back, rest) = RelayHeader::decode(&buf).unwrap();
        assert_eq!(back, h);
        assert!(rest.is_empty());
    }

    #[test]
    fn client_header_truncated() {
        let buf = [1u8, 2, 3];
        assert!(Dhcp6Header::decode(&buf).is_err());
    }

    #[test]
    fn relay_header_truncated() {
        let buf = [12u8, 0];
        assert!(RelayHeader::decode(&buf).is_err());
    }

    #[test]
    fn all_dhcp_constant() {
        assert_eq!(
            ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
            "ff02::1:2".parse::<Ipv6Addr>().unwrap()
        );
    }
}
