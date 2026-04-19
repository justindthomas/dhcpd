//! DHCPv6 message assembly — header + options with optional relay
//! encapsulation.
//!
//! A received DHCPv6 datagram is one of:
//!
//!   - A client message (Solicit, Request, Renew, ..., Information-Request).
//!     Layout: [header:4][options].
//!   - A Relay-Forw (sent by a relay agent on behalf of a client).
//!     Layout: [relay-header:34][options including Relay-Msg].
//!     Nested: the Relay-Msg option contains either another
//!     Relay-Forw or, at the innermost layer, a client message.
//!
//! [`Dhcp6Message::decode`] unwraps a single layer and returns a
//! [`Dhcp6Message`]; if the caller needs to recursively descend
//! Relay-Forw chains, it does so via [`Dhcp6Message::unwrap_relay`].

use crate::error::DhcpdError;
use crate::packet::v6::header::{
    Dhcp6Header, RelayHeader, DHCP6_CLIENT_HEADER_LEN, DHCP6_RELAY_HEADER_LEN,
};
use crate::packet::v6::options::{decode_options, Dhcp6Option};

/// RFC 8415 §7.3 message type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcp6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForw = 12,
    RelayRepl = 13,
}

impl Dhcp6MessageType {
    pub fn from_u8(v: u8) -> Result<Self, DhcpdError> {
        Ok(match v {
            1 => Dhcp6MessageType::Solicit,
            2 => Dhcp6MessageType::Advertise,
            3 => Dhcp6MessageType::Request,
            4 => Dhcp6MessageType::Confirm,
            5 => Dhcp6MessageType::Renew,
            6 => Dhcp6MessageType::Rebind,
            7 => Dhcp6MessageType::Reply,
            8 => Dhcp6MessageType::Release,
            9 => Dhcp6MessageType::Decline,
            10 => Dhcp6MessageType::Reconfigure,
            11 => Dhcp6MessageType::InformationRequest,
            12 => Dhcp6MessageType::RelayForw,
            13 => Dhcp6MessageType::RelayRepl,
            other => return Err(DhcpdError::Parse(format!("unknown dhcp6 msg type {}", other))),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Dhcp6MessageType::Solicit => "SOLICIT",
            Dhcp6MessageType::Advertise => "ADVERTISE",
            Dhcp6MessageType::Request => "REQUEST",
            Dhcp6MessageType::Confirm => "CONFIRM",
            Dhcp6MessageType::Renew => "RENEW",
            Dhcp6MessageType::Rebind => "REBIND",
            Dhcp6MessageType::Reply => "REPLY",
            Dhcp6MessageType::Release => "RELEASE",
            Dhcp6MessageType::Decline => "DECLINE",
            Dhcp6MessageType::Reconfigure => "RECONFIGURE",
            Dhcp6MessageType::InformationRequest => "INFORMATION-REQUEST",
            Dhcp6MessageType::RelayForw => "RELAY-FORW",
            Dhcp6MessageType::RelayRepl => "RELAY-REPL",
        }
    }

    pub fn is_relay(&self) -> bool {
        matches!(
            self,
            Dhcp6MessageType::RelayForw | Dhcp6MessageType::RelayRepl
        )
    }
}

/// A parsed DHCPv6 message. Client and relay variants are tagged by
/// the `Body` enum so the FSM can distinguish.
#[derive(Debug, Clone)]
pub struct Dhcp6Message {
    pub msg_type: Dhcp6MessageType,
    pub body: Dhcp6Body,
    pub options: Vec<Dhcp6Option>,
}

#[derive(Debug, Clone)]
pub enum Dhcp6Body {
    Client { xid: u32 },
    Relay(RelayHeader),
}

impl Dhcp6Message {
    /// Parse a DHCPv6 datagram (one layer). To unwrap nested relay
    /// chains use [`Self::unwrap_relay`].
    pub fn decode(buf: &[u8]) -> Result<Self, DhcpdError> {
        if buf.is_empty() {
            return Err(DhcpdError::Parse("empty DHCPv6 datagram".into()));
        }
        let msg_type = Dhcp6MessageType::from_u8(buf[0])?;
        if msg_type.is_relay() {
            if buf.len() < DHCP6_RELAY_HEADER_LEN {
                return Err(DhcpdError::Parse(
                    "relay datagram too short for header".into(),
                ));
            }
            let (header, rest) = RelayHeader::decode(buf)?;
            let options = decode_options(rest)?;
            Ok(Dhcp6Message {
                msg_type,
                body: Dhcp6Body::Relay(header),
                options,
            })
        } else {
            if buf.len() < DHCP6_CLIENT_HEADER_LEN {
                return Err(DhcpdError::Parse(
                    "client datagram too short for header".into(),
                ));
            }
            let (header, rest) = Dhcp6Header::decode(buf)?;
            let options = decode_options(rest)?;
            Ok(Dhcp6Message {
                msg_type,
                body: Dhcp6Body::Client { xid: header.xid },
                options,
            })
        }
    }

    /// Encode back to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.options.len() * 16);
        match &self.body {
            Dhcp6Body::Client { xid } => {
                Dhcp6Header {
                    msg_type: self.msg_type as u8,
                    xid: *xid,
                }
                .encode(&mut buf);
            }
            Dhcp6Body::Relay(header) => {
                let mut h = *header;
                h.msg_type = self.msg_type as u8;
                h.encode(&mut buf);
            }
        }
        for o in &self.options {
            o.encode(&mut buf);
        }
        buf
    }

    /// If this message is Relay-Forw / Relay-Repl, look up the
    /// inner Relay-Msg option and decode it as another Dhcp6Message.
    /// Returns `Ok(None)` for a client message (no relay wrapping).
    pub fn unwrap_relay(&self) -> Result<Option<Dhcp6Message>, DhcpdError> {
        if !self.msg_type.is_relay() {
            return Ok(None);
        }
        let inner = crate::packet::v6::options::find_relay_message(&self.options)
            .ok_or_else(|| {
                DhcpdError::Parse("Relay-Forw/Repl missing Relay-Msg option".into())
            })?;
        let parsed = Dhcp6Message::decode(inner)?;
        Ok(Some(parsed))
    }

    /// Peel all relay layers and return the innermost client
    /// message, along with the chain of relay headers from outer
    /// to inner. Used when the FSM needs to dispatch on the
    /// client's own message type.
    pub fn peel_relays(&self) -> Result<(Vec<RelayHeader>, Dhcp6Message), DhcpdError> {
        let mut relays = Vec::new();
        let mut cur = self.clone();
        while let Some(inner) = cur.unwrap_relay()? {
            if let Dhcp6Body::Relay(h) = cur.body {
                relays.push(h);
            }
            cur = inner;
        }
        if matches!(cur.body, Dhcp6Body::Relay(_)) {
            return Err(DhcpdError::Parse(
                "relay chain bottom is still a relay message".into(),
            ));
        }
        Ok((relays, cur))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::v6::duid::Duid;
    use crate::packet::v6::options::IaNa;

    fn sample_solicit_bytes(xid: u32) -> Vec<u8> {
        let msg = Dhcp6Message {
            msg_type: Dhcp6MessageType::Solicit,
            body: Dhcp6Body::Client { xid },
            options: vec![
                Dhcp6Option::ClientId(
                    Duid::parse(&[0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).unwrap(),
                ),
                Dhcp6Option::IaNa(IaNa {
                    iaid: 1,
                    t1: 0,
                    t2: 0,
                    addresses: vec![],
                    status: None,
                }),
            ],
        };
        msg.encode()
    }

    #[test]
    fn client_solicit_round_trip() {
        let bytes = sample_solicit_bytes(0x123456);
        let back = Dhcp6Message::decode(&bytes).unwrap();
        assert_eq!(back.msg_type, Dhcp6MessageType::Solicit);
        match back.body {
            Dhcp6Body::Client { xid } => assert_eq!(xid, 0x123456),
            _ => panic!("expected Client body"),
        }
        assert_eq!(back.options.len(), 2);
    }

    #[test]
    fn relay_forw_wraps_client_solicit() {
        let inner_bytes = sample_solicit_bytes(0xabcd);
        let relay = Dhcp6Message {
            msg_type: Dhcp6MessageType::RelayForw,
            body: Dhcp6Body::Relay(RelayHeader {
                msg_type: 12,
                hop_count: 0,
                link_address: "2001:db8::1".parse().unwrap(),
                peer_address: "fe80::1".parse().unwrap(),
            }),
            options: vec![
                Dhcp6Option::InterfaceId(b"lan.100".to_vec()),
                Dhcp6Option::RelayMessage(inner_bytes),
            ],
        };
        let bytes = relay.encode();
        let decoded = Dhcp6Message::decode(&bytes).unwrap();
        assert_eq!(decoded.msg_type, Dhcp6MessageType::RelayForw);
        let inner = decoded.unwrap_relay().unwrap().unwrap();
        assert_eq!(inner.msg_type, Dhcp6MessageType::Solicit);
        if let Dhcp6Body::Client { xid } = inner.body {
            assert_eq!(xid, 0xabcd);
        } else {
            panic!("expected inner Client");
        }
    }

    #[test]
    fn nested_relay_forw_peels() {
        // Relay -> Relay -> Solicit.
        let inner_bytes = sample_solicit_bytes(1);
        let inner_relay = Dhcp6Message {
            msg_type: Dhcp6MessageType::RelayForw,
            body: Dhcp6Body::Relay(RelayHeader {
                msg_type: 12,
                hop_count: 0,
                link_address: "2001:db8:1::1".parse().unwrap(),
                peer_address: "fe80::1".parse().unwrap(),
            }),
            options: vec![Dhcp6Option::RelayMessage(inner_bytes)],
        };
        let inner_relay_bytes = inner_relay.encode();
        let outer = Dhcp6Message {
            msg_type: Dhcp6MessageType::RelayForw,
            body: Dhcp6Body::Relay(RelayHeader {
                msg_type: 12,
                hop_count: 1,
                link_address: "2001:db8:2::1".parse().unwrap(),
                peer_address: "fe80::2".parse().unwrap(),
            }),
            options: vec![Dhcp6Option::RelayMessage(inner_relay_bytes)],
        };
        let (relays, inner_client) = outer.peel_relays().unwrap();
        assert_eq!(relays.len(), 2);
        assert_eq!(inner_client.msg_type, Dhcp6MessageType::Solicit);
    }

    #[test]
    fn peel_relays_on_client_message_returns_it() {
        let bytes = sample_solicit_bytes(1);
        let msg = Dhcp6Message::decode(&bytes).unwrap();
        let (relays, inner) = msg.peel_relays().unwrap();
        assert!(relays.is_empty());
        assert_eq!(inner.msg_type, Dhcp6MessageType::Solicit);
    }

    #[test]
    fn decode_rejects_unknown_message_type() {
        let buf = [99, 0, 0, 0];
        assert!(Dhcp6Message::decode(&buf).is_err());
    }

}
