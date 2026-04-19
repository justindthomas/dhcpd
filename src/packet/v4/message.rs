//! High-level DHCPv4 message: BOOTP header + typed options.
//!
//! The codec in [`crate::packet::v4::header`] and
//! [`crate::packet::v4::options`] operates on bytes; this module
//! assembles them into a single [`DhcpMessage`] with a typed
//! [`DhcpMessageType`] and keeps the raw option list for unusual
//! cases.

use crate::error::DhcpdError;
use crate::packet::v4::header::{decode_header, encode_header, BootpHeader};
use crate::packet::v4::options::{
    decode_options, encode_options, find_message_type, DhcpOption,
};

/// RFC 2131 §9.6 message type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl DhcpMessageType {
    pub fn from_u8(v: u8) -> Result<Self, DhcpdError> {
        Ok(match v {
            1 => DhcpMessageType::Discover,
            2 => DhcpMessageType::Offer,
            3 => DhcpMessageType::Request,
            4 => DhcpMessageType::Decline,
            5 => DhcpMessageType::Ack,
            6 => DhcpMessageType::Nak,
            7 => DhcpMessageType::Release,
            8 => DhcpMessageType::Inform,
            other => return Err(DhcpdError::Parse(format!("unknown dhcp msg type {}", other))),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            DhcpMessageType::Discover => "DISCOVER",
            DhcpMessageType::Offer => "OFFER",
            DhcpMessageType::Request => "REQUEST",
            DhcpMessageType::Decline => "DECLINE",
            DhcpMessageType::Ack => "ACK",
            DhcpMessageType::Nak => "NAK",
            DhcpMessageType::Release => "RELEASE",
            DhcpMessageType::Inform => "INFORM",
        }
    }
}

/// A full DHCP message — BOOTP header plus the decoded options list.
/// The `msg_type` is extracted from Option 53 for convenience; it's
/// redundant with `options` but every code path needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    pub header: BootpHeader,
    pub msg_type: DhcpMessageType,
    pub options: Vec<DhcpOption>,
}

impl DhcpMessage {
    /// Parse a full UDP payload into a DhcpMessage. Fails if the
    /// datagram is too short, the magic cookie is missing, or
    /// Option 53 (message type) is absent.
    pub fn decode(buf: &[u8]) -> Result<Self, DhcpdError> {
        let (header, options_area) = decode_header(buf)?;
        let options = decode_options(options_area)?;
        let msg_type_raw = find_message_type(&options)
            .ok_or_else(|| DhcpdError::Parse("missing option 53 (message type)".into()))?;
        let msg_type = DhcpMessageType::from_u8(msg_type_raw)?;
        Ok(DhcpMessage {
            header,
            msg_type,
            options,
        })
    }

    /// Encode a full UDP payload. The options list must contain a
    /// `MessageType(..)` option; this is not auto-inserted so
    /// reply-builders stay explicit about the type they're sending.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        encode_header(&self.header, &mut buf);
        encode_options(&self.options, &mut buf);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::v4::header::{BootOp, BOOTP_FLAG_BROADCAST};
    use std::net::Ipv4Addr;

    fn header_template(xid: u32) -> BootpHeader {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        BootpHeader {
            op: BootOp::Request,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags: BOOTP_FLAG_BROADCAST,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
        }
    }

    #[test]
    fn round_trip_discover() {
        let msg = DhcpMessage {
            header: header_template(0xdeadbeef),
            msg_type: DhcpMessageType::Discover,
            options: vec![
                DhcpOption::MessageType(1),
                DhcpOption::ParamRequestList(vec![1, 3, 6, 51]),
                DhcpOption::ClientIdentifier(vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ],
        };
        let bytes = msg.encode();
        let back = DhcpMessage::decode(&bytes).unwrap();
        assert_eq!(msg.header, back.header);
        assert_eq!(msg.msg_type, back.msg_type);
        assert_eq!(msg.options, back.options);
    }

    #[test]
    fn decode_rejects_missing_message_type() {
        let msg = DhcpMessage {
            header: header_template(1),
            msg_type: DhcpMessageType::Discover,
            options: vec![DhcpOption::ParamRequestList(vec![1])],
        };
        let bytes = msg.encode();
        let err = DhcpMessage::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("option 53"), "got: {}", err);
    }

    #[test]
    fn message_type_names() {
        assert_eq!(DhcpMessageType::Discover.name(), "DISCOVER");
        assert_eq!(DhcpMessageType::Ack.name(), "ACK");
        assert_eq!(DhcpMessageType::Nak.name(), "NAK");
    }

    #[test]
    fn unknown_message_type_errors() {
        assert!(DhcpMessageType::from_u8(99).is_err());
    }
}
