//! BOOTP fixed-format header (RFC 2131 §2, Figure 1).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +---------------+---------------+---------------+---------------+
//! |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
//! +---------------+---------------+---------------+---------------+
//! |                            xid (4)                            |
//! +-------------------------------+-------------------------------+
//! |           secs (2)            |           flags (2)           |
//! +-------------------------------+-------------------------------+
//! |                          ciaddr  (4)                          |
//! +---------------------------------------------------------------+
//! |                          yiaddr  (4)                          |
//! +---------------------------------------------------------------+
//! |                          siaddr  (4)                          |
//! +---------------------------------------------------------------+
//! |                          giaddr  (4)                          |
//! +---------------------------------------------------------------+
//! |                                                               |
//! |                          chaddr  (16)                         |
//! |                                                               |
//! |                                                               |
//! +---------------------------------------------------------------+
//! |                                                               |
//! |                          sname   (64)                         |
//! +---------------------------------------------------------------+
//! |                                                               |
//! |                          file    (128)                        |
//! +---------------------------------------------------------------+
//! |                          options (variable)                   |
//! +---------------------------------------------------------------+
//! ```
//!
//! Fixed portion is 236 bytes; the magic cookie + options follow,
//! with the options payload ending at the first END (0xff) option.

use std::net::Ipv4Addr;

use crate::error::DhcpdError;

/// BOOTP op field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootOp {
    Request = 1,
    Reply = 2,
}

impl BootOp {
    pub fn from_u8(v: u8) -> Result<Self, DhcpdError> {
        match v {
            1 => Ok(BootOp::Request),
            2 => Ok(BootOp::Reply),
            other => Err(DhcpdError::Parse(format!("bootp op {}", other))),
        }
    }
}

/// RFC 1497 magic cookie that marks the start of the options area.
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Size of the BOOTP fixed header up to (but not including) the
/// magic cookie. `236 = 4 + 4 + 2 + 2 + 4*4 + 16 + 64 + 128`.
pub const BOOTP_FIXED_LEN: usize = 236;

/// Minimum total BOOTP packet length per BOOTPS §3 and RFC 2131 §4.1:
/// fixed header + magic + END option = `236 + 4 + 1 = 241`. Clients
/// in the wild often expect ≥300 bytes so we zero-pad short replies
/// in the encoder.
pub const BOOTP_MIN_WIRE_LEN: usize = 300;

/// BOOTP broadcast flag (RFC 2131 §2): first bit of the flags field.
/// Clients set it when they can only accept broadcast replies
/// (no IP stack bound yet); servers mirror it in the response.
pub const BOOTP_FLAG_BROADCAST: u16 = 0x8000;

/// Parsed BOOTP header. The options area is stored as a raw byte
/// slice reference; the caller decodes it via [`crate::packet::v4::options`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootpHeader {
    pub op: BootOp,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    /// Hardware address — 16 bytes; ethernet uses first 6.
    pub chaddr: [u8; 16],
    /// Server name, NUL-padded. Usually empty.
    pub sname: [u8; 64],
    /// Boot file name, NUL-padded.
    pub file: [u8; 128],
}

impl BootpHeader {
    /// Is the broadcast bit set in `flags`?
    pub fn broadcast_flag(&self) -> bool {
        (self.flags & BOOTP_FLAG_BROADCAST) != 0
    }

    /// Return the client MAC (first 6 bytes of chaddr) when htype=1
    /// and hlen=6. Other htypes return None.
    pub fn ethernet_mac(&self) -> Option<[u8; 6]> {
        if self.htype == 1 && self.hlen == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&self.chaddr[..6]);
            Some(mac)
        } else {
            None
        }
    }
}

/// Decode the full BOOTP/DHCP datagram payload into a (header, options_area).
/// Caller invokes [`crate::packet::v4::options::decode_options`] on the returned
/// slice to parse individual TLVs.
pub fn decode_header(buf: &[u8]) -> Result<(BootpHeader, &[u8]), DhcpdError> {
    if buf.len() < BOOTP_FIXED_LEN + 4 {
        return Err(DhcpdError::Parse(format!(
            "datagram too short for BOOTP header: {} < {}",
            buf.len(),
            BOOTP_FIXED_LEN + 4
        )));
    }
    let op = BootOp::from_u8(buf[0])?;
    let htype = buf[1];
    let hlen = buf[2];
    let hops = buf[3];
    let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let secs = u16::from_be_bytes([buf[8], buf[9]]);
    let flags = u16::from_be_bytes([buf[10], buf[11]]);
    let ciaddr = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let yiaddr = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let siaddr = Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23]);
    let giaddr = Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]);
    let mut chaddr = [0u8; 16];
    chaddr.copy_from_slice(&buf[28..44]);
    let mut sname = [0u8; 64];
    sname.copy_from_slice(&buf[44..108]);
    let mut file = [0u8; 128];
    file.copy_from_slice(&buf[108..236]);
    // Magic cookie check
    if buf[236..240] != DHCP_MAGIC_COOKIE {
        return Err(DhcpdError::Parse(format!(
            "bad magic cookie: {:02x?}",
            &buf[236..240]
        )));
    }
    let hdr = BootpHeader {
        op,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr,
        sname,
        file,
    };
    Ok((hdr, &buf[240..]))
}

/// Encode a BOOTP header + magic cookie into `buf`. The caller
/// appends options and the END marker afterwards.
pub fn encode_header(hdr: &BootpHeader, buf: &mut Vec<u8>) {
    buf.push(hdr.op as u8);
    buf.push(hdr.htype);
    buf.push(hdr.hlen);
    buf.push(hdr.hops);
    buf.extend_from_slice(&hdr.xid.to_be_bytes());
    buf.extend_from_slice(&hdr.secs.to_be_bytes());
    buf.extend_from_slice(&hdr.flags.to_be_bytes());
    buf.extend_from_slice(&hdr.ciaddr.octets());
    buf.extend_from_slice(&hdr.yiaddr.octets());
    buf.extend_from_slice(&hdr.siaddr.octets());
    buf.extend_from_slice(&hdr.giaddr.octets());
    buf.extend_from_slice(&hdr.chaddr);
    buf.extend_from_slice(&hdr.sname);
    buf.extend_from_slice(&hdr.file);
    buf.extend_from_slice(&DHCP_MAGIC_COOKIE);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> BootpHeader {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        BootpHeader {
            op: BootOp::Request,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0x12345678,
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
    fn header_round_trip() {
        let hdr = sample_request();
        let mut buf = Vec::new();
        encode_header(&hdr, &mut buf);
        // One END option + minimum pad, to mirror what clients send.
        buf.push(0xff);
        let (back, opts) = decode_header(&buf).unwrap();
        assert_eq!(hdr, back);
        assert_eq!(opts, &[0xff]);
    }

    #[test]
    fn rejects_short_datagram() {
        let short = vec![0u8; 100];
        assert!(decode_header(&short).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let hdr = sample_request();
        let mut buf = Vec::new();
        encode_header(&hdr, &mut buf);
        buf[236] = 0; // corrupt the cookie
        let err = decode_header(&buf).unwrap_err();
        assert!(err.to_string().contains("magic cookie"));
    }

    #[test]
    fn broadcast_flag_parses() {
        let hdr = sample_request();
        assert!(hdr.broadcast_flag());
        let hdr = BootpHeader {
            flags: 0,
            ..sample_request()
        };
        assert!(!hdr.broadcast_flag());
    }

    #[test]
    fn ethernet_mac_extracts() {
        let hdr = sample_request();
        assert_eq!(hdr.ethernet_mac(), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn ethernet_mac_rejects_nonethernet() {
        let mut hdr = sample_request();
        hdr.htype = 6; // IEEE 802
        assert_eq!(hdr.ethernet_mac(), None);
    }
}
