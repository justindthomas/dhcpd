//! DHCPv6 option codec — RFC 8415 + RFC 3646 + RFC 4704 + RFC 6939.
//!
//! Each option: `[code:u16][len:u16][body:len]`. Some options
//! contain nested sub-options (IA_NA wraps IA_Address, for
//! example) — the nesting is recursive but shallow enough that a
//! straight-line parse is clear.

use std::net::Ipv6Addr;

use crate::error::DhcpdError;
use crate::packet::v6::duid::Duid;

// RFC 8415 Section 24 — IANA-assigned option codes.
pub const OPT_CLIENTID: u16 = 1;
pub const OPT_SERVERID: u16 = 2;
pub const OPT_IA_NA: u16 = 3;
pub const OPT_IA_TA: u16 = 4;
pub const OPT_IAADDR: u16 = 5;
pub const OPT_ORO: u16 = 6;
pub const OPT_PREFERENCE: u16 = 7;
pub const OPT_ELAPSED_TIME: u16 = 8;
pub const OPT_RELAY_MSG: u16 = 9;
pub const OPT_AUTH: u16 = 11;
pub const OPT_UNICAST: u16 = 12;
pub const OPT_STATUS_CODE: u16 = 13;
pub const OPT_RAPID_COMMIT: u16 = 14;
pub const OPT_USER_CLASS: u16 = 15;
pub const OPT_VENDOR_CLASS: u16 = 16;
pub const OPT_VENDOR_OPTS: u16 = 17;
pub const OPT_INTERFACE_ID: u16 = 18;
pub const OPT_RECONF_MSG: u16 = 19;
pub const OPT_RECONF_ACCEPT: u16 = 20;
pub const OPT_DNS_SERVERS: u16 = 23; // RFC 3646
pub const OPT_DOMAIN_LIST: u16 = 24; // RFC 3646
pub const OPT_IA_PD: u16 = 25; // Phase 4
pub const OPT_IAPREFIX: u16 = 26; // Phase 4
pub const OPT_INFO_REFRESH_TIME: u16 = 32;
pub const OPT_CLIENT_FQDN: u16 = 39; // RFC 4704
pub const OPT_PD_EXCLUDE: u16 = 67; // RFC 6603, Phase 4
pub const OPT_CLIENT_LINKLAYER_ADDR: u16 = 79; // RFC 6939
pub const OPT_SOL_MAX_RT: u16 = 82;
pub const OPT_INF_MAX_RT: u16 = 83;

/// RFC 8415 §21.13 status codes we set/check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusCode {
    Success = 0,
    UnspecFail = 1,
    NoAddrsAvail = 2,
    NoBinding = 3,
    NotOnLink = 4,
    UseMulticast = 5,
    NoPrefixAvail = 6,
}

impl StatusCode {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0 => StatusCode::Success,
            1 => StatusCode::UnspecFail,
            2 => StatusCode::NoAddrsAvail,
            3 => StatusCode::NoBinding,
            4 => StatusCode::NotOnLink,
            5 => StatusCode::UseMulticast,
            6 => StatusCode::NoPrefixAvail,
            _ => return None,
        })
    }
}

/// An IA Address sub-option body (RFC 8415 §21.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaAddress {
    pub address: Ipv6Addr,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    /// Nested status-code sub-option, if present.
    pub status: Option<(StatusCode, String)>,
}

/// An IA_NA (non-temporary address) option body (RFC 8415 §21.4).
/// Holds zero-or-more `IaAddress` plus an optional nested status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaNa {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub addresses: Vec<IaAddress>,
    pub status: Option<(StatusCode, String)>,
}

/// An IAPrefix sub-option body (RFC 8415 §21.22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaPrefix {
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub prefix_len: u8,
    pub prefix: Ipv6Addr,
    pub status: Option<(StatusCode, String)>,
}

/// An IA_PD (identity association for prefix delegation) option
/// body (RFC 8415 §21.21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaPd {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub prefixes: Vec<IaPrefix>,
    pub status: Option<(StatusCode, String)>,
}

/// A decoded DHCPv6 option.
///
/// Known codes are typed; everything else lands in `Unknown` with
/// raw bytes so callers can echo/log without a structural claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dhcp6Option {
    ClientId(Duid),
    ServerId(Duid),
    IaNa(IaNa),
    /// Standalone IA Address outside an IA_NA wrapper (unusual; some
    /// clients send this in Request).
    IaAddress(IaAddress),
    IaPd(IaPd),
    /// Standalone IAPrefix — rare outside IA_PD but handled for
    /// completeness.
    IaPrefix(IaPrefix),
    Oro(Vec<u16>),
    Preference(u8),
    ElapsedTime(u16),
    /// Nested DHCPv6 message raw bytes (RFC 8415 §21.10).
    RelayMessage(Vec<u8>),
    /// Unique identifier the relay supplies so it can match a reply
    /// back to an ingress interface (RFC 8415 §21.18).
    InterfaceId(Vec<u8>),
    StatusCode(StatusCode, String),
    RapidCommit,
    /// RFC 6939 — link-layer address of the client as seen by the
    /// relay. Type (2 bytes) + body.
    ClientLinklayerAddr(u16, Vec<u8>),
    DnsServers(Vec<Ipv6Addr>),
    DomainList(Vec<u8>),
    /// RFC 4704 Client-FQDN. Body parsed opaquely for v1.
    ClientFqdn(Vec<u8>),
    SolMaxRt(u32),
    InfMaxRt(u32),
    InfoRefreshTime(u32),
    Unknown { code: u16, data: Vec<u8> },
}

impl Dhcp6Option {
    pub fn code(&self) -> u16 {
        match self {
            Dhcp6Option::ClientId(_) => OPT_CLIENTID,
            Dhcp6Option::ServerId(_) => OPT_SERVERID,
            Dhcp6Option::IaNa(_) => OPT_IA_NA,
            Dhcp6Option::IaAddress(_) => OPT_IAADDR,
            Dhcp6Option::IaPd(_) => OPT_IA_PD,
            Dhcp6Option::IaPrefix(_) => OPT_IAPREFIX,
            Dhcp6Option::Oro(_) => OPT_ORO,
            Dhcp6Option::Preference(_) => OPT_PREFERENCE,
            Dhcp6Option::ElapsedTime(_) => OPT_ELAPSED_TIME,
            Dhcp6Option::RelayMessage(_) => OPT_RELAY_MSG,
            Dhcp6Option::InterfaceId(_) => OPT_INTERFACE_ID,
            Dhcp6Option::StatusCode(_, _) => OPT_STATUS_CODE,
            Dhcp6Option::RapidCommit => OPT_RAPID_COMMIT,
            Dhcp6Option::ClientLinklayerAddr(_, _) => OPT_CLIENT_LINKLAYER_ADDR,
            Dhcp6Option::DnsServers(_) => OPT_DNS_SERVERS,
            Dhcp6Option::DomainList(_) => OPT_DOMAIN_LIST,
            Dhcp6Option::ClientFqdn(_) => OPT_CLIENT_FQDN,
            Dhcp6Option::SolMaxRt(_) => OPT_SOL_MAX_RT,
            Dhcp6Option::InfMaxRt(_) => OPT_INF_MAX_RT,
            Dhcp6Option::InfoRefreshTime(_) => OPT_INFO_REFRESH_TIME,
            Dhcp6Option::Unknown { code, .. } => *code,
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Dhcp6Option::ClientId(d) => encode_raw(buf, OPT_CLIENTID, d.as_bytes()),
            Dhcp6Option::ServerId(d) => encode_raw(buf, OPT_SERVERID, d.as_bytes()),
            Dhcp6Option::IaNa(ia) => encode_iana(buf, ia),
            Dhcp6Option::IaAddress(a) => encode_iaaddr(buf, a),
            Dhcp6Option::IaPd(ia) => encode_iapd(buf, ia),
            Dhcp6Option::IaPrefix(p) => encode_iaprefix(buf, p),
            Dhcp6Option::Oro(codes) => {
                let mut body = Vec::with_capacity(codes.len() * 2);
                for c in codes {
                    body.extend_from_slice(&c.to_be_bytes());
                }
                encode_raw(buf, OPT_ORO, &body);
            }
            Dhcp6Option::Preference(v) => encode_raw(buf, OPT_PREFERENCE, &[*v]),
            Dhcp6Option::ElapsedTime(v) => encode_raw(buf, OPT_ELAPSED_TIME, &v.to_be_bytes()),
            Dhcp6Option::RelayMessage(b) => encode_raw(buf, OPT_RELAY_MSG, b),
            Dhcp6Option::InterfaceId(b) => encode_raw(buf, OPT_INTERFACE_ID, b),
            Dhcp6Option::StatusCode(code, msg) => {
                let mut body = Vec::with_capacity(2 + msg.len());
                body.extend_from_slice(&(*code as u16).to_be_bytes());
                body.extend_from_slice(msg.as_bytes());
                encode_raw(buf, OPT_STATUS_CODE, &body);
            }
            Dhcp6Option::RapidCommit => encode_raw(buf, OPT_RAPID_COMMIT, &[]),
            Dhcp6Option::ClientLinklayerAddr(hw_type, body) => {
                let mut full = Vec::with_capacity(2 + body.len());
                full.extend_from_slice(&hw_type.to_be_bytes());
                full.extend_from_slice(body);
                encode_raw(buf, OPT_CLIENT_LINKLAYER_ADDR, &full);
            }
            Dhcp6Option::DnsServers(servers) => {
                let mut body = Vec::with_capacity(servers.len() * 16);
                for s in servers {
                    body.extend_from_slice(&s.octets());
                }
                encode_raw(buf, OPT_DNS_SERVERS, &body);
            }
            Dhcp6Option::DomainList(b) => encode_raw(buf, OPT_DOMAIN_LIST, b),
            Dhcp6Option::ClientFqdn(b) => encode_raw(buf, OPT_CLIENT_FQDN, b),
            Dhcp6Option::SolMaxRt(v) => encode_raw(buf, OPT_SOL_MAX_RT, &v.to_be_bytes()),
            Dhcp6Option::InfMaxRt(v) => encode_raw(buf, OPT_INF_MAX_RT, &v.to_be_bytes()),
            Dhcp6Option::InfoRefreshTime(v) => {
                encode_raw(buf, OPT_INFO_REFRESH_TIME, &v.to_be_bytes())
            }
            Dhcp6Option::Unknown { code, data } => encode_raw(buf, *code, data),
        }
    }
}

fn encode_raw(buf: &mut Vec<u8>, code: u16, body: &[u8]) {
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
    buf.extend_from_slice(body);
}

fn encode_iana(buf: &mut Vec<u8>, ia: &IaNa) {
    // IA_NA body: iaid(4) + t1(4) + t2(4) + sub-options.
    let mut body = Vec::with_capacity(12 + ia.addresses.len() * 28);
    body.extend_from_slice(&ia.iaid.to_be_bytes());
    body.extend_from_slice(&ia.t1.to_be_bytes());
    body.extend_from_slice(&ia.t2.to_be_bytes());
    for a in &ia.addresses {
        encode_iaaddr(&mut body, a);
    }
    if let Some((c, m)) = &ia.status {
        let mut sc = Vec::with_capacity(2 + m.len());
        sc.extend_from_slice(&(*c as u16).to_be_bytes());
        sc.extend_from_slice(m.as_bytes());
        encode_raw(&mut body, OPT_STATUS_CODE, &sc);
    }
    encode_raw(buf, OPT_IA_NA, &body);
}

fn encode_iaaddr(buf: &mut Vec<u8>, a: &IaAddress) {
    // IA Address body: addr(16) + preferred(4) + valid(4) + sub-options.
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&a.address.octets());
    body.extend_from_slice(&a.preferred_lifetime.to_be_bytes());
    body.extend_from_slice(&a.valid_lifetime.to_be_bytes());
    if let Some((c, m)) = &a.status {
        let mut sc = Vec::with_capacity(2 + m.len());
        sc.extend_from_slice(&(*c as u16).to_be_bytes());
        sc.extend_from_slice(m.as_bytes());
        encode_raw(&mut body, OPT_STATUS_CODE, &sc);
    }
    encode_raw(buf, OPT_IAADDR, &body);
}

fn encode_iapd(buf: &mut Vec<u8>, ia: &IaPd) {
    // IA_PD body: iaid(4) + t1(4) + t2(4) + IAPrefix sub-options.
    let mut body = Vec::with_capacity(12 + ia.prefixes.len() * 29);
    body.extend_from_slice(&ia.iaid.to_be_bytes());
    body.extend_from_slice(&ia.t1.to_be_bytes());
    body.extend_from_slice(&ia.t2.to_be_bytes());
    for p in &ia.prefixes {
        encode_iaprefix(&mut body, p);
    }
    if let Some((c, m)) = &ia.status {
        let mut sc = Vec::with_capacity(2 + m.len());
        sc.extend_from_slice(&(*c as u16).to_be_bytes());
        sc.extend_from_slice(m.as_bytes());
        encode_raw(&mut body, OPT_STATUS_CODE, &sc);
    }
    encode_raw(buf, OPT_IA_PD, &body);
}

fn encode_iaprefix(buf: &mut Vec<u8>, p: &IaPrefix) {
    // IAPrefix body: preferred(4) + valid(4) + prefix_len(1) +
    // prefix(16) + sub-options.
    let mut body = Vec::with_capacity(25);
    body.extend_from_slice(&p.preferred_lifetime.to_be_bytes());
    body.extend_from_slice(&p.valid_lifetime.to_be_bytes());
    body.push(p.prefix_len);
    body.extend_from_slice(&p.prefix.octets());
    if let Some((c, m)) = &p.status {
        let mut sc = Vec::with_capacity(2 + m.len());
        sc.extend_from_slice(&(*c as u16).to_be_bytes());
        sc.extend_from_slice(m.as_bytes());
        encode_raw(&mut body, OPT_STATUS_CODE, &sc);
    }
    encode_raw(buf, OPT_IAPREFIX, &body);
}

/// Decode a DHCPv6 options area. Stops at the end of `buf`.
pub fn decode_options(buf: &[u8]) -> Result<Vec<Dhcp6Option>, DhcpdError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if i + 4 > buf.len() {
            return Err(DhcpdError::Parse("truncated v6 option header".into()));
        }
        let code = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let body_start = i + 4;
        let body_end = body_start + len;
        if body_end > buf.len() {
            return Err(DhcpdError::Parse(format!(
                "v6 option {} len {} exceeds buffer",
                code, len
            )));
        }
        let body = &buf[body_start..body_end];
        out.push(decode_single(code, body)?);
        i = body_end;
    }
    Ok(out)
}

fn decode_single(code: u16, body: &[u8]) -> Result<Dhcp6Option, DhcpdError> {
    Ok(match code {
        OPT_CLIENTID => Dhcp6Option::ClientId(Duid::parse(body)?),
        OPT_SERVERID => Dhcp6Option::ServerId(Duid::parse(body)?),
        OPT_IA_NA => Dhcp6Option::IaNa(decode_iana(body)?),
        OPT_IAADDR => Dhcp6Option::IaAddress(decode_iaaddr(body)?),
        OPT_IA_PD => Dhcp6Option::IaPd(decode_iapd(body)?),
        OPT_IAPREFIX => Dhcp6Option::IaPrefix(decode_iaprefix(body)?),
        OPT_ORO => {
            if body.len() % 2 != 0 {
                return Err(DhcpdError::Parse(format!(
                    "ORO body must be multiple of 2, got {}",
                    body.len()
                )));
            }
            let codes = body
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            Dhcp6Option::Oro(codes)
        }
        OPT_PREFERENCE => {
            if body.len() != 1 {
                return Err(DhcpdError::Parse(format!(
                    "preference len {} (expected 1)",
                    body.len()
                )));
            }
            Dhcp6Option::Preference(body[0])
        }
        OPT_ELAPSED_TIME => {
            if body.len() != 2 {
                return Err(DhcpdError::Parse(format!(
                    "elapsed-time len {} (expected 2)",
                    body.len()
                )));
            }
            Dhcp6Option::ElapsedTime(u16::from_be_bytes([body[0], body[1]]))
        }
        OPT_RELAY_MSG => Dhcp6Option::RelayMessage(body.to_vec()),
        OPT_INTERFACE_ID => Dhcp6Option::InterfaceId(body.to_vec()),
        OPT_STATUS_CODE => {
            if body.len() < 2 {
                return Err(DhcpdError::Parse(format!(
                    "status-code len {} < 2",
                    body.len()
                )));
            }
            let code_raw = u16::from_be_bytes([body[0], body[1]]);
            let code = StatusCode::from_u16(code_raw).unwrap_or(StatusCode::UnspecFail);
            let msg = String::from_utf8_lossy(&body[2..]).into_owned();
            Dhcp6Option::StatusCode(code, msg)
        }
        OPT_RAPID_COMMIT => {
            if !body.is_empty() {
                return Err(DhcpdError::Parse(format!(
                    "rapid-commit has body {}",
                    body.len()
                )));
            }
            Dhcp6Option::RapidCommit
        }
        OPT_CLIENT_LINKLAYER_ADDR => {
            if body.len() < 2 {
                return Err(DhcpdError::Parse(format!(
                    "client-linklayer-addr len {} < 2",
                    body.len()
                )));
            }
            let hw_type = u16::from_be_bytes([body[0], body[1]]);
            Dhcp6Option::ClientLinklayerAddr(hw_type, body[2..].to_vec())
        }
        OPT_DNS_SERVERS => {
            if body.len() % 16 != 0 {
                return Err(DhcpdError::Parse(format!(
                    "dns-servers body {} not a multiple of 16",
                    body.len()
                )));
            }
            let servers = body
                .chunks_exact(16)
                .map(|c| {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(c);
                    Ipv6Addr::from(octets)
                })
                .collect();
            Dhcp6Option::DnsServers(servers)
        }
        OPT_DOMAIN_LIST => Dhcp6Option::DomainList(body.to_vec()),
        OPT_CLIENT_FQDN => Dhcp6Option::ClientFqdn(body.to_vec()),
        OPT_SOL_MAX_RT | OPT_INF_MAX_RT | OPT_INFO_REFRESH_TIME => {
            if body.len() != 4 {
                return Err(DhcpdError::Parse(format!(
                    "v6 uint32 option len {} (expected 4)",
                    body.len()
                )));
            }
            let v = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            match code {
                OPT_SOL_MAX_RT => Dhcp6Option::SolMaxRt(v),
                OPT_INF_MAX_RT => Dhcp6Option::InfMaxRt(v),
                _ => Dhcp6Option::InfoRefreshTime(v),
            }
        }
        _ => Dhcp6Option::Unknown {
            code,
            data: body.to_vec(),
        },
    })
}

fn decode_iana(body: &[u8]) -> Result<IaNa, DhcpdError> {
    if body.len() < 12 {
        return Err(DhcpdError::Parse(format!(
            "IA_NA body len {} < 12",
            body.len()
        )));
    }
    let iaid = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let t1 = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let t2 = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
    let subs = decode_options(&body[12..])?;
    let mut addresses = Vec::new();
    let mut status = None;
    for o in subs {
        match o {
            Dhcp6Option::IaAddress(a) => addresses.push(a),
            Dhcp6Option::StatusCode(c, m) => status = Some((c, m)),
            _ => {} // Ignore other sub-options for now.
        }
    }
    Ok(IaNa {
        iaid,
        t1,
        t2,
        addresses,
        status,
    })
}

fn decode_iaaddr(body: &[u8]) -> Result<IaAddress, DhcpdError> {
    if body.len() < 24 {
        return Err(DhcpdError::Parse(format!(
            "IA Address body len {} < 24",
            body.len()
        )));
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&body[..16]);
    let preferred = u32::from_be_bytes([body[16], body[17], body[18], body[19]]);
    let valid = u32::from_be_bytes([body[20], body[21], body[22], body[23]]);
    let subs = decode_options(&body[24..])?;
    let mut status = None;
    for o in subs {
        if let Dhcp6Option::StatusCode(c, m) = o {
            status = Some((c, m));
        }
    }
    Ok(IaAddress {
        address: Ipv6Addr::from(octets),
        preferred_lifetime: preferred,
        valid_lifetime: valid,
        status,
    })
}

fn decode_iapd(body: &[u8]) -> Result<IaPd, DhcpdError> {
    if body.len() < 12 {
        return Err(DhcpdError::Parse(format!(
            "IA_PD body len {} < 12",
            body.len()
        )));
    }
    let iaid = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let t1 = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let t2 = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
    let subs = decode_options(&body[12..])?;
    let mut prefixes = Vec::new();
    let mut status = None;
    for o in subs {
        match o {
            Dhcp6Option::IaPrefix(p) => prefixes.push(p),
            Dhcp6Option::StatusCode(c, m) => status = Some((c, m)),
            _ => {}
        }
    }
    Ok(IaPd {
        iaid,
        t1,
        t2,
        prefixes,
        status,
    })
}

fn decode_iaprefix(body: &[u8]) -> Result<IaPrefix, DhcpdError> {
    // IAPrefix body: preferred(4) + valid(4) + prefix_len(1) + prefix(16) + sub-options
    if body.len() < 25 {
        return Err(DhcpdError::Parse(format!(
            "IAPrefix body len {} < 25",
            body.len()
        )));
    }
    let preferred = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let valid = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let prefix_len = body[8];
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&body[9..25]);
    let subs = decode_options(&body[25..])?;
    let mut status = None;
    for o in subs {
        if let Dhcp6Option::StatusCode(c, m) = o {
            status = Some((c, m));
        }
    }
    Ok(IaPrefix {
        preferred_lifetime: preferred,
        valid_lifetime: valid,
        prefix_len,
        prefix: Ipv6Addr::from(octets),
        status,
    })
}

/// Find the first option of a given code in an options list.
pub fn find(opts: &[Dhcp6Option], want: u16) -> Option<&Dhcp6Option> {
    opts.iter().find(|o| o.code() == want)
}

pub fn find_client_id(opts: &[Dhcp6Option]) -> Option<&Duid> {
    opts.iter().find_map(|o| match o {
        Dhcp6Option::ClientId(d) => Some(d),
        _ => None,
    })
}

pub fn find_server_id(opts: &[Dhcp6Option]) -> Option<&Duid> {
    opts.iter().find_map(|o| match o {
        Dhcp6Option::ServerId(d) => Some(d),
        _ => None,
    })
}

pub fn find_ia_na(opts: &[Dhcp6Option]) -> Option<&IaNa> {
    opts.iter().find_map(|o| match o {
        Dhcp6Option::IaNa(ia) => Some(ia),
        _ => None,
    })
}

pub fn find_ia_pd(opts: &[Dhcp6Option]) -> Option<&IaPd> {
    opts.iter().find_map(|o| match o {
        Dhcp6Option::IaPd(ia) => Some(ia),
        _ => None,
    })
}

pub fn find_relay_message(opts: &[Dhcp6Option]) -> Option<&[u8]> {
    opts.iter().find_map(|o| match o {
        Dhcp6Option::RelayMessage(b) => Some(b.as_slice()),
        _ => None,
    })
}

pub fn find_interface_id(opts: &[Dhcp6Option]) -> Option<&[u8]> {
    opts.iter().find_map(|o| match o {
        Dhcp6Option::InterfaceId(b) => Some(b.as_slice()),
        _ => None,
    })
}

pub fn has_rapid_commit(opts: &[Dhcp6Option]) -> bool {
    opts.iter().any(|o| matches!(o, Dhcp6Option::RapidCommit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_round_trip() {
        let d = Duid::parse(&[0, 1, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6]).unwrap();
        let opt = Dhcp6Option::ClientId(d.clone());
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, vec![Dhcp6Option::ClientId(d)]);
    }

    #[test]
    fn iana_with_address_round_trip() {
        let addr = IaAddress {
            address: "2001:db8::1".parse().unwrap(),
            preferred_lifetime: 1800,
            valid_lifetime: 3600,
            status: None,
        };
        let ia = IaNa {
            iaid: 42,
            t1: 900,
            t2: 1575,
            addresses: vec![addr.clone()],
            status: None,
        };
        let opt = Dhcp6Option::IaNa(ia.clone());
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, vec![Dhcp6Option::IaNa(ia)]);
    }

    #[test]
    fn iapd_with_prefix_round_trip() {
        let p = IaPrefix {
            preferred_lifetime: 1800,
            valid_lifetime: 3600,
            prefix_len: 56,
            prefix: "2001:db8:1000::".parse().unwrap(),
            status: None,
        };
        let ia = IaPd {
            iaid: 42,
            t1: 900,
            t2: 1575,
            prefixes: vec![p.clone()],
            status: None,
        };
        let opt = Dhcp6Option::IaPd(ia.clone());
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, vec![Dhcp6Option::IaPd(ia)]);
    }

    #[test]
    fn iapd_with_status_noprefixavail() {
        let ia = IaPd {
            iaid: 1,
            t1: 0,
            t2: 0,
            prefixes: vec![],
            status: Some((StatusCode::NoPrefixAvail, "pool empty".into())),
        };
        let opt = Dhcp6Option::IaPd(ia.clone());
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        if let Dhcp6Option::IaPd(back) = &decoded[0] {
            assert_eq!(back.status, ia.status);
        } else {
            panic!("expected IaPd");
        }
    }

    #[test]
    fn iana_with_status_code_nested() {
        let ia = IaNa {
            iaid: 1,
            t1: 0,
            t2: 0,
            addresses: vec![],
            status: Some((StatusCode::NoAddrsAvail, "pool empty".into())),
        };
        let opt = Dhcp6Option::IaNa(ia.clone());
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        match &decoded[0] {
            Dhcp6Option::IaNa(got) => {
                assert_eq!(got.status, ia.status);
            }
            other => panic!("expected IaNa, got {:?}", other),
        }
    }

    #[test]
    fn dns_servers_multi_address() {
        let servers = vec![
            "2001:4860:4860::8888".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        let opt = Dhcp6Option::DnsServers(servers.clone());
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, vec![Dhcp6Option::DnsServers(servers)]);
    }

    #[test]
    fn rapid_commit_is_empty_body() {
        let opt = Dhcp6Option::RapidCommit;
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        assert_eq!(buf, vec![0, 14, 0, 0]);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, vec![Dhcp6Option::RapidCommit]);
    }

    #[test]
    fn status_code_round_trip() {
        let opt = Dhcp6Option::StatusCode(StatusCode::Success, "all good".into());
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(
            decoded,
            vec![Dhcp6Option::StatusCode(StatusCode::Success, "all good".into())]
        );
    }

    #[test]
    fn relay_message_preserves_bytes() {
        let opt = Dhcp6Option::RelayMessage(vec![1, 0x01, 0x02, 0x03, 0, 1, 0, 2, 0, 0]);
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded[0], opt);
    }

    #[test]
    fn interface_id_preserves_bytes() {
        let opt = Dhcp6Option::InterfaceId(b"eth0.100".to_vec());
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded[0], opt);
    }

    #[test]
    fn oro_round_trip() {
        let opt = Dhcp6Option::Oro(vec![OPT_DNS_SERVERS, OPT_DOMAIN_LIST, OPT_SOL_MAX_RT]);
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded[0], opt);
    }

    #[test]
    fn client_linklayer_addr_round_trip() {
        let opt = Dhcp6Option::ClientLinklayerAddr(1, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded[0], opt);
    }

    #[test]
    fn decode_rejects_truncated() {
        let buf = [0, 1, 0, 10, 0, 0, 0]; // says len=10 but only 3 body bytes
        assert!(decode_options(&buf).is_err());
    }

    #[test]
    fn unknown_code_preserved() {
        // Fabricate option 300 (well into reserved space).
        let mut buf = Vec::new();
        buf.extend_from_slice(&300u16.to_be_bytes());
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3]);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(
            decoded[0],
            Dhcp6Option::Unknown {
                code: 300,
                data: vec![1, 2, 3],
            }
        );
    }

    #[test]
    fn finders_work() {
        let duid = Duid::parse(&[0, 3, 0, 1, 1, 2, 3, 4, 5, 6]).unwrap();
        let opts = vec![
            Dhcp6Option::ClientId(duid.clone()),
            Dhcp6Option::ElapsedTime(50),
            Dhcp6Option::RapidCommit,
        ];
        assert_eq!(find_client_id(&opts), Some(&duid));
        assert!(has_rapid_commit(&opts));
    }
}
