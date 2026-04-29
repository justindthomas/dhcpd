//! DHCPv4 option codec.
//!
//! Each option is a `[code:1][len:1][body:len]` TLV. The PAD (0x00)
//! option has no length byte; END (0xff) terminates the options area.
//!
//! Option codes covered (v1 scope):
//!
//! | code | RFC  | name                           | codec |
//! |------|------|--------------------------------|-------|
//! |   1  | 2132 | Subnet Mask                    | `SubnetMask`         |
//! |   3  | 2132 | Router                         | `Router`             |
//! |   6  | 2132 | Domain Name Server             | `DomainNameServer`   |
//! |  12  | 2132 | Host Name                      | `HostName`           |
//! |  15  | 2132 | Domain Name                    | `DomainName`         |
//! |  28  | 2132 | Broadcast Address              | `BroadcastAddress`   |
//! |  50  | 2132 | Requested IP Address           | `RequestedIp`        |
//! |  51  | 2132 | Lease Time                     | `LeaseTime`          |
//! |  53  | 2132 | DHCP Message Type              | `MessageType`        |
//! |  54  | 2132 | Server Identifier              | `ServerId`           |
//! |  55  | 2132 | Parameter Request List         | `ParamRequestList`   |
//! |  57  | 2132 | Max DHCP Message Size          | `MaxMessageSize`     |
//! |  58  | 2132 | Renewal Time (T1)              | `RenewalTime`        |
//! |  59  | 2132 | Rebinding Time (T2)            | `RebindingTime`      |
//! |  60  | 2132 | Vendor Class Identifier        | `VendorClass`        |
//! |  61  | 4361 | Client Identifier              | `ClientIdentifier`   |
//! |  82  | 3046 | Relay Agent Information        | `RelayAgentInfo`     |
//! | 108  | 8925 | IPv6-Only Preferred (V6ONLY_WAIT) | `V6OnlyPreferred` |
//! | 121  | 3442 | Classless Static Route         | `ClasslessStaticRoute` |
//! | 255  | 2132 | End                            | implicit             |

use std::net::Ipv4Addr;

use crate::error::DhcpdError;

/// Marker value for the end of the options area (RFC 2132 §3.1).
pub const DECODE_END_OF_OPTIONS: u8 = 0xff;

// Individual option codes.
pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_HOST_NAME: u8 = 12;
pub const OPT_DOMAIN_NAME: u8 = 15;
pub const OPT_BROADCAST_ADDR: u8 = 28;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_MESSAGE_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_REQUEST_LIST: u8 = 55;
pub const OPT_MAX_MESSAGE_SIZE: u8 = 57;
pub const OPT_RENEWAL_TIME: u8 = 58;
pub const OPT_REBINDING_TIME: u8 = 59;
pub const OPT_VENDOR_CLASS: u8 = 60;
pub const OPT_CLIENT_IDENTIFIER: u8 = 61;
pub const OPT_RELAY_AGENT_INFO: u8 = 82;
pub const OPT_V6_ONLY_PREFERRED: u8 = 108;
pub const OPT_CLASSLESS_STATIC_ROUTE: u8 = 121;
pub const OPT_END: u8 = 0xff;

/// RFC 8925 §3.5: clients clamp any received V6ONLY_WAIT < 300 to 300.
/// Servers SHOULD send a value at least this large.
pub const MIN_V6ONLY_WAIT: u32 = 300;

// Option 82 sub-option codes (RFC 3046).
pub const SUBOPT_CIRCUIT_ID: u8 = 1;
pub const SUBOPT_REMOTE_ID: u8 = 2;
pub const SUBOPT_LINK_SELECTION: u8 = 5;
pub const SUBOPT_SERVER_ID_OVERRIDE: u8 = 11;

/// A classless static-route entry for Option 121. RFC 3442 encodes
/// each entry as `[dest_prefix_len:1][dest_bytes][gateway:4]` where
/// `dest_bytes` is the minimum number of octets needed to hold the
/// significant bits of the destination prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
}

impl RouteEntry {
    /// Number of prefix bytes transmitted on the wire for this entry.
    fn prefix_byte_len(&self) -> usize {
        ((self.prefix_len + 7) / 8) as usize
    }
}

/// Parsed Option 82 (RFC 3046) payload. Unknown sub-options are
/// preserved as raw bytes so a server can echo them back untouched
/// per §2.0 "server MUST return this option unmodified".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Option82 {
    pub circuit_id: Option<Vec<u8>>,
    pub remote_id: Option<Vec<u8>>,
    /// Sub-option 5 — link-selection (RFC 3527). Server honors only
    /// when its interface config has `dhcp_server_trust_relay: true`.
    pub link_selection: Option<Ipv4Addr>,
    /// Sub-option 11 — server-id-override (RFC 5107).
    pub server_id_override: Option<Ipv4Addr>,
    /// Unparsed sub-options, kept so we can echo them back verbatim.
    pub raw: Vec<u8>,
}

/// A decoded DHCP option. Unknown codes land in `Unknown` so we can
/// round-trip them if needed (rare but useful for logging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DomainNameServer(Vec<Ipv4Addr>),
    HostName(String),
    DomainName(String),
    BroadcastAddress(Ipv4Addr),
    RequestedIp(Ipv4Addr),
    LeaseTime(u32),
    MessageType(u8),
    ServerId(Ipv4Addr),
    ParamRequestList(Vec<u8>),
    MaxMessageSize(u16),
    RenewalTime(u32),
    RebindingTime(u32),
    VendorClass(Vec<u8>),
    ClientIdentifier(Vec<u8>),
    RelayAgentInfo(Option82),
    /// RFC 8925 — V6ONLY_WAIT timer in seconds. When present in a
    /// DHCPOFFER/DHCPACK with `yiaddr=0`, tells the client to disable
    /// IPv4 on this interface for the duration. Server only includes
    /// this when the client requested option 108 in its PRL.
    V6OnlyPreferred(u32),
    ClasslessStaticRoute(Vec<RouteEntry>),
    Unknown { code: u8, data: Vec<u8> },
}

impl DhcpOption {
    pub fn code(&self) -> u8 {
        match self {
            DhcpOption::SubnetMask(_) => OPT_SUBNET_MASK,
            DhcpOption::Router(_) => OPT_ROUTER,
            DhcpOption::DomainNameServer(_) => OPT_DNS,
            DhcpOption::HostName(_) => OPT_HOST_NAME,
            DhcpOption::DomainName(_) => OPT_DOMAIN_NAME,
            DhcpOption::BroadcastAddress(_) => OPT_BROADCAST_ADDR,
            DhcpOption::RequestedIp(_) => OPT_REQUESTED_IP,
            DhcpOption::LeaseTime(_) => OPT_LEASE_TIME,
            DhcpOption::MessageType(_) => OPT_MESSAGE_TYPE,
            DhcpOption::ServerId(_) => OPT_SERVER_ID,
            DhcpOption::ParamRequestList(_) => OPT_PARAM_REQUEST_LIST,
            DhcpOption::MaxMessageSize(_) => OPT_MAX_MESSAGE_SIZE,
            DhcpOption::RenewalTime(_) => OPT_RENEWAL_TIME,
            DhcpOption::RebindingTime(_) => OPT_REBINDING_TIME,
            DhcpOption::VendorClass(_) => OPT_VENDOR_CLASS,
            DhcpOption::ClientIdentifier(_) => OPT_CLIENT_IDENTIFIER,
            DhcpOption::RelayAgentInfo(_) => OPT_RELAY_AGENT_INFO,
            DhcpOption::V6OnlyPreferred(_) => OPT_V6_ONLY_PREFERRED,
            DhcpOption::ClasslessStaticRoute(_) => OPT_CLASSLESS_STATIC_ROUTE,
            DhcpOption::Unknown { code, .. } => *code,
        }
    }

    /// Encode this option as a TLV into `buf`. Multi-byte options
    /// are written in network order.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            DhcpOption::SubnetMask(a) => {
                push_ip(buf, OPT_SUBNET_MASK, a);
            }
            DhcpOption::Router(list) => {
                push_ip_list(buf, OPT_ROUTER, list);
            }
            DhcpOption::DomainNameServer(list) => {
                push_ip_list(buf, OPT_DNS, list);
            }
            DhcpOption::HostName(s) => {
                push_string(buf, OPT_HOST_NAME, s);
            }
            DhcpOption::DomainName(s) => {
                push_string(buf, OPT_DOMAIN_NAME, s);
            }
            DhcpOption::BroadcastAddress(a) => {
                push_ip(buf, OPT_BROADCAST_ADDR, a);
            }
            DhcpOption::RequestedIp(a) => {
                push_ip(buf, OPT_REQUESTED_IP, a);
            }
            DhcpOption::LeaseTime(v) => {
                push_u32(buf, OPT_LEASE_TIME, *v);
            }
            DhcpOption::MessageType(t) => {
                buf.push(OPT_MESSAGE_TYPE);
                buf.push(1);
                buf.push(*t);
            }
            DhcpOption::ServerId(a) => {
                push_ip(buf, OPT_SERVER_ID, a);
            }
            DhcpOption::ParamRequestList(codes) => {
                push_bytes(buf, OPT_PARAM_REQUEST_LIST, codes);
            }
            DhcpOption::MaxMessageSize(v) => {
                buf.push(OPT_MAX_MESSAGE_SIZE);
                buf.push(2);
                buf.extend_from_slice(&v.to_be_bytes());
            }
            DhcpOption::RenewalTime(v) => {
                push_u32(buf, OPT_RENEWAL_TIME, *v);
            }
            DhcpOption::RebindingTime(v) => {
                push_u32(buf, OPT_REBINDING_TIME, *v);
            }
            DhcpOption::VendorClass(b) => {
                push_bytes(buf, OPT_VENDOR_CLASS, b);
            }
            DhcpOption::ClientIdentifier(b) => {
                push_bytes(buf, OPT_CLIENT_IDENTIFIER, b);
            }
            DhcpOption::RelayAgentInfo(agent) => {
                encode_option_82(buf, agent);
            }
            DhcpOption::V6OnlyPreferred(secs) => {
                push_u32(buf, OPT_V6_ONLY_PREFERRED, *secs);
            }
            DhcpOption::ClasslessStaticRoute(entries) => {
                encode_classless_routes(buf, entries);
            }
            DhcpOption::Unknown { code, data } => {
                push_bytes(buf, *code, data);
            }
        }
    }
}

fn push_ip(buf: &mut Vec<u8>, code: u8, a: &Ipv4Addr) {
    buf.push(code);
    buf.push(4);
    buf.extend_from_slice(&a.octets());
}

fn push_ip_list(buf: &mut Vec<u8>, code: u8, list: &[Ipv4Addr]) {
    buf.push(code);
    buf.push((list.len() * 4) as u8);
    for a in list {
        buf.extend_from_slice(&a.octets());
    }
}

fn push_string(buf: &mut Vec<u8>, code: u8, s: &str) {
    push_bytes(buf, code, s.as_bytes());
}

fn push_bytes(buf: &mut Vec<u8>, code: u8, b: &[u8]) {
    buf.push(code);
    buf.push(b.len() as u8);
    buf.extend_from_slice(b);
}

fn push_u32(buf: &mut Vec<u8>, code: u8, v: u32) {
    buf.push(code);
    buf.push(4);
    buf.extend_from_slice(&v.to_be_bytes());
}

fn encode_option_82(buf: &mut Vec<u8>, agent: &Option82) {
    // Re-encode from parsed fields — prefer this over echoing `raw`
    // because the server may have updated sub-options (server-id-
    // override, for example). Sub-options that weren't populated by
    // the parser are taken from `raw` so we round-trip opaque data.
    let mut body: Vec<u8> = Vec::new();
    if let Some(ci) = &agent.circuit_id {
        body.push(SUBOPT_CIRCUIT_ID);
        body.push(ci.len() as u8);
        body.extend_from_slice(ci);
    }
    if let Some(ri) = &agent.remote_id {
        body.push(SUBOPT_REMOTE_ID);
        body.push(ri.len() as u8);
        body.extend_from_slice(ri);
    }
    if let Some(ls) = agent.link_selection {
        body.push(SUBOPT_LINK_SELECTION);
        body.push(4);
        body.extend_from_slice(&ls.octets());
    }
    if let Some(sid) = agent.server_id_override {
        body.push(SUBOPT_SERVER_ID_OVERRIDE);
        body.push(4);
        body.extend_from_slice(&sid.octets());
    }
    // Append any raw (unknown) sub-options preserved by the parser.
    body.extend_from_slice(&agent.raw);
    push_bytes(buf, OPT_RELAY_AGENT_INFO, &body);
}

fn encode_classless_routes(buf: &mut Vec<u8>, entries: &[RouteEntry]) {
    let mut body: Vec<u8> = Vec::new();
    for e in entries {
        let prefix_bytes = e.prefix_byte_len();
        body.push(e.prefix_len);
        body.extend_from_slice(&e.prefix.octets()[..prefix_bytes]);
        body.extend_from_slice(&e.gateway.octets());
    }
    push_bytes(buf, OPT_CLASSLESS_STATIC_ROUTE, &body);
}

/// Decode an options area up to the first `END`. Returns the list
/// of parsed options. PAD bytes are silently skipped. Options with
/// invalid length or truncated body bail out with a Parse error.
pub fn decode_options(buf: &[u8]) -> Result<Vec<DhcpOption>, DhcpdError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let code = buf[i];
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            i += 1;
            continue;
        }
        if i + 1 >= buf.len() {
            return Err(DhcpdError::Parse(format!("truncated option {}", code)));
        }
        let len = buf[i + 1] as usize;
        let body_start = i + 2;
        let body_end = body_start + len;
        if body_end > buf.len() {
            return Err(DhcpdError::Parse(format!(
                "option {} len {} exceeds buffer ({} bytes left)",
                code,
                len,
                buf.len() - body_start
            )));
        }
        let body = &buf[body_start..body_end];
        out.push(decode_single(code, body)?);
        i = body_end;
    }
    Ok(out)
}

fn decode_single(code: u8, body: &[u8]) -> Result<DhcpOption, DhcpdError> {
    Ok(match code {
        OPT_SUBNET_MASK => DhcpOption::SubnetMask(expect_ip(code, body)?),
        OPT_ROUTER => DhcpOption::Router(expect_ip_list(code, body)?),
        OPT_DNS => DhcpOption::DomainNameServer(expect_ip_list(code, body)?),
        OPT_HOST_NAME => DhcpOption::HostName(String::from_utf8_lossy(body).into_owned()),
        OPT_DOMAIN_NAME => DhcpOption::DomainName(String::from_utf8_lossy(body).into_owned()),
        OPT_BROADCAST_ADDR => DhcpOption::BroadcastAddress(expect_ip(code, body)?),
        OPT_REQUESTED_IP => DhcpOption::RequestedIp(expect_ip(code, body)?),
        OPT_LEASE_TIME => DhcpOption::LeaseTime(expect_u32(code, body)?),
        OPT_MESSAGE_TYPE => {
            if body.len() != 1 {
                return Err(DhcpdError::Parse(format!(
                    "message-type len {} (expected 1)",
                    body.len()
                )));
            }
            DhcpOption::MessageType(body[0])
        }
        OPT_SERVER_ID => DhcpOption::ServerId(expect_ip(code, body)?),
        OPT_PARAM_REQUEST_LIST => DhcpOption::ParamRequestList(body.to_vec()),
        OPT_MAX_MESSAGE_SIZE => {
            if body.len() != 2 {
                return Err(DhcpdError::Parse(format!(
                    "max-message-size len {} (expected 2)",
                    body.len()
                )));
            }
            DhcpOption::MaxMessageSize(u16::from_be_bytes([body[0], body[1]]))
        }
        OPT_RENEWAL_TIME => DhcpOption::RenewalTime(expect_u32(code, body)?),
        OPT_REBINDING_TIME => DhcpOption::RebindingTime(expect_u32(code, body)?),
        OPT_VENDOR_CLASS => DhcpOption::VendorClass(body.to_vec()),
        OPT_CLIENT_IDENTIFIER => DhcpOption::ClientIdentifier(body.to_vec()),
        OPT_RELAY_AGENT_INFO => DhcpOption::RelayAgentInfo(decode_option_82(body)?),
        OPT_V6_ONLY_PREFERRED => DhcpOption::V6OnlyPreferred(expect_u32(code, body)?),
        OPT_CLASSLESS_STATIC_ROUTE => {
            DhcpOption::ClasslessStaticRoute(decode_classless_routes(body)?)
        }
        _ => DhcpOption::Unknown {
            code,
            data: body.to_vec(),
        },
    })
}

fn expect_ip(code: u8, body: &[u8]) -> Result<Ipv4Addr, DhcpdError> {
    if body.len() != 4 {
        return Err(DhcpdError::Parse(format!(
            "option {} expects 4 bytes, got {}",
            code,
            body.len()
        )));
    }
    Ok(Ipv4Addr::new(body[0], body[1], body[2], body[3]))
}

fn expect_ip_list(code: u8, body: &[u8]) -> Result<Vec<Ipv4Addr>, DhcpdError> {
    if body.len() % 4 != 0 || body.is_empty() {
        return Err(DhcpdError::Parse(format!(
            "option {} expects multiple of 4 bytes, got {}",
            code,
            body.len()
        )));
    }
    Ok(body
        .chunks_exact(4)
        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
        .collect())
}

fn expect_u32(code: u8, body: &[u8]) -> Result<u32, DhcpdError> {
    if body.len() != 4 {
        return Err(DhcpdError::Parse(format!(
            "option {} expects 4 bytes, got {}",
            code,
            body.len()
        )));
    }
    Ok(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
}

fn decode_option_82(body: &[u8]) -> Result<Option82, DhcpdError> {
    let mut out = Option82::default();
    let mut raw: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let code = body[i];
        if i + 1 >= body.len() {
            return Err(DhcpdError::Parse(
                "option 82 truncated sub-option".into(),
            ));
        }
        let len = body[i + 1] as usize;
        let sub_body_start = i + 2;
        let sub_body_end = sub_body_start + len;
        if sub_body_end > body.len() {
            return Err(DhcpdError::Parse(format!(
                "option 82 sub-{} len {} exceeds option body",
                code, len
            )));
        }
        let sub_body = &body[sub_body_start..sub_body_end];
        match code {
            SUBOPT_CIRCUIT_ID => out.circuit_id = Some(sub_body.to_vec()),
            SUBOPT_REMOTE_ID => out.remote_id = Some(sub_body.to_vec()),
            SUBOPT_LINK_SELECTION => out.link_selection = Some(expect_ip(code, sub_body)?),
            SUBOPT_SERVER_ID_OVERRIDE => {
                out.server_id_override = Some(expect_ip(code, sub_body)?)
            }
            _ => {
                // Preserve unknown sub-options as raw bytes so
                // encode_option_82 can echo them back unchanged.
                raw.push(code);
                raw.push(len as u8);
                raw.extend_from_slice(sub_body);
            }
        }
        i = sub_body_end;
    }
    out.raw = raw;
    Ok(out)
}

fn decode_classless_routes(body: &[u8]) -> Result<Vec<RouteEntry>, DhcpdError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let prefix_len = body[i];
        if prefix_len > 32 {
            return Err(DhcpdError::Parse(format!(
                "classless route prefix {} > 32",
                prefix_len
            )));
        }
        let prefix_bytes = ((prefix_len + 7) / 8) as usize;
        i += 1;
        if i + prefix_bytes + 4 > body.len() {
            return Err(DhcpdError::Parse(
                "classless route entry truncated".into(),
            ));
        }
        let mut prefix_octets = [0u8; 4];
        prefix_octets[..prefix_bytes].copy_from_slice(&body[i..i + prefix_bytes]);
        i += prefix_bytes;
        let gateway = Ipv4Addr::new(body[i], body[i + 1], body[i + 2], body[i + 3]);
        i += 4;
        out.push(RouteEntry {
            prefix: Ipv4Addr::from(prefix_octets),
            prefix_len,
            gateway,
        });
    }
    Ok(out)
}

/// Encode a full options area: [options...][END][pad to min 300-byte total].
/// `total_with_header` is the byte length of the entire BOOTP/DHCP
/// payload including the fixed header (`240`) and options up to the
/// END marker. The encoder pads with trailing zeroes so very short
/// replies still hit the RFC 2131 §4.1 minimum of 300 bytes.
pub fn encode_options(opts: &[DhcpOption], buf: &mut Vec<u8>) {
    for o in opts {
        o.encode(buf);
    }
    buf.push(OPT_END);
    while buf.len() < super::header::BOOTP_MIN_WIRE_LEN {
        buf.push(0);
    }
}

/// Look up the message-type option (53) in a decoded option list.
/// Most code paths want this specifically so we provide a helper.
pub fn find_message_type(opts: &[DhcpOption]) -> Option<u8> {
    opts.iter().find_map(|o| match o {
        DhcpOption::MessageType(t) => Some(*t),
        _ => None,
    })
}

/// Look up the server-identifier option (54) in a decoded option list.
pub fn find_server_id(opts: &[DhcpOption]) -> Option<Ipv4Addr> {
    opts.iter().find_map(|o| match o {
        DhcpOption::ServerId(a) => Some(*a),
        _ => None,
    })
}

/// Look up the requested-IP option (50) in a decoded option list.
pub fn find_requested_ip(opts: &[DhcpOption]) -> Option<Ipv4Addr> {
    opts.iter().find_map(|o| match o {
        DhcpOption::RequestedIp(a) => Some(*a),
        _ => None,
    })
}

/// Look up the relay-agent-info option (82).
pub fn find_option_82(opts: &[DhcpOption]) -> Option<&Option82> {
    opts.iter().find_map(|o| match o {
        DhcpOption::RelayAgentInfo(a) => Some(a),
        _ => None,
    })
}

/// Look up the client-identifier option (61) raw bytes.
pub fn find_client_identifier(opts: &[DhcpOption]) -> Option<&[u8]> {
    opts.iter().find_map(|o| match o {
        DhcpOption::ClientIdentifier(b) => Some(b.as_slice()),
        _ => None,
    })
}

/// Look up the parameter-request-list option (55) raw codes.
pub fn find_param_request_list(opts: &[DhcpOption]) -> Option<&[u8]> {
    opts.iter().find_map(|o| match o {
        DhcpOption::ParamRequestList(b) => Some(b.as_slice()),
        _ => None,
    })
}

/// True if the client signalled support for RFC 8925 IPv6-Only
/// Preferred — i.e. the parameter-request-list (option 55) contains
/// option code 108.
pub fn client_requests_v6_only_preferred(opts: &[DhcpOption]) -> bool {
    find_param_request_list(opts)
        .map(|prl| prl.contains(&OPT_V6_ONLY_PREFERRED))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_message_type_round_trips() {
        let opt = DhcpOption::MessageType(1);
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        buf.push(OPT_END);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, vec![DhcpOption::MessageType(1)]);
    }

    #[test]
    fn common_options_round_trip() {
        let mask: Ipv4Addr = "255.255.255.0".parse().unwrap();
        let router: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dns1: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let dns2: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let server: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let opts = vec![
            DhcpOption::MessageType(2),
            DhcpOption::ServerId(server),
            DhcpOption::LeaseTime(3600),
            DhcpOption::SubnetMask(mask),
            DhcpOption::Router(vec![router]),
            DhcpOption::DomainNameServer(vec![dns1, dns2]),
            DhcpOption::DomainName("example.net".into()),
            DhcpOption::HostName("client".into()),
            DhcpOption::BroadcastAddress("10.0.0.255".parse().unwrap()),
            DhcpOption::RequestedIp("10.0.0.50".parse().unwrap()),
            DhcpOption::MaxMessageSize(1500),
            DhcpOption::RenewalTime(1800),
            DhcpOption::RebindingTime(3150),
            DhcpOption::ParamRequestList(vec![1, 3, 6, 51]),
            DhcpOption::VendorClass(b"MSFT 5.0".to_vec()),
            DhcpOption::ClientIdentifier(vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        ];
        let mut buf = Vec::new();
        for o in &opts {
            o.encode(&mut buf);
        }
        buf.push(OPT_END);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, opts);
    }

    #[test]
    fn option_82_round_trip_with_unknown_suboption() {
        let mut body = Vec::new();
        // Known sub-options.
        body.push(SUBOPT_CIRCUIT_ID);
        body.push(4);
        body.extend_from_slice(b"port");
        body.push(SUBOPT_REMOTE_ID);
        body.push(5);
        body.extend_from_slice(b"rmtid");
        body.push(SUBOPT_LINK_SELECTION);
        body.push(4);
        body.extend_from_slice(&[10, 0, 0, 1]);
        // Unknown sub-option 99 — should be preserved verbatim.
        body.push(99);
        body.push(3);
        body.extend_from_slice(b"abc");

        let agent = decode_option_82(&body).unwrap();
        assert_eq!(agent.circuit_id.as_deref(), Some(b"port".as_ref()));
        assert_eq!(agent.remote_id.as_deref(), Some(b"rmtid".as_ref()));
        assert_eq!(agent.link_selection, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(agent.raw, vec![99, 3, b'a', b'b', b'c']);

        let mut reencoded = Vec::new();
        encode_option_82(&mut reencoded, &agent);
        // Decode again and compare logical equivalence (order of known
        // sub-options is fixed by encode_option_82).
        let decoded = decode_options(&reencoded).unwrap();
        match &decoded[0] {
            DhcpOption::RelayAgentInfo(a2) => {
                assert_eq!(a2.circuit_id, agent.circuit_id);
                assert_eq!(a2.remote_id, agent.remote_id);
                assert_eq!(a2.link_selection, agent.link_selection);
                assert_eq!(a2.raw, agent.raw);
            }
            other => panic!("expected option 82, got {:?}", other),
        }
    }

    #[test]
    fn classless_routes_encode_variable_length_prefix() {
        // 0.0.0.0/0 via 10.0.0.1 — zero prefix bytes on the wire.
        let e1 = RouteEntry {
            prefix: "0.0.0.0".parse().unwrap(),
            prefix_len: 0,
            gateway: "10.0.0.1".parse().unwrap(),
        };
        // 10.0.0.0/8 via 10.0.0.1 — one prefix byte.
        let e2 = RouteEntry {
            prefix: "10.0.0.0".parse().unwrap(),
            prefix_len: 8,
            gateway: "10.0.0.1".parse().unwrap(),
        };
        // 192.168.99.0/24 via 192.168.1.1 — three prefix bytes.
        let e3 = RouteEntry {
            prefix: "192.168.99.0".parse().unwrap(),
            prefix_len: 24,
            gateway: "192.168.1.1".parse().unwrap(),
        };
        let entries = vec![e1.clone(), e2.clone(), e3.clone()];
        let mut buf = Vec::new();
        encode_classless_routes(&mut buf, &entries);
        buf.push(OPT_END);

        // Verify the wire format explicitly:
        //   [121][body_len][0][10,0,0,1][8][10][10,0,0,1][24][192,168,99][192,168,1,1][255]
        // body_len = 5 + 6 + 8 = 19
        assert_eq!(buf[0], OPT_CLASSLESS_STATIC_ROUTE);
        assert_eq!(buf[1], 19);

        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, vec![DhcpOption::ClasslessStaticRoute(entries)]);
    }

    #[test]
    fn encode_options_pads_to_min() {
        let opts = vec![DhcpOption::MessageType(2)];
        let mut buf = Vec::new();
        // Pre-fill with 240 bytes to simulate header + magic cookie.
        buf.resize(240, 0);
        encode_options(&opts, &mut buf);
        assert!(buf.len() >= crate::packet::v4::header::BOOTP_MIN_WIRE_LEN);
        assert_eq!(buf[240], OPT_MESSAGE_TYPE);
        assert_eq!(buf[241], 1);
        assert_eq!(buf[242], 2);
        assert_eq!(buf[243], OPT_END);
    }

    #[test]
    fn decode_rejects_truncated_option() {
        // Option 51 (lease time) has len=4 but only 2 body bytes.
        let buf = [OPT_LEASE_TIME, 4, 0, 0, OPT_END];
        let err = decode_options(&buf).unwrap_err();
        assert!(err.to_string().contains("exceeds buffer"), "got: {}", err);
    }

    #[test]
    fn decode_rejects_bad_length() {
        // Option 53 (message-type) with len=3 is invalid.
        let buf = [OPT_MESSAGE_TYPE, 3, 1, 2, 3, OPT_END];
        let err = decode_options(&buf).unwrap_err();
        assert!(err.to_string().contains("message-type"), "got: {}", err);
    }

    #[test]
    fn pad_bytes_skipped() {
        // [PAD][PAD][msg-type=1][END]
        let buf = [OPT_PAD, OPT_PAD, OPT_MESSAGE_TYPE, 1, 1, OPT_END];
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, vec![DhcpOption::MessageType(1)]);
    }

    #[test]
    fn unknown_option_preserved_round_trip() {
        let opt = DhcpOption::Unknown {
            code: 200,
            data: vec![1, 2, 3],
        };
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        buf.push(OPT_END);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded.len(), 1);
        if let DhcpOption::Unknown { code, data } = &decoded[0] {
            assert_eq!(*code, 200);
            assert_eq!(data, &vec![1, 2, 3]);
        } else {
            panic!("expected unknown, got {:?}", decoded[0]);
        }
    }

    #[test]
    fn v6_only_preferred_round_trips() {
        let opt = DhcpOption::V6OnlyPreferred(1800);
        let mut buf = Vec::new();
        opt.encode(&mut buf);
        // Wire shape: [108][4][0,0,7,8] (1800 == 0x0708).
        assert_eq!(buf, vec![OPT_V6_ONLY_PREFERRED, 4, 0x00, 0x00, 0x07, 0x08]);
        buf.push(OPT_END);
        let decoded = decode_options(&buf).unwrap();
        assert_eq!(decoded, vec![DhcpOption::V6OnlyPreferred(1800)]);
    }

    #[test]
    fn client_requests_v6_only_via_prl() {
        let with = vec![DhcpOption::ParamRequestList(vec![1, 3, 6, 108, 51])];
        assert!(client_requests_v6_only_preferred(&with));
        let without = vec![DhcpOption::ParamRequestList(vec![1, 3, 6, 51])];
        assert!(!client_requests_v6_only_preferred(&without));
        let no_prl: Vec<DhcpOption> = vec![DhcpOption::MessageType(1)];
        assert!(!client_requests_v6_only_preferred(&no_prl));
    }

    #[test]
    fn finders_work() {
        let opts = vec![
            DhcpOption::MessageType(3),
            DhcpOption::RequestedIp("10.0.0.5".parse().unwrap()),
            DhcpOption::ServerId("10.0.0.1".parse().unwrap()),
            DhcpOption::ClientIdentifier(vec![1, 2, 3, 4, 5, 6, 7]),
        ];
        assert_eq!(find_message_type(&opts), Some(3));
        assert_eq!(find_requested_ip(&opts), Some("10.0.0.5".parse().unwrap()));
        assert_eq!(find_server_id(&opts), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(find_client_identifier(&opts), Some([1, 2, 3, 4, 5, 6, 7].as_ref()));
    }
}
