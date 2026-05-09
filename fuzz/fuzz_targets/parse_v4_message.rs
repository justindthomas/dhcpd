#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the DHCPv4 message decoder (RFC 2131 BOOTP-shaped header + RFC 2132
// options TLVs). Every DHCPv4 packet — DISCOVER, OFFER, REQUEST, RELEASE,
// INFORM — flows through here. Reachable by any host with L2 access to a
// DHCP-served subnet (the broadcast nature means every device on the
// segment is in the attack window). DhcpMessage::decode invokes the
// header decoder + the options decoder in sequence; bugs in either
// surface here.
fuzz_target!(|data: &[u8]| {
    let _ = dhcpd::packet::v4::message::DhcpMessage::decode(data);
});
