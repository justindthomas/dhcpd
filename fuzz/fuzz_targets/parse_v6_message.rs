#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the DHCPv6 message decoder (RFC 8415). Covers both client/server
// messages (Solicit, Advertise, Request, Renew, Reply, ...) and the
// relay-agent encapsulation chain (Relay-Forward / Relay-Reply with
// nested Relay-Message option recursion). Reachable by any host on a
// link with link-local multicast access to ff02::1:2 (All_DHCP_Servers).
//
// Nested relay encapsulation is the highest-risk recursive surface in
// DHCPv6 — RFC 8415 §15 caps the relay chain depth but malicious chains
// have been the source of stack-exhaustion CVEs in other servers.
fuzz_target!(|data: &[u8]| {
    let _ = dhcpd::packet::v6::message::Dhcp6Message::decode(data);
});
