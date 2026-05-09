#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the DHCPv6 options TLV decoder in isolation (RFC 8415). The v6
// options block contains length-prefixed nested options inside IA_NA
// (RFC 8415 §21.4), IA_TA (§21.5), and IA_PD (RFC 8415 §21.21) — each
// with its own recursive sub-option decoder. Direct targeting gives
// libFuzzer maximum mutation budget on the IA-option framing, which is
// where prefix-delegation handling has had bugs in other servers.
fuzz_target!(|data: &[u8]| {
    let _ = dhcpd::packet::v6::options::decode_options(data);
});
