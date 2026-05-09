#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the DHCPv4 options TLV decoder in isolation (RFC 2132 + RFC 3046
// Option 82 sub-options + RFC 3442 classless static routes). The DHCP
// header eats a fixed number of bytes from any input, leaving little
// budget for libFuzzer to mutate the options block via parse_v4_message
// alone. Targeting decode_options directly explores the per-option
// length-byte space and the nested Option-82 sub-options that have
// historically been the source of buffer-overflow CVEs in other DHCP
// implementations (ISC dhcpd CVE-2017-3144 et al.).
fuzz_target!(|data: &[u8]| {
    let _ = dhcpd::packet::v4::options::decode_options(data);
});
