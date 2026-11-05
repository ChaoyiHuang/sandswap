#![no_main]
//! Fuzz the netlink sock_diag response parser used by the unmount sweep:
//! arbitrary bytes as a dump datagram / an ack message. The parser must
//! never panic on a malformed length or an out-of-range TCP state.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = warden::pure::parse_diag_dump(data, 1u32 << 6); // TIME_WAIT mask
    let _ = warden::pure::parse_diag_ack(data, 1);
});
