#![no_main]
//! Fuzz the /proc/sysvipc table reader used by the residue sweep.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = warden::pure::parse_sysvipc_ids(&s);
});
