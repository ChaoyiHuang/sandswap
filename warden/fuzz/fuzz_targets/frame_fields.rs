#![no_main]

//! Fuzz the warden raw-frame body parser with arbitrary bytes. The parser is
//! the tenant/host crash boundary for malformed `[u32 len][bytes]` fields:
//! every input is fed to the exact function the warden runs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = warden::frame_parse::parse_fields(data);
});
