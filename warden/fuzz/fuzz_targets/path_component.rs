#![no_main]
//! Fuzz the single-component rule used by every anchored warden path.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = warden::pure::check_component(&s);
});
