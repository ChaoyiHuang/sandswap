#![no_main]
//! Fuzz the resolv.conf formatter with arbitrary DNS-list entries.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let dns: Vec<String> = s.split('\n').map(|x| x.to_string()).collect();
    let _ = warden::pure::format_resolv_conf(&dns);
});
