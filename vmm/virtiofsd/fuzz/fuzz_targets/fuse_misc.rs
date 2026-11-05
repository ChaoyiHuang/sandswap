#![no_main]

//! Fuzz the FUSE security-context / supplementary-group payload parsers.
//! These are sandswap-relevant because they parse guest-controlled extension
//! bytes before any filesystem operation.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((&nr, rest)) = data.split_first() {
        let _ = virtiofsd::server::parse_security_context(nr as u32, rest);
        let _ = virtiofsd::server::parse_security_context((nr % 3) as u32, rest);
    }
    let _ = virtiofsd::server::parse_sup_groups(data);
});
