#![no_main]
//! Fuzz the warden TOML config parser (`AgentConfig::from_str`).
use std::str::FromStr;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = warden::config::AgentConfig::from_str(s);
    }
});
