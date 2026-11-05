#![no_main]

//! Fuzz the sandswap-modified virtiofsd share-root gate: the guest supplies
//! names (FUSE lookup/readdir/create paths); the operator supplies the
//! allow-list. Only the NAME is fuzz input; the whitelist is fixed so both the
//! allowed and denied branches run.

use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
use std::sync::Once;
use virtiofsd::filesystem::validate_name;
use virtiofsd::server::{get_basename_from_path, FilterList};

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        let _ = std::fs::create_dir_all("/tmp/sandswap-fuzz-allow");
    });
    let whitelist = vec!["/tmp/sandswap-fuzz-allow".to_string()];
    let filter = FilterList::new(1, &whitelist, Some("fuzz-alias"))
        .or_else(|_| FilterList::new(1, &[], None))
        .expect("empty whitelist is always constructible");
    let s = String::from_utf8_lossy(data);
    let _ = filter.get_allow_dir(&s);
    if let Ok(c) = CString::new(data.to_vec()) {
        let _ = validate_name(&c);
        let _ = filter.root_lookup(&c);
    }
    let _ = get_basename_from_path(&s);
});
