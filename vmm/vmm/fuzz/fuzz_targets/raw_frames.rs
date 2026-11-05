#![no_main]

//! Fuzz the sandswap-added sandvmm SET_FS body parser. The parser is included
//! from the exact source the VMM compiles (`src/raw_parse.rs`), without the
//! whole VMM dependency graph (the workspace's pinned crates do not build
//! under cargo-fuzz's nightly+ASan toolchain).

#[path = "../../src/raw_parse.rs"]
mod raw_parse;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = raw_parse::parse_set_fs_body(data);
});
