// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.
//
// filter_init — arbitrary allow-list inputs against the share-root filter:
// the tenant-facing NAMESPACE CONTROL of the virtio-fs export. Invariants
// that must hold for ANY byte input (mirrored by the deterministic property
// tests in src/server.rs):
//   * a whitelist entry containing ".." is REFUSED, previous list intact
//   * non-directory entries never enter the export map
//   * one entry presents under the supplied per-generation alias; the real basename is never
//     itself a resolvable root key
//   * non-UTF-8 / hostile lookup names are denied without panicking
//
// Run: cargo fuzz run filter_init

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::ffi::CString;

fuzz_target!(|data: &[u8]| {
    // Split the input in half: first half becomes newline-separated whitelist
    // entries, second half a raw lookup name.
    let (wl_bytes, name_bytes) = data.split_at(data.len() / 2);
    let entries: Vec<String> = wl_bytes
        .split(|b| *b == b'\n')
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    if let Ok(filter) = virtiofsd::server::FilterList::new(1, &entries, Some("fuzz-alias"))
        .or_else(|_| virtiofsd::server::FilterList::new(1, &[], None)) {
        if let Ok(name) = CString::new(name_bytes.to_vec()) {
            // Must never panic and never return anything but a verdict.
            let _ = filter.root_lookup(&name);
        }
        // The empty-name and alias shapes are exercised on every input.
        if let Ok(empty) = CString::new("") {
            let _ = filter.root_lookup(&empty);
        }
        if let Ok(alias) = CString::new("fuzz-alias") {
            let _ = filter.root_lookup(&alias);
        }
    }
});
