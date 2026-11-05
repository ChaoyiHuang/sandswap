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

//! Dependency-free parser for the sandswap-added sandvmm raw SET_FS frame
//! body. Extracted from `api/http/raw.rs` so the cargo-fuzz target can compile
//! the exact code without the whole VMM dependency graph (whose nightly/ASan
//! build is not supported by the workspace's pinned crates).

/// Per-path length cap == PATH_MAX-1 (a longer path cannot exist on the host).
pub const MAX_PATH_LEN: usize = 4095;
/// allowed_dirs entry count cap. One VM exports exactly one host directory
/// (the active tenant volume); the sandlot sends 0 (clear) or 1 (mount). The
/// cap is 1 so a compromised sandlot cannot widen a guest to several tenants'
/// volumes in one frame — the HTTP/config path enforces the same contract in
/// `validate_allowed_dirs_containment`.
pub const MAX_PATHS: usize = 1;
/// tag / id length caps (constants in practice: "sandswap", "fs0").
pub const MAX_TAG_LEN: usize = 32;
pub const MAX_ID_LEN: usize = 64;
/// Export-alias cap (the sandlot sends 32 hex characters; the cap leaves
/// room for a different generator without widening the wire).
pub const MAX_ALIAS_LEN: usize = 64;

/// Parsed SET_FS request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetFsRequest {
    pub tag: String,
    pub id: String,
    pub allowed_dirs: Vec<String>,
    /// The generation's guest-visible root name. Empty for the clear
    /// request; required (and validated by the filter) for an export.
    pub alias: String,
}

/// Cursor over the SET_FS body. Every read is bounds-checked; the error
/// string is user-facing (it lands in the error frame).
pub fn parse_set_fs_body(body: &[u8]) -> Result<SetFsRequest, String> {
    let mut off = 0usize;

    let tag_len = *body.get(off).ok_or("truncated body: missing tag_len")? as usize;
    off += 1;
    if tag_len == 0 || tag_len > MAX_TAG_LEN {
        return Err(format!("invalid tag_len {tag_len}"));
    }
    let tag = body
        .get(off..off + tag_len)
        .ok_or("truncated body: tag")?
        .to_vec();
    let tag = String::from_utf8(tag).map_err(|_| "tag is not valid UTF-8")?;
    off += tag_len;

    let id_len = *body.get(off).ok_or("truncated body: missing id_len")? as usize;
    off += 1;
    if id_len == 0 || id_len > MAX_ID_LEN {
        return Err(format!("invalid id_len {id_len}"));
    }
    let id = body
        .get(off..off + id_len)
        .ok_or("truncated body: id")?
        .to_vec();
    let id = String::from_utf8(id).map_err(|_| "id is not valid UTF-8")?;
    off += id_len;

    let n_paths = u16::from_be_bytes([
        *body.get(off).ok_or("truncated body: n_paths")?,
        *body.get(off + 1).ok_or("truncated body: n_paths")?,
    ]);
    off += 2;
    if n_paths as usize > MAX_PATHS {
        return Err(format!("n_paths {n_paths} exceeds {MAX_PATHS}"));
    }

    let mut allowed_dirs = Vec::with_capacity(n_paths as usize);
    for i in 0..n_paths as usize {
        let len_hi = *body.get(off).ok_or("truncated body: path len")?;
        let len_lo = *body.get(off + 1).ok_or("truncated body: path len")?;
        let path_len = u16::from_be_bytes([len_hi, len_lo]) as usize;
        off += 2;
        if path_len == 0 || path_len > MAX_PATH_LEN {
            return Err(format!(
                "path {} length {path_len} out of 1..={MAX_PATH_LEN}",
                i
            ));
        }
        let path = body
            .get(off..off + path_len)
            .ok_or("truncated body: path")?
            .to_vec();
        let path = String::from_utf8(path).map_err(|_| "path is not valid UTF-8")?;
        if !path.starts_with('/') {
            return Err(format!("path {path:?} is not absolute"));
        }
        allowed_dirs.push(path);
        off += path_len;
    }

    let alias_len = *body
        .get(off)
        .ok_or("truncated body: missing alias_len")? as usize;
    off += 1;
    if alias_len > MAX_ALIAS_LEN {
        return Err(format!("invalid alias_len {alias_len}"));
    }
    let alias = body
        .get(off..off + alias_len)
        .ok_or("truncated body: alias")?
        .to_vec();
    let alias = String::from_utf8(alias).map_err(|_| "alias is not valid UTF-8")?;
    if !alias.is_empty() && !virtiofsd::server::validate_alias(&alias) {
        return Err(format!("invalid export alias {alias:?}"));
    }
    off += alias_len;

    if off != body.len() {
        return Err(format!(
            "{} trailing bytes after last path",
            body.len() - off
        ));
    }

    Ok(SetFsRequest {
        tag,
        id,
        allowed_dirs,
        alias,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(paths: &[&str], alias: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(8);
        b.extend_from_slice(b"sandswap");
        b.push(3);
        b.extend_from_slice(b"fs0");
        b.extend_from_slice(&(paths.len() as u16).to_be_bytes());
        for p in paths {
            b.extend_from_slice(&(p.len() as u16).to_be_bytes());
            b.extend_from_slice(p.as_bytes());
        }
        b.push(alias.len() as u8);
        b.extend_from_slice(alias.as_bytes());
        b
    }

    #[test]
    fn one_path_is_the_maximum() {
        let req = parse_set_fs_body(&body(&["/vol/a"], "gen0")).expect("one path must parse");
        assert_eq!(req.allowed_dirs, vec!["/vol/a"]);
        assert_eq!(req.alias, "gen0");
        let empty = parse_set_fs_body(&body(&[], "")).expect("clear must parse");
        assert!(empty.allowed_dirs.is_empty());
        assert!(empty.alias.is_empty());
    }

    #[test]
    fn two_paths_are_refused() {
        // One VM exports exactly one tenant volume. The cap is enforced in the
        // parser as well as in validate_allowed_dirs_containment (HTTP/config
        // path), so neither transport can widen a guest to several tenants.
        let err = parse_set_fs_body(&body(&["/vol/a", "/vol/b"], "gen0"))
            .expect_err("a multi-entry allow-list must be refused");
        assert!(err.contains("exceeds 1"), "got {err:?}");
    }

    #[test]
    fn alias_is_mandatory_and_validated() {
        // A body without the alias field is truncated: fail closed, never
        // fall back to a constant root name.
        let mut no_alias = body(&["/vol/a"], "");
        no_alias.pop();
        assert!(parse_set_fs_body(&no_alias)
            .expect_err("missing alias_len must be refused")
            .contains("alias_len"));

        for bad in ["..", "../x", "a/b", "bad name", &"x".repeat(65)] {
            let err = parse_set_fs_body(&body(&["/vol/a"], bad))
                .expect_err("invalid alias must be refused");
            assert!(err.contains("alias"), "got {err:?}");
        }
        // Trailing bytes after the alias are refused.
        let mut trailing = body(&["/vol/a"], "gen0");
        trailing.push(0);
        assert!(parse_set_fs_body(&trailing)
            .expect_err("trailing bytes must be refused")
            .contains("trailing"));
    }
}
