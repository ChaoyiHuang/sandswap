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

//! Pure parsing for the warden raw vsock request frame body.
//!
//! Extracted from `raw_server.rs` so the wire parser is a stable, dependency-
//! free library target: the unit tests exercise it directly and the fuzz
//! target (`fuzz/fuzz_targets/frame_fields.rs`) calls it on arbitrary bytes.
//! No I/O, no unsafe — a malformed body is rejected with `InvalidData`.
//!
//! The production path parses SPANS, not copies: `parse_field_spans` returns
//! the byte ranges of the fields inside the caller's body buffer, so a
//! request holds exactly one body allocation and the in-flight body budget
//! accounts for it byte-for-byte (the former per-field `to_vec()` view kept a
//! second full copy alive for the whole request). `parse_fields` stays as the
//! owned convenience view for the fuzz target and the parser tests.

/// Upper bound on fields in one frame: this protocol uses at most 6 fields;
/// anything beyond that is garbage or hostile. Without a cap, a 16 MiB body
/// of zero-length fields parses into ~4M Vec headers (~96 MiB of heap) from a
/// single frame — reachable from a peer holding the VM's session key (a
/// compromised sandlot) and, for a malformed body, from a buggy legitimate
/// peer. The cap is checked DURING parsing, so a hostile body is rejected
/// before the Vecs accumulate.
pub const MAX_FIELDS: usize = 64;

/// Parse a request body as a sequence of `[u32 len][bytes]` fields, returning
/// each field's byte range inside `body`. A malformed body (a field length
/// that runs past the end, a trailing partial length header, or more than
/// MAX_FIELDS fields) is rejected with `InvalidData` rather than silently
/// truncated: treating a truncated frame as a request with fewer fields could
/// mask a real protocol/transport corruption and execute a command with
/// defaulted (possibly unsafe) arguments.
///
/// The ranges borrow nothing — callers keep the body buffer alive and index
/// it — so no per-field copy is made. Every returned range is in bounds.
pub fn parse_field_spans(body: &[u8]) -> std::io::Result<Vec<std::ops::Range<usize>>> {
    let mut spans = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        // Need a full 4-byte length header for the next field.
        if pos + 4 > body.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "truncated field length header: {} bytes left, need 4",
                    body.len() - pos
                ),
            ));
        }
        // Field-count cap BEFORE accumulating: a hostile 16 MiB body of empty
        // fields must be rejected at field MAX_FIELDS+1, not after allocating
        // millions of Vec headers (see MAX_FIELDS).
        if spans.len() >= MAX_FIELDS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("too many fields (max {})", MAX_FIELDS),
            ));
        }
        let flen =
            u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + flen > body.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "field length {} runs past body end ({} bytes left)",
                    flen,
                    body.len() - pos
                ),
            ));
        }
        spans.push(pos..pos + flen);
        pos += flen;
    }
    Ok(spans)
}

/// Owned copy of the parsed fields. Used by the fuzz target and the parser
/// tests; the warden's request path uses `parse_field_spans` instead so it
/// never holds both the body and a copy of every field.
pub fn parse_fields(body: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
    Ok(parse_field_spans(body)?
        .into_iter()
        .map(|span| body[span].to_vec())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fields_roundtrip_and_bounds() {
        // Two fields with a zero-length one; the parser preserves order.
        let mut body = Vec::new();
        for f in [b"abc".as_slice(), b"".as_slice(), b"xyz".as_slice()] {
            body.extend_from_slice(&(f.len() as u32).to_be_bytes());
            body.extend_from_slice(f);
        }
        let spans = parse_field_spans(&body).expect("valid body");
        assert_eq!(spans.len(), 3);
        assert_eq!(&body[spans[0].clone()], b"abc");
        assert!(body[spans[1].clone()].is_empty());
        assert_eq!(&body[spans[2].clone()], b"xyz");
        let fields = parse_fields(&body).expect("valid body");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0], b"abc");
        assert!(fields[1].is_empty());
        assert_eq!(fields[2], b"xyz");

        // Truncated length header.
        assert!(parse_field_spans(&[0, 0, 0]).is_err());
        assert!(parse_fields(&[0, 0, 0]).is_err());
        // Length runs past the end.
        assert!(parse_field_spans(&[0, 0, 0, 5, 1, 2]).is_err());
        assert!(parse_fields(&[0, 0, 0, 5, 1, 2]).is_err());
        // MAX_FIELDS empty fields is fine; MAX_FIELDS+1 is rejected.
        let ok = vec![0u8; MAX_FIELDS * 4];
        assert_eq!(parse_field_spans(&ok).unwrap().len(), MAX_FIELDS);
        assert_eq!(parse_fields(&ok).unwrap().len(), MAX_FIELDS);
        let over = vec![0u8; (MAX_FIELDS + 1) * 4];
        assert!(parse_field_spans(&over).is_err());
        assert!(parse_fields(&over).is_err());
    }
}
