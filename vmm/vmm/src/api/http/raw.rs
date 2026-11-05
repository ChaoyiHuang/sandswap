// Copyright © 2026 Sandswap
//
// SPDX-License-Identifier: Apache-2.0
//
// Raw control-frame protocol served on the canonical sandvmm API socket.
//
// The HTTP API (micro_http) stays for VM lifecycle operations (vm.create /
// vm.boot / vm.add-vsock / sandvmm.shutdown ...), but the per-request hot
// operations (vm.set-fs on every cold attach, sandvmm.ping health probes)
// pay the HTTP/1.1 framing + JSON tax on every call. This module defines the
// length-prefixed binary framing they use instead, dispatched per connection
// by the first byte on the wire (see dispatch.rs): a raw frame always starts
// with the protocol version byte 0x01, an HTTP request with an ASCII method
// letter — the two can never collide.
//
// Wire format (all integers big-endian):
//
//   request:  [u8 version][u8 op][u16 flags=0][u32 body_len] body...
//   response: [u8 version][u8 op][u8 status][u8 reserved=0][u32 body_len] body...
//
// Version doctrine mirrors the warden vsock protocol: an in-range version is
// echoed in the response; an out-of-range version gets a rejection frame
// carrying THIS server's version (status VERSION_REJECT) and the connection
// is closed, so a client can classify the mismatch and fail fast (the
// rolling-upgrade window hook).
//
// Budgets are aligned byte-for-byte with what the HTTP path accepts today:
//   - body_len cap == micro_http MAX_PAYLOAD_SIZE (51200): the raw protocol
//     is never narrower than the HTTP envelope it replaces.
//   - per-path cap == PATH_MAX-1 (4095): a longer allowed_dir path cannot
//     exist on the host (open/mount reject it), so nothing regresses.
// Parsing discipline follows the warden raw_server philosophy: header-level
// anomalies (bad version, unknown flags, oversize body_len, truncation) close
// the connection; frame-level errors (unknown op, malformed body, op failure)
// get an error frame and the connection stays usable — the length prefix
// keeps the stream coherent.

use crate::api::{vm_set_fs, vmm_ping};
use crate::vm_config::FsConfig;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use crate::raw_parse::{parse_set_fs_body, SetFsRequest, MAX_ID_LEN, MAX_PATH_LEN, MAX_PATHS, MAX_TAG_LEN};
use virtio_devices::fs::BackendFsConfig;

/// Protocol version of this build. In-range requests are answered in the
/// request's own version; out-of-range requests get this value in the
/// rejection frame.
pub const RAW_PROTO_VERSION: u8 = 1;

/// Operations. PING carries no body; SET_FS carries the encoded whitelist.
pub const OP_PING: u8 = 0;
pub const OP_SET_FS: u8 = 1;

/// Total request-body budget == micro_http MAX_PAYLOAD_SIZE.
pub const MAX_FRAME_BODY: usize = 51_200;
/// Response body budget (error / rejection message strings).
pub const MAX_RESP_BODY: usize = 1024;

const HEADER_LEN: usize = 8;
const RESP_HEADER_LEN: usize = 8;

/// Response status codes.
pub const STATUS_OK: u8 = 0;
pub const STATUS_ERROR: u8 = 1;
pub const STATUS_VERSION_REJECT: u8 = 2;

/// The version byte doubles as the dispatch key: every raw frame starts with
/// it and no HTTP method letter can equal it.
pub const RAW_DISPATCH_BYTE: u8 = RAW_PROTO_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub op: u8,
    pub flags: u16,
    pub body_len: u32,
}

impl FrameHeader {
    pub fn parse(buf: &[u8; HEADER_LEN]) -> Self {
        FrameHeader {
            version: buf[0],
            op: buf[1],
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            body_len: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        }
    }

    pub fn encode(&self, buf: &mut [u8; HEADER_LEN]) {
        buf[0] = self.version;
        buf[1] = self.op;
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..8].copy_from_slice(&self.body_len.to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    pub version: u8,
    pub op: u8,
    pub status: u8,
    pub body_len: u32,
}

impl ResponseHeader {
    pub fn parse(buf: &[u8; RESP_HEADER_LEN]) -> Self {
        ResponseHeader {
            version: buf[0],
            op: buf[1],
            status: buf[2],
            // buf[3] reserved, must be zero on the wire
            body_len: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        }
    }

    pub fn encode(&self, buf: &mut [u8; RESP_HEADER_LEN]) {
        buf[0] = self.version;
        buf[1] = self.op;
        buf[2] = self.status;
        buf[3] = 0;
        buf[4..8].copy_from_slice(&self.body_len.to_be_bytes());
    }
}

/// Build the FsConfig handed to the existing vm.set-fs pipeline. Field
/// semantics match what the HTTP JSON body may express:
///   - `id` + `tag` must match the live device (validate_fs_update enforces);
///   - `shared_dir` empty means "omitted" — the immutable-field check passes;
///   - `allowed_dirs` is ALWAYS Some: `Some(vec![])` is the clear-whitelist
///     request; None would mean "field omitted" and the stored whitelist
///     would be overwritten with None instead of cleared;
///   - every other field takes its default, which the validation treats as
///     "no change attempt".
pub fn build_fs_config(
    tag: &str,
    id: &str,
    allowed_dirs: Vec<String>,
    alias: String,
) -> FsConfig {
    FsConfig {
        tag: tag.to_owned(),
        id: Some(id.to_owned()),
        backendfs_config: Some(BackendFsConfig {
            shared_dir: String::new(),
            allowed_dirs: Some(allowed_dirs),
            alias: if alias.is_empty() { None } else { Some(alias) },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Encode a response frame (header + optional message) into `out`; returns
/// the total length. `msg` longer than MAX_RESP_BODY is truncated on a UTF-8
/// byte boundary (error path only — never on the hot path).
fn encode_response(
    out: &mut [u8; RESP_HEADER_LEN + MAX_RESP_BODY],
    version: u8,
    op: u8,
    status: u8,
    msg: &str,
) -> usize {
    // Truncate on a BYTE boundary, not by chars: MAX_RESP_BODY counts the
    // bytes that fit in `out`, and taking MAX_RESP_BODY chars can yield up to
    // 4x that in bytes (UTF-8), making the copy below index past the end of a
    // 1032-byte buffer — a panic reachable from a client-supplied path in the
    // SET_FS error message (e.g. a long CJK relative path). A panic here also
    // leaked a MAX_RAW_CONNS slot (see dispatch.rs), so 16 of them disabled the
    // raw set-fs/ping protocol for the VM's lifetime.
    let mut end = MAX_RESP_BODY.min(msg.len());
    while !msg.is_char_boundary(end) {
        end -= 1;
    }
    let msg = &msg[..end];
    let header = ResponseHeader {
        version,
        op,
        status,
        body_len: msg.len() as u32,
    };
    let mut hdr_buf = [0u8; RESP_HEADER_LEN];
    header.encode(&mut hdr_buf);
    out[..RESP_HEADER_LEN].copy_from_slice(&hdr_buf);
    out[RESP_HEADER_LEN..RESP_HEADER_LEN + msg.len()].copy_from_slice(msg.as_bytes());
    RESP_HEADER_LEN + msg.len()
}

/// Serve one established raw connection: read frames until EOF, a
/// header-level violation, or a version rejection. Blocking I/O; the
/// connection is exclusively ours (the dispatcher handed it over and holds
/// no reference).
pub fn serve_raw_connection(mut stream: UnixStream) {
    // One buffer per connection, reused for every frame: zero per-frame
    // allocation on the receive path.
    let mut body_buf = vec![0u8; MAX_FRAME_BODY];
    let mut hdr = [0u8; HEADER_LEN];
    let mut resp = [0u8; RESP_HEADER_LEN + MAX_RESP_BODY];

    loop {
        // Header-level violations close the connection without a frame.
        if stream.read_exact(&mut hdr).is_err() {
            return; // EOF or transport error
        }
        let header = FrameHeader::parse(&hdr);

        if header.version != RAW_PROTO_VERSION {
            // Rejection frame carries THIS server's version so the client can
            // classify the mismatch, then the connection is closed.
            let n = encode_response(
                &mut resp,
                RAW_PROTO_VERSION,
                header.op,
                STATUS_VERSION_REJECT,
                &format!(
                    "protocol version {} not supported (server speaks {})",
                    header.version, RAW_PROTO_VERSION
                ),
            );
            let _ = stream.write_all(&resp[..n]);
            return;
        }
        if header.flags != 0 {
            return; // unknown flags: refuse the whole connection
        }
        if header.body_len as usize > MAX_FRAME_BODY {
            return; // over budget: never read it into memory
        }

        if header.body_len > 0
            && stream
                .read_exact(&mut body_buf[..header.body_len as usize])
                .is_err()
        {
            return; // truncated body
        }
        let body = &body_buf[..header.body_len as usize];

        // Frame-level errors answer with an error frame and keep the
        // connection usable (the length prefix keeps the stream coherent).
        let (status, msg): (u8, String) = match header.op {
            OP_PING if body.is_empty() => match vmm_ping() {
                Ok(_) => (STATUS_OK, String::new()),
                Err(e) => (STATUS_ERROR, format!("{e}")),
            },
            OP_SET_FS => match parse_set_fs_body(body) {
                Ok(req) => {
                    let cfg = build_fs_config(&req.tag, &req.id, req.allowed_dirs, req.alias);
                    match vm_set_fs(Arc::new(cfg)) {
                        Ok(_) => (STATUS_OK, String::new()),
                        Err(e) => (STATUS_ERROR, format!("{e}")),
                    }
                }
                Err(e) => (STATUS_ERROR, e),
            },
            other => (STATUS_ERROR, format!("unknown op {other}")),
        };

        let n = encode_response(&mut resp, header.version, header.op, status, &msg);
        if stream.write_all(&resp[..n]).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_fs_body(tag: &str, id: &str, dirs: &[&str], alias: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(tag.len() as u8);
        b.extend_from_slice(tag.as_bytes());
        b.push(id.len() as u8);
        b.extend_from_slice(id.as_bytes());
        b.extend_from_slice(&(dirs.len() as u16).to_be_bytes());
        for d in dirs {
            b.extend_from_slice(&(d.len() as u16).to_be_bytes());
            b.extend_from_slice(d.as_bytes());
        }
        b.push(alias.len() as u8);
        b.extend_from_slice(alias.as_bytes());
        b
    }

    /// The raw op numbers are WIRE VALUES shared with sandlot's client;
    /// renumbering them silently breaks every live sandlot against a
    /// mixed-version deploy (the protocol-version e2e covers the
    /// version-window behavior; this pins the op table itself). The
    /// complete raw surface is exactly these two ops — anything else
    /// answers `unknown op` at the dispatch match.
    #[test]
    fn raw_op_wire_values_are_pinned() {
        assert_eq!(OP_PING, 0, "PING is wire op 0");
        assert_eq!(OP_SET_FS, 1, "SET_FS is wire op 1");
    }

    /// encode_response must truncate on a UTF-8 BYTE boundary: MAX_RESP_BODY
    /// counts bytes, and a chars().take() clamp could emit up to 4x that,
    /// indexing past the 1032-byte output buffer (panic reachable from a
    /// client-supplied path in a SET_FS error message).
    #[test]
    fn test_encode_response_truncates_multibyte_on_byte_boundary() {
        let mut out = [0u8; RESP_HEADER_LEN + MAX_RESP_BODY];
        let msg = "路".repeat(2000); // 3 bytes/char: 2000 chars = 6000 bytes
        let n = encode_response(&mut out, 1, OP_SET_FS, 1, &msg);
        assert!(n <= RESP_HEADER_LEN + MAX_RESP_BODY, "wrote {n} bytes");
        let body_len = u32::from_be_bytes([out[4], out[5], out[6], out[7]]) as usize;
        assert_eq!(body_len, n - RESP_HEADER_LEN);
        assert!(
            std::str::from_utf8(&out[RESP_HEADER_LEN..n]).is_ok(),
            "truncated body is not valid UTF-8 (cut mid-character)"
        );
        // The byte-exact fit must also not overflow.
        let exact = "a".repeat(MAX_RESP_BODY);
        let n2 = encode_response(&mut out, 1, OP_SET_FS, 1, &exact);
        assert_eq!(n2, RESP_HEADER_LEN + MAX_RESP_BODY);
    }

    #[test]
    fn test_header_roundtrip() {
        let h = FrameHeader {
            version: 1,
            op: OP_SET_FS,
            flags: 0,
            body_len: 42,
        };
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        assert_eq!(FrameHeader::parse(&buf), h);
    }

    #[test]
    fn test_set_fs_body_roundtrip() {
        let body = set_fs_body("sandswap", "fs0", &["/vol/agent-a"], "gen0");
        let req = parse_set_fs_body(&body).unwrap();
        assert_eq!(req.tag, "sandswap");
        assert_eq!(req.id, "fs0");
        assert_eq!(req.allowed_dirs, vec!["/vol/agent-a".to_owned()]);
        assert_eq!(req.alias, "gen0");
    }

    #[test]
    fn test_set_fs_body_clear_is_empty_vec() {
        // n_paths = 0 is the clear-whitelist request: Some(vec![]), not None.
        let body = set_fs_body("sandswap", "fs0", &[], "");
        let req = parse_set_fs_body(&body).unwrap();
        assert!(req.allowed_dirs.is_empty());
        let cfg = build_fs_config(&req.tag, &req.id, req.allowed_dirs, req.alias);
        assert_eq!(
            cfg.backendfs_config.as_ref().unwrap().allowed_dirs,
            Some(Vec::new())
        );
    }

    #[test]
    fn test_set_fs_body_rejects_relative_path() {
        let body = set_fs_body("sandswap", "fs0", &["vol/agent-a"], "gen0");
        let err = parse_set_fs_body(&body).unwrap_err();
        assert!(err.contains("not absolute"), "{err}");
    }

    #[test]
    fn test_set_fs_body_rejects_oversize_path() {
        let long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert_eq!(long.len(), MAX_PATH_LEN + 1);
        let body = set_fs_body("sandswap", "fs0", &[long.as_str()], "");
        let err = parse_set_fs_body(&body).unwrap_err();
        assert!(err.contains("out of 1..="), "{err}");
    }

    #[test]
    fn test_set_fs_body_accepts_max_path() {
        // PATH_MAX-1 bytes: the longest path that can exist on the host.
        let max_path = format!("/{}", "a".repeat(MAX_PATH_LEN - 1));
        assert_eq!(max_path.len(), MAX_PATH_LEN);
        let body = set_fs_body("sandswap", "fs0", &[max_path.as_str()], "");
        assert!(parse_set_fs_body(&body).is_ok());
    }

    #[test]
    fn test_set_fs_body_rejects_trailing_bytes() {
        let mut body = set_fs_body("sandswap", "fs0", &["/vol/a"], "gen0");
        body.push(b'x');
        let err = parse_set_fs_body(&body).unwrap_err();
        assert!(err.contains("trailing"), "{err}");
    }

    #[test]
    fn test_set_fs_body_rejects_truncation() {
        let body = set_fs_body("sandswap", "fs0", &["/vol/a"], "gen0");
        for cut in 1..body.len() {
            let res = parse_set_fs_body(&body[..cut]);
            assert!(res.is_err(), "cut at {cut} should fail");
        }
    }

    #[test]
    fn test_set_fs_body_rejects_too_many_paths() {
        let dirs: Vec<&str> = (0..MAX_PATHS + 1)
            .map(|i| Box::leak(format!("/v{i}").into_boxed_str()) as &str)
            .collect();
        let body = set_fs_body("sandswap", "fs0", &dirs, "");
        let err = parse_set_fs_body(&body).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn test_response_header_roundtrip_and_reserved_zero() {
        let h = ResponseHeader {
            version: 1,
            op: OP_SET_FS,
            status: STATUS_ERROR,
            body_len: 5,
        };
        let mut buf = [0u8; RESP_HEADER_LEN];
        h.encode(&mut buf);
        assert_eq!(buf[3], 0);
        assert_eq!(ResponseHeader::parse(&buf), h);
    }

    #[test]
    fn test_encode_response_truncates_long_message() {
        let mut out = [0u8; RESP_HEADER_LEN + MAX_RESP_BODY];
        let msg = "x".repeat(MAX_RESP_BODY + 100);
        let n = encode_response(&mut out, 1, OP_PING, STATUS_ERROR, &msg);
        assert_eq!(n, RESP_HEADER_LEN + MAX_RESP_BODY);
        let h = ResponseHeader::parse(&out[..RESP_HEADER_LEN].try_into().unwrap());
        assert_eq!(h.body_len as usize, MAX_RESP_BODY);
    }

    #[test]
    fn test_serve_connection_version_reject_frame() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || serve_raw_connection(server));

        // version 99 → rejection frame carrying the server's version, then close.
        let mut frame = Vec::new();
        frame.push(99u8);
        frame.push(OP_PING);
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        client.write_all(&frame).unwrap();

        let mut resp = [0u8; RESP_HEADER_LEN];
        client.read_exact(&mut resp).unwrap();
        let h = ResponseHeader::parse(&resp);
        assert_eq!(h.version, RAW_PROTO_VERSION);
        assert_eq!(h.status, STATUS_VERSION_REJECT);
        assert!(h.body_len > 0);
        let mut msg = vec![0u8; h.body_len as usize];
        client.read_exact(&mut msg).unwrap();
        assert!(String::from_utf8(msg).unwrap().contains("not supported"));
        // Connection closed after the rejection.
        assert_eq!(client.read(&mut resp).unwrap(), 0);
        handle.join().unwrap();
    }

    #[test]
    fn test_serve_connection_ping_frame_path() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || serve_raw_connection(server));

        // In a unit-test process VMM_SERVICE is not initialized: the PING op
        // must still answer a coherent ERROR frame (frame-level error, the
        // connection stays usable), and a second frame must also be answered.
        for _ in 0..2 {
            let mut frame = Vec::new();
            frame.push(RAW_PROTO_VERSION);
            frame.push(OP_PING);
            frame.extend_from_slice(&0u16.to_be_bytes());
            frame.extend_from_slice(&0u32.to_be_bytes());
            client.write_all(&frame).unwrap();

            let mut resp = [0u8; RESP_HEADER_LEN];
            client.read_exact(&mut resp).unwrap();
            let h = ResponseHeader::parse(&resp);
            assert_eq!(h.version, RAW_PROTO_VERSION);
            assert_eq!(h.op, OP_PING);
            assert_eq!(h.status, STATUS_ERROR); // "Vmm Service not init"
            if h.body_len > 0 {
                let mut msg = vec![0u8; h.body_len as usize];
                client.read_exact(&mut msg).unwrap();
                assert!(String::from_utf8(msg).unwrap().contains("not init"));
            }
        }
        drop(client);
        handle.join().unwrap();
    }

    #[test]
    fn test_serve_connection_set_fs_body_error_frame() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || serve_raw_connection(server));

        let body = set_fs_body("sandswap", "fs0", &["relative/path"], "gen0");
        let mut frame = Vec::new();
        frame.push(RAW_PROTO_VERSION);
        frame.push(OP_SET_FS);
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        client.write_all(&frame).unwrap();

        let mut resp = [0u8; RESP_HEADER_LEN];
        client.read_exact(&mut resp).unwrap();
        let h = ResponseHeader::parse(&resp);
        assert_eq!(h.status, STATUS_ERROR);
        let mut msg = vec![0u8; h.body_len as usize];
        client.read_exact(&mut msg).unwrap();
        assert!(String::from_utf8(msg).unwrap().contains("not absolute"));
        drop(client);
        handle.join().unwrap();
    }

    #[test]
    fn test_serve_connection_oversize_body_closes() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || serve_raw_connection(server));

        // body_len over budget: server must close without reading/answering.
        let mut frame = Vec::new();
        frame.push(RAW_PROTO_VERSION);
        frame.push(OP_SET_FS);
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&((MAX_FRAME_BODY + 1) as u32).to_be_bytes());
        client.write_all(&frame).unwrap();

        let mut resp = [0u8; RESP_HEADER_LEN];
        assert_eq!(client.read(&mut resp).unwrap(), 0);
        handle.join().unwrap();
    }

    #[test]
    fn test_build_fs_config_field_semantics() {
        let cfg = build_fs_config("sandswap", "fs0", vec!["/v/a".to_owned()], "gen0".to_owned());
        assert_eq!(cfg.tag, "sandswap");
        assert_eq!(cfg.id.as_deref(), Some("fs0"));
        let backend = cfg.backendfs_config.as_ref().unwrap();
        assert_eq!(backend.shared_dir, "");
        assert_eq!(backend.allowed_dirs, Some(vec!["/v/a".to_owned()]));
        assert_eq!(backend.alias.as_deref(), Some("gen0"));
    }
}
