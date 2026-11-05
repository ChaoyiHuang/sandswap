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

//! Dependency-free pure helpers extracted from the warden binary so the fuzz
//! targets exercise the exact code the warden runs:
//! * `check_component` — the single-component path rule used by every
//!   anchored mount/file operation;
//! * `parse_sysvipc_ids` — the `/proc/sysvipc/*` table reader used by the
//!   cross-tenant residue sweep.

/// The single-component rule for every path the warden resolves under an
/// anchor: a real name, not `.`/`..`, no separator, no NUL.
pub fn check_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

/// Parse the ID column of a `/proc/sysvipc/{msg,sem,shm}` table. The kernel
/// prints DECIMAL keys in column 1 (modern kernels: "%10d", not 0x-prefixed
/// — a `0x`-prefix filter here silently matches nothing and the sweep no-ops;
/// caught by the cross-tenant residue e2e); column 2 is the id that
/// msgctl/semctl/shmctl's IPC_RMID actually takes (passing the KEY there is
/// a silent EINVAL no-op).
pub fn parse_sysvipc_ids(table: &str) -> Vec<i32> {
    table
        .lines()
        .skip(1) // header line
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|id| id.parse::<i32>().ok())
        .collect()
}

// ── Netlink sock_diag response parsing (warden unmount sweep) ──────────
//
// The warden dumps dead-state TCP sockets and destroys them by echoing the
// kernel's 48-byte sockid. The response is kernel-generated, but a hostile
// or corrupted kernel (the guest kernel is ptrace-adjacent to this process)
// must not be able to panic PID 1: every length/state read is bounds-checked,
// and the TCP-state shift is checked (a `state` byte >= 32 would otherwise
// overflow `1u32 << state`).

const NLMSG_HDR_LEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const SOCK_DIAG_BY_FAMILY: u16 = 20;

/// One parsed dump response.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DiagDump {
    /// The 48-byte `sockid` of each dead-state socket (state in the mask).
    pub sockids: Vec<[u8; 48]>,
    /// A NLMSG_DONE was seen.
    pub done: bool,
    /// NLMSG_ERROR messages seen (each counted as a failure).
    pub failed: usize,
}

/// Iterate the netlink messages in a received buffer, stopping at the first
/// header that is too short or overruns the buffer.
pub fn nl_messages(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + NLMSG_HDR_LEN <= buf.len() {
        let hdr_len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        if hdr_len < NLMSG_HDR_LEN || off + hdr_len > buf.len() {
            break;
        }
        out.push(&buf[off..off + hdr_len]);
        off += hdr_len;
    }
    out
}

pub fn nl_type(msg: &[u8]) -> u16 {
    u16::from_ne_bytes(msg[4..6].try_into().unwrap())
}

/// Parse one sock_diag dump datagram: collect every dead-state TCP sockid,
/// note NLMSG_DONE and count NLMSG_ERROR. `dead_state_bits` is the state mask.
pub fn parse_diag_dump(buf: &[u8], dead_state_bits: u32) -> DiagDump {
    let mut out = DiagDump::default();
    for msg in nl_messages(buf) {
        match nl_type(msg) {
            SOCK_DIAG_BY_FAMILY => {
                // inet_diag_msg starts after the 16-byte nlmsghdr: family(1),
                // state(1), timer(1), retrans(1), then the 48-byte sockid.
                if msg.len() >= 16 + 4 + 48 {
                    let state = msg[16 + 1] as u32;
                    // checked shift: a state byte >= 32 must not panic PID 1.
                    if state < 32 && dead_state_bits & (1u32 << state) != 0 {
                        let mut id = [0u8; 48];
                        id.copy_from_slice(&msg[16 + 4..16 + 4 + 48]);
                        out.sockids.push(id);
                    }
                }
            }
            NLMSG_DONE => out.done = true,
            NLMSG_ERROR => out.failed += 1,
            _ => {}
        }
    }
    out
}

/// Parse one NLMSG_ERROR ack for `seq`; returns the kernel error code (0 =
/// success) when the message is a matching ack, None otherwise.
pub fn parse_diag_ack(msg: &[u8], seq: u32) -> Option<i32> {
    // Length first: nl_type() indexes bytes 4..6, and a public parser must
    // not panic on an empty/short slice. (The netlink fuzz target's first
    // crash is exactly this: the empty input.)
    if msg.len() < 20 || nl_type(msg) != NLMSG_ERROR {
        return None;
    }
    if u32::from_ne_bytes(msg[8..12].try_into().unwrap()) != seq {
        return None;
    }
    Some(i32::from_ne_bytes(msg[16..20].try_into().unwrap()))
}

/// RTM_DELNEIGH echo-delete request for one dumped RTM_NEWNEIGH entry
/// (neighbor-table flush at unmount — the `ip neigh flush all` algorithm).
///
/// The dumped entry already carries everything the kernel's delete handler
/// parses (ndmsg + NDA_DST), so the request is the entry with the header
/// re-stamped: type → RTM_DELNEIGH(29), flags → NLM_F_REQUEST|NLM_F_ACK,
/// our seq, pid 0. Echoing avoids attribute parsing entirely — no NDA walk
/// a corrupted dump could subvert. None when the entry is too short to be a
/// nlmsghdr+ndmsg pair (skipped by the caller, counted as a failure).
pub fn neigh_delete_request(entry: &[u8], seq: u32) -> Option<Vec<u8>> {
    const RTM_DELNEIGH: u16 = 29;
    const NLM_F_REQUEST: u16 = 0x01;
    const NLM_F_ACK: u16 = 0x04;
    if entry.len() < NLMSG_HDR_LEN + 12 {
        return None;
    }
    let mut out = entry.to_vec();
    out[4..6].copy_from_slice(&RTM_DELNEIGH.to_ne_bytes());
    out[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    out[8..12].copy_from_slice(&seq.to_ne_bytes());
    out[12..16].copy_from_slice(&0u32.to_ne_bytes());
    Some(out)
}

/// Decode one escaped mountinfo field. The kernel escapes space/tab/newline/
/// backslash in mount points as \040/\011/\012/\134; the decode is the same
/// one the per-path comparison used before the mount-point set existed.
pub fn decode_mount_point(field: &str) -> String {
    field
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

/// Parse the mount-point column (field 5) of a `/proc/self/mountinfo`
/// listing into a set of DECODED mount points. Pure so the kernel escape
/// handling stays unit-pinned — the teardown snapshot is built from this.
pub fn parse_mount_points(mountinfo: &str) -> std::collections::HashSet<String> {
    mountinfo
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .map(decode_mount_point)
        .collect()
}

/// Format a resolv.conf body from a DNS server list ("nameserver X" per
/// line, trailing newline). Shared by the boot-time guest DNS setup and the
/// per-mount chroot injection so the two writers cannot drift.
pub fn format_resolv_conf(dns: &[String]) -> String {
    dns.iter()
        .map(|s| format!("nameserver {}", s.trim()))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_parser_bounds_and_state_shift() {
        // One valid dead-state record (state byte 6 = TIME_WAIT) and DONE.
        let mut msg = vec![0u8; 16 + 4 + 48];
        msg[0..4].copy_from_slice(&(68u32).to_ne_bytes());
        msg[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        msg[16 + 1] = 6;
        for (i, b) in msg[16 + 4..16 + 4 + 48].iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut done = vec![0u8; 16];
        done[0..4].copy_from_slice(&(16u32).to_ne_bytes());
        done[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        let buf = [msg.clone(), done].concat();
        let d = parse_diag_dump(&buf, 1 << 6);
        assert_eq!(d.sockids.len(), 1);
        assert!(d.done);
        assert_eq!(d.failed, 0);
        // State 255 must not panic and must not match.
        let mut bad = msg.clone();
        bad[16 + 1] = 255;
        let d = parse_diag_dump(&bad, 1 << 6);
        assert!(d.sockids.is_empty());
        // Truncated header / overrun are ignored, not panics.
        assert!(parse_diag_dump(&[0, 0, 0], 1 << 6).sockids.is_empty());
        assert!(parse_diag_dump(&[0xff, 0xff, 0xff, 0xff], 1 << 6)
            .sockids
            .is_empty());
        // Ack: matching seq, len <20, wrong seq.
        let mut ack = vec![0u8; 20];
        ack[0..4].copy_from_slice(&(20u32).to_ne_bytes());
        ack[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        ack[8..12].copy_from_slice(&(7u32).to_ne_bytes());
        ack[16..20].copy_from_slice(&(-2i32).to_ne_bytes());
        assert_eq!(parse_diag_ack(&ack, 7), Some(-2));
        assert_eq!(parse_diag_ack(&ack, 8), None);
        assert_eq!(parse_diag_ack(&ack[..19], 7), None);
        // Empty and shorter-than-header inputs must not panic (fuzz find).
        assert_eq!(parse_diag_ack(&[], 1), None);
        assert_eq!(parse_diag_ack(&[0, 0, 0], 1), None);
    }

    #[test]
    fn component_rule_and_table() {
        for bad in ["", ".", "..", "a/b", "/abs", "a\0b"] {
            assert!(!check_component(bad));
        }
        for good in ["bin", "..x", "x..", "resolv.conf"] {
            assert!(check_component(good));
        }
        let table = "       key      msqid perms\n   1234      42  666\n   0x55      7  600\n";
        assert_eq!(parse_sysvipc_ids(table), vec![42, 7]);
    }

    #[test]
    fn mount_point_set_decodes_kernel_escapes() {
        // Real mountinfo shape: id parent major:minor root MOUNT_POINT opts.
        let info = "22 20 0:21 / / rw - ext4 rw\n\
                    23 22 0:21 /vol /mnt/my\\040root rw - ext4 rw\n\
                    garbage-line-with-fewer-fields\n";
        let set = parse_mount_points(info);
        assert_eq!(set.len(), 2, "short lines are skipped: {set:?}");
        assert!(set.contains("/"));
        assert!(set.contains("/mnt/my root"), "\\040 must decode to a space");
        // Every escape the kernel documents, and only those four.
        assert_eq!(
            decode_mount_point("a\\040b\\011c\\012d\\134e"),
            "a b\tc\nd\\e"
        );
        // An unescaped field passes through verbatim.
        assert_eq!(decode_mount_point("/mnt/rootfs"), "/mnt/rootfs");
    }

    #[test]
    fn neigh_delete_request_repatches_header_only() {
        // A dumped RTM_NEWNEIGH entry: nlmsghdr + 12-byte ndmsg + one NLA.
        let mut entry = vec![0u8; 16 + 12 + 8];
        let total = entry.len() as u32;
        entry[0..4].copy_from_slice(&total.to_ne_bytes());
        entry[4..6].copy_from_slice(&28u16.to_ne_bytes()); // RTM_NEWNEIGH
        entry[6..8].copy_from_slice(&0x0301u16.to_ne_bytes()); // dump flags
        entry[8..12].copy_from_slice(&77u32.to_ne_bytes()); // dump seq
        entry[12..16].copy_from_slice(&12345u32.to_ne_bytes()); // dump pid
        entry[16] = 2; // ndm_family AF_INET (payload must survive verbatim)
        entry[20] = 0xAB;
        entry[31] = 0xCD;

        let req = neigh_delete_request(&entry, 9).expect("valid entry must patch");
        assert_eq!(u32::from_ne_bytes(req[0..4].try_into().unwrap()), total);
        assert_eq!(
            u16::from_ne_bytes(req[4..6].try_into().unwrap()),
            29,
            "type must become RTM_DELNEIGH"
        );
        assert_eq!(u16::from_ne_bytes(req[6..8].try_into().unwrap()), 0x05);
        assert_eq!(u32::from_ne_bytes(req[8..12].try_into().unwrap()), 9);
        assert_eq!(u32::from_ne_bytes(req[12..16].try_into().unwrap()), 0);
        assert_eq!(
            &req[16..],
            &entry[16..],
            "ndmsg+NLA payload must be verbatim"
        );
        assert_eq!(req.len(), entry.len());

        // Too short to be nlmsghdr+ndmsg: refused, never panicked on.
        assert!(neigh_delete_request(&entry[..27], 9).is_none());
        assert!(neigh_delete_request(&[], 9).is_none());
    }
}
