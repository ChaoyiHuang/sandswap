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

//! Dead-state TCP socket destruction (the `ss -K` algorithm over
//! NETLINK_SOCK_DIAG).

use crate::residue::{nl_recv, nl_send};

// ── Cross-tenant TCP dead-state cleanup (sock_diag destroy) ──────────────
//
// /proc/net/tcp{,6} rows for sockets in TIME_WAIT / FIN_WAIT1/2 / CLOSE_WAIT
// / LAST_ACK / CLOSING outlive their (killed) owning process and reveal the
// previous agent's connection 4-tuples. There is no global "clear TIME_WAIT"
// sysctl; the standard mechanism (what `ss -K` does under the hood) is
// NETLINK_SOCK_DIAG: DUMP the dead-state sockets, then destroy each by its
// sockid+cookie. Warden (PID 1, CAP_NET_ADMIN) may; best-effort, runs on the
// unmount cold path after the process sweep so only dead-agent sockets match.

pub(crate) const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// Destroy op message type. NOT a SOCK_DIAG_BY_FAMILY request: a type-20
/// destroy ACKs success without destroying anything (verified against
/// `ss -K` on a live kernel). ss uses 21 with idiag_states=0.
pub(crate) const SOCK_DESTROY: u16 = 21;
/// TCP state bits (linux/tcp.h values) whose sockets persist past process
/// death. ESTABLISHED sockets of killed processes transition INTO these
/// states as the kernel closes their fds, so post-sweep these are exactly
/// the residue.
pub(crate) const DEAD_TCP_STATE_BITS: u32 = (1 << 4) // FIN_WAIT1
    | (1 << 5) // FIN_WAIT2
    | (1 << 6) // TIME_WAIT
    | (1 << 8) // CLOSE_WAIT
    | (1 << 9) // LAST_ACK
    | (1 << 11); // CLOSING;

// Compile-time mask pins: dead states in, live states (ESTABLISHED=1,
// LISTEN=10) out — a wrong bit here fails the BUILD, not just a test.
const _: () = assert!(DEAD_TCP_STATE_BITS & (1 << 6) != 0); // TIME_WAIT
const _: () = assert!(DEAD_TCP_STATE_BITS & (1 << 1) == 0); // ESTABLISHED
const _: () = assert!(DEAD_TCP_STATE_BITS & (1 << 10) == 0); // LISTEN

/// nlmsghdr size in bytes (len/type/flags/seq/pid — offsets pinned by the
/// sock_diag_message_wire_layout test).
use crate::residue::{NLMSG_F_ACK, NLMSG_F_DUMP, NLMSG_F_REQUEST};

pub(crate) const INET_DIAG_NOCOOKIE: [u32; 2] = [u32::MAX, u32::MAX];

/// Build a 72-byte sock_diag wire message (nlmsghdr + inet_diag_req_v2).
/// `id: None` = wildcard dump id (NOCOOKIE); `Some` echoes a dumped sockid.
pub(crate) fn sock_diag_msg(
    nltype: u16,
    flags: u16,
    seq: u32,
    family: u8,
    states: u32,
    id: Option<&[u8; 48]>,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(72);
    m.extend_from_slice(&72u32.to_ne_bytes());
    m.extend_from_slice(&nltype.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.push(family);
    m.push(libc::IPPROTO_TCP as u8);
    m.push(0); // ext
    m.push(0); // pad
    m.extend_from_slice(&states.to_ne_bytes());
    match id {
        Some(id) => m.extend_from_slice(id),
        None => {
            m.extend_from_slice(&[0u8; 40]);
            for c in INET_DIAG_NOCOOKIE {
                m.extend_from_slice(&c.to_ne_bytes());
            }
        }
    }
    m
}

/// Destroy every dead-state TCP socket (both families). Returns
/// (destroyed, failed). Best-effort: any netlink error returns what it has.
pub(crate) fn destroy_dead_tcp_sockets() -> (usize, usize) {
    let mut destroyed = 0usize;
    let mut failed = 0usize;
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        // The sweep could not even open its socket: report a failure so the
        // unmount fails closed instead of declaring residue cleared.
        return (0, 1);
    }
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    for &family in &[libc::AF_INET as u8, libc::AF_INET6 as u8] {
        // Phase 1: dump dead-state sockets; drain until NLMSG_DONE so no dump
        // residue stays queued (a stale message read as a later ACK lies).
        let dump = sock_diag_msg(
            SOCK_DIAG_BY_FAMILY,
            NLMSG_F_REQUEST | NLMSG_F_DUMP,
            1,
            family,
            DEAD_TCP_STATE_BITS,
            None,
        );
        let mut sockids: Vec<[u8; 48]> = Vec::new();
        let mut done = false;
        let mut messages = 0usize;
        if nl_send(fd, &dump).is_ok() {
            while messages < crate::residue::TCP_DIAG_DUMP_MAX_MESSAGES {
                let Ok(resp) = nl_recv(fd) else { break };
                if resp.is_empty() {
                    break;
                }
                messages += 1;
                let parsed = warden::pure::parse_diag_dump(&resp, DEAD_TCP_STATE_BITS);
                sockids.extend(parsed.sockids);
                failed += parsed.failed;
                if sockids.len() > crate::residue::TCP_DIAG_MAX_SOCKETS {
                    sockids.truncate(crate::residue::TCP_DIAG_MAX_SOCKETS);
                    failed += 1;
                }
                if parsed.done {
                    done = true;
                    break;
                }
            }
            if !done {
                // A dump that did not terminate is an incomplete sweep: the
                // caller must not treat the residue as cleared.
                failed += 1;
            }
        } else {
            failed += 1;
        }
        // Phase 2: destroy each dumped socket: SOCK_DESTROY with states=0 and
        // the sockid echoed verbatim (the ss -K algorithm).
        for (i, id) in sockids.iter().enumerate() {
            let seq = 2 + i as u32;
            let req = sock_diag_msg(
                SOCK_DESTROY,
                NLMSG_F_REQUEST | NLMSG_F_ACK,
                seq,
                family,
                0,
                Some(id),
            );
            if nl_send(fd, &req).is_err() {
                failed += 1;
                continue;
            }
            // Read until the seq-matched NLMSG_ERROR ack (0 = destroyed;
            // ENOENT/ESRCH = already gone, counts as cleared).
            let mut resolved = false;
            let mut ack_messages = 0usize;
            while ack_messages < crate::residue::NL_ACK_MAX_MESSAGES {
                let Ok(ack) = nl_recv(fd) else { break };
                if ack.is_empty() {
                    break;
                }
                ack_messages += 1;
                for msg in warden::pure::nl_messages(&ack) {
                    if let Some(e) = warden::pure::parse_diag_ack(msg, seq) {
                        if e == 0 || e == -libc::ENOENT || e == -libc::ESRCH {
                            destroyed += 1;
                        } else {
                            failed += 1;
                        }
                        resolved = true;
                    }
                }
                if resolved {
                    break;
                }
            }
            if !resolved {
                failed += 1;
            }
        }
    }
    unsafe { libc::close(fd) };
    (destroyed, failed)
}
