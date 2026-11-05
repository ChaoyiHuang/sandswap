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

//! Neighbor-table flush (the `ip neigh flush all` algorithm).

use crate::residue::{nl_recv, nl_send, NLMSG_F_DUMP, NLMSG_F_REQUEST};

// ── Cross-tenant neighbor-table flush (RTM_DELNEIGH) ────────────────────
//
// The sock_diag sweep destroys per-SOCKET state; the neighbor table is the
// other network object that outlives its creator: entries the previous agent
// resolved (the gateway, anything it probed on the L2 segment) persist in the
// netns and are readable by the next agent through /proc/net/arp — aggregate
// metadata, no payload, but exactly the residue class the switch clears.
//
// The algorithm is `ip neigh flush all`: dump every entry over NETLINK_ROUTE
// (RTM_GETNEIGH, all families), then echo each dumped message back as an
// RTM_DELNEIGH (see pure::neigh_delete_request — echo-delete needs no
// attribute parsing). Deliberately NOT the single-send NLM_F_BULK form:
// bulk delete for RTM_DELNEIGH is not supported on every kernel generation
// (it arrived for other families first), and dump-then-delete works wherever
// iproute2 does. Best-effort, unmount path only; the table is tiny on the
// static-IP guest (usually just the gateway), so the whole flush is one dump
// round trip plus a handful of echoed deletes — sub-millisecond.

pub(crate) const RTM_NEWNEIGH: u16 = 28;
pub(crate) const RTM_GETNEIGH: u16 = 30;
pub(crate) const NLMSG_DONE_MSG: u16 = 3;
pub(crate) const NLMSG_ERROR_MSG: u16 = 2;
/// Bound on dumped messages walked per flush: a hostile or corrupted kernel
/// must not be able to loop the warden forever on a synthetic dump stream
/// (the same reasoning as the diag sweep's datagram drain).
pub(crate) const NEIGH_DUMP_MAX_MESSAGES: usize = 1024;

/// Build the 20-byte RTM_GETNEIGH dump request for all address families
/// (nlmsghdr + rtgenmsg{family=AF_UNSPEC}, NLM_LOG_ALIGN padded).
pub(crate) fn neigh_dump_request(seq: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(20);
    m.extend_from_slice(&20u32.to_ne_bytes()); // nlmsg_len
    m.extend_from_slice(&RTM_GETNEIGH.to_ne_bytes()); // type
    m.extend_from_slice(&(NLMSG_F_REQUEST | NLMSG_F_DUMP).to_ne_bytes()); // flags
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes()); // pid
    m.push(0); // rtgenmsg.ndt_family = AF_UNSPEC
    m.extend_from_slice(&[0u8; 3]); // NLMSG_ALIGN padding
    m
}

/// Classification of one dumped neighbor message. Extracted as an ENUM-returning
/// pure function so a mistyped match arm cannot compile into a catch-all
/// binding (the classic const-name-becomes-binding Rust bug, which would
/// silently swallow NLMSG_ERROR into the done path) — a wrong arm here is a
/// compile error, and the classification itself is unit-pinned below.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NeighMsgKind {
    Entry,
    Done,
    Error,
    Other,
}

pub(crate) fn neigh_msg_kind(msg: &[u8]) -> NeighMsgKind {
    match warden::pure::nl_type(msg) {
        RTM_NEWNEIGH => NeighMsgKind::Entry,
        NLMSG_DONE_MSG => NeighMsgKind::Done,
        NLMSG_ERROR_MSG => NeighMsgKind::Error,
        _ => NeighMsgKind::Other,
    }
}

/// Remove every neighbor-table entry. Returns (removed, failed), the same
/// shape as destroy_dead_tcp_sockets.
pub(crate) fn flush_neighbor_table() -> (usize, usize) {
    let mut removed = 0usize;
    let mut failed = 0usize;
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        // A sweep that cannot open its socket has not cleared anything;
        // report the failure so unmount fails closed.
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
    // Phase 1: dump entries until NLMSG_DONE (bounded).
    let mut entries: Vec<Vec<u8>> = Vec::new();
    let mut done = false;
    let mut walked = 0usize;
    if nl_send(fd, &neigh_dump_request(1)).is_ok() {
        while !done && walked < NEIGH_DUMP_MAX_MESSAGES {
            let Ok(resp) = nl_recv(fd) else { break };
            if resp.is_empty() {
                break;
            }
            for msg in warden::pure::nl_messages(&resp) {
                walked += 1;
                match neigh_msg_kind(msg) {
                    NeighMsgKind::Entry => entries.push(msg.to_vec()),
                    NeighMsgKind::Done => done = true,
                    NeighMsgKind::Error => {
                        failed += 1;
                        done = true;
                    }
                    NeighMsgKind::Other => {}
                }
            }
        }
        if !done {
            // An incomplete dump means entries may remain; the sweep must not
            // report success.
            failed += 1;
        }
    } else {
        failed += 1;
    }

    // Phase 2: echo each entry back as a delete, ack per message.
    for (i, entry) in entries.iter().enumerate() {
        let seq = 2 + i as u32;
        let Some(req) = warden::pure::neigh_delete_request(entry, seq) else {
            failed += 1;
            continue;
        };
        if nl_send(fd, &req).is_err() {
            failed += 1;
            continue;
        }
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
                        removed += 1;
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
    unsafe { libc::close(fd) };
    (removed, failed)
}
