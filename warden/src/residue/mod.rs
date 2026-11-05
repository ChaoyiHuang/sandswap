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

//! Cross-tenant residue clearing at unmount: kernel objects and network
//! state that outlive their creators (SysV IPC, the user keyring, dead-state
//! TCP sockets, neighbor-table entries), the warden's own task attributes,
//! and the rule-A process sweep. Everything here runs AFTER the agent's
//! processes are provably dead.
//!
//! KNOWN, ACCEPTED residue: per-interface and protocol traffic counters
//! (/proc/net/dev, /proc/net/snmp+netstat, and the same figures via
//! rtnetlink RTM_GETLINK) accumulate for the network namespace's whole
//! lifetime, so a later tenant on a reused VM reads the byte/packet totals
//! of every earlier one summed together. No reset API exists (rtnetlink
//! counters are read-only; masking /proc/net would not cover the netlink
//! path), and the only complete close — a per-attach network namespace —
//! would rework the VM-level network identity for zero security gain: the
//! figures carry no content, no identity, and no per-tenant attribution.
//! Deliberately not swept.

pub mod attrs;
pub mod ipc;
pub mod neigh;
pub mod sweep;
pub mod tcp_diag;

pub(crate) use attrs::restore_warden_attrs;
pub(crate) use ipc::clear_kernel_ipc_residue;
pub(crate) use neigh::flush_neighbor_table;
pub(crate) use sweep::{sweep_non_init_processes, unclean_pids};
pub(crate) use tcp_diag::destroy_dead_tcp_sockets;

/// Netlink message flags shared by the sock-diag and neighbor flushes.
pub(crate) const NLMSG_F_REQUEST: u16 = 1;
pub(crate) const NLMSG_F_DUMP: u16 = 0x300; // ROOT|MATCH
pub(crate) const NLMSG_F_ACK: u16 = 4;

/// Bounds on the diag dump drain and on the messages consumed while waiting
/// for one acknowledgement. A hostile or corrupted kernel could otherwise
/// stream messages forever (the warden runs unmount on its single thread, and
/// an unbounded loop would stall the switch instead of failing it).
pub(crate) const TCP_DIAG_DUMP_MAX_MESSAGES: usize = 4096;
pub(crate) const TCP_DIAG_MAX_SOCKETS: usize = 16384;
pub(crate) const NL_ACK_MAX_MESSAGES: usize = 64;

pub(crate) fn nl_send(fd: libc::c_int, msg: &[u8]) -> std::io::Result<()> {
    let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    dst.nl_family = libc::AF_NETLINK as u16;
    let n = unsafe {
        libc::sendto(
            fd,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else if n as usize != msg.len() {
        // A partial netlink datagram is not a delivered request; treating it
        // as success would wait for an ACK that never comes.
        Err(std::io::Error::other("short netlink write"))
    } else {
        Ok(())
    }
}

/// Receive one netlink datagram (200ms receive timeout — a hung diag exchange
/// must never stall the unmount path). EINTR is retried; every other failure
/// (including the timeout) is returned so the caller can fail closed.
pub(crate) fn nl_recv(fd: libc::c_int) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        buf.truncate(n as usize);
        return Ok(buf);
    }
}
