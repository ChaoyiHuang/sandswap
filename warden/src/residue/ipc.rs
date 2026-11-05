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

//! SysV IPC + user-keyring residue sweep.

use std::fs;
use warden::pure::parse_sysvipc_ids;

// ── Cross-tenant kernel-object residue sweep ─────────────────────────────
//
// The rule-A sweep kills PROCESSES; these channels are KERNEL OBJECTS that
// outlive their creators — SysV queues/semaphore sets/segments live in the
// VM's single IPC namespace, and the per-uid persistent user keyring lives in
// the user namespace. Agents sharing a reused VM run as the same uid 0, so
// the next agent could otherwise read whatever the previous one planted.
// The keyring and POSIX-mqueue families are denied outright by the exec
// profile (seccomp.rs); this sweep is the belt-and-braces clear for keys and
// the primary close for SysV (which stays usable within an agent's own
// lease). Runs after umount, when every agent process is provably dead —
// nothing can recreate objects past this point.

/// Parse the ID column of a /proc/sysvipc/{msg,sem,shm} table. The kernel
/// prints DECIMAL keys in column 1 (modern kernels: "%10d", not 0x-prefixed
/// — a `0x`-prefix filter here silently matches nothing and the sweep no-ops;
/// caught by the cross-tenant residue e2e); column 2 is the id that
/// msgctl/semctl/shmctl's IPC_RMID actually takes (passing the KEY there is
/// a silent EINVAL no-op). Pure function for unit testing.

/// KEYCTL_CLEAR the persistent uid-0 user keyring: keys planted there by the
/// previous agent survive process death (user-namespace scope, not IPC).
pub(crate) fn clear_user_keyring() {
    // KEYCTL_CLEAR = 7, KEY_SPEC_USER_KEYRING = -4.
    let rc = unsafe { libc::syscall(libc::SYS_keyctl, 7i64, -4i64) };
    let _ = rc;
}

/// Remove every SysV IPC object, then clear the persistent user keyring.
/// Returns the number of objects whose removal could not be proven: the
/// caller fails the unmount on a nonzero count, because residue that outlives
/// its creator is visible to the next tenant. POSIX mqueues need no sweep
/// here: the exec profile denies the whole mq_* family, so an agent can
/// neither create nor open a queue.
pub(crate) fn clear_kernel_ipc_residue() -> usize {
    let mut removed: usize = 0;
    let mut failed: usize = 0;
    for file in ["msg", "sem", "shm"] {
        let table = match fs::read_to_string(format!("/proc/sysvipc/{}", file)) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, // family not built
            Err(_) => {
                failed += 1;
                continue;
            }
        };
        for id in parse_sysvipc_ids(&table) {
            // Variadic libc::syscall args are NOT auto-promoted: every scalar
            // must be passed as c_long or the upper register bits are garbage
            // and the *ctl call fails EINVAL on a corrupted id.
            let id = id as libc::c_long;
            let rm = libc::IPC_RMID as libc::c_long;
            let rc = match file {
                "msg" => unsafe {
                    libc::syscall(
                        libc::SYS_msgctl,
                        id,
                        rm,
                        std::ptr::null_mut::<libc::c_void>(),
                    )
                },
                "sem" => unsafe { libc::syscall(libc::SYS_semctl, id, 0, rm) },
                _ => unsafe {
                    libc::syscall(
                        libc::SYS_shmctl,
                        id,
                        rm,
                        std::ptr::null_mut::<libc::c_void>(),
                    )
                },
            };
            if rc == 0 {
                removed += 1;
            } else {
                failed += 1;
            }
        }
    }
    clear_user_keyring();
    // Security-relevant and rare (a residue-free switch removes nothing):
    // the greppable signature for detection, silent in the common case —
    // but removal FAILURES always surface.
    if removed > 0 || failed > 0 {
        slog_scope::warn!(
            "cross-tenant residue sweep at unmount: removed {} kernel IPC object(s), {} removal failure(s)",
            removed,
            failed
        );
    }
    failed
}
