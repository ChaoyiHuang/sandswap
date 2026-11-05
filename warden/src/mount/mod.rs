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

// mount/mod.rs — the swap orchestrator: the workspace mount/unmount entry
// points and the shared path constants. The mechanics live in focused
// submodules (boot, workspace, hardening, anchor); cross-tenant residue
// clearing lives in the crate::residue module tree.

mod anchor;
mod boot;
mod hardening;
#[cfg(test)]
mod tests;
mod workspace;

pub use boot::{general_mount, setup_busybox_source};
pub(crate) use hardening::harden_kernel_sysctls;
pub use workspace::mount_workspace;
pub(crate) use anchor::RootAnchor;
pub(crate) use workspace::{
    fuse_ops_begin, fuse_ops_end, open_volume_anchor, validate_export_alias,
    ERR_MOUNT_TARGET_NOT_EXPORTED,
};

use crate::residue::{
    clear_kernel_ipc_residue, destroy_dead_tcp_sockets, flush_neighbor_table, restore_warden_attrs,
    sweep_non_init_processes, unclean_pids,
};
use anyhow::{anyhow, Result};
use hardening::{drop_caches, teardown_masked, umount_verified, MountSet};

/// The bind mount point where the agent rootfs is mounted inside the VM.
/// Used by files.rs for path validation (all file I/O paths are resolved
/// relative to this chroot root).
pub const MOUNT_POINT: &str = "/mnt/rootfs";

/// The default working directory for agent commands inside the chroot.
/// After chroot into MOUNT_POINT, chdir(2) targets this path so that
/// `pwd` is /workspace (not /). Agent file I/O paths are also resolved
/// relative to this directory, keeping system dirs (/bin, /etc, /proc)
/// out of the agent's default namespace.
pub const WORKSPACE_DIR: &str = "/workspace";

/// The agent's home directory inside the chroot. Used for:
/// - Package installation via pip --user, npm prefix, etc.
/// - Configuration files (.bashrc, .profile, etc.)
/// - Shell dotfiles and user-specific settings
///
/// This directory lives on the SandFS volume's own storage — a shared backend
/// (NFS/CephFS/...) on multi-node deployments — and persists across node migrations.
pub const HOME_DIR: &str = "/home/agent";

/// Unmount the workspace before an agent switch.
///
/// # Exclusive-Ownership Invariant
///
/// A microVM belongs to exactly one SandFS at any time. When switching agents,
/// ALL processes from the previous SandFS must be dead and the rootfs unmounted
/// before the next SandFS's rootfs can be mounted. This invariant is enforced
/// by the following chain:
///
///   1. cgroup.kill → poll procs empty (timeout) — clears the agent cgroup
///      tree (background execs and their descendants)
///   2. Rule-A sweep → SIGKILL everything except PID 1, short reap window —
///      clears EVERY straggler (setsid'd sync-exec descendants, processes
///      planted by a hostile in-guest actor, anything else alive)
///   3. teardown masked mounts → umount workspace
///   4. If umount EBUSY (D-state process only, post-sweep): retry once after 500ms
///   5. If retry also fails: return error → gateway destroys the VM
///   6. Final state gate: a ZOMBIE left above PID 1 fails the unmount the same
///      way (owner ruling), and so does a live userspace task still
///      parked in uninterruptible sleep ('D') — the umount-EBUSY probe above
///      only sees a park that holds a path on /mnt/rootfs
///
/// After step 2 the only remaining EBUSY source is a D-state process stuck in
/// uninterruptible I/O — the destroy backstop is the last resort, not the
/// routine path. Zombies are the sibling case for the process TABLE rather
/// than the mount: nothing can pin a mount with a corpse, but an unreaped
/// process means the guest is not provably clean, and "provably clean" is the
/// whole point of the switch. The step-6 gate therefore fails on both classes
/// (and only those two: a running/sleeping userspace task is just a SIGKILL
/// in flight, given its bounded re-drain window). (Kernel threads are neither
/// — they ignore signals by design and are exempt, see sweep_target_pid.)
///
/// We do NOT use MNT_DETACH. While MNT_DETACH would detach the mount from the
/// namespace immediately, it leaves the D-state process alive. When the next
/// agent's rootfs is mounted, the old process would coexist with the new one
/// in the same VM — violating the invariant that only one SandFS's processes
/// run in a microVM at a time. Destroying the VM is the safe alternative: it
/// kills every process (including D-state) and guarantees a clean slate.
///
/// The cost of VM destruction is a one-time cold-boot (~2-3s) for the next
/// agent, but it provides absolute isolation — no chain of technical mitigations
/// (chroot + seccomp + vsock isolation + bounding set) needed to be relied upon.
///
/// # Page-cache eviction
///
/// The bind mount at `mount_point` is backed by virtio-fs. `umount(2)` flushes
/// dirty pages for the mount being removed, so no explicit `sync()` is needed.
/// The prior global `sync()` was dropped (~40ms stall).
///
/// Global `drop_caches=3` after umount frees pagecache + dentries + inodes
/// guest-wide. The hot-busybox overlay is on tmpfs and unaffected by drop_caches.
pub fn unmount_workspace(
    mount_point: &str,
    agent_cgroup: Option<crate::exec_cgroup::AgentCgroup>,
    fallback_pgids: Vec<i32>,
) -> Result<()> {
    // EXCLUSIVE-OWNERSHIP INVARIANT (agent-switch clearing): kill ALL of the current
    // agent's processes BEFORE umount, so none can hold the mount busy (EBUSY)
    // or coexist with the next agent's processes. If processes survive (D-state),
    // the umount returns EBUSY and the gateway destroys the VM — guaranteeing
    // that only one SandFS's processes exist in a microVM at any time.
    if let Some(cg) = &agent_cgroup {
        // Preferred path: cgroup.kill (O(1), atomic recursive SIGKILL).
        // The per-agent cgroup contains every exec's process group (sync +
        // background); cgroup.kill atomically SIGKILLs the whole tree, then
        // we poll cgroup.procs empty. Background processes survive across exec
        // calls (within the agent's lease) and are cleared only here, at agent
        // switch.
        let clear_timeout = crate::AGENT_CONFIG.cgroup_clear_timeout;
        cg.kill_and_reap(clear_timeout);
    } else {
        // Fallback: no cgroup available (kernel without CONFIG_CGROUPS or
        // cgroup2 mount failed). Kill each background exec's pgid individually
        // (collected by the async caller from bg_execs), then reap. Sync execs
        // are already dead (do_exec kills pgid on return), but background execs
        // may still be running. Without this, they survive the unmount and hold
        // /mnt/rootfs open (EBUSY) or leak into the next agent's mount namespace.
        //
        // Note: agent_mem_percent=0 no longer takes this path — the cgroup is
        // still created (just without memory.max) so cgroup.kill is available.
        for pgid in &fallback_pgids {
            if *pgid > 0 {
                unsafe {
                    let _ = libc::kill(-*pgid, libc::SIGKILL);
                }
            }
        }
        // Brief reap window (shorter than cgroup path — these are individual
        // kills, not an atomic cgroup.kill, so a few hundred ms suffices).
        //
        // Reap through the central registry (reap_zombie: WAIT_PID_LOCKER +
        // forward_exit), NEVER a bare waitpid(-1): a bare global reap silently
        // discards the status of a concurrently-waiting exec's child (the
        // waiter would hang until its timeout), and could land inside the
        // spawn→register window. The forwarding version is what makes a
        // global reap safe next to in-flight execs.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            if matches!(
                crate::signal::reap_zombie(libc::WNOHANG | libc::__WALL),
                crate::signal::Reaped::Nothing
            ) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    // Rule-A sweep: with the cgroup tree dead, kill EVERYTHING else alive
    // (setsid'd sync-exec stragglers belong to no cgroup and no registered
    // pgid — only the sweep reaches them), then give the SIGKILLs a short
    // window to land before teardown so a dying straggler does not hold
    // /mnt/rootfs busy. Same registry-based reap as above.
    //
    // A failed /proc scan is FATAL to this VM: "cannot prove there is
    // nothing alive" must never be treated as "nothing is alive".
    //
    // The same applies to the sweep's bounded round budget: Ok means a round
    // observed ZERO live userspace targets; exhausting the budget while
    // still signalling targets is returned as an error here and FAILS the
    // unmount (the sandlot destroys the VM). Proceeding on the exhausted
    // path would let a forker survive the budget.
    //
    // The returned kernel-thread pids are HINTS FOR OBSERVABILITY ONLY. The
    // final gate below re-reads every pid: a pid is not an identity, and a
    // kernel thread that exits frees its pid for a userspace task.
    let sweep_kthreads = match sweep_non_init_processes() {
        Ok(kthreads) => kthreads,
        Err(e) => {
            return Err(anyhow!(
                "process sweep failed ({}): refusing to reuse this VM",
                e
            ));
        }
    };
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
        while std::time::Instant::now() < deadline {
            if matches!(
                crate::signal::reap_zombie(libc::WNOHANG | libc::__WALL),
                crate::signal::Reaped::Nothing
            ) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    // Restore the warden's own per-task attributes. The agent ran as the same
    // uid and could retune PID 1 or its worker threads (nice, affinity,
    // scheduling policy) without any capability; those values are kernel
    // state that outlives the tenant switch. Done after the sweep (no agent
    // process can re-poison it) and before the teardown so a pinned/starved
    // warden finishes the rest of the unmount at its own priority.
    restore_warden_attrs();

    // Teardown mount set: ONE /proc/self/mountinfo read shared by every
    // umount_verified probe below (4 binds + the stamp cover + 22 masked
    // covers + 6 teardown rels + busybox — re-reading mountinfo per probe
    // was a measured share of the switch path).
    //
    // PRECONDITION (see MountSet): this function must run with
    // MOUNT_GATE.write() held — every caller does (OP_UNMOUNT and the
    // ensure_mounted_once self-heal), and every mount creator takes the same
    // write guard, so no mount can appear after the snapshot; the sweep has
    // also proved no userspace process exists that could mount.
    //
    // A snapshot READ FAILURE is FATAL to the unmount (fail closed): an
    // empty set would silently skip every probe, so one transient read error
    // would disable the whole teardown.
    let mut mounts = MountSet::snapshot().map_err(|e| {
        anyhow!(
            "teardown mountinfo snapshot failed ({}): cannot prove the guest's mount set — refusing to reuse this VM",
            e
        )
    })?;

    // Hardening: tear down the masked proc/dev/tmpfs child mounts FIRST so the
    // workspace umount doesn't hit EBUSY, and so tmpfs contents (prior agent's
    // shared memory) are released. Best-effort.
    //
    // Unmount the writable home and workspace bind mounts BEFORE teardown_masked,
    // since teardown_masked unmounts /tmp (which is now tmpfs, not backed by the
    // workspace) and we need the workspace/home unmounted before the rootfs
    // bind mount can be released.
    let home_target = format!("{}{}", mount_point, HOME_DIR);
    umount_verified(&home_target, None, &mut mounts);

    let workspace_target = format!("{}/workspace", mount_point);
    umount_verified(&workspace_target, None, &mut mounts);

    // The agent-chroot resolv.conf: in overlay mode inject_guest_resolv_conf
    // cannot write the read-only rootfs and BIND-MOUNTS its tmpfs fallback
    // over {mp}/etc/resolv.conf instead. That file bind is a CHILD MOUNT of
    // {mp} — leaving it in place makes umount({mp}) fail EBUSY (kernel rule:
    // a mount with submounts cannot be detached; the 500ms retry cannot clear
    // it), so EVERY overlay+DNS agent switch ended in "unmount failed →
    // gateway destroys the VM" — a ~2-3s cold rebuild per switch instead of
    // the warm switch, invisible to green tests (destroy-and-replace is
    // behaviorally transparent). Verified on a real kernel: a file bind under
    // the workspace mount yields EBUSY now and after the retry. Unmount it
    // with the home/workspace binds above.
    let r = mount_point.trim_end_matches('/');
    let resolv_target = format!("{}/etc/resolv.conf", r);
    umount_verified(&resolv_target, None, &mut mounts);

    // The flat-mode stamp cover (mask_volume_stamp): a child file bind —
    // unmount it before the workspace parent, same ordering rule as resolv.
    umount_verified(&format!("{}/{}", r, workspace::VOLUME_STAMP_NAME), None, &mut mounts);

    teardown_masked(mount_point, &mut mounts);

    // ④: unmount the hot-busybox overlay BEFORE the workspace, otherwise the
    // child mount at <mount_point>/bin/busybox makes umount(mount_point) fail
    // with EBUSY. Best-effort.
    let guest_busybox = format!("{}/bin/busybox", mount_point);
    umount_verified(&guest_busybox, None, &mut mounts);

    // umount(2) flushes this mount's dirty pages before returning.
    // EINVAL = not a mount point (already unmounted or mount never happened,
    // e.g. after a transport error on the mount path) — idempotent success.
    // The preceding cgroup.kill + teardown_masked are still valuable (they
    // clear stale state from a prior mount).
    //
    // EBUSY = a process still holds files open on this mount (e.g. D-state
    // process that cgroup.kill could not reap within the timeout). We retry
    // once after a short sleep: the D-state process may have just woken up
    // and been reaped by the SIGCHLD handler. If retry also fails, we return
    // an error — the gateway will destroy this VM to guarantee that NO process
    // from the old SandFS coexists with the next SandFS's process. This is the
    // exclusive-ownership security invariant: one microVM = one SandFS at a time.
    // We do NOT use MNT_DETACH here, as it would detach the mount from the
    // namespace while leaving the D-state process alive, allowing it to coexist
    // with the next agent's process in the same VM — violating the invariant.
    //
    // The std::thread::sleep in the EBUSY retry and the fallback reap above are
    // safe: this function runs inside spawn_blocking on the async detach path,
    // so blocking sleeps occupy a blocking-pool thread, not an async worker.
    // Detach the root LAST, and keep detaching until the kernel reports the
    // path is not a mount point. A successful umount removes exactly ONE
    // layer: a partial mount_workspace failure can leave a stack behind
    // (mount_active was never set, so no other path would remove it), and
    // stopping after one layer would silently leave the old rootfs mounted
    // underneath the next tenant. EINVAL/ENOENT is the proof that no layer
    // remains — only then may the caller set mounts_clean.
    let mut layers = 0u32;
    let mut busy_retried = false;
    loop {
        match nix::mount::umount(mount_point) {
            Ok(()) => {
                layers += 1;
                if layers > 8 {
                    return Err(anyhow!(
                        "failed to unmount workspace: still mounted after {} layers \
                         — VM must be destroyed to maintain exclusive-ownership invariant",
                        layers
                    ));
                }
                // Another layer may remain below; umount again.
                continue;
            }
            Err(nix::errno::Errno::EINVAL) => {
                // Not a mount point — idempotent success, and the proof that
                // no layer remains.
                break;
            }
            Err(nix::errno::Errno::ENOENT) => {
                // The mount point path itself does not exist — provably
                // nothing is mounted there, so this is idempotent success too
                // (the self-heal path in raw_server relies on this when it
                // unmounts a guest whose /mnt/rootfs was never created).
                break;
            }
            Err(nix::errno::Errno::EBUSY) => {
                if busy_retried {
                    return Err(anyhow!(
                        "failed to unmount workspace after retry (EBUSY) \
                         — VM must be destroyed to maintain exclusive-ownership invariant"
                    ));
                }
                busy_retried = true;
                slog_scope::warn!(
                    "umount {} EBUSY (D-state process?); waiting 500ms and retrying...",
                    mount_point
                );
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Err(e) => {
                return Err(anyhow!("failed to unmount workspace: {}", e));
            }
        }
    }

    // Global drop_caches=3: frees ALL clean pagecache + dentries + inodes
    // guest-wide. This is broader than strictly necessary (only the unmounted
    // agent's pages need clearing), but Linux has no per-mount drop_caches API.
    // The hot-busybox overlay (④) is on tmpfs and unaffected. Best-effort.
    drop_caches();

    // Cross-tenant kernel-object residue (SysV IPC, persistent user keyring):
    // kernel objects the process sweep above cannot touch. POSIX mqueues are
    // closed by the exec profile's mq_* syscall deny (seccomp.rs), so there is
    // nothing to sweep. Every agent process is dead by this point, so nothing
    // recreates the swept objects.
    let ipc_failed = clear_kernel_ipc_residue();

    // Cross-tenant TCP dead-state residue (the previous agent's connection
    // 4-tuples visible via /proc/net for the TIME_WAIT window): sock_diag
    // destroy. Best-effort, cold path.
    let (tcp_cleared, tcp_failed) = destroy_dead_tcp_sockets();
    if tcp_cleared > 0 || tcp_failed > 0 {
        slog_scope::warn!(
            "cross-tenant TCP dead-state sweep at unmount: destroyed {}, failed {}",
            tcp_cleared,
            tcp_failed
        );
    }

    // Cross-tenant neighbor-table residue: entries the previous agent resolved
    // (the gateway, anything it probed on the L2 segment) persist in the netns
    // and are visible to the next agent via /proc/net/arp. Same best-effort
    // shape as the TCP sweep above.
    let (neigh_cleared, neigh_failed) = flush_neighbor_table();
    if neigh_cleared > 0 || neigh_failed > 0 {
        slog_scope::warn!(
            "cross-tenant neighbor-table flush at unmount: removed {}, failed {}",
            neigh_cleared,
            neigh_failed
        );
    }

    // Residue sweeps are FAIL-CLOSED, matching the process sweep: a sweep that
    // could not prove its residue gone leaves kernel objects visible to the
    // next tenant on this VM, and reuse is the cheap path, not the correct one.
    let residue_failed = ipc_failed + tcp_failed + neigh_failed;
    if residue_failed > 0 {
        return Err(anyhow!(
            "cross-tenant residue could not be cleared ({} failure(s): ipc={}, tcp={}, neighbor={}) — refusing to reuse this VM; the sandlot must destroy it",
            residue_failed,
            ipc_failed,
            tcp_failed,
            neigh_failed
        ));
    }

    // AgentCgroup::Drop removes the cgroup dir. No separate fs::remove_dir
    // needed — the owned AgentCgroup handles cleanup when it goes out of scope.
    drop(agent_cgroup);

    // Final-state gate (owner ruling): a zombie left in the guest —
    // anything above PID 1 in state Z — means the process table is NOT
    // provably clean. Like the D-state process that surfaces as umount-EBUSY,
    // this must FAIL the unmount (Response::err → transport-error class) so
    // the sandlot destroys the microVM instead of handing it to the next
    // tenant: exclusive ownership admits no unclearable residue, and reuse is
    // the cheap path, not the correct one. In a healthy guest the set is
    // empty — every child and reparented orphan is waited for by the warden's
    // registry, and the drains above have already run. Bounded re-drain first:
    // a process killed moments ago may still be exiting.
    //
    // The gate also covers 'D': the umount-EBUSY probe only fires
    // while a task holds a path under /mnt/rootfs, so a task SIGKILLed by the
    // sweep but still parked in uninterruptible sleep without such a path
    // would otherwise ride into the next tenant's VM. The same bounded
    // re-drain gives a just-killed park its wakeup window before the gate
    // fails the unmount (see stat_line_is_unclean for the kernel-thread
    // exemption and why this cannot false-fire on the warden itself).
    //
    // PID-1 gated for the same reason as the sweep: unit tests run this
    // function on the host, whose /proc may legitimately hold unrelated
    // zombies and D-state tasks (unrelated kernel I/O parks). The predicate
    // itself is unit-tested directly with synthetic stat lines.
    if std::process::id() == 1 {
        let mut unclean: Vec<i32> = Vec::new();
        for attempt in 0..10 {
            loop {
                if matches!(
                    crate::signal::reap_zombie(libc::WNOHANG | libc::__WALL),
                    crate::signal::Reaped::Nothing
                ) {
                    break;
                }
            }
            // A failed /proc scan is FATAL: the gate exists to prove
            // the tenant is gone, and "unreadable" is not "clean".
            // The sweep's kernel-thread pids are passed in as HINTS only:
            // EVERY pid is read and judged fresh (a pid is not an identity —
            // a kernel thread can exit and its pid be recycled to a userspace
            // task, so a pid-only exemption would be a fail-open).
            unclean = match unclean_pids(&sweep_kthreads) {
                Ok(v) => v,
                Err(e) => {
                    return Err(anyhow!(
                        "guest cleanliness scan could not read /proc ({}): refusing to reuse this VM",
                        e
                    ))
                }
            };
            if unclean.is_empty() {
                break;
            }
            if attempt < 9 {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        if !unclean.is_empty() {
            return Err(anyhow!(
                "guest not clean at unmount: live or zombie process(es) {:?} — \
                 refusing to reuse this VM; the sandlot must destroy it \
                 (exclusive-ownership invariant)",
                unclean
            ));
        }
    }
    Ok(())
}
