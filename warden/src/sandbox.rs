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
// Sandswap warden — minimal sandbox state.
// The warden is a pure chroot executor. The only state the live path
// (main + raw_server) touches is the logger, the VM-shutdown oneshot
// sender, and the rtnetlink handle (for guest eth0 setup).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use slog::Logger;
use tokio::sync::Mutex;

use crate::exec_cgroup::AgentCgroup;
use crate::netlink::Handle;

/// Status of a background exec, tracked in the registry for status_exec/kill_exec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BgStatus {
    /// Shell spawned, not yet observed exited (liveness checked via kill(-pgid,0)).
    Running,
    /// Agent explicitly killed via kill_exec.
    Killed,
}

/// A tracked background exec. Registered at start_exec, looked up by exec_id
/// for status_exec/kill_exec. The shell is reaped by the warden subreaper
/// (signal.rs) on natural exit — the registry does NOT track exit code (the
/// reaper would have to write back, coupling it to the registry and racing
/// with kill_exec). Liveness is probed as kill(-pgid,0) PLUS an identity
/// check against `started_at` (exec.rs BgGroupProbe): a pgid recycled by
/// PID wraparound must not misreport a dead exec as running, nor be killed.
#[derive(Clone)]
pub struct BgExec {
    pub pgid: i32,
    pub log_path: String,
    pub status: BgStatus,
    pub started_at: Instant,
    /// The mount generation this exec was spawned under (Sandbox::
    /// mount_generation at spawn). status/kill refuse an entry whose
    /// generation has been superseded: the exec_id names a process group and
    /// a log from a PREVIOUS tenant's mount, so it must not resolve across
    /// the switch even if registry bookkeeping slipped.
    pub mount_generation: u64,
}

/// Process-global mount gate: readers = in-flight sync execs / file ops (ops
/// that touch the mounted workspace); writers = mount_workspace and
/// unmount_workspace. Historically the warden relied on the sandlot's per-VM
/// execMu for all of this — with parallel slot connections the warden must
/// guard itself:
///   - an unmount (write) waits for all in-flight execs (readers) before
///     cgroup.kill, so a concurrent teardown can never kill a running sync
///     exec;
///   - concurrent cold-start MOUNT_AND_EXECs (parallel slot connections
///     racing the same cold mount) serialize on the write guard; the second
///     one sees mount_active and skips the redundant mount instead of
///     stacking a second bind over the first;
///   - the warm-path mount_active check is done INSIDE the read guard,
///     closing the check→exec TOCTOU window against a concurrent unmount.
///
/// A process global (like WAIT_PID_LOCKER) rather than a Sandbox field: there
/// is exactly one warden per VM, and a global can be taken without holding
/// the sandbox mutex. Lock ordering: MOUNT_GATE → sandbox lock (never the
/// reverse).
pub static MOUNT_GATE: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// Warden sandbox state — only the fields the live path touches.
pub struct Sandbox {
    pub logger: Logger,
    /// rtnetlink handle for guest network (eth0) configuration at boot.
    pub rtnl: Handle,
    /// Per-agent cgroup, created LAZILY by the first background exec (the
    /// cgroup's only consumer: memory cap + cgroup.kill clearing), taken and
    /// removed at unmount_workspace. Sync-only mounts never create one (the
    /// cgroupfs mkdir + memory.max write costs ms inside a KVM microVM and
    /// sync execs do not join the cgroup). None until the first background
    /// exec, or if cgroups are unavailable. Holds the AgentCgroup alive for
    /// the agent's lease.
    pub agent_cgroup: Option<AgentCgroup>,
    /// Whether a SandFS is currently mounted in this VM. Set true on a
    /// successful mount_workspace, false on unmount_workspace. This is the
    /// authoritative "is there a live mount?" signal for the warden countdown:
    /// the countdown only powers off the VM when a mount is still live (not
    /// unmounted) — a clean/unmounted VM must survive so the sandlot can reuse
    /// it. Independent of agent_cgroup (which can be None even with a live
    /// mount if cgroups are unavailable, and vice versa).
    pub mount_active: bool,
    /// Monotonic mount generation: incremented on every mount-state
    /// transition (a successful mount, a successful unmount). Background
    /// execs record the generation they were spawned under, and
    /// status/kill resolve an exec_id only within the CURRENT generation —
    /// a stale id from a previous mount must never reach that mount's
    /// process group or log.
    pub mount_generation: u64,
    /// Identity (basename of the host device_path, e.g. "sf-a51f3c2d9e..." —
    /// the seed-derived name, never the sandfs id) of the
    /// volume CURRENTLY mounted at /mnt/rootfs. Cleared together with
    /// mount_active at unmount, so at any moment it only ever names the
    /// CURRENT agent's own volume — never another agent's. This is the
    /// exclusive-ownership identity check: a mount request naming a DIFFERENT
    /// volume while one is mounted means warden state was twisted out-of-band
    /// (a peer holding the VM's session key), and the
    /// mount path self-heals (unmount stale + mount requested) instead of
    /// dedup-skipping — a skip would run the new agent's exec inside the OLD
    /// agent's rootfs. See ensure_mounted_once.
    pub mounted_volume: Option<String>,
    /// Whether /mnt/rootfs is KNOWN to carry no leftover child mounts from a
    /// previous attach: true on VM start and after a fully-successful
    /// unmount_workspace, false from the moment a mount is dispatched (a
    /// partial mount_workspace failure can leave sub-mounts behind). When true,
    /// the mount path skips its defensive try_umount sweeps — each probe is a
    /// path walk through virtio-fs (one FUSE round trip). Conservative: any
    /// uncertainty keeps the full sweep, so the idempotent/self-healing mount
    /// contract is unchanged.
    pub mounts_clean: bool,
    /// Whether a FAILED mount may have left a partial stack behind. Set when
    /// mount_workspace fails after it may have established a bind (and the
    /// best-effort teardown could not prove the tree clean); cleared only by
    /// a verified teardown. The forced/re-adopt path ignores mount_active and
    /// tears down whenever this is set, and the cold-mount self-heal treats it
    /// like an active mount — otherwise a partial stack would either be
    /// stacked over or silently reused, breaking the one-SandFS-per-VM
    /// invariant.
    pub mount_dirty: bool,
    /// Background exec registry: exec_id → BgExec. Used by status_exec/kill_exec
    /// to map an agent's exec_id to its process group + log path. Cleared at
    /// unmount (the agent's processes are killed via cgroup.kill regardless).
    pub bg_execs: Arc<Mutex<HashMap<String, BgExec>>>,
    /// Last time sandlot sent a heartbeat (OP_MEM_STATS). This is the anchor of
    /// the warden single countdown: ONLY heartbeats reset it;
    /// business RPCs (mount/exec/unmount/file) deliberately do NOT. The sandlot
    /// stops heartbeating at T_tolerance, so a mount still live at
    /// T_tolerance + T_warden exits the VM (last-resort mount release).
    pub last_heartbeat: Instant,
}

impl Sandbox {
    pub fn new(logger: &Logger) -> Result<Self> {
        let logger = logger.new(o!("subsystem" => "sandbox"));
        Ok(Sandbox {
            logger,
            rtnl: Handle::new()?,
            agent_cgroup: None,
            mount_active: false,
            mount_generation: 0,
            mounted_volume: None,
            mounts_clean: true,
            mount_dirty: false,
            bg_execs: Arc::new(Mutex::new(HashMap::new())),
            last_heartbeat: Instant::now(),
        })
    }
}
