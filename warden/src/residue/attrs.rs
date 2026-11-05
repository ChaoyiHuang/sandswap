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

//! Warden task-attribute snapshot/restore: nice, CPU affinity and
//! scheduling policy are same-uid retunable by the agent and outlive the
//! tenant switch; the warden rewrites them from a boot-time snapshot.

use std::fs;

// ── Warden task-attribute restore (cross-tenant PID-1 interference) ──────
//
// The agent and the warden share uid/gid 0. Linux's same-owner checks let a
// same-uid caller retune ANOTHER task with no capability at all: lower a
// target's rlimits (only raising the hard limit needs CAP_SYS_RESOURCE),
// raise its nice value (`set_one_prio`), or change its CPU affinity and
// scheduling policy (`check_same_owner`). Those properties are per-task
// kernel state and survive process death — exactly the residue class the
// switch must clear, or tenant A can make tenant B's mounts fail (a tiny
// RLIMIT_NOFILE), starve the warden (nice 19 / one CPU), or kill PID 1
// outright (a tiny RLIMIT_CPU hard limit forces a group exit, which PID-1
// signal immunity does not stop).
//
// The seccomp filter's self-target guard leaves refuse every non-self target
// for the attribute syscalls (seccomp::PID1_GUARDED), which covers PID 1 and
// also its worker threads (their tids are just "not self" to classic BPF).
// Signals are a different class: PID 1's protection there is the kernel's
// global-init immunity (default-action signals are ignored and
// SIGKILL/SIGSTOP are undeliverable), with the filter additionally refusing
// the addressed target (args[0] == 1). What the filter cannot cover is state
// already planted through a path it does not see; this restore is the second
// layer: the warden snapshots its own attributes at boot (before any agent
// runs) and rewrites them for every thread of PID 1 at unmount, after the
// rule-A sweep has killed every agent process. O(threads × 3 syscalls) on the
// cold path only.

#[derive(Clone)]
pub(crate) struct WardenAttrs {
    pub(crate) nice: i32,
    pub(crate) affinity: libc::cpu_set_t,
    pub(crate) affinity_valid: bool,
    pub(crate) policy: i32,
}

// The static-musl libc's sched_getscheduler/sched_setscheduler wrappers
// return -1/ENOSYS in this build (measured in-guest: the identical raw
// syscall returns 0; glibc peers succeed), while some host test sandboxes
// filter the raw syscall with ENOSYS and leave the libc wrapper working.
// Try the raw syscall first, then fall back to the libc wrapper: the guest
// gets the kernel truth, the host tests keep running.
unsafe fn sched_getaffinity_compat(
    pid: libc::pid_t,
    size: usize,
    set: *mut libc::cpu_set_t,
) -> libc::c_int {
    let rc = libc::syscall(
        libc::SYS_sched_getaffinity,
        pid as libc::c_long,
        size as libc::c_long,
        set,
    ) as libc::c_int;
    if rc == 0 {
        0
    } else {
        libc::sched_getaffinity(pid, size, set)
    }
}

unsafe fn sched_setaffinity_compat(
    pid: libc::pid_t,
    size: usize,
    set: *const libc::cpu_set_t,
) -> libc::c_int {
    let rc = libc::syscall(
        libc::SYS_sched_setaffinity,
        pid as libc::c_long,
        size as libc::c_long,
        set,
    ) as libc::c_int;
    if rc == 0 {
        0
    } else {
        libc::sched_setaffinity(pid, size, set)
    }
}

unsafe fn sched_getscheduler_compat(pid: libc::pid_t) -> libc::c_int {
    let rc = libc::syscall(libc::SYS_sched_getscheduler, pid as libc::c_long) as libc::c_int;
    if rc >= 0 {
        rc
    } else {
        libc::sched_getscheduler(pid)
    }
}

unsafe fn sched_setscheduler_compat(
    pid: libc::pid_t,
    policy: libc::c_int,
    param: *const libc::sched_param,
) -> libc::c_int {
    let rc = libc::syscall(
        libc::SYS_sched_setscheduler,
        pid as libc::c_long,
        policy as libc::c_long,
        param,
    ) as libc::c_int;
    if rc == 0 {
        0
    } else {
        libc::sched_setscheduler(pid, policy, param)
    }
}

impl WardenAttrs {
    pub(crate) fn capture_self() -> WardenAttrs {
        let nice_raw = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            sched_getaffinity_compat(
                0,
                std::mem::size_of::<libc::cpu_set_t>(),
                &mut set as *mut libc::cpu_set_t,
            )
        };
        let policy_raw = unsafe { sched_getscheduler_compat(0) };
        // Both libc wrappers return -1 on error AND -1 is a legal nice value,
        // so validate the range rather than the sign alone. A captured -1
        // policy was the measured 0/N cause: sched_setscheduler(tid, -1, ...)
        // fails for every tid at unmount. SCHED_OTHER/nice 0 are the boot
        // defaults; the fallback restores those instead of poisoning every
        // restore call.
        let nice = if (-20..=19).contains(&nice_raw) {
            nice_raw
        } else {
            libc::SCHED_OTHER // 0 == the default nice as well
        };
        let policy = if policy_raw < 0 {
            libc::SCHED_OTHER
        } else {
            policy_raw
        };
        WardenAttrs {
            nice,
            affinity: set,
            // A failed snapshot must be skipped, never applied as a zero mask.
            affinity_valid: rc == 0,
            policy,
        }
    }
}

static WARDEN_ATTRS: std::sync::OnceLock<WardenAttrs> = std::sync::OnceLock::new();

/// Boot-time rlimit snapshot. rlimits live in the shared `signal_struct`, so a
/// same-uid caller can lower them on any worker tid and the value survives the
/// tenant switch. The seccomp filter now admits only self-target
/// `prlimit64`, but the restore is the second layer (and covers a future gap
/// in that filter).
// The rlimit resource parameter is c_uint on glibc and c_int on musl; the
// libc crate's internal alias is not re-exported. The warden ships musl, the
// host unit tests compile glibc.
#[cfg(target_env = "gnu")]
type RlimitResource = libc::c_uint;
#[cfg(target_env = "musl")]
type RlimitResource = libc::c_int;

static WARDEN_RLIMITS: std::sync::OnceLock<Vec<(RlimitResource, libc::rlimit)>> =
    std::sync::OnceLock::new();

fn capture_rlimits() -> Vec<(RlimitResource, libc::rlimit)> {
    const RESOURCES: &[RlimitResource] = &[
        libc::RLIMIT_CPU,
        libc::RLIMIT_FSIZE,
        libc::RLIMIT_DATA,
        libc::RLIMIT_STACK,
        libc::RLIMIT_CORE,
        libc::RLIMIT_RSS,
        libc::RLIMIT_NPROC,
        libc::RLIMIT_NOFILE,
        libc::RLIMIT_MEMLOCK,
        libc::RLIMIT_AS,
    ];
    let mut out = Vec::with_capacity(RESOURCES.len());
    for &r in RESOURCES {
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(r, &mut lim) } == 0 {
            out.push((r, lim));
        }
    }
    out
}

fn restore_rlimits() -> (usize, usize) {
    let Some(list) = WARDEN_RLIMITS.get() else {
        return (0, 0);
    };
    let mut ok = 0usize;
    for (r, lim) in list.iter() {
        if unsafe { libc::setrlimit(*r, lim as *const libc::rlimit) } == 0 {
            ok += 1;
        }
    }
    (ok, list.len())
}

/// Snapshot the warden's own scheduling/limit attributes BEFORE any agent can
/// run. Called once at boot (PID 1 only); a no-op on a second call.
pub fn init_warden_attrs() {
    WARDEN_ATTRS.get_or_init(WardenAttrs::capture_self);
    WARDEN_RLIMITS.get_or_init(capture_rlimits);
}

/// Restore `attrs` on each tid. Extracted so the root-gated tests can drive
/// it against the test process's own thread without touching PID 1.
pub(crate) fn restore_attrs_for_tids(attrs: &WardenAttrs, tids: &[i32]) -> usize {
    let mut restored = 0usize;
    let param: libc::sched_param = unsafe { std::mem::zeroed() };
    let mut first_fail: Option<(i32, &'static str, i32)> = None;
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    for &tid in tids {
        let mut ok = true;
        // Affinity: skip an unset (failed) snapshot instead of applying an
        // empty mask.
        if attrs.affinity_valid {
            if unsafe {
                sched_setaffinity_compat(
                    tid,
                    std::mem::size_of::<libc::cpu_set_t>(),
                    &attrs.affinity as *const libc::cpu_set_t,
                )
            } != 0
            {
                ok = false;
                if first_fail.is_none() {
                    first_fail = Some((tid, "sched_setaffinity", errno()));
                }
            }
        }
        if unsafe {
            sched_setscheduler_compat(tid, attrs.policy, &param as *const libc::sched_param)
        } != 0
        {
            ok = false;
            if first_fail.is_none() {
                first_fail = Some((tid, "sched_setscheduler", errno()));
            }
        }
        if unsafe { libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, attrs.nice) } != 0 {
            ok = false;
            if first_fail.is_none() {
                first_fail = Some((tid, "setpriority", errno()));
            }
        }
        if ok {
            restored += 1;
        }
    }
    if let Some((tid, call, e)) = first_fail {
        // Security-relevant detail (the caller logs the aggregate count):
        // which syscall failed, its errno, and the captured values make a
        // regression diagnosable from the guest console without a rebuild.
        slog_scope::warn!(
            "warden attribute restore first failure: tid={} call={} errno={} (policy={} nice={} affinity_valid={})",
            tid,
            call,
            e,
            attrs.policy,
            attrs.nice,
            attrs.affinity_valid
        );
    }
    restored
}

/// Rewrite the warden's own nice/affinity/policy on every thread of PID 1.
/// PID-1 gated (like the rule-A sweep): unit tests run this code on a host
/// where touching PID 1 would be catastrophic.
pub(crate) fn restore_warden_attrs() {
    if std::process::id() != 1 {
        return;
    }
    // rlimits are process-wide (signal_struct): restore them first so the
    // per-thread nice/affinity restore is not itself blocked by a lowered
    // RLIMIT_NICE.
    let (limits_ok, limits_total) = restore_rlimits();
    if limits_ok < limits_total {
        slog_scope::warn!(
            "warden rlimit restore at unmount: restored {}/{} limit(s)",
            limits_ok,
            limits_total
        );
    }
    let attrs = WARDEN_ATTRS.get_or_init(WardenAttrs::capture_self);
    let mut tids: Vec<i32> = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc/1/task") {
        for entry in entries.flatten() {
            if let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            {
                tids.push(tid);
            }
        }
    }
    if tids.is_empty() {
        tids.push(0); // current thread; still better than leaving a plant
    }
    let restored = restore_attrs_for_tids(attrs, &tids);
    if restored < tids.len() {
        // Rare and security-relevant: the agent tried to retune the warden
        // and the restore could not fully undo it. Visible on purpose.
        // (The same-uid cross-task syscalls that could plant this state are
        // EPERM'd by the self-only seccomp guard; this restore is the second
        // layer.)
        slog_scope::warn!(
            "warden attribute restore at unmount: restored {}/{} thread(s)",
            restored,
            tids.len()
        );
    }
}
