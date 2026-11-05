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
//! Sandswap hardening (OOM A): per-AGENT memory cgroup + switch-time clearing.
//!
//! One cgroup per mounted agent (`memory.max` = `MemTotal ×
//! agent_mem_percent / 100`) lives across all of the agent's execs and is
//! destroyed at agent switch. If the agent blows past the cap, the cgroup OOM
//! killer kills only the agent process tree — warden (PID 1) survives.
//!
//! Only the memory controller is used (no cpuset/blkio), keeping the cold-boot
//! cost Sandswap stripped out (~45ms) off the path. cgroup v2 only: the boot
//! path (mount::boot::ensure_cgroup2) refuses to start on a v1 hierarchy,
//! because v1 has no `cgroup.kill` and cannot provide the atomic
//! agent-switch clearing guarantee. The v1 branch below therefore only runs
//! in non-booted test/dev shapes; production is v2.
//!
//! BACKGROUND execs self-migrate into the cgroup in pre_exec (see
//! exec::migrate_self_cgroup — the parent-side cross-task write cost 13-19ms
//! on some kernels); SYNC execs deliberately stay OUT of it (the migration is
//! ms-scale in-guest and sits on the exec hot path — their per-process guard
//! is the RLIMIT_AS below, their stragglers are swept at switch). At unmount,
//! `kill_and_reap` writes `cgroup.kill` to atomically SIGKILL the whole tree,
//! then polls `cgroup.procs` empty. All operations are best-effort: on any
//! failure the exec still runs (just without the cap), since correctness of
//! execution outranks it.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Detect cgroup v2 by checking `/sys/fs/cgroup/cgroup.controllers`.
pub fn is_cgroup_v2() -> bool {
    fs::metadata("/sys/fs/cgroup/cgroup.controllers").is_ok()
}

// ── Sync-exec per-process memory cap (RLIMIT_AS) ──────────────────────
//
// Sync execs do NOT join the per-agent cgroup: a cgroup v2 task migration is
// ms-scale inside the microVM and sits on the exec hot
// path. Their per-exec balloon guard is instead a setrlimit(RLIMIT_AS) in
// pre_exec — one syscall, inherited by the whole child tree. Same knob and
// same value formula as the cgroup cap: MemTotal × agent_mem_percent / 100
// (compute_mem_limit).
//
// Parallelism semantics (deliberate): RLIMIT_AS bounds EACH PROCESS, not the
// aggregate — `exec_slots` parallel sync execs can together reach
// slots × cap before the guest OOM killer intervenes. Prorating the cap by
// slot count was rejected: RLIMIT_AS counts address space, and legitimate
// heavy runtimes (Python, JVM) map far more VA than RSS, so a prorated cap
// breaks them outright. The aggregate overrun is self-contained: one SandFS
// per VM means the agent only OOMs its own VM, warden (PID 1) is
// OOM-killer-exempt, and the fixed VM memory bounds the platform impact.
// Per-process cap + fixed VM RAM is strictly stronger than no cap.
//
// Frozen once at boot (MemTotal is fixed for the VM's lifetime); pre_exec
// reads it with a plain atomic load — async-signal-safe, zero allocation.
static SYNC_RLIMIT_AS_CAP: AtomicU64 = AtomicU64::new(0);

/// Compute and freeze the sync-exec RLIMIT_AS from the agent config. Called
/// once at boot after /proc is mounted. Always logs the outcome — the cap's
/// visibility contract matches the cgroup path's (degradation is never
/// silent).
pub fn init_sync_rlimit_cap() {
    let pct = crate::AGENT_CONFIG.agent_mem_percent;
    let cap = match read_mem_total_bytes() {
        Some(total) => compute_mem_limit(total, pct),
        None => 0,
    };
    if cap > 0 {
        slog_scope::info!(
            "sync exec RLIMIT_AS cap = {} MiB ({}% of MemTotal)",
            cap / (1024 * 1024),
            pct
        );
    } else {
        slog_scope::info!(
            "sync exec RLIMIT_AS cap disabled (agent_mem_percent=0 or MemTotal unreadable)"
        );
    }
    SYNC_RLIMIT_AS_CAP.store(cap, Ordering::Release);
}

/// The frozen per-exec RLIMIT_AS in bytes; 0 = uncapped. Async-signal-safe
/// read (plain atomic load) for use inside pre_exec.
pub fn sync_rlimit_as() -> u64 {
    SYNC_RLIMIT_AS_CAP.load(Ordering::Acquire)
}

/// Test-only setter for the frozen cap (root-gated exec tests pin it to a
/// known value and must restore 0 afterwards).
#[cfg(test)]
pub fn set_sync_rlimit_as_for_tests(v: u64) {
    SYNC_RLIMIT_AS_CAP.store(v, Ordering::Release);
}

// ── Agent-visible tmpfs size cap (/dev/shm; /tmp in overlay mode) ─────
//
// tmpfs pages are UNRECLAIMABLE guest memory. Without a size cap, a sync
// exec filling tmpfs walks the guest toward the OOM corner where every
// eligible victim (agent processes only — warden/PID 1 is OOM-exempt) is
// already dead but the tmpfs pages remain: the end state is a VM-killing
// OOM storm/panic. RLIMIT_AS cannot prevent this (tmpfs writes consume no
// writer address space), and the bg cgroup only covers bg writers. With a
// per-mount size cap the failure degrades to ENOSPC at the writer — a
// normal, per-command error. Two independent mounts each get the SAME cap.
//
// Value: explicit warden.tmpfs_size_mb. When unset (0), the AUTO default is
// MemTotal/4 (the documented default): each agent-visible tmpfs gets a
// quarter of guest RAM, so a fill degrades to ENOSPC long before the
// unreclaimable pages can walk the guest into the OOM corner. The kernel's
// own per-mount default (50% of RAM) applies only when MemTotal is
// unreadable. Operators override with warden.tmpfs_size_mb. Frozen once at
// boot.
static TMPFS_SIZE_BYTES: AtomicU64 = AtomicU64::new(0);

/// Host MemTotal in bytes, read once. 0 when /proc/meminfo is unreadable.
fn mem_total_bytes() -> u64 {
    static MEM: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *MEM.get_or_init(|| {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    let rest = l.strip_prefix("MemTotal:")?;
                    let kb: u64 = rest.trim().split_whitespace().next()?.parse().ok()?;
                    Some(kb.saturating_mul(1024))
                })
            })
            .unwrap_or(0)
    })
}

/// Pure resolver: explicit MiB → bytes; 0 → auto (MemTotal/4); 0 total (an
/// unreadable /proc/meminfo) → no size option, leaving the kernel default.
/// Extracted for unit testing.
fn resolve_tmpfs_size_with(explicit_mb: u64, mem_total: u64) -> u64 {
    if explicit_mb > 0 {
        return explicit_mb.saturating_mul(1024 * 1024);
    }
    mem_total / 4
}

fn resolve_tmpfs_size(explicit_mb: u64) -> u64 {
    resolve_tmpfs_size_with(explicit_mb, mem_total_bytes())
}

/// Compute and freeze the tmpfs per-mount size cap. Called once at boot.
/// Always logs the outcome (degradation is never silent).
pub fn init_tmpfs_size() {
    let explicit_mb = crate::AGENT_CONFIG.tmpfs_size_mb as u64;
    let cap = resolve_tmpfs_size(explicit_mb);
    if cap > 0 {
        slog_scope::info!(
            "tmpfs per-mount size cap = {} MiB ({})",
            cap / (1024 * 1024),
            if explicit_mb > 0 {
                "warden.tmpfs_size_mb"
            } else {
                "auto: MemTotal/4"
            }
        );
    } else {
        slog_scope::info!(
            "tmpfs mounts use the kernel default size (50% of RAM) — MemTotal is unreadable and warden.tmpfs_size_mb is unset"
        );
    }
    TMPFS_SIZE_BYTES.store(cap, Ordering::Release);
}

/// The mount-option fragment for the frozen tmpfs cap: `",size=Nk"` to
/// append to a tmpfs mount's options, or "" when the cap is disabled.
pub fn tmpfs_size_opt() -> String {
    let cap = TMPFS_SIZE_BYTES.load(Ordering::Acquire);
    if cap == 0 {
        String::new()
    } else {
        format!(",size={}k", cap / 1024)
    }
}

/// Test-only setter, mirroring set_sync_rlimit_as_for_tests.
#[cfg(test)]
pub fn set_tmpfs_size_for_tests(v: u64) {
    TMPFS_SIZE_BYTES.store(v, Ordering::Release);
}

/// Parse a meminfo value (in kB) from the content of /proc/meminfo.
/// Returns the value in bytes (kB × 1024).
fn parse_meminfo_value(content: &str, key: &str) -> Option<u64> {
    let prefix = format!("{}:", key);
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Read MemTotal (bytes) from /proc/meminfo once.
pub fn read_mem_total_bytes() -> Option<u64> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo_value(&content, "MemTotal")
}

/// Read MemAvailable (bytes) from /proc/meminfo. Used by the OOM-B reclaim
/// threshold: sandlot polls this and the gateway recreates the VM when it drops
/// below max(MemTotal × pct, abs).
pub fn read_mem_available_bytes() -> Option<u64> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo_value(&content, "MemAvailable")
}

/// A per-AGENT cgroup (lives across all of an agent's execs, destroyed at agent
/// switch). It serves two purposes:
///   1. Memory cap (memory.max = MemTotal × pct/100) for the whole agent
///      process tree — if the agent blows the cap, the cgroup OOM killer kills
///      only the agent group, warden (PID 1) survives.
///   2. Agent-switch clearing: at unmount, `kill_and_reap` writes cgroup.kill
///      (v2) to atomically SIGKILL every process in the group, then polls
///      cgroup.procs until empty — guaranteeing no agent process outlives the
///      exec (hard isolation invariant: the next agent's mount is clean).
///
/// This replaces the former per-exec ExecMemCgroup. Per-agent is strictly
/// better: one cgroup.create per agent (not per exec) saves warm-path µs, and
/// one cgroup.kill at switch time (not kill(-pgid) per exec) lets background
/// processes (`nohup &`) survive across exec calls within the same agent's
/// lease — they are only killed when the agent switches.
pub struct AgentCgroup {
    pub path: PathBuf,
    pub v2: bool,
}

impl AgentCgroup {
    /// Create a per-agent cgroup named `name` (typically the VM/mount id).
    /// When `pct > 0`, sets memory.max = mem_total × pct/100; when `pct == 0`,
    /// the memory cap is skipped but the cgroup is still created so that
    /// cgroup.kill remains available for agent-switch process clearing.
    /// Returns Ok(None) only if the cgroup directory itself cannot be created
    /// (e.g. cgroup2 not mounted, kernel without CONFIG_CGROUPS).
    pub fn create(name: &str, mem_total_bytes: u64, pct: u32) -> io::Result<Option<Self>> {
        let v2 = is_cgroup_v2();
        let path = if v2 {
            PathBuf::from(format!("/sys/fs/cgroup/sandswap-agent-{}", name))
        } else {
            PathBuf::from(format!("/sys/fs/cgroup/memory/sandswap-agent-{}", name))
        };

        // mkdir the cgroup dir.
        match fs::create_dir(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                // Can't create cgroup (e.g. cgroup2 not mounted, EACCES,
                // ENOSPC). Best-effort: run without a cap rather than failing
                // the exec — but NEVER silently: without the cgroup the agent
                // loses both the memory cap and the cgroup.kill agent-switch
                // clearing (the fallback kill path only covers registered
                // bg-exec pgids).
                slog_scope::error!(
                    "agent cgroup: cannot create {} ({}) — agent runs WITHOUT memory cap and cgroup.kill clearing",
                    path.display(),
                    e
                );
                return Ok(None);
            }
        }

        // Set the memory limit (only when pct > 0 and the computed limit is
        // nonzero). When pct == 0 the operator explicitly disabled the memory
        // cap, but the cgroup is still created for cgroup.kill-based clearing.
        let limit = compute_mem_limit(mem_total_bytes, pct);
        if limit > 0 {
            let limit_str = limit.to_string();
            let set_ok = if v2 {
                fs::write(path.join("memory.max"), limit_str.as_bytes()).is_ok()
            } else {
                fs::write(path.join("memory.limit_in_bytes"), limit_str.as_bytes()).is_ok()
            };
            if !set_ok {
                // Can't set memory limit, but the cgroup still works for
                // cgroup.kill (agent-switch clearing). Log and continue —
                // don't destroy the cgroup just because memory.max failed.
                slog_scope::warn!(
                    "agent cgroup: failed to set memory.max (cgroup still usable for kill); path={}",
                    path.display()
                );
            }
        }

        Ok(Some(AgentCgroup { path, v2 }))
    }

    /// The cgroup's filesystem path (for registry/logging).
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Kill every process in this cgroup and poll until `cgroup.procs` is empty
    /// or `timeout` elapses. This is the agent-switch clearing primitive.
    ///
    /// v2: write "1" to `cgroup.kill` — the kernel recursively SIGKILLs the
    ///     whole cgroup tree atomically (O(1), no per-pid iteration).
    /// v1: read `cgroup.procs`, kill each pid, poll (v1 has no cgroup.kill).
    ///
    /// On timeout (e.g. a D-state process stuck in uninterruptible I/O), we
    /// log and return — the caller proceeds to umount. If umount also fails
    /// with EBUSY (the D-state process still holds files open), the warden
    /// returns an error, causing the gateway to destroy the VM entirely.
    /// This guarantees the exclusive-ownership invariant: one microVM = one
    /// SandFS at a time. The destroyed VM's resources are released by the
    /// kernel, killing the D-state process along with it.
    pub fn kill_and_reap(&self, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        if self.v2 {
            // Atomic recursive kill. Writing "1" to cgroup.kill synchronously
            // kills all processes in the cgroup; they are reaped by the warden
            // subreaper (signal.rs) as they exit.
            let _ = fs::write(self.path.join("cgroup.kill"), b"1");
        } else {
            // v1 fallback: kill each pid individually.
            if let Ok(procs) = fs::read_to_string(self.path.join("cgroup.procs")) {
                for line in procs.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        unsafe {
                            let _ = libc::kill(pid, libc::SIGKILL);
                        }
                    }
                }
            }
        }
        // Poll cgroup.procs until empty (all processes reaped) or timeout.
        while std::time::Instant::now() < deadline {
            match fs::read_to_string(self.path.join("cgroup.procs")) {
                Ok(s) if s.trim().is_empty() => return,
                Ok(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                Err(_) => return, // cgroup gone — nothing to reap
            }
        }
        slog_scope::warn!(
            "agent cgroup kill_and_reap: procs not empty after {:?} \
             (D-state process? increase warden.cgroup_clear_timeout to allow more time); \
             proceeding to umount — if EBUSY, the gateway will destroy the VM \
             to maintain exclusive-ownership invariant",
            timeout
        );
    }
}

impl Drop for AgentCgroup {
    fn drop(&mut self) {
        // Remove the cgroup dir. On v2/v1 the dir is removed once empty; by
        // drop time kill_and_reap has cleared it (or timed out). A failure
        // here leaks a cgroup dir until the VM is destroyed — visible, not
        // silent.
        if let Err(e) = fs::remove_dir(&self.path) {
            slog_scope::warn!(
                "agent cgroup: remove_dir {} failed ({}) — dir leaks until VM destruction",
                self.path.display(),
                e
            );
        }
    }
}

/// memory.max computation: MemTotal × pct / 100, saturating. 0 when pct == 0
/// (cap explicitly disabled) or mem_total == 0 (unreadable meminfo). Extracted
/// as a pure function for unit testing.
fn compute_mem_limit(mem_total_bytes: u64, pct: u32) -> u64 {
    mem_total_bytes.saturating_mul(pct as u64) / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_meminfo_value ─────────────────────────────────────────

    #[test]
    fn parse_meminfo_value_memtotal() {
        let content = "MemTotal:       261838 kB\nMemFree:         12345 kB\n";
        assert_eq!(
            parse_meminfo_value(content, "MemTotal"),
            Some(261838 * 1024)
        );
    }

    #[test]
    fn parse_meminfo_value_memavailable() {
        let content = "MemTotal:       261838 kB\nMemAvailable:   200000 kB\n";
        assert_eq!(
            parse_meminfo_value(content, "MemAvailable"),
            Some(200000 * 1024)
        );
    }

    #[test]
    fn parse_meminfo_value_missing_key() {
        let content = "MemTotal:       261838 kB\n";
        assert_eq!(parse_meminfo_value(content, "MemAvailable"), None);
    }

    #[test]
    fn parse_meminfo_value_empty_content() {
        assert_eq!(parse_meminfo_value("", "MemTotal"), None);
    }

    #[test]
    fn parse_meminfo_value_unusual_spacing() {
        // Extra whitespace between key and value.
        let content = "MemTotal:    1024 kB\n";
        assert_eq!(parse_meminfo_value(content, "MemTotal"), Some(1024 * 1024));
    }

    // ── compute_mem_limit ───────────────────────────────────────────

    #[test]
    fn compute_mem_limit_typical() {
        // 256 MiB total, 70% → 187904819 bytes (integer division truncates).
        assert_eq!(compute_mem_limit(256 * 1024 * 1024, 70), 187_904_819);
    }

    // ── resolve_tmpfs_size ──────────────────────────────────────────

    #[test]
    fn resolve_tmpfs_size_explicit_wins() {
        // The explicit value is used even when MemTotal is known.
        assert_eq!(
            resolve_tmpfs_size_with(32, 64 * 1024 * 1024 * 1024),
            32 * 1024 * 1024
        );
    }

    #[test]
    fn resolve_tmpfs_size_zero_is_auto_quarter() {
        // The documented default: 0 = auto = MemTotal/4.
        assert_eq!(
            resolve_tmpfs_size_with(0, 4 * 1024 * 1024 * 1024),
            1024 * 1024 * 1024
        );
        // Unknowable MemTotal falls back to the kernel default (no option).
        assert_eq!(resolve_tmpfs_size_with(0, 0), 0);
    }

    #[test]
    fn resolve_tmpfs_size_saturates() {
        assert_eq!(resolve_tmpfs_size_with(u64::MAX, 0), u64::MAX);
    }

    #[test]
    fn tmpfs_size_opt_fragment() {
        set_tmpfs_size_for_tests(4 * 1024 * 1024);
        assert_eq!(tmpfs_size_opt(), ",size=4096k");
        set_tmpfs_size_for_tests(0);
        assert_eq!(tmpfs_size_opt(), "");
    }

    #[test]
    fn compute_mem_limit_pct_zero_is_zero() {
        assert_eq!(compute_mem_limit(256 * 1024 * 1024, 0), 0);
    }

    #[test]
    fn compute_mem_limit_zero_total_is_zero() {
        assert_eq!(compute_mem_limit(0, 70), 0);
    }

    #[test]
    fn compute_mem_limit_saturates_without_wrap() {
        // The saturating_mul guard exists so an absurd meminfo value cannot
        // WRAP to a small limit (which would silently cap the agent at ~0).
        // MAX×100 saturates to MAX, then /100 → MAX/100 (still huge). A
        // wrapping mul would instead produce a small, garbage limit.
        assert_eq!(compute_mem_limit(u64::MAX, 100), u64::MAX / 100);
        assert_eq!(compute_mem_limit(u64::MAX, 70), u64::MAX / 100);
    }

    #[test]
    fn compute_mem_limit_rounding_truncates() {
        // Integer division truncates toward zero.
        assert_eq!(compute_mem_limit(1000, 33), 330);
        assert_eq!(compute_mem_limit(999, 50), 499);
    }

    // ── AgentCgroup::create edge cases ──────────────────────────────

    /// euid of the test process — the create() outcomes differ between
    /// privileged (can mkdir under /sys/fs/cgroup) and unprivileged runs.
    fn running_as_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn agent_cgroup_create_pct_zero_returns_some() {
        // pct == 0 disables the memory cap, but the cgroup is still created
        // so cgroup.kill is available for agent-switch clearing. Under root
        // this MUST be Some; unprivileged CI can only observe the Ok(None)
        // degradation path (mkdir EACCES).
        let result = AgentCgroup::create("warden-test-pct0", 1024 * 1024 * 256, 0).unwrap();
        if running_as_root() {
            let cg = result.expect("root: cgroup must be created even with pct=0");
            // No memory.max set (pct==0): the file exists on cgroup2 with
            // "max" (default) — the create path skipped writing it.
            let _ = fs::remove_dir(&cg.path);
        } else {
            assert!(result.is_none(), "unprivileged: mkdir must fail → Ok(None)");
        }
    }

    #[test]
    fn agent_cgroup_create_zero_mem_total_no_early_return() {
        // mem_total_bytes == 0 → computed limit 0 → no memory.max written,
        // but the cgroup dir is still created for cgroup.kill: create must
        // NOT early-return on the zero limit. Under root this returns
        // Some(...) with no cap; unprivileged CI observes Ok(None) from the
        // mkdir failure — either way the Ok variant, never Err.
        let result = AgentCgroup::create("warden-test-zero-total", 0, 70).unwrap();
        if running_as_root() {
            let cg = result.expect("root: cgroup must be created despite mem_total=0");
            let _ = fs::remove_dir(&cg.path);
        } else {
            assert!(result.is_none());
        }
    }
}
