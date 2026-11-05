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
// Sandswap warden — chrooted exec implementation.
// raw_server.rs (the raw vsock transport) calls do_exec. do_exec spawns
// /bin/sh -c <command> chrooted into /mnt/rootfs with setsid + capability-drop
// + deny-list seccomp, waits for the exit status via the reaper registry
// (signal.rs), and returns raw stdout/stderr bytes + exit code. The wait runs
// WITHOUT the reaper lock, so concurrent sync execs (parallel slot
// connections) each wait on their own child through the registry.

use std::ffi::CString;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::ExitStatus;
use std::time::Instant;

use anyhow::{anyhow, Result};
use nix::fcntl::OFlag;
use nix::poll::{PollFd, PollFlags};
use slog::{debug, error, warn};

use crate::sandbox::{BgExec, BgStatus};
use crate::AGENT_CONFIG;

/// Execution security profile — determines capability and seccomp policy.
///
/// **Strict** (default): drops ALL capabilities from the bounding set + full
/// 78-syscall seccomp deny list (docs/how-it-works/syscall-surface.md). The agent process runs as uid=0 with zero
/// kernel capabilities — the strongest isolation, but package managers cannot
/// work (dpkg needs CAP_CHOWN/CAP_SETUID/CAP_SETGID/etc.).
///
/// **Install**: retains 10 minimal capabilities — Docker's default set minus
/// CAP_NET_RAW/CAP_SETFCAP/CAP_SYS_CHROOT (design) and CAP_SETPCAP/CAP_MKNOD
/// (owner ruling; the exact list is INSTALL_CAPS below) — via the
/// ambient capability mechanism (Linux 4.3+), while keeping PR_SET_NO_NEW_PRIVS
/// and the **identical** 78-syscall seccomp deny list. The ambient caps survive
/// execve() even under NO_NEW_PRIVS, enabling apt-get/dpkg to function.
/// Security rationale:
///   - mount/unshare/setns/bpf stay in seccomp deny list (defense-in-depth
///     independent of capability checks)
///   - NO_NEW_PRIVS prevents suid binary exploitation
///   - CAP_SYS_ADMIN/CAP_SYS_PTRACE/CAP_SYS_RAWIO/CAP_SYS_BOOT etc. remain dropped
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecProfile {
    /// Default: all capabilities dropped, maximum isolation.
    Strict,
    /// Package installation: 10 ambient capabilities retained for dpkg/apt-get.
    Install,
}

/// Capabilities retained in Install profile.
///
/// These match Docker's default 14-capability set, minus five that are
/// unnecessary or risky in the Sandswap chroot:
///   - CAP_NET_RAW (can sniff network traffic in guest)
///   - CAP_SETFCAP (can set file capabilities for persistence)
///   - CAP_SYS_CHROOT (already chrooted; escape risk if first chroot is broken)
///   - CAP_SETPCAP (owner ruling: dpkg/
///     apt/npm never need it — only capsh/setpriv-style self-reconfiguration;
///     file-cap setting is SETFCAP, which was already absent, so setcap-style
///     packages are unchanged)
///   - CAP_MKNOD (same ruling: no Debian/Ubuntu main package creates device
///     nodes in postinst — devices belong to udev/devtmpfs, managed here by
///     the warden; guest-created nodes were already inert through the
///     nosuid,nodev volumes mounts, so this only removes the ability to
///     create them at all)
///
/// Kept (the package-install core — owner ruling: trimming must not limit
/// apt/dpkg/npm in practice):
///   0  CAP_CHOWN           — chown file ownership (dpkg)
///   1  CAP_DAC_OVERRIDE    — bypass file permission checks (dpkg)
///   2  CAP_DAC_READ_SEARCH — bypass directory read/search (dpkg)
///   3  CAP_FOWNER          — modify files you don't own (dpkg)
///   4  CAP_FSETID          — preserve setuid/setgid bits (dpkg)
///   5  CAP_KILL            — send signals (process management)
///   6  CAP_SETGID          — setgroups/initgroups (dpkg/adduser)
///   7  CAP_SETUID          — seteuid/setuid (dpkg/adduser)
///   10 CAP_NET_BIND_SERVICE — bind privileged ports (some service packages)
///   29 CAP_AUDIT_WRITE     — write audit records (dbus, systemd-logger)
const INSTALL_CAPS: &[i32] = &[0, 1, 2, 3, 4, 5, 6, 7, 10, 29];

/// Map the wire's install_packages flag to the execution security profile.
/// Extracted as a pure function so the mapping is unit-testable.
pub(crate) fn profile_for(install_packages: bool) -> ExecProfile {
    if install_packages {
        ExecProfile::Install
    } else {
        ExecProfile::Strict
    }
}

/// Set at warden boot (PID 1 only): the parent's capability bounding set was
/// successfully pre-dropped to the INSTALL_CAPS baseline. The bounding set is
/// inherited across fork, so every exec child then starts from exactly those
/// baseline caps (INSTALL_CAPS) and the pre_exec sweep shrinks from ~40+
/// PR_CAPBSET_DROP prctls to 10 (Strict) or 0 (Install) — identical end state on execve, fewer syscalls
/// on the hot path. When false (boot pre-drop failed, or a non-init run such
/// as the test process, whose bounding set must not be mutated), children fall
/// back to the full sweep below.
static PARENT_CAP_BASELINE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The kernel's last capability index, read once from
/// /proc/sys/kernel/cap_last_cap (40 on current kernels). Bounds the fallback
/// PR_CAPBSET_DROP sweep instead of the old hardcoded 0..=63 — everything past
/// the last cap is a guaranteed-EINVAL syscall the child paid for on every
/// exec. Falls back to 63 when unreadable: the sweep then self-terminates on
/// EINVAL exactly as before.
fn cap_last_cap() -> i32 {
    static LAST: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *LAST.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .filter(|&v| (0..=63).contains(&v))
            .unwrap_or(63)
    })
}

/// Pre-drop the calling process's bounding set to the INSTALL_CAPS baseline.
/// Called once at warden boot (PID 1). Returns true only when EVERY non-
/// baseline cap was dropped — any failure leaves an over-wide baseline and the
/// children keep the conservative full sweep (never a weaker guarantee).
pub(crate) fn predrop_parent_bounding_set() -> bool {
    for cap in 0..=cap_last_cap() {
        if INSTALL_CAPS.contains(&cap) {
            continue;
        }
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc < 0 {
            return false;
        }
    }
    PARENT_CAP_BASELINE.store(true, std::sync::atomic::Ordering::Relaxed);
    true
}

/// Environment variables applied to every chrooted exec via Command::env (the
/// envp of the execve — constructed BEFORE fork, so nothing here runs between
/// fork and exec). They guide pip/npm/cargo/go to install into /home/agent,
/// which is a writable bind mount of the SandFS volume's storage and persists
/// across node migrations.
///
/// NOTE: these MUST stay on Command::env and NOT on setenv() inside pre_exec.
/// setenv allocates (malloc) and is not async-signal-safe; calling it between
/// fork and exec of a multithreaded process can deadlock the child if another
/// thread held the allocator lock at fork time.
fn apply_exec_env(cmd: &mut std::process::Command) {
    // env_clear FIRST: the agent must inherit EXACTLY the set below, nothing
    // of the warden's own environment (RUST_BACKTRACE, the kernel's init
    // HOME/TERM, and any WARDEN_*/MAX_* env-config channel a deployment may
    // have set). Clearing a PID-1-sized env is a handful of map removals
    // before fork — nothing measurable on the exec path.
    cmd.env_clear()
        .env("HOME", "/home/agent")
        .env(
            "PATH",
            "/home/agent/.local/bin:/home/agent/bin:/home/agent/.npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("PYTHONUSERBASE", "/home/agent/.local")
        .env("npm_config_prefix", "/home/agent/.npm-global")
        .env("CARGO_HOME", "/home/agent/.cargo")
        .env("GOPATH", "/home/agent/go");
}

/// Result of a chrooted exec: raw stdout/stderr bytes + exit code.
///
/// stdout/stderr are `Vec<u8>` (not `String`) so the raw vsock server writes
/// them straight into the response frame body with no copy. `exit_code` is a
/// `u8`: POSIX process exit codes are 0–255 (`WEXITSTATUS` is 8-bit) and
/// signal-death uses the shell convention `128 + signum` (max 128+64=192), so
/// a single byte covers the whole range with no sentinel leaking into it.
pub(crate) struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: u8,
}

/// The outcome of a sync exec: either the command ran to completion (normal
/// exit or signal death, both carried as a real exit code in `Done`), or it
/// exceeded the timeout (`TimedOut`, carrying whatever output was drained
/// before the kill). Replaces the former `exit_code: -5` timed-out sentinel:
/// the transport layer (raw_server) matches on the variant to set the wire
/// `code` field, so no magic value can collide with a real exit code.
pub(crate) enum ExecOutcome {
    Done(ExecResult),
    TimedOut(ExecResult),
}

/// Derive the exit code from a child's `ExitStatus`.
///
/// A process that exited normally yields its exit code (0–255). A process
/// killed by a signal yields the shell convention `128 + signum` (SIGKILL →
/// 137, SIGSEGV → 139). Both fit in a `u8`. If the status carries neither a
/// code nor a signal (does not happen on Linux for a reaped child) we return
/// 0 — the wire `code` field, not the exit code, is what distinguishes a
/// transport error now, so exit_code never needs a negative sentinel.
pub(crate) fn exit_code_from(status: &ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return code as u8;
    }
    if let Some(sig) = status.signal() {
        return (128 + sig) as u8;
    }
    0
}

/// Child-side self-migration into the per-agent cgroup (pre_exec, raw
/// syscalls only — async-signal-safe).
///
/// The parent used to write the child's pid into cgroup.procs right after
/// spawn, but a cross-task migration blocks on the target task reaching a
/// safe point (kernel task_call) — measured 13-19ms per exec on some kernels.
/// Self-migration runs in the child's own context (already at a safe point),
/// costs microseconds, and removes the write from the parent's hot path
/// entirely.
///
/// MUST run before chroot() — after chroot the absolute /sys/fs/cgroup path
/// is unreachable.
unsafe fn migrate_self_cgroup(procs_path: Option<&std::ffi::CStr>) {
    let Some(path) = procs_path else { return };
    let fd = libc::open(path.as_ptr(), libc::O_WRONLY);
    if fd >= 0 {
        let pid = libc::getpid();
        // Manual decimal itoa into a stack buffer (no allocation after fork).
        let mut tmp = [0u8; 16];
        let mut i = 0usize;
        let mut v = pid as u64;
        if v == 0 {
            tmp[0] = b'0';
            i = 1;
        } else {
            while v > 0 {
                tmp[i] = b'0' + (v % 10) as u8;
                v /= 10;
                i += 1;
            }
        }
        let mut buf = [0u8; 17];
        let mut n = 0usize;
        while i > 0 {
            i -= 1;
            buf[n] = tmp[i];
            n += 1;
        }
        buf[n] = b'\n';
        n += 1;
        libc::write(fd, buf.as_ptr() as *const libc::c_void, n);
        libc::close(fd);
    }
}

/// Apply the chroot + security profile in pre_exec (after fork, before exec).
///
/// This function is called inside the `pre_exec` closure of a `Command`. It
/// runs between fork and exec — only async-signal-safe calls are permitted
/// (no allocation, no std::io, no panics). All CStrings are built OUTSIDE
/// the closure and passed in (no-allocation-after-fork principle).
///
/// Sequence:
///   1. setsid()         — session + process group leader (isolation)
///   2. chroot() + chdir — restrict filesystem access
///   3. PR_SET_NO_NEW_PRIVS — block suid/cap re-acquisition
///   4. Capability setup (profile-dependent):
///      - Strict: PR_CAPBSET_DROP all 64 caps (bounding set = empty)
///      - Install: PR_CAPBSET_DROP all except INSTALL_CAPS → capset(inheritable=baseline)
///        → PR_CAP_AMBIENT_RAISE for each baseline cap
///   5. Install seccomp deny-list filter (identical deny list for both profiles;
///      see seccomp.rs DENY_SYSCALLS — the count is pinned by the filter-shape test)
///
/// All operations use raw libc syscalls — async-signal-safe.
unsafe fn apply_exec_profile(
    root_cstr: &std::ffi::CStr,
    workdir_cstr: &std::ffi::CStr,
    seccomp_filter: &[libc::sock_filter],
    profile: ExecProfile,
    cg_procs_cstr: Option<&std::ffi::CStr>,
) -> std::io::Result<()> {
    // Close every inherited descriptor at exec time. CLOSE_RANGE_CLOEXEC
    // (NOT CLOSE_RANGE_UNSHARE, and not an immediate close) marks the CURRENT
    // set CLOEXEC: the exec itself closes them, Rust's Command
    // error-reporting pipe keeps working until execve (so a failed execve is
    // still reported as Err, not a silent success), and the cgroup fd opened
    // below is created after the sweep. This makes fd leaks (a pidfd, a
    // future non-CLOEXEC open) structurally unable to reach agent code.
    //
    // FAIL CLOSED on error: an fd the sweep could not mark would leak into
    // the agent — exactly the guarantee this call exists for. ENOSYS is not
    // special-cased: every guest kernel sandswap ships has close_range
    // (5.9+); a kernel without it must not silently run agents with
    // inherited host-side descriptors.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            /* CLOSE_RANGE_CLOEXEC */ 4u32,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Self-migrate into the per-agent cgroup FIRST — before chroot makes the
    // cgroupfs path unreachable (see migrate_self_cgroup for why the child,
    // not the parent, does this).
    migrate_self_cgroup(cg_procs_cstr);
    // become a new session + process-group leader (pgid = pid).
    if libc::setsid() < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Per-process memory cap (RLIMIT_AS): sync execs do not join the agent
    // cgroup (in-guest migration is ms-scale), so this is their balloon
    // guard — one raw syscall, inherited by the whole child tree. Applied
    // before chroot/seccomp/cap-drop so nothing can block it. Best-effort:
    // lowering an address-space limit on a fresh fork cannot fail in
    // practice, and a hardening miss must not kill the exec (the frozen
    // value's visibility is the boot-time init_sync_rlimit_cap log line).
    // Aggregate semantics under parallel sync execs: see
    // exec_cgroup::SYNC_RLIMIT_AS_CAP's doc comment.
    let cap_as = crate::exec_cgroup::sync_rlimit_as();
    if cap_as > 0 {
        let rl = libc::rlimit {
            rlim_cur: cap_as,
            rlim_max: cap_as,
        };
        let _ = libc::setrlimit(libc::RLIMIT_AS, &rl);
    }
    // Chroot into the agent rootfs.
    if libc::chroot(root_cstr.as_ptr()) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if libc::chdir(workdir_cstr.as_ptr()) != 0 {
        // /workspace may not exist in old rootfs templates; fall back to /
        if libc::chdir(c"/".as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // (Exec environment variables — HOME/PATH/PYTHONUSERBASE/etc. — are set
    // via Command::env BEFORE fork; see apply_exec_env for why they must not
    // be setenv'd here.)

    // No new privileges: suid binaries cannot raise caps.
    crate::seccomp::set_no_new_privs()?;

    match profile {
        ExecProfile::Strict => {
            if PARENT_CAP_BASELINE.load(std::sync::atomic::Ordering::Relaxed) {
                // Boot pre-drop left exactly the 10 INSTALL_CAPS in the
                // inherited bounding set: drop just those to reach empty.
                for &cap in INSTALL_CAPS {
                    let _ = libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
                }
            } else {
                // Full sweep (no boot pre-drop): drop the entire bounding set.
                // EINVAL on an index beyond the kernel's last cap means we're
                // done; other errors are best-effort ignored (the empty
                // bounding set is the win).
                for cap in 0..=cap_last_cap() {
                    let rc = libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
                    if rc < 0 {
                        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        if e == libc::EINVAL {
                            break;
                        }
                        // best-effort: keep dropping the rest
                    }
                }
            }
        }
        ExecProfile::Install => {
            if !PARENT_CAP_BASELINE.load(std::sync::atomic::Ordering::Relaxed) {
                // No boot pre-drop: drop all capabilities from the bounding
                // set EXCEPT the 10 we need for package installation. The
                // bounding set constrains what can be in the
                // permitted/inheritable sets after exec.
                let retain: std::collections::HashSet<i32> = INSTALL_CAPS.iter().copied().collect();
                for cap in 0..=cap_last_cap() {
                    if retain.contains(&cap) {
                        continue; // keep this one in the bounding set
                    }
                    let rc = libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
                    if rc < 0 {
                        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        if e == libc::EINVAL {
                            break;
                        }
                    }
                }
            }
            // With the pre-drop the bounding set is already exactly the 10
            // retained caps — nothing to drop here.

            // Set effective/permitted/inheritable to the 10 retained caps
            // via capset(). This uses raw libc::syscall (async-signal-safe)
            // rather than the capctl crate (which allocates Error objects).
            let mut bits0: u32 = 0; // caps 0-31
            let mut bits1: u32 = 0; // caps 32-63
            for &cap in INSTALL_CAPS {
                if cap < 32 {
                    bits0 |= 1u32 << cap;
                } else {
                    bits1 |= 1u32 << (cap - 32);
                }
            }
            // struct cap_user_header_t { version: u32, pid: i32 }
            // struct cap_user_data_t  { effective: u32, permitted: u32, inheritable: u32 }
            // We use version 3 (LINUX_CAPABILITY_VERSION_3 = 0x20080522)
            // which requires an array of 2 cap_user_data_t entries.
            #[repr(C)]
            struct CapUserHeader {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            struct CapUserData {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = CapUserHeader {
                version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
                pid: 0,               // current thread
            };
            let data = [
                CapUserData {
                    effective: bits0,
                    permitted: bits0,
                    inheritable: bits0,
                },
                CapUserData {
                    effective: bits1,
                    permitted: bits1,
                    inheritable: bits1,
                },
            ];
            let rc = libc::syscall(
                libc::SYS_capset,
                &header as *const CapUserHeader as *const libc::c_void,
                data.as_ptr() as *const libc::c_void,
            );
            if rc < 0 {
                // capset failed — best-effort: continue without ambient caps.
                // Package installation may fail, but the seccomp filter
                // still provides the core isolation guarantee.
            } else {
                // Raise each retained cap in the ambient set.
                // PR_CAP_AMBIENT = 47, PR_CAP_AMBIENT_RAISE = 1.
                // Ambient caps are automatically added to permitted and
                // effective after execve(), even with NO_NEW_PRIVS.
                // This is the key mechanism that makes package installation
                // work under NO_NEW_PRIVS.
                for &cap in INSTALL_CAPS {
                    let _ = libc::prctl(47, 1, cap as libc::c_ulong, 0, 0);
                }
            }
        }
    }

    // Install the deny-list seccomp filter (identical for both profiles).
    // This is the defense-in-depth layer: even if capability checks are
    // somehow bypassed, mount/unshare/setns/bpf etc. are still EPERM'd.
    crate::seccomp::install(seccomp_filter)?;
    Ok(())
}

/// Reap straggler processes left in a command's process group after the shell
/// has exited or been killed. Sync exec is one-shot: any children the shell
/// spawned (even with `&`) are cleaned up here so they cannot leak into the
/// next agent's mount namespace. Background persistence uses `start_exec`
/// instead, whose group is only cleared at agent switch.
///
/// Reaping goes through the central reap_one (signal.rs): our group's
/// stragglers come back as orphans and are reaped here; another exec's
/// registered child is forwarded to its waiter — never stolen. The loop stops
/// when there is nothing left to reap or the `budget` elapses.
/// `tokio::time::sleep` between probes yields the async worker so concurrent
/// probes (e.g. heartbeat MemStats on a separate vsock connection) are not
/// starved — a plain busy-wait would pin the worker for the whole budget.
async fn reap_stragglers(pgid: i32, budget: std::time::Duration) {
    if pgid <= 0 {
        return;
    }
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        // Forwarded = another exec's registered child; keep probing for our
        // own stragglers.
        if let crate::signal::Reaped::Nothing = crate::signal::reap_one(libc::WNOHANG).await {
            break;
        }
        // Yield between probes rather than spin.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

impl AgentService {
    // do_exec is the shared chroot+spawn+wait implementation. Returns
    // (ExecResult, spawn_ms, wait_ms). pub(crate) so the raw vsock server
    // (raw_server.rs) can reuse it directly — all isolation logic
    // lives here, unchanged.
    //
    // The result carries stdout/stderr as Vec<u8> (not String) so the raw
    // vsock server can place the bytes directly into the response frame body
    // with zero intermediate copy — no Vec::new()+read_to_end() realloc churn,
    // no String::from_utf8_lossy() copy, no .into_bytes() round-trip. The pipe
    // is drained into a single pre-allocated buffer (drain_pipe), falling back
    // to grow-on-demand only if a command emits more than the inline capacity.
    // This is also more correct than the old lossy String path: binary stdout
    // (e.g. `cat` of a non-UTF-8 file) is preserved byte-for-byte.
    pub(crate) async fn do_exec(
        logger: &slog::Logger,
        command: &str,
        start: Instant,
        timeout: std::time::Duration,
        install_packages: bool,
    ) -> Result<(ExecOutcome, u128, u128)> {
        // The exec root is the fixed chroot target; parameterized internally
        // (do_exec_rooted) so the spawn/wait/timeout machinery is testable
        // against any root (tests use "/").
        let root_cstr =
            CString::new(crate::mount::MOUNT_POINT).expect("MOUNT_POINT is a valid CString");
        Self::do_exec_rooted(&root_cstr, logger, command, start, timeout, install_packages).await
    }

    // Root-parameterized core of do_exec (see do_exec). Tests call this
    // directly with "/" to exercise the spawn/wait/timeout/kill machinery
    // without a mounted agent rootfs.
    pub(crate) async fn do_exec_rooted(
        root: &std::ffi::CStr,
        logger: &slog::Logger,
        command: &str,
        start: Instant,
        timeout: std::time::Duration,
        install_packages: bool,
    ) -> Result<(ExecOutcome, u128, u128)> {
        let profile = profile_for(install_packages);
        // CStrings built OUTSIDE pre_exec closure (no allocation after fork).
        let workdir_cstr =
            CString::new(crate::mount::WORKSPACE_DIR).expect("WORKSPACE_DIR is a valid CString");
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(command)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // Env via execve envp (pre-fork); see apply_exec_env for the
        // fork-safety rationale.
        apply_exec_env(&mut cmd);
        // seccomp filter built OUTSIDE the closure (no allocation after fork).
        let seccomp_filter = crate::seccomp::deny_filter();
        let root_cstr = root.to_owned();
        // SYNC execs deliberately do NOT join the per-agent cgroup: a real
        // cgroup v2 task migration (writing the pid to cgroup.procs — whether
        // done by the parent post-spawn or self-done in pre_exec) costs 8-20ms
        // inside a KVM microVM (measured on CH v6.2 and v6.16.9 guest kernels;
        // the identical operation on the bare-metal host kernel is µs-scale),
        // which would sit directly on the exec hot path. Sync execs are
        // one-shot and are fully cleaned up by the finish-tail kill(-pgid)
        // group kill, so the loss is only the transient memory cap (the VM's
        // fixed memory size still bounds the worst case). Background execs
        // (start_exec, off the hot path and long-lived) keep the self-
        // migration for the memory cap and cgroup.kill agent-switch clearing.
        // SYNC execs deliberately do NOT join the per-agent cgroup (background
        // execs do — start_exec): a real cgroup v2 task migration costs 8-20ms
        // inside a KVM microVM (measured on CH v6.2 and v6.16.9 guest kernels;
        // µs-scale on the bare-metal host kernel), which would sit directly on
        // the exec hot path. Sync execs are one-shot and are fully cleaned up
        // by the finish-tail kill(-pgid) group kill, so the loss is only the
        // transient memory cap (the VM's fixed memory size still bounds the
        // worst case).
        unsafe {
            cmd.pre_exec(move || {
                apply_exec_profile(&root_cstr, &workdir_cstr, &seccomp_filter, profile, None)
            });
        }
        // Spawn + register under the reaper lock: the reaper must never
        // observe the child before it is registered, or the wait below would
        // block on an exit status nobody delivers. The lock is released
        // immediately after registration — it is NOT held across the child
        // wait anymore, which is what allows concurrent sync execs (parallel
        // slot connections) to run while this command is in flight.
        let (exit_tx, mut exit_rx) = tokio::sync::oneshot::channel::<i32>();
        // Hardening (OOM A) lives elsewhere for sync execs: the per-process
        // RLIMIT_AS frozen at boot (apply_exec_profile) and the per-agent
        // cgroup (memory cap + cgroup.kill clearing) that only BACKGROUND
        // execs join — see the comment above for why sync execs stay out of
        // the cgroup on this path.
        let max_out = AGENT_CONFIG.max_output_bytes;
        let spawn_start = Instant::now();
        let (mut child, pgid, spawn_ms) = {
            let _reaper_lock = crate::signal::lock_reaper();
            let child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    error!(logger, "exec_workspace spawn failed: {:?}", e);
                    return Err(anyhow!("exec_workspace spawn failed: {}", e));
                }
            };
            let spawn_ms = spawn_start.elapsed().as_millis();
            // the shell's pid == its pgid (it is the session leader). Capture it
            // for timeout-kill and for adding to the agent cgroup.
            let pgid = child.id() as i32;
            crate::signal::register_exit_waiter(pgid, exit_tx);
            (child, pgid, spawn_ms)
        };

        // warden is PID 1 / a subreaper: the SIGCHLD handler reaps ANY child
        // via the central waitpid(-1) (signal.rs reap_one) and forwards
        // registered exits to their waiters. The wait below runs WITHOUT the
        // reaper lock, so concurrent execs each wait on their own child
        // through the registry.
        //
        // The pipe drains start NOW, concurrently with the child — NOT after
        // the exit status arrives. A child whose output exceeds the ~64 KiB
        // pipe capacity blocks on write() until someone reads; draining only
        // after exit would deadlock it until the exec timeout. The drain keeps
        // reading past the output cap (discarding), so the child always
        // finishes and the response carries capped output + a real exit code.
        // Pre-allocated buffer + byte-true Vec<u8> on the blocking pool,
        // handed straight to the response frame.
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        // The Child handle is dead weight now: the registry owns exit-status
        // delivery and the pipes are already taken. Child::drop neither kills
        // nor reaps, so dropping here is safe.
        drop(child);
        // ONE fused drain task serves both pipes (poll(2)-multiplexed): the
        // old pair of spawn_blocking tasks cost two blocking-pool thread
        // dispatches per exec on the guest's 1-2 vCPUs.
        let drains = DrainPair::spawn(stdout, stderr, max_out);
        let wait_start = Instant::now();

        // Preferred wait channel: pidfd (direct epoll wakeup — no SIGCHLD
        // signal-task hop chain, ~1ms less wakeup latency per exec; opt out
        // with `warden.pidfd=0` on the guest cmdline). The spawn-time
        // registry oneshot stays registered as the status source of record —
        // see resolve_exit for how the two channels cooperate (an earlier
        // waitid-only version raced the central reaper into intermittent
        // ECHILD exec failures, surfacing as gateway 503 SANDBOX_CLEANING
        // bursts). There is no double-wait race: a pidfd keeps the
        // task_struct alive, so waitid(P_PIDFD) is authoritative even after
        // the reaper has reaped the zombie; when the pidfd path resolves the
        // exit, cancel_exit_waiter below simply drops the unused oneshot.
        let mut pidfd = if crate::exec::pidfd_enabled() {
            open_pidfd(pgid)
        } else {
            None
        };

        // Wait for the shell to exit, bounded by the command timeout. On
        // timeout, kill(-pgid) the whole group + reap, and return a timed_out
        // result. This is the ONLY command-level timeout: SO_RCVTIMEO on the
        // sandlot side is transport-liveness only, so long commands are no
        // longer mis-killed by the transport.
        //
        // On normal exit (shell returned), we also kill(-pgid) the whole group
        // and reap stragglers. Sync exec is a one-shot command — any child
        // processes it spawned (even with `&`) are cleaned up here. Agents that
        // need a persistent background process should use the dedicated
        // start_exec API instead (OP_ASYNC_EXEC), which does NOT kill the group
        // on return.
        if timeout.is_zero() {
            let raw = match resolve_exit(&mut pidfd, &mut exit_rx).await {
                Some(raw) => raw,
                None => {
                    // Both channels lost (should not happen: registration and
                    // spawn share the reaper lock). Last resort: direct
                    // blocking waitpid on our own pid.
                    crate::signal::cancel_exit_waiter(pgid);
                    let status = direct_wait_pid(pgid).await?;
                    return finish_sync_exec(
                        logger, pgid, &status, drains, start, spawn_ms, wait_start,
                    )
                    .await;
                }
            };
            if pidfd.is_some() {
                crate::signal::cancel_exit_waiter(pgid);
            }
            let status = status_from_raw(raw);
            return finish_sync_exec(logger, pgid, &status, drains, start, spawn_ms, wait_start)
                .await;
        }

        let mut pidfd_mut = pidfd.take();
        let mut exit_rx_mut = exit_rx;
        match tokio::time::timeout(timeout, resolve_exit(&mut pidfd_mut, &mut exit_rx_mut)).await {
            Ok(Some(raw)) => {
                if pidfd_mut.is_some() {
                    crate::signal::cancel_exit_waiter(pgid);
                }
                let status = status_from_raw(raw);
                finish_sync_exec(logger, pgid, &status, drains, start, spawn_ms, wait_start).await
            }
            Ok(None) => {
                // pidfd errored mid-wait or the registry oneshot was dropped
                // without a status — recover with a direct waitpid.
                crate::signal::cancel_exit_waiter(pgid);
                let status = direct_wait_pid(pgid).await?;
                finish_sync_exec(logger, pgid, &status, drains, start, spawn_ms, wait_start).await
            }
            Err(_elapsed) => {
                // Timeout: kill the whole group, then bounded-wait for the
                // exit so the killed shell is observed and reaped
                // before we return.
                if pgid > 0 {
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGKILL);
                    }
                }
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    resolve_exit(&mut pidfd_mut, &mut exit_rx_mut),
                )
                .await;
                // Brief reap window so the killed group doesn't leak.
                reap_stragglers(pgid, std::time::Duration::from_millis(500)).await;
                let wait_ms = wait_start.elapsed().as_millis();
                // The group is dead — the drain hits EOF immediately. A
                // D-state writer would block the drain; the bounded collect
                // detaches it (partial output only).
                let ((out, out_trunc), (err, err_trunc)) =
                    drains.collect(std::time::Duration::from_millis(500)).await;
                // debug level: a timeout and its truncation are per-op
                // outcomes the agent can trigger in a loop; at info/warn they
                // flood the serial console and crowd the log channel. The
                // response itself (CODE_TIMED_OUT) carries the outcome.
                if out_trunc || err_trunc {
                    debug!(logger, "exec_workspace timed out, output truncated");
                }
                debug!(
                    logger,
                    "exec_workspace timed out after {}ms (spawn={}ms)", wait_ms, spawn_ms
                );
                Ok((
                    ExecOutcome::TimedOut(ExecResult {
                        stdout: out,
                        stderr: err,
                        exit_code: 0,
                    }),
                    spawn_ms,
                    wait_ms,
                ))
            }
        }
    }
}

/// Rebuild an ExitStatus from a raw waitpid status word delivered by the
/// reaper registry. Safety: the word comes from libc::waitpid on our own
/// child, which is exactly what from_raw expects.
fn status_from_raw(raw: i32) -> ExitStatus {
    ExitStatus::from_raw(raw)
}

/// Fallback: blocking waitpid on a specific pid. Only used if the registry
/// wait is ever lost (the spawn+register critical section makes that
/// effectively impossible). Runs in spawn_blocking so it does not pin an
/// async worker.
async fn direct_wait_pid(pid: i32) -> Result<ExitStatus> {
    tokio::task::spawn_blocking(move || {
        let mut status: i32 = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            Ok(status_from_raw(status))
        } else {
            Err(anyhow!("waitpid({}) failed: rc={}", pid, rc))
        }
    })
    .await
    .map_err(|e| anyhow!("exec_workspace wait join failed: {}", e))?
}

/// pidfd wait is ON by default; opt out with `warden.pidfd=0` on the guest
/// cmdline (or WARDEN_PIDFD=0 in a test process — guests have no env).
pub(crate) fn pidfd_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        if let Ok(v) = std::env::var("WARDEN_PIDFD") {
            return v != "0";
        }
        !std::fs::read_to_string("/proc/cmdline")
            .map(|c| c.contains("warden.pidfd=0"))
            .unwrap_or(false)
    })
}

/// P_PIDFD for waitid(2): not exported by the libc crate on all targets.
const P_PIDFD: u32 = 3;

/// Open a pidfd for the just-spawned child (kernel ≥ 5.3). Ok(None) means
/// pidfd is unavailable on this kernel — callers fall back to the SIGCHLD
/// registry path.
fn open_pidfd(pid: i32) -> Option<tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>> {
    let fd =
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) } as libc::c_int;
    if fd < 0 {
        return None;
    }
    // The pidfd is parent-side state: every concurrent agent child forked
    // while it exists must NOT inherit it (a leaked pidfd is another exec's
    // liveness oracle, and future rule changes could make it actionable).
    // Set CLOEXEC immediately, before the fd can be observed by a fork.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        unsafe { libc::close(fd) };
        return None;
    }
    // OwnedFd (NOT RawFd): AsyncFd never closes the inner fd itself — closing
    // is the owned type's job on drop. With a bare i32 every exec leaked one
    // pidfd (60 execs → +60 fds), eventually wedging warden's io.
    use std::os::unix::io::FromRawFd;
    let owned = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) };
    tokio::io::unix::AsyncFd::with_interest(owned, tokio::io::Interest::READABLE).ok()
}

/// Wait for the child's exit through its pidfd: the kernel marks the fd
/// readable on exit, waking the waiting task DIRECTLY from epoll — no
/// SIGCHLD handler → signal-driver task → registry oneshot hop chain
/// (measured ~1ms of pure wakeup latency per exec inside a microVM).
/// Returns the raw wait status word (same encoding as waitpid's wstatus).
///
/// A pidfd holds a reference to the task_struct, so waitid(P_PIDFD) still
/// returns the correct exit status even if the central SIGCHLD reaper has
/// already reaped the zombie — no race with signal.rs.
async fn wait_child_pidfd(
    pfd: &mut tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
) -> Result<i32, std::io::Error> {
    use std::os::unix::io::AsRawFd;
    let fd = pfd.as_raw_fd();
    loop {
        let mut guard = pfd.readable().await?;
        // WNOHANG + si_pid check guards against spurious readiness; POLLIN on
        // a pidfd always means a waitable state in practice.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc =
            unsafe { libc::waitid(P_PIDFD, fd as u32, &mut info, libc::WEXITED | libc::WNOHANG) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { info.si_pid() } == 0 {
            guard.clear_ready();
            continue; // spurious wakeup — wait for the next readiness
        }
        // Rebuild the waitpid-style status word from siginfo.
        let code = info.si_code;
        let val = unsafe { info.si_status() } as i32;
        let wstatus = match code {
            libc::CLD_EXITED => val << 8,
            libc::CLD_KILLED | libc::CLD_DUMPED => val,
            _ => 0,
        };
        return Ok(wstatus);
    }
}

/// Resolve the child's raw wait status, unifying both wait channels:
/// the pidfd is the WAKEUP source (direct epoll readiness — no SIGCHLD
/// signal-task hop chain), while the registry oneshot is the STATUS source of
/// record. They race by design: if the central SIGCHLD reaper reaps the child
/// first, waitid(P_PIDFD) fails with ECHILD — and that same reap has already
/// forwarded the status into exit_rx, so the oneshot holds the answer.
/// A bare waitid-only path turned that race into intermittent exec failures
/// (ECHILD → Err → gateway 503 SANDBOX_CLEANING bursts).
async fn resolve_exit(
    pidfd: &mut Option<tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>>,
    exit_rx: &mut tokio::sync::oneshot::Receiver<i32>,
) -> Option<i32> {
    match pidfd {
        Some(pfd) => match wait_child_pidfd(pfd).await {
            Ok(raw) => Some(raw),
            Err(_) => (&mut *exit_rx).await.ok(),
        },
        None => wait_child_exit(exit_rx).await,
    }
}

/// Wait for a registered child's exit. Primary channel: the oneshot the
/// reaper registry resolves when it reaps the pid. Fallback: a periodic
/// WNOHANG reap probe — if a SIGCHLD notification were ever lost, reap_one
/// reaps and forwards, resolving the oneshot anyway. Returns None only if
/// the sender was dropped without sending (registry entry cancelled — should
/// not happen while the wait is in flight).
async fn wait_child_exit(rx: &mut tokio::sync::oneshot::Receiver<i32>) -> Option<i32> {
    let mut fallback = tokio::time::interval(std::time::Duration::from_secs(2));
    fallback.tick().await; // skip the immediate first tick
    loop {
        tokio::select! {
            res = &mut *rx => {
                match res {
                    Ok(raw) => return Some(raw),
                    Err(_) => return None,
                }
            }
            _ = fallback.tick() => {
                let _ = crate::signal::reap_one(libc::WNOHANG).await;
            }
        }
    }
}

/// Common tail of a completed sync exec: kill any remaining processes in the
/// group (e.g. `sleep 60 &` without nohup), reap stragglers, collect the
/// concurrently-drained pipes, and pack the Done result. The drain was
/// spawned at fork time (see do_exec_rooted); by now the shell has exited and
/// the group kill below closes any straggler-held write ends, so the collect
/// hits EOF immediately in the normal case. The kept output is capped at
/// max_out bytes per stream (the drain discards beyond it, see drain_pipe).
async fn finish_sync_exec(
    logger: &slog::Logger,
    pgid: i32,
    status: &ExitStatus,
    drains: DrainPair,
    start: Instant,
    spawn_ms: u128,
    wait_start: Instant,
) -> Result<(ExecOutcome, u128, u128)> {
    let wait_ms = wait_start.elapsed().as_millis();
    if pgid > 0 {
        unsafe {
            let _ = libc::kill(-pgid, libc::SIGKILL);
        }
        reap_stragglers(pgid, std::time::Duration::from_millis(200)).await;
    }
    // Both pipes are at EOF by now (the shell exited, the group kill closed
    // any straggler-held write ends), so the single fused drain's collect
    // returns immediately in the normal case.
    let ((out, out_trunc), (err, err_trunc)) =
        drains.collect(std::time::Duration::from_secs(2)).await;
    let exit_code = exit_code_from(status);
    // debug level: output truncation is the per-exec output cap doing its job
    // and is agent-triggerable on every call; the response carries the
    // truncated (or complete) output, so an info/warn line here only floods
    // the console.
    if out_trunc || err_trunc {
        debug!(
            logger,
            "exec_workspace output truncated (out_trunc={} err_trunc={})", out_trunc, err_trunc
        );
    }
    // debug level: per-op timing summary (fires every sync exec). The raw
    // server's op wrapper logs its own copy; at info these two lines kept the
    // console drain busy through back-to-back exec windows. warden.log=debug
    // restores it for profiling sessions.
    debug!(
        logger,
        "exec_workspace done in {}ms (spawn={}ms wait={}ms exit={})",
        start.elapsed().as_millis(),
        spawn_ms,
        wait_ms,
        exit_code
    );
    Ok((
        ExecOutcome::Done(ExecResult {
            stdout: out,
            stderr: err,
            exit_code,
        }),
        spawn_ms,
        wait_ms,
    ))
}

// AgentService exists only as an impl owner for do_exec. raw_server.rs calls
// do_exec as an associated function. This empty marker struct keeps the
// `impl AgentService` block valid.
pub(crate) struct AgentService;

/// Build a chrooted, setsid'd, seccomp+cap-dropped `/bin/sh -c command` with
/// caller-supplied stdout/stderr targets. Used by start_exec (background) to
/// hand the child the write end of the warden-side log relay pipe via
/// inherited fds (Stdio::from(pipe write end)). do_exec (sync) builds its own
/// Command directly with piped stdio so it can drain stdout/stderr into the
/// response.
/// Returns the spawned child + its pgid (== shell pid, since setsid makes it a
/// session leader). The caller decides whether to wait (sync) or not (background).
fn spawn_chrooted_with(
    command: &str,
    profile: ExecProfile,
    stdout: std::process::Stdio,
    stderr: std::process::Stdio,
    cg_procs_cstr: Option<CString>,
) -> Result<std::process::Child> {
    let root_cstr =
        std::ffi::CString::new(crate::mount::MOUNT_POINT).expect("MOUNT_POINT is a valid CString");
    let workdir_cstr =
        std::ffi::CString::new(crate::mount::WORKSPACE_DIR).expect("WORKSPACE_DIR is a valid CString");
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    // Same exec env as the sync path (pre-fork envp, see apply_exec_env).
    apply_exec_env(&mut cmd);
    let seccomp_filter = crate::seccomp::deny_filter();
    unsafe {
        cmd.pre_exec(move || {
            apply_exec_profile(
                &root_cstr,
                &workdir_cstr,
                &seccomp_filter,
                profile,
                cg_procs_cstr.as_deref(),
            )
        });
    }
    cmd.spawn().map_err(|e| anyhow!("spawn chrooted: {}", e))
}

/// Start a background exec: spawn the command chrooted, relay its stdout and
/// stderr through ONE pipe into a warden-side log file (NOT inside the agent
/// rootfs), register it under a new exec_id, and return immediately (do NOT
/// wait). The shell is reaped by the warden subreaper (signal.rs) on natural
/// exit; status_exec reports liveness via kill(-pgid,0). The pgid is added to
/// the per-agent cgroup so cgroup.kill at unmount clears it.
///
/// The log is BOUNDED BY CONSTRUCTION. The child writes to a pipe, and a
/// relay thread keeps only the last `bg_log_tail_bytes` (default `BG_LOG_KEEP`)
/// in the log file (appending while the file has room, rewriting the retained
/// tail once it does not) while discard-draining everything past that. A
/// flooding command therefore hits kernel pipe backpressure (64 KiB) instead
/// of growing a file on the RAM-backed initramfs between watchdog sweeps; the
/// periodic sweep stays as defense in depth. No RLIMIT_FSIZE is set — that
/// would also break legitimate large file writes made by the command.
///
/// The log file lives on the warden's initramfs rootfs (RAM-backed tmpfs) at
/// `/tmp/sandswap-bg/<id>.log`. It is deliberately NOT written inside the
/// chrooted `/mnt/rootfs`: in flat/bind-mount mode the whole agent directory is
/// the read-write rootfs, so a chrooted `/tmp/...` log would persist into the
/// agent's SandFS volume — polluting persistent agent storage with warden
/// bookkeeping. The pipe fd is inherited across chroot (fds are path-
/// independent), so the chrooted child writes to the warden-side relay without
/// the log path existing inside the chroot. status_exec reads the file back
/// from the warden side; the tail is returned over vsock, so the agent never
/// needs direct filesystem access to the log.
pub(crate) async fn start_exec(
    logger: &slog::Logger,
    command: &str,
    agent_cgroup_path: Option<&str>,
    bg_execs: &std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, BgExec>>>,
    install_packages: bool,
    mount_generation: u64,
) -> Result<String> {
    let exec_id = next_exec_id();

    // Warden-side log on initramfs tmpfs (RAM). create_dir_all is best-effort;
    // /tmp always exists on the initramfs rootfs and is writable by PID 1.
    let log_dir = BG_LOG_DIR;
    let _ = std::fs::create_dir_all(log_dir);
    let log_path = format!("{}/{}.log", log_dir, exec_id);
    // The relay owns the log file; open it (and fail the exec) BEFORE the
    // child exists so an unwritable log directory cannot turn into a
    // silently-untracked background command.
    let log_file =
        open_bg_log_for_relay(&log_path).map_err(|e| anyhow!("open bg log {}: {}", log_path, e))?;
    // One pipe for both streams: stdout and stderr share the log file, so the
    // relay merges them in arrival order (the same observable contract as the
    // former shared-file fd redirect). try_clone dups the write end so each
    // stdio slot owns an independent fd (Stdio::from consumes one File).
    let (pipe_r, pipe_w) =
        nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(|e| anyhow!("create bg log pipe: {}", e))?;
    // Wrap BOTH raw fds immediately (each error path below then closes them
    // through Drop, never leaking a pipe end).
    let writer = unsafe { std::fs::File::from_raw_fd(pipe_w) };
    let reader = unsafe { std::fs::File::from_raw_fd(pipe_r) };
    let stderr_writer = writer
        .try_clone()
        .map_err(|e| anyhow!("dup bg log pipe fd: {}", e))?;
    // Start the relay BEFORE spawning: if the thread cannot be created the
    // exec must fail rather than leave the child writing into a pipe nobody
    // drains (it would block forever on the first 64 KiB of output).
    spawn_bg_log_relay(reader, log_file, crate::AGENT_CONFIG.bg_log_tail_bytes)
        .map_err(|e| anyhow!("spawn bg log relay: {}", e))?;
    let stdout = std::process::Stdio::from(writer);
    let stderr = std::process::Stdio::from(stderr_writer);

    let profile = profile_for(install_packages);
    // Per-agent cgroup.procs path for the child's self-migration in pre_exec
    // (migrate_self_cgroup): the parent-side cross-task migration write cost
    // 13-19ms on some kernels; the child self-migrating is µs-scale.
    let cg_procs_cstr =
        agent_cgroup_path.and_then(|p| CString::new(format!("{}/cgroup.procs", p)).ok());
    // Spawn the ORIGINAL command (no shell-level `> log 2>&1` wrapping): the
    // redirect is done at the fd level by the inherited Stdio, so the command
    // string reaches the shell unmodified.
    let mut child = spawn_chrooted_with(command, profile, stdout, stderr, cg_procs_cstr)?;
    let pgid = child.id() as i32;
    // Detach: drop the child handle WITHOUT waiting. The subreaper reaps it on
    // exit. stdout/stderr are None (inherited pipe fds, not piped through
    // std), but take() them anyway for symmetry before dropping the handle.
    drop(child.stdout.take());
    drop(child.stderr.take());
    drop(child);

    bg_execs.lock().await.insert(
        exec_id.clone(),
        BgExec {
            pgid,
            log_path,
            status: BgStatus::Running,
            started_at: Instant::now(),
            mount_generation,
        },
    );
    // Bound the registry: natural-exited entries stay until unmount so the
    // agent can read the final log tail once, but a long-lived VM must not
    // accumulate them forever. Past the cap, evict the oldest DEAD entries
    // (and their log files); live entries are never evicted. Dead = the probe
    // sees the group gone or its id recycled (same rule as status_exec).
    const BG_REGISTRY_CAP: usize = 1024;
    {
        // Snapshot the candidates under the lock, then run the identity
        // probes (/proc/<pid>/stat reads) OUTSIDE it: the registry lock is
        // also taken by every status/kill/insert on this VM, and a
        // synchronous /proc read per registered entry must not stall them.
        let candidates: Vec<(String, i32, Instant, String)> = {
            let map = bg_execs.lock().await;
            if map.len() <= BG_REGISTRY_CAP {
                Vec::new()
            } else {
                map.iter()
                    .filter(|(_, bg)| bg.status != BgStatus::Killed)
                    .map(|(id, bg)| (id.clone(), bg.pgid, bg.started_at, bg.log_path.clone()))
                    .collect()
            }
        };
        if !candidates.is_empty() {
            let mut dead: Vec<(String, Instant, String)> = candidates
                .into_iter()
                .filter(|(_, pgid, started_at, _)| {
                    matches!(
                        probe_bg_group(*pgid, *started_at),
                        BgGroupProbe::Gone | BgGroupProbe::Recycled
                    )
                })
                .map(|(id, _, started_at, log_path)| (id, started_at, log_path))
                .collect();
            dead.sort_by_key(|(_, started, _)| *started);
            let mut map = bg_execs.lock().await;
            // Recompute the excess under the lock (concurrent inserts may
            // have grown the map while the probes ran).
            let mut excess = map.len().saturating_sub(BG_REGISTRY_CAP);
            for (id, _, log_path) in dead {
                if excess == 0 {
                    break;
                }
                // Re-check the entry is still present and still dead by the
                // cheap state we already captured; a concurrent kill_exec
                // marks Killed but never resurrects a dead group.
                if map.remove(&id).is_some() {
                    let _ = std::fs::remove_file(&log_path);
                    warn!(logger, "bg registry cap: evicted dead entry {}", id);
                    excess -= 1;
                }
            }
        }
    }
    // debug level: fires on every background exec start, and cmd={:?} prints
    // the WHOLE command (unbounded length on the UART). exec_id travels in the
    // response; profiling sessions enable it with warden.log=debug.
    debug!(
        logger,
        "start_exec: exec_id={} pgid={} cmd={:?}", exec_id, pgid, command
    );
    Ok(exec_id)
}

/// Remove the warden-side bg log files for all registered background execs.
/// Called at unmount (before the registry is cleared) so logs do not accumulate
/// across agent switches within a single VM lifetime. The logs live on initramfs
/// tmpfs and would vanish on VM destruction anyway; this is just tidy in-VM
/// hygiene. Best-effort: missing files are ignored.
pub(crate) async fn cleanup_bg_logs(
    bg_execs: &std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, BgExec>>>,
) {
    let map = bg_execs.lock().await;
    for (_, bg) in map.iter() {
        let _ = std::fs::remove_file(&bg.log_path);
    }
}

/// Probed identity of the process group recorded for a background exec.
///
/// Liveness alone (`kill(-pgid, 0)`) is NOT identity: PIDs are recycled after
/// a full `pid_max` cycle, and every warden-spawned shell is a session+group
/// leader (setsid), so a recycled pid recreates a group with the SAME id. A
/// stale registry entry (kept until unmount so the agent can read the final
/// log tail) would then misreport a long-dead exec as running — and a kill
/// aimed at it would SIGKILL the innocent new group. The probe distinguishes
/// the cases by the group leader's start time (/proc/<pgid>/stat field 22),
/// which is unique per pid-generation.
enum BgGroupProbe {
    /// `kill(-pgid, 0)` failed: no such process group — the exec is done.
    Gone,
    /// The group still has members but `/proc/<pgid>` is gone (the leader
    /// exited, orphaned group members still run). Pre-existing semantics
    /// treat this as still-running.
    Members,
    /// The group leader is the process we spawned (started no later than the
    /// recorded exec start, within measurement slack) — genuinely ours.
    Ours,
    /// The group id was recycled onto a NEW process after our exec exited
    /// (PID wraparound): the exec is dead, and killing the group would hit
    /// an unrelated (same-agent) process.
    Recycled,
}

/// Slack when comparing the leader's start time against the recorded
/// `BgExec.started_at`: /proc/uptime and Instant::now() are read at slightly
/// different instants (and CLOCK_MONOTONIC vs CLOCK_BOOTTIME can drift by
/// milliseconds). 2s is far above that noise and far below any real
/// PID-wraparound gap (a full pid_max cycle takes minutes-to-hours of
/// forking), so it can never misclassify either way in practice.
const BG_START_SLACK: std::time::Duration = std::time::Duration::from_secs(2);

/// Probe the process group of a background exec: existence + identity.
fn probe_bg_group(pgid: i32, started_at: Instant) -> BgGroupProbe {
    if pgid <= 0 {
        return BgGroupProbe::Gone;
    }
    // The LEADER first. A status/kill can arrive between spawn and the
    // child's pre_exec: the leader pid exists, but it has not called setsid
    // yet, so the process GROUP named `pgid` does not exist. Checking the
    // group first reported such a live exec as Gone (a spurious "done" on a
    // just-started background command). The leader's start time is the
    // identity: ours → running (pre- or post-setsid); newer → a recycled id.
    match proc_leader_start(pgid) {
        Some(leader_start) => {
            return if leader_start <= started_at + BG_START_SLACK {
                BgGroupProbe::Ours
            } else {
                BgGroupProbe::Recycled
            };
        }
        // Leader gone: group members may still be alive (the leader exited
        // while children kept the group).
        None => {}
    }
    if unsafe { libc::kill(-pgid, 0) } != 0 {
        return BgGroupProbe::Gone;
    }
    BgGroupProbe::Members
}

/// The process's start time as an Instant, from /proc/<pid>/stat field 22
/// (starttime, clock_t since boot) anchored against /proc/uptime. None when
/// either file is unreadable or unparseable (leader gone / non-standard
/// format) — callers treat that as "identity unknown".
// The two negated float comparisons below are deliberate NaN guards: a NaN
// uptime/ticks parse must be rejected, and `!(x >= 0.0)` is the only spelling
// that is false-safe against NaN (a plain `x < 0.0` would let NaN through).
#[allow(clippy::neg_cmp_op_on_partial_ord)]
fn proc_leader_start(pid: i32) -> Option<Instant> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // comm (field 2) can contain spaces and parens — parse everything after
    // the LAST ')'. Fields 3.. follow; starttime is field 22 → the 20th token
    // after ')' (state is field 3 = token 0, so field N = token N-3).
    let after_comm = stat.rsplit_once(')')?.1;
    let ticks: u64 = after_comm.split_whitespace().nth(19)?.parse().ok()?;
    let tps = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    if !(tps > 0.0) {
        return None;
    }
    let uptime: f64 = std::fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let age_secs = uptime - ticks as f64 / tps; // how long ago the process started
    if !(age_secs >= 0.0) {
        return None;
    }
    Some(Instant::now() - std::time::Duration::from_secs_f64(age_secs))
}

/// Whether /proc/<pid>/stat still identifies the process the registry
/// recorded: the leader's start time is no later than the recorded exec start
/// (within measurement slack). A pid that exited and was recycled by PID
/// wraparound fails this check, so a signal aimed at the old exec can never
/// hit the unrelated process now holding the id.
fn leader_start_matches(pid: i32, started_at: Instant) -> bool {
    matches!(
        proc_leader_start(pid),
        Some(leader_start) if leader_start <= started_at + BG_START_SLACK
    )
}

/// Poll a background exec: return its liveness + a tail of its log. Liveness is
/// kill(-pgid, 0) plus an IDENTITY check (see BgGroupProbe): a recycled pgid
/// after PID wraparound reports done instead of running, and never counts as
/// ours. The entry must also belong to the CURRENT mount generation — a
/// superseded generation (a prior tenant's mount) resolves as not found. The
/// exit code is NOT captured (the subreaper reaps the shell without writing
/// back to the registry — lazy design, no reaper coupling). An agent that
/// needs the exit code should have the command write `echo $?` to the log.
pub(crate) async fn status_exec(
    logger: &slog::Logger,
    exec_id: &str,
    bg_execs: &std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, BgExec>>>,
    mount_generation: u64,
) -> Result<(u8, Vec<u8>)> {
    let entry = bg_execs.lock().await.get(exec_id).cloned();
    match entry {
        None => Ok((crate::raw_server::CODE_BG_NOT_FOUND, Vec::new())),
        // An entry registered under a SUPERSEDED mount generation belongs to
        // a previous tenant's mount. It must not yield a log tail (or a
        // liveness verdict) to the current one; report it exactly as unknown.
        Some(bg) if bg.mount_generation != mount_generation => {
            debug!(
                logger,
                "status_exec: exec_id={} belongs to mount generation {} (current {}); refused",
                exec_id,
                bg.mount_generation,
                mount_generation
            );
            Ok((crate::raw_server::CODE_BG_NOT_FOUND, Vec::new()))
        }
        Some(bg) => {
            // Liveness of the whole process group, WITH identity: a recycled
            // pgid (PID wraparound after a full pid_max cycle) must report
            // done, not running (see BgGroupProbe).
            let probe = probe_bg_group(bg.pgid, bg.started_at);
            let alive = matches!(probe, BgGroupProbe::Members | BgGroupProbe::Ours);
            let code = if bg.status == BgStatus::Killed {
                crate::raw_server::CODE_BG_KILLED
            } else if alive {
                crate::raw_server::CODE_BG_RUNNING
            } else {
                // Gone (or recycled) but not killed by us: natural exit. Leave
                // the entry so the agent can read the final log tail once;
                // it's cleared at unmount. CODE_OK signals "done".
                crate::raw_server::CODE_OK
            };
            // Read the log tail (best-effort). The log lives on the warden-side
            // tmpfs (BG_LOG_DIR), not inside the chroot — read the stored path
            // directly. See start_exec for why the log is kept out of /mnt/rootfs.
            let tail = read_tail(&bg.log_path, crate::AGENT_CONFIG.bg_log_tail_bytes);
            // debug level: status polls run in tight agent loops (the response
            // carries every field printed here).
            debug!(
                logger,
                "status_exec: exec_id={} pgid={} alive={} code={} age_ms={}",
                exec_id,
                bg.pgid,
                alive,
                code,
                bg.started_at.elapsed().as_millis()
            );
            Ok((code, tail))
        }
    }
}

/// Kill a background exec by exec_id: SIGKILL the whole process group + mark
/// killed in the registry. The subreaper reaps the dying processes. The group
/// is only signalled when it is (still) OURS: a recycled pgid must never be
/// signalled — that would SIGKILL an innocent new process group that happens
/// to hold the wrapped-around id (see BgGroupProbe). An entry registered
/// under a SUPERSEDED mount generation resolves as not found and is never
/// signalled.
pub(crate) async fn kill_exec(
    logger: &slog::Logger,
    exec_id: &str,
    bg_execs: &std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, BgExec>>>,
    mount_generation: u64,
) -> Result<u8> {
    let mut map = bg_execs.lock().await;
    let (pgid, started_at) = match map.get_mut(exec_id) {
        None => return Ok(crate::raw_server::CODE_BG_NOT_FOUND),
        Some(bg) if bg.mount_generation != mount_generation => {
            debug!(
                logger,
                "kill_exec: exec_id={} belongs to mount generation {} (current {}); refused",
                exec_id,
                bg.mount_generation,
                mount_generation
            );
            return Ok(crate::raw_server::CODE_BG_NOT_FOUND);
        }
        Some(bg) => {
            bg.status = BgStatus::Killed;
            (bg.pgid, bg.started_at)
        }
    };
    drop(map);
    match probe_bg_group(pgid, started_at) {
        BgGroupProbe::Gone | BgGroupProbe::Recycled => {
            // Nothing of ours to signal (Recycled: the id now belongs to a
            // new, unrelated process group — killing it would be collateral
            // damage, and the exec this id refers to is already dead).
        }
        BgGroupProbe::Members | BgGroupProbe::Ours => {
            if pgid > 0 {
                unsafe {
                    // The group kill fails while the leader is still in
                    // pre_exec (setsid not yet called); the leader pid is the
                    // future group, so kill it directly as the fallback.
                    // The pid was identity-checked by the probe above, but it
                    // can exit and be RECYCLED between that check and this
                    // syscall, so re-check its start time immediately before
                    // the direct kill: a recycled pid belongs to an unrelated
                    // process and must never be signalled.
                    if libc::kill(-pgid, libc::SIGKILL) != 0
                        && leader_start_matches(pgid, started_at)
                    {
                        let _ = libc::kill(pgid, libc::SIGKILL);
                    }
                }
            }
        }
    }
    debug!(logger, "kill_exec: exec_id={} pgid={}", exec_id, pgid);
    Ok(crate::raw_server::CODE_OK)
}

/// Read the last `max` bytes of a file (best-effort). The read is capped:
/// the file is being appended by the agent's background process, so a
/// metadata-length minus max seek can still be followed by an unbounded
/// growth between the stat and read_to_end (the tail contract is 8 KiB; the
/// transport would otherwise carry megabytes).
fn read_tail(path: &str, max: usize) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let len = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    if len > max {
        let _ = f.seek(SeekFrom::Start((len - max) as u64));
    }
    let mut buf = Vec::with_capacity(max.min(len));
    let _ = f.by_ref().take(max as u64).read_to_end(&mut buf);
    buf
}

/// Bytes of a background exec's output retained on the warden side: the tail
/// the relay keeps in the log file, and the maximum status log tail served.
/// Runtime reads the configured value (warden.bg_log_tail_bytes, defaulting to
/// DEFAULT_BG_LOG_TAIL_BYTES); this named default is what the tests pin.
#[cfg(test)]
pub(crate) const BG_LOG_KEEP: usize = 8 * 1024; // default for bg_log_tail_bytes

/// Read chunk size for the bg-log relay (one page).
const BG_LOG_READ_CHUNK: usize = 4096;

/// Stack size for a relay thread. The loop is one blocking read plus a
/// bounded ring update, so the default 2 MiB stack would be pure
/// virtual-address waste per live background exec.
const BG_LOG_RELAY_STACK: usize = 128 * 1024;

/// Fixed-size ring holding the LAST `keep` bytes pushed into it.
struct BgLogRing {
    buf: Vec<u8>,
    keep: usize,
}

impl BgLogRing {
    fn new(keep: usize) -> Self {
        Self {
            buf: Vec::with_capacity(keep),
            keep,
        }
    }

    /// Append `chunk`, dropping the oldest bytes past `keep`. Every push
    /// leaves `buf.len() <= keep` (a `keep` of 0 retains nothing).
    fn push(&mut self, chunk: &[u8]) {
        if chunk.len() >= self.keep {
            self.buf.clear();
            self.buf
                .extend_from_slice(&chunk[chunk.len() - self.keep..]);
            return;
        }
        let overflow = (self.buf.len() + chunk.len()).saturating_sub(self.keep);
        if overflow > 0 {
            self.buf.drain(..overflow);
        }
        self.buf.extend_from_slice(chunk);
    }
}

/// Open the bg log for the relay: create/truncate, then switch the descriptor
/// to O_APPEND. Appending matters because the watchdog rewrites the file
/// through its OWN descriptor (seek + set_len + write); without O_APPEND the
/// relay's stale file offset would punch a hole or overwrite the watchdog's
/// tail. Set with fcntl rather than OpenOptions because the create/truncate +
/// append combination is rejected on some kernels (EINVAL).
fn open_bg_log_for_relay(path: &str) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, libc::O_APPEND) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

/// Publish one relayed chunk to the log file, keeping the file at most `keep`
/// bytes: append while the file has room, otherwise rewrite it with exactly
/// the retained tail. Both branches are bounded, so a flooding writer hits
/// pipe backpressure instead of growing the RAM-backed log file.
fn publish_bg_tail(file: &mut std::fs::File, ring: &BgLogRing, new: &[u8], file_len: &mut usize) {
    use std::io::Write;
    if *file_len != usize::MAX && file_len.saturating_add(new.len()) <= ring.keep {
        if file.write_all(new).is_ok() {
            *file_len += new.len();
            return;
        }
    }
    let rewritten = file.set_len(0).is_ok() && file.write_all(&ring.buf).is_ok();
    // On a failed rewrite the tracked length is unknowable: the sentinel
    // forces the full-rewrite branch on the next chunk (never a blind append
    // at a stale offset).
    *file_len = if rewritten {
        ring.buf.len()
    } else {
        usize::MAX
    };
}

/// Drain the background exec's output pipe until EOF, keeping only the last
/// `keep` bytes in `file`. Runs on its own thread for the exec's lifetime;
/// never panics on I/O errors (the child then sees EPIPE, never a blocked
/// pipe held by a dead relay).
fn relay_bg_log(mut reader: std::fs::File, mut file: std::fs::File, keep: usize) {
    use std::io::Read;
    let mut ring = BgLogRing::new(keep);
    let mut chunk = [0u8; BG_LOG_READ_CHUNK];
    // The file was created/truncated just before the relay started.
    let mut file_len = 0usize;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                ring.push(&chunk[..n]);
                publish_bg_tail(&mut file, &ring, &chunk[..n], &mut file_len);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Start the per-exec log relay thread. Split out so the bounded-tail logic
/// can be driven by a unit test without spawning a chrooted command.
fn spawn_bg_log_relay(
    reader: std::fs::File,
    file: std::fs::File,
    keep: usize,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("bg-log-relay".into())
        .stack_size(BG_LOG_RELAY_STACK)
        .spawn(move || relay_bg_log(reader, file, keep))
}

/// Monotonic part of an exec_id. The RANDOM suffix is the unguessability half
/// (see next_exec_id): a bare counter is enumerable from inside the guest.
static BG_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Directory for warden-side background exec logs. Lives on the initramfs
/// rootfs (RAM-backed tmpfs), NOT inside the chrooted agent rootfs — so bg exec
/// output never persists into the agent's SandFS volume (see start_exec).
const BG_LOG_DIR: &str = "/tmp/sandswap-bg";

/// Generate an unguessable exec_id: "bg-{counter}-{64-bit random}".
///
/// The counter alone made the id enumerable from inside the guest (bg-1,
/// bg-2, ...), and status/kill resolve ONLY by id. Today the background-exec
/// registry is per-VM and cleared at every unmount, so a guessed id reaches
/// nothing across a switch — but a guessable capability is one bookkeeping
/// skew away from a cross-tenant log-tail read or kill, and the random
/// suffix costs one getrandom(2) on the BACKGROUND spawn path only (sync
/// execs never call this). A failed getrandom keeps the counter-only form:
/// uniqueness must never depend on the entropy source.
fn next_exec_id() -> String {
    let n = BG_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut rnd = [0u8; 8];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            rnd.as_mut_ptr() as *mut libc::c_void,
            rnd.len(),
            0u32,
        )
    };
    if rc == rnd.len() as i64 {
        format!("bg-{}-{:016x}", n, u64::from_ne_bytes(rnd))
    } else {
        format!("bg-{}", n)
    }
}

/// Drain a captured child pipe into a Vec<u8>, capping the bytes KEPT at
/// `max_bytes`.
///
/// Test-only driver of the shared `drain_read_step` (production drains both
/// pipes through the poll(2)-multiplexed `drain_pipes_poll` on ONE blocking
/// thread — same step function): the Cursor-based unit tests below use this
/// single-pipe form to pin the step semantics (cap, truncation marker,
/// discard-past-cap, EOF/error) that BOTH drivers inherit.
///
/// Starts with a single inline-capacity buffer (no per-call Vec::new() +
/// read_to_end() realloc churn for the common small-output case), and only
/// grows if a command emits more. Read errors are ignored (pipe already closed
/// / EINTR after the child exited) — we return whatever was drained so far,
/// matching the old read_all semantics. Bytes are preserved as-is (no lossy
/// UTF-8 conversion), so binary stdout is correct.
///
/// Cap semantics: when the output exceeds `max_bytes`, the buffer is trimmed
/// to the cap with a truncation marker appended and `truncated=true` — but
/// reading CONTINUES to EOF, discarding the excess. This is load-bearing, not
/// cosmetic: the drain runs CONCURRENTLY with the child (spawned right after
/// fork in do_exec_rooted), and a child whose output exceeds the ~64 KiB pipe
/// capacity blocks on write() until someone reads. Stopping at the cap would
/// deadlock the child until the exec timeout killed it; discard-draining lets
/// it finish normally, so the response carries capped output AND a real exit
/// code. Without any cap a `cat /dev/zero`-style command would instead grow
/// the warden heap without bound.
#[cfg(test)]
fn drain_pipe<R: std::io::Read>(mut r: Option<R>, max_bytes: usize) -> (Vec<u8>, bool) {
    let r = match r.as_mut() {
        Some(r) => r,
        None => return (Vec::new(), false),
    };
    // 4 KiB covers a typical echo/grep output without any realloc.
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut truncated = false;
    let mut capped = false;
    while !drain_read_step(
        r,
        &mut buf,
        &mut chunk,
        max_bytes,
        &mut truncated,
        &mut capped,
    ) {}
    (buf, truncated)
}

/// One drain-loop iteration body, shared by drain_pipe (single blocking pipe)
/// and the poll(2)-multiplexed dual drain below — extracting it keeps the two
/// paths identical in cap/truncation/discard semantics (the contract the
/// drain_pipe unit tests pin). Returns `true` when the stream is DONE (EOF or
/// a non-EINTR read error — keep what we have).
fn drain_read_step<R: std::io::Read>(
    r: &mut R,
    buf: &mut Vec<u8>,
    chunk: &mut [u8; 4096],
    max_bytes: usize,
    truncated: &mut bool,
    capped: &mut bool,
) -> bool {
    if *capped {
        // Past the cap: keep draining so the writer never blocks on a
        // full pipe; discard what we read.
        match r.read(chunk) {
            Ok(0) => return true, // EOF — all write ends closed.
            Ok(_) => return false,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => return false,
            Err(_) => return true,
        }
    }
    if buf.len() >= max_bytes {
        // Trim to exactly the cap and append a marker (if room).
        buf.truncate(max_bytes);
        let marker = b"\n...[output truncated: per-exec cap reached]\n";
        // Reserve space for the marker WITHIN the cap budget by dropping the
        // last marker.len() bytes of payload. When the cap is smaller than
        // the marker itself there is no room at all: keep the payload only
        // and report truncation via the flag — the output must never EXCEED
        // max_bytes (callers and tests rely on that invariant).
        if marker.len() <= buf.len() {
            buf.truncate(buf.len() - marker.len());
            buf.extend_from_slice(marker);
        }
        *truncated = true;
        *capped = true;
        return false;
    }
    // Never read more than would fit under the cap.
    let want = std::cmp::min(chunk.len(), max_bytes - buf.len());
    match r.read(&mut chunk[..want]) {
        Ok(0) => true, // EOF — child closed its write end.
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            false
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => false,
        Err(_) => true, // pipe closed / error: keep what we have.
    }
}

/// Per-stream state of the poll(2)-multiplexed dual drain.
struct DrainStream<R> {
    reader: Option<R>,
    buf: Vec<u8>,
    chunk: [u8; 4096],
    truncated: bool,
    capped: bool,
}

impl<R: std::io::Read + AsRawFd> DrainStream<R> {
    fn new(reader: Option<R>) -> Self {
        DrainStream {
            reader,
            // 4 KiB covers a typical echo/grep output without any realloc.
            buf: Vec::with_capacity(4096),
            chunk: [0u8; 4096],
            truncated: false,
            capped: false,
        }
    }

    /// fd of the still-open reader (None once the stream hit EOF/error).
    fn fd(&self) -> Option<RawFd> {
        self.reader.as_ref().map(|r| r.as_raw_fd())
    }

    /// One drain step; drops the reader once the stream is done so the poll
    /// set below stops watching it.
    fn step(&mut self, max_bytes: usize) {
        if let Some(r) = self.reader.as_mut() {
            if drain_read_step(
                r,
                &mut self.buf,
                &mut self.chunk,
                max_bytes,
                &mut self.truncated,
                &mut self.capped,
            ) {
                self.reader = None;
            }
        }
    }

    fn finish(self) -> (Vec<u8>, bool) {
        (self.buf, self.truncated)
    }
}

/// Drain BOTH the child's stdout and stderr pipes from ONE blocking-pool
/// thread, multiplexed with poll(2). Replaces the former pair of
/// spawn_blocking drain tasks (one per pipe): every dispatch is a futex wake
/// plus a thread schedule on the guest's 1-2 vCPUs, and the old shape paid
/// that TWICE per sync exec. The loop performs exactly one drain_read_step per
/// readiness event per stream (a readable pipe read returns immediately;
/// POLLHUP-without-data reads 0 → EOF), so per-stream semantics are
/// byte-identical to drain_pipe — cap, discard-past-cap, truncation marker,
/// EOF/error handling (pinned by its tests). A finished stream leaves the
/// poll set (fd −1 is ignored by poll), letting the other block on alone.
fn drain_pipes_poll<O, E>(
    out: Option<O>,
    err: Option<E>,
    max_bytes: usize,
) -> (StreamDrain, StreamDrain)
where
    O: std::io::Read + AsRawFd,
    E: std::io::Read + AsRawFd,
{
    let mut out = DrainStream::new(out);
    let mut err = DrainStream::new(err);
    loop {
        if out.fd().is_none() && err.fd().is_none() {
            break;
        }
        let mut fds = [
            PollFd::new(out.fd().unwrap_or(-1), PollFlags::POLLIN),
            PollFd::new(err.fd().unwrap_or(-1), PollFlags::POLLIN),
        ];
        match nix::poll::poll(&mut fds, -1) {
            Ok(_) => {}
            // Spurious signal delivery — rebuild the set and wait again.
            Err(nix::errno::Errno::EINTR) => continue,
            // poll itself failing (EBADF after an fd teardown race): keep what
            // we have; the affected stream's next read would error anyway.
            Err(_) => break,
        }
        // POLLHUP/POLLERR are reported in revents regardless of the requested
        // set; ANY nonzero revents on a live fd warrants one read step.
        if fds[0].revents().is_some_and(|f| !f.is_empty()) {
            out.step(max_bytes);
        }
        if fds[1].revents().is_some_and(|f| !f.is_empty()) {
            err.step(max_bytes);
        }
    }
    (out.finish(), err.finish())
}

/// Async drain handle for the fused dual drain: the blocking poll task is
/// spawned immediately (so the child can never block on a full pipe — see
/// drain_pipe) and awaited later, bounded by a timeout. The drain is BLOCKING
/// pipe I/O and must not run on an async worker: a small VM has 1-2 tokio
/// workers, and concurrent drains there would starve heartbeats and other
/// slots. A D-state process (stuck in uninterruptible guest I/O) survives the
/// group SIGKILL while holding its pipe write end — the drain then blocks
/// INDEFINITELY. On the blocking pool that leaks one pool thread (bounded,
/// 512); on an async worker it would wedge the runtime. When the bounded
/// await times out, the detached task keeps draining to its own EOF — its
/// result is simply not collected.
/// Per-stream drain outcome: (bytes, truncated).
type StreamDrain = (Vec<u8>, bool);

struct DrainPair {
    task: tokio::task::JoinHandle<(StreamDrain, StreamDrain)>,
}

impl DrainPair {
    /// Spawn the concurrent dual drain (call immediately after stdio-take —
    /// never after waiting for the child).
    fn spawn<O, E>(out: Option<O>, err: Option<E>, max_bytes: usize) -> Self
    where
        O: std::io::Read + AsRawFd + Send + 'static,
        E: std::io::Read + AsRawFd + Send + 'static,
    {
        DrainPair {
            task: tokio::task::spawn_blocking(move || drain_pipes_poll(out, err, max_bytes)),
        }
    }

    /// Collect both drained outputs. `bound` caps the wait (the child is dead
    /// or dying by the time this is called, so EOF is immediate in the normal
    /// case); on timeout the handle is dropped and the task runs detached.
    async fn collect(self, bound: std::time::Duration) -> ((Vec<u8>, bool), (Vec<u8>, bool)) {
        match tokio::time::timeout(bound, self.task).await {
            Ok(Ok(res)) => res,
            Ok(Err(join_err)) => {
                // Drain task panicked (never expected): empty, not fatal.
                slog_scope::warn!("drain task failed: {}", join_err);
                ((Vec::new(), true), (Vec::new(), true))
            }
            Err(_) => {
                slog_scope::warn!("drain collect timed out (D-state writer?); detaching");
                ((Vec::new(), true), (Vec::new(), true))
            }
        }
    }
}

// The process-touching tests below hold the cross-module proc lock ACROSS
// await points by design: they serialize every test that spawns children and
// runs reap probes, so a sibling test's waitpid can never steal a child's
// status (the flake class documented in test_sync.rs).
#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Tests here spawn real children and run waitpid(-1) reap probes — they
    // MUST hold the SHARED cross-module proc lock (crate::test_sync): cargo
    // runs tests in parallel threads, and a reap probe in one test could
    // steal another test's child exit status (its .status() would fail with
    // ECHILD). Seccomp.rs's spawn-based tests hold the same lock.
    use crate::test_sync::proc_lock;

    // ── reaper registry: concurrent execs each get their own status ──

    #[tokio::test]
    async fn registry_reap_delivers_child_exit_status() {
        let _guard = proc_lock();
        // The child's exit is gated BEHIND the registration via a stdin handoff
        // (`read` blocks until we write, then EOF releases it). No wall-clock
        // assumption about scheduling — under a saturated build machine a
        // self-timed child (`exit 5`) could starve past the whole probe budget
        // and fail the assert with nothing wrong in the reaper. Property
        // under test is unchanged:
        // by the first reap probe below the child IS a zombie, and a registered
        // zombie is FORWARDED, never reported as an orphan.
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("read _; exit 5")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let pid = child.id() as i32;
        let mut gate = child.stdin.take().expect("child stdin");
        drop(child);
        let (tx, mut rx) = tokio::sync::oneshot::channel::<i32>();
        crate::signal::register_exit_waiter(pid, tx);
        // Release the child: `read` returns, `exit 5` runs, the zombie is ours.
        use std::io::Write;
        gate.write_all(b"go\n").expect("release child");
        drop(gate);
        // Property: the registered waiter receives the child's status, and the
        // child is NEVER reported as an orphan. Assert on the CHANNEL, not on
        // a local "I was the one who forwarded" flag: cargo runs 190 tests in
        // parallel threads, and a sibling test's reap_one call may legally
        // forward OUR registered child first (the registry semantics are
        // exactly-once-per-pid, whichever thread reaps). The old local-flag
        // assertion flaked under load for that reason.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut got: Option<i32> = None;
        let mut orphaned_ours = false;
        for _ in 0..250 {
            if let Ok(x) = rx.try_recv() {
                got = Some(x);
                break;
            }
            match crate::signal::reap_one(libc::WNOHANG | libc::__WALL).await {
                crate::signal::Reaped::Forwarded | crate::signal::Reaped::Nothing => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                crate::signal::Reaped::Orphan(p) if p == pid => {
                    orphaned_ours = true;
                }
                crate::signal::Reaped::Orphan(_) => {}
            }
        }
        assert!(
            !orphaned_ours,
            "registered child must never be reported as an orphan"
        );
        let raw = got.unwrap_or_else(|| {
            rx.blocking_recv()
                .expect("status delivered to the registered waiter")
        });
        assert_eq!(exit_code_from(&status_from_raw(raw)), 5);
    }

    #[tokio::test]
    async fn registry_forwarding_is_per_pid_not_serialized() {
        let _guard = proc_lock();
        // Two children with different lifetimes and exit codes: each waiter
        // must receive its own status regardless of reap order — the property
        // concurrent sync execs rely on (no cross-exec status theft).
        let c1 = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 0.1; exit 11")
            .spawn()
            .expect("spawn sh1");
        let c2 = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 0.25; exit 22")
            .spawn()
            .expect("spawn sh2");
        let pid1 = c1.id() as i32;
        let pid2 = c2.id() as i32;
        drop(c1);
        drop(c2);
        let (t1, mut r1) = tokio::sync::oneshot::channel::<i32>();
        let (t2, mut r2) = tokio::sync::oneshot::channel::<i32>();
        crate::signal::register_exit_waiter(pid1, t1);
        crate::signal::register_exit_waiter(pid2, t2);

        let mut got1 = None;
        let mut got2 = None;
        for _ in 0..200 {
            let _ = crate::signal::reap_one(libc::WNOHANG | libc::__WALL).await;
            if got1.is_none() {
                if let Ok(x) = r1.try_recv() {
                    got1 = Some(x);
                }
            }
            if got2.is_none() {
                if let Ok(x) = r2.try_recv() {
                    got2 = Some(x);
                }
            }
            if got1.is_some() && got2.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert_eq!(
            exit_code_from(&status_from_raw(got1.expect("child1 status"))),
            11
        );
        assert_eq!(
            exit_code_from(&status_from_raw(got2.expect("child2 status"))),
            22
        );
    }

    // ── drain_pipe ──────────────────────────────────────────────────

    #[test]
    fn drain_pipe_none_input() {
        let (data, trunc) = drain_pipe(None::<Cursor<Vec<u8>>>, 1024);
        assert!(data.is_empty());
        assert!(!trunc);
    }

    #[test]
    fn drain_pipe_empty_input() {
        let input = Cursor::new(Vec::new());
        let (data, trunc) = drain_pipe(Some(input), 1024);
        assert!(data.is_empty());
        assert!(!trunc);
    }

    #[test]
    fn drain_pipe_small_output() {
        let input = Cursor::new(b"hello world".to_vec());
        let (data, trunc) = drain_pipe(Some(input), 1024);
        assert_eq!(data, b"hello world");
        assert!(!trunc);
    }

    #[test]
    fn drain_pipe_truncation() {
        // 100 bytes of input, max_bytes = 50 → truncated.
        let input = Cursor::new(vec![0xAA; 100]);
        let (data, trunc) = drain_pipe(Some(input), 50);
        assert!(trunc);
        // Data should be <= 50 bytes (may be slightly less due to truncation marker space).
        assert!(data.len() <= 50);
        // Should contain the truncation marker.
        let marker = b"\n...[output truncated: per-exec cap reached]\n";
        assert!(
            data.windows(marker.len()).any(|w| w == marker),
            "truncated output should contain the truncation marker"
        );
    }

    #[test]
    fn drain_pipe_exact_cap() {
        // Output exactly equals max_bytes → the truncation logic fires
        // (buf.len() >= max_bytes) and appends the truncation marker,
        // replacing the last bytes. This is by design: the marker signals
        // that output was capped, even at the exact boundary.
        let input = Cursor::new(vec![0x42; 64]);
        let (data, trunc) = drain_pipe(Some(input), 64);
        assert!(trunc);
        // Data should be <= 64 bytes (truncation marker replaces some payload).
        assert!(data.len() <= 64);
    }

    #[test]
    fn drain_pipe_one_byte_under_cap() {
        // Output is 1 byte less than max_bytes → not truncated.
        let input = Cursor::new(vec![0x42; 63]);
        let (data, trunc) = drain_pipe(Some(input), 64);
        assert_eq!(data.len(), 63);
        assert!(!trunc);
    }

    #[test]
    fn drain_pipe_tiny_cap_never_exceeds_cap() {
        // REGRESSION (cap invariant): when the cap is SMALLER than the
        // truncation marker, the marker used to be appended anyway — the
        // returned buffer EXCEEDED max_bytes. A tiny cap must still yield
        // buf.len() <= cap (with the truncation flag carrying the signal).
        let input = Cursor::new(vec![0x42; 100]);
        let (data, trunc) = drain_pipe(Some(input), 10);
        assert!(trunc, "past-cap output must be flagged truncated");
        assert!(
            data.len() <= 10,
            "output must never exceed the cap, got {}",
            data.len()
        );
    }

    // ── read_tail ───────────────────────────────────────────────────

    #[test]
    fn read_tail_missing_file() {
        let data = read_tail("/nonexistent/path/file.log", 1024);
        assert!(data.is_empty());
    }

    #[test]
    fn read_tail_empty_file() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_tail")
            .tempdir()
            .unwrap();
        let path = dir.path().join("empty.log");
        std::fs::File::create(&path).unwrap();
        let data = read_tail(path.to_str().unwrap(), 1024);
        assert!(data.is_empty());
    }

    #[test]
    fn read_tail_file_shorter_than_max() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_tail")
            .tempdir()
            .unwrap();
        let path = dir.path().join("short.log");
        std::fs::write(&path, b"hello").unwrap();
        let data = read_tail(path.to_str().unwrap(), 1024);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn read_tail_file_longer_than_max() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_tail")
            .tempdir()
            .unwrap();
        let path = dir.path().join("long.log");
        // 200 bytes, max 50 → should read last 50 bytes.
        let content: Vec<u8> = (0..200).collect();
        std::fs::write(&path, &content).unwrap();
        let data = read_tail(path.to_str().unwrap(), 50);
        assert_eq!(data.len(), 50);
        assert_eq!(data, &content[150..200]);
    }

    // ── bg-log relay: bounded tail ───────────────────────────────────

    #[test]
    fn bg_log_ring_keeps_only_the_tail() {
        let mut ring = BgLogRing::new(8);
        ring.push(b"abc");
        assert_eq!(ring.buf, b"abc");
        // 3 + 7 bytes into keep=8: the two oldest bytes are dropped.
        ring.push(b"defghij");
        assert_eq!(ring.buf, b"cdefghij");
        // A chunk larger than keep replaces the ring with its own tail.
        ring.push(b"0123456789");
        assert_eq!(ring.buf, b"23456789");
        assert!(ring.buf.len() <= ring.keep);

        // keep = 0 retains nothing (degenerate configuration).
        let mut empty = BgLogRing::new(0);
        empty.push(b"anything");
        assert!(empty.buf.is_empty());
    }

    #[test]
    fn bg_log_relay_bounds_the_file_and_keeps_the_tail() {
        use std::io::Write;
        use std::os::unix::io::FromRawFd;

        let dir = tempfile::Builder::new()
            .prefix("warden_test_relay")
            .tempdir()
            .unwrap();
        let path = dir.path().join("bg.log");
        let file = open_bg_log_for_relay(path.to_str().unwrap()).unwrap();
        let (r, w) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let reader = unsafe { std::fs::File::from_raw_fd(r) };
        let mut writer = unsafe { std::fs::File::from_raw_fd(w) };

        const KEEP: usize = 1024;
        let handle = spawn_bg_log_relay(reader, file, KEEP).expect("spawn relay");

        // Flood far past the pipe capacity and the keep budget. The write
        // loop only completes because the relay keeps draining (a relay that
        // stopped at the cap would block the writer forever).
        let block = [b'x'; 300];
        let mut written = 0usize;
        for _ in 0..2000 {
            writer.write_all(&block).expect("writer");
            written += block.len();
        }
        assert!(written > KEEP * 100);
        drop(writer); // EOF → the relay finishes
        handle.join().expect("relay thread");

        let got = std::fs::read(&path).expect("read log");
        // The file never grows past the keep budget...
        assert!(
            got.len() <= KEEP,
            "relay log must stay within {KEEP} bytes, got {}",
            got.len()
        );
        // ...and holds exactly the LAST bytes the child wrote.
        assert_eq!(got.len(), KEEP);
        assert_eq!(&got[..], &vec![b'x'; KEEP][..]);
    }

    // ── next_exec_id ────────────────────────────────────────────────

    #[test]
    fn next_exec_id_is_monotonic_and_unguessable() {
        let id1 = next_exec_id();
        let id2 = next_exec_id();
        assert!(id1.starts_with("bg-"), "exec_id should start with 'bg-'");
        assert!(id2.starts_with("bg-"), "exec_id should start with 'bg-'");
        let mut parts = id1.split('-');
        assert_eq!(parts.next(), Some("bg"));
        let n1: u64 = parts.next().expect("counter part").parse().unwrap();
        let n2: u64 = id2
            .split('-')
            .nth(1)
            .expect("counter part")
            .parse()
            .unwrap();
        assert!(
            n2 > n1,
            "exec_id counter should be monotonically increasing"
        );
        // The random suffix is what closes the in-guest enumeration channel.
        // On a host whose getrandom works the id carries it; the fallback
        // shape (counter only) stays valid for kernels without the syscall.
        let suffix = id1.split('-').nth(2);
        if let Some(suffix) = suffix {
            assert_eq!(suffix.len(), 16, "random suffix must be a full u64");
            assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
            assert_ne!(
                id1, id2,
                "two exec ids must never collide, randomness included"
            );
        }
    }

    // ── exit_code_from ──────────────────────────────────────────────

    #[test]
    fn exit_code_from_normal_exit() {
        let _guard = proc_lock();
        // A command that exits 0 → exit code 0.
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .status()
            .expect("spawn sh");
        assert_eq!(exit_code_from(&status), 0);
    }

    #[test]
    fn exit_code_from_nonzero_exit() {
        let _guard = proc_lock();
        // A command that exits 42 → exit code 42 (not -1).
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 42")
            .status()
            .expect("spawn sh");
        assert_eq!(exit_code_from(&status), 42);
    }

    #[test]
    fn exit_code_from_signal_death() {
        let _guard = proc_lock();
        // A command killed by SIGKILL → 128 + 9 = 137 (NOT -1).
        // -1 would collide with the wire protocol's transport-error sentinel
        // and make the sandlot client treat a signal-killed command as a
        // transport failure.
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg("kill -9 $$")
            .status()
            .expect("spawn sh");
        assert!(
            status.signal().is_some(),
            "child should have died by signal"
        );
        assert_eq!(exit_code_from(&status), (128 + libc::SIGKILL) as u8);
    }

    #[test]
    fn exit_code_from_sigsegv() {
        let _guard = proc_lock();
        // SIGSEGV (11) → 128 + 11 = 139.
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg("exec kill -SEGV $$")
            .status()
            .expect("spawn sh");
        assert_eq!(exit_code_from(&status), (128 + libc::SIGSEGV) as u8);
    }

    // ── INSTALL_CAPS ────────────────────────────────────────────────

    /// Pins the EXACT Install capability set (owner ruling:
    /// Docker-minus-five — SETPCAP and MKNOD joined the excluded three).
    /// Redundant with install_caps_properties by design: this table is the
    /// decision record, that test is the invariant (distinct, in range).
    /// RED against any addition OR removal — a cap change is an owner
    /// decision, never a drive-by.
    #[test]
    fn install_caps_exact_set() {
        assert_eq!(
            INSTALL_CAPS,
            &[
                0,  // CAP_CHOWN (dpkg)
                1,  // CAP_DAC_OVERRIDE (dpkg)
                2,  // CAP_DAC_READ_SEARCH (dpkg)
                3,  // CAP_FOWNER (dpkg)
                4,  // CAP_FSETID (dpkg: preserve suid bits on chown)
                5,  // CAP_KILL (process management)
                6,  // CAP_SETGID (dpkg/adduser)
                7,  // CAP_SETUID (dpkg/adduser)
                10, // CAP_NET_BIND_SERVICE (service packages)
                29, // CAP_AUDIT_WRITE (dbus/logger)
            ]
        );
    }

    #[test]
    fn install_caps_properties() {
        // Exactly 10 capabilities retained (the excluded five are deliberate).
        assert_eq!(INSTALL_CAPS.len(), 10);
        // All values are distinct.
        let mut seen = std::collections::HashSet::new();
        for &cap in INSTALL_CAPS {
            assert!(seen.insert(cap), "duplicate cap {} in INSTALL_CAPS", cap);
        }
        // No value exceeds 63 (Linux cap range 0-63 on x86_64).
        for &cap in INSTALL_CAPS {
            assert!(cap <= 63, "cap {} exceeds 63", cap);
        }
        // The excluded caps stay excluded (the ruling's negative space).
        for &excluded in &[
            8,  /* SETPCAP */
            27, /* MKNOD */
            9,  /* NET_RAW-ish */
            12, /* NET_ADMIN */
            21, /* SYS_ADMIN */
        ] {
            assert!(
                !seen.contains(&excluded),
                "cap {} re-entered INSTALL_CAPS",
                excluded
            );
        }
    }

    // ── ExecProfile mapping ─────────────────────────────────────────

    #[test]
    fn profile_for_install_packages_flag() {
        assert_eq!(profile_for(true), ExecProfile::Install);
        assert_eq!(profile_for(false), ExecProfile::Strict);
    }

    // ── drain_pipe against a REAL child pipe ────────────────────────

    #[tokio::test]
    async fn drain_pair_real_child_pipes() {
        // A child that writes output and exits: the fused concurrent drain
        // (one blocking-pool task, poll-multiplexed) must return its stdout
        // byte-true and its stderr empty.
        let _guard = proc_lock();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("printf hello-pipe")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let _ = child.wait();
        let drains = DrainPair::spawn(stdout, stderr, 64 * 1024);
        let ((out, trunc), (err, err_trunc)) =
            drains.collect(std::time::Duration::from_secs(2)).await;
        assert!(!trunc && !err_trunc);
        assert_eq!(out, b"hello-pipe");
        assert!(err.is_empty());
    }

    #[tokio::test]
    async fn drain_pair_keeps_child_writing_past_pipe_capacity_alive() {
        // REGRESSION (pipe deadlock): a child emitting 2 MiB — far past the
        // ~64 KiB pipe capacity — into a 64-byte-capped drain must still reach
        // EOF (the drain keeps reading past the cap and discarding). The old
        // drain-then-stop design deadlocked such children until their exec
        // timeout killed them. Runs through the fused drain (stderr absent)
        // to pin the same contract on the poll-multiplexed path.
        let _guard = proc_lock();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("head -c 2097152 /dev/zero | tr '\\0' b; echo; echo DONE_MARKER")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let stdout = child.stdout.take();
        let drains = DrainPair::spawn(stdout, None::<std::process::ChildStderr>, 64);
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::task::spawn_blocking(move || child.wait()),
        )
        .await
        .expect("child must not deadlock on a full pipe")
        .expect("join")
        .expect("wait");
        assert!(status.success(), "pipeline must complete normally");
        let ((out, trunc), (err, err_trunc)) =
            drains.collect(std::time::Duration::from_secs(2)).await;
        assert!(trunc, "2 MiB into a 64-byte cap must be truncated");
        assert!(out.len() <= 64);
        assert!(err.is_empty() && !err_trunc);
        let marker = b"...[output truncated: per-exec cap reached]";
        assert!(
            out.windows(marker.len()).any(|w| w == marker),
            "truncation marker missing"
        );
    }

    #[tokio::test]
    async fn drain_pair_multiplexes_both_streams() {
        // The poll loop must service BOTH pipes from the single task: a child
        // writing interleaved stdout/stderr (stdout LAST, after a large
        // stderr burst that alone would keep poll busy) delivers both
        // byte-true. Guards against a multiplexer that drops the second
        // stream's readiness (e.g. watching only fds[0]).
        let _guard = proc_lock();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("printf ERR-A >&2; head -c 131072 /dev/zero | tr '\\0' e >&2; printf ERR-B >&2; printf OUT-END")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let drains = DrainPair::spawn(stdout, stderr, 1 << 20);
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::task::spawn_blocking(move || child.wait()),
        )
        .await
        .expect("child must not deadlock")
        .expect("join")
        .expect("wait");
        assert!(status.success());
        let ((out, out_trunc), (err, err_trunc)) =
            drains.collect(std::time::Duration::from_secs(2)).await;
        assert!(!out_trunc && !err_trunc);
        assert_eq!(out, b"OUT-END");
        assert_eq!(err.first(), Some(&b'E'));
        assert_eq!(err.last(), Some(&b'B'));
        assert_eq!(err.len(), "ERR-A".len() + "ERR-B".len() + 131072);
    }

    // ── BgGroupProbe: pgid identity vs PID wraparound ──────────────

    /// Spawn /bin/sh as a NEW session+group leader (pgid == pid, exactly how
    /// start_exec's children look) running `cmd`, stdio discarded.
    fn spawn_group_leader(cmd: &str) -> std::process::Child {
        use std::os::unix::process::CommandExt;
        let mut c = std::process::Command::new("/bin/sh");
        c.arg("-c")
            .arg(cmd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            c.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        c.spawn().expect("spawn setsid'd sh")
    }

    #[test]
    fn probe_fresh_group_is_ours() {
        let _guard = proc_lock();
        let child = spawn_group_leader("sleep 10");
        let pgid = child.id() as i32;
        let started_at = Instant::now(); // recorded AFTER spawn, like start_exec
                                         // The leader's /proc start time must resolve and match the spawn.
        let leader_start = proc_leader_start(pgid).expect("leader start readable");
        assert!(
            leader_start <= started_at + BG_START_SLACK,
            "leader started after the recorded start + slack (recycled?)"
        );
        assert!(
            leader_start >= started_at - std::time::Duration::from_secs(60),
            "leader start implausibly old"
        );
        assert!(matches!(
            probe_bg_group(pgid, started_at),
            BgGroupProbe::Ours
        ));
        // Cleanup: kill + reap so the group is gone for other tests.
        let mut child = child;
        let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
        let _ = child.wait();
    }

    #[test]
    fn probe_pre_setsid_leader_is_ours() {
        let _guard = proc_lock();
        // No pre_exec setsid: the child is alive but not yet a group leader,
        // exactly the fork→pre_exec window start_exec exposes to a fast
        // status poll. The group lookup fails; the leader's identity check
        // must still classify the exec as live.
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 10")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn non-setsid sh");
        let pgid = child.id() as i32;
        let started_at = Instant::now();
        assert!(matches!(
            probe_bg_group(pgid, started_at),
            BgGroupProbe::Ours
        ));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn probe_recycled_pgid_is_not_ours() {
        let _guard = proc_lock();
        // Simulate the wraparound signature: a registry entry claiming the
        // exec started 10 minutes ago, while the process CURRENTLY holding
        // that pgid started just now. The probe must classify it Recycled —
        // status_exec would report done and kill_exec would NOT signal it.
        let child = spawn_group_leader("sleep 10");
        let pgid = child.id() as i32;
        let stale_started_at = Instant::now() - std::time::Duration::from_secs(600);
        assert!(matches!(
            probe_bg_group(pgid, stale_started_at),
            BgGroupProbe::Recycled
        ));
        let mut child = child;
        let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
        let _ = child.wait();
    }

    #[test]
    fn probe_reaped_group_is_gone() {
        let _guard = proc_lock();
        let mut child = spawn_group_leader("true");
        let pgid = child.id() as i32;
        let started_at = Instant::now();
        let _ = child.wait(); // exit + reap → group disappears
                              // The kernel may need a beat to tear the group down after the reap.
        let mut gone = false;
        for _ in 0..50 {
            if matches!(probe_bg_group(pgid, started_at), BgGroupProbe::Gone) {
                gone = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(gone, "reaped group must probe Gone");
    }

    #[test]
    fn probe_orphaned_group_members_report_members() {
        let _guard = proc_lock();
        // Leader exits immediately (and is reaped by us), leaving an orphaned
        // `sleep` in the group: kill(-pgid,0) succeeds, /proc/<pgid> is gone.
        let mut child = spawn_group_leader("sleep 2 & exit 0");
        let pgid = child.id() as i32;
        let started_at = Instant::now();
        let _ = child.wait(); // reap the leader while the orphan sleeps
        match probe_bg_group(pgid, started_at) {
            BgGroupProbe::Members => {
                // Expected: preserve the pre-existing "still running while
                // group members live" semantics.
            }
            BgGroupProbe::Gone => {
                // Tolerable ONLY if the orphan already exited (slow host):
                // verify the group really is empty.
                assert_ne!(
                    unsafe { libc::kill(-pgid, 0) },
                    0,
                    "group still exists but probe said Gone"
                );
            }
            BgGroupProbe::Ours | BgGroupProbe::Recycled => {
                panic!("leader is reaped; probe must not report Ours/Recycled")
            }
        }
    }

    #[test]
    fn leader_start_matches_rejects_recycled_and_gone() {
        let _guard = proc_lock();
        // A live pid whose start time is consistent with the recorded exec
        // start matches...
        let pid = std::process::id() as i32;
        let now = Instant::now();
        assert!(leader_start_matches(pid, now));
        // ...a registry entry claiming the exec started 10 minutes ago does
        // not (the current process started later: the id was recycled)...
        let stale = now - std::time::Duration::from_secs(600);
        assert!(
            !leader_start_matches(pid, stale),
            "a newer process must never pass as the recorded exec"
        );
        // ...and a pid with no /proc entry never matches.
        assert!(!leader_start_matches(999_999_999, now));
    }

    #[tokio::test]
    async fn bg_exec_status_and_kill_refuse_superseded_mount_generation() {
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let bg_execs =
            std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        // pgid -1 probes as Gone, so neither path touches a real process.
        bg_execs.lock().await.insert(
            "bg-stale".to_string(),
            BgExec {
                pgid: -1,
                log_path: "/nonexistent/bg.log".to_string(),
                status: BgStatus::Running,
                started_at: Instant::now(),
                mount_generation: 7,
            },
        );

        // Superseded generation (current = 8): both resolve as unknown and
        // the entry is not mutated by the refused kill.
        let (code, tail) = status_exec(&logger, "bg-stale", &bg_execs, 8)
            .await
            .unwrap();
        assert_eq!(code, crate::raw_server::CODE_BG_NOT_FOUND);
        assert!(tail.is_empty());
        assert_eq!(
            kill_exec(&logger, "bg-stale", &bg_execs, 8).await.unwrap(),
            crate::raw_server::CODE_BG_NOT_FOUND
        );
        assert_eq!(
            bg_execs.lock().await.get("bg-stale").unwrap().status,
            BgStatus::Running
        );

        // Matching generation: the normal semantics are unchanged.
        let (code, tail) = status_exec(&logger, "bg-stale", &bg_execs, 7)
            .await
            .unwrap();
        assert_eq!(code, crate::raw_server::CODE_OK);
        assert!(tail.is_empty());
        assert_eq!(
            kill_exec(&logger, "bg-stale", &bg_execs, 7).await.unwrap(),
            crate::raw_server::CODE_OK
        );
        assert_eq!(
            bg_execs.lock().await.get("bg-stale").unwrap().status,
            BgStatus::Killed
        );
    }

    // ── do_exec_rooted: end-to-end spawn/wait/timeout (root-gated) ──
    //
    // These exercise the REAL chroot machinery (setsid + chroot + seccomp +
    // cap drop in pre_exec) with root="/" so they run on any host with
    // /bin/sh — no mounted agent rootfs needed. chroot(2) requires
    // CAP_SYS_CHROOT, hence #[ignore] + the root test gate
    // (cargo test -- --ignored).

    fn host_root() -> std::ffi::CString {
        std::ffi::CString::new("/").unwrap()
    }

    /// Restore the frozen sync-exec cap to 0 no matter how the test exits
    /// (a leaked non-zero cap would cap every later test's children).
    struct CapReset;
    impl Drop for CapReset {
        fn drop(&mut self) {
            crate::exec_cgroup::set_sync_rlimit_as_for_tests(0);
        }
    }

    // ── sync-exec RLIMIT_AS cap (root-gated: real chroot spawn path) ──

    #[tokio::test]
    #[ignore]
    async fn sync_exec_rlimit_as_applied_and_inherited() {
        let _guard = proc_lock();
        let _cap_reset = CapReset;
        const CAP: u64 = 64 * 1024 * 1024;
        crate::exec_cgroup::set_sync_rlimit_as_for_tests(CAP);

        // do_exec_rooted runs the REAL pre_exec chain (setsid + rlimit +
        // chroot + seccomp) with root="/". The child reports the inherited
        // address-space limit via its shell's ulimit builtin (KiB units on
        // both bash and dash).
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let (outcome, _, _) = AgentService::do_exec_rooted(
            &host_root(),
            &logger,
            "ulimit -v",
            Instant::now(),
            std::time::Duration::from_secs(10),
            false,
        )
        .await
        .expect("exec");
        match outcome {
            ExecOutcome::Done(r) => {
                assert_eq!(r.exit_code, 0, "ulimit -v must succeed");
                let ulimit_kib: u64 = String::from_utf8_lossy(&r.stdout)
                    .trim()
                    .parse()
                    .unwrap_or_else(|_| {
                        panic!(
                            "non-numeric ulimit output: {:?}",
                            String::from_utf8_lossy(&r.stdout)
                        )
                    });
                assert_eq!(ulimit_kib * 1024, CAP, "child must inherit the frozen cap");
            }
            ExecOutcome::TimedOut(_) => panic!("ulimit -v must not time out"),
        }

        // Cap = 0 means uncapped: the child must see "unlimited".
        crate::exec_cgroup::set_sync_rlimit_as_for_tests(0);
        let (outcome, _, _) = AgentService::do_exec_rooted(
            &host_root(),
            &logger,
            "ulimit -v",
            Instant::now(),
            std::time::Duration::from_secs(10),
            false,
        )
        .await
        .expect("exec");
        match outcome {
            ExecOutcome::Done(r) => {
                assert_eq!(r.exit_code, 0);
                assert_eq!(
                    String::from_utf8_lossy(&r.stdout).trim(),
                    "unlimited",
                    "cap=0 must leave the child's RLIMIT_AS unlimited"
                );
            }
            ExecOutcome::TimedOut(_) => panic!("must not time out"),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn strict_exec_child_bounding_set_is_empty() {
        // The agent must exec with an EMPTY capability bounding set — the
        // load-bearing guarantee behind "uid=0 with zero kernel capabilities"
        // (execve recomputes permitted/effective from bounding + inheritable;
        // empty bounding + empty inheritable + no file caps ⇒ zero caps).
        // Covers the fallback sweep path (no boot pre-drop — the test process
        // never predrops its own bounding set). The boot-predropped baseline
        // path runs the identical prctl loop over INSTALL_CAPS and is covered
        // end-to-end by the e2e suite (warden boots as PID 1 pre-dropped).
        let _guard = proc_lock();
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let (outcome, _, _) = AgentService::do_exec_rooted(
            &host_root(),
            &logger,
            "grep CapBnd /proc/self/status",
            Instant::now(),
            std::time::Duration::from_secs(10),
            false,
        )
        .await
        .expect("exec");
        match outcome {
            ExecOutcome::Done(r) => {
                let out = String::from_utf8_lossy(&r.stdout);
                assert!(
                    out.contains("CapBnd:\t0000000000000000"),
                    "strict exec child must have an empty bounding set, got: {}",
                    out.trim()
                );
            }
            ExecOutcome::TimedOut(_) => panic!("must not time out"),
        }
    }

    /// fd-sweep + error-pipe regression: a descriptor inherited WITHOUT
    /// CLOEXEC must not reach the agent, and a failed execve must still be
    /// reported as Err. RED with the close_range flag reverted to
    /// CLOSE_RANGE_UNSHARE: the immediate close also closed the Command
    /// error pipe, so the parent saw EOF and treated a failed execve as
    /// success. Also RED with the flag dropped to plain CLOEXEC-less close.
    #[tokio::test]
    #[ignore]
    async fn do_exec_rooted_closes_inherited_fds_and_reports_exec_failure() {
        let _guard = proc_lock();
        let logger = slog::Logger::root(slog::Discard, slog::o!());

        let leak = std::fs::File::open("/etc/passwd").expect("open a host file whose fd can leak");
        let raw = leak.as_raw_fd();
        unsafe {
            let flags = libc::fcntl(raw, libc::F_GETFD);
            assert!(flags >= 0, "fcntl F_GETFD failed");
            // Clear FD_CLOEXEC on the parent's copy: without the sweep this
            // descriptor survives into the chrooted child.
            assert!(libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) >= 0);
        }
        let cmd = format!("if [ -e /proc/self/fd/{raw} ]; then echo LEAK; else echo OK; fi");
        let (outcome, _, _) = AgentService::do_exec_rooted(
            &host_root(),
            &logger,
            &cmd,
            Instant::now(),
            std::time::Duration::from_secs(10),
            false,
        )
        .await
        .expect("exec");
        match outcome {
            ExecOutcome::Done(r) => assert_eq!(
                String::from_utf8_lossy(&r.stdout).trim(),
                "OK",
                "an inherited non-CLOEXEC fd reached the agent"
            ),
            ExecOutcome::TimedOut(_) => panic!("must not time out"),
        }

        // A root without /bin/sh makes execve fail. The parent must get an
        // Err — the error pipe has to survive the sweep until execve.
        let empty = std::env::temp_dir().join(format!("warden-exec-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        let empty_root = std::ffi::CString::new(empty.to_str().unwrap()).unwrap();
        let res = AgentService::do_exec_rooted(
            &empty_root,
            &logger,
            "true",
            Instant::now(),
            std::time::Duration::from_secs(10),
            false,
        )
        .await;
        let _ = std::fs::remove_dir_all(&empty);
        assert!(
            res.is_err(),
            "a failed execve must surface as Err (the error pipe was closed by the fd sweep)"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn do_exec_rooted_exit_code_and_env() {
        let _guard = proc_lock();
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let start = Instant::now();
        // env_clear regression probe: a variable present in the WARDEN's own
        // environment must NOT reach the chrooted child (the exec env is
        // exactly apply_exec_env's set). Restore no matter how we exit.
        std::env::set_var("WARDEN_TEST_ENV_LEAK", "leaked");
        struct EnvReset;
        impl Drop for EnvReset {
            fn drop(&mut self) {
                std::env::remove_var("WARDEN_TEST_ENV_LEAK");
            }
        }
        let _env_reset = EnvReset;
        let (outcome, _, _) = AgentService::do_exec_rooted(
            &std::ffi::CString::new("/").unwrap(),
            &logger,
            "echo $HOME; echo $PYTHONUSERBASE; echo X${WARDEN_TEST_ENV_LEAK}X; exit 42",
            start,
            std::time::Duration::from_secs(10),
            false,
        )
        .await
        .expect("do_exec_rooted");
        match outcome {
            ExecOutcome::Done(r) => {
                assert_eq!(r.exit_code, 42);
                let out = String::from_utf8_lossy(&r.stdout);
                // apply_exec_env (Command::env, pre-fork) must reach the
                // chrooted shell — the old pre_exec setenv path is gone.
                assert!(out.contains("/home/agent"), "HOME not set: {}", out);
                assert!(
                    out.contains("/home/agent/.local"),
                    "PYTHONUSERBASE not set: {}",
                    out
                );
                // env_clear: the warden-side variable must not leak through
                // (X..X with nothing between = empty expansion).
                assert!(
                    out.lines().any(|l| l == "XX"),
                    "warden env leaked into the chrooted exec: {}",
                    out
                );
            }
            ExecOutcome::TimedOut(_) => panic!("fast command must not time out"),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn do_exec_rooted_timeout_kills_group() {
        let _guard = proc_lock();
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let start = Instant::now();
        // `sleep 30 & sleep 30` — the shell exits only after the foreground
        // sleep; the timeout fires first and must kill the WHOLE group
        // (including the backgrounded child) and return partial output.
        let (outcome, _, _) = AgentService::do_exec_rooted(
            &std::ffi::CString::new("/").unwrap(),
            &logger,
            "echo started; sleep 30 & sleep 30",
            start,
            std::time::Duration::from_millis(700),
            false,
        )
        .await
        .expect("do_exec_rooted");
        match outcome {
            ExecOutcome::TimedOut(r) => {
                assert!(String::from_utf8_lossy(&r.stdout).contains("started"));
            }
            ExecOutcome::Done(_) => panic!("sleep 30 with 700ms timeout must time out"),
        }
        // The group (shell + both sleeps) must be gone shortly after: probe
        // via the reaper for a bounded window.
        for _ in 0..20 {
            let _ = crate::signal::reap_one(libc::WNOHANG).await;
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    #[tokio::test]
    #[ignore]
    async fn do_exec_rooted_output_truncated_at_cap() {
        let _guard = proc_lock();
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let start = Instant::now();
        let cap = AGENT_CONFIG.max_output_bytes;
        // Emit 2 MiB against the configured per-stream cap (default 1 MiB):
        // the kept output must be capped and carry the truncation marker.
        let (outcome, _, _) = AgentService::do_exec_rooted(
            &std::ffi::CString::new("/").unwrap(),
            &logger,
            "head -c 2097152 /dev/zero | tr '\\0' 'a'",
            start,
            std::time::Duration::from_secs(20),
            false,
        )
        .await
        .expect("do_exec_rooted");
        match outcome {
            ExecOutcome::Done(r) => {
                assert!(
                    r.stdout.len() <= cap,
                    "output must be capped at {}, got {}",
                    cap,
                    r.stdout.len()
                );
                let marker = b"...[output truncated: per-exec cap reached]";
                assert!(
                    r.stdout.windows(marker.len()).any(|w| w == marker),
                    "truncation marker missing"
                );
            }
            ExecOutcome::TimedOut(_) => panic!("command is fast; must not time out"),
        }
    }
}

// fd-leak regression guard for the pidfd path: AsyncFd must be built over an
// OWNED fd type (OwnedFd), or every exec leaks one pidfd (observed as +1 fd
// per exec; ~200 execs later warden's io wedges and unmounts stall, surfacing
// as gateway 503 SANDBOX_CLEANING). 60 sequential execs must not grow the
// process fd count.
//
// ── Regression record: "3/10 failed" was 1 flake + 2
// echoes — do NOT reintroduce either half. ──
//
// PRIMARY (this test): the final at-rest check originally slept a FIXED
// 200ms and then asserted count <= 3 in one shot. The count includes the
// test's OWN cargo output-capture pipe (2 pipe ends on fds 1/2 for the whole
// test life), and the LAST exec's drain-pipe pair is closed ASYNCHRONOUSLY on
// another thread — so the fixed grace was a timing bet. Run immediately
// after a heavy deploy phase (reproduced 1/1 with: egress-enabler bpf +
// routed-ipv6 scenario, then this suite in the same minute), the drain pair
// was still open at scan time: 2 capture ends + 2 drain ends = 4 > 3 → a
// FALSE "fd leak: 4 lingering" failure. 60 execs had leaked ZERO pidfds (no
// accumulation — the actual regression this guards never happened). Plain
// resource pressure does NOT reproduce it (green at 1.5GB free + CPU
// spinners): millisecond-scale host timing drift is the trigger, so if this
// test fails again, first check `after` for GROWTH across execs (real leak)
// vs a constant 4 (this race), and re-run before investigating the runtime.
//
// CASCADE (why one failure read as three): this test and the do_exec_rooted*
// tests serialize on the shared TEST_PROC_LOCK (crate::test_sync). The primary
// panic POISONED that mutex, so the next two lock waiters failed with
// PoisonError BEFORE their own assertions ran, inflating 1 flake into 3/10
// "failed". Lock acquisition goes through the poison-tolerant
// crate::test_sync::proc_lock() — keep it that way; a plain .lock().unwrap()
// here would resurrect the echo failures.
#[tokio::test]
#[ignore]
// Lives after the tests module (its own cfg(test) gated item); needs its own
// await-holding-lock allowance for the shared proc_lock (see mod tests).
#[allow(clippy::await_holding_lock)]
async fn pidfd_wait_no_fd_leak() {
    // Serialize with the other process-spawning tests (same as do_exec_rooted*
    // in tests below): a concurrent test's tokio runtime owns
    // eventpoll/eventfd/waker fds whose create/teardown windows used to
    // inflate the TOTAL-fd snapshot below into false "leak" failures under
    // parallel test execution.
    let _guard = crate::test_sync::proc_lock();
    // NB: pidfd_enabled() is OnceLock-cached process-wide, so if an earlier
    // test already read it, this set_var cannot change the cached value — on
    // a normal test host the cache resolves to true anyway (no warden.pidfd=0
    // on the host cmdline). Restore the env no matter how the test exits: a
    // leaked WARDEN_PIDFD would pin the switch for every later reader.
    struct PidfdEnvReset;
    impl Drop for PidfdEnvReset {
        fn drop(&mut self) {
            std::env::remove_var("WARDEN_PIDFD");
        }
    }
    let _env_reset = PidfdEnvReset;
    std::env::set_var("WARDEN_PIDFD", "1");
    // pidfd must be live for this guard to mean anything: assert the switch.
    assert!(crate::exec::pidfd_enabled());
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    // Count ONLY the fd classes this guard exists for: pidfds (the historical
    // leak — one RawFd pidfd per exec until warden's io wedged) and exec
    // pipes. Other fd classes (eventpoll/eventfd/socket — tokio runtime
    // internals, /proc/self/fd's own dirfd) churn with concurrently-running
    // tests and say nothing about a pidfd leak.
    let count_guard_fds = || {
        std::fs::read_dir("/proc/self/fd")
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .filter_map(|e| std::fs::read_link(e.path()).ok())
                    .filter(|t| {
                        let s = t.to_string_lossy();
                        s.contains("anon_inode:[pidfd]") || s.starts_with("pipe:")
                    })
                    .count()
            })
            .unwrap_or(0)
    };
    for i in 0..60 {
        let (outcome, _, _) = AgentService::do_exec_rooted(
            &std::ffi::CString::new("/").unwrap(),
            &logger,
            &format!("echo {}", i),
            Instant::now(),
            std::time::Duration::from_secs(10),
            false,
        )
        .await
        .expect("exec");
        match outcome {
            ExecOutcome::Done(r) => assert_eq!(r.exit_code, 0),
            ExecOutcome::TimedOut(_) => panic!("must not time out"),
        }
    }
    // Wait for AsyncFd drops / drain-pipe teardown to settle — as a bounded
    // POLL, not a fixed-sleep bet. A single 200ms grace raced the last exec's
    // drain-pipe pair closing (an asynchronous drop on another thread): under
    // shifted host timing (e.g. right after a heavy deploy phase) the pair was
    // still open at scan time, counting 2 of the test's own capture pipe ends
    // + 2 drain ends = 4 > 3, a FALSE leak (60 execs leaked zero pidfds — no
    // accumulation). Poll up to 3s for the at-rest state instead.
    let mut after = count_guard_fds();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while after > 3 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        after = count_guard_fds();
    }
    eprintln!("guard fds (pidfd+pipe) after loop = {}", after);
    for e in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let tgt = std::fs::read_link(e.path()).unwrap_or_default();
        eprintln!("  fd {} -> {}", name, tgt.display());
    }
    // At rest there must be no lingering pidfd and at most the last exec's
    // pair of drain pipes plus the test's own captured-output pipe (2 ends).
    // A per-exec pidfd leak (the regression this guards: 60 execs → 60 pidfds)
    // cannot hide here — it would exceed the bound by 60 no matter how long
    // we poll.
    assert!(after <= 3, "fd leak: {} lingering pidfd/pipe fds", after);
}
