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
// Sandswap warden — PID 1 entry point.
// Boots as init (PID 1) inside the microVM: base mounts (proc/sys/dev),
// hostname, logger, guest eth0 setup (netlink), SIGCHLD reaper, then the raw
// vsock server on port 1024 that serves mount/unmount/exec. On server exit the
// VM is powered off. Sandswap is a pure chroot executor.

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate slog;

use anyhow::{anyhow, Context, Result};
use clap::{AppSettings, Parser};
use nix::fcntl::OFlag;
use nix::unistd::{self, dup, Pid};
use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::process::exit;
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::Arc;
use tokio::sync::{watch::Receiver, Mutex};
use tokio::task::JoinHandle;
use tracing::{instrument, span};

mod auth;
mod config;
mod exec;
mod exec_cgroup;
mod files;
mod logging;
mod mount;
mod netlink;
mod network;
mod raw_server;
mod residue;
mod sandbox;
mod seccomp;
mod signal;
#[cfg(test)]
// Cross-module test serialization lock (ECHILD protection) — test-only:
// never compiled into the release binary.
#[cfg(test)]
mod test_sync;
mod util;
mod version;

use mount::general_mount;
use sandbox::Sandbox;
use signal::setup_signal_handler;
use slog::{error, o, warn, Logger};

use futures::future::join_all;

const NAME: &str = "warden";

// Parsed agent config, initialized once at startup and read lock-free
// thereafter. lazy_static derefs to &AgentConfig, so hot-path reads
// (crate::AGENT_CONFIG.field) need no RwLock acquisition — the config is
// immutable for the VM's lifetime (kernel cmdline + env are fixed at boot).
// Initialized explicitly after /proc is mounted (see lazy_static::initialize
// in real_main), not on first access, so from_cmdline always sees /proc.
lazy_static! {
    static ref AGENT_CONFIG: AgentConfig =
        AgentConfig::from_cmdline("/proc/cmdline", env::args().collect()).unwrap();
}

#[derive(Parser)]
#[clap(global_setting(AppSettings::DisableVersionFlag))]
struct AgentOpts {
    /// Print the version information
    #[clap(short, long)]
    version: bool,
    #[clap(long)]
    config: Option<String>,
}

// Create a task to read from the logger pipe and forward it to stdout (the
// preferred /dev/console (hvc0 with the current cmdline, captured by the VMM
// into console.log). The reader is the read
// end of a pipe whose write end is the slog async drain's writer.
//
// NB: the former warden.log_vport vsock log listener was REMOVED. It had no
// producer (no deploy path ever set the cmdline param) and no consumer, and an
// enabled listener was an unauthenticated vsock port outside vsockguard's
// port-1024 rule — dead functionality with a live attack surface. Logs go to
// stdout only.
async fn create_logger_task(rfd: RawFd, shutdown: Receiver<bool>) -> Result<()> {
    let mut reader = unsafe { tokio::fs::File::from_raw_fd(rfd) };
    let mut writer = tokio::io::stdout();

    let _ = util::pump_until_shutdown(&mut reader, &mut writer, shutdown).await;

    Ok(())
}

/// Point `fd` at /dev/null (read-only). PID 1 uses this for its stdin so no
/// child can inherit the console; the exec paths use Stdio::null() for the
/// same reason.
fn point_fd_at_devnull(fd: RawFd) -> std::io::Result<()> {
    let null = std::fs::File::open("/dev/null")?;
    let rc = unsafe { libc::dup2(std::os::unix::io::AsRawFd::as_raw_fd(&null), fd) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

async fn real_main(predropped: bool) -> std::result::Result<(), Box<dyn std::error::Error>> {
    env::set_var("RUST_BACKTRACE", "full");
    println!(
        "enter real main at:{}",
        moniclock::Clock::new().elapsed().as_millis()
    );

    let mut tasks: Vec<JoinHandle<Result<()>>> = vec![];

    // vsock log: a pipe whose write end is the slog drain's writer, read end
    // forwarded by create_logger_task.
    let (rfd, wfd) = unistd::pipe2(OFlag::O_CLOEXEC)?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(true);

    let init_mode = unistd::getpid() == Pid::from_raw(1);

    if init_mode {
        let newwfd = dup(wfd)?;
        let writer = unsafe { File::from_raw_fd(newwfd) };

        // Temporary logger used before /proc/cmdline is parsed for the log level.
        let (logger, logger_async_guard) = logging::create_logger(slog::Level::Info, writer);

        general_mount(&logger).map_err(|e| {
            error!(logger, "fail general mount: {}", e);
            e
        })?;

        // Kill-chain layer 2: the busybox hot-bind source must not be writable
        // by an escaped tenant (uid 0, no caps) — otherwise one escape becomes
        // cross-tenant delivery to every later tenant in this VM. Boot-time
        // only; the mount path reads an atomic, never a syscall.
        mount::setup_busybox_source(&logger);

        // Close the capability-free kernel-information channels (kptr
        // restrictions, dmesg, perf, unprivileged BPF, Yama) before any agent
        // can run. Best-effort per knob; /proc is mounted by general_mount.
        mount::harden_kernel_sysctls().map_err(|e| {
            error!(logger, "kernel sysctl hardening failed: {}", e);
            e
        })?;

        // Pin the warden out of the OOM killer's victim set. PID 1 is already
        // exempt from selection (is_global_init), so this is belt-and-braces:
        // it makes the guarantee explicit and survives any future non-init
        // deployment shape. Requires /proc (mounted just above); best-effort.
        if let Err(e) = std::fs::write("/proc/self/oom_score_adj", b"-1000") {
            warn!(logger, "oom_score_adj pin failed: {}", e);
        }

        // Hide PID 1 from same-uid ptrace-gated /proc access. Agent execs run
        // as the SAME uid 0 in the SAME pid namespace, so without this every
        // ptrace-checked /proc/1 entry (mem, root, fd, maps, environ,
        // task/N/*) is reachable by exec'd code whenever the guest kernel's
        // Yama allows it (ptrace syscall and process_vm_* are already denied
        // by seccomp, but /proc/1/mem goes through open+read+write — seccomp
        // cannot block those). PR_SET_DUMPABLE=0 makes the kernel deny all of
        // them to callers without CAP_SYS_PTRACE (which no exec profile keeps
        // in its bounding set), independent of guest kernel Yama config.
        // Failure is FATAL: without dumpable=0 every same-uid agent process can
        // open /proc/1/mem|root|fd and read the initramfs and session key. A
        // warden that cannot enforce this must not serve tenants; exiting as
        // PID 1 kills the VM, which the pool replaces.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) } < 0 {
            error!(
                logger,
                "PR_SET_DUMPABLE=0 failed: {} — refusing to start (PVM would be same-uid readable)",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
        let dumpable = unsafe {
            libc::prctl(
                libc::PR_GET_DUMPABLE,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if let Err(dumpable) = dumpable_check(|| dumpable) {
            error!(
                logger,
                "PR_SET_DUMPABLE=0 did not take effect (PR_GET_DUMPABLE={dumpable}) — refusing to start"
            );
            std::process::exit(1);
        }
        // Surface the remaining dependency explicitly: with dumpable=0 the
        // warden is protected regardless, but a Yama-disabled guest kernel
        // means every OTHER same-uid hardening assumption is weaker — the
        // operator should see it once at boot.
        let yama_scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok());
        if yama_scope_unsafe(yama_scope) {
            warn!(
                logger,
                "guest kernel yama/ptrace_scope is {} — Yama absent or permissive; warden relies solely on PR_SET_DUMPABLE=0 for /proc/1 isolation",
                match yama_scope {
                    Some(v) => v.to_string(),
                    None => "unavailable".to_string(),
                }
            );
        }

        // PID 1's stdin is the console (hvc0). Nothing in the warden reads
        // it, and leaving it open hands every inherited child a console
        // descriptor; the exec paths already use Stdio::null(), and this
        // makes the warden's own fd 0 equally inert.
        if let Err(e) = point_fd_at_devnull(0) {
            warn!(logger, "failed to point PID 1 fd 0 at /dev/null: {}", e);
        }

        // Parse the config now that /proc is mounted (from_cmdline reads
        // /proc/cmdline). Published via lazy_static for lock-free reads.
        lazy_static::initialize(&AGENT_CONFIG);
        init_agent_as_init(&logger)?;
        // Snapshot the warden's own scheduling/limit attributes BEFORE any
        // agent can run: the same-uid agent can retune PID 1's nice/affinity/
        // policy (and lower its rlimits) with no capability, and the unmount
        // restore must know the pre-agent values (see residue::attrs).
        residue::attrs::init_warden_attrs();
        // Freeze the boot-time memory hardening knobs (both need
        // /proc/meminfo; both log their outcome — see exec_cgroup).
        exec_cgroup::init_sync_rlimit_cap();
        exec_cgroup::init_tmpfs_size();
        drop(logger_async_guard);
    } else {
        lazy_static::initialize(&AGENT_CONFIG);
        // Test/host process path: same freezes (meminfo of the host we run on).
        exec_cgroup::init_sync_rlimit_cap();
        exec_cgroup::init_tmpfs_size();
    }

    let config: &AgentConfig = &AGENT_CONFIG;

    let log_handle = tokio::spawn(create_logger_task(rfd, shutdown_rx.clone()));
    tasks.push(log_handle);

    let writer = unsafe { File::from_raw_fd(wfd) };

    // Recreate the logger with the level from /proc/cmdline.
    let (logger, logger_async_guard) = logging::create_logger(config.log_level, writer);

    // Cap the exec hot path: drop PID 1's capability bounding set down to the
    // INSTALL_CAPS baseline (done in main() BEFORE the tokio worker threads
    // spawn — see the comment there for why the ordering is load-bearing).
    // Children inherit the bounding set across fork, so the per-exec pre_exec
    // sweep shrinks from ~40 PR_CAPBSET_DROP prctls to 10 (Strict) / 0
    // (Install) with an IDENTICAL end state on execve (the bounding set only
    // constrains execve-time acquisition; warden's own effective caps —
    // mounts, cgroupfs — are unaffected, and warden never execve's anything
    // needing more than the baseline). Any failure falls back to the
    // conservative per-exec full sweep.
    if init_mode {
        if predropped {
            info!(
                logger,
                "exec bounding set pre-dropped to install-cap baseline (10 caps)"
            );
        } else {
            warn!(
                logger,
                "exec bounding set pre-drop failed; exec children fall back to the full sweep"
            );
        }
    }

    let global_logger = slog_scope::set_global_logger(logger.new(o!()));
    global_logger.cancel_reset();

    // Redirect log crate calls to slog only when full trace is requested.
    if config.log_level == slog::Level::Trace {
        let _ = slog_stdlog::init();
    }

    let root_span = span!(tracing::Level::TRACE, "root-span");
    let span_guard = root_span.enter();
    println!(
        "start sandbox at:{}",
        moniclock::Clock::new().elapsed().as_millis()
    );

    start_sandbox(&logger, config, init_mode, &mut tasks, shutdown_rx.clone()).await?;

    // NOP logger for the shutdown tail so local crate log calls don't fail.
    let global_logger_guard2 = slog_scope::set_global_logger(logging::discard_logger());
    global_logger_guard2.cancel_reset();

    drop(logger_async_guard);

    shutdown_tx
        .send(true)
        .map_err(|e| anyhow!(e).context("failed to request shutdown"))?;

    let results = join_all(tasks).await;

    drop(span_guard);
    drop(root_span);

    eprintln!("{} shutdown complete", NAME);

    let mut wait_errors: Vec<tokio::task::JoinError> = vec![];
    for result in results {
        if let Err(e) = result {
            eprintln!("wait task error: {:#?}", e);
            wait_errors.push(e);
        }
    }

    if wait_errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("wait all tasks failed: {:#?}", wait_errors).into())
    }
}

/// Power the VM off when running as PID 1. As PID 1, a plain exit only
/// panics the kernel ("Attempted to kill init") and HANGS the VM until the
/// sandlot's health probes fail — the power-off makes sandvmm exit and the
/// host reclaim the node immediately (mirrors start_sandbox's handling of a
/// serve() failure and the countdown's POWER_OFF). No-op in non-init runs
/// (tests, host processes).
fn power_off_if_init() {
    if unistd::getpid() == Pid::from_raw(1) {
        unsafe {
            let _ = libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    }
}

/// Whether the guest kernel's Yama ptrace_scope leaves same-uid attach open:
/// None (kernel without CONFIG_SECURITY_YAMA, or the sysctl unreadable) and
/// any value < 1 both count. With PR_SET_DUMPABLE=0 set this is informational
/// only — the dumpable gate alone denies every ptrace-checked /proc/1 entry
/// to callers without CAP_SYS_PTRACE. Extracted as a pure function for tests.
fn yama_scope_unsafe(scope: Option<i32>) -> bool {
    match scope {
        Some(v) => v < 1,
        None => true,
    }
}

/// dumpable_check enforces the PID-1 dumpability contract: 0 = protected,
/// anything else = refuse to start. Split from the prctl call so the readback
/// rule itself is unit-testable (a warn-only regression must fail a test).
fn dumpable_check(get: impl FnOnce() -> libc::c_int) -> std::result::Result<(), libc::c_int> {
    match get() {
        0 => Ok(()),
        other => Err(other),
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // try_parse (not parse): clap's parse() EXITS the process on a malformed
    // argv, which as PID 1 skips every POWER_OFF path below and leaves a
    // hung VM. Route the failure through the same power-off tail instead.
    let args = match AgentOpts::try_parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("warden: {}", e);
            power_off_if_init();
            exit(2);
        }
    };

    if args.version {
        println!(
            "{} {} ({}) built at {}",
            version::WARDEN_NAME,
            version::WARDEN_VERSION,
            version::VERSION_COMMIT,
            version::BUILD_TIME,
        );
        exit(0);
    }

    println!(
        "agent start at:{}",
        moniclock::Clock::new().elapsed().as_millis()
    );

    compiler_fence(Ordering::SeqCst);

    // Group-writable defaults (umask 0002): guest-created files land 0664 and
    // directories 0775 on the host-side share (owner sandvmm, group sandlot),
    // so the storage-plane identity (sandprov, group sandlot) can remove them
    // at sandfs deletion — the same group-access convention the prov instance
    // already applies to template-seeded content. Explicit modes from the
    // agent are untouched (umask only shapes defaults; mkdir(path, 0700)
    // still lands 0700); deliberately restrictive modes that DO block
    // deletion are converged by the prov side's orphan-rename fallback. Set
    // once here at PID 1: every exec inherits it — zero per-command cost.
    unsafe { libc::umask(0o002) };

    // Pre-drop the capability bounding set BEFORE the tokio runtime spawns its
    // worker threads. PR_CAPBSET_DROP mutates the calling thread's credentials
    // only; threads clone a credential snapshot at spawn. A pre-drop after
    // Builder::build() would therefore cover just the one worker that ran it,
    // leaving every other worker forking exec children with the FULL bounding
    // set while PARENT_CAP_BASELINE makes those children skip their own sweep
    // (Install profile: nothing dropped; Strict: only the 10 dropped) — a
    // silent capability-leak regression caught by e2e/seccomp.sh. Here the
    // pre-drop is inherited by every worker, so all exec children start from
    // the reduced set. PID 1 only (a non-init run must not mutate its own
    // bounding set); the outcome is logged in real_main where the logger
    // exists.
    let predropped = if unistd::getpid() == Pid::from_raw(1) {
        exec::predrop_parent_bounding_set()
    } else {
        false
    };

    let rt: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // catch_unwind: a panic on the main task (anything under block_on, e.g.
    // a config unwrap or the serve loop) would otherwise unwind straight out
    // of main — the same "PID 1 dies without POWER_OFF → VM hangs" shape as
    // the exit() paths above. Panics inside SPAWNED tasks stay contained by
    // tokio (surface as JoinError, never killing PID 1) and are intentionally
    // NOT fatal.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(real_main(predropped))
    }));
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            eprintln!("warden fatal: {:#?}", e);
            power_off_if_init();
            std::process::exit(1);
        }
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic>".to_string());
            eprintln!("warden panicked on the main task: {}", msg);
            power_off_if_init();
            std::process::exit(101);
        }
    }
}

#[instrument]
async fn start_sandbox(
    logger: &Logger,
    config: &AgentConfig,
    init_mode: bool,
    tasks: &mut Vec<JoinHandle<Result<()>>>,
    shutdown: Receiver<bool>,
) -> Result<()> {
    let s = Sandbox::new(logger).context("Failed to create sandbox")?;
    if init_mode {
        s.rtnl.handle_localhost().await?;

        // Configure the guest's static eth0 (Sandswap bridge+NAT backend) from
        // the warden.net_* cmdline params. Best-effort: a VM without
        // warden.net_ip stays offline. Logged, not fatal.
        if let Err(e) = network::setup_guest_network(logger.clone(), config).await {
            warn!(logger, "guest network setup failed: {}", e);
        }
    }

    let sandbox = Arc::new(Mutex::new(s));

    let signal_handler_task = tokio::spawn(setup_signal_handler(logger.clone(), shutdown.clone()));
    tasks.push(signal_handler_task);

    println!(
        "rpc start at:{}",
        moniclock::Clock::new().elapsed().as_millis()
    );
    // Raw vsock protocol: the accept loop on port 1024 runs inline. It does
    // not return under normal operation — the VM is terminated either by the
    // warden countdown (POWER_OFF from the countdown task when a mount is
    // stale and heartbeats have stopped) or by the sandlot destroying the VM.
    // If serve returns at all (e.g. bind failure, a future graceful-exit
    // path), power the VM off so sandvmm exits and the host reclaims the
    // sandfs mount — a lingering PID 1 would hang the VM (kernel panic on
    // init death) and keep the mount stuck.
    if let Err(e) = raw_server::serve(sandbox.clone(), raw_server::PORT).await {
        error!(logger, "raw vsock server exited with error: {}", e);
    }

    let ret = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
    if ret != 0 {
        error!(logger, "shutdown vm failed, ret:{}", ret);
    }

    Ok(())
}

// init_agent_as_init does PID-1 initialization: PATH + hostname. Sandswap skips
// cgroup mounts and tty/ptmx setup — headless chroot execution needs none.
fn init_agent_as_init(logger: &Logger) -> Result<()> {
    let _ = logger;

    env::set_var("PATH", "/bin:/sbin:/usr/bin:/usr/sbin");

    let contents =
        std::fs::read_to_string("/etc/hostname").unwrap_or_else(|_| String::from("localhost"));
    let hostname = contents.split(' ').next().unwrap_or("localhost").trim();

    let _ = unistd::sethostname(OsStr::new(hostname));

    Ok(())
}

use crate::config::AgentConfig;

#[cfg(test)]
mod tests {
    use super::*;

    // The fd0 redirect used at PID 1 boot must actually point the descriptor
    // at /dev/null (a spare fd here, so the test process's stdin is untouched).
    #[test]
    fn point_fd_at_devnull_redirects_a_descriptor() {
        let spare = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 50) };
        if spare < 0 {
            panic!("F_DUPFD_CLOEXEC: {}", std::io::Error::last_os_error());
        }
        point_fd_at_devnull(spare).expect("point fd at /dev/null");
        let link = std::fs::read_link(format!("/proc/self/fd/{spare}")).expect("readlink");
        unsafe { libc::close(spare) };
        assert_eq!(link.to_string_lossy(), "/dev/null");
    }

    use super::yama_scope_unsafe;

    #[test]
    fn dumpable_zero_is_required() {
        assert!(dumpable_check(|| 0).is_ok());
        assert_eq!(dumpable_check(|| 1), Err(1));
    }

    #[test]
    fn yama_scope_safety_thresholds() {
        // Absent/unreadable Yama and scope 0 are "unsafe" (attach allowed for
        // same-uid); scope >= 1 restricts attach to ancestor relationships.
        assert!(yama_scope_unsafe(None));
        assert!(yama_scope_unsafe(Some(0)));
        assert!(!yama_scope_unsafe(Some(1)));
        assert!(!yama_scope_unsafe(Some(3)));
    }
}
