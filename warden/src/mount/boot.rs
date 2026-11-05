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

//! Boot-time guest mounts and cgroup setup: the warden's own /proc, /sys,
//! /dev, the read-only busybox hot-bind source, and the cgroup2 mount the
//! per-agent memory cap and switch-time clearing depend on.

use anyhow::{anyhow, Context, Result};
use lazy_static::lazy_static;
use nix::mount::MsFlags;
use slog::{debug, error, info, o, Logger};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Instant;
use tracing::instrument;

#[rustfmt::skip]
lazy_static! {
    pub static ref FLAGS: HashMap<&'static str, (bool, MsFlags)> = {
        let mut m = HashMap::new();
        m.insert("defaults",      (false, MsFlags::empty()));
        m.insert("ro",            (false, MsFlags::MS_RDONLY));
        m.insert("rw",            (true,  MsFlags::MS_RDONLY));
        m.insert("suid",          (true,  MsFlags::MS_NOSUID));
        m.insert("nosuid",        (false, MsFlags::MS_NOSUID));
        m.insert("dev",           (true,  MsFlags::MS_NODEV));
        m.insert("nodev",         (false, MsFlags::MS_NODEV));
        m.insert("exec",          (true,  MsFlags::MS_NOEXEC));
        m.insert("noexec",        (false, MsFlags::MS_NOEXEC));
        m.insert("sync",          (false, MsFlags::MS_SYNCHRONOUS));
        m.insert("async",         (true,  MsFlags::MS_SYNCHRONOUS));
        m.insert("dirsync",       (false, MsFlags::MS_DIRSYNC));
        m.insert("remount",       (false, MsFlags::MS_REMOUNT));
        m.insert("mand",          (false, MsFlags::MS_MANDLOCK));
        m.insert("nomand",        (true,  MsFlags::MS_MANDLOCK));
        m.insert("atime",         (true,  MsFlags::MS_NOATIME));
        m.insert("noatime",       (false, MsFlags::MS_NOATIME));
        m.insert("diratime",      (true,  MsFlags::MS_NODIRATIME));
        m.insert("nodiratime",    (false, MsFlags::MS_NODIRATIME));
        m.insert("bind",          (false, MsFlags::MS_BIND));
        m.insert("rbind",         (false, MsFlags::MS_BIND | MsFlags::MS_REC));
        m.insert("unbindable",    (false, MsFlags::MS_UNBINDABLE));
        m.insert("runbindable",   (false, MsFlags::MS_UNBINDABLE | MsFlags::MS_REC));
        m.insert("private",       (false, MsFlags::MS_PRIVATE));
        m.insert("rprivate",      (false, MsFlags::MS_PRIVATE | MsFlags::MS_REC));
        m.insert("shared",        (false, MsFlags::MS_SHARED));
        m.insert("rshared",       (false, MsFlags::MS_SHARED | MsFlags::MS_REC));
        m.insert("slave",         (false, MsFlags::MS_SLAVE));
        m.insert("rslave",        (false, MsFlags::MS_SLAVE | MsFlags::MS_REC));
        m.insert("relatime",      (false, MsFlags::MS_RELATIME));
        m.insert("norelatime",    (true,  MsFlags::MS_RELATIME));
        m.insert("strictatime",   (false, MsFlags::MS_STRICTATIME));
        m.insert("nostrictatime", (true,  MsFlags::MS_STRICTATIME));
        m
    };
}

#[derive(Debug, PartialEq)]
pub struct InitMount<'a> {
    pub(crate) fstype: &'a str,
    pub(crate) src: &'a str,
    pub(crate) dest: &'a str,
    pub(crate) options: Vec<&'a str>,
}

#[rustfmt::skip]
lazy_static! {
    // Sandswap: minimal mounts for a chroot-execution warden. proc is needed to
    // parse /proc/cmdline (config); devtmpfs provides /dev device nodes;
    // sysfs backs /sys device probing.
    pub static ref INIT_ROOTFS_MOUNTS: Vec<InitMount<'static>> = vec![
        InitMount{fstype: "proc", src: "proc", dest: "/proc", options: vec!["nosuid", "nodev", "noexec"]},
        InitMount{fstype: "sysfs", src: "sysfs", dest: "/sys", options: vec!["nosuid", "nodev", "noexec"]},
        InitMount{fstype: "devtmpfs", src: "dev", dest: "/dev", options: vec!["nosuid"]},
    ];
}

/// Low-level mount helper. Wraps nix::mount::mount with validation + timing.
pub fn baremount(
    source: &Path,
    destination: &Path,
    fs_type: &str,
    flags: MsFlags,
    options: &str,
    logger: &Logger,
) -> Result<()> {
    if source.as_os_str().is_empty() {
        return Err(anyhow!("need mount source"));
    }
    if destination.as_os_str().is_empty() {
        return Err(anyhow!("need mount destination"));
    }
    if fs_type.is_empty() {
        return Err(anyhow!("need mount FS type"));
    }

    debug!(
        logger,
        "bare mount {} to {} fs:{} flags:{:?}, opt:{}",
        source.display(),
        destination.display(),
        fs_type,
        flags,
        options
    );
    let start = Instant::now();
    let res = nix::mount::mount(
        Some(source),
        destination,
        Some(fs_type),
        flags,
        Some(options),
    )
    .map_err(|e| anyhow!("mount failed: {}", e));

    let duration = start.elapsed().as_millis();
    if duration > 10 {
        info!(
            logger,
            "mount {:?} to {:?} cost: {}ms", source, destination, duration
        );
    }

    res
}

/// Looks for `mount_point` entry in the /proc/mounts.
#[instrument]
pub fn is_mounted(mount_point: &str) -> Result<bool> {
    let mount_point = mount_point.trim_end_matches('/');
    let found = fs::metadata(mount_point).is_ok()
        // Looks through /proc/mounts and check if the mount exists
        && fs::read_to_string("/proc/mounts")?
            .lines()
            .any(|line| {
                // The 2nd column reveals the mount point.
                line.split_whitespace()
                    .nth(1)
                    .map(|target| mount_point.eq(target))
                    .unwrap_or(false)
            });

    Ok(found)
}

#[instrument]
pub(crate) fn parse_mount_flags_and_options(options_vec: Vec<&str>) -> (MsFlags, String) {
    let mut flags = MsFlags::empty();
    let mut options: String = "".to_string();

    for opt in options_vec {
        if !opt.is_empty() {
            match FLAGS.get(opt) {
                Some(x) => {
                    let (clear, f) = *x;
                    if clear {
                        flags &= !f;
                    } else {
                        flags |= f;
                    }
                }
                None => {
                    if !options.is_empty() {
                        options.push_str(format!(",{}", opt).as_str());
                    } else {
                        options.push_str(opt.to_string().as_str());
                    }
                }
            };
        }
    }
    (flags, options)
}

// add_storages takes a list of storages passed by the caller, and perform the
// associated operations such as waiting for the device to show up, and mount
// it to a specific location, according to the type of handler chosen, and for
// each storage.
#[instrument]
fn mount_to_rootfs(logger: &Logger, m: &InitMount) -> Result<()> {
    let options_vec: Vec<&str> = m.options.clone();

    let (flags, options) = parse_mount_flags_and_options(options_vec);

    fs::create_dir_all(Path::new(m.dest)).context("could not create directory")?;

    let source = Path::new(m.src);
    let dest = Path::new(m.dest);

    baremount(source, dest, m.fstype, flags, &options, logger).or_else(|e| {
        if m.src != "dev" {
            return Err(e);
        }

        Ok(())
    })?;

    Ok(())
}

#[instrument]
pub fn general_mount(logger: &Logger) -> Result<()> {
    let logger = logger.new(o!("subsystem" => "mount"));

    for m in INIT_ROOTFS_MOUNTS.iter() {
        mount_to_rootfs(&logger, m)?;
    }

    // Ensure cgroup2 is mounted and the memory controller is enabled.
    // Required for: (1) per-agent memory cap (OOM A), (2) agent-switch clearing
    // (cgroup.kill). Without this, AgentCgroup::create returns Ok(None) and
    // kill_and_reap is skipped — background execs survive unmount.
    ensure_cgroup2(&logger)?;

    Ok(())
}

// The warden's busybox hot-bind source. The initramfs copy at /bin/busybox
// is writable by guest root (mode 0755, owner uid 0), so a future chroot
// escape could overwrite it and the NEXT tenant in this
// VM would execute the poisoned binary through the hot-bind — a cross-tenant
// payload needing no second escape. At boot the warden copies the binary
// onto a small read-only tmpfs; every exec profile drops CAP_SYS_ADMIN and
// seccomp denies the mount family, so an escaped tenant can neither write the
// source (EROFS) nor remount it rw (EPERM). FATAL: a boot that cannot build
// the read-only source refuses to start (see setup_busybox_source) — there is
// no writable fallback, and every mount reads BUSYBOX_SOURCE_RO.
pub(crate) const BUSYBOX_SOURCE_DIR: &str = "/warden-bin";
pub(crate) const BUSYBOX_SOURCE_RO: &str = "/warden-bin/busybox";
/// The copy SOURCE (the initramfs busybox). Only ever read to build the
/// read-only tmpfs copy above; it is never bound into an agent tree.
pub(crate) const BUSYBOX_SOURCE_INITRAMFS: &str = "/bin/busybox";

/// setup_busybox_source — boot-time (init mode) hardening of the hot-bind
/// source. FATAL, not best-effort: without the read-only source the hot bind
/// would have to hand the tenant the writable initramfs copy, re-opening the
/// cross-tenant busybox delivery path. The boot refuses — PID 1 powers the VM
/// off (a bare exit as PID 1 only panics the kernel and hangs the VM), so the
/// sandvmm exits and the pool replaces the VM.
pub fn setup_busybox_source(logger: &Logger) {
    let logger = logger.new(o!("subsystem" => "mount"));
    match prepare_busybox_source(&logger) {
        Ok(()) => {}
        Err(e) => {
            error!(
                logger,
                "busybox RO source unavailable ({}): refusing to start — the hot-bind must never fall back to the writable initramfs copy",
                e
            );
            // A plain exit as PID 1 only panics the kernel ("Attempted to
            // kill init") and HANGS the VM with the sandvmm alive and the
            // virtio-fs share mounted; POWER_OFF drives the ACPI S5 path so
            // sandvmm exits and the host reclaims the node. The bare exit is
            // the fallback for a non-init invocation (tests, host runs).
            if std::process::id() == 1 {
                unsafe {
                    let _ = libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
                }
            }
            std::process::exit(1);
        }
    }
}

/// Build the read-only hot-bind source and emit the boot evidence line.
/// Split out from `setup_busybox_source` so the failure half is unit-testable
/// (the caller turns Err into the refused boot).
fn prepare_busybox_source(logger: &Logger) -> Result<()> {
    setup_ro_tmpfs_source(
        BUSYBOX_SOURCE_DIR,
        BUSYBOX_SOURCE_INITRAMFS,
        BUSYBOX_SOURCE_RO,
    )?;
    // Boot-time only (once per VM), not on the measured mount path.
    // The smoke gate asserts this positive line: a stale warden that
    // predates the layer emits neither it nor the failure error, so a
    // warn-only gate would pass vacuously.
    info!(
        logger,
        "busybox hot-bind source is read-only at {}", BUSYBOX_SOURCE_RO
    );
    Ok(())
}

/// Copy `source` onto a fresh tmpfs at `dir`, then remount it read-only.
/// Split out so the root-gated test can drive it on a throwaway directory.
pub(crate) fn setup_ro_tmpfs_source(dir: &str, source: &str, dest: &str) -> Result<()> {
    // The mountpoint is created with the initramfs (build time), not here:
    // the warden must not run a following create_dir_all on a path derived
    // from runtime state (the path-safety gate).
    if !Path::new(dir).is_dir() {
        return Err(anyhow!("mountpoint {} does not exist", dir));
    }
    // Size the tmpfs from the source instead of a hard-coded cap; keep a
    // small floor for filesystem overhead.
    let len = fs::metadata(source)
        .with_context(|| format!("stat {}", source))?
        .len();
    let size_mb = std::cmp::max(8, (len.saturating_mul(2) + (1 << 20) - 1) >> 20);
    let opts = format!("size={}m,mode=0755", size_mb);
    nix::mount::mount(
        Some(Path::new("tmpfs")),
        Path::new(dir),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(opts.as_str()),
    )
    .with_context(|| format!("mount tmpfs at {}", dir))?;
    // Never leave a partially populated or still-writable source behind: on
    // any failure the tmpfs is unmounted and the caller falls back.
    let setup = (|| -> Result<()> {
        fs::copy(source, dest).with_context(|| format!("copy {} -> {}", source, dest))?;
        let mut perms = fs::metadata(dest)?.permissions();
        perms.set_mode(0o555);
        fs::set_permissions(dest, perms)?;
        // A remount replaces the flag set; keep the initial nosuid/nodev.
        nix::mount::mount::<Path, Path, str, str>(
            None,
            Path::new(dir),
            None,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None,
        )
        .with_context(|| format!("remount {} read-only", dir))?;
        Ok(())
    })();
    if setup.is_err() {
        let _ = nix::mount::umount(dir);
    }
    setup
}

/// Pure boot decision: cgroup v2 is REQUIRED. The agent-switch clearing
/// guarantee (cgroup.kill atomically SIGKILLs the whole agent tree, then
/// cgroup.procs is polled empty) exists only on v2; the v1 fallback cannot
/// guarantee it (no cgroup.kill, and a single cgroup.procs read misses
/// processes forked after it). A warden that cannot enforce the switch
/// invariant must not serve tenants, so the check fails closed — the caller
/// turns this into a refused boot (PID 1 exits, the VM is powered off and
/// replaced). Extracted for the error-path unit test.
fn require_cgroup_v2(v2_mounted: bool) -> Result<()> {
    if v2_mounted {
        return Ok(());
    }
    Err(anyhow!(
        "cgroup v2 is not mounted at /sys/fs/cgroup: the warden requires cgroup v2 \
         for agent-switch process clearing (cgroup.kill); cgroup v1 is not supported — \
         refusing to start"
    ))
}

/// Mount cgroup2 and enable the memory controller.
///
/// REQUIRED, not best-effort: when cgroup2 cannot be mounted (kernel without
/// CONFIG_CGROUPS, cgroup v1 hierarchy, mount failure) the warden refuses to
/// start rather than losing cgroup.kill agent-switch clearing. When
/// agent_mem_percent=0, the cgroup is still created (for cgroup.kill) but
/// memory.max is skipped.
fn ensure_cgroup2(logger: &Logger) -> Result<()> {
    let cg_root = Path::new("/sys/fs/cgroup");
    // The memory controller is only enabled when a cap will actually be set:
    // warden.agent_mem_percent=0 means "no memory cap", so the agent cgroup is
    // bare (kill-only) and no controller is enabled in subtree_control.
    let enable_memory = crate::AGENT_CONFIG.agent_mem_percent > 0;

    // Already mounted? (kernel auto-mount or prior call)
    if is_mounted("/sys/fs/cgroup")? {
        // Ensure memory controller is enabled in subtree_control.
        // A fresh cgroup2 mount has no controllers enabled by default.
        if enable_memory {
            let _ = fs::write(cg_root.join("cgroup.subtree_control"), b"+memory");
        }
    } else {
        fs::create_dir_all(cg_root).context("create /sys/fs/cgroup")?;
        baremount(
            Path::new("cgroup2"),
            cg_root,
            "cgroup2",
            MsFlags::empty(),
            "",
            logger,
        )
        .context("mount cgroup2")?;

        // Enable memory controller so AgentCgroup::create can set memory.max.
        if enable_memory {
            let _ = fs::write(cg_root.join("cgroup.subtree_control"), b"+memory");
            info!(logger, "cgroup2 mounted, memory controller enabled");
        } else {
            info!(
                logger,
                "cgroup2 mounted, memory controller disabled (mem_percent=0)"
            );
        }
    }

    // An existing mount could be the v1 hierarchy (or a hybrid without the
    // unified controller file): verify v2 before serving anything.
    require_cgroup_v2(crate::exec_cgroup::is_cgroup_v2())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_cgroup_v2_accepts_v2_and_refuses_v1() {
        assert!(require_cgroup_v2(true).is_ok());
        let err = require_cgroup_v2(false).expect_err("cgroup v1 must be refused");
        let msg = format!("{:#}", err);
        // The refusal must name the mechanism and the action, not just fail.
        assert!(msg.contains("cgroup v2"), "message: {msg}");
        assert!(msg.contains("cgroup.kill"), "message: {msg}");
        assert!(msg.contains("refusing to start"), "message: {msg}");
    }

    #[test]
    fn ro_busybox_source_failure_is_an_error() {
        // The writable initramfs copy must never be an accepted fallback: a
        // source setup that cannot build the read-only tmpfs copy has to
        // return Err, which setup_busybox_source turns into a refused boot
        // (PID 1 exits). On a normal host the mountpoint is absent (it exists
        // only in the guest initramfs), so the setup fails before any mount.
        if Path::new(BUSYBOX_SOURCE_DIR).exists() {
            eprintln!(
                "skipping: {} exists on this host (guest-only path)",
                BUSYBOX_SOURCE_DIR
            );
            return;
        }
        let logger = Logger::root(slog::Discard, slog::o!());
        let err = prepare_busybox_source(&logger)
            .expect_err("a missing read-only source mountpoint must fail the boot preparation");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("does not exist"),
            "the refusal must name the missing mountpoint: {msg}"
        );
        assert!(
            !msg.contains("falling back"),
            "the writable copy must not be accepted as a fallback: {msg}"
        );
    }
}
