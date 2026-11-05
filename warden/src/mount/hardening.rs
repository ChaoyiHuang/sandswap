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

//! Workspace hardening mounts and their teardown twins: the read-only bind
//! family, the RAM-backed busybox hot-bind, masked /proc, minimal /dev,
//! per-attachment resolv.conf, and the defensive umount helper everything
//! else tears down through.

use anyhow::{anyhow, Result};
use nix::errno::Errno;
use nix::mount::MsFlags;
use nix::sys::stat;
use slog::{debug, warn, Logger};
use std::ffi::CString;
use std::fs;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use crate::mount::anchor::RootAnchor;
use crate::mount::boot::{baremount, BUSYBOX_SOURCE_RO};
use crate::mount::workspace::note_fuse_op;
use crate::mount::MOUNT_POINT;

/// The read-only remount flags, extracted so the composition is unit-testable
/// without root (the root-gated `bind_ro_...` test pins the kernel effect).
pub(crate) fn bind_ro_remount_flags() -> MsFlags {
    // RO only. MS_NODEV must NOT be added here: this flag set is shared by
    // the /dev/null proc covers, and nodev on those binds makes a shell's
    // `> /dev/null` fail with EACCES (the cover must stay a usable device).
    // The mount_setattr path (the default on every kernel that has it) only
    // toggles RDONLY and therefore preserves the source mount's inherited
    // nosuid/nodev; the busybox source tmpfs is separately remounted with
    // both flags in mount/boot.rs.
    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY
}

/// Bind `source` over `target` and then remount the bind READ-ONLY in a
/// second step. mount(2) DROPS per-mount flags passed in the same call as
/// MS_BIND (pinned by `share_bind_flags_land_in_mountinfo`), so a one-shot
/// `MS_BIND|MS_RDONLY` leaves the bind read-write; the REMOUNT form really
/// applies and is per-mount — the source and every other bind are unaffected
/// (the kernel checks the same flag at every write-open, the idiom
/// setup_masked_proc already uses for /proc).
///
/// Every WARDEN-OWNED source bound into an agent-visible tree goes through
/// this. The agent's exec runs euid 0 and a bind aliases the SOURCE inode, so
/// a writable alias of a warden file is directly writable by the tenant:
/// The busybox hot-bind is the canonical case: the warden's own /bin/busybox, hot-bound
/// into every tenant's chroot, so a trojan planted by tenant A executed for
/// every later tenant in the same VM (and survived unmount: tmpfs is not
/// cleared by drop_caches). The same class covers the /dev/null proc covers
/// and the resolv.conf fallback file: no exec payload today, but the source
/// belongs to the warden, not to the agent.
///
/// `target` may be an O_PATH fd anchor (`/proc/self/fd/N`, the race-free
/// form); the caller must keep that fd open until this returns.
pub(crate) fn bind_ro(source: &str, target: &str, logger: &Logger) -> Result<()> {
    baremount(
        Path::new(source),
        Path::new(target),
        "none",
        MsFlags::MS_BIND,
        "",
        logger,
    )?;
    let flags = bind_ro_remount_flags();
    nix::mount::mount(Some(target), target, None::<&str>, flags, None::<&str>).map_err(|e| {
        anyhow!(
            "read-only remount of the bind at {} failed: {} — the bind would stay a WRITABLE alias of the warden's file",
            target,
            e
        )
    })
}

/// MOUNT_ATTR_RDONLY, applied with `mount_setattr(2)` + `AT_EMPTY_PATH` on an
/// O_PATH fd: the ONE fd-anchored way to make a bind read-only.
///
/// A path-based `MS_REMOUNT|MS_BIND` cannot do it through a magic link — the
/// kernel answers EINVAL (verified live on the guest kernel: the warden's
/// busybox bind failed exactly this way, and the caller correctly fell back
/// rather than leaving a writable alias). `mount_setattr` acts on the mount
/// CONTAINING the fd's path, with no path re-resolution, so the target stays
/// race-free.
pub(crate) fn mount_setattr_readonly(fd: RawFd) -> std::io::Result<()> {
    #[repr(C)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }
    const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
    const AT_EMPTY_PATH: libc::c_int = 0x1000;
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd,
            b"\0".as_ptr() as *const libc::c_char,
            AT_EMPTY_PATH,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Bind `source` onto the file an O_PATH fd anchors (race-free) and make the
/// resulting mount READ-ONLY.
///
/// `mount_setattr(AT_EMPTY_PATH)` only acts on the root of the mount
/// containing the fd. The fd that anchored the bind predates the bind and is a
/// path on the UNDERLYING mount, so calling mount_setattr on it answers EINVAL
/// (measured). After the bind, the target path must be re-opened and the fd it
/// now resolves to (the topmost mount, i.e. the bind itself) is the one to
/// flip. Only when the kernel has no mount_setattr at all (ENOSYS) does the
/// path-based remount fallback run — it re-resolves the path, so it is the
/// fallback, not the default.
pub(crate) fn bind_ro_fd(
    source: &str,
    target: &fs::File,
    target_path: &str,
    logger: &Logger,
) -> Result<()> {
    let fd_target = format!("/proc/self/fd/{}", target.as_raw_fd());
    baremount(
        Path::new(source),
        Path::new(&fd_target),
        "none",
        MsFlags::MS_BIND,
        "",
        logger,
    )?;

    // Re-open the target AFTER the bind: the path now resolves to the bind
    // mount, whose root is the only fd mount_setattr(AT_EMPTY_PATH) accepts.
    // O_NOFOLLOW keeps a symlink swap from redirecting the flip.
    let c_path = CString::new(target_path.as_bytes())
        .map_err(|_| anyhow!("bind target path contains NUL: {}", target_path))?;
    let reopened = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if reopened < 0 {
        return Err(anyhow!(
            "re-open of bind target {} for the read-only flip failed: {} — refusing to leave a writable alias",
            target_path,
            std::io::Error::last_os_error()
        ));
    }
    let reopened = unsafe { OwnedFd::from_raw_fd(reopened) };
    match mount_setattr_readonly(reopened.as_raw_fd()) {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => debug!(
            logger,
            "mount_setattr unavailable on this kernel ({}), using the path-remount fallback for {}",
            e,
            target_path
        ),
        Err(e) => debug!(
            logger,
            "mount_setattr(AT_EMPTY_PATH) on {} failed ({}), falling back to a path remount",
            target_path,
            e
        ),
    }
    nix::mount::mount(
        Some(target_path),
        target_path,
        None::<&str>,
        bind_ro_remount_flags(),
        None::<&str>,
    )
    .map_err(|e| {
        anyhow!(
            "read-only remount of the bind at {} failed: {} — the bind would stay a WRITABLE alias of the warden's file",
            target_path,
            e
        )
    })
}

/// ④: bind-mount the initramfs (tmpfs) /bin/busybox over the agent rootfs's
/// /bin/busybox so the chrooted /bin/sh is always RAM-backed (no cold read).
///
/// FAIL-CLOSED on the read-only flip: the bind is only acceptable once it is
/// proven read-only. A failed bind/remount leaves either a writable alias of
/// the warden's busybox or no warden binary at all, and neither may be handed
/// to a tenant: the bind is torn down and the caller refuses the mount (the
/// sandlot then destroys the VM). The boot-time RO source is mandatory (the
/// warden refuses to start without it), so there is no writable fallback.
///
/// The documented SKIPS stay skips: a template's usrmerge `bin` symlink and
/// an unsecurable `bin/`/`bin/busybox` mean no bind was attempted, so no
/// warden file is exposed and the agent keeps its own rootfs binary.
pub(crate) fn overlay_hot_busybox(root: &RootAnchor, logger: &Logger) -> Result<()> {
    let host_busybox = BUSYBOX_SOURCE_RO;
    let guest_busybox = "bin/busybox"; // for log messages (relative to the anchor)
                                       // usrmerge rootfs (Ubuntu 24.04): `bin -> usr/bin` is template content.
                                       // Removing it (open_dir's agent-planted guard) would destroy /bin/sh;
                                       // skip the hot bind instead — see merged_usr_bin_symlink.
    if root.symlink_in_rootfs("bin") {
        debug!(
            logger,
            "overlay_hot_busybox: {} is a symlink (template usrmerge content or agent-planted; target stays inside the chroot) — skipping the hot bind",
            guest_busybox
        );
        return Ok(());
    }
    // Both `bin` and `bin/busybox` live under agent-writable paths in flat
    // mode: `bin` may be a planted symlink and `bin/busybox` a symlink whose
    // target would be covered in the WARDEN's namespace. Both are secured
    // relative to the root anchor and mounted THROUGH their fds (race-free).
    let bin_dir = match root.open_dir("bin", logger) {
        Some((_p, fd)) => RootAnchor { fd },
        None => {
            warn!(
                logger,
                "overlay_hot_busybox: bin/ could not be secured (skipping)"
            );
            return Ok(());
        }
    };
    let target = match bin_dir.open_file("busybox", true, logger) {
        Some(f) => f,
        None => {
            warn!(
                logger,
                "overlay_hot_busybox: {} could not be secured (skipping)", guest_busybox
            );
            return Ok(());
        }
    };
    // The bind must be made READ-ONLY — the warden's busybox is the
    // payload every later tenant in this VM executes, and a bare MS_BIND
    // leaves the source inode writable through the agent-visible alias.
    let bound = bind_ro_fd(
        host_busybox,
        &target,
        &format!("{}/{}", MOUNT_POINT, guest_busybox),
        logger,
    );
    // Release the anchor fd before any cleanup umount: an open fd on the file
    // bind makes even our own umount(2) return EBUSY.
    drop(target);
    if let Err(e) = bound {
        // A failed read-only flip must not leave a WRITABLE alias of the
        // warden's busybox behind, and the mount must not proceed on the
        // agent's own binary either: drop the bind and refuse the mount.
        // Fresh snapshot: the cleanup must see a bind this function may have
        // half-created above, so the set is taken HERE, not at entry.
        let guest_busybox_mp = format!("{}/{}", MOUNT_POINT, guest_busybox);
        let mut mounts = MountSet::defensive(Some(logger));
        umount_verified(&guest_busybox_mp, Some(logger), &mut mounts);
        return Err(anyhow!(
            "busybox hot-bind {} -> {} failed: {} — refusing the mount rather than serving a chroot without the read-only warden busybox",
            host_busybox,
            guest_busybox,
            e
        ));
    }
    Ok(())
}

/// inject_guest_resolv_conf writes /etc/resolv.conf into the agent rootfs
/// (mount_point/etc/resolv.conf) from the warden.net_dns cmdline params, so the
/// chrooted agent can resolve DNS. This is required because exec runs chrooted
/// into the agent volume, whose /etc/resolv.conf is otherwise absent — the
/// warden's own /etc/resolv.conf (set at boot) is not visible inside the
/// chroot. Best-effort: any failure is logged and swallowed.
pub(crate) async fn inject_guest_resolv_conf(root: &RootAnchor, logger: &Logger) {
    let dns = crate::AGENT_CONFIG.net_dns.clone();
    if dns.is_empty() {
        // No warden.net_dns configured (offline VM) — leave the agent rootfs as
        // is. A default resolv.conf baked into the rootfs template, if any,
        // stays in place.
        return;
    }
    // `etc` sits in the agent's rootfs (flat mode): secure it against a
    // planted symlink before anything is created or written beneath it.
    let etc_dir = match root.open_dir("etc", logger) {
        Some((_p, fd)) => RootAnchor { fd },
        None => {
            warn!(
                logger,
                "inject_guest_resolv_conf: etc/ could not be secured (skipping)"
            );
            return;
        }
    };
    let content = crate::network::format_resolv_conf(&dns);
    let path = format!("{}/etc/resolv.conf", MOUNT_POINT);
    // Remove any existing bind mount first so a stale mount from a prior agent
    // does not shadow the write/bind below.
    let mut mounts = MountSet::defensive(Some(logger));
    umount_verified(&path, Some(logger), &mut mounts);
    // O_NOFOLLOW write: a planted `etc/resolv.conf -> /…` symlink must never
    // turn into an arbitrary-path truncating write in the warden's namespace.
    match etc_dir.write_file("resolv.conf", content.as_bytes(), logger) {
        Ok(_f) => {
            debug!(
                logger,
                "inject_guest_resolv_conf: wrote {} (dns={:?})", path, dns
            );
        }
        Err(e) => {
            // Write failed — most likely the read-only overlay rootfs (EROFS):
            // overlay mode mounts /mnt/rootfs read-only, so a direct write to
            // /etc/resolv.conf is rejected. Fall back to a bind mount from a
            // warden-side tmpfs file. A bind mount is a namespace operation,
            // not a filesystem write, so it can shadow a file that exists on a
            // read-only mount (the template rootfs ships /etc/resolv.conf).
            // Without this, the chrooted agent in overlay mode has no DNS.
            let tmp_resolv = "/tmp/sandswap-resolv.conf";
            // O_NOFOLLOW + regular-file check: the fallback path is in the
            // agent's tmpfs, where a planted symlink (the agent runs as the
            // same uid family) must not turn this into an arbitrary truncate.
            let write_tmp = || -> std::io::Result<()> {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(tmp_resolv)?;
                if !f.metadata()?.file_type().is_file() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "not a regular file",
                    ));
                }
                f.write_all(content.as_bytes())?;
                f.flush()
            };
            if let Err(e2) = write_tmp() {
                warn!(
                    logger,
                    "inject_guest_resolv_conf: write {} failed ({}), and tmp fallback write {} failed ({}) — skipping",
                    path, e, tmp_resolv, e2
                );
                return;
            }
            // Bind onto an O_NOFOLLOW fd anchor as well, so this target is as
            // race-free as the write above.
            let anchor = match etc_dir.open_file("resolv.conf", false, logger) {
                Some(f) => f,
                None => {
                    warn!(
                        logger,
                        "inject_guest_resolv_conf: write {} failed ({}), and {} could not be anchored — skipping",
                        path, e, path
                    );
                    return;
                }
            };
            // Same class: /tmp/sandswap-resolv.conf is the WARDEN's tmpfs
            // file — bind it read-only, or the agent's writes reach warden
            // memory (and the file it would own anyway is the agent's own
            // /etc/resolv.conf, not this one). In overlay mode the template
            // rootfs is read-only, so no agent write to /etc/resolv.conf was
            // going to reach its own storage either way. Bind THROUGH the
            // O_PATH anchor and make it RO via mount_setattr(2): the
            // path-based MS_REMOUNT through /proc/self/fd answers EINVAL (the
            // exact defect fixed for the busybox bind; this second
            // call site was missed, which silently disabled overlay DNS).
            let bound = bind_ro_fd(tmp_resolv, &anchor, &path, logger);
            drop(anchor);
            if let Err(e2) = bound {
                warn!(
                    logger,
                    "inject_guest_resolv_conf: write {} failed ({}), and bind mount {} -> {} failed ({}) — dropping the writable alias and skipping",
                    path, e, tmp_resolv, path, e2
                );
                // Fresh snapshot: this cleanup runs right after a bind attempt
                // on the same path and must see whatever that attempt left.
                let mut mounts = MountSet::defensive(Some(logger));
                umount_verified(&path, Some(logger), &mut mounts);
                return;
            }
            debug!(
                logger,
                "inject_guest_resolv_conf: bind-mounted {} -> {} (dns={:?}, read-only rootfs fallback)",
                tmp_resolv, path, dns
            );
        }
    }
}

// Idempotent: real rootfs-templates vary and may already ship /proc, /dev,
// /dev/shm mounts or dangerous nodes, so each setup first tears down whatever
// the template brought, then builds the masked version. Best-effort for the
// masking EXTRAS (the /dev/pts, /dev/shm and /tmp mounts and the per-entry
// covers), with three fatal classes: the masked-/proc read-only remount
// (masked_proc_ro_remount_verdict), an unsecurable /proc or /dev mount TARGET
// (the masked tree cannot be installed at all), and the busybox hot-bind's
// read-only flip (overlay_hot_busybox).

/// A teardown umount target's shape, decided by an lstat — extracted so the
/// symlink rule is unit-testable without mount privileges.
#[derive(Debug, PartialEq)]
pub(crate) enum UmountTargetKind {
    /// A plain directory or file: safe to hand to umount(2).
    Real,
    /// A symlink: NEVER handed to umount(2) — the kernel resolves it.
    Symlink,
    /// Nothing at the path: nothing to unmount.
    Absent,
}

pub(crate) fn umount_target_kind(path: &str) -> UmountTargetKind {
    note_fuse_op();
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => UmountTargetKind::Symlink,
        Ok(_) => UmountTargetKind::Real,
        Err(_) => UmountTargetKind::Absent,
    }
}

/// Umount a teardown target WITHOUT following a symlink.
///
/// umount(2) resolves symlinks in the final component: a planted
/// `<root>/run -> /proc` made the warden unmount its OWN /proc — the
/// masked-proc layer, the process sweep's listing and drop_caches all sit
/// behind it — and any `{root}/<entry>` symlink could detach the virtio-fs
/// share or another warden mount. Errors were swallowed on top of that
/// (`let _ = umount(...)`), so a surviving child mount was invisible. All
/// teardown probes therefore go through this: lstat the target and never
/// hand a symlink to umount(2) (the is_real_dir discipline, applied to
/// teardown targets).
///
/// The lstat rule is sound against the agent, not merely best-effort: an
/// entry that currently carries a mount cannot be unlinked/renamed (the
/// kernel returns EBUSY for a mountpoint), so an entry the agent could have
/// replaced by a symlink is provably NOT mounted and skipping its umount
/// loses nothing; and every caller runs either after the process sweep
/// (unmount teardown) or before the next agent's first exec (mount-time
/// probes), so no live agent process exists to race the lstat.
///
/// Idempotence is preserved: EINVAL (not a mount point) and ENOENT are the
/// expected no-op results of a defensive probe. Every other error is logged
/// — `logger` where the caller has one, else the process-scope logger
/// (unmount_workspace's own EBUSY path already logs through slog_scope).
pub(crate) fn umount_verified(path: &str, logger: Option<&Logger>, mounts: &mut MountSet) {
    macro_rules! umount_warn {
        ($($arg:tt)*) => {
            match logger {
                Some(l) => warn!(l, $($arg)*),
                None => slog_scope::warn!($($arg)*),
            }
        };
    }
    // A teardown target is one of two things:
    //   * a REAL mountpoint (the agent cannot rename or unlink it: the kernel
    //     returns EBUSY), or
    //   * a plain entry the warden probes defensively (flat-mode /tmp, /run,
    //     /workspace, home/agent are not mounts).
    // Only the first may be handed to umount(2). The second class is exactly
    // what a sweep survivor can swap to `-> /dev` between the lstat and the
    // umount; refusing to call umount for anything not in the teardown
    // mount-point set closes that TOCTOU without depending on the lstat
    // verdict alone. A mountpoint stays a mountpoint until THIS teardown
    // detaches it (the agent has no CAP_SYS_ADMIN), so the path is stable
    // once the snapshot names it.
    match umount_target_kind(path) {
        UmountTargetKind::Symlink => {
            umount_warn!(
                "{}: umount target is a symlink (agent-planted) — not followed, skipping",
                path
            );
            return;
        }
        UmountTargetKind::Absent => return,
        UmountTargetKind::Real => {}
    }
    if !mounts.contains(path) {
        // Not a mount point per the teardown snapshot (or, on the mount
        // path's per-probe fallback, per a fresh read). Nothing to detach,
        // and no umount(2) call: that is the symlink-following path the
        // race abuses.
        return;
    }
    match nix::mount::umount(path) {
        Ok(()) => {
            mounts.remove(path);
        }
        Err(Errno::EINVAL) | Err(Errno::ENOENT) => {
            // Not a mount point (idempotent no-op) — it is detached either
            // way; keep the set faithful for later probes.
            mounts.remove(path);
        }
        Err(e) => {
            umount_warn!(
                "{}: umount failed: {} (a child mount may survive the teardown)",
                path,
                e
            );
        }
    }
}

/// The set of mount points in the warden's namespace, snapshotted from
/// `/proc/self/mountinfo` ONCE per teardown and shared by every
/// `umount_verified` probe. Re-reading mountinfo per probe (33 reads per
/// unmount: 4 binds + the stamp + 22 masked covers + 6 teardown rels +
/// busybox) was a measured cost on the switch path — one read + hash
/// lookups replaces it.
///
/// # Preconditions (enforced by the CALLER, not by this type)
///
/// The snapshot is a claim about the FUTURE only while no mount can appear
/// after it. That holds only when BOTH are true:
///   1. the caller holds `sandbox::MOUNT_GATE.write()` for the whole
///      teardown — every mount creator (`mount_workspace` via
///      `ensure_mounted_once`) takes the same write guard, so none can run
///      concurrently; and
///   2. the warden itself creates no mounts between the snapshot and the
///      probes (it only calls umount(2) during teardown).
/// The agent cannot create mounts at all: the seccomp deny-list covers the
/// whole mount API (mount/umount2/fsopen/fsmount/move_mount/open_tree/
/// fspick/mount_setattr/pivot_root/chroot/unshare/setns) and neither exec
/// profile keeps CAP_SYS_ADMIN. With the gate held the set can therefore
/// only SHRINK (each successful umount removes its entry), so:
///   * a path IN the snapshot is still a mount point at probe time — the
///     stable-target rule the per-probe read relied on ("the agent cannot
///     rename/unlink a mountpoint: EBUSY");
///   * a path ABSENT from the snapshot is not a mount point at probe time —
///     skipping it without an lstat or umount loses nothing.
/// If dispatch ever becomes cancellable (timeout/select!/abort), the guard
/// could drop while a blocking teardown still runs — the teardown must be
/// cancelled with it, or this premise does not hold.
///
/// # Read-failure contract
///
/// `snapshot` returns an ERROR on a mountinfo read failure, and the teardown
/// turns that into a FAILED unmount (the sandlot destroys the VM). It must
/// never degrade to an empty set: an empty set silently skips every probe.
/// The mount path's defensive probes use `defensive`, which on a read
/// failure falls back to a fresh read PER probe, so a transient failure
/// still clears the stale mount it is probing.
pub(crate) struct MountSet {
    /// `Some` = the one snapshot every probe consults. `None` = a fresh
    /// read per probe (the mount-path fallback).
    mounts: Option<std::collections::HashSet<String>>,
}

impl MountSet {
    /// Take the one snapshot for a teardown. A read failure is returned as
    /// an error so the caller can fail closed (see the type doc).
    pub(crate) fn snapshot() -> std::io::Result<Self> {
        Self::snapshot_from(|| std::fs::read_to_string("/proc/self/mountinfo"))
    }

    /// Testable core of `snapshot`: the reader is injected so the
    /// read-failure contract is pinned without touching /proc.
    pub(crate) fn snapshot_from<F>(read: F) -> std::io::Result<Self>
    where
        F: FnOnce() -> std::io::Result<String>,
    {
        let info = read()?;
        Ok(Self {
            mounts: Some(warden::pure::parse_mount_points(&info)),
        })
    }

    /// Mount-path fallback: a fresh mountinfo read per probe, used only
    /// when the one-read snapshot could not be taken.
    pub(crate) fn per_probe() -> Self {
        Self { mounts: None }
    }

    /// Snapshot for a defensive mount-path probe: on a read failure, fall
    /// back to per-probe reads instead of disabling the probe.
    pub(crate) fn defensive(logger: Option<&Logger>) -> Self {
        match Self::snapshot() {
            Ok(set) => set,
            Err(e) => {
                match logger {
                    Some(l) => warn!(l, "mountinfo snapshot failed ({e}) — defensive probes fall back to per-probe reads"),
                    None => slog_scope::warn!("mountinfo snapshot failed ({e}) — defensive probes fall back to per-probe reads"),
                }
                Self::per_probe()
            }
        }
    }

    /// True when `path` is a mount point per this set (or, for a per-probe
    /// set, per a fresh read).
    pub(crate) fn contains(&self, path: &str) -> bool {
        match &self.mounts {
            Some(set) => set.contains(path),
            None => std::fs::read_to_string("/proc/self/mountinfo")
                .map(|info| warden::pure::parse_mount_points(&info).contains(path))
                .unwrap_or(false),
        }
    }

    /// Drop a path after THIS teardown detached it, keeping the set a
    /// faithful "still mounted" view for later probes.
    fn remove(&mut self, path: &str) {
        if let Some(set) = &mut self.mounts {
            set.remove(path);
        }
    }
}

/// Mount a fresh tmpfs at `mp` (dest relative to root). If something is already
/// mounted there (template-provided or a stale mount from a prior agent), umount
/// it first — tmpfs has no backing, so umount releases all of the previous
/// agent's shared memory in one shot. This is the close for the shm leak:
/// posix_fadvise/drop_caches do NOT clear tmpfs/shmem, only umount does.
/// `clean` = /mnt/rootfs provably carries no leftover child mounts (fresh VM or
/// fully-successful unmount), so the umount probe is skipped.
///
/// The frozen per-mount size cap (exec_cgroup::tmpfs_size_opt) is appended to
/// `opts`: tmpfs is unreclaimable, and a size cap turns a guest-wide OOM
/// corner into a per-writer ENOSPC (see exec_cgroup::TMPFS_SIZE_BYTES).
pub(crate) fn setup_fresh_tmpfs(
    root: &RootAnchor,
    rel: &str,
    opts: &str,
    logger: &Logger,
    clean: bool,
) {
    let mp = format!("{}/{}", MOUNT_POINT, rel);
    if !clean {
        // Mount-path defensive probe (a dirty/partial prior state): its own
        // snapshot — one read, the same shape the per-probe read had.
        let mut mounts = MountSet::defensive(Some(logger));
        umount_verified(&mp, Some(logger), &mut mounts);
    }
    // fd-anchored target: a planted symlink at `rel` must not redirect the
    // tmpfs mount into the warden's own namespace.
    let (target, _keep) = match root.open_dir(rel, logger) {
        Some(t) => t,
        None => return,
    };
    let opts_with_size = format!("{}{}", opts, crate::exec_cgroup::tmpfs_size_opt());
    // nodev for class consistency: no consumer may put a device node in /tmp
    // or /dev/shm (agents cannot mknod — seccomp — and the warden never does);
    // the flag makes that a mount-level invariant, same as nosuid. The /dev
    // tmpfs itself is mounted WITHOUT nodev (it hosts the safe device nodes).
    if let Err(e) = nix::mount::mount(
        Some("tmpfs"),
        target.as_str(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(opts_with_size.as_str()),
    ) {
        warn!(
            logger,
            "setup_fresh_tmpfs: mount tmpfs at {} failed: {}", mp, e
        );
    }
}

/// Mount a masked, read-only /proc inside the agent rootfs. Dangerous entries
/// (/proc/kcore, /proc/kallsyms, ...) are bind-covered with /dev/null so the
/// agent cannot dump guest physical memory / kernel symbols, then the whole
/// proc is remounted read-only so the agent cannot write drop_caches / cgroup
/// knobs. The agent still sees /proc/cpuinfo, /proc/meminfo, /proc/self/*.
/// `clean` skips the defensive umount probe (see mount_workspace).
///
/// The read-only remount is the ONE non-best-effort step here: a
/// failure refuses the whole mount (see masked_proc_ro_remount_verdict).
/// Securing the mount TARGET is equally fatal: a missing/symlinked/unopenable
/// `proc` means the masked procfs cannot be installed, and the agent would
/// keep whatever the template (or a previous host-side anomaly) left there —
/// so the mount is refused instead. The proc MOUNT itself and the per-entry
/// /dev/null masking stay best-effort (a failed proc mount leaves no procfs
/// to abuse; masking failures are logged and are not this finding's
/// write-side surface).
pub(crate) fn setup_masked_proc(
    root_anchor: &RootAnchor,
    logger: &Logger,
    clean: bool,
) -> Result<()> {
    let proc = format!("{}/proc", MOUNT_POINT);
    if !clean {
        let mut mounts = MountSet::defensive(Some(logger));
        umount_verified(&proc, Some(logger), &mut mounts);
    }
    // fd-anchored target: a planted `proc -> /etc` symlink would otherwise
    // land this proc mount on the warden's own /etc.
    let (proc_target, _proc_keep) = match root_anchor.open_dir("proc", logger) {
        Some(t) => t,
        None => {
            return Err(anyhow!(
                "masked /proc target could not be secured under {} (missing, symlink or unopenable): refusing the mount — an unverified /proc must not be served to a tenant",
                MOUNT_POINT
            ))
        }
    };
    if let Err(e) = nix::mount::mount(
        Some("proc"),
        proc_target.as_str(),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ) {
        warn!(
            logger,
            "setup_masked_proc: mount proc at {} failed: {}", proc, e
        );
        return Ok(());
    }
    // Cover dangerous proc entries with /dev/null (read → empty, write →
    // discard) — but ONLY the entries THIS kernel ships. The static
    // list spans kernel versions; on 7.0 four entries (timer_stats,
    // schedstat, sched_debug, latency_stats) are absent, and masking them
    // paid two failed syscalls AND a WARN line per entry PER MOUNT — ~4×9.5ms
    // of guest-console drain (83µs/char) through the async slog thread, which
    // is the measured +21ms cold-mount regression (the FUSE-op count delta
    // alone explains only ~+3ms). The presence probe is ≤10 lstats on the
    // freshly mounted, kernel-local procfs — microseconds, no FUSE, no UART —
    // so it runs per mount and the mount path stays stateless.
    // The mask source is the warden's own /dev/null. If it is gone (an
    // agent-planted teardown symlink detached /dev, a boot anomaly, ...),
    // every cover below fails ENOENT and the agent-visible /proc would expose
    // kcore/kmsg/kallsyms to the NEXT tenant. Refuse the mount instead: the
    // sandlot destroys the VM, which is the only sound outcome when the
    // masking layer cannot be installed.
    // ALLOW-EXISTS: /dev/null is the warden's own boot device node (devtmpfs,
    // before any agent exists); this is not an agent-controlled path. A
    // symlink here would be a host/template anomaly, and the failure mode is
    // refusing the mount (an unmasked proc would be the alternative).
    if !std::path::Path::new("/dev/null").exists() {
        return Err(anyhow::anyhow!(
            "warden /dev/null is missing — refusing to mount an unmasked proc"
        ));
    }
    let present =
        present_masked_entries(|name| fs::symlink_metadata(format!("{}/{}", proc, name)).is_ok());
    for name in present {
        let p = format!("{}/{}", proc, name);
        // Same class: /dev/null is the WARDEN's inode — bind it read-only
        // like the busybox. (Reads still return empty and device writes still
        // reach the driver: MNT_READONLY gates filesystem writes, and the
        // root-gated bind_ro test pins both halves on a live kernel.)
        if let Err(e) = bind_ro("/dev/null", &p, logger) {
            if e.to_string().contains("ENOENT") {
                // Vanished between the probe and the bind: absent, not an
                // error. Debug only — a warn here is a per-mount UART tax on
                // the measured path (see the comment above).
                debug!(
                    logger,
                    "setup_masked_proc: {} is absent on this kernel — not masked", name
                );
            } else {
                warn!(
                    logger,
                    "setup_masked_proc: masking {} with /dev/null failed: {}", name, e
                );
            }
        }
    }
    // Remount proc read-only so the agent can't write /proc/sys/* knobs
    // (drop_caches, cgroup filesystems, sysctls). The capability drop denies
    // SOME of these to strict-profile execs, but several sysctls are
    // owner-write/DAC-gated only (e.g. core_pattern), so a failed remount is
    // FATAL: the agent must not enter a chroot whose /proc is
    // writable. Refusing here fails the mount, and the sandlot destroys the
    // VM instead of leasing it.
    if let Err(e) = nix::mount::mount(
        Some(proc.as_str()),
        proc.as_str(),
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV
            | MsFlags::MS_NOEXEC,
        None::<&str>,
    ) {
        return masked_proc_ro_remount_verdict(&proc, e);
    }
    Ok(())
}

/// Verdict for a failed read-only remount of the masked /proc: FATAL for the
/// mount. Extracted as a pure fn so the verdict is unit-testable
/// without a live mount table (the remount itself needs mount privileges).
///
/// Rationale: /proc/sys/* writes are largely owner-write/DAC-gated rather
/// than capability-gated, so a writable /proc inside the chroot widens the
/// guest's reach beyond its own filesystem (guest kernel tunables). The
/// failure is environmental (the remount is a no-op on healthy kernels), so
/// refusing the mount costs a VM destroy in exactly the case where the
/// isolation guarantee cannot be met.
pub(crate) fn masked_proc_ro_remount_verdict(proc: &str, e: nix::errno::Errno) -> Result<()> {
    Err(anyhow!(
        "masked /proc read-only remount of {} failed ({}): refusing the mount — an agent-writable /proc inside the chroot is not permitted",
        proc,
        e
    ))
}

/// Mount a minimal /dev inside the agent rootfs: tmpfs with only the safe
/// device nodes (null, zero, full, urandom, random, tty), devpts for ptys, and
/// a fresh /dev/shm tmpfs. /dev/mem, /dev/kmem, /dev/port, /dev/dri are NOT
/// created, so the agent cannot open them even with leftover privileges.
/// `clean` skips the defensive umount probes (see mount_workspace).
///
/// FAIL-CLOSED on the target: a `dev` directory that cannot be secured means
/// the minimal device tree cannot be installed and the agent would inherit
/// whatever the template left at /dev — the mount is refused. (A failed tmpfs
/// MOUNT after a secured target is still best-effort: the template's /dev
/// nodes are inert on the shipped kernel — DEVMEM/DEVPORT are compiled out,
/// and agents cannot mknod.)
pub(crate) fn setup_minimal_dev(
    root_anchor: &RootAnchor,
    logger: &Logger,
    clean: bool,
) -> Result<()> {
    let dev = format!("{}/dev", MOUNT_POINT);
    if !clean {
        // One snapshot for the three consecutive probes: nothing mounts
        // between them (the warden only umounts here), and each path's
        // membership is independent of the others' detachment.
        let mut mounts = MountSet::defensive(Some(logger));
        umount_verified(&format!("{}/dev/pts", MOUNT_POINT), Some(logger), &mut mounts);
        umount_verified(&format!("{}/dev/shm", MOUNT_POINT), Some(logger), &mut mounts);
        umount_verified(&dev, Some(logger), &mut mounts);
    }
    // fd-anchored target: a planted `<root>/dev -> <dir>` symlink must not
    // redirect the device tmpfs (see prepare_mount_dir).
    let (dev_target, _dev_keep) = match root_anchor.open_dir("dev", logger) {
        Some(t) => t,
        None => {
            return Err(anyhow!(
                "minimal /dev target could not be secured under {} (missing, symlink or unopenable): refusing the mount — the template's device tree must not be served to a tenant",
                MOUNT_POINT
            ))
        }
    };
    // A tmpfs over /dev covers any template-provided device nodes. It carries
    // the same per-mount size cap as every other agent-visible tmpfs: the
    // agent runs as uid 0 and can create regular files under /dev, so an
    // uncapped tmpfs would be a guest-OOM lever that the documented
    // tmpfs-size invariant claims is closed.
    let dev_opts = format!("mode=755{}", crate::exec_cgroup::tmpfs_size_opt());
    if let Err(e) = nix::mount::mount(
        Some("tmpfs"),
        dev_target.as_str(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID,
        Some(dev_opts.as_str()),
    ) {
        warn!(
            logger,
            "setup_minimal_dev: mount tmpfs at {} failed: {}", dev, e
        );
        return Ok(());
    }

    // mknod helper: (name, major, minor, mode).
    let nodes: &[(&str, u32, u32, u32)] = &[
        ("null", 1, 3, 0o666),
        ("zero", 1, 5, 0o666),
        ("full", 1, 7, 0o666),
        ("urandom", 1, 9, 0o666),
        ("random", 1, 8, 0o666),
        ("tty", 5, 0, 0o666),
    ];
    for &(name, maj, min, mode) in nodes {
        let p = format!("{}/{}", dev, name);
        let _ = stat::mknod(
            Path::new(&p),
            stat::SFlag::S_IFCHR,
            stat::Mode::from_bits_truncate(mode),
            nix::sys::stat::makedev(maj as u64, min as u64),
        );
    }

    // /dev/pts for ptys (needed by pty-based tools / shells).
    let pts = format!("{}/pts", dev);
    let _ = std::fs::create_dir_all(&pts);
    let _ = nix::mount::mount(
        Some("devpts"),
        pts.as_str(),
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        // max=1024 bounds the pty count: each pty costs kernel memory that
        // RLIMIT_AS and the cgroup cap never see, and an agent that opens
        // ptys in a loop would otherwise pressure the guest toward OOM until
        // the unmount clears them. An option-string change — zero syscalls.
        Some("gid=5,mode=620,ptmxmode=666,max=1024"),
    );
    // ptmx symlink to pts/ptmx.
    let _ = std::os::unix::fs::symlink("pts/ptmx", format!("{}/ptmx", dev));

    // /dev/shm: fresh tmpfs (browser/mysql need it; destroyed each attach so
    // no agent sees a prior agent's shared memory). The anchor must be
    // re-opened AFTER the dev tmpfs mount above: an fd opened before it
    // refers to the covered directory, not the new tmpfs root.
    match RootAnchor::open(&dev, logger) {
        Some(dev_anchor) => setup_fresh_tmpfs(&dev_anchor, "shm", "mode=1777", logger, clean),
        None => warn!(
            logger,
            "setup_minimal_dev: dev/ could not be re-anchored — skipping /dev/shm"
        ),
    }
    // /dev/fd, stdin/stdout/stderr symlinks → /proc/self/fd.
    let _ = std::os::unix::fs::symlink("/proc/self/fd", format!("{}/fd", dev));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/0", format!("{}/stdin", dev));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/1", format!("{}/stdout", dev));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/2", format!("{}/stderr", dev));
    Ok(())
}

/// Names of /proc entries covered with /dev/null by setup_masked_proc. Shared
/// with teardown so the bind covers are unmounted before proc itself (else
/// umount(proc) hits EBUSY).
/// The masked-proc entries that exist on THIS kernel, with the
/// existence probe injected so the absence-filtering is unit-testable without
/// a live procfs. Masking an absent entry is not just wasted syscalls — the
/// per-entry failure WARN was a per-mount guest-console tax (the +21ms cold
/// regression; see setup_masked_proc).
pub(crate) fn present_masked_entries<F: Fn(&str) -> bool>(exists: F) -> Vec<&'static str> {
    MASKED_PROC_ENTRIES
        .iter()
        .copied()
        .filter(|n| exists(n))
        .collect()
}

pub(crate) const MASKED_PROC_ENTRIES: &[&str] = &[
    // Kernel build config: the release kernel compiles IKCONFIG out; the
    // mask is the dev/older-kernel backstop.
    "config.gz",
    // The kernel command line is masked as defense in depth: the session key
    // no longer rides it (delivered over vsock), but boot-time tokens and any
    // future secret must not be readable from inside the chroot.
    "cmdline",
    "kcore",
    "keys",
    // kmsg carries kernel-log traces of the PREVIOUS agent (OOM lines name
    // its processes) — same cross-tenant reasoning as kcore/kallsyms.
    "kmsg",
    "latency_stats",
    "timer_list",
    "timer_stats",
    "sched_debug",
    "kallsyms",
    "schedstat",
    // Kernel-internal state files (mode 0400 root-owned): the agent runs as
    // uid 0, so file mode alone admits it — the same "kernel internals" class
    // as kcore/kallsyms (heap statistics, physical page maps). No tenant
    // content, but no agent use case either.
    "slabinfo",
    "kpagecount",
    "kpageflags",
    "pagetypeinfo",
    "buddyinfo",
    "zoneinfo",
    // Kernel address layout / physical memory map:
    // vmallocinfo prints %pK (raw virtual addresses when kptr_restrict=0),
    // iomem/ioports expose the physical map, modules the loaded-image list.
    // The shipped kernel has CONFIG_MODULES=n (the entry is absence-probed),
    // but all four are the same "kernel internals" class as kallsyms/kcore.
    "vmallocinfo",
    "iomem",
    "ioports",
    "modules",
    // Physical page metadata: pagemap exposes PFN/soft-dirty bits (a
    // cross-tenant memory-layout channel on a REUSED VM, and the agent runs
    // as uid 0 inside the guest's initial user namespace).
    "pagemap",
    // NOTE: /proc/sysvipc/{msg,sem,shm} are NOT masked here. The mask list is
    // deliberately bare proc-relative names (the teardown invariant that keeps
    // an edited list from constructing an escape path), and /proc/sysvipc is a
    // directory — a /dev/null bind cannot cover it. The cross-tenant guarantee
    // for those tables is the unmount residue sweep, which now FAILS THE
    // UNMOUNT (destroy-and-replace) whenever it cannot prove them cleared.
    //
    // NOTE: /proc/net is NOT maskable and must NOT be added here. It is a
    // magic symlink to `self/net`, and each /proc/<pid>/net is a separate
    // procfs directory: mount(2) resolves the link, so a cover would attach to
    // the WARDEN's own /proc/<warden-pid>/net while every agent process keeps
    // reading its own /proc/self/net (verified on a live kernel). A /dev/null
    // bind on the symlink answers ENOTDIR, which would be a per-mount WARN for
    // zero coverage. The netlink-table address disclosure is closed in the
    // guest KERNEL (the table hashes a net_cookie, not the net pointer); the
    // masked procfs and the sysctl hardening are the surrounding layers.
];

/// Boot-time kernel sysctl hardening (best-effort). The guest kernel ships
/// without CONFIG_SECURITY, so the seccomp deny-list and the proc masking are
/// the load-bearing controls; these knobs close the remaining read-only
/// information channels that need no capability:
///   - kptr_restrict=2: %pK prints zeros even for uid 0 (vmallocinfo and
///     friends stop leaking KASLR/slab layout);
///   - dmesg_restrict=1: /dev/kmsg and the syslog path are already masked /
///     denied, but the knob keeps any future read path closed;
///   - perf_event_paranoid=3: perf_event_open is seccomp-denied; keep the
///     kernel-side gate too;
///   - unprivileged_bpf_disabled=2: bpf(2) is seccomp-denied; the knob keeps
///     unprivileged BPF off at the kernel for anything seccomp misses;
///   - yama/ptrace_scope=3: absent on the shipped CONFIG_SECURITY=n kernel
///     (the write fails ENOENT and is logged at debug) — included so a future
///     kernel with Yama starts locked down;
///   - user/max_user_namespaces=0: the shipped guest kernel DISABLES
///     CONFIG_USER_NS at build time (kernel/build.sh), so the sysctl is
///     absent there (debug). This runtime write covers older/dev kernels and
///     any config regression: a userns is the enabler for the namespace and
///     mount-API classes the seccomp deny-list closes, and the agent has no
///     legitimate use for it. The Debian-compat
///     kernel/unprivileged_userns_clone knob is written too (absent on
///     mainline, hence debug).
pub(crate) const KERNEL_SYSCTL_HARDENING: &[(&str, &str)] = &[
    ("/proc/sys/kernel/kptr_restrict", "2"),
    ("/proc/sys/kernel/dmesg_restrict", "1"),
    ("/proc/sys/kernel/perf_event_paranoid", "3"),
    ("/proc/sys/kernel/unprivileged_bpf_disabled", "2"),
    ("/proc/sys/kernel/yama/ptrace_scope", "3"),
    // Namespace-creation enabler: zero user namespaces. On the release
    // kernel CONFIG_USER_NS=n makes this path absent (NotFound -> debug); on
    // a dev/older kernel it is the runtime close. Written after /proc is
    // mounted and before any agent can execute.
    ("/proc/sys/user/max_user_namespaces", "0"),
    // Debian/Ubuntu carry the same policy as a separate knob. Mainline lacks
    // it (NotFound -> debug).
    ("/proc/sys/kernel/unprivileged_userns_clone", "0"),
];

/// Apply `KERNEL_SYSCTL_HARDENING`. Runs once at boot (init mode) after /proc
/// is mounted and before any agent can execute.
///
/// Every knob is READ BACK. The namespace knobs are load-bearing — a dev or
/// older kernel with CONFIG_USER_NS=y whose sysctl could not be zeroed would
/// re-open namespace creation, so a mismatch there fails the boot (the VM
/// never serves an agent). The remaining knobs are read-only information
/// channels whose failure is logged but tolerated (a locked-down host may
/// refuse some writes). A missing file is fine: it means the kernel feature is
/// compiled out (the release kernel ships CONFIG_USER_NS=n, Yama=n).
pub(crate) fn harden_kernel_sysctls() -> Result<()> {
    let mut hard_failure: Option<(String, String, String)> = None;
    for (path, value) in KERNEL_SYSCTL_HARDENING {
        let hard = path.ends_with("max_user_namespaces")
            || path.ends_with("unprivileged_userns_clone");
        let write_err = match std::fs::write(path, format!("{}\n", value)) {
            Ok(()) => None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Expected for Yama/userns on the shipped minimized kernel.
                slog_scope::debug!("sysctl hardening: {} absent on this kernel", path);
                continue;
            }
            Err(e) => Some(e),
        };
        match std::fs::read_to_string(path) {
            Ok(actual) if actual.trim() == *value => {}
            Ok(actual) => {
                let msg = format!(
                    "sysctl hardening: {} reads {:?}, want {}",
                    path,
                    actual.trim(),
                    value
                );
                if hard {
                    hard_failure = Some((path.to_string(), value.to_string(), msg.clone()));
                    slog_scope::error!("{}", msg);
                } else {
                    slog_scope::warn!("{}", msg);
                }
            }
            Err(e) => {
                let msg = match write_err {
                    Some(we) => format!(
                        "sysctl hardening write {}={} failed: {} (read-back: {})",
                        path, value, we, e
                    ),
                    None => format!(
                        "sysctl hardening read-back of {} failed: {}",
                        path, e
                    ),
                };
                if hard {
                    hard_failure = Some((path.to_string(), value.to_string(), msg.clone()));
                    slog_scope::error!("{}", msg);
                } else {
                    slog_scope::warn!("{}", msg);
                }
            }
        }
    }
    if let Some((path, value, _)) = hard_failure {
        return Err(anyhow!(
            "mandatory sysctl hardening could not be applied: {}={} — refusing to serve an agent with namespace creation available",
            path,
            value
        ));
    }
    Ok(())
}

/// Sub-paths (relative to the agent rootfs) unmounted by teardown_masked after
/// the masked-proc bind covers. Every path that setup can mount a filesystem
/// on MUST appear here, or unmount_workspace hits EBUSY and the VM is
/// destroyed unnecessarily. Extracted as a const so the setup↔teardown
/// symmetry is unit-testable.
pub(crate) const TEARDOWN_RELS: &[&str] = &["dev/pts", "dev/shm", "dev", "proc", "tmp", "run"];

/// Tear down the masked proc/dev/tmpfs mounts before umounting the workspace,
/// so the workspace umount doesn't hit EBUSY on child mounts and so any tmpfs
/// contents (prior agent's shm) are released. Best-effort. `mounts` is the
/// teardown snapshot the caller took after the process sweep — all 28 probes
/// share its ONE mountinfo read.
pub(crate) fn teardown_masked(root: &str, mounts: &mut MountSet) {
    let r = root.trim_end_matches('/');
    // Unmount the /dev/null bind covers on masked proc entries FIRST — without
    // this, umount(proc) fails with EBUSY (a child mount is still attached).
    for name in MASKED_PROC_ENTRIES {
        umount_verified(&format!("{}/proc/{}", r, name), None, mounts);
    }
    // dev symlinks (fd/stdin/stdout/stderr/ptmx) are not mounts, so no umount.
    for rel in TEARDOWN_RELS {
        umount_verified(&format!("{}/{}", r, rel), None, mounts);
    }
}

/// Global page-cache + dentry/inode drop. Runs in the warden init namespace
/// (root, /proc writable). umount(2) has already flushed this mount's dirty
/// pages, so no extra sync() is needed; drop_caches=3 then frees clean
/// pagecache + dentries + inodes guest-wide, closing the residual-cache leak
/// that targeted evict_page_cache misses (symlink-referenced files, slab
/// dentries/inodes). Best-effort: a failure (e.g. /proc not writable) only
/// means caches linger, which the masked-proc layer already makes unreachable.
pub(crate) fn drop_caches() {
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/sys/vm/drop_caches")
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(b"3\n") {
                // Best-effort, but visible: the write failing means stale
                // dentries from the previous agent survive until they age
                // out of the guest cache (root-level entries have zero
                // timeouts in the VMM, so this is defense in depth, not the
                // primary barrier).
                slog_scope::warn!("drop_caches write failed: {:?}", e);
            }
        }
        Err(e) => {
            slog_scope::warn!("drop_caches open failed: {:?}", e);
        }
    }
}
