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

//! The fd-anchored path API every agent-controlled mount path resolves
//! through: one component per openat(2), no absolute re-walks, no implicit
//! symlink follows.

use anyhow::{anyhow, Result};
use nix::errno::Errno;
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{self, fstat, fstatat, mkdirat, SFlag};
use nix::unistd::{unlinkat, UnlinkatFlags};
use slog::{warn, Logger};
use std::fs;
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd};
use warden::pure::check_component;

use crate::mount::workspace::note_fuse_op;

// ── agent-controlled path safety ─────────────────────────────────────
//
// In FLAT mode the agent's chroot root IS its volume: every `<volume>/…`
// path is agent writable. The kernel resolves symlinks in bind SOURCES, in
// mount TARGETS and in plain open() paths — and all three would then act in
// the WARDEN'S namespace. A planted `<volume>/rootfs -> /` symlink made the
// mode probe read "overlay", bound the warden's own initramfs as the chroot
// (a full escape), and the busybox hot-bind then carried whatever the agent
// left there into the NEXT tenant's chroot in the same VM. Two rules close
// the class:
//   * sources are lstat-checked (`require_real_dir`), and
//   * targets are opened O_NOFOLLOW and mounted THROUGH the fd
//     (`prepare_mount_dir`, `open_agent_file_target`) — mount(2) on
//     /proc/self/fd/N attaches to that exact inode, so nothing re-planted
//     between the check and the mount can redirect it.

/// True only when `path` is ITSELF a directory: `symlink_metadata` reports a
/// symlink as a symlink, however it points. `Path::exists()` follows symlinks
/// and made a flat volume with a planted `rootfs` symlink read as overlay.
/// One path component: non-empty, no '/', not "." or "..", no NUL.
/// The anchored API accepts NOTHING else — a caller cannot smuggle an
/// absolute path, a traversal or a nested path through it (nested targets
/// chain anchors instead: home → agent).

/// A directory fd that every mounted-tree path is resolved RELATIVE to
/// One anchor is opened per mount per tree:
///   * the VOLUME root (bind sources: overlay rootfs/workspace/home, and the
///     flat whole-volume bind), and
///   * the MOUNTED rootfs (bind targets: bin/etc/proc/dev/tmp, workspace,
///     home/agent).
///
/// Two properties come from resolving relative to a pinned fd, and neither
/// is available to absolute-path code:
///  1. The object is pinned by the openat(2) that created its fd — binds are
///     attached to THAT inode (`mount` on /proc/self/fd/N), so there is no
///     check-to-use window anywhere (the old lstat-then-mount pair let
///     mount(2) re-resolve the source path; fstat checks what was opened).
///  2. Each openat(2) resolves ONE component. Absolute-path walks re-walk
///     the shared prefix every time, and after each unmount's drop_caches
///     every prefix component is a cold FUSE round trip (the class of regression a
// doubled walk re-introduces).
pub(crate) struct RootAnchor {
    pub(crate) fd: fs::File,
}

impl RootAnchor {
    /// Anchor `dir` (O_PATH|O_DIRECTORY|O_NOFOLLOW). A symlinked or
    /// non-directory anchor is refused, never followed: the volume root and
    /// /mnt/rootfs are both warden/prov-owned, and a link here would poison
    /// every relative resolution below.
    pub(crate) fn open(dir: &str, logger: &Logger) -> Option<RootAnchor> {
        Self::open_inner(dir, logger, true)
    }

    /// Quiet twin for a lookup whose failure is an EXPECTED protocol outcome
    /// (a mount request carrying a superseded generation's alias): the caller
    /// returns a named refusal, so a warning here would be log noise on a
    /// path an attacker can drive.
    pub(crate) fn open_quiet(dir: &str, logger: &Logger) -> Option<RootAnchor> {
        Self::open_inner(dir, logger, false)
    }

    fn open_inner(dir: &str, logger: &Logger, warn_on_failure: bool) -> Option<RootAnchor> {
        note_fuse_op();
        match open(
            dir,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            stat::Mode::empty(),
        ) {
            Ok(fd) => Some(RootAnchor {
                fd: unsafe { fs::File::from_raw_fd(fd) },
            }),
            Err(e) => {
                if warn_on_failure {
                    warn!(
                        logger,
                        "anchor {}: open failed (symlink or non-directory refused): {}", dir, e
                    );
                }
                None
            }
        }
    }

    pub(crate) fn fd_path(&self) -> String {
        format!("/proc/self/fd/{}", self.fd.as_raw_fd())
    }

    /// Secure a DIRECTORY `name` under this anchor as a MOUNT TARGET: a
    /// planted symlink is removed (the entry belongs to the agent's rootfs),
    /// a missing directory is created, and the result is opened
    /// O_PATH|O_DIRECTORY|O_NOFOLLOW. Mount on the returned fd path; keep the
    /// fd alive until mount(2) returns.
    pub(crate) fn open_dir(&self, name: &str, logger: &Logger) -> Option<(String, fs::File)> {
        if !check_component(name) {
            warn!(logger, "open_dir: refusing non-component name {:?}", name);
            return None;
        }
        for _ in 0..3 {
            note_fuse_op();
            match openat(
                self.fd.as_raw_fd(),
                name,
                OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                stat::Mode::empty(),
            ) {
                Ok(fd) => {
                    let f = unsafe { fs::File::from_raw_fd(fd) };
                    return Some((format!("/proc/self/fd/{}", f.as_raw_fd()), f));
                }
                // O_PATH|O_NOFOLLOW|O_DIRECTORY surfaces a symlink as ENOTDIR.
                Err(Errno::ENOTDIR) | Err(Errno::ELOOP) => {
                    warn!(
                        logger,
                        "mount target {} is a symlink — removing it (agent-planted)", name
                    );
                    note_fuse_op();
                    if let Err(e) =
                        unlinkat(Some(self.fd.as_raw_fd()), name, UnlinkatFlags::NoRemoveDir)
                    {
                        warn!(logger, "mount target {}: removing it failed: {}", name, e);
                        return None;
                    }
                }
                Err(Errno::ENOENT) => {
                    note_fuse_op();
                    if let Err(e) = mkdirat(
                        self.fd.as_raw_fd(),
                        name,
                        stat::Mode::from_bits_truncate(0o755),
                    ) {
                        warn!(logger, "mount target {}: mkdir failed: {}", name, e);
                        return None;
                    }
                }
                Err(e) => {
                    warn!(logger, "mount target {}: open failed: {}", name, e);
                    return None;
                }
            }
        }
        warn!(
            logger,
            "mount target {}: could not be secured (kept reappearing) — skipping the mount", name
        );
        None
    }

    /// Like open_dir but for a SOURCE: never creates, never removes — a
    /// missing or symlinked source is a refusal (fail closed).
    pub(crate) fn open_dir_strict(&self, name: &str, logger: &Logger) -> Result<fs::File> {
        if !check_component(name) {
            warn!(
                logger,
                "bind source name {:?} is not one path component", name
            );
            return Err(anyhow!(
                "bind source name {:?} is not one path component",
                name
            ));
        }
        note_fuse_op();
        openat(
            self.fd.as_raw_fd(),
            name,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            stat::Mode::empty(),
        )
        .map(|fd| unsafe { fs::File::from_raw_fd(fd) })
        .map_err(|e| {
            anyhow!(
                "refusing to bind-mount {:?}: not a plain directory under the volume root (symlink, special file or missing): {}",
                name,
                e
            )
        })
    }

    /// Secure a FILE `name` under this anchor: open O_PATH|O_NOFOLLOW (which
    /// never blocks — no FUSE OPEN request) and TYPE-CHECK THE OBJECT THAT
    /// WAS OPENED via fstat: a planted symlink surfaces as ELOOP/ENOTDIR and
    /// is removed + retried, a non-regular object (FIFO/device/socket) is
    /// refused by name (a FIFO must never reach a blocking open).
    pub(crate) fn open_file(&self, name: &str, create: bool, logger: &Logger) -> Option<fs::File> {
        if !check_component(name) {
            warn!(logger, "open_file: refusing non-component name {:?}", name);
            return None;
        }
        for _ in 0..3 {
            note_fuse_op();
            match openat(
                self.fd.as_raw_fd(),
                name,
                OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                stat::Mode::empty(),
            ) {
                Ok(fd) => {
                    let f = unsafe { fs::File::from_raw_fd(fd) };
                    let kind = fstat(f.as_raw_fd())
                        .map(|st| SFlag::from_bits_truncate(st.st_mode))
                        .unwrap_or_else(|e| {
                            warn!(logger, "{}: fstat failed: {}", name, e);
                            SFlag::empty()
                        });
                    // O_PATH|O_NOFOLLOW on a symlink SUCCEEDS and returns an fd
                    // for the link itself (unlike a plain open, which gives
                    // ELOOP) — the type check is what sees it. Remove and retry.
                    if kind.contains(SFlag::S_IFLNK) {
                        warn!(
                            logger,
                            "{} is a symlink — removing it (agent-planted)", name
                        );
                        note_fuse_op();
                        if let Err(e) =
                            unlinkat(Some(self.fd.as_raw_fd()), name, UnlinkatFlags::NoRemoveDir)
                        {
                            warn!(logger, "{}: removing the symlink failed: {}", name, e);
                            return None;
                        }
                    } else if kind.contains(SFlag::S_IFREG) {
                        return Some(f);
                    } else {
                        warn!(
                            logger,
                            "{}: not a regular file — refusing it as a mount target", name
                        );
                        return None;
                    }
                }
                Err(Errno::ELOOP) | Err(Errno::ENOTDIR) => {
                    warn!(
                        logger,
                        "{} is a symlink — removing it (agent-planted)", name
                    );
                    note_fuse_op();
                    if let Err(e) =
                        unlinkat(Some(self.fd.as_raw_fd()), name, UnlinkatFlags::NoRemoveDir)
                    {
                        warn!(logger, "{}: removing the symlink failed: {}", name, e);
                        return None;
                    }
                }
                Err(Errno::ENOENT) if create => {
                    note_fuse_op();
                    match openat(
                        self.fd.as_raw_fd(),
                        name,
                        OFlag::O_CREAT
                            | OFlag::O_EXCL
                            | OFlag::O_WRONLY
                            | OFlag::O_CLOEXEC
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_NONBLOCK,
                        stat::Mode::from_bits_truncate(0o644),
                    ) {
                        Ok(fd) => drop(unsafe { fs::File::from_raw_fd(fd) }),
                        Err(Errno::EEXIST) => {} // lost a race — reopen above
                        Err(e) => {
                            warn!(logger, "{}: create failed: {}", name, e);
                            return None;
                        }
                    }
                }
                Err(e) => {
                    warn!(logger, "{}: not stat-able: {}", name, e);
                    return None;
                }
            }
        }
        warn!(logger, "{}: could not be secured — skipping", name);
        None
    }

    /// Write `content` into file `name` under this anchor without ever
    /// following a symlink: O_NOFOLLOW|O_NONBLOCK (a planted FIFO answers
    /// ENXIO immediately instead of parking the mount). A planted
    /// link is removed and retried, never followed.
    pub(crate) fn write_file(
        &self,
        name: &str,
        content: &[u8],
        logger: &Logger,
    ) -> std::io::Result<fs::File> {
        if !check_component(name) {
            return Err(std::io::Error::from(Errno::EINVAL));
        }
        for _ in 0..2 {
            note_fuse_op();
            match openat(
                self.fd.as_raw_fd(),
                name,
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_TRUNC
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_NONBLOCK,
                stat::Mode::from_bits_truncate(0o644),
            ) {
                Ok(fd) => {
                    let mut f = unsafe { fs::File::from_raw_fd(fd) };
                    f.write_all(content)?;
                    return Ok(f);
                }
                Err(Errno::ELOOP) => {
                    warn!(
                        logger,
                        "{} is a symlink — removing it (agent-planted)", name
                    );
                    let _ = unlinkat(Some(self.fd.as_raw_fd()), name, UnlinkatFlags::NoRemoveDir);
                }
                Err(e) => return Err(std::io::Error::from(e)),
            }
        }
        Err(std::io::Error::from(Errno::ELOOP))
    }

    /// True when `name` under this anchor is a symlink of ANY shape.
    ///
    /// The busybox hot-bind skips when `bin` is a symlink: a template's
    /// usrmerge link (`bin -> usr/bin`, relative or absolute) must not be
    /// destroyed, and an agent-planted link is self-harm only — the target is
    /// resolved inside the agent's own chroot, and no warden file is handed to
    /// a kernel primitive on this path (the bind target is an anchored fd).
    pub(crate) fn symlink_in_rootfs(&self, name: &str) -> bool {
        note_fuse_op();
        fstatat(self.fd.as_raw_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map(|st| SFlag::from_bits_truncate(st.st_mode).contains(SFlag::S_IFLNK))
            .unwrap_or(false)
    }
}
