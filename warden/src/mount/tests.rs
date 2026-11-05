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

use super::*;
use nix::errno::Errno;
use nix::mount::MsFlags;
use nix::sys::stat;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use warden::pure::{check_component, nl_messages, nl_type, parse_sysvipc_ids};

use crate::mount::anchor::RootAnchor;

use crate::mount::boot::{
    baremount, is_mounted, parse_mount_flags_and_options, setup_ro_tmpfs_source, BUSYBOX_SOURCE_RO,
    INIT_ROOTFS_MOUNTS,
};
use crate::mount::hardening::{
    bind_ro, bind_ro_fd, bind_ro_remount_flags, masked_proc_ro_remount_verdict,
    overlay_hot_busybox, present_masked_entries, setup_fresh_tmpfs, setup_masked_proc,
    setup_minimal_dev, teardown_masked, umount_target_kind, umount_verified, MountSet,
    UmountTargetKind, KERNEL_SYSCTL_HARDENING, MASKED_PROC_ENTRIES, TEARDOWN_RELS,
};
use crate::mount::workspace::share_harden_flags;
use crate::residue::attrs::restore_attrs_for_tids;
use crate::residue::attrs::WardenAttrs;
use crate::residue::neigh::{neigh_msg_kind, NeighMsgKind};
use crate::residue::sweep::{
    proc_stat_state, run_sweep, stat_bytes_are_sweep_target, stat_bytes_are_unclean,
    stat_line_is_live_userspace, stat_line_is_unclean, sweep_target_pid, unclean_pids,
};
use crate::residue::tcp_diag::{
    sock_diag_msg, DEAD_TCP_STATE_BITS, SOCK_DESTROY, SOCK_DIAG_BY_FAMILY,
};
use crate::residue::{NLMSG_F_ACK, NLMSG_F_DUMP, NLMSG_F_REQUEST};

// Mount tests must not share fixed temp paths: a concurrent test binary
// (parallel cargo, a second build) or a stale mount left by a killed run
// at the SAME path makes a mountinfo assertion read the WRONG mount —
// observed once as a flaky share_bind_flags failure under build load.
// Namespace every mount-test directory by pid.
fn test_dir(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{}_{}", name, std::process::id()))
}

// ── agent-controlled path safety (the symlink class) ─────────────
//
// Pins for the symlink-class escape: a flat volume is agent-writable, so
// `<volume>/rootfs -> /` used to read as "overlay mode" (Path::exists
// follows symlinks) and the kernel then bound the warden's own root as
// the chroot. These tests are non-root: they pin the PROBE and the
// target-anchoring, not the mount(2) itself.

// The runtime user-namespace close is defense-in-depth for dev/older kernels
// and for a config regression (the release kernel compiles CONFIG_USER_NS
// out). A "cleanup" that drops the knob would silently re-open the namespace
// and mount-API classes the seccomp deny-list closes by policy.
#[test]
fn kernel_sysctl_hardening_disables_user_namespaces() {
    let has = |path: &str, val: &str| {
        KERNEL_SYSCTL_HARDENING
            .iter()
            .any(|&(p, v)| p == path && v == val)
    };
    assert!(
        has("/proc/sys/user/max_user_namespaces", "0"),
        "max_user_namespaces=0 missing from the boot hardening set"
    );
    assert!(
        has("/proc/sys/kernel/unprivileged_userns_clone", "0"),
        "the Debian-compat userns knob is missing"
    );
    // The pre-existing knobs stay pinned alongside it.
    assert!(has("/proc/sys/kernel/kptr_restrict", "2"));
    assert!(has("/proc/sys/kernel/unprivileged_bpf_disabled", "2"));
}

// The masking loop must only touch entries the kernel ships.
// On kernel 7.0 four entries are absent and masking them emitted a WARN
// per entry per mount — a per-mount guest-console tax of ~4x9.5ms, the
// measured +21ms cold-mount regression. Mutation replay: invert the
// filter (mask the ABSENT ones) and this goes red.
#[test]
fn present_masked_entries_filters_absent() {
    let all = MASKED_PROC_ENTRIES;
    // Kernel ships only these two:
    let present = present_masked_entries(|n| n == "kcore" || n == "kallsyms");
    assert_eq!(present, vec!["kcore", "kallsyms"]);
    // A kernel shipping every entry masks every entry:
    let present_all = present_masked_entries(|_| true);
    assert_eq!(present_all, all.to_vec());
    // A kernel shipping none masks none (no failed syscalls, no WARN):
    assert!(present_masked_entries(|_| false).is_empty());
    // Order follows the static list (teardown symmetry relies on names,
    // not order, but a stable order keeps the serial output diff-able).
    let smol = present_masked_entries(|n| n == "schedstat" || n == "kcore");
    assert_eq!(smol, vec!["kcore", "schedstat"]);
}

// ── Anchored API ─────────────────────────────────────
// The single-component rule is the API's whole defense against a caller
// smuggling a traversal or an absolute path into a relative open.
#[test]
fn check_component_rejects_escape_forms() {
    for bad in ["", ".", "..", "a/b", "/abs", "a\0b", "../x", "x/../y"] {
        assert!(!check_component(bad), "{bad:?} must be rejected");
    }
    for good in [
        "bin",
        "etc",
        "resolv.conf",
        "busybox",
        "home",
        "agent",
        "..x",
        "x..",
    ] {
        assert!(check_component(good), "{good:?} must be accepted");
    }
}

#[test]
fn anchor_open_dir_strict_refuses_symlink_and_missing() {
    // A bind SOURCE must never be created or followed: a symlinked or
    // missing source is a refusal (the old require_real_dir rule).
    let dir = test_dir("warden_test_anchor_strict");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::create_dir_all(dir.join("rootfs")).expect("mkdir rootfs");
    std::os::unix::fs::symlink("/", dir.join("link")).expect("symlink");

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let anchor = RootAnchor::open(dir.to_str().unwrap(), &logger).expect("anchor the temp dir");
    assert!(anchor.open_dir_strict("rootfs", &logger).is_ok());
    let res = anchor.open_dir_strict("link", &logger);
    assert!(res.is_err(), "a symlinked bind source must be refused");
    assert!(format!("{}", res.unwrap_err()).contains("not a plain directory"));
    assert!(
        anchor.open_dir_strict("missing", &logger).is_err(),
        "a missing bind source must be refused, not created"
    );
    assert!(
        !dir.join("missing").exists(),
        "strict open must never create the source directory"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn anchor_open_dir_replaces_planted_symlink() {
    let dir = test_dir("warden_test_anchor_target");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let elsewhere = dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("mkdir elsewhere");
    std::os::unix::fs::symlink(&elsewhere, dir.join("proc")).expect("plant symlink");

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let anchor = RootAnchor::open(dir.to_str().unwrap(), &logger).expect("anchor");
    let (fd_path, keep) = anchor
        .open_dir("proc", &logger)
        .expect("must secure the target");
    assert!(
        fd_path.starts_with("/proc/self/fd/"),
        "mount goes through the fd"
    );
    let md = std::fs::symlink_metadata(dir.join("proc")).expect("lstat target");
    assert!(
        md.file_type().is_dir(),
        "the symlink must be replaced by a directory"
    );
    assert!(keep.as_raw_fd() >= 0);
    // A missing target is created.
    let (_p2, _k2) = anchor
        .open_dir("dev", &logger)
        .expect("create missing target");
    assert!(dir.join("dev").is_dir());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn anchor_open_file_never_follows_symlink_and_creates() {
    let dir = test_dir("warden_test_anchor_file");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let victim = dir.join("victim");
    std::fs::write(&victim, "important").expect("write victim");
    std::os::unix::fs::symlink(&victim, dir.join("busybox")).expect("plant symlink");

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let anchor = RootAnchor::open(dir.to_str().unwrap(), &logger).expect("anchor");
    let f = anchor
        .open_file("busybox", true, &logger)
        .expect("must secure the target");
    assert!(!std::fs::symlink_metadata(dir.join("busybox"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "important");
    assert!(f.as_raw_fd() >= 0);
    // Missing + create=true creates a regular file; create=false refuses.
    assert!(anchor.open_file("fresh", true, &logger).is_some());
    assert!(dir.join("fresh").is_file());
    assert!(anchor.open_file("absent", false, &logger).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

// FIFO plants (mount-time twin), now type-based: a FIFO planted at a file
// target must be REFUSED by fstat on the opened object — an O_PATH open
// never blocks, and the type check happens before any blocking open.
#[test]
fn anchor_open_file_refuses_fifo_type() {
    let dir = test_dir("warden_test_anchor_fifo_type");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let target = dir.join("busybox");
    let c = std::ffi::CString::new(target.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let anchor = RootAnchor::open(dir.to_str().unwrap(), &logger).expect("anchor");
    let start = std::time::Instant::now();
    assert!(
        anchor.open_file("busybox", true, &logger).is_none(),
        "a FIFO must be refused as a mount target"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "the refusal must be prompt (O_PATH + fstat, no blocking open)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn anchor_write_file_never_follows_symlink() {
    let dir = test_dir("warden_test_anchor_write");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let victim = dir.join("victim");
    std::fs::write(&victim, "#!/bin/sh\necho real\n").expect("write victim");
    std::os::unix::fs::symlink(&victim, dir.join("resolv.conf")).expect("plant symlink");

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let anchor = RootAnchor::open(dir.to_str().unwrap(), &logger).expect("anchor");
    anchor
        .write_file("resolv.conf", b"nameserver 10.0.0.1\n", &logger)
        .expect("write must succeed through a replaced symlink");
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "#!/bin/sh\necho real\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("resolv.conf")).unwrap(),
        "nameserver 10.0.0.1\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn anchor_write_file_fifo_returns_promptly() {
    let dir = test_dir("warden_test_anchor_write_fifo");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let target = dir.join("resolv.conf");
    let c = std::ffi::CString::new(target.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let (tx, rx) = std::sync::mpsc::channel();
    let anchor_path = dir.to_str().unwrap().to_owned();
    std::thread::spawn(move || {
        let a = RootAnchor::open(&anchor_path, &logger).expect("anchor");
        let _ = tx.send(
            a.write_file("resolv.conf", b"nameserver 10.0.0.1\n", &logger)
                .map(|_| ()),
        );
    });
    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(Err(_)) => {} // ENXIO — the point is it RETURNED
        Ok(Ok(())) => panic!("write_file must not write into a FIFO"),
        Err(_) => panic!("write_file on a FIFO did not return within 5s"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// The hot-bind skip applies to ANY symlink at `bin`. Relative
// usrmerge links are template content; absolute links resolve inside the
// chroot and must not be destroyed either; an agent-planted link is
// self-harm only (no warden file is handed to a kernel primitive).
#[test]
fn anchor_symlink_in_rootfs() {
    let dir = test_dir("warden_test_anchor_usrmerge");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("usr/bin")).expect("mkdir");
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let anchor = RootAnchor::open(dir.to_str().unwrap(), &logger).expect("anchor");

    std::os::unix::fs::symlink("usr/bin", dir.join("bin")).expect("relative link");
    assert!(
        anchor.symlink_in_rootfs("bin"),
        "bin -> usr/bin must skip the hot bind"
    );
    std::fs::remove_file(dir.join("bin")).expect("rm");
    std::os::unix::fs::symlink("/usr/bin", dir.join("bin")).expect("absolute link");
    assert!(
        anchor.symlink_in_rootfs("bin"),
        "absolute link must skip too (chroot-contained)"
    );
    std::fs::remove_file(dir.join("bin")).expect("rm");
    std::os::unix::fs::symlink("../bin", dir.join("bin")).expect("dotdot link");
    assert!(
        anchor.symlink_in_rootfs("bin"),
        "any symlink skips; never follow/remove it"
    );
    std::fs::remove_file(dir.join("bin")).expect("rm");
    std::fs::create_dir_all(dir.join("bin")).expect("real dir wins");
    assert!(
        !anchor.symlink_in_rootfs("bin"),
        "a real dir is not a symlink"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── the masked-/proc read-only remount verdict is FATAL ──

#[test]
fn masked_proc_ro_remount_failure_is_fatal() {
    // A failed read-only remount must REFUSE the mount: the agent must
    // not enter a chroot with a writable /proc (owner-write/DAC-gated
    // sysctls such as core_pattern are not denied by the capability
    // drop). RED with the verdict relaxed to Ok(()) — the pre-fix
    // warn-only behaviour.
    let err = masked_proc_ro_remount_verdict("/mnt/rootfs/proc", Errno::EPERM)
        .expect_err("a failed read-only remount must refuse the mount");
    let msg = format!("{err}");
    assert!(
        msg.contains("/mnt/rootfs/proc"),
        "the refusal must name the mount: {msg}"
    );
    assert!(
        msg.contains("not permitted"),
        "the refusal must state the mount is refused: {msg}"
    );
    assert!(
        msg.contains("EPERM"),
        "the refusal must carry the remount errno: {msg}"
    );
}

// ── hardening steps that must REFUSE the mount, not degrade ──
//
// The three layers below each widen the blast radius across tenants when they
// silently degrade: a busybox hot-bind that is not provably read-only hands
// the warden's binary to a writable alias (or leaves the agent's own binary),
// and an unsecurable /proc//dev target leaves the template's tree in place.
// All three return Err; mount_workspace propagates it and the sandlot destroys
// the VM. These tests pin the Err verdicts without mount privileges.

#[test]
fn hot_busybox_bind_failure_refuses_the_mount() {
    // Outside the guest initramfs the boot-built read-only source does not
    // exist, so the bind/flip must fail; the failure must reach the caller as
    // an error instead of being swallowed (the old warn-and-continue shape).
    if Path::new(BUSYBOX_SOURCE_RO).exists() {
        eprintln!(
            "skipping: {} exists on this host (guest-only path)",
            BUSYBOX_SOURCE_RO
        );
        return;
    }
    let dir = test_dir("warden_test_hot_busybox_fail");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("bin")).expect("mkdir bin");
    std::fs::write(dir.join("bin/busybox"), b"agent busybox").expect("write busybox");
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let anchor = RootAnchor::open(dir.to_str().unwrap(), &logger).expect("anchor");

    let err = overlay_hot_busybox(&anchor, &logger)
        .expect_err("a failed busybox hot-bind must refuse the mount");
    let msg = format!("{err}");
    assert!(
        msg.contains("busybox hot-bind"),
        "the refusal must name the step: {msg}"
    );
    assert!(
        msg.contains("refusing the mount"),
        "the refusal must state the mount is refused: {msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An fd on a NON-directory: every relative openat under it answers ENOTDIR,
/// which is exactly the "target could not be secured" verdict these tests need
/// without a real rootfs mount.
fn non_directory_anchor() -> RootAnchor {
    RootAnchor {
        fd: std::fs::File::open("/dev/null").expect("open /dev/null"),
    }
}

#[test]
fn masked_proc_unsecurable_target_refuses_the_mount() {
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let anchor = non_directory_anchor();
    let err = setup_masked_proc(&anchor, &logger, true)
        .expect_err("an unsecurable /proc target must refuse the mount");
    let msg = format!("{err}");
    assert!(
        msg.contains("/proc") || msg.contains("proc"),
        "the refusal must name the masked /proc target: {msg}"
    );
    assert!(
        msg.contains("refusing the mount"),
        "the refusal must state the mount is refused: {msg}"
    );
}

#[test]
fn minimal_dev_unsecurable_target_refuses_the_mount() {
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let anchor = non_directory_anchor();
    let err = setup_minimal_dev(&anchor, &logger, true)
        .expect_err("an unsecurable /dev target must refuse the mount");
    let msg = format!("{err}");
    assert!(
        msg.contains("/dev") || msg.contains("dev"),
        "the refusal must name the minimal /dev target: {msg}"
    );
    assert!(
        msg.contains("refusing the mount"),
        "the refusal must state the mount is refused: {msg}"
    );
}

// ── warden-owned binds + teardown umount containment ────────────────

#[test]
fn bind_ro_remount_flags_composition() {
    // The remount is the load-bearing half: a bare MS_BIND (the old
    // busybox hot-bind) leaves a WRITABLE alias of a warden-owned source
    // in the agent's tree. The root-gated test below pins the kernel's
    // side (MNT_READONLY really applies); this pins the call composition.
    let f = bind_ro_remount_flags();
    assert!(
        f.contains(MsFlags::MS_BIND),
        "the remount must target the bind"
    );
    assert!(
        f.contains(MsFlags::MS_REMOUNT),
        "without MS_REMOUNT the flags are dropped"
    );
    assert!(
        f.contains(MsFlags::MS_RDONLY),
        "the whole point: the bound warden file must not be writable through the alias"
    );
    assert_ne!(
        f,
        MsFlags::MS_BIND,
        "bind_ro must never degrade to the one-shot MS_BIND that the kernel silently ignores the RO flag of"
    );
}

#[test]
fn umount_target_kind_classifies_before_umount() {
    // The umount predicate: umount(2) resolves symlinks, so a symlink target
    // must never reach it. Pinned without mount privileges.
    let dir = test_dir("warden_test_umount_kind");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::create_dir(dir.join("real")).expect("mkdir real");
    std::fs::write(dir.join("file"), b"x").expect("write file");
    std::os::unix::fs::symlink("/proc", dir.join("run")).expect("plant symlink");

    assert_eq!(
        umount_target_kind(dir.join("real").to_str().unwrap()),
        UmountTargetKind::Real
    );
    assert_eq!(
        umount_target_kind(dir.join("file").to_str().unwrap()),
        UmountTargetKind::Real
    );
    assert_eq!(
        umount_target_kind(dir.join("run").to_str().unwrap()),
        UmountTargetKind::Symlink,
        "a planted symlink must be classified as such — never handed to umount(2)"
    );
    assert_eq!(
        umount_target_kind(dir.join("ghost").to_str().unwrap()),
        UmountTargetKind::Absent
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// Requires root (mount(2)); marked #[ignore].
//
// regression pin, live-kernel half: a warden-owned source bound through
// bind_ro must show `ro` in mountinfo and reject a write through the
// bind with EROFS — while the SOURCE stays writable (per-mount flag: the
// warden keeps full control of its own file) and the /dev/null cover
// keeps working as a device (redirects to /dev/null must not break).
// Verified on kernel 7.0.0-1014-gcp: the remount form applies
// to file binds and char-device binds alike; the one-shot MS_BIND form is
// the one the kernel drops (share_bind_flags_land_in_mountinfo).
// Requires root (mount(2)); marked #[ignore].
//
// Follow-up: the bind is made read-only through mount_setattr(2)
// with AT_EMPTY_PATH on the anchor fd — the path-based MS_REMOUNT cannot
// do it through /proc/self/fd/N (EINVAL, verified live on the guest
// kernel, which is why this test exists: it pins the fd-anchored
// primitive itself, not just the flag word).
#[test]
#[ignore]
fn bind_ro_fd_makes_the_bind_read_only() {
    let dir = test_dir("warden_test_bind_ro_fd");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    // A warden-owned file as the bind SOURCE (what /bin/busybox is).
    let src = dir.join("src_busybox");
    std::fs::write(&src, b"#!/bin/sh\necho real\n").expect("write src");
    let target_path = dir.join("bin_busybox");
    std::fs::write(&target_path, b"agent file\n").expect("write target");

    let target = std::fs::File::open(&target_path).expect("open target");
    let res = bind_ro_fd(
        src.to_str().unwrap(),
        &target,
        target_path.to_str().unwrap(),
        &logger,
    );
    // Read the verdict BEFORE tearing the bind down, then always clean up.
    let write_res = std::fs::write(&target_path, b"tamper");
    let opts = std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .find(|l| l.split_whitespace().nth(4) == Some(target_path.to_str().unwrap()))
        .map(|l| l.split_whitespace().nth(5).unwrap_or("").to_string());
    let _ = nix::mount::umount(target_path.to_str().unwrap());
    drop(target);
    let _ = std::fs::remove_dir_all(&dir);

    res.expect("bind_ro_fd must succeed on a root-gated kernel with mount_setattr");
    assert!(
        write_res.is_err(),
        "a write through the bound name must be refused (got {:?}) — a writable alias of the warden's file is the cross-tenant payload",
        write_res
    );
    match opts {
        Some(o) => assert!(
            o.split(',').any(|f| f == "ro"),
            "mountinfo must show ro, got {o}"
        ),
        None => panic!("the bind is not in mountinfo at all"),
    }
}

// Root-gated: mounts a tmpfs and remounts it read-only.
//
// Kill-chain layer 2 pin: the busybox hot-bind source must be immutable to
// an escaped tenant (uid 0, no capabilities). A write must fail EROFS; a
// capability-less child's attempt to remount it rw must fail EPERM. RED if
// the remount-ro is dropped (write succeeds) or the source is left rw.
#[test]
#[ignore]
fn busybox_ro_source_refuses_write_and_cap_less_remount() {
    let dir = test_dir("warden_test_busybox_ro_src");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let src = dir.join("src_busybox");
    std::fs::write(&src, b"#!/bin/sh\necho real\n").expect("write src");
    let ro_dir = dir.join("ro");
    std::fs::create_dir_all(&ro_dir).expect("mkdir ro");
    let dest = ro_dir.join("busybox");
    setup_ro_tmpfs_source(
        ro_dir.to_str().unwrap(),
        src.to_str().unwrap(),
        dest.to_str().unwrap(),
    )
    .expect("RO tmpfs source must set up on a root-gated kernel");

    let mode = std::fs::metadata(&dest)
        .expect("stat dest")
        .permissions()
        .mode()
        & 0o777;
    let write_res = std::fs::OpenOptions::new().write(true).open(&dest);
    let write_errno = write_res.as_ref().err().and_then(|e| e.raw_os_error());

    // Child: drop to an unprivileged uid (setuid from root clears the
    // permitted/effective capability sets — the same no-CAP_SYS_ADMIN
    // position as an escaped tenant), then try to flip the tmpfs rw.
    // 0 = remount refused (the layer holds); 1 = remount SUCCEEDED (RED);
    // 2 = this probe could not drop privileges (harness failure).
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        unsafe {
            libc::setgroups(0, std::ptr::null());
        }
        if unsafe { libc::setgid(65534) } != 0 || unsafe { libc::setuid(65534) } != 0 {
            std::process::exit(2);
        }
        let r = nix::mount::mount::<Path, Path, str, str>(
            None,
            ro_dir.as_path(),
            None,
            MsFlags::MS_REMOUNT,
            None,
        );
        std::process::exit(if r.is_err() { 0 } else { 1 });
    }
    let mut status = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    // libc::WEXITSTATUS is a pure bit-shift helper in this libc version —
    // no unsafe block needed (the waitpid above is the actual syscall).
    let child_rc = libc::WEXITSTATUS(status);
    let _ = nix::mount::umount(ro_dir.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(mode, 0o555, "the RO source must carry mode 0555");
    assert_eq!(
        write_errno,
        Some(libc::EROFS),
        "a write to the RO source must fail EROFS (got {:?})",
        write_res.err()
    );
    assert_ne!(
        child_rc, 1,
        "a capability-less process remounted the source rw — the kill-chain layer is absent"
    );
    assert_eq!(
        child_rc, 0,
        "the cap-drop probe failed to reach its assertion (exit {})",
        child_rc
    );
}

#[test]
#[ignore]
fn bind_ro_applies_read_only_remount() {
    let dir = test_dir("warden_test_bind_ro");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir src");
    std::fs::create_dir_all(dir.join("t")).expect("mkdir t");
    let src = dir.join("src");
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    if baremount(
        std::path::Path::new("tmpfs"),
        &src,
        "tmpfs",
        MsFlags::empty(),
        "size=1m",
        &logger,
    )
    .is_err()
    {
        let _ = std::fs::remove_dir_all(&dir);
        panic!("tmpfs mount failed (not root?)");
    }
    std::fs::write(src.join("wardenfile"), b"warden payload").expect("write source");
    stat::mknod(
        &src.join("null"),
        stat::SFlag::S_IFCHR,
        stat::Mode::from_bits_truncate(0o666),
        nix::sys::stat::makedev(1, 3),
    )
    .expect("mknod null");

    let file_target = dir.join("t/file");
    let dev_target = dir.join("t/null");
    std::fs::write(&file_target, b"").expect("touch file target");
    std::fs::write(&dev_target, b"").expect("touch dev target");

    let r1 = bind_ro(
        src.join("wardenfile").to_str().unwrap(),
        file_target.to_str().unwrap(),
        &logger,
    );
    let r2 = bind_ro(
        src.join("null").to_str().unwrap(),
        dev_target.to_str().unwrap(),
        &logger,
    );

    // mountinfo: the bind must carry `ro` (MNT_READONLY really applied).
    let mounts = fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
    let mount_opts = |target: &str| -> Vec<String> {
        mounts
            .lines()
            .find_map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 6 || f[4] != target {
                    None
                } else {
                    Some(f[5].split(',').map(String::from).collect())
                }
            })
            .unwrap_or_default()
    };
    let o_file = mount_opts(file_target.to_str().unwrap());
    let o_dev = mount_opts(dev_target.to_str().unwrap());

    // The write through the alias must fail EROFS; the source stays
    // warden-writable (the RO flag is per-mount, not on the inode).
    let write_alias = std::fs::write(&file_target, b"trojan");
    let write_source = std::fs::write(src.join("wardenfile"), b"warden payload");
    // The /dev/null cover must keep working as a device (read empty,
    // write discarded) — a shell's `> /dev/null` must not start failing.
    let dev_write = (|| -> std::io::Result<()> {
        use std::io::Write as _;
        let mut f = fs::OpenOptions::new().write(true).open(&dev_target)?;
        f.write_all(b"discard")?;
        Ok(())
    })();
    let dev_read = std::fs::read(&dev_target);

    let _ = nix::mount::umount(file_target.to_str().unwrap());
    let _ = nix::mount::umount(dev_target.to_str().unwrap());
    let _ = nix::mount::umount(src.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);

    if r1.is_err() || r2.is_err() {
        panic!(
            "bind_ro failed (not root?): r1={:?} r2={:?}",
            r1.err(),
            r2.err()
        );
    }
    assert!(
        o_file.contains(&"ro".to_string()),
        "the file bind is not read-only in mountinfo (opts={o_file:?}) — the warden's file stays agent-writable"
    );
    assert!(
        o_dev.contains(&"ro".to_string()),
        "the device bind is not read-only in mountinfo (opts={o_dev:?})"
    );
    match write_alias {
        Err(e) if e.raw_os_error() == Some(libc::EROFS) => {}
        other => panic!(
            "a write through the read-only bind must fail with EROFS, got: {:?}",
            other.map(|_| ())
        ),
    }
    assert!(
        write_source.is_ok(),
        "the SOURCE must stay warden-writable: MS_REMOUNT|MS_BIND|MS_RDONLY is per-mount, not per-inode"
    );
    assert!(
        dev_write.is_ok(),
        "writing to a /dev/null cover through the read-only bind must still work (shells redirect to it): {:?}",
        dev_write.err()
    );
    assert_eq!(
        dev_read.expect("read /dev/null cover"),
        b"",
        "the /dev/null cover must still read as empty"
    );
}

// Requires root (mount(2)); marked #[ignore].
//
// regression pin, live-kernel half: umount(2) resolves symlinks (verified
// on kernel 7.0.0-1014-gcp: `ln -s <mnt> run; umount run`
// detaches the target), so a planted `<root>/run -> <warden mount>` made
// the teardown unmount the WARDEN's own mount. The victim tmpfs stands in
// for /proc; the real path must still be torn down.
#[test]
#[ignore]
fn umount_teardown_never_follows_planted_symlink() {
    let dir = test_dir("warden_test_umount_symlink");
    let victim = test_dir("warden_test_umount_victim");
    for d in [&dir, &victim] {
        let _ = std::fs::remove_dir_all(d);
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    if baremount(
        std::path::Path::new("tmpfs"),
        &victim,
        "tmpfs",
        MsFlags::empty(),
        "size=1m",
        &logger,
    )
    .is_err()
    {
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&victim);
        panic!("tmpfs mount failed (not root?)");
    }
    // The plant: `<root>/run -> <victim>` (the attack renames its target).
    let planted = dir.join("run");
    std::os::unix::fs::symlink(&victim, &planted).expect("plant symlink");

    let mut mounts = MountSet::snapshot().expect("mountinfo snapshot");
    teardown_masked(dir.to_str().unwrap(), &mut mounts);

    let survived = is_mounted(victim.to_str().unwrap()).unwrap_or(false);
    let still_link = std::fs::symlink_metadata(&planted)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    // Control: a REAL target under the same root is still torn down —
    // the helper must not have become a no-op.
    let real = dir.join("tmp");
    std::fs::remove_file(&planted).expect("remove symlink");
    std::fs::create_dir_all(&real).expect("mkdir tmp");
    let real_mounted = baremount(
        std::path::Path::new("tmpfs"),
        &real,
        "tmpfs",
        MsFlags::empty(),
        "size=1m",
        &logger,
    )
    .is_ok();
    // A FRESH snapshot: the control mount happened after the first teardown,
    // so the old set must not name it — this is also the API contract the
    // unmount path relies on (snapshot at teardown start, once per teardown).
    let mut mounts = MountSet::snapshot().expect("mountinfo snapshot");
    teardown_masked(dir.to_str().unwrap(), &mut mounts);
    let real_survived = is_mounted(real.to_str().unwrap()).unwrap_or(false);

    let _ = nix::mount::umount(victim.to_str().unwrap());
    let _ = nix::mount::umount(real.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&victim);

    assert!(
        survived,
        "the planted symlink WAS followed: the warden's own mount under the link target was unmounted"
    );
    assert!(
        still_link,
        "the planted symlink must be left alone, not followed"
    );
    assert!(real_mounted, "control tmpfs mount failed");
    assert!(
        !real_survived,
        "teardown must still unmount a REAL mount target — the symlink rule must not disable the whole teardown"
    );
}

// ── cross-tenant residue sweep parsing ───────────────────────────

#[test]
fn parse_sysvipc_ids_extracts_id_column() {
    // REAL kernel format: decimal key, decimal id (verified against
    // /proc/sysvipc/msg on this kernel family — see the function doc).
    let msg = "       key      msqid perms      cbytes qnum ...\n\
               1364283729          0   666           0    1\n\
               987654321          17   644           5    2\n";
    assert_eq!(parse_sysvipc_ids(msg), vec![0, 17]);
    // Header-only table: nothing to remove.
    assert!(parse_sysvipc_ids("key msqid ...\n").is_empty());
    // Junk rows are skipped, not fatal.
    assert_eq!(parse_sysvipc_ids("key\nnotakey\nk 3\n"), vec![3]);
}

// ── sock_diag dead-state cleanup ────────────────────────────────

#[test]
fn sock_diag_message_wire_layout() {
    // The builder writes raw bytes; pin the ABI it must produce:
    // nlmsghdr(16) + inet_diag_req_v2(56) = 72, field offsets included.
    let wild = sock_diag_msg(
        SOCK_DIAG_BY_FAMILY,
        NLMSG_F_REQUEST | NLMSG_F_DUMP,
        7,
        2,
        0x60,
        None,
    );
    assert_eq!(wild.len(), 72);
    assert_eq!(u32::from_ne_bytes(wild[0..4].try_into().unwrap()), 72); // len
    assert_eq!(
        u16::from_ne_bytes(wild[4..6].try_into().unwrap()),
        SOCK_DIAG_BY_FAMILY
    );
    assert_eq!(
        u16::from_ne_bytes(wild[6..8].try_into().unwrap()),
        NLMSG_F_REQUEST | NLMSG_F_DUMP
    );
    assert_eq!(u32::from_ne_bytes(wild[8..12].try_into().unwrap()), 7); // seq
    assert_eq!(wild[16], 2); // family AF_INET
    assert_eq!(wild[17], libc::IPPROTO_TCP as u8);
    assert_eq!(u32::from_ne_bytes(wild[20..24].try_into().unwrap()), 0x60); // states
                                                                            // Wildcard id: zeros, then INET_DIAG_NOCOOKIE at offset 60..68.
    assert!(wild[24..64].iter().all(|&b| b == 0));
    let nocookie: Vec<u8> = 0xffffffffu32
        .to_ne_bytes()
        .iter()
        .copied()
        .chain(0xffffffffu32.to_ne_bytes().iter().copied())
        .collect();
    assert_eq!(&wild[64..72], &nocookie[..]);
    // Echoed id lands verbatim at 24..72.
    let id = [7u8; 48];
    let d = sock_diag_msg(
        SOCK_DESTROY,
        NLMSG_F_REQUEST | NLMSG_F_ACK,
        9,
        10,
        0,
        Some(&id),
    );
    assert_eq!(d.len(), 72);
    assert_eq!(
        u16::from_ne_bytes(d[4..6].try_into().unwrap()),
        SOCK_DESTROY
    );
    assert_eq!(&d[24..72], &id[..]);
    assert_eq!(u32::from_ne_bytes(d[20..24].try_into().unwrap()), 0);
}

#[test]
fn nl_message_iteration_and_state_mask() {
    let mut buf = Vec::new();
    // msg1: len=24, type=SOCK_DIAG_BY_FAMILY, payload 8 bytes.
    buf.extend_from_slice(&24u32.to_ne_bytes());
    buf.extend_from_slice(&20u16.to_ne_bytes());
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&1u32.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&[0u8; 8]);
    // msg2: len=16, type=NLMSG_DONE (no payload).
    buf.extend_from_slice(&16u32.to_ne_bytes());
    buf.extend_from_slice(&3u16.to_ne_bytes());
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&2u32.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    let msgs = nl_messages(&buf);
    assert_eq!(msgs.len(), 2);
    assert_eq!(nl_type(msgs[0]), 20);
    assert_eq!(nl_type(msgs[1]), 3);
    // (The mask's membership is pinned at COMPILE time next to the const.)
    let _ = (DEAD_TCP_STATE_BITS, 1u32, 6u32, 10u32);
    // Truncated header breaks iteration, not panics.
    assert!(nl_messages(&buf[..3]).is_empty());
}

// Plants a loopback TIME_WAIT (fixed port), runs the sweep, asserts the
// planted row is gone. Root-only (netlink): cargo test -- --ignored.
#[test]
#[ignore]
fn sock_diag_destroys_planted_time_wait() {
    let port: u16 = 47123; // 0xB863
    let hex_port = format!(":{:04X}", port);
    let count_rows = |t: &str| -> usize {
        t.lines()
            .skip(1)
            .filter(|l| {
                let c: Vec<&str> = l.split_whitespace().collect();
                c.len() > 3
                    && c[3] == "06"
                    && (c[1].contains(&hex_port) || c[2].contains(&hex_port))
            })
            .count()
    };
    // Plant with retries: sibling tests in this binary also invoke the
    // sweep (which destroys EVERY dead-state socket in the netns), so a
    // freshly planted TIME_WAIT can be collateralized before the read —
    // and a leftover TIME_WAIT from a previous attempt makes the bind
    // fail with AddrInUse until it ages out. Both are retried, bounded.
    let mut before = String::new();
    for _ in 0..8 {
        let plant = (|| -> Option<()> {
            let l = std::net::TcpListener::bind(("127.0.0.1", port)).ok()?;
            let c = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
            let (a, _) = l.accept().ok()?;
            drop(c);
            drop(a);
            drop(l);
            Some(())
        })();
        if plant.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
        before = fs::read_to_string("/proc/net/tcp").unwrap();
        if count_rows(&before) > 0 {
            break;
        }
    }
    assert!(
        count_rows(&before) > 0,
        "plant failed: no TIME_WAIT row after retries"
    );
    let (d, f) = destroy_dead_tcp_sockets();
    eprintln!("destroyed={d} failed={f}");
    std::thread::sleep(std::time::Duration::from_millis(150));
    let after = fs::read_to_string("/proc/net/tcp").unwrap();
    assert_eq!(
        count_rows(&after),
        0,
        "planted TIME_WAIT survived the sock_diag destroy"
    );
}

// ── rule-A sweep target predicate ─────────────────────────────

#[test]
fn sweep_target_exempts_init_and_kernel_threads() {
    // PID 1 (the warden) and 0 (swapper, never in /proc as killable) are
    // exempt, and so is pid 2: on any Linux it is kthreadd, a kernel
    // thread whose /proc entry never goes away and whose signal is a
    // silent no-op — counting it made every sweep round look productive
    // and burned the 8 × 25 ms budget on every unmount.
    assert!(!sweep_target_pid(0));
    assert!(!sweep_target_pid(1));
    assert!(!sweep_target_pid(-1)); // defensive: never a real pid here
                                    // A pid with no /proc entry (just-exited, or absurd) is not a target.
    assert!(!sweep_target_pid(999_999));
    if let Ok(stat) = std::fs::read_to_string("/proc/2/stat") {
        // On a container/namespace where pid 2 is not kthreadd the
        // predicate legitimately says true; where it IS a kernel thread
        // it must never be a sweep target.
        if !stat_line_is_live_userspace(&stat) {
            assert!(!sweep_target_pid(2), "kthreadd must not be a sweep target");
        }
    }
}

#[test]
fn stat_line_parsing_handles_comm_with_spaces_and_parens() {
    const PF_KTHREAD: u64 = 0x0020_0000;
    // Real layout after comm: state ppid pgrp session tty_nr tpgid flags …
    let live = |pid: i32, comm: &str, state: char, flags: u64| {
        format!("{pid} ({comm}) {state} 1 {pid} {pid} 0 -1 {flags} 0 0 0 0")
    };
    // Live userspace: targeted.
    assert!(stat_line_is_live_userspace(&live(42, "sh", 'S', 0x400000)));
    // comm with spaces and parens — the classic parse trap.
    assert!(stat_line_is_live_userspace(&live(
        43,
        "sh -c echo (hi)",
        'R',
        0x400000
    )));
    // Kernel thread: PF_KTHREAD set → exempt.
    assert!(!stat_line_is_live_userspace(&live(
        2,
        "kthreadd",
        'S',
        0x400000 | PF_KTHREAD
    )));
    // Zombies and dead states: exempt (no mount is held by a corpse).
    assert!(!stat_line_is_live_userspace(&live(44, "sh", 'Z', 0x400000)));
    assert!(!stat_line_is_live_userspace(&live(45, "sh", 'X', 0x400000)));
    // Malformed / truncated lines are never counted as killed targets.
    assert!(!stat_line_is_live_userspace(""));
    assert!(!stat_line_is_live_userspace("42 sh S"));
    assert!(!stat_line_is_live_userspace("42 (sh) S"));
}

#[test]
fn proc_stat_state_reads_field_three() {
    // Same LAST-')' rule: a comm containing parens must not shift the state.
    assert_eq!(proc_stat_state("2 (kthreadd) S 0 0 0 0 0 0 0"), Some('S'));
    assert_eq!(
        proc_stat_state("44 (sh -c echo (hi)) Z 1 44 44 0 -1 0 0"),
        Some('Z')
    );
    assert_eq!(proc_stat_state(""), None);
    assert_eq!(proc_stat_state("no-paren"), None);
}

#[test]
fn final_gate_predicate_flags_any_live_userspace() {
    const PF_KTHREAD: u64 = 0x0020_0000;
    // Real layout after comm: state ppid pgrp session tty_nr tpgid flags …
    let live = |pid: i32, comm: &str, state: char, flags: u64| {
        format!("{pid} ({comm}) {state} 1 {pid} {pid} 0 -1 {flags} 0 0 0 0")
    };
    // Positive: an unreaped zombie, a D-state userspace task, and every other
    // live userspace state (R/S/T) fail the gate. A survivor of the bounded
    // sweep is exactly this class: it pins /mnt/rootfs and can race the
    // teardown lstat->umount, so the VM must be destroyed, not reused.
    assert!(stat_line_is_unclean(&live(44, "sh", 'Z', 0x400000)));
    assert!(stat_line_is_unclean(&live(46, "dd", 'D', 0x400000)));
    // comm with spaces and parens must not shift the state field.
    assert!(stat_line_is_unclean(&live(
        47,
        "sh -c echo (hi)",
        'D',
        0x400000
    )));
    assert!(stat_line_is_unclean(&live(42, "sh", 'R', 0x400000)));
    assert!(stat_line_is_unclean(&live(43, "sh", 'S', 0x400000)));
    assert!(stat_line_is_unclean(&live(45, "sh", 'T', 0x400000)));
    // Kernel threads: 'D' is their normal parking state and they ignore
    // every signal — never a gate hit.
    assert!(!stat_line_is_unclean(&live(
        2,
        "kworker/u8:0",
        'D',
        0x400000 | PF_KTHREAD
    )));
    // Malformed / truncated lines FAIL CLOSED : the gate cannot prove
    // the process is not a live tenant, so it must report unclean rather than
    // silently skip it (the old behavior let a non-UTF-8 comm through).
    assert!(stat_line_is_unclean(""));
    assert!(stat_line_is_unclean("42 sh D"));
    assert!(stat_line_is_unclean("42 (sh) D"));
}

#[test]
fn invalid_utf8_comm_is_never_treated_as_vanished() {
    // Regression pin: `prctl(PR_SET_NAME)` is allowed by the seccomp
    // filter, and the kernel prints comm as raw bytes. The old
    // `read_to_string` returned Err(InvalidData), which both the rule-A
    // sweep and the final gate interpreted as "the process vanished".
    // The byte path must instead classify the line normally (the numeric
    // tail after the last ')' is ASCII regardless of the comm bytes).
    let bad_comm = b"42 (\xff\xff\xff\xff) S 1 42 42 0 -1 4194304 0 0 0 0";
    assert!(stat_bytes_are_sweep_target(bad_comm));
    assert!(stat_bytes_are_unclean(bad_comm));

    // A real kernel-thread line (kthreadd: flags carries PF_KTHREAD) stays
    // exempt — the fail-closed change must not reintroduce the 200ms
    // every-switch regression that counting kernel threads caused.
    let kthread = b"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0";
    assert!(!stat_bytes_are_sweep_target(kthread));
    assert!(!stat_bytes_are_unclean(kthread));

    // A truncated numeric tail after a valid comm also fails closed.
    assert!(stat_bytes_are_sweep_target(b"42 (sh) S"));
    assert!(stat_bytes_are_unclean(b"42 (sh) S"));

    // Zombie and dead states stay non-targets for the sweep but unclean
    // for the gate.
    let zombie = b"44 (sh) Z 1 44 44 0 -1 4194304 0 0 0 0";
    assert!(!stat_bytes_are_sweep_target(zombie));
    assert!(stat_bytes_are_unclean(zombie));
}

#[test]
fn masked_proc_covers_kernel_address_and_physical_map_files() {
    // vmallocinfo prints raw %pK addresses when kptr_restrict=0;
    // iomem/ioports expose the physical map; modules the loaded-image list.
    for name in ["vmallocinfo", "iomem", "ioports", "modules"] {
        assert!(
            crate::mount::hardening::MASKED_PROC_ENTRIES.contains(&name),
            "{name} must be in MASKED_PROC_ENTRIES"
        );
    }
}

#[test]
fn kernel_sysctl_hardening_covers_the_information_channels() {
    let pairs = crate::mount::hardening::KERNEL_SYSCTL_HARDENING;
    assert!(pairs.contains(&("/proc/sys/kernel/kptr_restrict", "2")));
    assert!(pairs.contains(&("/proc/sys/kernel/dmesg_restrict", "1")));
    assert!(pairs.contains(&("/proc/sys/kernel/perf_event_paranoid", "3")));
    assert!(pairs.contains(&("/proc/sys/kernel/unprivileged_bpf_disabled", "2")));
}

// Regression: the final gate must never exempt a pid based only on an
// earlier sweep classification. A pid is not an identity — a kernel thread
// can exit and its pid be recycled to a userspace task — so such an
// exemption would be a fail-open in the last control that proves the guest
// clean. The gate must report a live pid even when that pid is passed as a
// sweep hint: a hint is observability only.
#[test]
fn stale_kthread_hint_never_exempts_a_live_pid() {
    // The child's exit is gated BEHIND our stdin write (`read` blocks until
    // then): no wall-clock assumption about /bin/sh scheduling on a loaded
    // build host (the same discipline as the exec.rs registry tests). We
    // NEVER try_wait/wait before the scan assertions — any wait reaps the
    // zombie and the pid vanishes from /proc (try_wait's Ok(Some) means
    // "reaped", not "zombie exists").
    let _proc_guard = crate::test_sync::proc_lock();
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("read _; exit 0")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn probe child");
    let pid = child.id() as i32;
    let mut gate = child.stdin.take().expect("child stdin");
    // Release the child: `read` returns, `exit 0` runs, the zombie is ours
    // (nobody else reaps: every reap probe in this suite holds proc_lock).
    use std::io::Write;
    gate.write_all(b"go\n").expect("release child");
    drop(gate);
    let mut reported_with_hint = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if unclean_pids(&[]).expect("scan /proc").contains(&pid) {
            // The SAME pid, now claimed as a sweep-proven kernel thread:
            // the hint must NOT exempt it.
            let hinted = unclean_pids(&[pid]).expect("scan /proc");
            assert!(
                hinted.contains(&pid),
                "a sweep kernel-thread HINT must never exempt a live pid — \
                 a recycled pid would otherwise skip the final gate"
            );
            reported_with_hint = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        reported_with_hint,
        "the live zombie {pid} was never reported by a fresh scan"
    );
    let _ = child.wait();
}

// Regression: a sweep that exhausts its round budget while still signalling
// live targets proves NOTHING. It must return an error so the unmount fails
// and the VM is destroyed; returning Ok would let the final gate decide on
// an unproven guest.
#[test]
fn sweep_budget_exhaustion_is_an_error() {
    // Always killing: never converges -> Err after exactly max_rounds.
    let mut rounds = 0usize;
    let mut waits = 0usize;
    let r = run_sweep(
        || {
            rounds += 1;
            Ok(1)
        },
        3,
        || waits += 1,
    );
    assert!(
        r.is_err(),
        "a sweep that never observes a zero-kill round must fail"
    );
    assert_eq!(rounds, 3, "the loop must use the whole budget before failing");
    assert_eq!(waits, 3, "a wait follows every non-zero round");
    // Converges on the zero-kill round: Ok, and no wait after it.
    let mut rounds = 0usize;
    let mut waits = 0usize;
    let r = run_sweep(
        || {
            rounds += 1;
            Ok(if rounds < 3 { 2 } else { 0 })
        },
        8,
        || waits += 1,
    );
    assert!(r.is_ok(), "a zero-kill round must end the loop with Ok");
    assert_eq!((rounds, waits), (3, 2));
    // A /proc scan error propagates instead of being treated as "clean".
    let r = run_sweep(|| Err(std::io::Error::other("scan failed")), 8, || {});
    assert!(r.is_err(), "a scan failure must propagate");
}

// Regression: a mountinfo read failure must not degrade to an EMPTY mount
// set — that silently skips every teardown probe (one transient read error
// would disable the whole teardown). It must surface as an error so the
// unmount can fail closed (destroy the VM).
#[test]
fn mountinfo_snapshot_read_failure_is_an_error() {
    let err = match MountSet::snapshot_from(|| Err(std::io::Error::other("boom"))) {
        Ok(_) => panic!("a mountinfo read failure must be an error, not an empty set"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("boom"));
    // A successful read still parses normally.
    let set = MountSet::snapshot_from(|| Ok("22 20 0:21 / / rw - ext4 rw\n".to_string()))
        .expect("parse a synthetic mountinfo");
    assert!(
        set.contains("/"),
        "the parser must still find a real mount point"
    );
}

// Requires root (mount(2)); marked #[ignore].
//
// Pins the teardown snapshot contract: umount_verified detaches a path the
// snapshot names, skips (without any umount(2)) a path it does not, and the
// set stops naming a path after THIS teardown detached it.
#[test]
#[ignore]
fn umount_verified_uses_the_teardown_snapshot() {
    let dir = test_dir("warden_test_umount_snapshot");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let member = dir.join("tmp");
    std::fs::create_dir_all(&member).expect("mkdir member");
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    if baremount(
        std::path::Path::new("tmpfs"),
        &member,
        "tmpfs",
        MsFlags::empty(),
        "size=1m",
        &logger,
    )
    .is_err()
    {
        let _ = std::fs::remove_dir_all(&dir);
        panic!("tmpfs mount failed (not root?)");
    }
    let non_member = dir.join("run");
    std::fs::create_dir_all(&non_member).expect("mkdir non-member");

    let mut mounts = MountSet::snapshot().expect("mountinfo snapshot");
    assert!(
        mounts.contains(member.to_str().unwrap()),
        "the live tmpfs must be in the snapshot"
    );
    assert!(
        !mounts.contains(non_member.to_str().unwrap()),
        "a plain directory must not be in the snapshot"
    );
    // The mount-path fallback (used when the one-read snapshot fails) must
    // still see a live mount: per_probe() re-reads mountinfo per probe.
    assert!(
        MountSet::per_probe().contains(member.to_str().unwrap()),
        "the per-probe fallback must see the live mount"
    );
    assert!(
        !MountSet::per_probe().contains(non_member.to_str().unwrap()),
        "the per-probe fallback must not invent a mount"
    );

    // Absent from the snapshot: a no-op probe (no umount, no error).
    umount_verified(non_member.to_str().unwrap(), None, &mut mounts);
    assert!(
        non_member.exists(),
        "a non-member path must be left untouched"
    );
    // Named by the snapshot: detached, and removed from the set.
    umount_verified(member.to_str().unwrap(), None, &mut mounts);
    assert!(
        !is_mounted(member.to_str().unwrap()).unwrap_or(false),
        "the snapshot member must be unmounted"
    );
    assert!(
        !mounts.contains(member.to_str().unwrap()),
        "a detached path must leave the set"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unclean_pids_finds_an_unreaped_child_and_never_pid_one() {
    // Spawn a child that exits immediately and DO NOT wait for it: it is a
    // zombie until reaped. The helper must report it — that report is what
    // fails the unmount (and destroys the VM) instead of serving a guest
    // whose process table is not clean.
    // Serialized against every sibling test that spawns children or drives
    // the central reap probe: `waitpid(-1)` is process-global, so a
    // concurrently running reaper test forwards OUR child first and the
    // zombie this test waits for never exists (observed: green in
    // isolation, red in the full parallel suite). The lock is the file's
    // own established convention for exactly this.
    let _proc_guard = crate::test_sync::proc_lock();
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .spawn()
        .expect("spawn probe child");
    let pid = child.id() as i32;
    // 20 s, not 5: the child only becomes a zombie once the scheduler runs
    // it to completion, and a loaded build host (parallel cargo/go builds)
    // can stretch /bin/sh startup past a tight window — a load-sensitive
    // gate that fails healthy suites is worse than a generous deadline.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut seen = false;
    while std::time::Instant::now() < deadline {
        if unclean_pids(&[]).expect("scan /proc").contains(&pid) {
            seen = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(seen, "unreaped child {pid} not reported as unclean");
    assert!(
        !unclean_pids(&[]).expect("scan /proc").contains(&1),
        "PID 1 (the reaper itself) must never be a gate target"
    );
    // On a real kernel pid 2 is kthreadd: whatever state it parks in, the
    // PF_KTHREAD exemption must keep it out of the failing set.
    if let Ok(stat) = std::fs::read_to_string("/proc/2/stat") {
        if !stat_line_is_live_userspace(&stat) {
            assert!(
                !unclean_pids(&[]).expect("scan /proc").contains(&2),
                "kthreadd must never be reported unclean"
            );
        }
    }
    let _ = child.wait(); // reap so later tests start clean
    assert!(
        !unclean_pids(&[]).expect("scan /proc").contains(&pid),
        "reaped child {pid} must disappear from the gate set"
    );
}

// ── parse_mount_flags_and_options ──────────────────────────────

#[test]
fn parse_flags_known_flag_words() {
    // Known flag words map to MsFlags and never leak into the options
    // string (a leaked "ro" would be passed as a mount DATA option).
    let (flags, options) = parse_mount_flags_and_options(vec!["ro", "nosuid", "nodev", "noexec"]);
    assert!(flags.contains(MsFlags::MS_RDONLY));
    assert!(flags.contains(MsFlags::MS_NOSUID));
    assert!(flags.contains(MsFlags::MS_NODEV));
    assert!(flags.contains(MsFlags::MS_NOEXEC));
    assert!(!flags.contains(MsFlags::MS_BIND));
    assert_eq!(options, "");
}

#[test]
fn parse_flags_inversion_words_clear() {
    // Inverting words (rw/suid/dev/exec) CLEAR the corresponding flag.
    let (flags, _) = parse_mount_flags_and_options(vec!["rw", "suid", "dev", "exec"]);
    assert!(!flags.contains(MsFlags::MS_RDONLY));
    assert!(!flags.contains(MsFlags::MS_NOSUID));
    assert!(!flags.contains(MsFlags::MS_NODEV));
    assert!(!flags.contains(MsFlags::MS_NOEXEC));
}

#[test]
fn parse_flags_bind_and_rbind() {
    let (flags, _) = parse_mount_flags_and_options(vec!["bind"]);
    assert_eq!(flags, MsFlags::MS_BIND);
    let (flags, _) = parse_mount_flags_and_options(vec!["rbind"]);
    assert_eq!(flags, MsFlags::MS_BIND | MsFlags::MS_REC);
}

#[test]
fn parse_flags_unknown_words_become_data_options() {
    // Unknown words are filesystem-specific DATA options, comma-joined in
    // order (e.g. tmpfs "mode=1777").
    let (flags, options) = parse_mount_flags_and_options(vec!["mode=1777", "size=16m"]);
    assert_eq!(flags, MsFlags::empty());
    assert_eq!(options, "mode=1777,size=16m");
}

#[test]
fn parse_flags_empty_words_skipped() {
    let (flags, options) = parse_mount_flags_and_options(vec!["", "ro", ""]);
    assert!(flags.contains(MsFlags::MS_RDONLY));
    assert_eq!(options, "");
}

#[test]
fn parse_flags_defaults_mount_options_are_safe() {
    // The actual INIT_ROOTFS_MOUNTS options: proc/sysfs get
    // nosuid,nodev,noexec; devtmpfs gets nosuid.
    for m in INIT_ROOTFS_MOUNTS.iter() {
        let (flags, options) = parse_mount_flags_and_options(m.options.clone());
        assert!(
            flags.contains(MsFlags::MS_NOSUID),
            "{} must be nosuid",
            m.dest
        );
        assert_eq!(options, "", "{} has no data options", m.dest);
        if m.dest != "/dev" {
            assert!(
                flags.contains(MsFlags::MS_NODEV),
                "{} must be nodev",
                m.dest
            );
            assert!(
                flags.contains(MsFlags::MS_NOEXEC),
                "{} must be noexec",
                m.dest
            );
        }
    }
}

// ── setup ↔ teardown symmetry ──────────────────────────────────

#[test]
fn teardown_covers_every_setup_mount_point() {
    // Every sub-path that setup_minimal_dev / setup_masked_proc /
    // setup_fresh_tmpfs can mount a filesystem on (relative to the agent
    // rootfs) must be present in TEARDOWN_RELS, else unmount_workspace
    // hits EBUSY and the VM is needlessly destroyed. The setup list is
    // restated here (from the setup fns) so adding a new mount point
    // without extending teardown fails this test. NB: some paths are
    // cleared by DEDICATED umounts in unmount_workspace (restated below)
    // rather than by TEARDOWN_RELS — the guard covers both sets.
    let setup_mounts = [
        "proc",            // setup_masked_proc
        "dev",             // setup_minimal_dev tmpfs
        "dev/pts",         // setup_minimal_dev devpts
        "dev/shm",         // setup_fresh_tmpfs via setup_minimal_dev
        "tmp",             // setup_fresh_tmpfs (overlay mode)
        "etc/resolv.conf", // inject_guest_resolv_conf read-only-rootfs fallback bind
        "run",             // legacy path kept in teardown
    ];
    // Paths unmounted by a dedicated statement in unmount_workspace (NOT
    // via teardown_masked): the resolv fallback bind is a FILE bind under
    // {mp}/etc — see the regression test below for why leaving it mounted
    // breaks umount({mp}) with EBUSY.
    const DEDICATED_UNMOUNT_RELS: &[&str] = &["etc/resolv.conf"];
    for m in setup_mounts {
        assert!(
            TEARDOWN_RELS.contains(&m) || DEDICATED_UNMOUNT_RELS.contains(&m),
            "neither teardown_masked nor a dedicated unmount clears {} — setup/teardown asymmetry",
            m
        );
    }
}

#[test]
fn teardown_unmounts_masked_proc_covers_before_proc() {
    // The masked-proc /dev/null bind covers live UNDER <root>/proc/... and
    // must be unmounted before <root>/proc itself (EBUSY otherwise). This
    // is encoded in teardown_masked's statement order; the invariant this
    // test pins is that every masked entry is a plain proc-relative name
    // (no '/', no '..' — it must not be possible to construct an escape
    // path by editing MASKED_PROC_ENTRIES).
    for name in MASKED_PROC_ENTRIES {
        assert!(
            !name.contains('/'),
            "masked entry must be a bare name: {}",
            name
        );
        assert!(
            !name.contains(".."),
            "masked entry must not traverse: {}",
            name
        );
        assert!(!name.is_empty());
    }
}

// umount on a non-mount-point returns EINVAL. The production code
// (unmount_workspace) treats this as idempotent success so that a
// transport-error recovery path that calls unmount on an already-unmounted
// or never-mounted workspace doesn't fail. This test verifies the kernel
// behavior we rely on: a plain directory that was never mounted yields
// EINVAL from umount(2).
//
// Requires root (CAP_SYS_ADMIN) to call umount(2); marked #[ignore] so
// `cargo test` passes in unprivileged CI. Run with `cargo test -- --ignored`
// or in the initramfs where warden runs as PID 1 (root).
#[test]
#[ignore]
fn umount_non_mount_point_returns_einval() {
    let dir = test_dir("warden_test_einval");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.to_str().expect("path is utf-8");
    let result = nix::mount::umount(path);
    match result {
        Err(nix::errno::Errno::EINVAL) => {} // expected
        other => panic!(
            "umount on non-mount-point {:?} should return EINVAL, got {:?}",
            path, other
        ),
    }
    let _ = std::fs::remove_dir(&dir);
}

// tmpfs size cap: writing past the per-mount cap must yield ENOSPC at the
// writer — the plain-error degradation that replaces the guest-wide OOM
// corner (warden/PID 1 is OOM-exempt, so the un-capped end state is a dead
// VM). Regression guard for setup_fresh_tmpfs + tmpfs_size_opt.
// Requires root (mount); marked #[ignore].
#[test]
#[ignore]
fn tmpfs_size_cap_yields_enospc_not_oom() {
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let dir = test_dir("warden_test_tmpfs_cap");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir test root");
    let root = dir.to_str().expect("path is utf-8").to_string();

    // 1 MiB cap, then write 2 MiB into the mounted tmpfs.
    crate::exec_cgroup::set_tmpfs_size_for_tests(1024 * 1024);
    let anchor = RootAnchor::open(&root, &logger).expect("anchor the test root");
    setup_fresh_tmpfs(&anchor, "shm", "mode=1777", &logger, true);
    let mp = format!("{}/shm", root);
    let wrote = std::fs::write(format!("{}/fill", mp), vec![0u8; 2 * 1024 * 1024]);
    let _ = nix::mount::umount(mp.as_str());
    crate::exec_cgroup::set_tmpfs_size_for_tests(0);
    let _ = std::fs::remove_dir_all(&dir);
    match wrote {
        Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {} // the fix
        Err(e) => panic!("expected ENOSPC past the 1 MiB tmpfs cap, got: {}", e),
        Ok(()) => panic!("2 MiB write into a 1 MiB-capped tmpfs must fail with ENOSPC"),
    }
}

// Verify that umount_workspace on a path that was never mounted succeeds
// (EINVAL treated as idempotent success). This is the exact scenario that
// occurs when sandlot sends UNMOUNT after a transport error on the mount
// path: the guest never mounted anything, but unmount_workspace must still
// return Ok(()) so the VM can be reused.
//
// Requires root; marked #[ignore].
#[test]
#[ignore]
fn unmount_workspace_never_mounted_is_ok() {
    // unmount_workspace's fallback path (no cgroup) runs the global
    // reap_zombie(WNOHANG|__WALL) loop — hold the suite's proc lock so it
    // cannot steal a sibling test's zombie children (caught live by strace:
    // this loop reaped a parallel test's probe child, which then failed its
    // scan assertion with the pid gone from /proc).
    let _proc_guard = crate::test_sync::proc_lock();
    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    rt.block_on(async {
            let dir = test_dir("warden_test_unmount_never_mounted");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.to_str().expect("path is utf-8").to_string();
        // No cgroup, no background execs — pure EINVAL path. fallback_pgids
        // is empty (the async caller collects them from bg_execs before the
        // sync unmount; here there are none).
        let result = unmount_workspace(&path, None, Vec::new());
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Ok(()) => {} // idempotent success — the fix we're testing
            Err(e) => panic!(
                "unmount_workspace on never-mounted {:?} should succeed (EINVAL idempotent), got: {}",
                path, e
            ),
        }
    });
}

// Detach the root until no layer remains: a partial mount failure can leave a
// stack behind (mount_active never became true, so no other path removes it).
// Stopping after the top layer would let the next tenant's mount sit over the
// old rootfs, breaking the one-SandFS-per-VM invariant.
// Requires root; marked #[ignore].
#[test]
#[ignore]
fn unmount_workspace_removes_stacked_layers() {
    // Same as unmount_workspace_never_mounted_is_ok: the fallback reap loop
    // is process-global, so the suite's proc lock is mandatory here too.
    let _proc_guard = crate::test_sync::proc_lock();
    let dir = test_dir("warden_test_unmount_stacked");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let mp = dir.to_str().expect("path is utf-8").to_string();
    for _ in 0..2 {
        baremount(
            std::path::Path::new("tmpfs"),
            &dir,
            "tmpfs",
            MsFlags::empty(),
            "size=1m",
            &logger,
        )
        .expect("stacked tmpfs mount (root required)");
    }
    assert!(
        is_mounted(&mp).unwrap_or(false),
        "fixture: the stack must be mounted"
    );
    unmount_workspace(&mp, None, Vec::new()).expect("unmount_workspace");
    assert!(
        !is_mounted(&mp).unwrap_or(false),
        "every stacked layer must be detached (the EINVAL proof)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── warden task-attribute capture/restore (PID-1 interference) ──────
// The agent and the warden share uid 0; setpriority/sched_setaffinity
// with a same-owner target need no capability, and the values survive the
// tenant switch. The unmount restore rewrites them. These tests drive the
// restore against the TEST process's own thread (tid 0 = current);
// restore_warden_attrs itself is PID-1 gated and never touches the host.

fn cpu_set_bytes(s: &libc::cpu_set_t) -> Vec<u8> {
    unsafe {
        std::slice::from_raw_parts(
            s as *const libc::cpu_set_t as *const u8,
            std::mem::size_of::<libc::cpu_set_t>(),
        )
    }
    .to_vec()
}

#[test]
fn warden_attr_restore_rewrites_affinity_on_the_current_thread() {
    let attrs = WardenAttrs::capture_self();
    assert!(
        attrs.affinity_valid,
        "the test host must expose an affinity mask"
    );
    // Pin THIS thread to CPU 0 (per-thread, safe: other tests unaffected)
    // and confirm the capture/restore round trip.
    let mut one: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_SET(0, &mut one) };
    let size = std::mem::size_of::<libc::cpu_set_t>();
    assert_eq!(unsafe { libc::sched_setaffinity(0, size, &one) }, 0);
    let _ = restore_attrs_for_tids(&attrs, &[0]);
    let mut got: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sched_getaffinity(0, size, &mut got) }, 0);
    assert_eq!(
        cpu_set_bytes(&got),
        cpu_set_bytes(&attrs.affinity),
        "restore must reinstate the captured mask"
    );
}

#[test]
#[ignore = "root-gated: lowering nice back to the captured value needs CAP_SYS_NICE"]
fn warden_attr_restore_rewrites_nice() {
    let attrs = WardenAttrs::capture_self();
    // Raising nice is permitted without privilege; restoring the captured
    // (lower) value is the operation the warden performs as root.
    let raised = attrs.nice.saturating_add(5).min(19);
    assert!(raised > attrs.nice, "test host nice is already at the max");
    assert_eq!(
        unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, raised) },
        0
    );
    let _ = restore_attrs_for_tids(&attrs, &[0]);
    assert_eq!(
        unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) },
        attrs.nice,
        "restore must reinstate the captured nice value"
    );
}

#[test]
fn restore_warden_attrs_is_inert_outside_pid1() {
    // The production entry point must never touch the host's PID 1 when
    // the test binary runs on a host (the sweep has the same gate).
    assert_ne!(std::process::id(), 1, "unit tests run outside a guest");
    restore_warden_attrs(); // must return immediately
}

// REGRESSION (overlay mode + warden.net_dns): inject_guest_resolv_conf's
// read-only-rootfs fallback bind-mounts a tmpfs file over
// {root}/etc/resolv.conf. That file bind is a CHILD MOUNT of {root}; a
// kernel refuses umount({root}) with EBUSY while a submount exists (the
// 500ms retry cannot clear it — verified on a real kernel), so without
// the dedicated umount in unmount_workspace EVERY overlay+DNS agent
// switch ended in "unmount failed → destroy the VM". This test builds the
// exact mount shape (tmpfs root + file bind under etc/) and asserts
// unmount_workspace succeeds. Without the fix it fails with the EBUSY
// retry error, deterministically.
//
// Requires root (mount(2)); marked #[ignore].
#[test]
#[ignore]
fn unmount_workspace_clears_resolv_fallback_bind() {
    // Same as unmount_workspace_never_mounted_is_ok: the fallback reap loop
    // is process-global, so the suite's proc lock is mandatory here too.
    let _proc_guard = crate::test_sync::proc_lock();
    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    rt.block_on(async {
        let dir = test_dir("warden_test_unmount_resolv");
        let src = test_dir("warden_test_unmount_resolv_src");
        for d in [&dir, &src] {
            let _ = std::fs::remove_dir_all(d);
        }
        std::fs::create_dir_all(dir.join("etc")).expect("mkdir etc");
        std::fs::create_dir_all(&src).expect("mkdir src");
        // {root} must be a real mount point for umount({root}) to be the
        // operation under test (mirrors /mnt/rootfs being a bind mount).
        nix::mount::mount(
            Some("tmpfs"),
            dir.to_str().unwrap(),
            Some("tmpfs"),
            MsFlags::empty(),
            Some("mode=755"),
        )
        .expect("mount tmpfs root");
        // NOTE: build the tree INSIDE the fresh tmpfs — the pre-mount
        // mkdir above is shadowed by the mount (same trap as the bind
        // itself).
        std::fs::create_dir_all(dir.join("etc")).expect("mkdir etc (in tmpfs)");
        std::fs::write(dir.join("etc/resolv.conf"), b"nameserver 1.1.1.1")
            .expect("seed template resolv.conf");
        std::fs::write(src.join("resolv.conf"), b"nameserver 8.8.8.8")
            .expect("write fallback source");
        // The exact fallback bind inject_guest_resolv_conf performs.
        nix::mount::mount(
            Some(src.join("resolv.conf").to_str().unwrap()),
            dir.join("etc/resolv.conf").to_str().unwrap(),
            Some("none"),
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .expect("bind resolv fallback");

        let result = unmount_workspace(dir.to_str().unwrap(), None, Vec::new());

        // Cleanup regardless of the outcome (a failed unmount leaves the
        // tmpfs mounted; remove_dir_all alone would not release it).
        let _ = nix::mount::umount(dir.join("etc/resolv.conf").to_str().unwrap());
        let _ = nix::mount::umount(dir.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&src);
        match result {
            Ok(()) => {}
            Err(e) => panic!(
                "unmount_workspace must clear the resolv fallback bind; got: {}",
                e
            ),
        }
    });
}
// ── Share hardening flags (setuid/device neutrality) ────────────────

// The composition is the contract: every mount of the virtio-fs share and
// every bind derived from it carries NOSUID|NODEV. The FUSE passthrough
// stores guest-requested mode bits (incl. setuid) and mknod verbatim on
// the host volume, and the guest-side presentation is present-as-root —
// these flags are what makes planted bits inert at guest exec/open time
// (second layer under the pre_exec NO_NEW_PRIVS).
#[test]
fn share_hardening_flags_composition() {
    let f = share_harden_flags();
    assert!(f.contains(MsFlags::MS_NOSUID));
    assert!(f.contains(MsFlags::MS_NODEV));
    // Nothing that would change datapath semantics (ro/noexec) sneaks in.
    assert!(!f.contains(MsFlags::MS_RDONLY));
    assert!(!f.contains(MsFlags::MS_NOEXEC));
}

// Requires root (mount(2)); marked #[ignore].
//
// Pins the ACTUAL kernel contract the agent share binds rely on.
// Verified on kernel 7.0.0-1013-gcp with a raw mount(2):
// per-mount flags (MS_NOSUID/MS_NODEV) passed in the SAME call as
// MS_BIND are SILENTLY DROPPED — mountinfo shows the plain inherited
// options (rw,relatime on ext4). The old version of this test passed
// only by ACCIDENT: its tempdir sat on /tmp (a nosuid,nodev tmpfs), so
// the bind INHERITED the parent's flags and satisfied the assertion —
// a false pass that broke loudly the first time TMPDIR pointed at an
// unhardened fs. Production hardening never came from the bind call:
// ensure_virtiofs_mounted mounts the virtio-fs share at /mnt/volumes
// with share_harden_flags() (a non-bind mount — flags DO apply there),
// and every agent bind under it inherits nosuid,nodev. This test pins
// both halves of that contract:
//   1. inheritance — a bind from a hardened source carries
//      nosuid,nodev in mountinfo (what mount_workspace actually
//      relies on);
//   2. same-call flags on an unhardened source are dropped by the
//      kernel (the false premise; if a future kernel starts honoring
//      them, this half fails and the premise needs re-derivation —
//      the binds' share_harden_flags argument would then become
//      load-bearing again).
#[test]
#[ignore]
fn share_bind_flags_land_in_mountinfo() {
    let dir = test_dir("warden_test_share_flags");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("hardened_src")).expect("mkdir hardened_src");
    std::fs::create_dir_all(dir.join("plain_src")).expect("mkdir plain_src");
    std::fs::create_dir_all(dir.join("dst1")).expect("mkdir dst1");
    std::fs::create_dir_all(dir.join("dst2")).expect("mkdir dst2");

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let hardened_src = dir.join("hardened_src");
    let plain_src = dir.join("plain_src");
    let dst1 = dir.join("dst1");
    let dst2 = dir.join("dst2");

    // A hardened share root, exactly what ensure_virtiofs_mounted
    // creates at /mnt/volumes (non-bind mount — flags apply).
    let res = baremount(
        std::path::Path::new("tmpfs"),
        &hardened_src,
        "tmpfs",
        share_harden_flags(),
        "size=1m",
        &logger,
    );
    if res.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        panic!("tmpfs mount failed (not root?): {:?}", res.err());
    }
    // The unhardened counter-source must not inherit hardening from its
    // PARENT either (a tempdir on a nosuid tmpfs would make the
    // same-call-flags-are-dropped assertion below a false failure) —
    // so it is its own flagless tmpfs mount, environment-independent.
    let res = baremount(
        std::path::Path::new("tmpfs"),
        &plain_src,
        "tmpfs",
        MsFlags::empty(),
        "size=1m",
        &logger,
    );
    if res.is_err() {
        let _ = nix::mount::umount(hardened_src.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        panic!("plain tmpfs mount failed (not root?): {:?}", res.err());
    }

    // 1. Agent bind from the hardened share (production call shape):
    //    must carry nosuid,nodev via INHERITANCE.
    let r1 = baremount(
        &hardened_src,
        &dst1,
        "none",
        MsFlags::MS_BIND | share_harden_flags(),
        "",
        &logger,
    );
    // 2. Bind from an unhardened fs with the same flags: the kernel
    //    must DROP them (documented false premise of the old test).
    let r2 = baremount(
        &plain_src,
        &dst2,
        "none",
        MsFlags::MS_BIND | share_harden_flags(),
        "",
        &logger,
    );

    let mounts = fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
    // mountinfo: mnt_id parent majmin root TARGET OPTIONS[,more] ...
    let mount_opts = |target: &str| {
        mounts
            .lines()
            .find_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 6 || fields[4] != target {
                    None
                } else {
                    Some(fields[5].split(',').map(String::from).collect::<Vec<_>>())
                }
            })
            .unwrap_or_default()
    };
    let o1 = mount_opts(dst1.to_str().unwrap());
    let o2 = mount_opts(dst2.to_str().unwrap());

    // Tear down first so a failure never poisons the batch.
    let _ = nix::mount::umount(dst1.to_str().unwrap());
    let _ = nix::mount::umount(dst2.to_str().unwrap());
    let _ = nix::mount::umount(hardened_src.to_str().unwrap());
    let _ = nix::mount::umount(plain_src.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);

    if r1.is_err() || r2.is_err() {
        panic!(
            "bind mount failed (not root?): r1={:?} r2={:?}",
            r1.err(),
            r2.err()
        );
    }
    assert!(
        o1.contains(&"nosuid".to_string()) && o1.contains(&"nodev".to_string()),
        "bind from the hardened share lost nosuid,nodev in mountinfo (opts={o1:?}) — \
         the inheritance the agent binds rely on is broken; mount_workspace's \
         ensure_virtiofs_mounted flags need re-derivation"
    );
    assert!(
        !o2.contains(&"nosuid".to_string()) && !o2.contains(&"nodev".to_string()),
        "same-call bind flags unexpectedly LANDED (opts={o2:?}) — kernel behavior \
         changed: the kernel now honors per-mount flags at bind time. Re-derive: \
         the share-root hardening is no longer the only load-bearing mechanism"
    );
}

// ── neighbor-table flush classification (F2a companion) ────────────
// Pins the dump-walk classification: an NLMSG_ERROR must classify as
// Error (a mistyped pattern arm once turned it into a catch-all binding
// that swallowed errors into the done path — this test makes that class
// impossible to reintroduce silently).
fn nl_test_msg(ty: u16) -> Vec<u8> {
    let mut m = vec![0u8; 40];
    m[0..4].copy_from_slice(&40u32.to_ne_bytes());
    m[4..6].copy_from_slice(&ty.to_ne_bytes());
    m
}

#[test]
fn neigh_msg_kind_classifies_every_netlink_type() {
    assert_eq!(neigh_msg_kind(&nl_test_msg(28)), NeighMsgKind::Entry);
    assert_eq!(neigh_msg_kind(&nl_test_msg(3)), NeighMsgKind::Done);
    assert_eq!(neigh_msg_kind(&nl_test_msg(2)), NeighMsgKind::Error);
    // NLMSG_NOOP(0) and unrelated route-netlink types are noise.
    assert_eq!(neigh_msg_kind(&nl_test_msg(0)), NeighMsgKind::Other);
    assert_eq!(neigh_msg_kind(&nl_test_msg(19)), NeighMsgKind::Other);
}
