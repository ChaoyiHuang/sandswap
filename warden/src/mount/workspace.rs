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

//! The agent workspace mount: the once-per-VM virtio-fs share, the flat /
//! record-driven mount mode, and the mount_workspace orchestration of the
//! hardening layers.

use anyhow::{anyhow, Context, Result};
use nix::mount::MsFlags;
use slog::{debug, info, Logger};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::mount::anchor::RootAnchor;
use crate::mount::MOUNT_POINT;
use crate::mount::boot::{baremount, is_mounted};
use crate::mount::hardening::{
    inject_guest_resolv_conf, overlay_hot_busybox, setup_fresh_tmpfs, setup_masked_proc,
    setup_minimal_dev,
};
use crate::mount::WORKSPACE_DIR;

// ---- Workspace mount for agent sandbox pool ----
// These functions handle mounting/dismounting an agent's persistent workspace
// via virtio-fs native PassthroughFs. The virtio-fs device is created once at
// VM boot and shares the host volumes directory. Agent switching only requires
// a bind mount — no device hotplug, no ext4 mount, no ACPI eject races.
//
// Security: The VMM enforces allowed_dirs filtering at the virtio-fs layer.
// Even if chroot escapes, non-whitelisted agent directories return NotFound.

const VIRTIOFS_MOUNT_POINT: &str = "/mnt/volumes";
/// Named refusal token for a mount whose alias is not exported by the
/// CURRENT filter generation (a request that lost the race to a later
/// set-fs). The sandlot classifies this as a superseded generation, not as
/// an uncertain mount state.
pub(crate) const ERR_MOUNT_TARGET_NOT_EXPORTED: &str = "mount_target_not_exported";

/// The alias is one path component: no parent/absolute forms, no control
/// bytes. The VMM applies the same rules before it ever presents the name.
pub(crate) fn validate_export_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 64
        && alias != "."
        && alias != ".."
        && alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
/// The prov instance's volume-identity stamp file name (masked out of the
/// flat-mode agent tree at mount, unmasked at teardown — see mask_volume_stamp).
pub(crate) const VOLUME_STAMP_NAME: &str = ".sandfs-id";
const VIRTIOFS_TAG: &str = "sandswap";

/// Guest-side hardening flags for the virtio-fs share and every bind mount
/// derived from it (rootfs / workspace / home).
///
/// Why they matter: the FUSE passthrough applies guest-requested mode bits
/// (including setuid/setgid) and mknod verbatim on the host volume, so the
/// share can CARRY hostile bits — and the guest-side presentation is
/// present-as-root, so a planted setuid file would nominally be setuid-ROOT.
/// These flags make such bits inert at guest exec/device-open time. They are
/// the SECOND layer: the primary exec-time guarantee is the pre_exec
/// PR_SET_NO_NEW_PRIVS (the kernel checks bprm->no_new_privs before it ever
/// consults the mount suid flags), which blocks both suid and file
/// capabilities across execve for the whole child tree. The mount flags
/// exist so that no future non-NNP exec path re-opens the door.
///
/// Zero datapath cost: per-mount flags are consulted only at execve and
/// device-node open decision points — never on the lookup/read/write FUSE
/// path — and the binds are the same single mount(2) call with a different
/// flags word (verified by the root-gated share_mounts flags test).
pub(crate) fn share_harden_flags() -> MsFlags {
    MsFlags::MS_NOSUID | MsFlags::MS_NODEV
}

/// Set once the virtio-fs share is mounted; the mount persists for the whole
/// VM lifetime, so later attaches pay one atomic load instead of a
/// /proc/mounts scan. Invariant: anything that unmounts /mnt/volumes must
/// clear this flag. Verification below uses /proc/mounts only — statfs(2) on
/// the mounted path is forwarded to the FUSE daemon, a guest→host round trip.
static VIRTIOFS_MOUNTED: AtomicBool = AtomicBool::new(false);

// ── FUSE-op accounting ────────────────────────────────────────────────────
// Counts every guest→host round trip the mount path pays on the virtio-fs
// share (opens/lstats/creates/removes of volume-tree paths). After each
// unmount's drop_caches every one of these is a COLD FUSE lookup — the
// per-mount cost is (op count) x (cold lookup latency), so the COUNT is the
// latency budget. The steps line prints it as fuse_ops=N; a unit test pins
// the budget so a future hardening pass cannot silently double the walks
// (a silently doubled walk is exactly what regressed cold P95 11.9→32ms
// once).
// Gated by the same debug flag as the steps line: one relaxed load + branch
// per op site when off, no allocation, nothing on the exec path.
static FUSE_OPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FUSE_COUNTING: AtomicBool = AtomicBool::new(false);

#[inline]
pub(crate) fn note_fuse_op() {
    if FUSE_COUNTING.load(Ordering::Relaxed) {
        FUSE_OPS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Begin/reset op accounting for one mount (only when the debug trace is on).
pub(crate) fn fuse_ops_begin() {
    if crate::logging::debug_trace_enabled() {
        FUSE_OPS.store(0, Ordering::Relaxed);
        FUSE_COUNTING.store(true, Ordering::Relaxed);
    }
}

/// Stop accounting and return this mount's op count (0 when never enabled).
pub(crate) fn fuse_ops_end() -> usize {
    FUSE_COUNTING.store(false, Ordering::Relaxed);
    FUSE_OPS.load(Ordering::Relaxed)
}

/// Ensure the virtio-fs shared volume directory is mounted (once per VM lifetime).
pub(crate) fn ensure_virtiofs_mounted(logger: &Logger) -> Result<()> {
    if VIRTIOFS_MOUNTED.load(Ordering::Relaxed) {
        return Ok(());
    }
    if !is_mounted(VIRTIOFS_MOUNT_POINT)? {
        std::fs::create_dir_all(VIRTIOFS_MOUNT_POINT).context("create virtio-fs mount point")?;
        // Dedicated-identity note: the virtiofs server (in sandvmm) presents
        // ownership to the guest as root:root (passthrough::present_guest_
        // ownership) — host service-identity uids would mean nothing to the
        // single-user, root-only guest and its kernel would deny traversal
        // before any request reaches the daemon. Real enforcement stays
        // host-side with the daemon's own credentials; the guest never sees
        // a uid it could leverage.
        baremount(
            Path::new(VIRTIOFS_TAG),
            Path::new(VIRTIOFS_MOUNT_POINT),
            "virtiofs",
            share_harden_flags(),
            "",
            logger,
        )
        .context("mount virtio-fs sandswap tag")?;
        info!(logger, "virtio-fs mounted at {}", VIRTIOFS_MOUNT_POINT);
    }
    VIRTIOFS_MOUNTED.store(true, Ordering::Relaxed);
    Ok(())
}

/// Open the volume anchor for THIS generation's alias. This is both the
/// probe (a superseded alias is not exported, so the open fails ENOENT) and
/// the anchor the subsequent mount binds from — one FUSE lookup, no extra
/// round trip. Failures are expected on the stale-generation path, so the
/// anchor open is quiet; the caller turns them into a named refusal.
pub(crate) fn open_volume_anchor(logger: &Logger, alias: &str) -> Result<RootAnchor> {
    ensure_virtiofs_mounted(logger)?;
    if !validate_export_alias(alias) {
        return Err(anyhow!(
            "invalid export alias {alias:?}: one component of [A-Za-z0-9._-], 1..=64 bytes, not . or .."
        ));
    }
    let virtio_base = format!("{}/{}", VIRTIOFS_MOUNT_POINT, alias);
    RootAnchor::open_quiet(&virtio_base, logger).ok_or_else(|| {
        anyhow!(
            "{}: export alias {alias:?} is not exported by the current filter generation",
            ERR_MOUNT_TARGET_NOT_EXPORTED
        )
    })
}

/// Bind-mount an agent's directory as the workspace rootfs.
///
/// `vol` is the anchor opened by `open_volume_anchor` for this request's
/// generation alias; the caller holds the mount gate across both. The VMM has
/// already made that alias the only root entry, so the anchor cannot name a
/// different tenant's directory.
///
/// Two mount modes, selected by the identity record:
///
/// **Overlay mode** (the identity record says overlay — template-based SandFS;
/// the bind source is the host overlay mounted at `<volume>/rootfs`):
///   1. bind mount /mnt/volumes/<alias>/rootfs → /mnt/rootfs (read-only overlay)
///   2. bind mount /mnt/volumes/<alias>/workspace → /mnt/rootfs/workspace (writable)
///   3. bind mount /mnt/volumes/<alias>/home → /mnt/rootfs/home/agent (writable)
///   4. tmpfs at /mnt/rootfs/tmp (local, not shared across nodes)
///   5. Hardening (busybox hot-bind, masked proc, minimal dev, resolv.conf) —
///      the first three are FATAL on failure
///
/// **Bind-mount mode** (the identity record says flat — default/template-seeded
/// SandFS):
///   1. bind mount /mnt/volumes/<alias> → /mnt/rootfs (read-write, flat directory)
///   2. Hardening (busybox hot-bind, masked proc, minimal dev, resolv.conf) —
///      the first three are FATAL on failure
///
/// This is called after the VMM has set `allowed_dirs` to only include this
/// generation's directory, so the virtio-fs layer only exposes one agent at a
/// time.
pub async fn mount_workspace(
    logger: &Logger,
    vol: RootAnchor,
    alias: &str,
    mount_point: &str,
    volume_mode: &str, // identity record's mode: "flat" | "overlay"
    known_clean: bool, // /mnt/rootfs provably carries no leftover child mounts
) -> Result<()> {
    // debug level: printed at op START, so its console drain runs concurrently
    // with the mount AND the first exec behind it — the worst placement for a
    // hot-path line.
    debug!(
        logger,
        "mount_workspace: alias={} mnt={}", alias, mount_point
    );

    // Per-step timing (µs) — one summary line per mount, same style as
    // "mount_and_exec done (mount=…)" in raw_server. Sub-steps that traverse
    // virtio-fs (stat/mkdir/write) cost a FUSE round trip each; this line is
    // how their share is attributed. GATED on the debug level BEFORE any of
    // the instrumentation runs: the step vector and its formatted string are
    // eager locals, so without the gate every mount paid ~a dozen allocations
    // plus formatting for a line the default level discards (the same
    // doctrine as the per-op log lines themselves).
    let trace = crate::logging::debug_trace_enabled();
    let mut steps: Vec<(&'static str, u128)> = Vec::new();
    let mut step_t = Instant::now();
    // Record one step's elapsed µs and re-arm the anchor. With tracing off
    // this is one bool check + one Instant::now() — no allocation, no growth.
    macro_rules! step {
        ($name:literal) => {{
            if trace {
                steps.push(($name, step_t.elapsed().as_micros()));
            }
            step_t = Instant::now();
        }};
    }

    // The volume is reached through this generation's ALIAS, never its real
    // (seed-derived, secret) directory name. The alias is the capability the
    // VMM's filter currently exports; a request carrying a superseded
    // generation's alias failed at open_volume_anchor, before this function.

    // Mount mode is the IDENTITY RECORD's, carried on the wire by the
    // gateway/sandlot. Never probe the volume's on-disk layout: a flat
    // volume is agent-writable, and a planted `rootfs/` directory must not
    // be able to flip the mount into overlay semantics (which would drop the
    // bind's read-only intent and skip the flat-mode stamp cover). Unknown
    // modes fail closed.
    let overlay_mode = match volume_mode {
        "overlay" => true,
        "flat" => false,
        other => {
            return Err(anyhow!(
                "invalid volume mode {:?}: the mount mode must come from the identity record (flat/overlay)",
                other
            ))
        }
    };
    step!("mode_record");

    std::fs::create_dir_all(mount_point).context("create mount point")?;
    step!("mkdir_mp");

    if overlay_mode {
        // ── Overlay mode: read-only overlay + writable workspace/home ──

        // 1. Bind mount the overlay rootfs → /mnt/rootfs. The read-only-ness
        //    comes from the HOST-side overlay mount (MS_RDONLY there; writes
        //    return EROFS through virtiofsd) — the kernel drops MS_RDONLY
        //    passed in the same call as MS_BIND (share_bind_flags_land_in_
        //    mountinfo pins that). The source fd pins the inode: mount(2) sees
        //    /proc/self/fd/N and cannot re-resolve a swapped path.
        let rootfs_src = vol.open_dir_strict("rootfs", logger)?;
        baremount(
            Path::new(&format!("/proc/self/fd/{}", rootfs_src.as_raw_fd())),
            Path::new(mount_point),
            "none",
            MsFlags::MS_BIND | MsFlags::MS_RDONLY | share_harden_flags(),
            "",
            logger,
        )
        .context("bind mount read-only overlay")?;
        drop(rootfs_src);
        step!("bind_rootfs");

        // 2. Bind mount writable workspace → /mnt/rootfs/workspace.
        //    The source is fd-anchored under the volume root; the target is
        //    secured relative to the mounted rootfs anchor.
        let workspace_src = vol.open_dir_strict("workspace", logger)?;
        let root = RootAnchor::open(mount_point, logger)
            .ok_or_else(|| anyhow!("mounted rootfs {} could not be anchored", mount_point))?;
        let (ws_target, _ws_keep) = root
            .open_dir("workspace", logger)
            .ok_or_else(|| anyhow!("workspace mount target could not be secured"))?;
        baremount(
            Path::new(&format!("/proc/self/fd/{}", workspace_src.as_raw_fd())),
            Path::new(&ws_target),
            "none",
            MsFlags::MS_BIND | share_harden_flags(),
            "",
            logger,
        )
        .context("bind mount writable workspace")?;
        drop(workspace_src);
        step!("bind_workspace");

        // 3. Bind mount writable home → /mnt/rootfs/home/agent (read-write).
        //    Nested targets chain anchors (home → agent): the single-component
        //    API has no way to pass "home/agent".
        let home_src = vol.open_dir_strict("home", logger)?;
        let home_parent = root
            .open_dir("home", logger)
            .ok_or_else(|| anyhow!("home mount parent could not be secured"))?;
        let home_anchor = RootAnchor { fd: home_parent.1 };
        let (hm_target, _hm_keep) = home_anchor
            .open_dir("agent", logger)
            .ok_or_else(|| anyhow!("home mount target could not be secured"))?;
        baremount(
            Path::new(&format!("/proc/self/fd/{}", home_src.as_raw_fd())),
            Path::new(&hm_target),
            "none",
            MsFlags::MS_BIND | share_harden_flags(),
            "",
            logger,
        )
        .context("bind mount writable home")?;
        drop(home_src);
        step!("bind_home");

        // 4. Fresh tmpfs at /tmp (local, not shared across nodes)
        setup_fresh_tmpfs(&root, "tmp", "mode=1777", logger, known_clean);
        step!("tmpfs_tmp");

        // 5. Hardening (targets anchored on the mounted rootfs). Each of these
        //    is FATAL on failure: a hot bind that cannot be proven read-only,
        //    a masked /proc that cannot be installed (or remounted read-only)
        //    and an unsecurable minimal-dev target all mean the isolation
        //    layers are incomplete — the mount is refused, never degraded.
        overlay_hot_busybox(&root, logger)?;
        step!("busybox");
        setup_masked_proc(&root, logger, known_clean)?;
        step!("masked_proc");
        setup_minimal_dev(&root, logger, known_clean)?;
        step!("minimal_dev");
        inject_guest_resolv_conf(&root, logger).await;
        step!("resolv");
    } else {
        // ── Bind-mount mode: whole directory is the rootfs ──
        // The source is the anchor fd itself (nothing to re-resolve).
        baremount(
            Path::new(&vol.fd_path()),
            Path::new(mount_point),
            "none",
            MsFlags::MS_BIND | share_harden_flags(),
            "",
            logger,
        )
        .context("bind mount workspace")?;
        step!("bind_rootfs");

        let root = RootAnchor::open(mount_point, logger)
            .ok_or_else(|| anyhow!("mounted rootfs {} could not be anchored", mount_point))?;

        // Hardening (targets anchored on the mounted rootfs; same fatal
        // classes as the overlay branch).
        overlay_hot_busybox(&root, logger)?;
        step!("busybox");
        setup_masked_proc(&root, logger, known_clean)?;
        step!("masked_proc");
        setup_minimal_dev(&root, logger, known_clean)?;
        step!("minimal_dev");
        mask_volume_stamp(&root, logger, known_clean)?;
        step!("stamp_mask");
        inject_guest_resolv_conf(&root, logger).await;
        step!("resolv");
    }

    // Explicit first-exec warm-up. The first execve after this mount walks
    // paths no mount step touched: the /bin/sh symlink (lookup + readlink —
    // overlay_hot_busybox only resolves .../bin/busybox) and the chdir
    // target /workspace. Each miss is a cold virtio-fs FUSE round trip
    // landing INSIDE the first exec's fork/chroot/execve, where it is worth
    // measurably more than the same lookups cost here (they also warm the
    // guest dcache for every later exec of this attach). Best-effort: a
    // template without /bin/sh or /workspace loses nothing.
    note_fuse_op();
    let _ = std::fs::read_link(format!("{}/bin/sh", mount_point));
    note_fuse_op();
    let _ = std::fs::metadata(format!("{}{}", mount_point, WORKSPACE_DIR));
    step!("warmup");
    // Read the anchor once more so the macro's final re-arm is not a dead
    // assignment (the last step has no successor to measure).
    let _ = step_t;

    // debug level, NOT info: this line is ~130 chars on the emulated serial
    // UART (~83µs/char) — at info it measurably slows the very
    // path it profiles (the async drain thread contends for the 2 vCPUs with
    // the first exec after the mount). Enabled only for targeted profiling;
    // the payload construction is skipped entirely when debug is off (see the
    // `trace` gate above).
    if trace {
        let fuse_ops = fuse_ops_end();
        let steps_fmt = steps
            .iter()
            .map(|(n, us)| format!("{}={}µs", n, us))
            .collect::<Vec<_>>()
            .join(" ");
        debug!(logger, "mount steps: fuse_ops={} {}", fuse_ops, steps_fmt);
    } else {
        fuse_ops_end();
    }

    if overlay_mode {
        debug!(
            logger,
            "workspace mounted: alias={} (ro overlay + rw workspace + rw home)", alias
        );
    } else {
        debug!(logger, "workspace mounted: alias={} (bind mount)", alias);
    }
    Ok(())
}


/// Mask the storage plane's `.sandfs-id` stamp out of the agent's tree (FLAT mode
/// only: there the volume root IS the chroot root, so the stamp — carrying
/// the sandfs id, the seed generation and its HMAC — is ambient agent-readable
/// data, and ambient strings leak to third-party LLMs wholesale. The id is
/// the tenant's own, but nothing inside the sandbox needs it). A read-only
/// /dev/null cover: reads return EOF, writes fail EROFS, and the entry
/// cannot be unlinked or renamed over (it is a mountpoint). OVERLAY mode
/// needs no mask: the volume root is outside the chroot entirely.
/// Non-regular planted entries are simply not covered (open_file refuses
/// them; a planted link/FIFO is the agent's own file, harmless).
///
/// FAIL-CLOSED: if a real stamp exists and covering it fails, the mount is
/// refused. The leaked fields are the tenant's own (id, seed generation,
/// HMAC), not another tenant's, but "secret material never enters the guest"
/// is a contract; a mount that cannot honour it must not proceed.
fn mask_volume_stamp(root: &RootAnchor, logger: &Logger, clean: bool) -> anyhow::Result<()> {
    let mp = format!("{}/{}", MOUNT_POINT, VOLUME_STAMP_NAME);
    if !clean {
        // Mount-path defensive probe (dirty/partial prior state): its own
        // snapshot — one read, the same shape the per-probe read had.
        let mut mounts = crate::mount::hardening::MountSet::defensive(Some(logger));
        crate::mount::hardening::umount_verified(&mp, Some(logger), &mut mounts);
    }
    let Some(target) = root.open_file(VOLUME_STAMP_NAME, false, logger) else {
        return Ok(()); // absent (no stamp yet) or planted non-regular — nothing to cover
    };
    let bound = crate::mount::hardening::bind_ro_fd("/dev/null", &target, &mp, logger);
    drop(target);
    if let Err(e) = bound {
        return Err(anyhow!(
            "stamp mask: covering {} failed: {e} — refusing the mount rather than exposing the volume stamp",
            VOLUME_STAMP_NAME
        ));
    }
    Ok(())
}
