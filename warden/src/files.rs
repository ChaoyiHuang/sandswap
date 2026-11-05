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
// File I/O operations for the OP_FILE vsock protocol extension.
// All paths are resolved relative to the workspace directory
// (MOUNT_POINT + WORKSPACE_DIR = /mnt/rootfs/workspace). This matches
// the exec chdir target, so file paths share the same base as `pwd`.
// Every op pins that base as a DIRECTORY FD (BaseDir::open) and
// walks the request path openat()-relative to it, verifying containment
// against the fd's kernel-reported real path. The base path itself is
// agent-replaceable in flat mode (the chroot root IS the volume), so it must
// never be resolved by string: a planted `<volume>/workspace -> /` made the
// old `base.canonicalize()` prefix check vacuous (`starts_with("/")`) and
// every op acted in the WARDEN's namespace as root. This is defense-in-depth
// on top of the existing chroot + seccomp.
// All operations use direct syscalls (std::fs::read, std::fs::write, etc.) —
// zero process spawn overhead compared to shelling out via /execute. They
// are blocking and therefore SYNCHRONOUS functions: the caller (raw_server)
// runs each on the blocking pool via spawn_blocking so a large/slow file op
// never pins an async worker.
// The workspace base is a parameter (not a constant read) so the path
// validation and every op are unit-testable against a temp directory — the
// production caller passes /mnt/rootfs/workspace.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

// Sub-opcodes for OP_FILE (carried in the first byte of the request body).
pub(crate) const SUB_OP_READ: u8 = 1;
pub(crate) const SUB_OP_WRITE: u8 = 2;
pub(crate) const SUB_OP_STAT: u8 = 3;
pub(crate) const SUB_OP_LIST_DIR: u8 = 4;
pub(crate) const SUB_OP_MAKE_DIR: u8 = 5;
pub(crate) const SUB_OP_REMOVE: u8 = 6;
pub(crate) const SUB_OP_RENAME: u8 = 7;

/// Structured metadata for a file/directory entry, returned by STAT and LIST_DIR.
/// Serialized as JSON in the response stdout field — avoids fragile shell
/// output parsing.
#[derive(Debug, Serialize)]
pub(crate) struct EntryInfo {
    pub name: String,
    pub path: String,
    pub file_type: String, // "file" | "dir" | "symlink" | "truncated" (marker)
    pub size: u64,
    pub mode: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<String>,
}

// ── LIST_DIR response bounds ────────────────────────────────────────────
//
// read_file has had a hard byte cap (max_file_read_bytes) since the file API
// exists; LIST_DIR used to collect EVERY entry of the (recursively listed)
// directory into a Vec before serializing — a directory with enough entries
// (runaway agent, or a compromised peer holding the VM's session key; see the
// raw_server DoS bounds) grows the listing JSON without bound on the
// warden heap and into the response frame. The listing now carries the SAME
// budget as a read: collection stops when the estimated serialized size
// reaches max_bytes, and a trailing marker entry (file_type "truncated")
// tells the caller the listing is partial. A hard entry-count cap backs the
// byte estimate (which cannot see per-entry allocation overhead).

/// Recursion depth cap applied to the wire's depth field (u32::MAX must not
/// reach the recursion unclamped — deep trees are path-length-bounded in
/// practice, but the clamp makes that a local invariant instead of a
/// PATH_MAX side effect).
pub(crate) const MAX_LIST_DEPTH: u32 = 64;

/// Hard entry-count cap (backs the byte estimate; bounds the Vec itself).
pub(crate) const MAX_LIST_ENTRIES: usize = 16_384;

/// Conservative per-entry serialization overhead (JSON keys, numbers,
/// Option) added to the name+path bytes when consuming the byte budget.
const LIST_ENTRY_FIXED_BYTES: usize = 256;

/// Cap on a wire-supplied workspace-relative path. Linux PATH_MAX is 4096
/// including the NUL, so a longer string cannot name an object the kernel
/// would resolve; worse, the ancestor walk in validate_path_under allocates
/// one OsString per component until it finds an existing ancestor — an 8 MiB
/// path kept a blocking-pool thread busy for seconds while it held the
/// MOUNT_GATE read guard (the 30 s unmount read timeout then destroyed the
/// VM). Refuse by length before any filesystem work.
pub(crate) const MAX_PATH_BYTES: usize = 4095;

/// Component cap: a path of 4095 one-character components still forces ~2 K
/// walk iterations and allocations. Real trees are far shallower (the list
/// depth cap itself is 64); refuse anything past this.
pub(crate) const MAX_PATH_COMPONENTS: usize = 1024;

/// The truncation marker appended when a listing hit its budget: clients
/// iterating entries see one well-formed object instead of a silently short
/// listing. `size` carries the entry count actually returned.
fn truncated_marker(returned: usize) -> EntryInfo {
    EntryInfo {
        name: "[truncated]".to_string(),
        path: "[truncated]".to_string(),
        file_type: "truncated".to_string(),
        size: returned as u64,
        mode: 0,
        modified_time: None,
    }
}

/// Clamp the wire's depth to MAX_LIST_DEPTH. Extracted for unit testing.
fn clamp_list_depth(depth: u32) -> u32 {
    depth.min(MAX_LIST_DEPTH)
}

/// Mutable budget carried through the listing recursion.
struct ListBudget {
    remaining: usize,
    truncated: bool,
}

/// Validate a path relative to `base`, returning the resolved workspace path.
/// Prevents path traversal attacks (e.g., "../../etc/passwd") and symlink
/// escapes (a symlink inside the workspace pointing to /mnt/rootfs/home/agent
/// or /mnt/rootfs/etc) as defense-in-depth on top of chroot + seccomp.
///
/// The check is against `base.real` — the REAL path of the pinned base fd
/// (kernel-generated, see BaseDir) — NOT a re-resolved base string: in flat
/// mode the agent can replace `<volume>/workspace` with a symlink, and a
/// canonicalized base would simply follow it, making the prefix check below
/// vacuous. Symlinks INSIDE the workspace still resolve normally: a
/// target that stays under the base is legitimate and returned resolved, a
/// target that leaves it is refused.
///
/// If the path does not yet exist (e.g., for WRITE or MAKE_DIR), we validate
/// the closest existing ancestor stays within the base and reconstruct the
/// target from it.
///
/// Parameterized by `base` so tests run against a temp directory.
pub(crate) fn validate_path_under(base: &BaseDir, path: &str) -> Result<PathBuf> {
    // Bounded input BEFORE any resolution work (the walk below is O(bytes)):
    // a >PATH_MAX name cannot resolve, and an unbounded component walk parked
    // the MOUNT_GATE read guard for seconds.
    if path.len() > MAX_PATH_BYTES {
        return Err(anyhow!(
            "path too long ({} bytes; max {})",
            path.len(),
            MAX_PATH_BYTES
        ));
    }
    if path.bytes().filter(|b| *b == b'/').count() >= MAX_PATH_COMPONENTS {
        return Err(anyhow!(
            "path has too many components (max {})",
            MAX_PATH_COMPONENTS
        ));
    }
    let base_real = &base.real;
    let full = format!("{}/{}", base_real.display(), path.trim_start_matches('/'));
    let full_path = Path::new(&full);

    // Try canonicalize first (works for existing paths).
    if let Ok(canonical) = full_path.canonicalize() {
        if !canonical.starts_with(base_real) {
            return Err(anyhow!("path traversal blocked"));
        }
        return Ok(canonical);
    }

    // Path doesn't exist yet (WRITE/MAKE_DIR target). A `..` component here
    // cannot be resolved against real directories (that is exactly what made
    // the canonicalize above fail), and silently dropping it — what the
    // ancestor walk below used to do, since Path::file_name() yields None
    // for `..`-terminated paths — would aim the write at a DIFFERENT
    // directory than the caller named. Reject outright instead.
    if std::path::Path::new(path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(anyhow!(
            "path traversal blocked (.. component on a non-existent path)"
        ));
    }

    // Walk up to find the
    // closest existing ancestor and validate it stays within the workspace base.
    // This allows writes to nested paths like "workflow/test.txt" where the
    // intermediate "workflow/" directory doesn't exist yet — the write will
    // auto-create parent directories.
    let mut current = full_path;
    let mut missing_components: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canonical) = current.canonicalize() {
            if !canonical.starts_with(base_real) {
                return Err(anyhow!("path traversal blocked"));
            }
            // Reconstruct the full path from the canonical ancestor + missing components.
            let mut resolved = canonical;
            for comp in missing_components.iter().rev() {
                resolved = resolved.join(comp);
            }
            if !resolved.starts_with(base_real) {
                return Err(anyhow!("path traversal blocked"));
            }
            return Ok(resolved);
        }
        // Current path component doesn't exist. Record it and walk up.
        if let Some(name) = current.file_name() {
            missing_components.push(name.to_os_string());
        }
        match current.parent() {
            Some(p) if !p.as_os_str().is_empty() => current = p,
            _ => {
                return Err(anyhow!(
                    "no existing ancestor within mount point for: {}",
                    path
                ))
            }
        }
    }
}

/// The workspace base, pinned as an OPEN DIRECTORY FD for the whole operation.
///
/// The base path (`MOUNT_POINT + WORKSPACE_DIR`) lives inside the
/// agent's own rootfs and is agent-replaceable — in flat mode the chroot root
/// IS the volume, so `rm -rf /workspace && ln -s / /workspace` is one exec.
/// Resolving that string (the old `base.canonicalize()`) followed the link:
/// the containment prefix became `/`, the O_NOFOLLOW walk started at `/`, and
/// every file op — read, write, unlink, chmod — acted in the WARDEN's
/// namespace as root. The base is therefore established the way `mount.rs`
/// establishes every agent-controlled path (`prepare_mount_dir`'s idiom): the
/// entry is opened `O_PATH|O_DIRECTORY|O_NOFOLLOW`, a planted symlink entry
/// is removed and rebuilt as a real directory, and the fd is held for the
/// whole op — the component walk is `openat`-relative to THAT fd, so no
/// string-level swap (before, during or after validation) can redirect it.
/// `real` is the fd's kernel-reported path (`/proc/self/fd` readlink), the
/// single containment prefix every check compares against.
///
/// A symlinked base is NOT followed even when it points inside the volume:
/// the warden cannot tell a benign in-volume target from an escape without
/// the very resolution that is the bug, so the entry is rebuilt — the same
/// choice `prepare_mount_dir` makes for this path in overlay mode.
///
/// Cost: one O_PATH open + one readlink per op, replacing two canonicalize()
/// walks of the base — a net syscall reduction (the old code re-resolved the
/// base in both validate_path_under and openat_verified).
pub(crate) struct BaseDir {
    fd: OwnedFd,
    real: PathBuf,
}

impl BaseDir {
    fn open(base: &Path) -> Result<BaseDir> {
        let cstr = cstr_from_os(base.as_os_str())?;
        for _ in 0..3 {
            let raw = unsafe {
                libc::open(
                    cstr.as_ptr(),
                    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw >= 0 {
                let fd = unsafe { OwnedFd::from_raw_fd(raw) };
                let real = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                    .map_err(|e| anyhow!("read workspace base fd: {}", e))?;
                return Ok(BaseDir { fd, real });
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // O_PATH|O_DIRECTORY|O_NOFOLLOW never follows the final
                // component: a symlink (or any other non-directory) surfaces
                // as ENOTDIR. Remove the planted entry and retry.
                Some(libc::ENOTDIR) | Some(libc::ELOOP) => {
                    // debug level: the agent can plant this entry on every
                    // cold mount, so an info/warn line here is agent-paced
                    // console flooding. The removal is the fix; a failure to
                    // remove still returns an error to the caller.
                    slog_scope::debug!(
                        "workspace base {} is a symlink or non-directory — removing it (agent-planted)",
                        base.display()
                    );
                    fs::remove_file(base).map_err(|e| {
                        anyhow!(
                            "workspace base {}: removing the planted entry failed: {}",
                            base.display(),
                            e
                        )
                    })?;
                }
                Some(libc::ENOENT) => {
                    fs::create_dir_all(base).map_err(|e| {
                        anyhow!("workspace base {}: create failed: {}", base.display(), e)
                    })?;
                }
                _ => return Err(anyhow!("open workspace base {}: {}", base.display(), err)),
            }
        }
        Err(anyhow!(
            "workspace base {} could not be secured (kept reappearing)",
            base.display()
        ))
    }

    fn dirfd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

// ── Race-hardened opens: component walk + fd backstop ──────────────────
//
// validate_path_under closes the STATIC escapes (traversal, pre-existing
// symlink out). It cannot close the RACE: the agent can swap any path
// component for a symlink between the canonicalize and the open (both sides
// reach the same underlying volume — the agent through its chroot, the
// warden through /mnt/volumes). The former open_no_follow pinned only the
// FINAL component with O_NOFOLLOW; intermediate components were followed
// silently at open() time, so a won race escaped the workspace entirely
// (deterministically reproducible: validate "d/f" with d a real directory,
// swap d for a symlink to an outside directory, the open follows it).
//
// The replacement walks the path one component at a time with
// openat(O_NOFOLLOW): a symlink component raises ELOOP and is expanded
// EXPLICITLY — its target is re-walked under the same rules, so an
// in-workspace symlink keeps working while an escaping one is rejected.
// Containment is enforced once, at the end, against the /proc/self/fd
// readlink of the OPENED INODE (kernel-generated, not racy): the fd must
// live under the workspace before any byte is read or written. Destructive
// open flags (O_TRUNC) are deferred until after verification — nothing
// outside the workspace may be modified as a side effect of a lost race.
//
// All of this is blocking libc, running on the caller's blocking-pool thread.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Walk budget: total components (symlink cycles would otherwise walk
/// forever) and symlink expansions (ELOOP chains).
const WALK_MAX_COMPONENTS: usize = 64;
const WALK_MAX_SYMLINKS: usize = 8;

/// Convert an OsStr path component to a CString (interior NULs are invalid).
fn cstr_from_os(s: &OsStr) -> Result<std::ffi::CString> {
    std::ffi::CString::new(s.as_bytes()).map_err(|_| anyhow!("path component contains NUL"))
}

/// readlinkat(2) for one component; returns the raw target bytes.
fn readlinkat_os(dirfd: RawFd, name: &OsStr) -> Result<std::ffi::OsString> {
    let cstr = cstr_from_os(name)?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let n =
        unsafe { libc::readlinkat(dirfd, cstr.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) };
    if n < 0 {
        return Err(anyhow!(
            "readlink {}: {}",
            name.to_string_lossy(),
            std::io::Error::last_os_error()
        ));
    }
    buf.truncate(n as usize);
    Ok(std::ffi::OsString::from_vec(buf))
}

/// Lexically normalize a path (resolve "." and ".." without touching the
/// filesystem). Used on symlink targets before they are re-walked; the
/// result still passes through the component walk, so any symlink remaining
/// in it is expanded and checked there.
fn normalize_lexical(p: &Path) -> PathBuf {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::RootDir => out.clear(),
            std::path::Component::Normal(n) => out.push(n.to_os_string()),
            std::path::Component::Prefix(_) => {}
        }
    }
    let mut s = std::ffi::OsString::from("/");
    for (i, part) in out.iter().enumerate() {
        if i > 0 {
            s.push("/");
        }
        s.push(part);
    }
    PathBuf::from(s)
}

fn open_root_dir() -> Result<OwnedFd> {
    let raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(anyhow!("open /: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// The directory a walked component is resolved from: the walk's own fd once
/// it has descended, else the PINNED base fd itself. When the walk returns
/// None it descended nowhere, so every lookup stays relative to the base fd
/// that `validate_path_under` checked — the base is never re-resolved.
fn effective_dirfd(owned: &Option<OwnedFd>, base: &BaseDir) -> RawFd {
    owned
        .as_ref()
        .map(|f| f.as_raw_fd())
        .unwrap_or_else(|| base.dirfd())
}

/// Resolve `path` (absolute, already validated under the workspace) to the
/// fd of its PARENT directory plus the final component name. Every
/// intermediate component is openat'd with O_NOFOLLOW; a symlink component
/// (ELOOP) is expanded by re-queueing its target — the parent fd that comes
/// back was therefore reached WITHOUT following any symlink implicitly. With
/// `create_missing`, ENOENT intermediate components are mkdirat'd first
/// (write/mkdir semantics: missing parents are auto-created in-workspace —
/// the queue only contains Normal names below a verified-in-base fd, so the
/// created dirs cannot land outside).
///
/// Returns `None` for the parent fd when the walk never descended: the
/// caller resolves the final component against the pinned base fd itself
/// (effective_dirfd), which is exactly the directory the containment checks
/// were made against — no re-resolution window.
fn resolve_parent(
    base: &BaseDir,
    path: &Path,
    create_missing: bool,
) -> Result<(Option<OwnedFd>, std::ffi::OsString, bool)> {
    // Start from the pinned workspace BASE fd, not from "/": the components
    // above the base (/, /mnt, /mnt/rootfs) live on the warden's own rootfs
    // and mount namespace — the agent's filesystem access is chrooted into
    // its volume and cannot swap them — so re-walking them per op buys no
    // security, only syscalls (measured +50µs/op on the full walk). The base
    // itself IS agent-replaceable in flat mode, hence the pinned fd: a swap
    // after BaseDir::open cannot move this walk.
    // Falls back to the full "/" walk when `path` is not under `base.real`
    // (only possible for symlink-expansion re-walks).
    let (mut pending, mut dirfd): (VecDeque<std::ffi::OsString>, Option<OwnedFd>) =
        match path.strip_prefix(&base.real) {
            Ok(rel) => {
                let comps: VecDeque<std::ffi::OsString> = rel
                    .components()
                    .filter_map(|c| match c {
                        std::path::Component::Normal(n) => Some(n.to_os_string()),
                        _ => None,
                    })
                    .collect();
                if comps.len() > WALK_MAX_COMPONENTS {
                    return Err(anyhow!("path too deep ({} components)", comps.len()));
                }
                (comps, None)
            }
            Err(_) => {
                let comps: VecDeque<std::ffi::OsString> = path
                    .components()
                    .filter_map(|c| match c {
                        std::path::Component::Normal(n) => Some(n.to_os_string()),
                        _ => None,
                    })
                    .collect();
                if comps.len() > WALK_MAX_COMPONENTS {
                    return Err(anyhow!("path too deep ({} components)", comps.len()));
                }
                (comps, Some(open_root_dir()?))
            }
        };
    let mut symlinks = 0usize;

    // Leave the final component for the caller.
    while pending.len() > 1 {
        let comp = pending.pop_front().unwrap();
        let cstr = cstr_from_os(&comp)?;
        let from = effective_dirfd(&dirfd, base);
        let raw = unsafe {
            libc::openat(
                from,
                cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw >= 0 {
            dirfd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            continue;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                // Symlink component (ELOOP), or a symlink sitting where a
                // directory is required (ENOTDIR). Expand it EXPLICITLY:
                // re-queue the target's components and keep walking. Whether
                // the expansion stays in the workspace is decided by the fd
                // backstop in the callers — never by silently following it.
                symlinks += 1;
                if symlinks > WALK_MAX_SYMLINKS {
                    return Err(anyhow!("symlink chain too deep"));
                }
                let target = readlinkat_os(from, &comp)?;
                let target_path = PathBuf::from(&target);
                let resolved = if target_path.is_absolute() {
                    normalize_lexical(&target_path)
                } else {
                    // Resolve against the CURRENT dir's real location. The
                    // /proc/self/fd readlink is kernel-generated for the open
                    // dir inode — not attacker-raceable.
                    let dir_real = std::fs::read_link(format!("/proc/self/fd/{}", from))
                        .map_err(|e| anyhow!("readlink parent fd: {}", e))?;
                    normalize_lexical(&dir_real.join(target_path))
                };
                // Expansion-time containment: a validated path is canonical
                // (no symlinks), so an intermediate symlink is either a
                // post-validation swap or part of a final-symlink target —
                // either way its expansion must stay lexically under the
                // workspace, or the walk would descend outside and an O_CREAT
                // could fire there before the fd backstop rejects it. The
                // lexical check is computed against the dir's REAL path, so
                // in-workspace `..` targets normalize back inside.
                if !resolved.starts_with(&base.real) {
                    return Err(anyhow!(
                        "path traversal blocked (symlink component escapes workspace)"
                    ));
                }
                let mut queue: VecDeque<std::ffi::OsString> = resolved
                    .components()
                    .filter_map(|c| match c {
                        std::path::Component::Normal(n) => Some(n.to_os_string()),
                        _ => None,
                    })
                    .collect();
                queue.extend(pending);
                if queue.len() > WALK_MAX_COMPONENTS {
                    return Err(anyhow!("path too deep after symlink expansion"));
                }
                pending = queue;
                // Both absolute and dir-relative targets were resolved to an
                // absolute path in `resolved` — re-walk from the root.
                dirfd = Some(open_root_dir()?);
            }
            Some(libc::ENOENT) if create_missing => {
                let rc = unsafe { libc::mkdirat(from, cstr.as_ptr(), 0o755) };
                if rc < 0 {
                    return Err(anyhow!(
                        "mkdir {}: {}",
                        comp.to_string_lossy(),
                        std::io::Error::last_os_error()
                    ));
                }
                pending.push_front(comp);
            }
            _ => {
                return Err(anyhow!("open {} under workspace: {}", path.display(), err));
            }
        }
    }
    let final_name = pending
        .pop_front()
        .ok_or_else(|| anyhow!("empty path {}", path.display()))?;
    Ok((dirfd, final_name, symlinks > 0))
}

/// Verify the fd's real location is under the pinned base (kernel-authoritative
/// — /proc/self/fd readlinks point at the opened inode, not at a re-walked
/// path an attacker might have swapped).
fn fd_under_base(fd: RawFd, base_real: &Path) -> bool {
    match std::fs::read_link(format!("/proc/self/fd/{}", fd)) {
        Ok(real) => real.starts_with(base_real),
        Err(_) => false,
    }
}

/// Open the final component under a walked parent fd with `oflags |
/// O_NOFOLLOW`, expanding an in-workspace final symlink on ELOOP (re-resolve
/// and re-walk, bounded) and backstopping the fd's location before
/// returning. `create_mode` is the mode for O_CREAT (0600 — the agent's
/// requested mode is applied afterwards on the verified fd via fchmod, and a
/// raced artifact outside the workspace is left inert).
fn openat_verified(
    base: &BaseDir,
    full_path: &Path,
    oflags: libc::c_int,
    create_mode: libc::mode_t,
) -> Result<fs::File> {
    let mut current = full_path.to_path_buf();
    for _ in 0..WALK_MAX_SYMLINKS {
        // The workspace base itself (empty relative path, e.g. LIST_DIR of
        // the workspace root): open the PINNED fd with the op's flags. "."
        // resolves inside the fd's own directory, so this is the same
        // no-lookup-relative-to-a-name property the walk needs.
        if current == base.real {
            let raw = unsafe {
                libc::openat(
                    base.dirfd(),
                    c".".as_ptr(),
                    oflags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    create_mode as libc::c_uint,
                )
            };
            if raw < 0 {
                return Err(anyhow!(
                    "open {}: {}",
                    full_path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            if !fd_under_base(raw, &base.real) {
                return Err(anyhow!("path traversal blocked (raced symlink)"));
            }
            return Ok(unsafe { fs::File::from_raw_fd(raw) });
        }
        let (dirfd, name, expanded) = resolve_parent(base, &current, oflags & libc::O_CREAT != 0)?;
        let cstr = cstr_from_os(&name)?;
        let raw = unsafe {
            libc::openat(
                effective_dirfd(&dirfd, base),
                cstr.as_ptr(),
                oflags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                create_mode as libc::c_uint,
            )
        };
        if raw >= 0 {
            // Backstop only when the walk expanded a symlink: with zero
            // expansions every component (including the base) was opened
            // O_NOFOLLOW and none was a symlink, so the fd is structurally
            // under the base — the readlink would be a redundant syscall on
            // every common-case op. After an expansion the /proc/self/fd
            // check is cheap insurance against a lexical-check blind spot.
            if expanded && !fd_under_base(raw, &base.real) {
                // Raced intermediate symlink expanded outside the workspace.
                // The fd is closed on return; with O_CREAT an EMPTY 0600 file
                // may remain at the raced location (deleting it by path would
                // hand the attacker an unlink primitive — the artifact is
                // inert and the attempt is loud).
                return Err(anyhow!("path traversal blocked (raced symlink)"));
            }
            return Ok(unsafe { fs::File::from_raw_fd(raw) });
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENXIO) {
            // the leaf open carries O_NONBLOCK, so an ENXIO here is
            // the FIFO-with-no-reader open (or a driver-less device node) —
            // never a regular file. Name the class instead of surfacing the
            // bare OS message.
            return Err(anyhow!(
                "not a regular file (open failed with ENXIO): {}",
                full_path.display()
            ));
        }
        if err.raw_os_error() == Some(libc::ELOOP) {
            // Final component is a symlink. Resolve it lexically against the
            // parent's real path, require the result to stay under the
            // workspace, and re-walk it (symlinks inside the target are
            // expanded component-by-component by the next iteration).
            let from = effective_dirfd(&dirfd, base);
            let target = readlinkat_os(from, &name)?;
            let target_path = PathBuf::from(&target);
            let resolved = if target_path.is_absolute() {
                normalize_lexical(&target_path)
            } else {
                let dir_real = std::fs::read_link(format!("/proc/self/fd/{}", from))
                    .map_err(|e| anyhow!("readlink parent fd: {}", e))?;
                normalize_lexical(&dir_real.join(target_path))
            };
            if !resolved.starts_with(&base.real) {
                return Err(anyhow!("path traversal blocked (symlink escape)"));
            }
            current = resolved;
            continue;
        }
        return Err(anyhow!("open {}: {}", full_path.display(), err));
    }
    Err(anyhow!(
        "open {}: symlink chain too deep or repeatedly raced",
        full_path.display()
    ))
}

/// Read-only verified open (READ).
///
/// O_NONBLOCK: the agent can plant a FIFO in its own volume (mknod
/// is applied verbatim by the passthrough), and a blocking open(2) on one
/// parks the calling thread until a writer appears — holding the MOUNT_GATE
/// read guard and a warden connection-pool slot, so enough planted FIFOs
/// wedge unmount (a tenant self-DoS that also blocks the switch gate). The
/// flag is ignored for regular files, and the callers reject non-regular
/// files on the verified fd right after the open.
fn open_read_verified(base: &BaseDir, full_path: &Path) -> Result<fs::File> {
    openat_verified(base, full_path, libc::O_RDONLY | libc::O_NONBLOCK, 0)
}

/// Write verified open (WRITE). `create` per the op's semantics; append vs
/// overwrite is expressed with O_APPEND (truncate is deferred to the caller,
/// applied on the verified fd). Mode 0600 at creation; the requested mode is
/// fchmod'd afterwards by write_file.
///
/// O_NONBLOCK, same rule as the read open: a planted FIFO must
/// never park the thread on open(2). On a FIFO with no reader the kernel
/// answers ENXIO immediately, which openat_verified names.
fn open_write_verified(
    base: &BaseDir,
    full_path: &Path,
    create: bool,
    append: bool,
) -> Result<fs::File> {
    let mut flags = libc::O_WRONLY | libc::O_NONBLOCK;
    if append {
        flags |= libc::O_APPEND;
    }
    if create {
        flags |= libc::O_CREAT;
    }
    openat_verified(base, full_path, flags, 0o600)
}

/// Verified directory open (LIST_DIR): same walk, directory-final, fd
/// backstop before returning.
fn open_dir_verified(base: &BaseDir, full_path: &Path) -> Result<fs::File> {
    openat_verified(base, full_path, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

/// Read a file at the given path (relative to the workspace directory `base`).
///
/// - offset: byte offset to start reading from (0 = start; negative is treated
///   as 0 — read has no append semantics).
/// - length: max bytes to read (0 = read up to max_bytes, capped at file size).
/// - max_bytes: hard cap on read size (from config, default 16 MB).
///
/// Reads in a loop until `length` bytes are gathered or EOF: a single `read(2)`
/// over virtio-fs on a network-backed volume may return fewer bytes than
/// requested without an error,
/// and a single-read implementation would silently truncate large reads.
/// The buffer is pre-allocated to `min(effective_length, 8 KiB)` and grows on
/// demand rather than allocating the full cap up front.
pub(crate) fn read_file(
    base: &Path,
    path: &str,
    offset: i64,
    length: u64,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let base = BaseDir::open(base)?;
    let full_path = validate_path_under(&base, path)?;

    // Open first, then fstat the OPEN file — no separate stat whose result
    // could be raced; the verified open blocks both the swapped-final-symlink
    // and the swapped-intermediate-symlink escapes (see openat_verified).
    let mut file =
        open_read_verified(&base, &full_path).with_context(|| format!("open {}", path))?;
    let metadata = file.metadata().with_context(|| format!("stat {}", path))?;
    if !metadata.is_file() {
        // Named class: FIFOs/devices/directories are all refused
        // here, after the non-blocking open.
        return Err(anyhow!("not a regular file: {}", path));
    }

    let effective_length = if length > 0 {
        (length as usize).min(max_bytes)
    } else {
        (metadata.len() as usize).min(max_bytes)
    };

    if offset > 0 {
        file.seek(SeekFrom::Start(offset as u64))
            .with_context(|| format!("seek to offset {}", offset))?;
    }

    // Loop read until we have effective_length bytes or hit EOF. A single
    // read() can return a short count on network filesystems; without the
    // loop the response would silently carry fewer bytes than the agent asked
    // for (or than the file holds under the cap).
    let mut buf = Vec::with_capacity(effective_length.min(8192));
    let mut chunk = [0u8; 8192];
    loop {
        if buf.len() >= effective_length {
            break;
        }
        let want = std::cmp::min(chunk.len(), effective_length - buf.len());
        match file.read(&mut chunk[..want]) {
            Ok(0) => break, // EOF
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(anyhow!("read {}: {}", path, e)),
        }
    }
    Ok(buf)
}

/// Write data to a file at the given path (relative to `base`).
///
/// - offset: byte offset to start writing (0 = start/overwrite, -1 = append;
///   any other negative value is rejected — it has no defined semantics and
///   previously fell through to an implicit "write at 0 without truncate").
///   Positive offsets are capped at `max_sparse_offset`: an unbounded seek
///   lets a tenant create a sparse file whose apparent size a host-side
///   template save would then materialize into shared storage.
/// - mode: file creation mode (e.g., 0o644 = 0x1A4). 0 = default 0o644
/// - data: raw bytes to write (binary-safe, no shell escaping)
pub(crate) fn write_file(
    base: &Path,
    path: &str,
    offset: i64,
    mode: u32,
    data: &[u8],
    max_sparse_offset: i64,
) -> Result<()> {
    if offset < -1 {
        return Err(anyhow!(
            "invalid offset {} (0 = overwrite, -1 = append, >0 = sparse write)",
            offset
        ));
    }
    if offset > max_sparse_offset {
        return Err(anyhow!(
            "write offset {} exceeds the {} byte sparse-write cap",
            offset,
            max_sparse_offset
        ));
    }
    let base = BaseDir::open(base)?;
    let full_path = validate_path_under(&base, path)?;

    let effective_mode = if mode == 0 { 0o644 } else { mode };

    // Missing parent directories are auto-created by the verified open's
    // component walk (like mkdir -p, in-workspace only — see resolve_parent's
    // create_missing), which replaces the old path-based create_dir_all.

    // Whether the target exists before the open — decides if the creation
    // mode applies (path probe is fine here: mode only, not a security
    // decision).
    let was_created_now = !full_path.exists();

    // Verified write open. Truncate is DEFERRED: openat_verified refuses to
    // carry destructive flags so a raced symlink cannot damage anything
    // outside the workspace before the fd is verified. create=false for
    // append (POSIX O_APPEND|O_CREAT would also work, but a missing file
    // under append is created by create=true symmetrically — keep the old
    // semantic: append also creates).
    let create = true;
    let append = offset == -1;
    // `{:#}` renders the WHOLE cause chain into the top-level message:
    // Response::app_err prints Display (the top context only), so a refusal
    // that lives in the cause — the non-regular-file ENXIO class —
    // would otherwise reach the caller as a bare "open for write <path>".
    let mut file = open_write_verified(&base, &full_path, create, append)
        .map_err(|e| anyhow!("open for write {}: {:#}", path, e))?;

    // reject non-regular files on the VERIFIED fd (the same rule the
    // read path applies) — a planted FIFO with a reader, or a device node,
    // must never be written through the file API.
    if !(file.metadata().with_context(|| format!("stat {}", path)))?.is_file() {
        return Err(anyhow!("not a regular file: {}", path));
    }

    // Overwrite semantics (offset 0) truncate AFTER verification, on the
    // verified fd — ftruncate acts on the inode the fd pins, not on a
    // re-walkable path.
    if offset == 0 {
        file.set_len(0)
            .with_context(|| format!("truncate {}", path))?;
    }

    // Apply the requested mode to the file via the verified fd (fchmod — a
    // path-based chmod could be raced onto a swapped symlink). Only freshly
    // created files get the mode; an existing file keeps its permissions
    // (POSIX open semantics). Best-effort: ignore errors.
    if was_created_now {
        let _ = unsafe { libc::fchmod(file.as_raw_fd(), effective_mode) };
    }

    if offset > 0 {
        file.seek(SeekFrom::Start(offset as u64))
            .with_context(|| format!("seek to offset {}", offset))?;
    }

    file.write_all(data)
        .with_context(|| format!("write {}", path))?;
    file.flush().with_context(|| format!("flush {}", path))?;
    Ok(())
}

/// Get metadata for a file/directory at the given path.
/// Returns structured EntryInfo serialized as JSON.
pub(crate) fn stat_file(base: &Path, path: &str) -> Result<EntryInfo> {
    let base = BaseDir::open(base)?;
    let full_path = validate_path_under(&base, path)?;

    // lstat via the verified parent dirfd (fstatat AT_SYMLINK_NOFOLLOW): the
    // parent is reached without following any swapped symlink, and the final
    // component is reported as itself when it is a symlink — no content is
    // followed or leaked.
    let (dirfd, name, _) =
        resolve_parent(&base, &full_path, false).with_context(|| format!("stat {}", path))?;
    let cstr = cstr_from_os(&name)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            effective_dirfd(&dirfd, &base),
            cstr.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        return Err(anyhow!(
            "stat {}: {}",
            path,
            std::io::Error::last_os_error()
        ));
    }
    entry_info_from_stat(&base.real, &full_path, &st)
}

/// List directory contents at the given path.
///
/// - depth: recursion depth (0 = entries only, 1 = one level deep, etc.;
///   clamped to MAX_LIST_DEPTH)
/// - max_bytes: byte budget for the collected listing (the same cap a read
///   carries — see the LIST_DIR response bounds block above)
///
/// Returns a Vec of EntryInfo serialized as JSON array. When the budget or
/// the entry cap is hit, the listing ends with one marker entry
/// (file_type "truncated", size = entries actually returned).
pub(crate) fn list_dir(
    base: &Path,
    path: &str,
    depth: u32,
    max_bytes: usize,
) -> Result<Vec<EntryInfo>> {
    let base = BaseDir::open(base)?;
    let full_path = validate_path_under(&base, path)?;

    // Verified directory open (component walk + fd backstop), then readdir
    // through the /proc/self/fd magic symlink — kernel-generated for the
    // opened dir inode, immune to path swaps.
    let dir_file =
        open_dir_verified(&base, &full_path).with_context(|| format!("stat {}", path))?;
    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", dir_file.as_raw_fd()));

    let mut entries = Vec::new();
    let mut budget = ListBudget {
        remaining: max_bytes,
        truncated: false,
    };
    // The dir_file (and its fd) must stay open for the whole recursion — the
    // fd_path entries resolve through it.
    list_dir_recursive(
        &base.real,
        &fd_path,
        &full_path,
        clamp_list_depth(depth),
        &mut entries,
        &dir_file,
        &mut budget,
    )?;
    if budget.truncated {
        let returned = entries.len();
        entries.push(truncated_marker(returned));
    }
    Ok(entries)
}

/// Open `name` under `dir_fd` as a DIRECTORY, refusing a symlink or any
/// non-directory. Used by the listing recursion so the child is pinned by
/// descriptor and recursed through `/proc/self/fd/N` — an entry swapped for
/// a symlink between the lstat and the open is refused here (ENOTDIR/ELOOP)
/// instead of being followed into the warden's namespace.
fn open_child_dir_no_follow(dir_fd: &fs::File, name: &std::ffi::OsStr) -> Option<fs::File> {
    let c = cstr_from_os(name).ok()?;
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    Some(unsafe { fs::File::from_raw_fd(fd) })
}

/// `phys` is the fd-based path to read (immune to races), `logical` the
/// validated workspace-relative display path entries are reported under.
/// Stops (and flags `budget.truncated`) as soon as the budget or entry cap
/// is exhausted; the check runs BEFORE building the EntryInfo so the bounded
/// memory is the bound itself, not a post-hoc trim.
fn list_dir_recursive(
    base: &Path,
    phys: &Path,
    logical: &Path,
    remaining_depth: u32,
    entries: &mut Vec<EntryInfo>,
    dir_keepalive: &fs::File,
    budget: &mut ListBudget,
) -> Result<()> {
    let read_dir = fs::read_dir(phys).with_context(|| format!("readdir {}", logical.display()))?;

    for entry in read_dir {
        let entry = entry.context("readdir entry")?;
        let metadata = entry.metadata().context("readdir metadata")?;

        let name_len = entry.file_name().len();
        let path_len = logical.as_os_str().len() + 1 + name_len;
        // serde_json escapes each control byte as \u00XX (6 output bytes per
        // input byte). Charging 6x both strings is a conservative upper bound
        // on the serialized entry: a control-character name can no longer
        // turn a budget-fitting listing into a response several times larger
        // than the budget (the old 1x accounting let an 80-byte 0x01 name
        // produce ~6x its charge). Normal names are overcharged, but the
        // 16384-entry cap and the 16MiB budget still admit practical
        // listings; correctness of the bound beats the exact figure.
        let cost = 6 * (path_len + name_len) + LIST_ENTRY_FIXED_BYTES;
        if entries.len() >= MAX_LIST_ENTRIES || cost > budget.remaining {
            budget.truncated = true;
            return Ok(());
        }

        // Report under the LOGICAL path (the agent's workspace view), never
        // the /proc/self/fd internals.
        let logical_entry = logical.join(entry.file_name());
        let info = entry_info_for(base, &logical_entry, &metadata)?;
        entries.push(info);
        budget.remaining -= cost;

        // Recurse into subdirectories if depth allows. A symlinked dir is
        // NOT recursed into (entry.metadata() is lstat — is_dir() is false
        // for symlinks). The child is re-opened O_NOFOLLOW through the CURRENT
        // directory fd and recursed through its /proc/self/fd path: the old
        // `read_dir(entry.path())` re-resolved a string path, so an entry
        // swapped for a symlink between the lstat above and the read_dir
        // made the WARDEN list the link's target (a warden-namespace path)
        // instead of the workspace entry.
        if remaining_depth > 0 && metadata.is_dir() {
            match open_child_dir_no_follow(dir_keepalive, entry.file_name().as_os_str()) {
                Some(child) => {
                    let child_phys =
                        PathBuf::from(format!("/proc/self/fd/{}", child.as_raw_fd()));
                    list_dir_recursive(
                        base,
                        &child_phys,
                        &logical_entry,
                        remaining_depth - 1,
                        entries,
                        &child,
                        budget,
                    )?;
                    if budget.truncated {
                        return Ok(());
                    }
                }
                None => {
                    // Swapped to a symlink/special file after the lstat: skip
                    // it (never follow), same observable as a non-directory.
                }
            }
        }
    }
    Ok(())
}

/// chmod `name` under `dir_fd` WITHOUT ever following a symlink.
///
/// `fchmodat(..., flags=0)` follows the final component, and `make_dir` runs
/// right after `mkdirat` — a tenant process can replace the freshly created
/// directory with a symlink in that window, turning the warden's chmod into a
/// mode change on an arbitrary file in the WARDEN's mount namespace. Use
/// fchmodat2(AT_SYMLINK_NOFOLLOW) when the kernel has it (Linux 6.5+; the
/// shipped guest does), else open the entry O_NOFOLLOW|O_DIRECTORY and
/// fchmod the fd. Both forms act on the inode, never on a re-resolved path.
fn chmod_at_no_follow(dir_fd: RawFd, name: &std::ffi::OsStr, mode: u32) -> std::io::Result<()> {
    // x86_64 syscall number; libc's SYS_fchmodat2 is not in every crate
    // version this tree builds against.
    const SYS_FCHMODAT2: libc::c_long = 452;
    const AT_SYMLINK_NOFOLLOW: libc::c_int = 0x100;
    let c = cstr_from_os(name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    let rc = unsafe {
        libc::syscall(
            SYS_FCHMODAT2,
            dir_fd,
            c.as_ptr(),
            mode as libc::mode_t,
            AT_SYMLINK_NOFOLLOW as libc::c_long,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::ENOSYS) {
        return Err(err);
    }
    // Older kernel fallback: fd-anchored, no-follow; a symlink refuses here.
    let fd = unsafe {
        libc::openat(
            dir_fd,
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fchmod(fd, mode as libc::mode_t) };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if rc == 0 {
        Ok(())
    } else {
        Err(err)
    }
}

/// Create a directory at the given path (with parents).
///
/// - mode: directory mode (e.g., 0o755 = 0x1ED). 0 = default 0o755
///
/// Idempotent: no error if the directory already exists.
pub(crate) fn make_dir(base: &Path, path: &str, mode: u32) -> Result<()> {
    let base = BaseDir::open(base)?;
    let full_path = validate_path_under(&base, path)?;

    let effective_mode = if mode == 0 { 0o755 } else { mode };

    if full_path.is_dir() {
        return Ok(()); // idempotent
    }

    // mkdir -p under the verified walk: missing parents are created by
    // resolve_parent(create_missing), the final component by mkdirat on the
    // walked parent fd (never on a re-walked path).
    let (dirfd, name, _) =
        resolve_parent(&base, &full_path, true).with_context(|| format!("mkdir {}", path))?;
    let from = effective_dirfd(&dirfd, &base);
    let cstr = cstr_from_os(&name)?;
    let rc = unsafe { libc::mkdirat(from, cstr.as_ptr(), 0o755) };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        // Idempotent: already exists as a directory → ok.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let st_rc = unsafe { libc::fstatat(from, cstr.as_ptr(), &mut st, 0) };
        if st_rc == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            return Ok(());
        }
        return Err(anyhow!("mkdir {}: {}", path, e));
    }

    // Set mode on the created directory, fd-relative (no path re-walk) and
    // NO-FOLLOW: the entry was just created in an agent-writable tree and a
    // racing process may have replaced it with a symlink (fchmodat with
    // flags=0 would chmod the link's target in the warden's namespace).
    // Best-effort.
    let _ = chmod_at_no_follow(from, &name, effective_mode);
    Ok(())
}

/// Remove a file or directory at the given path.
/// - recursive: if true, remove directory and all contents (rm -rf).
///   If false and the path is a non-empty directory, returns an error.
pub(crate) fn remove_path(base: &Path, path: &str, recursive: bool) -> Result<()> {
    let base = BaseDir::open(base)?;
    let full_path = validate_path_under(&base, path)?;

    // lstat via the verified parent dirfd: existence + type (dir vs other,
    // symlinks count as "other" — unlink acts on the link itself).
    let (dirfd, name, _) =
        resolve_parent(&base, &full_path, false).with_context(|| format!("remove {}", path))?;
    let from = effective_dirfd(&dirfd, &base);
    let cstr = cstr_from_os(&name)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(from, cstr.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc < 0 {
        return Err(anyhow!("path does not exist: {}", path));
    }

    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    if is_dir {
        if recursive {
            // remove_dir_all by fd-relative walk: std has no remove_dirat; do
            // it by opening the dir through the verified parent (rmtree).
            let child = unsafe {
                libc::openat(
                    from,
                    cstr.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if child < 0 {
                return Err(anyhow!(
                    "remove_dir_all {}: {}",
                    path,
                    std::io::Error::last_os_error()
                ));
            }
            let child_file = unsafe { fs::File::from_raw_fd(child) };
            let res = remove_dir_all_fd(&child_file, &full_path);
            drop(child_file);
            // `{:#}` renders the WHOLE cause chain: Response::app_err prints
            // Display (top context only), so the named budget/depth refusals
            // from the traversal must not be buried under this prefix.
            res.map_err(|e| anyhow!("remove_dir_all {}: {:#}", path, e))?;
            // Contents gone — remove the (now empty) target directory itself.
            let rc = unsafe { libc::unlinkat(from, cstr.as_ptr(), libc::AT_REMOVEDIR) };
            if rc < 0 {
                return Err(anyhow!(
                    "remove_dir {}: {}",
                    path,
                    std::io::Error::last_os_error()
                ));
            }
        } else {
            let rc = unsafe { libc::unlinkat(from, cstr.as_ptr(), libc::AT_REMOVEDIR) };
            if rc < 0 {
                return Err(anyhow!(
                    "remove_dir {}: {}",
                    path,
                    std::io::Error::last_os_error()
                ));
            }
        }
    } else {
        // unlink acts on the final component itself (never follows a
        // symlink), fd-relative under the verified parent.
        let rc = unsafe { libc::unlinkat(from, cstr.as_ptr(), 0) };
        if rc < 0 {
            return Err(anyhow!(
                "remove_file {}: {}",
                path,
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// Depth cap for SUB_OP_REMOVE recursive deletes (see remove_dir_all_fd).
/// Each traversal level holds TWO fds (the O_NOFOLLOW-opened directory File
/// plus its ReadDir, which owns a second fd on the same inode), so the cap
/// bounds fd usage at 2×cap — safely under the warden's RLIMIT_NOFILE — and,
/// with the iterative traversal, replaces the unbounded recursion that a
/// tenant-planted deep tree used to turn into a warden stack overflow. (A
/// tree of ANY depth is creatable in-guest with openat chains: PATH_MAX
/// bounds single-lookup path length, not tree depth; the old one-frame-per-
/// level recursion on a ~2 MiB blocking-pool thread aborted PID 1 at a few
/// thousand levels → guest kernel panic → wedged VM, the init-death failure
/// mode raw_server documents.) Real trees sit far below this (deeper than
/// MAX_LIST_DEPTH = 64 listings already refuse); deeper cleanup belongs on
/// the exec path (`rm -rf` in-guest), which holds no warden lock.
pub(crate) const MAX_REMOVE_DEPTH: usize = 200;

/// Entry budget for one recursive remove: bounds the time a single op can
/// hold the MOUNT_GATE read guard (the same discipline as list_dir's byte
/// budget). Exceeding it is a NAMED error and the op is idempotent to
/// re-issue — partially deleted trees simply continue on the next call.
pub(crate) const MAX_REMOVE_ENTRIES: usize = 65_536;

/// One level of the iterative post-order traversal.
///
/// `dir` is the O_NOFOLLOW-opened directory (every openat/unlinkat below is
/// fd-relative to it); `read` is its readdir, opened through the
/// `/proc/self/fd/N` magic link (kernel-pinned inode — immune to path
/// swaps); `name_in_parent` is this directory's own name under its parent
/// (None for the traversal root, which the caller unlinks itself).
struct RemoveFrame {
    dir: fs::File,
    read: fs::ReadDir,
    name_in_parent: Option<std::ffi::CString>,
}

/// Build one traversal level for an already-opened directory fd.
fn remove_frame(
    dir: fs::File,
    name_in_parent: Option<std::ffi::CString>,
    logical: &Path,
) -> Result<RemoveFrame> {
    let fd_path = format!("/proc/self/fd/{}", dir.as_raw_fd());
    let read = fs::read_dir(&fd_path).with_context(|| format!("readdir {}", logical.display()))?;
    Ok(RemoveFrame {
        dir,
        read,
        name_in_parent,
    })
}

/// Removal starting from an OPENED directory fd — ITERATIVE (explicit stack,
/// post-order), bounded by `max_depth`/`max_entries`.
///
/// Security discipline is unchanged from the former recursive shape: child
/// directories open O_NOFOLLOW|O_DIRECTORY through the CURRENT level's fd
/// (an entry swapped to a symlink between the lstat and the open fails
/// closed instead of being followed into the warden's namespace), readdir
/// goes through the magic link, and every unlink/rmdir is fd-relative under
/// a walked parent. What changes is the resource shape: O(depth) HEAP
/// frames instead of O(depth) STACK frames, at most 2×max_depth fds, and
/// hostile shapes (unboundedly deep, unboundedly wide) surface as named
/// errors rather than a stack overflow in PID 1.
fn remove_dir_all_bounded(
    dir: &fs::File,
    logical: &Path,
    max_depth: usize,
    max_entries: usize,
) -> Result<()> {
    // The caller's fd is borrowed; the traversal owns a dup for the root
    // level (dropped when the level pops).
    let root = dir
        .try_clone()
        .with_context(|| format!("dup {}", logical.display()))?;
    let mut stack: Vec<RemoveFrame> = vec![remove_frame(root, None, logical)?];
    let mut entries = 0usize;
    // One step of the top frame's iteration. Pulled out under a SHORT
    // mutable borrow so the Entry/Exhausted handling below can push/pop the
    // stack freely (holding last_mut() across a push would not compile —
    // and that constraint is the load-bearing proof that each step touches
    // exactly one frame).
    enum Step {
        Entry(std::fs::DirEntry),
        Exhausted,
    }
    while !stack.is_empty() {
        let step = {
            let frame = stack
                .last_mut()
                .expect("loop condition guarantees a top frame");
            match frame.read.next() {
                Some(Ok(entry)) => Step::Entry(entry),
                Some(Err(e)) => return Err(anyhow!("readdir {}: {}", logical.display(), e)),
                None => Step::Exhausted,
            }
        };
        match step {
            Step::Entry(entry) => {
                entries += 1;
                if entries > max_entries {
                    return Err(anyhow!(
                        "remove budget exceeded ({} entries processed, max {}) — re-issue to continue, or use exec `rm -rf` for bulk cleanup",
                        entries,
                        max_entries
                    ));
                }
                let name = cstr_from_os(&entry.file_name())?;
                let metadata = entry.metadata().context("readdir metadata")?;
                if metadata.is_dir() {
                    if stack.len() >= max_depth {
                        return Err(anyhow!(
                            "remove depth exceeds {} — use exec `rm -rf` for deeper trees",
                            max_depth
                        ));
                    }
                    let parent_fd = stack
                        .last()
                        .expect("the frame this entry came from is still on the stack")
                        .dir
                        .as_raw_fd();
                    let child = unsafe {
                        libc::openat(
                            parent_fd,
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if child < 0 {
                        return Err(anyhow!(
                            "open subdir {}: {}",
                            entry.path().display(),
                            std::io::Error::last_os_error()
                        ));
                    }
                    let child_file = unsafe { fs::File::from_raw_fd(child) };
                    let child_logical = entry.path();
                    stack.push(remove_frame(
                        child_file,
                        Some(name),
                        Path::new(&child_logical),
                    )?);
                } else {
                    let parent_fd = stack
                        .last()
                        .expect("the frame this entry came from is still on the stack")
                        .dir
                        .as_raw_fd();
                    let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) };
                    if rc < 0 {
                        return Err(anyhow!(
                            "unlink {}: {}",
                            entry.path().display(),
                            std::io::Error::last_os_error()
                        ));
                    }
                }
            }
            Step::Exhausted => {
                // Directory exhausted: pop it (closing both fds via Drop),
                // then remove it from its parent — children were fully
                // processed first (post-order: a frame reaches Exhausted
                // only after its own readdir returned None, and every subdir
                // frame sat above it on the stack in the meantime).
                let frame = stack.pop().expect("loop condition guaranteed a frame");
                if let Some(name) = frame.name_in_parent {
                    let parent = stack
                        .last()
                        .expect("non-root frames always have a parent on the stack")
                        .dir
                        .as_raw_fd();
                    let rc = unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) };
                    if rc < 0 {
                        return Err(anyhow!(
                            "rmdir {}: {}",
                            name.to_string_lossy(),
                            std::io::Error::last_os_error()
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Recursive removal starting from an OPENED directory fd, at the production
/// budgets (MAX_REMOVE_DEPTH / MAX_REMOVE_ENTRIES). See remove_dir_all_bounded
/// for the traversal contract; `logical` is only for error messages.
fn remove_dir_all_fd(dir: &fs::File, logical: &Path) -> Result<()> {
    remove_dir_all_bounded(dir, logical, MAX_REMOVE_DEPTH, MAX_REMOVE_ENTRIES)
}

/// Rename a file or directory from old path to new path.
/// Both paths are relative to the workspace directory. rename(2) does not
/// follow symlinks on the operands.
pub(crate) fn rename_path(base: &Path, old: &str, new: &str) -> Result<()> {
    let base = BaseDir::open(base)?;
    let old_path = validate_path_under(&base, old)?;
    let new_path = validate_path_under(&base, new)?;

    if !old_path.exists() {
        return Err(anyhow!("source path does not exist: {}", old));
    }

    // renameat between two walked parent fds — both ends act on final
    // components under verified directories, never on re-walked paths.
    // rename(2) does not follow symlinks on the operands.
    let (old_dir, old_name, _) =
        resolve_parent(&base, &old_path, false).with_context(|| format!("rename {}", old))?;
    let (new_dir, new_name, _) =
        resolve_parent(&base, &new_path, false).with_context(|| format!("rename -> {}", new))?;
    let old_c = cstr_from_os(&old_name)?;
    let new_c = cstr_from_os(&new_name)?;
    let rc = unsafe {
        libc::renameat(
            effective_dirfd(&old_dir, &base),
            old_c.as_ptr(),
            effective_dirfd(&new_dir, &base),
            new_c.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(anyhow!(
            "rename {} -> {}: {}",
            old,
            new,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Build an EntryInfo from a raw stat (stat_file's fstatat result — no
/// std::fs::Metadata constructor exists for raw stats). Mirrors
/// entry_info_for's field mapping.
fn entry_info_from_stat(base: &Path, path: &Path, st: &libc::stat) -> Result<EntryInfo> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let rel_path = path
        .strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned();
    let fmt = st.st_mode & libc::S_IFMT;
    let file_type = if fmt == libc::S_IFLNK {
        "symlink"
    } else if fmt == libc::S_IFDIR {
        "dir"
    } else {
        "file"
    }
    .to_string();
    let modified_time = if st.st_mtime > 0 {
        time::OffsetDateTime::from_unix_timestamp(st.st_mtime)
            .ok()
            .and_then(|dt| {
                let f = time::format_description::well_known::Rfc3339;
                dt.format(&f).ok()
            })
    } else {
        None
    };
    Ok(EntryInfo {
        name,
        path: rel_path,
        file_type,
        size: st.st_size as u64,
        mode: st.st_mode & 0o7777,
        modified_time,
    })
}

/// Build an EntryInfo from a path and its metadata.
fn entry_info_for(base: &Path, path: &Path, metadata: &fs::Metadata) -> Result<EntryInfo> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Compute the path relative to the workspace directory for the response.
    // This matches the agent's perspective: file API paths are relative to
    // /workspace, so stat/list_dir responses should use the same base.
    let rel_path = path
        .strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned();

    let file_type = if metadata.is_symlink() {
        "symlink".to_string()
    } else if metadata.is_dir() {
        "dir".to_string()
    } else {
        "file".to_string()
    };

    let modified_time = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| {
            // RFC 3339 format using the time crate.
            let secs = d.as_secs();
            time::OffsetDateTime::from_unix_timestamp(secs as i64)
                .ok()
                .and_then(|dt| {
                    let fmt = time::format_description::well_known::Rfc3339;
                    dt.format(&fmt).ok()
                })
                .unwrap_or_else(|| format!("{}", secs))
        });

    Ok(EntryInfo {
        name,
        path: rel_path,
        file_type,
        size: metadata.len(),
        mode: metadata.permissions().mode(),
        modified_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // All tests run against a temp-dir base — the same code path as
    // production (base = canonical /mnt/rootfs/workspace), with no mount or
    // root privileges required.
    fn test_base() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("warden_test_files")
            .tempdir()
            .unwrap()
    }

    /// Pin the test directory as the ops pin production's base (the same
    /// entry point: BaseDir::open).
    fn base_dir(base: &Path) -> BaseDir {
        BaseDir::open(base).expect("open the test base")
    }

    // ── validate_path_under ─────────────────────────────────────────

    #[test]
    fn validate_path_rejects_oversized_paths_promptly() {
        // A hostile 8 MiB path used to drive the ancestor walk for seconds
        // while holding the MOUNT_GATE read guard (unmount 30 s timeout → VM
        // destroy). The length/component caps make it an immediate refusal.
        let base = test_base();
        let bd = base_dir(base.path());
        let long = "a/".repeat(4000); // 8000 bytes > PATH_MAX
        let start = std::time::Instant::now();
        let err = validate_path_under(&bd, &long).expect_err("oversized path must be refused");
        assert!(format!("{err}").contains("too long"));
        assert!(
            start.elapsed() < std::time::Duration::from_millis(100),
            "the refusal must not walk the path ({:?})",
            start.elapsed()
        );
        // Component bomb within the byte cap (1500 components > 1024).
        let comps = "a/".repeat(1500);
        let err = validate_path_under(&bd, &comps).expect_err("component bomb must be refused");
        assert!(format!("{err}").contains("too many components"));
        // Control: a legitimate nested path still resolves.
        std::fs::create_dir_all(base.path().join("work/sub")).unwrap();
        std::fs::write(base.path().join("work/sub/f.txt"), b"x").unwrap();
        assert!(validate_path_under(&bd, "work/sub/f.txt").is_ok());
    }

    #[test]
    fn validate_path_traversal_blocked() {
        let base = test_base();
        assert!(
            validate_path_under(&base_dir(base.path()), "../../etc/passwd").is_err(),
            "path traversal should be blocked"
        );
    }

    #[test]
    fn validate_path_absolute_leading_slash_trimmed() {
        let base = test_base();
        std::fs::write(base.path().join("file.txt"), b"x").unwrap();
        // A leading '/' is trimmed: "/file.txt" resolves relative to the base,
        // matching the sandlot/gateway client convention.
        let p = validate_path_under(&base_dir(base.path()), "/file.txt").unwrap();
        assert_eq!(p, base.path().join("file.txt").canonicalize().unwrap());
    }

    #[test]
    fn validate_path_empty_resolves_to_base() {
        let base = test_base();
        let p = validate_path_under(&base_dir(base.path()), "").unwrap();
        assert_eq!(p, base.path().canonicalize().unwrap());
    }

    #[test]
    fn validate_path_existing_file_canonicalized() {
        let base = test_base();
        std::fs::write(base.path().join("a.txt"), b"x").unwrap();
        let p = validate_path_under(&base_dir(base.path()), "a.txt").unwrap();
        assert_eq!(p, base.path().join("a.txt").canonicalize().unwrap());
    }

    #[test]
    fn validate_path_missing_tail_reconstructed_from_ancestor() {
        // "workflow/test.txt" where workflow/ doesn't exist yet: the closest
        // existing ancestor (the base) is validated and the tail appended.
        let base = test_base();
        let p = validate_path_under(&base_dir(base.path()), "workflow/test.txt").unwrap();
        assert!(p.ends_with("workflow/test.txt"));
        assert!(p.starts_with(base.path().canonicalize().unwrap()));
    }

    #[test]
    fn validate_path_symlink_escape_blocked() {
        // A symlink inside the workspace pointing outside the base must be
        // rejected by the canonicalize + prefix check.
        let base = test_base();
        let outside = tempfile::Builder::new()
            .prefix("warden_test_outside")
            .tempdir()
            .unwrap();
        std::os::unix::fs::symlink(outside.path(), base.path().join("escape")).unwrap();
        assert!(
            validate_path_under(&base_dir(base.path()), "escape").is_err(),
            "symlink escape must be blocked"
        );
        assert!(validate_path_under(&base_dir(base.path()), "escape/x").is_err());
    }

    #[test]
    fn validate_path_symlink_inside_base_followed() {
        // A symlink to another location INSIDE the base is legitimate.
        let base = test_base();
        std::fs::write(base.path().join("real.txt"), b"r").unwrap();
        std::os::unix::fs::symlink("real.txt", base.path().join("link.txt")).unwrap();
        let p = validate_path_under(&base_dir(base.path()), "link.txt").unwrap();
        assert!(p.ends_with("real.txt"));
    }

    // ── race-hardened opens (regression: intermediate-symlink TOCTOU) ──
    //
    // The agent can swap a non-final path component for a symlink between
    // validation and open (both sides reach the same underlying volume). The
    // component walk must refuse to follow an escaping swap — validated by
    // simulating the race deterministically: validate with d a REAL dir, then
    // swap d for a symlink before the op runs.
    #[test]
    fn raced_intermediate_symlink_swap_is_blocked() {
        // READ: validate with d a REAL dir, then swap d for a symlink to an
        // outside directory before the open — the hardened open must refuse
        // to follow it, and the outside file must be untouched.
        let base = test_base();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"WARDEN-SIDE").unwrap();
        std::fs::create_dir(base.path().join("d")).unwrap();
        let v = validate_path_under(&base_dir(base.path()), "d/secret").unwrap();
        std::fs::remove_dir(base.path().join("d")).unwrap();
        std::os::unix::fs::symlink(outside.path(), base.path().join("d")).unwrap();
        assert!(
            open_read_verified(&base_dir(base.path()), &v).is_err(),
            "read through a swapped intermediate symlink must be rejected"
        );
        assert_eq!(
            std::fs::read(outside.path().join("secret")).unwrap(),
            b"WARDEN-SIDE"
        );

        // WRITE (with create): same swap, must not create anything outside.
        let outside2 = tempfile::tempdir().unwrap();
        std::fs::remove_file(base.path().join("d")).unwrap(); // the symlink
        std::fs::create_dir(base.path().join("d")).unwrap();
        let v3 = validate_path_under(&base_dir(base.path()), "d/pwned").unwrap();
        assert!(v3.starts_with(base.path()));
        std::fs::remove_dir(base.path().join("d")).unwrap();
        std::os::unix::fs::symlink(outside2.path(), base.path().join("d")).unwrap();
        assert!(
            open_write_verified(&base_dir(base.path()), &v3, true, false).is_err(),
            "write through a swapped intermediate symlink must be rejected"
        );
        assert!(
            !outside2.path().join("pwned").exists(),
            "nothing may be created outside the workspace"
        );
    }

    #[test]
    fn validate_path_dotdot_on_missing_tail_is_rejected() {
        let base = test_base();
        // "a" does not exist, "b" does not exist: full canonicalize fails,
        // the walk-up branch runs.
        assert!(validate_path_under(&base_dir(base.path()), "a/../b").is_err());
    }

    #[test]
    fn validate_path_dotdot_with_existing_anchor_ok() {
        // a/../b with a EXISTING resolves to base/b — legal (canonicalize
        // branch resolves the .. against a real directory).
        let base = test_base();
        std::fs::create_dir(base.path().join("a")).unwrap();
        std::fs::write(base.path().join("b"), b"x").unwrap();
        let p = validate_path_under(&base_dir(base.path()), "a/../b").unwrap();
        assert!(p.ends_with("b"));
        assert_eq!(p.parent().unwrap(), base.path());
    }

    #[test]
    fn validate_path_dotdot_missing_anchor_is_enoent() {
        // a/../b with a MISSING: POSIX path resolution fails at `a` (ENOENT)
        // — the same semantics the kernel applies. (The old walk-up silently
        // dropped the `..` and wrote to a/b instead — a wrong target.)
        let base = test_base();
        std::fs::write(base.path().join("b"), b"x").unwrap();
        assert!(validate_path_under(&base_dir(base.path()), "a/../b").is_err());
    }

    // ── the workspace base is pinned as an fd ──────────────────────────
    //
    // The base (`/mnt/rootfs/workspace`) is agent-replaceable in flat mode,
    // where the chroot root IS the volume. The old code canonicalized it
    // (`base.canonicalize()`), so one planted `workspace -> /` made the
    // containment prefix "/" and every op ran in the WARDEN's namespace as
    // root. These pins plant the symlink and assert no op reaches the
    // warden-side sentinel — each op is exercised separately because each one
    // is a distinct privileged sink (read/write/unlink/rename/mkdir).

    /// Plant `<vol>/workspace -> <outside>` (the attack: one exec for the
    /// agent, `rm -rf /workspace && ln -s / /workspace`).
    fn plant_base_symlink(base: &Path, outside: &Path) {
        let _ = std::fs::remove_file(base);
        let _ = std::fs::remove_dir_all(base);
        std::os::unix::fs::symlink(outside, base).unwrap();
    }

    #[test]
    fn base_symlink_entry_is_not_followed() {
        // Mirrors the WARDEN-SIDE sentinel of raced_intermediate_symlink_
        // swap_is_blocked: `outside` stands in for the warden's own namespace
        // (the real attack plants `workspace -> /`, home of the warden's
        // /bin/busybox and /proc).
        let vol = test_base();
        let base = vol.path().join("workspace");
        std::fs::create_dir(&base).unwrap();
        std::fs::write(base.join("real.txt"), b"in-workspace").unwrap();
        let outside = tempfile::Builder::new()
            .prefix("warden_test_base_outside")
            .tempdir()
            .unwrap();
        std::fs::write(outside.path().join("secret"), b"WARDEN-SIDE").unwrap();

        // (name, probe) — the probe returns true when the op REACHED the
        // warden-side directory (a successful op against the sentinel, a
        // write/rename that landed there, or a listing that exposed it).
        // Every probe runs against a freshly planted symlink.
        let probes: Vec<(&str, Box<dyn Fn() -> bool>)> = vec![
            (
                "read",
                Box::new(|| {
                    read_file(&base, "secret", 0, 0, 1024)
                        .map(|d| d == b"WARDEN-SIDE")
                        .unwrap_or(false)
                }),
            ),
            (
                "write",
                Box::new(|| {
                    let _ = write_file(&base, "pwned", 0, 0o644, b"owned\n", i64::MAX);
                    outside.path().join("pwned").exists()
                }),
            ),
            ("stat", Box::new(|| stat_file(&base, "secret").is_ok())),
            (
                "list_dir",
                Box::new(|| {
                    list_dir(&base, "", 0, 1024 * 1024)
                        .map(|e| e.iter().any(|e| e.name == "secret"))
                        .unwrap_or(false)
                }),
            ),
            (
                "make_dir",
                Box::new(|| {
                    let _ = make_dir(&base, "warden-dir", 0o755);
                    outside.path().join("warden-dir").exists()
                }),
            ),
            (
                "remove",
                Box::new(|| remove_path(&base, "secret", false).is_ok()),
            ),
            (
                "rename",
                Box::new(|| rename_path(&base, "secret", "stolen").is_ok()),
            ),
        ];

        for (name, probe) in probes {
            plant_base_symlink(&base, outside.path());
            assert!(
                !probe(),
                "{} followed the planted base symlink into the warden-side directory",
                name
            );
            assert_eq!(
                std::fs::read(outside.path().join("secret")).unwrap(),
                b"WARDEN-SIDE",
                "{}: the warden-side sentinel was mutated",
                name
            );
            assert_eq!(
                std::fs::read_dir(outside.path()).unwrap().count(),
                1,
                "{}: an entry appeared in the warden-side directory",
                name
            );
            // The planted entry is rebuilt as a REAL directory
            // (prepare_mount_dir's idiom — a symlinked base is never
            // followed, not even to an in-volume target).
            let md = std::fs::symlink_metadata(&base).unwrap();
            assert!(
                md.file_type().is_dir() && !md.file_type().is_symlink(),
                "{}: the base entry must be a real directory after the op",
                name
            );
        }

        // Ops keep working, relative to the rebuilt real workspace.
        write_file(&base, "payload.txt", 0, 0o644, b"landed", i64::MAX).unwrap();
        assert_eq!(
            read_file(&base, "payload.txt", 0, 0, 1024).unwrap(),
            b"landed"
        );
    }

    #[test]
    fn in_workspace_symlinks_still_resolved() {
        // The fix must not break the legitimate cases the pre-existing tests
        // pin: a symlink INSIDE the workspace is still followed (final and
        // intermediate component); only the BASE is never followed.
        let base = test_base();
        std::fs::create_dir(base.path().join("sub")).unwrap();
        std::fs::write(base.path().join("sub/inner.txt"), b"inner").unwrap();
        std::os::unix::fs::symlink("sub/inner.txt", base.path().join("link.txt")).unwrap();
        std::os::unix::fs::symlink("sub", base.path().join("linkdir")).unwrap();

        assert_eq!(
            read_file(base.path(), "link.txt", 0, 0, 1024).unwrap(),
            b"inner"
        );
        assert_eq!(
            read_file(base.path(), "linkdir/inner.txt", 0, 0, 1024).unwrap(),
            b"inner"
        );
        write_file(base.path(), "linkdir/written.txt", 0, 0o644, b"w", i64::MAX).unwrap();
        assert_eq!(
            std::fs::read(base.path().join("sub/written.txt")).unwrap(),
            b"w"
        );
    }

    #[test]
    fn raced_base_swap_cannot_redirect_the_op() {
        // Base-swap TOCTOU: the base is resolved ONCE per op (BaseDir::open) and
        // every lookup is openat-relative to that fd. This test swaps the
        // entry AFTER the resolution — the seam is the internal entry point
        // the ops use — and asserts the swap cannot move the walk: the string
        // checks refuse the escaped path (fail closed) and the fd walk still
        // acts on the pinned inode. The old code re-resolved the base per
        // use, so each of these would have followed the planted link.
        let vol = test_base();
        let base = vol.path().join("workspace");
        std::fs::create_dir(&base).unwrap();
        std::fs::write(base.join("keep.txt"), b"pinned").unwrap();
        let outside = tempfile::Builder::new()
            .prefix("warden_test_base_race")
            .tempdir()
            .unwrap();
        std::fs::write(outside.path().join("secret"), b"WARDEN-SIDE").unwrap();

        let pinned = base_dir(&base);
        // The swap: the real directory is moved aside and a symlink planted
        // in the same slot (the agent's one exec — mv + symlink; the pinned
        // fd keeps the ORIGINAL inode alive under its new name).
        std::fs::rename(&base, vol.path().join("workspace-away")).unwrap();
        std::os::unix::fs::symlink(outside.path(), &base).unwrap();

        // A path that exists only OUTSIDE the pinned base is refused — the
        // re-resolved string would have resolved it into the warden-side dir.
        assert!(
            validate_path_under(&pinned, "secret").is_err(),
            "a swapped base must not validate a path that resolves outside"
        );
        // The fd walk still acts on the pinned inode: the file that lived in
        // the (now detached) workspace reads back from it.
        let kept = pinned.real.join("keep.txt");
        let mut f =
            open_read_verified(&pinned, &kept).expect("the pinned fd still holds the workspace");
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"pinned");
        // Nothing reached the warden-side directory.
        assert_eq!(
            std::fs::read(outside.path().join("secret")).unwrap(),
            b"WARDEN-SIDE"
        );
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
    }

    // ── read_file ───────────────────────────────────────────────────

    #[test]
    fn read_file_small() {
        let base = test_base();
        std::fs::write(base.path().join("hello.txt"), b"hello world").unwrap();
        let data = read_file(base.path(), "hello.txt", 0, 0, 64 * 1024).unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn read_file_with_offset() {
        let base = test_base();
        std::fs::write(base.path().join("offset.txt"), b"0123456789").unwrap();
        let data = read_file(base.path(), "offset.txt", 5, 3, 64 * 1024).unwrap();
        assert_eq!(data, b"567");
    }

    #[test]
    fn read_file_truncated_by_cap() {
        let base = test_base();
        std::fs::write(base.path().join("large.txt"), vec![0xABu8; 100]).unwrap();
        let data = read_file(base.path(), "large.txt", 0, 0, 10).unwrap();
        assert_eq!(data.len(), 10);
        assert!(data.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn read_file_missing_is_err() {
        let base = test_base();
        assert!(read_file(base.path(), "nope.txt", 0, 0, 1024).is_err());
    }

    #[test]
    fn read_file_directory_is_err() {
        let base = test_base();
        std::fs::create_dir(base.path().join("adir")).unwrap();
        assert!(read_file(base.path(), "adir", 0, 0, 1024).is_err());
    }

    #[test]
    fn read_file_via_internal_symlink_ok() {
        // Reading through a symlink that points inside the base works (the
        // ELOOP retry re-canonicalizes to the in-base target).
        let base = test_base();
        std::fs::write(base.path().join("real.txt"), b"via-link").unwrap();
        std::os::unix::fs::symlink("real.txt", base.path().join("link.txt")).unwrap();
        let data = read_file(base.path(), "link.txt", 0, 0, 1024).unwrap();
        assert_eq!(data, b"via-link");
    }

    // ── FIFO plants ──────────────────────────────────────────────────

    /// Plant a FIFO at `path` (mkfifo is legal in-sandbox — the passthrough
    /// applies it verbatim — so the agent can create one anywhere it can
    /// write).
    fn plant_fifo(path: &Path) {
        let c = std::ffi::CString::new(path.as_os_str().to_str().unwrap()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c.as_ptr(), 0o644) },
            0,
            "mkfifo {}",
            path.display()
        );
    }

    /// FIFO pin (read): a planted FIFO must not park the op on open(2).
    /// The leaf open carries O_NONBLOCK, so the FIFO opens immediately and
    /// the post-open fstat refuses it with a NAMED error. RED with
    /// O_NONBLOCK removed: the open blocks until a writer appears (never
    /// here), and the 5s watchdog below fires — mirroring the production
    /// symptom (the parked thread holds the MOUNT_GATE read guard and a
    /// warden pool slot).
    #[test]
    fn read_file_fifo_returns_promptly() {
        let base = test_base();
        plant_fifo(&base.path().join("planted.fifo"));
        let owned = base.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                read_file(&owned, "planted.fifo", 0, 0, 1 << 20)
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
            );
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Err(msg)) => {
                assert!(
                    msg.contains("not a regular file"),
                    "the refusal must be named, got: {msg}"
                );
            }
            Ok(Ok(())) => panic!("read_file must refuse a FIFO"),
            Err(_) => {
                panic!("read_file on a FIFO did not return within 5s (blocking open)")
            }
        }
    }

    /// FIFO pin (write, no reader): the O_NONBLOCK write open on a FIFO
    /// with no reader answers ENXIO immediately, which is named. RED with
    /// O_NONBLOCK removed: the open blocks (watchdog fires).
    #[test]
    fn write_file_fifo_returns_promptly() {
        let base = test_base();
        plant_fifo(&base.path().join("planted.fifo"));
        let owned = base.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                write_file(&owned, "planted.fifo", 0, 0o644, b"x", i64::MAX).map_err(|e| e.to_string()),
            );
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Err(msg)) => {
                assert!(
                    msg.contains("not a regular file"),
                    "the refusal must be named, got: {msg}"
                );
            }
            Ok(Ok(())) => panic!("write_file must refuse a FIFO"),
            Err(_) => {
                panic!("write_file on a FIFO did not return within 5s (blocking open)")
            }
        }
    }

    /// FIFO pin (write, reader held): with a reader present the open
    /// succeeds, so the refusal is the post-open fstat — never a write into
    /// the FIFO.
    #[test]
    fn write_file_fifo_with_reader_refused_by_fstat() {
        let base = test_base();
        let fifo = base.path().join("planted.fifo");
        plant_fifo(&fifo);
        let c = std::ffi::CString::new(fifo.as_os_str().to_str().unwrap()).unwrap();
        let rfd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(rfd >= 0, "open FIFO reader");
        let res = write_file(base.path(), "planted.fifo", 0, 0o644, b"x", i64::MAX);
        unsafe { libc::close(rfd) };
        let msg = res
            .expect_err("write_file must refuse a FIFO even with a reader")
            .to_string();
        assert!(
            msg.contains("not a regular file"),
            "the refusal must be named, got: {msg}"
        );
    }

    // ── write_file ──────────────────────────────────────────────────

    #[test]
    fn write_file_create() {
        let base = test_base();
        write_file(base.path(), "new.txt", 0, 0o644, b"created", i64::MAX).unwrap();
        assert_eq!(
            std::fs::read(base.path().join("new.txt")).unwrap(),
            b"created"
        );
    }

    #[test]
    fn write_file_append() {
        let base = test_base();
        std::fs::write(base.path().join("append.txt"), b"hello").unwrap();
        write_file(base.path(), "append.txt", -1, 0, b" world", i64::MAX).unwrap();
        assert_eq!(
            std::fs::read(base.path().join("append.txt")).unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn write_file_overwrite_offset() {
        let base = test_base();
        std::fs::write(base.path().join("overwrite.txt"), b"AAAAAAAAAA").unwrap();
        write_file(base.path(), "overwrite.txt", 5, 0, b"BBBBB", i64::MAX).unwrap();
        assert_eq!(
            std::fs::read(base.path().join("overwrite.txt")).unwrap(),
            b"AAAAABBBBB"
        );
    }

    #[test]
    fn write_file_creates_missing_parents() {
        let base = test_base();
        write_file(base.path(), "workflow/sub/out.txt", 0, 0, b"deep", i64::MAX).unwrap();
        assert_eq!(
            std::fs::read(base.path().join("workflow/sub/out.txt")).unwrap(),
            b"deep"
        );
    }

    #[test]
    fn write_file_mode_applied_on_create() {
        let base = test_base();
        write_file(base.path(), "mode.txt", 0, 0o600, b"x", i64::MAX).unwrap();
        let mode = std::fs::metadata(base.path().join("mode.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn write_file_invalid_negative_offset_rejected() {
        // Only 0 (overwrite), -1 (append) and positive offsets are defined;
        // anything else was previously an implicit "write at 0, no truncate".
        let base = test_base();
        assert!(write_file(base.path(), "x.txt", -5, 0, b"x", i64::MAX).is_err());
    }

    #[test]
    fn write_file_sparse_offset_capped() {
        // A seek past the cap would mint an arbitrarily large apparent file
        // whose hole a host-side template save would materialize.
        let base = test_base();
        let err = write_file(base.path(), "hole.bin", 4096, 0, b"x", 1024)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("sparse-write cap"),
            "the refusal must name the sparse-write cap, got: {err}"
        );
        // A gap within the cap is still a normal sparse write.
        write_file(base.path(), "ok.bin", 1024, 0, b"x", 1024).unwrap();
        assert_eq!(
            std::fs::metadata(base.path().join("ok.bin")).unwrap().len(),
            1025
        );
    }

    // ── stat_file ───────────────────────────────────────────────────

    #[test]
    fn stat_file_exists() {
        let base = test_base();
        std::fs::write(base.path().join("statme.txt"), b"stat content").unwrap();
        let info = stat_file(base.path(), "statme.txt").unwrap();
        assert_eq!(info.name, "statme.txt");
        assert_eq!(info.file_type, "file");
        assert_eq!(info.size, 12); // "stat content"
        assert_eq!(info.path, "statme.txt");
    }

    #[test]
    fn stat_file_not_found() {
        let base = test_base();
        assert!(stat_file(base.path(), "nope.txt").is_err());
    }

    #[test]
    fn stat_file_via_symlink_reports_target() {
        // validate_path_under canonicalizes (follows the final symlink), so
        // STAT through an in-workspace symlink describes the TARGET — matching
        // read/write semantics. (This is the pre-existing behavior; pinned
        // here so a future change is deliberate.)
        let base = test_base();
        std::fs::write(base.path().join("real"), b"r").unwrap();
        std::os::unix::fs::symlink("real", base.path().join("lnk")).unwrap();
        let info = stat_file(base.path(), "lnk").unwrap();
        assert_eq!(info.file_type, "file");
        assert_eq!(info.name, "real");
        // A directory entry that IS reachable as a path but whose validate
        // resolves elsewhere never leaks: the reported path is the resolved
        // in-base path.
        assert_eq!(info.path, "real");
    }

    // ── list_dir ────────────────────────────────────────────────────

    #[test]
    fn list_dir_basic() {
        let base = test_base();
        std::fs::write(base.path().join("a.txt"), b"a").unwrap();
        std::fs::write(base.path().join("b.txt"), b"b").unwrap();
        let entries = list_dir(base.path(), "", 0, 1024 * 1024).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.txt"));
    }

    #[test]
    fn list_dir_with_depth() {
        let base = test_base();
        std::fs::create_dir(base.path().join("sub")).unwrap();
        std::fs::write(base.path().join("sub/c.txt"), b"c").unwrap();
        let entries = list_dir(base.path(), "", 1, 1024 * 1024).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"sub"));
        assert!(names.contains(&"c.txt"));
    }

    #[test]
    fn list_dir_not_a_directory() {
        let base = test_base();
        std::fs::write(base.path().join("file.txt"), b"f").unwrap();
        assert!(list_dir(base.path(), "file.txt", 0, 1024 * 1024).is_err());
    }

    #[test]
    fn list_dir_budget_truncates_with_marker() {
        // REGRESSION (response bound): a directory larger than the byte
        // budget must stop collecting and end with ONE marker entry whose
        // file_type is "truncated" (size = entries actually returned) — never
        // grow without bound, never truncate silently.
        let base = test_base();
        for i in 0..64 {
            std::fs::write(base.path().join(format!("f{:03}.txt", i)), b"x").unwrap();
        }
        // Budget for ~2 entries under the conservative 6x JSON-escape charge
        // (LIST_ENTRY_FIXED_BYTES backs each entry; the path/name strings are
        // charged at their worst-case escaped size).
        let entries = list_dir(base.path(), "", 0, LIST_ENTRY_FIXED_BYTES * 6).unwrap();
        assert!(
            entries.len() >= 2 && entries.len() <= 3,
            "got {}",
            entries.len()
        );
        let marker = entries.last().unwrap();
        assert_eq!(marker.file_type, "truncated");
        assert_eq!(marker.name, "[truncated]");
        assert_eq!(marker.size as usize, entries.len() - 1);
        // Everything before the marker is a real entry.
        for e in &entries[..entries.len() - 1] {
            assert_ne!(e.file_type, "truncated");
        }
    }

    #[test]
    fn list_dir_generous_budget_no_marker() {
        let base = test_base();
        std::fs::write(base.path().join("a"), b"a").unwrap();
        std::fs::write(base.path().join("b"), b"b").unwrap();
        let entries = list_dir(base.path(), "", 0, 1024 * 1024).unwrap();
        assert!(entries.iter().all(|e| e.file_type != "truncated"));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn list_dir_depth_is_clamped() {
        // u32::MAX from the wire must not reach the recursion unclamped.
        assert_eq!(clamp_list_depth(0), 0);
        assert_eq!(clamp_list_depth(5), 5);
        assert_eq!(clamp_list_depth(u32::MAX), MAX_LIST_DEPTH);
        // Behavioral: a 3-level tree with depth=u32::MAX lists exactly the
        // 3 levels (no error, no runaway).
        let base = test_base();
        std::fs::create_dir_all(base.path().join("d1/d2/d3")).unwrap();
        std::fs::write(base.path().join("d1/d2/d3/leaf"), b"l").unwrap();
        let entries = list_dir(base.path(), "", u32::MAX, 1024 * 1024).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        for want in ["d1", "d2", "d3", "leaf"] {
            assert!(names.contains(&want), "missing {} in {:?}", want, names);
        }
        assert!(entries.iter().all(|e| e.file_type != "truncated"));
    }

    #[test]
    fn list_dir_recursion_stops_when_budget_hit_in_subdir() {
        // Truncation flagged inside a RECURSION level must unwind the whole
        // walk (one marker, not one per directory).
        let base = test_base();
        std::fs::create_dir_all(base.path().join("sub")).unwrap();
        for i in 0..32 {
            std::fs::write(base.path().join(format!("top{:02}", i)), b"x").unwrap();
            std::fs::write(base.path().join(format!("sub/s{:02}", i)), b"x").unwrap();
        }
        // Enough for the top dir's entries but not the subdir's.
        let entries = list_dir(base.path(), "", 1, LIST_ENTRY_FIXED_BYTES * 40).unwrap();
        let markers: Vec<&EntryInfo> = entries
            .iter()
            .filter(|e| e.file_type == "truncated")
            .collect();
        assert_eq!(markers.len(), 1, "exactly one marker");
        assert!(entries.last().unwrap().file_type == "truncated");
    }

    // ── make_dir / remove / rename ──────────────────────────────────

    #[test]
    fn make_dir_creates() {
        let base = test_base();
        make_dir(base.path(), "newdir", 0o755).unwrap();
        assert!(base.path().join("newdir").is_dir());
    }

    #[test]
    fn make_dir_exists_ok() {
        let base = test_base();
        std::fs::create_dir_all(base.path().join("existing")).unwrap();
        make_dir(base.path(), "existing", 0o755).unwrap();
    }

    #[test]
    fn chmod_at_no_follow_never_changes_a_symlink_target() {
        // The make_dir chmod used fchmodat(flags=0), which follows the final
        // component: a tenant racing the freshly created directory into a
        // symlink could chmod an arbitrary file in the WARDEN's namespace.
        let base = test_base();
        let victim = base.path().join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&victim, base.path().join("link")).unwrap();
        let dir = std::fs::File::open(base.path()).unwrap();

        let res = chmod_at_no_follow(
            dir.as_raw_fd(),
            std::ffi::OsStr::new("link"),
            0o777,
        );
        assert!(res.is_err(), "chmod through a planted symlink must be refused");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o700,
            "the symlink target's mode must be untouched"
        );

        // Control: a real directory is chmod'ed normally.
        std::fs::create_dir_all(base.path().join("real")).unwrap();
        chmod_at_no_follow(dir.as_raw_fd(), std::ffi::OsStr::new("real"), 0o750).unwrap();
        assert_eq!(
            std::fs::metadata(base.path().join("real"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
    }

    #[test]
    fn list_recursion_refuses_a_symlinked_child_directory() {
        // The recursion opens each child O_NOFOLLOW through the current
        // directory fd; the old entry.path() string re-resolution could be
        // raced into a symlink and list the warden-namespace target.
        let base = test_base();
        // The link target lives OUTSIDE the listing base (a second temp dir),
        // so enumerating it is unambiguously a containment break.
        let outside = test_base();
        std::fs::write(outside.path().join("secret.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), base.path().join("planted")).unwrap();
        std::fs::create_dir_all(base.path().join("real")).unwrap();
        std::fs::write(base.path().join("real/inner.txt"), b"x").unwrap();

        let dir = std::fs::File::open(base.path()).unwrap();
        assert!(
            open_child_dir_no_follow(&dir, std::ffi::OsStr::new("planted")).is_none(),
            "a symlinked child must never be opened for recursion"
        );
        assert!(
            open_child_dir_no_follow(&dir, std::ffi::OsStr::new("real")).is_some(),
            "a real child directory opens"
        );

        // End to end: the planted link is listed but never entered.
        let entries = list_dir(base.path(), "", 2, 1 << 20).unwrap();
        assert!(entries.iter().any(|e| e.name == "planted"));
        assert!(entries.iter().any(|e| e.name == "inner.txt"));
        assert!(
            !entries.iter().any(|e| e.name == "secret.txt"),
            "the symlink target must never be enumerated"
        );
    }

    #[test]
    fn remove_file() {
        let base = test_base();
        std::fs::write(base.path().join("rmme.txt"), b"rm").unwrap();
        remove_path(base.path(), "rmme.txt", false).unwrap();
        assert!(!base.path().join("rmme.txt").exists());
    }

    #[test]
    fn remove_dir_recursive() {
        let base = test_base();
        std::fs::create_dir(base.path().join("rmdir")).unwrap();
        std::fs::write(base.path().join("rmdir/inner.txt"), b"inner").unwrap();
        remove_path(base.path(), "rmdir", true).unwrap();
        assert!(!base.path().join("rmdir").exists());
    }

    #[test]
    fn remove_missing_is_err() {
        let base = test_base();
        assert!(remove_path(base.path(), "ghost", false).is_err());
    }

    #[test]
    fn rename_file() {
        let base = test_base();
        std::fs::write(base.path().join("old.txt"), b"rename me").unwrap();
        rename_path(base.path(), "old.txt", "new.txt").unwrap();
        assert!(!base.path().join("old.txt").exists());
        assert_eq!(
            std::fs::read(base.path().join("new.txt")).unwrap(),
            b"rename me"
        );
    }

    #[test]
    fn rename_missing_source_is_err() {
        let base = test_base();
        assert!(rename_path(base.path(), "ghost", "dest").is_err());
    }

    // ── iterative bounded rmtree (regression: unbounded recursion) ──────
    //
    // The former recursive remove_dir_all_fd cost one STACK frame per
    // directory level and ran on ~2 MiB blocking-pool threads: a tenant
    // tree a few thousand levels deep (creatable with openat chains —
    // PATH_MAX bounds single-lookup length, not tree depth) overflowed
    // PID 1 → guest kernel panic → wedged VM. The iterative traversal must
    // (a) complete deep trees within a SMALL stack (stack usage is O(1)
    // in tree depth — the structural property), (b) turn over-deep and
    // over-wide trees into NAMED errors, never crashes.

    /// Build a chain of `depth` nested directories under `root`, each named
    /// d<i>, with one leaf file at the bottom.
    fn build_deep_tree(root: &Path, depth: usize) -> PathBuf {
        let mut p = root.to_path_buf();
        for i in 0..depth {
            p.push(format!("d{i}"));
        }
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("leaf.txt"), b"x").unwrap();
        p
    }

    #[test]
    fn remove_deep_tree_is_iterative_not_recursive() {
        // 150 levels — within the production depth cap — must complete on a
        // deliberately tiny 128 KiB stack: with one frame per level the old
        // recursion could not reliably fit, and regardless of frame size the
        // structural claim pinned here is that stack usage no longer scales
        // with tree depth at all.
        let base = test_base();
        build_deep_tree(base.path(), 150);
        let root = base.path().to_path_buf();
        let handle = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                remove_path(&root, "d0", true).map(|_| ()).map_err(|e| e.to_string())
            })
            .expect("spawn small-stack worker");
        match handle.join().expect("worker must not panic") {
            Ok(()) => {}
            Err(msg) => panic!("deep remove failed on a small stack: {msg}"),
        }
        assert!(
            !base.path().join("d0").exists(),
            "the whole chain must be gone"
        );
    }

    #[test]
    fn remove_past_depth_cap_is_a_named_error() {
        // 250 levels > MAX_REMOVE_DEPTH: a named refusal (the tree is
        // partially walked and partially deleted — safe to re-issue), never
        // a crash and never a silent success.
        assert!(MAX_REMOVE_DEPTH < 250, "test must exceed the production cap");
        let base = test_base();
        build_deep_tree(base.path(), 250);
        let err = remove_path(base.path(), "d0", true)
            .expect_err("a tree past the depth cap must be refused");
        assert!(
            format!("{err}").contains("depth"),
            "the refusal must be named, got: {err}"
        );
    }

    #[test]
    fn remove_entry_budget_is_a_named_error() {
        // 20 files with a 10-entry budget: refused by name; re-issuing with
        // the same budget removes the rest in follow-up calls (idempotent
        // continuation is the documented contract).
        let base = test_base();
        let many = base.path().join("many");
        std::fs::create_dir_all(&many).unwrap();
        for i in 0..20 {
            std::fs::write(many.join(format!("f{i:02}.txt")), b"x").unwrap();
        }
        let dir_file = fs::File::open(&many).unwrap();
        let err = remove_dir_all_bounded(&dir_file, Path::new("many"), 200, 10)
            .expect_err("a tree past the entry budget must be refused");
        assert!(
            format!("{err}").contains("budget"),
            "the refusal must be named, got: {err}"
        );

        // Idempotent continuation: repeated bounded calls drain the tree.
        let mut remaining = 0usize;
        loop {
            let dir_file = fs::File::open(&many).unwrap();
            match remove_dir_all_bounded(&dir_file, Path::new("many"), 200, 10) {
                Ok(()) => break,
                Err(e) => {
                    assert!(
                        format!("{e}").contains("budget"),
                        "only the budget refusal may surface mid-drain: {e}"
                    );
                    remaining += 1;
                    assert!(remaining < 10, "drain must converge");
                }
            }
        }
        assert!(
            fs::read_dir(&many).unwrap().count() <= 10,
            "each pass removes exactly its budget"
        );
    }

    #[test]
    fn remove_budget_boundary_is_exact() {
        // Exactly max_entries entries: admitted (the check is >, not >=).
        let base = test_base();
        let many = base.path().join("many");
        std::fs::create_dir_all(&many).unwrap();
        for i in 0..10 {
            std::fs::write(many.join(format!("f{i:02}.txt")), b"x").unwrap();
        }
        let dir_file = fs::File::open(&many).unwrap();
        remove_dir_all_bounded(&dir_file, Path::new("many"), 200, 10)
            .expect("exactly-at-budget removal must succeed");
        assert_eq!(fs::read_dir(&many).unwrap().count(), 0);
    }

    #[test]
    fn remove_wide_tree_post_order_is_correct() {
        // Post-order correctness across nesting: every subdir frame must be
        // fully drained (and rmdir'd) before its parent pops. A mixed
        // width+depth tree exercises both the None-arm rmdir ordering and
        // interleaved file unlinks.
        let base = test_base();
        let top = base.path().join("top");
        for d in 0..5 {
            let dir = top.join(format!("s{d}"));
            for sd in 0..3 {
                std::fs::create_dir_all(dir.join(format!("ss{sd}"))).unwrap();
                std::fs::write(dir.join(format!("ss{sd}/f.txt")), b"x").unwrap();
            }
            std::fs::write(dir.join("g.txt"), b"x").unwrap();
        }
        std::fs::write(top.join("h.txt"), b"x").unwrap();
        remove_path(base.path(), "top", true).expect("mixed tree removal");
        assert!(!top.exists(), "the whole tree must be gone");
    }
}
