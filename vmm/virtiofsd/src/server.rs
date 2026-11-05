// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Modified by Sandswap (c) 2026: root allow-list filtering (FilterList) for
// per-agent virtio-fs isolation, hot-swapped at runtime via vm.set-fs. The
// filter is ALWAYS active — an empty allow-list hides every root entry, and
// there is no unfiltered mode to fall back to (fail-closed by construction).

use super::fs_cache_req_handler::FsCacheReqHandler;
use crate::descriptor_utils::{Reader, Writer};
use crate::filesystem::{
    Context, DirEntry, DirEntry2, DirectoryIterator, Entry, Extensions, FileSystem, FilterEntry,
    GetxattrReply, ListxattrReply, Name, SecContext, SerializableFileSystem, ZeroCopyReader,
    ZeroCopyWriter,
};
use crate::fuse::*;
use crate::passthrough::util::einval;
use crate::{oslib, Error, Result};
use anyhow::anyhow;
use rate_limiter::{BucketReduction, RateLimiter, TokenType};
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{size_of, MaybeUninit};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vm_memory::ByteValued;

use crate::passthrough::stat::statx;
use crate::passthrough::util::openat;

/// A guest can remount (and hit the pre-negotiation version rejection)
/// repeatedly: only the first is an error, the rest are debug. Without this,
/// a hostile guest turns each remount into a host-side log line (and console
/// tax).
static INIT_VERSION_REJECTED: AtomicBool = AtomicBool::new(false);

fn log_init_version_rejection(major: u32, minor: u32) {
    if !INIT_VERSION_REJECTED.swap(true, Ordering::Relaxed) {
        error!(
            "Unsupported fuse protocol version: {}.{} (further rejections are logged at debug)",
            major, minor
        );
    } else {
        debug!("Unsupported fuse protocol version: {}.{}", major, minor);
    }
}

const FUSE_BUFFER_HEADER_SIZE: u32 = 0x1000;
const MAX_BUFFER_SIZE: u32 = 1 << 20;
const DIRENT_PADDING: [u8; 8] = [0; 8];

const CURRENT_DIR_CSTR: &[u8] = b".";
const PARENT_DIR_CSTR: &[u8] = b"..";

/// THE ALLOW-LIST IS A NAMESPACE CONTROL AT THE SHARE ROOT, not just a
/// visibility filter. Only Lookup and the readdir family consult the filter
/// themselves; every other NAME-BASED op would go straight to the host
/// passthrough with the guest-supplied name, so an escaped guest could
/// create/unlink/rename/xattr entries beside the volumes it is allowed to
/// see — and read the errno as a name-existence oracle (the filter's own
/// contract: a non-whitelisted name must be indistinguishable from
/// absent). Exactly one entry is ever exposed at the root, so denying a
/// whole class there cannot break a legitimate guest operation. (Rename
/// additionally checks its SECOND parent in do_rename.)
///
/// This match is EXHAUSTIVE BY DESIGN — no wildcard arm. Every opcode the
/// kernel can send carries an explicit root decision, so adding an
/// `Opcode` variant (upstream merge, protocol bump) breaks compilation
/// until the new op is classified here. The `false` rows are standing
/// allow-decisions, each with its reason; keep them honest when touching
/// this table.
#[inline]
fn root_gate_denies(opcode: Opcode) -> bool {
    match opcode {
        // NAME-carrying ops that reach the host passthrough with a
        // guest-controlled root name: create/unlink/rename/link and the
        // xattr family (read side included — getxattr/listxattr at the
        // root would be name-existence oracles otherwise).
        // BOTH rename opcodes: Rename2 (45) carries the same two parents
        // and reaches do_rename through its own handler — omitting it
        // left "move a sibling's directory OUT of the share root"
        // reachable.
        Opcode::Mkdir
        | Opcode::Mknod
        | Opcode::Create
        // TmpFile (O_TMPFILE) has no NAME operand but CREATES an inode in
        // the parent directory: it belongs to this arm by effect, not by
        // operand. The passthrough does not implement tmpfile() today (the
        // trait default answers ENOSYS), but the gate must not depend on
        // that — the day an implementation lands, an ungated TmpFile at the
        // share root would mint anonymous inodes in the volumes root (host
        // disk consumed by an object no cleanup path can see).
        | Opcode::TmpFile
        | Opcode::Symlink
        | Opcode::Link
        | Opcode::Unlink
        | Opcode::Rmdir
        | Opcode::Rename
        | Opcode::Rename2
        | Opcode::Setxattr
        | Opcode::Getxattr
        | Opcode::Listxattr
        | Opcode::Removexattr
        // Nodeid-scoped but MUTATING the share root itself: chmod/chown/
        // truncate/utimens on the parent of every tenant volume. The standing
        // allow existed for the FUSE kernel's metadata traffic, but the guest
        // is the only client and has no legitimate need to mutate the export
        // root — deny it like the name-carrying mutations. Current
        // deployment DAC (share root 2710, sandvmm not the owner and without
        // CAP_FOWNER) also blocks it; this makes the deny independent of that
        // deployment shape.
        | Opcode::Setattr => true,

        // statfs at the share root returned the REAL host fstatvfs of
        // the volumes filesystem (capacity/usage/file counts) to every guest.
        // Denied at the root like the other root-scoped ops — the guest's own
        // statfs on mounted subdirectories is unaffected.
        Opcode::Statfs => true,

        // Open/Opendir at the share root mint a root fh, the one handle the
        // agent-reference bookkeeping and the reuse tripwire deliberately
        // exclude. The export root is not part of any tenant's tree (the
        // warden's bind uses subdirectory nodeids), so no legitimate caller
        // needs a root handle. Denying the open keeps "no root fh exists" a
        // structural invariant instead of a standing exemption.
        Opcode::Open | Opcode::Opendir => true,

        // NAME-carrying but SELF-FILTERED: Lookup and the readdir family
        // consult `FilterList` themselves (a non-whitelisted root name
        // answers as absent), so pre-denying them here would only hide
        // the one legitimate root entry.
        Opcode::Lookup | Opcode::Readdir | Opcode::Readdirplus => false,

        // No guest-controlled NAME operand: fd/inode-scoped I/O
        // (read/write/fsync/locks/lseek/copy_file_range/fallocate/ioctl),
        // protocol bookkeeping (init/forget/batch-forget/interrupt/
        // destroy/poll/notify-reply), and stat-class metadata that
        // reaches the host by nodeid, not by name.
        // NOTE the standing rows this arm implies — each is a recorded
        // decision, not an oversight, and e2e/share-root-gate.sh
        // re-probes the root-reachable ones: Readlink at the root would read
        // the export root's own (kernel-created) symlink, if any. Setattr is
        // DENIED above, and Open/Opendir are denied above so no root fh can
        // exist for the fd-scoped rows.
        Opcode::Forget
        | Opcode::Getattr
        | Opcode::Readlink
        | Opcode::Read
        | Opcode::Write
        | Opcode::Release
        | Opcode::Fsync
        | Opcode::Flush
        | Opcode::Init
        | Opcode::Releasedir
        | Opcode::Fsyncdir
        | Opcode::Getlk
        | Opcode::Setlk
        | Opcode::Setlkw
        | Opcode::Access
        | Opcode::Interrupt
        | Opcode::Bmap
        | Opcode::Destroy
        | Opcode::Ioctl
        | Opcode::Poll
        | Opcode::NotifyReply
        | Opcode::BatchForget
        | Opcode::Fallocate
        | Opcode::Lseek
        | Opcode::CopyFileRange
        | Opcode::SetupMapping
        | Opcode::RemoveMapping => false,

        // Syncfs is refused EVERYWHERE (see Server::syncfs — the
        // passthrough's implementation is `libc::syncfs(fd)`, filesystem-
        // wide, so even an in-share nodeid forces a host-wide writeback).
        // The root row keeps this decision table honest.
        Opcode::Syncfs => true,
    }
}

struct ZcReader<'a>(Reader<'a>);

/// Fixed metadata for the share root (nodeid 1). The real host directory
/// would leak aggregate tenant state (st_nlink ~ volume count, mtime ~
/// create/delete activity, host uid/gid/mode), and the guest has no
/// legitimate use for it: its chroot is the tenant volume beneath the root.
fn root_synthetic_stat() -> libc::stat64 {
    // SAFETY: stat64 is a plain C struct; zero is a valid initialized value
    // and every field we care about is set explicitly below.
    let mut st: libc::stat64 = unsafe { std::mem::zeroed() };
    st.st_ino = ROOT_ID;
    st.st_mode = libc::S_IFDIR | 0o755;
    st.st_nlink = 2;
    st.st_uid = 0;
    st.st_gid = 0;
    st.st_blksize = 4096;
    st
}

impl<'a> ZeroCopyReader for ZcReader<'a> {
    fn read_to(
        &mut self,
        f: &File,
        count: usize,
        off: u64,
        flags: Option<oslib::WritevFlags>,
    ) -> io::Result<usize> {
        self.0.read_to_at(f, count, off, flags)
    }
}

struct ZcWriter<'a>(Writer<'a>);

impl<'a> ZeroCopyWriter for ZcWriter<'a> {
    fn write_from(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
        self.0.write_from_at(f, count, off)
    }
}

pub fn get_basename_from_path(path: &str) -> Option<&str> {
    let path_obj = Path::new(path);
    path_obj.file_name().and_then(OsStr::to_str)
}

/// The share-root allow-list: only whitelisted basenames resolve at the FUSE
/// root; everything else is denied indistinguishably from a missing file.
///
/// The filter is ALWAYS active — there is no "no filtering" mode. An empty
/// whitelist hides every root entry (the fail-closed CLEAN state), and no
/// configuration can turn filtering off. An earlier revision had an
/// `inactive` state for a whitelist of `None` ("backward-compat: full fs
/// visible"), reachable from any config that omitted `allowed_dirs`; it was
/// removed precisely because a fail-open default has no business on an
/// isolation boundary.
pub struct FilterList {
    root_ino: u64,
    allowed_dirs: HashMap<String, FilterEntry>,
    root_dirents: Vec<DirEntry2>,
    /// EVERY alias used over this filter's lifetime (non-empty generations
    /// only). Keeping just the previous one let A→B→A replay A against a
    /// later export; a late mount from generation A would then resolve
    /// against the new export instead of failing ENOENT. The set is bounded
    /// by the VM's mount generations (10000 by default) at ≤64 bytes each.
    seen_aliases: HashSet<String>,
}

/// Wire-level alias rules, shared by every caller (raw frame, HTTP, config).
/// The alias is a single path component presented at the FUSE root and later
/// opened by the warden as `/mnt/volumes/<alias>`; it must never be able to
/// name a parent, absolute path, or control byte.
pub fn validate_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 64
        && alias != "."
        && alias != ".."
        && alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl FilterList {
    // Init filter base whitelist. An empty (or empty-after-normalization)
    // whitelist hides every root entry.
    fn init(
        &mut self,
        whitelist: &[String],
        alias: Option<&str>,
        cancel: Option<&AtomicBool>,
    ) -> Result<()> {
        let alias = alias.filter(|a| !a.is_empty());
        let mut dic: HashMap<String, FilterEntry> = HashMap::new();
        let mut dirents = Vec::<DirEntry2>::new();
        let mut index = 2;

        dirents.push(DirEntry2 {
            ino: self.root_ino,
            offset: 1,
            type_: libc::DT_DIR as u32,
            name: ".".to_string(),
        });
        dirents.push(DirEntry2 {
            // Synthetic inode for ".." (the shared root has no real parent on
            // the host side); the guest kernel does not use the parent's ino
            // for anything but display on a FUSE root mount.
            ino: 1001,
            offset: 2,
            type_: libc::DT_DIR as u32,
            name: "..".to_string(),
        });
        // dir should be absolute path.
        //
        // The new whitelist is fully validated (openat + statx per entry)
        // into locals BEFORE it replaces the live one: a mid-list failure
        // must leave the previous whitelist fully in place
        // (old `allowed_dirs`/`root_dirents` are only replaced by the
        // assignments below), never a half-updated mix.
        // Sort and Dedup dirs.
        let mut dirs = whitelist.to_vec();
        dirs.sort();
        dirs.dedup();
        let entry_count = dirs.iter().filter(|d| !d.is_empty()).count();

        // The alias is this generation's capability name: exactly one
        // non-empty export requires one valid alias, and a clear carries
        // none. An alias may never repeat the previous non-empty
        // generation's: a late mount from that generation would then resolve
        // against the new export instead of failing ENOENT.
        if entry_count > 1 {
            return Err(Error::InvalidFilter(anyhow!(
                "allowed_dirs has {entry_count} entries — one alias names exactly one export; multi-entry lists are refused"
            )));
        }
        match (entry_count, alias) {
            (1, Some(a)) => {
                if !validate_alias(a) {
                    return Err(Error::InvalidFilter(anyhow!(
                        "invalid export alias {a:?}: must be one component of [A-Za-z0-9._-], 1..=64 bytes, not . or .."
                    )));
                }
                if self.seen_aliases.contains(a) {
                    return Err(Error::InvalidFilter(anyhow!(
                        "export alias {a:?} was already used by an earlier generation — a fresh alias is required for every set-fs"
                    )));
                }
            }
            (1, None) => {
                return Err(Error::InvalidFilter(anyhow!(
                    "a non-empty allowed_dirs requires an export alias (this generation's guest-visible root name)"
                )));
            }
            (0, Some(_)) => {
                return Err(Error::InvalidFilter(anyhow!(
                    "the clear (empty allowed_dirs) request must not carry an export alias"
                )));
            }
            _ => {}
        }

        for dir in dirs {
            if dir.is_empty() {
                continue;
            }
            // A path with no basename component (a bare "/" — the config
            // gate upstream already refuses it) cannot be presented under an
            // alias: skip it rather than panic the swap.
            if get_basename_from_path(&dir).is_none() {
                warn!("Invalid path name: {:?}", dir);
                continue;
            }
            // Device-boundary `..` refusal, the last line in front of
            // the RESOLVER: an entry with a parent component is refused with a
            // named error even when the config gate upstream was bypassed.
            // This is where it matters — `openat(AT_FDCWD, dir, O_NOFOLLOW)`
            // below follows intermediate components, so `/share/../..` would
            // otherwise be exported as if it were the share's child. Refusing
            // aborts the whole swap, leaving the previous (fail-closed)
            // whitelist live rather than a partially widened one.
            if dir.split('/').any(|c| c == "..") {
                return Err(Error::InvalidFilter(anyhow!(
                    "allowed_dirs entry {:?} contains a '..' component — refused: resolving it on the host would escape the share root",
                    dir
                )));
            }
            // Two host dirs with the same basename are the same directory
            // reached twice (aliases cannot collide by construction); keep the
            // first and warn — this cannot happen in sandswap's single-parent
            // layout, but the API must not silently double-present one dir.
            if dic.values().any(|(kept, _, _)| kept == &dir) {
                warn!(
                    "Duplicate allowed_dirs entry {:?} (same host dir already presented) — dropping",
                    dir
                );
                continue;
            }
            let path_fd = openat(
                &libc::AT_FDCWD,
                &dir,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
            .map_err(|e| {
                Error::InvalidFilter(anyhow!("Failed to openat file {:?}: {:?}", dir, e))
            })?;
            // PIN the authorized object: every later root lookup dups THIS
            // descriptor instead of re-resolving `dir`, so a component
            // swapped between generation setup and the lookup cannot change
            // what the guest sees. OwnedFd also closes the descriptor on
            // every early return below and when the generation is replaced.
            let pinned: std::os::fd::OwnedFd = path_fd.into();
            let st = statx(&pinned, None).map_err(|e| {
                Error::InvalidFilter(anyhow!("Failed to statx file {:?}: {:?}", dir, e))
            })?;
            // only DIRECTORIES may enter the export map — a
            // non-directory entry was previously accepted and announced to
            // the guest as DT_DIR (a broken root entry; the passthrough
            // would then serve getattr on a file under a directory guise).
            if st.st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                warn!("Invalid path (not a directory): {:?}", dir);
                continue;
            }
            let ino = st.st.st_ino;
            // ALIAS PRESENTATION: the guest-visible name is this generation's
            // capability alias, never the host directory's basename and never
            // a constant. The real volume name is a secret (unguessability is
            // the tenant-isolation control against a storage-group reader).
            // The alias binds the filter generation to the warden's mount op:
            // after the next set-fs the old name is gone from the root, so a
            // late mount for it fails ENOENT before any bind or exec.
            let alias = alias.expect("validated above: a non-empty export carries an alias");
            dic.insert(alias.to_string(), (dir.clone(), Arc::new(pinned), st));
            index += 1;
            dirents.push(DirEntry2 {
                ino,
                offset: index,
                type_: libc::DT_DIR as u32,
                name: alias.to_string(),
            });
        }

        // The caller's bounded wait can expire while the validation above is
        // stalled on the backing store (openat/statx per entry). Re-check the
        // cancel flag AFTER the build and IMMEDIATELY before the swap: a
        // late-applied allow-list would export a volume the control plane
        // already reported as not attached (and may have placed elsewhere).
        // The previous whitelist stays fully in place on this path.
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(Error::InvalidFilter(anyhow!(
                "filter update cancelled by the caller before the swap — previous filter kept"
            )));
        }
        self.allowed_dirs = dic;
        self.root_dirents = dirents;
        if entry_count == 1 {
            if let Some(a) = alias {
                self.seen_aliases.insert(a.to_string());
            }
        }

        Ok(())
    }

    pub fn new(root_ino: u64, whitelist: &[String], alias: Option<&str>) -> Result<FilterList> {
        let mut filter = FilterList {
            root_ino,
            allowed_dirs: HashMap::new(),
            root_dirents: Vec::<DirEntry2>::new(),
            seen_aliases: HashSet::new(),
        };

        filter.init(whitelist, alias, None)?;

        Ok(filter)
    }

    // Update the filter with a new whitelist (the vm.set-fs hot swap). On
    // error the previous whitelist stays fully in place. `cancel` is the
    // caller's timeout flag: checked once before the expensive build and
    // again immediately before the swap.
    pub fn update(
        &mut self,
        whitelist: &[String],
        alias: Option<&str>,
        cancel: Option<&AtomicBool>,
    ) -> Result<()> {
        self.init(whitelist, alias, cancel)?;

        Ok(())
    }

    // return allow dire entry.
    pub fn get_allow_dir(&self, key: &str) -> Result<FilterEntry> {
        self.allowed_dirs.get(key).cloned().ok_or(Error::DisAllowed)
    }

    /// Live allow-list entries — the set-fs tripwire's "was there a previous
    /// export" question. A fresh VM's empty list means no tenant has ever
    /// been attached, so a first attach must not be gated on references.
    pub fn entry_count(&self) -> usize {
        self.allowed_dirs.len()
    }

    // return root dirent.
    pub fn get_root_dirents(&self) -> &Vec<DirEntry2> {
        &self.root_dirents
    }

    /// Root-lookup gate decision for a guest-supplied name (a single path
    /// component; file names are arbitrary byte strings, so possibly not
    /// valid UTF-8). Non-UTF-8 names can never match the UTF-8 allow-list
    /// keys and are denied instead of panicking on `to_str()` — a
    /// guest-triggerable panic here would poison `root_filter` and take
    /// down the whole VMM.
    pub fn root_lookup(&self, name: &CStr) -> RootLookup {
        match name.to_str() {
            Ok(name_str) => match self.get_allow_dir(name_str) {
                Ok(entry) => RootLookup::Allowed(entry),
                Err(_) => RootLookup::Denied,
            },
            Err(_) => RootLookup::Denied,
        }
    }
}

/// Result of gating a root-level FUSE lookup against the allow-list.
pub enum RootLookup {
    /// The name is not whitelisted (or not valid UTF-8): the caller must
    /// reply ENOENT — indistinguishable from a non-existent entry, so the
    /// allow-list leaks no existence oracle.
    Denied,
    /// The name is whitelisted: the passthrough lookup must use this
    /// (host path, stat) pair.
    Allowed(FilterEntry),
}

impl std::fmt::Debug for RootLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The stat payload has no Debug impl; the path is what tests and
        // logs care about.
        match self {
            RootLookup::Denied => write!(f, "Denied"),
            RootLookup::Allowed((dir, _, _)) => write!(f, "Allowed({:?})", dir),
        }
    }
}

/// Reply ENOENT for a name that failed `validate_name`, instead of letting the
/// error propagate (an error out of `handle_message` makes the device layer
/// overwrite the buffer with a bare -EIO, losing the distinguishable answer).
/// Usage is always at the top of a handler, before `w` is consumed.
macro_rules! name_or_enoent {
    ($res:expr, $hdr:expr, $w:expr) => {
        match $res {
            Ok(n) => n,
            Err(_) => {
                return reply_error(io::Error::from_raw_os_error(libc::ENOENT), $hdr.unique, $w)
            }
        }
    };
}


pub struct Server<F: FileSystem + Sync> {
    fs: F,
    options: AtomicU64,
    root_filter: Arc<Mutex<FilterList>>,
    /// A FUSE_DESTROY is terminal for the export: the device is immutable and
    /// there is nothing to re-initialize. Once set, a later INIT is refused and
    /// the owner-visible hook (the VMM exit event) has fired.
    destroyed: AtomicBool,
    on_destroy: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl<F: FileSystem + Sync> Server<F> {
    /// `whitelist` is the share-root allow-list. It is a SLICE, not an
    /// Option: there is deliberately no way to construct an unfiltered
    /// server — callers normalize "absent" to the empty (deny-all) list.
    pub fn new(fs: F, whitelist: &[String], alias: Option<&str>) -> Result<Server<F>> {
        // The filter's root nodeid is the FUSE root (1), never the backing
        // filesystem's st_ino: the "." dirent is guest-visible, and the host
        // inode number is an unnecessary leak (root_synthetic_stat already
        // reports ROOT_ID).
        let filter = FilterList::new(crate::fuse::ROOT_ID, whitelist, alias)?;

        Ok(Server {
            fs,
            options: AtomicU64::new(FsOptions::empty().bits()),
            root_filter: Arc::new(Mutex::new(filter)),
            destroyed: AtomicBool::new(false),
            on_destroy: None,
        })
    }

    /// Install the terminal-destroy notification (the VMM's exit event).
    /// Must be called before the server is shared.
    pub fn set_destroy_hook(&mut self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.on_destroy = Some(hook);
    }

    /// Swap the allow-list without a cancellation source (tests / callers
    /// that are not on the bounded set-fs path).
    pub fn update_filter(&self, whitelist: &[String], alias: Option<&str>) -> Result<()> {
        self.update_filter_cancellable(whitelist, alias, None)
    }

    /// Swap the allow-list, honouring the caller's timeout flag. `cancel` is
    /// checked before the expensive build and again inside FilterList::init
    /// immediately before the maps are installed, so a set-fs whose control
    /// plane already gave up cannot export a volume late.
    pub fn update_filter_cancellable(
        &self,
        whitelist: &[String],
        alias: Option<&str>,
        cancel: Option<&AtomicBool>,
    ) -> Result<()> {
        // Hold the filter lock across the tripwire, the swap AND the revoke.
        //
        // Root lookups hold this same lock across their allow-list snapshot
        // AND the inode insertion that snapshot drives (see `lookup`). Without
        // the shared scope, a lookup could read the OLD list, be descheduled,
        // and then insert the previous tenant's inode AFTER
        // revoke_agent_state bumped the inode epoch — resurrecting a
        // cross-tenant by-nodeid primitive on a reused VM. With both sides
        // under one lock the only two interleavings are safe: before the swap
        // (inserted inode is cleared by the revoke) or after it (new list).
        let mut filter = self.root_filter.as_ref().lock().unwrap();

        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(Error::InvalidFilter(anyhow!(
                "filter update cancelled by the caller — previous filter kept"
            )));
        }

        // REUSE TRIPWIRE (fail-closed, inside the same guard so the counts
        // describe exactly the export the swap is about to replace): when the
        // LIVE list exported anything, the guest must hold NOTHING into that
        // export at swap time — nonzero open handles or un-FORGOTTEN inode
        // references mean the previous tenant is still present (a lying
        // unmount reply is the canonical case: a process alive inside the
        // volume pins its root/cwd/files as dentries, and a skipped umount
        // pins the bind's source). Refuse WITHOUT swapping: the caller
        // destroys the VM (the only sound action when the warden's release
        // claim disagrees with the device's own observation). The empty-list
        // exemption is the first attach on a fresh VM, where no previous
        // export exists and boot-time probing references are legitimate.
        if filter.entry_count() > 0 {
            let (handles, inode_refs) = self.fs.agent_reference_count();
            if handles > 0 || inode_refs > 0 {
                return Err(Error::PreviousTenantRefs { handles, inode_refs });
            }
        }

        filter.update(whitelist, alias, cancel)?;

        // the swap is only the ROOT-namespace half. Inode-scoped ops
        // never consult the filter, so the previous agent's inodes and open
        // handles must be revoked atomically with the new list going live —
        // otherwise a kernel-level implant from the pre-swap session keeps a
        // cross-tenant read/write primitive by nodeid on a reused VM. The
        // revoke deliberately spares the share root (ROOT_ID): the kernel's
        // root reference lives for the whole /mnt/volumes mount, and there is
        // no per-switch FUSE_INIT to rebuild it (see revoke_agent_state).
        self.fs.revoke_agent_state();

        Ok(())
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn handle_message<T: FsCacheReqHandler>(
        &self,
        mut r: Reader,
        w: Writer,
        vu_req: Option<&mut T>,
        rl: &mut Option<RateLimiter>,
        rlret: &mut BucketReduction,
        rltyp: &mut TokenType,
    ) -> Result<usize> {
        let in_header: InHeader = r.read_obj().map_err(Error::DecodeMessage)?;

        if in_header.len > (MAX_BUFFER_SIZE + FUSE_BUFFER_HEADER_SIZE) {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        if let Ok(opcode) = Opcode::try_from(in_header.opcode) {
            debug!(
                "Received request: opcode={:?} ({}), inode={}, unique={}, pid={}",
                opcode, in_header.opcode, in_header.nodeid, in_header.unique, in_header.pid
            );
            // THE ALLOW-LIST IS A NAMESPACE CONTROL AT THE SHARE ROOT, not
            // just a visibility filter — every opcode's root decision lives
            // in `root_gate_denies` (exhaustive, no wildcard), so a new
            // opcode cannot slip past the gate unclassified.
            if in_header.nodeid == ROOT_ID && root_gate_denies(opcode) {
                return reply_hidden(in_header.unique, w);
            }

            match opcode {
                Opcode::Lookup => self.lookup(in_header, r, w),
                Opcode::Forget => self.forget(in_header, r), // No reply.
                Opcode::Getattr => self.getattr(in_header, r, w),
                Opcode::Setattr => self.setattr(in_header, r, w),
                Opcode::Readlink => self.readlink(in_header, w),
                Opcode::Symlink => self.symlink(in_header, r, w),
                Opcode::Mknod => self.mknod(in_header, r, w),
                Opcode::Mkdir => self.mkdir(in_header, r, w),
                Opcode::Unlink => self.unlink(in_header, r, w),
                Opcode::Rmdir => self.rmdir(in_header, r, w),
                Opcode::Rename => self.rename(in_header, r, w),
                Opcode::Link => self.link(in_header, r, w),
                Opcode::Open => self.open(in_header, r, w),
                Opcode::Read => self.read(in_header, r, w, rl, rlret, rltyp),
                Opcode::Write => self.write(in_header, r, w),
                Opcode::Statfs => self.statfs(in_header, w),
                Opcode::Release => self.release(in_header, r, w),
                Opcode::Fsync => self.fsync(in_header, r, w),
                Opcode::Setxattr => self.setxattr(in_header, r, w),
                Opcode::Getxattr => self.getxattr(in_header, r, w),
                Opcode::Listxattr => self.listxattr(in_header, r, w),
                Opcode::Removexattr => self.removexattr(in_header, r, w),
                Opcode::Flush => self.flush(in_header, r, w),
                Opcode::Init => self.init(in_header, r, w),
                Opcode::Opendir => self.opendir(in_header, r, w),
                Opcode::Readdir => self.readdir(in_header, r, w),
                Opcode::Releasedir => self.releasedir(in_header, r, w),
                Opcode::Fsyncdir => self.fsyncdir(in_header, r, w),
                Opcode::Getlk => self.getlk(in_header, r, w),
                Opcode::Setlk => self.setlk(in_header, r, w),
                Opcode::Setlkw => self.setlkw(in_header, r, w),
                Opcode::Access => self.access(in_header, r, w),
                Opcode::Create => self.create(in_header, r, w),
                Opcode::Interrupt => Ok(self.interrupt(in_header)),
                Opcode::Bmap => self.bmap(in_header, r, w),
                Opcode::Destroy => Ok(self.destroy()),
                Opcode::Ioctl => self.ioctl(in_header, r, w),
                Opcode::Poll => self.poll(in_header, r, w),
                Opcode::NotifyReply => self.notify_reply(in_header, r, w),
                Opcode::BatchForget => self.batch_forget(in_header, r, w),
                Opcode::Fallocate => self.fallocate(in_header, r, w),
                Opcode::Readdirplus => self.readdirplus(in_header, r, w),
                Opcode::Rename2 => self.rename2(in_header, r, w),
                Opcode::Lseek => self.lseek(in_header, r, w),
                Opcode::CopyFileRange => self.copyfilerange(in_header, r, w),
                Opcode::SetupMapping => self.setupmapping(in_header, r, w, vu_req),
                Opcode::RemoveMapping => self.removemapping(in_header, r, w, vu_req),
                Opcode::Syncfs => self.syncfs(in_header, w),
                Opcode::TmpFile => self.tmpfile(in_header, r, w),
            }
        } else {
            debug!(
                "Received unknown request: opcode={}, inode={}",
                in_header.opcode, in_header.nodeid
            );
            reply_error(
                io::Error::from_raw_os_error(libc::ENOSYS),
                in_header.unique,
                w,
            )
        }
    }

    fn setupmapping<T: FsCacheReqHandler>(
        &self,
        in_header: InHeader,
        mut r: Reader,
        w: Writer,
        vu_req: Option<&mut T>,
    ) -> Result<usize> {
        if let Some(req) = vu_req {
            let SetupmappingIn {
                fh,
                foffset,
                len,
                flags,
                moffset,
            } = r.read_obj().map_err(Error::DecodeMessage)?;

            match self.fs.setupmapping(
                Context::from(in_header),
                in_header.nodeid.into(),
                fh.into(),
                foffset,
                len,
                flags,
                moffset,
                req,
            ) {
                Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
                Err(e) => reply_error(e, in_header.unique, w),
            }
        } else {
            reply_error(
                io::Error::from_raw_os_error(libc::EINVAL),
                in_header.unique,
                w,
            )
        }
    }

    fn removemapping<T: FsCacheReqHandler>(
        &self,
        in_header: InHeader,
        mut r: Reader,
        w: Writer,
        vu_req: Option<&mut T>,
    ) -> Result<usize> {
        if let Some(req) = vu_req {
            let RemovemappingIn { count } = r.read_obj().map_err(Error::DecodeMessage)?;

            if let Some(size) = (count as usize).checked_mul(size_of::<RemovemappingOne>()) {
                if size > MAX_BUFFER_SIZE as usize {
                    return reply_error(
                        io::Error::from_raw_os_error(libc::ENOMEM),
                        in_header.unique,
                        w,
                    );
                }
            } else {
                return reply_error(
                    io::Error::from_raw_os_error(libc::EOVERFLOW),
                    in_header.unique,
                    w,
                );
            }

            let mut requests = Vec::with_capacity(count as usize);
            for _ in 0..count {
                requests.push(
                    r.read_obj::<RemovemappingOne>()
                        .map_err(Error::DecodeMessage)?,
                );
            }

            match self
                .fs
                .removemapping(Context::from(in_header), requests, req)
            {
                Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
                Err(e) => reply_error(e, in_header.unique, w),
            }
        } else {
            reply_error(
                io::Error::from_raw_os_error(libc::EINVAL),
                in_header.unique,
                w,
            )
        }
    }

    fn lookup(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0u8; namelen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        let name = name_or_enoent!(Name::parse(buf.as_ref()), in_header, w);

        let par_id = in_header.nodeid;
        let mut f_info = None;
        // HOLD the filter lock across fs.lookup: the allow-list
        // snapshot above and the inode insertion below must be atomic against
        // the vm.set-fs swap+revoke, which takes this same lock (see
        // update_filter). Dropping it between the snapshot and the lookup is
        // the epoch race: the lookup would capture the post-revoke epoch and
        // re-insert the OLD tenant's directory after the clear.
        let _filter_guard = if par_id == ROOT_ID {
            let filter = self.root_filter.as_ref().lock().unwrap();
            match filter.root_lookup(&name) {
                RootLookup::Denied => {
                    return reply_hidden(in_header.unique, w);
                }
                RootLookup::Allowed(entry) => f_info = Some(entry),
            }
            Some(filter)
        } else {
            None
        };

        match self.fs.lookup(
            Context::from(in_header),
            in_header.nodeid.into(),
            &name,
            f_info,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn forget(&self, in_header: InHeader, mut r: Reader) -> Result<usize> {
        let ForgetIn { nlookup } = r.read_obj().map_err(Error::DecodeMessage)?;

        // The share root is the persistent transport anchor for the VM's
        // /mnt/volumes mount (see revoke_agent_state). A guest-forged
        // FORGET(ROOT_ID, huge) evicts it and wedges every later path walk —
        // including the NEXT tenant's mount — with EBADF. A legitimate
        // kernel never forgets a mount root.
        if in_header.nodeid == ROOT_ID {
            return Ok(0);
        }

        self.fs
            .forget(Context::from(in_header), in_header.nodeid.into(), nlookup);

        // There is no reply for forget messages.
        Ok(0)
    }

    fn getattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let GetattrIn { flags, fh, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        let handle = if (flags & GETATTR_FH) != 0 {
            Some(fh.into())
        } else {
            None
        };

        // The share root's REAL metadata is host state: st_nlink tracks the
        // volume count, mtime tracks tenant create/delete activity, uid/mode
        // reveal the host layout. The guest never needs it (its chroot is the
        // tenant volume, not the share root), so answer with a fixed synthetic
        // directory attr. This is the only root-scoped op that returns more
        // than existence; the mutating/name-carrying classes are already
        // denied by root_gate_denies.
        if in_header.nodeid == ROOT_ID {
            let st = root_synthetic_stat();
            let out = AttrOut {
                attr_valid: 1,
                attr_valid_nsec: 0,
                dummy: 0,
                attr: st.into(),
            };
            return reply_ok(Some(out), None, in_header.unique, w);
        }

        match self
            .fs
            .getattr(Context::from(in_header), in_header.nodeid.into(), handle)
        {
            Ok((st, timeout)) => {
                let out = AttrOut {
                    attr_valid: timeout.as_secs(),
                    attr_valid_nsec: timeout.subsec_nanos(),
                    dummy: 0,
                    attr: st.into(),
                };
                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn setattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let setattr_in: SetattrIn = r.read_obj().map_err(Error::DecodeMessage)?;

        let handle = if setattr_in.valid & FATTR_FH != 0 {
            Some(setattr_in.fh.into())
        } else {
            None
        };

        let valid = SetattrValid::from_bits_truncate(setattr_in.valid);

        let st: libc::stat64 = setattr_in.into();

        match self.fs.setattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            st,
            handle,
            valid,
        ) {
            Ok((st, timeout)) => {
                let out = AttrOut {
                    attr_valid: timeout.as_secs(),
                    attr_valid_nsec: timeout.subsec_nanos(),
                    dummy: 0,
                    attr: st.into(),
                };
                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn readlink(&self, in_header: InHeader, w: Writer) -> Result<usize> {
        // The share root is a directory, never a symlink. Reading the host
        // root's own (kernel-created) link would expose host state; answer
        // ENOENT like any other non-link.
        if in_header.nodeid == ROOT_ID {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOENT),
                in_header.unique,
                w,
            );
        }
        match self
            .fs
            .readlink(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(linkname) => {
                // We need to disambiguate the option type here even though it is `None`.
                reply_ok(None::<u8>, Some(&linkname), in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn symlink(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        // Unfortunately the name and linkname are encoded one after another and
        // separated by a nul character.
        let len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        let mut components = buf.split_inclusive(|c| *c == b'\0');

        let name = components.next().ok_or(Error::MissingParameter)?;
        let linkname = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len() + linkname.len(), buf.as_slice())?;

        match self.fs.symlink(
            Context::from(in_header),
            // The TARGET may be any path (a symlink legitimately points
            // anywhere inside the agent's view); only the NAME must be one
            // component — see `symlink_target` for why the target is exempt.
            symlink_target(linkname)?,
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(name), in_header, w),
            extensions,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn mknod(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let MknodIn {
            mode, rdev, umask, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let remaining_len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<MknodIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; remaining_len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;
        let mut components = buf.split_inclusive(|c| *c == b'\0');
        let name = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len(), buf.as_slice())?;

        match self.fs.mknod(
            Context::from(in_header),
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(name), in_header, w),
            mode,
            rdev,
            umask,
            extensions,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn mkdir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let MkdirIn { mode, umask } = r.read_obj().map_err(Error::DecodeMessage)?;

        let remaining_len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<MkdirIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; remaining_len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;
        let mut components = buf.split_inclusive(|c| *c == b'\0');
        let name = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len(), buf.as_slice())?;

        match self.fs.mkdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(name), in_header, w),
            mode,
            umask,
            extensions,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn unlink(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.unlink(
            Context::from(in_header),
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(&name), in_header, w),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn rmdir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.rmdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(&name), in_header, w),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn do_rename(
        &self,
        in_header: InHeader,
        msg_size: usize,
        newdir: u64,
        flags: u32,
        mut r: Reader,
        w: Writer,
    ) -> Result<usize> {
        let buflen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(msg_size))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; buflen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        // We want to include the '\0' byte in the first slice.
        let split_pos = buf
            .iter()
            .position(|c| *c == b'\0')
            .map(|p| p + 1)
            .ok_or(Error::MissingParameter)?;

        let (oldname, newname) = buf.split_at(split_pos);

        // Rename carries TWO parents: the header's nodeid (old parent) is
        // gated at the dispatch site, the body's newdir is gated here — a
        // rename INTO the share root is the same namespace violation.
        if newdir == ROOT_ID {
            return reply_hidden(in_header.unique, w);
        }

        match self.fs.rename(
            Context::from(in_header),
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(oldname), in_header, w),
            newdir.into(),
            &name_or_enoent!(Name::parse(newname), in_header, w),
            flags,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn rename(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let RenameIn { newdir } = r.read_obj().map_err(Error::DecodeMessage)?;

        self.do_rename(in_header, size_of::<RenameIn>(), newdir, 0, r, w)
    }

    fn rename2(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let Rename2In { newdir, flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        let flags =
            flags & (libc::RENAME_EXCHANGE | libc::RENAME_NOREPLACE | libc::RENAME_WHITEOUT);

        self.do_rename(in_header, size_of::<Rename2In>(), newdir, flags, r, w)
    }

    fn link(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let LinkIn { oldnodeid } = r.read_obj().map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<LinkIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.link(
            Context::from(in_header),
            oldnodeid.into(),
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(&name), in_header, w),
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn open(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let OpenIn {
            flags, open_flags, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let kill_priv = open_flags & OPEN_KILL_SUIDGID != 0;

        match self.fs.open(
            Context::from(in_header),
            in_header.nodeid.into(),
            kill_priv,
            flags,
        ) {
            Ok((handle, opts)) => {
                let out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn read(
        &self,
        in_header: InHeader,
        mut r: Reader,
        mut w: Writer,
        rl: &mut Option<RateLimiter>,
        rlret: &mut BucketReduction,
        rltyp: &mut TokenType,
    ) -> Result<usize> {
        let ReadIn {
            fh,
            offset,
            size,
            read_flags,
            lock_owner,
            flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        // The read length is guest-supplied; the advertised FUSE max_read is
        // MAX_BUFFER_SIZE, so a larger request is a protocol violation. Cap
        // it here like write/getxattr do instead of letting the descriptor
        // capacity be the only bound.
        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        if let Some(rate_limiter) = rl {
            // If limiter.consume() fails it means there is no more TokenType::Ops
            // budget and rate limiting is in effect.
            *rlret = rate_limiter.consume(1, TokenType::Ops);
            match rlret {
                BucketReduction::Success => {}
                _ => {
                    *rltyp = TokenType::Ops;
                    return Ok(0);
                }
            }

            *rlret = rate_limiter.consume(size as u64, TokenType::Bytes);
            match rlret {
                BucketReduction::Failure => {
                    rate_limiter.manual_replenish(1, TokenType::Ops);
                    *rltyp = TokenType::Bytes;
                    return Ok(0);
                }
                _ => {}
            }
        }

        let owner = if read_flags & READ_LOCKOWNER != 0 {
            Some(lock_owner)
        } else {
            None
        };

        // Split the writer into 2 pieces: one for the `OutHeader` and the rest for the data.
        //
        // a compromised guest kernel can post a chain whose writable
        // region is too short for the reply header, or absent entirely (read
        // has no availability precondition). The split must answer ENOMEM —
        // a panic here killed the server thread and, through the thread
        // helper's exit event, the whole VMM (every VM on the node).
        let data_writer = match w.split_at(size_of::<OutHeader>()) {
            Ok(region) => ZcWriter(region),
            Err(_) => {
                return reply_error(
                    io::Error::from_raw_os_error(libc::ENOMEM),
                    in_header.unique,
                    w,
                );
            }
        };

        match self.fs.read(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            data_writer,
            size,
            offset,
            owner,
            flags,
        ) {
            Ok(count) => {
                // Don't use `reply_ok` because we need to set a custom size length for the
                // header.
                let out = OutHeader {
                    len: (size_of::<OutHeader>() + count) as u32,
                    error: 0,
                    unique: in_header.unique,
                };

                debug!("Replying OK, header: {:?}", out);
                w.write_all(out.as_slice()).map_err(Error::EncodeMessage)?;
                Ok(out.len as usize)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn write(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let WriteIn {
            fh,
            offset,
            size,
            write_flags,
            lock_owner,
            flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let owner = if write_flags & WRITE_LOCKOWNER != 0 {
            Some(lock_owner)
        } else {
            None
        };

        let delayed_write = write_flags & WRITE_CACHE != 0;
        let kill_priv = write_flags & WRITE_KILL_PRIV != 0;

        let data_reader = ZcReader(r);

        match self.fs.write(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            data_reader,
            size,
            offset,
            owner,
            delayed_write,
            kill_priv,
            flags,
        ) {
            Ok(count) => {
                let out = WriteOut {
                    size: count as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn statfs(&self, in_header: InHeader, w: Writer) -> Result<usize> {
        match self
            .fs
            .statfs(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(st) => reply_ok(Some(Kstatfs::from(st)), None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn release(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let ReleaseIn {
            fh,
            flags,
            release_flags,
            lock_owner,
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let flush = release_flags & RELEASE_FLUSH != 0;
        let flock_release = release_flags & RELEASE_FLOCK_UNLOCK != 0;
        let lock_owner = if flush || flock_release {
            Some(lock_owner)
        } else {
            None
        };

        match self.fs.release(
            Context::from(in_header),
            in_header.nodeid.into(),
            flags,
            fh.into(),
            flush,
            flock_release,
            lock_owner,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn fsync(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FsyncIn {
            fh, fsync_flags, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;
        let datasync = fsync_flags & 0x1 != 0;

        match self.fs.fsync(
            Context::from(in_header),
            in_header.nodeid.into(),
            datasync,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn setxattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));
        let (
            SetxattrIn {
                size,
                flags,
                setxattr_flags,
                ..
            },
            setxattrin_size,
        ) = if options.contains(FsOptions::SETXATTR_EXT) {
            (
                r.read_obj().map_err(Error::DecodeMessage)?,
                size_of::<SetxattrIn>(),
            )
        } else {
            let SetxattrInCompat { size, flags } = r.read_obj().map_err(Error::DecodeMessage)?;
            (
                SetxattrIn {
                    size,
                    flags,
                    setxattr_flags: 0,
                    padding: 0,
                },
                size_of::<SetxattrInCompat>(),
            )
        };

        // The name and value and encoded one after another and separated by a '\0' character.
        let len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(setxattrin_size))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        // We want to include the '\0' byte in the first slice.
        let split_pos = buf
            .iter()
            .position(|c| *c == b'\0')
            .map(|p| p + 1)
            .ok_or(Error::MissingParameter)?;

        let (name, value) = buf.split_at(split_pos);

        if size != value.len() as u32 {
            return Err(Error::InvalidXattrSize((size, value.len())));
        }

        match self.fs.setxattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(name), in_header, w),
            value,
            flags,
            SetxattrFlags::from_bits_truncate(setxattr_flags),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn getxattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let GetxattrIn { size, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<GetxattrIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        match self.fs.getxattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(&name), in_header, w),
            size,
        ) {
            Ok(GetxattrReply::Value(val)) => reply_ok(None::<u8>, Some(&val), in_header.unique, w),
            Ok(GetxattrReply::Count(count)) => {
                let out = GetxattrOut {
                    size: count,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn listxattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let GetxattrIn { size, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        match self
            .fs
            .listxattr(Context::from(in_header), in_header.nodeid.into(), size)
        {
            Ok(ListxattrReply::Names(val)) => reply_ok(None::<u8>, Some(&val), in_header.unique, w),
            Ok(ListxattrReply::Count(count)) => {
                let out = GetxattrOut {
                    size: count,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn removexattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0; namelen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        let name = name_or_enoent!(Name::parse(&buf), in_header, w);

        match self
            .fs
            .removexattr(Context::from(in_header), in_header.nodeid.into(), &name)
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn flush(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FlushIn { fh, lock_owner, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.flush(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            lock_owner,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn init(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        // The export was destroyed by the guest. It is never re-exported:
        // re-initialization could only resurrect a device whose filter and
        // handles were already torn down.
        if self.destroyed.load(Ordering::Acquire) {
            return reply_error(
                io::Error::from_raw_os_error(libc::EIO),
                in_header.unique,
                w,
            );
        }
        let InitInCompat {
            major,
            minor,
            max_readahead,
            flags,
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let options = FsOptions::from_bits_truncate(flags as u64);

        let InitInExt { flags2, .. } = if options.contains(FsOptions::INIT_EXT) {
            r.read_obj().map_err(Error::DecodeMessage)?
        } else {
            InitInExt::default()
        };

        if major < KERNEL_VERSION {
            log_init_version_rejection(major, minor);
            return reply_error(
                io::Error::from_raw_os_error(libc::EPROTO),
                in_header.unique,
                w,
            );
        }

        if major > KERNEL_VERSION {
            // Wait for the kernel to reply back with a 7.X version.
            let out = InitOut {
                major: KERNEL_VERSION,
                minor: KERNEL_MINOR_VERSION,
                ..Default::default()
            };

            return reply_ok(Some(out), None, in_header.unique, w);
        }

        if minor < MIN_KERNEL_MINOR_VERSION {
            log_init_version_rejection(major, minor);
            return reply_error(
                io::Error::from_raw_os_error(libc::EPROTO),
                in_header.unique,
                w,
            );
        }

        // These fuse features are supported by this server by default.
        let mut supported = FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::BIG_WRITES
            | FsOptions::AUTO_INVAL_DATA
            | FsOptions::ASYNC_DIO
            | FsOptions::HAS_IOCTL_DIR
            | FsOptions::ATOMIC_O_TRUNC
            | FsOptions::MAX_PAGES
            | FsOptions::SUBMOUNTS
            | FsOptions::INIT_EXT;

        // The supplementary-group extension is only usable when THIS process
        // may call setgroups(2). Advertising it without CAP_SETGID makes the
        // guest attach a supplementary gid to every create/mkdir, and each
        // such request then fails EPERM in the credential switch — a
        // per-request failure the guest never asked for. Advertise by
        // capability instead.
        let setgid_cap = capng::name_to_capability("SETGID").ok();
        if setgid_cap
            .map(|cap| capng::have_capability(capng::Type::EFFECTIVE, cap))
            .unwrap_or(false)
        {
            supported |= FsOptions::CREATE_SUPP_GROUP;
        }

        let flags_64 = ((flags2 as u64) << 32) | (flags as u64);
        let capable = FsOptions::from_bits_truncate(flags_64);

        let page_size: u32 = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
        let max_pages = ((MAX_BUFFER_SIZE - 1) / page_size) + 1;

        match self.fs.init(capable) {
            Ok(want) => {
                let enabled = (capable & (want | supported)).bits();
                self.options.store(enabled, Ordering::Relaxed);

                let mut out = InitOut {
                    major: KERNEL_VERSION,
                    minor: KERNEL_MINOR_VERSION,
                    max_readahead,
                    flags: enabled as u32,
                    max_background: u16::MAX,
                    congestion_threshold: (u16::MAX / 4) * 3,
                    max_write: MAX_BUFFER_SIZE,
                    time_gran: 1, // nanoseconds
                    max_pages: max_pages.try_into().unwrap(),
                    map_alignment: 0,
                    flags2: (enabled >> 32) as u32,
                    ..Default::default()
                };

                // Enable DIRECT_IO_ALLOW_MMAP when cache is disabled,
                // send then enabled feature with standard FUSE
                // protocol.
                if want.contains(FsOptions::DIRECT_IO_ALLOW_MMAP) {
                    out.flags2 = (FsOptions::DIRECT_IO_ALLOW_MMAP.bits() >> 32) as u32;
                }

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn opendir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let OpenIn { flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self
            .fs
            .opendir(Context::from(in_header), in_header.nodeid.into(), flags)
        {
            Ok((handle, opts)) => {
                let out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn mock_readdir(
        &self,
        root_dirents: &[DirEntry2],
        size: u32,
        offset: u64,
        cursor: &mut Writer,
    ) -> io::Result<usize> {
        let mut total_written = 0;
        let mut err = None;

        for dirent2 in root_dirents.iter().skip(offset as usize) {
            // Allow-list names come from trusted config; one containing an
            // interior NUL cannot be encoded as a dirent — skip it instead
            // of panicking on the request path.
            let dirent2_name = match CString::new(dirent2.name.clone()) {
                Ok(name) => name,
                Err(_) => {
                    warn!(
                        "root dirent name contains NUL, skipping: {:?}",
                        dirent2.name
                    );
                    continue;
                }
            };
            let dirent = DirEntry {
                ino: dirent2.ino,
                offset: dirent2.offset,
                type_: dirent2.type_,
                name: dirent2_name.as_c_str(),
            };
            let remaining = (size as usize).saturating_sub(total_written);
            match add_dirent(cursor, remaining, dirent, None) {
                // No more space left in the buffer.
                Ok(0) => break,
                Ok(bytes_written) => {
                    total_written += bytes_written;
                }
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }

        if let Some(err) = err {
            Err(err)
        } else {
            Ok(total_written)
        }
    }

    fn readdir(&self, in_header: InHeader, mut r: Reader, mut w: Writer) -> Result<usize> {
        let ReadIn {
            fh, offset, size, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        let available_bytes = w.available_bytes();
        if available_bytes < size as usize {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        // Skip over enough bytes for the header.
        let unique = in_header.unique;
        // the same short/absent-writable-region rule as read(). The
        // available_bytes() guard above does NOT cover it — `size == 0`
        // (an empty-buffer readdir) passes the guard and still needs the
        // header's bytes, so the split is reachable with nothing to split.
        let mut cursor = match w.split_at(size_of::<OutHeader>()) {
            Ok(cursor) => cursor,
            Err(_) => return reply_error(io::Error::from_raw_os_error(libc::ENOMEM), unique, w),
        };

        // Root enumeration is served from the allow-list when the filter is
        // active (see root_filter_snapshot for the single-lock semantics).
        let root_snapshot = self.root_filter_snapshot(in_header.nodeid);

        let result = if let Some(entries) = root_snapshot {
            let dirents: Vec<DirEntry2> = entries.into_iter().map(|(d, _)| d).collect();
            self.mock_readdir(&dirents, size, offset, &mut cursor)
        } else {
            match self.fs.readdir(
                Context::from(in_header),
                in_header.nodeid.into(),
                fh.into(),
                size,
                offset,
            ) {
                Ok(mut entries) => {
                    let mut total_written = 0;
                    let mut err = None;
                    while let Some(dirent) = entries.next() {
                        let remaining = (size as usize).saturating_sub(total_written);
                        match add_dirent(&mut cursor, remaining, dirent, None) {
                            // No more space left in the buffer.
                            Ok(0) => break,
                            Ok(bytes_written) => {
                                total_written += bytes_written;
                            }
                            Err(e) => {
                                err = Some(e);
                                break;
                            }
                        }
                    }
                    if let Some(err) = err {
                        Err(err)
                    } else {
                        Ok(total_written)
                    }
                }
                Err(e) => Err(e),
            }
        };

        match result {
            Ok(total_written) => reply_readdir(total_written, unique, w),
            Err(e) => reply_error(e, unique, w),
        }
    }

    fn handle_dirent<'d>(
        &self,
        in_header: &InHeader,
        dir_entry: DirEntry<'d>,
    ) -> io::Result<(DirEntry<'d>, Entry)> {
        let parent = in_header.nodeid.into();
        let name = dir_entry.name.to_bytes();
        let entry = if name == CURRENT_DIR_CSTR || name == PARENT_DIR_CSTR {
            // Don't do lookups on the current directory or the parent directory. Safe because
            // this only contains integer fields and any value is valid.
            let mut attr = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };
            attr.st_ino = dir_entry.ino;
            attr.st_mode = dir_entry.type_ << 12;

            // We use 0 for the inode value to indicate a negative entry.
            Entry {
                inode: 0,
                generation: 0,
                attr,
                attr_flags: 0,
                attr_timeout: Duration::from_secs(0),
                entry_timeout: Duration::from_secs(0),
            }
        } else {
            self.fs.lookup(
                Context::from(*in_header),
                parent,
                &dirent_name(dir_entry.name)?,
                None,
            )?
        };

        Ok((dir_entry, entry))
    }

    // Snapshot the root allow-list for mock enumeration (readdir/readdirplus).
    // Returns None when the request is not for the root — root enumeration
    // ALWAYS comes from the allow-list (the filter has no off state), never
    // from the real directory. The snapshot and the data are taken under ONE
    // lock acquisition so a concurrent vm.set-fs swap cannot tear them apart;
    // each entry carries the allow-list (path, stat) pair needed to build an
    // honest plus entry via fs.lookup.
    fn root_filter_snapshot(
        &self,
        nodeid: u64,
    ) -> Option<Vec<(DirEntry2, Option<FilterEntry>)>> {
        if nodeid != ROOT_ID {
            return None;
        }
        let filter = self.root_filter.as_ref().lock().unwrap();
        Some(
            filter
                .get_root_dirents()
                .iter()
                .map(|d| {
                    let f_info = if d.name == "." || d.name == ".." {
                        None
                    } else {
                        filter.get_allow_dir(&d.name).ok()
                    };
                    (d.clone(), f_info)
                })
                .collect(),
        )
    }

    /// Same allow-list snapshot as `root_filter_snapshot`, but the lock is
    /// RETURNED and held by the caller. readdirplus builds each Entry through
    /// `fs.lookup`, and that snapshot→lookup pair must be atomic against a
    /// vm.set-fs swap+revoke, exactly like the single-name LOOKUP
    /// path. The root listing carries at most "." / ".." / the one alias, so
    /// the hold is short and root-level only.
    fn root_filter_snapshot_locked(
        &self,
        nodeid: u64,
    ) -> Option<(
        std::sync::MutexGuard<'_, FilterList>,
        Vec<(DirEntry2, Option<FilterEntry>)>,
    )> {
        if nodeid != ROOT_ID {
            return None;
        }
        let filter = self.root_filter.as_ref().lock().unwrap();
        let entries = filter
            .get_root_dirents()
            .iter()
            .map(|d| {
                let f_info = if d.name == "." || d.name == ".." {
                    None
                } else {
                    filter.get_allow_dir(&d.name).ok()
                };
                (d.clone(), f_info)
            })
            .collect();
        Some((filter, entries))
    }

    fn readdirplus(&self, in_header: InHeader, mut r: Reader, mut w: Writer) -> Result<usize> {
        let ReadIn {
            fh, offset, size, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        let available_bytes = w.available_bytes();
        if available_bytes < size as usize {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        // Skip over enough bytes for the header.
        let unique = in_header.unique;
        // same short/absent-writable-region rule as readdir (a
        // `size == 0` request passes the guard above with nothing to split).
        let mut cursor = match w.split_at(size_of::<OutHeader>()) {
            Ok(cursor) => cursor,
            Err(_) => return reply_error(io::Error::from_raw_os_error(libc::ENOMEM), unique, w),
        };

        // Root enumeration is served from the allow-list when the filter is
        // active. Unlike plain readdir, every entry must carry an Entry
        // (plus data); these are built HONESTLY through fs.lookup on the
        // allow-listed directory, which allocates real passthrough inodes
        // with kernel-managed lookup counts — the same mechanism the LOOKUP
        // opcode uses. Buffer-full and error paths therefore do the same
        // FORGET bookkeeping as the unfiltered branch below, keeping lookup
        // counts balanced. The filter lock is held for the whole filtered
        // branch so each fs.lookup below is serialized with the vm.set-fs
        // swap+revoke.
        let root_snapshot = self.root_filter_snapshot_locked(in_header.nodeid);

        let result = if let Some((_filter_guard, entries)) = root_snapshot {
            let mut total_written = 0;
            let mut err = None;

            for (dirent2, f_info) in entries.iter().skip(offset as usize) {
                let dirent2_name = match CString::new(dirent2.name.clone()) {
                    Ok(name) => name,
                    Err(_) => {
                        warn!(
                            "root dirent name contains NUL, skipping: {:?}",
                            dirent2.name
                        );
                        continue;
                    }
                };

                let entry = if dirent2.name == "." || dirent2.name == ".." {
                    // Synthetic entry for the dot dirents, mirroring
                    // handle_dirent: kernel does not take lookup counts for
                    // these. Safe because this only contains integer fields
                    // and any value is valid.
                    let mut attr = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };
                    attr.st_ino = dirent2.ino;
                    attr.st_mode = dirent2.type_ << 12;
                    Entry {
                        inode: 0,
                        generation: 0,
                        attr,
                        attr_flags: 0,
                        attr_timeout: Duration::from_secs(0),
                        entry_timeout: Duration::from_secs(0),
                    }
                } else {
                    let name = match dirent_name(dirent2_name.as_c_str()) {
                        Ok(name) => name,
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    };
                    match self.fs.lookup(
                        Context::from(in_header),
                        ROOT_ID.into(),
                        &name,
                        f_info.clone(),
                    ) {
                        Ok(entry) => entry,
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                };

                let entry_inode = entry.inode;
                let dirent = DirEntry {
                    ino: dirent2.ino,
                    offset: dirent2.offset,
                    type_: dirent2.type_,
                    name: dirent2_name.as_c_str(),
                };
                let remaining = (size as usize).saturating_sub(total_written);
                match add_dirent(&mut cursor, remaining, dirent, Some(entry)) {
                    Ok(0) => {
                        // No more space left in the buffer but we need to undo the lookup
                        // that created the Entry or we will end up with mismatched lookup
                        // counts.
                        if entry_inode != 0 {
                            self.fs
                                .forget(Context::from(in_header), entry_inode.into(), 1);
                        }
                        break;
                    }
                    Ok(bytes_written) => {
                        total_written += bytes_written;
                    }
                    Err(e) => {
                        if entry_inode != 0 {
                            self.fs
                                .forget(Context::from(in_header), entry_inode.into(), 1);
                        }

                        if total_written == 0 {
                            // We haven't filled any entries yet so we can just propagate
                            // the error.
                            err = Some(e);
                        }

                        // We already filled in some entries. Returning an error now will
                        // cause lookup count mismatches for those entries so just return
                        // whatever we already have.
                        break;
                    }
                }
            }

            if let Some(err) = err {
                Err(err)
            } else {
                Ok(total_written)
            }
        } else {
            match self.fs.readdir(
                Context::from(in_header),
                in_header.nodeid.into(),
                fh.into(),
                size,
                offset,
            ) {
                Ok(mut entries) => {
                    let mut total_written = 0;
                    let mut err = None;
                    while let Some(dirent) = entries.next() {
                        let mut entry_inode = None;
                        let bytes_written =
                            self.handle_dirent(&in_header, dirent).and_then(|(d, e)| {
                                entry_inode = Some(e.inode);
                                let remaining = (size as usize).saturating_sub(total_written);
                                add_dirent(&mut cursor, remaining, d, Some(e))
                            });
                        match bytes_written {
                            Ok(0) => {
                                // No more space left in the buffer but we need to undo the lookup
                                // that created the Entry or we will end up with mismatched lookup
                                // counts.
                                if let Some(inode) = entry_inode {
                                    self.fs.forget(Context::from(in_header), inode.into(), 1);
                                }
                                break;
                            }
                            Ok(bytes_written) => {
                                total_written += bytes_written;
                            }
                            Err(e) => {
                                if let Some(inode) = entry_inode {
                                    self.fs.forget(Context::from(in_header), inode.into(), 1);
                                }

                                if total_written == 0 {
                                    // We haven't filled any entries yet so we can just propagate
                                    // the error.
                                    err = Some(e);
                                }

                                // We already filled in some entries. Returning an error now will
                                // cause lookup count mismatches for those entries so just return
                                // whatever we already have.
                                break;
                            }
                        }
                    }
                    if let Some(err) = err {
                        Err(err)
                    } else {
                        Ok(total_written)
                    }
                }
                Err(e) => Err(e),
            }
        };

        match result {
            Ok(total_written) => reply_readdir(total_written, unique, w),
            Err(e) => reply_error(e, unique, w),
        }
    }

    fn releasedir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let ReleaseIn { fh, flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.releasedir(
            Context::from(in_header),
            in_header.nodeid.into(),
            flags,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn fsyncdir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FsyncIn {
            fh, fsync_flags, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;
        let datasync = fsync_flags & 0x1 != 0;

        match self.fs.fsyncdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            datasync,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn getlk(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.getlk() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn setlk(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.setlk() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn setlkw(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.setlkw() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn access(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let AccessIn { mask, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        // The share root is a synthetic 0755 directory owned by root: F_OK
        // succeeds, everything else is denied (the guest has no legitimate
        // access to the export root; only the current tenant volume is
        // exposed). This mirrors the synthesized getattr above.
        if in_header.nodeid == ROOT_ID {
            if mask == libc::F_OK as u32 {
                return reply_ok(None::<u8>, None, in_header.unique, w);
            }
            return reply_error(
                io::Error::from_raw_os_error(libc::EACCES),
                in_header.unique,
                w,
            );
        }

        match self
            .fs
            .access(Context::from(in_header), in_header.nodeid.into(), mask)
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn create(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let CreateIn {
            flags,
            mode,
            umask,
            open_flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let remaining_len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<CreateIn>()))
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0; remaining_len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;
        let mut components = buf.split_inclusive(|c| *c == b'\0');
        let name = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len(), buf.as_slice())?;

        let kill_priv = open_flags & OPEN_KILL_SUIDGID != 0;

        match self.fs.create(
            Context::from(in_header),
            in_header.nodeid.into(),
            &name_or_enoent!(Name::parse(name), in_header, w),
            mode,
            kill_priv,
            flags,
            umask,
            extensions,
        ) {
            Ok((entry, handle, opts)) => {
                let entry_out = EntryOut {
                    nodeid: entry.inode,
                    generation: entry.generation,
                    entry_valid: entry.entry_timeout.as_secs(),
                    attr_valid: entry.attr_timeout.as_secs(),
                    entry_valid_nsec: entry.entry_timeout.subsec_nanos(),
                    attr_valid_nsec: entry.attr_timeout.subsec_nanos(),
                    attr: Attr::with_flags(entry.attr, entry.attr_flags),
                };
                let open_out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                // Kind of a hack to write both structs.
                reply_ok(
                    Some(entry_out),
                    Some(open_out.as_slice()),
                    in_header.unique,
                    w,
                )
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn interrupt(&self, _in_header: InHeader) -> usize {
        0
    }

    fn bmap(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.bmap() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn destroy(&self) -> usize {
        // No reply to this function. The destroy is terminal: mark the server
        // destroyed (a later INIT is refused) and tell the owner so it can
        // retire the whole microVM — a device cannot be rebuilt from a filter
        // and handle set that the guest just tore down.
        self.destroyed.store(true, Ordering::Release);
        if let Some(hook) = self.on_destroy.as_ref() {
            hook();
        }
        self.fs.destroy();
        self.options
            .store(FsOptions::empty().bits(), Ordering::Relaxed);

        0
    }

    fn ioctl(&self, in_header: InHeader, _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.ioctl() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn poll(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.poll() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn notify_reply(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.notify_reply() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn batch_forget(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let BatchForgetIn { count, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        if let Some(size) = (count as usize).checked_mul(size_of::<ForgetOne>()) {
            if size > MAX_BUFFER_SIZE as usize {
                return reply_error(
                    io::Error::from_raw_os_error(libc::ENOMEM),
                    in_header.unique,
                    w,
                );
            }
        } else {
            return reply_error(
                io::Error::from_raw_os_error(libc::EOVERFLOW),
                in_header.unique,
                w,
            );
        }

        let mut requests = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let f = r.read_obj::<ForgetOne>().map_err(Error::DecodeMessage)?;
            let nodeid: u64 = f.nodeid.into();
            // Same ROOT_ID protection as single FORGET.
            if nodeid == ROOT_ID {
                continue;
            }
            requests.push((nodeid.into(), f.nlookup));
        }

        self.fs.batch_forget(Context::from(in_header), requests);

        // No reply for forget messages.
        Ok(0)
    }

    fn fallocate(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FallocateIn {
            fh,
            offset,
            length,
            mode,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.fallocate(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            mode,
            offset,
            length,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn lseek(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let LseekIn {
            fh, offset, whence, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.lseek(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            offset,
            whence,
        ) {
            Ok(offset) => {
                let out = LseekOut { offset };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn copyfilerange(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let CopyfilerangeIn {
            fh_in,
            off_in,
            nodeid_out,
            fh_out,
            off_out,
            len,
            flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.copyfilerange(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh_in.into(),
            off_in,
            nodeid_out.into(),
            fh_out.into(),
            off_out,
            len,
            flags,
        ) {
            Ok(count) => {
                let out = WriteOut {
                    size: count as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    /// FUSE SYNCFS — REFUSED.
    ///
    /// The passthrough implements this as `libc::syncfs(fd)`
    /// (passthrough/mod.rs, syncfs): that syncs the WHOLE host filesystem
    /// backing the share — every tenant's volume on the node — so any guest
    /// could force a node-wide synchronous writeback at will (cross-tenant
    /// I/O amplification under load). The FUSE in-header nodeid cannot
    /// narrow it: every nodeid the guest can reach sits on the same host
    /// filesystem, so an in-share request is exactly as wide as a root one.
    /// Per-file/per-directory durability stays served by Fsync/Fsyncdir/
    /// Flush; a guest syncfs gets ENOSYS, the protocol's "not implemented"
    /// answer.
    fn syncfs(&self, in_header: InHeader, w: Writer) -> Result<usize> {
        reply_error(
            io::Error::from_raw_os_error(libc::ENOSYS),
            in_header.unique,
            w,
        )
    }

    fn tmpfile(&self, in_header: InHeader, _r: Reader, w: Writer) -> Result<usize> {
        // a future FileSystem impl returning Ok here must produce a
        // reply, never a panic (the in-process daemon's death kills every VM
        // on the node). Ok is unreachable today (both impls ENOSYS); the Ok
        // arm answers EOPNOTSUPP explicitly.
        match self.fs.tmpfile() {
            Err(e) => reply_error(e, in_header.unique, w),
            Ok(_) => reply_error(
                io::Error::from_raw_os_error(libc::EOPNOTSUPP),
                in_header.unique,
                w,
            ),
        }
    }
}

impl<F: FileSystem + SerializableFileSystem + Sync> SerializableFileSystem for Server<F> {
    fn prepare_serialization(&self, cancel: Arc<AtomicBool>) -> io::Result<()> {
        self.fs.prepare_serialization(cancel)
    }

    fn serialize(&self, state_pipe: File) -> io::Result<()> {
        self.fs.serialize(state_pipe)
    }

    fn deserialize_and_apply(&self, state_pipe: File) -> io::Result<()> {
        self.fs.deserialize_and_apply(state_pipe)
    }

    fn serialize_data(&self) -> io::Result<Vec<u8>> {
        self.fs.serialize_data()
    }

    fn deserialize_and_apply_data(&self, serialized: &Vec<u8>) -> io::Result<()> {
        self.fs.deserialize_and_apply_data(serialized)
    }
}

fn reply_readdir(len: usize, unique: u64, mut w: Writer) -> Result<usize> {
    let out = OutHeader {
        len: (size_of::<OutHeader>() + len) as u32,
        error: 0,
        unique,
    };

    debug!("Replying OK, header: {:?}", out);
    w.write_all(out.as_slice()).map_err(Error::EncodeMessage)?;
    w.flush().map_err(Error::FlushMessage)?;
    Ok(out.len as usize)
}

fn reply_ok<T: ByteValued>(
    out: Option<T>,
    data: Option<&[u8]>,
    unique: u64,
    mut w: Writer,
) -> Result<usize> {
    let mut len = size_of::<OutHeader>();

    if out.is_some() {
        len += size_of::<T>();
    }

    if let Some(data) = data {
        len += data.len();
    }

    let header = OutHeader {
        len: len as u32,
        error: 0,
        unique,
    };

    debug!("Replying OK, header: {:?}", header);

    w.write_all(header.as_slice())
        .map_err(Error::EncodeMessage)?;

    if let Some(out) = out {
        w.write_all(out.as_slice()).map_err(Error::EncodeMessage)?;
    }

    if let Some(data) = data {
        w.write_all(data).map_err(Error::EncodeMessage)?;
    }

    debug_assert_eq!(len, w.bytes_written());
    Ok(w.bytes_written())
}

fn strerror(error: i32) -> String {
    let mut err_desc: Vec<u8> = vec![0; 256];
    let buf_ptr = err_desc.as_mut_ptr() as *mut libc::c_char;

    // Safe because libc::strerror_r writes in err_desc at most err_desc.len() bytes
    unsafe {
        // We ignore the returned value since the two possible error values are:
        // EINVAL and ERANGE, in the former err_desc will be "Unknown error #"
        // and in the latter the message will be truncated to fit err_desc
        libc::strerror_r(error, buf_ptr, err_desc.len());
    }
    let err_desc = err_desc.split(|c| *c == b'\0').next().unwrap();
    String::from_utf8(err_desc.to_vec()).unwrap_or_else(|_| "".to_owned())
}

/// The reply for a name the allow-list hides. It MUST carry a real ENOENT:
/// `ErrorKind::NotFound.into()` produces an io::Error with NO raw OS error, and
/// reply_error falls back to EIO (`raw_os_error().unwrap_or(libc::EIO)`) — so
/// the pre-fix deny path answered **EIO**, letting a guest tell "hidden by the
/// filter" (EIO) apart from "does not exist" (ENOENT). That is exactly the
/// name-existence oracle this module's comments promise not to leak, and it
/// disclosed which sibling sandfs ids exist on the host. Found by driving the
/// real dispatch in `root_gate_tests`.
fn reply_hidden(unique: u64, w: Writer) -> Result<usize> {
    reply_error(
        io::Error::from_raw_os_error(libc::ENOENT),
        unique,
        w,
    )
}

fn reply_error(e: io::Error, unique: u64, mut w: Writer) -> Result<usize> {
    let header = OutHeader {
        len: size_of::<OutHeader>() as u32,
        error: -e.raw_os_error().unwrap_or(libc::EIO),
        unique,
    };

    debug!(
        "Replying ERROR, header: OutHeader {{ error: {} ({}), unique: {}, len: {} }}",
        header.error,
        strerror(-header.error),
        header.unique,
        header.len
    );

    w.write_all(header.as_slice())
        .map_err(Error::EncodeMessage)?;

    debug_assert_eq!(header.len as usize, w.bytes_written());
    Ok(w.bytes_written())
}

/// The symlink TARGET — the one place wire bytes become a `CStr` WITHOUT the
/// component rule, and deliberately so.
///
/// A symlink target is not a name: this daemon never resolves it. `symlinkat`
/// stores the bytes verbatim as the link's content, and only the *guest's own*
/// kernel ever resolves them, inside the guest's mount namespace (where an
/// absolute target names a path in the guest, not on the host). Validating it
/// would be wrong (targets are legitimately multi-component paths) and would
/// break `ln -s a/b/c`.
///
/// It exists as a purpose-named function rather than a general "bytes → CStr"
/// helper so that adding a new NAME field has no convenient generic converter
/// to reach for: the only way to feed a name to the filesystem layer is
/// [`crate::filesystem::Name::parse`], which validates.
fn symlink_target(buf: &[u8]) -> Result<&CStr> {
    // Convert to a `CStr` first so that we can drop the '\0' byte at the end
    // and make sure there are no interior '\0' bytes.
    CStr::from_bytes_with_nul(buf).map_err(Error::InvalidCString)
}

/// Wrap a HOST directory-entry name (this daemon's own `readdir` output, and
/// the allow-list basenames the root filter synthesizes) as a `Name`.
///
/// Host entries are single components by construction — `getdents64` cannot
/// return a name containing `/`, and both callers handle `.`/`..` before
/// reaching here — so the check can never fire; it runs anyway so that
/// [`Name::parse`] stays the ONE way a name is built. A second, unchecked
/// constructor is exactly the kind of convenience a later edit reaches for when
/// adding a NAME field, and the rule is only as strong as its weakest door.
fn dirent_name(name: &CStr) -> io::Result<Name<'_>> {
    Name::parse(name.to_bytes_with_nul()).map_err(|_| {
        // Unreachable for a real dirent; EIO is the honest answer if the
        // invariant is ever violated (it would mean this daemon's own readdir
        // produced something no filesystem may resolve).
        io::Error::from_raw_os_error(libc::EIO)
    })
}

fn add_dirent(
    cursor: &mut Writer,
    max: usize,
    d: DirEntry,
    entry: Option<Entry>,
) -> io::Result<usize> {
    // Strip the trailing '\0'.
    let name = d.name.to_bytes();
    if name.len() > u32::MAX as usize {
        return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
    }

    let dirent_len = size_of::<Dirent>()
        .checked_add(name.len())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    // Directory entries must be padded to 8-byte alignment.  If adding 7 causes
    // an overflow then this dirent cannot be properly padded.
    let padded_dirent_len = dirent_len
        .checked_add(7)
        .map(|l| l & !7)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    let total_len = if entry.is_some() {
        padded_dirent_len
            .checked_add(size_of::<EntryOut>())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?
    } else {
        padded_dirent_len
    };

    if max < total_len {
        Ok(0)
    } else {
        if let Some(entry) = entry {
            cursor.write_all(EntryOut::from(entry).as_slice())?;
        }

        let dirent = Dirent {
            ino: d.ino,
            off: d.offset,
            namelen: name.len() as u32,
            type_: d.type_,
        };

        cursor.write_all(dirent.as_slice())?;
        cursor.write_all(name)?;

        // We know that `dirent_len` <= `padded_dirent_len` due to the check above
        // so there's no need for checked arithmetic.
        let padding = padded_dirent_len - dirent_len;
        if padding > 0 {
            cursor.write_all(&DIRENT_PADDING[..padding])?;
        }

        Ok(total_len)
    }
}

fn take_object<T: ByteValued>(data: &[u8]) -> Result<(T, &[u8])> {
    if data.len() < size_of::<T>() {
        return Err(Error::DecodeMessage(einval()));
    }

    let (object_bytes, remaining_bytes) = data.split_at(size_of::<T>());
    // SAFETY: `T` implements `ByteValued` that guarantees that it is safe to instantiate
    // `T` with random data.
    let object: T = unsafe { std::ptr::read_unaligned(object_bytes.as_ptr() as *const T) };
    Ok((object, remaining_bytes))
}

pub fn parse_security_context(nr_secctx: u32, data: &[u8]) -> Result<Option<SecContext>> {
    // Although the FUSE security context extension allows sending several security contexts,
    // currently the guest kernel only sends one.
    if nr_secctx > 1 {
        return Err(Error::DecodeMessage(einval()));
    } else if nr_secctx == 0 {
        // No security context sent. May be no LSM supports it.
        return Ok(None);
    }

    let (secctx, data) = take_object::<Secctx>(data)?;

    if secctx.size == 0 {
        return Err(Error::DecodeMessage(einval()));
    }

    let mut components = data.split_inclusive(|c| *c == b'\0');
    let secctx_name = components.next().ok_or(Error::MissingParameter)?;
    let (_, data) = data.split_at(secctx_name.len());

    if data.len() < secctx.size as usize {
        return Err(Error::DecodeMessage(einval()));
    }

    // Fuse client aligns the whole security context block to 64 byte
    // boundary. So it is possible that after actual security context
    // of secctx.size, there are some null padding bytes left. If
    // we ever parse more data after secctx, we will have to take those
    // null bytes into account. Total size (including null bytes) is
    // available in SecctxHeader->size.
    let (remaining, _) = data.split_at(secctx.size as usize);

    let fuse_secctx = SecContext {
        name: CString::from_vec_with_nul(secctx_name.to_vec()).map_err(Error::InvalidCString2)?,
        secctx: remaining.to_vec(),
    };

    Ok(Some(fuse_secctx))
}

pub fn parse_sup_groups(data: &[u8]) -> Result<u32> {
    let (group_header, group_id_bytes) = take_object::<SuppGroups>(data)?;

    // The FUSE extension allows sending several group IDs, but currently the guest
    // kernel only sends one.
    if group_header.nr_groups != 1 {
        return Err(Error::DecodeMessage(einval()));
    }

    let (gid, _) = take_object::<u32>(group_id_bytes)?;
    Ok(gid)
}

fn get_extensions(options: FsOptions, skip: usize, request_bytes: &[u8]) -> Result<Extensions> {
    let mut extensions = Extensions::default();

    if !(options.contains(FsOptions::SECURITY_CTX)
        || options.contains(FsOptions::CREATE_SUPP_GROUP))
    {
        return Ok(extensions);
    }

    // It's not guaranty to receive an extension even if it's supported by the guest kernel
    if request_bytes.len() < skip {
        return Err(Error::DecodeMessage(einval()));
    }

    // We need to track if a SecCtx was received, because it's valid
    // for the guest to send an empty SecCtx (i.e, nr_secctx == 0)
    let mut secctx_received = false;

    let mut buf = &request_bytes[skip..];
    while !buf.is_empty() {
        let (extension_header, remaining_bytes) = take_object::<ExtHeader>(buf)?;

        let extension_size = (extension_header.size as usize)
            .checked_sub(size_of::<ExtHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        // The guest-supplied ExtHeader.size bounds-checked against the
        // remaining buffer BEFORE split_at: a forged (or corrupt) header
        // must answer EINVAL, not panic the request thread — the daemon is
        // in-process, so a panic kills the whole VMM.
        let (current_extension_bytes, next_extension_bytes) = remaining_bytes
            .split_at_checked(extension_size)
            .ok_or_else(|| Error::DecodeMessage(einval()))?;

        let ext_type = ExtType::try_from(extension_header.ext_type)
            .map_err(|_| Error::DecodeMessage(einval()))?;

        match ext_type {
            ExtType::SecCtx(nr_secctx) => {
                if !options.contains(FsOptions::SECURITY_CTX) || secctx_received {
                    return Err(Error::DecodeMessage(einval()));
                }

                secctx_received = true;
                extensions.secctx = parse_security_context(nr_secctx, current_extension_bytes)?;
                debug!("Extension received: {} SecCtx", nr_secctx);
            }
            ExtType::SupGroups => {
                if !options.contains(FsOptions::CREATE_SUPP_GROUP) || extensions.sup_gid.is_some() {
                    return Err(Error::DecodeMessage(einval()));
                }

                extensions.sup_gid = parse_sup_groups(current_extension_bytes)?.into();
                debug!("Extension received: SupGroups({:?})", extensions.sup_gid);
            }
        }

        // Let's process the next extension
        buf = next_extension_bytes;
    }

    // The SupGroup extension can be missing, since it is only sent if needed.
    // A SecCtx is always sent in create/synlink/mknod/mkdir if supported.
    if options.contains(FsOptions::SECURITY_CTX) && !secctx_received {
        return Err(Error::MissingExtension);
    }

    Ok(extensions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const VOL_ALIAS: &str = "gen0";
    const NEXT_ALIAS: &str = "gen1";

    /// Unique temp directory for allow-list entries (FilterList::init does
    /// real openat/statx on each entry, so the tests need real dirs).
    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("sandswap-virtiofsd-test-{}-{}", std::process::id(), name));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cstr(bytes: &[u8]) -> CString {
        CString::new(bytes).unwrap()
    }

    #[test]
    fn root_synthetic_stat_hides_host_metadata() {
        // The share root must not expose aggregate tenant state. Pin the
        // fixed fields: a directory with nlink=2 and zeroed timestamps/owner.
        let st = root_synthetic_stat();
        assert_eq!(st.st_ino, ROOT_ID);
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFDIR);
        assert_eq!(st.st_mode & 0o777, 0o755);
        assert_eq!(st.st_nlink, 2);
        assert_eq!(st.st_uid, 0);
        assert_eq!(st.st_gid, 0);
        assert_eq!(st.st_size, 0);
        assert_eq!(st.st_blksize, 4096);
        assert_eq!(st.st_atime, 0);
        assert_eq!(st.st_mtime, 0);
        assert_eq!(st.st_ctime, 0);
    }

    #[test]
    fn test_filter_empty_whitelist_hides_all() {
        // An empty allow-list is an ACTIVE filter that hides every root
        // entry — the fail-closed boot/detach state, and the ONLY empty
        // state (the former inactive/None mode was removed; there is no
        // unfiltered configuration).
        let filter = FilterList::new(1, &[], None).unwrap();
        assert!(matches!(filter.root_lookup(&cstr(b"agent-a")), RootLookup::Denied));
        assert!(matches!(filter.root_lookup(&cstr(b"anything")), RootLookup::Denied));
        // The synthesized dot dirents of the root listing are served by
        // mock readdir, not lookup; a lookup for them is denied like any
        // other non-whitelisted name.
        assert!(matches!(filter.root_lookup(&cstr(b".")), RootLookup::Denied));
        // Root enumeration still works: only "." and "..".
        assert_eq!(filter.get_root_dirents().len(), 2);
    }

    // regression pin (device boundary): an allow-list entry with a `..` component
    // is refused with a named error instead of being resolved by the openat
    // below (O_NOFOLLOW stops only the final component, so `..` escaped the
    // share and the guest got an export of the escaped directory). RED with
    // the refusal removed: FilterList::new accepts the entry and exposes
    // `outside` under its basename.
    #[test]
    fn test_filter_rejects_parent_component_entry() {
        let dir_a = temp_dir("dotdot-a");
        let outside_base = temp_dir("dotdot-outside");
        let escape = format!(
            "{}/../{}",
            dir_a.to_str().unwrap(),
            outside_base.file_name().unwrap().to_str().unwrap()
        );

        let res = FilterList::new(1, &[escape.clone()], Some(VOL_ALIAS));
        match res {
            Err(Error::InvalidFilter(e)) => {
                assert!(
                    format!("{e}").contains(".."),
                    "refusal must NAME the '..' component: {}",
                    e
                );
            }
            Ok(_) => panic!("'..' entry {:?} must be refused by the filter", escape),
            Err(other) => panic!("expected a named InvalidFilter refusal, got {:?}", other),
        }

        // Control: the same real directory without the `..` component is a
        // legal entry (the refusal is about the escape, not the path shape).
        let filter = FilterList::new(1, &[dir_a.to_str().unwrap().to_owned()], Some(VOL_ALIAS)).unwrap();
        assert!(matches!(
            filter.root_lookup(&cstr(VOL_ALIAS.as_bytes())),
            RootLookup::Allowed(_)
        ));

        fs::remove_dir_all(&dir_a).unwrap();
        fs::remove_dir_all(&outside_base).unwrap();
    }

    #[test]
    fn test_filter_whitelist_and_deny() {
        let dir_a = temp_dir("whitelist-a");
        let dir_b = temp_dir("whitelist-b");
        let a_name = dir_a.file_name().unwrap().to_str().unwrap().to_owned();
        let b_name = dir_b.file_name().unwrap().to_str().unwrap().to_owned();

        let filter =
            FilterList::new(1, &[dir_a.to_str().unwrap().to_owned()], Some(VOL_ALIAS)).unwrap();

        // The ALIAS resolves to the host path...
        match filter.root_lookup(&cstr(VOL_ALIAS.as_bytes())) {
            RootLookup::Allowed((path, _, _)) => assert_eq!(path, dir_a.to_str().unwrap()),
            other => panic!("expected Allowed, got {:?}", other),
        }
        // ...anything else is denied indistinguishably from non-existent:
        // siblings, dot entries, multi-component names — AND the real
        // basename of the active directory itself (the name is a secret the
        // guest must never be able to spell).
        assert!(matches!(filter.root_lookup(&cstr(a_name.as_bytes())), RootLookup::Denied));
        assert!(matches!(filter.root_lookup(&cstr(b_name.as_bytes())), RootLookup::Denied));
        assert!(matches!(filter.root_lookup(&cstr(b"..")), RootLookup::Denied));
        assert!(matches!(filter.root_lookup(&cstr(b"agent-a/inner")), RootLookup::Denied));

        // Root readdir only carries "." / ".." plus the alias — never the
        // real name.
        let names: Vec<&str> = filter
            .get_root_dirents()
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, vec![".", "..", VOL_ALIAS]);

        fs::remove_dir_all(&dir_a).unwrap();
        fs::remove_dir_all(&dir_b).unwrap();
    }

    #[test]
    fn test_filter_update_swaps_and_clears() {
        let dir_a = temp_dir("swap-a");
        let dir_b = temp_dir("swap-b");
        let a_name = dir_a.file_name().unwrap().to_str().unwrap().to_owned();
        let b_name = dir_b.file_name().unwrap().to_str().unwrap().to_owned();

        let mut filter =
            FilterList::new(1, &[dir_a.to_str().unwrap().to_owned()], Some(VOL_ALIAS)).unwrap();
        assert!(matches!(filter.root_lookup(&cstr(VOL_ALIAS.as_bytes())), RootLookup::Allowed(..)));
        assert!(matches!(
            filter.root_lookup(&cstr(a_name.as_bytes())),
            RootLookup::Denied
        ));

        // Agent switch: whitelist moves a → b; the ALIAS follows (the guest
        // gets a fresh alias across switches), the real names stay denied.
        filter.update(&[dir_b.to_str().unwrap().to_owned()], Some(NEXT_ALIAS), None).unwrap();
        assert!(matches!(filter.root_lookup(&cstr(VOL_ALIAS.as_bytes())), RootLookup::Denied));
        match filter.root_lookup(&cstr(NEXT_ALIAS.as_bytes())) {
            RootLookup::Allowed((path, _, _)) => assert_eq!(path, dir_b.to_str().unwrap()),
            other => panic!("expected Allowed after swap, got {:?}", other),
        }
        assert!(matches!(filter.root_lookup(&cstr(a_name.as_bytes())), RootLookup::Denied));
        assert!(matches!(filter.root_lookup(&cstr(b_name.as_bytes())), RootLookup::Denied));

        // Detach: the empty list hides everything again — and it is the only
        // empty state (there is no unfiltered mode to fall back to).
        filter.update(&[], None, None).unwrap();
        assert!(matches!(filter.root_lookup(&cstr(VOL_ALIAS.as_bytes())), RootLookup::Denied));

        fs::remove_dir_all(&dir_a).unwrap();
        fs::remove_dir_all(&dir_b).unwrap();
    }

    #[test]
    fn test_filter_update_failure_is_atomic() {
        let dir_a = temp_dir("atomic-a");
        let _a_name = dir_a.file_name().unwrap().to_str().unwrap().to_owned();
        let missing = std::env::temp_dir().join("sandswap-virtiofsd-test-definitely-missing");

        let mut filter =
            FilterList::new(1, &[dir_a.to_str().unwrap().to_owned()], Some(VOL_ALIAS)).unwrap();

        // A whitelist containing a directory that cannot be opened must be
        // rejected AND leave the previous whitelist fully in place — never
        // a half-updated mix.
        assert!(filter
            .update(
                &[missing.to_str().unwrap().to_owned()],
                Some(NEXT_ALIAS),
                None,
            )
            .is_err());
        assert!(matches!(filter.root_lookup(&cstr(VOL_ALIAS.as_bytes())), RootLookup::Allowed(..)));
        // The root listing still shows the old (single, aliased) entry.
        assert_eq!(filter.get_root_dirents().len(), 3); // ".", "..", vol

        fs::remove_dir_all(&dir_a).unwrap();
    }

    #[test]
    fn test_filter_update_cancelled_keeps_previous() {
        // The control plane's bounded set-fs wait expired while the filter
        // build was stalled: the swap must be dropped (the caller already
        // reported "not attached"), and the previous export stays fully in
        // place.
        let dir_a = temp_dir("cancel-a");
        let dir_b = temp_dir("cancel-b");
        let mut filter =
            FilterList::new(1, &[dir_a.to_str().unwrap().to_owned()], Some(VOL_ALIAS)).unwrap();

        let cancel = AtomicBool::new(true);
        assert!(filter
            .update(&[dir_b.to_str().unwrap().to_owned()], Some(NEXT_ALIAS), Some(&cancel))
            .is_err());
        match filter.root_lookup(&cstr(VOL_ALIAS.as_bytes())) {
            RootLookup::Allowed((path, _, _)) => assert_eq!(path, dir_a.to_str().unwrap()),
            other => panic!("cancelled update changed the filter: {:?}", other),
        }

        fs::remove_dir_all(&dir_a).unwrap();
        fs::remove_dir_all(&dir_b).unwrap();
    }

    #[test]
    fn test_filter_non_utf8_name_is_denied_not_panic() {
        // Regression: a non-UTF-8 file name at the root used to hit
        // `to_str().unwrap()` and take down the VMM (with the filter lock
        // poisoned for every later request). It must be denied instead.
        let dir_a = temp_dir("nonutf8");
        let filter =
            FilterList::new(1, &[dir_a.to_str().unwrap().to_owned()], Some(VOL_ALIAS)).unwrap();

        assert!(matches!(
            filter.root_lookup(&cstr(b"\xff\xfe invalid-utf8")),
            RootLookup::Denied
        ));

        fs::remove_dir_all(&dir_a).unwrap();
    }

    #[test]
    fn test_filter_one_alias_names_exactly_one_export() {
        // The alias is a per-generation capability name for ONE export: a
        // multi-entry list could not be addressed by a single mount alias
        // and is refused. The same host dir listed twice dedups to one
        // entry, so one alias still names exactly one directory.
        let parent1 = temp_dir("collide-p1");
        let parent2 = temp_dir("collide-p2");
        let dir1 = parent1.join("agent");
        let dir2 = parent2.join("agent");
        fs::create_dir_all(&dir1).unwrap();
        fs::create_dir_all(&dir2).unwrap();

        let res = FilterList::new(
            1,
            &[
                dir1.to_str().unwrap().to_owned(),
                dir2.to_str().unwrap().to_owned(),
            ],
            Some(VOL_ALIAS),
        );
        assert!(res.is_err(), "a multi-entry export must be refused");

        let filter2 = FilterList::new(
            1,
            &[
                dir1.to_str().unwrap().to_owned(),
                dir1.to_str().unwrap().to_owned(),
            ],
            Some(VOL_ALIAS),
        )
        .unwrap();
        assert_eq!(filter2.get_root_dirents().len(), 3); // ".", "..", alias
        match filter2.root_lookup(&cstr(VOL_ALIAS.as_bytes())) {
            RootLookup::Allowed((path, _, _)) => assert_eq!(path, dir1.to_str().unwrap()),
            other => panic!("expected Allowed, got {:?}", other),
        }

        fs::remove_dir_all(&parent1).unwrap();
        fs::remove_dir_all(&parent2).unwrap();
    }

    #[test]
    fn test_get_basename_from_path() {
        assert_eq!(get_basename_from_path("/vol/agent-a"), Some("agent-a"));
        // Trailing slash is normalized away.
        assert_eq!(get_basename_from_path("/vol/agent-a/"), Some("agent-a"));
        assert_eq!(get_basename_from_path("agent-a"), Some("agent-a"));
        // No file_name component: dropped at init time (warn + skip), never
        // exported as a whitelist key.
        assert_eq!(get_basename_from_path("/"), None);
        assert_eq!(get_basename_from_path(".."), None);
    }
}

/// the allow-list is a NAMESPACE control at the share root, not just a
/// visibility filter. These tests drive the REAL dispatch (`handle_message`,
/// the same entry the production device calls from
/// `virtio-devices/src/fs.rs`) with hand-built FUSE requests whose parent is
/// the share root, over a real `PassthroughFs` rooted at a temp directory —
/// so the assertions are about bytes on disk, not about a helper's opinion.
#[cfg(test)]
mod root_gate_tests {
    use super::*;
    use crate::fs_cache_req_handler::FsCacheReqHandler;
    use crate::passthrough::{Config as PtConfig, PassthroughFs};
    use std::fs;
    use std::io;
    use std::os::raw::c_int as RawFd;
    use virtio_queue::mock::MockSplitQueue;
    use virtio_queue::Descriptor;
    use vm_memory::bitmap::AtomicBitmap;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    /// Same shape as the sibling module's helper (each test module owns its
    /// fixture namespace).
    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sandswap-virtiofsd-rootgate-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const VIRTQ_DESC_F_NEXT: u16 = 1;
    const VIRTQ_DESC_F_WRITE: u16 = 2;
    const REQ_ADDR: u64 = 0x1000;
    const RESP_ADDR: u64 = 0x8000;
    const RESP_LEN: u32 = 4096;

    /// The root gate never reaches the DAX path; a no-op cache handler keeps
    /// the harness honest about what is exercised.
    struct NoDax;
    impl FsCacheReqHandler for NoDax {
        fn map(&mut self, _: u64, _: u64, _: u64, _: u64, _: RawFd) -> io::Result<()> {
            Ok(())
        }
        fn unmap(&mut self, _: Vec<crate::fuse::RemovemappingOne>) -> io::Result<()> {
            Ok(())
        }
    }

    struct Harness {
        mem: GuestMemoryMmap<AtomicBitmap>,
        server: Server<PassthroughFs>,
    }

    impl Harness {
        fn new(root: &std::path::Path, allowed: &[&str]) -> Self {
            let fs = PassthroughFs::new(PtConfig {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            })
            .expect("PassthroughFs::new");
            fs.open_root_node().expect("open_root_node");
            let dirs: Vec<String> = allowed.iter().map(|s| s.to_string()).collect();
            let alias = if dirs.is_empty() { None } else { Some(VOL_ALIAS) };
            let server = Server::new(fs, &dirs, alias)
                .expect("Server::new (allow-list init)");
            Harness {
                mem: GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(GuestAddress(0), 0x1_0000)])
                    .unwrap(),
                server,
            }
        }

        /// send one FUSE request whose descriptor chain carries NO
        /// writable region at all (a hostile guest kernel can post any chain)
        /// and report whether the dispatch survived without unwinding. The
        /// reply itself cannot be written where the guest left no room, so
        /// the pin is "no panic", not a particular errno — a panic here is
        /// what took down the server thread and the VMM with it.
        fn call_without_writable_region(
            &self,
            opcode: Opcode,
            nodeid: u64,
            payload: &[u8],
        ) -> bool {
            let mut req = Vec::new();
            let hdr = InHeader {
                len: (std::mem::size_of::<InHeader>() + payload.len()) as u32,
                opcode: opcode as u32,
                unique: 42,
                nodeid,
                uid: 0,
                gid: 0,
                pid: 1,
                total_extlen: 0,
                padding: 0,
            };
            req.extend_from_slice(hdr.as_slice());
            req.extend_from_slice(payload);
            self.mem
                .write_slice(&req, GuestAddress(REQ_ADDR))
                .expect("write request");

            let queue = MockSplitQueue::new(&self.mem, 16);
            let chain = queue
                .build_desc_chain(&[Descriptor::new(REQ_ADDR, req.len() as u32, 0, 0)])
                .expect("build_desc_chain");
            let reader = Reader::new(&self.mem, chain.clone()).expect("Reader::new");
            let writer = Writer::new(&self.mem, chain).expect("Writer::new");

            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut reduction = BucketReduction::Success;
                let mut token = TokenType::Ops;
                // The write of the error reply itself fails on a zero-length
                // region (WriteZero), which handle_message reports as Err —
                // expected and irrelevant; the pin is that it RETURNS.
                let _ = self.server.handle_message(
                    reader,
                    writer,
                    None::<&mut NoDax>,
                    &mut None,
                    &mut reduction,
                    &mut token,
                );
            }))
            .is_ok()
        }

        /// Send one FUSE request with the given parent inode and payload;
        /// return (error, reply body) where the body starts after OutHeader.
        fn call(&self, opcode: Opcode, nodeid: u64, payload: &[u8]) -> (i32, Vec<u8>) {
            let mut req = Vec::new();
            let hdr = InHeader {
                len: (std::mem::size_of::<InHeader>() + payload.len()) as u32,
                opcode: opcode as u32,
                unique: 42,
                nodeid,
                uid: 0,
                gid: 0,
                pid: 1,
                total_extlen: 0,
                padding: 0,
            };
            req.extend_from_slice(hdr.as_slice());
            req.extend_from_slice(payload);
            self.mem
                .write_slice(&req, GuestAddress(REQ_ADDR))
                .expect("write request");
            self.mem
                .write_slice(&vec![0u8; RESP_LEN as usize], GuestAddress(RESP_ADDR))
                .expect("clear reply");

            let queue = MockSplitQueue::new(&self.mem, 16);
            let chain = queue
                .build_desc_chain(&[
                    Descriptor::new(REQ_ADDR, req.len() as u32, VIRTQ_DESC_F_NEXT, 1),
                    Descriptor::new(RESP_ADDR, RESP_LEN, VIRTQ_DESC_F_WRITE, 0),
                ])
                .expect("build_desc_chain");
            let reader = Reader::new(&self.mem, chain.clone()).expect("Reader::new");
            let writer = Writer::new(&self.mem, chain).expect("Writer::new");

            let mut reduction = BucketReduction::Success;
            let mut token = TokenType::Ops;
            self.server
                .handle_message(
                    reader,
                    writer,
                    None::<&mut NoDax>,
                    &mut None,
                    &mut reduction,
                    &mut token,
                )
                .expect("handle_message");

            let out: OutHeader = self.mem.read_obj(GuestAddress(RESP_ADDR)).expect("read OutHeader");
            let body_len = (out.len as usize).saturating_sub(std::mem::size_of::<OutHeader>());
            let mut body = vec![0u8; body_len];
            self.mem
                .read_slice(&mut body, GuestAddress(RESP_ADDR + std::mem::size_of::<OutHeader>() as u64))
                .expect("read body");
            (out.error, body)
        }
    }

    /// The canonical guest-visible alias for the single allowed directory
    /// (FilterList presentation contract).
    const VOL_ALIAS: &str = "gen0";
    /// The alias a later generation (set-fs swap) may use; reuse of
    /// VOL_ALIAS would be refused by the filter.
    const NEXT_ALIAS: &str = "gen1";

    fn name_payload(name: &str) -> Vec<u8> {
        let mut v = name.as_bytes().to_vec();
        v.push(0);
        v
    }

    fn with_struct<T: ByteValued + Default>(name: &str) -> Vec<u8> {
        let mut v = T::default().as_slice().to_vec();
        v.extend_from_slice(&name_payload(name));
        v
    }

    /// The share root: one whitelisted agent dir + a sibling that is NOT
    /// whitelisted, holding data that must survive every attempt below.
    fn fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let root = temp_dir(tag);
        let allowed = root.join("agent-a");
        let sibling = root.join("agent-b");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("keep.txt"), b"victim-data").unwrap();
        (root, allowed, sibling)
    }

    fn root_entries(root: &std::path::Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// a guest-supplied NAME must be ONE path component. The FUSE
    /// protocol only ever carries one, so anything else is hostile — and it
    /// reaches the host untouched (`openat`/`unlinkat`/`mkdirat` resolve `..`
    /// against the REAL filesystem). Measured before the fix, with the parent
    /// INSIDE the whitelisted directory (so the share-root gate does not
    /// apply): create/unlink/rmdir with a "../…" name all SUCCEEDED —
    /// `unlink(agent-a, "../agent-b/keep.txt")` deleted a sibling tenant's
    /// file. Upstream virtiofsd leaves names unvalidated too but contains the
    /// blast radius with its process sandbox (`--sandbox`/chroot); sandswap
    /// runs this code in-process with no sandbox, so the escape lands on the
    /// pin: statfs at the share root is denied (was: the real host
    /// fstatvfs of the volumes filesystem leaked to every guest). RED with
    /// the root_gate_denies Statfs arm removed.
    #[test]
    fn test_statfs_at_root_is_denied() {
        let (root, allowed, _sibling) = fixture("statfs-root");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        let (err, _) = h.call(Opcode::Statfs, ROOT_ID, &[]);
        assert_eq!(err, -libc::ENOENT, "statfs at the root must answer ENOENT (hidden)");
        // Control: statfs on a REAL inode (the allowed dir) still works.
        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0);
        let a_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let (err2, _) = h.call(Opcode::Statfs, a_id, &[]);
        assert_eq!(err2, 0, "statfs on a mounted subdirectory must stay served");
    }

    /// regression pin: TmpFile (O_TMPFILE) creates an inode in the parent
    /// directory, so it is root-mutating even without a name operand. The
    /// passthrough does not implement tmpfile() yet (ENOSYS), which is why
    /// the gate must not rely on the handler: a later implementation would
    /// otherwise mint anonymous inodes in the shared root — host disk
    /// consumed by an object no cleanup path can see. RED with the TmpFile
    /// row moved back to the allow arm.
    #[test]
    fn test_tmpfile_refused_at_share_root_and_gate_pinned() {
        let (root, allowed, _sibling) = fixture("tmpfile-root-gate");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        let before = root_entries(&root);

        // The classification itself: pins the gate before any tmpfile()
        // implementation exists.
        assert!(
            root_gate_denies(Opcode::TmpFile),
            "TmpFile must be root-gated: it CREATES an inode in the parent"
        );

        // Real request at the share root: answered hidden (ENOENT), like the
        // other root-mutating ops, and the host tree is untouched.
        let (err, _) = h.call(Opcode::TmpFile, ROOT_ID, &[]);
        assert_eq!(
            err,
            -libc::ENOENT,
            "TmpFile at the share root must answer ENOENT (hidden)"
        );

        // Control: below the root the opcode is NOT gate-refused — it reaches
        // the handler, which answers ENOSYS because the passthrough has no
        // tmpfile() implementation (the gate is root-scoped, not a blanket
        // denial of O_TMPFILE inside a volume).
        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0);
        let a_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let (err2, _) = h.call(Opcode::TmpFile, a_id, &[]);
        assert_eq!(
            err2,
            -libc::ENOSYS,
            "an in-share TmpFile must reach the handler, not the root gate"
        );

        assert_eq!(root_entries(&root), before, "the root tree must be unchanged");
    }

    /// The allow-list DESCRIPTOR, not the path, is the authorization: after
    /// set-fs the exported directory can be renamed away and replaced by a
    /// symlink, and the root lookup must still serve the PINNED object. RED
    /// with the path re-resolved at lookup time (O_NOFOLLOW then answers
    /// ELOOP against the planted link, so the volume disappears).
    #[test]
    fn test_root_lookup_serves_the_pinned_object() {
        let (root, allowed, sibling) = fixture("pinned-fd");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);

        // Swap the authorized directory for a symlink AFTER the filter pinned
        // its descriptor.
        let moved = root.join("agent-a-moved");
        fs::rename(&allowed, &moved).unwrap();
        std::os::unix::fs::symlink(&sibling, &allowed).unwrap();

        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(
            err, 0,
            "the root lookup must use the descriptor pinned at set-fs time, not re-resolve the path"
        );
        assert!(
            fs::symlink_metadata(&allowed).unwrap().file_type().is_symlink(),
            "control: the on-disk path must really be a symlink after the swap"
        );
    }

    /// regression pin: a guest-posted chain with NO writable region must be
    /// ANSWERED, never panic the server thread. The three sites were
    /// `w.split_at(size_of::<OutHeader>()).unwrap()` in `read()`, `readdir()`
    /// and `readdirplus()`; a panic there ran through the thread helper's
    /// exit event and took the whole VMM (every VM on the node) down.
    /// readdir/readdirplus are driven with `size == 0`, which passes the
    /// available_bytes() guard and still needs the header's bytes. RED with
    /// any of the three checked branches reverted to `.unwrap()`.
    #[test]
    fn test_short_writable_region_never_panics() {
        let (root, allowed, _sibling) = fixture("short-writable");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        let read_in = ReadIn::default().as_slice().to_vec();
        for opcode in [Opcode::Read, Opcode::Readdir, Opcode::Readdirplus] {
            assert!(
                h.call_without_writable_region(opcode, 1, &read_in),
                "{:?} with no writable region panicked the dispatch",
                opcode
            );
        }
    }

    /// regression pin: Syncfs is refused at the share ROOT and on an IN-SHARE
    /// inode alike. The passthrough's implementation is `libc::syncfs(fd)` —
    /// filesystem-wide — so an in-share nodeid forces exactly the same
    /// host-wide writeback as the root one; leaving either reachable lets
    /// any guest drive node-wide I/O at will. RED with the handler restored
    /// (both calls answer 0).
    #[test]
    fn test_syncfs_refused_everywhere() {
        let (root, allowed, _sibling) = fixture("syncfs-refuse");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);

        let (err, _) = h.call(Opcode::Syncfs, ROOT_ID, &[]);
        assert_eq!(
            err,
            -libc::ENOENT,
            "syncfs at the share root must be refused as hidden"
        );

        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0);
        let a_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let (err2, _) = h.call(Opcode::Syncfs, a_id, &[]);
        assert_eq!(
            err2,
            -libc::ENOSYS,
            "an in-share syncfs must be refused too (libc::syncfs is filesystem-wide)"
        );

        // Control: Fsync on the same inode still needs a real handle, but
        // the opcode itself is NOT root-gated — the refusal is specific to
        // the filesystem-wide Syncfs (this asserts the gate did not turn
        // into a blanket freeze of the sync family).
        assert!(
            !root_gate_denies(Opcode::Fsync),
            "Fsync must stay served (per-file durability)"
        );
        assert!(root_gate_denies(Opcode::Syncfs));
    }

    /// pin: a NON-directory whitelist entry must be refused at
    /// FilterList init (was: accepted and announced to the guest as DT_DIR).
    /// RED with the S_ISDIR check removed.
    #[test]
    fn test_filter_list_rejects_non_directory_entries() {
        let (root, _allowed, _sibling) = fixture("nondir-filter");
        let plain = root.join("not-a-dir");
        std::fs::write(&plain, b"x").unwrap();
        let res = FilterList::new(ROOT_ID, &[plain.to_str().unwrap().to_string()], Some(VOL_ALIAS));
        // The entry must be silently DROPPED (warn), leaving an empty
        // fail-closed filter — a file can never become a root export.
        match res {
            Ok(f) => {
                assert!(
                    f.get_allow_dir("not-a-dir").is_err(),
                    "a file entry entered the export map "
                );
            }
            Err(_) => {} // refusing outright is equally acceptable
        }
    }

    /// pin: vm.set-fs must revoke the previous agent's inodes and
    /// open handles atomically with the allow-list swap. Inode-scoped ops
    /// consult no filter, so a nodeid that survives the swap is a
    /// cross-tenant read/write primitive by nodeid on a reused VM.
    /// RED with revoke_agent_state disabled: the stale getattr succeeds.
    #[test]
    fn test_set_fs_revokes_stale_inodes() {
        let (root, allowed, agent_b) = fixture("revoke-inodes");
        std::fs::write(agent_b.join("b-secret.txt"), b"agent-B-secret").unwrap();
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);

        // Establish agent-a's inode (Lookup root -> agent-a -> a file).
        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0);
        let a_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        std::fs::write(allowed.join("a-secret.txt"), b"agent-A-secret").unwrap();
        let (err, body) = h.call(Opcode::Lookup, a_id, &name_payload("a-secret.txt"));
        assert_eq!(err, 0);
        let a_file = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let (err, _) = h.call(Opcode::Getattr, a_file, &GetattrIn::default().as_slice().to_vec());
        assert_eq!(err, 0, "pre-swap sanity: agent-a inode serves");

        // The guest released its references: the documented sequence is
        // umount → FORGETs land → set-fs, and the reuse tripwire refuses a
        // swap while un-FORGOTTEN references remain (see the dedicated
        // tripwire test below), so the forgets are part of the sequence this
        // test models. Forget has no reply — the return is ignored.
        let _ = h.call(Opcode::Forget, a_file, &ForgetIn { nlookup: 1 }.as_slice().to_vec());
        let _ = h.call(Opcode::Forget, a_id, &ForgetIn { nlookup: 1 }.as_slice().to_vec());

        // Switch the share to agent-b (the documented sequence: umount →
        // set-fs → bind; the revoke is atomic with the swap).
        h.server
            .update_filter(&[agent_b.to_str().unwrap().to_string()], Some(NEXT_ALIAS))
            .expect("update_filter");

        // The previous agent's nodeid is DEAD — getattr must fail (ebadf→EIO),
        // never serve the stale inode.
        let (err, _) = h.call(Opcode::Getattr, a_file, &GetattrIn::default().as_slice().to_vec());
        assert_ne!(err, 0, "ESCAPE: stale inode survived the set-fs swap");

        // The revoke must not wedge the share for the NEXT agent, with NO
        // manual root re-init: production has none. The /mnt/volumes FUSE
        // connection is established once per VM and agent switches never
        // re-INIT, so the root nodeid must survive the revoke itself
        // (a full clear makes this exact Lookup answer EBADF and every
        // post-switch mount(2) fail).
        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(NEXT_ALIAS));
        assert_eq!(err, 0, "post-swap root Lookup must succeed without a re-init (root must survive the revoke)");
        let b_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let (err, _) = h.call(Opcode::Getattr, b_id, &GetattrIn::default().as_slice().to_vec());
        assert_eq!(err, 0);
    }

    /// REUSE TRIPWIRE: a vm.set-fs that would swap away a LIVE export must
    /// be REFUSED while the guest still holds references into it — the
    /// device-side answer to a lying unmount reply (a process alive inside
    /// the volume pins its dentries; the warden claimed they were gone).
    /// RED with the tripwire check removed: the swap succeeds silently.
    #[test]
    fn test_set_fs_refuses_while_previous_tenant_holds_references() {
        let (root, allowed, agent_b) = fixture("tripwire-refs");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);

        // Agent-a's presence: leaked lookup references (one per successful
        // LOOKUP reply — the guest kernel's dentry pins).
        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0);
        let a_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        std::fs::write(allowed.join("a-secret.txt"), b"x").unwrap();
        let (err, body) = h.call(Opcode::Lookup, a_id, &name_payload("a-secret.txt"));
        assert_eq!(err, 0);
        let _a_file = u64::from_le_bytes(body[0..8].try_into().unwrap());

        // The swap to agent-b is refused BY NAME, with the counts, and the
        // LIVE allow-list is untouched (no swap, no revoke happened).
        let err = h
            .server
            .update_filter(&[agent_b.to_str().unwrap().to_string()], Some(NEXT_ALIAS))
            .expect_err("swap with live references must be refused");
        match err {
            Error::PreviousTenantRefs { handles, inode_refs } => {
                assert_eq!(handles, 0, "no files were opened in this test");
                assert!(inode_refs >= 2, "two leaked lookups must be counted, got {}", inode_refs);
            }
            other => panic!("expected PreviousTenantRefs, got {:?}", other),
        }
        // Old export still live and still serving: the refusal must not have
        // revoked anything either.
        let (err, _) = h.call(Opcode::Getattr, a_id, &GetattrIn::default().as_slice().to_vec());
        assert_eq!(err, 0, "the refused swap must leave the old export untouched");
        let filter = h.server.root_filter.lock().unwrap();
        assert_eq!(
            filter.get_allow_dir(VOL_ALIAS).unwrap().0,
            allowed.to_string_lossy().into_owned(),
            "the live allow-list must still name the OLD export"
        );
        drop(filter);

        // Release the references (the guest's umount path): the same swap now
        // succeeds — the tripwire is a gate on liveness, not a deadlock.
        // Forget has no reply; returns ignored.
        let _ = h.call(Opcode::Forget, _a_file, &ForgetIn { nlookup: 1 }.as_slice().to_vec());
        let _ = h.call(Opcode::Forget, a_id, &ForgetIn { nlookup: 1 }.as_slice().to_vec());
        h.server
            .update_filter(&[agent_b.to_str().unwrap().to_string()], Some(NEXT_ALIAS))
            .expect("swap must succeed once the references are released");
    }

    /// The tripwire's first-attach exemption: a VM whose live allow-list is
    /// EMPTY (fresh boot, nothing exported yet) must not be gated — there is
    /// Root readdir's "." entry must report the FUSE root nodeid, not the
    /// backing filesystem's inode (an unnecessary host-side leak).
    #[test]
    fn test_root_dot_dirent_uses_root_id() {
        let filter = FilterList::new(crate::fuse::ROOT_ID, &[], None).unwrap();
        let entries = filter.get_root_dirents();
        assert!(!entries.is_empty());
        assert_eq!(entries[0].name, ".");
        assert_eq!(entries[0].ino, crate::fuse::ROOT_ID);
    }

    /// The alias history is the WHOLE lifetime, not just the previous
    /// generation: A→B→A must refuse A. With only the last alias checked, a
    /// late mount from the original generation A would resolve against the
    /// new export instead of failing ENOENT.
    #[test]
    fn test_alias_replay_is_refused_across_generations() {
        let (root, allowed, agent_b) = fixture("alias-replay");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        h.server
            .update_filter(&[agent_b.to_str().unwrap().to_string()], Some(NEXT_ALIAS))
            .expect("gen1 with a fresh alias");

        let err = h
            .server
            .update_filter(&[allowed.to_str().unwrap().to_string()], Some(VOL_ALIAS))
            .expect_err("gen2 reusing gen0's alias must be refused");
        assert!(
            format!("{err:?}").contains("already used"),
            "unexpected refusal: {:?}",
            err
        );
        // The refused update did not half-apply: gen1's alias still resolves,
        // the replayed one is gone.
        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(NEXT_ALIAS));
        assert_eq!(err, 0, "gen1 alias must stay live after the refusal");
        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, -libc::ENOENT, "replayed alias must not resolve");
    }

    /// no previous tenant whose references could matter.
    #[test]
    fn test_set_fs_first_attach_is_not_gated() {
        let (root, allowed, _agent_b) = fixture("tripwire-first");
        // Empty allow-list: the fail-closed CLEAN state of a fresh VM.
        let h = Harness::new(&root, &[]);
        // A stray reference exists (a root lookup that leaked, e.g. boot-time
        // probing) — it belongs to NO export, so it must not block the first
        // attach.
        let _ = h.call(Opcode::Lookup, ROOT_ID, &name_payload("anything"));
        h.server
            .update_filter(&[allowed.to_str().unwrap().to_string()], Some(VOL_ALIAS))
            .expect("first attach must not be gated by the tripwire");
    }

    /// host as the FUSE daemon's uid (a member of the shared storage group).
    #[test]
    fn test_name_validation_blocks_path_escape() {
        let (root, allowed, sibling) = fixture("name-escape");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0);
        let allowed_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let before = root_entries(&root);

        // Every guest-supplied name that is not a single component is ENOENT,
        // whatever the parent is.
        for bad in [
            "..",
            ".",
            "../agent-b",
            "../agent-b/keep.txt",
            "evil/../../agent-b",
            "x/y",
            "",
        ] {
            let (err, _) = h.call(Opcode::Lookup, allowed_id, &name_payload(bad));
            assert_eq!(err, -libc::ENOENT, "lookup({bad:?}) must be denied");
        }
        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(".."));
        assert_eq!(err, -libc::ENOENT, "lookup at the root must stay denied too");

        // The mutating class, from INSIDE the whitelisted dir.
        // SETXATTR_EXT is off in this harness, so the payload starts with the
        // 8-byte compat struct (size, flags) followed by name\0 + value.
        let mut sym = vec![];
        sym.extend_from_slice(&SetxattrInCompat { size: 1, flags: 0 }.as_slice());
        sym.extend_from_slice(&name_payload("../agent-b/keep.txt"));
        sym.push(b'v');
        let cases: Vec<(Opcode, Vec<u8>)> = vec![
            (Opcode::Mkdir, with_struct::<MkdirIn>("../escaped-dir")),
            (Opcode::Create, with_struct::<CreateIn>("../escaped-file")),
            (Opcode::Mknod, with_struct::<MknodIn>("../escaped-node")),
            (
                Opcode::Symlink,
                {
                    let mut v = name_payload("../escaped-link");
                    v.extend_from_slice(&name_payload("/etc/hostname"));
                    v
                },
            ),
            (Opcode::Unlink, name_payload("../agent-b/keep.txt")),
            (Opcode::Rmdir, name_payload("../agent-b")),
            (Opcode::Setxattr, sym),
        ];
        for (op, payload) in cases {
            let (err, _) = h.call(op, allowed_id, &payload);
            assert_eq!(err, -libc::ENOENT, "op {op:?} with a ../ name must be denied");
        }
        // Rename: both names validated.
        let mut p = RenameIn { newdir: ROOT_ID }.as_slice().to_vec();
        p.extend_from_slice(&name_payload("../agent-b"));
        p.extend_from_slice(&name_payload("gone"));
        assert_eq!(h.call(Opcode::Rename, allowed_id, &p).0, -libc::ENOENT);
        let mut p = RenameIn { newdir: ROOT_ID }.as_slice().to_vec();
        p.extend_from_slice(&name_payload("inner"));
        p.extend_from_slice(&name_payload("../escaped"));
        assert_eq!(h.call(Opcode::Rename, allowed_id, &p).0, -libc::ENOENT);

        // Nothing moved, nothing was destroyed.
        assert_eq!(root_entries(&root), before, "the share root changed");
        assert_eq!(
            fs::read(sibling.join("keep.txt")).unwrap(),
            b"victim-data",
            "the sibling tenant's data was damaged"
        );
        // And the same opcodes with a LEGAL name still work (the check is a
        // single-component rule, not a blanket denial).
        let (err, _) = h.call(Opcode::Mkdir, allowed_id, &with_struct::<MkdirIn>("legal-sub"));
        assert_eq!(err, 0, "a legal single-component name must still work");
        assert!(allowed.join("legal-sub").is_dir());
    }

    #[test]
    fn test_root_lookup_and_readdir_are_the_only_visible_surface() {
        let (root, allowed, _sibling) = fixture("gate-controls");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);

        // Control: the whitelisted name resolves (the gate is not a blanket deny).
        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0, "whitelisted root lookup must succeed");
        // ...and its inode is usable as a parent for later ops.
        let nodeid = u64::from_le_bytes(body[0..8].try_into().unwrap());
        assert!(nodeid > ROOT_ID);

        // ALIAS PIN: the ACTIVE volume's real basename must itself read as
        // ENOENT — the guest can spell only the alias, so no path, listing or
        // mountinfo field can ever carry the real (secret) name.
        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload("agent-a"));
        assert_eq!(err, -libc::ENOENT, "the real volume basename must be invisible at the share root");
        // The sibling is denied AS ENOENT — indistinguishable from a
        // non-existent name. This is the oracle pin: the deny path used to
        // answer EIO (ErrorKind::NotFound carries no raw errno), which told a
        // guest that the name EXISTS but is filtered.
        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload("agent-b"));
        assert_eq!(err, -libc::ENOENT, "a hidden sibling must read as non-existent");
        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload("no-such-name"));
        assert_eq!(err, -libc::ENOENT, "a genuinely absent name reads the same way");
    }

    #[test]
    fn test_root_level_mutating_ops_are_denied_and_touch_nothing() {
        for tag in ["mkdir", "mknod", "create", "unlink", "rmdir", "symlink", "link", "setxattr"] {
            let (root, allowed, sibling) = fixture(&format!("gate-{tag}"));
            let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
            let before = root_entries(&root);

            let (opcode, payload) = match tag {
                "mkdir" => (Opcode::Mkdir, with_struct::<MkdirIn>("new-dir")),
                "mknod" => (Opcode::Mknod, with_struct::<MknodIn>("new-node")),
                "create" => (Opcode::Create, with_struct::<CreateIn>("new-file")),
                // Acting on a REAL sibling entry: the strongest form — the
                // data is there, and the op must not reach it.
                "unlink" => (Opcode::Unlink, name_payload("agent-b/keep.txt")),
                "rmdir" => (Opcode::Rmdir, name_payload("agent-b")),
                "symlink" => (Opcode::Symlink, name_payload("new-link")),
                "link" => (Opcode::Link, with_struct::<LinkIn>("new-hardlink")),
                "setxattr" => (Opcode::Setxattr, with_struct::<SetxattrIn>("agent-b/keep.txt")),
                // Nodeid-scoped mutation of the export root itself
                // (chmod/chown/utimens on the parent of every tenant volume).
                "setattr" => (Opcode::Setattr, with_struct::<SetattrIn>("new-name")),
                other => panic!("unhandled {}", other),
            };

            let (err, _) = h.call(opcode, ROOT_ID, &payload);
            assert_eq!(
                err,
                -libc::ENOENT,
                "{tag} at the share root must be denied as ENOENT (got {err})"
            );

            // The side effect must not have happened: same entries, same data.
            assert_eq!(root_entries(&root), before, "{tag} changed the share root");
            assert_eq!(
                fs::read(sibling.join("keep.txt")).unwrap(),
                b"victim-data",
                "{tag} damaged the sibling's data"
            );
        }

        // Rename is the two-parent case: gated at the dispatch site for the
        // OLD parent and inside do_rename for the NEW one. BOTH opcodes:
        // Rename2 (45) has its own handler and was NOT covered by the first
        // version of this gate.
        let (root, allowed, sibling) = fixture("gate-rename");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        let before = root_entries(&root);

        // old parent = root, new parent = root
        let mut payload = RenameIn { newdir: ROOT_ID }.as_slice().to_vec();
        payload.extend_from_slice(&name_payload("agent-b"));
        payload.extend_from_slice(&name_payload("moved"));
        let (err, _) = h.call(Opcode::Rename, ROOT_ID, &payload);
        assert_eq!(err, -libc::ENOENT, "rename out of the share root must be denied");

        // old parent = a whitelisted dir, new parent = root: only the second
        // check catches this one.
        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0);
        let allowed_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let mut payload = RenameIn { newdir: ROOT_ID }.as_slice().to_vec();
        payload.extend_from_slice(&name_payload("inner"));
        payload.extend_from_slice(&name_payload("escaped"));
        let (err, _) = h.call(Opcode::Rename, allowed_id, &payload);
        assert_eq!(
            err,
            -libc::ENOENT,
            "rename INTO the share root must be denied (second-parent gate)"
        );

        assert_eq!(root_entries(&root), before, "rename changed the share root");
        assert!(sibling.join("keep.txt").exists());

        // Rename2: the same two gated directions, through its own handler.
        let mut payload = Rename2In { newdir: allowed_id, flags: 0, padding: 0 }.as_slice().to_vec();
        payload.extend_from_slice(&name_payload("agent-b"));
        payload.extend_from_slice(&name_payload("moved"));
        let (err, _) = h.call(Opcode::Rename2, ROOT_ID, &payload);
        assert_eq!(err, -libc::ENOENT, "Rename2 out of the share root must be denied");
        let mut payload = Rename2In { newdir: ROOT_ID, flags: 0, padding: 0 }.as_slice().to_vec();
        payload.extend_from_slice(&name_payload("inner"));
        payload.extend_from_slice(&name_payload("escaped"));
        let (err, _) = h.call(Opcode::Rename2, allowed_id, &payload);
        assert_eq!(err, -libc::ENOENT, "Rename2 INTO the share root must be denied");
        assert_eq!(root_entries(&root), before, "Rename2 changed the share root");
        assert!(sibling.join("keep.txt").exists(), "Rename2 moved the sibling's data");
    }

    /// The share root is the persistent transport anchor for the VM's
    /// /mnt/volumes mount. A guest-forged FORGET(ROOT_ID) / BatchForget root
    /// entry / DESTROY must not evict it — otherwise every later path walk
    /// (including the NEXT tenant's mount) fails EBADF and the VM is wedged.
    #[test]
    fn test_guest_cannot_forget_or_destroy_the_share_root() {
        let (root, allowed, _sibling) = fixture("root-pin");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);

        // Single FORGET with a count that would saturate the root refcount.
        let payload = ForgetIn { nlookup: u64::MAX }.as_slice().to_vec();
        let (err, _) = h.call(Opcode::Forget, ROOT_ID, &payload);
        assert_eq!(err, 0);
        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0, "FORGET(ROOT_ID) must not evict the share root");

        // BatchForget carries the same protection.
        let mut payload = BatchForgetIn { count: 1, dummy: 0 }.as_slice().to_vec();
        payload.extend_from_slice(
            &ForgetOne {
                nodeid: ROOT_ID,
                nlookup: u64::MAX,
            }
            .as_slice(),
        );
        let (err, _) = h.call(Opcode::BatchForget, ROOT_ID, &payload);
        assert_eq!(err, 0);
        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(
            err, 0,
            "BatchForget(ROOT_ID) must not evict the share root"
        );

        // DESTROY (the warden never unmounts the share) keeps the root too.
        let (err, _) = h.call(Opcode::Destroy, ROOT_ID, &[]);
        assert_eq!(err, 0);
        let (err, _) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0, "DESTROY must not wedge the next tenant's mount");
    }

    /// update_filter must take the same lock root lookups hold across
    /// their allow-list snapshot AND inode insertion. Holding it here proves
    /// the swap+revoke cannot run in the middle of a lookup.
    #[test]
    fn test_update_filter_takes_the_root_lookup_lock() {
        let (root, allowed, _sibling) = fixture("filter-lock");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        let guard = h.server.root_filter.as_ref().lock().unwrap();
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished_in_thread = finished.clone();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                h.server.update_filter(&[], None).unwrap();
                finished_in_thread.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert!(
                !finished.load(std::sync::atomic::Ordering::SeqCst),
                "update_filter must wait for the root-filter lock"
            );
            drop(guard);
        });
        assert!(
            finished.load(std::sync::atomic::Ordering::SeqCst),
            "update_filter must complete once the lock is released"
        );
    }

    /// completeness: every way a guest can spell a NAME, against every
    /// name-carrying opcode. Legal single-component names must still work
    /// (the rule is a component rule, not a blanket denial).
    #[test]
    fn test_name_spelling_matrix() {
        let (root, allowed, sibling) = fixture("names");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0);
        let a = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let before = root_entries(&root);

        // Hostile spellings: all must be ENOENT on every name-carrying op.
        let hostile: Vec<Vec<u8>> = vec![
            b"..".to_vec(),
            b".".to_vec(),
            b"../agent-b/keep.txt".to_vec(),
            b"sub/../../agent-b".to_vec(),
            b"/etc/passwd".to_vec(),
            b"//etc/passwd".to_vec(),
            b"x/".to_vec(),
            b"/".to_vec(),
            b"\x2e\x2e".to_vec(),          // literal backslash text, must be a LEGAL name (control below)
        ];
        let ops: Vec<(Opcode, fn(&str) -> Vec<u8>)> = vec![
            (Opcode::Lookup, |n| name_payload(n)),
            (Opcode::Mkdir, |n| with_struct::<MkdirIn>(n)),
            (Opcode::Create, |n| with_struct::<CreateIn>(n)),
            (Opcode::Mknod, |n| with_struct::<MknodIn>(n)),
            (Opcode::Unlink, |n| name_payload(n)),
            (Opcode::Rmdir, |n| name_payload(n)),
        ];
        for (op, mk) in &ops {
            for bad in &hostile {
                let name = String::from_utf8_lossy(bad).into_owned();
                if name == "\\x2e\\x2e" {
                    continue; // control handled below
                }
                let (err, _) = h.call(*op, a, &mk(&name));
                assert_eq!(err, -libc::ENOENT, "{op:?}({bad:?}) must be denied");
            }
        }
        // Rename: every hostile spelling in EITHER position.
        for bad in &hostile {
            let name = String::from_utf8_lossy(bad).into_owned();
            if name == "\\x2e\\x2e" {
                continue;
            }
            for (old, new) in [(bad.as_slice(), b"ok".as_slice()), (b"ok".as_slice(), bad.as_slice())] {
                let mut p = RenameIn { newdir: a }.as_slice().to_vec();
                p.extend_from_slice(&name_payload(std::str::from_utf8(old).unwrap()));
                p.extend_from_slice(&name_payload(std::str::from_utf8(new).unwrap()));
                assert_eq!(h.call(Opcode::Rename, a, &p).0, -libc::ENOENT);
            }
        }

        // LEGAL names that merely LOOK odd must still work: "...", a
        // backslash in the name, a 200-byte name, a non-UTF-8 byte.
        assert_eq!(h.call(Opcode::Mkdir, a, &with_struct::<MkdirIn>("...")).0, 0);
        assert!(allowed.join("...").is_dir());
        assert_eq!(h.call(Opcode::Mkdir, a, &with_struct::<MkdirIn>("a\\x2e\\x2e b")).0, 0);
        let long = "n".repeat(200);
        assert_eq!(h.call(Opcode::Mkdir, a, &with_struct::<MkdirIn>(&long)).0, 0);
        // Non-UTF-8 single component (raw bytes, not a string)
        let mut nb = vec![0x80u8, 0x81, 0x82];
        nb.push(0);
        assert_eq!(h.call(Opcode::Mkdir, a, {
            let mut v = MkdirIn::default().as_slice().to_vec();
            v.extend_from_slice(&nb);
            v
        }
        .as_slice()).0, 0, "a non-UTF-8 single component is a legal name");

        // Nothing appeared outside the agent's dir.
        assert_eq!(root_entries(&root), before, "the share root changed");
        assert!(sibling.join("keep.txt").exists());
    }

    /// completeness: the FILE-TYPE primitives — a symlink the guest
    /// planted must not be followed by the daemon, a hardlink to a directory
    /// must fail, and a device node must need CAP_MKNOD (the daemon has none).
    #[test]
    fn test_file_type_primitives() {
        let (root, allowed, sibling) = fixture("filetypes");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        let (_, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        let a = u64::from_le_bytes(body[0..8].try_into().unwrap());

        // 1. Plant a symlink INSIDE the agent dir pointing at the sibling.
        let mut sym = name_payload("planted-link");
        sym.extend_from_slice(&name_payload("../agent-b/keep.txt"));
        assert_eq!(h.call(Opcode::Symlink, a, &sym).0, 0, "legal symlink creation must work");
        assert!(allowed.join("planted-link").is_symlink());

        // 2. Resolve it through the daemon: the guest gets the SYMLINK (the
        //    kernel does the following through its own, filter-gated lookups).
        let (err, body) = h.call(Opcode::Lookup, a, &name_payload("planted-link"));
        assert_eq!(err, 0);
        let link_ino = u64::from_le_bytes(body[0..8].try_into().unwrap());
        // READLINK must return the planted text — proof the daemon treats the
        // inode as a symlink and never followed it on the host.
        let (err, body) = h.call(Opcode::Readlink, link_ino, &[]);
        assert_eq!(err, 0);
        let text = String::from_utf8_lossy(&body).trim_end_matches('\0').to_string();
        assert_eq!(text, "../agent-b/keep.txt");
        // GETATTR on that inode must report S_IFLNK (never the target's mode):
        // the reopen-through-/proc guard (`is_safe_inode`) only reopens
        // S_IFREG/S_IFDIR, so a symlink inode is handed back untouched.
        let (err, body) = h.call(Opcode::Getattr, link_ino, &GetattrIn::default().as_slice().to_vec());
        assert_eq!(err, 0);
        // AttrOut: attr_valid(8) attr_valid_nsec(4) padding(4) + Attr{ino,size,
        // blocks,atime,mtime,ctime = 48, then 3*4 nsec, then mode}
        let mode = u32::from_le_bytes(body[16 + 48 + 12..16 + 48 + 16].try_into().unwrap());
        assert_eq!(mode & libc::S_IFMT, libc::S_IFLNK, "daemon followed the symlink (mode={mode:o})");

        // 3. Hardlink to a DIRECTORY (the share root) must fail.
        let mut l = LinkIn { oldnodeid: ROOT_ID }.as_slice().to_vec();
        l.extend_from_slice(&name_payload("hardlinked-root"));
        let (err, _) = h.call(Opcode::Link, a, &l);
        assert_ne!(err, 0, "hardlinking a directory must fail");
        assert!(!allowed.join("hardlinked-root").exists());

        // 4. Device node. In PRODUCTION the daemon (sandvmm, uid 987) carries
        //    no capabilities at all — e2e/seccomp.sh pins CapEff to NET_ADMIN
        //    only — so mknod of a char device is EPERM, and the volumes mount
        //    is `nodev` regardless (storage contract row 9), making any node
        //    that did appear inert. A root-run unit harness holds CAP_MKNOD, so
        //    the assertion is profile-aware instead of pretending.
        let mut m = MknodIn {
            mode: libc::S_IFCHR | 0o666,
            rdev: 0x0101, // /dev/mem (1,1) — the classic target
            umask: 0,
            padding: 0,
        }
        .as_slice()
        .to_vec();
        m.extend_from_slice(&name_payload("evil-dev"));
        let (err, _) = h.call(Opcode::Mknod, a, &m);
        if unsafe { libc::geteuid() } == 0 {
            // Harness runs as root: creation succeeds here — the production
            // containment is the missing CAP_MKNOD (pinned by the identity e2e)
            // plus the nodev mount, not this code path.
            let _ = fs::remove_file(allowed.join("evil-dev"));
        } else {
            assert_ne!(err, 0, "mknod of a char device must fail without CAP_MKNOD");
        }

        // 5. A FIFO needs no capability: it is a LEGAL, inert entry (nodev has
        //    no bearing on FIFOs; it stays inside the agent's own directory).
        let mut fifo = MknodIn {
            mode: libc::S_IFIFO | 0o600,
            rdev: 0,
            umask: 0,
            padding: 0,
        }
        .as_slice()
        .to_vec();
        fifo.extend_from_slice(&name_payload("legal-fifo"));
        assert_eq!(h.call(Opcode::Mknod, a, &fifo).0, 0, "a FIFO inside the agent dir is legal");
        assert!(allowed.join("legal-fifo").exists());

        // 6. The sibling is untouched by any of it.
        assert_eq!(fs::read(sibling.join("keep.txt")).unwrap(), b"victim-data");
        assert_eq!(root_entries(&root), vec!["agent-a".to_string(), "agent-b".to_string()]);
    }

    #[test]
    fn test_mutating_ops_inside_the_whitelisted_dir_still_work() {
        // The gate must be ROOT-SCOPED: the same opcodes one level down are the
        // agent's normal filesystem and must keep working.
        let (root, allowed, _sibling) = fixture("gate-inside");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);

        let (err, body) = h.call(Opcode::Lookup, ROOT_ID, &name_payload(VOL_ALIAS));
        assert_eq!(err, 0);
        let allowed_id = u64::from_le_bytes(body[0..8].try_into().unwrap());

        let (err, body) = h.call(Opcode::Mkdir, allowed_id, &with_struct::<MkdirIn>("sub"));
        assert_eq!(err, 0, "mkdir inside the agent dir must succeed");
        let sub_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        assert!(allowed.join("sub").is_dir());

        let (err, _) = h.call(Opcode::Create, sub_id, &with_struct::<CreateIn>("f.txt"));
        assert_eq!(err, 0, "create inside the agent dir must succeed");
        assert!(allowed.join("sub/f.txt").is_file());

        let (err, _) = h.call(Opcode::Unlink, sub_id, &name_payload("f.txt"));
        assert_eq!(err, 0, "unlink inside the agent dir must succeed");
        let (err, _) = h.call(Opcode::Rmdir, allowed_id, &name_payload("sub"));
        assert_eq!(err, 0, "rmdir inside the agent dir must succeed");
        assert!(!allowed.join("sub").exists());
    }

    /// — the ONE host-side bound on how much work a single request can
    /// ask for, and therefore on how long any name can be.
    ///
    /// `handle_message` refuses a request whose header claims more than
    /// `MAX_BUFFER_SIZE + FUSE_BUFFER_HEADER_SIZE` (1 MiB + 4 KiB) *before*
    /// dispatching, so a name can never exceed that — no matter what the guest
    /// kernel is. That matters because the guest kernel's own limits
    /// (`PATH_MAX`, `NAME_MAX` = 255) are NOT a bound this daemon may lean on:
    /// the isolation model assumes the guest kernel can be replaced, which is
    /// the same reason names are validated at all. What this daemon does per
    /// request — the name scan included — is bounded by this gate.
    ///
    /// Pinned at the boundary, both sides: a request AT the cap is handled (the
    /// comparison is `>`, so the documented limit is inclusive), and one byte
    /// over is answered ENOMEM instead of reaching any handler.
    #[test]
    fn test_oversize_request_is_rejected_before_dispatch() {
        // Own memory layout: a request at the cap is just over 1 MiB, so the
        // shared 64 KiB fixture cannot carry it.
        const MEM_SIZE: usize = 4 << 20;
        const REQ_ADDR: u64 = 0x1000;
        const RESP_ADDR: u64 = 2 << 20;
        const CAP: u32 = MAX_BUFFER_SIZE + FUSE_BUFFER_HEADER_SIZE;

        let (root, allowed, _sibling) = fixture("length-gate");
        let h = Harness::new(&root, &[allowed.to_str().unwrap()]);
        let mem = GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(GuestAddress(0), MEM_SIZE)])
            .expect("guest memory");

        // A LOOKUP at the share root whose name fills the whole payload: the
        // filter denies it (ENOENT) — that answer IS the proof the handler ran.
        let send = |len: u32| -> i32 {
            let payload_len = (len - std::mem::size_of::<InHeader>() as u32) as usize;
            let mut req = Vec::with_capacity(len as usize);
            let hdr = InHeader {
                len,
                opcode: Opcode::Lookup as u32,
                unique: 7,
                nodeid: ROOT_ID,
                uid: 0,
                gid: 0,
                pid: 1,
                total_extlen: 0,
                padding: 0,
            };
            req.extend_from_slice(hdr.as_slice());
            req.extend(std::iter::repeat(b'a').take(payload_len - 1));
            req.push(0); // the name's NUL terminator
            assert_eq!(req.len(), len as usize);
            mem.write_slice(&req, GuestAddress(REQ_ADDR))
                .expect("write request");
            mem.write_slice(&vec![0u8; RESP_LEN as usize], GuestAddress(RESP_ADDR))
                .expect("clear reply");

            let queue = MockSplitQueue::new(&mem, 16);
            let chain = queue
                .build_desc_chain(&[
                    Descriptor::new(REQ_ADDR, req.len() as u32, VIRTQ_DESC_F_NEXT, 1),
                    Descriptor::new(RESP_ADDR, RESP_LEN, VIRTQ_DESC_F_WRITE, 0),
                ])
                .expect("build_desc_chain");
            let reader = Reader::new(&mem, chain.clone()).expect("Reader::new");
            let writer = Writer::new(&mem, chain).expect("Writer::new");

            let mut reduction = BucketReduction::Success;
            let mut token = TokenType::Ops;
            h.server
                .handle_message(
                    reader,
                    writer,
                    None::<&mut NoDax>,
                    &mut None,
                    &mut reduction,
                    &mut token,
                )
                .expect("handle_message");
            let out: OutHeader = mem.read_obj(GuestAddress(RESP_ADDR)).expect("read OutHeader");
            out.error
        };

        let at_cap = send(CAP);
        assert_eq!(
            at_cap,
            -libc::ENOENT,
            "a request AT the cap must be handled (the limit is inclusive), got {at_cap}"
        );

        let over = send(CAP + 1);
        assert_eq!(
            over,
            -libc::ENOMEM,
            "a request OVER the cap must be refused by the length gate before dispatch, got {over} \
             (ENOENT/-2 or ENAMETOOLONG/-36 would mean the name was parsed and dispatched)"
        );
    }

    fn cstr_local(bytes: &[u8]) -> CString {
        CString::new(bytes).unwrap()
    }

    // ── hostile-input property tests for the allow-list ─────────────────
    // (the fuzz crate drives the same surface with arbitrary bytes; these
    // pin the SECURITY-relevant invariants deterministically in CI)

    #[test]
    fn filter_refuses_parent_component_entries() {
        // A whitelist entry containing ".." must be REFUSED with an error
        // and leave the previous list fully in place (never a widened one).
        let a = temp_dir("pp-a");
        let mut base = FilterList::new(1, &[a.to_str().unwrap().to_string()], Some(VOL_ALIAS)).unwrap();
        let bad = format!("{}/../escape", a.display());
        assert!(base.update(&[bad], Some(NEXT_ALIAS), None).is_err(), "a .. entry must be refused");
        // The previous whitelist survived: the old alias still resolves to `a`.
        assert!(matches!(
            base.root_lookup(&cstr_local(VOL_ALIAS.as_bytes())),
            RootLookup::Allowed((p, _, _)) if p == a
        ));
    }

    #[test]
    fn filter_alias_is_stable_and_name_never_leaks() {
        // Exactly one entry presents under the supplied alias; the REAL basename must never
        // appear as a root key (alias contract: the seed-derived name is a
        // host-side secret).
        let secret_name = "sf-a51f3c2d9e8f7a6b5c4d";
        let dir = temp_dir(secret_name);
        let f = FilterList::new(1, &[dir.to_str().unwrap().to_string()], Some(VOL_ALIAS)).unwrap();
        assert!(matches!(f.root_lookup(&cstr_local(VOL_ALIAS.as_bytes())), RootLookup::Allowed(_)));
        assert!(matches!(f.root_lookup(&cstr_local(secret_name.as_bytes())), RootLookup::Denied));
        // Non-UTF-8 names can never match the UTF-8 key set: denied, no panic.
        assert!(matches!(f.root_lookup(&cstr_local(&[0xff, 0xfe, b'v', b'o', b'l'])), RootLookup::Denied));
    }

    #[test]
    fn filter_empty_whitelist_hides_everything() {
        // The fail-closed CLEAN state: no entry, no alias, nothing resolves.
        let f = FilterList::new(1, &[], None).unwrap();
        assert_eq!(f.entry_count(), 0);
        assert!(matches!(f.root_lookup(&cstr_local(VOL_ALIAS.as_bytes())), RootLookup::Denied));
        assert!(matches!(f.root_lookup(&cstr_local(b"")), RootLookup::Denied));
    }

    #[test]
    fn filter_non_directory_entry_is_dropped_not_exported() {
        // A file (not a dir) in the whitelist is skipped with a warn — never
        // announced as DT_DIR.
        let dir = temp_dir("nd");
        let file_path = dir.join("notadir");
        fs::write(&file_path, b"x").unwrap();
        let f = FilterList::new(1, &[file_path.to_str().unwrap().to_string()], Some(VOL_ALIAS)).unwrap();
        assert_eq!(f.entry_count(), 0, "a non-directory must not enter the export map");
    }

    #[test]
    fn filter_duplicate_entries_present_once() {
        // The same host dir reached twice keeps ONE alias (aliases cannot
        // collide by construction).
        let dir = temp_dir("dup");
        let entry = dir.to_str().unwrap().to_string();
        let f = FilterList::new(1, &[entry.clone(), entry], Some(VOL_ALIAS)).unwrap();
        assert_eq!(f.entry_count(), 1);
    }

    #[test]
    fn fuse_destroy_is_terminal_and_fires_the_owner_hook() {
        use std::sync::atomic::AtomicUsize;

        let dir = temp_dir("destroy-terminal");
        let fs = crate::passthrough::PassthroughFs::new(crate::passthrough::Config {
            root_dir: dir.to_str().unwrap().into(),
            ..Default::default()
        })
        .unwrap();
        let mut server = Server::new(fs, &[], None).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        server.set_destroy_hook(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        assert!(!server.destroyed.load(Ordering::Acquire));
        server.destroy();
        assert!(server.destroyed.load(Ordering::Acquire));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
