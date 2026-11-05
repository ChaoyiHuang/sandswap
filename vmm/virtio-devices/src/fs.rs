// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Modified by Sandswap (c) 2026: allowed_dirs filtering for per-agent virtio-fs isolation.

use super::RateLimiterConfig;
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::Error as DeviceError;
use crate::VirtioInterruptType;
use crate::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler,
    UserspaceMapping, VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterrupt,
    VirtioSharedMemoryList, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IN_ORDER, VIRTIO_F_IOMMU_PLATFORM,
    VIRTIO_F_NOTIFICATION_DATA, VIRTIO_F_ORDER_PLATFORM, VIRTIO_F_RING_INDIRECT_DESC,
    VIRTIO_F_VERSION_1,
};
use crate::{GuestMemoryMmap, MmapRegion};
use anyhow::anyhow;
use rate_limiter::{BucketReduction, RateLimiter, TokenType};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use std::fs;
use std::io;
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Instant;
use std::{collections::HashMap, convert::TryInto};
use thiserror::Error;
use virtio_queue::{DescriptorChain, Queue, QueueOwnedT, QueueT};
use virtiofsd::{
    descriptor_utils::{Error as VufDescriptorError, Reader, Writer},
    filesystem::SerializableFileSystem,
    fs_cache_req_handler::FsCacheReqHandler,
    fuse::{InHeader, OutHeader, RemovemappingOne},
    limits,
    passthrough::{
        self, read_only::PassthroughFsRo, xattrmap::XattrMap, CachePolicy, MigrationOnError,
        PassthroughFs,
    },
    server::Server,
    Error as VhostUserFsError,
};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const NUM_QUEUE_OFFSET: usize = 1;
const DEFAULT_QUEUE_NUMBER: usize = 2;

/// The allow-list is a NAMESPACE control at the share root: every entry must
/// be a DIRECT child of the shared directory. sandswap sends exactly one
/// volume directory under the volumes root, so nothing legitimate is refused;
/// refusing nested entries removes the intermediate-component class from the
/// authorization path entirely (the final component is opened `O_NOFOLLOW`
/// and its descriptor is pinned by the filter, so the set-fs decision binds
/// the inode, not a re-resolvable path).
///
/// TEXTUAL ONLY — this gate runs on the VirtioFs queue thread under seccomp,
/// and `fs::canonicalize` issues plain `readlink` (glibc realpath), which the
/// thread's allow-list deliberately does not carry: enforce mode SIGSYS-killed
/// the thread mid-swap and every cold mount failed. The pinned-descriptor
/// open in FilterList::init (`O_NOFOLLOW` + statx) is what binds the real
/// object; the textual parent check against BOTH the canonical and the
/// configured root reproduces exactly what the activation gate admitted.
pub(crate) fn validate_allowed_dirs_under_root(
    roots: &[std::path::PathBuf],
    dirs: &[String],
) -> io::Result<()> {
    for dir in dirs {
        if dir.is_empty() {
            continue;
        }
        let entry = std::path::Path::new(dir);
        if !entry.is_absolute() {
            return Err(io::Error::other(format!(
                "allowed_dirs entry {dir:?} must be absolute"
            )));
        }
        for comp in entry.components() {
            match comp {
                std::path::Component::Normal(_) | std::path::Component::RootDir => {}
                _ => {
                    return Err(io::Error::other(format!(
                        "allowed_dirs entry {dir:?} contains a non-normal component ('.' or '..') — refused"
                    )))
                }
            }
        }
        let parent = entry
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| io::Error::other(format!("allowed_dirs entry {dir:?} has no parent")))?;
        if !roots.iter().any(|r| r == &parent) {
            return Err(io::Error::other(format!(
                "allowed_dirs entry {dir:?} is not a direct child of the shared directory ({}) — nested exports are refused",
                roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>().join(" | ")
            )));
        }
    }
    Ok(())
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Processing queue failed: {0}")]
    ProcessQueue(VhostUserFsError),
    #[error("Creating a queue reader failed: {0}")]
    QueueReader(VufDescriptorError),
    #[error("Creating a queue writer failed: {0}")]
    QueueWriter(VufDescriptorError),
}

pub type Result<T> = result::Result<T, Error>;

pub const BACKEND_FS_CACHE_AUTO: u8 = 0;
pub const BACKEND_FS_CACHE_ALWAYS: u8 = 1;
pub const BACKEND_FS_CACHE_NEVER: u8 = 2;
pub const BACKEND_FS_CACHE_NONE: u8 = 3;
pub const DEFAULT_FS_LIMIT_NOFILE: u64 = 0;
pub const DEFAULT_FS_THREAD_POOL_SIZE: usize = 0;

pub fn default_fsconfig_cache() -> u8 {
    BACKEND_FS_CACHE_NEVER
}

/// FAIL-CLOSED default for `allowed_dirs`: an omitted field means "allow
/// nothing", never "no filtering". The in-process filter has no unfiltered
/// mode, so a config that forgets the field serves an empty root — it can
/// never expose the whole shared directory.
pub fn default_fsconfig_allowed_dirs() -> Option<Vec<String>> {
    Some(Vec::new())
}

pub fn default_fsconfig_no_readdirplus() -> bool {
    true
}

pub fn default_fsconfig_read_only() -> bool {
    true
}

pub fn default_fsconfig_rlimit_nofile() -> u64 {
    DEFAULT_FS_LIMIT_NOFILE
}

pub fn default_fsconfig_thread_pool_size() -> usize {
    DEFAULT_FS_THREAD_POOL_SIZE
}

pub fn default_fsconfig_xattr() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioFsConfig,
    #[serde(default)]
    pub back_state: Vec<u8>,
}

/// Size of the virtio-fs tag field in the device configuration space. The
/// tag is copied verbatim from config, so every producer must reject a longer
/// one instead of indexing past the fixed array.
pub const MAX_TAG_LEN: usize = 36;

#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize)]
#[repr(C, packed)]
pub struct VirtioFsConfig {
    #[serde_as(as = "Bytes")]
    pub tag: [u8; MAX_TAG_LEN],
    pub num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; MAX_TAG_LEN],
            num_request_queues: 0,
        }
    }
}

#[derive(Default, Clone)]
pub struct FsCounters {
    total_bytes: Arc<AtomicU64>,
    total_ops: Arc<AtomicU64>,
    min_latency: Arc<AtomicU64>,
    max_latency: Arc<AtomicU64>,
    avg_latency: Arc<AtomicU64>,
    limit_by_bytes: Arc<AtomicU64>,
    limit_by_ops: Arc<AtomicU64>,
}

/// True when a queued filter update was cancelled by the caller and must be
/// dropped instead of applied. Extracted as a pure function so the
/// contract is unit-testable without a virtqueue harness.
fn fs_event_cancelled(cancel: &std::sync::atomic::AtomicBool) -> bool {
    cancel.load(Ordering::Relaxed)
}

#[derive(Clone)]
pub struct FsEvent {
    /// Ok(()) = applied; Err(msg) = refused/failed, msg carrying the server
    /// error's Display (the reuse tripwire's stable "previous-tenant-refs"
    /// token must reach the caller's logs across this channel — a bare bool
    /// smothered it into a generic "failed to update filter list").
    pub tx: std::sync::mpsc::Sender<std::result::Result<(), String>>,
    pub backendfs_config: BackendFsConfig,
    /// Set by the caller when its bounded wait expired (or the reply channel
    /// died). The worker checks it when it finally drains the queue and DROPS
    /// the update instead of applying it late: a filter that goes live after
    /// the control plane gave up would expose a volume this VM was never
    /// attached to.
    pub cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone)]
struct CacheHandler {
    cache_size: u64,
    mmap_cache_addr: u64,
}

impl CacheHandler {
    // Make sure request is within cache range
    fn is_req_valid(&self, offset: u64, len: u64) -> bool {
        let end = match offset.checked_add(len) {
            Some(n) => n,
            None => return false,
        };

        !(offset >= self.cache_size || end > self.cache_size)
    }
}

impl FsCacheReqHandler for CacheHandler {
    fn map(
        &mut self,
        foffset: u64,
        moffset: u64,
        len: u64,
        flags: u64,
        fd: RawFd,
    ) -> result::Result<(), io::Error> {
        debug!("fs_slave_map");

        // Ignore if the length is 0.
        if len == 0 {
            return Ok(());
        }

        if !self.is_req_valid(moffset, len) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        let addr = self.mmap_cache_addr + moffset;
        // SAFETY: FFI call with valid arguments
        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                flags as i32,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd.as_raw_fd(),
                foffset as libc::off_t,
            )
        };
        if ret == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    fn unmap(&mut self, requests: Vec<RemovemappingOne>) -> std::result::Result<(), io::Error> {
        debug!("fs_slave_unmap");

        for req in requests {
            let mut offset = req.moffset;
            let mut len = req.len;

            // Ignore if the length is 0.
            if len == 0 {
                continue;
            }

            // Need to handle a special case where the slave ask for the unmapping
            // of the entire mapping.
            if len == 0xffff_ffff_ffff_ffff {
                len = self.cache_size;
                offset = 0;
            }

            if !self.is_req_valid(offset, len) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }

            let addr = self.mmap_cache_addr + offset;
            // SAFETY: FFI call with valid arguments
            let ret = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    len as usize,
                    libc::PROT_NONE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if ret == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

struct FsEpollHandler {
    queue_index: u16,
    queue_evt: EventFd,
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    server: Arc<ServerType>,
    cache_handler: Option<CacheHandler>,
    dev_evt: EventFd,
    pending_dev_message: Arc<Mutex<Vec<FsEvent>>>,
    rate_limiter: Option<RateLimiter>,
    counters: FsCounters,
    rate_limited: std::sync::Once,
    id: String,
    // The share root CANONICALIZED at activation. The runtime set-fs gate
    // compares allow-list entries against THIS, never against the event's
    // own config: a raw-frame vm.set-fs carries only id/tag/allowed_dirs/
    // alias, so the event's backendfs_config has no usable shared_dir (the
    // canonicalize of it failed on every real swap — "shared dir cannot be
    // resolved").
    shared_roots: Vec<std::path::PathBuf>,
}

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// New 'wake up' event from the rate limiter
const RATE_LIMITER_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;
// New event to backend device.
const DEVICE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 4;

// latency scale, for reduce precision loss in calculate.
const LATENCY_SCALE: u64 = 10000;

impl FsEpollHandler {
    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;

        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        if let Some(rate_limiter) = &self.rate_limiter {
            helper.add_event(rate_limiter.as_raw_fd(), RATE_LIMITER_EVENT)?;
        }
        // There always multi queue support for virtiofs, we only
        // need one thread to listen the DEVICE_EVENT.
        // Here we just add DEVICE_EVENT to queue which index is 0,
        // because this queue is always exist.
        if self.queue_index == 0 {
            helper.add_event(self.dev_evt.as_raw_fd(), DEVICE_EVENT)?;
        }
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(self.queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn return_descriptor(queue: &mut Queue, mem: &GuestMemoryMmap, head_index: u16, len: usize) {
        // In FUSE, a single response should never reach 4 GiB; if it ever does
        // (most likely a bug or a malformed request) we report 0 bytes used
        // and log a warning instead of panicking. Reporting 0 is safer than
        // saturating to u32::MAX because the Guest virtio-ring layer rejects
        // any used_len that exceeds the descriptor chain's writable capacity;
        // a 0-length reply makes the Guest FUSE driver fall back to its
        // short-reply / unmatched-reply path and complete the request with
        // -EIO, while the worker thread keeps serving the rest of the queue.
        let used_len: u32 = u32::try_from(len).unwrap_or_else(|_| {
            warn!(
                "virtio-fs: response length {} exceeds u32::MAX, reporting 0 used bytes; \
                 Guest will see a short reply and fail the request with -EIO",
                len
            );
            0
        });

        if queue.add_used(mem, head_index, used_len).is_err() {
            warn!("Couldn't return used descriptors to the ring");
        }
    }

    /// Try to peek the FUSE InHeader from a fresh Reader built on a clone of
    /// `desc_chain`, returning the request's `unique` id. The original reader
    /// used by the FUSE server is unaffected (Reader keeps its own cursor).
    ///
    /// On any failure (descriptor chain too short, guest memory error, etc.)
    /// returns `None`.
    fn peek_in_header_unique(
        mem: &GuestMemoryMmap,
        desc_chain: DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
    ) -> Option<u64> {
        let mut peek_reader = Reader::new(mem, desc_chain).ok()?;
        let in_header: InHeader = peek_reader.read_obj().ok()?;
        Some(in_header.unique)
    }

    /// Try to write a minimal FUSE error reply (`OutHeader { len: 16,
    /// error: -EIO, unique }`) into a freshly built Writer over `desc_chain`,
    /// returning the number of bytes actually written (always 16 on success,
    /// 0 on failure).
    ///
    /// This is used as a best-effort recovery path when reader/writer
    /// construction or `Server::handle_message` fails: instead of letting the
    /// worker thread die, we try to surface a clean `-EIO` to the Guest so
    /// the in-flight FUSE request is woken up immediately.
    fn try_write_fuse_eio(
        mem: &GuestMemoryMmap,
        desc_chain: DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
        unique: u64,
    ) -> usize {
        let mut writer = match Writer::new(mem, desc_chain) {
            Ok(w) => w,
            Err(_) => return 0,
        };
        // Bail out early when the descriptor chain has no room for a full
        // OutHeader, otherwise write_obj would partially succeed and report
        // a misleading bytes_written back to the Guest.
        if writer.available_bytes() < std::mem::size_of::<OutHeader>() {
            return 0;
        }
        let header = OutHeader {
            len: std::mem::size_of::<OutHeader>() as u32,
            error: -libc::EIO,
            unique,
        };
        writer
            .write_obj(header)
            .map_or(0, |_| writer.bytes_written())
    }

    fn process_queue_serial(&mut self) -> Result<bool> {
        let queue = &mut self.queue;
        let mut cache_handler = self.cache_handler.clone();
        let mut used_descs = false;
        let mut total_ops = Wrapping(0);
        let mut total_bytes = Wrapping(0);
        let ops_last = self.counters.total_ops.load(Ordering::Relaxed) as i64;
        let mut avg_latency = self.counters.avg_latency.load(Ordering::Relaxed) as i64;
        let mut limit_by_ops = Wrapping(0);
        let mut limit_by_bytes = Wrapping(0);

        // bound one drain so a guest that keeps this queue non-empty
        // cannot starve the DEVICE_EVENT epoll event on the same worker
        // thread. Each round returns to epoll_wait, which services a pending
        // filter update (the queue stays ready and is resumed there). The
        // budget is far above any legitimate burst and costs one epoll round
        // trip per 256 requests.
        const MAX_OPS_PER_ROUND: usize = 256;
        let mut serviced = 0usize;
        while serviced < MAX_OPS_PER_ROUND {
            let Some(desc_chain) = queue.pop_descriptor_chain(self.mem.memory()) else {
                break;
            };
            serviced += 1;
            let head_index = desc_chain.head_index();
            let mem_ref = desc_chain.memory();

            // Best-effort: peek the FUSE in_header.unique from a separate
            // Reader built on a clone of desc_chain, so we can produce a
            // matching FUSE error reply if anything below fails. If even the
            // peek fails (bad descriptor chain), fall back to unique=0; the
            // Guest driver will then fall back to its short-reply / unmatched
            // reply path and complete the request with -EIO.
            let peek_unique = Self::peek_in_header_unique(mem_ref, desc_chain.clone()).unwrap_or(0);

            let reader = match Reader::new(mem_ref, desc_chain.clone()) {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        "virtio-fs: failed to build Reader for request (unique={}): {:?}; \
                         replying -EIO and continuing",
                        peek_unique, e
                    );
                    let written =
                        Self::try_write_fuse_eio(mem_ref, desc_chain.clone(), peek_unique);
                    Self::return_descriptor(queue, mem_ref, head_index, written);
                    used_descs = true;
                    continue;
                }
            };
            let writer = match Writer::new(mem_ref, desc_chain.clone()) {
                Ok(w) => w,
                Err(e) => {
                    // Without a working Writer there is no way to deliver any
                    // reply at all; just hand the descriptor back with len=0
                    // and let the Guest's FUSE layer recover (modern kernels
                    // turn a short reply into -EIO).
                    warn!(
                        "virtio-fs: failed to build Writer for request (unique={}): {:?}; \
                         returning descriptor with len=0",
                        peek_unique, e
                    );
                    Self::return_descriptor(queue, mem_ref, head_index, 0);
                    used_descs = true;
                    continue;
                }
            };

            let mut rate_limited = BucketReduction::Success;
            let mut rate_limited_type = TokenType::Ops;
            let req_start = Instant::now();
            let len = match self.server.handle_message(
                reader,
                writer,
                cache_handler.as_mut(),
                &mut self.rate_limiter,
                &mut rate_limited,
                &mut rate_limited_type,
            ) {
                Ok(n) => n,
                Err(e) => {
                    // The FUSE server failed mid-way; the original writer may
                    // contain a partially-written reply with a stale `len`
                    // field. Build a fresh Writer from a clone of desc_chain
                    // (which always starts at the writable region's offset 0)
                    // and write a minimal -EIO header there. This overwrites
                    // whatever the server may have left behind, so the Guest
                    // sees a single, well-formed FUSE error reply.
                    warn!(
                        "virtio-fs: handle_message failed (unique={}): {:?}; replying -EIO",
                        peek_unique, e
                    );
                    let written =
                        Self::try_write_fuse_eio(mem_ref, desc_chain.clone(), peek_unique);
                    Self::return_descriptor(queue, mem_ref, head_index, written);
                    used_descs = true;
                    continue;
                }
            };

            if rate_limited != BucketReduction::Success {
                match rate_limited_type {
                    TokenType::Ops => {
                        limit_by_ops += Wrapping(1);
                        self.rate_limited
                            .call_once(|| info!("{} fs ops ratelimit fired", self.id));
                    }
                    TokenType::Bytes => {
                        limit_by_bytes += Wrapping(1);
                        self.rate_limited
                            .call_once(|| info!("{} fs bw ratelimit fired", self.id));
                    }
                }

                // Stop processing the queue and return this descriptor chain to the
                // avail ring, for later processing.
                if rate_limited == BucketReduction::Failure {
                    queue.go_to_previous_position();
                    break;
                }
            }

            let latency = req_start.elapsed().as_micros() as u64;
            total_bytes += Wrapping(len as u64);
            total_ops += Wrapping(1);
            if (ops_last == 0) || (latency < self.counters.min_latency.load(Ordering::Relaxed)) {
                self.counters.min_latency.store(latency, Ordering::Relaxed);
            }
            if latency > self.counters.max_latency.load(Ordering::Relaxed) {
                self.counters.max_latency.store(latency, Ordering::Relaxed);
            }
            if latency > 20_000 {
                warn!("Virtio-fs IO latency too long {}", latency);
            }
            avg_latency = avg_latency
                + ((latency * LATENCY_SCALE) as i64 - avg_latency)
                    / (ops_last + total_ops.0 as i64);
            Self::return_descriptor(queue, desc_chain.memory(), head_index, len);
            used_descs = true;

            // Proces BucketReduction::OverConsumption.
            if let BucketReduction::OverConsumption(_) = rate_limited {
                break;
            }
        }

        self.counters
            .total_bytes
            .fetch_add(total_bytes.0, Ordering::AcqRel);
        self.counters
            .total_ops
            .fetch_add(total_ops.0, Ordering::AcqRel);
        self.counters
            .avg_latency
            .store(avg_latency as u64, Ordering::Relaxed);
        self.counters
            .limit_by_bytes
            .fetch_add(limit_by_bytes.0, Ordering::AcqRel);
        self.counters
            .limit_by_ops
            .fetch_add(limit_by_ops.0, Ordering::AcqRel);

        Ok(used_descs)
    }

    fn handle_event_impl(&mut self) -> result::Result<(), EpollHelperError> {
        let needs_notification = self.process_queue_serial().map_err(|e| {
            EpollHelperError::HandleEvent(anyhow!("Failed to process queue (submit): {:?}", e))
        })?;

        if needs_notification {
            self.signal_used_queue().map_err(|e| {
                EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {:?}", e))
            })?
        };

        Ok(())
    }
}

impl EpollHelperHandler for FsEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {:?}", e))
                })?;
                let rate_limit_reached =
                    self.rate_limiter.as_ref().map_or(false, |r| r.is_blocked());

                // Process the queue only when the rate limit is not reached
                if !rate_limit_reached {
                    self.handle_event_impl()?
                }
            }
            RATE_LIMITER_EVENT => {
                if let Some(rate_limiter) = &mut self.rate_limiter {
                    // Upon rate limiter event, call the rate limiter handler
                    // and restart processing the queue.
                    rate_limiter.event_handler().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to process rate limiter event: {:?}",
                            e
                        ))
                    })?;

                    self.handle_event_impl()?
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unexpected 'RATE_LIMITER_EVENT' when rate_limiter is not enabled."
                    )));
                }
            }
            DEVICE_EVENT => {
                self.dev_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {:?}", e))
                })?;
                for event in self.pending_dev_message.lock().unwrap().drain(..) {
                    // the caller's bounded wait already expired and it
                    // reported the switch as failed. Applying the queued
                    // allow-list now would export a volume the control plane
                    // never attached to this VM (and may have placed
                    // elsewhere). Drop it; the caller gets "not applied".
                    if fs_event_cancelled(&event.cancel) {
                        let _ = event.tx.send(Err(
                            "update cancelled (caller timed out); filter left unchanged".into(),
                        ));
                        continue;
                    }
                    // The allow-list contains the live tenant volume path
                    // (the hidden seed-derived name): log its size, never the
                    // entries.
                    info!(
                        "Fs device update: {} allowed_dirs entr{}",
                        event
                            .backendfs_config
                            .allowed_dirs
                            .as_ref()
                            .map_or(0, |v| v.len()),
                        if event
                            .backendfs_config
                            .allowed_dirs
                            .as_ref()
                            .map_or(0, |v| v.len())
                            == 1
                        {
                            "y"
                        } else {
                            "ies"
                        }
                    );
                    // Fail-closed normalization, same as activation: `None`
                    // is the empty allow-list (deny all), never "filter off".
                    let allowed_dirs = event
                        .backendfs_config
                        .allowed_dirs
                        .clone()
                        .unwrap_or_default();
                    // Same single-component contract as activation: refuse a
                    // nested entry before it reaches the filter, leaving the
                    // previous generation fully in place. The root is the one
                    // canonicalized at activation (see the field doc — the
                    // event's own config does not carry a usable shared_dir).
                    if let Err(e) =
                        validate_allowed_dirs_under_root(&self.shared_roots, &allowed_dirs)
                    {
                        error!("Refusing allow-list update: {}", e);
                        let _ = event.tx.send(Err(e.to_string()));
                        continue;
                    }
                    let alias = event.backendfs_config.alias.as_deref();
                    let ret = self
                        .server
                        .update_filter_cancellable(&allowed_dirs, alias, Some(&event.cancel))
                        .map_err(|e| {
                            // A failed whitelist swap means the previous
                            // filter stays in place — the caller gets an
                            // error carrying this Display (the reuse
                            // tripwire refusal is a NAMED outcome, not a
                            // generic failure). This is the isolation
                            // boundary, so log at error level.
                            error!("Failed to update filter: {:?}", e);
                            e.to_string()
                        });
                    let _ = event.tx.send(ret);
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {}",
                    ev_type
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendFsConfig {
    #[serde(default)]
    pub shared_dir: String,
    #[serde(default = "default_fsconfig_thread_pool_size")]
    pub thread_pool_size: usize,
    #[serde(default = "default_fsconfig_xattr")]
    pub xattr: bool,
    #[serde(default)]
    pub posix_acl: bool,
    #[serde(default)]
    pub xattrmap: Option<String>,
    #[serde(default)]
    pub announce_submounts: bool,
    #[serde(default = "default_fsconfig_cache")]
    pub cache: u8,
    #[serde(default = "default_fsconfig_no_readdirplus")]
    pub no_readdirplus: bool,
    #[serde(default)]
    pub writeback: bool,
    #[serde(default)]
    pub allow_direct_io: bool,
    #[serde(default = "default_fsconfig_read_only")]
    pub read_only: bool,
    #[serde(default = "default_fsconfig_rlimit_nofile")]
    pub rlimit_nofile: u64,
    #[serde(default)]
    pub killpriv_v2: bool,
    #[serde(default)]
    pub security_label: bool,
    /// Share-root visibility allow-list (Sandswap per-agent isolation):
    /// only the listed directories' basenames resolve at the FUSE root, and
    /// an EMPTY list hides every root entry.
    ///
    /// FAIL-CLOSED default (see default_fsconfig_allowed_dirs): an omitted
    /// field is the empty allow-list, not "no filtering".
    #[serde(default = "default_fsconfig_allowed_dirs")]
    pub allowed_dirs: Option<Vec<String>>,
    /// Guest-visible root name presented for the single allow-listed
    /// directory. The sandlot mints a fresh random token for every set-fs
    /// generation and carries the same token to the warden's mount op, so a
    /// mount request that arrives after a later set-fs cannot resolve
    /// against the newer export. Required when `allowed_dirs` is non-empty;
    /// absent/empty means the deny-all (cleared) state.
    #[serde(default)]
    pub alias: Option<String>,
}

impl Default for BackendFsConfig {
    fn default() -> Self {
        BackendFsConfig {
            shared_dir: "".to_owned(),
            thread_pool_size: default_fsconfig_thread_pool_size(),
            xattr: default_fsconfig_xattr(),
            posix_acl: false,
            xattrmap: None,
            announce_submounts: false,
            cache: default_fsconfig_cache(),
            no_readdirplus: default_fsconfig_no_readdirplus(),
            writeback: false,
            allow_direct_io: false,
            read_only: default_fsconfig_read_only(),
            rlimit_nofile: default_fsconfig_rlimit_nofile(),
            killpriv_v2: false,
            security_label: false,
            allowed_dirs: default_fsconfig_allowed_dirs(),
            alias: None,
        }
    }
}

// SAFETY: only a series of integers
unsafe impl ByteValued for VirtioFsConfig {}

enum ServerType {
    PassthroughFs(Server<PassthroughFs>),
    PassthroughFsRo(Server<PassthroughFsRo>),
}

#[must_use]
struct BackendSerializationGuard<'a> {
    pre_serialization: &'a AtomicBool,
}

impl<'a> BackendSerializationGuard<'a> {
    fn new(pre_serialization: &'a AtomicBool) -> Self {
        Self { pre_serialization }
    }
}

impl Drop for BackendSerializationGuard<'_> {
    fn drop(&mut self) {
        self.pre_serialization.store(false, Ordering::Release);
    }
}

// Macro to forward method calls to the underlying server variant
// Supports both explicit parameter passing and automatic forwarding
macro_rules! forward_to_server {
    // Pattern: forward method with explicit arguments
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
            ServerType::PassthroughFs(server) => server.$method($($args),*),
            ServerType::PassthroughFsRo(server) => server.$method($($args),*),
        }
    };
}

// Macro to define a method that forwards to the server with automatic parameter passing
macro_rules! impl_forward_method {
    // Pattern: method without generic parameters
    (
        $(#[$attr:meta])*
        $vis:vis fn $method:ident
        ( &$self:ident $(, $param:ident: $param_ty:ty)* ) -> $ret:ty
    ) => {
        $(#[$attr])*
        $vis fn $method ( &$self $(, $param: $param_ty)* ) -> $ret
        {
            forward_to_server!($self, $method $(, $param)*)
        }
    };

    // Pattern: method with generic parameters (using where clause)
    (
        $(#[$attr:meta])*
        $vis:vis fn $method:ident <$($gen:ident),+>
        ( &$self:ident $(, $param:ident: $param_ty:ty)* ) -> $ret:ty
        where $($bounds:tt)+
    ) => {
        $(#[$attr])*
        $vis fn $method <$($gen),+> ( &$self $(, $param: $param_ty)* ) -> $ret
        where $($bounds)+
        {
            forward_to_server!($self, $method $(, $param)*)
        }
    };
}

impl ServerType {
    impl_forward_method! {
        #[allow(dead_code)] // Used by virtiofsd migration (not yet enabled in open branch)
        fn prepare_serialization(&self, cancel: Arc<AtomicBool>) -> io::Result<()>
    }

    impl_forward_method! {
        #[allow(dead_code)] // Used by virtiofsd migration (not yet enabled in open branch)
        fn serialize_data(&self) -> io::Result<Vec<u8>>
    }

    impl_forward_method! {
        fn deserialize_and_apply_data(&self, data: &Vec<u8>) -> io::Result<()>
    }

    impl_forward_method! {
        fn update_filter_cancellable(
            &self,
            whitelist: &[String],
            alias: Option<&str>,
            cancel: Option<&AtomicBool>
        ) -> virtiofsd::Result<()>
    }

    impl_forward_method! {
        #[allow(clippy::cognitive_complexity)]
        pub fn handle_message<T>(
            &self,
            r: Reader,
            w: Writer,
            vu_req: Option<&mut T>,
            rl: &mut Option<RateLimiter>,
            rlret: &mut BucketReduction,
            rltyp: &mut TokenType
        ) -> virtiofsd::Result<usize>
        where T: FsCacheReqHandler
    }
}

pub struct Fs {
    common: VirtioCommon,
    id: String,
    config: VirtioFsConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    backendfs_config: BackendFsConfig,
    cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    rate_limiter_config: Option<RateLimiterConfig>,
    dev_evt: EventFd,
    pending_dev_message: Arc<Mutex<Vec<FsEvent>>>,
    counters: FsCounters,
    server: Option<Arc<ServerType>>,
    back_state: Vec<u8>,
    restore: bool,
    #[allow(dead_code)] // Used by virtiofsd migration (not yet enabled in open branch)
    pre_serialization: AtomicBool,
}

impl Fs {
    /// Create a new virtio-fs device.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        iommu: bool,
        state: Option<State>,
        backendfs_config: &BackendFsConfig,
        cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
        rate_limiter_config: Option<RateLimiterConfig>,
        dev_evt: EventFd,
        pending_dev_message: Arc<Mutex<Vec<FsEvent>>>,
    ) -> io::Result<Fs> {
        let mut back_state = Vec::new();
        // Calculate the actual number of queues needed.
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;
        if num_queues > DEFAULT_QUEUE_NUMBER {
            error!(
                "virtio-fs requested too many queues ({}) since the backend only supports {}\n",
                num_queues, DEFAULT_QUEUE_NUMBER
            );
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("requested too many queues"),
            ));
        }

        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            debug!("Restoring virtio-fs {}", id);
            back_state = state.back_state;

            (
                state.avail_features,
                state.acked_features,
                state.config,
                true,
            )
        } else {
            // Filling device and vring features VMM supports.
            let mut avail_features: u64 = 1 << VIRTIO_F_RING_INDIRECT_DESC
                | 1 << VIRTIO_F_VERSION_1
                | 1 << VIRTIO_F_IN_ORDER
                | 1 << VIRTIO_F_ORDER_PLATFORM
                | 1 << VIRTIO_F_NOTIFICATION_DATA;

            if iommu {
                avail_features |= 1 << VIRTIO_F_IOMMU_PLATFORM;
            }

            // Create virtio-fs device configuration. The tag is a fixed-size
            // array in the virtio config space: a longer tag would index past
            // it (panic), and an empty one is not mountable by the guest.
            let tag_bytes_vec = tag.to_string().into_bytes();
            if tag_bytes_vec.is_empty() || tag_bytes_vec.len() > MAX_TAG_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("virtio-fs tag must be 1..={MAX_TAG_LEN} bytes"),
                ));
            }
            let mut config = VirtioFsConfig::default();
            config.tag[..tag_bytes_vec.len()].copy_from_slice(tag_bytes_vec.as_slice());
            config.num_request_queues = req_num_queues as u32;

            (avail_features, 0, config, false)
        };
        Ok(Fs {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Fs as u32,
                avail_features,
                acked_features,
                queue_sizes: vec![queue_size; num_queues],
                paused_sync: Some(Arc::new(Barrier::new(num_queues + 1))),
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            config,
            seccomp_action,
            exit_evt,
            backendfs_config: backendfs_config.clone(),
            cache,
            rate_limiter_config,
            dev_evt,
            pending_dev_message,
            counters: FsCounters::default(),
            server: None,
            back_state,
            restore: paused,
            pre_serialization: AtomicBool::new(false),
        })
    }

    fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
            back_state: Vec::new(),
        }
    }

    fn init_backend_fs_server(
        &self,
        backendfs_config: &BackendFsConfig,
    ) -> result::Result<Arc<ServerType>, ActivateError> {
        let shared_dir = &backendfs_config.shared_dir;
        let shared_dir_rp =
            fs::canonicalize(shared_dir).map_err(ActivateError::ActivateVirtioFs)?;
        let shared_dir_rp_str = shared_dir_rp
            .to_str()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
            .map_err(ActivateError::ActivateVirtioFs)?;

        // The boot-time allow-list obeys the same single-component contract
        // as every runtime swap.
        validate_allowed_dirs_under_root(
            &[shared_dir_rp.clone(), std::path::PathBuf::from(shared_dir)],
            backendfs_config.allowed_dirs.as_deref().unwrap_or(&[]),
        )
        .map_err(ActivateError::ActivateVirtioFs)?;

        let xattrmap = backendfs_config
            .xattrmap
            .as_ref()
            .map(|s| XattrMap::try_from(s.as_str()))
            .transpose()
            .map_err(|e| {
                ActivateError::ActivateVirtioFs(io::Error::other(format!(
                    "invalid xattrmap configuration: {e}"
                )))
            })?;

        let cache = match backendfs_config.cache {
            BACKEND_FS_CACHE_AUTO => CachePolicy::Auto,
            BACKEND_FS_CACHE_ALWAYS => CachePolicy::Always,
            BACKEND_FS_CACHE_NEVER => CachePolicy::Never,
            BACKEND_FS_CACHE_NONE => CachePolicy::None,
            num => {
                return Err(ActivateError::ActivateVirtioFs(io::Error::other(format!(
                    "unknown cache policy: {}, valid input: 0(auto), 1(always), 2(never), 3(none)",
                    num
                ))))
            }
        };
        let readdirplus = match cache {
            CachePolicy::Never => false,
            CachePolicy::None => false,
            _ => !backendfs_config.no_readdirplus,
        };

        limits::setup_rlimit_nofile(Some(backendfs_config.rlimit_nofile))
            .map_err(|error| io::Error::other(format!("setup rlimit nofile error {:?}", error)))
            .map_err(ActivateError::ActivateVirtioFs)?;

        let fs_cfg = passthrough::Config {
            cache_policy: cache,
            root_dir: shared_dir_rp_str.into(),
            mountinfo_prefix: None,
            xattr: backendfs_config.xattr,
            xattrmap,
            proc_sfd_rawfd: None,
            proc_mountinfo_rawfd: None,
            announce_submounts: backendfs_config.announce_submounts,
            readdirplus,
            writeback: backendfs_config.writeback,
            allow_direct_io: backendfs_config.allow_direct_io,
            killpriv_v2: backendfs_config.killpriv_v2,
            security_label: backendfs_config.security_label,
            posix_acl: backendfs_config.posix_acl,
            // Hardcoded override (not driven by BackendFsConfig): surface
            // per-inode restore failures to the guest instead of aborting
            // the whole live migration. Upstream default is `Abort`.
            migration_on_error: MigrationOnError::GuestError,
            ..Default::default()
        };

        // Fail-closed: the device never runs an unfiltered share. A config
        // whose allowed_dirs is None (unreachable through the config layer,
        // which defaults the field to the empty list) is normalized to the
        // empty allow-list here — deny all — never treated as "filter off".
        let allowed_dirs = backendfs_config
            .allowed_dirs
            .clone()
            .unwrap_or_default();
        let alias = backendfs_config.alias.clone();
        // A guest FUSE_DESTROY tears the export down for good: the hook makes
        // the VMM exit so the owner destroys and replaces the microVM instead
        // of living with a device that has no valid export.
        let destroy_hook: Option<Arc<dyn Fn() + Send + Sync>> =
            self.exit_evt.try_clone().ok().map(|evt| {
                Arc::new(move || {
                    let _ = evt.write(1);
                }) as Arc<dyn Fn() + Send + Sync>
            });
        if backendfs_config.read_only {
            let fs = PassthroughFsRo::new(fs_cfg).map_err(|e| {
                ActivateError::ActivateVirtioFs(io::Error::other(format!(
                    "Failed to create internal ro filesystem representation: {e:?}",
                )))
            })?;
            let mut server = Server::new(fs, &allowed_dirs, alias.as_deref())
                .map_err(ActivateError::InvalidServerConfig)?;
            if let Some(hook) = destroy_hook {
                server.set_destroy_hook(hook);
            }
            Ok(Arc::new(ServerType::PassthroughFsRo(server)))
        } else {
            let fs = PassthroughFs::new(fs_cfg).map_err(|e| {
                ActivateError::ActivateVirtioFs(io::Error::other(format!(
                    "Failed to create internal filesystem representation: {e:?}",
                )))
            })?;
            let mut server = Server::new(fs, &allowed_dirs, alias.as_deref())
                .map_err(ActivateError::InvalidServerConfig)?;
            if let Some(hook) = destroy_hook {
                server.set_destroy_hook(hook);
            }
            Ok(Arc::new(ServerType::PassthroughFs(server)))
        }
    }

    fn prepare_backend_serialization(
        &self,
        server: &ServerType,
    ) -> std::result::Result<(), MigratableError> {
        let start = Instant::now();
        let cancel = Arc::new(AtomicBool::new(false));
        debug!("serialize prepare");
        server.prepare_serialization(cancel).map_err(|e| {
            warn!("{} preserialization failed ({:?})", self.id, e);
            MigratableError::Snapshot(anyhow!("serialize prepare failed: {:?}", e))
        })?;
        self.pre_serialization.store(true, Ordering::Release);
        info!(
            "{} preserialization success after {}(us)",
            self.id,
            start.elapsed().as_micros()
        );
        Ok(())
    }

    fn prepare_backend_serialization_if_needed(
        &self,
        server: &ServerType,
    ) -> std::result::Result<(), MigratableError> {
        if self.pre_serialization.load(Ordering::Acquire) {
            return Ok(());
        }
        self.prepare_backend_serialization(server)
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Fs {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        // One-shot activation: the device is created deny-all and the export
        // is installed by vm.set-fs. An activation of an already-activated
        // device can only come from a guest-driven reset, which is terminal
        // (see reset) — refuse it rather than rebuild state.
        if self.server.is_some() {
            return Err(ActivateError::BadActivate);
        }
        self.common.activate(&queues, &interrupt_cb)?;
        let server = self.init_backend_fs_server(&self.backendfs_config)?;
        if self.restore {
            if !self.back_state.is_empty() {
                let start = Instant::now();
                server
                    .deserialize_and_apply_data(self.back_state.as_ref())
                    .map_err(|e| {
                        warn!("{} deserialization failed ({:?})", self.id, e);
                        ActivateError::InvalidVirtioFsState(e)
                    })?;
                info!(
                    "{} deserialization success after {}(us)",
                    self.id,
                    start.elapsed().as_micros()
                );
            }
            self.restore = false;
        }
        self.server = Some(server.clone());
        let mut epoll_threads = Vec::new();
        for i in 0..queues.len() {
            let (_, queue, queue_evt) = queues.remove(0);
            let (kill_evt, pause_evt) = self.common.dup_eventfds();

            let rate_limiter: Option<RateLimiter> = self
                .rate_limiter_config
                .map(RateLimiterConfig::try_into)
                .transpose()
                .map_err(ActivateError::CreateRateLimiter)?;

            let cache_handler = if let Some(cache) = self.cache.as_ref() {
                let handler = CacheHandler {
                    cache_size: cache.0.len,
                    mmap_cache_addr: cache.0.host_addr,
                };

                Some(handler)
            } else {
                None
            };
            // The same root set the activation gate admitted against: the
            // canonicalized shared dir plus its configured spelling. This
            // runs on the ACTIVATING thread (pre-spawn — the queue thread's
            // seccomp filter does not apply yet), where the activation gate's
            // own canonicalize already ran.
            let shared_roots = match fs::canonicalize(&self.backendfs_config.shared_dir) {
                Ok(rp) => vec![rp, std::path::PathBuf::from(&self.backendfs_config.shared_dir)],
                Err(_) => vec![std::path::PathBuf::from(&self.backendfs_config.shared_dir)],
            };
            let mut handler = FsEpollHandler {
                queue_index: i as u16,
                queue_evt,
                queue,
                mem: mem.clone(),
                interrupt_cb: interrupt_cb.clone(),
                kill_evt,
                pause_evt,
                server: server.clone(),
                cache_handler,
                dev_evt: self.dev_evt.try_clone().unwrap(),
                pending_dev_message: self.pending_dev_message.clone(),
                rate_limiter,
                counters: self.counters.clone(),
                rate_limited: std::sync::Once::new(),
                id: self.id.clone(),
                shared_roots,
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            spawn_virtio_thread(
                &format!("{}_q{}", self.id.clone(), i),
                &self.seccomp_action,
                Thread::VirtioFs,
                &mut epoll_threads,
                &self.exit_evt,
                move || handler.run(paused, paused_sync.unwrap()),
            )?;
        }

        self.common.epoll_threads = Some(epoll_threads);
        event!("virtio-device", "activated", "id", &self.id);

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // A virtio-fs device is immutable: it carries the only export, its
        // generation alias and the tripped reuse counters. A guest-triggered
        // reset would leave the VM without a valid export, so the reset is
        // TERMINAL — signal the VMM to exit and let the owner destroy and
        // replace the microVM.
        let _ = self.exit_evt.write(1);

        event!("virtio-device", "reset", "id", &self.id);

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        self.cache.as_ref().map(|cache| cache.0.clone())
    }

    fn set_shm_regions(
        &mut self,
        shm_regions: VirtioSharedMemoryList,
    ) -> std::result::Result<(), crate::Error> {
        if let Some(cache) = self.cache.as_mut() {
            cache.0 = shm_regions;
            Ok(())
        } else {
            Err(crate::Error::SetShmRegionsNotSupported)
        }
    }

    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        let mut mappings = Vec::new();
        if let Some(cache) = self.cache.as_ref() {
            mappings.push(UserspaceMapping {
                host_addr: cache.0.host_addr,
                mem_slot: cache.0.mem_slot,
                addr: cache.0.addr,
                len: cache.0.len,
                mergeable: false,
            })
        }

        mappings
    }

    fn counters(&self) -> Option<HashMap<&'static str, Wrapping<u64>>> {
        let mut counters = HashMap::new();

        counters.insert(
            "total_bytes",
            Wrapping(self.counters.total_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "total_ops",
            Wrapping(self.counters.total_ops.load(Ordering::Acquire)),
        );
        counters.insert(
            "min_latency",
            Wrapping(self.counters.min_latency.load(Ordering::Acquire)),
        );
        counters.insert(
            "max_latency",
            Wrapping(self.counters.max_latency.load(Ordering::Acquire)),
        );
        counters.insert(
            "avg_latency",
            Wrapping(self.counters.avg_latency.load(Ordering::Acquire) / LATENCY_SCALE),
        );
        counters.insert(
            "limit_by_bytes",
            Wrapping(self.counters.limit_by_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "limit_by_ops",
            Wrapping(self.counters.limit_by_ops.load(Ordering::Acquire)),
        );

        Some(counters)
    }
}

impl Pausable for Fs {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Fs {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let mut state = self.state();
        if let Some(server) = &self.server {
            self.prepare_backend_serialization_if_needed(server)?;
            let _serialization_cleanup = BackendSerializationGuard::new(&self.pre_serialization);
            let start = Instant::now();
            let result = server
                .serialize_data()
                .map_err(|e| {
                    warn!("{} serialization failed ({:?})", self.id, e);
                    MigratableError::Snapshot(anyhow!("serialize process failed: {:?}", e))
                })
                .map(|data| {
                    state.back_state = data;
                });
            result?;
            info!(
                "{} serialization success after {}(us)",
                self.id,
                start.elapsed().as_micros()
            );
        }
        Snapshot::new_from_state(&self.id(), &state)
    }
}

impl Transportable for Fs {}

impl Migratable for Fs {
    fn start_migration(&mut self) -> std::result::Result<(), MigratableError> {
        if let Some(server) = &self.server {
            self.prepare_backend_serialization(server)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "virtio-devices-fs-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn allow_list_refuses_nested_and_outside_exports() {
        let root = TestDir::new("nested-allow");
        let child = root.path().join("vol");
        let nested = child.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let root_rp = fs::canonicalize(root.path()).unwrap();

        // A direct child (the sandswap volume layout) is accepted.
        validate_allowed_dirs_under_root(
            &[root_rp.clone()],
            &[child.to_string_lossy().into_owned()],
        )
        .expect("a direct child must be accepted");

        // A nested entry is refused by name, leaving the caller to keep the
        // previous generation.
        let err = validate_allowed_dirs_under_root(
            &[root_rp.clone()],
            &[nested.to_string_lossy().into_owned()],
        )
        .expect_err("a nested export must be refused");
        assert!(
            err.to_string().contains("nested exports are refused"),
            "refusal must name the nested-export rule, got: {err}"
        );

        // An entry outside the shared root is refused the same way.
        let outside = TestDir::new("outside-allow");
        let err = validate_allowed_dirs_under_root(
            &[root_rp.clone()],
            &[outside.path().to_string_lossy().into_owned()],
        )
        .expect_err("an outside export must be refused");
        assert!(
            err.to_string().contains("nested exports are refused"),
            "refusal must name the nested-export rule, got: {err}"
        );

        // The empty allow-list (clear) carries no entries and is accepted.
        validate_allowed_dirs_under_root(&[root_rp.clone()], &[]).expect("a clear must be accepted");
    }

    #[test]
    fn backend_serialization_guard_clears_marker_on_drop() {
        let pre_serialization = AtomicBool::new(true);

        {
            let _guard = BackendSerializationGuard::new(&pre_serialization);
            assert!(pre_serialization.load(Ordering::Acquire));
        }

        assert!(!pre_serialization.load(Ordering::Acquire));
    }

    fn new_test_fs(root: &Path) -> Fs {
        let backendfs_config = BackendFsConfig {
            shared_dir: root.to_string_lossy().into_owned(),
            read_only: false,
            cache: BACKEND_FS_CACHE_NONE,
            ..Default::default()
        };
        let mut fs = Fs::new(
            "testfs".to_string(),
            "testfs",
            1,
            128,
            SeccompAction::Allow,
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            false,
            None,
            &backendfs_config,
            None,
            None,
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            Arc::new(Mutex::new(Vec::new())),
        )
        .unwrap();

        let passthrough = PassthroughFs::new(passthrough::Config {
            root_dir: root.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.open_root_node().unwrap();
        fs.server = Some(Arc::new(ServerType::PassthroughFs(
            Server::new(passthrough, &[], None).unwrap(),
        )));
        fs
    }

    #[test]
    fn snapshot_prepares_backend_serialization_when_needed() {
        let root = TestDir::new("snapshot-prepare");
        let mut fs = new_test_fs(root.path());

        let snapshot = fs.snapshot().unwrap();
        let state: State = snapshot.to_state("testfs").unwrap();

        assert!(!state.back_state.is_empty());
        assert!(!fs.pre_serialization.load(Ordering::Acquire));
    }

    #[test]
    fn snapshot_reuses_started_migration_and_clears_marker() {
        let root = TestDir::new("snapshot-reuse");
        let mut fs = new_test_fs(root.path());

        fs.start_migration().unwrap();
        assert!(fs.pre_serialization.load(Ordering::Acquire));

        let snapshot = fs.snapshot().unwrap();
        let state: State = snapshot.to_state("testfs").unwrap();

        assert!(!state.back_state.is_empty());
        assert!(!fs.pre_serialization.load(Ordering::Acquire));
    }

    /// a vm.set-fs whose caller's bounded wait expired marks the queued
    /// event cancelled; the worker must drop it (never apply it late, which
    /// would export a volume the control plane never attached).
    #[test]
    fn cancelled_filter_update_is_not_applied() {
        let cancel = std::sync::atomic::AtomicBool::new(false);
        assert!(!fs_event_cancelled(&cancel));
        cancel.store(true, Ordering::Relaxed);
        assert!(fs_event_cancelled(&cancel));
    }
}
