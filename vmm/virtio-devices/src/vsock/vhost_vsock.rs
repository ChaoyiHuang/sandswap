// Copyright 2024 Sandswap. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// kernel vhost-vsock backend: offloads the entire vsock data path to the
// Linux kernel via /dev/vhost-vsock. A kernel vhost worker thread directly
// reads/writes the guest virtio queues through shared memory and signals
// completion via the per-queue KVM irqfd — zero VMEXIT, zero VMM user-space
// involvement per packet.
//
// fd wiring (the crux of the zero-VMEXIT property):
//   KICK (guest → device) = the per-queue `queue_evt` EventFd, which the PCI
//     transport has ALREADY registered with KVM as an ioeventfd. The guest
//     kick therefore never exits the guest — KVM signals the eventfd in
//     kernel, and the vhost worker (which polls the same eventfd object via
//     a dup'd fd) drains it. No VMM thread is woken.
//   CALL (device → guest) = `interrupt_cb.notifier(Queue(i))`, i.e. a dup of
//     the per-queue KVM irqfd (registered via register_irqfd). When the vhost
//     worker writes it, KVM injects the MSIX IRQ directly in-kernel. Again no
//     VMM wake. (If a queue has no irqfd notifier — e.g. INTx — we fall back
//     to a plain userspace eventfd; that path still wakes a VMM thread to call
//     interrupt_cb.trigger(), costing one host wakeup per RX batch.)
//   ERR = a fresh eventfd watched by a thin thread that trips exit_evt.
//
// Uses direct ioctl(2) against /dev/vhost-vsock — zero external crate
// dependencies beyond libc. The ioctl ABI is stable (<linux/vhost.h>).

use super::VsockBackend;
use crate::{get_host_address_range, GuestMemoryMmap};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::sync::RwLock;
use virtio_queue::{Descriptor, Queue, QueueT};
use vm_memory::{
    GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryRegion,
};
use vm_migration::{MigratableError, Pausable, Snapshot, Snapshottable};
use vmm_sys_util::eventfd::EventFd;

// ── Linux vhost ioctl ABI (stable, from <linux/vhost.h>) ──────────────────
// ioctl encoding: _IO/_IOW/_IOR(type, nr, size); VHOST_VIRTIO magic = 0xAF.
// We hand-roll the encoding (matching the kernel's _IO/_IOW/_IOR macros) so
// we depend on no external vhost crate — the ABI is frozen.

const VHOST: u8 = 0xAF;

macro_rules! vhost_cmd_none {
    ($nr:expr) => {
        (0u64 << 30) | ((VHOST as u64) << 8) | ($nr as u64)
    };
}
macro_rules! vhost_cmd_read {
    ($nr:expr, $t:ty) => {
        (2u64 << 30)
            | ((std::mem::size_of::<$t>() as u64) << 16)
            | ((VHOST as u64) << 8)
            | ($nr as u64)
    };
}
macro_rules! vhost_cmd_write {
    ($nr:expr, $t:ty) => {
        (1u64 << 30)
            | ((std::mem::size_of::<$t>() as u64) << 16)
            | ((VHOST as u64) << 8)
            | ($nr as u64)
    };
}

const VHOST_SET_OWNER: u64 = vhost_cmd_none!(0x01);
const VHOST_GET_FEATURES: u64 = vhost_cmd_read!(0x00, u64);
const VHOST_SET_FEATURES: u64 = vhost_cmd_write!(0x00, u64);
const VHOST_SET_MEM_TABLE: u64 = vhost_cmd_write!(0x03, VhostMemory);
const VHOST_SET_VRING_NUM: u64 = vhost_cmd_write!(0x10, VhostVringState);
const VHOST_SET_VRING_ADDR: u64 = vhost_cmd_write!(0x11, VhostVringAddr);
const VHOST_SET_VRING_BASE: u64 = vhost_cmd_write!(0x12, VhostVringState);
const VHOST_SET_VRING_KICK: u64 = vhost_cmd_write!(0x20, VhostVringFile);
const VHOST_SET_VRING_CALL: u64 = vhost_cmd_write!(0x21, VhostVringFile);
const VHOST_SET_VRING_ERR: u64 = vhost_cmd_write!(0x22, VhostVringFile);
const VHOST_VSOCK_SET_GUEST_CID: u64 = vhost_cmd_write!(0x60, u64);
const VHOST_VSOCK_SET_RUNNING: u64 = vhost_cmd_write!(0x61, i32);

// ── C-struct layout matching <linux/vhost_types.h> ────────────────────────

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VhostVringState {
    index: u32,
    num: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VhostVringFile {
    index: u32,
    fd: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VhostVringAddr {
    index: u32,
    flags: u32,
    desc_user_addr: u64,
    used_user_addr: u64,
    avail_user_addr: u64,
    log_guest_addr: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VhostMemoryRegion {
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    flags_padding: u64,
}

#[repr(C)]
struct VhostMemory {
    nregions: u32,
    padding: u32,
}

// ── State (snapshot is a no-op: vhost state is not migrated by Sandswap) ──

#[derive(Default, Serialize, Deserialize)]
pub struct VhostVsockState {}

// ── Backend ───────────────────────────────────────────────────────────────

pub struct VhostVsockBackend {
    id: String,
    cid: u64,
    vhost_fd: RwLock<Option<File>>,
    // Per-queue KICK/CALL fds kept alive for the device lifetime: the kernel
    // vhost worker references them by fd number, so they must not be closed.
    kick_fds: RwLock<Vec<EventFd>>,
    call_fds: RwLock<Vec<Option<EventFd>>>,
    err_fd: EventFd,
}

fn check(ret: i32) -> anyhow::Result<()> {
    if ret != 0 {
        Err(anyhow!("ioctl failed: {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// Serialize the VHOST_SET_MEM_TABLE payload: the variable-length
/// `struct vhost_memory` — an 8-byte header followed CONTIGUOUSLY by the
/// region array (there is no per-region padding; the whole struct is a
/// multiple of 8 bytes). Backed by u64 words so the members the ioctl
/// reads are aligned by construction, not by allocator luck.
///
/// All pointer arithmetic is done on a `*mut u8` base: `ptr::add` on a
/// typed pointer counts ELEMENTS, and advancing a `*mut u64` by the
/// byte-size of the header lands the regions 8× too far out (an all-zero
/// memory table → EFAULT from VHOST_VSOCK_SET_RUNNING — caught by e2e,
/// invisible to the type system).
fn build_vhost_memory_table(regions: &[VhostMemoryRegion]) -> Vec<u64> {
    let header_size = std::mem::size_of::<VhostMemory>();
    let region_size = std::mem::size_of::<VhostMemoryRegion>();
    let total = header_size + regions.len() * region_size;
    debug_assert_eq!(total % std::mem::size_of::<u64>(), 0);

    let mut buf: Vec<u64> = vec![0u64; total / std::mem::size_of::<u64>()];
    // SAFETY: `base` points to `total` writable, 8-aligned bytes owned by
    // `buf`; the header and region writes below stay within bounds, do not
    // overlap, and the only pointers derived from `base` die before `buf`
    // is read again.
    unsafe {
        let base = buf.as_mut_ptr().cast::<u8>();
        let hdr = base as *mut VhostMemory;
        (*hdr).nregions = regions.len() as u32;
        (*hdr).padding = 0;
        let dst = base.add(header_size) as *mut VhostMemoryRegion;
        std::ptr::copy_nonoverlapping(regions.as_ptr(), dst, regions.len());
    }
    buf
}

// Split virtqueue ring layout (virtio 1.x §2.6.7 / §2.7).
const VIRTQ_USED_RING_HEADER_SIZE: usize = 4; // le16 flags + le16 idx
const VIRTQ_USED_ELEMENT_SIZE: usize = 8; // le32 id + le32 len
const VIRTQ_AVAIL_RING_HEADER_SIZE: usize = 4; // le16 flags + le16 idx
const VIRTQ_AVAIL_ELEMENT_SIZE: usize = 2; // le16 ring entry

// `used_event` (avail ring tail) and `avail_event` (used ring tail) exist
// whenever VIRTIO_RING_F_EVENT_IDX is negotiated.
const VIRTQ_EVENT_IDX_SIZE: usize = 2;

/// Exact byte spans the kernel vhost worker accesses for a queue of `num`
/// entries: descriptor table, used ring and available ring. The EVENT_IDX
/// fields are always included: the kernel sizes the rings from the feature
/// set handed to `VHOST_SET_FEATURES`, so the validation must cover the
/// kernel's widest layout rather than only the negotiated one.
fn vring_spans(num: u16) -> (usize, usize, usize) {
    let num = usize::from(num);
    (
        num * std::mem::size_of::<Descriptor>(),
        VIRTQ_USED_RING_HEADER_SIZE + num * VIRTQ_USED_ELEMENT_SIZE + VIRTQ_EVENT_IDX_SIZE,
        VIRTQ_AVAIL_RING_HEADER_SIZE + num * VIRTQ_AVAIL_ELEMENT_SIZE + VIRTQ_EVENT_IDX_SIZE,
    )
}

/// The features handed to VHOST_SET_FEATURES: the host's vhost set intersected
/// with the guest-negotiated allow-list. The intersection is where an
/// unnegotiated host bit (INDIRECT_DESC, ANY_LAYOUT, NOTIFY_ON_EMPTY,
/// SEQPACKET, LOG_ALL, IOMMU_PLATFORM) is dropped before the kernel backend
/// can act on it; see the call site for the full rationale.
fn vhost_features_for(host: u64, guest: u64) -> u64 {
    host & guest
}

impl VhostVsockBackend {
    pub fn new(id: String, cid: u64) -> std::io::Result<Self> {
        Ok(Self {
            id,
            cid,
            vhost_fd: RwLock::new(None),
            kick_fds: RwLock::new(Vec::new()),
            call_fds: RwLock::new(Vec::new()),
            err_fd: EventFd::new(libc::EFD_NONBLOCK).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("err_fd: {e}"))
            })?,
        })
    }

    /// Open /dev/vhost-vsock and register guest memory + virtqueues with the
    /// kernel. Called from Vsock::activate() once guest memory & the irqfd
    /// notifiers are ready.
    ///
    /// `queues[i].2` is the per-queue KICK eventfd (already a KVM ioeventfd);
    /// `call_fds[i]` is the per-queue CALL notifier (a KVM irqfd dup when
    /// available, else None → a userspace fallback eventfd is created).
    fn setup_kernel_impl(
        &self,
        mem: &GuestMemoryAtomic<GuestMemoryMmap>,
        queues: &[(usize, Queue, EventFd)],
        call_fds: Vec<Option<EventFd>>,
        guest_features: u64,
    ) -> anyhow::Result<()> {
        let mem_guard = mem.memory();
        let vhost_file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/vhost-vsock")
            .context("open /dev/vhost-vsock")?;
        let fd = vhost_file.as_raw_fd();

        // 1. VHOST_SET_OWNER — bind this fd to a vhost-vsock device.
        check(unsafe { libc::ioctl(fd, VHOST_SET_OWNER as _) }).context("VHOST_SET_OWNER")?;

        // 2. Feature negotiation: the kernel backend is told ONLY the guest's
        //    negotiated set (an explicit allow-list computed by the device:
        //    VERSION_1, IN_ORDER when acked, EVENT_IDX for the ring layout).
        //    Intersecting with the host's VHOST_GET_FEATURES keeps every vhost
        //    bit the guest never acked — INDIRECT_DESC, ANY_LAYOUT,
        //    NOTIFY_ON_EMPTY, SEQPACKET — out of the kernel backend's
        //    descriptor parsing (V-06). LOG_ALL and IOMMU_PLATFORM are absent
        //    from the allow-list as well: LOG_ALL would need a log_base, and
        //    IOMMU_PLATFORM would put vhost in IOTLB mode while we pass host
        //    user-virtual addresses.
        let mut features: u64 = 0;
        check(unsafe { libc::ioctl(fd, VHOST_GET_FEATURES as _, &mut features) })
            .context("VHOST_GET_FEATURES")?;
        let features = vhost_features_for(features, guest_features);
        check(unsafe { libc::ioctl(fd, VHOST_SET_FEATURES as _, &features) })
            .context("VHOST_SET_FEATURES")?;

        // 3. VHOST_SET_MEM_TABLE — share guest memory regions with the kernel.
        let regions: Vec<VhostMemoryRegion> = mem_guard
            .iter()
            .map(|r| VhostMemoryRegion {
                guest_phys_addr: r.start_addr().0,
                memory_size: r.len(),
                userspace_addr: r.as_ptr() as u64,
                flags_padding: 0,
            })
            .collect();
        let buf = build_vhost_memory_table(&regions);
        check(unsafe { libc::ioctl(fd, VHOST_SET_MEM_TABLE as _, buf.as_ptr()) })
            .context("VHOST_SET_MEM_TABLE")?;

        // 4. Per-vring setup: RX=0, TX=1, EVT=2. Each vring gets its own
        //    KICK / CALL / ERR fd. KICK comes from the queue_evt (KVM
        //    ioeventfd); CALL from the per-queue irqfd notifier (or a
        //    userspace fallback).
        let mut owned_kicks: Vec<EventFd> = Vec::with_capacity(queues.len());
        let mut owned_calls: Vec<Option<EventFd>> = Vec::with_capacity(queues.len());
        // take ownership of each per-queue CALL notifier by value (EventFd is
        // not Clone, only try_clone, so we move them out of the Vec).
        let mut call_fds = call_fds;

        // vhost-vsock's kernel backend only has 2 vqs (RX=0, TX=1); there is no
        // event vq in vhost-vsock (the guest's event queue is not offloaded).
        // SET_VRING_* for index >= 2 returns ENOBUFS.
        let nvqs = queues.len().min(2);

        for idx in 0..nvqs {
            let (_q_idx, queue, kick_evt) = &queues[idx];
            let vi = idx as u32;
            let size = queue.size();

            let vrs = VhostVringState {
                index: vi,
                num: size as u32,
            };
            check(unsafe { libc::ioctl(fd, VHOST_SET_VRING_NUM as _, &vrs) })
                .context(format!("VHOST_SET_VRING_NUM {vi}"))?;

            // vhost wants HOST user-virtual addresses (the mmap'd guest
            // memory pointers), not guest physical addresses — translate.
            // Validate the FULL ring span, not just the base address: the
            // kernel's own access_ok() only checks that the user address is
            // below TASK_SIZE, so a base placed near the end of a guest RAM
            // region would otherwise let the vhost worker's
            // copy_{from,to}_user() run past the region into the sandvmm
            // mapping that follows it. A span outside guest memory refuses
            // activation.
            let (desc_len, used_len, avail_len) = vring_spans(size);
            let desc_host =
                get_host_address_range(&*mem_guard, GuestAddress(queue.desc_table()), desc_len)
                    .ok_or_else(|| {
                        anyhow!(
                            "desc_table span outside guest memory (addr 0x{:x}, len {desc_len})",
                            queue.desc_table()
                        )
                    })? as u64;
            let used_host =
                get_host_address_range(&*mem_guard, GuestAddress(queue.used_ring()), used_len)
                    .ok_or_else(|| {
                        anyhow!(
                            "used_ring span outside guest memory (addr 0x{:x}, len {used_len})",
                            queue.used_ring()
                        )
                    })? as u64;
            let avail_host =
                get_host_address_range(&*mem_guard, GuestAddress(queue.avail_ring()), avail_len)
                    .ok_or_else(|| {
                        anyhow!(
                            "avail_ring span outside guest memory (addr 0x{:x}, len {avail_len})",
                            queue.avail_ring()
                        )
                    })? as u64;

            let vra = VhostVringAddr {
                index: vi,
                flags: 0,
                desc_user_addr: desc_host,
                used_user_addr: used_host,
                avail_user_addr: avail_host,
                log_guest_addr: 0,
            };
            check(unsafe { libc::ioctl(fd, VHOST_SET_VRING_ADDR as _, &vra) })
                .context(format!("VHOST_SET_VRING_ADDR {vi}"))?;

            let vrb = VhostVringState { index: vi, num: 0 };
            check(unsafe { libc::ioctl(fd, VHOST_SET_VRING_BASE as _, &vrb) })
                .context(format!("VHOST_SET_VRING_BASE {vi}"))?;

            // KICK: dup the queue_evt so we keep it alive; the kernel polls it.
            let kick = kick_evt.try_clone().context("clone kick evt for vhost")?;
            let vk = VhostVringFile {
                index: vi,
                fd: kick.as_raw_fd(),
            };
            check(unsafe { libc::ioctl(fd, VHOST_SET_VRING_KICK as _, &vk) })
                .context(format!("VHOST_SET_VRING_KICK {vi}"))?;

            // CALL: use the irqfd notifier if available (zero-VMEXIT path).
            // A None fallback eventfd is created only to satisfy the vhost
            // ioctl — nothing drains it, so RX completions on it would be
            // lost. That cannot happen on the virtio-pci transport used
            // here (MSI-X always provides an irqfd notifier); if a future
            // transport returns None, Vsock::activate() must also wire a
            // watcher thread to call interrupt_cb.trigger().
            let call = match call_fds.get_mut(idx).and_then(Option::take) {
                Some(notifier) => notifier,
                None => EventFd::new(libc::EFD_NONBLOCK).context("call fallback evt")?,
            };
            let vc = VhostVringFile {
                index: vi,
                fd: call.as_raw_fd(),
            };
            check(unsafe { libc::ioctl(fd, VHOST_SET_VRING_CALL as _, &vc) })
                .context(format!("VHOST_SET_VRING_CALL {vi}"))?;

            // ERR: shared across vsock vqs (errors are exceptional); the
            // activate() path spawns a watcher that trips exit_evt on signal.
            let ve = VhostVringFile {
                index: vi,
                fd: self.err_fd.as_raw_fd(),
            };
            check(unsafe { libc::ioctl(fd, VHOST_SET_VRING_ERR as _, &ve) })
                .context(format!("VHOST_SET_VRING_ERR {vi}"))?;

            owned_kicks.push(kick);
            owned_calls.push(Some(call));
        }

        // 5. VHOST_VSOCK_SET_GUEST_CID — route this CID to this vhost device.
        check(unsafe { libc::ioctl(fd, VHOST_VSOCK_SET_GUEST_CID as _, &self.cid) })
            .context(format!("VHOST_VSOCK_SET_GUEST_CID {}", self.cid))?;

        // 6. VHOST_VSOCK_SET_RUNNING — start the kernel data-path worker.
        let on: i32 = 1;
        check(unsafe { libc::ioctl(fd, VHOST_VSOCK_SET_RUNNING as _, &on) })
            .context("VHOST_VSOCK_SET_RUNNING")?;

        // Stash owned fds + the vhost file so they outlive activate().
        *self.kick_fds.write().unwrap() = owned_kicks;
        *self.call_fds.write().unwrap() = owned_calls;
        *self.vhost_fd.write().unwrap() = Some(vhost_file);
        Ok(())
    }
}

// ── VsockBackend ──────────────────────────────────────────────────────────

impl VsockBackend for VhostVsockBackend {
    fn setup_kernel(
        &self,
        mem: &GuestMemoryAtomic<GuestMemoryMmap>,
        queues: &[(usize, Queue, EventFd)],
        call_fds: Vec<Option<EventFd>>,
        guest_features: u64,
    ) -> anyhow::Result<()> {
        // Delegate to the inherent impl (defined above).
        VhostVsockBackend::setup_kernel_impl(self, mem, queues, call_fds, guest_features)
    }

    fn err_fd_try_clone(&self) -> std::io::Result<Option<EventFd>> {
        Ok(Some(self.err_fd.try_clone()?))
    }
}

// ── Pausable / Snapshottable ──────────────────────────────────────────────

impl Pausable for VhostVsockBackend {}

impl Snapshottable for VhostVsockBackend {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.id, &VhostVsockState::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vhost_ioctl_abi_constants() {
        // Reference: <include/uapi/linux/vhost.h> and <linux/vhost_types.h>.
        // The values are hand-encoded via the macros above; a wrong encoding
        // is not a compile error — it silently ENOTTYs the vsock data path
        // at runtime — so pin every command number and the struct layouts
        // the encoding is derived from.
        assert_eq!(VHOST_SET_OWNER, 0x0000_af01);
        assert_eq!(VHOST_GET_FEATURES, 0x8008_af00);
        assert_eq!(VHOST_SET_FEATURES, 0x4008_af00);
        assert_eq!(VHOST_SET_MEM_TABLE, 0x4008_af03);
        assert_eq!(VHOST_SET_VRING_NUM, 0x4008_af10);
        assert_eq!(VHOST_SET_VRING_ADDR, 0x4028_af11);
        assert_eq!(VHOST_SET_VRING_BASE, 0x4008_af12);
        assert_eq!(VHOST_SET_VRING_KICK, 0x4008_af20);
        assert_eq!(VHOST_SET_VRING_CALL, 0x4008_af21);
        assert_eq!(VHOST_SET_VRING_ERR, 0x4008_af22);
        assert_eq!(VHOST_VSOCK_SET_GUEST_CID, 0x4008_af60);
        assert_eq!(VHOST_VSOCK_SET_RUNNING, 0x4004_af61);
    }

    #[test]
    fn test_vhost_memory_table_byte_layout() {
        // The regions must land at byte offset 8 (right after the header),
        // byte-for-byte. A prior version advanced a *mut u64 by the header's
        // BYTE size, which `ptr::add` interprets as ELEMENTS — the regions
        // landed at offset 64, the kernel read an all-zero memory table and
        // VHOST_VSOCK_SET_RUNNING failed with EFAULT.
        let regions = vec![
            VhostMemoryRegion {
                guest_phys_addr: 0x0,
                memory_size: 0x1000_0000,
                userspace_addr: 0x7f00_0000_0000,
                flags_padding: 0xdead_beef,
            },
            VhostMemoryRegion {
                guest_phys_addr: 0x2000_0000,
                memory_size: 0x1000,
                userspace_addr: 0x7f10_0000_0000,
                flags_padding: 0,
            },
        ];

        let buf = build_vhost_memory_table(&regions);

        // Round-trip through bytes to verify the exact wire layout.
        let bytes: Vec<u8> = buf.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(bytes.len(), 8 + 2 * 32);

        let nregions = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(nregions, 2);
        let padding = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(padding, 0);

        let rd = |off: usize| u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        // Region 0 at byte offset 8.
        assert_eq!(rd(8), 0x0);
        assert_eq!(rd(16), 0x1000_0000);
        assert_eq!(rd(24), 0x7f00_0000_0000);
        assert_eq!(rd(32), 0xdead_beef);
        // Region 1 at byte offset 40 (= 8 + 32).
        assert_eq!(rd(40), 0x2000_0000);
        assert_eq!(rd(48), 0x1000);
        assert_eq!(rd(56), 0x7f10_0000_0000);
        assert_eq!(rd(64), 0);
    }

    #[test]
    fn test_vhost_struct_layouts() {
        // The ioctl size bits above are size_of::<T>() — keep them in lockstep.
        assert_eq!(std::mem::size_of::<VhostVringState>(), 8);
        assert_eq!(std::mem::size_of::<VhostVringFile>(), 8);
        assert_eq!(std::mem::size_of::<VhostVringAddr>(), 40);
        assert_eq!(std::mem::size_of::<VhostMemoryRegion>(), 32);
        assert_eq!(std::mem::size_of::<VhostMemory>(), 8);
    }

    #[test]
    fn test_vring_spans_include_event_idx_fields() {
        // 256 entries: desc = 256 * 16 = 4096;
        // used = 4 + 256 * 8 + 2 = 2054; avail = 4 + 256 * 2 + 2 = 518.
        assert_eq!(vring_spans(256), (4096, 2054, 518));
        // Even an empty queue owns both ring headers and both event fields.
        assert_eq!(vring_spans(0), (0, 6, 6));
    }

    #[test]
    fn test_ring_span_validation_rejects_region_tail_overrun() {
        // One 0x4000-byte guest region. A descriptor table whose base is
        // mapped but whose 256-entry span runs off the region end must be
        // refused, while a span that ends exactly at the region end is
        // accepted.
        let mem: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), 0x4000)]).unwrap();
        let (desc_len, _, _) = vring_spans(256);

        let tail_base = 0x4000 - std::mem::size_of::<Descriptor>() as u64;
        assert!(get_host_address_range(&mem, GuestAddress(tail_base), 16).is_some());
        assert!(get_host_address_range(&mem, GuestAddress(tail_base), desc_len).is_none());

        assert!(
            get_host_address_range(&mem, GuestAddress(0x4000 - desc_len as u64), desc_len)
                .is_some()
        );
        assert!(get_host_address_range(&mem, GuestAddress(0x8000), 16).is_none());
    }

    #[test]
    fn test_vhost_features_intersect_the_guest_ack() {
        const VERSION_1: u64 = 1 << 32;
        const IN_ORDER: u64 = 1 << 35;
        const EVENT_IDX: u64 = 1 << 29;
        // The host vhost set also carries these; the guest never acked them.
        let host_only = [
            1u64 << 24, // NOTIFY_ON_EMPTY
            1u64 << 26, // LOG_ALL
            1u64 << 27, // ANY_LAYOUT
            1u64 << 28, // INDIRECT_DESC
            1u64 << 33, // IOMMU_PLATFORM
            1u64,       // VIRTIO_VSOCK_F_SEQPACKET (device feature bit 0)
        ];
        let guest = VERSION_1 | IN_ORDER | EVENT_IDX;
        let host = guest | host_only.iter().copied().fold(0, |acc, bit| acc | bit);
        let features = vhost_features_for(host, guest);
        assert_eq!(features, guest, "only the guest-acked allow-list may reach vhost");
        for bit in host_only {
            assert_eq!(features & bit, 0, "unnegotiated host bit {bit:#x} leaked to vhost");
        }
    }
}
