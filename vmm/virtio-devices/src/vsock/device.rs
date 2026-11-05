// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

/// Virtio-vsock device.
///
/// Sandswap uses the kernel vhost-vsock backend exclusively. At `activate()`
/// the device hands guest memory + the virtqueues + the per-queue KICK/CALL/ERR
/// fds to the kernel vhost worker via `VhostVsockBackend::setup_kernel()`, then
/// spawns a thin watcher thread for the shared ERR fd (a vring error trips
/// `exit_evt` so the VM is torn down instead of hanging). The VMM never touches
/// a packet after activation — the data path lives entirely in the kernel
/// (zero VMEXIT per packet).
///
/// We aim to conform to the VirtIO v1.1 spec:
/// https://docs.virtio.org/virtio-v1.1/csic/devicenormative/
///
use super::{VhostVsockBackend, VsockBackend};
use crate::seccomp_filters::Thread;
use crate::GuestMemoryMmap;
use crate::VirtioInterrupt;
use crate::{
    thread_helper::spawn_virtio_thread, ActivateError, ActivateResult, EpollHelper,
    EpollHelperError, EpollHelperHandler, VirtioCommon, VirtioDevice, VirtioDeviceType,
    VirtioInterruptType, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IN_ORDER, VIRTIO_F_IOMMU_PLATFORM,
    VIRTIO_F_VERSION_1,
};
use byteorder::{ByteOrder, LittleEndian};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, RwLock};
use virtio_queue::Queue;
use vm_memory::GuestMemoryAtomic;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 3;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

// Notification coming from the backend (the vhost ERR fd).
pub const BACKEND_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

/// Minimal watcher for the vhost-vsock shared ERR fd. The kernel signals it
/// only on a virtqueue error (exceptional); on signal we trip the VMM
/// exit_evt so the VM is torn down instead of hanging. There is no
/// per-packet work — the data path lives entirely in the kernel.
struct VsockVhostErrHandler {
    err_fd: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    exit_evt: EventFd,
}

impl VsockVhostErrHandler {
    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.err_fd.as_raw_fd(), BACKEND_EVENT)?;
        helper.run(paused, paused_sync, self)?;
        Ok(())
    }
}

impl EpollHelperHandler for VsockVhostErrHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        if ev_type == BACKEND_EVENT {
            let _ = self.err_fd.read();
            error!("vhost-vsock: vring error signaled, requesting VM exit");
            let _ = self.exit_evt.write(1);
        }
        Ok(())
    }
}

/// Virtio device exposing a virtual socket to the guest, backed by the kernel
/// vhost-vsock worker.
pub struct Vsock {
    common: VirtioCommon,
    id: String,
    cid: u64,
    backend: Arc<RwLock<VhostVsockBackend>>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
}

#[derive(Serialize, Deserialize)]
pub struct VsockState {
    pub avail_features: u64,
    pub acked_features: u64,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM CID and vhost-vsock
    /// backend.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        cid: u64,
        iommu: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<VsockState>,
    ) -> std::io::Result<Vsock> {
        let (avail_features, acked_features) = if let Some(state) = state {
            debug!("Restoring virtio-vsock {}", id);
            (state.avail_features, state.acked_features)
        } else {
            let mut avail_features = 1u64 << VIRTIO_F_VERSION_1 | 1u64 << VIRTIO_F_IN_ORDER;
            if iommu {
                avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
            }
            (avail_features, 0)
        };

        Ok(Vsock {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Vsock as u32,
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                queue_sizes: QUEUE_SIZES.to_vec(),
                min_queues: NUM_QUEUES as u16,
                ..Default::default()
            },
            id: id.clone(),
            cid,
            backend: Arc::new(RwLock::new(VhostVsockBackend::new(
                format!("{id}-backend"),
                cid,
            )?)),
            seccomp_action,
            exit_evt,
        })
    }

    fn state(&self) -> VsockState {
        VsockState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
        }
    }
}

impl Drop for Vsock {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

/// The feature set the kernel vhost-vsock backend is allowed to see: an
/// explicit allow-list, not the host vhost feature set. The guest negotiates
/// VERSION_1/IN_ORDER; EVENT_IDX is kept unconditionally for the kernel's ring
/// layout (see activate). Everything else the host advertises — INDIRECT_DESC,
/// ANY_LAYOUT, NOTIFY_ON_EMPTY, SEQPACKET, LOG_ALL, IOMMU_PLATFORM — is never
/// presented as negotiated, so vhost cannot be steered into parsing descriptor
/// shapes the guest never agreed to.
fn vsock_guest_features(acked: u64) -> u64 {
    const VIRTIO_F_EVENT_IDX: u64 = 1 << 29;
    (1u64 << VIRTIO_F_VERSION_1)
        | (acked & (1u64 << VIRTIO_F_IN_ORDER))
        | VIRTIO_F_EVENT_IDX
}

impl VirtioDevice for Vsock {
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
        match offset {
            0 if data.len() == 8 => LittleEndian::write_u64(data, self.cid),
            0 if data.len() == 4 => LittleEndian::write_u32(data, (self.cid & 0xffff_ffff) as u32),
            4 if data.len() == 4 => {
                LittleEndian::write_u32(data, ((self.cid >> 32) & 0xffff_ffff) as u32)
            }
            _ => warn!(
                "vsock: virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, &interrupt_cb)?;

        // Hand the rings + fds to the kernel vhost worker and do NOT spawn a
        // VMM data-path handler (the kernel owns the rings; a user-space
        // handler would race it). KICK = per-queue queue_evt (already a KVM
        // ioeventfd), CALL = per-queue irqfd notifier (already a KVM irqfd)
        // → zero VMEXIT on both directions.
        //
        // Resolve the per-queue CALL notifiers. Each is a dup of the KVM irqfd
        // for that queue's MSIX vector; None falls back to a userspace eventfd
        // inside setup_kernel (Sandswap always uses MSIX, so Some is normal).
        let call_fds: Vec<Option<EventFd>> = (0..queues.len())
            .map(|i| interrupt_cb.notifier(VirtioInterruptType::Queue(i as u16)))
            .collect();

        // The kernel vhost-vsock backend must see ONLY the features the guest
        // actually negotiated. `acked_features` is the guest-acked device set
        // (VERSION_1/IN_ORDER); every other host-vhost bit (INDIRECT_DESC,
        // ANY_LAYOUT, NOTIFY_ON_EMPTY, SEQPACKET) stays off, or a malicious
        // guest could exercise vhost's unnegotiated descriptor paths (the
        // V-06 audit item). EVENT_IDX is the one deliberate exception: the
        // kernel sizes the rings with it and clearing it has historically
        // failed VHOST_VSOCK_SET_RUNNING with EFAULT; V-01 validates the
        // event-idx tail spans, so the bit only covers guest-owned memory.
        let guest_features = vsock_guest_features(self.common.acked_features);

        self.backend
            .read()
            .unwrap()
            .setup_kernel(&mem, &queues, call_fds, guest_features)
            .map_err(|e| {
                error!("vhost-vsock setup failed: {e:?}");
                ActivateError::VhostVsockSetup(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("{e:?}"),
                ))
            })?;

        // Watch the shared ERR fd: a vring error trips exit_evt so the VMM
        // tears the VM down rather than hanging. No per-packet work.
        let err_fd = self
            .backend
            .read()
            .unwrap()
            .err_fd_try_clone()
            .map_err(ActivateError::CloneExitEventFd)?
            .ok_or_else(|| {
                ActivateError::VhostVsockSetup(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "vhost-vsock backend has no ERR fd",
                ))
            })?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();
        let exit_evt = self
            .exit_evt
            .try_clone()
            .map_err(ActivateError::CloneExitEventFd)?;
        let mut handler = VsockVhostErrHandler {
            err_fd,
            kill_evt,
            pause_evt,
            exit_evt,
        };
        let mut epoll_threads = Vec::new();
        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVsock,
            &mut epoll_threads,
            &self.exit_evt,
            move || handler.run(paused, paused_sync.unwrap()),
        )?;
        self.common.epoll_threads = Some(epoll_threads);

        event!(
            "virtio-device",
            "activated",
            "id",
            &self.id,
            "mode",
            "vhost"
        );
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        result
    }

    fn shutdown(&mut self) {}

    fn set_access_platform(&mut self, access_platform: Arc<dyn vm_virtio::AccessPlatform>) {
        self.common.set_access_platform(access_platform)
    }
}

impl Pausable for Vsock {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Vsock {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        let mut snapshot = Snapshot::new_from_state(&self.id, &self.state())?;
        snapshot.add_snapshot(self.backend.write().unwrap().snapshot()?);
        Ok(snapshot)
    }
}
impl Transportable for Vsock {}
impl Migratable for Vsock {}

#[cfg(test)]
mod tests {
    use super::vsock_guest_features;

    const VIRTIO_F_NOTIFY_ON_EMPTY: u64 = 1 << 24;
    const VHOST_F_LOG_ALL: u64 = 1 << 26;
    const VIRTIO_F_ANY_LAYOUT: u64 = 1 << 27;
    const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1 << 28;
    const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;
    const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    const VIRTIO_F_IOMMU_PLATFORM: u64 = 1 << 33;
    const VIRTIO_F_IN_ORDER: u64 = 1 << 35;

    #[test]
    fn guest_features_are_an_allowlist() {
        let f = vsock_guest_features(VIRTIO_F_VERSION_1 | VIRTIO_F_IN_ORDER);
        assert_ne!(f & VIRTIO_F_VERSION_1, 0);
        assert_ne!(f & VIRTIO_F_IN_ORDER, 0);
        assert_ne!(f & VIRTIO_F_RING_EVENT_IDX, 0, "EVENT_IDX is kept for the kernel ring layout");
        for bit in [
            VIRTIO_F_NOTIFY_ON_EMPTY,
            VHOST_F_LOG_ALL,
            VIRTIO_F_ANY_LAYOUT,
            VIRTIO_F_RING_INDIRECT_DESC,
            VIRTIO_F_IOMMU_PLATFORM,
            1u64, // VIRTIO_VSOCK_F_SEQPACKET (device feature bit 0)
        ] {
            assert_eq!(f & bit, 0, "unnegotiated feature {bit:#x} must not reach vhost");
        }
    }

    #[test]
    fn in_order_is_intersected_with_the_guest_ack() {
        let f = vsock_guest_features(VIRTIO_F_VERSION_1);
        assert_eq!(f & VIRTIO_F_IN_ORDER, 0, "IN_ORDER must follow the guest ack");
        assert_ne!(f & VIRTIO_F_VERSION_1, 0);
        assert_ne!(f & VIRTIO_F_RING_EVENT_IDX, 0);
    }
}
