// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Virtio-vsock device.
//!
//! Sandswap uses the **kernel vhost-vsock** backend exclusively
//! (`VhostVsockBackend`): the entire vsock data path is offloaded to the
//! Linux kernel via `/dev/vhost-vsock`. The VMM only sets the device up at
//! `activate()` time (handing the guest memory + virtqueues + KICK/CALL/ERR
//! fds to the kernel worker) and otherwise never touches a packet — zero
//! VMEXIT per packet, zero VMM user-space involvement on the hot path.

mod device;
mod vhost_vsock;

pub use self::device::Vsock;
pub use self::vhost_vsock::VhostVsockBackend;

use vm_migration::Snapshottable;

/// The vsock backend. Sandswap has a single implementation,
/// `VhostVsockBackend`, which offloads the data path to the kernel.
///
/// `setup_kernel` is called once from `Vsock::activate()` after guest memory
/// and the per-queue KVM irqfd notifiers are ready. It opens `/dev/vhost-vsock`,
/// registers guest memory + the virtqueues with the kernel worker, and starts
/// the worker. After it returns, the VMM never participates in vsock I/O.
pub trait VsockBackend: Snapshottable + Send {
    /// Hand guest memory + virtqueues + per-queue CALL notifiers to the kernel
    /// vhost-vsock worker.
    fn setup_kernel(
        &self,
        mem: &vm_memory::GuestMemoryAtomic<crate::GuestMemoryMmap>,
        queues: &[(usize, virtio_queue::Queue, vmm_sys_util::eventfd::EventFd)],
        call_fds: Vec<Option<vmm_sys_util::eventfd::EventFd>>,
        guest_features: u64,
    ) -> anyhow::Result<()>;

    /// A dup of the vhost ERR eventfd for the watcher thread that trips
    /// exit_evt on a virtqueue error.
    fn err_fd_try_clone(&self) -> std::io::Result<Option<vmm_sys_util::eventfd::EventFd>>;
}
