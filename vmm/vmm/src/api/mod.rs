// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! The internal VMM API for Cloud Hypervisor.
//!
//! This API is a synchronous, [mpsc](https://doc.rust-lang.org/std/sync/mpsc/)
//! based IPC for sending commands to the VMM thread, from other
//! Cloud Hypervisor threads. The IPC follows a command-response protocol, i.e.
//! each command will receive a response back.
//!
//! The main Cloud Hypervisor thread creates an API event file descriptor
//! to notify the VMM thread about pending API commands, together with an
//! API mpsc channel. The former is the IPC control channel, the latter is the
//! IPC data channel.
//! In order to use the IPC, a Cloud Hypervisor thread needs to have a clone
//! of both the API event file descriptor and the channel Sender. Then it must
//! go through the following steps:
//!
//! 1. The thread creates an mpsc channel for receiving the command response.
//! 2. The thread sends an ApiRequest to the Sender endpoint. The ApiRequest
//!    contains the response channel Sender, for the VMM API server to be able
//!    to send the response back.
//! 3. The thread writes to the API event file descriptor to notify the VMM
//!    API server about a pending command.
//! 4. The thread reads the response back from the VMM API server, from the
//!    response channel Receiver.
//! 5. The thread handles the response and forwards potential errors.

pub use self::http::start_api_dispatcher;
pub use self::http::start_http_fd_thread;
use core::fmt;
use std::fmt::Display;

pub mod http;
pub mod service;

use crate::api::service::VMM_SERVICE;
use crate::device_tree::DeviceTree;
use crate::vm::{Error as VmError, VmState};
use crate::vm_config::{FsConfig, VmConfig, VsockConfig};
use micro_http::Body;
use serde::{Deserialize, Serialize};
use service::Error as VmmServiceError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const SNAPSHOT_VERSION: &str = "1.0.3";

/// API errors are sent back from the VMM API server through the ApiResponse.
#[derive(Debug)]
pub enum ApiError {
    /// Wrong response payload type
    ResponsePayloadType,

    /// The VM could not boot.
    VmBoot(VmError),

    /// The VM could not be created.
    VmCreate(VmError),

    /// The VM could not be deleted.
    VmDelete(VmError),

    /// The VM info is not available.
    VmInfo(VmError),

    /// The VM could not be paused.
    VmPause(VmError),

    /// The VM could not be paused or snapshot or deleted.

    /// The VM could not resume.
    VmResume(VmError),

    /// The VM could not be restored or resumed.

    /// The VM is not booted.
    VmNotBooted,

    /// The VM is not created.
    VmNotCreated,

    /// The VM could not shutdown.
    VmShutdown(VmError),

    /// The VM could not reboot.
    VmReboot(VmError),

    /// The VM could not be snapshotted.

    /// The VM could not restored.

    /// The VM could not be coredumped.

    /// The VMM could not shutdown.
    VmmShutdown(VmError),

    /// The VM could not be resized
    VmResize(VmError),

    /// The memory zone could not be resized.
    VmResizeZone(VmError),

    /// The device could not be added to the VM.

    /// The user device could not be added to the VM.

    /// The device could not be removed from the VM.

    /// Cannot create seccomp filter
    CreateSeccompFilter(seccompiler::Error),

    /// Cannot apply seccomp filter
    ApplySeccompFilter(seccompiler::Error),

    /// The disk could not be added to the VM.

    // Modified by Sandswap (c) 2026: the VmAddFs error variant was removed
    // together with the vm.add-fs endpoint — a VM in Sandswap has exactly ONE
    // virtio-fs device, created at boot; see the note on ApiRequest::VmSetFs.

    /// The fs could not be updated on the VM.
    VmSetFs(VmError),

    /// The pmem device could not be added to the VM.


    /// The vDPA device could not be added to the VM.

    /// The vsock device could not be added to the VM.
    VmAddVsock(VmError),

    /// Error starting migration receiever

    /// Error starting migration sender

    /// Error triggering power button
    VmPowerButton(VmError),
    Service(VmmServiceError),
}
pub type ApiResult<T> = std::result::Result<T, ApiError>;

impl Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ApiError::*;
        match self {
            ResponsePayloadType => write!(f, "Wrong response payload type"),
            VmBoot(vm_error) => write!(f, "{}", vm_error),
            VmCreate(vm_error) => write!(f, "{}", vm_error),
            VmDelete(vm_error) => write!(f, "{}", vm_error),
            VmInfo(vm_error) => write!(f, "{}", vm_error),
            VmPause(vm_error) => write!(f, "{}", vm_error),
            VmResume(vm_error) => write!(f, "{}", vm_error),
            VmNotBooted => write!(f, "VM is not booted"),
            VmNotCreated => write!(f, "VM is not created"),
            VmShutdown(vm_error) => write!(f, "{}", vm_error),
            VmReboot(vm_error) => write!(f, "{}", vm_error),
            VmmShutdown(vm_error) => write!(f, "{}", vm_error),
            VmResize(vm_error) => write!(f, "{}", vm_error),
            VmResizeZone(vm_error) => write!(f, "{}", vm_error),
            CreateSeccompFilter(seccomp_error) => write!(f, "{}", seccomp_error),
            ApplySeccompFilter(seccomp_error) => write!(f, "{}", seccomp_error),
                    VmAddVsock(vm_error) => write!(f, "{}", vm_error),
            VmPowerButton(vm_error) => write!(f, "{}", vm_error),
            VmSetFs(vm_error) => write!(f, "{}", vm_error),
            Service(service_error) => write!(f, "{}", service_error),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VmInfo {
    pub config: Arc<Mutex<VmConfig>>,
    pub state: VmState,
    pub memory_actual_size: u64,
    pub device_tree: Option<Arc<Mutex<DeviceTree>>>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VmmPingResponse {
    pub version: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VmWaitStartResponse {
    pub started: bool,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmResizeData {
    pub desired_vcpus: Option<u8>,
    pub desired_ram: Option<u64>,
    pub desired_balloon: Option<u64>,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmResizeZoneData {
    pub id: String,
    pub desired_ram: u64,
}

pub enum ApiResponsePayload {
    /// No data is sent on the channel.
    Empty,

    /// Virtual machine information
    VmInfo(VmInfo),

    /// Vmm ping response
    VmmPing(VmmPingResponse),

    /// Vmm wait response
    VmWaitStart(VmWaitStartResponse),

    /// Vm action response
    VmAction(Option<Vec<u8>>),
}

/// This is the response sent by the VMM API server through the mpsc channel.
pub type ApiResponse = std::result::Result<ApiResponsePayload, ApiError>;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ApiRequest {
    /// Create the virtual machine. This request payload is a VM configuration
    /// (VmConfig).
    /// If the VMM API server could not create the VM, it will send a VmCreate
    /// error back.
    VmCreate(Box<VmConfig>),

    /// Boot the previously created virtual machine.
    /// If the VM was not previously created, the VMM API server will send a
    /// VmBoot error back.
    VmBoot,

    /// Delete the previously created virtual machine.
    /// If the VM was not previously created, the VMM API server will send a
    /// VmDelete error back.
    /// If the VM is booted, we shut it down first.
    VmDelete,

    /// Request the VM information.
    VmInfo,

    /// Request the VMM API server status
    VmmPing,

    /// Pause a VM.
    VmPause,

    /// Pause a VM to snapshot

    /// Resume a VM from snapshot

    /// Resume a VM.
    VmResume,

    /// Wait vm started.
    VmWaitStart,

    /// Get counters for a VM.
    VmCounters,

    /// Shut the previously booted virtual machine down.
    /// If the VM was not previously booted or created, the VMM API server
    /// will send a VmShutdown error back.
    VmShutdown,

    /// Reboot the previously booted virtual machine.
    /// If the VM was not previously booted or created, the VMM API server
    /// will send a VmReboot error back.
    VmReboot,

    /// Shut the VMM down.
    /// This will shutdown and delete the current VM, if any, and then exit the
    /// VMM process.
    VmmShutdown,

    /// Resize the VM.
    VmResize(Arc<VmResizeData>),

    /// Resize the memory zone.
    VmResizeZone(Arc<VmResizeZoneData>),

    /// Add a device to the VM.

    /// Add a user device to the VM.

    /// Remove a device from the VM.

    /// Add a disk to the VM.

    // Modified by Sandswap (c) 2026: `VmAddFs` was removed. Sandswap's
    // isolation model is ONE virtio-fs device per VM, created at boot and
    // never hot-plugged (agent switching = `vm.set-fs`, a whitelist swap on
    // that single device). A hot-added fs device would be a second, separately
    // whitelisted window from the guest into the host filesystem — outside the
    // single-device invariant the isolation boundary is stated in terms of —
    // and sandlot never called this API. Removing the request (and its HTTP
    // route) makes "there is exactly one share" a property of the API surface
    // rather than a property of the caller.

    /// Add a vsock device to the VM.
    VmSetFs(Arc<FsConfig>),

    /// Add a pmem device to the VM.

    // Modified by Sandswap (c) 2026: `VmAddNet` was removed with the
    // `/vm.add-net` route. A VM's network device is fixed at `vm.create` (one
    // TAP per VM, provisioned by sandlot before boot; the guest addressing
    // travels in the kernel cmdline). Attaching a NIC to a running VM would be
    // a second, unaccounted egress path — the egress-identity binding an
    // enforcer reads is keyed on the one provisioned interface — and nothing
    // in Sandswap ever asked for one.

    /// Add a vDPA device to the VM.

    /// Add a vsock device to the VM.
    VmAddVsock(Arc<VsockConfig>),

    /// Take a VM snapshot

    /// Restore from a VM snapshot

    /// Take a VM coredump

    /// Incoming migration

    /// Outgoing migration
    // Trigger power button
    VmPowerButton,
}

pub fn vm_create(config: Box<VmConfig>) -> ApiResult<()> {
    // Send the VM creation request.
    VMM_SERVICE
        .lock()
        .unwrap()
        .send_request(ApiRequest::VmCreate(config))
        .map_err(ApiError::Service)??;

    Ok(())
}

/// Represents a VM related action.
/// This is mostly used to factorize code between VM routines
/// that only differ by the IPC command they send.
pub enum VmAction {
    /// Boot a VM
    Boot,

    /// Delete a VM
    Delete,

    /// Shut a VM down
    Shutdown,

    /// Reboot a VM
    Reboot,

    /// Pause a VM
    Pause,

    /// Resume a VM
    Resume,

    /// Return VM counters
    Counters,

    /// Update the allowed_dirs whitelist of the VM's single virtio-fs device.
    SetFs(Arc<FsConfig>),

    /// Add vsock
    AddVsock(Arc<VsockConfig>),

    /// Resize VM
    Resize(Arc<VmResizeData>),

    /// Resize memory zone
    ResizeZone(Arc<VmResizeZoneData>),

    /// Power Button for clean shutdown
    PowerButton,
}

fn vm_action(action: VmAction) -> ApiResult<Option<Body>> {
    use VmAction::*;
    let request = match action {
        Boot => ApiRequest::VmBoot,
        Delete => ApiRequest::VmDelete,
        Shutdown => ApiRequest::VmShutdown,
        Reboot => ApiRequest::VmReboot,
        Pause => ApiRequest::VmPause,
        Resume => ApiRequest::VmResume,
        Counters => ApiRequest::VmCounters,
        SetFs(v) => ApiRequest::VmSetFs(v),
        AddVsock(v) => ApiRequest::VmAddVsock(v),
        Resize(v) => ApiRequest::VmResize(v),
        ResizeZone(v) => ApiRequest::VmResizeZone(v),
        PowerButton => ApiRequest::VmPowerButton,
    };

    let body = match VMM_SERVICE
        .lock()
        .unwrap()
        .send_request(request)
        .map_err(ApiError::Service)??
    {
        ApiResponsePayload::VmAction(response) => response.map(Body::new),
        ApiResponsePayload::Empty => None,
        _ => return Err(ApiError::ResponsePayloadType),
    };

    Ok(body)
}

pub fn vm_boot() -> ApiResult<Option<Body>> {
    vm_action(VmAction::Boot)
}

pub fn vm_delete() -> ApiResult<Option<Body>> {
    vm_action(VmAction::Delete)
}

pub fn vm_shutdown() -> ApiResult<Option<Body>> {
    vm_action(VmAction::Shutdown)
}

pub fn vm_reboot() -> ApiResult<Option<Body>> {
    vm_action(VmAction::Reboot)
}

pub fn vm_pause() -> ApiResult<Option<Body>> {
    vm_action(VmAction::Pause)
}

pub fn vm_resume() -> ApiResult<Option<Body>> {
    vm_action(VmAction::Resume)
}

pub fn vm_counters() -> ApiResult<Option<Body>> {
    vm_action(VmAction::Counters)
}

pub fn vm_power_button() -> ApiResult<Option<Body>> {
    vm_action(VmAction::PowerButton)
}

pub fn vm_info() -> ApiResult<VmInfo> {
    // Send the VM request.
    let vm_info = VMM_SERVICE
        .lock()
        .unwrap()
        .send_request(ApiRequest::VmInfo)
        .map_err(ApiError::Service)??;

    match vm_info {
        ApiResponsePayload::VmInfo(info) => Ok(info),
        _ => Err(ApiError::ResponsePayloadType),
    }
}

pub fn vmm_ping() -> ApiResult<VmmPingResponse> {
    let vmm_pong = VMM_SERVICE
        .lock()
        .unwrap()
        .send_request(ApiRequest::VmmPing)
        .map_err(ApiError::Service)??;

    match vmm_pong {
        ApiResponsePayload::VmmPing(pong) => Ok(pong),
        _ => Err(ApiError::ResponsePayloadType),
    }
}

pub fn vmm_shutdown() -> ApiResult<()> {
    // Send the VMM shutdown request.
    VMM_SERVICE
        .lock()
        .unwrap()
        .send_request(ApiRequest::VmmShutdown)
        .map_err(ApiError::Service)??;
    Ok(())
}

pub fn vm_wait_start() -> ApiResult<VmWaitStartResponse> {
    loop {
        let vmm_wait = VMM_SERVICE
            .lock()
            .unwrap()
            .send_request(ApiRequest::VmWaitStart)
            .map_err(ApiError::Service)??;

        match vmm_wait {
            ApiResponsePayload::VmWaitStart(wait) => {
                if wait.started {
                    return Ok(wait);
                } else {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }
            _ => return Err(ApiError::ResponsePayloadType),
        }
    }
}

pub fn vm_resize(data: Arc<VmResizeData>) -> ApiResult<Option<Body>> {
    vm_action(VmAction::Resize(data))
}

pub fn vm_resize_zone(data: Arc<VmResizeZoneData>) -> ApiResult<Option<Body>> {
    vm_action(VmAction::ResizeZone(data))
}

pub fn vm_set_fs(data: Arc<FsConfig>) -> ApiResult<Option<Body>> {
    vm_action(VmAction::SetFs(data))
}

pub fn vm_add_vsock(data: Arc<VsockConfig>) -> ApiResult<Option<Body>> {
    vm_action(VmAction::AddVsock(data))
}
