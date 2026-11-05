// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(clippy::significant_drop_in_scrutinee)]
#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate event_monitor;
#[macro_use]
extern crate log;

use crate::api::{
    ApiError, ApiRequest, ApiResponse, ApiResponsePayload, VmInfo, VmWaitStartResponse,
    VmmPingResponse,
};
use crate::config::{add_to_config, RestoreConfig};
use crate::memory_manager::MemoryManager;
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::vm::{Error as VmError, Vm, VmState};
use crate::vm_config::{
    DeviceConfig, DiskConfig, FsConfig, NetConfig, PmemConfig, UserDeviceConfig, VdpaConfig,
    VmConfig, VsockConfig,
};
use anyhow::anyhow;
use event_notifier::{event_notify, NotifyEvent};
use libc::{EFD_NONBLOCK, SIGINT, SIGTERM};
use memory_manager::MemoryManagerSnapshotData;
use pci::PciBdf;
use seccompiler::{apply_filter, SeccompAction};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use signal_hook::iterator::{Handle, Signals};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, RecvError, SendError, Sender};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Instant;
use std::{result, thread};
use thiserror::Error;
use tracer::trace_scoped;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{ReadVolatile, WriteVolatile};
use vm_migration::{protocol::*, Migratable};
use vm_migration::{MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
pub use vm_migration::{SnapshotConfig, SnapshotType};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::unblock_signal;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;
use vmm_sys_util::terminal::Terminal;

mod acpi;
pub mod raw_parse;
pub mod api;
mod clone3;
pub mod config;
pub mod cpu;
pub mod device_manager;
pub mod device_tree;
pub mod interrupt;
pub mod memory_manager;
pub mod migration;
mod pci_segment;
pub mod seccomp_filters;
mod serial_manager;
pub mod vm;
pub mod vm_config;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;
type GuestRegionMmap = vm_memory::GuestRegionMmap<AtomicBitmap>;

/// Minimum interval between guest-controlled MMIO error lines. A guest can
/// issue an invalid MMIO access at will (wrong offset or access width), so a
/// line per access is a guest-triggerable host-log flood; emit one line per
/// window with the suppressed count instead.
const MMIO_LOG_WINDOW_SEC: u64 = 10;

struct MmioLogLimiter {
    last_sec: std::sync::atomic::AtomicU64,
    suppressed: std::sync::atomic::AtomicU64,
}

impl MmioLogLimiter {
    const fn new() -> Self {
        Self {
            last_sec: std::sync::atomic::AtomicU64::new(0),
            suppressed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Whether a line may be emitted at `now_sec`. On `Some(n)` the caller
    /// should emit one line carrying `n` suppressed messages; `None` means
    /// the access was counted and must stay silent.
    fn claim(&self, now_sec: u64) -> Option<u64> {
        use std::sync::atomic::Ordering;

        let last = self.last_sec.load(Ordering::Relaxed);
        if now_sec.saturating_sub(last) < MMIO_LOG_WINDOW_SEC
            || self
                .last_sec
                .compare_exchange(last, now_sec, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(self.suppressed.swap(0, Ordering::Relaxed))
    }
}

static MMIO_LOG_LIMITER: MmioLogLimiter = MmioLogLimiter::new();

/// Emit a rate-limited warning about a guest-controlled MMIO access. The
/// arguments are formatted only when a line is actually emitted.
pub(crate) fn mmio_log_rate_limited(args: std::fmt::Arguments<'_>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(suppressed) = MMIO_LOG_LIMITER.claim(now) {
        if suppressed > 0 {
            warn!("{args} ({suppressed} similar MMIO messages suppressed)");
        } else {
            warn!("{args}");
        }
    }
}

/// Errors associated with VMM management
#[derive(Debug, Error)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// API request receive error
    #[error("Error receiving API request: {0}")]
    ApiRequestRecv(#[source] RecvError),

    /// API response send error
    #[error("Error sending API request: {0}")]
    ApiResponseSend(#[source] SendError<ApiResponse>),

    /// Cannot bind to the UNIX domain socket path
    #[error("Error binding to UNIX domain socket: {0}")]
    Bind(#[source] io::Error),

    /// Cannot clone EventFd.
    #[error("Error cloning EventFd: {0}")]
    EventFdClone(#[source] io::Error),

    /// Cannot create EventFd.
    #[error("Error creating EventFd: {0}")]
    EventFdCreate(#[source] io::Error),

    /// Cannot read from EventFd.
    #[error("Error reading from EventFd: {0}")]
    EventFdRead(#[source] io::Error),

    /// Cannot create epoll context.
    #[error("Error creating epoll context: {0}")]
    Epoll(#[source] io::Error),

    /// Cannot create HTTP thread
    #[error("Error spawning HTTP thread: {0}")]
    HttpThreadSpawn(#[source] io::Error),

    /// Cannot handle the VM STDIN stream
    #[error("Error handling VM stdin: {0:?}")]
    Stdin(VmError),

    /// Cannot handle the VM pty stream
    #[error("Error handling VM pty: {0:?}")]
    Pty(VmError),

    /// Cannot reboot the VM
    #[error("Error rebooting VM: {0:?}")]
    VmReboot(VmError),

    /// Cannot create VMM thread
    #[error("Error spawning VMM thread {0:?}")]
    VmmThreadSpawn(#[source] io::Error),

    /// Cannot shut the VMM down
    #[error("Error shutting down VMM: {0:?}")]
    VmmShutdown(VmError),

    /// Cannot create seccomp filter
    #[error("Error creating seccomp filter: {0}")]
    CreateSeccompFilter(seccompiler::Error),

    /// Cannot apply seccomp filter
    #[error("Error applying seccomp filter: {0}")]
    ApplySeccompFilter(seccompiler::Error),

    /// Error activating virtio devices
    #[error("Error activating virtio devices: {0:?}")]
    ActivateVirtioDevices(VmError),

    /// Error creating API server
    #[error("Error creating API server {0:?}")]
    CreateApiServer(micro_http::ServerError),

    /// Error binding API server socket
    #[error("Error creation API server's socket {0:?}")]
    CreateApiServerSocket(#[source] io::Error),

    #[cfg(feature = "guest_debug")]
    #[error("Failed to start the GDB thread: {0}")]
    GdbThreadSpawn(io::Error),

    /// GDB request receive error
    #[cfg(feature = "guest_debug")]
    #[error("Error receiving GDB request: {0}")]
    GdbRequestRecv(#[source] RecvError),

    /// GDB response send error
    #[cfg(feature = "guest_debug")]
    #[error("Error sending GDB request: {0}")]
    GdbResponseSend(#[source] SendError<gdb::GdbResponse>),

    #[error("Cannot spawn a signal handler thread: {0}")]
    SignalHandlerSpawn(#[source] io::Error),

    #[error("Failed to join on threads: {0:?}")]
    ThreadCleanup(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum EpollDispatch {
    Exit = 0,
    Reset = 1,
    Api = 2,
    ActivateVirtioDevices = 3,
    Debug = 4,
    Unknown,
}

impl From<u64> for EpollDispatch {
    fn from(v: u64) -> Self {
        use EpollDispatch::*;
        match v {
            0 => Exit,
            1 => Reset,
            2 => Api,
            3 => ActivateVirtioDevices,
            4 => Debug,
            _ => Unknown,
        }
    }
}

pub struct EpollContext {
    epoll_file: File,
}

impl EpollContext {
    pub fn new() -> result::Result<EpollContext, io::Error> {
        let epoll_fd = epoll::create(true)?;
        // Use 'File' to enforce closing on 'epoll_fd'
        // SAFETY: the epoll_fd returned by epoll::create is valid and owned by us.
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        Ok(EpollContext { epoll_file })
    }

    pub fn add_event<T>(&mut self, fd: &T, token: EpollDispatch) -> result::Result<(), io::Error>
    where
        T: AsRawFd,
    {
        let dispatch_index = token as u64;
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;

        Ok(())
    }
}

impl AsRawFd for EpollContext {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }
}

pub struct PciDeviceInfo {
    pub id: String,
    pub bdf: PciBdf,
}

impl Serialize for PciDeviceInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bdf_str = self.bdf.to_string();

        // Serialize the structure.
        let mut state = serializer.serialize_struct("PciDeviceInfo", 2)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("bdf", &bdf_str)?;
        state.end()
    }
}

#[allow(unused_variables)]
#[allow(clippy::too_many_arguments)]
pub fn start_vmm_thread(
    vmm_version: String,
    http_path: &Option<String>,
    http_fd: Option<RawFd>,
    api_event: EventFd,
    api_receiver: Receiver<ApiRequest>,
    res_sender: Sender<ApiResponse>,
    #[cfg(feature = "guest_debug")] debug_path: Option<PathBuf>,
    #[cfg(feature = "guest_debug")] debug_event: EventFd,
    #[cfg(feature = "guest_debug")] vm_debug_event: EventFd,
    seccomp_action: &SeccompAction,
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    vcpu_started: Arc<AtomicBool>,
    vmm_barrier: Option<Arc<Barrier>>,
    api_gid: Option<u32>,
    api_token: Option<[u8; 32]>,
    api_allowed_uid: Option<u32>,
) -> Result<thread::JoinHandle<Result<()>>> {
    #[cfg(feature = "guest_debug")]
    let gdb_hw_breakpoints = hypervisor.get_guest_debug_hw_bps();
    #[cfg(feature = "guest_debug")]
    let (gdb_sender, gdb_receiver) = std::sync::mpsc::channel();
    #[cfg(feature = "guest_debug")]
    let gdb_debug_event = debug_event.try_clone().map_err(Error::EventFdClone)?;
    #[cfg(feature = "guest_debug")]
    let gdb_vm_debug_event = vm_debug_event.try_clone().map_err(Error::EventFdClone)?;

    let hypervisor_type = hypervisor.hypervisor_type();

    let seccomp_filter = get_seccomp_filter(seccomp_action, Thread::All, hypervisor_type)
        .map_err(Error::CreateSeccompFilter)?;
    // Apply seccomp filter for ALL thread.
    if !seccomp_filter.is_empty() {
        apply_filter(&seccomp_filter).map_err(Error::ApplySeccompFilter)?;
    }

    // Retrieve seccomp filter
    let vmm_seccomp_filter = get_seccomp_filter(seccomp_action, Thread::Vmm, hypervisor_type)
        .map_err(Error::CreateSeccompFilter)?;

    let vmm_seccomp_action = seccomp_action.clone();
    let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
    let thread = {
        let exit_evt = exit_evt.try_clone().map_err(Error::EventFdClone)?;
        thread::Builder::new()
            .name("vmm".to_string())
            .spawn(move || {
                // Apply seccomp filter for VMM thread.
                if !vmm_seccomp_filter.is_empty() {
                    apply_filter(&vmm_seccomp_filter).map_err(Error::ApplySeccompFilter)?;
                }

                let mut vmm = Vmm::new(
                    vmm_version.to_string(),
                    api_event,
                    #[cfg(feature = "guest_debug")]
                    debug_event,
                    #[cfg(feature = "guest_debug")]
                    vm_debug_event,
                    vmm_seccomp_action,
                    hypervisor,
                    exit_evt,
                    vcpu_started,
                )?;

                vmm.setup_signal_handler()?;

                vmm.control_loop(
                    Rc::new(api_receiver),
                    Rc::new(res_sender),
                    #[cfg(feature = "guest_debug")]
                    Rc::new(gdb_receiver),
                    vmm_barrier,
                )
            })
            .map_err(Error::VmmThreadSpawn)?
    };

    // The VMM thread is started, we can start serving API requests:
    // the front dispatcher (raw hot ops + HTTP pump) on the canonical
    // socket, and the internal HTTP server the pump forwards to.
    if let Some(http_path) = http_path {
        api::start_api_dispatcher(
            &http_path,
            api_gid,
            api_token,
            api_allowed_uid,
            seccomp_action,
            exit_evt,
            hypervisor_type,
        )?;
    } else if let Some(http_fd) = http_fd {
        api::start_http_fd_thread(
            http_fd,
            seccomp_action,
            exit_evt,
            hypervisor_type,
        )?;
    }

    #[cfg(feature = "guest_debug")]
    if let Some(debug_path) = debug_path {
        let target = gdb::GdbStub::new(
            gdb_sender,
            gdb_debug_event,
            gdb_vm_debug_event,
            gdb_hw_breakpoints,
        );
        thread::Builder::new()
            .name("gdb".to_owned())
            .spawn(move || gdb::gdb_thread(target, &debug_path))
            .map_err(Error::GdbThreadSpawn)?;
    }

    Ok(thread)
}

#[derive(Clone, Deserialize, Serialize)]
struct VmMigrationConfig {
    vm_config: Arc<Mutex<VmConfig>>,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    common_cpuid: Vec<hypervisor::arch::x86::CpuIdEntry>,
    memory_manager_data: MemoryManagerSnapshotData,
}

pub struct Vmm {
    epoll: EpollContext,
    exit_evt: EventFd,
    reset_evt: EventFd,
    api_evt: EventFd,
    #[cfg(feature = "guest_debug")]
    debug_evt: EventFd,
    #[cfg(feature = "guest_debug")]
    vm_debug_evt: EventFd,
    version: String,
    vm: Option<Vm>,
    vm_config: Option<Arc<Mutex<VmConfig>>>,
    seccomp_action: SeccompAction,
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    activate_evt: EventFd,
    signals: Option<Handle>,
    threads: Vec<thread::JoinHandle<()>>,
    pinglog: u32,
    vcpu_started: Arc<AtomicBool>,
}

impl Vmm {
    pub const HANDLED_SIGNALS: [i32; 2] = [SIGTERM, SIGINT];

    fn signal_handler(mut signals: Signals, on_tty: bool, exit_evt: &EventFd) {
        for sig in &Self::HANDLED_SIGNALS {
            unblock_signal(*sig).unwrap();
        }

        for signal in signals.forever() {
            match signal {
                SIGTERM | SIGINT => {
                    if exit_evt.write(1).is_err() {
                        // Resetting the terminal is usually done as the VMM exits
                        if on_tty {
                            io::stdin()
                                .lock()
                                .set_canon_mode()
                                .expect("failed to restore terminal mode");
                        }
                        std::process::exit(1);
                    }
                }
                _ => (),
            }
        }
    }

    fn setup_signal_handler(&mut self) -> Result<()> {
        let signals = Signals::new(Self::HANDLED_SIGNALS);
        // SAFETY: trivially safe
        let on_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } != 0;

        if !on_tty {
            return Ok(());
        }

        match signals {
            Ok(signals) => {
                self.signals = Some(signals.handle());
                let exit_evt = self.exit_evt.try_clone().map_err(Error::EventFdClone)?;

                let signal_handler_seccomp_filter = get_seccomp_filter(
                    &self.seccomp_action,
                    Thread::SignalHandler,
                    self.hypervisor.hypervisor_type(),
                )
                .map_err(Error::CreateSeccompFilter)?;
                self.threads.push(
                    thread::Builder::new()
                        .name("vmm_signal_handler".to_string())
                        .spawn(move || {
                            if !signal_handler_seccomp_filter.is_empty() {
                                if let Err(e) = apply_filter(&signal_handler_seccomp_filter)
                                    .map_err(Error::ApplySeccompFilter)
                                {
                                    error!("Error applying seccomp filter: {:?}", e);
                                    exit_evt.write(1).ok();
                                    return;
                                }
                            }
                            std::panic::catch_unwind(AssertUnwindSafe(|| {
                                Vmm::signal_handler(signals, on_tty, &exit_evt);
                            }))
                            .map_err(|_| {
                                error!("signal_handler thead panicked");
                                exit_evt.write(1).ok()
                            })
                            .ok();
                        })
                        .map_err(Error::SignalHandlerSpawn)?,
                );
            }
            Err(e) => error!("Signal not found {}", e),
        }
        Ok(())
    }

    fn new(
        vmm_version: String,
        api_evt: EventFd,
        #[cfg(feature = "guest_debug")] debug_evt: EventFd,
        #[cfg(feature = "guest_debug")] vm_debug_evt: EventFd,
        seccomp_action: SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        exit_evt: EventFd,
        vcpu_started: Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut epoll = EpollContext::new().map_err(Error::Epoll)?;
        let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
        let activate_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;

        epoll
            .add_event(&exit_evt, EpollDispatch::Exit)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&reset_evt, EpollDispatch::Reset)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&activate_evt, EpollDispatch::ActivateVirtioDevices)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&api_evt, EpollDispatch::Api)
            .map_err(Error::Epoll)?;

        #[cfg(feature = "guest_debug")]
        epoll
            .add_event(&debug_evt, EpollDispatch::Debug)
            .map_err(Error::Epoll)?;

        Ok(Vmm {
            epoll,
            exit_evt,
            reset_evt,
            api_evt,
            #[cfg(feature = "guest_debug")]
            debug_evt,
            #[cfg(feature = "guest_debug")]
            vm_debug_evt,
            version: vmm_version,
            vm: None,
            vm_config: None,
            seccomp_action,
            hypervisor,
            activate_evt,
            signals: None,
            threads: vec![],
            pinglog: 3,
            vcpu_started,
        })
    }

    fn vm_create(&mut self, config: Box<VmConfig>) -> result::Result<(), VmError> {
        // We only store the passed VM config.
        // The VM will be created when being asked to boot it.
        if self.vm_config.is_none() {
            self.vm_config = Some(Arc::new(Mutex::new(*config)));
            Ok(())
        } else {
            Err(VmError::VmAlreadyCreated)
        }
    }

    fn vm_boot(&mut self) -> result::Result<(), VmError> {
        tracer::start();
        let r = {
            trace_scoped!("vm_boot");
            // If we don't have a config, we can not boot a VM.
            if self.vm_config.is_none() {
                return Err(VmError::VmMissingConfig);
            };

            // Create a new VM if we don't have one yet.
            if self.vm.is_none() {
                let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
                let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
                #[cfg(feature = "guest_debug")]
                let vm_debug_evt = self
                    .vm_debug_evt
                    .try_clone()
                    .map_err(VmError::EventFdClone)?;
                let activate_evt = self
                    .activate_evt
                    .try_clone()
                    .map_err(VmError::EventFdClone)?;

                if let Some(ref vm_config) = self.vm_config {
                    let vm = Vm::new(
                        Arc::clone(vm_config),
                        exit_evt,
                        reset_evt,
                        #[cfg(feature = "guest_debug")]
                        vm_debug_evt,
                        &self.seccomp_action,
                        self.hypervisor.clone(),
                        activate_evt,
                        None,
                        None,
                        None,
                        self.vcpu_started.clone(),
                    )?;

                    self.vm = Some(vm);
                }
            }

            // Now we can boot the VM.
            if let Some(ref mut vm) = self.vm {
                vm.boot()
            } else {
                Err(VmError::VmNotCreated)
            }
        };
        tracer::end();
        r
    }

    fn vm_pause(&mut self) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            vm.pause().map_err(VmError::Pause)
        } else {
            Err(VmError::VmNotRunning)
        }
    }
    fn vm_resume(&mut self) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            vm.resume().map_err(VmError::Resume)
        } else {
            Err(VmError::VmNotRunning)
        }
    }
    fn vm_shutdown(&mut self) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm.take() {
            match vm.counters() {
                Ok(info) => {
                    info!("counters details: {:?}", info);
                }
                Err(e) => {
                    info! {"counter failed {}", e};
                }
            };
            vm.shutdown()
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_reboot(&mut self) -> result::Result<(), VmError> {
        // First we stop the current VM
        let (config, serial_pty, console_pty, console_resize_pipe) =
            if let Some(mut vm) = self.vm.take() {
                let config = vm.get_config();
                let serial_pty = vm.serial_pty();
                let console_pty = vm.console_pty();
                let console_resize_pipe = vm
                    .console_resize_pipe()
                    .as_ref()
                    .map(|pipe| pipe.try_clone().unwrap());
                vm.shutdown()?;
                (config, serial_pty, console_pty, console_resize_pipe)
            } else {
                return Err(VmError::VmNotCreated);
            };

        let exit_evt = self.exit_evt.try_clone().map_err(VmError::EventFdClone)?;
        let reset_evt = self.reset_evt.try_clone().map_err(VmError::EventFdClone)?;
        #[cfg(feature = "guest_debug")]
        let debug_evt = self
            .vm_debug_evt
            .try_clone()
            .map_err(VmError::EventFdClone)?;
        let activate_evt = self
            .activate_evt
            .try_clone()
            .map_err(VmError::EventFdClone)?;

        // The Linux kernel fires off an i8042 reset after doing the ACPI reset so there may be
        // an event sitting in the shared reset_evt. Without doing this we get very early reboots
        // during the boot process.
        if self.reset_evt.read().is_ok() {
            warn!("Spurious second reset event received. Ignoring.");
        }

        // Then we create the new VM
        let mut vm = Vm::new(
            config,
            exit_evt,
            reset_evt,
            #[cfg(feature = "guest_debug")]
            debug_evt,
            &self.seccomp_action,
            self.hypervisor.clone(),
            activate_evt,
            serial_pty,
            console_pty,
            console_resize_pipe,
            self.vcpu_started.clone(),
        )?;

        // And we boot it
        vm.boot()?;

        self.vm = Some(vm);

        Ok(())
    }

    fn vm_info(&self) -> result::Result<VmInfo, VmError> {
        match &self.vm_config {
            Some(config) => {
                let state = match &self.vm {
                    Some(vm) => vm.get_state()?,
                    None => VmState::Created,
                };

                let config = Arc::clone(config);

                let mut memory_actual_size = config.lock().unwrap().memory.total_size();
                if let Some(vm) = &self.vm {
                    memory_actual_size -= vm.balloon_size();
                }

                let device_tree = self.vm.as_ref().map(|vm| vm.device_tree());

                Ok(VmInfo {
                    config,
                    state,
                    memory_actual_size,
                    device_tree,
                })
            }
            None => Err(VmError::VmNotCreated),
        }
    }

    fn vmm_ping(&self) -> VmmPingResponse {
        VmmPingResponse {
            version: self.version.clone(),
        }
    }

    fn vm_delete(&mut self) -> result::Result<(), VmError> {
        if self.vm_config.is_none() {
            return Ok(());
        }

        // If a VM is booted, we first try to shut it down.
        if self.vm.is_some() {
            self.vm_shutdown()?;
        }

        self.vm_config = None;

        event!("vm", "deleted");

        Ok(())
    }

    fn vmm_shutdown(&mut self) -> result::Result<(), VmError> {
        self.vm_delete()?;
        event!("vmm", "shutdown");
        Ok(())
    }

    fn vm_wait_start(&mut self) -> VmWaitStartResponse {
        // There is no guest→host "system started" device to poll; boot
        // completion is tracked by the guest itself (warden's vsock server
        // coming up on port 1024).
        VmWaitStartResponse { started: true }
    }

    fn vm_resize(
        &mut self,
        desired_vcpus: Option<u8>,
        desired_ram: Option<u64>,
        desired_balloon: Option<u64>,
    ) -> result::Result<(), VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        if let Some(ref mut vm) = self.vm {
            if let Err(e) = vm.resize(desired_vcpus, desired_ram, desired_balloon) {
                error!("Error when resizing VM: {:?}", e);
                Err(e)
            } else {
                Ok(())
            }
        } else {
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            if let Some(desired_vcpus) = desired_vcpus {
                config.cpus.boot_vcpus = desired_vcpus;
            }
            if let Some(desired_ram) = desired_ram {
                config.memory.size = desired_ram;
            }
            if let Some(desired_balloon) = desired_balloon {
                if let Some(balloon_config) = &mut config.balloon {
                    balloon_config.size = desired_balloon;
                }
            }
            Ok(())
        }
    }

    fn vm_resize_zone(&mut self, id: String, desired_ram: u64) -> result::Result<(), VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        if let Some(ref mut vm) = self.vm {
            if let Err(e) = vm.resize_zone(id, desired_ram) {
                error!("Error when resizing VM: {:?}", e);
                Err(e)
            } else {
                Ok(())
            }
        } else {
            // Update VmConfig by setting the new desired ram.
            let memory_config = &mut self.vm_config.as_ref().unwrap().lock().unwrap().memory;

            if let Some(zones) = &mut memory_config.zones {
                for zone in zones.iter_mut() {
                    if zone.id == id {
                        zone.size = desired_ram;
                        return Ok(());
                    }
                }
            }

            error!("Could not find the memory zone {} for the resize", id);
            Err(VmError::ResizeZone)
        }
    }
    fn vm_set_fs(&mut self, fs_cfg: FsConfig) -> result::Result<(), VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        // Order matters for failure atomicity: (1) validate the request
        // against the stored config (no side effects), (2) push the new
        // whitelist into the live device, (3) only then commit it to
        // VmConfig. Any failure leaves BOTH the config and the runtime
        // filter untouched — the old order (config first) left them
        // diverging after a device-side failure.
        {
            let config = self.vm_config.as_ref().unwrap().lock().unwrap();
            config
                .validate_fs_update(&fs_cfg)
                .map_err(VmError::ConfigValidation)?;
        }

        if let Some(ref mut vm) = self.vm {
            vm.fs_device_update(fs_cfg.clone())?;
        }

        let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
        config
            .update_fs_allowed_dirs(&fs_cfg)
            .map_err(VmError::ConfigValidation)?;

        Ok(())
    }
    fn vm_add_vsock(&mut self, vsock_cfg: VsockConfig) -> result::Result<Option<Vec<u8>>, VmError> {
        self.vm_config.as_ref().ok_or(VmError::VmNotCreated)?;

        {
            // Validate the configuration change in a cloned configuration
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap().clone();

            if config.vsock.is_some() {
                return Err(VmError::TooManyVsockDevices);
            }

            config.vsock = Some(vsock_cfg.clone());
            config.validate().map_err(VmError::ConfigValidation)?;
        }

        if let Some(ref mut vm) = self.vm {
            let info = vm.add_vsock(vsock_cfg).map_err(|e| {
                error!("Error when adding new vsock device to the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            // Update VmConfig by adding the new device.
            let mut config = self.vm_config.as_ref().unwrap().lock().unwrap();
            config.vsock = Some(vsock_cfg);
            Ok(None)
        }
    }

    fn vm_counters(&mut self) -> result::Result<Option<Vec<u8>>, VmError> {
        if let Some(ref mut vm) = self.vm {
            let info = vm.counters().map_err(|e| {
                error!("Error when getting counters from the VM: {:?}", e);
                e
            })?;
            serde_json::to_vec(&info)
                .map(Some)
                .map_err(VmError::SerializeJson)
        } else {
            Err(VmError::VmNotRunning)
        }
    }

    fn vm_power_button(&mut self) -> result::Result<(), VmError> {
        if let Some(ref mut vm) = self.vm {
            vm.power_button()
        } else {
            Err(VmError::VmNotRunning)
        }
    }
    fn socket_url_to_path(url: &str) -> result::Result<PathBuf, MigratableError> {
        url.strip_prefix("unix:")
            .ok_or_else(|| {
                MigratableError::MigrateSend(anyhow!("Could not extract path from URL: {}", url))
            })
            .map(|s| s.into())
    }
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    fn vm_check_cpuid_compatibility(
        &self,
        src_vm_config: &Arc<Mutex<VmConfig>>,
        src_vm_cpuid: &[hypervisor::arch::x86::CpuIdEntry],
    ) -> result::Result<(), MigratableError> {
        // We check the `CPUID` compatibility of between the source vm and destination, which is
        // mostly about feature compatibility and "topology/sgx" leaves are not relevant.
        let dest_cpuid = &{
            let vm_config = &src_vm_config.lock().unwrap();

            let phys_bits = vm::physical_bits(
                vm_config.cpus.max_phys_bits,
                self.hypervisor.hypervisor_type(),
            );

            arch::generate_common_cpuid(
                self.hypervisor.clone(),
                None,
                None,
                phys_bits,
                vm_config.cpus.kvm_hyperv,
                #[cfg(feature = "tdx")]
                vm_config.is_tdx_enabled(),
            )
            .map_err(|e| {
                MigratableError::MigrateReceive(anyhow!("Error generating common cpuid: {:?}", e))
            })?
        };
        arch::CpuidFeatureEntry::check_cpuid_compatibility(src_vm_cpuid, dest_cpuid).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!(
                "Error checking cpu feature compatibility': {:?}",
                e
            ))
        })
    }

    fn control_loop(
        &mut self,
        api_receiver: Rc<Receiver<ApiRequest>>,
        res_sender: Rc<Sender<ApiResponse>>,
        #[cfg(feature = "guest_debug")] gdb_receiver: Rc<Receiver<gdb::GdbRequest>>,
        vmm_barrier: Option<Arc<Barrier>>,
    ) -> Result<()> {
        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];
        let epoll_fd = self.epoll.as_raw_fd();

        if let Some(barrier) = vmm_barrier {
            barrier.wait();
        }
        info!("The control_loop is ready");
        'outer: loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(Error::Epoll(e));
                }
            };

            for event in events.iter().take(num_events) {
                let dispatch_event: EpollDispatch = event.data.into();
                match dispatch_event {
                    EpollDispatch::Unknown => {
                        let event = event.data;
                        warn!("Unknown VMM loop event: {}", event);
                    }
                    EpollDispatch::Exit => {
                        info!("VM exit event");
                        // Consume the event.
                        self.exit_evt.read().map_err(Error::EventFdRead)?;
                        self.vmm_shutdown().map_err(Error::VmmShutdown)?;

                        break 'outer;
                    }
                    EpollDispatch::Reset => {
                        info!("VM reset event");
                        // Consume the event.
                        self.reset_evt.read().map_err(Error::EventFdRead)?;
                        if let Err(e) = self.vm_reboot() {
                            // A guest-initiated reset rebuilds the VM from the
                            // live config. If that config no longer validates
                            // (e.g. a set-fs generation's allowed_dirs/alias
                            // is create-time-forbidden), the VM is already
                            // shut down; treating this as VM death is the
                            // correct outcome. Propagating the error would
                            // kill the sandvmm process itself.
                            error!("VM reset failed: {e}; treating as VM death");
                            let _ = self.exit_evt.write(1);
                        }
                    }
                    EpollDispatch::ActivateVirtioDevices => {
                        if let Some(ref vm) = self.vm {
                            let count = self.activate_evt.read().map_err(Error::EventFdRead)?;
                            info!(
                                "Trying to activate pending virtio devices: count = {}",
                                count
                            );
                            vm.activate_virtio_devices()
                                .map_err(Error::ActivateVirtioDevices)?;
                        }
                    }
                    EpollDispatch::Api => {
                        // Consume the events.
                        for _ in 0..self.api_evt.read().map_err(Error::EventFdRead)? {
                            // Read from the API receiver channel
                            let api_request = api_receiver.recv().map_err(Error::ApiRequestRecv)?;

                            match api_request {
                                ApiRequest::VmmPing => {
                                    if self.pinglog != 0 {
                                        self.pinglog -= 1;
                                        info!("API request event: {:?}", api_request);
                                    }
                                }
                                _ => {
                                    info!("API request event: {:?}", api_request);
                                }
                            }

                            match api_request {
                                ApiRequest::VmCreate(config) => {
                                    let response = self
                                        .vm_create(config)
                                        .map_err(ApiError::VmCreate)
                                        .map(|_| ApiResponsePayload::Empty);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmDelete => {
                                    let response = self
                                        .vm_delete()
                                        .map_err(ApiError::VmDelete)
                                        .map(|_| ApiResponsePayload::Empty);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmBoot => {
                                    let response = self
                                        .vm_boot()
                                        .map_err(ApiError::VmBoot)
                                        .map(|_| ApiResponsePayload::Empty);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmShutdown => {
                                    let response = self
                                        .vm_shutdown()
                                        .map_err(ApiError::VmShutdown)
                                        .map(|_| ApiResponsePayload::Empty);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmReboot => {
                                    let response = self
                                        .vm_reboot()
                                        .map_err(ApiError::VmReboot)
                                        .map(|_| ApiResponsePayload::Empty);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmInfo => {
                                    let response = self
                                        .vm_info()
                                        .map_err(ApiError::VmInfo)
                                        .map(ApiResponsePayload::VmInfo);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmmPing => {
                                    let response = ApiResponsePayload::VmmPing(self.vmm_ping());

                                    res_sender
                                        .send(Ok(response))
                                        .map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmPause => {
                                    let response = self
                                        .vm_pause()
                                        .map_err(ApiError::VmPause)
                                        .map(|_| ApiResponsePayload::Empty);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmResume => {
                                    let response = self
                                        .vm_resume()
                                        .map_err(ApiError::VmResume)
                                        .map(|_| ApiResponsePayload::Empty);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmmShutdown => {
                                    let response = self
                                        .vmm_shutdown()
                                        .map_err(ApiError::VmmShutdown)
                                        .map(|_| ApiResponsePayload::Empty);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;

                                    break 'outer;
                                }
                                ApiRequest::VmWaitStart => {
                                    let response =
                                        ApiResponsePayload::VmWaitStart(self.vm_wait_start());

                                    res_sender
                                        .send(Ok(response))
                                        .map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmResize(resize_data) => {
                                    let response = self
                                        .vm_resize(
                                            resize_data.desired_vcpus,
                                            resize_data.desired_ram,
                                            resize_data.desired_balloon,
                                        )
                                        .map_err(ApiError::VmResize)
                                        .map(|_| ApiResponsePayload::Empty);
                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmResizeZone(resize_zone_data) => {
                                    let response = self
                                        .vm_resize_zone(
                                            resize_zone_data.id.clone(),
                                            resize_zone_data.desired_ram,
                                        )
                                        .map_err(ApiError::VmResizeZone)
                                        .map(|_| ApiResponsePayload::Empty);
                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmSetFs(set_fs_data) => {
                                    let response = self
                                        .vm_set_fs(set_fs_data.as_ref().clone())
                                        .map_err(ApiError::VmSetFs)
                                        .map(|_| ApiResponsePayload::Empty);
                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmAddVsock(add_vsock_data) => {
                                    let response = self
                                        .vm_add_vsock(add_vsock_data.as_ref().clone())
                                        .map_err(ApiError::VmAddVsock)
                                        .map(ApiResponsePayload::VmAction);
                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmCounters => {
                                    let response = self
                                        .vm_counters()
                                        .map_err(ApiError::VmInfo)
                                        .map(ApiResponsePayload::VmAction);
                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmPowerButton => {
                                    let response = self
                                        .vm_power_button()
                                        .map_err(ApiError::VmPowerButton)
                                        .map(|_| ApiResponsePayload::Empty);

                                    res_sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                            }
                        }
                    }
                    #[cfg(feature = "guest_debug")]
                    EpollDispatch::Debug => {
                        // Consume the events.
                        for _ in 0..self.debug_evt.read().map_err(Error::EventFdRead)? {
                            // Read from the API receiver channel
                            let gdb_request = gdb_receiver.recv().map_err(Error::GdbRequestRecv)?;

                            let response = if let Some(ref mut vm) = self.vm {
                                vm.debug_request(&gdb_request.payload, gdb_request.cpu_id)
                            } else {
                                Err(VmError::VmNotRunning)
                            }
                            .map_err(gdb::Error::Vm);

                            gdb_request
                                .sender
                                .send(response)
                                .map_err(Error::GdbResponseSend)?;
                        }
                    }
                    #[cfg(not(feature = "guest_debug"))]
                    EpollDispatch::Debug => {}
                }
            }
        }

        // Trigger the termination of the signal_handler thread
        if let Some(signals) = self.signals.take() {
            signals.close();
        }

        // Wait for all the threads to finish
        for thread in self.threads.drain(..) {
            thread.join().map_err(Error::ThreadCleanup)?
        }

        Ok(())
    }
}

const CPU_MANAGER_SNAPSHOT_ID: &str = "cpu-manager";
const MEMORY_MANAGER_SNAPSHOT_ID: &str = "memory-manager";
const DEVICE_MANAGER_SNAPSHOT_ID: &str = "device-manager";

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::vm_config::CpuFeatures;
    use vm_config::{
        ConsoleConfig, ConsoleOutputMode, CpusConfig, HotplugMethod, MemoryConfig, PayloadConfig,
        RngConfig, VmConfig,
    };

    fn create_dummy_vmm() -> Vmm {
        Vmm::new(
            "dummy".to_string(),
            EventFd::new(EFD_NONBLOCK).unwrap(),
            #[cfg(feature = "guest_debug")]
            EventFd::new(EFD_NONBLOCK).unwrap(),
            #[cfg(feature = "guest_debug")]
            EventFd::new(EFD_NONBLOCK).unwrap(),
            SeccompAction::Allow,
            hypervisor::new().unwrap(),
            EventFd::new(EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    fn create_dummy_vm_config() -> Box<VmConfig> {
        Box::new(VmConfig {
            cpus: CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                topology: None,
                kvm_hyperv: false,
                max_phys_bits: 46,
                affinity: None,
                features: CpuFeatures::default(),
            },
            memory: MemoryConfig {
                size: 536_870_912,
                mergeable: false,
                hotplug_method: HotplugMethod::Acpi,
                hotplug_size: None,
                hotplugged_size: None,
                shared: true,
                hugepages: false,
                hugepage_size: None,
                prefault: false,
                zones: None,
                thp: true,
                dirty_log: false,
            },
            payload: Some(PayloadConfig {
                kernel: Some(PathBuf::from("/path/to/kernel")),
                ..Default::default()
            }),
            disks: None,
            net: None,
            rng: RngConfig {
                src: PathBuf::from("/dev/urandom"),
                iommu: false,
            },
            balloon: None,
            fs: None,
            pmem: None,
            serial: ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Null,
                iommu: false,
                sigwinch: false,
            },
            console: ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                sigwinch: false,
            },
            devices: None,
            user_devices: None,
            vdpa: None,
            vsock: None,
            iommu: false,
            #[cfg(target_arch = "x86_64")]
            sgx_epc: None,
            numa: None,
            watchdog: false,
            #[cfg(feature = "guest_debug")]
            gdb: false,
            platform: None,
            tpm: None,
        })
    }

    #[test]
    fn test_vmm_vm_create() {
        let mut vmm = create_dummy_vmm();
        let config = create_dummy_vm_config();

        assert!(matches!(vmm.vm_create(config.clone()), Ok(())));
        assert!(matches!(
            vmm.vm_create(config),
            Err(VmError::VmAlreadyCreated)
        ));
    }

    // Modified by Sandswap (c) 2026: `test_vmm_vm_cold_add_fs` was removed with
    // the vm.add-fs endpoint itself. The single-share invariant it exercised by
    // pushing a second device through the API is now enforced in
    // `VmConfig::validate` (see the fs-count test in config.rs) and pinned at
    // the HTTP layer (no route for /vm.add-fs).

    // Modified by Sandswap (c) 2026: `test_vmm_vm_cold_add_net` was removed with
    // the vm.add-net endpoint. A NIC may only come from `vm.create`; the route
    // is gone (pinned by `virtiofs_api_surface_is_set_fs_only` in
    // api/http/mod.rs, which asserts `/vm.add-net` is not routable).

    // regression pin: the vm.add-vsock route must refuse a reserved/wildcard
    // guest cid with a NAMED error instead of recording it (it would reach
    // VHOST_VSOCK_SET_GUEST_CID at device activation). RED with the
    // VmConfig::validate cid check removed: cid=1 is accepted and stored.
    #[test]
    fn test_vmm_vm_add_vsock_rejects_reserved_cid() {
        let mut vmm = create_dummy_vmm();
        let _ = vmm.vm_create(create_dummy_vm_config());
        for bad in [0u64, 1, 2, 0xFFFF_FFFF] {
            let cfg = VsockConfig {
                cid: bad,
                ..Default::default()
            };
            match vmm.vm_add_vsock(cfg) {
                Err(VmError::ConfigValidation(crate::config::ValidationError::VsockCid(v))) => {
                    assert_eq!(v, bad, "the refusal must name the offending cid");
                }
                other => panic!("reserved cid {bad} must be refused, got {other:?}"),
            }
        }
        // The refusals must not have poisoned the stored config.
        assert!(vmm
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .vsock
            .is_none());
    }

    #[test]
    fn test_vmm_vm_cold_add_vsock() {
        let mut vmm = create_dummy_vmm();
        // cid=3 is the sandlot allocator's floor (0/1/2 are kernel-reserved
        // and now refused — see the regression pin above).
        let vsock_config = VsockConfig::parse("cid=3,iommu=on").unwrap();

        assert!(matches!(
            vmm.vm_add_vsock(vsock_config.clone()),
            Err(VmError::VmNotCreated)
        ));

        let _ = vmm.vm_create(create_dummy_vm_config());
        assert!(vmm
            .vm_config
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .vsock
            .is_none());

        let result = vmm.vm_add_vsock(vsock_config.clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(
            vmm.vm_config
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .vsock
                .clone()
                .unwrap(),
            vsock_config
        );
    }
}

#[cfg(test)]
mod mmio_log_limiter_tests {
    use super::*;

    /// One line per window, with the suppressed count carried into the next
    /// emitted line — a guest hammering an invalid MMIO offset must not be
    /// able to grow the host log linearly with accesses.
    #[test]
    fn window_suppresses_and_reports_the_count() {
        let limiter = MmioLogLimiter::new();
        assert_eq!(limiter.claim(100), Some(0), "first access logs");
        assert_eq!(limiter.claim(101), None);
        assert_eq!(limiter.claim(109), None);
        assert_eq!(
            limiter.claim(110),
            Some(2),
            "the next window reports the two suppressed accesses"
        );
        assert_eq!(limiter.claim(111), None);
    }
}
