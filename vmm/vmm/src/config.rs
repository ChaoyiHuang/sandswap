// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

pub use virtio_devices::fs::{
    default_fsconfig_cache, default_fsconfig_read_only, default_fsconfig_rlimit_nofile,
    default_fsconfig_thread_pool_size, default_fsconfig_xattr, BackendFsConfig,
    BACKEND_FS_CACHE_ALWAYS, BACKEND_FS_CACHE_AUTO, BACKEND_FS_CACHE_NEVER, BACKEND_FS_CACHE_NONE,
};
pub use virtio_devices::{RateLimiterConfig, TokenBucketConfig};

use clap::ArgMatches;
use option_parser::{
    ByteSized, IntegerList, OptionParser, OptionParserError, StringList, Toggle, Tuple,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::convert::From;
use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::result;
use std::str::FromStr;
use std::{fmt, fs};
use thiserror::Error;
use virtiofsd::passthrough::xattrmap::XattrMap;

use crate::vm_config::*;

const MAX_NUM_PCI_SEGMENTS: u16 = 16;

/// Largest virtio queue (VIRTIO specification: queue sizes are a power of two
/// up to 32768).
const MAX_VIRTIO_QUEUE_SIZE: u16 = 32768;

/// Errors associated with VM configuration parameters.
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem tag is missing
    ParseFsTagMissing,
    /// Filesystem socket is missing
    ParseFsSockMissing,
    /// Missing persistent memory file parameter.
    ParsePmemFileMissing,
    /// Missing vsock cid parameter.
    ParseVsockCidMissing,
    /// Missing restore source_url parameter.
    ParseRestoreSourceUrlMissing,
    /// Missing restore device id parameter.
    ParseRestoreDeviceIdMissing,
    /// Missing restore device path parameter.
    ParseRestoreDevicePathMissing,
    /// Error parsing CPU options
    ParseCpus(OptionParserError),
    /// Invalid CPU features
    InvalidCpuFeatures(String),
    /// Error parsing memory options
    ParseMemory(OptionParserError),
    /// Error parsing memory zone options
    ParseMemoryZone(OptionParserError),
    /// Missing 'id' from memory zone
    ParseMemoryZoneIdMissing,
    /// Error parsing disk options
    ParseDisk(OptionParserError),
    /// Error parsing network options
    ParseNetwork(OptionParserError),
    /// Error parsing RNG options
    ParseRng(OptionParserError),
    /// Error parsing balloon options
    ParseBalloon(OptionParserError),
    /// Error parsing filesystem parameters
    ParseFileSystem(OptionParserError),
    /// Error parsing persistent memory parameters
    ParsePersistentMemory(OptionParserError),
    /// Failed parsing console
    ParseConsole(OptionParserError),
    /// No mode given for console
    ParseConsoleInvalidModeGiven,
    /// Failed parsing device parameters
    ParseDevice(OptionParserError),
    /// Missing path from device,
    ParseDevicePathMissing,
    /// Failed parsing vsock parameters
    ParseVsock(OptionParserError),
    /// Failed parsing restore parameters
    ParseRestore(OptionParserError),
    /// Failed parsing restore device parameters
    ParseRestoreDevice(OptionParserError),
    /// Failed parsing SGX EPC parameters
    #[cfg(target_arch = "x86_64")]
    ParseSgxEpc(OptionParserError),
    /// Missing 'id' from SGX EPC section
    #[cfg(target_arch = "x86_64")]
    ParseSgxEpcIdMissing,
    /// Failed parsing NUMA parameters
    ParseNuma(OptionParserError),
    /// Failed validating configuration
    Validation(ValidationError),
    #[cfg(feature = "tdx")]
    /// Failed parsing TDX config
    ParseTdx(OptionParserError),
    #[cfg(feature = "tdx")]
    /// No TDX firmware
    FirmwarePathMissing,
    /// Failed parsing userspace device
    ParseUserDevice(OptionParserError),
    /// Missing socket for userspace device
    ParseUserDeviceSocketMissing,
    /// Failed parsing platform parameters
    ParsePlatform(OptionParserError),
    /// Failed parsing vDPA device
    ParseVdpa(OptionParserError),
    /// Missing path for vDPA device
    ParseVdpaPathMissing,
    /// Failed parsing TPM device
    ParseTpm(OptionParserError),
    /// Missing path for TPM device
    ParseTpmPathMissing,
    /// Filesystem shared_dir is missing
    ParseFsSharedDirMissing,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// No kernel specified
    KernelMissing,
    /// Missing file value for console
    ConsoleFileMissing,
    /// Max is less than boot
    CpusMaxLowerThanBoot,
    /// Physical address width outside the architecture's supported range
    InvalidMaxPhysBits(u8),
    /// Both socket and path specified
    DiskSocketAndPath,
    /// Using vhost user requires shared memory
    VhostUserRequiresSharedMemory,
    /// No socket provided for vhost_use
    VhostUserMissingSocket,
    /// Trying to use IOMMU without PCI
    IommuUnsupported,
    /// Trying to use VFIO without PCI
    VfioUnsupported,
    /// CPU topology count doesn't match max
    CpuTopologyCount,
    /// One part of the CPU topology was zero
    CpuTopologyZeroPart,
    #[cfg(target_arch = "aarch64")]
    /// Dies per package must be 1
    CpuTopologyDiesPerPackage,
    /// Virtio needs a min of 2 queues
    VnetQueueLowerThan2,
    /// The input queue number for virtio_net must match the number of input fds
    VnetQueueFdMismatch,
    /// Using reserved fd
    VnetReservedFd,
    /// Hugepages not turned on
    HugePageSizeWithoutHugePages,
    /// Huge page size is not power of 2
    InvalidHugePageSize(u64),
    /// CPU Hotplug is not permitted with TDX
    #[cfg(feature = "tdx")]
    TdxNoCpuHotplug,
    /// Missing firmware for TDX
    #[cfg(feature = "tdx")]
    TdxFirmwareMissing,
    /// Insuffient vCPUs for queues
    TooManyQueues,
    /// Need shared memory for vfio-user
    UserDevicesRequireSharedMemory,
    /// Memory zone is reused across NUMA nodes
    MemoryZoneReused(String, u32, u32),
    /// vhost-user networking is not permitted in this build
    VhostUserNetNotPermitted,
    /// inherited-fd networking is not permitted in this build
    NetFdsNotPermitted,
    /// A host path is outside every configured deployment root
    HostPathNotAllowed(&'static str, PathBuf),
    /// Invalid number of PCI segments
    InvalidNumPciSegments(u16),
    /// Invalid PCI segment id
    InvalidPciSegment(u16),
    /// Balloon too big
    BalloonLargerThanRam(u64, u64),
    /// On a IOMMU segment but not behind IOMMU
    OnIommuSegment(u16),
    // On a IOMMU segment but IOMMU not suported
    IommuNotSupportedOnSegment(u16),
    // Identifier is not unique
    IdentifierNotUnique(String),
    /// Invalid identifier
    InvalidIdentifier(String),
    /// Placing the device behind a virtual IOMMU is not supported
    IommuNotSupported,
    /// Duplicated device path (device added twice)
    DuplicateDevicePath(String),
    /// Provided MTU is lower than what the VIRTIO specification expects
    InvalidMtu(u16),
    /// native virtio-fs shouldn't have socket argument
    NativeVirtioFsSocket,
    /// A vm.set-fs request was rejected (unknown device, immutable field
    /// changed, invalid or replayed alias, ...)
    InvalidFsUpdate(String),
    /// Sandswap: more than one virtio-fs device configured
    TooManyFsDevices,
    /// Sandswap: a guest vsock CID outside the legal guest range
    /// (3..=0xFFFFFFFE — 0/1/2 are the kernel-reserved hypervisor/local/host
    /// ids and 0xFFFFFFFF is VMADDR_CID_ANY)
    VsockCid(u64),
    /// virtio-fs tag is empty or exceeds the fixed virtio config field
    InvalidFsTag(String),
    /// virtio queue size is not a power of two in 1..=32768
    InvalidQueueSize(u16),
}

type ValidationResult<T> = std::result::Result<T, ValidationError>;

/// The Linux vsock context ids a GUEST may not claim:
/// 0 = VMADDR_CID_HYPERVISOR, 1 = VMADDR_CID_LOCAL, 2 = VMADDR_CID_HOST,
/// and 0xFFFFFFFF = VMADDR_CID_ANY (the wildcard, which must never be handed
/// to VHOST_VSOCK_SET_GUEST_CID). Only `[FIRST, ANY)` is a legal guest cid.
pub const VMADDR_CID_GUEST_FIRST: u64 = 3;
pub const VMADDR_CID_ANY: u64 = 0xFFFF_FFFF;

/// Is `cid` legal for a VM's guest-vsock context id?
///
/// Single-VM rule only: the VMM cannot see other VMs' cids (one VMM process
/// per VM, no shared state), so the no-collision half of the rule stays with
/// the sandlot's allocator (which starts at 3 and tracks claimed cids); this
/// predicate is what keeps the reserved ids away from the vhost ioctl.
pub fn guest_cid_is_legal(cid: u64) -> bool {
    (VMADDR_CID_GUEST_FIRST..VMADDR_CID_ANY).contains(&cid)
}

/// Upper bound for a device's `pci_segment`. Every device config must call
/// this, including the hotplug path (`vm.add-vsock`): with no `platform`
/// there is still one default segment, and DeviceManager indexes its segment
/// vector with the value — an unchecked segment panics the VMM.
fn validate_pci_segment_bounds(pci_segment: u16, vm_config: &VmConfig) -> ValidationResult<()> {
    let num_pci_segments = vm_config
        .platform
        .as_ref()
        .map(|platform| platform.num_pci_segments)
        .unwrap_or(DEFAULT_NUM_PCI_SEGMENTS);
    if pci_segment >= num_pci_segments {
        return Err(ValidationError::InvalidPciSegment(pci_segment));
    }
    Ok(())
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ValidationError::*;
        match self {
            KernelMissing => write!(f, "No kernel specified"),
            ConsoleFileMissing => write!(f, "Path missing when using file console mode"),
            CpusMaxLowerThanBoot => write!(f, "Max CPUs lower than boot CPUs"),
            InvalidMaxPhysBits(bits) => {
                write!(f, "max_phys_bits ({}) not in the supported 32..=52 range", bits)
            }
            DiskSocketAndPath => write!(f, "Disk path and vhost socket both provided"),
            VhostUserRequiresSharedMemory => {
                write!(
                    f,
                    "Using vhost-user requires using shared memory or huge pages"
                )
            }
            VhostUserMissingSocket => write!(f, "No socket provided when using vhost-user"),
            IommuUnsupported => write!(f, "Using an IOMMU without PCI support is unsupported"),
            VfioUnsupported => write!(f, "Using VFIO without PCI support is unsupported"),
            CpuTopologyZeroPart => write!(f, "No part of the CPU topology can be zero"),
            CpuTopologyCount => write!(
                f,
                "Product of CPU topology parts does not match maximum vCPUs"
            ),
            #[cfg(target_arch = "aarch64")]
            CpuTopologyDiesPerPackage => write!(f, "Dies per package must be 1"),
            VnetQueueLowerThan2 => write!(f, "Number of queues to virtio_net less than 2"),
            VnetQueueFdMismatch => write!(
                f,
                "Number of queues to virtio_net does not match the number of input FDs"
            ),
            VnetReservedFd => write!(f, "Reserved fd number (<= 2)"),
            HugePageSizeWithoutHugePages => {
                write!(f, "Huge page size specified but huge pages not enabled")
            }
            InvalidHugePageSize(s) => {
                write!(f, "Huge page size is not power of 2: {}", s)
            }
            #[cfg(feature = "tdx")]
            TdxNoCpuHotplug => {
                write!(f, "CPU hotplug is not permitted with TDX")
            }
            #[cfg(feature = "tdx")]
            TdxFirmwareMissing => {
                write!(f, "No TDX firmware specified")
            }
            TooManyQueues => {
                write!(f, "Number of vCPUs is insufficient for number of queues")
            }
            UserDevicesRequireSharedMemory => {
                write!(
                    f,
                    "Using user devices requires using shared memory or huge pages"
                )
            }
            MemoryZoneReused(s, u1, u2) => {
                write!(
                    f,
                    "Memory zone: {} belongs to multiple NUMA nodes {} and {}",
                    s, u1, u2
                )
            }
            VhostUserNetNotPermitted => write!(
                f,
                "vhost-user virtio-net is not permitted: the VMM attaches only a host TAP it owns"
            ),
            NetFdsNotPermitted => write!(
                f,
                "inherited-fd virtio-net is not permitted: the VMM attaches only a host TAP it owns"
            ),
            HostPathNotAllowed(what, path) => write!(
                f,
                "{} path {} is outside every configured deployment root",
                what,
                path.display()
            ),
            InvalidNumPciSegments(n) => {
                write!(
                    f,
                    "Number of PCI segments ({}) not in range of 1 to {}",
                    n, MAX_NUM_PCI_SEGMENTS
                )
            }
            InvalidPciSegment(pci_segment) => {
                write!(f, "Invalid PCI segment id: {}", pci_segment)
            }
            BalloonLargerThanRam(balloon_size, ram_size) => {
                write!(
                    f,
                    "Ballon size ({}) greater than RAM ({})",
                    balloon_size, ram_size
                )
            }
            OnIommuSegment(pci_segment) => {
                write!(
                    f,
                    "Device is on an IOMMU PCI segment ({}) but not placed behind IOMMU",
                    pci_segment
                )
            }
            IommuNotSupportedOnSegment(pci_segment) => {
                write!(
                    f,
                    "Device is on an IOMMU PCI segment ({}) but does not support being placed behind IOMMU",
                    pci_segment
                )
            }
            IdentifierNotUnique(s) => {
                write!(f, "Identifier {} is not unique", s)
            }
            InvalidIdentifier(s) => {
                write!(f, "Identifier {} is invalid", s)
            }
            IommuNotSupported => {
                write!(f, "Device does not support being placed behind IOMMU")
            }
            DuplicateDevicePath(p) => write!(f, "Duplicated device path: {}", p),
            NativeVirtioFsSocket => {
                write!(f, "Native virtio-fs shouldn't have socket argument")
            }
            InvalidFsUpdate(msg) => write!(f, "Invalid vm.set-fs request: {}", msg),
            TooManyFsDevices => write!(
                f,
                "At most one virtio-fs device is supported (one share per VM, whitelisted by vm.set-fs)"
            ),
            VsockCid(cid) => write!(
                f,
                "Invalid guest vsock cid {} (legal guest cids are {}..={}; 0/1/2 are the reserved hypervisor/local/host ids and 0xFFFFFFFF is VMADDR_CID_ANY)",
                cid,
                VMADDR_CID_GUEST_FIRST,
                VMADDR_CID_ANY - 1
            ),
            InvalidFsTag(tag) => write!(
                f,
                "virtio-fs tag {tag:?} must be 1..={} bytes (the virtio config field is fixed-size)",
                virtio_devices::fs::MAX_TAG_LEN
            ),
            InvalidQueueSize(size) => write!(
                f,
                "virtio queue size {} must be a power of two in 1..=32768",
                size
            ),
            &InvalidMtu(mtu) => {
                write!(
                    f,
                    "Provided MTU {} is lower than 1280 (expected by VIRTIO specification)",
                    mtu
                )
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match self {
            ParseConsole(o) => write!(f, "Error parsing --console: {}", o),
            ParseConsoleInvalidModeGiven => {
                write!(f, "Error parsing --console: invalid console mode given")
            }
            ParseCpus(o) => write!(f, "Error parsing --cpus: {}", o),
            InvalidCpuFeatures(o) => write!(f, "Invalid feature in --cpus features list: {}", o),
            ParseDevice(o) => write!(f, "Error parsing --device: {}", o),
            ParseDevicePathMissing => write!(f, "Error parsing --device: path missing"),
            ParseFileSystem(o) => write!(f, "Error parsing --fs: {}", o),
            ParseFsSockMissing => write!(f, "Error parsing --fs: socket missing"),
            ParseFsTagMissing => write!(f, "Error parsing --fs: tag missing"),
            ParsePersistentMemory(o) => write!(f, "Error parsing --pmem: {}", o),
            ParsePmemFileMissing => write!(f, "Error parsing --pmem: file missing"),
            ParseVsock(o) => write!(f, "Error parsing --vsock: {}", o),
            ParseVsockCidMissing => write!(f, "Error parsing --vsock: cid missing"),
            ParseMemory(o) => write!(f, "Error parsing --memory: {}", o),
            ParseMemoryZone(o) => write!(f, "Error parsing --memory-zone: {}", o),
            ParseMemoryZoneIdMissing => write!(f, "Error parsing --memory-zone: id missing"),
            ParseNetwork(o) => write!(f, "Error parsing --net: {}", o),
            ParseDisk(o) => write!(f, "Error parsing --disk: {}", o),
            ParseRng(o) => write!(f, "Error parsing --rng: {}", o),
            ParseBalloon(o) => write!(f, "Error parsing --balloon: {}", o),
            ParseRestore(o) => write!(f, "Error parsing --restore: {}", o),
            ParseRestoreDevice(o) => write!(f, "Error parsing --restore-device: {}", o),
            #[cfg(target_arch = "x86_64")]
            ParseSgxEpc(o) => write!(f, "Error parsing --sgx-epc: {}", o),
            #[cfg(target_arch = "x86_64")]
            ParseSgxEpcIdMissing => write!(f, "Error parsing --sgx-epc: id missing"),
            ParseNuma(o) => write!(f, "Error parsing --numa: {}", o),
            ParseRestoreSourceUrlMissing => {
                write!(f, "Error parsing --restore: source_url missing")
            }
            ParseRestoreDeviceIdMissing => {
                write!(f, "Error parsing --restore-device: id missing")
            }
            ParseRestoreDevicePathMissing => {
                write!(f, "Error parsing --restore-device: path missing")
            }
            ParseUserDeviceSocketMissing => {
                write!(f, "Error parsing --user-device: socket missing")
            }
            ParseUserDevice(o) => write!(f, "Error parsing --user-device: {}", o),
            Validation(v) => write!(f, "Error validating configuration: {}", v),
            #[cfg(feature = "tdx")]
            ParseTdx(o) => write!(f, "Error parsing --tdx: {}", o),
            #[cfg(feature = "tdx")]
            FirmwarePathMissing => write!(f, "TDX firmware missing"),
            ParsePlatform(o) => write!(f, "Error parsing --platform: {}", o),
            ParseVdpa(o) => write!(f, "Error parsing --vdpa: {}", o),
            ParseVdpaPathMissing => write!(f, "Error parsing --vdpa: path missing"),
            ParseTpm(o) => write!(f, "Error parsing --tpm: {}", o),
            ParseTpmPathMissing => write!(f, "Error parsing --tpm: path missing"),
            ParseFsSharedDirMissing => write!(f, "Error parsing --shared_dir: path missing"),
        }
    }
}

pub fn add_to_config<T>(items: &mut Option<Vec<T>>, item: T) {
    if let Some(items) = items {
        items.push(item);
    } else {
        *items = Some(vec![item]);
    }
}

pub type Result<T> = result::Result<T, Error>;

pub struct VmParams<'a> {
    pub cpus: &'a str,
    pub memory: &'a str,
    pub memory_zones: Option<Vec<&'a str>>,
    pub firmware: Option<&'a str>,
    pub kernel: Option<&'a str>,
    pub initramfs: Option<&'a str>,
    pub cmdline: Option<&'a str>,
    pub disks: Option<Vec<&'a str>>,
    pub net: Option<Vec<&'a str>>,
    pub rng: &'a str,
    pub balloon: Option<&'a str>,
    pub fs: Option<Vec<&'a str>>,
    pub pmem: Option<Vec<&'a str>>,
    pub serial: &'a str,
    pub console: &'a str,
    pub devices: Option<Vec<&'a str>>,
    pub user_devices: Option<Vec<&'a str>>,
    pub vdpa: Option<Vec<&'a str>>,
    pub vsock: Option<&'a str>,
    #[cfg(target_arch = "x86_64")]
    pub sgx_epc: Option<Vec<&'a str>>,
    pub numa: Option<Vec<&'a str>>,
    pub watchdog: bool,
    #[cfg(feature = "guest_debug")]
    pub gdb: bool,
    pub platform: Option<&'a str>,
    pub tpm: Option<&'a str>,
}

impl<'a> VmParams<'a> {
    pub fn from_arg_matches(args: &'a ArgMatches) -> Self {
        // These .unwrap()s cannot fail as there is a default value defined
        let cpus = args.get_one::<String>("cpus").unwrap();
        let memory = args.get_one::<String>("memory").unwrap();
        let memory_zones: Option<Vec<&str>> = args
            .get_many::<String>("memory-zone")
            .map(|x| x.map(|y| y as &str).collect());
        let rng = args.get_one::<String>("rng").unwrap();
        let serial = args.get_one::<String>("serial").unwrap();
        let firmware = args.get_one::<String>("firmware").map(|x| x as &str);
        let kernel = args.get_one::<String>("kernel").map(|x| x as &str);
        let initramfs = args.get_one::<String>("initramfs").map(|x| x as &str);
        let cmdline = args.get_one::<String>("cmdline").map(|x| x as &str);
        let disks: Option<Vec<&str>> = args
            .get_many::<String>("disk")
            .map(|x| x.map(|y| y as &str).collect());
        let net: Option<Vec<&str>> = args
            .get_many::<String>("net")
            .map(|x| x.map(|y| y as &str).collect());
        let console = args.get_one::<String>("console").unwrap();
        let balloon = args.get_one::<String>("balloon").map(|x| x as &str);
        let fs: Option<Vec<&str>> = args
            .get_many::<String>("fs")
            .map(|x| x.map(|y| y as &str).collect());
        let pmem: Option<Vec<&str>> = args
            .get_many::<String>("pmem")
            .map(|x| x.map(|y| y as &str).collect());
        let devices: Option<Vec<&str>> = args
            .get_many::<String>("device")
            .map(|x| x.map(|y| y as &str).collect());
        let user_devices: Option<Vec<&str>> = args
            .get_many::<String>("user-device")
            .map(|x| x.map(|y| y as &str).collect());
        let vdpa: Option<Vec<&str>> = args
            .get_many::<String>("vdpa")
            .map(|x| x.map(|y| y as &str).collect());
        let vsock: Option<&str> = args.get_one::<String>("vsock").map(|x| x as &str);
        #[cfg(target_arch = "x86_64")]
        let sgx_epc: Option<Vec<&str>> = args
            .get_many::<String>("sgx-epc")
            .map(|x| x.map(|y| y as &str).collect());
        let numa: Option<Vec<&str>> = args
            .get_many::<String>("numa")
            .map(|x| x.map(|y| y as &str).collect());
        let watchdog = args.get_flag("watchdog");
        let platform = args.get_one::<String>("platform").map(|x| x as &str);
        #[cfg(feature = "guest_debug")]
        let gdb = args.contains_id("gdb");
        let tpm: Option<&str> = args.get_one::<String>("tpm").map(|x| x as &str);
        VmParams {
            cpus,
            memory,
            memory_zones,
            firmware,
            kernel,
            initramfs,
            cmdline,
            disks,
            net,
            rng,
            balloon,
            fs,
            pmem,
            serial,
            console,
            devices,
            user_devices,
            vdpa,
            vsock,
            #[cfg(target_arch = "x86_64")]
            sgx_epc,
            numa,
            watchdog,
            #[cfg(feature = "guest_debug")]
            gdb,
            platform,
            tpm,
        }
    }
}

#[derive(Debug)]
pub enum ParseHotplugMethodError {
    InvalidValue(String),
}

impl FromStr for HotplugMethod {
    type Err = ParseHotplugMethodError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "acpi" => Ok(HotplugMethod::Acpi),
            "virtio-mem" => Ok(HotplugMethod::VirtioMem),
            _ => Err(ParseHotplugMethodError::InvalidValue(s.to_owned())),
        }
    }
}

pub enum CpuTopologyParseError {
    InvalidValue(String),
}

impl FromStr for CpuTopology {
    type Err = CpuTopologyParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 4 {
            return Err(Self::Err::InvalidValue(s.to_owned()));
        }

        let t = CpuTopology {
            threads_per_core: parts[0]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
            cores_per_die: parts[1]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
            dies_per_package: parts[2]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
            packages: parts[3]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
        };

        Ok(t)
    }
}

impl CpusConfig {
    pub fn parse(cpus: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("boot")
            .add("max")
            .add("topology")
            .add("kvm_hyperv")
            .add("max_phys_bits")
            .add("affinity")
            .add("features");
        parser.parse(cpus).map_err(Error::ParseCpus)?;

        let boot_vcpus: u8 = parser
            .convert("boot")
            .map_err(Error::ParseCpus)?
            .unwrap_or(DEFAULT_VCPUS);
        let max_vcpus: u8 = parser
            .convert("max")
            .map_err(Error::ParseCpus)?
            .unwrap_or(boot_vcpus);
        let topology = parser.convert("topology").map_err(Error::ParseCpus)?;
        let kvm_hyperv = parser
            .convert::<Toggle>("kvm_hyperv")
            .map_err(Error::ParseCpus)?
            .unwrap_or(Toggle(false))
            .0;
        let max_phys_bits = parser
            .convert::<u8>("max_phys_bits")
            .map_err(Error::ParseCpus)?
            .unwrap_or(DEFAULT_MAX_PHYS_BITS);
        let affinity = parser
            .convert::<Tuple<u8, Vec<u8>>>("affinity")
            .map_err(Error::ParseCpus)?
            .map(|v| {
                v.0.iter()
                    .map(|(e1, e2)| CpuAffinity {
                        vcpu: *e1,
                        host_cpus: e2.clone(),
                    })
                    .collect()
            });
        let features_list = parser
            .convert::<StringList>("features")
            .map_err(Error::ParseCpus)?
            .unwrap_or_default();

        // Some ugliness here as the features being checked might be disabled
        // at compile time causing the below allow and the need to specify the
        // ref type in the match.
        // The issue will go away once kvm_hyperv is moved under the features
        // list as it will always be checked for.
        #[allow(unused_mut)]
        let mut features = CpuFeatures::default();
        for s in features_list.0 {
            match <std::string::String as AsRef<str>>::as_ref(&s) {
                #[cfg(target_arch = "x86_64")]
                "amx" => {
                    features.amx = true;
                    Ok(())
                }
                _ => Err(Error::InvalidCpuFeatures(s)),
            }?;
        }

        Ok(CpusConfig {
            boot_vcpus,
            max_vcpus,
            topology,
            kvm_hyperv,
            max_phys_bits,
            affinity,
            features,
        })
    }
}

impl PlatformConfig {
    pub fn parse(platform: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("num_pci_segments")
            .add("iommu_segments")
            .add("serial_number")
            .add("uuid")
            .add("oem_strings");
        #[cfg(feature = "tdx")]
        parser.add("tdx");
        parser.parse(platform).map_err(Error::ParsePlatform)?;

        let num_pci_segments: u16 = parser
            .convert("num_pci_segments")
            .map_err(Error::ParsePlatform)?
            .unwrap_or(DEFAULT_NUM_PCI_SEGMENTS);
        let iommu_segments = parser
            .convert::<IntegerList>("iommu_segments")
            .map_err(Error::ParsePlatform)?
            .map(|v| v.0.iter().map(|e| *e as u16).collect());
        let serial_number = parser
            .convert("serial_number")
            .map_err(Error::ParsePlatform)?;
        let uuid = parser.convert("uuid").map_err(Error::ParsePlatform)?;
        let oem_strings = parser
            .convert::<StringList>("oem_strings")
            .map_err(Error::ParsePlatform)?
            .map(|v| v.0);
        #[cfg(feature = "tdx")]
        let tdx = parser
            .convert::<Toggle>("tdx")
            .map_err(Error::ParsePlatform)?
            .unwrap_or(Toggle(false))
            .0;
        Ok(PlatformConfig {
            num_pci_segments,
            iommu_segments,
            serial_number,
            uuid,
            oem_strings,
            #[cfg(feature = "tdx")]
            tdx,
        })
    }

    pub fn validate(&self) -> ValidationResult<()> {
        if self.num_pci_segments == 0 || self.num_pci_segments > MAX_NUM_PCI_SEGMENTS {
            return Err(ValidationError::InvalidNumPciSegments(
                self.num_pci_segments,
            ));
        }

        if let Some(iommu_segments) = &self.iommu_segments {
            for segment in iommu_segments {
                if *segment >= self.num_pci_segments {
                    return Err(ValidationError::InvalidPciSegment(*segment));
                }
            }
        }

        Ok(())
    }
}

impl MemoryConfig {
    pub fn parse(memory: &str, memory_zones: Option<Vec<&str>>) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("mergeable")
            .add("hotplug_method")
            .add("hotplug_size")
            .add("hotplugged_size")
            .add("shared")
            .add("hugepages")
            .add("hugepage_size")
            .add("prefault")
            .add("thp")
            .add("dirty_log");
        parser.parse(memory).map_err(Error::ParseMemory)?;

        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParseMemory)?
            .unwrap_or(ByteSized(DEFAULT_MEMORY_MB << 20))
            .0;
        let mergeable = parser
            .convert::<Toggle>("mergeable")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let hotplug_method = parser
            .convert("hotplug_method")
            .map_err(Error::ParseMemory)?
            .unwrap_or_default();
        let hotplug_size = parser
            .convert::<ByteSized>("hotplug_size")
            .map_err(Error::ParseMemory)?
            .map(|v| v.0);
        let hotplugged_size = parser
            .convert::<ByteSized>("hotplugged_size")
            .map_err(Error::ParseMemory)?
            .map(|v| v.0);
        let shared = parser
            .convert::<Toggle>("shared")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let hugepages = parser
            .convert::<Toggle>("hugepages")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let hugepage_size = parser
            .convert::<ByteSized>("hugepage_size")
            .map_err(Error::ParseMemory)?
            .map(|v| v.0);
        let prefault = parser
            .convert::<Toggle>("prefault")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let thp = parser
            .convert::<Toggle>("thp")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(true))
            .0;
        let dirty_log = parser
            .convert::<Toggle>("dirty_log")
            .map_err(Error::ParseMemory)?
            .unwrap_or(Toggle(false))
            .0;

        let zones: Option<Vec<MemoryZoneConfig>> = if let Some(memory_zones) = &memory_zones {
            let mut zones = Vec::new();
            for memory_zone in memory_zones.iter() {
                let mut parser = OptionParser::new();
                parser
                    .add("id")
                    .add("size")
                    .add("file")
                    .add("shared")
                    .add("hugepages")
                    .add("hugepage_size")
                    .add("host_numa_node")
                    .add("hotplug_size")
                    .add("hotplugged_size")
                    .add("prefault");
                parser.parse(memory_zone).map_err(Error::ParseMemoryZone)?;

                let id = parser.get("id").ok_or(Error::ParseMemoryZoneIdMissing)?;
                let size = parser
                    .convert::<ByteSized>("size")
                    .map_err(Error::ParseMemoryZone)?
                    .unwrap_or(ByteSized(DEFAULT_MEMORY_MB << 20))
                    .0;
                let file = parser.get("file").map(PathBuf::from);
                let shared = parser
                    .convert::<Toggle>("shared")
                    .map_err(Error::ParseMemoryZone)?
                    .unwrap_or(Toggle(false))
                    .0;
                let hugepages = parser
                    .convert::<Toggle>("hugepages")
                    .map_err(Error::ParseMemoryZone)?
                    .unwrap_or(Toggle(false))
                    .0;
                let hugepage_size = parser
                    .convert::<ByteSized>("hugepage_size")
                    .map_err(Error::ParseMemoryZone)?
                    .map(|v| v.0);

                let host_numa_node = parser
                    .convert::<u32>("host_numa_node")
                    .map_err(Error::ParseMemoryZone)?;
                let hotplug_size = parser
                    .convert::<ByteSized>("hotplug_size")
                    .map_err(Error::ParseMemoryZone)?
                    .map(|v| v.0);
                let hotplugged_size = parser
                    .convert::<ByteSized>("hotplugged_size")
                    .map_err(Error::ParseMemoryZone)?
                    .map(|v| v.0);
                let prefault = parser
                    .convert::<Toggle>("prefault")
                    .map_err(Error::ParseMemoryZone)?
                    .unwrap_or(Toggle(false))
                    .0;

                zones.push(MemoryZoneConfig {
                    id,
                    size,
                    file,
                    shared,
                    hugepages,
                    hugepage_size,
                    host_numa_node,
                    hotplug_size,
                    hotplugged_size,
                    prefault,
                });
            }
            Some(zones)
        } else {
            None
        };

        Ok(MemoryConfig {
            size,
            mergeable,
            hotplug_method,
            hotplug_size,
            hotplugged_size,
            shared,
            hugepages,
            hugepage_size,
            prefault,
            zones,
            thp,
            dirty_log,
        })
    }

    pub fn total_size(&self) -> u64 {
        let mut size = self.size;
        if let Some(hotplugged_size) = self.hotplugged_size {
            size += hotplugged_size;
        }

        if let Some(zones) = &self.zones {
            for zone in zones.iter() {
                size += zone.size;
                if let Some(hotplugged_size) = zone.hotplugged_size {
                    size += hotplugged_size;
                }
            }
        }

        size
    }

    pub fn exist_shared(&self) -> bool {
        if self.shared {
            return true;
        }

        if let Some(zones) = &self.zones {
            for zone in zones.iter() {
                if zone.shared {
                    return true;
                }
            }
        }

        false
    }

    pub fn has_hotplug_virtio_mem(&self) -> bool {
        self.hotplug_method == HotplugMethod::VirtioMem
            && self.hotplugged_size.is_some()
            && self.hotplugged_size.unwrap() > 0
    }
}

impl DiskConfig {
    pub const SYNTAX: &'static str = "Disk parameters \
         \"path=<disk_image_path>,readonly=on|off,direct=on|off,iommu=on|off,\
         num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,\
         vhost_user=on|off,socket=<vhost_user_socket_path>,\
         bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,\
         ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,\
         id=<device_id>,pci_segment=<segment_id>\"";

    pub fn parse(disk: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("path")
            .add("readonly")
            .add("direct")
            .add("iommu")
            .add("queue_size")
            .add("num_queues")
            .add("vhost_user")
            .add("socket")
            .add("bw_size")
            .add("bw_one_time_burst")
            .add("bw_refill_time")
            .add("ops_size")
            .add("ops_one_time_burst")
            .add("ops_refill_time")
            .add("id")
            .add("_disable_io_uring")
            .add("pci_segment");
        parser.parse(disk).map_err(Error::ParseDisk)?;

        let path = parser.get("path").map(PathBuf::from);
        let readonly = parser
            .convert::<Toggle>("readonly")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let direct = parser
            .convert::<Toggle>("direct")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let queue_size = parser
            .convert("queue_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_else(default_diskconfig_queue_size);
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::ParseDisk)?
            .unwrap_or_else(default_diskconfig_num_queues);
        let vhost_user = parser
            .convert::<Toggle>("vhost_user")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let vhost_socket = parser.get("socket");
        let id = parser.get("id");
        let disable_io_uring = parser
            .convert::<Toggle>("_disable_io_uring")
            .map_err(Error::ParseDisk)?
            .unwrap_or(Toggle(false))
            .0;
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_size = parser
            .convert("bw_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_one_time_burst = parser
            .convert("bw_one_time_burst")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_refill_time = parser
            .convert("bw_refill_time")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_size = parser
            .convert("ops_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_one_time_burst = parser
            .convert("ops_one_time_burst")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_refill_time = parser
            .convert("ops_refill_time")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_tb_config = if bw_size != 0 && bw_refill_time != 0 {
            Some(TokenBucketConfig {
                size: bw_size,
                one_time_burst: Some(bw_one_time_burst),
                refill_time: bw_refill_time,
            })
        } else {
            None
        };
        let ops_tb_config = if ops_size != 0 && ops_refill_time != 0 {
            Some(TokenBucketConfig {
                size: ops_size,
                one_time_burst: Some(ops_one_time_burst),
                refill_time: ops_refill_time,
            })
        } else {
            None
        };
        let rate_limiter_config = if bw_tb_config.is_some() || ops_tb_config.is_some() {
            Some(RateLimiterConfig {
                bandwidth: bw_tb_config,
                ops: ops_tb_config,
            })
        } else {
            None
        };

        Ok(DiskConfig {
            path,
            readonly,
            direct,
            iommu,
            num_queues,
            queue_size,
            vhost_user,
            vhost_socket,
            rate_limiter_config,
            id,
            disable_io_uring,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if self.num_queues > vm_config.cpus.boot_vcpus as usize {
            return Err(ValidationError::TooManyQueues);
        }

        if self.vhost_user && self.iommu {
            return Err(ValidationError::IommuNotSupported);
        }

        validate_pci_segment_bounds(self.pci_segment, vm_config)?;
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ParseVhostModeError {
    InvalidValue(String),
}

impl FromStr for VhostMode {
    type Err = ParseVhostModeError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "client" => Ok(VhostMode::Client),
            "server" => Ok(VhostMode::Server),
            _ => Err(ParseVhostModeError::InvalidValue(s.to_owned())),
        }
    }
}

impl NetConfig {
    pub const SYNTAX: &'static str = "Network parameters \
    \"tap=<if_name>,ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,fd=<fd1,fd2...>,iommu=on|off,\
    num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,id=<device_id>,\
    vhost_user=<vhost_user_enable>,socket=<vhost_user_socket_path>,vhost_mode=client|server,\
    bw_size=<bytes>,bw_one_time_burst=<bytes>,bw_refill_time=<ms>,\
    ops_size=<io_ops>,ops_one_time_burst=<io_ops>,ops_refill_time=<ms>,pci_segment=<segment_id>\"";

    pub fn parse(net: &str) -> Result<Self> {
        let mut parser = OptionParser::new();

        parser
            .add("tap")
            .add("ip")
            .add("mask")
            .add("mac")
            .add("host_mac")
            .add("mtu")
            .add("iommu")
            .add("queue_size")
            .add("num_queues")
            .add("vhost_user")
            .add("socket")
            .add("vhost_mode")
            .add("id")
            .add("fd")
            .add("bw_size")
            .add("bw_one_time_burst")
            .add("bw_refill_time")
            .add("ops_size")
            .add("ops_one_time_burst")
            .add("ops_refill_time")
            .add("pci_segment");
        parser.parse(net).map_err(Error::ParseNetwork)?;

        let tap = parser.get("tap");
        let ip = parser
            .convert("ip")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_ip);
        let mask = parser
            .convert("mask")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_mask);
        let mac = parser
            .convert("mac")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_mac);
        let host_mac = parser.convert("host_mac").map_err(Error::ParseNetwork)?;
        let mtu = parser.convert("mtu").map_err(Error::ParseNetwork)?;
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseNetwork)?
            .unwrap_or(Toggle(false))
            .0;
        let queue_size = parser
            .convert("queue_size")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_queue_size);
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_else(default_netconfig_num_queues);
        let vhost_user = parser
            .convert::<Toggle>("vhost_user")
            .map_err(Error::ParseNetwork)?
            .unwrap_or(Toggle(false))
            .0;
        let vhost_socket = parser.get("socket");
        let vhost_mode = parser
            .convert("vhost_mode")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_default();
        let id = parser.get("id");
        let fds = parser
            .convert::<IntegerList>("fd")
            .map_err(Error::ParseNetwork)?
            .map(|v| v.0.iter().map(|e| *e as i32).collect());
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseNetwork)?
            .unwrap_or_default();
        let bw_size = parser
            .convert("bw_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_one_time_burst = parser
            .convert("bw_one_time_burst")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_refill_time = parser
            .convert("bw_refill_time")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_size = parser
            .convert("ops_size")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_one_time_burst = parser
            .convert("ops_one_time_burst")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let ops_refill_time = parser
            .convert("ops_refill_time")
            .map_err(Error::ParseDisk)?
            .unwrap_or_default();
        let bw_tb_config = if bw_size != 0 && bw_refill_time != 0 {
            Some(TokenBucketConfig {
                size: bw_size,
                one_time_burst: Some(bw_one_time_burst),
                refill_time: bw_refill_time,
            })
        } else {
            None
        };
        let ops_tb_config = if ops_size != 0 && ops_refill_time != 0 {
            Some(TokenBucketConfig {
                size: ops_size,
                one_time_burst: Some(ops_one_time_burst),
                refill_time: ops_refill_time,
            })
        } else {
            None
        };
        let rate_limiter_config = if bw_tb_config.is_some() || ops_tb_config.is_some() {
            Some(RateLimiterConfig {
                bandwidth: bw_tb_config,
                ops: ops_tb_config,
            })
        } else {
            None
        };

        let config = NetConfig {
            tap,
            ip,
            mask,
            mac,
            host_mac,
            mtu,
            iommu,
            num_queues,
            queue_size,
            vhost_user,
            vhost_socket,
            vhost_mode,
            id,
            fds,
            rate_limiter_config,
            pci_segment,
        };
        Ok(config)
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        // Sandswap never uses vhost-user or caller-inherited fds for guest
        // networking: the VMM attaches a host TAP it owns (owner-match
        // TUNSETIFF). Both alternatives are privilege primitives for the
        // unprivileged caller (connect to an arbitrary Unix socket / dup an
        // arbitrary inherited fd), so they are refused by name.
        if self.vhost_user {
            return Err(ValidationError::VhostUserNetNotPermitted);
        }
        if self.fds.is_some() {
            return Err(ValidationError::NetFdsNotPermitted);
        }
        if self.num_queues < 2 {
            return Err(ValidationError::VnetQueueLowerThan2);
        }

        if self.fds.is_some() && self.fds.as_ref().unwrap().len() * 2 != self.num_queues {
            return Err(ValidationError::VnetQueueFdMismatch);
        }

        if let Some(fds) = self.fds.as_ref() {
            for fd in fds {
                if *fd <= 2 {
                    return Err(ValidationError::VnetReservedFd);
                }
            }
        }

        if (self.num_queues / 2) > vm_config.cpus.boot_vcpus as usize {
            return Err(ValidationError::TooManyQueues);
        }

        if self.vhost_user && self.iommu {
            return Err(ValidationError::IommuNotSupported);
        }

        validate_pci_segment_bounds(self.pci_segment, vm_config)?;
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        if let Some(mtu) = self.mtu {
            if mtu < virtio_devices::net::MIN_MTU {
                return Err(ValidationError::InvalidMtu(mtu));
            }
        }

        Ok(())
    }
}

impl RngConfig {
    pub fn parse(rng: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("src").add("iommu");
        parser.parse(rng).map_err(Error::ParseRng)?;

        let src = PathBuf::from(
            parser
                .get("src")
                .unwrap_or_else(|| DEFAULT_RNG_SOURCE.to_owned()),
        );
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseRng)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(RngConfig { src, iommu })
    }
}

impl BalloonConfig {
    pub const SYNTAX: &'static str =
        "Balloon parameters \"size=<balloon_size>,deflate_on_oom=on|off,\
        free_page_reporting=on|off\"";

    pub fn parse(balloon: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("size");
        parser.add("deflate_on_oom");
        parser.add("free_page_reporting");
        parser.parse(balloon).map_err(Error::ParseBalloon)?;

        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParseBalloon)?
            .map(|v| v.0)
            .unwrap_or(0);

        let deflate_on_oom = parser
            .convert::<Toggle>("deflate_on_oom")
            .map_err(Error::ParseBalloon)?
            .unwrap_or(Toggle(false))
            .0;

        let free_page_reporting = parser
            .convert::<Toggle>("free_page_reporting")
            .map_err(Error::ParseBalloon)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(BalloonConfig {
            size,
            deflate_on_oom,
            free_page_reporting,
        })
    }
}

impl FsConfig {
    pub const SYNTAX: &'static str = "virtio-fs parameters \
    \"tag=<tag_name>,socket=<socket_path>,num_queues=<number_of_queues>,\
    queue_size=<size_of_each_queue>,id=<device_id>,pci_segment=<segment_id>,\
    native=<use_native_virtiofs>,shared_dir=<shared_dir>,xattr=<xattr>,\
    posix_acl=<posix_acl>,xattrmap=<xattrmap>,announce_submounts=<announce_submounts>\
    cache=<cache>,no_readdirplus=<no_readdirplus>,writeback=<writeback>,\
    allow_direct_io=<allow_direct_io>,read_only=<read_only>,rlimit_nofile=<rlimit_nofile>,\
    killpriv_v2=<killpriv_v2>,security_label=<security_label>,\
    thread_pool_size=<thread_pool_size>,ops_size=<ops_size>,\
    ops_one_time_burst=<ops_one_time_burst>,ops_refill_time=<ops_refill_time>,\
    bw_size=<bw_size>,bw_one_time_burst=<bw_one_time_burst>,bw_refill_time=<bw_refill_time>,\
    allowed_dirs=<dir_list>,alias=<root_name>\"";

    fn add_frontend_args(parser: &mut OptionParser) {
        parser
            .add("tag")
            .add("queue_size")
            .add("num_queues")
            .add("socket")
            .add("id")
            .add("pci_segment")
            .add("native");
    }

    fn add_backend_args(parser: &mut OptionParser) {
        parser
            .add("shared_dir")
            .add("thread_pool_size")
            .add("xattr")
            .add("posix_acl")
            .add("xattrmap")
            .add("announce_submounts")
            .add("cache")
            .add("no_readdirplus")
            .add("writeback")
            .add("allow_direct_io")
            .add("read_only")
            .add("rlimit_nofile")
            .add("killpriv_v2")
            .add("security_label")
            .add("allowed_dirs")
            .add("alias");
    }

    fn add_ratelimiter_args(parser: &mut OptionParser) {
        parser
            .add("ops_size")
            .add("ops_one_time_burst")
            .add("ops_refill_time")
            .add("bw_size")
            .add("bw_one_time_burst")
            .add("bw_refill_time");
    }

    fn parse_backendfs(parser: &OptionParser) -> Result<BackendFsConfig> {
        let shared_dir = parser
            .get("shared_dir")
            .ok_or(Error::ParseFsSharedDirMissing)?;
        let thread_pool_size = parser
            .convert("thread_pool_size")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(default_fsconfig_thread_pool_size);
        let xattr = parser
            .convert("xattr")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(default_fsconfig_xattr);
        let posix_acl = parser
            .convert::<Toggle>("posix_acl")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or(Toggle(false))
            .0;
        let xattrmap = parser.get("xattrmap");
        if let Some(ref map_str) = xattrmap {
            XattrMap::try_from(map_str.as_str()).map_err(|_| {
                Error::ParseFileSystem(OptionParserError::Conversion(
                    "xattrmap".to_string(),
                    map_str.to_string(),
                ))
            })?;
        }
        let announce_submounts = parser
            .convert::<Toggle>("announce_submounts")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or(Toggle(false))
            .0;
        let no_readdirplus = parser
            .convert::<Toggle>("no_readdirplus")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or(Toggle(false))
            .0;
        let writeback = parser
            .convert::<Toggle>("writeback")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or(Toggle(false))
            .0;
        let allow_direct_io = parser
            .convert::<Toggle>("allow_direct_io")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or(Toggle(false))
            .0;
        let read_only = parser
            .convert("read_only")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(default_fsconfig_read_only);
        let killpriv_v2 = parser
            .convert::<Toggle>("killpriv_v2")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or(Toggle(false))
            .0;
        let security_label = parser
            .convert::<Toggle>("security_label")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or(Toggle(false))
            .0;
        let cache;
        if let Some(cache_string) = parser.get("cache") {
            cache = match cache_string.as_str() {
                "auto" => BACKEND_FS_CACHE_AUTO,
                "always" => BACKEND_FS_CACHE_ALWAYS,
                "never" => BACKEND_FS_CACHE_NEVER,
                "none" => BACKEND_FS_CACHE_NONE,
                cache_str => {
                    return Err(Error::ParseFileSystem(OptionParserError::Conversion(
                        "cache".to_string(),
                        cache_str.to_string(),
                    )))
                }
            }
        } else {
            cache = default_fsconfig_cache();
        }
        let rlimit_nofile = parser
            .convert("rlimit_nofile")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(default_fsconfig_rlimit_nofile);
        // FAIL-CLOSED: an omitted allowed_dirs parses to the empty
        // (allow-nothing) list — never to None. The share filter has no
        // unfiltered mode, so "not specified" must mean "nothing visible".
        let allowed_dirs = Some(
            parser
                .convert::<StringList>("allowed_dirs")
                .map_err(Error::ParseFileSystem)?
                .map(|v| v.0)
                .unwrap_or_default(),
        );

        let alias = parser.get("alias").map(|v| v.to_string());

        Ok(BackendFsConfig {
            shared_dir,
            thread_pool_size,
            xattr,
            posix_acl,
            xattrmap,
            announce_submounts,
            cache,
            no_readdirplus,
            writeback,
            read_only,
            allow_direct_io,
            rlimit_nofile,
            killpriv_v2,
            security_label,
            allowed_dirs,
            alias,
        })
    }

    pub fn parse(fs: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        Self::add_frontend_args(&mut parser);
        Self::add_backend_args(&mut parser);
        Self::add_ratelimiter_args(&mut parser);

        parser.parse(fs).map_err(Error::ParseFileSystem)?;

        let native = parser
            .convert::<Toggle>("native")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or(Toggle(false))
            .0;

        let tag = parser.get("tag").ok_or(Error::ParseFsTagMissing)?;
        let mut socket = PathBuf::new();
        if !native {
            socket = PathBuf::from(parser.get("socket").ok_or(Error::ParseFsSockMissing)?);
        }

        let queue_size = parser
            .convert("queue_size")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(default_fsconfig_queue_size);
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_else(default_fsconfig_num_queues);

        let id = parser.get("id");

        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseFileSystem)?
            .unwrap_or_default();

        let mut backendfs_config = None;
        // backend args are ignored if native is false
        let rate_limiter_config = if native {
            backendfs_config = Some(Self::parse_backendfs(&parser)?);

            let ops_size = parser
                .convert("ops_size")
                .map_err(Error::ParseFileSystem)?
                .unwrap_or_default();
            let ops_one_time_burst = parser
                .convert("ops_one_time_burst")
                .map_err(Error::ParseFileSystem)?
                .unwrap_or_default();
            let ops_refill_time = parser
                .convert("ops_refill_time")
                .map_err(Error::ParseFileSystem)?
                .unwrap_or_default();
            let ops_tb_config = if ops_size != 0 && ops_refill_time != 0 {
                Some(TokenBucketConfig {
                    size: ops_size,
                    one_time_burst: Some(ops_one_time_burst),
                    refill_time: ops_refill_time,
                })
            } else {
                None
            };

            let bw_size = parser
                .convert("bw_size")
                .map_err(Error::ParseFileSystem)?
                .unwrap_or_default();
            let bw_one_time_burst = parser
                .convert("bw_one_time_burst")
                .map_err(Error::ParseFileSystem)?
                .unwrap_or_default();
            let bw_refill_time = parser
                .convert("bw_refill_time")
                .map_err(Error::ParseFileSystem)?
                .unwrap_or_default();
            let bw_tb_config = if bw_size != 0 && bw_refill_time != 0 {
                Some(TokenBucketConfig {
                    size: bw_size,
                    one_time_burst: Some(bw_one_time_burst),
                    refill_time: bw_refill_time,
                })
            } else {
                None
            };

            if ops_tb_config.is_some() || bw_tb_config.is_some() {
                Some(RateLimiterConfig {
                    bandwidth: bw_tb_config,
                    ops: ops_tb_config,
                })
            } else {
                None
            }
        } else {
            None
        };

        Ok(FsConfig {
            tag,
            socket,
            num_queues,
            queue_size,
            id,
            pci_segment,
            backendfs_config,
            rate_limiter_config,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        if self.num_queues > vm_config.cpus.boot_vcpus as usize {
            return Err(ValidationError::TooManyQueues);
        }

        validate_pci_segment_bounds(self.pci_segment, vm_config)?;
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) {
                    return Err(ValidationError::IommuNotSupportedOnSegment(
                        self.pci_segment,
                    ));
                }
            }
        }

        if let Some(backend) = self.backendfs_config.as_ref() {
            if self.socket.to_str() != Some("") {
                return Err(ValidationError::NativeVirtioFsSocket);
            }
            // The device is IMMUTABLE: it is created with an EMPTY allow-list
            // (deny-all) and only vm.set-fs installs an export at runtime.
            // Accepting a populated list here would bake a second, divergent
            // filter source into the device — the exact shape a reset could
            // resurrect. Entries are validated at set-fs time instead.
            if let Some(dirs) = backend.allowed_dirs.as_ref() {
                if dirs.iter().any(|d| !d.is_empty()) {
                    return Err(ValidationError::InvalidFsUpdate(
                        "fs: a non-empty allowed_dirs is refused at vm.create — the export is installed by vm.set-fs"
                            .to_string(),
                    ));
                }
            }
            validate_export_alias_pair(backend, "fs: ")
                .map_err(ValidationError::InvalidFsUpdate)?;
        } else {
            if !vm_config.backed_by_shared_memory() {
                return Err(ValidationError::VhostUserRequiresSharedMemory);
            }
            if self.socket.to_str() == Some("") {
                return Err(ValidationError::VhostUserMissingSocket);
            }
        }

        // The tag lands in a fixed-size virtio config field and the queue
        // size feeds Queue::new (which rejects anything but a power of two).
        // Validate both so a bad value fails the config instead of panicking
        // device construction.
        if self.tag.is_empty() || self.tag.len() > virtio_devices::fs::MAX_TAG_LEN {
            return Err(ValidationError::InvalidFsTag(self.tag.clone()));
        }
        if self.queue_size == 0
            || !self.queue_size.is_power_of_two()
            || self.queue_size > MAX_VIRTIO_QUEUE_SIZE
        {
            return Err(ValidationError::InvalidQueueSize(self.queue_size));
        }

        Ok(())
    }
}

/// Pair-level rules for the export alias (create-time config and vm.set-fs).
/// A non-empty allow-list requires one valid alias; the empty (deny-all)
/// list must not carry one.
fn validate_export_alias_pair(
    backend: &BackendFsConfig,
    prefix: &str,
) -> std::result::Result<(), String> {
    let non_empty = backend
        .allowed_dirs
        .as_ref()
        .is_some_and(|d| d.iter().any(|e| !e.is_empty()));
    match (non_empty, backend.alias.as_deref()) {
        (true, Some(alias)) => {
            if virtiofsd::server::validate_alias(alias) {
                Ok(())
            } else {
                Err(format!(
                    "{prefix}invalid export alias {alias:?}: one component of [A-Za-z0-9._-], 1..=64 bytes, not . or .."
                ))
            }
        }
        (true, None) => Err(format!(
            "{prefix}a non-empty allowed_dirs requires an export alias (the generation's guest-visible root name)"
        )),
        (false, Some(alias)) if !alias.is_empty() => Err(format!(
            "{prefix}the clear (empty allowed_dirs) must not carry an export alias (got {alias:?})"
        )),
        _ => Ok(()),
    }
}

/// Structural containment of an `allowed_dirs` allow-list.
///
/// The share exports exactly one host directory; an allow-list entry outside
/// it (crafted raw frame / compromised sandlot / a sibling VMM on the same
/// API socket) would widen the export to arbitrary host directories — a
/// second window past the one-share isolation invariant. Rules, in order:
///   1. every entry must be absolute (a relative path would resolve against
///      the sandvmm process CWD at filter-init time);
///   2. no entry may contain a `..` component;
///   3. when `shared_dir` is non-empty, every entry must be the share root
///      itself or a lexical descendant of it AND must RESOLVE beneath an fd
///      of the share root with every relative component opened O_NOFOLLOW.
///      A symlinked component — above or below the root — is refused: the
///      entry must name a real directory literally, so the filter's later
///      openat (O_NOFOLLOW on the entry's own final component) cannot be
///      re-pointed by a symlink swap between validation and activation.
///
/// A non-existent entry (or one that is not a directory) is refused: the
/// runtime filter refuses such an entry anyway (its openat fails and the
/// whitelist swap aborts), and validating here turns a device-level failure
/// after acceptance into a named API error.
///
/// `prefix` labels the caller's error messages ("vm.set-fs: " for the API
/// path, "fs: " at create time); both paths call this one implementation.
fn validate_allowed_dirs_containment(
    shared_dir: &str,
    dirs: &[String],
    prefix: &str,
) -> result::Result<(), String> {
    // The one-share contract in its narrowest form: a VM exports the active
    // tenant volume, never a set. Sandlot sends 0 (clear) or 1 (mount); a
    // compromised sandlot must not be able to widen one guest to several
    // tenants' directories in a single vm.set-fs (or a create config).
    if dirs.len() > 1 {
        return Err(format!(
            "{prefix}allowed_dirs has {} entries — one VM exports at most one host directory (the active tenant volume); a multi-entry list is refused",
            dirs.len()
        ));
    }
    let shared = shared_dir.trim_end_matches('/');
    for dir in dirs {
        if !dir.starts_with('/') {
            return Err(format!(
                "{prefix}allowed_dirs entries must be absolute paths, got {dir:?}"
            ));
        }
        if dir.split('/').any(|c| c == "..") {
            return Err(format!(
                "{prefix}allowed_dirs entry {dir:?} contains a '..' component — refused: resolving it on the host would escape the share root"
            ));
        }
        if shared.is_empty() {
            // `shared_dir` was empty or "/" (trim_end_matches('/') folds the
            // root to ""): no containment is possible, and an allow-list
            // entry would resolve anywhere on the host. This used to
            // `continue` — accepting arbitrary absolute entries — so refuse
            // the pair outright. A create-time config with an EMPTY list is
            // still fine (the filter denies everything; fail-closed).
            return Err(format!(
                "{prefix}allowed_dirs requires a non-empty shared_dir that is not the host root (got {shared_dir:?}) — one VM exports exactly one host directory"
            ));
        }
        // The share root itself is NOT a legal entry: exporting it makes
        // every tenant directory a single visible root entry (and every
        // name derived under it resolvable), which no sandswap caller does.
        // Only strict descendants are accepted.
        if dir == shared {
            return Err(format!(
                "{prefix}allowed_dirs entry {dir:?} is the share root itself — entries must name a directory BENEATH it (one VM exports exactly one host directory, and never the whole tree)"
            ));
        }
        // Lexical normalization closes the spelling variants that bypass the
        // exact comparison above: a trailing slash, `//`, or `/.` components
        // resolve to the share root but are not byte-equal to it. The old
        // resolver filtered those components and opened the share root under
        // the alias (the whole-tree export this function exists to refuse).
        let normalized = {
            let mut parts: Vec<&str> = Vec::new();
            for c in dir.split('/') {
                if !c.is_empty() && c != "." {
                    parts.push(c);
                }
            }
            format!("/{}", parts.join("/"))
        };
        if normalized == shared {
            return Err(format!(
                "{prefix}allowed_dirs entry {dir:?} normalizes to the share root itself ({normalized:?}) — entries must name a directory STRICTLY beneath it"
            ));
        }
        let inside = dir.starts_with(shared) && dir.as_bytes().get(shared.len()) == Some(&b'/');
        if !inside {
            return Err(format!(
                "{prefix}allowed_dirs entry {dir:?} is outside the VM's shared_dir {shared:?} — one VM exports exactly one host directory"
            ));
        }
        resolve_beneath_share_root(shared, dir, prefix)?;
    }
    Ok(())
}

/// Open a host directory O_PATH|O_DIRECTORY, returning a directory fd.
/// The share root itself is opened with the same semantics the passthrough
/// root uses (intermediate symlinks of the operator-configured root are
/// followed; the root is the trust anchor), but the final component must be a
/// real directory.
fn open_dir_fd(path: &str) -> std::io::Result<OwnedFd> {
    let c = CString::new(path).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open one path COMPONENT below `dir` with O_PATH|O_DIRECTORY|O_NOFOLLOW:
/// `O_NOFOLLOW` applies to each component because each is the final component
/// of its own openat, so a symlink (or a non-directory) anywhere in the walk
/// is refused with ENOTDIR/ELOOP instead of followed.
fn open_component_nofollow(dir: &OwnedFd, name: &CStr) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Resolve `dir` (already lexically contained in `shared`) against an fd of
/// `shared`, one component at a time, O_NOFOLLOW per component. The equivalent
/// of `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` without the 5.6+ kernel
/// dependency, and of the component walk the warden's file API uses. A failure
/// means the entry does not resolve to a real directory beneath the share
/// root — refused with a named error.
fn resolve_beneath_share_root(shared: &str, dir: &str, prefix: &str) -> result::Result<(), String> {
    let root_fd = open_dir_fd(shared).map_err(|e| {
        format!("{prefix}shared_dir {shared:?} cannot be opened for containment resolution: {e}")
    })?;
    let suffix = if dir == shared {
        "."
    } else {
        &dir[shared.len() + 1..]
    };
    let mut cur = root_fd;
    for comp in suffix.split('/').filter(|c| !c.is_empty() && *c != ".") {
        let c = CString::new(comp).map_err(|_| {
            format!("{prefix}allowed_dirs entry {dir:?} contains a NUL byte in a component")
        })?;
        let next = open_component_nofollow(&cur, &c).map_err(|e| {
            format!(
                "{prefix}allowed_dirs entry {dir:?} does not resolve to a directory beneath the share root {shared:?} (refused component {comp:?}: {e})"
            )
        })?;
        cur = next;
    }
    Ok(())
}

impl PmemConfig {
    pub const SYNTAX: &'static str = "Persistent memory parameters \
    \"file=<backing_file_path>,size=<persistent_memory_size>,iommu=on|off,\
    discard_writes=on|off,id=<device_id>,pci_segment=<segment_id>\"";
    pub fn parse(pmem: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("size")
            .add("file")
            .add("iommu")
            .add("discard_writes")
            .add("id")
            .add("pci_segment");
        parser.parse(pmem).map_err(Error::ParsePersistentMemory)?;

        let file = PathBuf::from(parser.get("file").ok_or(Error::ParsePmemFileMissing)?);
        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParsePersistentMemory)?
            .map(|v| v.0);
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParsePersistentMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let discard_writes = parser
            .convert::<Toggle>("discard_writes")
            .map_err(Error::ParsePersistentMemory)?
            .unwrap_or(Toggle(false))
            .0;
        let id = parser.get("id");
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParsePersistentMemory)?
            .unwrap_or_default();

        Ok(PmemConfig {
            file,
            size,
            iommu,
            discard_writes,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        validate_pci_segment_bounds(self.pci_segment, vm_config)?;
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        Ok(())
    }
}

impl ConsoleConfig {
    pub fn parse(console: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add_valueless("off")
            .add_valueless("pty")
            .add_valueless("tty")
            .add_valueless("null")
            .add("file")
            .add("sigwinch")
            .add("iommu");
        parser.parse(console).map_err(Error::ParseConsole)?;

        let mut file: Option<PathBuf> = default_consoleconfig_file();
        let mut mode: ConsoleOutputMode = ConsoleOutputMode::Off;

        if parser.is_set("off") {
        } else if parser.is_set("pty") {
            mode = ConsoleOutputMode::Pty
        } else if parser.is_set("tty") {
            mode = ConsoleOutputMode::Tty
        } else if parser.is_set("null") {
            mode = ConsoleOutputMode::Null
        } else if parser.is_set("file") {
            mode = ConsoleOutputMode::File;
            file =
                Some(PathBuf::from(parser.get("file").ok_or(
                    Error::Validation(ValidationError::ConsoleFileMissing),
                )?));
        } else {
            return Err(Error::ParseConsoleInvalidModeGiven);
        }
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseConsole)?
            .unwrap_or(Toggle(false))
            .0;
        let sigwinch = parser
            .convert::<Toggle>("sigwinch")
            .map_err(Error::ParseConsole)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(Self {
            file,
            mode,
            iommu,
            sigwinch,
        })
    }
}

impl DeviceConfig {
    pub const SYNTAX: &'static str =
        "Direct device assignment parameters \"path=<device_path>,iommu=on|off,id=<device_id>,pci_segment=<segment_id>\"";
    pub fn parse(device: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("path").add("id").add("iommu").add("pci_segment");
        parser.parse(device).map_err(Error::ParseDevice)?;

        let path = parser
            .get("path")
            .map(PathBuf::from)
            .ok_or(Error::ParseDevicePathMissing)?;
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseDevice)?
            .unwrap_or(Toggle(false))
            .0;
        let id = parser.get("id");
        let pci_segment = parser
            .convert::<u16>("pci_segment")
            .map_err(Error::ParseDevice)?
            .unwrap_or_default();

        Ok(DeviceConfig {
            path,
            iommu,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        validate_pci_segment_bounds(self.pci_segment, vm_config)?;
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        Ok(())
    }
}

impl UserDeviceConfig {
    pub const SYNTAX: &'static str =
        "Userspace device socket=<socket_path>,id=<device_id>,pci_segment=<segment_id>\"";
    pub fn parse(user_device: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("socket").add("id").add("pci_segment");
        parser.parse(user_device).map_err(Error::ParseUserDevice)?;

        let socket = parser
            .get("socket")
            .map(PathBuf::from)
            .ok_or(Error::ParseUserDeviceSocketMissing)?;
        let id = parser.get("id");
        let pci_segment = parser
            .convert::<u16>("pci_segment")
            .map_err(Error::ParseUserDevice)?
            .unwrap_or_default();

        Ok(UserDeviceConfig {
            socket,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        validate_pci_segment_bounds(self.pci_segment, vm_config)?;
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) {
                    return Err(ValidationError::IommuNotSupportedOnSegment(
                        self.pci_segment,
                    ));
                }
            }
        }

        Ok(())
    }
}

impl VdpaConfig {
    pub const SYNTAX: &'static str = "vDPA device \
        \"path=<device_path>,num_queues=<number_of_queues>,iommu=on|off,\
        id=<device_id>,pci_segment=<segment_id>\"";
    pub fn parse(vdpa: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("path")
            .add("num_queues")
            .add("iommu")
            .add("id")
            .add("pci_segment");
        parser.parse(vdpa).map_err(Error::ParseVdpa)?;

        let path = parser
            .get("path")
            .map(PathBuf::from)
            .ok_or(Error::ParseVdpaPathMissing)?;
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::ParseVdpa)?
            .unwrap_or_else(default_vdpaconfig_num_queues);
        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseVdpa)?
            .unwrap_or(Toggle(false))
            .0;
        let id = parser.get("id");
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseVdpa)?
            .unwrap_or_default();

        Ok(VdpaConfig {
            path,
            num_queues,
            iommu,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        validate_pci_segment_bounds(self.pci_segment, vm_config)?;
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        Ok(())
    }
}

impl VsockConfig {
    pub const SYNTAX: &'static str = "Virtio VSOCK parameters \
        \"cid=<context_id>,iommu=on|off,id=<device_id>,pci_segment=<segment_id>\"";
    pub fn parse(vsock: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("cid").add("iommu").add("id").add("pci_segment");
        parser.parse(vsock).map_err(Error::ParseVsock)?;

        let iommu = parser
            .convert::<Toggle>("iommu")
            .map_err(Error::ParseVsock)?
            .unwrap_or(Toggle(false))
            .0;
        let cid = parser
            .convert("cid")
            .map_err(Error::ParseVsock)?
            .ok_or(Error::ParseVsockCidMissing)?;
        let id = parser.get("id");
        let pci_segment = parser
            .convert("pci_segment")
            .map_err(Error::ParseVsock)?
            .unwrap_or_default();

        Ok(VsockConfig {
            cid,
            iommu,
            id,
            pci_segment,
        })
    }

    pub fn validate(&self, vm_config: &VmConfig) -> ValidationResult<()> {
        validate_pci_segment_bounds(self.pci_segment, vm_config)?;
        if let Some(platform_config) = vm_config.platform.as_ref() {
            if let Some(iommu_segments) = platform_config.iommu_segments.as_ref() {
                if iommu_segments.contains(&self.pci_segment) && !self.iommu {
                    return Err(ValidationError::OnIommuSegment(self.pci_segment));
                }
            }
        }

        // the cid reaches VHOST_VSOCK_SET_GUEST_CID verbatim, where a
        // reserved or wildcard value would reroute host-side vsock traffic
        // (0/1/2 are the hypervisor/local/host ids; 0xFFFFFFFF is ANY).
        // Refused here so BOTH entry points are covered: the config that
        // arrives at vm.create and the clone vm.add-vsock validates before
        // hotplug.
        if !guest_cid_is_legal(self.cid) {
            return Err(ValidationError::VsockCid(self.cid));
        }

        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
impl SgxEpcConfig {
    pub const SYNTAX: &'static str = "SGX EPC parameters \
        \"id=<epc_section_identifier>,size=<epc_section_size>,prefault=on|off\"";
    pub fn parse(sgx_epc: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("id").add("size").add("prefault");
        parser.parse(sgx_epc).map_err(Error::ParseSgxEpc)?;

        let id = parser.get("id").ok_or(Error::ParseSgxEpcIdMissing)?;
        let size = parser
            .convert::<ByteSized>("size")
            .map_err(Error::ParseSgxEpc)?
            .unwrap_or(ByteSized(0))
            .0;
        let prefault = parser
            .convert::<Toggle>("prefault")
            .map_err(Error::ParseSgxEpc)?
            .unwrap_or(Toggle(false))
            .0;

        Ok(SgxEpcConfig { id, size, prefault })
    }
}

impl NumaConfig {
    pub const SYNTAX: &'static str = "Settings related to a given NUMA node \
        \"guest_numa_id=<node_id>,cpus=<cpus_id>,distances=<list_of_distances_to_destination_nodes>,\
        memory_zones=<list_of_memory_zones>,sgx_epc_sections=<list_of_sgx_epc_sections>\"";
    pub fn parse(numa: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("guest_numa_id")
            .add("cpus")
            .add("distances")
            .add("memory_zones")
            .add("sgx_epc_sections");
        parser.parse(numa).map_err(Error::ParseNuma)?;

        let guest_numa_id = parser
            .convert::<u32>("guest_numa_id")
            .map_err(Error::ParseNuma)?
            .unwrap_or(0);
        let cpus = parser
            .convert::<IntegerList>("cpus")
            .map_err(Error::ParseNuma)?
            .map(|v| v.0.iter().map(|e| *e as u8).collect());
        let distances = parser
            .convert::<Tuple<u64, u64>>("distances")
            .map_err(Error::ParseNuma)?
            .map(|v| {
                v.0.iter()
                    .map(|(e1, e2)| NumaDistance {
                        destination: *e1 as u32,
                        distance: *e2 as u8,
                    })
                    .collect()
            });
        let memory_zones = parser
            .convert::<StringList>("memory_zones")
            .map_err(Error::ParseNuma)?
            .map(|v| v.0);
        #[cfg(target_arch = "x86_64")]
        let sgx_epc_sections = parser
            .convert::<StringList>("sgx_epc_sections")
            .map_err(Error::ParseNuma)?
            .map(|v| v.0);

        Ok(NumaConfig {
            guest_numa_id,
            cpus,
            distances,
            memory_zones,
            #[cfg(target_arch = "x86_64")]
            sgx_epc_sections,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RestoreDevice {
    pub id: String,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct RestoreConfig {
    pub source_url: PathBuf,
    #[serde(default)]
    pub prefault: bool,
    pub disks: Option<Vec<DiskConfig>>,
    pub net: Option<Vec<NetConfig>>,
    pub fs: Option<Vec<FsConfig>>,
    pub vsock: Option<VsockConfig>,
    pub pmem: Option<Vec<PmemConfig>>,
    #[serde(default)]
    pub dirty_log: bool,
    /// Optional existing memory blob path for reading memory range data from a
    /// separate volume.
    /// Accepts either an absolute path like `/dev/vdb` or a `file:///dev/vdb`
    /// URL. When set, memory snapshots are read from this path instead of
    /// source_url/<SNAPSHOT_FILENAME>.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_vol_url: Option<String>,
}

impl RestoreConfig {
    pub const SYNTAX: &'static str = "Restore from a VM snapshot. \
        \nRestore parameters \"source_url=<source_url>,prefault=on|off,memory_vol_url=<memory_vol_url>\" \
        \n`source_url` should be a valid URL (e.g file:///foo/bar or tcp://192.168.1.10/foo) \
        \n`prefault` brings memory pages in when enabled (disabled by default) \
        \n`memory_vol_url` optional existing memory blob path (for example /dev/vdb or file:///dev/vdb) \
        \nfor reading memory range data from a separate volume";
    pub fn parse(restore: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("source_url")
            .add("prefault")
            .add("memory_vol_url");
        parser.parse(restore).map_err(Error::ParseRestore)?;

        let source_url = parser
            .get("source_url")
            .map(PathBuf::from)
            .ok_or(Error::ParseRestoreSourceUrlMissing)?;
        let prefault = parser
            .convert::<Toggle>("prefault")
            .map_err(Error::ParseRestore)?
            .unwrap_or(Toggle(false))
            .0;
        let dirty_log = parser
            .convert::<Toggle>("dirty_log")
            .map_err(Error::ParseRestore)?
            .unwrap_or(Toggle(false))
            .0;

        let memory_vol_url = parser.get("memory_vol_url");

        Ok(RestoreConfig {
            source_url,
            prefault,
            disks: None,
            net: None,
            fs: None,
            vsock: None,
            pmem: None,
            dirty_log,
            memory_vol_url,
        })
    }
}

impl TpmConfig {
    pub const SYNTAX: &'static str = "TPM device \
        \"(UNIX Domain Socket from swtpm) socket=</path/to/a/socket>\"";
    pub fn parse(tpm: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser.add("socket");
        parser.parse(tpm).map_err(Error::ParseTpm)?;
        let socket = parser
            .get("socket")
            .map(PathBuf::from)
            .ok_or(Error::ParseTpmPathMissing)?;
        Ok(TpmConfig { socket })
    }
}

/// Deployment roots for host-path validation (--sandswap-allowed-root,
/// repeatable). Empty = no restriction (upstream/dev usage); the Sandswap
/// launcher always sets them, so a compromised sandlot cannot point the VMM at
/// arbitrary host files (kernel/initramfs/serial/console/fs/zone/device paths).
static ALLOWED_PATH_ROOTS: OnceLock<Vec<PathBuf>> = OnceLock::new();

/// set_allowed_path_roots installs the deployment roots once at startup.
pub fn set_allowed_path_roots(roots: Vec<PathBuf>) {
    let _ = ALLOWED_PATH_ROOTS.set(roots);
}

fn normalize_host_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// host_path_allowed reports whether p lives under one of the deployment
/// roots. Both the lexical form and the canonical form are checked, so a
/// symlink inside an allowed root cannot redirect to a path outside it.
fn host_path_allowed(p: &Path) -> bool {
    let roots = match ALLOWED_PATH_ROOTS.get() {
        Some(r) if !r.is_empty() => r,
        _ => return true,
    };
    let pn = normalize_host_path(p);
    let pcheck = std::fs::canonicalize(p).unwrap_or_else(|_| pn.clone());
    roots.iter().any(|r| {
        let rn = normalize_host_path(r);
        let rcheck = std::fs::canonicalize(r).unwrap_or_else(|_| rn.clone());
        pn == rn || pn.starts_with(&rn) || pcheck == rcheck || pcheck.starts_with(&rcheck)
    })
}

fn require_allowed_host_path(what: &'static str, p: &Path) -> ValidationResult<()> {
    if !p.is_absolute() || !host_path_allowed(p) {
        return Err(ValidationError::HostPathNotAllowed(what, p.to_path_buf()));
    }
    Ok(())
}

impl VmConfig {
    fn validate_identifier(
        id_list: &mut BTreeSet<String>,
        id: &Option<String>,
    ) -> ValidationResult<()> {
        if let Some(id) = id.as_ref() {
            if id.starts_with("__") {
                return Err(ValidationError::InvalidIdentifier(id.clone()));
            }

            if !id_list.insert(id.clone()) {
                return Err(ValidationError::IdentifierNotUnique(id.clone()));
            }
        }

        Ok(())
    }

    pub fn backed_by_shared_memory(&self) -> bool {
        if self.memory.shared || self.memory.hugepages {
            return true;
        }

        if self.memory.size == 0 {
            for zone in self.memory.zones.as_ref().unwrap() {
                if !zone.shared && !zone.hugepages {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    pub fn update_disks(&mut self, disk_cfgs: &Vec<DiskConfig>) {
        if let Some(disks) = &mut self.disks {
            let mut devices: HashMap<String, PathBuf> = HashMap::default();
            let mut rate_limiter: HashMap<String, RateLimiterConfig> = HashMap::default();
            for disk_cfg in disk_cfgs.iter() {
                if disk_cfg.id.is_none() {
                    continue;
                }
                if disk_cfg.path.is_some() {
                    devices.insert(
                        disk_cfg.id.as_ref().unwrap().clone(),
                        disk_cfg.path.as_ref().unwrap().clone(),
                    );
                }
                if disk_cfg.rate_limiter_config.is_some() {
                    rate_limiter.insert(
                        disk_cfg.id.as_ref().unwrap().clone(),
                        disk_cfg.rate_limiter_config.as_ref().unwrap().clone(),
                    );
                }
            }

            for disk in disks.iter_mut() {
                if let Some(id) = &disk.id {
                    if let Some(path) = devices.get(&id.clone()) {
                        disk.path = Some(PathBuf::from(path));
                    }
                    if let Some(rate_limit) = rate_limiter.get(&id.clone()) {
                        disk.rate_limiter_config = Some(*rate_limit);
                    }
                }
            }
        }
    }

    pub fn update_nets(&mut self, net_cfgs: &Vec<NetConfig>) {
        if let Some(nets) = &mut self.net {
            let mut devices: HashMap<String, String> = HashMap::default();
            let mut rate_limiter: HashMap<String, RateLimiterConfig> = HashMap::default();
            for net_cfg in net_cfgs.iter() {
                if net_cfg.id.is_none() {
                    continue;
                }
                if net_cfg.tap.is_some() {
                    devices.insert(
                        net_cfg.id.as_ref().unwrap().clone(),
                        net_cfg.tap.as_ref().unwrap().clone(),
                    );
                }
                if net_cfg.rate_limiter_config.is_some() {
                    rate_limiter.insert(
                        net_cfg.id.as_ref().unwrap().clone(),
                        net_cfg.rate_limiter_config.as_ref().unwrap().clone(),
                    );
                }
            }

            for net in nets.iter_mut() {
                if let Some(id) = &net.id {
                    if let Some(tap) = devices.get(&id.clone()) {
                        net.tap = Some(tap.clone());
                    }
                    if let Some(rate_limit) = rate_limiter.get(&id.clone()) {
                        net.rate_limiter_config = Some(*rate_limit);
                    }
                }
            }
        }
    }

    /// Validate a vm.set-fs request against the stored config WITHOUT
    /// applying it. vm.set-fs updates ONLY the virtio-fs `allowed_dirs`
    /// whitelist — everything else about the live device is fixed at
    /// activation, so a request that disagrees with the stored device is
    /// rejected here instead of being silently accepted-but-ignored.
    ///
    /// Omitted JSON fields deserialize to serde defaults; those defaults
    /// are tolerated as "not specified": an empty `shared_dir` and the
    /// default cache policy never count as a change attempt. `allowed_dirs`
    /// defaults to the EMPTY allow-list (fail-closed), so an omitted field
    /// means "clear", never "disable the filter" — and an explicit `null`
    /// is normalized to the same empty list when applied.
    pub fn validate_fs_update(&self, fs_cfg: &FsConfig) -> ValidationResult<()> {
        let id = fs_cfg.id.as_ref().ok_or_else(|| {
            ValidationError::InvalidFsUpdate("vm.set-fs: missing fs id".to_owned())
        })?;
        let new_backend = fs_cfg.backendfs_config.as_ref().ok_or_else(|| {
            ValidationError::InvalidFsUpdate("vm.set-fs: missing backendfs_config".to_owned())
        })?;

        let fses = self.fs.as_ref().ok_or_else(|| {
            ValidationError::InvalidFsUpdate("vm.set-fs: VM has no fs devices".to_owned())
        })?;
        let fs = fses
            .iter()
            .find(|fs| fs.id.as_ref() == Some(id))
            .ok_or_else(|| {
                ValidationError::InvalidFsUpdate(format!(
                    "vm.set-fs: unknown fs device id {:?}",
                    id
                ))
            })?;

        // The guest mounts by tag and the live device keeps its original
        // tag; retagging is not a supported operation.
        if fs_cfg.tag != fs.tag {
            return Err(ValidationError::InvalidFsUpdate(format!(
                "vm.set-fs: tag {:?} does not match device tag {:?}",
                fs_cfg.tag, fs.tag
            )));
        }

        let backend = fs.backendfs_config.as_ref().ok_or_else(|| {
            ValidationError::InvalidFsUpdate(format!(
                "vm.set-fs: stored fs device {:?} has no backendfs_config",
                id
            ))
        })?;

        // The passthrough root is opened at device activation and cannot
        // move; empty means the request omitted the field.
        if !new_backend.shared_dir.is_empty() && new_backend.shared_dir != backend.shared_dir {
            return Err(ValidationError::InvalidFsUpdate(format!(
                "vm.set-fs: shared_dir is immutable (got {:?}, live device uses {:?})",
                new_backend.shared_dir, backend.shared_dir
            )));
        }

        // Cache policy is baked into the live PassthroughFs at activation;
        // only a non-default value differing from the live one is a change
        // attempt.
        if new_backend.cache != backend.cache && new_backend.cache != default_fsconfig_cache() {
            return Err(ValidationError::InvalidFsUpdate(format!(
                "vm.set-fs: cache policy is immutable (got {}, live device uses {})",
                new_backend.cache, backend.cache
            )));
        }

        // Containment of the allow-list under the VM's share (structural, not
        // lexical). The rules and the reasons live in
        // `validate_allowed_dirs_containment`: absolute-only, no `..`
        // components, and a NOFOLLOW component walk beneath an fd of the
        // stored share root — the previous lexical prefix check accepted
        // `/vol/agent-a/../../etc`, which the filter's
        // openat(O_PATH|O_NOFOLLOW) then resolved out of the share.
        if let Some(dirs) = &new_backend.allowed_dirs {
            validate_allowed_dirs_containment(&backend.shared_dir, dirs, "vm.set-fs: ")
                .map_err(ValidationError::InvalidFsUpdate)?;
        }
        // The alias is the generation's capability name: required for a
        // non-empty export, forbidden on a clear, never a replayed previous
        // generation (the live filter enforces the same rules under its
        // lock; this check makes the failure surface before the device).
        validate_export_alias_pair(new_backend, "vm.set-fs: ")
            .map_err(ValidationError::InvalidFsUpdate)?;
        if new_backend
            .allowed_dirs
            .as_ref()
            .is_some_and(|d| !d.is_empty())
            && new_backend.alias == backend.alias
        {
            return Err(ValidationError::InvalidFsUpdate(format!(
                "vm.set-fs: export alias {:?} was already used by the previous generation",
                new_backend.alias
            )));
        }

        Ok(())
    }

    /// Apply the `allowed_dirs` whitelist from a validated vm.set-fs request
    /// to the stored config. Callers must run `validate_fs_update` (or this
    /// function, which revalidates) BEFORE updating the live device, and
    /// only call this after the device accepted the update, so a failure
    /// anywhere leaves both the config and the runtime untouched.
    pub fn update_fs_allowed_dirs(&mut self, fs_cfg: &FsConfig) -> ValidationResult<()> {
        self.validate_fs_update(fs_cfg)?;

        let id = fs_cfg.id.as_ref().expect("validated above");
        let fses = self.fs.as_mut().expect("validated above");
        let fs = fses
            .iter_mut()
            .find(|fs| fs.id.as_ref() == Some(id))
            .expect("validated above");
        let backend = fs.backendfs_config.as_mut().expect("validated above");
        // Normalize to Some(...): the stored config must always name the
        // allow-list the live filter will run. A `None` here (an explicit
        // JSON `null`, the only remaining way to reach it) means the EMPTY
        // list — deny all — never "filter off".
        let new_backend = fs_cfg
            .backendfs_config
            .as_ref()
            .expect("validated above");
        let dirs = new_backend.allowed_dirs.clone().unwrap_or_default();
        if !dirs.is_empty() {
            backend.alias = new_backend.alias.clone();
        }
        backend.allowed_dirs = Some(dirs);

        Ok(())
    }

    pub fn update_vsock(&mut self, vsock_cfg: &VsockConfig) {
        if let Some(vsock) = &mut self.vsock {
            if vsock.id.is_none() {
                return;
            }
            if vsock_cfg.id.is_none() {
                return;
            }
            vsock.cid = vsock_cfg.cid;
            vsock.iommu = vsock_cfg.iommu;
            vsock.pci_segment = vsock_cfg.pci_segment;
        }
    }

    pub fn update_pmem(&mut self, pmem_cfgs: &[PmemConfig]) {
        if let Some(pmems) = &mut self.pmem {
            let mut new_cfgs: HashMap<String, PathBuf> = HashMap::default();

            for cfg in pmem_cfgs.iter() {
                if let Some(id) = &cfg.id {
                    new_cfgs.insert(id.to_string(), cfg.file.clone());
                }
            }

            for pmem in pmems.iter_mut() {
                if let Some(id) = &pmem.id {
                    if let Some(file) = new_cfgs.get(&id.clone()) {
                        pmem.file = file.to_path_buf();
                    }
                }
            }
        }
    }

    // Also enables virtio-iommu if the config needs it
    // Returns the list of unique identifiers provided through the
    // configuration.
    pub fn validate(&mut self) -> ValidationResult<BTreeSet<String>> {
        let mut id_list = BTreeSet::new();

        self.payload
            .as_ref()
            .ok_or(ValidationError::KernelMissing)?;

        // Host-path whitelist: every path the VMM will open/create must live
        // under a deployment root (set by the launcher). See ALLOWED_PATH_ROOTS.
        if let Some(payload) = &self.payload {
            if let Some(p) = &payload.firmware {
                require_allowed_host_path("payload.firmware", p)?;
            }
            if let Some(p) = &payload.kernel {
                require_allowed_host_path("payload.kernel", p)?;
            }
            if let Some(p) = &payload.initramfs {
                require_allowed_host_path("payload.initramfs", p)?;
            }
        }
        if let Some(p) = &self.serial.file {
            require_allowed_host_path("serial.file", p)?;
        }
        if let Some(p) = &self.console.file {
            require_allowed_host_path("console.file", p)?;
        }
        // The virtio-rng source is a HOST DEVICE NODE, not a deployment
        // file: the two canonical entropy devices are always acceptable; any
        // other path must still sit under an allowed root.
        if self.rng.src != Path::new("/dev/urandom") && self.rng.src != Path::new("/dev/random") {
            require_allowed_host_path("rng.src", &self.rng.src)?;
        }
        if let Some(memory_zones) = &self.memory.zones {
            for zone in memory_zones {
                if let Some(p) = &zone.file {
                    require_allowed_host_path("memory.zones.file", p)?;
                }
            }
        }
        if let Some(disks) = &self.disks {
            for disk in disks {
                if let Some(p) = &disk.path {
                    require_allowed_host_path("disk.path", p)?;
                }
                if let Some(p) = &disk.vhost_socket {
                    require_allowed_host_path("disk.vhost_socket", Path::new(p))?;
                }
            }
        }
        if let Some(devices) = &self.devices {
            for dev in devices {
                require_allowed_host_path("devices.path", &dev.path)?;
            }
        }
        if let Some(fses) = &self.fs {
            for fs in fses {
                if let Some(backend) = &fs.backendfs_config {
                    require_allowed_host_path("fs.shared_dir", Path::new(&backend.shared_dir))?;
                }
                if !fs.socket.as_os_str().is_empty() {
                    require_allowed_host_path("fs.socket", &fs.socket)?;
                }
            }
        }

        #[cfg(feature = "tdx")]
        {
            let tdx_enabled = self.platform.as_ref().map(|p| p.tdx).unwrap_or(false);
            // At this point we know payload isn't None.
            if tdx_enabled && self.payload.as_ref().unwrap().firmware.is_none() {
                return Err(ValidationError::TdxFirmwareMissing);
            }
            if tdx_enabled && (self.cpus.max_vcpus != self.cpus.boot_vcpus) {
                return Err(ValidationError::TdxNoCpuHotplug);
            }
        }

        // The 'conflict' check is introduced in commit 24438e0390d3
        // (vm-virtio: Enable the vmm support for virtio-console).
        //
        // Allow simultaneously set serial and console as TTY mode, for
        // someone want to use virtio console for better performance, and
        // want to keep legacy serial to catch boot stage logs for debug.
        // Using such double tty mode, you need to configure the kernel
        // properly, such as:
        // "console=hvc0 earlyprintk=ttyS0"
        if self.console.mode == ConsoleOutputMode::Tty && self.serial.mode == ConsoleOutputMode::Tty
        {
            warn!("Using TTY output for both virtio-console and serial port");
        }

        if self.console.mode == ConsoleOutputMode::File && self.console.file.is_none() {
            return Err(ValidationError::ConsoleFileMissing);
        }

        if self.serial.mode == ConsoleOutputMode::File && self.serial.file.is_none() {
            return Err(ValidationError::ConsoleFileMissing);
        }

        if self.cpus.max_vcpus < self.cpus.boot_vcpus {
            return Err(ValidationError::CpusMaxLowerThanBoot);
        }

        // x86_64 KVM accepts a physical address width of 32..=52 bits. A value
        // outside that range must fail at configuration validation instead of
        // reaching the address-space arithmetic.
        if !(32..=52).contains(&self.cpus.max_phys_bits) {
            return Err(ValidationError::InvalidMaxPhysBits(self.cpus.max_phys_bits));
        }

        if let Some(disks) = &self.disks {
            for disk in disks {
                if disk.vhost_socket.as_ref().and(disk.path.as_ref()).is_some() {
                    return Err(ValidationError::DiskSocketAndPath);
                }
                if disk.vhost_user && !self.backed_by_shared_memory() {
                    return Err(ValidationError::VhostUserRequiresSharedMemory);
                }
                if disk.vhost_user && disk.vhost_socket.is_none() {
                    return Err(ValidationError::VhostUserMissingSocket);
                }
                disk.validate(self)?;
                self.iommu |= disk.iommu;

                Self::validate_identifier(&mut id_list, &disk.id)?;
            }
        }

        if let Some(nets) = &self.net {
            for net in nets {
                if net.vhost_user && !self.backed_by_shared_memory() {
                    return Err(ValidationError::VhostUserRequiresSharedMemory);
                }
                net.validate(self)?;
                self.iommu |= net.iommu;

                Self::validate_identifier(&mut id_list, &net.id)?;
            }
        }

        if let Some(fses) = &self.fs {
            // Modified by Sandswap (c) 2026 — THE single-share invariant.
            //
            // Sandswap's isolation boundary is stated over ONE virtio-fs
            // device per VM: the host volumes directory is shared once, and
            // which agent directory is reachable through that share is decided
            // exclusively by `vm.set-fs`'s allowed_dirs whitelist on that
            // device. A second fs device would be a second window into the
            // host filesystem with its own whitelist — outside the invariant,
            // and reachable neither by `vm.set-fs` (it matches by the single
            // device id `vfs-rootfs`) nor by any Sandswap component, but
            // visible to the guest if it were ever mounted.
            //
            // So the count is capped here, at the one place every create path
            // funnels through (CLI, `vm.create`, and any future caller), which
            // is also what keeps the removed `vm.add-fs` endpoint from being
            // reintroduced by accident: the config layer would refuse the
            // second device even if a route existed.
            if fses.len() > 1 {
                return Err(ValidationError::TooManyFsDevices);
            }
            for fs in fses {
                fs.validate(self)?;

                Self::validate_identifier(&mut id_list, &fs.id)?;
            }
        }

        if let Some(pmems) = &self.pmem {
            for pmem in pmems {
                pmem.validate(self)?;
                self.iommu |= pmem.iommu;

                Self::validate_identifier(&mut id_list, &pmem.id)?;
            }
        }

        self.iommu |= self.rng.iommu;
        self.iommu |= self.console.iommu;

        if let Some(t) = &self.cpus.topology {
            if t.threads_per_core == 0
                || t.cores_per_die == 0
                || t.dies_per_package == 0
                || t.packages == 0
            {
                return Err(ValidationError::CpuTopologyZeroPart);
            }

            // The setting of dies doesen't apply on AArch64.
            // Only '1' value is accepted, so its impact on the vcpu topology
            // setting can be ignored.
            #[cfg(target_arch = "aarch64")]
            if t.dies_per_package != 1 {
                return Err(ValidationError::CpuTopologyDiesPerPackage);
            }

            let total = t.threads_per_core * t.cores_per_die * t.dies_per_package * t.packages;
            if total != self.cpus.max_vcpus {
                return Err(ValidationError::CpuTopologyCount);
            }
        }

        if let Some(hugepage_size) = &self.memory.hugepage_size {
            if !self.memory.hugepages {
                return Err(ValidationError::HugePageSizeWithoutHugePages);
            }
            if !hugepage_size.is_power_of_two() {
                return Err(ValidationError::InvalidHugePageSize(*hugepage_size));
            }
        }

        if let Some(user_devices) = &self.user_devices {
            if !user_devices.is_empty() && !self.backed_by_shared_memory() {
                return Err(ValidationError::UserDevicesRequireSharedMemory);
            }

            for user_device in user_devices {
                user_device.validate(self)?;

                Self::validate_identifier(&mut id_list, &user_device.id)?;
            }
        }

        if let Some(vdpa_devices) = &self.vdpa {
            for vdpa_device in vdpa_devices {
                vdpa_device.validate(self)?;
                self.iommu |= vdpa_device.iommu;

                Self::validate_identifier(&mut id_list, &vdpa_device.id)?;
            }
        }

        if let Some(balloon) = &self.balloon {
            let mut ram_size = self.memory.size;

            if let Some(zones) = &self.memory.zones {
                for zone in zones {
                    ram_size += zone.size;
                }
            }

            if balloon.size >= ram_size {
                return Err(ValidationError::BalloonLargerThanRam(
                    balloon.size,
                    ram_size,
                ));
            }
        }

        if let Some(devices) = &self.devices {
            let mut device_paths = BTreeSet::new();
            for device in devices {
                if !device_paths.insert(device.path.to_string_lossy()) {
                    return Err(ValidationError::DuplicateDevicePath(
                        device.path.to_string_lossy().to_string(),
                    ));
                }

                device.validate(self)?;
                self.iommu |= device.iommu;

                Self::validate_identifier(&mut id_list, &device.id)?;
            }
        }

        if let Some(vsock) = &self.vsock {
            vsock.validate(self)?;
            self.iommu |= vsock.iommu;

            Self::validate_identifier(&mut id_list, &vsock.id)?;
        }

        if let Some(numa) = &self.numa {
            let mut used_numa_node_memory_zones = HashMap::new();
            for numa_node in numa.iter() {
                for memory_zone in numa_node.memory_zones.clone().unwrap().iter() {
                    if !used_numa_node_memory_zones.contains_key(memory_zone) {
                        used_numa_node_memory_zones
                            .insert(memory_zone.to_string(), numa_node.guest_numa_id);
                    } else {
                        return Err(ValidationError::MemoryZoneReused(
                            memory_zone.to_string(),
                            *used_numa_node_memory_zones.get(memory_zone).unwrap(),
                            numa_node.guest_numa_id,
                        ));
                    }
                }
            }
        }

        if let Some(zones) = &self.memory.zones {
            for zone in zones.iter() {
                let id = zone.id.clone();
                Self::validate_identifier(&mut id_list, &Some(id))?;
            }
        }

        #[cfg(target_arch = "x86_64")]
        if let Some(sgx_epcs) = &self.sgx_epc {
            for sgx_epc in sgx_epcs.iter() {
                let id = sgx_epc.id.clone();
                Self::validate_identifier(&mut id_list, &Some(id))?;
            }
        }

        self.platform.as_ref().map(|p| p.validate()).transpose()?;
        self.iommu |= self
            .platform
            .as_ref()
            .map(|p| p.iommu_segments.is_some())
            .unwrap_or_default();

        Ok(id_list)
    }

    pub fn parse(vm_params: VmParams) -> Result<Self> {
        let mut disks: Option<Vec<DiskConfig>> = None;
        if let Some(disk_list) = &vm_params.disks {
            let mut disk_config_list = Vec::new();
            for item in disk_list.iter() {
                let disk_config = DiskConfig::parse(item)?;
                disk_config_list.push(disk_config);
            }
            disks = Some(disk_config_list);
        }

        let mut net: Option<Vec<NetConfig>> = None;
        if let Some(net_list) = &vm_params.net {
            let mut net_config_list = Vec::new();
            for item in net_list.iter() {
                let net_config = NetConfig::parse(item)?;
                net_config_list.push(net_config);
            }
            net = Some(net_config_list);
        }

        let rng = RngConfig::parse(vm_params.rng)?;

        let mut balloon: Option<BalloonConfig> = None;
        if let Some(balloon_params) = &vm_params.balloon {
            balloon = Some(BalloonConfig::parse(balloon_params)?);
        }

        let mut fs: Option<Vec<FsConfig>> = None;
        if let Some(fs_list) = &vm_params.fs {
            let mut fs_config_list = Vec::new();
            for item in fs_list.iter() {
                fs_config_list.push(FsConfig::parse(item)?);
            }
            fs = Some(fs_config_list);
        }

        let mut pmem: Option<Vec<PmemConfig>> = None;
        if let Some(pmem_list) = &vm_params.pmem {
            let mut pmem_config_list = Vec::new();
            for item in pmem_list.iter() {
                let pmem_config = PmemConfig::parse(item)?;
                pmem_config_list.push(pmem_config);
            }
            pmem = Some(pmem_config_list);
        }

        let console = ConsoleConfig::parse(vm_params.console)?;
        let serial = ConsoleConfig::parse(vm_params.serial)?;

        let mut devices: Option<Vec<DeviceConfig>> = None;
        if let Some(device_list) = &vm_params.devices {
            let mut device_config_list = Vec::new();
            for item in device_list.iter() {
                let device_config = DeviceConfig::parse(item)?;
                device_config_list.push(device_config);
            }
            devices = Some(device_config_list);
        }

        let mut user_devices: Option<Vec<UserDeviceConfig>> = None;
        if let Some(user_device_list) = &vm_params.user_devices {
            let mut user_device_config_list = Vec::new();
            for item in user_device_list.iter() {
                let user_device_config = UserDeviceConfig::parse(item)?;
                user_device_config_list.push(user_device_config);
            }
            user_devices = Some(user_device_config_list);
        }

        let mut vdpa: Option<Vec<VdpaConfig>> = None;
        if let Some(vdpa_list) = &vm_params.vdpa {
            let mut vdpa_config_list = Vec::new();
            for item in vdpa_list.iter() {
                let vdpa_config = VdpaConfig::parse(item)?;
                vdpa_config_list.push(vdpa_config);
            }
            vdpa = Some(vdpa_config_list);
        }

        let mut vsock: Option<VsockConfig> = None;
        if let Some(vs) = &vm_params.vsock {
            let vsock_config = VsockConfig::parse(vs)?;
            vsock = Some(vsock_config);
        }

        let platform = vm_params.platform.map(PlatformConfig::parse).transpose()?;

        #[cfg(target_arch = "x86_64")]
        let mut sgx_epc: Option<Vec<SgxEpcConfig>> = None;
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(sgx_epc_list) = &vm_params.sgx_epc {
                let mut sgx_epc_config_list = Vec::new();
                for item in sgx_epc_list.iter() {
                    let sgx_epc_config = SgxEpcConfig::parse(item)?;
                    sgx_epc_config_list.push(sgx_epc_config);
                }
                sgx_epc = Some(sgx_epc_config_list);
            }
        }

        let mut numa: Option<Vec<NumaConfig>> = None;
        if let Some(numa_list) = &vm_params.numa {
            let mut numa_config_list = Vec::new();
            for item in numa_list.iter() {
                let numa_config = NumaConfig::parse(item)?;
                numa_config_list.push(numa_config);
            }
            numa = Some(numa_config_list);
        }

        let payload = if vm_params.kernel.is_some() || vm_params.firmware.is_some() {
            Some(PayloadConfig {
                kernel: vm_params.kernel.map(PathBuf::from),
                initramfs: vm_params.initramfs.map(PathBuf::from),
                cmdline: vm_params.cmdline.map(|s| s.to_string()),
                firmware: vm_params.firmware.map(PathBuf::from),
            })
        } else {
            None
        };

        let mut tpm: Option<TpmConfig> = None;
        if let Some(tc) = vm_params.tpm {
            let tpm_conf = TpmConfig::parse(tc)?;
            tpm = Some(TpmConfig {
                socket: tpm_conf.socket,
            });
        }

        #[cfg(feature = "guest_debug")]
        let gdb = vm_params.gdb;

        let mut config = VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory, vm_params.memory_zones)?,
            payload,
            disks,
            net,
            rng,
            balloon,
            fs,
            pmem,
            serial,
            console,
            devices,
            user_devices,
            vdpa,
            vsock,
            iommu: false, // updated in VmConfig::validate()
            #[cfg(target_arch = "x86_64")]
            sgx_epc,
            numa,
            watchdog: vm_params.watchdog,
            #[cfg(feature = "guest_debug")]
            gdb,
            platform,
            tpm,
        };
        config.validate().map_err(Error::Validation)?;
        Ok(config)
    }

    #[cfg(feature = "tdx")]
    pub fn is_tdx_enabled(&self) -> bool {
        self.platform.as_ref().map(|p| p.tdx).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_util::MacAddr;

    #[test]
    fn test_cpu_parsing() -> Result<()> {
        assert_eq!(CpusConfig::parse("")?, CpusConfig::default());

        assert_eq!(
            CpusConfig::parse("boot=1")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=1,max=2")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 2,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=8,topology=2:2:1:2")?,
            CpusConfig {
                boot_vcpus: 8,
                max_vcpus: 8,
                topology: Some(CpuTopology {
                    threads_per_core: 2,
                    cores_per_die: 2,
                    dies_per_package: 1,
                    packages: 2
                }),
                ..Default::default()
            }
        );

        assert!(CpusConfig::parse("boot=8,topology=2:2:1").is_err());
        assert!(CpusConfig::parse("boot=8,topology=2:2:1:x").is_err());
        assert_eq!(
            CpusConfig::parse("boot=1,kvm_hyperv=on")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                kvm_hyperv: true,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=2,affinity=[0@[0,2],1@[1,3]]")?,
            CpusConfig {
                boot_vcpus: 2,
                max_vcpus: 2,
                affinity: Some(vec![
                    CpuAffinity {
                        vcpu: 0,
                        host_cpus: vec![0, 2],
                    },
                    CpuAffinity {
                        vcpu: 1,
                        host_cpus: vec![1, 3],
                    }
                ]),
                ..Default::default()
            },
        );

        Ok(())
    }

    #[test]
    fn test_mem_parsing() -> Result<()> {
        assert_eq!(MemoryConfig::parse("", None)?, MemoryConfig::default());
        // Default string
        assert_eq!(
            MemoryConfig::parse("size=512M", None)?,
            MemoryConfig::default()
        );
        assert_eq!(
            MemoryConfig::parse("size=512M,mergeable=on", None)?,
            MemoryConfig {
                size: 512 << 20,
                mergeable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("mergeable=on", None)?,
            MemoryConfig {
                mergeable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("size=1G,mergeable=off", None)?,
            MemoryConfig {
                size: 1 << 30,
                mergeable: false,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=acpi", None)?,
            MemoryConfig {
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=acpi,hotplug_size=512M", None)?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hotplug_method=virtio-mem,hotplug_size=512M", None)?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                hotplug_method: HotplugMethod::VirtioMem,
                ..Default::default()
            }
        );
        assert_eq!(
            MemoryConfig::parse("hugepages=on,size=1G,hugepage_size=2M", None)?,
            MemoryConfig {
                hugepage_size: Some(2 << 20),
                size: 1 << 30,
                hugepages: true,
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_disk_parsing() -> Result<()> {
        assert_eq!(
            DiskConfig::parse("path=/path/to_file")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,id=mydisk0")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                id: Some("mydisk0".to_owned()),
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("vhost_user=true,socket=/tmp/sock")?,
            DiskConfig {
                vhost_socket: Some(String::from("/tmp/sock")),
                vhost_user: true,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                iommu: true,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on,queue_size=256")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                iommu: true,
                queue_size: 256,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,iommu=on,queue_size=256,num_queues=4")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                iommu: true,
                queue_size: 256,
                num_queues: 4,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file,direct=on")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                direct: true,
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                ..Default::default()
            }
        );
        assert_eq!(
            DiskConfig::parse("path=/path/to_file")?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_net_parsing() -> Result<()> {
        // mac address is random
        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,id=mynet0")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                id: Some("mynet0".to_owned()),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,tap=tap0,ip=192.168.100.1,mask=255.255.255.128"
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                tap: Some("tap0".to_owned()),
                ip: "192.168.100.1".parse().unwrap(),
                mask: "255.255.255.128".parse().unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse(
                "mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,vhost_user=true,socket=/tmp/sock"
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                vhost_user: true,
                vhost_socket: Some("/tmp/sock".to_owned()),
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,host_mac=12:34:de:ad:be:ef,num_queues=4,queue_size=1024,iommu=on")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                num_queues: 4,
                queue_size: 1024,
                iommu: true,
                ..Default::default()
            }
        );

        assert_eq!(
            NetConfig::parse("mac=de:ad:be:ef:12:34,fd=[3,7],num_queues=4")?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                fds: Some(vec![3, 7]),
                num_queues: 4,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_parse_rng() -> Result<()> {
        assert_eq!(RngConfig::parse("")?, RngConfig::default());
        assert_eq!(
            RngConfig::parse("src=/dev/random")?,
            RngConfig {
                src: PathBuf::from("/dev/random"),
                ..Default::default()
            }
        );
        assert_eq!(
            RngConfig::parse("src=/dev/random,iommu=on")?,
            RngConfig {
                src: PathBuf::from("/dev/random"),
                iommu: true,
            }
        );
        assert_eq!(
            RngConfig::parse("iommu=on")?,
            RngConfig {
                iommu: true,
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_fs() -> Result<()> {
        // "tag" and "socket" must be supplied
        assert!(FsConfig::parse("").is_err());
        assert!(FsConfig::parse("tag=mytag").is_err());
        assert!(FsConfig::parse("socket=/tmp/sock").is_err());
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock")?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                ..Default::default()
            }
        );
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock")?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                ..Default::default()
            }
        );
        assert_eq!(
            FsConfig::parse("tag=mytag,socket=/tmp/sock,num_queues=4,queue_size=1024")?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                num_queues: 4,
                queue_size: 1024,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_pmem_parsing() -> Result<()> {
        // Must always give a file and size
        assert!(PmemConfig::parse("").is_err());
        assert!(PmemConfig::parse("size=128M").is_err());
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M")?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
                ..Default::default()
            }
        );
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M,id=mypmem0")?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
                id: Some("mypmem0".to_owned()),
                ..Default::default()
            }
        );
        assert_eq!(
            PmemConfig::parse("file=/tmp/pmem,size=128M,iommu=on,discard_writes=on")?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
                discard_writes: true,
                iommu: true,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_console_parsing() -> Result<()> {
        assert!(ConsoleConfig::parse("").is_err());
        assert!(ConsoleConfig::parse("badmode").is_err());
        assert_eq!(
            ConsoleConfig::parse("off")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Off,
                iommu: false,
                sigwinch: false,
                file: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("pty")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Pty,
                iommu: false,
                sigwinch: false,
                file: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("tty")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                sigwinch: false,
                file: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("null")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Null,
                iommu: false,
                sigwinch: false,
                file: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("file=/tmp/console")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::File,
                iommu: false,
                sigwinch: false,
                file: Some(PathBuf::from("/tmp/console"))
            }
        );
        assert_eq!(
            ConsoleConfig::parse("null,iommu=on")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Null,
                iommu: true,
                sigwinch: false,
                file: None,
            }
        );
        assert_eq!(
            ConsoleConfig::parse("file=/tmp/console,iommu=on")?,
            ConsoleConfig {
                mode: ConsoleOutputMode::File,
                iommu: true,
                sigwinch: false,
                file: Some(PathBuf::from("/tmp/console"))
            }
        );
        Ok(())
    }

    #[test]
    fn test_device_parsing() -> Result<()> {
        // Device must have a path provided
        assert!(DeviceConfig::parse("").is_err());
        assert_eq!(
            DeviceConfig::parse("path=/path/to/device")?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: None,
                iommu: false,
                ..Default::default()
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on")?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: None,
                iommu: true,
                ..Default::default()
            }
        );

        assert_eq!(
            DeviceConfig::parse("path=/path/to/device,iommu=on,id=mydevice0")?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: Some("mydevice0".to_owned()),
                iommu: true,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_vdpa_parsing() -> Result<()> {
        // path is required
        assert!(VdpaConfig::parse("").is_err());
        assert_eq!(
            VdpaConfig::parse("path=/dev/vhost-vdpa")?,
            VdpaConfig {
                path: PathBuf::from("/dev/vhost-vdpa"),
                num_queues: 1,
                id: None,
                ..Default::default()
            }
        );
        assert_eq!(
            VdpaConfig::parse("path=/dev/vhost-vdpa,num_queues=2,id=my_vdpa")?,
            VdpaConfig {
                path: PathBuf::from("/dev/vhost-vdpa"),
                num_queues: 2,
                id: Some("my_vdpa".to_owned()),
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_tpm_parsing() -> Result<()> {
        // path is required
        assert!(TpmConfig::parse("").is_err());
        assert_eq!(
            TpmConfig::parse("socket=/var/run/tpm.sock")?,
            TpmConfig {
                socket: PathBuf::from("/var/run/tpm.sock"),
            }
        );
        Ok(())
    }

    #[test]
    fn test_vsock_parsing() -> Result<()> {
        // cid is required; the legacy `socket` key (unix muxer backend) is gone
        assert!(VsockConfig::parse("").is_err());
        assert!(VsockConfig::parse("socket=/tmp/sock,cid=1").is_err());
        assert_eq!(
            VsockConfig::parse("cid=1")?,
            VsockConfig {
                cid: 1,
                iommu: false,
                id: None,
                ..Default::default()
            }
        );
        assert_eq!(
            VsockConfig::parse("cid=1,iommu=on")?,
            VsockConfig {
                cid: 1,
                iommu: true,
                id: None,
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_config_validation() {
        let mut valid_config = VmConfig {
            cpus: CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                ..Default::default()
            },
            memory: MemoryConfig {
                size: 536_870_912,
                mergeable: false,
                hotplug_method: HotplugMethod::Acpi,
                hotplug_size: None,
                hotplugged_size: None,
                shared: false,
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
                sigwinch: false,
                iommu: false,
            },
            console: ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                sigwinch: false,
                iommu: false,
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
        };

        assert!(valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.serial.mode = ConsoleOutputMode::Tty;
        invalid_config.console.mode = ConsoleOutputMode::Tty;
        assert!(valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.payload = None;
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::KernelMissing)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.serial.mode = ConsoleOutputMode::File;
        invalid_config.serial.file = None;
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::ConsoleFileMissing)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.cpus.max_vcpus = 16;
        invalid_config.cpus.boot_vcpus = 32;
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::CpusMaxLowerThanBoot)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.cpus.max_vcpus = 16;
        invalid_config.cpus.boot_vcpus = 16;
        invalid_config.cpus.topology = Some(CpuTopology {
            threads_per_core: 2,
            cores_per_die: 8,
            dies_per_package: 1,
            packages: 2,
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::CpuTopologyCount)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.disks = Some(vec![DiskConfig {
            vhost_socket: Some("/path/to/sock".to_owned()),
            path: Some(PathBuf::from("/path/to/image")),
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::DiskSocketAndPath)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.shared = true;
        invalid_config.disks = Some(vec![DiskConfig {
            vhost_user: true,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserMissingSocket)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.disks = Some(vec![DiskConfig {
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserRequiresSharedMemory)
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.disks = Some(vec![DiskConfig {
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..Default::default()
        }]);
        still_valid_config.memory.shared = true;
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.net = Some(vec![NetConfig {
            vhost_user: true,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserRequiresSharedMemory)
        );

        // This fork REFUSES vhost-user networking outright (the VMM attaches
        // a host TAP it owns; a caller-supplied socket is a privilege
        // primitive), so the upstream "now valid" shape is still refused.
        let mut still_invalid_config = valid_config.clone();
        still_invalid_config.net = Some(vec![NetConfig {
            vhost_user: true,
            vhost_socket: Some("/path/to/sock".to_owned()),
            ..Default::default()
        }]);
        still_invalid_config.memory.shared = true;
        assert_eq!(
            still_invalid_config.validate(),
            Err(ValidationError::VhostUserNetNotPermitted)
        );

        // Caller-inherited net fds are refused outright in this fork (a
        // dup of an arbitrary inherited fd is a privilege primitive); the
        // reserved-fd check below it is unreachable by design.
        let mut invalid_config = valid_config.clone();
        invalid_config.net = Some(vec![NetConfig {
            fds: Some(vec![0]),
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::NetFdsNotPermitted)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.fs = Some(vec![FsConfig {
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::VhostUserRequiresSharedMemory)
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.memory.shared = true;
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.memory.hugepages = true;
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.memory.hugepages = true;
        still_valid_config.memory.hugepage_size = Some(2 << 20);
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.hugepages = false;
        invalid_config.memory.hugepage_size = Some(2 << 20);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::HugePageSizeWithoutHugePages)
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.hugepages = true;
        invalid_config.memory.hugepage_size = Some(3 << 20);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidHugePageSize(3 << 20))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            ..Default::default()
        });
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 17,
            ..Default::default()
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidNumPciSegments(17))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![17, 18]),
            ..Default::default()
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::InvalidPciSegment(17))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.disks = Some(vec![DiskConfig {
            iommu: true,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.net = Some(vec![NetConfig {
            iommu: true,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.pmem = Some(vec![PmemConfig {
            iommu: true,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.devices = Some(vec![DeviceConfig {
            path: PathBuf::from("/path/to/device"),
            iommu: true,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert!(still_valid_config.validate().is_ok());

        let mut still_valid_config = valid_config.clone();
        still_valid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        still_valid_config.vsock = Some(VsockConfig {
            // cid is incidental to the iommu/segment assertions here, but it
            // must be a LEGAL guest cid: the Default (0) is a reserved id and
            // is refused.
            cid: 3,
            iommu: true,
            pci_segment: 1,
            ..Default::default()
        });
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.disks = Some(vec![DiskConfig {
            iommu: false,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.net = Some(vec![NetConfig {
            iommu: false,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.pmem = Some(vec![PmemConfig {
            iommu: false,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.devices = Some(vec![DeviceConfig {
            path: PathBuf::from("/path/to/device"),
            iommu: false,
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.vsock = Some(VsockConfig {
            iommu: false,
            pci_segment: 1,
            ..Default::default()
        });
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.shared = true;
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.user_devices = Some(vec![UserDeviceConfig {
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::IommuNotSupportedOnSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.vdpa = Some(vec![VdpaConfig {
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::OnIommuSegment(1))
        );

        let mut invalid_config = valid_config.clone();
        invalid_config.memory.shared = true;
        invalid_config.platform = Some(PlatformConfig {
            num_pci_segments: 16,
            iommu_segments: Some(vec![1, 2, 3]),
            ..Default::default()
        });
        invalid_config.fs = Some(vec![FsConfig {
            pci_segment: 1,
            ..Default::default()
        }]);
        assert_eq!(
            invalid_config.validate(),
            Err(ValidationError::IommuNotSupportedOnSegment(1))
        );

        let mut still_valid_config = valid_config.clone();
        still_valid_config.devices = Some(vec![
            DeviceConfig {
                path: "/device1".into(),
                ..Default::default()
            },
            DeviceConfig {
                path: "/device2".into(),
                ..Default::default()
            },
        ]);
        assert!(still_valid_config.validate().is_ok());

        let mut invalid_config = valid_config;
        invalid_config.devices = Some(vec![
            DeviceConfig {
                path: "/device1".into(),
                ..Default::default()
            },
            DeviceConfig {
                path: "/device1".into(),
                ..Default::default()
            },
        ]);
        assert!(invalid_config.validate().is_err());
    }

    fn setfs_vm_config(tag: &str, shared_dir: &str, cache: u8) -> VmConfig {
        serde_json::from_str(&format!(
            r#"{{"fs":[{{"id":"vfs-rootfs","tag":"{}","backendfs_config":{{"shared_dir":"{}","cache":{},"allowed_dirs":[]}}}}]}}"#,
            tag, shared_dir, cache
        ))
        .unwrap()
    }

    fn setfs_request(
        tag: &str,
        shared_dir: &str,
        cache: u8,
        allowed_dirs: Option<Vec<&str>>,
    ) -> FsConfig {
        let (dirs, alias) = match allowed_dirs {
            Some(v) if !v.is_empty() => (format!("{:?}", v), "\"gen0\"".to_string()),
            Some(v) => (format!("{:?}", v), "null".to_string()),
            None => ("null".to_string(), "null".to_string()),
        };
        serde_json::from_str(&format!(
            r#"{{"id":"vfs-rootfs","tag":"{}","backendfs_config":{{"shared_dir":"{}","cache":{},"allowed_dirs":{},"alias":{}}}}}"#,
            tag, shared_dir, cache, dirs, alias
        ))
        .unwrap()
    }

    /// A real on-disk share tree for the containment pins: the
    /// allow-list is now resolved against the share root, so entries must
    /// exist for the walk to validate them — exactly as they do in production
    /// (the prov instance creates the volume dir before any set-fs names it).
    /// Layout: `<tmp>/sandswap-r4u13-<pid>-<tag>/{vol/agent-a,outside}`.
    struct ShareTree {
        base: PathBuf,
    }

    impl ShareTree {
        fn new(tag: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("sandswap-r4u13-{}-{}", std::process::id(), tag));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(base.join("vol/agent-a")).unwrap();
            fs::create_dir_all(base.join("outside")).unwrap();
            ShareTree { base }
        }
        /// The configured share root (shared_dir).
        fn root(&self) -> String {
            self.base.join("vol").to_string_lossy().into_owned()
        }
        /// An absolute path under the fixture base.
        fn path(&self, rel: &str) -> String {
            self.base.join(rel).to_string_lossy().into_owned()
        }
    }

    impl Drop for ShareTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn test_setfs_happy_path_updates_allowed_dirs() {
        let tree = ShareTree::new("happy");
        let root = tree.root();
        let entry = tree.path("vol/agent-a");
        let mut config = setfs_vm_config("sandswap", &root, 2);
        let req = setfs_request("sandswap", &root, 2, Some(vec![entry.as_str()]));

        config.validate_fs_update(&req).unwrap();
        config.update_fs_allowed_dirs(&req).unwrap();

        let fs = config.fs.as_ref().unwrap().first().unwrap();
        assert_eq!(
            fs.backendfs_config.as_ref().unwrap().allowed_dirs,
            Some(vec![entry.clone()])
        );
        // Immutable fields untouched.
        assert_eq!(
            fs.backendfs_config.as_ref().unwrap().shared_dir,
            root.clone()
        );
    }

    #[test]
    fn test_setfs_rejects_missing_fields_and_unknown_device() {
        let config = setfs_vm_config("sandswap", "/vol", 2);

        // Missing id (serde default None).
        let no_id: FsConfig =
            serde_json::from_str(r#"{"tag":"sandswap","backendfs_config":{"allowed_dirs":[]}}"#)
                .unwrap();
        assert!(matches!(
            config.validate_fs_update(&no_id),
            Err(ValidationError::InvalidFsUpdate(_))
        ));

        // Missing backendfs_config.
        let no_backend: FsConfig =
            serde_json::from_str(r#"{"id":"vfs-rootfs","tag":"sandswap"}"#).unwrap();
        assert!(matches!(
            config.validate_fs_update(&no_backend),
            Err(ValidationError::InvalidFsUpdate(_))
        ));

        // Unknown device id.
        let unknown: FsConfig = serde_json::from_str(
            r#"{"id":"no-such-device","tag":"sandswap","backendfs_config":{"allowed_dirs":[]}}"#,
        )
        .unwrap();
        assert!(matches!(
            config.validate_fs_update(&unknown),
            Err(ValidationError::InvalidFsUpdate(_))
        ));
    }

    #[test]
    fn test_setfs_rejects_tag_mismatch() {
        let config = setfs_vm_config("sandswap", "/vol", 2);
        let req = setfs_request("other-tag", "/vol", 2, Some(vec!["/vol/agent-b"]));
        assert!(matches!(
            config.validate_fs_update(&req),
            Err(ValidationError::InvalidFsUpdate(_))
        ));
    }

    #[test]
    fn test_setfs_shared_dir_is_immutable_unless_omitted() {
        let tree = ShareTree::new("shared-dir");
        let root = tree.root();
        let entry = tree.path("vol/agent-a");
        let config = setfs_vm_config("sandswap", &root, 2);

        // An explicit different shared_dir is rejected.
        let moved = setfs_request("sandswap", "/other-vol", 2, Some(vec!["/other-vol/a"]));
        assert!(matches!(
            config.validate_fs_update(&moved),
            Err(ValidationError::InvalidFsUpdate(_))
        ));

        // An omitted shared_dir (serde default = "") is tolerated — the
        // request is contained against the STORED root.
        let omitted = setfs_request("sandswap", "", 2, Some(vec![entry.as_str()]));
        config.validate_fs_update(&omitted).unwrap();
    }

    #[test]
    fn test_setfs_cache_is_immutable_except_serde_default() {
        let tree = ShareTree::new("cache");
        let root = tree.root();
        let entry = tree.path("vol/agent-a");
        // Device created with cache=Always(1); a request omitting cache
        // deserializes to the serde default Never(2) — tolerated as "not
        // specified" even though it differs from the stored policy.
        let config = setfs_vm_config("sandswap", &root, 1);
        let omitted = setfs_request("sandswap", "", 2, Some(vec![entry.as_str()]));
        config.validate_fs_update(&omitted).unwrap();

        // An explicit non-default policy differing from the stored one is a
        // rejected change attempt.
        let changed = setfs_request("sandswap", "", 0, Some(vec!["/vol/agent-b"]));
        assert!(matches!(
            config.validate_fs_update(&changed),
            Err(ValidationError::InvalidFsUpdate(_))
        ));
    }

    #[test]
    fn test_setfs_rejects_relative_allowed_dirs() {
        let config = setfs_vm_config("sandswap", "/vol", 2);
        let req = setfs_request("sandswap", "", 2, Some(vec!["agent-b"]));
        assert!(matches!(
            config.validate_fs_update(&req),
            Err(ValidationError::InvalidFsUpdate(_))
        ));
        // The failing request must not have modified the stored config.
        let fs = config.fs.as_ref().unwrap().first().unwrap();
        assert_eq!(
            fs.backendfs_config.as_ref().unwrap().allowed_dirs,
            Some(vec![])
        );
    }

    #[test]
    fn test_setfs_refuses_root_shared_dir_and_the_share_root_itself() {
        // shared_dir="/" folds to "" under trim_end_matches('/'): no
        // containment is possible, so an absolute entry must be refused
        // (it used to be accepted, exporting any host directory).
        let config = setfs_vm_config("sandswap", "/", 2);
        let req = setfs_request("sandswap", "", 2, Some(vec!["/etc"]));
        assert!(
            matches!(
                config.validate_fs_update(&req),
                Err(ValidationError::InvalidFsUpdate(_))
            ),
            "shared_dir=/ must not accept an arbitrary absolute entry"
        );
        // dir == shared is the whole-tree export (every tenant directory as
        // one visible root entry) — refused; only strict descendants pass.
        let config = setfs_vm_config("sandswap", "/vol", 2);
        let req = setfs_request("sandswap", "", 2, Some(vec!["/vol"]));
        assert!(
            matches!(
                config.validate_fs_update(&req),
                Err(ValidationError::InvalidFsUpdate(_))
            ),
            "the share root itself must not be an allowed entry"
        );
        for spelling in ["/vol/", "/vol/.", "/vol//", "/vol/./", "/vol/."] {
            let req = setfs_request("sandswap", "", 2, Some(vec![spelling]));
            assert!(
                matches!(
                    config.validate_fs_update(&req),
                    Err(ValidationError::InvalidFsUpdate(_))
                ),
                "share-root spelling {spelling:?} must be refused"
            );
        }
    }

    // pin: allowed_dirs entries must live UNDER the VM's shared_dir —
    // the share exports exactly one host directory, and an entry outside it
    // (crafted raw frame / compromised sandlot) would widen the export.
    // RED with the containment check disabled: /other/data validates.
    #[test]
    fn test_setfs_rejects_allowed_dirs_outside_shared_dir() {
        let tree = ShareTree::new("outside");
        let root = tree.root();
        let config = setfs_vm_config("sandswap", &root, 2);
        for bad in [
            tree.path("outside"),
            "/volume2/x".to_string(),
            "/tmp".to_string(),
        ] {
            let req = setfs_request("sandswap", "", 2, Some(vec![bad.as_str()]));
            assert!(
                matches!(
                    config.validate_fs_update(&req),
                    Err(ValidationError::InvalidFsUpdate(_))
                ),
                "outside-shared_dir entry {bad:?} must be refused"
            );
        }
        // The share root itself is NOT a legal entry (it would export every
        // tenant directory as one visible root); strict children are.
        {
            let req = setfs_request("sandswap", "", 2, Some(vec![root.as_str()]));
            assert!(
                matches!(
                    config.validate_fs_update(&req),
                    Err(ValidationError::InvalidFsUpdate(_))
                ),
                "the share root itself must be refused as an allowed_dir"
            );
        }
        for ok in [tree.path("vol/agent-a")] {
            let req = setfs_request("sandswap", "", 2, Some(vec![ok.as_str()]));
            config
                .validate_fs_update(&req)
                .unwrap_or_else(|e| panic!("inside entry {ok:?} refused: {e:?}"));
        }
        // A trailing slash on the stored shared_dir must not break children.
        let slash = setfs_vm_config("sandswap", &(root.clone() + "/"), 2);
        let req = setfs_request(
            "sandswap",
            "",
            2,
            Some(vec![tree.path("vol/agent-a").as_str()]),
        );
        slash
            .validate_fs_update(&req)
            .expect("trailing-slash shared_dir must still contain its children");
    }

    // regression pin: containment is STRUCTURAL, not lexical. The lexical prefix
    // check alone accepted `/share/agent-a/../../outside` (it "starts with"
    // the share), and the filter that consumes the entry opens it with
    // O_PATH|O_NOFOLLOW — final component only — so the `..`/symlink
    // components resolved on the host and an arbitrary directory was exported
    // into the guest. RED with the containment check removed/bypassed: the
    // `..` entry validates and the symlink entries resolve.
    #[test]
    fn test_setfs_containment_rejects_dotdot_and_symlink_escapes() {
        let tree = ShareTree::new("escape");
        let root = tree.root();
        let config = setfs_vm_config("sandswap", &root, 2);
        let outside = tree.path("outside");

        // 1. `..` escape — lexically inside, structurally outside.
        let dotdot = tree.path("vol/agent-a/../../outside");
        assert!(
            dotdot.starts_with(&(root.clone() + "/")),
            "fixture must stay lexically inside: {dotdot}"
        );
        let req = setfs_request("sandswap", "", 2, Some(vec![dotdot.as_str()]));
        let err = config.validate_fs_update(&req).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidFsUpdate(_)),
            "'..' escape must be refused, got {err:?}"
        );
        assert!(
            format!("{err:?}").contains(".."),
            "refusal must NAME the '..' component: {err:?}"
        );

        // 2. Symlink escape — the link itself and anything below it.
        std::os::unix::fs::symlink(&outside, tree.path("vol/link")).unwrap();
        for bad in [tree.path("vol/link"), tree.path("vol/link/sub")] {
            let req = setfs_request("sandswap", "", 2, Some(vec![bad.as_str()]));
            assert!(
                matches!(
                    config.validate_fs_update(&req),
                    Err(ValidationError::InvalidFsUpdate(_))
                ),
                "symlinked entry {bad:?} must be refused"
            );
        }

        // 3. Legit shapes still validate: a real nested directory. The share
        // root itself is refused (see the containment rule).
        for ok in [tree.path("vol/agent-a")] {
            let req = setfs_request("sandswap", "", 2, Some(vec![ok.as_str()]));
            config
                .validate_fs_update(&req)
                .unwrap_or_else(|e| panic!("legit entry {ok:?} refused: {e:?}"));
        }

        // 4. A create-time allow-list (FsConfig::validate — the filter is
        // built from it at activation) gets the same containment.
        let fs_cfg: FsConfig = serde_json::from_str(&format!(
            r#"{{"id":"vfs-rootfs","tag":"sandswap","backendfs_config":{{"shared_dir":"{}","allowed_dirs":["{}"]}}}}"#,
            root,
            tree.path("vol/agent-a/../../outside")
        ))
        .unwrap();
        let vm_config: VmConfig = serde_json::from_str("{}").unwrap();
        assert!(
            matches!(
                fs_cfg.validate(&vm_config),
                Err(ValidationError::InvalidFsUpdate(_))
            ),
            "create-time '..' entry must be refused"
        );
    }

    #[test]
    fn test_setfs_rejects_when_no_fs_devices() {
        let config: VmConfig = serde_json::from_str("{}").unwrap();
        let req = setfs_request("sandswap", "", 2, Some(vec!["/vol/agent-b"]));
        assert!(matches!(
            config.validate_fs_update(&req),
            Err(ValidationError::InvalidFsUpdate(_))
        ));
    }

    // --- fail-closed allowed_dirs defaults ---------------------------------
    // The share filter has no "no filtering" mode, so every config surface
    // defaults an omitted list to the EMPTY (allow-nothing) list — never to
    // None, which used to mean "full fs visible" on an isolation boundary.

    #[test]
    fn test_fs_config_omitted_allowed_dirs_is_fail_closed() {
        // vm.create body with an fs device that omits allowed_dirs.
        let config: VmConfig = serde_json::from_str(
            r#"{"fs":[{"id":"vfs-rootfs","tag":"sandswap","backendfs_config":{"shared_dir":"/vol"}}]}"#,
        )
        .unwrap();
        let fs = config.fs.as_ref().unwrap().first().unwrap();
        assert_eq!(
            fs.backendfs_config.as_ref().unwrap().allowed_dirs,
            Some(vec![])
        );
    }

    #[test]
    fn test_fs_cli_omitted_allowed_dirs_is_fail_closed() {
        // `--fs tag=…,native=on,shared_dir=…` without allowed_dirs.
        let fs = FsConfig::parse("tag=sandswap,native=on,shared_dir=/vol").unwrap();
        assert_eq!(
            fs.backendfs_config.as_ref().unwrap().allowed_dirs,
            Some(vec![])
        );
    }

    #[test]
    fn test_setfs_null_allowed_dirs_clears_never_unfilters() {
        // An explicit null in a set-fs request is normalized to the empty
        // allow-list when applied — "clear everything", never "filter off".
        // The stored config then reflects exactly what the device will run.
        let mut config = setfs_vm_config("sandswap", "/vol", 2);
        let req = setfs_request("sandswap", "", 2, None);
        config.update_fs_allowed_dirs(&req).unwrap();
        let fs = config.fs.as_ref().unwrap().first().unwrap();
        assert_eq!(
            fs.backendfs_config.as_ref().unwrap().allowed_dirs,
            Some(vec![])
        );
    }

    // --- the single-share invariant ---------------------------------------
    // Sandswap supports exactly one virtio-fs device per VM; the create path
    // is the only place a device can come from (the vm.add-fs endpoint is
    // gone), and this is where the count is capped. A second device would be
    // a second window into the host filesystem, outside the allowed_dirs
    // filter the isolation model is stated over.

    fn fs_count_config(n: usize) -> VmConfig {
        let devices: Vec<String> = (0..n)
            .map(|i| {
                format!(
                    r#"{{"id":"vfs-{i}","tag":"tag{i}","backendfs_config":{{"shared_dir":"/vol","allowed_dirs":[]}}}}"#
                )
            })
            .collect();
        serde_json::from_str(&format!(
            r#"{{"payload":{{"kernel":"/path/to/kernel"}},"fs":[{}]}}"#,
            devices.join(",")
        ))
        .unwrap()
    }

    #[test]
    fn fs_tag_and_queue_size_are_bounded() {
        let cfg = |tag: &str, queue_size: u16| -> VmConfig {
            serde_json::from_str(&format!(
                r#"{{"payload":{{"kernel":"/path/to/kernel"}},"fs":[{{"id":"vfs-rootfs","tag":"{tag}","queue_size":{queue_size},"backendfs_config":{{"shared_dir":"/vol","allowed_dirs":[]}}}}]}}"#
            ))
            .unwrap()
        };

        let mut long_tag = cfg(&"a".repeat(virtio_devices::fs::MAX_TAG_LEN + 1), 128);
        assert!(matches!(
            long_tag.validate(),
            Err(ValidationError::InvalidFsTag(_))
        ));

        let mut non_power_of_two = cfg("sandswap", 1000);
        assert!(matches!(
            non_power_of_two.validate(),
            Err(ValidationError::InvalidQueueSize(1000))
        ));

        let mut zero = cfg("sandswap", 0);
        assert!(matches!(
            zero.validate(),
            Err(ValidationError::InvalidQueueSize(0))
        ));

        let mut valid = cfg("sandswap", 1024);
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_single_fs_device_is_the_supported_shape() {
        // Zero or one fs device validates (a VM without a share is legal for
        // scratch use); the sandlot always creates exactly one.
        let mut none = fs_count_config(0);
        assert!(none.validate().is_ok());
        let mut one = fs_count_config(1);
        assert!(one.validate().is_ok());
    }

    #[test]
    fn test_more_than_one_fs_device_is_rejected() {
        let mut two = fs_count_config(2);
        assert!(matches!(
            two.validate(),
            Err(ValidationError::TooManyFsDevices)
        ));
        let mut three = fs_count_config(3);
        assert!(matches!(
            three.validate(),
            Err(ValidationError::TooManyFsDevices)
        ));
    }

    // --- guest vsock cid legality ---------------------------------
    // The cid reaches VHOST_VSOCK_SET_GUEST_CID verbatim; 0/1/2 are the
    // reserved hypervisor/local/host ids and 0xFFFFFFFF is VMADDR_CID_ANY.
    // RED with the validate check removed: cid=1 (the value the pre-fix
    // vm.add-vsock fixture used) validates Ok.

    #[test]
    fn test_reserved_vsock_cids_are_rejected() {
        let vm_config = VmConfig::default();
        for bad in [0u64, 1, 2, 0xFFFF_FFFF] {
            let cfg = VsockConfig {
                cid: bad,
                ..Default::default()
            };
            match cfg.validate(&vm_config) {
                Err(ValidationError::VsockCid(v)) => {
                    assert_eq!(v, bad, "the refusal must name the offending cid");
                }
                other => panic!("reserved cid {bad} must be refused, got {other:?}"),
            }
        }
        // Controls: the sandlot allocator's floor and the top legal cid.
        for good in [3u64, 0xFFFF_FFFE] {
            let cfg = VsockConfig {
                cid: good,
                ..Default::default()
            };
            assert!(
                cfg.validate(&vm_config).is_ok(),
                "legal guest cid {good} must validate"
            );
        }
        assert!(guest_cid_is_legal(3) && guest_cid_is_legal(0xFFFF_FFFE));
        assert!(!guest_cid_is_legal(2) && !guest_cid_is_legal(0xFFFF_FFFF));
    }

    // --- pci_segment bounds without a platform config --------------
    // DeviceManager builds one default segment when `platform` is absent and
    // indexes its vector with the requested id (vm.add-vsock reaches this
    // after create). Before the fix the check was skipped entirely and the
    // index panicked.

    #[test]
    fn vsock_pci_segment_is_bounded_without_platform() {
        let vm_config = VmConfig::default();
        assert!(vm_config.platform.is_none(), "fixture must have no platform");

        let default_segment = VsockConfig {
            cid: 3,
            pci_segment: 0,
            ..Default::default()
        };
        assert!(default_segment.validate(&vm_config).is_ok());

        let out_of_range = VsockConfig {
            cid: 3,
            pci_segment: 1,
            ..Default::default()
        };
        assert!(matches!(
            out_of_range.validate(&vm_config),
            Err(ValidationError::InvalidPciSegment(1))
        ));
    }

    #[test]
    fn vsock_pci_segment_is_bounded_with_platform() {
        let mut vm_config = VmConfig::default();
        vm_config.platform = Some(PlatformConfig {
            num_pci_segments: 2,
            ..Default::default()
        });

        let second = VsockConfig {
            cid: 3,
            pci_segment: 1,
            ..Default::default()
        };
        assert!(second.validate(&vm_config).is_ok());

        let third = VsockConfig {
            cid: 3,
            pci_segment: 2,
            ..Default::default()
        };
        assert!(matches!(
            third.validate(&vm_config),
            Err(ValidationError::InvalidPciSegment(2))
        ));
    }
}
