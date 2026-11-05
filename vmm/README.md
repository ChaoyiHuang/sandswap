# sandvmm — KVM Virtual Machine Monitor

This directory contains the **VMM (Virtual Machine Monitor)** component of
[Sandswap](https://github.com/sandswap/sandswap), a transparent remote code
execution sandbox for AI agents. Every microVM runs under one dedicated
`sandvmm` process, driven by sandlot over a dual-protocol (raw control
frames + HTTP) API on a Unix-domain socket.

## Provenance

`sandvmm` is derived from **[Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)**
v28.0 (dual-licensed Apache-2.0 / BSD-3-Clause — see
[LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-BSD-3-Clause](./LICENSE-BSD-3-Clause)).
The code history has three sources, each kept honest by per-file
copyright/SPDX headers:

1. **Inherited from upstream** — the Cloud Hypervisor v28.0 base, plus the
   [virtio-fs](https://gitlab.com/virtio-fs/virtiofsd) virtiofsd crate
   (CH v28 itself ships no such crate; see §1).
2. **Ported from the sandbox fork** — sandbox-oriented features built in
   CubeSandbox, a public Tencent fork of Cloud Hypervisor (Tencent
   copyright headers), carried over deliberately.
3. **Sandswap originals** — new code written for this project.

A fourth section, **Removed**, logs the subtractive pass over the first
two sources — general-purpose VMM features Sandswap does not need. It is
a change log, not a source.

The full compatibility contract a replacement VMM/hypervisor must satisfy is
documented in [docs/integration/vmm.md](../docs/integration/vmm.md).

### 1. Inherited from upstream (Cloud Hypervisor v28.0 + virtio-fs virtiofsd)

| Area | Crates | Notes |
|------|--------|-------|
| VMM core loop, epoll, HTTP API framework | `vmm/` | API-only mode: create → boot via UDS |
| PVH / direct kernel boot | `arch/` | kernel + initramfs + cmdline, no firmware |
| Hypervisor abstraction + KVM backend | `hypervisor/` | split irqchip, irqfd/ioeventfd, memory slots |
| Virtio PCI transport, MSI-X | `virtio-devices/`, `pci/`, `vm-virtio/` | |
| ACPI tables incl. S5 shutdown → process exit | `devices/`, `acpi_tables/` | warden `power_off` relies on this |
| Memory manager (mmap guest RAM) | `vmm/` | dirty-page logging compiled out of use |
| virtio-net (TAP), virtio-rng | `virtio-devices/`, `net_util/` | |
| In-process virtiofsd (`PassthroughFs`) | `virtiofsd/` | vendored from the [virtio-fs project's virtiofsd](https://gitlab.com/virtio-fs/virtiofsd): fuse protocol, passthrough engine, sandbox, idmap — most files byte-identical or near-identical to upstream. Not a CH v28 crate (v28's fs device is vhost-user); the in-process vendoring itself is fork work (§2) |
| Logging, option parsing, misc utilities | `logging/`, `log_json/`, `option_parser/`, … | |

### 2. Ported from the sandbox fork (kept)

| Feature | Where | Notes |
|---------|-------|-------|
| **virtio-fs `allowed_dirs` allow-list + `vm.set-fs` hot-swap** | `virtiofsd/src/server.rs` (`FilterList`; `Server::new`/`update_filter` take the whitelist), `virtio-devices/src/fs.rs` (in-process `PassthroughFs` device, `BackendFsConfig.allowed_dirs`), `vmm/src/api/mod.rs` (`vm_set_fs`), `vmm/src/device_manager.rs` (`fs_device_update`) | the fork's original isolation core — upstream virtiofsd has no filtering at all (`Server::new(fs)` takes no whitelist), and CH v28's fs device is vhost-user. Sandswap hardened the same chain into today's agent switch: always-on fail-closed filter (no unfiltered fallback), per-generation alias, cancellable swap, the `previous-tenant-refs` tripwire, the raw-frame transport (§3) |
| `VmmService` (internal start path) | `vmm/src/api/service.rs` | eventfd-driven API service used by the in-process entry |
| Log-control protocol & defaults | `src/common.rs` | `LOG_CTRL_REOPEN` etc. |
| JSON log writer | `log_json/` | |


### 3. Sandswap originals

| Feature | Where | Notes |
|---------|-------|-------|
| **Kernel vhost-vsock backend** | `virtio-devices/src/vsock/vhost_vsock.rs` (new file), `vsock/{device,mod}.rs` (rewritten) | entire vsock data path offloaded to `/dev/vhost-vsock`: KICK = the already-registered KVM ioeventfd, CALL = per-queue KVM irqfd — **zero VMEXIT, zero VMM user-space involvement per packet**. Replaces upstream's userspace unix-muxer (~1k lines) |
| API socket hardening (`--api-allowed-uid`, `--api-gid`, `--api-token-fd`) | `src/main.rs`, `vmm/src/api/http/{mod,dispatch}.rs` | owner is always the sandvmm process identity itself (it binds; it holds zero capabilities). `--api-gid` chgrps the sockets to the shared group (`0660`, group-membership chown needs no caps) so the sandlot identity can connect; without it they stay `0600` owner-only. `--api-allowed-uid` is a `SO_PEERCRED` peer-uid gate on every connection (root + one named uid; without it the legacy "not-own-uid" rule). `--api-token-fd` adds a per-VM 32-byte token challenge-response — `[0xA5][1][32-byte challenge]` answered with `token XOR challenge` — before the first protocol byte, transport-independent (wraps the raw and the HTTP framing) |
| **Raw control-frame protocol** | `vmm/src/api/http/{dispatch,raw,raw_parse}.rs` | the canonical API socket is dual-protocol, routed per connection by the first byte (`0x01` → raw frame, ASCII method letter → HTTP); the hot ops (`vm.set-fs`, `sandvmm.ping`) skip the HTTP/JSON envelope entirely. Version doctrine mirrors the warden vsock protocol (in-range echoed, out-of-range rejected with this build's version); budgets byte-aligned with the HTTP envelope (body ≤ 51,200, per-path ≤ PATH_MAX−1). HTTP lifecycle ops are pumped through an internal listener that is bound, anchored via `/proc/self/fd`, and unlinked — the dispatcher's `SO_PEERCRED` verdict is the only door, and both sockets are proven at startup to still reach this process (a sibling-squat check closing the bind→anchor window) |
| **`vm.set-fs` reuse tripwire** | `virtio-devices/src/fs.rs`, `vmm/src/device_manager.rs` | the swap is refused (stable `previous-tenant-refs` error token, on both transports) while the export being swapped away still holds open handles or un-FORGOTTEN inode references — a lying warden unmount reply cannot carry a live tenant into the next one; the sandlot retries once and then dirty-destroys the VM |
| Host-path containment (`--sandswap-allowed-root`) | `src/main.rs`, `vmm/src/config.rs` | every host path in `vm.create` (kernel/initramfs, serial/console logs, the fs share root, …) must live under one of the repeatable deployment roots, checked lexically AND canonically — a compromised sandlot cannot point the VMM at arbitrary host files |
| Seccomp filter fixes | `vmm/src/seccomp_filters.rs`, `virtio-devices/src/seccomp_filters.rs` | allow `TCGETS2/TCSETS2/TCSETSW2` (glibc ≥ 2.36 `isatty`) + `rt_sigaction`/`rt_sigprocmask`; `virtio_fs_thread_rules` extended for the in-process virtio-fs server (path-based `chmod`/`chown`/`lchown` secctx rollback, `umask`, `getrandom`, `tgkill`, `readlinkat`) with pin tests — a future mismatch kills the VMM thread |
| vsock CID range gate | `vmm/src/vm.rs`, `vmm/src/config.rs` | `vm.add-vsock` refuses a CID outside 3..=0xFFFFFFFE (0/1/2 are kernel-reserved hypervisor/local/host ids, 0xFFFFFFFF is `VMADDR_CID_ANY`) |
| `sandvmm.ping` / `sandvmm.shutdown` endpoints | `vmm/src/api/http/` | renamed from `vmm.*` |
| Chrono-based log rolling | `logging/src/lib.rs` | replaces the fork's reopen protocol |
| Modern toolchain fixes | various | lint attributes, `slog` macro style, doctest repairs |
| **A guest name is a validated type** | `virtiofsd/src/filesystem.rs` (`Name`), `server.rs` (the only constructor) | the sandbox fork's `allowed_dirs` filtering assumes a name is one path component, but upstream never checked it (it contained the blast radius with `--sandbox`; this fork runs in-process, with no sandbox). Every handler now receives a `Name` that only the validating constructor can produce, so an unvalidated guest name cannot reach the filesystem layer at all — a new opcode (or an upstream merge) fails to compile instead of silently escaping. The symlink *target* stays a plain `&CStr`: it is inert data, never resolved by the daemon |


### Removed

Everything the general-purpose VMM carries that Sandswap's model (one
rootfs-share per VM, no disks, no migration) does not need — upstream
features and fork-era remnants alike (~15k lines total):

| Removed | Why |
|---------|-----|
| Block device stack: `block_util/`, `qcow/`, `vhdx/`, virtio-blk, vhost-user-block | rootfs is a permanent virtio-fs share; no disks anywhere |
| vhost-user-net | networking is a single TAP per VM |
| pmem, balloon, vdpa, TPM | unused device classes |
| Live migration, snapshot / restore, `SnapshotType::{Incremental, SoftDirty}` | VMs are disposable; agent switching is a filter swap, not a snapshot |
| Guest debug: `gdb` | compiled out — the `guest_debug` cargo feature is enabled by no target (`--coredump` stays as a best-effort, explicitly non-fatal debug aid) |
| mshv / tdx backends — out of the build | the build is KVM-only: both are cargo features nothing enables; the mshv source stays in-tree but is explicitly broken (pinned mshv-ioctls rev no longer compiles — see `hypervisor/Cargo.toml`), tdx stays feature-gated in `arch/` |
| `fuzz/`, `performance-metrics/`, `test_infra/`, `api_client/`, `ch-remote`, `tests/integration.rs` (11 075 lines) | test/tooling for the removed features above; Sandswap business tests live in `/e2e` |
| `vmm/src/soft_dirty.rs`, `pagemap_anon.rs` | snapshot dirty-page tracking for the (removed) incremental snapshot feature — zero callers |
| `devices/src/ivshmem.rs`, `pvpanic.rs` | fork-added inter-VM-shm / guest-panic devices — CLI-only, unreachable from sandlot |
| `arch/src/x86_64/cpuid_filter.rs`, `CompatibleMode` | CPUID template machinery reading a fork-specific host-side JSON (with a double-`unwrap` panic path); the `compatible=vendor` default made it a no-op |
| `devices/src/legacy/sys_ctrl.rs` | fork-added guest→host "system started" port (0x0680) — sandswap tracks boot via warden's vsock server instead |
| `vm.add-net` route + `Vm::add_net` / `DeviceManager::add_net` hotplug path | a VM has exactly one NIC, configured at `vm.create` (one TAP per VM, provisioned by sandlot before boot; guest addressing travels in the kernel cmdline). A NIC attached to a running VM would be a second, unaccounted egress path — the egress-identity binding an enforcer reads is keyed on the one provisioned interface — and nothing in Sandswap ever asked for one |
| `vm.add-fs` route + `Vm::add_fs` / `DeviceManager::add_fs` hotplug path | the rootfs share is ONE device, created at boot and re-filtered by `vm.set-fs`. A second virtio-fs device would be a second window into the host filesystem with its own `allowed_dirs`, invisible to `vm.set-fs` (which matches by device id) — so the route is gone and `VmConfig::validate` refuses a config naming more than one fs device |

Known quirks kept as-is: the CLI still parses (but cannot instantiate)
`--disk/--pmem/--tpm/--vdpa/--device`; the default log directory
`/data/log/sandvmm/` is not created automatically (sandlot always passes
`--log-stderr`).

## How this VMM fits in Sandswap

```
sandlot (Go) ── raw+HTTP ──→ sandvmm (Rust/KVM)
                                │
                                ├── virtio-fs  ← host volumes dir (PassthroughFs)
                                ├── vhost-vsock ← kernel /dev/vhost-vsock
                                ├── virtio-net  ← TAP on host bridge
                                └── virtio-rng
                                       │
                                  KVM microVM
                                  ├── kernel (PVH)
                                  └── initramfs (warden)
```

The sandlot process spawns one `sandvmm` per microVM. All operations are
issued over one Unix-domain socket that speaks two protocols, routed per
connection by the first byte: raw control frames for the hot ops
(`vm.set-fs`, `sandvmm.ping`) and HTTP/JSON for lifecycle (create, boot,
add-vsock, shutdown). Agent switching is implemented by updating the
virtio-fs `allowed_dirs` filter at runtime under a fresh per-generation
alias (`vm.set-fs`), so only the active agent's rootfs directory is visible
inside the guest.

## Building

```bash
cd /path/to/sandswap
bash build/build.sh vmm     # compiles to output/sandvmm
```

## Relationship to upstream

This codebase is **not** a general-purpose VMM. It is a purpose-built subset
of Cloud Hypervisor, maintained for Sandswap's specific needs. We gratefully
acknowledge the Cloud Hypervisor authors, the [virtio-fs](https://gitlab.com/virtio-fs/virtiofsd)
project whose virtiofsd is the basis of the in-process passthrough backend
(`virtiofsd/`, Chromium OS BSD lineage), the Tencent engineers whose
public sandbox fork of Cloud Hypervisor (CubeSandbox) contributed the virtio-fs
`allowed_dirs` filtering and related sandbox-oriented features listed above,
and the broader [rust-vmm](https://github.com/rust-vmm) community whose
crates form the foundation of this component.

For the full Cloud Hypervisor project — including support for disk images,
live migration, snapshot/restore, VFIO, vDPA, TPM, multiple architectures,
and firmware boot — see the upstream repository at
<https://github.com/cloud-hypervisor/cloud-hypervisor>.

## License

This component retains the original Cloud Hypervisor licensing:
[Apache 2.0](./LICENSE-APACHE) and [BSD-3-Clause](./LICENSE-BSD-3-Clause).
Per-file copyright/SPDX headers are preserved verbatim; Sandswap
modifications are marked in-place.
