---
title: Guest Kernel Hardening
nav_order: 9
parent: How It Works
---

# Guest Kernel Hardening

The warden executes agent code as uid 0 inside the agent's own sandfs, and
the guest kernel is the only boundary underneath that execution. This page
is the kernel's risk story in one place: what its compromise means, and
the layers that reduce it — the build-time configuration that shrinks the
kernel, the load-time and runtime configuration that hardens it, the
capability and seccomp fence around what agent code can ask of it, the
kernel objects cleared at every unmount, and the reuse and network
bounds that shrink the blast radius.
[Isolation and Swap](isolation-and-swap.md) covers the swap machinery that assumes
this boundary holds; [Threat Model](threat-model.md) covers the
adversaries outside the microVM.

## 1. The kernel is a trust root

**Compromise of the guest kernel is a boundary breach, not an in-sandbox
event.** The kernel is the executor of every in-VM clear — the kill sweep,
the unmount, `drop_caches`, the FORGET accounting — so an implant in it
survives the tenant switch and reads the next attachment's volume. VM
reuse therefore does not protect
against kernel-level implants; every layer below reduces either the
probability of that event or its reach.

What the model does claim about it:

- The kernel and initramfs (the warden) are an **upstream artifact** —
  the pinned kernel tree plus the in-repo warden crate, built from pinned
  sources — so nothing inside the sandbox can influence what the next VM
  boots.
- The blast radius is **per-VM, never fleet-wide** (§6): an implant reads
  the volume attached at compromise and every volume later attached to
  that VM, and reaches other tenants only through that VM's reuse.
- The reuse chain is **bounded by policy** (§7). High-security tenants
  that cannot accept any cross-tenant reuse use a dedicated Sandswap
  cluster.

## 2. Shrinking the kernel at build time

The release kernel (`kernel/build.sh`) minimizes the guest attack surface
at build time:

- **Compiled out**: `CONFIG_USER_NS`, `CONFIG_TUN`, `CONFIG_VETH`,
  `CONFIG_KVM`, `CONFIG_DEBUG_FS`, `CONFIG_USERFAULTFD`,
  `CONFIG_IO_URING`, `CONFIG_BPF_SYSCALL`, `CONFIG_CGROUP_BPF`,
  `CONFIG_OVERLAY_FS`, `CONFIG_POSIX_MQUEUE`, `CONFIG_VSOCKETS_DIAG`,
  `CONFIG_DEVMEM`, `CONFIG_X86_MSR`, `CONFIG_PROC_KCORE`,
  `CONFIG_FUSE_DAX`, `CONFIG_FUSE_PASSTHROUGH`, `CONFIG_FUSE_IO_URING`,
  `CONFIG_PACKET`, `CONFIG_ZSWAP`, `CONFIG_ZRAM`, `CONFIG_ZSMALLOC`,
  `CONFIG_ZSMALLOC_STAT`, `CONFIG_CONNECTOR`, `CONFIG_AUDIT`,
  `CONFIG_MODIFY_LDT_SYSCALL`, `CONFIG_UNIX_DIAG`,
  `CONFIG_CRYPTO_USER_API_RNG`. (`CONFIG_TLS` stays at its defconfig
  value: kTLS is a workload feature with no unprivileged parser surface
  comparable to the `AF_ALG` RNG interface, which is the part compiled
  out.)
- **Hardening compiled in**: beyond the defconfig, `CONFIG_X86_UMIP`
  traps `SGDT`/`SIDT`/`SLDT`/`STR`/`SMSW` in user mode (no kernel
  address leaks through them) and `CONFIG_LEGACY_VSYSCALL_NONE` removes
  the legacy vsyscall page entirely (modern glibc uses the vDSO). The
  memory-hardening baseline — `CONFIG_HARDENED_USERCOPY`,
  `CONFIG_KMALLOC_PARTITION_CACHES` (+`_RANDOM`), and
  `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION` — is required, with the
  `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` / `CONFIG_INIT_ON_FREE_DEFAULT_ON`
  pair selected by the `KERNEL_INIT_HARDENING` build variant (default
  `both`).
- **Not disabled, for a kernel-structural reason**: `CONFIG_PERF_EVENTS`
  is `select`ed by `config X86` itself (`arch/x86/Kconfig`), so it cannot
  be compiled out without patching the arch Kconfig. `perf_event_open` is
  on the seccomp deny list; the kernel's perf code is not guest-userland
  reachable through the denied syscall.
- **Kept by necessity**: `CONFIG_FUSE_FS` (VIRTIO_FS `depends on FUSE_FS`;
  the guest rootfs is virtio-fs), `CONFIG_VIRTIO_FS`, `CONFIG_VIRTIO_NET`,
  `CONFIG_VIRTIO_CONSOLE`, `CONFIG_VSOCKETS`, `CONFIG_VIRTIO_PCI`,
  `CONFIG_IPV6`, `CONFIG_INET_DIAG(_DESTROY)`.
- **Backfill patches**: `kernel/patches/` carries the backport series the
  build applies in order (network/UDP/IP hygiene, the futex private-hash
  UAF, the legacy-AIO/eventfd/epoll recursion, and netlink's
  `net_cookie` hashing that removes the `/proc/net/netlink` pointer
  disclosure, plus its `sk_filter` header reset). The patch-set hash is
  part of the artifact identity (`output/vmlinux.config-rev`).
- **Gates**: after `make olddefconfig` the build runs
  `check_kernel_config`, which fails naming any re-enabled disabled symbol
  (a `select` edge) or missing required symbol — a renamed disable is
  fatal, never silently inert. The pre-strip image is then probed with
  `nm` for `create_user_ns`, `tun_chr_open`, `kvm_init`,
  `debugfs_create_dir`, the four disabled syscall entry points
  (`__x64_sys_userfaultfd`, `__x64_sys_bpf`, `__x64_sys_io_uring_setup`,
  `__x64_sys_mq_open`), `ovl_fill_super` and `packet_create` (absent), and
  `virtio_fs_init`/`fuse_dev_init` (present). The policy revision —
  config hash, patch-set hash, tag, commit, and init-hardening variant —
  is recorded in `output/vmlinux.config-rev` so an artifact built before
  the minimization is never considered current.

Tests: `e2e/kernel-config-gate.sh` exercises the gate against synthetic
`.config` files (no root/KVM/kernel build), and `e2e/seccomp.sh` uploads a
static probe that asserts `clone3(CLONE_NEWUSER)` is refused and each new
denied syscall returns EPERM in a live guest.

## 3. Load-time and runtime posture

- **No KASLR under PVH direct boot**: `CONFIG_RANDOMIZE_BASE` is enabled,
  but the VMM loads the ELF with `kernel_offset = None` and the PVH entry
  path refuses an offset, so the kernel runs at its link-time physical
  base (`phys_base`). The VMM logs `_text`/`phys_base` at load and checks
  the expected `__START_KERNEL_map` delta rather than claiming
  randomization; treat the release image's kernel layout as fixed.
  Randomizing the PVH load address is tracked as an upstream RFC and would
  be adopted on a future kernel rebase — a correctness change to the
  loader, not a build option.
- **User namespaces off at runtime, belt-and-braces**: the warden writes
  `/proc/sys/user/max_user_namespaces=0` (and the Debian-compat
  `kernel/unprivileged_userns_clone=0`) at boot, so a dev/older kernel —
  or a config regression — still cannot create a user namespace. On the
  release kernel `CONFIG_USER_NS` is compiled out and the sysctl file is
  absent (NotFound → debug).
- **Memory-initialization posture**: `init_on_alloc` stays on — fresh
  allocations are zeroed, so the cross-tenant freed-page channel stays
  closed. The free-time wipe is overridden off by default through an
  explicit `init_on_free=0` on every VM's kernel command line
  (`microvm.init_on_free`, default off): a fresh microVM's RAM is host
  anonymous mmap, so `INIT_ON_FREE`'s wipe-on-free is pure redundancy
  measured linear in RAM. High-security deployments set it back on.

## 4. What agent code can ask of the kernel

Every exec runs with the capability bounding set dropped (Strict) or
reduced to the package-manager set (Install), `NO_NEW_PRIVS`, a chroot,
and a seccomp filter installed in `pre_exec` before `execve` — the full
per-exec pipeline is [Isolation and Swap](isolation-and-swap.md) §7. The
build (§2) decides what exists in the kernel; this filter decides what
agent code may invoke.

The filter is a **deny-list**: everything not listed is allowed, because
the product must run arbitrary agent code (interpreters, package
managers, databases). "Allowed" therefore means "not a known cross-tenant
channel or privileged kernel surface", not "audited safe". The lists
below are the complete policy; adding a capability means adding it to the
warden's `DENY_SYSCALLS` (with its pin test) and to this page.

### 4.1 Allowed

| Class | Examples | Why |
|---|---|---|
| Process / thread lifecycle | `clone`, `clone3`, `fork`, `execve`, `execveat`, `wait4`, `exit`, `setsid`, `setpgid`, `kill`, `tgkill` | Arbitrary workloads; signal targets are still bound by uid and by the warden's `PR_SET_DUMPABLE=0` for PID 1. The **pidfd pair** (`pidfd_open`/`pidfd_send_signal`) is DENIED — see the cross-process row |
| Memory | `mmap`, `mprotect`, `madvise`, `brk`, `mlock`, `mincore`, `membarrier`, `rseq` | Language runtimes and allocators |
| Files inside the chroot | `openat`, `openat2`, `read`, `write`, `rename`, `unlink`, `mkdir`, `chmod`, `chown`, `statx`, xattrs | The sandfs is the workload |
| Synchronization | `futex`, `eventfd`, `epoll`, `poll`, `timerfd`, `signalfd`, pipes, `AF_UNIX` sockets | User-space IPC between an agent's own processes |
| POSIX shared memory | `shm_open` / `shm_unlink` over `/dev/shm` | Browsers, databases, Python multiprocessing; the tmpfs is created fresh at every mount and released at unmount |
| SysV IPC | `shmget`/`shmat`, `msgget`/`msgsnd`, `semget`/`semop` | Legacy libraries and databases still use it; the warden sweeps all objects at every unmount (see §5) |
| Network | `socket(AF_INET/AF_INET6/AF_UNIX)`, connect/accept/send/recv | Guest egress; tenant-to-tenant east-west is blocked at the TAP/bridge layer |
| Self-restriction | `seccomp`, `landlock_*`, `prctl` | A process may always make itself stricter |
| Scheduling / limits | `sched_*`, `setpriority`, `setrlimit`, `prlimit64`, `setitimer` | Own-task tuning is allowed. The target-taking calls admit **exactly the self target**: `prlimit64`, `sched_setparam`, `sched_setscheduler`, `sched_setaffinity` and `sched_setattr` allow `args[0] == 0` and return EPERM for every other pid/tid — PID 1 **and** the warden's worker-thread tids (the agent and the warden share uid/gid 0, so same-owner checks would otherwise let the agent retune the warden with no capability at all, including lowering `RLIMIT_CPU`). `setpriority` is on the deny list outright because its target is `args[1]`; only self-renice is lost. The warden restores its own rlimits and nice/affinity/policy at every unmount as the second layer |

Deliberately allowed for compatibility, though rarely needed: `personality`
(ASLR/layout switches used by debuggers and Wine), `modify_ldt` (16-bit
segment users), and the legacy AIO family (`io_setup`/`io_submit`/…, used by
some databases). None is a cross-tenant channel; `io_uring` is denied.

The filter matches native x86_64 syscall numbers. x32 numbers
(`0x40000000 | nr`) report the same `AUDIT_ARCH_X86_64`, so they are not
distinguishable by the arch check; the program's far-right binary-search leaf
refuses every number at or above `0x40000000`, and the shipped kernel is
built without the x32 ABI. Ordinary syscall numbers pay no instruction for
that check — only numbers above the largest deny-list entry reach that leaf.

### 4.2 Denied

The filter returns EPERM (or the kernel returns it because the capability is
absent — the explicit denial keeps the class closed if a future profile ever
changes).

| Class | Syscalls (examples) | Why |
|---|---|---|
| Privilege / mount / namespaces | `mount`, `umount2`, `pivot_root`, `chroot`, `open_tree`, `open_tree_attr`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `statmount`, `listmount`, `unshare`, `setns`, `swapon`, `swapoff` | Keep the agent inside its chroot and the VM's namespace. The whole mount API is denied as a class (`mount_setattr`/`open_tree_attr` were the last live spellings; `statmount`/`listmount` are its read-side pair) |
| Cross-process access | `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `pidfd_open`, `pidfd_send_signal`, `process_madvise`, `process_mrelease`, `kcmp` | Same uid 0 in the VM; these reach the warden or another exec. `pidfd_open` + `pidfd_send_signal` complete the fd/signal class around the already-denied `pidfd_getfd` |
| Kernel modules / loaders | `init_module`, `finit_module`, `delete_module`, `create_module`, `query_module`, `get_kernel_syms`, `kexec_load`, `kexec_file_load`, `uselib` | Kernel integrity and obsolete loaders. `vm86`/`vm86old` are i386-only; on x86_64 their numbers are `setsid`/`setreuid`, both allowed |
| Kernel attack surface | `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_setup`, `open_by_handle_at`, `name_to_handle_at`, `memfd_secret`, `syslog` | Canonical sandbox-escape surfaces; the handle pair is denied as a pair |
| Keyring / mqueue | `add_key`, `request_key`, `keyctl`, `mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr` | Objects survive process death and are readable by the next tenant; background IPC uses user-space channels |
| Host-global state | `reboot`, `sethostname`, `setdomainname`, `settimeofday`, `clock_settime`, `adjtimex`, `clock_adjtime`, `acct`, `quotactl`, `quotactl_fd`, `iopl`, `ioperm`, `lookup_dcookie`, `fanotify_init`, `ioprio_set` | Host or VM-wide state the agent never owns. `ioprio_set` targets another task by `args[1]` (the same-owner check admits PID 1), the block-side sibling of the scheduler guard; `quotactl_fd` is the fd-based spelling of the quota interface |
| Device nodes | `mknod`, `mknodat` | The Install profile already drops `CAP_MKNOD`; device nodes are inert (`nosuid,nodev`) and have no workload use |
| NUMA policy | `mbind`, `set_mempolicy`, `set_mempolicy_home_node`, `get_mempolicy`, `migrate_pages`, `move_pages` | Host memory policy; no cross-tenant need |

### 4.3 Where the filter is pinned

`warden/src/seccomp.rs` carries the deny list, the `dangerous_classes_are_denied`
and `mqueue_syscalls_are_denied` pins, and the filter-shape test. The list is
compiled into a **balanced binary-search classic-BPF tree** (one `JGE` per
internal node, one exact `JEQ` per leaf) rather than a linear chain: a syscall
pays `ceil(log2 N)+1` comparisons instead of up to N, while the program length
— and therefore the per-exec `PR_SET_SECCOMP` installation cost — is unchanged
(`2N+5`). A small in-test cBPF interpreter pins that every listed syscall is
denied and unlisted ones are allowed;
`e2e/seccomp.sh` and `e2e/cross-tenant-residue.sh` exercise the classes live,
including the mqueue EPERM and the SysV/keyring sweep. `e2e/warden-hostile.sh`
covers malformed raw frames. The warden's own root-gated tests cover the
mount and sweep primitives.

## 5. Kernel objects cleared at every unmount

Even with the denials above, the warden treats the VM as a shared object and
clears, at unmount: all agent processes (`cgroup.kill` + rule-A sweep), the
per-agent cgroup, every mount, `/tmp` and `/dev/shm` tmpfs contents, the
page/dentry/inode cache (`drop_caches`), SysV IPC objects, the persistent
user keyring, and TCP dead-state sockets. POSIX mqueues need no sweep: the
whole `mq_*` family is denied, so an agent can neither create nor touch one. The next mount starts from an empty IPC and mount
namespace; only the agent's own volume carries data across.

## 6. Blast radius in three questions

- **How many SandFS volumes can a compromised kernel read?** One at a
  time, but not "only one": the implant can read the volume attached when
  it lands and every volume later attached to that VM until the VM is
  destroyed. It cannot enumerate the volumes root (2710, group
  execute-only) or guess a name (2^128 seed-derived), so it cannot browse
  the fleet. The number is bounded by the VM's reuse history, not by a
  small constant — the recycle counter allows many commands and pool VMs
  are long-lived, so this is a real per-VM exposure, not a theoretical one.
- **Can it reach other microVMs through virtio-fs?** Not directly. Each
  VM has its own sandvmm/VMM process, no shared memory, a per-VM vsock CID
  whose uniqueness vhost-vsock enforces in-kernel, vsockguard denying uid
  987 the warden port, and `ptrace_scope`. A guest→VMM exploit would land
  as uid 987 with zero capabilities; it inherits the paths that VM has
  served (not the tree), cannot read the volume-name seed, and cannot
  address another guest's vsock. Reaching other VMs requires a further
  host-level compromise (host root or a fleet-wide VMM escape), which is
  outside the guest-kernel boundary and the KVM trust model.
- **Can every microVM be compromised?** Not from one guest kernel. The
  implant is per-VM: an attacker can only plant it in VMs their own SandFS
  is scheduled on, and it spreads to later tenants only through those VMs'
  reuse. It does not fan out to arbitrary tenants' VMs. A fleet-wide
  compromise requires host root (or a VMM escape plus host escalation),
  not a guest-kernel exploit alone.

## 7. Shrinking the blast radius

Four `recycle.*` parameters bound the reuse chain — each caps one
direction in which an implant travels through VM reuse:

| Parameter | What it bounds | Default |
|---|---|---|
| `recycle.affinity_vms` | an agent keeps landing on the microVMs it has already used (best-effort, up to N per sandfs) — one agent's footprint, and one implant's landing sites, stay on few VMs | 3 |
| `recycle.max_distinct_agents` | a VM is destroyed once it has served this many different agents — the fan-in of later tenants an implant can read | 300 |
| `recycle.max_mounts` | a VM is destroyed after this many mount generations (one per successful cold attach; warm ops do not count) | 10000 |
| `recycle.max_uses` | a VM is destroyed after this many commands — execs and file ops, warm and cold | 100000 |

The mount and command counters fire at unmount (destroy-and-replace); the
distinct-agent cap destroys the VM at the mount that would exceed it; the
memory thresholds (`-recycle-mem-percent` / `-recycle-mem-abs-mb`) retire
VMs on the same path.

- **The one-use option**: `recycle.max_uses: 1` / `-max-uses 1` (destroy
  after every command — the recycle counter is command-based, not
  lease-based) exists as a technical option but is **not** the recommended
  general answer: a multi-command lease pays a cold boot per command while
  the exposure is already bounded to one VM's reuse chain.
- **TODO — make destroy-after-every-use practical**: a microVM boot is
  only the kernel and the warden, so it is inherently lightweight. Once
  technical work brings the boot down to the millisecond range — on the
  order of the swap-out cleanup itself — destroying the VM after every
  use becomes practical and reduces the kernel-implant risk to its
  minimum.
- **The high-security answer**: a dedicated Sandswap cluster. Tenants that
  cannot accept any cross-tenant reuse get their own fleet instead of a
  per-command knob.
- **Namespace-limited reuse** (a VM serving only one tenant namespace) is
  a planned feature, not a shipped control; deployments that need that
  isolation today use a dedicated cluster or a lower mount cap.

The network bounds the blast radius from the other side. A microVM has
**egress-only** traffic: there is no inbound path for an outside prober
to reach the guest kernel's network stacks. On the way out, every
attachment carries an unforgeable per-agent identity (the
[Egress Enabler Contract](egress-enabler.md)), so the network policy controller can
enforce and audit what an agent's traffic may reach — an implant's
exfiltration channel is confined to the destinations its segment's policy
already admits, and every flow is attributable to the agent that sent it.
