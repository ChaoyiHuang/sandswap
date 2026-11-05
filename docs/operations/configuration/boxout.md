---
title: Boxout
nav_order: 3
parent: Configuration
grand_parent: Operations
---

# Boxout Configuration

> Sources: `boxout/main.go` (entry: config, network provider, socket) + `boxout/server/server.go` (request protocol).

**What boxout is.** In Kubernetes, the sandlot runs unprivileged (UID 65536 — the reserved sandbox identity, outside every id the node allocates on its own; see [Prerequisites](../../deployment/prerequisites.md) §3 — all capabilities dropped). Boxout is its privileged sidecar (UID 0): it owns the sandvmm process lifecycle (launch/kill/shutdown), network provisioning (TAP/IP, egress baseline), host-side OverlayFS mount/unmount, `/proc` re-adopt scanning, and crash detection — everything sandlot would do itself in [embedded mode](sandlot.md). Sandlot stays unprivileged on the hot path (mount-and-exec, warden vsock, leases) and relays privileged operations to boxout over a Unix socket using newline-delimited JSON. Deployment details are in [Install (Kubernetes)](../../deployment/install-kubernetes.md); the split of duties is covered in [Architecture](../../how-it-works/architecture.md).

## 1. Flags

**Background.** Boxout has no config file of its own: `-config` points at the **same sandlot YAML** sandlot uses (see [Sandlot](sandlot.md)), and boxout reads the `network.*`, `microvm.*`, and `vmm_binary` sections from it. The network flags below exist to override the file per-deployment; an empty value means "use the config file's value". All flags are restart-required; the shared file's `microvm.*` hot-reloadable subset is picked up live (see below), everything else is restart-required.

| CLI flag | Default | Meaning |
|---|---|---|
| `-socket` | `/run/sandswap-boxout/boxout.sock` | Unix socket path for sandlot communication (must match sandlot's `-boxout-socket`). The directory is boxout-private: root-owned `0711` (sandlot traverses, cannot create/rename entries there) — deliberately separate from the sandlot-writable `/run/sandswap`. |
| `-config` | "" | Path to the sandlot YAML config file (shared format; no file = built-in sandlot defaults). |
| `-allowed-uid` | 1001 | The only UID allowed to connect to the boxout socket (also chowns the socket, the binding region and state.json). The shipped k8s manifests pass the reserved sandbox uid **65536** EXPLICITLY rather than relying on this built-in default, and `e2e/deploy-tree-pins.sh` (U22) fails a deploy tree that drops the flag or reverts to a collidable uid. |
| `-client-token-file` | "" (UID-only admission) | Enables a per-connection HMAC-SHA256 challenge-response in addition to SO_PEERCRED: the peer credential authenticates a UID, not the sandlot process, so a foreign pod that merely shares the uid could otherwise drive root boxout. The token is read at startup (created 0400, owner `allowed-uid`, if absent) and **never crosses the wire** — the server sends a fresh nonce, the client returns `HMAC(token, "client:"+nonce)` plus its own nonce, and the server proves itself with `HMAC(token, "server:"+clientNonce)`; a failed MAC ends the connection before any request is read. Must live in a pod-private directory readable only by the sidecar pair and must match sandlot's `-boxout-token-file`. Empty = UID-only admission — not for production. |
| `-allow-insecure-volumes` | false | Admit a `volumes_dir` that is NOT on a `nosuid,nodev` mount (dev/test only). Production never sets it: the gate is what makes guest-planted setuid bits and device nodes on the shared tree inert. |
| `-max-vms` | 256 | Maximum concurrent VMs boxout will launch (`0` = unbounded). Enforced at `create_vm` admission time together with the memory cap below. |
| `-max-total-memory-mb` | 0 (80% of host MemTotal) | Aggregate guest memory cap in MiB across all VMs boxout has launched (`0` = the 80%-of-MemTotal default). A `create_vm` that would exceed it is refused at admission. |
| `-network-backend` | "" (from config) | `none` \| `bridge` \| `routed-ipv6`. In boxout mode the network provider is built here, not in sandlot. |
| `-bridge` | "" (from config) | Host bridge name (bridge backend). |
| `-subnet` | "" (from config) | Guest subnet (CIDR). |
| `-gateway` | "" (from config) | Guest gateway / host bridge IP. |
| `-dns` | "" (from config) | Comma-separated guest DNS nameservers. |
| `-egress-baseline` | "" (from config; `on` when unset) | Egress network baseline: `on` \| `off`. Auto-disabled with a warning when nftables is unavailable. |
| `-vm-to-vm-policy` | "" (from config) | Guest-to-guest posture: `deny` (config default) \| `allow`. |
| `-network-v6-prefix` | "" (from config) | Routed-ipv6 site prefix (config default `fd00:5341:4e44::/48`). |
| `-iid-template` | "" (from config) | IPv6 IID layout for identity-in-address. |
| `-version` | — | Print the version (version / commit / build time) and exit. |

> **Flag names differ from sandlot's.** Sandlot says `-network-bridge`/`-network-subnet`/`-network-gateway`/`-network-dns`; boxout shortens them to `-bridge`/`-subnet`/`-gateway`/`-dns`. `-socket`, `-config`, `-egress-baseline`, `-vm-to-vm-policy`, `-network-v6-prefix`, and `-iid-template` are spelled the same on both.

## 2. Shared sandlot YAML

**Background.** Boxout reuses `sandlotconfig.LoadFromFile`, so the YAML keys and defaults are exactly sandlot's. Boxout reads:

| YAML section | Used for |
|---|---|
| `network.*` (backend, bridge, subnet, gateway, dns, egress_baseline, vm_to_vm, v6_prefix, iid_template) | Building the network provider — in boxout mode this is the only place it is built, since sandlot delegates networking. |
| `network.bind_backend: bpf` + `network.bind_path` | Boxout creates and pins the BPF binding region and hands it to the unprivileged sandlot (see below). |
| `microvm.*` + `vmm_binary` | VMM defaults (kernel, initramfs, vcpus, memory, volumes_dir, overlayfs_templates) for VMs it launches. |

Sandlot-only sections (`pool`, `specs`, `recycle`, `stream`, `resilience`, `tls`, `instance`) are ignored by boxout. Typically both containers mount the same ConfigMap.

## 3. Hot-reload: the shared microvm.* subset

When `-config` is set, boxout watches the shared sandlot YAML and hot-applies the `microvm.*` subset sandlot also classifies hot: `kernel`, `initramfs`, `default_vcpus`, `default_memory_mb` (new VMs only). Everything else in the file — `network.*` included — is logged as restart-required and not applied.

**Why boxout needs this at all:** `create_vm`'s parameter whitelist compares the kernel/initramfs paths sandlot sends against boxout's own VMM defaults. Without a hot-reload on the boxout side, a sandlot-side `microvm.kernel` hot-reload (a new kernel image) would have every subsequent `create_vm` **rejected** ("kernel path not allowed") until boxout restarts — the two must move together.

Known transient: the two processes watch the file independently, so a reload can land in boxout up to ~one watch-interval after sandlot's. A `create_vm` racing that window fails once and the node's 60s pool reconcile refills; no cross-process coordination is worth that complexity. `microvm.warden_*` are restart-required in sandlot, so a file edit changing them lands in boxout's restart-required warnings (never applied live) — the warden cmdline is built sandlot-side and crosses as an opaque `kernel_cmdline` the whitelist never inspects.

## 4. Socket security

**Background.** The socket grants root-equivalent power (launch VMs, mount filesystems, provision network), so it is locked to exactly one peer UID:

- **Private directory + entry-level enforcement**: the socket lives in boxout's own root-owned `0711` directory (created/re-shaped at startup, Lstat-verified: a directory, not group/world-writable). After `listen` the socket entry is secured by `Fchownat`/`Fchmodat` with the no-follow flag (AT_SYMLINK_NOFOLLOW) on the DIRECTORY fd, then re-`fstatat`'d and refused unless the inode/device are unchanged and the type/uid/mode are exactly socket/`allowed-uid`/`0600` — there is no path-based chmod/chown window and no fchmod on the listener descriptor (which would act on the sockfs inode, not the filesystem entry). A pre-existing non-socket path is fatal.
- **Peer-credential verification (SO_PEERCRED)**: on every accepted connection, boxout reads the kernel-supplied credential of the connecting process and **rejects any connection whose UID ≠ `-allowed-uid`**. The credential is kernel-enforced and cannot be forged by the caller.
- **Optional HMAC challenge-response** (`-client-token-file`): see §1 — per-connection, fresh nonces both directions, constant-time MAC comparison, before any request is read.
- **Client-side dial verification** (sandlot): `Lstat` requires a Unix socket owned by root or the caller's euid with no group/world write bits, the peer credential must name root or the caller's euid, and the HMAC handshake (when a token is configured) must succeed — a swapped socket or a fake peer is refused before any request body is sent.
- **Traversable sandbox root**: `/run/sandswap/vm` is forced to `0711` so the unprivileged sandlot can reach the per-VM sandvmm API sockets inside (traverse without list).
- **BPF binding region handoff**: `-allowed-uid` owns the handoff (bpffs root and pin directory made traversable `0711`, the pin chowned `allowed-uid` with mode `0660`, so sandlot can write through its mmap without `CAP_BPF`). The sandvmm API sockets are NOT chowned by boxout — sandvmm itself owns them, widened to the shared group via `--api-gid` (`0660`; without it they stay `0600` owner-only).

## 5. Request hardening

Boxout does not trust sandlot-supplied paths, sizes, or addresses:

- `create_vm` accepts only the **pre-configured** kernel/initramfs/volumes_dir (anything else is rejected); `vcpus` must be an integer in [1,16], `memory_mb` an integer in [MinBootMemoryMB, 8192], and `guest_cid` an integer inside the configured CID range (floor 3; `0xFFFFFFFF` is never admissible). Admission reserves under the lock against `max_vms` and `max-total-memory-mb`, and a failed launch releases the reservation.
- `sandbox_dir` must be exactly `<instance sandbox root>/<vm_id>` with no symlink component; volume paths are resolved relative to the volumes root with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` and must be a single direct child (the `.template` marker is read through the same contained fd).
- **Network**: `release_network` requires the vm id to be a live lease this boxout instance holds; `reclaim_network` refuses a duplicate id, applies the same `max_vms` admission, and derives the network spec from the persisted state — never from caller-supplied addresses. The per-TAP anti-spoof rules are replayed on reclaim (failure refuses it), and routed-ipv6 refuses a subnet already reserved by another VM.
- **Destroy/re-adopt**: destroying an untracked VM validates the sandbox dir, discovers the sandvmm through its socket, kills via pidfd (a signal failure FAILS the destroy rather than leaking a live process under removed state), releases the network lease, and only then removes state; re-adopt requires the request's sandbox root to be this instance's own and registers reclaimed network leases.
- **Overlay tracking** is bounded (4096 entries), overlay-only (a flat volume is never tracked), and persisted only when the tracked set changes; the overlay state file is written atomically.
- **Process identity**: the `/proc` scan verifies argv, `/proc/<pid>/exe` basename (`sandvmm`/`sandswap-sandvmm`), the expected API socket, and the socket owner uid, and kills through a pidfd opened before verification — argv alone is forgeable.

These are code constants, not configuration.
