---
title: Sandlot
nav_order: 2
parent: Configuration
grand_parent: Operations
---

# Sandlot Configuration

> Sources: `sandlot/cmd/main.go` (CLI flags) + `sandlot/config/config.go` (YAML structure, defaults, reload classification) + `sandlot/core/reload.go` (reload application) + `sandlot/core/runner.go` (resilience reconnect state machine).
> Two entry points: CLI flags alone, or `-config <yaml>` plus flags. Only flags **explicitly set** on the command line override the YAML value (unset flags fall through to the file, then to built-in defaults).
>
> **Hot-reload vs restart**: when `-config` is set, the file is watched (fsnotify, debounced) and hot-reloadable fields apply live; everything else is logged as "requires restart". CLI flags always take effect at process start. See the `classifyField` summary at the bottom.
>
> The [Gateway](gateway.md) page documents the other end of the stream; the cross-component invariants (stream windows, 16 MB FileOp chain, exec-timeout ceiling) involve both.


**Role applicability.** Which sections matter for which `-roles` value. A
knob outside an instance's role list is accepted but inert there — and the
refusals in §11 are the hard edges (a prov-only instance rejects exec
machinery outright).

| Section | exec | prov | exec,prov (merged) |
|---|---|---|---|
| §1 Node identity / top level | ○ (per-row) | ○ (per-row) | ○ |
| §2 microVM defaults | ○ | — | ○ |
| §3 Specs and pool | ○ | — | ○ |
| §4 Recycle | ○ | — | ○ |
| §5 Resilience timings | ○ | ○ (no mounts to clean) | ○ |
| §6 Stream transport | ○ | ○ | ○ |
| §7 Network | ○ | — (prov refuses non-`none`) | ○ |
| §8 Egress binding + baseline | ○ | — | ○ |
| §9 TLS | ○ | ○ | ○ |
| §10 Go runtime GC pacing | ○ | ○ | ○ |
| §11 Roles + provision block | `roles` only | ○ (the whole `provision.*` block) | ○ |
| §12–§14 Logging / example / reload summary | ○ | ○ | ○ |

---

## 1. Node identity / top level — restart-required
**Scope:** all roles; the per-row Used by column marks the exec-only knobs (`vmm_binary`, `vm_mode`, `boxout_socket`, `setfs_transport`).

**Background.** A sandlot is one node: it owns the microVMs on a host, dials exactly one outbound gRPC stream to a gateway, and identifies itself in every heartbeat. `node_id` names the node in etcd records (ownership placement, presence), so it must be stable across restarts — the hostname default works on bare metal.

| CLI flag | YAML key | Default | Meaning | Used by |
|---|---|---|---|---|
| `-config` | — | "" | Path to the YAML config file (optional; enables the hot-reload watcher). | all |
| `-version` | — | — | Print the version (version / commit / build time, ldflags-stamped by `build/build.sh`) and exit. | all |
| `-gateway-addr` | `gateway_addr` | `localhost:9998` | Gateway stream address (host:port or DNS name; production uses the stream DNS name, single-node uses localhost). | all |
| `-node-id` | `node_id` | "" (hostname) | Unique node identifier. Keys under `/sandswap/node/{id}/` hang off it. | all |
| `-vmm-binary` | `vmm_binary` | `sandvmm` | Path to the sandvmm binary. | exec |
| `-vm-mode` | `vm_mode` | `embedded` | `embedded` = sandlot is privileged and manages sandvmm directly; `boxout` = sandlot is unprivileged (UID 65536, the reserved sandbox identity) and delegates privileged lifecycle ops to a [Boxout](boxout.md) sidecar over a Unix socket. | exec |
| `-boxout-socket` | `boxout_socket` | `/run/sandswap-boxout/boxout.sock` | Unix socket path for boxout mode (must match boxout's `-socket`). The default lives in boxout's own root-owned 0711 directory, NOT the sandlot-writable `/run/sandswap`. | exec |
| `-boxout-token-file` | `boxout_token_file` | "" (UID-only admission) | File holding the per-pod admission token presented to boxout on every socket connection. Boxout verifies it in addition to SO_PEERCRED: the peer credential authenticates a UID, not the sandlot process, so without the token any process that merely shares the sandbox uid could drive root boxout. Must match boxout's `-client-token-file`; set both sides in production boxout deployments. | exec |
| `-roles` | `roles` | `["exec"]` | Capability sets this instance serves: `exec` (microVM lifecycle/mount/exec), `prov` (sandfs + template lifecycle on shared storage — §11), or `exec,prov` (merged, single-node). Restart-required. **One sandlot process per host** (role-lock on `/run/sandswap/sandlot.role`; the refusal names the three blessed shapes). `-allow-colocated-instances` is the simulation-only escape hatch — a duplicate `node_id` is refused even with it. | all |
| `-setfs-transport` | `setfs_transport` | `raw` | Transport for the sandvmm hot ops (`vm.set-fs` on every cold attach + lease-expiry clear, `sandvmm.ping` probes): `raw` = binary control frames on the same API socket (no HTTP/JSON framing — the fastest path; budgets aligned with the HTTP envelope, see [protocols](../../reference/protocols.md)), `http` = the legacy REST form. Restart-required (fixed at process start before any VMM client exists). | exec |
| — | `instance.id` | "" | Multi-instance suffix: run several sandlots on one host. Effective node id becomes `<node_id>-<instance.id>`, and per-VM state moves under `instance.base_dir/<id>/vm`. | all |
| — | `instance.base_dir` | `/run/sandswap` | Parent directory for per-instance VM state (used only when `instance.id` is set). | all |
| — | `instance.cid_range_start` | 3 | First guest vsock CID the instance may allocate (avoid overlap between instances). **Minimum 3** (0/1/2 are reserved AF_VSOCK CIDs) — lower values are rejected by the config validation. | all |
| — | `instance.cid_range_end` | 0 (unbounded) | Last guest vsock CID; 0 = no upper bound. When set it must be **> `cid_range_start`** (an inverted range exhausts allocation immediately) — validated. | all |

## 2. microVM defaults — kernel/size hot-reload, paths restart-required
**Scope:** exec instances (a prov instance touches no VMM).

**Background.** These are the defaults for VMs created outside a named spec (pool pre-create uses spec entries instead; see §3). The kernel/initramfs/CPU/memory values hot-reload and affect **newly created VMs only** — running VMs keep what they booted with. The two directory paths shape host-side state and are restart-required.

| CLI flag | YAML key | Default | Reload | Meaning |
|---|---|---|---|---|
| `-kernel` | `microvm.kernel` | `/usr/local/lib/sandswap/guest/vmlinux.bin` | hot | Path to the PVH kernel image every microVM boots. The default is the root-owned guest TCB directory (0755 root:root, outside every service identity's write reach) — the kernel executes every in-VM clear, so it must never live in the service-writable state root. When both TCB files resolve under that directory, an exec-role start requires a root-owned SHA256SUMS file beside them and verifies both hashes before booting; a mismatch is fatal. Paths outside the directory (dev/e2e) log that the hash check was skipped. |
| `-initramfs` | `microvm.initramfs` | `/usr/local/lib/sandswap/guest/initramfs.cpio.gz` | hot | Path to the initramfs containing the warden; same TCB directory and hash verification as `-kernel`. |
| `-default-vcpus` | `microvm.default_vcpus` | 2 | hot | Default vCPUs. **Minimum 1** — a negative CLI flag would silently wrap in the int→uint32 conversion and every VM creation would fail; validated at startup and on hot-reload. |
| `-default-memory` | `microvm.default_memory_mb` | 512 | hot | Default memory (MiB). **Minimum 64** (`MinBootMemoryMB` — a smaller VM cannot boot the kernel + warden); same wrap/validation note as vcpus. |
| `-volumes-dir` | `microvm.volumes_dir` | `/var/sandswap/volumes` | restart | Host directory shared into every VM through the single virtio-fs device (`tag=sandswap`). Must be the same shared filesystem the gateway's `-vol-root` points at. |
| `-allow-insecure-volumes` | — | false | DEV/TEST ONLY: start even when `-volumes-dir` is not on a `nosuid,nodev` mount. The virtio-fs passthrough stores guest-planted setuid bits and `mknod` verbatim, and only those mount flags make them inert on the host (storage contract row 9, [storage](../storage.md)). Production fixes the mount instead — self-bind + `remount,bind,nosuid,nodev`, which the bare-metal deployer's `ss_harden_volumes_mount` performs; e2e trees pass the flag deliberately. | exec |
| `-allow-missing-vsockguard` | — | false | DEV/TEST ONLY: start an embedded exec node without a valid root-written vsockguard attestation. The sandlot service uid cannot read bpffs (`/sys/fs/bpf` is root-only), so `security/vsockguard-attach.sh` (root) writes `/run/sandswap/vsockguard.allowed_uid` after a successful attach and the systemd unit's root `ExecStartPre` re-proves the live pin at every start; a non-root sandlot requires that file to be root-owned, non-writable and to name its own uid. A missing/mismatched attestation refuses unless this flag is set (loud WARN). Root-run sandlots skip the check (root is a trust root and the BPF hook admits root); boxout-mode sandlots skip it because the host-setup unit owns the guard. | exec |
| `-overlayfs-templates` | `microvm.overlayfs_templates` | "" (falls back to the sibling `templates/` dir beside `-volumes-dir`) | restart | Overlay template cache directory for OverlayFS lazy mount. When empty, the exec role reads lowerdirs from the same sibling store the prov role writes — keep the two flags pointing at one place or set both explicitly. |
| `-warden-max-exec-timeout-sec` | `microvm.warden_max_exec_timeout_sec` | 0 (warden default 180) | restart | Passed to the warden as `warden.max_exec_timeout` via the kernel cmdline. See [Warden](warden.md). |
| — | `microvm.vmm_uid` | 987 | restart | sandvmm identity uid (contract-pinned). The spawn wraps through setpriv: the VMM + FUSE passthrough daemon run as this uid with **zero capabilities**. The network provider creates the persistent TAP owned by this uid and pre-configures its MTU/bridge/up state, so the VMM attaches by owner match (TUNSETIFF) and skips the privileged MTU/enable ioctls. 0 (with `vmm_gid`) = no transition. |
| — | `microvm.vmm_gid` | 987 | restart | sandvmm primary gid; must be set together with `vmm_uid`. |
| — | `microvm.vmm_groups` | `kvm,985` | restart | Supplementary groups for the sandvmm child — numeric gids or group NAMES (names resolve per host, e.g. `kvm`; numbers carry contract pins, e.g. 985 = the sandlot shared group for volume writes + the API-socket group grant). The spawn REPLACES the child's supplementary set with exactly this list (`setpriv --groups`; `--clear-groups` when empty) — it never inherits the parent's, so the merged exec,prov sandlot's `sandprov` grant (for reading the volume-name seed) does not reach the VMM/FUSE passthrough daemon. |
| — | `microvm.api_gid` | 985 | restart | Group granted connect access to the sandvmm API sockets (0660 owner:group via `--api-gid`). Must be a group `vmm_groups` contains and one sandlot belongs to. Mandatory >0 when `vmm_uid` is set (validated). k8s/boxout: set to the pod's shared group (fsGroup). |
| — | `microvm.vmm_seccomp` | `true` | restart | sandvmm `--seccomp` mode: `true` enforces the v28 per-thread allow-lists (Trap/SIGSYS), `log` installs them in audit mode (a missed rule is logged and allowed), `false` = no filter (the explicit escape hatch). `process` (KillProcess) is rejected: it installs empty per-thread filters. The default was promoted after `e2e/vmm-seccomp.sh` proved both phases green (log mode: zero RET_LOG hits across the battery; enforce mode: whole battery passes). A future VMM syscall that the allow-list misses traps that thread — re-run the gate before changing the lists. |
| `-vmm-api-auth` | `microvm.vmm_api_auth` | true | Enable the per-VM sandvmm API token/challenge handshake (default ON: DAC + `--api-allowed-uid` alone put the API behind one uid boundary, shared by the FUSE passthrough daemon). Set `false` only for test tooling that drives the socket directly. When on, each VM gets a 32-byte random token delivered over an inherited fd, and every canonical-socket connection starts with a transport-independent challenge-response preface (it applies to both raw and HTTP framing). When off, the socket relies on DAC + `--api-allowed-uid` alone. Restart-required; in boxout mode set the YAML key (boxout reads the shared config). | exec |
| `-warden-log` | `microvm.warden_log` | "" (warden default info) | restart | Warden log level via the kernel cmdline. Deliberately NOT hot-reloadable: `debug` puts per-op timing lines on the guest console (hvc0 → `console.log`; the legacy UART cost ~83 µs/char), on the measured path — an online flip would enable that across every new VM at fleet scale, so the restart is the safety gate. A `microvm.*` hot-reload preserves the startup value (never drops it). |
| `-init-on-free` | `microvm.init_on_free` | false | restart | Guest kernel free-time page wipe, written as an explicit `init_on_free=` token on every VM's kernel cmdline (the effective cmdline is persisted in state.json, so the posture is auditable per VM). The guest kernel builds with `INIT_ON_FREE_DEFAULT_ON`, whose boot-time bulk clear of all guest RAM is redundant in a fresh microVM — the VMM's guest RAM is host anonymous mmap (untouched pages are already host-zero) and no tenant has run — while the measured boot cost is linear in RAM (~0.65 ms/MB on nested virt; boot becomes RAM-independent with the override). `init_on_alloc` stays on either way (separate kernel static key) and keeps the cross-tenant "next allocation reads the previous tenant's freed pages" channel closed. Set `true` only for deployments that require the stronger wipe (contents zeroed at free time as well — shorter lifetime after free, stale-mapping defense); that mode also keeps the per-free memset on exec teardown. Security-posture knob, restart-required like `vmm_seccomp`/`vmm_api_auth`; boxout mode reads the shared YAML. |

## 3. Specs and pool — pool hot-reload, specs restart-required
**Scope:** exec instances.

**Background.** A *spec* is a named VM shape; the *pool* pre-creates CLEAN VMs per spec so first exec on a node is warm. `pool` is a `spec:count` list parsed against the specs map; editing it live resizes the pool in **both** directions (scale-up creates, scale-down destroys idle excess; busy VMs are destroyed on their next unmount). Specs themselves are read at startup; a restarted sandlot also re-converges the live pool to the configured target.

| CLI flag | YAML key | Default | Meaning |
|---|---|---|---|
| `-pool` | `pool` | "" (no pool) | Comma-separated `spec:count` pairs, e.g. `small:2,medium:3,large:1`. Empty = no pre-created pool (VMs are created on demand). |
| `-vm-create-concurrency` | `concurrency.vm_create` | 5 | Maximum microVMs booting at once during a pool scale-up, the 60s reconcile fill, or startup pre-create. Restart-required. |
| `-vm-destroy-concurrency` | `concurrency.vm_destroy` | 10 | Maximum idle microVMs destroyed at once during a pool scale-down. Restart-required. |
| — | `specs.<name>.vcpus` | (below) | vCPUs for the spec. **Minimum 1** — a zero-vCPU spec is rejected at parse time (both startup and hot-reload go through the parser) instead of failing later inside KVM with a confusing per-VM error. |
| — | `specs.<name>.memory_mb` | (below) | Memory (MiB) for the spec; minimum 64 (smaller specs are rejected at parse time). |
| — | `specs.<name>.exec_slots` | (below) | Per-VM sync-command concurrency = warden connection-pool size (one in-flight request per vsock connection). `0`/omitted = 1 (serial — the memory-safe fallback for custom specs that don't declare it). |

Built-in spec defaults (bare-metal sizing; nested-virtualization hosts override via `-config`):

| Spec | vcpus | memory_mb | exec_slots |
|---|---|---|---|
| `small` | 2 | 256 | 3 |
| `medium` | 4 | 1024 | 4 |
| `large` | 8 | 2048 | 5 |

Hard limits enforced at startup **and** at hot-reload (a rejected reload keeps the previous pool target):

- **Memory overcommit**: total pool memory (`Σ count × memory_mb`) must fit within 80% of host `MemTotal`, or the node refuses to start / refuses the edit.
- **Boot floor**: `memory_mb` ≥ 64 per spec.
- A pool self-heal pass runs every 60s to refill gaps left by transient creation failures.

## 4. Recycle — hot-reload
**Scope:** exec instances.

**Background.** VMs are recycled (destroyed and replaced at the next unmount) when they wear out. `max_uses` bounds the cumulative commands served (execs and file ops, warm and cold, counted per command); the two memory thresholds catch guest memory fragmentation/leakage. The effective memory threshold is the **lower** of the enabled ones (percent decides on small VMs, absolute MiB on large ones), clamped to ≤ 50% of MemTotal.

| CLI flag | YAML key | Default | Unit | Meaning |
|---|---|---|---|---|
| `-max-uses` | `recycle.max_uses` | 100000 | count | Destroy+recreate a VM after it serves this many commands (execs and file ops alike, warm and cold; -1 = unlimited, 0 = disable; any other negative is rejected at startup and on hot-reload). Default raised from 10000 (itself raised from 50): a freshly recycled VM's first ops carry a cold-guest tax (and an occasional ~20 ms tail, ~1/160 cold ops) — at 100000 the recycle effectively only fires on the memory thresholds, and a node restart/redeploy replaces VMs anyway. |
| — | `recycle.max_mounts` | 10000 | count | Destroy+recreate a VM after this many cold mount generations (one per successful attach; warm ops do not count; -1 = unlimited, 0 = disable). |
| — | `recycle.max_distinct_agents` | 300 | count | Cap on distinct agents one VM may serve over its lifetime; a new agent on a VM at the cap is refused at selection (or the VM is recycled). -1 = unlimited, 0 = disable. |
| — | `recycle.affinity_vms` | 3 | count | How many recently-used VMs a sandfs prefers to reuse (best-effort in-memory affinity; 0 disables). |
| `-recycle-mem-percent` | `recycle.mem_percent` | 10 | % | Recycle when guest `MemAvailable < MemTotal × this / 100` (0 = disable). |
| `-recycle-mem-abs-mb` | `recycle.mem_abs_mb` | 100 | MiB | Absolute recycle threshold of guest MemAvailable (0 = disable). |
| `-min-idle-floor-frac` | `recycle.min_idle_floor_frac` | 0 (disabled) | fraction | Maintain per-spec CLEAN headroom of `max(1, floor(frac × target))` on top of the pool target, so a spare CLEAN VM always absorbs a burst (dampens zero-clean load shedding). `0.05` = 5%. |

## 5. Resilience timings — restart-required
**Scope:** all roles — the values ride `NodeHello.timing` on every connection; the tolerance/cleanup semantics bite where mounts exist (exec instances; a prov instance holds no mounts).

**Background.** The tolerance-first model: when the stream to the gateway breaks, the sandlot first *tolerates* (mounts are kept so in-flight vsock commands finish), then *cleans* (releases mounts within a budget), then *isolates* (waits before reconnecting). The warden's in-VM countdown is the last-resort backstop. These four values are sent to the gateway in `NodeHello.timing`; the gateway derives its presence-key TTL `T_safe = T_tolerance + T_warden + 60s` from them and **rejects the connect** if the ordering invariants below are violated. The phase is persisted across sandlot restarts (a restart never resets the tolerance clock).

| CLI flag | YAML key | Default | Meaning |
|---|---|---|---|
| `-tolerance-sec` | `resilience.tolerance_sec` | 300 | **T_tolerance**: stream-outage grace before the sandlot starts cleaning mounts. During it, only the preferred gateway is re-dialed and ownership is untouched. |
| `-cleanup-sec` | `resilience.cleanup_sec` | 300 | **T_clean**: time budget for the concurrent unmount sweep. Unmount failures and overruns are force-destroyed (destroy-and-replace). |
| `-warden-countdown-sec` | `resilience.warden_countdown_sec` | 300 | **T_warden**: the warden's single countdown, reset only by OP_MEM_STATS heartbeats; expiry with a live mount exits the warden (killing the VM). Passed to each VM via the kernel cmdline as `warden.warden_countdown_sec`. |
| `-isolation-sec` | `resilience.isolation_sec` | 720 | **T_isolation**: wait after cleanup before reconnecting — past T_safe, so no new gateway can mount this node's shared sandfs before every old mount is gone. |
| `-allow-short-resilience-timings` | — (CLI only) | false | **DEBUG/TEST ONLY**: permits sub-300s T_tolerance/T_clean/T_warden. Short timings collapse the tolerance window and reintroduce the double-mount race the tolerance model eliminates — never set in production. |

**Invariants (validated at startup; the gateway re-checks them at connect):**

- `T_clean ≤ T_warden` — cleanup must always finish before the countdown backstop fires at `T_tolerance + T_warden` (fatal at startup if violated).
- **300s production floor**: T_tolerance, T_clean, T_warden must each be ≥ 300s unless `-allow-short-resilience-timings` is set (fatal otherwise).
- `T_isolation > T_safe = T_tolerance + T_warden + 60s`.
- **Exec vs countdown bounds** (fatal unless `-allow-short-resilience-timings`): `warden-countdown-sec` must be strictly greater than the warden's effective max exec timeout (`-warden-max-exec-timeout-sec`, or the warden default 180 when unset — the warden raises its countdown to it, which would invalidate the gateway's T_safe proof), and greater than `warden-max-exec-timeout-sec + 30s` (the transport read margin: a max-length exec's read racing the warden's timeout response could let a retry re-execute a command that already ran). Under the escape flag the read-margin violation downgrades to a warning.
- **Hard ceilings** (fatal): `-warden-max-exec-timeout-sec` ≤ 3600 s and `-warden-countdown-sec` ≤ 4200 s — the warden refuses larger values at boot too.

## 6. Stream concurrency / transport — restart-required
**Scope:** all roles — exec streams carry VM commands, prov streams carry provision commands.

**Background.** All VM commands from the gateway are multiplexed over one bidi gRPC stream. These knobs size that pipe — how many in-flight commands it absorbs, how long a write may block (half-open TCP detection), and the HTTP/2 flow-control windows / max message size. Defaults serve 2000 concurrent commands and 16 MB FileOp payloads; dial options and the command semaphore are fixed at startup.

| CLI flag | YAML key | Default | Unit |
|---|---|---|---|
| `-stream-send-buffer` | `stream.send_buffer_size` | 2000 | commands (sendCh capacity). **Minimum 1** |
| `-stream-recv-buffer` | `stream.recv_buffer_size` | 2000 | commands (recvCh capacity). **Minimum 1** |
| `-max-concurrent-commands` | `stream.max_concurrent_commands` | 2000 | commands (cmdSem; the (N+1)th blocks). **Minimum 1** |
| `-stream-write-timeout-sec` | `stream.write_timeout_sec` | 30 | seconds. **Minimum 1** |
| `-stream-initial-window-mb` | `stream.initial_window` | 64 | MB (HTTP/2 per-stream window; must be ≥ max message size). **Minimum 1** |
| `-stream-conn-window-mb` | `stream.initial_conn_window` | 128 | MB (HTTP/2 per-connection window). **Minimum 1** |
| `-stream-max-msg-size-mb` | `stream.max_msg_size` | 16 | MB (gRPC max send/recv message size). **Minimum 16** (the FileOp chain floor) |

Deployment rule: gateway `-stream-send-buffer` ≥ sandlot `-max-concurrent-commands` (both 2000); keep the 16 MB cap aligned with the warden limits and the gateway's `stream_concurrency.max_msg_size` (see [Troubleshooting](../troubleshooting.md)).

Local bounds are validated at startup (restart-required knobs — no hot-reload case) via the shared `common/config.ValidateStreamCaps`: every cap ≥ 1, windows within int32 range, `initial_window ≥ max_msg_size`, `initial_conn_window ≥ initial_window`, `max_msg_size ≥ 16 MB`.

## 7. Network — restart-required
**Scope:** exec instances — a prov-only instance refuses any non-`none` backend at startup (§11).

**Background.** Outbound guest networking for pooled microVMs. `none` keeps VMs offline; `bridge` attaches each VM to a host bridge with NAT; `routed-ipv6` gives each VM a routed static IPv6 address (identity-in-address). All of it is built once at startup. In boxout mode sandlot does no networking itself — these keys are then read by the boxout sidecar instead (see [Boxout](boxout.md)).

| CLI flag | YAML key | Default | Meaning |
|---|---|---|---|
| `-network-backend` | `network.backend` | `none` | `none` \| `bridge` \| `routed-ipv6`. |
| `-network-bridge` | `network.bridge` | `br-sandswap` | Host bridge (bridge backend). Startup fails if the bridge is missing or `net.ipv4.ip_forward` is off — run `deploy/setup-network.sh`. |
| `-network-subnet` | `network.subnet` | `10.188.0.0/16` | Guest subnet (CIDR, bridge backend). |
| `-network-gateway` | `network.gateway` | `10.188.0.1` | Guest gateway / host bridge IP. Must be an IPv4 **inside** `network.subnet`, at its first host address (`.1` by convention — the address allocator reserves exactly `.0`/`.1`); validated at provider construction, so a typo fails at startup instead of silently breaking every guest's default route. This is guest-network plumbing, NOT how the sandlot finds the gateway service — that is `gateway_addr` (DNS name or IP both work). |
| `-network-dns` | `network.dns` | `1.1.1.1,8.8.8.8` | Comma-separated guest DNS nameservers. |
| `-network-v6-prefix` | `network.v6_prefix` | `fd00:5341:4e44::/48` | Routed-ipv6 site prefix (multiple-of-8 length, ≤ /48; "SAND" in ASCII hex). |
| `-iid-template` | `network.iid_template` | "" (stamping disabled) | IPv6 IID layout for identity-in-address, e.g. `"agent:32,epoch:32"` or `"deployment:16=42,agent:32,epoch:16"` (identity fields are pinned to exactly 32 bits — a narrower `agent`/`sandfs` field is rejected at startup; `deployment` is the one operator-assigned field, its value written into the template and width-checked at startup). |

> `routed-ipv6` requires a guest kernel with `CONFIG_IPV6=y` — the default `kernel/build.sh` build includes it; only the dev-only `kernel/build.sh download` variant ships the official prebuilt without IPv6.

## 8. Egress identity binding + baseline — restart-required
**Scope:** exec instances.

**Background.** Two independent egress features share the `network.` block. The **binding region** publishes `(tap-ifindex → agent/sandfs)` at mount time for third-party network policy enforcers to read (see [Egress Enabler Contract](../../how-it-works/egress-enabler.md)); `off` (default) leaves the hot path byte-identical to a build without it. The **egress baseline** is nftables anti-spoof + VM isolation (not policy) and is on by default.

| CLI flag | YAML key | Default | Meaning |
|---|---|---|---|
| `-binding-backend` | `network.bind_backend` | `off` | Binding region carrier: `off` \| `shm` (tmpfs file) \| `bpf` (pinned mmapable BPF array). |
| `-require-egress-binding` | `network.require_egress_binding` | false | Refuse to start an exec-role instance when no egress identity enabler is configured (Carrier A `-binding-backend=shm\|bpf`, or Carrier B `-network-backend=routed-ipv6` + `-iid-template`). Unset = a loud startup WARN plus `egress_bindings[].binding = "none"` in `/stats`; production should set it. |
| `-binding-path` | `network.bind_path` | "" (per-backend default) | Region location override. Defaults: `/dev/shm/sandswap-bindings` (shm), `/sys/fs/bpf/sandswap/bindings` (bpf). |
| `-egress-baseline` | `network.egress_baseline` | `on` | `on` \| `off`. Requires nftables. **Fail-closed**: when nftables is missing or the baseline tables cannot be installed, the node refuses to start — set `off` explicitly to accept a per-VM-only deployment (logged as a startup WARN). |
| `-vm-to-vm-policy` | `network.vm_to_vm` | `deny` | Guest-to-guest traffic posture: `deny` \| `allow` (multi-agent systems may allow direct VM-to-VM traffic). |

## 9. TLS (gateway stream client) — restart-required
**Scope:** all roles.

**Background.** The sandlot is the TLS client of the one outbound stream to the gateway. Material is loaded once at startup and reused across reconnects; the SAN verified is the gateway address's hostname (service name), even when a specific gateway IP is dialed. The client certificate's **CN must equal this instance's `node_id` exactly** — the gateway binds the stream hello's declared `node_id` to the presented certificate's CN and refuses a mismatch by name, so one shared pair across nodes does not connect (`deploy/gen-certs.sh --client-cn <node-id>`, `deploy/baremetal/gen-baremetal-certs.sh` with `SANDLOT_NODE_ID=<effective node id>`; k8s mints one Secret per node).

| CLI flag | YAML key | Default | Meaning |
|---|---|---|---|
| `-tls-cert` | `tls.cert` | "" | Client certificate for mTLS. Empty = plaintext (dev only). |
| `-tls-key` | `tls.key` | "" | Client private key (required if `tls.cert` is set). |
| `-tls-ca` | `tls.ca` | "" | CA bundle to verify the gateway server cert. Empty = skip verification. |

## 10. Go runtime GC pacing — restart-required
**Scope:** all roles.

Same mechanism as the gateway ([gateway config §16](gateway.md)): `-gogc` (0 = auto — `GOGC` env var wins if set, else 200; positive = force) and `-gomemlimit` (e.g. `512MiB`; empty = `GOMEMLIMIT` env var wins, else no limit). The collector's mark/assist cycles share the node's cores with the VM command handlers and the VMM threads, so on busy nodes the default 200 halves GC frequency for lower tail latency. On hosts shared with many microVMs, set `-gomemlimit` to a fraction of the sandlot-side memory budget so VM RAM and the Go heap cannot collide unnoticed.

## 11. Roles (exec / prov) — restart-required
**Scope:** `roles` applies to every instance; the whole `provision.*` block is prov-only.

**Background.** A sandlot can serve two capability sets. **exec** is the
classic per-node daemon (VM pool, mounts, exec). **prov** is the storage side:
sandfs + template lifecycle on the shared volumes/templates trees — the work
the gateway would otherwise do in-process. The gateway never
mounts storage; it relays every sandfs/template API call to a prov instance
over the stream.

| CLI flag | YAML key | Default | Meaning | Used by |
|---|---|---|---|---|
| `-roles` | `roles` | `["exec"]` | `exec` \| `prov` \| `exec,prov` (see §1). | all |
| `-templates-dir` | `provision.templates_dir` | "" (resolves to `-overlayfs-templates` when set, else the sibling `templates/` dir beside `-volumes-dir` — same filesystem as the volumes tree) | The layers/ + refs/ template store root (shared with the exec role, which reads overlay lowerdirs from it). | prov |
| `-oci-registry` | `provision.oci_registry` | "" | Registry for pull/push/auto-pull. The egress lives on the PROV host — gateway hosts never reach a registry. | prov |
| `-registry-username` | `provision.registry_username` | "" | Registry basic-auth username (requires `oci_registry`). | prov |
| `-registry-password` | `provision.registry_password` | "" | Registry basic-auth password. Prefer the YAML key over the flag: a flag value is visible in `/proc/<pid>/cmdline`. | prov |
| `-registry-token` | `provision.registry_token` | "" | Registry bearer token; alternative to username/password (basic wins when both are set). | prov |
| `-registry-cert` | `provision.registry_cert` | "" | TLS client certificate file (mTLS); must be paired with `registry_key`. | prov |
| `-registry-key` | `provision.registry_key` | "" | TLS client key file (mTLS); must be paired with `registry_cert`. | prov |
| `-registry-ca` | `provision.registry_ca` | "" | CA bundle for server verification against a private CA; combines with any credential (basic + private CA is the common Harbor shape). | prov |
| `-flat-templates` | `provision.flat_templates_dir` | "" | Startup scan dir for local flat templates (`<dir>/<name>/<version>/` → ref `<name>:<version>`). | prov |
| `-max-provision-ops` | `provision.max_concurrent_ops` | 2 | Concurrent provision commands (GB-scale work must not starvation the host). | prov |
| `-provision-deadline-sec` | `provision.default_deadline_sec` | 300 | Per-op deadline when the gateway sends none (auto-pulls are cancelled at it). | prov |
| `-provision-reconnect-sec` | `provision.reconnect_sec` | 300 | PROV connection recycle age (±20% jitter) for spread rebalance across gateway addresses. Exec connections are sticky and NEVER recycled. | prov |
| `-volume-seed-next-file` | `provision.volume_seed_next_file` | "" | Flag form of the staged next seed (rotation step 1) — see the YAML key's row below. | prov |
| `-volume-seed-file` | `provision.volume_seed_file` | — (REQUIRED for prov) | File holding the volume-name seed (hex or base64, decoded ≥ 32 bytes). Every sandfs directory name is `sf-` + base32(HMAC-SHA256(seed, id)) — see [isolation §4.6](../../how-it-works/isolation-and-swap.md). Prefer the YAML key: the flag value (a path) is visible in `/proc/<pid>/cmdline`; the seed VALUE must never be a flag or a ConfigMap entry. Scope the file like the prov config (root:sandprov 0640): the prov identity reads it at startup AND on every reload, while the sandvmm identity must never be able to (a leaked seed makes every name guessable again); `security/verify-host-security.sh` FAILS when a sandvmm process carries the seed's group. Bare metal: minted once by `sandswap_ensure_volume_seed`; k8s: the `sandswap-volume-seed` Secret, created once by deploy-lib and never regenerated. | prov |
| — | `provision.volume_seed` | "" | Inline seed value (same validation). Mutually exclusive with `volume_seed_file` — both set is refused at load. Prefer the file form. | prov |
| — | `provision.volume_seed_next_file` | "" | **Stages the next seed generation** (rotation window step 1): with it set, the prov instance refuses NEW volume creation (`ErrRotationStaged` — a volume created mid-window would strand in the old generation) while existing volumes keep resolving (current name first, staged name as fallback). Managed by `rotate-volume-seed.sh --stage`; cleared by `--promote`. | prov |
| — | `provision.volume_seed_next` | "" | Inline staged seed; same relation to `volume_seed_next_file` as `volume_seed` to `volume_seed_file`. | prov |
| `-allow-seed-generation-mismatch` | — (CLI only) | false | Start even when the volumes root carries a naming generation NO configured seed derives — deliberate re-key / disaster recovery only, paired with the one-time migration (see [Volume seed](../../integration/volume-seed.md)); volumes stay unresolvable until that migration runs. Does not weaken the promote completeness gate. | prov |
| — | `provision.seed_poll_sec` | 30 (0 = default) | How often (seconds) the prov instance re-reads its seed sources. fsnotify covers local writes; the poll is what still notices a change on filesystems where inotify never fires. Restart-required. | prov |
| — | `provision.quota_stamp_cmd` | "" (disabled) | Storage plane's quota hook, executed as `<cmd> <sandfs-id>` with the **volume path on stdin** (one line; never argv — `/proc/<pid>/cmdline` is world-readable and the path is the seed-derived tenant name) once per freshly seeded volume (empty = no-op; non-empty must be an absolute path; 10s deadline). Exit 0 = stamped; failure refuses the create fail-closed (the provisioning marker stays, so a retry self-heals). The concrete implementation belongs to the storage operator — see the contract in `sandlot/provision/volume/quota.go` and storage contract row 13. Restart-required. | prov |
| — | `provision.max_sparse_bytes` | 8589934592 (8 GiB) | Cap on one file's APPARENT size when `SaveAsTemplate` copies a tenant volume into a template layer. A sparse file's hole is materialized as zeros host-side, so without a cap one file-API write at a huge offset could fill shared storage; the copy also refuses to write more than the destination filesystem's free space minus a reserve. 0 = built-in default. Restart-required. | prov |

The four `volume_seed*` keys are the ONLY `provision.*` keys that
**hot-reload** — staging and promotion are config edits by design (the
rotation window must not restart the prov instance; see
`deploy/baremetal/rotate-volume-seed.sh`). The reload applies a strict
transition table (stage / abort / promote); anything else — a current seed
changing without a staged promotion, a current seed disappearing, editing
while staged — is refused by name and the live namer keeps its previous
state. Seed values are redacted (`(redacted)`) in the reload log; the
observability surface is a one-way 8-hex fingerprint of the generation.

Validation matrix: a **prov-only** instance refuses exec machinery (a `pool`,
`vm_mode: boxout`, or a non-`none` network backend) at startup with a named
error; an `exec,prov` instance is only meaningful against a UNIFIED gateway
(single-node / one-gw topologies). Placement, presence, and sandns never see
prov sandlot instances — they carry zero etcd footprint. Registry credentials are
refused at startup when `oci_registry` is empty (nothing to authenticate to)
or when `registry_cert`/`registry_key` are not set together. Every other
`provision.*` key — credentials included — is **restart-required**: the
registry client is built once at startup, and a credential edit is redacted
(`(redacted)`) in the reload log.

## 12. Logging
**Scope:** all roles.

| CLI flag | Default | Meaning |
|---|---|---|
| `-debug` | `false` | Per-op success-path logging (mount/exec/unmount/file_op timings, VM boot/ready). Off by default: a busy node performs thousands of ops/sec and these lines flood the log AND sit on the response path (unbuffered stdout write before the handler returns). Error/warning lines are always logged. |
| `-warden-log` | "" (warden default `info`) | In-VM warden log level passed via kernel cmdline; also settable (restart-required) as `microvm.warden_log` — see §2. Set `debug` for profiling sessions — per-op hot-path timing lines live at debug because their console drain taxes the measured path. |

## 13. Worked example: sandlot.yaml
**Scope:** merged-shape example; the comments mark the prov-only and exec-only parts.

A representative embedded-mode config (the bare-metal deployer generates this shape — see [Install (bare metal)](../../deployment/install-baremetal.md)):

```yaml
gateway_addr: "sandswap-stream.local:9998"   # DNS name in production;
                                             # localhost:9998 single-node
node_id: "sandlot-X"
vm_mode: embedded
vmm_binary: /usr/local/bin/sandswap-sandvmm
# Merged roles (the single-node / all-in-one shape): this instance is both the
# exec node and the storage side. Compute hosts use roles: [exec]; dedicated
# storage hosts use roles: [prov] + the provision block below.
roles: [exec, prov]
provision:
  templates_dir: /var/sandswap/templates     # layers/ + refs/ store —
                                             # default (unset): sibling templates/
                                             # beside volumes_dir, same filesystem
  flat_templates_dir: /var/sandswap/flat-templates
  # Volume-name seed (REQUIRED on prov): derives every sandfs directory name.
  # File-scoped secret, never inline in a shared file and never a ConfigMap
  # value; minted once by the deploy tooling. Rotation stages a second key:
  #   volume_seed_next_file: /etc/sandswap/volume-seed-next
  volume_seed_file: /etc/sandswap/volume-seed
  # oci_registry: registry.example.com      # egress lives on THIS host
  # Credentials for a private registry (only with oci_registry; this file
  # must then be root-owned 0640 — the deploy tooling scopes it via
  # ss_protect_config):
  # registry_username: robot
  # registry_password: "…"
  # registry_ca: /etc/sandswap/certs/registry-ca.pem   # private CA
  # registry_cert: /etc/sandswap/certs/registry-client.crt  # mTLS (with key)
  # registry_key: /etc/sandswap/certs/registry-client.key

microvm:
  # The deploy tooling installs the TCB pair as vmlinux.bin /
  # initramfs.cpio.gz in this root-only directory (with SHA256SUMS) and pins
  # the paths here. Omit both keys to use the sandlot defaults, which name
  # defaults name .../guest/vmlinux.bin (the deployed artifact's name) — see §2.
  kernel: /usr/local/lib/sandswap/guest/vmlinux.bin
  initramfs: /usr/local/lib/sandswap/guest/initramfs.cpio.gz
  default_vcpus: 2
  default_memory_mb: 512
  volumes_dir: /mnt/sandswap/volumes
  # warden_max_exec_timeout_sec: 0   # 0 = warden default 180; restart-required
  # warden_log: ""                   # "" = warden default info; restart-required (debug taxes the guest console)
  # init_on_free: false              # guest free-wipe posture; false boots with init_on_free=0
                                      # (fast, RAM-independent boot; init_on_alloc stays on). true = the
                                      # stronger wipe for high-security deployments; restart-required

specs:
  small:  { vcpus: 2, memory_mb: 256,  exec_slots: 3 }
  medium: { vcpus: 4, memory_mb: 1024, exec_slots: 4 }
  large:  { vcpus: 8, memory_mb: 2048, exec_slots: 5 }

pool: "medium:5"

recycle:
  # max_uses omitted = default 100000 (recycle effectively fires on the memory
  # thresholds only; a low use-count makes every recycled VM's first ops pay
  # the cold-guest tax)
  mem_percent: 10
  mem_abs_mb: 100

network:
  backend: bridge
  bridge: br-sandswap
  subnet: 10.188.X.0/24
  gateway: 10.188.X.1
  dns: "1.1.1.1,8.8.8.8"

tls:
  cert: /etc/sandswap/certs/sandlot.crt
  key: /etc/sandswap/certs/sandlot.key
  ca: /etc/sandswap/certs/ca.crt
```

## 14. Hot-reload vs restart-required summary
**Scope:** all roles.

- **Hot-reload** (YAML edit applies live): `microvm.kernel`, `microvm.initramfs`, `microvm.default_vcpus`, `microvm.default_memory_mb` (new VMs only; the reload is a partial application — `microvm.volumes_dir`/`overlayfs_templates` and the warden cmdline fields keep their startup values), `pool` (resize both directions, overcommit-checked), `recycle.*`, `provision.volume_seed*` (the rotation window — stage/abort/promote transition table enforced)
- **Restart-required** (logged as a warning, applied on next start): everything else — top level (`gateway_addr`/`node_id`/`vmm_binary`/`vm_mode`/`boxout_socket`), `instance.*`, `specs`, `microvm.volumes_dir`/`microvm.overlayfs_templates`, `microvm.warden_max_exec_timeout_sec`/`microvm.warden_log` (warden debug logging is deliberately restart-gated: an online flip would tax the guest console on the measured path at fleet scale), `microvm.init_on_free` (security-posture knob, like the other posture keys), `stream.*`, `resilience.*`, `network.*` (incl. binding/baseline), `tls.*`, `provision.*` (the registry, its credentials, and the store dirs are all read once at startup)
