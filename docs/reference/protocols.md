---
title: Internal Protocols
nav_order: 4
parent: Reference
---

# Internal Protocol Reference

The wire protocols between Sandswap's components. These are internal
surfaces (not the agent-facing API) — relevant when contributing to
gateway/sandlot/warden or debugging at the transport level. The generated
protobuf (`common/proto/stream/stream.proto`) and the frame handlers in the
source tree are the source of truth; this page is the orientation and the
contracts' shapes.

## gRPC stream: `NodeStream` (gateway ↔ sandlot)

Defined in the protobuf (package `sandswap.stream.v1`), served on the
stream listener (`-stream-addr`, default `:9998`). **Outbound-only from
sandlot**: each sandlot
dials the gateway and maintains one persistent bidirectional stream
multiplexing all commands by `command_id` — one TCP/TLS connection per
node, NAT-friendly, no listener on the sandlot side.

Two command families share that one stream: `VMCommand`/`CommandResponse`
(exec role) and `ProvisionCommand`/`ProvisionResponse` (prov role). The
gateway routes each family only to connections advertising the matching
role; messages are correlated by `command_id`.

```proto
service NodeStream {
  rpc Connect(stream NodeMessage) returns (stream GatewayMessage);
}
```

### Handshake

The sandlot sends `NodeHello`; the gateway validates it and replies
`HelloAck`. The gates run in this order, and every rejection is named:

1. **Protocol version** — the hello's `protocol_version` must be within
   `[StreamProtocolMinSupported, StreamProtocolVersion]` (currently
   `[1, 1]`; an absent field reads as 0 and is rejected the same way). An
   out-of-range hello terminates the stream with an error carrying the
   received and supported ranges; **no** `HelloAck` is sent, so the
   sandlot reports its own handshake failure.
2. **Node identity** — the declared `node_id` must equal the CN of the
   TLS client certificate the connection presented, exactly
   (`gateway/stream/server.go::verifyNodeIdentity`). A mismatch, a
   connection with no client certificate, and a plaintext listener are all
   refused; the refusal is sent as a `HelloAck.reject_reason` before the
   stream closes.
   The certificate ALSO grants the stream roles: each role a connection
   advertises needs a URI SAN `sandswap://role/<role>` (`exec`, `prov`) on
   that same leaf. The TLS layer verifies the CA signature, so the grant is
   issuance-time; a certificate with no role URI authorizes nothing.
3. **Roles** — the advertised role set is checked against the gateway's
   accepted set (see below). An unknown role, or an advertisement with
   **no** accepted role, is refused with a named
   `HelloAck.reject_reason`; a mixed advertisement (for example `exec,prov`
   at an exec-only gateway) is accepted for the roles the gateway serves.

`NodeHello` fields:

| Field | Meaning |
|-------|---------|
| `node_id` | Stable node identity; bound to the client-certificate CN as above. |
| `version` | Build-info string only — never used for decisions. |
| `total_cpus`, `total_memory_mb` | Host capacity for scheduling. |
| `active_vm_ids`, `vms[]` | Live VMs at (re)connect (re-adopted survivors + fresh ones); `vms[].spec_id` feeds the by-spec pool index. Empty `spec_id` means the default spec. |
| `pool_target` | The pool size the instance intends to keep (0 = no pool constraint). |
| `specs[]` | The node's VM spec table (`id`, `vcpus`, `memory_mb`, `exec_slots`); the gateway learns sizing from it. |
| `timing` | Resilience timings in seconds: `tolerance_sec` (T_tolerance), `cleanup_sec` (T_clean), `warden_countdown_sec` (T_warden), `isolation_sec` (T_isolation). The gateway rejects degenerate timings, `T_clean > T_warden`, and `T_isolation <= T_safe` (T_safe = T_tolerance + T_warden + 60 s, the presence-key TTL). |
| `protocol_version` | The stream wire version this sandlot speaks. |
| `roles` | Capability set: `exec` (VM lifecycle, mounts, exec/file ops) and/or `prov` (sandfs + template lifecycle). **Empty means `["exec"]`** — a pre-roles build is an exec node. |

`HelloAck` fields:

| Field | Meaning |
|-------|---------|
| `gateway_id` | The serving gateway's identity. |
| `max_concurrent_vms` | The gateway's per-node in-flight command capacity (its send-queue size). |
| `protocol_version` | **Negotiated echo**: the hello's version, validated into the gateway's range and sent back. The sandlot aborts unless the ack equals the version it sent. |
| `reject_reason` | Non-empty on a named rejection (identity or role). The instance logs it verbatim and moves to the next configured gateway address. |

Named rejection reasons (the leading sentence is the stable part; the
detail names the fix):

- `no TLS client certificate presented — …` (no certificate on the stream).
- `certificate CN "<cn>" does not match declared node_id "<id>" — …`
  (shared or misissued client certificate).
- `unknown roles [<roles>] advertised (known: exec,prov) — …` (a newer
  build's role this gateway does not understand).
- `roles not accepted: instance advertises [<roles>] but this gateway
  accepts [<accepted>] — point prov instances at a human/unified gateway`.

**Node identity binding.** Nodes are addressable state: the gateway routes
a sandfs's VMCommands by `node_id`, so a party that could claim another
node's id would receive that node's commands (agent code, volume paths,
file contents) and its answers would be accepted. Deploy tooling therefore
mints one client certificate per node with `CN=<node-id>`
(`deploy/gen-certs.sh --client-cn <node-id>`,
`deploy/baremetal/gen-baremetal-certs.sh` with `SANDLOT_NODE_ID=<node-id>`,
and one Kubernetes Secret per node). The stream listener always requires a
client certificate: `RequireAndVerifyClientCert` with `-stream-tls-ca`
(verified mTLS), `RequireAnyClientCert` without it (the CN is then
self-asserted). Production deployments configure stream mTLS on both
sides.

**Roles and routing.** Each gateway derives its accepted set from its own
endpoints: an exec gateway accepts `exec`, a human gateway accepts `prov`
(it serves the storage plane's stream listener), and the single-node /
one-gw unified gateway accepts both. VM commands never reach a prov-only
connection and provision commands never reach an exec-only one. Prov
connections are **non-sticky** (each reconnect re-picks an address, plus a
connection-age recycler that spreads instances across gateway replicas)
and carry zero etcd footprint — no presence key, never placement-eligible.

### Version negotiation and rolling upgrades

The gateway accepts a sandlot's `protocol_version` only inside
`[StreamProtocolMinSupported, StreamProtocolVersion]` — currently `[1, 1]`
— and rejects the handshake before the node is registered or `OnConnect`
fires. The ack's negotiated echo then makes both sides agree on ONE
version per connection, and both sides' exact-match check guards every
subsequent command.

The supported upgrade path is **expand → migrate → contract**:

1. **Expand** — deploy the newer binary with the window open
   (`MinSupported` stays at the old version, current bumped). An old peer
   inside the window receives its own version echoed in the ack and keeps
   working. (This applies to the gRPC stream transport; the warden frames are
   version-matched with the sandlot at `[1, 1]` — see below.)
2. **Migrate** — redeploy the rest of the fleet.
3. **Contract** — raise `MinSupported` once nothing speaks the old
   version; a leftover peer then fails one dial with both version numbers
   and the remedy.

Out-of-window mixes fail ONE dial / ONE VM creation — never a silent
semantic misinterpretation, never a destroy loop. The `version` string in
`NodeHello` is build info only.

### VMCommand (gateway → exec sandlot)

Common fields: `command_id` (correlation), and `agent_id` — the
authenticated agent identity, opaque to the node except that it is
required on mount-bearing commands and is recorded in the node's egress
identity binding (tap/IP → agent/sandfs). Exactly one action is set:

| Action | Fields | Purpose |
|--------|--------|---------|
| `MountRootfsAndExecute` | `sandfs_id`, `volume_path`, `volume_epoch`, `command`, `background`, `timeout_ms`, `lease_duration_ms`, `install_packages`, `min_spec`, `template_ref`, `volume_mode` | Combined attach + (sync or background) exec in one RPC; the cold path is one warden `mount_and_exec` round trip, the warm path is exec-only. |
| `UnmountRootfs` | `sandfs_id`, `volume_path`, `volume_epoch` | Bind umount of `/mnt/rootfs` + clear the virtio-fs `allowed_dirs` filter. A different path/epoch names a SUPERSEDED generation: idempotent success without touching the live mount. |
| `StatusExec` | `sandfs_id`, `exec_id` | Poll a background exec (liveness + log tail). |
| `KillExec` | `sandfs_id`, `exec_id` | Kill a background exec's process group. |
| `FileOp` | `sandfs_id`, `action`, `path`, `new_path`, `offset`, `length`, `mode`, `recursive`, `depth`, `data`, `volume_path`, `volume_epoch`, `min_spec`, `template_ref`, `volume_mode` | Unified file I/O (`read`/`write`/`stat`/`list_dir`/`mkdir`/`remove`/`rename`). Mounts rootfs first when `volume_path` is set and not yet mounted. |
| `CleanupOverlay` | `volume_path` | Unmount a host-side read-only overlay before SandFS deletion (avoids EBUSY on removal). |

Field semantics:

- `background` — `true` starts a background exec and returns `exec_id` +
  `status="running"` immediately; `false` blocks until completion or
  timeout.
- `volume_epoch` — the per-create volume generation (128-bit hex). The node
  compares it against the volume's signed `.sandfs-id` stamp; a mismatched or
  empty epoch is refused (pre-epoch volumes are not mountable), so a stale
  record for a reused id cannot mount the new owner's volume. On unmount a
  different `(volume_path, volume_epoch)` than the current binding is a
  superseded generation and is a no-op success.
- `timeout_ms` — sync-exec timeout (0 = the warden's configured default;
  values above the warden maximum are clamped). Ignored by background
  execs, which are bounded by the lease.
- `lease_duration_ms` — background-exec hold time; the gateway resolves an
  omitted agent `lease_duration` to its configured
  `-max-background-lease-sec` cap before sending. Ignored for sync execs,
  which use the default sticky window.
- `install_packages` — retained on the wire for compatibility; the gateway
  fills it from the sandfs mode (flat → true, overlay → false).
- `min_spec` — minimum VM spec the sandfs requires; the node picks the
  smallest CLEAN VM that satisfies it. Empty = any VM.
- `template_ref` — **an empty value is a positive statement: the volume is
  FLAT.** For an overlay volume it is the template ref the gateway's
  identity record expects; the node compares it with the ref its tracked
  host-side overlay was mounted from and, on a mismatch, remounts from the
  volume's `.template` marker (storage truth, written before the record).
  On divergence the marker wins. A non-empty value for a flat volume is
  never sent; an empty value tells the node to mount flat and ignore
  anything at the marker path (in flat mode the volume root is the agent's
  chroot root, so a marker there is agent-written data, not storage
  truth).
- `volume_mode` — the identity record's volume mode (`flat`/`overlay`). The
  node and the warden mount by THIS value; neither probes the volume's
  layout. A flat record with a template ref, an overlay record without one,
  an empty mode, or an unknown value is refused before any mount or filter
  swap. Flat volumes are agent-writable, so the probe is exactly the class
  this field removes: a planted `rootfs/` directory must not be able to
  choose overlay semantics. Added before first production use; both sides
  deploy together (the warden frame window is `[1,1]`; the stream window is
  negotiated), so no version bump.

### ProvisionCommand (gateway → prov sandlot)

The storage-plane vocabulary, routed only to `prov`-advertising
connections. Common fields: `command_id` (correlation) and `deadline_ms`
(per-op deadline; 0 = the node's configured default, 300 s — template
pulls can move GBs). Every op is idempotent (a transport failure retries
the next connected instance); the node re-validates every argument (ids
and refs as single path elements) and resolves all paths itself. The one
exception is `VerifyVolume`'s read-only `rootfs_path` check, where the
node validates the supplied directory against its own volumes root and
`.sandfs-id` stamp; no other op carries a host path — in particular the
gateway never sends one for materialization. The stamp is HMAC-signed with
the volume-name seed generation and binds the volume's directory name; an
unsigned or non-verifying stamp is refused (tampering, or a directory
created by a build that predates signatures — the rotation `--migrate`
re-signs it).

| Action | Fields | Purpose |
|--------|--------|---------|
| `EnsureVolume` | `sandfs_id`, `mode` (`flat`/`overlay`), `template_ref` | Idempotently materialize a volume (mkdir + shared-group layout; seed by mode; auto-pull a missing ref when a registry is configured). A `.provisioning` marker with no signed identity stamp makes a killed run self-healing on retry; a marker beside a valid signed stamp is tenant debris and is cleared without wiping the volume. Returns the volume path and the template's declared min resources. |
| `DeleteVolume` | `sandfs_id` | Remove the volume directory. ENOENT = success. The gateway orchestrates the unmount sweep + overlay cleanup over exec-role connections first. |
| `PullTemplate` | `template_ref`, `mode` (empty = overlay) | Registry → local template store. |
| `PushTemplate` | `template_ref`, `mode` (empty = auto-detect overlay-then-flat) | Local store → registry. |
| `SaveAsTemplate` | `sandfs_id`, `template_ref`, `description`, `vcpus`, `memory_mb` | Flat sandfs volume → local template (0 sizes = the source sandfs's values). |
| `ListTemplates` | — | Local template store listing. |
| `StatTemplate` | `template_ref` | Ref existence + modes + declared min resources — no materialization. |
| `SwapTemplate` | `sandfs_id`, `template_ref`, `home_policy` (`keep`/`archive`/`reset`) | Re-point a DETACHED overlay volume at a new template: validate/auto-pull the ref, apply the `/home` policy (workspace never touched), atomically rewrite the `.template` marker, return the new min resources. Idempotent per (ref, policy). |
| `DeleteTemplate` | `template_ref`, `mode` (empty = auto-detect), `force` | Remove a ref and reachability-GC its unreferenced layers. Refuses with `TEMPLATE_IN_USE` (+ `in_use_count`/`in_use_sample`) while any volume's marker names the ref; flat templates skip the marker scan. `force` skips the in-use check. |
| `VerifyVolume` | `sandfs_id`, `rootfs_path` | READ-ONLY identity check behind the gateway's `rootfs-path` repoint: the directory must be contained under the volumes root and carry a signed `.sandfs-id` stamp naming `sandfs_id` exactly (an unsigned or non-verifying stamp is refused). Never creates or modifies anything. A mismatch is the named class `VOLUME_IDENTITY_MISMATCH`. |

### Responses (sandlot → gateway)

`CommandResponse` (reply to a `VMCommand`):

| Field | Meaning |
|-------|---------|
| `success`, `error` | Outcome and human-readable failure text. |
| `error_code` | Structured class. `NO_AVAILABLE_VM` = no fitting CLEAN VM (the gateway retries another node without marking the sandfs dirty). Empty for successes and for errors without a specific code. |
| `vm_id` | The serving VM. |
| `stdout`, `stdout_raw` | Text output; `stdout_raw` carries binary-safe bytes (FileOp reads) and takes precedence. |
| `stderr` | Standard error (sync exec). |
| `exit_code` | Real process exit code for a completed sync exec (0–255; 128+signum for signal death); 0 for timed-out/background/FileOp results. |
| `exec_id`, `status` | Background-exec handle and the sentinel set `done` / `running` / `killed` / `timed_out` / `expired` / `not_found`. |
| `exec_duration_ns` | Warden-side wall time of the operation this response closes: spawn-to-wait for a warm sync exec; mount + exec for the cold combined op; unmount wall time for `UnmountRootfs`. Zero for other ops and errors. |
| `sandlot_duration_ns` | Sandlot handler total (includes set-fs, vsock RTT, warden execution). |
| `spec` | The actual VM spec that served a mount-bearing op (the gateway corrects its provisional reservation). |

`VMEvent`: `vm_id`, `type`, `message`. Types: `VM_EVENT_CRASHED`,
`VM_EVENT_VSOCK_READY`, and `VM_EVENT_RESOURCE_SHORTAGE` (the node refused
a VM creation for lack of host memory; `message` carries the numbers and
the node does not retry on its own).

`Heartbeat`: `active_vm_count`, `active_vm_ids`, per-VM `vm_mem`
(`mem_available_bytes`, `mem_total_bytes`), per-spec `spec_capacity`
(`clean`, `total`, and the windowed floor/saturation counters),
`metrics` (the node's scheduling signals), and — on **prov** connections
only — the naming-generation fingerprints:
`seed_generation` (the generation names are currently derived from),
`seed_staged` (a rotation window is open), and `seed_staged_generation`
(the staged generation). Fingerprints are one-way 8-hex hashes, never seed
material; the gateway projects them per node in `/stats` so a rotation can
prove every prov instance converged.
Every heartbeat also carries `egress_binding` — the identity-binding mode in
force on the node (`shm`/`bpf` for Carrier A, `routed-ipv6` for Carrier B,
or `none` = guest traffic is not attributable to an agent). `/stats`
projects it per node as `egress_bindings`; an exec-role instance refuses to
start unbound only when `network.require_egress_binding` is set.

`ProvisionResponse`: `success`, `error`, `error_code` (node-side values:
`INVALID_ARGUMENT`, `TEMPLATE_NOT_FOUND`, `TEMPLATE_IN_USE`,
`VOLUME_IDENTITY_MISMATCH`; the gateway maps these to fixed HTTP shapes —
a mismatch becomes a fixed 409 whose raw node text is deliberately not
echoed), `rootfs_path`, `min_vcpus`/
`min_memory_mb`, `modes`, `digest`, `size_bytes`, `push_time_ms`,
`push_layers`, `path`, `size_kb`, `templates[]` (`ref`, `mode`,
`description`, `min_vcpus`, `min_memory_mb`, `name`, `version`), `name`,
`version`, `in_use_count`, `in_use_sample`, `pulled` (the op auto-pulled
the ref — surfaces as `pull_status: "pulled"`), `duration_ns`.

### Concurrency/transport caps

Restart-required knobs, aligned across both sides (defaults serve 2000
concurrent commands and 16 MB FileOp payloads):

| Knob | gateway flag | sandlot flag | Default |
|------|--------------|--------------|---------|
| gateway send queue (in-flight commands) | `-stream-send-buffer` | — | 2000 |
| sandlot outbound send queue | — | `-stream-send-buffer` | 2000 |
| sandlot inbound command queue | — | `-stream-recv-buffer` | 2000 |
| sandlot command concurrency | — | `-max-concurrent-commands` | 2000 |
| write timeout (half-open detection) | `-stream-write-timeout-sec` | `-stream-write-timeout-sec` | 30 s |
| HTTP/2 per-stream window | `-stream-initial-window-mb` | `-stream-initial-window-mb` | 64 MB |
| HTTP/2 per-connection window | `-stream-conn-window-mb` | `-stream-conn-window-mb` | 128 MB |
| gRPC max message size | `-stream-max-msg-size-mb` | `-stream-max-msg-size-mb` | 16 MB |

Deployment invariants: gateway `-stream-send-buffer` ≥ sandlot
`-max-concurrent-commands`; `max-msg-size` ≥ the warden single-op cap
(16 MB); the HTTP/2 per-stream window ≥ `max-msg-size` and sized for
concurrency (see [Gateway configuration](../operations/configuration/gateway.md)
§4 for the full rationale). The gateway's single-op FileOp payload cap is
`max-msg-size` minus 64 KiB of envelope headroom; an oversize data or
length argument is refused with `FILE_TOO_LARGE` before any stream write.

## Warden vsock frame protocol (sandlot ↔ warden)

The warden listens on **vsock port 1024** and speaks a fixed-frame binary
protocol — no protobuf, minimal parsing, one request per connection slot.
Transport: kernel vhost-vsock (zero user-space intermediary; see
[Architecture](../how-it-works/architecture.md)).

### Operations

| Op | Code | Description |
|----|------|-------------|
| `OP_MOUNT_AND_EXEC` | 1 | Mount + sync exec in one RTT (cold path). An EMPTY `command` field means mount-only: establish the mount and skip the exec. |
| `OP_UNMOUNT` | 2 | cgroup.kill + teardown + umount + drop_caches |
| `OP_EXEC` | 3 | Sync exec only (warm path, already mounted) |
| `OP_MEM_STATS` | 4 | Heartbeat: guest MemAvailable / MemTotal |
| `OP_ASYNC_EXEC` | 5 | Start background exec (warm path) |
| `OP_MOUNT_AND_ASYNC_EXEC` | 6 | Mount + start background exec (cold path, one RTT) |
| `OP_STATUS_EXEC` | 7 | Poll background exec status + log tail |
| `OP_KILL_EXEC` | 8 | Kill background exec by exec_id |
| `OP_FILE` | 9 | File I/O: unified sub-opcode dispatch |
| `OP_KEY_DELIVERY` | 10 | First frame on a connection: deliver the per-VM session key (unauthenticated request; response tagged with the delivered key) |

### Request field layouts

The body is a sequence of length-prefixed fields; their **order** is the
op's ABI:

| Op | Fields (index order) |
|----|----------------------|
| `OP_MOUNT_AND_EXEC` | 0 `mount_identity` (this generation's export alias, one component `[A-Za-z0-9._-]{1,64}`), 1 `mount_point` (must be exactly `/mnt/rootfs`), 2 `fs_type` (ignored), 3 `command` (empty = mount-only), 4 `timeout_ms` (ASCII), 5 `install_packages` (`"1"` = true), 6 `volume_mode` (`flat`/`overlay`, from the identity record; empty/unknown is refused) |
| `OP_UNMOUNT` | 0 `mount_point` (must be exactly `/mnt/rootfs`), 1 `mount_identity` (empty only with `forced`), 2 `forced` (`"1"` = tear down without an identity match; reserved for re-adopt/dirty cleanup of a non-selectable VM) |
| `OP_EXEC` | 0 `command`, 1 `timeout_ms` (ASCII), 2 `install_packages`, 3 mounted-volume identity |
| `OP_MEM_STATS` | none |
| `OP_ASYNC_EXEC` | 0 `command`, 1 `install_packages`, 2 mounted-volume identity |
| `OP_MOUNT_AND_ASYNC_EXEC` | 0 `mount_identity` (alias, as above), 1 `mount_point`, 2 `fs_type`, 3 `command`, 4 `install_packages`, 5 `volume_mode` (`flat`/`overlay`) |
| `OP_STATUS_EXEC` | 0 `exec_id` |
| `OP_KILL_EXEC` | 0 `exec_id` |
| `OP_FILE` | 0 `sub_op` (one byte), 1 `path`, then sub-op fields; 5 mounted-volume identity |
| `OP_KEY_DELIVERY` | 0 `session_key` (exactly 32 raw bytes) |

`timeout_ms` 0 (or unparsable) selects the warden's configured default;
values above its maximum are clamped.

### File I/O sub-operations (`OP_FILE`)

| Sub-op | Code | Fields after `path` |
|--------|------|---------------------|
| `SUB_OP_READ` | 1 | 2 `offset` (i64 ASCII), 3 `length` (u64 ASCII; 0 = up to the cap) |
| `SUB_OP_WRITE` | 2 | 2 `offset` (-1 = append), 3 `mode`, 4 `data` (raw bytes) |
| `SUB_OP_STAT` | 3 | — (JSON metadata in the response) |
| `SUB_OP_LIST_DIR` | 4 | 2 `depth` (0 = flat; JSON listing in the response) |
| `SUB_OP_MAKE_DIR` | 5 | 2 `mode` (0 = default; parents created, idempotent) |
| `SUB_OP_REMOVE` | 6 | 2 `recursive` (`"1"`/`"true"`) |
| `SUB_OP_RENAME` | 7 | 2 `new_path` |

All file paths are relative to the sandbox workspace. The warden validates
them (canonicalize + workspace prefix check) against traversal and
symlink escape; opens use `O_NOFOLLOW` on the final component with
revalidation. A read, a listing, and the request body are each bounded
(`max_file_read_bytes`, `max_body_len`, both 16 MiB by default).

### Wire format

**Request**: `[u32 magic][u8 version][u8 op][u32 body_len][u8 nonce[16]][u8
body_mac[32]][tag[32]][body]` (90-byte header) — magic `0x53414e44` (`"SAND"`), `version`
1 (`raw_server.rs::PROTOCOL_VERSION`, window `[1,1]`); the tag covers the
header INCLUDING the op-specific body-field MAC (the warm-op mounted-volume
identity, or a cold mount op's alias/mount_point/volume_mode), and responses
carry a trailing mounted-identity MAC after the mounted segment; the body is a sequence
of `[u32 len][bytes]` fields whose order depends on the op. All integers are
big-endian. A request outside the window is answered with one transport-error
frame carrying the supported range, and the VM is destroy-and-replaced. A body carries at most **64** fields (the ops use at most 6);
the body length is capped by the warden's `max_body_len` (16 MiB default).

**Authentication**: every request carries `tag = HMAC-SHA256(key,
"sandswap.warden.request.v1" || version || op || body_len || nonce)` where
`key` is the per-VM 32-byte session key, generated by the sandlot at VM
creation and delivered over the first host connection with an
`OP_KEY_DELIVERY` frame (op 10, one 32-byte field). The delivery request is
the one unauthenticated frame (the warden has no key yet); it is accepted
only from the host CID, and its response is tagged with the delivered key,
which proves installation. After that every request's tag is verified
BEFORE the body is read; a mismatch closes the connection. The key never
appears on the kernel command line. The nonce is a per-connection random prefix plus a counter,
so generating it costs no syscall. The tag authenticates the fixed header
(key possession); it deliberately does not hash the body — the transport is a
point-to-point kernel vsock channel, and a full-body MAC would tax large file
writes.

**Response**: `[u32 magic][u8 version][u8 code][u8 exit_code][u8
reserved][u32 stdout_len][u32 stderr_len][u64 exec_duration_ns][u32
mounted_len][u8 tag[32]][stdout][stderr][mounted]` (60-byte header). The
response tag is HMAC-SHA256 over the response label, the REQUEST nonce, and
the fixed response fields; the sandlot refuses a response whose tag does not
verify (and destroys the VM). The `mounted`
segment carries the basename of the volume the op left at `/mnt/rootfs`
— non-empty only on successful mount-family ops (`OP_MOUNT_AND_EXEC`
including mount-only, `OP_MOUNT_AND_ASYNC_EXEC`), so the sandlot can
cross-check it against the path it requested even when the exec itself
failed. `exec_duration_ns` is the warden-monotonic wall time of the
operation the frame closes (spawn-to-wait for a warm sync exec, mount +
exec for the cold combined op, unmount wall time for `OP_UNMOUNT`; zero
elsewhere). Responses are written with `writev`; the sandlot client caps
each of the three segments at 32 MiB before allocating.

Response codes (`code` is the single field the client branches on):

| Code | Meaning |
|------|---------|
| 0 | OK — for sync exec, `exit_code` holds the real process code |
| 1 | Application error (VM healthy; message in `stdout`) |
| 2 | Transport/protocol error (invalidate the cached connection; message in `stderr`) |
| 3 | Background exec still running (`OP_STATUS_EXEC`) |
| 4 | Background exec killed (`OP_STATUS_EXEC`/`OP_KILL_EXEC`) |
| 5 | Background exec not found (`OP_STATUS_EXEC`/`OP_KILL_EXEC`) |
| 6 | Sync exec timed out (partial output in `stdout`) |
| 7 | Mount target not exported by the current filter generation (VM healthy; superseded request — nothing mounted, nothing torn down) |
| 8 | Unmount: nothing was mounted (idempotent no-op) |
| 9 | Unmount: the live mount carries a different identity (nothing torn down; `mounted` carries the live identity) |

Background execs do not report an exit code (the warden reaps them without
capturing it); agents that need one should echo `$?` into the captured
log. `OP_STATUS_EXEC` and `OP_KILL_EXEC` deliberately carry no
mounted-volume identity: they execute nothing and resolve no path under
the mounted rootfs, and they must stay answerable after a mount is torn
down.

### Version negotiation

Requests carry the sandlot's version; the warden accepts
`[PROTOCOL_MIN_ACCEPTED, PROTOCOL_VERSION]` — currently **`[1, 1]`** — and
echoes the request's version in the response header. An out-of-range
request is answered with ONE transport-error frame whose header carries
the **warden's own** version and whose message names the supported range,
then the connection closes. Symmetrically, the sandlot classifies any
response whose version differs from its own as `ProtocolVersionError`
(both version numbers in the message): VM creation fails fast, pool
scale-up aborts, and re-adopted survivors from an older deploy are
destroy-and-replaced. Destroying and retrying against the same warden
build is never attempted.

The mounted-volume identity field (below) is part of the current `[1, 1]`
layout; it is not a version-gated addition. Sandlot and initramfs are
deployed together, and a layout change that is not
zero-value-compatible requires changing the constant on both sides.

### Mounted-volume identity (warm ops)

The sandlot appends the identity of the volume its own mount bookkeeping
believes is attached — this generation's export ALIAS, the same value the
mount-family responses echo — at a FIXED field index per op:

| Op | Identity field index |
|----|----------------------|
| `OP_EXEC` | 3 (after command, timeout_ms, install_packages) |
| `OP_ASYNC_EXEC` | 2 (after command, install_packages) |
| `OP_FILE` | 5 (after sub_op, path, and the sub-op's fields; shorter sub-ops are padded with empty fields up to this index) |

**Generation-bound alias.** Every set-fs generation gets a fresh
128-bit alias (32 lowercase hex characters) minted by the sandlot. The same
alias rides the VMM's `vm.set-fs` (as the guest-visible root name) and the
warden mount RPC. After a later set-fs the previous alias is not exported,
so a mount request that lost the race resolves nothing and fails with code
7 before any bind or exec — the VMM root lookup is the atomic gate. The
alias carries no part of the seed-derived volume name. The warden treats the
value opaquely for identity purposes; the mount MODE travels separately in
the mount op's `volume_mode` field and comes from the identity record (never
from a probe of the agent-writable
volume layout). A bare basename is accepted as an unnamed shape; the
sandlot always sends the nonce after a cold mount.

A non-empty identity that does not match the warden's actually mounted
volume is a transport-error response whose message leads with the token
**`volume_identity_mismatch`** — the op is refused **without executing**,
and the sandlot surfaces the message verbatim in the command error. An
empty identity field is refused by name too (**`volume_identity_missing`**):
it is a bookkeeping/protocol failure, not a licence to execute against
whatever happens to be mounted. Only the cold combined mount ops carry no
identity by design (they pass `None`, not an empty field) and establish the
mount themselves.

### Protocol hardening

The warden port is unauthenticated (seccomp does not block socket/connect,
and reachability of the port is a kernel-config property, not a designed
control — see [Isolation and Swap](../how-it-works/isolation-and-swap.md),
"The warden's vsock port"), so the frame layer assumes a hostile peer:

- `mount_point` must be **exactly** `/mnt/rootfs`; anything else is a
  transport error. The sandlot always sends that literal; the pin exists
  so a hostile in-guest connection cannot steer a mount over
  warden-critical guest paths (e.g. `/sys/fs/cgroup`, which would silently
  defeat the per-agent cgroup kill/cap at switch).
- A body carries at most 64 fields; a hostile body of millions of empty
  fields is rejected during parsing instead of allocating unbounded
  headers.
- Malformed frames (bad magic, body over `max_body_len`, truncated field
  headers, a field length past the body end, an incomplete header or body)
  close the connection with no response; an out-of-range version answers
  the single rejection frame described above and then closes; an unknown
  op is a well-formed frame answered with a transport-error response.
  Neither may kill PID 1.
- Concurrent connections are capped at 16; a fresh connection must send
  its first frame within 30 s; in-flight body pre-allocations are bounded
  at 4 × `max_body_len`. A peer beyond the bounds is accepted-then-closed
  or failed silently at a rate-limited warn.
- `output/warden-probe` (`sandlot/cmd/warden-probe`) is the raw-vsock
  client used by `e2e/warden-hostile.sh` to exercise all of the above
  against a live VM.

### Connection discipline

Business traffic uses a per-VM connection pool (up to `exec_slots`
resident connections, one in-flight request each — the slot index is the
correlation key); each slot's receive timeout is re-armed per request to
the op's duration + 30 s margin (capped at the warden countdown), so a
wedged slot is discarded and redialed rather than blocking the VM.
Heartbeats (`OP_MEM_STATS`) ride separate short-lived connections so they
never queue behind a long sync exec. A **pre-warmed** pool slot (dialed
eagerly at VM registration) sends one `OP_MEM_STATS` immediately after the
dial: the warden closes a fresh connection that sends no first frame within
30 s, and a pre-warmed slot can legitimately idle past that before its first
business request. The **single countdown** semantics (only host-peer
heartbeats reset it; expiry with a live mount powers the VM off) are part of
the resilience model — see
[Resilience](../how-it-works/resilience.md) §8.2.

## Additive-field compatibility rule (both internal protocols)

Both protocols evolve by **appending** fields, and a newly added field
must obey one rule: **its zero value (absent or empty) means "behave
exactly as before."** That is what makes an old peer work unchanged inside
a compatibility window:

- **Stream (protobuf):** proto3 cannot distinguish an absent scalar from
  its zero value, so an add-only field is safe only when zero preserves
  the old behavior. A field whose zero value would change behavior is a
  version-defining change: bump `StreamProtocolVersion` (and
  `StreamProtocolMinSupported` per the expand/contract step), not an
  add-only claim.
- **Warden frames:** absent fields read as empty, so the same rule holds
  mechanically. The mounted-volume identity is the exemplar: a frame that
  lacks the field reads as an empty identity and keeps the old behavior.

`template_ref` is the documented exception, made explicitly instead of
silently: **empty means FLAT** (a positive mount-mode instruction, see
the VMCommand semantics above), so its zero value is semantic. It is
therefore **not an add-only field**: it is v1-defining — the field is part
of v1, the stream window is `[1, 1]`, and pre-release builds that predate
the field are not part of a supported in-window fleet. Future fields must
either keep zero = old behavior or take a version bump.

## sandvmm API (sandlot ↔ VMM): dual protocol on one socket

The per-VM Unix domain socket
(`/run/sandswap/vm/<id>/sandvmm.sock`; owned by the sandvmm process
identity itself — it binds the socket and holds no CAP_CHOWN — mode 0600
owner-only, or 0660 with the `--api-gid` shared-group grant so the sandlot
identity connects as a group member) serves TWO protocols, dispatched per
connection by the first byte on the wire — a raw frame starts with the
protocol version byte `0x01`, an HTTP request with an ASCII method
letter; the two can never collide. Every accepted connection is
additionally checked against the VMM's OWN identity by SO_PEERCRED: a
peer whose uid equals the VMM's uid is refused (every sibling VMM/FUSE
service on a node shares that uid, and DAC alone cannot tell them apart),
and an unreadable peer credential is a fail-closed refusal. uid 0 is
exempt (dev/e2e run the whole stack as root) — a documented known limit.

- **Raw control frames** (the default transport for the per-request hot
  ops — `vm.set-fs` on every cold attach + lease-expiry clear,
  `sandvmm.ping` health probes): length-prefixed binary frames, no HTTP
  framing, no JSON, one persistent connection per VM, two syscalls per op
  (write frame, read response). Selected by sandlot's `-setfs-transport
  raw` (the default).
- **HTTP/JSON** (VM lifecycle — each once per VM, never per request; also
  the `-setfs-transport http` fallback for the hot ops): the endpoint
  table below, byte-pumped by the front dispatcher to an internal
  micro_http listener bound at `sandvmm.sock.http`. That listener is
  created owner-only (0600) and then **unlinked** — the dispatcher reaches
  it only through the O_PATH anchor the VMM keeps open
  (`/proc/self/fd/<anchor>`), so the socket name is not connectable and
  the pump is the single door into micro_http.

| HTTP endpoint | Purpose |
|----------|---------|
| `PUT /api/v1/vm.create` | Create the VM (kernel, initramfs, the permanent virtio-fs device, memory/vcpus) |
| `PUT /api/v1/vm.boot` | Boot |
| `PUT /api/v1/vm.add-vsock` | Attach the vhost-vsock device (body `{cid}`) |
| `PUT /api/v1/vm.set-fs` | **Runtime `allowed_dirs` + export-alias update** (HTTP form; the raw op carries the same fields) — absolute host paths + the `tag` field + `backendfs_config.alias` |
| `GET /api/v1/sandvmm.ping` | Liveness probe (HTTP form) |
| `PUT /api/v1/sandvmm.shutdown` | Graceful stop |

`vm.add-disk` / `vm.remove-device` exist upstream (the VMM is a fork of
Cloud Hypervisor) but are unused — the rootfs is the permanent virtio-fs
device, and agent switching never touches block devices.

### Raw frame format (all integers big-endian)

```
request:  [u8 version][u8 op][u16 flags=0][u32 body_len] body...
response: [u8 version][u8 op][u8 status][u8 reserved=0][u32 body_len] body...
```

- Version: `1` (`RAW_PROTO_VERSION`). Ops: `0 = PING` (empty body),
  `1 = SET_FS`. The alias field is part of the version-1 layout; sandlot
  and sandvmm are deployed together and there is no constant-alias
  fallback.
- `SET_FS` body: `[u8 tag_len][tag][u8 id_len][id][u16 n_paths]` + per
  path `[u16 len][bytes]` + `[u8 alias_len][alias]`. `n_paths = 0` is the
  clear-whitelist request and carries an empty alias; a non-empty list
  requires one alias (1..64 bytes, `[A-Za-z0-9._-]`, not `.`/`..`) that
  becomes the guest-visible root name for that generation. The VMM refuses
  an alias equal to the previous non-empty generation's. Every path must
  be absolute.
- Caps: `tag` 1..32 bytes, `id` 1..64 bytes, `n_paths ≤ 8`, per-path
  1..4,095 bytes (`PATH_MAX−1`), request body **51,200** bytes (== the
  HTTP path's payload cap), response body **1,024** bytes (the error
  message, truncated on a UTF-8 boundary).
- Response status: `0` OK, `1` error (message in the body), `2` version
  rejection. An in-range request version is echoed; an out-of-range
  version gets a `2` frame carrying the server's own version and the
  connection closes, so the sandlot classifies
  `ErrRawProtocolVersion` and fails fast — the same rolling-upgrade hook
  as the other two protocols.
- Parsing discipline: header-level anomalies (bad version, unknown
  flags, oversize `body_len`, truncation) close the connection;
  frame-level errors (unknown op, malformed body, op failure) answer an
  error frame and keep the connection usable. Concurrent raw connections
  are capped at 16.
- The raw `SET_FS` handler builds the same `FsConfig` the JSON body would
  have produced and rides the same elevator (`validate_fs_update` →
  `fs_device_update` → `update_fs_allowed_dirs`); validation and the
  failure-atomicity ordering are identical to the HTTP path.

## Boxout UDS protocol (sandlot ↔ boxout, K8s boxout mode)

A newline-delimited JSON protocol over `/run/sandswap-boxout/boxout.sock`
(a boxout-private root-owned 0711 directory; the socket entry is
`allowed-uid` 0600 and secured through directory-fd `Fchownat`/`Fchmodat`
with an inode re-check). SO_PEERCRED admits only the configured sandlot
UID. With `-client-token-file`, each CONNECTION first runs an HMAC-SHA256
challenge-response and no request is read before it succeeds:

```
server → {"type":"auth_challenge","nonce":<32B hex S>}
client → {"type":"auth_response","hmac":HMAC(token,"client:"+S),"nonce":<32B hex C>}
server → {"type":"auth_ok","ok":true,"hmac":HMAC(token,"server:"+C)}
```

The token never crosses the wire; MACs are compared in constant time. It
carries the privileged operations the
unprivileged sandlot delegates: sandvmm launch/kill/shutdown, network
provisioning, host-side OverlayFS mount/unmount (the `mount_overlay`
request carries `expected_template_ref`; the sidecar's tracked ref map —
persisted beside its socket — drives the same swap-staleness remount as
embedded mode, and the reply names the ref actually backing the mount),
/proc re-adopt scans, crash detection — and, on egress-enabler nodes, the
identity-stamp relay (bounded transport budget; failure degrades to
unstamped egress, never blocking a mount). See
[Install — Kubernetes](../deployment/install-kubernetes.md) and the
[Boxout configuration](../operations/configuration/boxout.md).
