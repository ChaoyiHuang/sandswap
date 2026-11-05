---
title: Sandlot
nav_order: 2
parent: Components
grand_parent: How It Works
---

# Sandlot

## 1. Overview

Sandlot is the per-node daemon: it keeps a pool of warm microVMs ready,
performs the rootfs hot-swap that *is* agent switching, and does the
control plane's sandfs/template storage work in its prov role. It dials
the gateway — the gateway never dials in. Source: `sandlot/` (Go).

One binary, three shapes (`-roles`): **exec**, **prov**, and the merged
**exec,prov** (the single-node shape). One instance per host — a role
lock (flock) refuses duplicates.

## 2. Key Responsibilities

### 2.1 exec role

The exec plane's node daemon — owns the VMs:

- **Pool management**: pre-create CLEAN VMs, resize/reconcile the pool,
  recycle VMs on memory/uses thresholds, destroy-and-replace unhealthy
  ones.
- **VM lifecycle**: spawn sandvmm, create the VM with the permanent
  virtio-fs device, poll until ready; detect crashes (a pidfd monitor
  covers re-adopted VMs); re-adopt surviving VMs after a restart.
- **The hot path**: `vm.set-fs` (virtio-fs `allowed_dirs` swap) plus the
  combined mount+exec vsock RPC — one round trip, cached warden
  connections, debug-gated logging only.
- **Resilience**: run the CONNECTED → TOLERATING → CLEANING → DONE state
  machine; release all mounts before every reconnect (the connect-clean
  invariant).
- **Egress identity**: publish bindings to the region (`sandlot/bindreg`),
  stamp identity-in-address with the routed-IPv6 backend
  (`sandlot/network`), install the static nftables baseline.

Runs privileged in embedded mode; unprivileged (UID 65536 — the reserved
sandbox identity the k8s manifests pin, see
[Prerequisites](../../deployment/prerequisites.md) — all caps dropped) in
Kubernetes boxout mode.

### 2.2 prov role

The control plane's storage side — the only role that writes the storage
plane's volumes/templates trees. The `sandprov` identity carries the
shared-storage write grant and the registry egress. It executes the seven
ProvisionCommands over the node stream (`sandlot/provision/`), each
idempotent, deadline-bounded (`-provision-deadline-sec`), and under
bounded concurrency (`-max-provision-ops`):

- **`EnsureVolume`** — materialize a SandFS volume from a template: flat
  copy, OCI stream-extract, or the overlay layout. Idempotent: a
  `.provisioning` marker with NO signed identity stamp identifies an
  interrupted run (a retry wipes and redoes it). A marker beside a valid
  signed stamp is tenant debris: the stamp, written after the quota hook,
  is the completion proof, so the marker is cleared without touching the
  volume.
- **`DeleteVolume`** — remove the volume directory; `ENOENT` = success. A
  tree whose guest-planted modes block direct removal converges via an
  orphan-rename beside the volumes root — delete always succeeds, the id
  stays reusable. The prov role reclaims orphans in the background
  (startup + hourly, entries older than an hour, each with a 5-minute
  budget); anything still stuck is appended to the volumes-root
  `.orphan-queue` file for ops. A volume whose identity stamp cannot be
  read is QUARANTINED by the same rename instead of deleted (data
  preserved); `SwapTemplate` refuses such a volume.
- **`SaveAsTemplate`** — freeze a flat volume's rootfs into the template
  store as an overlay ref. Self-heals aborted runs: a target directory
  whose ref file is missing is a crashed copy (the ref is written last),
  wiped and redone on retry — the same partial-run discipline as
  `EnsureVolume`.
- **`SwapTemplate`** — the attach half of a template swap: rewrite the
  volume's `.template` marker to the new ref (the storage-side truth) and
  apply the home policy — `keep` (default) / `archive` / `reset` for
  `/home/agent`; `workspace/` is never touched.
- **`PullTemplate` / `PushTemplate`** — OCI registry ↔ the local store.
  Pull also runs on demand at the first create of a registry-only ref;
  credentials/TLS come from the `-registry-*` flags (restart-required).
  An overlay pull extracts every layer once into the shared
  content-addressed `layers/` cache; a flat pull records digests only and
  streams blobs straight into the volume.
- **`ListTemplates` / `StatTemplate`** — the ref-file listing (re-scanned
  per call, no in-memory cache) and ref existence/modes + declared
  minimum resources (create-time sizing).
- **The template store**: `layers/` + `refs/` under `-templates-dir`; the
  ref file is the whole registration, and disk is the sole source of
  truth.
- **Node-side validation**: re-validate every wire-supplied id/ref as a
  single path element before any path join.
- **Volume naming**: derive every volume's on-disk name from the
  deployment seed (`-volume-seed-file`, required for this role) — the
  record is the only path source. Two layers keep a compromised FUSE
  daemon (sandvmm) out of other tenants: the volumes root is
  traverse-only for its group (`2710` — it cannot list the root), and the
  derived names (`sf-` + a 128-bit keyed hash) are unguessable; rotating
  the seed revokes the paths a previously compromised daemon memorized
  (`sandlot/provision/volname`).

### 2.3 Merged deployment (`-roles=exec,prov`)

The single-node shape: both roles in one process, one stream connection.
The role lock admits exactly this colocation (plus the simulation
scripts and the one-machine-etcd deploy's exec+prov pair). Duties and
interfaces are the union of 2.1 and 2.2 — nothing else changes.

### 2.4 Shared core (all shapes)

- **The stream client**: dial the gateway, negotiate roles, protocol
  version, and resilience timings in the hello. The exec connection is
  sticky (mounts and ownership demand it); the prov connection dials the
  human gateway's prov stream — default `:9998`, moved to `:9996` only
  when the human gateway is co-located with an exec gateway (which owns
  `:9998` on that host); the deploy scripts use `:9996` throughout — and
  is non-sticky with an age recycler for spread rebalance.
- **The role lock**: one sandlot per host, per instance identity; VM ids
  are namespaced by `instance.id` and the orphan sweep only signals
  processes under its own sandbox root.

## 3. Interfaces / Data Flow

**Inputs:**

- VMCommands from the gateway over the gRPC stream (exec role).
- ProvisionCommands from the gateway over the same stream (prov role),
  correlated by `commandId`: EnsureVolume, DeleteVolume, PullTemplate,
  PushTemplate, SaveAsTemplate, ListTemplates, StatTemplate.
- Warden replies over vsock (one connection pool per VM, sized by the
  spec's `exec_slots`).
- The sandvmm API over the per-VM Unix socket (HTTP/JSON or raw frames);
  or the boxout socket in Kubernetes mode.
- OCI registry traffic (prov role): template pulls and pushes against
  `-oci-registry`, with the `-registry-*` credentials/TLS.
- YAML config + flags; the volume-seed file (prov role, secret).

**Outputs:**

- Stream responses to the gateway, correlated by `commandId`.
- `vm.create` / `vm.boot` / `vm.set-fs` / `sandvmm.shutdown` calls to the
  VMM API (exec role).
- The 8 raw vsock ops to each VM's warden (exec role).
- Netlink + nftables work on the host: TAP setup, guest addresses, the
  static egress baseline (per-TAP anti-spoof + v4 metadata drop + VM-to-VM
  and routable guards, each rule family converged in ONE `nft -f`
  transaction — add and delete together, never a delete-first window),
  identity SNAT stamps (exec role). A baseline install/verify failure
  refuses the TAP attach.
- Binding-region writes: shm file or pinned bpf map (exec role).
- Volume and template trees on shared storage: volume materialization/
  deletion, the `layers/` + `refs/` template store, `.provisioning`
  markers and `.template` markers (prov role).

```
Gateway         Sandlot              sandvmm          Warden
  │ VMCommand      │                     │                │
  │───────────────▶│ 1-4 bookkeeping     │                │
  │                │ (per-VM mountMu)    │                │
  │                │ 5. mount+exec RPC (lock released)    │
  │                │───vm.set-fs────────▶│                │
  │                │───MOUNT_AND_EXEC (vsock)────────────▶│
  │                │                     │    MOUNT_GATE  │
  │                │                     │    mount + exec│
  │◀───────────────│ result              │◀───────────────│
```

The prov role's data flow — the storage plane's writes all land here:

```
Gateway(human)    Sandlot(prov)            Shared storage / OCI registry
  │ ProvisionCommand{op, commandId}                          │
  │────────────────▶│ validate id/ref (single path element)  │
  │                 │ EnsureVolume: seed → name,             │
  │                 │   copy / stream-extract ──────────────▶│ volumes/<sf-…>/
  │                 │ SaveAsTemplate: freeze rootfs ─────────▶│ layers/local-…/ + refs/
  │                 │ PullTemplate ──▶ registry ─────────────▶│ layers/sha256-…/
  │◀────────────────│ result{commandId}                       │
```

Idempotent by contract: a retried materialization wipes a genuine
partial-run tree (a marker with no valid signed stamp) and redoes it; a
valid stamped volume is never wiped. Delete succeeds on `ENOENT`.

## 4. How It Processes

**exec role:**

1. **Start up**: take the role lock. Load config, re-adopt surviving VMs
   from `state.json`, release all mounts, then dial the gateway and
   negotiate the hello.
2. **Size the pool**: create CLEAN VMs up to the target. Each spawn
   allocates a CID, provisions the network (TAP + baseline), launches
   sandvmm, creates the VM with the permanent virtio-fs device, and polls
   until ready.
3. **Serve a cold request (mount+exec)** — the hot path:
   1. Resolve the target VM for the SandFS (pool, spec, placement).
   2. Run the per-VM bookkeeping under the per-VM `mountMu`: lease/state
      update, record-driven volume mode (`volume_mode`, never a layout
      probe), `allowed_dirs` payload, egress identity publish to the binding
      region.
   3. Release `mountMu`, then issue the combined RPC: `vm.set-fs` (raw
      frames by default) followed by `OP_MOUNT_AND_EXEC` on a connection
      from the VM's warden pool. The lock deliberately does not span the
      RPC, so a concurrent cold request waits for the mount
      (milliseconds), not for the exec.
   4. The warden serializes guest-side mounts through its `MOUNT_GATE`,
      mounts the SandFS, and execs the command.
   5. Relay the result to the gateway. Warm requests skip the mount and
      call `OP_EXEC` directly.
4. **Tear down on idle**: the gateway's lease expiry triggers unmount —
   `OP_UNMOUNT` kills the agent's processes (cgroup.kill + sweeps),
   unmounts, and drops caches, entirely off the response path.
5. **Degrade gracefully**: on stream loss, hold mounts through
   `T_tolerance` so in-flight commands finish, then unmount and reconnect
   (TOLERATING → CLEANING → DONE). On restart, resume the persisted phase.

**prov role:**

1. Receive a ProvisionCommand over the stream.
2. Validate the id/ref (single path element) and the op's preconditions.
3. Execute with bounded concurrency (`-max-provision-ops`) and a per-op
   deadline (`-provision-deadline-sec`). Idempotent by contract: a retried
   `EnsureVolume` wipes a `.provisioning`-marked tree only when it has no
   valid signed stamp (a marker beside a valid stamp is tenant debris and
   is cleared in place); a retried `SaveAsTemplate` wipes a ref-less
   partial target (the
   ref is written last, with a sibling publish marker spanning the
   rename/ref window); `DeleteVolume` succeeds on `ENOENT` and converges
   via orphan-rename (or quarantine for an unreadable stamp).
4. Reply with the structured result or error code. The on-demand pull
   path uses the same machinery: the first SandFS create naming a
   registry-only ref triggers `PullTemplate` before materialization.

**Template swap (detach / attach / swap) — the gateway–sandlot
cooperation:**

1. **Gate** (human gateway): set the record's status to `detaching` —
   execs and file ops answer 409 `SANDFS_NOT_ACTIVE` from here on.
2. **Drain** (exec role): the holder unmounts the SandFS everywhere;
   in-flight sync execs are waited out by the warden's `MOUNT_GATE`. On
   split deployments the exec gateway learns the gate via its identity
   watch and writes the settled `detached` status back over etcd.
3. **Attach** (prov role): the gateway dispatches `SwapTemplate` — the
   prov role rewrites the volume's `.template` marker to the new ref
   (storage truth) and applies the home policy (`keep`/`archive`/`reset`;
   `workspace/` untouched). The record returns to `active`.
4. **Offline backstop** (exec role): every mount command carries the
   record's `template_ref`, and each node persists the ref its overlay
   was last built from — a mount that sees a mismatch remounts from the
   volume's marker. A swap executed while a node was offline therefore
   converges on the node's next mount, with no coordination protocol.

`swap-template` is the one-shot form: the gateway runs the same sequence
end to end (gate → drain → `SwapTemplate` → active).

## 5. State & Storage

Sandlot is **stateful**. It owns host-local state and writes the shared
storage in the prov role.

- **Persisted**: `state.json` (sandbox dirs, VM ids, CIDs — the
  re-adoption anchor), per-node template refs (the remount backstop for
  offline template swaps), the volume-seed file (prov role; a deployment
  secret, root-readable only).
- **Host-side, restart-surviving**: the egress binding region (shm file
  or pinned bpf map — a fresh process resets the slots it re-adopts),
  TAPs and nftables rules (torn down with the VM).
- **Memory-only**: pool and VM state (beyond `state.json`), leases, mount
  state, subnet allocations (recovered from guest addresses on re-adopt).

Component configuration:
[Sandlot configuration](../../operations/configuration/sandlot.md).
Privileged-path delegation: [Boxout](boxout.md).
