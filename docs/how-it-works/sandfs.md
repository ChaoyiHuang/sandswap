---
title: SandFS
nav_order: 5
parent: How It Works
---

# SandFS

A SandFS is the agent's persistent filesystem: **one directory** under the
volumes root (sandlot `-volumes-dir`, default `/var/sandswap/volumes`) holding
everything the agent keeps. The microVM is the compute; the SandFS is the
disk. It reaches the VM through one virtio-fs device (tag `sandswap`) that is
created at VM boot and never hot-plugged — attaching a different SandFS to a
running VM is a filter swap (`allowed_dirs`, ~0.20 ms) plus a guest
bind-mount swap. Nothing inside the VM persists unless it lands in the
SandFS directory.

Every SandFS is created in one of two volume modes — **flat** or
**overlay** ([Concepts](concepts.md)). The mode is chosen at creation
(`POST /human/sandfs`, where both `template` and `mode` are required —
Sandswap does not auto-detect the mode) and recorded on the SandFS. It decides how the template
becomes the volume's content, what the guest may write, and whether OS
package managers work. Where templates come from and how they are stored is
[Templates](templates.md); making your own is in
[Building Templates](../building/templates.md).

## 1. The two modes

### 1.1 Flat — the whole directory is a writable rootfs

Creation seeds the volume with a full copy of the template: copied from a
locally registered flat template directory, or — for a template pulled from
an OCI registry — by streaming the layer blobs straight into the volume
(each creation materializes its own copy; dedup is the storage backend's
concern). There is no marker and no fixed subdirectory structure.

In the guest, the entire directory is bind-mounted read-write at
`/mnt/rootfs` and the command runs in a chroot of it (cwd `/workspace`, which
the template provides). The agent can modify anything — `/usr`, `/etc`,
`/bin` — and it all persists.

Flat is the **build** mode: it is where OS package managers run
(`apt`/`dpkg`, `yum`/`dnf` — see [packages: OS vs language](#3-packages-os-vs-language)).
A finished flat SandFS is frozen into a template with one call
([save-as-template](templates.md#13-freeze-it-save-as-template)),
and the new template then serves any number of overlay SandFS instances.

### 1.2 Overlay — read-only shared base + writable workspace

Creation is instant and moves no template bytes: a **prov instance**
(prov sandlot — the only writer of the volumes tree) creates
`rootfs/`, `workspace/`, `home/` plus a `.template` marker holding the
template ref. The template's layers were already extracted once into the
shared content-addressed `layers/` cache (the pull happens at creation if
the ref is not cached yet) — every overlay SandFS from that template shares
that one extraction. The gateway itself mounts nothing; it relays the
creation as a ProvisionCommand over the stream to the prov instance (which
dials human gateway).

On the first execute, sandlot mounts the read-only overlay on the volume's
`rootfs/`: `lowerdir` = the template's layer directories, **no upperdir and
no workdir** (why: [below](#4-why-the-overlay-is-read-only)). The warden then
builds the guest view in four mount steps plus hardening:

```
chroot /mnt/rootfs
├── template files   → read-only overlay mount (kernel-enforced)
├── /workspace       → volumes/…/workspace   (writable bind mount)
├── /home/agent      → volumes/…/home        (writable bind mount)
└── /tmp             → fresh tmpfs           (node-local, never shared)
    hardening: RAM-backed busybox, masked proc, minimal /dev, resolv.conf
```

The writable parts are the **agent's workspace**: `/workspace` for project
files, `/home/agent` for everything a home directory accumulates. Overlay is
the **serve** mode: many SandFS instances share one immutable template while
each keeps its own private, persistent writable area.

## 2. What persists where

| Path (guest) | Flat | Overlay |
|---|---|---|
| template files (`/usr`, `/etc`, …) | writable, persists | **read-only** (kernel-enforced) |
| `/workspace` | persists (in the volume) | persists (bind to the volume) |
| `/home/agent` | persists (in the volume) | persists (bind to the volume) |
| `/tmp` | persists (plain dir in the volume) | tmpfs — node-local, lost on switch |

In both modes the persistent paths live on the volume's own storage, so
files survive agent switches, VM recreation, and node migration.

## 3. Packages: OS vs language

The warden sets the same environment on **every** exec, in both modes,
steering installs into `/home/agent`:

| Variable | Value |
|---|---|
| `HOME` | `/home/agent` |
| `PATH` | `/home/agent/.local/bin:/home/agent/bin:/home/agent/.npm-global/bin:…` (system paths follow) |
| `PYTHONUSERBASE` | `/home/agent/.local` |
| `npm_config_prefix` | `/home/agent/.npm-global` |
| `CARGO_HOME` | `/home/agent/.cargo` |
| `GOPATH` | `/home/agent/go` |

`pip install --user numpy`, `npm install -g typescript`, `cargo install
ripgrep`, and `go install …` all land under `/home/agent` — they need no
privileges, so they work in **both** modes and persist like any other file.

OS package managers are different: `apt`/`dpkg` need capabilities
(`CAP_CHOWN`, `CAP_SETUID`, …). Sandswap makes that a property of the mode,
derived server-side from the SandFS record — agents cannot request it:

| | Flat | Overlay |
|---|---|---|
| Exec profile | **Install** — 10 ambient capabilities (Docker's default set minus `CAP_NET_RAW`/`CAP_SETFCAP`/`CAP_SYS_CHROOT`/`CAP_SETPCAP`/`CAP_MKNOD`) | **Strict** — zero capabilities |
| `apt` / `yum` / `dnf` | work | fail (by design) |
| seccomp / `NO_NEW_PRIVS` | same 82-syscall deny list, enforced in both | same |

The intended workflow follows directly: **build in flat** (install OS
packages, configure the environment), **freeze with save-as-template**,
**serve many overlay SandFS from the result** — each instance getting a
read-only, tamper-proof copy of what flat produced, with full language-level
extensibility in `/home/agent`.

## 4. Why the overlay is read-only

A **writable** OverlayFS upperdir needs `RENAME_WHITEOUT` and `trusted.*`
xattrs — which network filesystems (NFS, CephFS, most managed NAS) do not
provide. Sandswap's overlay is therefore read-only: no upperdir, no workdir,
so it mounts on **any** POSIX filesystem, and every agent write travels a
plain bind mount instead. This choice has two further benefits:

- read-only enforcement is the kernel mount, not permission bits the guest
  could change;
- the overlay is stateless — no upperdir to garbage-collect, concurrent
  read-only mounts on different nodes are inherently safe, and cross-node
  migration needs no coordination (node A unmounts; node B mounts the same
  shared layers).

The host-side mount is still kernel state, so each node runs a periodic
stale-overlay sweep (embedded sandlot and the boxout sidecar share the same
implementation) that unmounts overlays whose SandFS is gone — crash
leftovers only; normal unmounts never rely on it. The sweep also runs once
per stream reconnect, and each node tracks WHICH template ref its overlay
was mounted from (persisted across restarts beside the state file): a mount
command whose expected ref disagrees with the tracked ref — a template
swapped while this node was offline — remounts from the volume's `.template`
marker before the guest mounts. The volume's marker is the storage-side
source of truth.

## 5. Template swap (detach/attach)

Because `workspace/` and `home/` live in the volume and the read-only
template is only the overlay's lowerdir, an overlay SandFS can change
templates **without losing agent work**: detach unmounts everything,
attach re-points the `.template` marker at a new ref and lets the next exec
take the ordinary cold path onto the new layers. This is the upgrade path —
rebuild the template, swap the fleet, delete the old one.

The lifecycle states ride on the sandfs record (visible in every listing and
on `GET /human/sandfs/{id}`; full API semantics in
[Human API](../reference/human-api.md#template-swap-detach--attach--swap-template)):

```
active ──detach──▶ detaching ──drain settles──▶ detached ──attach──▶ active
  └────────delete────────▶ deleting ──drain (bounded)──▶ terminal delete
```

The `active` status is stored as the empty string (the record field's zero
value) — the API names it `active` in responses. Every other status is a
literal string, which is why the gate is "status is empty ⇒ active".

Three properties make it safe under concurrent execution:

- **The status gate protects the window**: while the status is
  non-active, execs and file ops are refused with a retryable
  `409 SANDFS_NOT_ACTIVE` — one struct-field compare on the hot path (the
  record is already read during auth), zero added latency when active.
- **The drain is confirmed, not assumed**: the mount holder unmounts the
  sandfs everywhere (in-flight sync execs are waited out by the node-side
  mount gate) and only then settles the status to `detached`. Deletion uses
  the same drain but proceeds past its budget — the operator asked for the
  sandfs to go.
- **Correctness never depends on watch latency** (split deployments): the
  status reaches exec gateways via the etcd identity watch in milliseconds,
  but every invariant holds regardless — node-side mount serialization plus
  the marker-as-storage-truth rule above close any stale-cache interleaving,
  and a just-attached sandfs is never falsely rejected (the gate re-checks
  with a linearizable read before refusing).

`/home/agent` carries over by default (`keep`); `archive` renames it aside
(recoverable), `reset` starts fresh. `/tmp` is tmpfs and never survives a
swap — the same rule as an agent switch. Background execs do not survive a
swap either: the drain's unmount clears them, and their status polls
resolve to `expired`.

## 6. Security

Both modes share the same layer stack (full model in
[Isolation and Swap](isolation-and-swap.md)):

1. **virtio-fs `allowed_dirs`** (VMM level) — the guest sees exactly one
   directory: the active SandFS's. Not whitelisted paths return NotFound
   even from a guest escape.
2. **chroot** (guest level) — the command is confined to `/mnt/rootfs`.
3. **Read-only rootfs** (overlay mode) — kernel-enforced, on top of the
   above.

Capability policy is per [mode](#3-packages-os-vs-language): flat execs run
with the 10-capability install profile, overlay execs with zero — both
under the same seccomp deny list and `NO_NEW_PRIVS`.

**What flat's install profile is for.** Flat is the template-build
environment: it is the one place where OS packages are installed, and the
result is frozen into a template with `save-template`. Building and saving
templates is an ops/admin capability — namespace users consume the resulting
overlay templates, they do not create templates. A flat SandFS handed to a
tenant therefore carries the install profile inside that tenant's sandbox:
the capabilities are in-guest only (no host effect; `CAP_KILL` cannot signal
PID 1, `DAC_*` is bounded by the chroot and the virtio-fs allow-list), and
the guest-kernel attack surface is the accepted cost of the build workflow.
Teams that do not need package installation should use overlay.

## 7. Choosing a mode

| If you need | Pick |
|---|---|
| OS package installation, full control of the rootfs, building an image | **flat** |
| One template serving many sandboxes cheaply | **overlay** |
| Tamper-proof base files (`/usr` immutable to the agent) | **overlay** |
| Fast creation at scale (no per-instance copy) | **overlay** |
| Storage efficiency (layers shared, not copied) | **overlay** |

Flat on a local disk and overlay on a shared filesystem mix freely in one
deployment — the mode is per-SandFS. What each mode costs on which storage
backend is in [Storage Backends](../integration/storage-backends.md).
