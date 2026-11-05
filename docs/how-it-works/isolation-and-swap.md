---
title: Isolation and Swap
nav_order: 8
parent: How It Works
---

# Isolation and Swap

A microVM is expensive to boot and cheap to reuse. Sandswap scales by
**time-sharing**: a pooled microVM serves one SandFS at a time and then
hands the machine to the next one, swapping the filesystem view for about
the cost of a bind mount. The hard part is not the mount — it is the
guarantee that comes with it: **the next SandFS starts on a machine with
zero residue of the previous one.**

This page covers that machinery end to end: how the sandlot, sandvmm, and
the warden cooperate on a swap; the two boundaries that keep one agent's
SandFS invisible to another (the VMM's virtio-fs filter and the warden's
guest-side mount stack); what dies at a switch — processes, filesystem
state, kernel objects, network metadata, memory; and what agent code can
still reach afterwards, and what it cannot.

Neighbors: which gateway owns which SandFS is
[Ownership & DNS](ownership-and-dns.md); what happens when a component
fails mid-swap is [Resilience](resilience.md); pool states, verified
creation and recycling are [microVM Lifecycle](vm-lifecycle.md); threats
that are *not* the in-VM isolation boundary (the host, the network, a
compromised gateway) are [Threat Model](threat-model.md).

## 1. One microVM, one SandFS at a time

```
One microVM's timeline — the same machine is used by A, returned to the
idle pool, and then used by B:

                    (1) attach A        (2) swap out        (3) attach B
                    set-fs [sf-a51f3c]  unmount + the       set-fs [sf-b7e2d9]
                    + guest mount       clearing chain      + guest mount
                            │                   │                   │
                            ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ CLEAN         │   │ IN USE        │   │ CLEAN         │   │ IN USE        │
│ allowed_dirs= │   │ allowed_dirs= │   │ allowed_dirs= │   │ allowed_dirs= │
│    []         │   │ [sf-a51f3c]   │   │    []         │   │ [sf-b7e2d9]   │
│ no mount,     │   │ A mounted,    │   │ no mount,     │   │ B mounted,    │
│ no processes  │   │ A executing   │   │ no processes  │   │ B executing   │
└───────────────┘   └───────────────┘   └───────────────┘   └───────────────┘
idle in the pool        serving A         back in the pool      serving B
```

This VM is reused by B only after (2) completed; if the swap-out cannot be
proven complete, the VM is destroyed and a replacement boots fresh (§6.6).

The invariant is [Design Principles](design-principles.md) Principle 4 —
**never double-mounted**: a SandFS is mounted on at most one microVM at any
instant, and a microVM holds at most one SandFS at a time. It is enforced
at four levels, each of which can stop a violation on its own:

| Level | Guard |
|---|---|
| Cluster | ownership + placement ([Ownership & DNS](ownership-and-dns.md), [Resilience](resilience.md)) — one gateway owns a sandfs |
| Node | the sandlot binds one sandfs to one VM (`resolveVMForMount`); a VM is one sandfs's machine until released |
| VM | the warden's mount gate (`MOUNT_GATE`, §3.2) + the mounted-volume identity (`mounted_volume`) — the in-guest serialization point |
| Guest | `chroot` into the mounted volume — processes can only ever name the current mount |

Why swap instead of booting fresh for every agent: a swap costs a filter
update (~0.2 ms) plus a guest bind mount; a boot costs seconds. The VM's
kernel, warden, and device model persist across the swap — only the
filesystem view changes. That is also what makes [recycling](vm-lifecycle.md)
a hygiene choice, not a correctness one: the isolation between two agents
never depends on the VM being fresh, only on the swap being complete.

## 2. Three actors, one machine

Time-sharing works because each layer does one job and the swap is a
strictly ordered sequence of RPCs among them.

| Actor | Runs | Owns during a swap |
|---|---|---|
| **sandlot** | host, per node | decides the attachment, serializes per-VM bookkeeping, drives the VMM and warden RPCs in order |
| **sandvmm** (VMM) | host, per VM | the virtio-fs device and its `allowed_dirs` filter — which host directories are visible to the guest *at all* |
| **warden** (PID 1) | in-VM | the guest-side mount stack, the process cgroup, and every teardown step that must run from inside |

The two sides of the swap are deliberately independent:

- The **VMM filter** controls what the guest kernel can *reach* (a
  host-side allow-list — the `allowed_dirs` filter — on the shared
  directory). It is swapped by the
  sandlot over a Unix socket, and the guest cannot influence it.
- The **guest mount stack** controls what guest processes can *name*
  (bind mounts + chroot inside the VM). It is built and torn down by the
  warden, and the sandlot cannot fake it — the warden verifies what it
  actually mounted.

One virtio-fs device, created once at VM boot and never hot-plugged:

```
host                                    guest
/var/sandswap/volumes/  ── virtio-fs ──►  /mnt/volumes   (tag "sandswap",
  ├── sf-a51f3c/          device         │               allowed_dirs
  ├── sf-b7e2d9/          (permanent)    │               filters the share root)
  └── sf-cd08b4/                         └─ /mnt/rootfs ← bind mount of the
                                                          ACTIVE sandfs only
```

Volume directories never carry the sandfs id — their names are derived from
a deployment secret (`sf-` + HMAC, §4.3), so even if someone reads the
directory listing of the volumes root, the names reveal nothing about which
agent owns which volume. The device is created with an **explicitly empty
`allowed_dirs`** — the
fail-closed state: no agent directory is visible, not even for the window
before the first attach.

## 3. The swap, step by step

### 3.1 Attach (the cold path)

A cold request for SandFS B on a CLEAN VM. Steps 1–4 are the sandlot's
per-VM bookkeeping, serialized by the sandlot's per-VM mount lock
(`mountMu`). Step 5 — the combined mount+exec RPC — runs *after* that lock
is released, on a connection taken from the VM's warden connection pool
(sized by the spec's `exec_slots`); guest-side mutual exclusion is the
warden's `MOUNT_GATE` (§3.2). The lock is deliberately not held across the
RPC: it protects only the bookkeeping, so a concurrent cold request waits
for this request's *mount* (milliseconds), not for its *exec* (up to the
exec timeout).

1. **Host overlay** (overlay mode only): mount the template's layers
   read-only at `<volume>/rootfs/` on the host — the guest's read-only
   rootfs is backed by a read-only mount, so the read-only property is the
   kernel's, not a permission bit the guest could change.
2. **Swap out any old volume** — normally none (the lease-expiry release
   already unmounted), but if the VM still holds A's mount (a stale lease
   window, a failed earlier release), the warden's full unmount sequence
   runs first (§3.3), and A's egress binding is revoked with it. Never
   stack mounts.
3. **Filter swap**: `set-fs allowed_dirs = [B's directory]`. From this
   point the guest can see B's directory through virtio-fs — and only B's.
4. **Publish the egress identity binding** for the new attachment
   ([Egress Enabler Contract](egress-enabler.md)) — before the mount RPC, so the
   first guest process that runs can never produce un-attributed traffic.
5. **Mount + exec, one round trip**: the warden's combined
   `mount + exec` op builds the guest mount stack and runs the first
   command. (File ops use the mount-only form of the same op; the exec is
   empty.)

The ordering is required in both directions: the filter must be active
*before* the guest mounts (otherwise the bind target does not exist), and
the stale mount must be gone *before* the filter swaps (otherwise the guest
could still resolve A's files while B is being attached).

### 3.2 The in-guest mount

The warden builds the guest view inside `mount_workspace`, for both volume
modes ([SandFS](sandfs.md) has the mode semantics). The mode is the
**identity record's**, carried on the mount op (`volume_mode`): the warden
never probes the volume's layout. This matters because a flat volume is
agent-writable — a planted `rootfs/` directory must not be able to choose
overlay semantics (which would drop the bind's read-only intent and skip
the flat-mode stamp cover).

1. **Mount the virtio-fs share** at `/mnt/volumes` — once per VM lifetime,
   hardened `nosuid,nodev` (the share carries guest-requested mode bits and
   `mknod`s verbatim, so every bind derived from it must inherit those
   flags; the kernel drops per-mount flags passed on a bind call, so the
   hardening lives on the share root and is inherited).
2. **Bind the active volume**:
   - *flat*: the volume directory itself → `/mnt/rootfs`, read-write.
   - *overlay*: `<volume>/rootfs` → `/mnt/rootfs` (read-only, inherited
     from the host overlay), `<volume>/workspace` → `…/workspace` and
     `<volume>/home` → `…/home/agent` (read-write).
3. **Fresh tmpfs** at `/tmp` (overlay mode) — node-local, never shared,
   size-capped.
4. **Hardening** (both modes): a RAM-backed busybox bound over
   `/bin/busybox` and made **read-only** through a `mount_setattr(2)`
   fd-anchored flip (a writable alias of the warden's own binary would let
   one tenant's trojan execute for every later tenant in the same VM); a
   masked `/proc` (dangerous entries covered, whole proc
   remounted read-only); a minimal `/dev` (fixed safe device nodes, devpts,
   and a **fresh** `/dev/shm` tmpfs, size-capped); `/etc/resolv.conf`
   injected for this attachment.
   These are **fail-closed**: if the read-only busybox flip, the masked
   `/proc` covers/remount, or an unsecurable `/dev` target fails, the warden
   refuses the mount (the already-built pieces are unmounted) instead of
   serving a tenant a de-hardened tree. Skips that never attempted a bind —
   a usrmerge `bin` symlink, a template with no `bin/` — stay non-fatal.
   The `/dev/shm` tmpfs mount itself remains best-effort after its target
   is secured (the mount can fail on a template without that path).
   `/proc/net` is deliberately NOT masked: it is a magic symlink to the
   per-PID `net` directory, so a bind cover would attach to the warden's
   own `/proc/<warden-pid>/net` while every agent process keeps reading its
   own; the netlink-table address disclosure it would otherwise enable is closed in
   the guest kernel by hashing a `net_cookie` instead of the network
   namespace pointer (see [Guest Kernel Hardening](guest-kernel-hardening.md) §2).

Two properties make this idempotent and race-free:

- **The mount gate (`MOUNT_GATE`).** A process-global read/write lock in
  the warden: mounts and unmounts take the write side; in-flight sync
  execs and file ops take the read side, and the warm-path "already
  mounted" check runs inside the read side so it cannot race a concurrent
  unmount. An unmount therefore waits for running commands to finish
  before it kills anything; of two concurrent cold mounts, the second
  waits on the write side and then sees `mount_active` and skips the
  redundant mount instead of stacking it.
- **Volume identity (`mounted_volume`).** The warden remembers *which*
  volume it mounted (the directory basename, e.g. `sf-b7e2d9` — the
  seed-derived name of §4.3), recorded
  only after the mount fully succeeds. A mount request for the same volume
  is a duplicate (skip). A request for a **different** volume while one is
  mounted is a state the protocol forbids — a duplicate-skip would run the
  new agent's exec inside the old agent's rootfs — so the warden tears the
  stale mount down (full unmount sequence) and mounts the requested volume
  in its place. Successful mount responses carry the mounted basename on
  the wire, and the sandlot asserts it matches what it asked for; a
  mismatch means the VM is dirty-destroyed — the exec result of that RPC
  is never trusted. Every exec — warm and the combined cold mount+exec
  alike — carries the identity the op believes it mounted, and the warden
  asserts it under the mount gate immediately before spawning. The cold op
  passes the basename its own mount phase established: the write gate is
  released when `ensure_mounted_once` returns, so a concurrent cold mount
  for a different volume can self-heal (unmount this one, mount its own)
  before this op's exec acquires the read gate. Without the assertion, that
  exec would run one tenant's command inside the other volume's rootfs. A
  mismatch is refused by name (`volume_identity_mismatch`) **without
  executing**. The file API takes its identity from the request's own
  volume record, never from the VM's current mount record.

### 3.3 Swap out (the clearing sequence)

The lease expired ([microVM Lifecycle](vm-lifecycle.md) §4); the warden
runs the teardown in this order — each step must precede the next:

```
1. gate (write)        wait out in-flight sync execs / file ops
2. cgroup.kill         SIGKILL the agent's whole process tree, poll empty
3. rule-A sweep        SIGKILL every live userspace process except PID 1
4. child mounts        home, workspace, resolv.conf + busybox file binds
5. masked mounts       proc covers, dev/pts, /dev/shm, /dev, proc, /tmp
6. umount /mnt/rootfs  flush dirty pages, detach the mount
7. drop_caches=3       evict clean pagecache + dentries + inodes
8. kernel-object sweep SysV IPC, user keyring
9. socket sweep        destroy dead-state TCP sockets, flush the neighbor table
10. final-state gate   a zombie or D-state task above PID 1 fails the
                       unmount — the sandlot destroys the VM instead of
                       reusing it
```

Then the sandlot clears the filter (`set-fs allowed_dirs = []`), clears its
bookkeeping, and revokes the egress binding. The **same unmount-then-clear
order** holds on re-adopt and on the gateway-loss CLEANING path: the reuse
tripwire refuses a filter swap while the guest still holds handles/un-
FORGOTTEN inodes into the outgoing export (a live bind mount pins those
references), so clearing first would fail closed and destroy an otherwise
reusable VM. Ordering across the two sides
matters: the filter clear runs **after** the guest unmount — the teardown
walks paths under the share (its defensive umount probes), so withdrawing
the guest's visibility first would make the teardown itself fail.

Two design rules inside the chain:

- **No `MNT_DETACH`.** Detaching the mount lazily would leave a D-state
  process alive while the next agent mounts — two agents' processes in one
  VM. Sandswap fails loudly instead: if `umount` still returns `EBUSY`
  after one retry, the warden returns an error and the sandlot **destroys
  the VM and replaces it**. A VM in an unknown mount state is never reused.
- **Every mount step has a matching teardown step.** Every path the mount
  code can put a filesystem on (including the resolv.conf *file* bind used
  when the rootfs is read-only) must be unmounted before the parent, or the
  parent umount fails `EBUSY` and the VM dies unnecessarily — a
  setup↔teardown symmetry that is unit-tested.

### 3.4 The swap protocol assumes a hostile peer

The mount protocol is written as if its peer is hostile: vsock carries no
authentication, seccomp does not block `socket`/`connect`, and whether a
guest process can actually reach the port is a kernel-config property, not
a designed control (§7.3). The isolation must not depend on the caller
being the sandlot:

- The wire's `mount_point` must be **exactly** `/mnt/rootfs`. A hostile
  process cannot steer a mount over warden-critical guest paths — e.g.
  `/sys/fs/cgroup`, which would shadow the cgroup filesystem and silently
  defeat both the memory cap and the switch-time `cgroup.kill`.
- The volume identity rules above (record, cross-check, self-heal) exist
  for the same reason: a hostile mount-only RPC racing into the switch
  window must not be able to leave agent B executing inside agent A's
  rootfs. The combined cold mount+exec is covered too: its exec asserts the
  volume its own mount phase established, so a different-volume heal between
  the mount and the exec answers `volume_identity_mismatch` instead of
  executing.
- Frames are parsed defensively (magic + version check, ≤64 fields per
  body, body size cap), and a malformed frame closes the connection —
  never PID 1.

## 4. The host-side boundary: the virtio-fs filter

The guest never touches the host filesystem. Every file request from the
guest travels to a program on the host — the virtio-fs server inside
sandvmm (this section: *the daemon*) — and that program answers with one
rulebook, the filter:

```
guest (agent code)                 host (sandvmm)
  open("/workspace/file.txt")  →   virtio-fs server
                                     │  is /workspace on the allow-list?
                                     │  the allow-list holds exactly ONE
                                     │  directory: the active agent's volume
                                     ├─ yes → serve the file
                                     └─ no  → answer "no such file or
                                              directory"
```

The boundary lives at the **share root** — the top directory of the shared
volumes tree on the host (not the host's root directory `/`, and not the
`root` user) — the only place where an agent directory can be named at all.

### 4.1 What the guest sees

The guest sees one virtio-fs share at `/mnt/volumes` containing exactly one
agent directory — presented under a per-generation alias (32 random hex
characters, minted by the sandlot for each set-fs), never its real
(seed-derived) name: names are secrets (§4.3), and every guest-pathable
string — `/proc/self/mountinfo` root fields included — must stay free of
them, because agents leak ambient strings to third-party LLMs wholesale.
Everything else is answered as if it did not exist:

- A lookup of any name outside the allow-list gets `ENOENT` — the same
  reply a genuinely missing file gets, a real errno, not a synthesized I/O
  error. Probing another tenant is indistinguishable from probing a name
  that was never there.
- A listing of the share root is answered **from the allow-list itself**,
  not by filtering the real directory.
- A chroot escape changes nothing: every path above the mount still
  resolves through the filtered share (§5).

Problem solved: all tenants live in one host directory tree, yet an agent
must not be able to name, list, or even prove the existence of another
tenant's directory. Attack this closes: an agent probing
`/mnt/volumes/../<sibling>`, brute-forcing sibling names, or reading the
mount table — all of it sees only the allowed directory.

### 4.2 What sandvmm enforces

One virtio-fs device per VM, created at boot and never hot-plugged. There
is no `vm.add-fs` route and a configuration with more than one fs device is
refused — a second device would be a second, separately filtered window
into the host that `vm.set-fs` (which addresses the one device by id)
could neither see nor re-filter. The allow-list is swapped by the sandlot
via `vm.set-fs` (~0.2 ms); the guest cannot influence it.

The filter's rules, as implemented in the daemon:

1. **Not on the list = does not exist.** Rule §4.1's uniform `ENOENT`. The
   allow-list PRESENTS its single entry under the generation's alias
   (lookups by the real directory name answer ENOENT too — the guest cannot
   even spell the secret, let alone prove it exists). The alias is the
   capability binding one filter generation to the warden mount that
   follows it: after the next set-fs the old name is gone, so a mount
   request that lost the race fails before it can touch the new export.
   The same holds for invented objects: node ids and file handles are
   numbers minted by the daemon's own tables, never guest-chosen — a
   forged or revoked one names no host object and answers `ESTALE` /
   `EBADF`. A guest can only ever ask about objects the daemon itself
   handed it.
2. **Nothing can be done at the share root either.** `mkdir`, `mknod`,
   `create`, `symlink`, `link`, `unlink`, `rmdir`, all rename forms, the
   four xattr operations, and `statfs` at the share root (the volumes
   filesystem's real host capacity/usage is not exposed there; an allowed
   directory's `statfs` is served from the backing filesystem — a coarse
   node-wide capacity/free-byte signal, no tenant identity) are refused by
   **one class check
   before the per-opcode dispatch** — these handlers pass names straight to
   the host and do not consult the filter themselves, so the gate sits above
   all of them. The gate's match is exhaustive over the opcode enum: a new
   opcode (an upstream merge, a protocol bump) fails to compile until it is
   classified here, so none can silently skip the gate. A non-UTF-8 root
   name can never match the UTF-8 allow-list keys and is denied — never a
   panic. The wire surface itself is an allow-list: an opcode number that is
   not part of the protocol enum is refused with `ENOSYS`, and the
   per-opcode dispatch match carries no wildcard either — a newly added
   opcode (an upstream merge, a protocol bump) fails to compile until it is
   both routed and classified, so no request can reach a handler this build
   did not intend to serve.
3. **A guest-supplied name is exactly one path component.** `.` / `..` / an
   embedded `/` / empty are refused, because host `*at()` calls treat the
   name as a path — `../other-agent` would walk out of the share. In code
   the name exists only as a validated type produced by the validating
   constructor; there is no raw-bytes path left, so a new opcode cannot
   reintroduce the hole without failing to compile. Legal-but-odd names
   (`...`, backslashes, 200 bytes, non-UTF-8) still work.
4. **The host never follows a path the guest chose.** Lookups go through
   `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` with `O_NOFOLLOW`,
   rooted at the parent directory's descriptor; inodes are held as
   descriptors, never as stored paths; `/proc/self/fd` reopens are limited
   to regular files and directories. A planted symlink is never followed by
   the daemon — the guest's own kernel resolves symlinks, through lookups
   the filter gates.
5. **The filter is always on.** An empty allow-list hides every share-root
   entry and no configuration can turn filtering off: the config layer
   defaults an omitted list to empty, the fs device normalizes any remaining
   absence to empty, and the filter's constructor takes a list (there is no
   "no list" value). A list swap validates the new list first (each
   directory opened and stat'ed), then replaces the old one under a single
   lock; a failed swap leaves the previous list in place.
6. **The filter gates new lookups, not cached answers.** The guest kernel
   caches directory entries, and an already-open file descriptor keeps
   resolving. That is why the swap-out sequence (§3.3) kills the agent's
   processes and drops the caches before the next attach: a dead process
   holds no descriptors and `drop_caches` evicts the entries. The swap
   itself is a second, kernel-side line of the same defence: every
   `vm.set-fs` clears the daemon's inode and handle tables (the share root
   alone survives) and bumps each store's revocation epoch under the same
   lock the clear runs under. A lookup or open captures the epoch when it
   starts and re-checks it at insertion, so a request that began before the
   swap can never re-insert the previous agent's object after the clear —
   it answers `ESTALE`. A stale node id or file handle minted under the
   previous agent therefore answers `ESTALE` / `EBADF` even in the A→B→A
   same-VM reuse case, where the outgoing guest kernel could otherwise
   still be holding one. The read-only backend forwards the same revoke (the
   virtio-devices default for an FS config that omits `read_only` is `true`,
   so inheriting the trait's no-op default would leave that variant
   unprotected). One node id survives by design: the
   share root itself — the guest kernel holds a persistent reference to
   it for the whole `/mnt/volumes` mount (established once; switches never
   re-INIT), so the daemon keeps it alive across revokes while every
   agent-content node id still dies.

Attack examples this closes: a planted symlink pointing at a sibling
(rule 4), a `renameat2` with a path-shaped name (rule 3), a planted device
node handed back through `/proc/self/fd` (rule 4 — the daemon never reopens
one, and the mount flags and missing capabilities make the inode inert
anyway).

### 4.3 If sandvmm is compromised

Assume the daemon is hostile. It can skip the filter entirely — it is a
host process in the shared storage group — and simply `stat` candidate
paths under the share root.

**What it can read:** every volume directory whose path it has been
handed. The daemon learns the path of each volume its own VM serves
through `allowed_dirs`, so the exposure is the tenant history of that one
VM (the current and previously served volumes), not the tree. **What it
cannot do:** find a path it was never handed. Five facts bound that
exposure:

- **It cannot list the share root.** The share root is owned by `sandprov`
  (uid 983) and the daemon's group has **traverse only** — no read, no
  write. There is no `ls` to enumerate tenant directories, and creating,
  removing or renaming beside the allowed directory fails `EACCES` in the
  kernel itself, even if the class gate (rule 2) were ever regressed away.
- **It cannot guess a name.** Volume directories are named
  `sf-` + base32(HMAC-SHA256(seed, id)) — 128 bits
  (`sandlot/provision/volname`). The seed lives in the prov sandlot's
  config (scoped `root:sandprov` 0640) and never reaches the daemon: the
  merged exec,prov sandlot carries the `sandprov` group to read the seed,
  but every sandvmm spawn REPLACES its supplementary-group set with exactly
  `microvm.vmm_groups` (`setpriv --groups`, `--clear-groups` when empty), so
  the daemon never inherits the grant.
  The sandfs id itself is deliberately *not* the name: `sandfs-` + 8 hex is
  32 bits — a `stat` loop finds some tenant of a 10 000-tenant node in well
  under a second. A name collision between two volumes needs ~2^64 tries.
- **Rotation revokes knowledge.** A daemon compromised earlier remembers
  the paths it served. `deploy/baremetal/rotate-volume-seed.sh` re-keys
  every name at once in a maintenance window. Each volume carries a
  `.sandfs-id` stamp — the stamp, not the name, is the authority on which
  sandfs a directory belongs to.
- **It cannot reach the warden.** vsockguard admits only the sandlot uid
  (985) on the warden port; the daemon runs as 987 (§4.4). A full VMM
  compromise cannot touch the guest control transport.
- **It cannot write the storage plane.** The daemon writes only through its
  FUSE service, inside the one allowed directory. The share root and every
  sibling tenant directory are outside its write reach: the root is owned by
  `sandprov` (983) with traverse-only for the daemon's group, and prov
  sandlot instances are the only writer of the tree's structure. This is
  also why a stamp inside a tenant-writable volume cannot be trusted by
  itself: it carries an HMAC keyed by the volume-name seed (see
  [Sandlot Configuration](../operations/configuration/sandlot.md)).

### 4.4 Why sandvmm has a dedicated identity

The daemon parses untrusted guest file requests — the largest attack
surface on the exec path. It therefore runs as its own user, `sandvmm`
(987), spawned through a setpriv wrapper holding **zero capabilities**
(`--inh-caps=-all --ambient-caps=-all`). The network provider creates the
persistent TAP owned by that uid and pre-configures its MTU/bridge/up
state; the VMM's attach is an owner-match `TUNSETIFF`, and its MTU/enable
ioctls are skipped when the desired state is already present.
The split is chosen so a full VMM compromise lands on an identity with
nothing to take:

- Not the warden-trusted uid (985): vsockguard's allow-list excludes 987,
  so a compromised VMM cannot connect to any warden port.
- Guest-planted setuid files land owned by 987 — an escalation target with
  no warden access and no storage-write grant.
- The daemon must read/write the volume it serves (shared storage group),
  so the identity cannot be further reduced by permissions. The group is
  not a whole-tree grant: the share root is traverse-only (no listing) and
  derived names are 2^128, so only paths the daemon has been handed are
  reachable — the filter, the share-root permissions, and the derived
  names are what hold (§4.2–§4.3, §4.5).
- The sandlot (985) still reaches the API sockets through the `--api-gid`
  shared-group grant (0660).

Cost: the TAP work happens once at VM creation (the cold path), not per
command; the VMM seccomp filter runs in the VMM's own threads, never in
the guest's exec syscalls, and the kernel's seccomp cache makes a repeated
syscall's filter cost tens of nanoseconds (measured on a nested-virt dev
host; the guest's own syscalls are unaffected). The zero-cap split adds no
warm-path command work.

A VMM running as root, or as the sandlot uid, would turn any VMM bug into
full host access or warden access; the dedicated identity caps the blast
radius at "can read/write the volumes this VM has served" — bounded by the
traverse-only share root and the seed-derived names, and revoked by a
volume-name-seed rotation.

### 4.5 The host-side controls behind the filter

The host layout closes what filter code alone cannot:

- **`nosuid,nodev` on the volumes filesystem, every consumer host.** The
  passthrough stores guest-requested setuid bits and `mknod`s verbatim; the
  mount flags make them inert on the host. Checked by
  `security/verify-host-security.sh` (check 7) and `e2e/seccomp.sh`.
- **Per-owner device nodes.** `/dev/vhost-vsock` owner `sandvmm` 0600,
  `/dev/vsock` owner `sandlot` 0600 — each vsock device is reachable by
  exactly the identity that needs it.
- **The share root's permissions** (§4.3) are the kernel-enforced backstop
  for the filter's class gate.
- **The daemon's identity** (§4.4) is the backstop for everything else:
  capabilities, storage access, and warden reachability are all fixed at
  spawn, not by filter behavior.

### 4.6 Summary: what the boundary covers, and what keeps it closed

Every operation class a guest could attempt at the boundary, and the
mechanism that stops it:

| Operation class | Examples | Enforced by |
|---|---|---|
| Naming at the share root | `lookup`, `readdir`/`readdirplus` | the allow-list (and its validated snapshot) |
| Mutating / host-leaking at the share root | `mkdir`, `mknod`, `create`, `symlink`, `link`, `unlink`, `rmdir`, `rename`/`rename2`, xattrs, `statfs` | the share-root class gate — one check before per-opcode dispatch, exhaustive over the opcode enum |
| Any name spelling | `..`, `.`, `a/b`, absolute paths, empty, non-UTF-8 bytes | the single-component rule at the one name-extraction point (a validated type); non-UTF-8 root names denied, never a panic |
| Reaching outside by path | planted symlinks, `..` inside a resolution, magic links | `openat2(RESOLVE_IN_ROOT)` + `O_NOFOLLOW` rooted at the parent descriptor; inodes held as descriptors |
| File-type tricks | planted symlink/FIFO/socket, device nodes | the reopen guard (regular files and directories only), missing capabilities, `nodev`/`nosuid` mounts |
| Metadata ops on the root itself (nodeid-scoped, no name operand) | `open`/`opendir`/`getattr`/`setattr`/`readlink` on the share root | standing allow-decisions: the root is the one exposed entry — open/opendir/getattr are the filtered listing path; `setattr` cannot write (the daemon's group holds no write on the root, kernel `EACCES`) |
| Unsupported paths | `tmpfile`, inode-handle mappings, opcode numbers outside the protocol enum | `tmpfile`/unknown opcodes answered `ENOSYS`; handle mappings `EINVAL` (no DAX cache); file handles are never generated |
| Turning the filter off | an omitted or empty allow-list in any config layer | fail-closed defaults: config defaults to empty, the device normalizes absence to empty, no unfiltered mode exists |
| Widening the filter via the VMM API | a forged `vm.set-fs`, a second fs device | no `vm.add-fs` route; multi-fs configurations refused; `vm.set-fs` DAC-admitted only to the socket's owner/group, and the **peer-uid gate then accepts only root or the configured sandlot uid** (`--api-allowed-uid`; `dispatch.rs:163`) — an `--api-gid` member with a different uid, such as prov, is still refused |
| Cached answers after a swap | an open file descriptor, a cached dentry, a retained node id/handle naming A's files | two lines: every `vm.set-fs` clears the daemon's inode and handle tables and bumps their revocation epochs (an insertion that began before the swap answers `ESTALE`), and the swap-out sequence (§3.3) kills the agent's processes and drops the caches before the next attach |
| Planting at the share root if the class gate were regressed | `mkdir`/`create`/`unlink`/`rename` beside the allowed directory | the share root's permissions: `sandprov` (uid 983) owns it, the daemon's group has traverse only — the kernel answers `EACCES` |
| Exhausting the daemon's open handles | `open`/`opendir` without a matching `release` | a hard handle-table cap (65 536) answers `EMFILE` past the bound — an unbounded table would exhaust the shared sandvmm process's file descriptors and take down every VM it serves |
| Discovering a sibling's name offline (a compromised daemon stats the host; no FUSE request) | guessing `<share-root>/<volume>` | derived names: `sf-` + HMAC-SHA256(seed, id) — 128 bits; the seed never reaches the daemon; seed rotation re-keys every name |

Two invariants keep the boundary closed, and both are written down where
they are enforced: a FUSE name is one component and exists only as a
validated value (§4.2 rule 3), and no host-side resolution follows a
guest-controlled symlink (§4.2 rule 4). The share root's unwritability by
the daemon identity is enforced by the kernel and checked live
(`security/verify-host-security.sh`, `e2e/share-root-gate.sh`). The tests
that pin the whole surface are enumerated in §8.

## 5. The guest-side boundary: chroot and the mount stack

The second boundary is built inside the VM by the warden at mount time,
sitting under the filter (§4): the filter decides which host directories
*exist* for the guest; the mount stack decides what a guest process can
*name*. Even a chroot escape is still confined by the filter.

- **`chroot` + `chdir`** into the bind-mounted volume on every exec — the
  process's namespace root *is* the active SandFS. Nothing above it is
  reachable by path.
- **Masked `/proc`**: dangerous entries (`kcore`, `kallsyms`, `keys`, and
  `kmsg` — kernel-log lines from the *previous* agent's OOM, for example)
  are covered with `/dev/null`, then the whole proc is remounted read-only
  so the agent cannot write `drop_caches` or cgroup knobs. The warden's
  own `/proc/sys/vm/drop_caches` writes happen outside the chroot, where
  the agent cannot reach.
- **Minimal `/dev`**: a fresh tmpfs with only safe device nodes
  (null/zero/full/urandom/random/tty), devpts for ptys, and a fresh,
  size-capped `/dev/shm`. `/dev/mem`, `/dev/kmem`, `/dev/port` are never
  created.
- **Per-attachment `/tmp`** (overlay mode): fresh tmpfs — nothing an agent
  writes there is visible to the next one, and nothing persists.
- **File API's own guard**: file operations never trust a path. Each is
  resolved by a component-by-component walk that refuses to follow
  symlinks implicitly, re-expands in-workspace symlinks explicitly, and
  finishes with a kernel-authoritative check that the *opened inode* lives
  under the workspace before a byte is read or written; destructive flags
  are deferred until after that check. This is defense in depth on top of
  chroot and seccomp — the race-hardened replacement for a canonicalize
  check that a symlink swap could beat. Shell commands bypass the file API,
  but they cannot bypass chroot + the filter: a symlink a shell command
  plants resolves inside the guest's own view (and a `chroot` escape is
  still confined by the filter), so agent-created files and links cannot reach
  another SandFS or the host *through the guest*.
- **Host-side reads of agent-writable paths trust nothing either**: in flat
  mode the volume root IS the agent's chroot root, so host processes never
  treat anything there as storage-plane-written. The gateway sends the record's
  template only for **overlay** records; a flat record's mount commands say
  "no template", and the node then ignores the marker path entirely (mounts
  flat) — a planted marker can neither flip the volume into an unresolvable
  overlay mount nor, being ignored, be used to wedge it. Underneath that,
  the marker read itself is hardened (`O_NOFOLLOW` + regular-file check):
  a planted symlink cannot become a host-file read and a planted FIFO
  cannot block the node's mount path, covering the overlay-record path and
  version skew. The storage plane's copy never follows symlinks (it
  recreates them, and skips any that escape the source root), and deletion
  unlinks without following. Planted markers are ignored, never deleted —
  the volume root of a flat SandFS is the agent's own filesystem.

## 6. Nothing of agent A survives the switch

When agent B's mount succeeds, the VM must contain nothing of A that B
could name, open, map, or observe. Resource by resource:

### 6.1 Processes

- **`cgroup.kill`** (cgroup v2): writing one value to the agent cgroup's
  `kill` file SIGKILLs the whole tree atomically — background execs started
  during the lease, their descendants, everything. The warden then polls
  the cgroup until it is empty (bounded; a stuck process does not hang the
  swap — it becomes the next section's problem). Background execs join the
  cgroup at spawn; they are the only reason the cgroup exists.
- **Sync execs have two independent kill paths.** Each one-shot exec
  already ends with a group `SIGKILL` (`kill(-pgid)`) on normal return, on
  timeout, and a short straggler reap. But a descendant that called
  `setsid()` escapes its process group — and sync execs deliberately never
  join the agent cgroup (moving a task into a cgroup costs milliseconds
  inside a microVM, which would sit on the exec hot path). So at unmount
  the warden runs the **rule-A sweep**: `SIGKILL` every live userspace
  process in the guest except PID 1. An unmounted VM contains nothing but
  the warden. Kernel threads are not targets (they ignore signals by
  design — they are exempt from the sweep's *round budget*, which
  otherwise re-armed on them 8×25 ms per unmount), and a **zombie left
  above PID 1 fails the unmount outright**: like the D-state process that
  surfaces as `umount` `EBUSY`, it makes the warden return an error and
  the sandlot **destroys** the microVM rather than reusing a guest whose
  process table is not provably clean (in a healthy guest the set is
  empty — the warden is PID 1 and a subreaper, so it waits for every
  child and reparented orphan).
- Without the sweep, one `setsid sleep infinity &` would pin the mount,
  every switch would end in `EBUSY`, and the VM would be destroyed. The
  sweep makes "the VM is clean" true by construction; the `EBUSY → destroy`
  path remains as the backstop for a process in uninterruptible I/O, which
  no signal can move.
- The background-exec registry and its log files are cleared with the
  unmount (the logs live on the warden's own RAM filesystem, never inside
  the agent's volume).

### 6.2 Filesystem

- **`umount` flushes and detaches.** Dirty pages are written back to the
  backing store on unmount; after it returns, no path in the guest reaches
  agent A's files. The virtio-fs inode cache for that mount dies with it.
- **tmpfs is released by unmount, not by caches.** `/dev/shm` (always) and
  `/tmp` (overlay mode) are unmounted with their contents; fresh instances
  are mounted for B. This is the only mechanism that frees tmpfs pages —
  `drop_caches` cannot touch them.
- **`drop_caches=3`** evicts clean pagecache + dentries + inodes
  guest-wide. Linux has no per-mount drop, so this is broad — but it is
  cheap on a microVM, and it is the step that removes the *clean* leftovers
  of A's rootfs (source files, configs) and the directory metadata that
  would otherwise linger in slab caches until memory pressure. Best-effort
  by design: the completed unmount already made the bytes unreachable; the
  drop closes the residual-cache window.
- The masked mounts and the RAM-backed busybox bind are unmounted in the
  same pass (they are tmpfs-backed and would otherwise survive).

### 6.3 Kernel objects that outlive processes

Some state is not a process and not a file — and unlike both, it survives
death of its creator. All of it is cleaned, because agents sharing a VM run
as the same uid and the *next* agent could otherwise read what the previous
one planted:

- **SysV IPC** (message queues, semaphore sets, shared-memory segments):
  legal within an agent's own lease, reset at switch — the warden walks
  `/proc/sysvipc/*` and `IPC_RMID`s every object in the VM's single IPC
  namespace.
- **POSIX message queues**: the whole `mq_*` family is denied by the exec
  profile, so an agent can neither create nor open a queue; no unmount
  sweep is needed (there is nothing an agent could have planted). This sole
  close assumes every exec profile installs the identical filter — both do
  today; any future unfiltered in-guest path must bring the sweep back. The
  filter also denies the x32 spelling of every number (the arch check does
  not separate x32 — it reports `AUDIT_ARCH_X86_64`) and `kernel/build.sh`
  refuses an x32-capable config, so the `mq_*` family cannot be reached
  through x32.
- **The user keyring**: a persistent per-uid kernel keyring survives
  process death. Two independent closes: agent execs are denied the keyring
  syscalls (`add_key`/`request_key`/`keyctl`) by seccomp, so nothing can be
  planted — and the warden additionally clears the uid-0 user keyring at
  unmount as well.

The sweep runs after the umount, when every agent process is provably dead
— nothing can recreate an object past that point. It is silent in the
common case and logs (with counts) whenever it actually removes something.

### 6.4 Network metadata

- Every VM has its own guest network namespace and its own TAP on the host —
  but the TAPs all plug into ONE shared L2 bridge, so the tenant-to-tenant
  network boundary is the host-side filter set, not the bridge
  (§7.4). Agent A's sockets die with A's processes. The exception is
  **dead-state
  TCP sockets** — `TIME_WAIT`, `FIN_WAIT1/2`, `CLOSE_WAIT`, `LAST_ACK`,
  `CLOSING` — which the kernel keeps after the owning process is gone and
  which are visible in `/proc/net/tcp` with A's connection 4-tuples. The
  warden destroys every dead-state socket via `sock_diag` (the mechanism
  behind `ss -K`); the guest kernel is built with the required
  `CONFIG_INET_DIAG_DESTROY`.
- The **neighbor table** is swept the same way: entries A resolved (the
  gateway, anything it probed on the L2 segment) persist in the netns and
  are readable by B via `/proc/net/arp`; the warden flushes them at switch
  (`RTM_DELNEIGH` — the `ip neigh flush all` algorithm). What remains by
  design is **aggregate counters**: `/proc/net/{dev,snmp,netstat}` are
  per-netns lifetime totals, so B can read A's traffic volume and
  packet-type histogram — no payload, no per-flow state, no addresses the
  static gateway setup does not already imply.
- The guest's `resolv.conf` is injected per attachment, and the egress
  identity binding is revoked at unmount — no new traffic can be
  attributed to the previous attachment, and the next agent starts with a
  fresh identity ([Egress Enabler Contract](egress-enabler.md)).

### 6.5 Memory

There is no process of A left to hold an address space, no cached page
that maps A's files, no tmpfs mount holding A's shared memory, and no
kernel object naming A's data. Sandswap does not (and does not need to)
scrub every freed physical page: the guarantee is that **no path from B's
world resolves to A's state** — access requires a live process, an open
descriptor, a cached page, or a kernel object, and every one of those is
gone before B is mounted. Pages the kernel hands to new userspace
allocations are zero-filled, and A's background-exec memory was freed when
its cgroup was killed. One per-task class needs an explicit close because
the agent and the warden share uid 0: Linux's same-owner checks let a
same-uid caller retune another task with no capability. The exec filter
refuses `prlimit64`/`setpriority`/`sched_setparam`/`sched_setscheduler`/
`sched_setaffinity`/`sched_setattr` when the target is PID 1, and the
unmount rewrites the warden's own nice/affinity/scheduling policy on every
thread (the worker-thread tids classic BPF cannot name) from a boot-time
snapshot. Two residues sit outside this guarantee by design:
the netns **cumulative counters** (§6.4 — aggregate totals only), and
**tenant linkability**: the VM's boot identity (`boot_id`, uptime
continuity) and its external source IP/MAC persist across tenants, so an
observer of two leases can correlate that one machine served both. The
egress identity binding attributes every flow to its attachment; it does
not hide the machine reuse. Volume names and identity stamps do NOT reach the guest at all: the
filter presents the active directory under its generation alias (so no
`/proc/self/mountinfo` root field can carry a name), and in flat mode the
warden masks the storage plane's `.sandfs-id` stamp (sandfs id, seed generation,
HMAC) with a read-only `/dev/null` cover — agents leak ambient strings to
third-party LLMs wholesale, so the sandbox must not contain either
artifact. Both are pinned live (`e2e/share-root-gate.sh`:
`mountinfo_name_free`, `stamp_masked`).

### 6.6 What each layer closes

| Leak vector | Closed by | What remains if the layer is skipped |
|---|---|---|
| Running A process | cgroup.kill + rule-A sweep | process holds the rootfs open, reads A's files after B mounts |
| `setsid`'d sync straggler | rule-A sweep (the cgroup never held it) | mount pinned → `EBUSY` → every switch destroys the VM |
| Zombie left above PID 1 | unmount final-state gate: warden returns an error → sandlot destroys the VM | an unreaped process rides into the next tenant's VM (process table not provably clean) |
| POSIX shm / tmpfs content | unmount of `/dev/shm`, `/tmp` (+ fresh for B) | tmpfs pages survive in RAM; `drop_caches` cannot clear them |
| Dirty pagecache | `umount` (flush + detach) | dirty file data not written back; unreachable but unflushed |
| Clean pagecache + dentries/inodes | `drop_caches=3` | A's file content and directory structure linger in guest RAM |
| SysV IPC / keyring / mqueue | kernel-object sweep (+ seccomp denial for keys and the whole mq_* family) | B reads objects A planted — same uid, same namespaces |
| Dead-state TCP tuples | `sock_diag` destroy | A's connection endpoints visible in `/proc/net/tcp` |
| Neighbor-table entries | `RTM_DELNEIGH` flush at unmount | B sees which L3 addresses A resolved, via `/proc/net/arp` |
| Netns cumulative counters | accepted residue (aggregate totals; no payload, no per-flow state) | B reads A's traffic volume / packet-type histogram |
| Virtio-fs visibility of A's dir | `set-fs allowed_dirs = []` after unmount | a chroot escape reads A's files via `/mnt/volumes/` |
| Process in D-state (unkillable) | `umount EBUSY` → **destroy the VM** | the only safe alternative to `MNT_DETACH` coexistence |

Each layer is independently necessary — no single one subsumes another —
and the last row is the design rule that makes the set closed: **a VM whose
teardown cannot be proven is destroyed, never reused.** Destroying the KVM
process kills every guest process including D-state ones; the cost is a
one-time cold boot, off the request path
([microVM Lifecycle](vm-lifecycle.md) §4).

## 7. What agent code cannot reach

Everything above keeps agents apart. This section is the other direction:
what the agent itself runs under, and what it still cannot do — even
assuming the agent's code is fully hostile and the guest kernel is the
shared boundary of last resort ([Threat Model](threat-model.md) covers the
adversaries *outside* the VM).

### 7.1 Per-exec confinement

Every exec goes through the same pipeline: new session (`setsid`), chroot
into the active SandFS, environment cleared to a fixed set, no new
privileges, capability sets, seccomp — then `/bin/sh -c <command>`. The
kernel-side half of this confinement — the minimized build and the
complete allowed/denied policy — is
[Guest Kernel Hardening](guest-kernel-hardening.md).

| Layer | Strict (overlay default) | Install (flat default) |
|---|---|---|
| Capabilities | all dropped (empty bounding set) | 10 ambient caps (Docker's set minus `NET_RAW`/`SETFCAP`/`SYS_CHROOT`/`SETPCAP`/`MKNOD`) |
| `NO_NEW_PRIVS` | set | set |
| Seccomp deny list | 82 syscalls | identical 82 syscalls |
| Per-process memory cap | `RLIMIT_AS` = 70% of VM RAM | same |
| Per-agent cgroup cap | `memory.max` = 70% of VM RAM (background execs) | same |

The deny list covers: the mount API (old and new, including
`mount_setattr` and the read-side `statmount`/`listmount` pair), namespace
entry (`unshare`, `setns`), cross-process access (`ptrace`, `process_vm_*`,
`pidfd_getfd`, `pidfd_open`/`pidfd_send_signal`,
`process_madvise`/`process_mrelease`, `kcmp`), kernel modules and loaders,
the kernel attack surfaces (`bpf`, `perf_event_open`, `open_by_handle_at`,
`name_to_handle_at`, `io_uring_setup`, `userfaultfd`, `memfd_secret`,
`syslog`), the keyring and POSIX-mqueue families, host-global state
(clock/hostname/accounting/quota/IO ports/`ioprio_set`), device nodes and
NUMA policy. The shipped guest kernel additionally compiles out
`CONFIG_USER_NS` (and TUN/VETH/KVM/DEBUG_FS/USERFAULTFD/IO_URING/
BPF/OVERLAY_FS/ZSWAP/... — see [Guest Kernel Hardening](guest-kernel-hardening.md) §2; PERF_EVENTS is arch-selected by x86 and stays seccomp-denied), so
`clone3(CLONE_NEWUSER)` cannot succeed; the warden also writes
`user.max_user_namespaces=0` at boot for dev/older kernels. The full
allowed/denied surface is [Guest Kernel Hardening](guest-kernel-hardening.md) §4. The same
filter carries two additions outside the 82-entry deny list: the self-target argument guard above (five
syscalls — `prlimit64` and the four `sched_set*`; `args[0] == 0` is the only
admitted target, any other pid/tid is EPERM; `setpriority` is denied outright
because its target is `args[1]`) and a range check on the far-right
binary-search leaf that refuses every `nr >= 0x40000000` (the x32 spelling
of any syscall, which the x86_64 arch check cannot distinguish). The range
check costs the common syscall path no instruction: only numbers above the
largest list entry reach that leaf. `clone3` is deliberately
*not* denied (glibc uses it for threads and treats `EPERM` as fatal);
namespace creation via `clone3` is inert here because everything that could
exploit it is denied anyway. `NO_NEW_PRIVS` is the primary guarantee that planted
setuid bits are inert at exec time — checked by the kernel before mount
suid flags are even consulted; the `nosuid,nodev` share flags exist so no
future non-NO_NEW_PRIVS exec path reopens the door.

How the profiles compare to the common container runtimes — the Install
profile is the most privileged thing Sandswap ever runs (it exists so
`apt`/`dpkg` work in flat mode):

| Defense | Sandswap Strict | Sandswap Install | Docker default | Kata |
|---|---|---|---|---|
| `NO_NEW_PRIVS` | yes | yes | no | no |
| Seccomp deny list | 82 syscalls | identical 82 | default profile | Docker profile |
| mount / unshare / setns / bpf | blocked | blocked | allowed | allowed |
| ptrace / `process_vm_*` | blocked | blocked | allowed | allowed |
| Capability bounding set | empty | 10 caps | 14 caps | 14 caps |
| VMM-level `allowed_dirs` | yes | yes | none | different mechanism |

Sandswap Install is not weaker than Docker/Kata on any line above, and
strictly stronger on seccomp and `NO_NEW_PRIVS`; the 10 ambient caps
(`CHOWN`, `DAC_OVERRIDE`, `SETUID`/`SETGID`, `AUDIT_WRITE`, …)
cannot widen because `capset` is bounded by the bounding set, and the
capabilities Docker grants that Sandswap withholds — `CAP_NET_RAW`,
`CAP_SETFCAP`, `CAP_SYS_CHROOT`, and the `CAP_SETPCAP`/`CAP_MKNOD` pair —
are exactly the persistence and escape
primitives a chrooted workload does not need.

### 7.2 The warden as a target

Agent code and the warden run as the same uid 0 in the same pid namespace,
so the warden hardens itself at boot:

- **`PR_SET_DUMPABLE=0`** makes the kernel deny every ptrace-checked
  `/proc/1` entry (`mem`, `root`, `fd`, `maps`, `environ`, `task/N/*`) to
  callers without `CAP_SYS_PTRACE` — which no exec profile keeps in its
  bounding set. This does not depend on the guest's Yama configuration
  (the warden logs a boot warning when Yama is absent so the residual
  assumption is visible). The masked-proc layout is defense in depth on
  top: the sensitive entries are covered and the agent's whole `/proc` is
  read-only.
- **Signals to PID 1 are inert**: PID 1 can signal everyone; the kernel
  discards every signal to PID 1 whose disposition is default, and
  `SIGKILL`/`SIGSTOP` can never be delivered. `kill -9 1` does nothing.
- **The capability set cannot be widened**: `capset` is bounded by the
  bounding set (pre-dropped at boot to the install baseline), and
  `CAP_SETPCAP` — the capability that would otherwise reconfigure a set —
  is not granted to either profile. The paths
  that would reach the warden's privileges — ptrace, `process_vm_*`,
  `open_by_handle_at`, mount API, `unshare`/`setns`, `bpf` — are all
  seccomp-denied regardless of capabilities.

### 7.3 The warden's vsock port

Seccomp does not block `socket`/`connect`, so reachability is closed at
three layers. With the shipped guest kernel an agent cannot reach any
warden: a `connect()` to the VM's own CID fails `ENODEV` (the guest kernel
ships no vsock loopback transport — pinned at build time: kernel/build.sh
refuses a config that enables it), and a packet to another VM's CID is
dropped on the host (vhost-vsock accepts guest packets addressed to the
host CID 2 only; it never relays between guests). The warden then refuses
to lean on either kernel fact alone: the accept loop closes every
connection whose peer is not the host (CID 2 — the same hypervisor-assigned
identity the heartbeat gate below uses), so a kernel or VMM-backend change
that made in-guest dialing reachable still meets a protocol that will not
talk to it. One direction stays open by design: an agent can connect to
the HOST CID 2, where vsockguard does not apply (it gates host-originated
connects). No host service listens on vsock today; any future host-side
vsock listener must treat guest-originated connections as hostile
([Threat Model](threat-model.md)). Beyond the gate, the protocol is still
written as if a hostile peer could connect:

- **Nothing a peer sends can affect another connection.** The warden
  serves each connection as an independent request/response task; its
  listening fd is PID 1's private descriptor (`/proc/1/fd/N` returns
  `ENXIO` when reopening socket fds); vsock is a stream protocol, so data
  cannot be injected into the sandlot's established connection. Response
  forgery to the sandlot is structurally impossible.
- **The swap ops are hardened against a hostile caller**: pinned
  `mount_point`, volume-identity cross-check + self-heal, frame parsing
  that assumes garbage (§3.4).
- **Resource parking is bounded** (a peer holding resources without
  using them): a hard cap on concurrent connections
  (excess connections are accepted-then-closed — the sandlot treats that
  as a re-dialable transport error), a global in-flight request-body
  budget, a first-frame timeout for freshly connected peers (idle pooled
  connections are deliberately *not* timed out), and a per-window log
  limiter so a frame-flood attack cannot burn the guest CPU or the serial
  console through the logging path.
- **The same holds for the VMM's decisions**: the sandlot — not the guest
  — sets `allowed_dirs`; a hostile connection can mount only within what
  the filter already allows, and can never widen it.
- **One op carries a VM-wide side effect, not just a caller-local one**: a
  heartbeat (`OP_MEM_STATS`) resets the warden countdown anchor, the
  last-resort mount release ([microVM Lifecycle](vm-lifecycle.md) §8). Only
  the sandlot is a legitimate sender, and the warden enforces it: **only a
  heartbeat whose peer is the host (CID 2) resets the anchor** — a
  guest-originated heartbeat is ignored (and logged at a bounded rate). The
  source CID is assigned by the hypervisor/vsock transport and cannot be
  forged from inside a guest, so this gate holds even on a guest kernel
  where in-guest dialing would otherwise become reachable.

### 7.4 The tenant network: one shared bridge, filtered

The network is the one boundary that does NOT come from the microVM: every
VM's TAP is enslaved to one shared host bridge, so without a filter set all
tenants are L2 neighbors — able to ARP-poison each other, to reach each
other's guest kernel network stack directly (the same crafted-packet
surface an internet host sees), and to reach the host's own listeners on
the bridge IP. The isolation is a three-layer nftables baseline the sandlot
installs and owns, enforced with the same fail-closed discipline as the
rest of the stack:

| Layer | What it stops | Mechanism |
|---|---|---|
| Per-TAP source anti-spoof | a tenant emitting frames with another tenant's (or a foreign) source address — the precondition for "address = identity" and for the egress binding | netdev ingress chain on each TAP: any frame whose source address is not the TAP's assigned address is dropped |
| VM-to-VM deny (default posture) | tenant↔tenant traffic of every kind — ARP/NDP poisoning, port scans, crafted-packet attacks on another guest's kernel stack | bridge-family forward chain: frames forwarded between `tap*` ports are dropped (operators can explicitly allow this for cooperative multi-VM agent systems) |
| Guest→host default-deny | every host listener over the bridge IP — the agent/human/stream listeners and any future host service | inet input chain scoped to the bridge/TAP INTERFACE (not the guest source prefix, so a forged source cannot bypass it): only the DNS resolver (and replies to host-initiated flows) is admitted; everything else is dropped |

Fail-closed: with a network backend configured, a sandlot that cannot
install the baseline (nftables missing, table installation refused) does
not degrade to an unfiltered bridge — it refuses to start; the only opt-out
is an explicit `egress_baseline: off`. `security/verify-host-security.sh`
(check 12) re-asserts all three layers on any host carrying the sandbox
bridge. The routed-ipv6 backend adds the same per-TAP anti-spoof plus the
per-attachment identity stamp ([Egress Enabler
Contract](egress-enabler.md)).

What remains by design: aggregate per-netns counters (§6.4), and the
machine-reuse linkability already listed in §6.5 — the bridge filtering
isolates tenants from each other, it does not hide that one host serves
them all.

## 8. How this is verified

The swap and isolation behaviors are pinned by dedicated end-to-end
suites, not by inspection:

| Suite | What it proves |
|---|---|
| `e2e/overlayfs-isolation.sh` | read-only rootfs (kernel-enforced), writable `/workspace`·`/home/agent`, only the active volume visible through the filter, `/tmp` local to the node, and planted markers (symlink / FIFO / regular junk file) inert on the host side — no host-file read, no mount-path hang, no mode flip |
| `e2e/cross-tenant-residue.sh` | the A→B switch on one VM: A's SysV/`/dev/shm` plants are swept, mqueue creation and the keyring plant are denied by seccomp, the masked `/proc` (kmsg/kcore/kallsyms/keys/kernel-state files, read-only) and minimal `/dev` hold for B, no dead-state TCP rows survive, and the warden vsock port is unreachable from inside the guest (no loopback, no cross-VM routing) |
| `e2e/warden-hostile.sh` | the hostile-peer contract (malformed frames, oversized bodies, hostile `mount_point`, connection/body DoS bounds — none may kill PID 1), plus `/proc/1` dumpable + fd-channel isolation, PID-1 signal immunity, the switch-window mount self-heal, the `setsid`-straggler sweep, and `RLIMIT_AS` enforcement |
| `e2e/seccomp.sh` | the exec profiles live: deny-list, `NO_NEW_PRIVS` + `nosuid` suid neutrality, capability bounds |
| `e2e/share-root-gate.sh` | the filter as a namespace control, on a real stack: the escape-attempt matrix from inside an exec context (`/proc/1/root`, `..`, mount table, a `find` for the sibling volume — the share root must be unreachable), the agent's own tree still fully usable, the share root's entry set unchanged by a whole agent workload, a sibling volume's sentinel untouched, the running VMM's API surface (a second share is not attachable: no `vm.add-fs` route; `vm.set-fs` still applies), and the dispatch-level tests below run against the same binary |
| `security/verify-host-security.sh` | the host-side invariants the VM boundary leans on: device ownership, mount hardening, and the network isolation baseline of §7.4 (check 12) |

Unit-level pins live with the code they pin — the filter's fail-closed
defaults and share-root class gate, the single-component name rule, the
set-fs revocation epoch and open-handle cap (`virtiofsd`/`vmm` suites); the
teardown setup↔teardown symmetry, the residue-sweep wire parsing, the
cold-exec identity refusal and the warden-attribute restore (warden suite);
the sandlot's mount-identity cross-check and the file-op identity
(`sandlot` suites); the volume-stamp MAC and the rotation tool's safe
read/write (`sandlot/provision/volume`).

## 9. In one paragraph

A pooled microVM is time-shared across SandFS by swapping what it can see,
never by rebooting: the sandlot drives the swap, the VMM's virtio-fs filter
decides which host directories exist for the guest at all, and the warden —
from inside — builds the guest mount stack, proves what it mounted, and at
release kills every process, detaches every mount, drops every cache,
sweeps every kernel object and socket, before the filter is cleared. If any
step cannot be proven complete, the VM is destroyed rather than reused.
The result is the guarantee this page set out to explain: **agent B's
execution on a reused microVM starts with zero residual state from agent
A** — no process, no reachable page, no shared memory, no filesystem
metadata, no network trace, and no path in any layer that names A at all.
