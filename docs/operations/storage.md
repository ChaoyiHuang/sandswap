---
title: Storage Requirements
nav_order: 4
parent: Operations
---

# Storage Requirements

Sandswap's volume and template storage is a contract, not a preference. This
page defines what the system actually needs from a filesystem (derived from
code behavior, not aspirations) and how to deploy the reference shared
setup. Sandswap imposes no backend type or vendor restriction — backend
options and their trade-offs are covered in
[Storage Backends](../integration/storage-backends.md).

## 1. The storage contract

A backend is supported if and only if it satisfies every MUST:

| # | Requirement | Why (code behavior) |
|---|---|---|
| 1 | POSIX filesystem, mounted at **identical absolute paths on every node** | `allowed_dirs` carries absolute host paths; placement migrates volumes across nodes |
| 2 | **Numeric uid/gid fidelity** — ownership crosses nodes as bare numbers, no name-based mapping | The shared-group model is built on pinned identities (below) |
| 3 | **setgid directory inheritance** honored server-side | Every shared directory propagates the shared group through setgid |
| 4 | Atomic `rename()` within a directory | Template refs and identity snapshots are written tmp+rename |
| 5 | Symlinks and mode bits (incl. exec) preserved | Template seeding copies with `cp -a`; agents create symlinks |
| 6 | Read-only **OverlayFS lowerdir** mountable by the node kernel on this fs | Overlay-mode SandFS mounts the template layers as a lowerdir-only overlay (no upperdir or workdir ever lives on shared storage) |
| 7 | **No cross-node file locking required** | The only `flock`s in the system are node-LOCAL: the single-node identity store and the one-sandlot-per-host role lock (`/run/sandswap/sandlot.role`) — both on private filesystems, never traversing shared storage; distributed identity lives in etcd. This is an invariant — new code must not introduce cross-node locks |
| 8 | **Unmount acts as a durability barrier** | The failover model (placement + CONNECT-CLEAN) releases mounts before another node may take over; the release path's `umount` + cache drop is what makes takeover safe |
| 9 | **Mounted `nosuid,nodev` on every consumer host** | The virtio-fs passthrough stores guest-requested mode bits (incl. setuid/setgid) and `mknod` verbatim on the volume. The planted-file owner is the sandvmm identity (987) — NOT the vsockguard-trusted uid — so the identity split already breaks the escalation chain; these flags are the host-side belt that keeps planted bits/device nodes inert even on a host that skipped the split. **Startup-enforced**: the sandlot statfs-checks `-volumes-dir` and refuses to start without both flags (fix: `mount --bind <dir> <dir> && mount -o remount,bind,nosuid,nodev <dir>`; `-allow-insecure-volumes` is the explicit dev/test admission). Also checked by `security/verify-host-security.sh` (guest-side containment: warden `NO_NEW_PRIVS` + `nosuid` share mounts, asserted in `e2e/seccomp.sh`) |
| 10 | **The sandvmm (987) and sandprov (983) identities pinned on every node** | FUSE-created files carry uid 987 and prov-created volume files carry uid 983 everywhere; mixed 983/985/987 ownership across nodes is the normal state, bridged by the shared group (setgid dirs; target modes 2770/0660 — the current copy path may leave 2775/0664, see §4.3.4). Creator uid is irrelevant to the model — the shared group is the grant. Deletion relies on it twice: the warden's umask 0002 makes guest-created defaults group-writable (target 0660/2770; current defaults can be 0664/0775 — see §4.3.4; prov removes them directly), and deliberately restrictive guest modes (chmod 700) converge via DeleteVolume's orphan-rename (a `rename()` beside the volumes root needs write on the root, which the provision identity — its owner — has: row 11) |
| 11 | **The volumes root (the virtio-fs share root) is `<prov-user>:<shared-group> 2710`** — setgid, group **traverse-only (no read)** | The FUSE daemon (sandvmm 987) is in the shared group, so group write on the share root would let a guest-driven escape *create, remove or rename entries at the root* (the class the daemon's root gate also refuses). With the root group-write-free, that class fails in the **kernel**: the only writer is the prov role, which owns it (`EnsureVolume`, `DeleteVolume`, the orphan-rename). Group READ is also denied: the daemon cannot even `ls` the root, so tenant directory names are not enumerable — guessing is the only remaining path, and row 12 closes that. Guest read/write inside a volume is unaffected — reaching a volume needs *traverse* on the root, and each volume must stay group-rw (2770 + inherited setgid; the current copy path can leave 2775 — see §4.3.4). Built by `ss_prepare_dirs` / `sandswap_create_dirs`, re-asserted by the gateway units' `ExecStartPost` and both k8s DaemonSets' prep container, checked by `security/verify-host-security.sh` (check 9) and probed live by `e2e/share-root-gate.sh` (list refused, traverse OK) |
| 12 | **Volume directory names are opaque (derived, not the sandfs id) and every volume carries a `.sandfs-id` identity stamp** | A volume directory is named `sf-` + base32(HMAC-SHA256(seed, sandfs_id))[:128 bits] by the prov role (`sandlot/provision/volname`) — the id alone is 32 bits of entropy, guessable in a fraction of a second by a local `stat` loop, while the derived name is 2^128. The seed is a deployment secret (root-scoped, `provision.volume_seed_file`; NEVER in a file or identity the sandvmm side can read) and is rotatable (`deploy/baremetal/rotate-volume-seed.sh`) to revoke paths a previously-compromised daemon memorized. The `.sandfs-id` stamp inside every volume (id + one-way seed-generation fingerprint + epoch + mode + created_unix, **HMAC-SHA256-signed with the generation seed and binding the directory name**) is the AUTHORITY on which sandfs a directory belongs to: `EnsureVolume`/`SwapTemplate` refuse a directory whose stamp names another id or whose signature does not verify, the `rootfs-path` repoint endpoint accepts only a verified stamp, and the rotation/migration tooling refuses to move a mismatched one. A stamp that exists but is unreadable (symlink/FIFO/oversize/planted epoch) is the distinct "unreadable" class: `DeleteVolume` still succeeds by **quarantining** the tree (the orphan-rename below, data preserved for ops) instead of deleting it, and `SwapTemplate` refuses. `SaveAsTemplate` additionally refuses a verified stamp whose id differs from the requested sandfs. At startup a FOREIGN generation refuses the prov instance; an UNVERIFIED stamp is a recorded WARNING (the volume stays quarantined), because one tampered stamp must not crash-loop the storage plane. Moving the authoritative stamp OUT of the tenant-writable volume root into a separate metadata directory (volmeta) is the structural fix and remains a planned feature — until then the HMAC signature is the evidence and the quarantine behavior is the containment. In flat mode the volume root is the tenant's chroot, so the file is tenant-writable — the signature is what makes it evidence. **Tool contract: never read or write the stamp with shell redirection/grep** (a planted symlink turns that into an arbitrary host-file operation); use `template-tool volume-stamp-read` / `volume-stamp-write`, which are symlink/FIFO-proof. **Tool contract: never derive a volume path from the sandfs id** — resolve it via the API record (`rootfs_path`) or the prov role; anything hard-coding `<volumes>/<sandfs-id>` breaks the moment this feature exists |

| 13 | **Per-sandfs quota is the STORAGE PLANE's to enforce** — sandswap only stamps | A quota is only observable where 100% of writes land: agent writes go guest kernel → virtio-fs → the backend, while the prov instances' own writes (template seeding, `SaveAsTemplate`, deletes) go host-side around virtio-fs entirely. No sandswap layer sees both. The prov role therefore exposes a stamping hook only — `provision.quota_stamp_cmd` (empty = disabled; the contract lives in `sandlot/provision/volume/quota.go`): the storage operator's implementation receives the sandfs id in argv and the volume path on **stdin** (the path is the seed-derived, unguessable directory name and must never appear in `/proc/<pid>/cmdline`, which the sandvmm identity can read) at creation, exit 0 = stamped, failure refuses the create (fail-closed). Map it onto the backend's primitive: CephFS `ceph.quota.max_bytes` xattr, an XFS project-ID assignment, a ZFS dataset property, or an external quota manager. **Production deployments must configure this hook** (or enforce quotas directly on the backend); the built-in `-max-uses`/VM memory limits bound a guest's RAM, not its persistent volume. NFS has no per-directory quota primitive — if quota is a requirement, that is a backend-selection criterion, not a sandswap feature |
| 14 | **`.orphan-<ts>` reclamation is the prov role's, with an ops queue for stragglers** | When a tenant's restrictive modes block physical removal (or the stamp is unreadable and the tree is quarantined), `DeleteVolume` renames the tree to `.<volume>.orphan-<ts>` beside the volumes root so the id becomes reusable immediately — the directory then has no record, no agent and no platform reference. The prov role runs the reclamation: an immediate pass at startup and then hourly, removing orphan-shaped direct children older than one hour (each under a 5-minute context). A tree that still cannot be removed is deduplicated and appended (one name per line, capped at 4096 entries, oldest first) to the volumes-root `.orphan-queue` file (0600) for the storage operator to act on. Ops must drain that file; it is the only surfacing of stuck sequences |

Additional properties that are relied upon where present: close-to-open
freshness (a node mounting after takeover sees the latest state on first
open), and xattr support (virtio-fs passthrough; degrades gracefully).

## 2. Pinned service identities

All nodes must create the service identities with the SAME numbers:

| Identity | uid | gid |
|---|---|---|
| `sandlot` (the per-node daemon; the uid vsockguard trusts) | 985 | 985 |
| `sandserv` (gateway + sandns; renamed from `sandswap`, same pinned 986) | 986 | 986 |
| `sandvmm` (VMM + FUSE passthrough daemon; **separate from the warden-trusted uid**, zero capabilities) | 987 | 987 |
| `sandprov` (provision identity — sandfs/template lifecycle; carries the shared-storage write grant the gateway sheds) | 983 | 983 |
| `sandtmpl` (group only — template-store metadata group; members `sandprov` + `sandlot`, never `sandvmm`) | — | 982 |

`sandserv` holds **no shared-group membership and no storage path**: every
sandfs/template operation routes over the node stream to a prov sandlot instance,
so the external-facing identity never touches the volumes tree (its only state
is the identity snapshot in its own state directory). `sandprov`'s grants
are the shared group and `sandtmpl` (no capabilities, no kvm, no vsock
devices).

`sandvmm` membership: `kvm` (/dev/kvm) + the `sandlot` shared group (volume
writes via the setgid model, API-socket group grant). Files its FUSE daemon
creates carry uid 987 — a guest-planted setuid file owned by it escalates to
an identity with **no warden access** (vsockguard pins 985), which is the
point of the split. Existing 985-owned volume files need no migration: the
shared group keeps them writable by both.

`deploy/baremetal/setup-host.sh` pins these; a host where the numbers are
taken refuses loudly (override with `SS_UID_*`/`SS_GID_*` — but the SAME
override must be used on every node, and the numbers must match what the
storage server sees). A dynamically-assigned gid is the classic
shared-storage failure: node A's `sandlot` group is gid 990, node B's is
994, and a volume that migrates between them carries group ownership nobody
on the other node can use.

## 3. NFS deployment recipe

The single-node e2e suite validates real NFS semantics on every run with
`STORAGE_BACKEND=nfs` (a loopback `nfs-kernel-server` export under
`/srv/sandswap-nfs`): numeric identity, setgid inheritance, OverlayFS
lowerdir over NFS, and the umount barrier all execute through the actual
client-server path. Production exports should follow the same shape:

```text
# /etc/exports on the storage server.
# NEVER use '*', the sandbox subnet, or the node's general/uplink IP here:
# guest traffic can NAT to the node IP. Use the compute nodes' dedicated
# STORAGE interface IPs only, and still block sandbox -> storage at the host
# firewall (§4).
# Choose ONE line per export. Preferred: Kerberos. Fallback: squash all
# identities (pre-create the export layout on the storage server as local
# root before exporting).
# /export/sandswap/volumes   <compute-node-storage-ip>(rw,sync,no_subtree_check,sec=krb5p)
/export/sandswap/volumes   <compute-node-storage-ip>(rw,sync,no_subtree_check,root_squash,all_squash)
# on EVERY consumer host: mount the export with nosuid,nodev (contract row 9)
mount -t nfs4 -o nosuid,nodev storage:/export/sandswap/volumes /var/lib/sandswap
# /export/sandswap/templates <compute-node-storage-ip>(rw,sync,no_subtree_check,sec=krb5p)
/export/sandswap/templates <compute-node-storage-ip>(rw,sync,no_subtree_check,root_squash,all_squash)
```

Rules:

1. **A non-squashing export is a deployment-time bootstrap concession, not a
   runtime control.** NFSv3/v4 `sec=sys` (AUTH_SYS) lets any reachable client
   *claim* uid 0 / gid 985; if the export does not squash that identity, the
   server treats the claim as root, and a guest that can reach the export can
   read/write every volume — the 2710 share root, the seed, and the
   `.sandfs-id` stamp do not help (see §4). Prefer `sec=krb5p`; if that is not
   possible, use `root_squash,all_squash`, keep volume modes 2770/0660, and
   still block sandbox → storage at the network layer. The export client list
   is necessary but not sufficient: do not allow `*`, the sandbox subnet, or
   an IP that guest traffic can NAT to. The production bootstrap is a one-time
   operation on the storage server (local root): pre-create the export layout
   (`<prov>:<shared-group> 2710` volumes, 2750 templates), then export with
   Kerberos or `root_squash,all_squash`. Do not leave a non-squashing export
   on at runtime just because the deployment scripts bootstrap from a
   compute node.
2. **NFSv4 idmapping** — either keep `/etc/idmapd.conf` domains identical on
   server and all clients (the pinned users must resolve identically), or
   use numeric-only mounts (NFSv3 style). A mismatch silently maps uids to
   `nobody`, which fails exactly like a broken gid.
3. **Uniform mountpoints** — every node mounts the exports at the same
   paths (`/var/lib/sandswap/volumes`, template dir), matching the
   single-node layout. Placement, `allowed_dirs`, and OverlayFS lowerdir
   paths are absolute.
4. **Export root layout** — the exported directories carry the same layout
   `setup-host.sh` builds locally: the **volumes root is
   `<prov>:sandlot 2710`** (setgid, group traverse-only — row 11 in the MUST
   table) and the template store is
   `<prov>:<shared-group> 2750` for the store root (prov writes; the FUSE
   daemon reads layer content through the shared group) with the `refs/`
   metadata tree group-scoped to **`sandtmpl` (gid 982)** — members
   `sandprov` + `sandlot` only, **never `sandvmm`**: the daemon can serve
   layers but cannot enumerate template refs. Host prep creates `sandtmpl`
   with the identities; a host without the group keeps the shared group on
   `refs/` (best-effort — the mode still blocks every other local user).
   Human users list/use templates through the gateway/prov, not the host
   filesystem; the store is never directly readable by human callers. A
   rename-swap of `layers/`/`refs/` must be impossible.
   Server-side inheritance must match, or volumes created over the export
   land in the wrong group.

## 4. Production storage isolation (MUST) — the storage service is not a tenant network

> This section is the operational answer to the **C1** class. It applies to
> **every** backend (NFS, CephFS, SMB/CFS/NAS, managed cloud file storage,
> local ext4/bind mounts, object stores), not just NFS. The rule is simple:
> **no guest process may have a network path to the storage backend or to
> storage credentials.** The in-sandbox controls (virtio-fs `allowed_dirs`,
> alias, `.sandfs-id`, 2710 share root, seed-derived names) only protect the
> virtio-fs path; they are not a defense against a guest that speaks the
> storage protocol directly.
>
> **Owner boundary.** The controls below are **deployer/storage-operator
> responsibilities**, not Sandswap core code. Sandswap provides the
> virtio-fs isolation, volume modes/seed/stamp, the host input guard
> (guest→host default block) and the egress identity enabler (Carrier A
> binding region or Carrier B identity-in-IPv6 address). The production
> network/egress policy, storage-server authentication and export allowlists
> are owned by the deployer/storage operator; the e2e/deploy scripts are
> test/validation scripts and not a production implementation.

### 4.1 The attack risk

A tenant controls arbitrary code inside its microVM and can open AF_INET
sockets. It does **not** need `mount(2)`, CAP_SYS_ADMIN, or a VMM escape: a
userspace NFS/SMB/HTTP client is enough. If the sandbox network can reach the
storage service, the guest can:

- **NFS**: speak AUTH_SYS and claim **uid 0 / gid 985**, because AUTH_SYS
  credentials are client-supplied. With a non-squashing export the server
  treats that as root; it can `READDIRPLUS` the volumes root (root bypasses the 2710
  DAC), read/write/delete every `<volumes>/sf-*`, and read/poison
  `<templates>/layers/local-*`. The seed-derived names and the `.sandfs-id`
  signature are irrelevant: root can list the directory.
- **SMB/CFS/NAS**: guest/blank credentials, NTLM relay, or a permissive share
  can give read/write to the same tree.
- **CephFS**: a cephx key leaked into the guest, a world-readable key, or
  overly broad caps give direct filesystem access; the mon/mgr endpoints are
  also reachable attack surface.
- **Managed/cloud file storage**: the security group/export policy may allow
  the node's general IP (which guest traffic NATs to) or the sandbox subnet,
  and root squash may be off.
- **Local ext4/bind**: not network-reachable, but a VMM/host path escape, a
  leaked host path, or a mistaken re-export of the parent exposes the same
  tree; the file-mode/other-read issue below applies equally.
- **Object stores**: credentials in the guest environment, a world-readable
  key file, or the cloud metadata path (see the deployment hardening) give
  bucket read/write.
- **Template store**: `save-template` can copy a tenant's flat volume into
  the shared template store. If the store is readable, that is cross-tenant
  exfiltration; if writable, a template can be poisoned so another tenant's
  next mount executes attacker content.

The blast radius is the entire volumes/template tree, not one SandFS, and it
never touches the VMM, warden, alias, or seed.

### 4.2 Why the in-sandbox controls do not help

- The virtio-fs allow-list/alias/revoke, warden chroot, and `.sandfs-id`
  checks run only on the virtio-fs/vsock path. Direct storage traffic does not
  pass through them.
- The 2710 share root denies group read/list, but **root (real or claimed via
  AUTH_SYS over a non-squashing export) bypasses DAC**. The seed-derived name is only
  unguessable if the client cannot list; a storage-root client can list.
- With `root_squash`, a squashed client maps to `nobody`; if volume dirs are
  2775 and files 0664, `nobody` can still **read** the tree. Modes and network
  isolation are both required.

### 4.3 Mandatory controls

#### 4.3.1 Network segmentation (strongest control)

1. Put storage on a dedicated network/VLAN/interface. Compute nodes reach it
   only through their **storage interface**; the sandbox bridge/TAP must have
   **no route** to that network.
2. Guest egress is default-deny. Allow only explicit destinations; explicitly
   drop the storage CIDR, cloud metadata/link-local, the cluster Pod/Service
   network, and any management network.
3. On the host, add explicit firewall drops for
   `<sandbox-cidr> → <storage-cidr>` and the reverse, and remove any NAT from
   the sandbox to storage. Do not rely on the export allowlist: a guest can
   NAT to the node IP that the export allows.
4. Keep blanket FORWARD acceptance out of production. The deployer installs
   the `inet sandswap forward` chain — metadata DROP → uplink-scoped ACCEPT →
   established/related ACCEPT → terminal guest-subnet DROP — and there is no
   iptables FORWARD policy; an operator adding storage/metadata/cluster drops
   edits the same nft table, never a blanket ACCEPT.
5. If storage is on the same host (compact/loopback), bind it to a non-sandbox
   address and firewall the sandbox bridge; never export a directory on the
   bridge subnet.

#### 4.3.2 Export/share authorization

- NFS exports / SMB shares / cloud NAS policies allow **only the compute
  nodes' dedicated storage IPs**. Never `*`, never the sandbox subnet, never
  the node's general/uplink IP that guest traffic NATs to.
- Separate volumes and templates. Templates are writable only by the prov
  plane; compute nodes mount them read-only where the backend allows it.
- Mount with `nosuid,nodev` on every consumer (contract row 9); use read-only
  mounts for paths that do not need writes.
- Restrict export options (`no_subtree_check`, root squash, TLS/Kerberos) per
  backend; do not copy the e2e loopback export.

#### 4.3.3 Protocol identity

| Backend | Required identity control |
|---|---|
| NFS | `sec=krb5p` preferred. If unavailable: `root_squash,all_squash` and 2770/0660 modes **plus** network isolation. Never allow client-claimed root on a reachable export. AUTH_SYS alone is not authentication. |
| SMB/CFS/NAS | Signing + encryption, no guest account, per-share ACLs, network isolation. |
| CephFS | Per-node cephx key with caps limited to the volumes path; key not readable by `sandvmm`/guest; mon/mgr not reachable from sandbox; rotate on compromise. |
| Cloud file storage | Restrict the export/security group to storage IPs, enable root squash where possible, TLS, per-tenant access policy. |
| Object store | Per-tenant scoped credentials/STS; never put node credentials in the guest; block metadata; audit bucket access. |

#### 4.3.4 Mount flags, modes, and the VMM group

- Share root `<prov>:<shared-group> 2710`; volume dirs **2770**; volume files
  **0660**; templates **2750/0640**. Do not rely on 2710 alone; verify each
  volume. The current copy path can leave other-read bits (2775/0664) — that
  is a defect to fix/verify, not a permission to document as 0770.
- Never `chmod 0777` to make an NFS group mismatch go away. On NFS, AUTH_SYS
  checks the **primary gid**; the VMM's supplementary storage group may not be
  honored. Run the VMM with `primary gid = the existing shared volume group`
  (985 by default; uid 987 unchanged, zero caps — no new group and no volume
  ownership migration), and verify it at two points: a node-startup probe that
  opens the volumes root plus one existing volume as the VMM identity (refuses
  to start on failure), and a one-syscall check in the VMM at startup against
  its `--shared-dir` (catches export/group drift without a per-VM process).
- `all_squash` maps every identity to the export's anonymous uid/gid. If you
  use it, the anonymous identity must not collapse the three service
  identities (983/985/987) — otherwise shared-storage access fails even with
  the primary gid aligned. `root_squash` affects only root and does not.
- Keep `nosuid,nodev` even on backends that preserve mode bits; the guest can
  plant setuid/device nodes through virtio-fs.

#### 4.3.5 Privilege separation and credentials

- Only the prov role mounts/writes shared storage. The gateway (`sandserv`)
  holds no storage credentials; `sandvmm` and `sandlot` must not hold storage
  credentials beyond the group grant needed to serve volumes.
- The volume-name seed and storage keys are root:`sandprov` 0640; not
  readable by `sandvmm`; not in the guest environment; not in templates.
- Do not expose `rootfs_path` to agents. Do not put storage credentials in
  agent-visible env/TOML. Rotate keys after any suspected host compromise.

#### 4.3.6 Template store and `save-template`

- Treat `save-template` as a **data-export operation**: authorize it per
  owner/namespace, audit it, and do not let an anonymous/ops-wide caller copy
  any tenant volume.
- Store saved templates in a dedicated group **excluding sandvmm**
  (`sandtmpl`); encrypt or tenant-scope them; never leave 2755/0644 with
  other/group read.
- A writable template store is cross-tenant code execution: a poisoned
  `local-*` layer is executed by the next tenant's mount. Write only from the
  prov instances; verify layer digests/signatures where the backend supports it.

#### 4.3.7 Egress policy and verification

- The default policy is deny; allowlist destinations. Block cloud
  metadata/link-local (`169.254.0.0/16`), storage, cluster control plane, and
  management networks.
- Verify from a guest-like netns (or a real guest): storage port, metadata,
  cluster Service must be unreachable. Do not only test from the host.
- Monitor: export/share configs (`showmount -e`, export policy), NFS/SMB
  client logs, firewall counters, unexpected storage access from sandbox IPs,
  volume mode scans, template save audit.

### 4.4 Backend-specific checklist

| Backend | Specific risk | Required controls |
|---|---|---|
| NFS | AUTH_SYS with client-claimed root (non-squashing export); broad client list | Kerberos or `root_squash,all_squash`; export only storage IPs; block sandbox→storage; 2770/0660; VMM primary gid |
| CephFS | cephx key/caps; mon/mgr exposure | Per-node key scoped to the volumes path; key not readable by sandvmm/guest; network isolation |
| SMB/CFS/NAS | Guest/blank creds, NTLM relay, permissive share | Signing/encryption, no guest, per-share ACL, network isolation |
| Local ext4/bind | VMM/host path escape, leaked path, other-read modes | Dedicated mount, `nosuid,nodev`, 2770/0660; no parent export; treat VMM compromise as storage compromise |
| Object store | Credentials in guest/metadata; presigned URLs | Per-tenant scoped creds; no node creds in guest; metadata block; audit |
| Template/registry | Poisoned template; save-template exfil | Auth + owner binding; per-tenant/encrypted store; write only from prov |

### 4.5 Verification checklist (before production)

- [ ] From a guest-like netns/real guest, storage port (NFS 2049, SMB 445,
  Ceph mon/mgr, object-store endpoint) is **unreachable**.
- [ ] Cloud metadata (`169.254.169.254`) and cluster Pod/Service CIDRs are
  unreachable from the guest.
- [ ] No export/share uses `*` or the sandbox subnet; the client list is the
  compute nodes' storage IPs only.
- [ ] NFS/SMB server logs show no clients from the sandbox subnet; firewall
  counters for sandbox→storage drops are non-zero when probed.
- [ ] Volume dirs 2770, files 0660; templates 2750/0640; no 2775/0664; no
  `chmod 0777` workaround.
- [ ] The VMM identity can open a volume on the chosen backend (primary gid).
- [ ] `save-template` requires authorization and is owner/namespace-bound;
  sandvmm cannot enumerate the `refs/` metadata tree (layer content it
  reads through the shared group).
- [ ] The test-only settings are absent: `-allow-anonymous-human`, the
  loopback NFS test export, `chmod 666 /dev/net/tun`, blanket FORWARD ACCEPT.
- [ ] `security/verify-host-security.sh` and the storage probes pass; rerun
  after any backend/network change.

### 4.6 Corrections to earlier wording in this document

- The old sentence “a non-squashing export … does not widen the runtime attack
  surface; restrict export clients at the network layer instead” is only true
  if the export is **unreachable from the guest** and guest traffic cannot NAT
  to an allowed client IP. With a reachable export, AUTH_SYS + a
  non-squashing export is a root-equivalent grant. The recipe now says this
  explicitly.
- The `*` and `10.0.0.0/8` examples included the default sandbox subnet
  (`10.188.0.0/16`). They are replaced with an explicit storage-IP
  placeholder; do not use `*` or a broad RFC1918 range in production.
- The 2710 share root, seed-derived names, and `.sandfs-id` signature protect
  the **virtio-fs path**. They are not a defense against a guest that can
  reach the storage protocol and claim root/list the tree.
- `root_squash` alone is not enough if volume modes are 2775/0664: `nobody`
  can still read. Fix the modes and the copy path; do not rely on squash.
- The VMM's supplementary storage group is not honored by NFS AUTH_SYS
  (primary gid only). Set the VMM's primary gid to the storage group or use
  a dedicated volume group; otherwise cold mounts fail with EACCES.
- The e2e/deploy loopback NFS, anonymous human gateway, `chmod 666
  /dev/net/tun`, and blanket FORWARD ACCEPT are test scaffolding. They are
  not production recipes and must not be promoted.

## 5. Why local-disk semantics transfer unchanged

Every host-side privilege decision runs through the two service identities
and the host kernel's DAC — the filesystem only has to store and return the
numbers faithfully. Guest-visible ownership is translated in software at the
virtio-fs boundary (the daemon presents root:root to the single-user guest),
so the shared-storage medium never affects what the guest sees.
