---
title: Template Contract
nav_order: 5
parent: Operations
---

# Template Contract

A Sandswap template is a rootfs tree that the platform materializes into SandFS volumes
(flat) or mounts as read-only OverlayFS lowerdirs (overlay). Template content is served to
guests by the **virtio-fs passthrough daemon** (the `sandvmm` identity) and mounted by the
**exec sandlot** identity — neither is the tree's owner. Every read therefore travels
through the **shared group** (the same grant the storage contract uses). The contract below
is what makes that possible; it is implemented once, in
`sandlot/provision/template.NormalizeTemplateTree` / `ValidateTemplateTree`, exposed as the
`output/template-tool` CLI.

## 1. The rules

| # | Rule | Why |
|---|---|---|
| 1 | **Directories: `g+rx`** (group traverse + list) | the virtio-fs server resolves paths through them; without group traverse every guest read EACCESes |
| 2 | **Regular files: `g+r` where the owner can read; `g+x` where the owner can execute** | the virtio-fs server performs the guest's reads as its own uid; the group bit is the grant |
| 3 | setuid/setgid/sticky are preserved as authored | inert host-side (`nosuid,nodev` mounts, storage contract row 9); guest-side semantics (`su`, `umount`) stay intact |
| 4 | Ownership inside the tree is irrelevant | materialization ignores tar uid/gid; the setgid store assigns the shared group. The TREE-level group is load-bearing — see §2.1: normalize grants the bits, the tree must carry the deployment's shared group for them to open anything |
| 5 | Symlinks: tree-internal relative targets (absolute targets are rewritten at extraction) | extraction containment |
| 6 | Device/FIFO/socket entries are not supported | inert under `nodev`; no template needs them |
| 7 | Content that must stay private (SSH private keys, credentials) belongs in `home/` or `workspace/`, **never the read-only rootfs** | rootfs content is necessarily group-readable by the service identities |
| 8 | **Group and other write bits are cleared** (the owner keeps write; sticky/setuid/setgid survive) | template trees are shared storage; a tenant-chmod'ed `0777` entry would let another local identity rewrite content every tenant executes. Flat materialization re-adds group write (the agent's shared-group path) but never other-write. |

## 2. Producing a conformant template

```bash
# 1. Build the tree however you like (debootstrap, tar extraction, cp -a …).
# 2. Normalize it with the canonical tool:
output/template-tool normalize /path/to/rootfs
# 3. Validate (also a build gate): the rules above PLUS the rootfs
#    well-formedness rules in §3 — an off-contract template reads as EACCES
#    inside every guest, one without /bin/sh never execs at all:
output/template-tool validate /path/to/rootfs
```

- The stock build scripts (`build/build-rootfs-template.sh`,
  `build/build-ubuntu-rootfs.sh`) run both steps automatically; the deploy scripts that
  stage templates into the flat scan dir do the same and `chgrp` the tree to the shared
  group (the group is the grant — **do not** "fix" readability with `chmod -R a+rX`,
  which widens to every local user instead of the service group).
- `template-tool import` (an OCI image archive / rootfs tar → template tree
  or OCI registry;
  [Building Templates](../building/templates.md#21-automated-template-tool-import))
  normalizes and validates as part of the conversion — its output needs no
  extra pass. It also **settles the published tree's group** (§2.1 below).

## 2.1 The group grant and cross-host moves

Normalize grants the group BITS (rules 1–2); the grant only opens anything
when the tree's GROUP is the deployment's shared group — the group of the
scan root / template store — because the consuming identities (prov copy,
overlay mount, the FUSE daemon's every guest read) hold that group as a
supplementary group and are never the tree's owner. Two consequences:

- **Publish straight into the scan root when you can**: the setgid root
  gives the tree the right group at creation, and `template-tool import`
  settles any residue (`--group NUM|NAME` overrides; a numeric gid is used
  as-is, a name resolves on the host you run it on). The one flow that
  still bites is a private `--out` followed by a privilege-preserving copy
  (`sudo cp -a`): the invoker's group travels with the tree and every
  group-grant entry EACCESes at sandfs create (`STORAGE_ERROR`). If you
  must move a tree between hosts, re-settle it on the target:
  `chgrp -R <shared gid> <tree>` — **numbers, not names**: group names
  carry per-host variance while the numbers are the contract (take the
  target's numbers from its `/etc/sandswap/identity.env`; see also
  `common/sh/runtime.sh` on fleet-wide identity pinning).
- **Audit offline**: `template-tool validate <dir> --expect-group NUM|NAME`
  walks the tree and reports every group-grant-reliant entry — a regular
  file without other-read, or a directory missing either other-traverse
  or other-list (the daemon's readdir is every guest `ls`) — whose gid
  differs from the expected one: error severity, with the exact
  `chgrp -R` fix in the finding. The walk needs to LIST every directory
  (the contract rules run on the same pass), so a real distro tree with
  a `0700 /root` can only be audited by its owner or root — run the
  audit as the identity that built the tree, or as root; an entry the
  walk cannot list is reported as `unreadable` (error), never silently
  skipped. `check-store` runs the same audit over `layers/`, over every
  template tree a ref registers INSIDE the store (the
  `import --out <store>` shape), and — with `--expect-group` — over the
  store root itself, all against the store root's own group by default.
  A store moved with `cp -a`/`rsync -a` from a differently-numbered host
  is internally consistent yet unreadable on the target, so pass the
  TARGET's shared gid: `check-store <store> --expect-group <gid>`
  (numeric form; a name resolves here). Flat scan-root trees outside the
  store may carry a different group each — audit them with
  `validate --expect-group`.
- `save-template` and OCI template *pulls* are normalized by the prov role itself at
  materialization; when it has to repair a non-conformant artifact it logs a warning naming
  the layer — run `template-tool normalize` on the source to fix it upstream.
- Flat-template registration (`flat-templates/` scan) validates and warns (it does not
  refuse: flat seeding repairs modes at consume, so foreign content cannot brick startup).

## 3. Rootfs well-formedness: `template-tool validate`

`validate` is the full offline conformance pass over a template tree — the
modes contract of §1 plus everything a runtime consumer needs from the tree's
SHAPE. It mirrors checks the platform applies at consume time (warden exec,
mount-time validation, import paths), so a template that passes cannot fail a
runtime check for a STATIC reason:

| # | Rule | Severity | Why / runtime counterpart |
|---|---|---|---|
| 1 | the §1 modes contract (same findings as `check`) | error | the guest read path (§1) |
| 2 | `/bin/sh` resolves, via symlinks with **chroot semantics** (absolute targets resolve against the tree root), to an executable regular file | error | the warden execs `/bin/sh -c` for every agent command; a root without it cannot exec |
| 3 | no volume control files at the tree root (`.sandfs-id`, `.provisioning`, `.save-staging`) | error | volume state is never template content; save-as-template strips them — a template carrying them leaks the source volume's metadata into every guest |
| 4 | the attach-critical skeleton entries `dev proc workspace home` are **real directories** | missing, symlinked or not a directory → error | the warden secures each with a FATAL mount step (`open_dir`: mkdirat on ENOENT, refuse a symlink); a read-only overlay root cannot be repaired, so the whole attach is refused — and the import paths cannot create or replace the entry either |
| 5 | the soft skeleton entries `bin etc` resolve to a directory (same chroot semantics as `/bin/sh`; a usr-merge `bin -> usr/bin` is legitimate) | missing → warning; dangling symlink, unresolvable or not a directory → error | these degrade instead of refusing (the busybox hot-bind is skipped, resolv.conf injection is best-effort) — but a dangling link is still unrepairable by the import paths |
| 6 | `sys/` and `tmp/` exist (same chroot-semantic resolution) | warning | the warden mounts the real proc/dev inside the guest and expects them (empty is fine) |
| 7 | no device/FIFO/socket entries | warning | unsupported (§1 rule 6); skipped when the template is pushed — a saved layer may carry tenant-planted ones, a hand-built tree should not |
| 8 | `--expect-group`: every group-grant-reliant entry carries the expected gid — a file without other-read, or a directory missing other-traverse or other-list | wrong gid or an unreachable subtree → error; all reliant entries matching → info | §2.1 — the group is the grant; a reliant entry with a foreign gid is EACCES for every consuming service identity |
| 9 | the walk can LIST every directory (the contract rules share the pass) | a directory this identity cannot list → `unreadable` error naming it; the contract below it is unjudged | §2.1 — run the audit as the tree's owner or root; a partially inspected tree never passes the gate |

Errors fail the gate (exit 1); warnings and info print but exit 0. Given a
scan root (`<name>/<version>/` nesting, or a bare `<name>/` rootfs) the tool
descends and validates every leaf tree — the same classification the
registration scans apply. Given a store directory (`refs/` or `layers/`) it
refuses and points at `check-store`: layer trees under `layers/` are
fragments, not complete rootfs trees.

## 4. Store integrity: `template-tool check-store`

```bash
output/template-tool check-store /var/sandswap/templates \
    --flat-root /var/sandswap/flat-templates
# cross-host store (moved with cp -a from a differently-numbered host):
output/template-tool check-store /var/sandswap/templates --expect-group 985
```

The offline pass over a template store (`refs/` + `layers/`). Every rule
mirrors a check the two runtime ref loaders and the layer validators enforce
at consume time — on shared storage a peer node or a tampered store can
rewrite a ref, which is exactly why those checks exist; this finds the same
defects before a template reaches a consumer:

| # | Rule | Severity | Runtime counterpart |
|---|---|---|---|
| 1 | every `refs/*.json` is a **regular file** (bounded size) that parses; the entry's `name`/`version` encode to the ref file's base name | non-regular or oversized → error; unparseable → error; identity mismatch → error (the `:`↔`_` filename encoding is not injective — the cross-tenant rootfs-substitution class; every loader refuses it); legacy or partial identity → warning | the ref loaders; a FIFO or device at a ref name would block a reader forever, and no writer produces one |
| 2 | `mode` is `flat`/`overlay`/empty and agrees with the filename suffix (a recorded empty mode reads as overlay) | all disagreements → warning (readers select the file by filename suffix and never consult the field); a legacy no-suffix filename → warning (listing-only: loaders open only `<ref>.<mode>.json`) | the ref loaders |
| 3 | layer ids carry no `:`/`,` separator; relative ids stay under `layers/` lexically; absolute overlay ids stay inside the store | error | the mount-time layer trust boundary (the `:`/`,` rule is `validateLayerID`'s overwrite of the `lowerdir=` option) |
| 4 | a layer's RESOLVED path stays inside its per-consumer root: overlay → the store; flat → the store or a configured scan root | outside the store (overlay) / outside every root (flat) → error; a relative layer that leaves `layers/` but stays in the store → warning (mounting and seeding accept it; packing refuses it) | the mount-time symlink leg (`overlay.go`) and the flat seeding boundary (`--flat-root` repeats the prov instance's `-flat-templates` roots) |
| 5 | absolute **flat** layer paths are lexically inside the store or a configured scan root | unjudgeable (no `--flat-root` given) → warning; outside every given root → error | the flat seeding trust boundary — pass the PROV instance's `-flat-templates` path as the refs record it (a shared store records the PROV host's mount path, which differs from other hosts' view) |
| 6 | every named layer exists and is a directory | store-owned relative layer → error; absolute scan-root source → warning (durable ref by design: re-creating the source directory restores the template) | read-time existence (a missing layer hides the ref from listings and fails creation fast) |
| 7 | recorded OCI layer digests parse; an `oci_layers`-only ref is stored as flat; a ref does not mix `layers` with `oci_layers` | unparseable digest or an OCI-only overlay ref → error; mixed provenance → warning | only the flat creation path consumes `oci_layers`; the overlay mount loader refuses a ref with no local layers |
| 8 | `layers/` naming (`sha256-<digest>` / `local-<name>-<version>`), orphaned layers, writer debris (staging dirs, publish markers, save locks) | warning / info | reachability-GC inverse; the staging reaper |
| 9 | static group audit (§2.1): every group-grant-reliant entry under `layers/` and in every template tree a ref registers INSIDE the store (the `import --out <store>` shape) carries the expected group; with `--expect-group` the store ROOT is judged too | error | the group-grant failure class — the FUSE daemon's reads and the overlay mounts; the default expected value is the store root's own group, which cannot catch a whole store moved from a differently-numbered host (internally consistent, unreachable) — hence `--expect-group <target gid>`. Flat scan-root trees (outside the store, each possibly with its own group) are audited by `validate <flat-root> --expect-group` instead; writer-internal staging under `layers/` is never judged (mid-flight state) |

## 5. What the contract does not require

- No specific owner/uid (rule 4).
- No world access. Templates are readable by exactly: root, the file's owner, and the
  shared group — nothing else on the host.
- No size or layout constraints (beyond the platform's general path limits).
