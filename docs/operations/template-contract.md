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
| 1 | **Directories: `g+rx`** (group traverse + list) | the daemon resolves paths through them; without group traverse every guest read EACCESes |
| 2 | **Regular files: `g+r` where the owner can read; `g+x` where the owner can execute** | the daemon performs the guest's reads as its own uid; the group bit is the grant |
| 3 | setuid/setgid/sticky are preserved as authored | inert host-side (`nosuid,nodev` mounts, storage contract row 9); guest-side semantics (`su`, `umount`) stay intact |
| 4 | Ownership inside the tree is irrelevant | materialization ignores tar uid/gid; the setgid store assigns the shared group |
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

## 5. What the contract does not require

- No specific owner/uid (rule 4).
- No world access. Templates are readable by exactly: root, the file's owner, and the
  shared group — nothing else on the host.
- No size or layout constraints (beyond the platform's general path limits).
