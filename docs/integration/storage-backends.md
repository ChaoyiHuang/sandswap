---
title: Storage Backends
nav_order: 7
parent: Integration
---

# Storage Backends

Where the volumes and templates trees live — the storage plane behind every
SandFS. The full contract any backend must satisfy is rows 1–12 of
[Storage](../operations/storage.md); the design principle behind it is
[Design Principle 8](../how-it-works/design-principles.md): **sandlots see
shared directories, not a storage backend**. This page is the practical
options menu.

## 1. Sandswap does not restrict the backend

Sandswap imposes **no type or vendor restriction** on the storage backend.
A SandFS volume is a plain directory and the templates tree is a plain
directory tree: any filesystem that presents them at the same path on every
node works — local disk on a single node, any shared or distributed
filesystem on many, and new storage systems as they appear. Nothing else in
Sandswap depends on the backend, which is what lets any SandFS be served by
any node and migrate between nodes seamlessly.

This matches how virtual machines are actually operated today: cloud VMs
nearly universally boot and run on distributed (remote) storage, and
remote read/write latency has not prevented their use in production at
massive scale. Sandswap's requirement in multi-node topologies — every
sandlot host sees the same volumes and templates trees under one share
root — is therefore an ordinary, well-served requirement: there are many
proven techniques (managed cloud file services, parallel and distributed
filesystems, NFS tuning, RDMA/NVMe-oF fabrics, client-side caches) to make
it high-performance.

## 2. The contract, in brief

- **Who writes and who reads.** prov sandlot instances are the ONLY writer
  (volume create/seed/delete, template pull/push/save). exec sandlot nodes
  read: the overlay `lowerdirs` at mount and the active SandFS via virtio-fs
  passthrough. Gateways mount nothing.
- **Visibility.** Every exec sandlot node must see the shared `layers/`
  tree (each node resolves the same paths to build its overlay lowerdirs).
  Flat-template directories only need prov-instance visibility.
- **Filesystem capabilities.** POSIX semantics; hard links and rename
  (template-layer dedup relies on them); works as a **read-only overlay
  lowerdir** — Sandswap's overlay has no upperdir and no workdir, so it
  avoids the `RENAME_WHITEOUT` / `trusted.*` xattr requirements that make
  *writable* OverlayFS unusable on network filesystems. This is the one
  overlay property that makes virtually any network filesystem usable as a
  template store.
- **Performance.** Target ≤ 5 ms access latency. Not on the exec hot path
  (mount/umount run off the response path), but template operations and
  agent file I/O traverse it.
- **Host layout (enforced, not optional).** Same mount path on every
  consumer node; the volumes filesystem mounted `nosuid,nodev`; the share
  root owned by `sandprov` (uid 983), group traverse-only; volume directory
  names derived from the deployment seed. Host prep and
  `security/verify-host-security.sh` assert these.

## 3. Backend options

| Backend | Type | Notes |
|---|---|---|
| Local disk (NVMe SSD) | single node | best performance; development and single-node shapes; flat and overlay both work |
| NFS (classic, on-prem) | shared, multi-node | the export must give the prov identity unrestricted writes — see [Install — Bare Metal → Shared filesystem](../deployment/install-baremetal.md#8-shared-filesystem) |
| Cloud managed file services | shared, multi-node, HA | Tencent CFS, Aliyun NAS / CPFS, AWS EFS / FSx, GCP Filestore, Azure Files (NFS) — NFS-protocol or native POSIX clients; managed services usually allow the writes the prov identity needs by default |
| Distributed / parallel filesystems | shared, multi-node, HA | CephFS, Lustre, GPFS / IBM Spectrum Scale, GlusterFS, JuiceFS, SeaweedFS — and newer systems as they appear; POSIX-compliant ones slot in unchanged |
| Pre-mounted | any | ops mounts whatever the site standard is; the deploy scripts only verify the agreed path |

Multi-AZ replication and HA clustering remove the storage SPOF for
production shapes.

## 4. Choosing a backend

| If you need | Pick |
|---|---|
| max I/O performance, one box | local disk |
| multi-node fleets, many SandFS per template | any shared filesystem + overlay mode |
| HA storage for production | a multi-AZ managed service, or CephFS / a parallel filesystem |

Flat volumes on one backend and overlay SandFS on another mix freely in one
deployment — the mode is per-SandFS, chosen at creation time. The storage
contract each option must satisfy is [Storage](../operations/storage.md).
