---
title: Templates
nav_order: 6
parent: How It Works
---

# Templates

A template is the rootfs a SandFS starts from. Templates are named by a
**ref** (`name:version`, e.g. `rootfs:v1`, `ubuntu:24.04`) and live in two
places:

- a **local template store** on shared storage (next to the volumes tree) —
  always present, and what mounts actually read;
- an **OCI registry** — optional: how templates cross storage boundaries
  (separate clusters or sites), using the same push/pull/tags/replication
  workflows as container images
  ([OCI Registry Integration](../integration/registry.md)).

How a template is *consumed* — copied into a writable volume (flat) or
mounted read-only under one (overlay) — is [SandFS](sandfs.md). This page
follows the working lifecycle; the reference layout of the local store is at
the [bottom](#2-the-local-template-store).

## 1. The workflow

```
 ① build a flat template         ② make it through an agent
    a chroot-able          ──▶   create a flat SandFS (--mode flat),
    rootfs directory             the agent installs and configures it
                                        (apt install, pip, …)
                                         │
                                         │  ③ freeze it: save-as-template
                                         ▼
        new template in the local store (overlay mode)
         │
         ├─▶ ④ publish (optional): push to an OCI registry — only when
         │        other gateways do not share this store; they pull from it
         │
         └─▶ ⑤ serve: create overlay SandFS × N — a shared
                  read-only base + a private writable workspace
```

① is offline tooling. ② and ③ run through the same agent API the agent
will use in production — the agents that use the environment build it.
Deployments whose prov sandlot instances share the templates tree see the frozen
template at once — the store's disk is the only source of truth — so ④
exists only where storage is not shared (separate clusters or sites). ⑤ is the
production consumption step.

### 1.1 Create a flat template

A flat template is nothing but a **chroot-able rootfs directory**: `/bin/sh`
present, `dev/ proc/ sys/ tmp/ workspace/ home/` existing (the warden mounts
the real proc/dev inside the guest). Any source works — the repo ships two builders:

- `build.sh rootfs-template` — the minimal busybox base: one static binary,
  a symlink farm for the coreutils, minimal `/etc`, writable `/tmp`
  `/workspace` `/home/agent` (a few MB).
- `build.sh ubuntu-rootfs` — the official minimal Ubuntu base tarball (no
  debootstrap), extracted and optionally extended with `UBUNTU_PACKAGES`
  via a chroot apt pass (~80 MB).

Container images work too — `docker export`, an alpine/busybox minirootfs
tarball — unpacked into a directory. Step-by-step recipes are in
[Building Templates](../building/templates.md), and `template-tool validate`
checks a finished tree against all of this offline before it is ever
registered (rules and severities:
[Template Contract](../operations/template-contract.md)).

Register it by placing the directory in the prov instance's
`-flat-templates` scan root as `<name>/<version>/` — no restart, no
registration command: the prov instance re-runs its discovery scan
whenever a template is referenced or listed, so the ref file appears on
first use:

```bash
sudo mkdir -p /var/sandswap/flat-templates/ubuntu
sudo cp -a output/rootfs-ubuntu /var/sandswap/flat-templates/ubuntu/24.04
# "ubuntu:24.04" (mode flat) is immediately usable on POST /human/sandfs
```

### 1.2 Make it real: work through an agent

The base template is a starting point; the environment you actually want is
built **through the agent**. Create a flat SandFS from the template and let
the agent install whatever it needs — the same API, key, and execute calls
it will use in production. There is no separate image pipeline:

```bash
sandctl api sandfs create --agent agent-1 --name build \
    --template ubuntu:24.04 --mode flat
sandctl api execute --agent agent-1 --sandfs <id> \
    --code 'apt-get update && apt-get install -y python3 python3-pip' --language shell
```

Creating the **flat SandFS** copies the whole template directory into the
new volume — that writable, self-contained copy is what makes flat the
**build** environment: flat retains the install execution profile, so
`apt`/`yum`/`dnf` work (capability policy per mode in
[SandFS](sandfs.md#3-packages-os-vs-language)). Consumption is per-instance:
no blob cache, no gateway-side dedup — the byte-level efficiency of the
duplicated copies is the storage backend's concern. If the ref came from a
registry instead of a local scan, the copy streams the layer blobs straight
into the volume (a flat pull caches nothing —
[step 4](#14-publish-it-the-oci-artifact)).

### 1.3 Freeze it: save-as-template

A working flat SandFS becomes a template in one call. Freezing captures the
volume's rootfs, everything the agent installed included:

```
POST /human/sandfs/{sandfs_id}/save-template
{"template_ref": "python-ml:v1", "description": "…", "vcpus": 2, "memory_mb": 512}
```

The rootfs directory is copied into the local store's
`layers/local-<name>-<ver>/` and the ref is registered **as an overlay
template** — the frozen rootfs becomes a read-only base. On a shared
templates tree that single call makes the template available to every
prov instance in the deployment at once; there is no publish step on the way
([step 4](#14-publish-it-the-oci-artifact) is only for storage boundaries).
`vcpus` / `memory_mb` become the template's minimum resources (overridable
at creation). Two boundaries:

- only a **flat** SandFS can be saved — an overlay SandFS's rootfs is a
  read-only overlay, and its agent writes live in `workspace/`/`home/`,
  not in the rootfs;
- the capture is a point-in-time copy — quiesce the agent for a consistent
  snapshot.

### 1.4 Publish it: the OCI artifact

Deployments whose prov sandlot instances share the templates tree skip this step
entirely — a template saved on one is already on all of them. Publishing is for **storage
boundaries**: a second cluster, another site, an air-gapped transfer.
Templates cross those as **OCI artifacts** — ordinary registries (Harbor,
Zot, Distribution, Docker Hub) store and replicate them unmodified:

```
artifactType: application/vnd.sandswap.template.v1+json
config:       application/vnd.sandswap.template.config.v1+json
layers:       application/vnd.oci.image.layer.v1.tar+gzip   (tar.gz of each layer dir)
annotations:  sandswap.template.name / .version / .description
```

Two things to know:

- Refs and registry tags are not spelled the same: OCI tags cannot contain
  colons, so the ref `python-ml:v1` is stored as the tag **`python-ml-v1`**.
- The mode lives in the local ref file, not in the artifact: pull and push
  accept an optional `mode` (`overlay` is the default), and the same tag
  can be pulled as either — an overlay pull extracts every layer into the
  local `layers/` cache, a flat pull records only the layer digests
  (which is why a registry-origin flat ref has no local content and cannot
  be pushed again).

Publishing is `sandctl api template push <ref>` for something already in
the local store, or the ORAS-based `build/build-template.sh` for an
assembled template directory
([Building Templates](../building/templates.md)). Pulling happens explicitly
(`sandctl api template pull`) or automatically on the first SandFS creation
that names a ref not yet in the local store (the create response's
`pull_status` says `cached` or `pulled` — see
[1.5](#15-pull-by-creating-a-registry-only-ref)).

### 1.5 Pull by creating: a registry-only ref

A registry ref does not need an explicit `template pull` first — the first
SandFS creation that names it **pulls it on demand**, in either mode:

```bash
# The ref exists only in the registry (nothing was pulled locally):
sandctl api sandfs create --agent agent-2 --name serve \
    --template python-ml:v1 --mode overlay
sandctl api sandfs create --agent agent-1 --name build \
    --template ubuntu:24.04 --mode flat
```

What the create does, per mode (the two differ because the volumes differ):

- **overlay** — the whole template is downloaded and extracted into the
  shared content-addressed `layers/` cache once; every later create from
  that ref (any sandfs, any node sharing the store) reuses that single
  extraction. The first create therefore moves GBs; those after it move
  nothing.
- **flat** — only the manifest is fetched; the layer blobs stream straight
  into that one volume. Nothing is cached, because a flat volume is a
  private writable copy — the next flat create streams again.

The create response says which happened: `pull_status` is **`pulled`** when
that create fetched the ref (it was missing from the local store) and
**`cached`** on every create after it. The pull happens on the **prov
instance** (the storage plane), which is where the registry — and its
credentials — are configured
([OCI Registry Integration](../integration/registry.md)); the gateway only relays the
create. A deployment whose prov sandlot instances share the templates tree needs
exactly one pull for the whole fleet.

### 1.6 Serve: create overlay SandFS from the template

Creating an **overlay SandFS** names the template with `mode: overlay`:

```bash
sandctl api sandfs create --agent agent-2 --name serve \
    --template python-ml:v1 --mode overlay
```

Creation is instant and moves no template bytes: a **prov instance**
(prov sandlot) creates `rootfs/`, `workspace/`, `home/` plus a
`.template` marker holding the ref. The template's layers are already
extracted once into the shared content-addressed `layers/` cache (every
SandFS from that template shares that one extraction), and on the first
execute the node's sandlot mounts them as the read-only overlay `lowerdir`.
The gateway relays the creation over the stream; it never touches the
storage itself. Layer stacking follows OCI
convention: bottom→top, later layers overwrite earlier entries; there is no
whiteout handling (Sandswap produces and consumes this format itself), and
tar xattrs (file capabilities) are not preserved.

Each instance then works in its own private, persistent `workspace/` and
`home/agent` on top of the shared immutable base — the **serve** mode.
What that looks like inside the VM is [SandFS](sandfs.md).

### 1.7 The loop, end to end

```bash
# ① the flat template exists (step 1) — e.g. ubuntu:24.04

# ② create a flat SandFS from it; the agent installs OS packages
sandctl api sandfs create --agent agent-1 --name build \
    --template ubuntu:24.04 --mode flat
sandctl api execute --agent agent-1 --sandfs <id> \
    --code 'apt-get update && apt-get install -y python3 python3-pip' --language shell

# ③ freeze it as a template (local store, overlay mode)
sandctl api sandfs save-template <id> --name python-ml --version v1

# ④ (optional) publish — only when other gateways
#    do not share this store
sandctl api template push python-ml:v1

# ⑤ serve: every instance starts from the frozen base,
#    installs language packages into /home/agent at runtime
sandctl api sandfs create --agent agent-2 --name serve \
    --template python-ml:v1 --mode overlay

# ⑥ upgrade + retire: swap LIVE sandfs onto a new base without losing
#    agent work (workspace/home carry over), then delete the old
#    template once nothing references it anymore
sandctl api template pull python-ml:v2          # new base lands in the store
sandctl api sandfs swap-template <id> python-ml:v2 --home keep
sandctl api template delete python-ml:v1        # 409 TEMPLATE_IN_USE while
                                                # any volume still names it;
                                                # 204 once the last swap lands
```

The swap leg (⑥) is what makes the loop circular instead of linear:
templates are not frozen under their instances — see
[SandFS — template swap](sandfs.md#5-template-swap-detachattach) for the
lifecycle states and [Deleting a template](#3-deleting-a-template-and-the-retirement-loop)
for the in-use rules.

### 1.8 Latency: prefer statically linked programs

Prefer statically linked programs, including the shell (for example busybox
or a static Go/Rust binary): a program start then opens one file instead of
the ELF, dynamic loader and shared libraries, so it touches virtio-fs and the
overlay layers fewer times.

The programs in a SandFS are agent-authored and short-lived, so
human-oriented language advice does not transfer: startup speed and runtime
performance decide. An interpreted-language start pays the interpreter and
its imports, which walk the same cold virtio-fs path as the dynamic loader
above; a compiled one pays the build step but starts and runs faster.

## 2. The local template store

One directory tree, shared by every node in a deployment — prov sandlot
writes it, exec nodes read overlay lowerdirs from it (default: the sibling
`templates/` directory beside the volumes dir; flags `-templates-dir`,
`-overlayfs-templates`):

```
<templates>/
├── layers/                      # extracted rootfs directories
│   ├── sha256-abc123…/          #   OCI layer, extracted once (content-addressed)
│   └── local-python-ml-v1/      #   save-as-template output (a frozen flat SandFS)
├── refs/                        # ref → layer stack, one small JSON per ref
│   ├── rootfs_v1.flat.json      #   flat refs  — from the -flat-templates scan
│   ├── ubuntu_24.04.flat.json
│   └── python-ml_v1.overlay.json   # overlay refs — save-as-template, OCI pull,
│                                  #   or the -overlayfs-templates scan
└── <name>/<version>/            # local template source directories
    └── sqlite/v1/               #   auto-scan registers them (mode overlay)
```

The ref file is the whole registration: it names the template's mode and
its layer stack. Scan-registered local templates record absolute directory
paths; pulled layers and saved templates record paths relative to `layers/`.
Disk is the sole source of truth — listings re-scan `refs/` and there is no
in-memory cache, so prov sandlot instances sharing the tree stay consistent
without any coordination. Two visibility facts follow:

- **Flat template directories only need to be visible to the prov
  instance** — flat consumption copies from them at SandFS creation, and
  the copy is executed by prov sandlot. The scan root (`-flat-templates`)
  can be prov-local.
- **Overlay layers must be visible to every node** — each node's sandlot
  resolves the same `layers/` paths to build its overlay `lowerdir`, so in
  multi-node deployments the templates tree belongs on the shared storage
  (the flat and overlay scans can point at different roots; the refs land
  in the same `refs/` either way).

A store's integrity — ref identity, the layer trust boundary, layer presence
— is checkable offline with `template-tool check-store` (rules:
[Template Contract](../operations/template-contract.md)).

## 3. Deleting a template (and the retirement loop)

`DELETE /human/templates/{ref}` (full API semantics in
[Human API](../reference/human-api.md#delete-humantemplatesref--delete-a-template))
removes the ref file and garbage-collects the `layers/` entries no remaining
ref names. Two properties of the store shape the rules:

- **Layers are content-addressed and shared.** Two tags over the same base
  layer reference the same `layers/sha256-…/` directory, so deletion is
  reachability-GC, not `rm -rf`: only layers that NO remaining ref names are
  removed, and a shared base layer survives until its last referent does.
  Hand-deleting directories under `layers/` is the one way to break other
  templates — use the API instead.
- **Overlay refs are runtime dependencies; flat refs are not.** Every
  overlay SandFS's `.template` marker names its ref, and every cold mount
  re-reads `refs/` + `layers/`. The delete therefore refuses with
  `409 TEMPLATE_IN_USE` while any overlay volume still names the ref
  (a two-layer check: the gateway's records, then the node-side marker scan
  that also catches orphan volumes). Flat volumes copied their content at
  creation — a flat template is deletable the moment no creation is
  mid-flight.

The upgrade workflow this completes: build the new template →
`swap-template` every sandfs onto it (agent work carries over; see
[SandFS — template swap](sandfs.md#5-template-swap-detachattach)) → the old
ref's in-use count drops to zero exactly when the last marker stops naming
it → delete the old template. Retirement is checkable, not assumed.

## 4. Shipped samples

The repo ships sample templates under `templates/` — each is a
`template.json` metadata file demonstrating the schema (name, version,
description, timeouts, default env). Note the gateway consumes only the
directory layout and the layer content at runtime; `template.json` is
documentation, plus input to the ORAS publishing script
(`build/build-template.sh`, which turns it into OCI annotations). The
samples are starting points, not buildable rootfs directories on their own:

| Sample | What it shows | How a real one is built |
|---|---|---|
| `base` | minimal busybox rootfs metadata | `build.sh rootfs-template` assembles the actual directory (`output/rootfs-template/`); deploy tooling seeds it as `flat-templates/rootfs/v1/` → the default **`rootfs:v1`** |
| `python` | language-runtime metadata + default env (`PYTHONUNBUFFERED`, …) | build an Ubuntu base (step 1 above), chroot-install `python3`/`pip`, register the directory |
| `sqlite` | embedded-database metadata + `SQLITE_*` env defaults | same base, add the `sqlite3` binary as a layer — the README in `templates/sqlite/` walks the layout |
