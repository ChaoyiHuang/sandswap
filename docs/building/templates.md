---
title: Building Templates
nav_order: 2
parent: Building
---

# Building Templates

How to construct a Sandswap **template** — the rootfs a SandFS starts from —
and register or publish it. This page is the recipes; what a template is,
where it is stored, and how each mode consumes it are in
[Templates](../how-it-works/templates.md) and
[SandFS](../how-it-works/sandfs.md); registry endpoints and auth are in
[OCI Registry Integration](../integration/registry.md).

Everything here is grounded in the repo's own scripts
(`build/build-*-rootfs.sh`, `build/build-template.sh`) and the template
manager (`sandlot/provision/template/manager.go`). The storage plane owns
that code: a prov sandlot instance runs every scan, pull, push and
save-as-template, and the gateway merely forwards those ops over the node
stream (it mounts no storage and holds no registry egress).

## 1. The one thing to understand first

A template is, at its core, **a plain chroot-able rootfs directory**. Which
scan root you place it in decides its mode, and the mode decides how every
SandFS creation consumes it:

| | Registered as **flat** | Registered as **overlay** |
|---|---|---|
| Place the directory under | a `-flat-templates` scan root | the template store (`-templates-dir`) |
| Ref written | `refs/<name>_<ver>.flat.json` | `refs/<name>_<ver>.overlay.json` |
| Consumed by SandFS | copied into each new flat volume | mounted read-only, shared by all |

(Flat template directories only need **prov-instance visibility** — the
prov sandlot copies from them at creation. Overlay layers must sit on
storage every exec node can read, because each node's sandlot mounts them
as lowerdirs.)

Registration scans accept two layouts: `name/version/` subdirectories
register as `name:version`; a directory that itself looks like a rootfs
(has `bin/` etc.) registers as itself with version `local`.

```
flat-templates/              templates/ (= the template store)/
├── ubuntu/                  ├── python-ml/
│   ├── 24.04/  → ubuntu:24.04   └── v1/   → python-ml:v1
│   └── 26.04/  → ubuntu:26.04
└── alpine/3.20/ → alpine:3.20
```

## 2. Recipe: rootfs from a container image

Any container image with a Linux amd64 userspace is a valid rootfs source —
`docker export`, a distro minirootfs tarball, `debootstrap` output. Pick an
image that satisfies three properties:

- **`/bin/sh` exists** — the warden execs through a shell.
- **`dev/`, `proc/`, `sys/`, `tmp/` exist** (empty directories are fine —
  the warden mounts the real proc/dev inside the guest).
- **No kernel, no init system required.** Sandswap boots its own kernel +
  initramfs, and the warden is PID 1 — the image needs neither. This is
  why images without systemd (busybox, ubuntu-base, alpine) work as-is.

Export an image's filesystem. Create a stopped container from the image:

```bash
docker create --name rootfs-src <image>:<tag>
```

Export its rootfs to a tarball:

```bash
docker export rootfs-src -o /tmp/rootfs.tar
```

Unpack it into a build directory:

```bash
mkdir -p output/my-rootfs && tar -C output/my-rootfs -xf /tmp/rootfs.tar
```

Remove the helper container:

```bash
docker rm rootfs-src
```

Verify the directory is chroot-able. The automated form of every check in
this step is one command — the permission contract plus `/bin/sh`, the
skeleton directories, and the absence of volume control files (rules and
severities: [Template Contract](../operations/template-contract.md)):

```bash
output/template-tool validate output/my-rootfs
```

It exits 1 and lists the findings on a bad tree (the first 20, with the
total counts); warnings (e.g. missing `sys/`, `tmp/`) print but pass. The
manual equivalent, for when the tool is not at hand:

```bash
ls output/my-rootfs/bin/sh
```

Expected output: the path itself. If any of `dev/ proc/ sys/ tmp/ workspace/
home/` are missing, create them:

```bash
mkdir -p output/my-rootfs/{dev,proc,sys,tmp,workspace,home}
```

Register the directory as a **flat** template. Place it under a
`-flat-templates` scan root as `<name>/<version>/`:

```bash
sudo mkdir -p /var/sandswap/flat-templates/my-rootfs
sudo cp -a output/my-rootfs /var/sandswap/flat-templates/my-rootfs/v1
```

Point the prov sandlot at the scan root (flag shown for completeness —
deployment tooling usually sets it):

```bash
sandlot -roles prov -flat-templates /var/sandswap/flat-templates ...
```

The scan registers `my-rootfs:v1` on first reference — no restart, no
registration command ([Scan mechanics](#7-scan-mechanics)).

Verify by creating a SandFS and executing:

```bash
sandctl api sandfs create --agent <agent_id> --name t1 \
    --template my-rootfs:v1 --mode flat
```

```bash
sandctl api execute --agent <agent_id> --sandfs <sandfs_id> \
    --code 'cat /etc/os-release | head -1' --language shell
```

Expected output: the first line of the image's distro identity. A template
that registers but does not exec is not done.

## 3. The repo's own builders

The repo ships two worked examples of §2 — read them as reference
implementations of the recipe.

### 3.1 Busybox base — `build.sh rootfs-template`

Build the minimal base template:

```bash
bash build/build.sh rootfs-template
```

Output: `output/rootfs-template/` (a few MB). Read
`build/build-rootfs-template.sh` for the anatomy — it is §2 reduced
to its minimum: one static busybox binary, a symlink farm for the coreutils,
a minimal `/etc`, and writable `/tmp` `/workspace` `/home/agent`. The
deployment tooling seeds it as `flat-templates/rootfs/v1/`, which is why
`rootfs:v1` exists out of the box.

### 3.2 Ubuntu base — `build/build-ubuntu-rootfs.sh`

Build the Ubuntu 24.04 base rootfs (run as root — the extra-packages step
runs apt inside a chroot):

```bash
sudo bash build/build-ubuntu-rootfs.sh
```

Output: `output/rootfs-ubuntu/`. The builder downloads the official minimal
`ubuntu-base` tarball (no debootstrap), unpacks it, configures apt sources,
and installs extra packages in one chroot pass. Environment knobs:

| Variable | Default | Effect |
|---|---|---|
| `UBUNTU_BASE_URL` | cdimage.ubuntu.com ubuntu-base 24.04 URL | the base tarball to download (point at a mirror copy) |
| `UBUNTU_MIRROR` | `https://archive.ubuntu.com/ubuntu` | apt mirror written into the chroot's sources |
| `UBUNTU_SUITE` | `noble` | apt suite written into the chroot's sources |
| `UBUNTU_PACKAGES` | `python3,ca-certificates,locales` | extra apt packages installed in the chroot pass |
| `OUTPUT` | `output/rootfs-ubuntu/` | destination directory |

Register it where the prov sandlot scans flat templates:

```bash
sudo mkdir -p /var/sandswap/flat-templates/ubuntu
sudo cp -a output/rootfs-ubuntu /var/sandswap/flat-templates/ubuntu/24.04
```

Verify — the ref `ubuntu:24.04` (mode flat) is immediately usable:

```bash
sandctl api sandfs create --agent <agent_id> --name t1 \
    --template ubuntu:24.04 --mode flat
```

```bash
sandctl api execute --agent <agent_id> --sandfs <sandfs_id> \
    --code 'cat /etc/os-release | head -1' --language shell
```

Expected output: `PRETTY_NAME="Ubuntu 24.04.x LTS"`.

## 4. Example — overlay template `python-ml:v1`

**Path A (grown from a live SandFS — recommended).** Run a flat SandFS,
install what you want, freeze it:

```bash
sandctl api sandfs create --agent <id> --name build --template ubuntu:24.04 --mode flat
```

```bash
sandctl api execute --agent <id> --sandfs <sandfs_id> \
    --code 'pip install --break-system-packages numpy pandas' --language shell
```

```bash
sandctl api sandfs save-template <sandfs_id> --name python-ml --version v1
```

`save-template` (flat-mode SandFS only — an overlay rootfs is read-only and
cannot be saved) snapshots the rootfs into the storage plane's template
store and registers the ref **as an overlay template** — the gateway
forwards the request and the prov instance does the copy; the frozen
rootfs becomes a read-only base shared by every SandFS created from it.

**Path B (offline).** Build a rootfs directory (§2's machinery) and place
it under the template store the prov instance scans (`-templates-dir`;
see [Scan mechanics](#7-scan-mechanics) for the default):

```
templates/python-ml/v1/    → registered as python-ml:v1 (mode=overlay)
```

Creating a SandFS from an overlay ref writes the volume structure
(`rootfs/`, `workspace/`, `home/`) plus the `.template` marker holding the
ref; the read-only overlay is mounted lazily on first execute.

Verify the overlay semantics. A write to the read-only base must fail:

```bash
sandctl api execute ... --code 'touch /usr/ro-test' --language shell
```

Expected output: `EROFS` / read-only file system. A write to the workspace
must succeed and persist:

```bash
sandctl api execute ... --code 'echo hi > /workspace/w.txt && cat /workspace/w.txt' --language shell
```

Expected output: `hi`.

## 5. Example — publish to OCI, pull elsewhere

Assemble a versioned template directory — `layer-0/`, `layer-1/`, … plus a
`template.json` (its fields feed the artifact's annotations) — and
`build/build-template.sh` pushes it as an OCI artifact via
[ORAS](https://oras.land):

```bash
bash build/build-template.sh ./my-template-dir python-ml:v1 \
    registry.example.com/sandswap-templates
```

(A template already in the local store can also be pushed through the
gateway API: `sandctl api template push python-ml:v1` — the gateway
forwards, the prov instance does the registry work.)

On the consuming side (any registry auth method — see
[OCI Registry Integration](../integration/registry.md)), pull the ref:

```bash
sandctl api template pull python-ml:v1     # → local layers/ cache
```

Create a SandFS from it:

```bash
sandctl api sandfs create --agent <id> --name prod \
    --template python-ml:v1 --mode overlay
```

The registry is only the distribution point — mounts always read the
storage plane's local `layers/` cache. First creation on a ref with
`-oci-registry` configured (prov instance flag) also pulls on demand —
the explicit `template pull` above is optional, not required
([Templates § 1.5](../how-it-works/templates.md#15-pull-by-creating-a-registry-only-ref);
`pull_status: pulled|cached` in the create response).

## 6. template.json field semantics

The metadata file alongside a template directory (see
`templates/base/template.json`). One thing to be clear about: **nothing
reads `template.json` at runtime** — registration uses the directory
layout (`name/version/`), and in-guest behavior is fixed by the platform
(workspace at `/workspace`, exec timeouts from platform config, the
warden's fixed env — see [SandFS](../how-it-works/sandfs.md)). The file
exists for humans and for the ORAS publishing script, which turns it into
OCI annotations:

| Field | Consumed by | Meaning |
|---|---|---|
| `name`, `version` | `build/build-template.sh` | identity; pushed as `sandswap.template.*` annotations; the scan derives the same from the directory name |
| `description` | `build/build-template.sh` | artifact annotation; human documentation |
| `workspace_path`, `default_timeout`, `is_serverless`, `idle_timeout`, `env` | nobody (documentation only) | sample metadata — the platform applies none of these; do not rely on them |
| `vcpus`, `memory_mb` | save-template **request** fields (not this file) | the **minimum** resources a SandFS from the template requests; recorded in the ref file, overridable at create time; the create path resolves them to an internal VM spec |

## 7. Scan mechanics

Discovery never requires a restart: the prov sandlot scans at
startup and re-runs the same discovery walks lazily whenever a template is
referenced or listed, so a directory dropped into a scan root is usable on
first use. (Changing *where* to scan — the flag paths themselves — is
still restart-required.) The template store (`-templates-dir`) resolves to
`-overlayfs-templates` when set, else to the sibling `templates/`
directory next to the volumes dir (same filesystem, so the shared-storage
contract covers it); it holds the
unified `layers/` + `refs/` store that pull/push/save-as-template also
write. The deploy tooling seeds `flat-templates/rootfs/v1/` the same way so
`rootfs:v1` exists out of the box (the bare-metal deployers seed the same
runtime layout).

Three rules keep lazy discovery safe (pinned by
`e2e/template-lifecycle.sh` and `e2e/overlayfs-isolation.sh` §8):

1. **Discovery only CREATES ref files — it never rewrites an existing
   one.** A ref is the authoritative point-in-time record; a rescan that
   "healed" a tampered refs file would launder it back to legal before the
   sandlot's mount-time layer validation could refuse it.
2. **Refs are never deleted.** A template directory removed after
   registration leaves its ref behind — a temporarily unmounted scan root
   must not permanently erase records.
3. **Existence is judged at read time.** The listing hides a template
   whose backing directories are gone, and SandFS creation from it fails
   fast ("source missing") instead of producing a sandfs that would fail
   at every mount. Re-creating the directory at the same path restores the
   template instantly via the kept ref — no restart, no re-registration.

Discipline: after changing any template, re-verify by creating a SandFS
from the ref and executing — a template that registers but does not exec
is not done.
