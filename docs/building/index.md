---
title: Building
nav_order: 6
has_children: true
permalink: /building/
---

# Building

Everything needed to compile Sandswap from source. Follow the five
sections in order: requirements, clone, build, options, verification.
For building **template images** (flat rootfs / overlay templates), see
[building/templates](templates.md).

## 1. Build Requirements

| Requirement | Value |
|---|---|
| OS | Linux, x86_64. `apt`-based (Ubuntu/Debian) and `dnf`-based (RHEL/Fedora/TencentOS/openCloudOS/openEuler) distros auto-install all packages; other distros print a checklist |
| RAM | ≥ 4 GB; ≥ 8 GB when compiling the guest kernel from source |
| Disk | ≥ 10 GB free (`output/` holds ~200 MB; a from-source kernel compile is the largest consumer) |
| Go | **1.26.3 (pinned)** — the version every release is built and validated with; dev hosts with any Go ≥ 1.26 are reused as-is |
| Rust | **1.99.1 (pinned)** + the `x86_64-unknown-linux-musl` target — pinned in both `rust-toolchain.toml` files and by the installer |
| Build tools | `build-essential` (gcc/ld), `clang`, `libbpf-dev`, `bpftool`, `busybox-static`, `cpio`, `libseccomp-dev`, `libcap-ng-dev`, `git`, `wget`, `curl` |

**Toolchain pinning.** The two language toolchains are pinned, not floating —
other versions are simply not validated, and what breaks on them is not
enumerated here:

- **Go 1.26.3** — `build/install-deps.sh` downloads exactly this tarball and
  verifies its SHA-256 against the pinned checksum (an already-installed
  Go ≥ 1.26 is reused on dev hosts). The release CI hard-pins
  `GOTOOLCHAIN=go1.26.3` so a runner-provided Go can never leak in;
  `GOTOOLCHAIN=go1.26.3 bash build/build.sh all` does the same locally.
- **Rust 1.99.1** — the installer installs it system-wide
  (`--default-toolchain`, exposed through `/usr/local/bin`), and
  `vmm/rust-toolchain.toml` + `warden/rust-toolchain.toml` resolve any
  rustup-shim invocation to the same version. The workspace is validated
  against exactly this toolchain.

`sudo bash build/install-deps.sh` installs every row in one shot and is
idempotent — re-running is a no-op. Per component, what the build actually
needs:

| Component | Needs | Missing-tool symptom |
|---|---|---|
| all Go parts (gateway, sandlot, boxout, sandns, sandctl, examples) | Go 1.26.3 (pinned; ≥ 1.26 works) | `go not found` |
| warden (in-VM PID 1) | Rust (rustup) + the **`x86_64-unknown-linux-musl`** target | warden build fails at link |
| sandvmm (KVM VMM, Rust) | cargo, **libseccomp-dev**, **libcap-ng-dev** (static or shared) | sandvmm link errors |
| initramfs | **cpio**, curl or wget (the pinned `busybox-static` .deb is fetched and checksum-verified; the host's busybox is not used) | a silent 20-byte (broken) initramfs |
| vsockguard (BPF LSM) | **clang**, **libbpf-dev** (`bpf/bpf_helpers.h`), **bpftool** (vmlinux.h generation from `/sys/kernel/btf/vmlinux`) | BPF object not built |
| kernel | git (clones the pinned cloud-hypervisor linux tree); flex, bison, bc, libelf-dev, libssl-dev | kernel build fails |
| rootfs templates | busybox (base template); root for the Ubuntu template's chroot steps | template build fails |

Note: `sudo` resets `PATH`. The installer exposes the toolchains through
`/usr/local/bin` (the `go` symlink, the `cargo`/`rustc` symlinks and the
`rustup` wrapper that carries `RUSTUP_HOME`; `$CARGO_HOME/env` additionally
prepends the cargo bin dir for login shells). `build.sh` then re-adds
`/usr/local/go/bin` and `~/.cargo/bin` when absent and puts `/usr/local/bin`
first whenever the system rustup exists, so a root-run build resolves the
same toolchain as an interactive one.

## 2. Clone & Setup

The repository has **no submodules** — one clone is the whole source tree.

Clone the repository:

```bash
git clone https://github.com/ChaoyiHuang/sandswap.git
```

Enter the source tree:

```bash
cd sandswap
```

Install the toolchain (one-time; skip on a machine that already built):

```bash
sudo bash build/install-deps.sh
```

If you install Rust outside the installer, match the pinned version
(1.99.1) and add the warden's target explicitly:

```bash
rustup toolchain install 1.99.1 --profile minimal
rustup target add --toolchain 1.99.1 x86_64-unknown-linux-musl
```

## 3. Build Steps

Build every component in dependency order (kernel → warden → initramfs →
vmm → go → examples → rootfs template → vsockguard):

```bash
sudo bash build/build.sh all
```

The Ubuntu rootfs template layer is a chroot package install, so the full
build runs as root. Unprivileged targets (kernel/vmm/go/…) still build
without root; an unprivileged `all` keeps an existing complete template and
fails with the command above when none exists.

Wait for the freshness verdict at the end. Expected output (last line):

```
[==] All artifacts are fresh (newer than their sources).
```

The build runs `verify_freshness` at the end and **fails if any artifact
in `output/` is older than its newest source file**. A green build means
tests run freshly compiled code — never stale binaries left over from a
partial rebuild (the classic trap: edit `warden/src/mount.rs`, rebuild
only warden, and the initramfs still embeds the old binary). The build
also runs `check_build_deps` first and prints the complete missing list
with the one-line fix instead of dying mid-build.

Verify freshness again at any time, without building:

```bash
bash build/build.sh check
```

## 4. Build Options

### 4.1 Targets

Run one target instead of `all` when you touched a single component:

```bash
bash build/build.sh <target>
```

| Target | Builds | Output |
|---|---|---|
| `kernel` | builds the pinned CH kernel from source (pinned COMMIT, not a mutable tag) with the IPv6/sock_diag features **and the attack-surface minimization** (USER_NS/TUN/VETH/KVM/DEBUG_FS/USERFAULTFD/IO_URING/BPF/OVERLAY_FS/FUSE-extras/PACKET/ZSWAP/ZRAM/ZSMALLOC(_STAT)/CONNECTOR/AUDIT/MODIFY_LDT_SYSCALL/UNIX_DIAG/CRYPTO_USER_API_RNG compiled out; X86_UMIP + LEGACY_VSYSCALL_NONE enabled; FUSE_FS kept for VIRTIO_FS; PERF_EVENTS is arch-selected by x86 and stays seccomp-denied). The dev-only v6.2 `download` path is refused | `output/vmlinux.bin` (~12–20 MB) + `output/vmlinux.config-rev` + `output/vmlinux.bin.config` |
| `warden` | the in-VM agent (musl static; runs the Rust unit suite first) | `warden/target/.../release/warden` |
| `initramfs` | packs warden + busybox into the boot image. The busybox is the tenant-visible guest TCB: the build fetches one pinned published build — `busybox-static` **1.37.0-7ubuntu1** (Ubuntu 26.04, baseline amd64) from the Ubuntu archive — and verifies both the .deb and the extracted binary against `build/checksums.sh`, so the guest shell is the same bytes on every build host regardless of the distro's busybox version; it aborts on any mismatch, installs it **0555 root:root** (the guest root must not rewrite the shell later tenants execute), and packs the cpio with `--owner root:root` | `output/initramfs.cpio.gz` (~5 MB) |
| `vmm` | sandvmm (release profile) | `output/sandvmm` (~6–8 MB) |
| `go` | gateway, sandlot, boxout, sandns, sandctl + the `bindregdump` and `warden-probe` diagnostics tools — all CGO_ENABLED=0 static | `output/{gateway,sandlot,boxout,sandns,sandctl,bindregdump,warden-probe}` |
| `sandctl` | just the operator CLI | `output/sandctl` |
| `examples` | openai-sandswap, eino-sandswap, keepalive-sandswap + the loadgen benchmark driver | `output/{openai,eino,keepalive}-sandswap`, `output/loadgen` |
| `rootfs-template` | the busybox base rootfs directory | `output/rootfs-template/` |

The kernel build's policy gate (`bash kernel/build.sh config-check <config>`)
refuses a `.config` that re-enables a minimized symbol (a Kconfig `select`
edge) or drops a required one (`VIRTIO_FS`/`FUSE_FS`/`VIRTIO_NET`/
`VIRTIO_CONSOLE`/`VSOCKETS`/`IPV6`/`INET_DIAG(_DESTROY)`/`X86_UMIP`). It
also refuses a disable/enable name that is not a real Kconfig symbol (a
rename would otherwise make the option silently inert). The build runs it
after `make olddefconfig` and again as `nm` symbol probes on the pre-strip
image, and records the policy revision, `config_sha256`, `patchset_sha256`,
`policy_sha256`, tag, commit and init-hardening variant in
`output/vmlinux.config-rev` (the saved `.config` sits beside the image) so
an artifact built before the policy is never considered current; the
release packager re-derives and compares every one of those values. See
[Guest Kernel Hardening](../how-it-works/guest-kernel-hardening.md) §2.

The seccomp census (`security/seccomp-syscall-census.sh`) compares the
warden's deny list against the repo-pinned
`security/syscall-universe-x86_64.h` (385 x86_64 syscalls from the pinned
kernel tree, x32 excluded) rather than the build host's `/usr/include`.
Regenerate that file from the pinned tree on every kernel rebase and commit
it — the header carries the exact command.
| `ubuntu-rootfs` | Ubuntu 24.04 base rootfs (env knobs in [templates](templates.md#3-the-repos-own-builders)) | `output/rootfs-ubuntu/` |
| `vsockguard` | BPF LSM object + control tool (vmlinux.h regenerated from BTF when stale) | `output/vsockguard.bpf.o`, `output/vsockguardctl` |
| `check` | freshness verification only (no build) | — |
| `proto` | regenerate the gateway↔sandlot protobuf bindings (`common/proto`) | checked-in generated code |
| `deps` | install the toolchain (same as `build/install-deps.sh`) | host |
| `all` | everything above in dependency order, then `verify_freshness` | — |

There is no prebuilt-kernel shortcut: `kernel/build.sh download` (the old
dev-only v6.2 fetch) is refused — the pinned custom build is the only
supported kernel.

### 4.2 Environment variables

| Variable | Default | Effect |
|---|---|---|
| `WARDEN_SKIP_TESTS` | unset (tests run) | `=1` skips the warden Rust unit suite for scratch builds; run `e2e/warden-unit.sh` separately |
| `AUTO_REBUILD` | `1` | e2e freshness gate: `=0` forbids automatic rebuilds of stale artifacts — the check then fails instead of rebuilding |
| `KERNEL_REPO` / `KERNEL_TAG` | CH linux tree / release tag | `kernel` custom mode: build from source at this remote + tag |
| `OUTPUT` | `output/rootfs-ubuntu/` | `ubuntu-rootfs`: destination directory |

## 5. Output & Verification

Everything lands in `output/`. The runtime pairing:

| Artifact | Role |
|---|---|
| `output/vmlinux.bin` + `output/initramfs.cpio.gz` | what sandlot boots every microVM with (`-kernel` / `-initramfs`) |
| `output/sandvmm` | the VMM binary per node (`-vmm-binary`) |
| `output/{gateway,sandlot,boxout,sandns}` | the services (`boxout` for K8s boxout mode, `sandns` for distributed) |
| `output/sandctl` | the operator CLI |
| `output/rootfs-template/` | the busybox base rootfs the bare-metal/e2e deploy scripts stage as the flat template `rootfs:v1` (scanned by the prov sandlot's `-flat-templates` dir) |
| `output/rootfs-ubuntu/` | the Ubuntu 24.04 base rootfs (python3/ca-certificates/locales layered via a root chroot) the **k8s deployers** stage as their flat `rootfs:v1` — `deploy-k8s-*.sh` auto-builds it when missing; an unprivileged `build.sh all` keeps an existing complete one and tells you to rerun as root (see §3) |
| `output/vsockguard.bpf.o` + `output/vsockguardctl` | vsockguard attach ([Deployment → Host Prerequisites](../deployment/prerequisites.md#42-vsockguard-impersonation-control)) |

Verify the freshness gate:

```bash
bash build/build.sh check
```

Expected output:

```
[==] All artifacts are fresh (newer than their sources).
```

Verify a binary runs:

```bash
output/sandctl version
```

Expected output (version and commit vary):

```
sandctl 0.0.0-dev (commit <sha>, built <timestamp>)
```

Verify the base rootfs is a chroot-able directory:

```bash
ls output/rootfs-template/bin/sh
```

Expected output: the path itself (`output/rootfs-template/bin/sh`).

Host networking for guest egress (`--network-backend=bridge`) is a separate
one-time ops step: `deploy/setup-network.sh` — the build never touches it.

## 6. Common build failures

| Symptom | Cause | Fix |
|---|---|---|
| `missing build deps: ...` at startup | toolchain incomplete | `sudo bash build/install-deps.sh` |
| any compile error that does not reproduce on a pinned-toolchain host | toolchain version drift (only Go 1.26.3 / Rust 1.99.1 are validated) | rebuild with the pinned toolchains — §1 Toolchain pinning |
| initramfs is ~20 bytes | `cpio` missing — the pack pipeline silently degrades | install cpio; rebuild `initramfs` |
| warden link failure | musl target not installed | `rustup target add x86_64-unknown-linux-musl` |
| sandvmm link failure | libseccomp/libcap-ng dev packages missing | install both; rebuild `vmm` |
| vsockguard skipped / bpftool error | clang+libbpf-dev missing, or kernel BTF absent (`/sys/kernel/btf/vmlinux`) | install deps; BTF requires a kernel built with `CONFIG_DEBUG_INFO_BTF` |
| `build.sh check` says STALE | source newer than artifact after a partial build | rerun `build.sh all` (or the affected target) |
| warden unit suite fails during `all` | environment issues (root-gated chroot/mount tests) | fix the suite — or `WARDEN_SKIP_TESTS=1` for scratch builds and run `e2e/warden-unit.sh` separately |

## 7. Proto regeneration

Only when `common/proto` changes, regenerate the bindings:

```bash
bash build/gen-proto.sh
```

This step is not part of `all` — the checked-in generated code is what
builds.
