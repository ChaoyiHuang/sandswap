---
title: Release
nav_order: 8
parent: Operations
---

# Release

How Sandswap releases are cut, what the release package contains, and how to
consume it. The pipeline produces a fully OFFLINE tarball: extract on any
x86_64 Linux host with KVM and deploy — no Go/Rust toolchain required.

Related: [Storage Requirements](storage.md) (the storage
contract the package satisfies).

## 1. Cutting a release

```bash
# 1. Ensure main is green and the working tree is clean.
# 2. Tag and push — the pipeline does the rest:
git tag <version> && git push origin <version>
# 3. Watch the "release" workflow on GitHub Actions (30–40 min:
#    the custom kernel build dominates).
# 4. Verify the release assets: tarball + SHA256SUMS.
# 5. Spot-check: sha256sum -c SHA256SUMS on the downloaded tarball.
```

The pipeline (`.github/workflows/release.yml`, ubuntu-24.04):

1. installs build + deploy dependencies (`build/install-deps.sh` plus the
   custom-kernel compile deps: flex bison bc libelf-dev libssl-dev);
2. builds the guest kernel (`kernel/build.sh custom`; the packaged kernel is
   always the IPv6 variant — routed-ipv6 networking and the egress enabler
   depend on it);
3. builds all artifacts with the version stamped into every Go binary
   (`GO_LDFLAGS_EXTRA` passing `-X …Version/Commit/BuildTime`);
4. builds the Ubuntu rootfs template (chroot: root; ownership handed back);
5. packages via `build/package-release.sh` — this gates on the packaged
   kernel (an IPv6 probe plus a `tcp_diag_destroy` probe: the warden's
   cross-tenant TIME_WAIT sweep must have its kernel side compiled in) and
   vendors etcd;
6. creates the GitHub Release with the tarball and `SHA256SUMS`.

## 2. Dry run without a tag

Run the workflow manually (`workflow_dispatch`) with a version label (e.g.
`<version>-rc1`): it produces a **draft** release with the full asset set.
Inspect, then publish from the release page, or delete and re-cut.

## 3. Local fallback (no CI)

On a machine with the full toolchain:

```bash
bash build/build.sh all            # incl. kernel/custom if you need IPv6
bash build/build-ubuntu-rootfs.sh  # chroot: needs root
bash build/package-release.sh <version>
# → dist/sandswap-<version>-linux-amd64.tar.gz + SHA256SUMS + RELEASE_NOTES.md
# then, with the GitHub CLI authenticated:
gh release create <version> dist/sandswap-<version>-linux-amd64.tar.gz \
    dist/SHA256SUMS --title "sandswap <version>" --notes-file dist/RELEASE_NOTES.md
```

`package-release.sh` first asserts artifact completeness (every binary,
kernel, initramfs, and template present), `build.sh check`, the syscall
census, and the kernel gates above. The gates run **unconditionally** (there is no bypass flag); the vendored etcd
(v3.6.13) is downloaded on first use into `output/etcd/` and re-verified
against its pinned checksum.

## 4. Package contents

```text
sandswap-<ver>-linux-amd64/
├── deploy/
│   ├── baremetal/          bare-metal deploys (single-node, cluster,
│   │                       one-machine-etcd) + single-host simulations,
│   │                       ops tooling (sandswap-ops.sh,
│   │                       rotate-volume-seed.sh), gen-baremetal-certs,
│   │                       setup-host, cleanup/uninstall, systemd units,
│   │                       cluster sample yamls, and the deployed-stack
│   │                       drills verify-eino / verify-etcd-fence /
│   │                       verify-negative-path / verify-cert-rotation
│   ├── setup-network.sh    host bridge + NAT
│   ├── gen-certs.sh        mTLS material generator (the e2e benchmark
│   │                       harness in the package shells out to it)
│   └── udev/               vsock device lockdown rule (sandlot group)
├── common/sh/              runtime.sh + stack.sh — the shared runtime the
│                           deploy tree sources (logging, path defaults,
│                           ss_* identity helpers)
├── e2e/                    the latency benchmark scripts + their shared
│                           harness (common.sh, pin.sh,
│                           latency-benchmark-aiagent,
│                           latency-benchmark-unmount,
│                           latency-benchmark-load,
│                           latency-benchmark-alloc-sweep): the package lets
│                           non-developers reproduce docs/benchmark
│                           against the prebuilt output/
├── security/               vsockguard attach/attest/detach/verify, host checks
├── docs/                   the documentation tree
├── output/                 PREBUILT artifacts + .release-stamp:
│                           static binaries (gateway, sandlot, sandvmm, sandns,
│                           boxout, sandctl, bindregdump, warden-probe,
│                           template-tool, vsockguardctl, vsockguard.bpf.o),
│                           vmlinux.bin (CONFIG_IPV6=y), initramfs.cpio.gz,
│                           rootfs-template/, rootfs-ubuntu/,
│                           eino/openai/keepalive example agents,
│                           loadgen (the benchmark client),
│                           etcd/{etcd,etcdctl} (vendored v3.6.13)
├── META                    version / commit / built / arch / kernel gates
└── LICENSE LICENSE-FAQ.md NOTICE README.md VERSION
```

The `.release-stamp` (VERSION's content, inside `output/`) is what flips
`bm_build_artifacts` — and every freshness gate that reads it — into
"prebuilt package, bypass builds": a consumer deploy runs with NO toolchain.

Deliberately excluded: `build/`, `kernel/` and all other sources (prebuilt
binaries ship), the rest of `e2e/` (dev-side suites), `deploy/k8s/`
(container-image deployments use their own pipeline), and the dev-only
private-topology drills `verify-failover.sh` / `verify-binpack.sh`.

## 5. Consumer quick start

Unpack under a directory the service identities can traverse and deploy
with the bare-metal script below (no toolchain). The deployer writes
`/etc/sandswap/sandctl.env` (public URLs + CA), so the `sandctl` client
commands work without extra flags. See
[Quick Start → Using a release package](../getting-started/index.md#11-using-a-release-package)
for the full walkthrough.

```bash
tar xzf sandswap-<ver>-linux-amd64.tar.gz && cd sandswap-<ver>-linux-amd64

# 1. Deploy (systemd, leave-running; no LLM key needed):
sudo bash deploy/baremetal/deploy-single-node.sh --skip-build

# 2. Verify with a live multi-agent interaction — 4 AI agents working their
#    sandboxes through the deployed gateway, all interaction printed:
sudo env DEEPSEEK_API_KEY=sk-... \
    bash deploy/baremetal/verify-eino.sh --agent-count 4
```

`verify-eino.sh` creates the agents and SandFS instances itself, runs every
LLM↔tool interaction, and prints a PASS/FAIL summary; its full transcript
lands in `/tmp/sandswap-logs/eino-test.log`.

## 6. Uninstall

One command removes everything the deployment installed:

```bash
sudo bash deploy/baremetal/uninstall.sh
```

It stops and disables the systemd units, kills any leftover processes,
detaches the vsockguard BPF program, tears down the host bridge/TAPs and
nftables rules, unmounts overlay mounts, and removes: `/etc/sandswap`
(configs + certs), installed binaries, the systemd units, the udev rule and
sysctl file, runtime/log state, and etcd data dirs.

**Data warning — `/var/lib/sandswap` (including agent volumes) is deleted
by default.** To keep agent data:

```bash
sudo bash deploy/baremetal/uninstall.sh --keep-data
```

The service identities (`sandlot`, `sandserv`, `sandprov`) are intentionally
kept — their pinned uid/gid must stay stable across reinstalls (see
[Storage Requirements](storage.md)). To also remove them:
`sudo userdel sandlot sandserv sandprov && sudo groupdel sandlot sandserv sandprov`
(re-run any deploy to recreate them).

`deploy/baremetal/cleanup.sh` is the lighter tool for a different job:
resetting the host BETWEEN deploys (processes, mounts, network — data and
configs stay). Use `cleanup.sh` to redeploy cleanly, `uninstall.sh` to
remove Sandswap from the machine.

## 7. Requirements and caveats

- x86_64 Linux, KVM (`/dev/kvm`), root for the deploy scripts,
  curl/python3 (standard). Binaries are static — no distribution glibc
  constraint. Services run as dedicated non-root identities
  (`sandlot` 985:985, `sandserv` 986:986, `sandprov` 983:983 —
  auto-created by the deploy).
- Shared-storage deployments: all nodes sharing
  volumes/templates MUST use identical uid/gid numbers for the service
  identities (pinned by default; overrides via `SS_UID_*`/`SS_GID_*` must
  match fleet-wide). Full contract and the NFS export
  recipe: [Storage Requirements](storage.md).
- `vsockguard.bpf.o` is compiled against the build kernel's BTF; attaching
  is best-effort and degrades to a warning on incompatible kernels.
- Cluster deploys (`deploy-cluster-*.sh`) are **local-only**: the control
  host prepares a self-contained stage bundle and prints per-node install
  commands — shipping it to the target hosts and running each host's role
  install is the operator's job (Ansible, rsync, or by hand).
- The eino verification paths (`e2e/single-node-multi-agent.sh`, `deploy/baremetal/verify-eino.sh`)
  need an LLM API key; the deploys themselves do not.
