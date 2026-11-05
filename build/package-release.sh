#!/bin/bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0.
#
# package-release.sh — Assemble the offline bare-metal release tarball.
#
# The release is a repo-shaped tree with PREBUILT artifacts: a consumer
# extracts it and runs deploy/baremetal/*.sh with NO Go/Rust toolchain —
# `bm_build_artifacts` sees output/.release-stamp and bypasses every build;
# the eino example ships prebuilt (no `go build`); templates ship
# normalized; the etcd binaries are vendored for the cluster/simulation
# scripts' `command -v etcd || output/etcd/etcd` fallback.
#
# Package layout (see docs/operations/release.md for the full rationale):
#   sandswap-<ver>-linux-amd64/
#     deploy/baremetal/   (no verify-failover / verify-binpack: dev-only
#                          private-topology drills)
#     deploy/setup-network.sh, deploy/gen-certs.sh, deploy/udev/
#     e2e/  (the latency benchmark scripts + their shared harness — the
#            release lets non-developers reproduce docs/benchmark without a
#            toolchain; includes the core-allocation sweep)
#     common/sh/runtime.sh  (shared runtime the deploy tree sources)
#     security/  (the operational vsockguard/host-security scripts only —
#                 never the audit reports or exploit material)
#     docs/  LICENSE  LICENSE-FAQ.md  NOTICE  README.md  VERSION
#     output/  (static binaries, IPv6 vmlinux, initramfs, templates,
#               examples, vendored etcd, .release-stamp)
#
# Usage:
#   bash build/package-release.sh [VERSION]
#     VERSION: tag-like label (CI passes the pushed tag); defaults to
#     `git describe --tags --always`.
# Env:
#   ETCD_VERSION            vendored etcd version (default v3.6.13; must be
#                           in build/checksums.sh)
#   DIST_DIR                output directory (default <repo>/dist)
#
# This is the release path: it runs the artifact-freshness check, the seccomp
# syscall census, and the full kernel content gate UNCONDITIONALLY (there is no
# environment-variable escape) before anything is staged, and every download is
# verified against build/checksums.sh. output/.release-stamp only marks the
# tarball as a prebuilt package for consumers; it never waives a gate here.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="${DIST_DIR:-$ROOT/dist}"
ETCD_VERSION="${ETCD_VERSION:-v3.6.13}"

# shellcheck source=build/checksums.sh
. "$ROOT/build/checksums.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${GREEN}[==]${NC} $1"; }
err() { echo -e "${RED}[!!]${NC} $1"; exit 1; }

# ── Version & arch ────────────────────────────────────────────────────
VERSION="${1:-$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo v0.0.0-unknown)}"
[ "$(uname -m)" = "x86_64" ] || err "release packaging is x86_64-only (got $(uname -m))"
PKG="sandswap-${VERSION}-linux-amd64"
COMMIT=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)

if [ "${ALLOW_NO_IPV6_KERNEL:-0}" = "1" ]; then
    log "ALLOW_NO_IPV6_KERNEL is ignored: the release packager runs the kernel gate unconditionally"
fi


# ── Artifact completeness (report ALL missing at once) ───────────────
MISSING=()
for f in gateway sandlot sandvmm sandns boxout sandctl bindregdump warden-probe \
         template-tool \
         vsockguardctl vsockguard.bpf.o vmlinux.bin initramfs.cpio.gz \
         rootfs-template rootfs-ubuntu \
         eino-sandswap openai-sandswap keepalive-sandswap loadgen; do
    [ -e "$ROOT/output/$f" ] || MISSING+=("output/$f")
done
[ ${#MISSING[@]} -eq 0 ] || err "missing artifacts:
  ${MISSING[*]}
  Run: bash build/build.sh all"

# ── Pre-package gates (unconditional) ─────────────────────────────────
# A release is only meaningful when it packages the CURRENT source tree's
# build. These gates run before anything is staged and have no environment
# escape: a stale artifact, a drifted seccomp decision ledger, or a kernel that
# does not carry the config policy and the applied upstream series aborts the
# run here.
log "Running build.sh check (artifact freshness + seccomp census)..."
bash "$ROOT/build/build.sh" check >/dev/null \
    || err "build/build.sh check failed: an artifact is stale or missing, or the seccomp census is red. Rebuild: bash build/build.sh all"
log "Artifacts fresh; seccomp census clean"

CENSUS="$ROOT/security/seccomp-syscall-census.sh"
[ -x "$CENSUS" ] || err "missing seccomp syscall census: $CENSUS"
bash "$CENSUS" >/dev/null \
    || err "seccomp syscall census FAILED (run: bash security/seccomp-syscall-census.sh) — refusing to package"
log "seccomp syscall census verified"

# ── Kernel gate ───────────────────────────────────────────────────────
# The shipped vmlinux must be the CONFIG_IPV6=y custom build: routed-ipv6
# networking and deploy-egress-enabler depend on it. Same probe as
# kernel/build.sh (a string only present when net/ipv6 is compiled in).
kernel_has_ipv6() { strings "$1" 2>/dev/null | grep "ip6_frag_reasm" > /dev/null; }
# SOCK_DESTROY proof: tcp_diag_destroy's address sits in the handler table, so
# it exists iff the cross-tenant TIME_WAIT sweep's kernel side is compiled in.
# (nm, NOT readelf -s — readelf truncates long symbol names; and no grep -q —
# SIGPIPE under pipefail. Both traps documented in kernel/build.sh.)
kernel_has_sock_destroy() { nm "$1" 2>/dev/null | grep -w tcp_diag_destroy > /dev/null; }
# virtio-console (guest hvc0) + earlyprintk: the warden's main log sink and
# the earliest boot/panic sink (sandlot sends console=hvc0 earlyprintk=ttyS0
# and a File console backend). Same string probes as kernel/build.sh.
kernel_has_virtio_console() {
    strings "$1" 2>/dev/null | grep "drivers/char/virtio_console.c" > /dev/null && \
        strings "$1" 2>/dev/null | grep "hvc_console.c" > /dev/null
}
kernel_has_earlyprintk() { strings "$1" 2>/dev/null | grep "earlyprintk" > /dev/null; }
# Guest-side warden-port reachability and the x32 syscall ABI: both are
# SECURITY properties of the shipped artifact (see kernel/build.sh). The
# loopback transport would expose the raw warden protocol to guest code; an
# x32-capable kernel makes every seccomp-denied syscall reachable in its x32
# spelling (x32 numbers share AUDIT_ARCH_X86_64 with native syscalls).
kernel_lacks_vsock_loopback() { ! strings "$1" 2>/dev/null | grep "vsock_loopback" > /dev/null; }
kernel_lacks_x32() { ! nm "$1" 2>/dev/null | grep -w "x32_sys_call_table" > /dev/null; }

KERNEL_IMG="$ROOT/output/vmlinux.bin"
bash "$ROOT/kernel/build.sh" check >/dev/null \
    || err "output/vmlinux.bin does not pass 'kernel/build.sh check' (stale, wrong tag, config/patch identity mismatch, or missing minimized-config features). Rebuild: bash kernel/build.sh"
log "kernel artifact passes kernel/build.sh check (version + config rev + .config digest + patch-set digest + features)"

kernel_has_sock_destroy "$KERNEL_IMG" \
    || err "output/vmlinux.bin lacks tcp_diag_destroy (SOCK_DESTROY): the warden's
  cross-tenant TIME_WAIT cleanup would silently no-op. Ship the custom kernel
  (bash kernel/build.sh)."
SOCK_DESTROY_MISSING=0
kernel_has_ipv6 "$KERNEL_IMG" \
    || err "output/vmlinux.bin lacks CONFIG_IPV6 (no ip6_frag_reasm strings).
  Release packages must ship the custom kernel: bash kernel/build.sh custom"
IPV6_OK=1
kernel_has_virtio_console "$KERNEL_IMG" \
    || err "output/vmlinux.bin lacks virtio-console (hvc0). The warden's logs
  would have no console sink (sandlot sends console=hvc0). Ship the custom
  kernel (bash kernel/build.sh)."
VIRTIO_CONSOLE_OK=1
kernel_lacks_vsock_loopback "$KERNEL_IMG" \
    || err "output/vmlinux.bin contains the vsock loopback transport: the warden's
  raw control protocol would be reachable from guest code. Ship a kernel built
  without CONFIG_VSOCKETS_LOOPBACK (bash kernel/build.sh)"
kernel_lacks_x32 "$KERNEL_IMG" \
    || err "output/vmlinux.bin contains x32_sys_call_table: the agent seccomp deny
  list would be bypassable via x32 syscall numbers. Ship a kernel built with
  CONFIG_X86_X32 unset (bash kernel/build.sh)"
kernel_has_earlyprintk "$KERNEL_IMG" \
    || err "output/vmlinux.bin lacks earlyprintk (CONFIG_EARLY_PRINTK).
  The earliest boot/panic output would be lost. Ship the custom kernel
  (bash kernel/build.sh)."
EARLYPRINTK_OK=1

# Kernel identity: the config policy revision, the .config digest and the
# applied patch-set digest. The patch-set digest is recomputed from
# kernel/patches/, so a tarball cannot carry an image built from a different
# series (kernel/build.sh check already compares it; this is the release-side
# assertion on the bytes actually staged).
KERNEL_REV_FILE="$ROOT/output/vmlinux.bin.config-rev"
[ -f "$KERNEL_REV_FILE" ] || err "missing kernel identity sidecar: $KERNEL_REV_FILE (rebuild: bash kernel/build.sh)"
KERNEL_PATCHSET="$(bash "$ROOT/kernel/build.sh" patchset-hash)" \
    || err "cannot compute the kernel patch-set digest from kernel/patches/"
grep -qx "patchset_sha256=$KERNEL_PATCHSET" "$KERNEL_REV_FILE" \
    || err "kernel identity sidecar does not name the current patch series — rebuild the kernel (bash kernel/build.sh)"
KERNEL_REV="$(awk -F= '$1 == "rev" {print $2}' "$KERNEL_REV_FILE")"
[ -n "$KERNEL_REV" ] || err "kernel identity sidecar has no rev= line"
KERNEL_CONFIG_SHA="$(awk -F= '$1 == "config_sha256" {print $2}' "$KERNEL_REV_FILE")"
[[ "$KERNEL_CONFIG_SHA" =~ ^[0-9a-f]{64}$ ]] \
    || err "kernel identity sidecar has no valid config_sha256 (got '$KERNEL_CONFIG_SHA')"
KERNEL_EXPECTED="$(bash "$ROOT/kernel/build.sh" expected-identity)" \
    || err "cannot read the expected kernel identity from kernel/build.sh"
while IFS= read -r line; do
    [ -n "$line" ] || continue
    grep -qx "$line" "$KERNEL_REV_FILE" \
        || err "kernel identity sidecar does not match the pinned identity '$line' — rebuild: bash kernel/build.sh"
done <<< "$KERNEL_EXPECTED"
grep -qx "init_hardening=both" "$KERNEL_REV_FILE" \
    || err "release kernel was built with a non-'both' KERNEL_INIT_HARDENING — rebuild with the release default"
KERNEL_POLICY="$(bash "$ROOT/kernel/build.sh" policy-hash)" \
    || err "cannot compute the kernel policy digest"
grep -qx "policy_sha256=$KERNEL_POLICY" "$KERNEL_REV_FILE" \
    || err "kernel identity sidecar does not name the current config policy — rebuild: bash kernel/build.sh"
KERNEL_CONFIG_FILE="${KERNEL_REV_FILE%.config-rev}.config"
[ -f "$KERNEL_CONFIG_FILE" ] \
    || err "missing saved kernel .config: $KERNEL_CONFIG_FILE (rebuild: bash kernel/build.sh)"
[ "$(sha256sum "$KERNEL_CONFIG_FILE" | awk '{print $1}')" = "$KERNEL_CONFIG_SHA" ] \
    || err "saved kernel .config does not match the sidecar config_sha256 — rebuild: bash kernel/build.sh"
log "kernel identity: rev=$KERNEL_REV config_sha256=${KERNEL_CONFIG_SHA:0:12}... patchset=${KERNEL_PATCHSET:0:12}... policy=${KERNEL_POLICY:0:12}..."

# ── Template write-bit gate ───────────────────────────────────────────
# The template builders create the agent-writable directories 0755, and the
# normalizer only ADDS group read/execute bits, so a world-writable tree is a
# build defect it cannot repair. A release must not ship a shared template
# whose content another local identity can rewrite.
for d in "$ROOT/output/rootfs-template/workspace" \
         "$ROOT/output/rootfs-template/home/agent" \
         "$ROOT/output/rootfs-ubuntu/workspace" \
         "$ROOT/output/rootfs-ubuntu/home/agent"; do
    [ -d "$d" ] || err "missing template directory: $d (rebuild: bash build/build.sh rootfs-template; bash build/build-ubuntu-rootfs.sh)"
    mode=$((8#$(stat -c %a "$d")))
    if (( mode & 8#022 )); then
        err "template directory is group/other-writable (mode $(stat -c %a "$d")): $d — rebuild the templates"
    fi
done
log "template write-bit gate clean (agent-writable dirs are owner-write-only)"

# ── Vendored etcd (verified download into output/etcd) ────────────────
# Runs before the stage assembly: a first packaging run is expected to lack
# output/etcd — the download below IS the fix. The download is verified
# against the built-in checksum in build/checksums.sh BEFORE extraction; the
# per-file .sha256 URL is not published, and an existing output/etcd tree is
# not trusted (a previous or hand-placed copy carries no provenance).
ETCD_SHA="$(etcd_tarball_sha256 "$ETCD_VERSION" amd64)" \
    || err "etcd ${ETCD_VERSION} (amd64) has no pinned checksum in build/checksums.sh"
log "Downloading vendored etcd ${ETCD_VERSION}..."
mkdir -p "$ROOT/output/etcd"
ETCD_TGZ="etcd-${ETCD_VERSION}-linux-amd64.tar.gz"
ETCD_URL="https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/${ETCD_TGZ}"
ETCD_TMP="$(mktemp -d "${TMPDIR:-/tmp}/sandswap-etcd-pkg.XXXXXX")"
trap 'rm -rf "${ETCD_TMP:-}" "${STAGE_PARENT:-}"' EXIT
TMP_TGZ="$ETCD_TMP/$ETCD_TGZ"
if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar -o "$TMP_TGZ" "$ETCD_URL" || err "etcd download failed: $ETCD_URL"
else
    wget -q -O "$TMP_TGZ" "$ETCD_URL" || err "etcd download failed: $ETCD_URL"
fi
ETCD_GOT="$(sha256sum "$TMP_TGZ" | awk '{print $1}')"
[ "$ETCD_SHA" = "$ETCD_GOT" ] \
    || err "etcd tarball SHA256 mismatch (pinned $ETCD_SHA, got $ETCD_GOT) — refusing to package it"
log "etcd tarball SHA256 verified against the built-in checksum"
tar xzf "$TMP_TGZ" -C "$ETCD_TMP"
install -m 0755 "$ETCD_TMP/etcd-${ETCD_VERSION}-linux-amd64/etcd" "$ROOT/output/etcd/etcd"
install -m 0755 "$ETCD_TMP/etcd-${ETCD_VERSION}-linux-amd64/etcdctl" "$ROOT/output/etcd/etcdctl"
"$ROOT/output/etcd/etcd" --version >/dev/null 2>&1 || err "vendored etcd does not execute"
rm -rf "$ETCD_TMP"
ETCD_TMP=""
log "etcd ${ETCD_VERSION} vendored into output/etcd (checksum verified, executable)"

# ── Assemble the stage ────────────────────────────────────────────────
STAGE_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/sandswap-pkg-XXXX")"
STAGE="$STAGE_PARENT/$PKG"
trap 'rm -rf "$STAGE_PARENT"' EXIT

log "Assembling $PKG ..."
mkdir -p "$STAGE/deploy" "$STAGE/common/sh" "$STAGE/output"

# deploy/: baremetal scripts (drop the two dev-only private-topology
# drills), the network setup, and the udev vsock-lockdown rule. k8s/,
# udev's k8s-only siblings and gen-certs.sh (e2e-only) stay out.
cp -a "$ROOT/deploy/baremetal" "$STAGE/deploy/baremetal"
rm -f "$STAGE/deploy/baremetal/verify-failover.sh" \
      "$STAGE/deploy/baremetal/verify-binpack.sh"
cp -a "$ROOT/deploy/setup-network.sh" "$STAGE/deploy/setup-network.sh"
mkdir -p "$STAGE/deploy/udev"
cp -a "$ROOT/deploy/udev/99-sandswap-vsock.rules" "$STAGE/deploy/udev/"

# common/sh: the shared runtime + the stack layer (deploy/baremetal/common.sh
# resolves them local-first; the package has no local copy → these files are
# the ones it sources).
cp -a "$ROOT/common/sh/runtime.sh" "$STAGE/common/sh/runtime.sh"
cp -a "$ROOT/common/sh/stack.sh" "$STAGE/common/sh/stack.sh"

# e2e/: the benchmark scripts + their shared harness. docs/benchmark's
# reproduction path 2 runs them straight from the extracted package against
# the prebuilt output/ (the freshness gate short-circuits on .release-stamp,
# so no toolchain is needed). Dev-only e2e suites stay out.
mkdir -p "$STAGE/e2e"
for f in e2e/common.sh e2e/pin.sh e2e/latency-benchmark-aiagent.sh \
         e2e/latency-benchmark-unmount.sh e2e/latency-benchmark-load.sh \
         e2e/latency-benchmark-alloc-sweep.sh; do
    cp -a "$ROOT/$f" "$STAGE/$f"
done

# deploy/gen-certs.sh — tc_gen_certs (e2e/common.sh) shells out to it for the
# gateway<->sandlot mTLS material at benchmark deploy time (e2e-only helper;
# the deploy/baremetal scripts don't use it).
cp -a "$ROOT/deploy/gen-certs.sh" "$STAGE/deploy/gen-certs.sh"

# security/: the operational scripts the deploy/e2e tree invokes, nothing
# else. The directory also holds the audit reports, decision ledgers and
# exploit notes — internal material that must not reach a customer tarball.
# vsockguard-verify.sh rides along because verify-host-security.sh points at
# it for the live denial probe. vsockguard-attest.sh rides along because the
# sandlot unit's root ExecStartPre installs it (a release package without it
# crash-loops the sandlot service at start).
mkdir -p "$STAGE/security"
for f in setup-bpf-lsm.sh vsockguard-attach.sh vsockguard-attest.sh \
         vsockguard-detach.sh vsockguard-verify.sh verify-host-security.sh; do
    [ -f "$ROOT/security/$f" ] || err "missing security script: security/$f"
    cp -a "$ROOT/security/$f" "$STAGE/security/$f"
done

# docs/
cp -a "$ROOT/docs" "$STAGE/docs"

# output/: prebuilt artifacts. Everything the deploy/e2e scripts and the
# storage contract need; explicitly NOT output/warden (embedded in the
# initramfs) and no Go/Rust sources.
for f in gateway sandlot sandvmm sandns boxout sandctl bindregdump warden-probe \
         template-tool \
         vsockguardctl vsockguard.bpf.o vmlinux.bin initramfs.cpio.gz \
         eino-sandswap openai-sandswap keepalive-sandswap loadgen; do
    cp -a "$ROOT/output/$f" "$STAGE/output/$f"
done
cp -a "$ROOT/output/rootfs-template" "$STAGE/output/rootfs-template"
cp -a "$ROOT/output/rootfs-ubuntu" "$STAGE/output/rootfs-ubuntu"
# Kernel identity travels with the image: config policy revision, .config
# digest and applied patch-set digest (the gates above proved they match).
cp -a "$KERNEL_REV_FILE" "$STAGE/output/vmlinux.bin.config-rev"
mkdir -p "$STAGE/output/etcd"
cp -a "$ROOT/output/etcd/etcd" "$ROOT/output/etcd/etcdctl" "$STAGE/output/etcd/"
chmod +x "$STAGE/output/gateway" "$STAGE/output/sandlot" "$STAGE/output/sandvmm" \
         "$STAGE/output/sandns" "$STAGE/output/boxout" "$STAGE/output/sandctl" \
         "$STAGE/output/bindregdump" "$STAGE/output/warden-probe" \
         "$STAGE/output/vsockguardctl" "$STAGE/output/eino-sandswap" \
         "$STAGE/output/openai-sandswap" "$STAGE/output/keepalive-sandswap" \
         "$STAGE/output/loadgen" \
         "$STAGE/output/etcd/etcd" "$STAGE/output/etcd/etcdctl"

# Metadata: VERSION + the .release-stamp that flips bm_build_artifacts (and
# anything else reading it) into "prebuilt package, bypass builds". The stamp
# is a consumer-side marker that RECORDS the package shape; it waives nothing
# in this script — every gate above ran unconditionally before staging.
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# VERSION is the PLAIN tag (no "version: " prefix): warden/build.sh cats it
# verbatim when a consumer-host rebuild regenerates version.rs. Build metadata
# lives beside it in META (human-readable; nothing parses it).
printf '%s' "$VERSION" > "$STAGE/VERSION"
cat > "$STAGE/META" <<EOF
version: $VERSION
commit: $COMMIT
built: $DATE
arch: linux-amd64
kernel_ipv6: $IPV6_OK
kernel_sock_destroy: $((1 - SOCK_DESTROY_MISSING))
kernel_virtio_console: $VIRTIO_CONSOLE_OK
kernel_earlyprintk: $EARLYPRINTK_OK
kernel_config_rev: $KERNEL_REV
kernel_config_sha256: $KERNEL_CONFIG_SHA
kernel_patchset_sha256: $KERNEL_PATCHSET
EOF
cp "$STAGE/VERSION" "$STAGE/output/.release-stamp"

# Top-level meta files
for f in LICENSE LICENSE-FAQ.md NOTICE README.md; do
    cp -a "$ROOT/$f" "$STAGE/$f"
done

# Every shipped artifact must exist and be non-empty before the tarball is
# sealed: a truncated/missing binary fails only on the consumer host, and the
# tarball hash cannot catch an omission that happened before assembly. The
# list mirrors the copy above (plus the kernel identity sidecar).
for art in gateway sandlot sandvmm sandns boxout sandctl bindregdump \
           warden-probe template-tool vsockguardctl vsockguard.bpf.o \
           vmlinux.bin vmlinux.bin.config-rev initramfs.cpio.gz \
           eino-sandswap openai-sandswap keepalive-sandswap loadgen \
           etcd/etcd etcd/etcdctl; do
    [ -s "$STAGE/output/$art" ] || err "release artifact missing or empty: output/$art"
done
[ -d "$STAGE/output/rootfs-template" ] || err "release artifact missing: output/rootfs-template"
[ -d "$STAGE/output/rootfs-ubuntu" ] || err "release artifact missing: output/rootfs-ubuntu"
log "release artifacts present and non-empty (binaries, kernel + identity, initramfs, templates, etcd)"

# ── Tar + checksums + release notes ──────────────────────────────────
mkdir -p "$DIST_DIR"
log "Packing $DIST_DIR/$PKG.tar.gz ..."
tar -czf "$DIST_DIR/$PKG.tar.gz" --owner=0 --group=0 -C "$STAGE_PARENT" "$PKG"

cd "$DIST_DIR"
sha256sum "$PKG.tar.gz" > SHA256SUMS

cat > RELEASE_NOTES.md <<EOF
# sandswap $VERSION

Offline bare-metal release: extract and deploy — no Go/Rust toolchain
required (all user-space binaries are static; the kernel and initramfs are
self-contained).

- commit: $COMMIT
- built: $DATE
- kernel: CONFIG_IPV6=$([ "$IPV6_OK" = 1 ] && echo y || echo NO)
- kernel rev: $KERNEL_REV
- kernel .config sha256: $KERNEL_CONFIG_SHA
- kernel patch-set sha256: $KERNEL_PATCHSET
- sha256 ($PKG.tar.gz): see SHA256SUMS

## Quick start

    tar xzf $PKG.tar.gz && cd $PKG
    sudo bash deploy/baremetal/deploy-single-node.sh --skip-build

Then watch live AI agents work against the deployment (4 agents, one
command — creates the agents/sandfs, prints every LLM↔sandbox interaction):

    sudo env DEEPSEEK_API_KEY=sk-... \
        bash deploy/baremetal/verify-eino.sh --agent-count 4

Services run as dedicated non-root identities (sandlot 985 / sandswap 986,
auto-created). Requirements: KVM (/dev/kvm), root, curl/python3. The
verification step needs an LLM API key (DEEPSEEK_API_KEY / OPENAI_API_KEY /
GOOGLE_API_KEY) — the deployment itself does not.

## Contents

- deploy/baremetal: one-click deploys (embedded + single-node systemd),
  cluster deploys and single-host simulations, ops tooling, uninstall/cleanup
- deploy/udev: vsock device lockdown rule (pinned to the sandlot identity)
- e2e: benchmark scripts (latency-benchmark-aiagent / -unmount / -load /
  -alloc-sweep) + the shared harness (common.sh, pin.sh) — reproduce
  docs/benchmark from this package, no toolchain
- common/sh: shared runtime + stack layer (deploy + e2e + sandctl)
- security: operational vsockguard/host-security scripts (audit material is
  not shipped)
- docs: configuration, deployment, integration, storage contract
- output: static binaries (gateway/sandlot/sandvmm/sandns/boxout/sandctl/...),
  IPv6-enabled guest kernel, initramfs, rootfs templates (busybox + ubuntu),
  example agents, vendored etcd

## Uninstall

    sudo bash deploy/baremetal/uninstall.sh

Removes services, binaries, configs, network setup, and BPF attachments.
DATA WARNING: /var/lib/sandswap (agent volumes) is deleted by default; pass
the --keep-data flag to keep it. The service identities stay (pinned uid/gid must
remain stable; a redeploy reuses them). See docs/operations/release.md for
the full breakdown and the lighter between-deploys cleanup.sh.

## Notes

- Shared-storage deployments (NFS and every numeric-credential distributed
  fs): all nodes MUST use identical uid/gid numbers for the service
  identities — see docs/operations/storage.md for the full storage contract
  and support matrix.
- vsockguard.bpf.o is compiled against the build kernel's BTF; attaching is
  best-effort and warns on kernels where it cannot load.
- Real multi-host cluster deploys (deploy-cluster-*-gw.sh) additionally need
  SSH access to the target nodes.
EOF

log "Release assembled:"
log "  $DIST_DIR/$PKG.tar.gz ($(du -sh "$DIST_DIR/$PKG.tar.gz" | cut -f1))"
log "  $DIST_DIR/SHA256SUMS"
log "  $DIST_DIR/RELEASE_NOTES.md"
