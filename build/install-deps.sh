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
# install-deps.sh — Install all build + deploy dependencies for Sandswap.
# One-shot, idempotent prerequisite installer so a FRESH machine can run
# `build.sh all` and the k8s/baremetal deploy scripts end-to-end without manual
# package hunting. Covers everything the build and deploy actually need:
#   Build (build.sh):
#     - build-essential (gcc/ld)   — sandvmm + warden + vsockguard
#     - clang libbpf-dev bpftool   — vsockguard BPF LSM
#     - busybox-static             — base rootfs template (the initramfs
#                                    fetches its own pinned busybox build)
#     - cpio                       — initramfs
#     - libseccomp-dev libcap-ng-dev — sandvmm static link
#     - curl wget git              — kernel download, k3s install
#     - rustup + musl target       — warden (x86_64-unknown-linux-musl)
#   Deploy (deploy-k8s*.sh / baremetal):
#     - docker.io                  — container image builds
#     - dnsutils                   — owner-aware DNS verification (dig)
#     - python3                    — deploy harness JSON parsing
#     - etcd                       — sandctl / gateway / dns coordination (v3.6.13)
# Usage:
#   sudo bash build/install-deps.sh
# apt-based distros (Ubuntu/Debian) and dnf/yum-based distros (RHEL/CentOS/
# Fedora/TencentOS/openCloudOS/openEuler) are auto-installed with the right
# per-family package names; others print a checklist and exit. Re-running is
# a no-op (the package manager is idempotent).

set -euo pipefail

log() { echo -e "\033[0;32m[✓]\033[0m $1"; }
warn() { echo -e "\033[1;33m[!]\033[0m $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Pinned download checksums (see build/checksums.sh). Sourcing is part of the
# dependency contract: without it a download cannot be verified and must not
# be installed.
# shellcheck source=build/checksums.sh
. "$SCRIPT_DIR/checksums.sh"

# Pinned-checksum etcd download/install helpers (self-testable).
. "$SCRIPT_DIR/etcd-download.sh"

# --verify-selftest: exercise the checksum gate WITHOUT installing anything.
# Used by e2e/build-gate-selftest.sh; the normal install path is untouched.
if [[ "${1:-}" == "--verify-selftest" ]]; then
    etcd_tarball_sha256 v3.6.13 amd64 >/dev/null || {
        echo "verify-selftest: FAIL: the v3.6.13/amd64 checksum pin is missing" >&2
        exit 1
    }
    refuse_dir="$(mktemp -d)"
    if etcd_download_verified v0.0.0 amd64 "$refuse_dir/bin" >/dev/null 2>&1; then
        echo "verify-selftest: FAIL: an unpinned version was accepted" >&2
        rm -rf "$refuse_dir"
        exit 1
    fi
    # A download whose bytes do not match the pin must be refused BEFORE
    # extraction. Stub curl + sha256sum; the real pin is compared to zeros.
    fakebin="$refuse_dir/fakebin"; mkdir -p "$fakebin"
    cat > "$fakebin/curl" <<'FAKE'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done
[ -n "$out" ] && printf 'not-etcd' > "$out"
exit 0
FAKE
    cat > "$fakebin/sha256sum" <<'FAKE'
#!/bin/sh
echo "0000000000000000000000000000000000000000000000000000000000000000  $1"
FAKE
    chmod +x "$fakebin/curl" "$fakebin/sha256sum"
    if PATH="$fakebin:$PATH" etcd_download_verified v3.6.13 amd64 "$refuse_dir/bin" >/dev/null 2>&1; then
        echo "verify-selftest: FAIL: a checksum mismatch was installed" >&2
        rm -rf "$refuse_dir"
        exit 1
    fi
    if [[ -e "$refuse_dir/bin/etcd" || -e "$refuse_dir/bin/etcdctl" ]]; then
        echo "verify-selftest: FAIL: binaries appeared despite the checksum refusal" >&2
        rm -rf "$refuse_dir"
        exit 1
    fi
    rm -rf "$refuse_dir"
    echo "verify-selftest: OK (pinned checksum required; unpinned version and mismatch refused before extraction)"
    exit 0
fi

# ── 1. Rust toolchain (rustup + musl target, system-wide, PINNED) ──
# System-wide so `sudo bash build/install-deps.sh` followed by an
# unprivileged `bash build/build.sh all` works: a per-user install under
# /root is invisible to the invoking user. The toolchain binaries are exposed
# on the default PATH; cargo keeps its crate cache in the caller's ~/.cargo.
# The toolchain VERSION is pinned to the release-validated one: CI, bare
# metal and dev hosts must compile with identical rustc (warden/vmm/sandvmm
# are validated against exactly this version — a floating "latest stable"
# is how release builds drift). The pin must match vmm/rust-toolchain.toml
# and satisfy BOTH consumers: vmm needs >= 1.90 (linker-features=-lld for
# the static sandvmm link; the arch crate's edition-2024 unsafe code) and
# the workspace's warning-clean state (Atomic::try_update). warden builds
# on the same version. rustup-init gets --default-toolchain; a pre-existing
# system rustup gets the same toolchain installed idempotently.
RUST_TOOLCHAIN="1.99.1"
export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"
export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"
# A real rustup is an ELF binary; a script at that path is a wrapper (or a
# damaged install) and must be replaced before it can be exec'd.
rustup_is_binary() {
    [[ -f "$1" && -x "$1" ]] || return 1
    [[ "$(head -c 4 "$1" 2>/dev/null)" == $'\x7fELF' ]]
}
if ! rustup_is_binary "$CARGO_HOME/bin/rustup"; then
    log "Installing Rust (rustup) into $CARGO_HOME..."
    rm -f "$CARGO_HOME/bin/rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" \
          sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
fi
# Idempotent on a pre-existing system rustup whose default toolchain is
# something else: install the pinned one explicitly (a no-op when present).
# Components/targets mirror vmm/rust-toolchain.toml so shim-based cargo runs
# (which honor that file) find everything locally installed.
RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" \
    "$CARGO_HOME/bin/rustup" toolchain install "$RUST_TOOLCHAIN" --profile minimal \
        --component rust-src --component clippy \
        --target x86_64-unknown-linux-gnu --target x86_64-unknown-linux-musl
# || true on the assignment: with no toolchain directory the glob hands ls a
# literal pattern, the pipeline fails (pipefail), and errexit would kill the
# script before the else branch below could say so. The branch is the
# verdict. The glob is anchored at the PINNED toolchain: a plain */bin glob
# plus head -1 would resolve nondeterministically once several toolchains
# exist under RUSTUP_HOME.
TOOLCHAIN_BIN="$(ls -d "$RUSTUP_HOME"/toolchains/"$RUST_TOOLCHAIN"-*/bin 2>/dev/null | head -1)" || true
if [[ -n "$TOOLCHAIN_BIN" ]]; then
    log "Adding Rust musl target (x86_64-unknown-linux-musl) to $RUST_TOOLCHAIN for warden..."
    RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" \
        "$CARGO_HOME/bin/rustup" target add --toolchain "$RUST_TOOLCHAIN" x86_64-unknown-linux-musl
    for b in cargo rustc rustdoc; do
        [[ -x "$TOOLCHAIN_BIN/$b" ]] && ln -sf "$TOOLCHAIN_BIN/$b" "/usr/local/bin/$b"
    done
    if [[ -x "$CARGO_HOME/bin/rustup" ]]; then
        # A wrapper, not a symlink: any shell (including a non-login
        # `bash -c`) must resolve the system toolchain without inheriting
        # RUSTUP_HOME from an interactive profile.
        rm -f /usr/local/bin/rustup
        cat > /usr/local/bin/rustup <<RUSTUP_WRAPPER
#!/bin/sh
export RUSTUP_HOME="\${RUSTUP_HOME:-$RUSTUP_HOME}"
exec "$CARGO_HOME/bin/rustup" "\$@"
RUSTUP_WRAPPER
        chmod 0755 /usr/local/bin/rustup
    fi
else
    warn "Rust toolchain $RUST_TOOLCHAIN unavailable — cannot add musl target; warden build will fail."
fi

# The shims in CARGO_HOME/bin locate their toolchain through RUSTUP_HOME and
# fall back to the caller's ~/.rustup, which a system-wide install never
# creates. The env file login shells source must therefore point at the
# system store — RUSTUP_HOME only: CARGO_HOME stays unset so an unprivileged
# cargo keeps its crate cache under the caller's home.
if [[ -d "$RUSTUP_HOME/toolchains" ]]; then
    cat > "$CARGO_HOME/env" <<CARGO_ENV
#!/bin/sh
# sandswap system-wide Rust setup (owned by build/install-deps.sh)
export RUSTUP_HOME="$RUSTUP_HOME"
case ":\${PATH}:" in
    *:"$CARGO_HOME/bin":*) ;;
    *) export PATH="$CARGO_HOME/bin:\$PATH" ;;
esac
CARGO_ENV
    chmod 0644 "$CARGO_HOME/env"
fi

# ── 1b. Go (pinned release, system-wide) ──────────────────────────
# Same rule: a per-user Go install is invisible to other builders. The pinned
# release is verified against its published SHA-256 and exposed on the default
# PATH. The PIN is the version the tree is validated with (all modules,
# clean module cache): a newer Go once broke the release build through a
# grpc/x/net compile incompatibility, so CI additionally hard-pins
# GOTOOLCHAIN (see .github/workflows/release.yml). An already-installed
# Go >= 1.26 is reused on dev hosts.
GO_VERSION="1.26.3"
go_usable() {
    local v
    v="$("${1:-go}" env GOVERSION 2>/dev/null)" || return 1
    v="${v#go}"
    [[ "$(printf '%s\n1.26\n' "$v" | sort -V | head -1)" == "1.26" ]]
}
GO_BIN=""
if [[ -x /usr/local/go/bin/go ]] && go_usable /usr/local/go/bin/go; then
    GO_BIN=/usr/local/go/bin/go
elif command -v go >/dev/null 2>&1 && go_usable go; then
    GO_BIN="$(command -v go)"
fi
if [[ -n "$GO_BIN" ]]; then
    ln -sf "$GO_BIN" /usr/local/bin/go
    ln -sf "$(dirname "$GO_BIN")/gofmt" /usr/local/bin/gofmt 2>/dev/null || true
    log "Go $( "$GO_BIN" env GOVERSION ) present ($GO_BIN)"
else
    case "$(uname -m)" in
        x86_64|amd64)  GO_ARCH=amd64; GO_SHA256=2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556 ;;
        aarch64|arm64) GO_ARCH=arm64; GO_SHA256=9d89a3ea57d141c2b22d70083f2c8459ba3890f2d9e818e7e933b75614936565 ;;
        *)             GO_ARCH=""; GO_SHA256="" ;;
    esac
    if [[ -z "$GO_ARCH" ]]; then
        warn "no pinned Go tarball for $(uname -m) — install Go >= 1.26 from https://go.dev/dl/"
    else
        log "Installing Go ${GO_VERSION} (linux-${GO_ARCH}, checksum pinned)..."
        GO_TMP="$(mktemp -d)"
        if curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o "$GO_TMP/go.tar.gz" \
           && echo "${GO_SHA256}  $GO_TMP/go.tar.gz" | sha256sum -c - >/dev/null; then
            rm -rf /usr/local/go
            tar -C /usr/local -xzf "$GO_TMP/go.tar.gz"
            ln -sf /usr/local/go/bin/go /usr/local/bin/go
            ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
            log "Go ${GO_VERSION} installed to /usr/local/go"
        else
            warn "Go install failed — install Go >= 1.26 from https://go.dev/dl/"
        fi
        rm -rf "$GO_TMP"
    fi
fi

# ── 2. distro packages ────────────────────────────────────────────
# One dependency set, per-family package names: apt (Debian/Ubuntu), dnf/yum
# (Fedora/RHEL/Rocky/Alma/CentOS Stream), zypper (openSUSE/SLES) and pacman
# (Arch/Manjaro). Go/Rust come from their distro-independent installers above.
# Static devel archives (libbpf.a / libz.a / libzstd.a) are best-effort on
# dnf/yum: they only matter for the fully-static vsockguardctl link, and
# build.sh falls back to a static-libbpf-only link without them.
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
    # NOTE: bpftool is deliberately NOT in this list — Ubuntu 24.04 has no
    # standalone bpftool package; it is only shipped inside linux-tools.
    # Installed separately below with a fallback chain.
    APT_PKGS="build-essential curl wget git ca-certificates \
clang libbpf-dev busybox-static cpio \
libseccomp-dev libcap-ng-dev \
python3 dnsutils nftables sqlite3 \
flex bison bc libelf-dev libssl-dev \
conntrack numactl nfs-common nfs-kernel-server \
openssl iptables util-linux"
    log "Installing apt packages: $APT_PKGS"
    # A stale UNRELATED third-party source must not abort a deployment whose
    # packages are already installed: the update is best-effort, the install
    # below is the contract.
    apt-get update -qq || warn "apt-get update failed (a broken or unreachable apt source) — continuing"
    apt-get install -y -qq $APT_PKGS
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PKG_MGR="$(command -v dnf || command -v yum)"
    DNF_PKGS="gcc gcc-c++ make curl wget git ca-certificates \
clang libbpf-devel busybox cpio \
libseccomp-devel libcap-ng-devel elfutils-libelf-devel openssl-devel \
python3 bind-utils nftables sqlite \
flex bison bc \
conntrack-tools numactl nfs-utils openssl iptables util-linux"
    log "Installing $("$PKG_MGR" --version | head -1) packages: $DNF_PKGS"
    "$PKG_MGR" install -y -q $DNF_PKGS
    DNF_STATIC_PKGS="libbpf-static zlib-static libzstd-devel"
    "$PKG_MGR" install -y -q $DNF_STATIC_PKGS \
        || warn "Some static devel archives unavailable ($DNF_STATIC_PKGS) — vsockguardctl links static-libbpf-only"
elif command -v zypper >/dev/null 2>&1; then
    ZYPPER_PKGS="gcc gcc-c++ make curl wget git ca-certificates \
clang libbpf-devel busybox cpio \
libseccomp-devel libcap-ng-devel libelf-devel libopenssl-devel \
python3 bind-utils nftables sqlite3 \
flex bison bc \
conntrack-tools numactl nfs-kernel-server nfs-client openssl iptables util-linux"
    log "Installing zypper packages: $ZYPPER_PKGS"
    zypper --non-interactive refresh || warn "zypper refresh failed — continuing"
    zypper --non-interactive install -y $ZYPPER_PKGS
elif command -v pacman >/dev/null 2>&1; then
    PACMAN_PKGS="base-devel curl wget git ca-certificates \
clang libbpf busybox cpio \
libseccomp libcap-ng libelf openssl \
python bind nftables sqlite \
flex bison bc \
conntrack-tools numactl nfs-utils openssl iptables util-linux"
    log "Installing pacman packages: $PACMAN_PKGS"
    pacman -Sy --noconfirm --needed $PACMAN_PKGS
else
    warn "No supported package manager (apt/dnf/yum/zypper/pacman) found — install manually:"
    warn "  gcc make clang libbpf(-devel) busybox cpio libseccomp(-devel) libcap-ng(-devel)"
    warn "  libelf(-devel) openssl(-devel) python3 dig nftables sqlite3 flex bison bc"
    warn "  conntrack numactl nfs-server nfs-client openssl iptables util-linux"
fi

# busybox name normalization: Debian/Ubuntu ship the static binary as
# busybox-static, while build.sh's dependency check requires `busybox`.
if ! command -v busybox >/dev/null 2>&1; then
    for b in /bin/busybox /usr/bin/busybox /bin/busybox-static /usr/bin/busybox-static; do
        if [[ -x "$b" ]]; then
            mkdir -p /usr/local/bin
            ln -sf "$b" /usr/local/bin/busybox
            break
        fi
    done
fi

# ── bpftool with fallbacks ──
# The test is FUNCTIONAL ("bpftool version" succeeds), never "is it on PATH":
# Ubuntu's linux-tools-common installs a /usr/sbin/bpftool WRAPPER that exits 2
# ("bpftool not found for kernel X") when no linux-tools-<running-kernel>
# package matches. Versioned binaries under /usr/lib/linux-tools*/ are
# kernel-agnostic; symlinking one onto PATH (ahead of the wrapper) fixes it.
bpftool_ok() { command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; }
if ! bpftool_ok; then
    if command -v apt-get >/dev/null 2>&1; then
        log "Installing bpftool (via linux-tools fallback)..."
        apt-get install -y -qq bpftool 2>/dev/null \
            || apt-get install -y -qq linux-tools-common linux-tools-generic 2>/dev/null \
            || true
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        "$(command -v dnf || command -v yum)" install -y -q bpftool 2>/dev/null || true
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install -y bpftool 2>/dev/null || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -S --noconfirm --needed bpf 2>/dev/null || true
    fi
fi
if ! bpftool_ok; then
    for b in /usr/lib/linux-tools/*/bpftool /usr/lib/linux-tools-*/bpftool \
             /usr/lib/linux-tools/*-generic/bpftool; do
        if [ -x "$b" ] && "$b" version >/dev/null 2>&1; then
            mkdir -p /usr/local/bin
            ln -sf "$b" /usr/local/bin/bpftool
            break
        fi
    done
fi
if bpftool_ok; then
    log "bpftool: $(command -v bpftool)"
else
    warn "bpftool unavailable or non-functional — vsockguard vmlinux.h generation will fail (build.sh vsockguard)"
fi

# ── 3. docker (for container image builds; only needed for k8s deploy) ─
if ! command -v docker >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        log "Installing docker.io (container image builds)..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y -qq docker.io || warn "docker.io install failed — install manually if you need k8s deploy"
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        PKG_MGR="$(command -v dnf || command -v yum)"
        log "Installing docker (container image builds; docker-ce, falling back to docker/moby)..."
        "$PKG_MGR" install -y -q docker-ce || "$PKG_MGR" install -y -q docker || \
            warn "docker install failed (repo may not carry it) — install manually if you need k8s deploy"
    else
        warn "docker not found — install docker to build/import container images."
    fi
fi

# ── 4. etcd (for gateway / dns coordination) ─────────────────────
# The gateway --mode exec/human and sandns need `etcd`; etcdctl (separate
# apt package etcd-client) backs `sandctl pool` and `sandctl dns sticky`.
# Idempotent: an etcd already on PATH is reused; etcdctl is completed from
# the official tarball when missing.
#
# The tarball is ALWAYS verified against the checksum pinned in
# build/checksums.sh before extraction. There is no persistent cache and no
# publisher-.sha256 fetch: a predictable /tmp tree is world-writable and the
# tarball's .sha256 URL is not published, so trusting either would mean
# installing bytes nobody verified.


ETCD_VERSION="${ETCD_VERSION:-v3.6.13}"
ETCD_BIN_DIR="/usr/local/bin"
ETCD_ARCH="$(etcd_arch)" || {
    warn "unsupported architecture $(uname -m) for the pinned etcd tarball"
    ETCD_ARCH=""
}
if [ -n "$ETCD_ARCH" ] && ! etcd_tarball_sha256 "$ETCD_VERSION" "$ETCD_ARCH" >/dev/null; then
    warn "etcd ${ETCD_VERSION} (${ETCD_ARCH}) has no pinned checksum — set ETCD_VERSION to a supported release (build/checksums.sh)"
    ETCD_ARCH=""
fi

can_install_etcd() { [ "$(id -u)" -eq 0 ] || [ -w "$ETCD_BIN_DIR" ]; }

if command -v etcd >/dev/null 2>&1; then
    log "etcd present: $(command -v etcd) ($(etcd --version 2>/dev/null | head -1 || echo ok))"
    # apt's etcd package does not ship etcdctl (etcd-client does); the package
    # manager is a signed source, so it is tried before the tarball.
    if ! command -v etcdctl >/dev/null 2>&1; then
        log "etcdctl missing — attempting the etcd-client package"
        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq || true
            apt-get install -y -qq etcd-client 2>/dev/null || true
        fi
    fi
    if command -v etcdctl >/dev/null 2>&1; then
        log "etcdctl present: $(command -v etcdctl) ($(etcdctl version 2>/dev/null | head -1 || echo ok))"
    elif [ -n "$ETCD_ARCH" ] && can_install_etcd; then
        log "etcdctl still missing — fetching the pinned ${ETCD_VERSION} tarball"
        if etcd_download_verified "$ETCD_VERSION" "$ETCD_ARCH" "$ETCD_BIN_DIR"; then
            log "etcdctl ${ETCD_VERSION} installed to ${ETCD_BIN_DIR}/etcdctl"
        fi
    else
        warn "etcdctl unavailable — sandctl dns sticky needs it"
    fi
else
    if [ -z "$ETCD_ARCH" ]; then
        warn "etcd not installed: no pinned tarball for this version/arch"
    elif ! can_install_etcd; then
        warn "etcd not installed and ${ETCD_BIN_DIR} is not writable — rerun as root"
    else
        log "Installing etcd ${ETCD_VERSION} (checksum pinned)..."
        if etcd_download_verified "$ETCD_VERSION" "$ETCD_ARCH" "$ETCD_BIN_DIR"; then
            log "etcd ${ETCD_VERSION} installed to ${ETCD_BIN_DIR}/etcd (etcdctl too)"
        else
            warn "etcd install failed — refusing to install an unverified binary"
        fi
    fi
fi

# ── Verify ────────────────────────────────────────────────────────
MISSING=()
for cmd in gcc make clang bpftool busybox cpio docker dig python3 etcd etcdctl \
           go cargo rustup conntrack numactl taskset setpriv openssl iptables nft exportfs mount.nfs; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING+=("$cmd")
done
# Go is a separate install (>= 1.26, https://go.dev/dl/); it is verified here
# so a bare host fails with one actionable line.
if ! command -v go >/dev/null 2>&1; then
    warn "go not found — install Go >= 1.26 from https://go.dev/dl/"
fi
if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Still missing: ${MISSING[*]}"
else
    log "All Sandswap build/deploy/test dependencies present."
fi
log "Next: bash build/build.sh all && bash deploy/k8s/deploy-k8s-embedded.sh"
