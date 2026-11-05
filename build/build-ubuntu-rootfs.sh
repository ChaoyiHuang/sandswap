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
# build-ubuntu-rootfs.sh — Build an Ubuntu rootfs template directory for Sandswap.
# Downloads the pre-built Ubuntu minimal base rootfs from cdimage.ubuntu.com
# and extracts it into a chroot-able directory suitable as a Sandswap template.
# Why ubuntu-base tarball instead of debootstrap?
#   - Official minimal chroot-able rootfs (~80MB compressed)
#   - No debootstrap dependency, no root required for base extraction
#   - Much faster: download + extract vs. debootstrap's package-by-package bootstrap
#   - Still supports apt install for additional packages (requires chroot + root)
# The template can be used in two ways:
#   1. Bind mount mode: -flat-templates output/rootfs-ubuntu/
#   2. OverlayFS mode:  place under -overlayfs-templates as ubuntu/v1/
# Output: $OUTPUT (default: output/rootfs-ubuntu/)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=build/checksums.sh
. "$SCRIPT_DIR/checksums.sh"

# ── Configuration ──────────────────────────────────────────────
OUTPUT="${OUTPUT:-$PROJECT_ROOT/output/rootfs-ubuntu}"
UBUNTU_BASE_URL="${UBUNTU_BASE_URL:-https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.3-base-amd64.tar.gz}"
UBUNTU_MIRROR="${UBUNTU_MIRROR:-https://archive.ubuntu.com/ubuntu}"
UBUNTU_SUITE="${UBUNTU_SUITE:-noble}"
UBUNTU_PACKAGES="${UBUNTU_PACKAGES:-python3,ca-certificates,locales}"
DOWNLOAD_CACHE="${DOWNLOAD_CACHE:-}"

# ── Colors ─────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log_step()  { echo -e "${GREEN}[→]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[✓]${NC} $1"; }

# ── Prerequisites ──────────────────────────────────────────────
log_step "Checking prerequisites..."

if ! command -v curl >/dev/null 2>&1; then
    log_error "curl not found. Install: apt install curl"
    exit 1
fi
if ! command -v tar >/dev/null 2>&1; then
    log_error "tar not found. Install: apt install tar"
    exit 1
fi

log_pass "Prerequisites OK (curl + tar)"

# The extra packages install inside a chroot — a root-only phase. Refuse
# BEFORE touching OUTPUT: a non-root run must never replace a complete
# template with one missing python3/ca-certificates/locales.
if [[ -n "$UBUNTU_PACKAGES" && "$(id -u)" -ne 0 ]]; then
    log_error "UBUNTU_PACKAGES='$UBUNTU_PACKAGES' requires root (chroot apt install)."
    log_error "Run: sudo bash $0    (or set UBUNTU_PACKAGES= to build the bare base image)"
    exit 1
fi

# ── Download integrity policy ─────────────────────────────────
# The base tarball seeds every tenant-visible template, so it is fetched over
# HTTPS and matched against a SHA256 pinned in build/checksums.sh. A different
# tarball is allowed only with an explicit UBUNTU_BASE_SHA256. Size checks and
# HTTP fallbacks are not integrity controls.
case "$UBUNTU_BASE_URL" in
    https://*) ;;
    *)
        log_error "UBUNTU_BASE_URL must be https:// (got: $UBUNTU_BASE_URL)"
        exit 1
        ;;
esac
TARBALL_FILENAME="$(basename "$UBUNTU_BASE_URL")"
if [[ -z "${UBUNTU_BASE_SHA256:-}" ]]; then
    UBUNTU_BASE_SHA256="$(ubuntu_base_sha256 "$TARBALL_FILENAME")" || {
        log_error "no pinned SHA256 for $TARBALL_FILENAME"
        log_error "set UBUNTU_BASE_SHA256 to the publisher's checksum for this tarball"
        exit 1
    }
fi
if [[ ! "$UBUNTU_BASE_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    log_error "UBUNTU_BASE_SHA256 is not a lowercase hex SHA256: $UBUNTU_BASE_SHA256"
    exit 1
fi

# verify_base_tarball <path> — match the file against the pinned digest.
verify_base_tarball() {
    local got
    got="$(sha256sum "$1" | awk '{print $1}')"
    if [[ "$got" != "$UBUNTU_BASE_SHA256" ]]; then
        log_error "base tarball SHA256 mismatch: pinned $UBUNTU_BASE_SHA256, got $got"
        return 1
    fi
}

# ── Phase 1: Download ─────────────────────────────────────────
TARBALL_PATH=""

if [[ -n "$DOWNLOAD_CACHE" ]]; then
    mkdir -p "$DOWNLOAD_CACHE"
    TARBALL_PATH="$DOWNLOAD_CACHE/$TARBALL_FILENAME"
fi

if [[ -n "$TARBALL_PATH" ]] && [[ -f "$TARBALL_PATH" ]]; then
    if verify_base_tarball "$TARBALL_PATH"; then
        log_pass "Using cached tarball (SHA256 verified): $TARBALL_PATH"
    else
        log_warn "Cached tarball failed verification — discarding and re-downloading"
        rm -f "$TARBALL_PATH"
        TARBALL_PATH=""
    fi
fi

if [[ -z "$TARBALL_PATH" ]] || [[ ! -f "$TARBALL_PATH" ]]; then
    # Need to download. A cache miss (or a rejected cached file) re-fills the
    # cache path when a cache is configured; otherwise use a private temp file.
    if [[ -z "$TARBALL_PATH" ]]; then
        if [[ -n "$DOWNLOAD_CACHE" ]]; then
            mkdir -p "$DOWNLOAD_CACHE"
            TARBALL_PATH="$DOWNLOAD_CACHE/$TARBALL_FILENAME"
        else
            TARBALL_PATH="$(mktemp /tmp/ubuntu-base-XXXXXX.tar.gz)"
            # Clean up temp file on exit (only if we created it, not cached)
            CLEANUP_TARBALL=1
        fi
    fi

    log_step "Downloading Ubuntu base rootfs..."
    echo "  URL: $UBUNTU_BASE_URL"
    echo "  →   $TARBALL_PATH"

    curl -fL --progress-bar -o "$TARBALL_PATH" "$UBUNTU_BASE_URL"

    # A failed transfer or a substituted file is refused here, before extraction.
    verify_base_tarball "$TARBALL_PATH" || {
        rm -f "$TARBALL_PATH"
        exit 1
    }

    log_pass "Downloaded and SHA256-verified $(numfmt --to=iec "$(stat -c%s "$TARBALL_PATH")")"
fi

# ── Phase 2: Extract ──────────────────────────────────────────
log_step "Extracting rootfs to $OUTPUT..."

# Unmount any stale chroot mounts from a previous run
umount -R "$OUTPUT/dev/pts" 2>/dev/null || true
umount -R "$OUTPUT/dev" 2>/dev/null || true
umount -R "$OUTPUT/proc" 2>/dev/null || true
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"

tar -xzf "$TARBALL_PATH" -C "$OUTPUT"

log_pass "Rootfs extracted"

# ── Phase 3: Configure apt sources ────────────────────────────
log_step "Configuring apt sources (mirror: $UBUNTU_MIRROR, suite: $UBUNTU_SUITE)..."

# Signed sources only: no [trusted=yes] (which disables Release signature
# verification) and no HTTP. The base image carries the Ubuntu archive keyring
# under /etc/apt/trusted.gpg.d, so apt verifies the InRelease signature.
case "$UBUNTU_MIRROR" in
    https://*) ;;
    *)
        log_error "UBUNTU_MIRROR must be https:// (got: $UBUNTU_MIRROR)"
        exit 1
        ;;
esac

cat > "$OUTPUT/etc/apt/sources.list" << EOF
deb $UBUNTU_MIRROR $UBUNTU_SUITE main universe
deb $UBUNTU_MIRROR $UBUNTU_SUITE-updates main universe
deb $UBUNTU_MIRROR $UBUNTU_SUITE-security main universe
EOF

# Remove DEB822-format sources to avoid duplicate configuration warnings
rm -f "$OUTPUT/etc/apt/sources.list.d/ubuntu.sources"

log_pass "Apt sources configured"

# ── Phase 4: Install extra packages ───────────────────────────
if [[ -n "$UBUNTU_PACKAGES" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
        log_step "Installing extra packages: $UBUNTU_PACKAGES..."

        # Ensure /proc, /dev, and DNS are available in chroot for apt.
        # The unmounts ride a trap: an apt failure exits through set -e and
        # would otherwise SKIP them, leaking the /dev bind into the template
        # dir (the historical mount-leak class).
        cleanup_chroot_mounts() {
            umount "$OUTPUT/dev/pts" 2>/dev/null || true
            umount "$OUTPUT/dev" 2>/dev/null || true
            umount "$OUTPUT/proc" 2>/dev/null || true
        }
        trap cleanup_chroot_mounts EXIT
        mount -t proc proc "$OUTPUT/proc" 2>/dev/null || true
        mount --bind /dev "$OUTPUT/dev" 2>/dev/null || true
        mount --bind /dev/pts "$OUTPUT/dev/pts" 2>/dev/null || true
        cp /etc/resolv.conf "$OUTPUT/etc/resolv.conf" 2>/dev/null || true

        # HTTPS sources need a trust store inside the chroot. The minimal base
        # image ships none until ca-certificates is installed, and the first
        # apt-get update runs before that, so seed the host's bundle. This is
        # only the TLS trust store; the apt Release signatures are still
        # verified against the Ubuntu archive keyring in the image.
        if [[ ! -s "$OUTPUT/etc/ssl/certs/ca-certificates.crt" ]]; then
            mkdir -p "$OUTPUT/etc/ssl/certs"
            cp /etc/ssl/certs/ca-certificates.crt "$OUTPUT/etc/ssl/certs/ca-certificates.crt" || {
                log_error "host CA bundle missing (/etc/ssl/certs/ca-certificates.crt) — cannot verify HTTPS apt sources"
                exit 1
            }
        fi

        # Convert comma-separated to space-separated
        PKG_LIST="${UBUNTU_PACKAGES//,/ }"

        # chroot inherits the environment: debconf must never try to prompt.
        # This build runs under nohup/CI with no TTY, and the ca-certificates
        # and locales postinsts ask debconf questions — an interactive frontend
        # that cannot initialize exits non-zero and dpkg reports the package
        # as errored. Same idiom as install-deps.sh and the vmm Dockerfiles.
        export DEBIAN_FRONTEND=noninteractive

        chroot "$OUTPUT" bash -c "apt-get update && apt-get install -y --no-install-recommends gpgv $PKG_LIST && apt-get clean" 2>&1 | tail -10

        # Unmount chroot mounts (the trap also covers this on failure paths)
        cleanup_chroot_mounts
        trap - EXIT

        log_pass "Extra packages installed"
    else
        # Unreachable (guarded above); keep a hard stop if the guard moves.
        log_error "package installation requires root (chroot apt install)"
        exit 1
    fi
fi

# ── Phase 5: Sandbox setup ────────────────────────────────────
log_step "Setting up sandbox environment..."

# Create /workspace and $HOME (/home/agent) — both agent-writable, matching
# the busybox template's convention (build-rootfs-template.sh). The ubuntu
# script originally created only /workspace; a template rebuilt from it lacked
# $HOME, and the flat-mode rootfs needs both.
mkdir -p "$OUTPUT/workspace" "$OUTPUT/home/agent"
# The template is shared storage read through the virtio-fs daemon; a
# world-writable tree would let any local identity rewrite content every
# tenant executes. The in-guest agent is root and writes these regardless.
chmod 0755 "$OUTPUT/workspace" "$OUTPUT/home/agent"

# Set hostname
echo "sandswap" > "$OUTPUT/etc/hostname"

# Configure locale
mkdir -p "$OUTPUT/etc/default"
cat > "$OUTPUT/etc/default/locale" << 'EOF'
LANG=en_US.UTF-8
LC_ALL=en_US.UTF-8
EOF

# Clean apt cache to reduce template size
rm -rf "$OUTPUT/var/lib/apt/lists/"*
rm -rf "$OUTPUT/var/cache/apt/"*

log_pass "Sandbox environment configured"

# ── Phase 6: Verify ───────────────────────────────────────────
log_step "Verifying rootfs template..."

ERRORS=0

if [[ ! -x "$OUTPUT/bin/sh" ]]; then
    log_error "/bin/sh not found or not executable"
    ERRORS=$((ERRORS + 1))
fi

if [[ ! -d "$OUTPUT/workspace" ]]; then
    log_error "/workspace directory not found"
    ERRORS=$((ERRORS + 1))
fi

if [[ ! -w "$OUTPUT/workspace" ]]; then
    log_error "/workspace directory not writable"
    ERRORS=$((ERRORS + 1))
fi

if [[ ! -f "$OUTPUT/etc/hostname" ]]; then
    log_error "/etc/hostname not found"
    ERRORS=$((ERRORS + 1))
fi

if [[ "$ERRORS" -gt 0 ]]; then
    log_error "Verification failed with $ERRORS error(s)"
    exit 1
fi

log_pass "Verification passed"

# ── Summary ────────────────────────────────────────────────────
SIZE=$(du -sh "$OUTPUT" | cut -f1)
FILE_COUNT=$(find "$OUTPUT" -type f | wc -l)

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Ubuntu rootfs template built successfully"
echo "  Output:     $OUTPUT"
echo "  Size:       $SIZE"
echo "  Files:      $FILE_COUNT"
echo "  Mirror:     $UBUNTU_MIRROR"
echo "  Suite:      $UBUNTU_SUITE"
echo ""
echo "  Usage (bind mount):"
echo "    gateway -flat-templates $OUTPUT"
echo ""
echo "  Usage (OverlayFS template):"
echo "    mkdir -p /var/sandswap/templates/ubuntu/v1"
echo "    cp -a $OUTPUT/. /var/sandswap/templates/ubuntu/v1/"
echo "    gateway -overlayfs-templates /var/sandswap/templates"
echo "    # Then create sandfs with {\"template\": \"ubuntu:v1\"}"
echo "═══════════════════════════════════════════════════════"

# Public template: normalize to the Sandswap TEMPLATE CONTRACT
# (docs/operations/template-contract.md) with the single canonical
# implementation — every consumer identity (the FUSE daemon 987 + the exec
# sandlot) reaches template content through the shared group, and distro trees
# carry mode-0000/0600 oddballs (e.g. /etc/.pwd.lock) that only root could
# read. template-tool normalize applies the contract; the validate right
# after is the build gate — a produced template that would be unreadable
# in-guest, lack /bin/sh, or carry volume control files fails the build here,
# not silently at an agent's first read. (The previous ad-hoc `chmod -R
# a+rX` widened to OTHER-readable; the contract needs the group grant only.)
TOOL="$PROJECT_ROOT/output/template-tool"
if [[ ! -x "$TOOL" ]]; then
    echo "error: output/template-tool missing — run: bash build/build.sh go" >&2
    exit 1
fi
"$TOOL" normalize "$OUTPUT"
"$TOOL" validate "$OUTPUT"

# Write-bit gate: the normalizer only ADDS group read/execute bits, so it
# cannot repair a world-writable build artifact. The agent-writable
# directories must stay owner-write-only; a shared template that another
# local identity can rewrite is a supply-chain hole.
for d in "$OUTPUT/workspace" "$OUTPUT/home/agent"; do
    mode=$((8#$(stat -c %a "$d")))
    if (( mode & 8#022 )); then
        echo "error: $d is group/other-writable (mode $(stat -c %a "$d"))" >&2
        exit 1
    fi
done

# ── Cleanup ───────────────────────────────────────────────────
if [[ "${CLEANUP_TARBALL:-0}" == "1" ]] && [[ -f "$TARBALL_PATH" ]]; then
    rm -f "$TARBALL_PATH"
fi
