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
# build.sh — Build a minimal initramfs for sandswap rootfs hot-swap mode.
# The initramfs contains only warden (statically linked) and busybox.
# The VM boots from this tmpfs root, then agent rootfs directories are shared
# via native virtio-fs (PassthroughFs) and bind-mounted at /mnt/rootfs.
# Output: initramfs.cpio.gz (~5MB)
# Usage: ./build.sh [--output /path/to/initramfs.cpio.gz]

set -euo pipefail

# The initramfs busybox is tenant-visible guest TCB (the warden's shell and the
# hot-bind payload), so it is PINNED TO ONE PUBLISHED BUILD — never the host's
# `busybox`. The host build changes with the distro release (Ubuntu 24.04 ships
# 1.36.1, 26.04 ships 1.37.0) and even between package variants of ONE version
# (26.04 publishes an amd64v3 build that is a different binary than its
# baseline amd64 build), so using it silently changes the release artifact and
# fails on any build host that carries another build. The pinned .deb is
# fetched from the Ubuntu archive and BOTH the .deb and the extracted binary
# are verified against build/checksums.sh before anything is packed.
# BUSYBOX=<path> is the offline escape hatch and is accepted only when that
# file IS the pinned binary. To adopt another build, update the pins in
# build/checksums.sh and the version here deliberately.
BUSYBOX_PKG_VERSION_PIN="1.37.0-7ubuntu1"   # Ubuntu 26.04 (resolute), baseline amd64 build
BUSYBOX_PKG_ARCH_PIN="amd64"
BUSYBOX_VERSION_PIN="1.37.0"

# Deterministic tree modes for the archive (owner/group are normalized at
# cpio time): nothing in the guest root should carry a build-host-specific
# writable shape.
umask 022

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="${OUTPUT:-$PROJECT_ROOT/output/initramfs.cpio.gz}"
WARDEN_BIN="${WARDEN_BIN:-$PROJECT_ROOT/output/warden}"
BUSYBOX="${BUSYBOX:-}"

# shellcheck source=build/checksums.sh
. "$PROJECT_ROOT/build/checksums.sh"

echo "=== Building sandswap initramfs for rootfs hot-swap ==="
echo "Output:     $OUTPUT"
echo "Warden bin: $WARDEN_BIN"

# Build warden if not found. The cargo build lands in warden/target/<musl>/
# while WARDEN_BIN defaults to output/warden — copy the built binary there or
# the existence check below fails on a SUCCESSFUL build (standalone runs only;
# build/build.sh always passes WARDEN_BIN explicitly).
if [ ! -f "$WARDEN_BIN" ]; then
    echo ""
    echo "Warden binary not found. Building warden..."
    (cd "$PROJECT_ROOT/warden" && cargo build --release --target x86_64-unknown-linux-musl)
    BUILT="$PROJECT_ROOT/warden/target/$(uname -m)-unknown-linux-musl/release/warden"
    mkdir -p "$PROJECT_ROOT/output"
    cp "$BUILT" "$WARDEN_BIN"
fi

if [ ! -f "$WARDEN_BIN" ]; then
    echo "ERROR: warden binary not found at $WARDEN_BIN"
    echo "  Build it: cd warden && cargo build --release --target x86_64-unknown-linux-musl"
    exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# ── Pinned busybox resolution ─────────────────────────────────────
# verify_pinned_busybox <path> — the version banner and the SHA-256 must both
# match the pin; nothing is packed otherwise.
verify_pinned_busybox() {
    local bin="$1" version want got
    version="$("$bin" 2>&1 | sed -n '1s/^BusyBox v\([0-9][0-9.]*\).*/\1/p' || true)"
    if [ "$version" != "$BUSYBOX_VERSION_PIN" ]; then
        echo "ERROR: busybox version mismatch at $bin" >&2
        echo "  found:  ${version:-unparsable}" >&2
        echo "  pinned: $BUSYBOX_VERSION_PIN (busybox-static $BUSYBOX_PKG_VERSION_PIN)" >&2
        return 1
    fi
    want="$(busybox_binary_sha256 "$BUSYBOX_PKG_VERSION_PIN" "$BUSYBOX_PKG_ARCH_PIN")"
    got="$(sha256sum "$bin" | awk '{print $1}')"
    if [ "$got" != "$want" ]; then
        echo "ERROR: busybox checksum mismatch at $bin" >&2
        echo "  pinned: $want" >&2
        echo "  actual: $got" >&2
        echo "  The initramfs busybox is guest TCB: only the pinned build is accepted." >&2
        return 1
    fi
}

# deb_extract_member <deb> <member> <out> — extract one file from a .deb.
# dpkg-deb handles every payload compression; without it, unpack the data
# member with ar + tar (the pinned package is zstd-compressed, so that path
# needs zstd on PATH).
deb_extract_member() {
    local deb="$1" member="$2" out="$3" data
    if command -v dpkg-deb >/dev/null 2>&1; then
        dpkg-deb --fsys-tarfile "$deb" | tar -xOf - "$member" > "$out"
        return
    fi
    if ! command -v ar >/dev/null 2>&1; then
        echo "ERROR: need dpkg-deb or ar to unpack the pinned busybox .deb" >&2
        return 1
    fi
    data="$(ar t "$deb" | grep -E '^data\.tar\.' | head -1)"
    case "$data" in
        *.zst)
            command -v zstd >/dev/null 2>&1 || {
                echo "ERROR: the pinned .deb is zstd-compressed — install dpkg-deb or zstd" >&2
                return 1
            }
            ar p "$deb" "$data" | tar --zstd -xOf - "$member" > "$out"
            ;;
        *.xz)  ar p "$deb" "$data" | tar -xJOf - "$member" > "$out" ;;
        *.gz)  ar p "$deb" "$data" | tar -xzOf - "$member" > "$out" ;;
        *) echo "ERROR: unsupported .deb payload ($data) — install dpkg-deb" >&2; return 1 ;;
    esac
}

if [ "$(uname -m)" != "x86_64" ]; then
    echo "ERROR: the guest (and its pinned busybox) is x86_64-only — found $(uname -m)" >&2
    exit 1
fi

# Both paths verify through a file literally named `busybox`: the multicall
# binary dispatches on argv[0], so a differently-named copy would answer
# "applet not found" instead of the version banner.
PINNED_DIR="$WORKDIR/pinned"
mkdir -p "$PINNED_DIR"

if [ -n "$BUSYBOX" ]; then
    if [ ! -f "$BUSYBOX" ]; then
        echo "ERROR: BUSYBOX=$BUSYBOX is not a file" >&2
        exit 1
    fi
    echo "Busybox:    $BUSYBOX (explicit; verified against the pin)"
    ln -s "$(readlink -f "$BUSYBOX")" "$PINNED_DIR/busybox"
    BUSYBOX="$PINNED_DIR/busybox"
    verify_pinned_busybox "$BUSYBOX" || exit 1
else
    BUSYBOX_URL="$(busybox_static_deb_url "$BUSYBOX_PKG_VERSION_PIN" "$BUSYBOX_PKG_ARCH_PIN")" || {
        echo "ERROR: no pinned busybox .deb for ${BUSYBOX_PKG_VERSION_PIN}/${BUSYBOX_PKG_ARCH_PIN} (build/checksums.sh)" >&2
        exit 1
    }
    BUSYBOX_DEB_SHA="$(busybox_static_deb_sha256 "$BUSYBOX_PKG_VERSION_PIN" "$BUSYBOX_PKG_ARCH_PIN")"
    BUSYBOX_DEB="$WORKDIR/busybox-static.deb"
    echo "Busybox:    busybox-static ${BUSYBOX_PKG_VERSION_PIN} (${BUSYBOX_PKG_ARCH_PIN}, pinned) — fetching"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$BUSYBOX_DEB" "$BUSYBOX_URL" || {
            echo "ERROR: cannot fetch the pinned busybox: $BUSYBOX_URL" >&2
            echo "  offline build: BUSYBOX=/path/to/busybox (sha256 $(busybox_binary_sha256 "$BUSYBOX_PKG_VERSION_PIN" "$BUSYBOX_PKG_ARCH_PIN"))" >&2
            exit 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$BUSYBOX_DEB" "$BUSYBOX_URL" || {
            echo "ERROR: cannot fetch the pinned busybox: $BUSYBOX_URL" >&2
            echo "  offline build: BUSYBOX=/path/to/busybox (sha256 $(busybox_binary_sha256 "$BUSYBOX_PKG_VERSION_PIN" "$BUSYBOX_PKG_ARCH_PIN"))" >&2
            exit 1
        }
    else
        echo "ERROR: curl or wget is required to fetch the pinned busybox" >&2
        exit 1
    fi
    BUSYBOX_DEB_ACTUAL="$(sha256sum "$BUSYBOX_DEB" | awk '{print $1}')"
    if [ "$BUSYBOX_DEB_ACTUAL" != "$BUSYBOX_DEB_SHA" ]; then
        echo "ERROR: busybox .deb checksum mismatch ($BUSYBOX_URL)" >&2
        echo "  pinned: $BUSYBOX_DEB_SHA" >&2
        echo "  actual: $BUSYBOX_DEB_ACTUAL" >&2
        exit 1
    fi
    BUSYBOX="$PINNED_DIR/busybox"
    deb_extract_member "$BUSYBOX_DEB" ./usr/bin/busybox "$BUSYBOX" || exit 1
    chmod 0755 "$BUSYBOX"
    verify_pinned_busybox "$BUSYBOX" || exit 1
fi

# Create initramfs directory structure
mkdir -p "$WORKDIR"/{bin,dev/shm,dev/pts,proc,sys,tmp,run,mnt/rootfs,etc,warden-bin}

# Copy busybox. 0555: guest root must not be able to rewrite the shell that
# later tenants of this VM execute (the warden additionally hot-binds a
# read-only tmpfs copy as its defense in depth).
cp "$BUSYBOX" "$WORKDIR/bin/busybox"
chmod 0555 "$WORKDIR/bin/busybox"

# Create busybox symlinks for essential commands. Every name must be an applet
# compiled into the pinned build: the multicall binary answers "applet not
# found" otherwise, leaving a dead symlink in the guest TCB.
cd "$WORKDIR/bin"
for cmd in sh mount umount ls cat cp mv rm mkdir sync chroot; do
    ln -sf busybox "$cmd"
done
cd -

# Copy warden as init.orig
cp "$WARDEN_BIN" "$WORKDIR/init.orig"
chmod +x "$WORKDIR/init.orig"

# Create /init script (PID 1)
cat > "$WORKDIR/init" << 'INITEOF'
#!/bin/sh
mkdir -p /mnt/rootfs
ln -sf /bin/busybox /bin/sh
exec /init.orig
INITEOF
chmod +x "$WORKDIR/init"

# Build cpio archive. Owner/group are normalized to root:root regardless of
# who runs the build (newc otherwise records the build host's uid/gid).
cd "$WORKDIR"
find . -print0 | cpio --null -ov --format=newc --owner root:root 2>/dev/null | gzip > "$OUTPUT"
cd -

SIZE=$(du -h "$OUTPUT" | cut -f1)
echo "=== Initramfs built: $OUTPUT ($SIZE) ==="
echo ""
echo "To use with sandswap:"
echo "  Deploy to /var/lib/sandswap/initramfs.cpio.gz on each node"
echo "  The sandlot will pass it to sandvmm via --initramfs"
