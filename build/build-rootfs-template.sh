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
# build-rootfs-template.sh — Build a minimal chroot-able rootfs template directory.
# With virtio-fs + bind mount, each agent's rootfs is a plain directory (no ext4).
# This script builds a template directory containing busybox-based root filesystem
# with /bin/sh and core utilities.
# The template is intentionally minimal (static busybox only) so it is:
#   - tiny (~a few MB)
#   - free of dynamic-library dependencies (works in any chroot)
#   - sufficient for shell-based file read/write execution tests
# Output: $OUTPUT (default: output/rootfs-template/)
# Consumed as a FLAT template: deploy tooling copies it to
# flat-templates/rootfs/v1/ so the gateway's -flat-templates scan registers
# "rootfs:v1", and SandFS creation seeds new flat volumes from it by copy.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="${ROOTFS_TEMPLATE:-$PROJECT_ROOT/output/rootfs-template}"
BUSYBOX="${BUSYBOX:-$(which busybox 2>/dev/null || echo '')}"

if [ -z "$BUSYBOX" ]; then
    echo "ERROR: busybox not found. Install: apt install busybox-static" >&2
    exit 1
fi

echo "=== Building rootfs template directory ==="
echo "Output:   $OUTPUT"
echo "Busybox:  $BUSYBOX ($(file -b "$BUSYBOX" 2>/dev/null | cut -d, -f1 || echo static))"

# Clean and recreate
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"/{bin,sbin,usr/bin,usr/sbin,lib,lib64,dev,proc,sys,tmp,run,etc,root,workspace,home/agent}

# Copy the static busybox and create symlinks for a usable shell + coreutils.
cp "$BUSYBOX" "$OUTPUT/bin/busybox"
cd "$OUTPUT/bin"
for cmd in sh ash bash cat echo ls mkdir rmdir cp mv rm ln touch head tail \
           grep sed awk test true false printf wc sort uniq tr cut date \
           sleep sync mount umount env pwd cd chmod chown stat dirname basename \
           tee dd tar gzip gunzip find which id whoami hostname uname \
           ip nc ping ping6 \
           yes seq expr realpath readlink; do
    ln -sf busybox "$cmd"
done
cd "$SCRIPT_DIR/.."

# /bin/sh is the primary shell used by exec_workspace.

# Minimal /etc files.
cat > "$OUTPUT/etc/passwd" << 'EOF'
root:x:0:0:root:/root:/bin/sh
EOF
cat > "$OUTPUT/etc/group" << 'EOF'
root:x:0:
EOF
cat > "$OUTPUT/etc/hostname" << 'EOF'
sandswap
EOF

# /tmp is the only sticky world-writable directory (standard semantics). The
# agent's workspace and home are ordinary 0755 directories: the template is
# shared storage read through the virtio-fs daemon, so a world-writable tree
# would let any local identity rewrite content every tenant executes. The
# in-guest agent is root and writes them regardless.
chmod 1777 "$OUTPUT/tmp"
chmod 0755 "$OUTPUT/workspace"
chmod 0755 "$OUTPUT/home/agent"

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

SIZE=$(du -sh "$OUTPUT" | cut -f1)
echo "=== Rootfs template built: $OUTPUT ($SIZE) ==="
echo "Register as flat template: copy to <flat-templates>/rootfs/v1/ (see docs/building/templates.md)."
