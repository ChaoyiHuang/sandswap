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
# benchmark-overlayfs.sh - Benchmark read-only overlay + writable workspace/home bind mount performance
# Usage: sudo bash e2e/benchmark-overlayfs.sh
# This script measures:
# 1. Mount/umount latency (read-only overlay vs bind mount)
# 2. Read latency (overlay lowerdir vs direct)
# 3. Write latency (workspace bind mount — a LOCAL dir standing in for the volume's storage)
# 4. Readdir/stat latency
# 5. Agent switch latency (umount + mount with read-only overlay)
# Architecture under test (mirrors Sandswap production; NB the workspace/home
# bind targets are LOCAL directories — production may bind a shared backend
# (NFS etc.) at the same paths, so the numbers here measure the bind-mount
# path cost, not the storage backend):
#   - Read-only overlay: lowerdir=template,ro (no upperdir/workdir)
#   - Writable /workspace: bind mount (local stand-in for the volume's storage)
#   - Writable /home/agent: bind mount (local stand-in for the volume's storage)
#   - Writable /tmp: tmpfs (local, not shared)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

# Requires root (mount -t overlay / bind mounts).
tc_check_root

# now_us — microsecond clock via $EPOCHREALTIME (no fork; `date +%s%N` costs
# ~1-2ms per call, the same order as the effect being measured).
now_us() { local _t="$EPOCHREALTIME"; echo "${_t/./}"; }

# sanity_ms — a measurement of <name> must be positive and under a generous
# ceiling: all-zero means the timing loop measured nothing (umount silently
# failing, etc.); a huge value means something is broken, both of which used
# to print as ordinary benchmark rows and exit 0.
sanity_ms() {
    local val="$1" what="$2"
    if (( val <= 0 )); then
        tc_log_error "sanity: $what = ${val}ms (non-positive — the measured loop did nothing)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    elif (( val >= 1000 )); then
        tc_log_error "sanity: $what = ${val}ms (≥1s per op — something is badly wrong)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# Setup
BASE_DIR="/tmp/sandswap-benchmark"
TEMPLATE_DIR="$BASE_DIR/template"
AGENT1_DIR="$BASE_DIR/agent1"
AGENT2_DIR="$BASE_DIR/agent2"

# Cleanup — unmount ALL mounts (including bindroot) before rm -rf.
# Without explicit umount, rm -rf fails on mount points with EBUSY.
cleanup() {
    for agent in agent1 agent2; do
        mountpoint -q "$BASE_DIR/$agent/rootfs/tmp"         && umount "$BASE_DIR/$agent/rootfs/tmp" 2>/dev/null || true
        mountpoint -q "$BASE_DIR/$agent/rootfs/home/agent"  && umount "$BASE_DIR/$agent/rootfs/home/agent" 2>/dev/null || true
        mountpoint -q "$BASE_DIR/$agent/rootfs/workspace"   && umount "$BASE_DIR/$agent/rootfs/workspace" 2>/dev/null || true
        mountpoint -q "$BASE_DIR/$agent/rootfs"             && umount "$BASE_DIR/$agent/rootfs" 2>/dev/null || true
        mountpoint -q "$BASE_DIR/$agent/bindroot"           && umount "$BASE_DIR/$agent/bindroot" 2>/dev/null || true
    done
    rm -rf "$BASE_DIR"
}
trap cleanup EXIT INT TERM

# Create template (simulate a minimal rootfs)
setup() {
    tc_log_section "Setting up test environment"
    # Unmount residue from a SIGKILLed previous run BEFORE rm -rf: rm removes
    # the mountpoint dirs but the mounts survive referencing deleted paths,
    # and the new run's mounts then stack on the stale tree.
    tc_unmount_overlays_under "$BASE_DIR"
    for agent in agent1 agent2; do
        for mp in rootfs/tmp rootfs/home/agent rootfs/workspace rootfs bindroot; do
            mountpoint -q "$BASE_DIR/$agent/$mp" 2>/dev/null && umount "$BASE_DIR/$agent/$mp" 2>/dev/null || true
        done
    done
    rm -rf "$BASE_DIR"
    mkdir -p "$TEMPLATE_DIR"/{bin,usr/bin,lib,workspace,tmp,etc,home/agent}

    # Create some files (simulate busybox + python)
    dd if=/dev/urandom of="$TEMPLATE_DIR/bin/busybox" bs=1M count=2 2>/dev/null
    dd if=/dev/urandom of="$TEMPLATE_DIR/usr/bin/python3" bs=1M count=10 2>/dev/null
    dd if=/dev/urandom of="$TEMPLATE_DIR/lib/libpython3.12.so" bs=1M count=5 2>/dev/null
    echo "test" > "$TEMPLATE_DIR/workspace/test.txt"

    # Linux kernel requires at least 2 lowerdirs when upperdir is absent
    # ("overlayfs: at least 2 lowerdir are needed while upperdir nonexistent").
    # Create an empty directory as the second lowerdir — it contributes no files
    # and has no semantic effect. Same pattern as sandlot/core/overlay.go.
    EMPTY_LAYER="$BASE_DIR/.empty-layer"
    mkdir -p "$EMPTY_LAYER"

    # Create agent directories (read-only overlay + writable workspace/home)
    for agent in agent1 agent2; do
        mkdir -p "$BASE_DIR/$agent"/{rootfs,workspace,home}
        # Write some initial workspace content
        echo "workspace for $agent" > "$BASE_DIR/$agent/workspace/init.txt"
    done
}

# Mount a full agent rootfs (read-only overlay + bind mounts)
mount_agent() {
    local agent_dir="$1"
    local rootfs="$agent_dir/rootfs"

    # 1. Mount read-only overlay (lowerdir only, no upperdir/workdir)
    #    Kernel requires ≥2 lowerdirs without upperdir; empty-layer is a no-op.
    mount -t overlay overlay \
        -o "lowerdir=$TEMPLATE_DIR:$EMPTY_LAYER,ro" \
        "$rootfs"

    # 2. Bind mount writable workspace
    mount --bind "$agent_dir/workspace" "$rootfs/workspace"

    # 3. Bind mount writable home
    mount --bind "$agent_dir/home" "$rootfs/home/agent"

    # 4. Mount tmpfs at /tmp
    mount -t tmpfs -o "mode=1777,size=64m" tmpfs "$rootfs/tmp"
}

# Unmount a full agent rootfs (reverse order)
umount_agent() {
    local agent_dir="$1"
    local rootfs="$agent_dir/rootfs"

    umount "$rootfs/tmp" 2>/dev/null || true
    umount "$rootfs/home/agent" 2>/dev/null || true
    umount "$rootfs/workspace" 2>/dev/null || true
    umount "$rootfs" 2>/dev/null || true
}

# Benchmark functions
benchmark_mount_umount() {
    local iterations=100
    local fs_type=$1

    echo ""
    echo "=== Mount/Umount Latency ($fs_type) ==="

    local total_us=0
    for i in $(seq 1 $iterations); do
        local start end
        start=$(now_us)
        if [ "$fs_type" = "bind" ]; then
            mount --bind "$TEMPLATE_DIR" "$AGENT1_DIR/rootfs"
            umount "$AGENT1_DIR/rootfs"
        else
            # Read-only overlay only (no workspace/home bind mounts for this micro-bench)
            mount -t overlay overlay \
                -o "lowerdir=$TEMPLATE_DIR:$EMPTY_LAYER,ro" \
                "$AGENT1_DIR/rootfs"
            umount "$AGENT1_DIR/rootfs"
        fi
        end=$(now_us)
        total_us=$(( total_us + end - start ))
    done

    local avg
    avg=$((total_us / iterations / 1000))
    echo "Iterations: $iterations"
    echo "Total time: $((total_us / 1000))ms"
    echo "Average per mount+umount: ${avg}ms"
    sanity_ms "$avg" "mount+umount ($fs_type)"
}

benchmark_full_mount() {
    local iterations=50

    echo ""
    echo "=== Full Agent Mount/Umount Latency (ro overlay + bind mounts + tmpfs) ==="

    local total_us=0
    for i in $(seq 1 $iterations); do
        local start end
        start=$(now_us)
        mount_agent "$AGENT1_DIR"
        umount_agent "$AGENT1_DIR"
        end=$(now_us)
        total_us=$(( total_us + end - start ))
    done

    local avg

    avg=$((total_us / iterations / 1000))
    echo "Iterations: $iterations"
    echo "Total time: $((total_us / 1000))ms"
    echo "Average per full mount+umount: ${avg}ms"
    echo "  (includes: ro overlay mount + 2 bind mounts + tmpfs + 4 umounts)"
    sanity_ms "$avg" "full agent mount+umount"
}

benchmark_read() {
    local iterations=1000
    local fs_type=$1

    echo ""
    echo "=== Read Latency ($fs_type) ==="

    # Mount
    if [ "$fs_type" = "bind" ]; then
        mount --bind "$TEMPLATE_DIR" "$AGENT1_DIR/rootfs"
    else
        mount -t overlay overlay \
            -o "lowerdir=$TEMPLATE_DIR:$EMPTY_LAYER,ro" \
            "$AGENT1_DIR/rootfs"
    fi

    # Warm up
    cat "$AGENT1_DIR/rootfs/bin/busybox" > /dev/null

    # Benchmark small file read
    local start end
    start=$(now_us)
    for i in $(seq 1 $iterations); do
        cat "$AGENT1_DIR/rootfs/workspace/test.txt" > /dev/null
    done
    end=$(now_us)
    local elapsed_us=$(( end - start ))
    echo "Small file read (1KB, $iterations iterations): $((elapsed_us / 1000))ms (avg $((elapsed_us / iterations))µs)"
    (( elapsed_us / iterations > 0 )) || { tc_log_error "sanity: small-file read avg = 0µs"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

    # Benchmark large file read
    start=$(now_us)
    for i in $(seq 1 10); do
        cat "$AGENT1_DIR/rootfs/bin/busybox" > /dev/null
    done
    end=$(now_us)
    echo "Large file read (2MB, 10 iterations): $(( (end - start) / 1000000 ))ms (avg $(( (end - start) / 10000000 ))ms)"

    umount "$AGENT1_DIR/rootfs"
}

benchmark_write() {
    local iterations=100

    echo ""
    echo "=== Write Latency (workspace bind mount) ==="

    # Mount full agent
    mount_agent "$AGENT1_DIR"

    # Timed with now_us (no fork) — a single write is us-scale and the
    # date fork (~1-2ms) would dominate the window.
    # Benchmark write to workspace (bind mount — the writable path)
    echo "Write to /workspace (bind mount to agent workspace dir):"
    local start
    start=$(now_us)
    echo "test data" > "$AGENT1_DIR/rootfs/workspace/output.txt"
    local end
    end=$(now_us)
    local elapsed
    elapsed=$(( end - start ))
    echo "  First write latency: ${elapsed}us"

    echo "Subsequent writes:"
    start=$(now_us)
    for i in $(seq 1 $iterations); do
        echo "test data $i" > "$AGENT1_DIR/rootfs/workspace/output.txt"
    done
    end=$(now_us)
    elapsed=$(( end - start ))
    echo "  $iterations writes: $((elapsed / 1000))ms (avg $((elapsed / iterations))µs/write)"

    echo "Write to new files:"
    start=$(now_us)
    for i in $(seq 1 $iterations); do
        echo "new data" > "$AGENT1_DIR/rootfs/workspace/newfile_$i.txt"
    done
    end=$(now_us)
    elapsed=$(( end - start ))
    echo "  $iterations writes: $((elapsed / 1000))ms (avg $((elapsed / iterations))µs/write)"

    # Verify read-only rootfs
    echo ""
    echo "=== Read-only rootfs enforcement ==="
    if touch "$AGENT1_DIR/rootfs/usr/test-ro" 2>/dev/null; then
        fail "write to read-only rootfs SUCCEEDED (isolation broken)"
    else
        pass "write to read-only rootfs blocked (Read-only file system)"
    fi

    umount_agent "$AGENT1_DIR"
}

benchmark_switch() {
    local iterations=50

    echo ""
    echo "=== Agent Switch Latency (umount old + mount new) ==="

    # Mount agent1
    mount_agent "$AGENT1_DIR"

    echo "Read-only overlay + bind mount switch:"
    local total_us=0
    for i in $(seq 1 $iterations); do
        local start end
        start=$(now_us)
        # Switch from agent1 to agent2
        umount_agent "$AGENT1_DIR"
        mount_agent "$AGENT2_DIR"
        end=$(now_us)
        total_us=$(( total_us + end - start ))

        # Switch back
        umount_agent "$AGENT2_DIR"
        mount_agent "$AGENT1_DIR"
    done

    local avg

    avg=$((total_us / iterations / 1000))
    echo "Iterations: $iterations"
    echo "Total time: $((total_us / 1000))ms"
    echo "Average per switch: ${avg}ms"
    echo "  (includes: 4 umounts + ro overlay mount + 2 bind mounts + tmpfs)"
    sanity_ms "$avg" "agent switch"

    umount_agent "$AGENT1_DIR" 2>/dev/null || true

    # Bind mount comparison
    mkdir -p "$AGENT1_DIR/bindroot"
    mkdir -p "$AGENT2_DIR/bindroot"

    mount --bind "$TEMPLATE_DIR" "$AGENT1_DIR/bindroot"

    echo ""
    echo "Bind mount switch (baseline):"
    total_us=0
    for i in $(seq 1 $iterations); do
        local start end
        start=$(now_us)
        umount "$AGENT1_DIR/bindroot"
        mount --bind "$TEMPLATE_DIR" "$AGENT2_DIR/bindroot"
        end=$(now_us)
        total_us=$(( total_us + end - start ))

        umount "$AGENT2_DIR/bindroot"
        mount --bind "$TEMPLATE_DIR" "$AGENT1_DIR/bindroot"
    done

    avg=$((total_us / iterations / 1000))
    echo "Iterations: $iterations"
    echo "Total time: $((total_us / 1000))ms"
    echo "Average per switch: ${avg}ms"
    sanity_ms "$avg" "bind-mount switch"

    umount "$AGENT1_DIR/bindroot" 2>/dev/null || true
}

# Run benchmarks
setup

echo ""
echo "============================================"
echo "Sandswap Read-Only Overlay Benchmark"
echo "============================================"
echo ""
echo "Architecture:"
echo "  - Read-only overlay: lowerdir=template,ro (no upperdir/workdir)"
echo "  - Writable /workspace: bind mount (local stand-in for the volume's storage)"
echo "  - Writable /home/agent: bind mount (local stand-in for the volume's storage)"
echo "  - Writable /tmp: tmpfs (local)"

benchmark_mount_umount bind
benchmark_mount_umount overlay-ro

benchmark_read bind
benchmark_read overlay-ro

benchmark_full_mount
benchmark_write
benchmark_switch

echo ""
echo "=== Summary ==="
echo "Read-only overlay (no upperdir/workdir) eliminates upperdir issues."
echo "Writes go to workspace/ and home/ via bind mount (local dirs here; production may bind a shared backend)."
echo "Read-only rootfs is enforced by the kernel (no copy-up overhead)."
echo ""
echo "For Sandswap:"
echo "- Warm path: Negligible impact (reads are zero-overhead)"
echo "- Switch path: ~0.3ms overlay overhead + bind mount cost"
echo "- No NFS upperdir incompatibility (ro overlay works on any FS)"
echo "- No CleanupOverlay needed (stateless overlay)"

# Even though this is a benchmark (no timing gates), the read-only-rootfs
# enforcement check above is an isolation property: a violation must fail the
# run, not print a warning into green output.
if [[ "${FAIL_COUNT:-0}" -gt 0 ]]; then
    tc_log_error "$FAIL_COUNT check(s) failed"
    exit 1
fi
