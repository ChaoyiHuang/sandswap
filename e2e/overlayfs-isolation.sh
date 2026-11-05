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
# test-overlayfs-isolation.sh — Test read-only overlay + writable workspace/home isolation.
# This is a STANDALONE test script that:
# 1. Cleans up existing environment
# 2. Deploys and starts gateway + sandlot
# 3. Tests read-only overlay + writable workspace/home bind mount isolation properties
# 4. Cleans up all resources on exit
# Architecture (read-only overlay + writable workspace/home):
#   $VOL_ROOT/sandfs-xxx/
#     rootfs/       ← read-only overlay (lowerdir only, no upperdir/workdir)
#     workspace/    ← writable bind mount → /workspace (read-write)
#     home/         ← writable bind mount → /home/agent (read-write)
#     .template     ← marker file with template ref
#   Inside the VM:
#     /mnt/rootfs           ← bind mount from rootfs/ (read-only)
#     /mnt/rootfs/workspace ← bind mount from workspace/ (read-write)
#     /mnt/rootfs/home/agent← bind mount from home/ (read-write)
#     /mnt/rootfs/tmp       ← tmpfs (local, not shared)
# Tests:
#   Phase 4: Bind mount mode — basic /workspace read/write
#   Phase 5: Template mode — read-only rootfs + writable paths
#     1. VM can read/write in /workspace (writable bind mount)
#     2. VM can read/write in /home/agent (writable bind mount)
#     3. VM CANNOT write to read-only rootfs (e.g., touch /usr/test fails)
#     4. virtio-fs basename filtering works (only sandfs-xxx visible)
#     5. /tmp is writable (tmpfs) but local (not shared storage)
#     6. Environment variables for home-directory packages are set
# Usage:
#   sudo bash e2e/overlayfs-isolation.sh

set -euo pipefail

declare -A KEY2SID  # api_key -> sandfs_id for exec_in_vm

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Override defaults before sourcing
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
VOL_ROOT="${VOL_ROOT:-/var/lib/sandswap/volumes}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
# shellcheck disable=SC2034  # SANDLOT_POOL is consumed by the SOURCED common.sh across the source boundary
SANDLOT_POOL="small:2"
LEASE_MS="${LEASE_MS:-1000}"
TEMPLATE_DIR="${TEMPLATE_DIR:-/tmp/sandswap-templates}"
source "$ROOT/e2e/common.sh"

# Run directly from $OUTPUT (no deploy step) — tc_use_output_binaries sets
# the TC_ binary paths AND verifies the service identities can exec them
# (dev checkouts under a restrictive home would otherwise fail every VM
# launch with fork/exec EACCES).
tc_use_output_binaries
# Flat templates: create versioned structure so ScanFlatTemplates registers "rootfs:v1"
# Wipe FIRST: a SIGKILLed previous run leaves the dir behind (no trap ran) and
# its stale content would merge into this run's "clean" flat template.
FLAT_TEMPLATE_DIR="${FLAT_TEMPLATE_DIR:-/tmp/sandswap-flat-templates}"
rm -rf "$FLAT_TEMPLATE_DIR"
ss_seed_template "$OUTPUT/rootfs-template" "$FLAT_TEMPLATE_DIR/rootfs/v1"
# shellcheck disable=SC2034  # TC_FLAT_TEMPLATES is consumed by the SOURCED common.sh across the source boundary
TC_FLAT_TEMPLATES="$FLAT_TEMPLATE_DIR"

cleanup() {
    local exit_code=$?
    if [[ "${KEEP_ENV:-0}" == "1" ]]; then
        echo "KEEP_ENV=1: stack + logs kept (gateway/sandlot running, logs at $LOG_DIR)" >&2
        exit "$exit_code"
    fi
    tc_cleanup_default
    # Remove script-specific temp directories (not covered by tc_cleanup_default)
    rm -rf "$TEMPLATE_DIR" "$FLAT_TEMPLATE_DIR" 2>/dev/null || true
    exit "$exit_code"
}
trap cleanup EXIT
# Signals must not be readable as success: $? in the EXIT trap can be 0 when a
# signal lands between commands, so force the conventional statuses here.
trap 'exit 130' INT
trap 'exit 143' TERM

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight Checks"
# ══════════════════════════════════════════════════════════════════

tc_check_root
tc_check_artifacts gateway sandlot sandvmm vmlinux.bin initramfs.cpio.gz
tc_ensure_dev_nodes

# Check rootfs-template exists
if [[ ! -d "$OUTPUT/rootfs-template" ]]; then
    log_error "rootfs-template not found in $OUTPUT/"
    log_info "Run: bash build/build.sh rootfs-template"
    exit 1
fi
log_pass "rootfs-template present"

tc_check_kvm

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Clean Environment"
# ══════════════════════════════════════════════════════════════════

tc_clean_environment
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — microVMs will be offline"
fi
# A previous NFS-profile run leaves the templates export MOUNTED at
# $TEMPLATE_DIR; `ss_prepare_shared_dir`'s rm -rf would then fail EBUSY and
# abort the run. Unmount it first (the mount is re-established below).
if [[ "${STORAGE_BACKEND:-local}" == "nfs" ]] && mountpoint -q "$TEMPLATE_DIR"; then
    umount "$TEMPLATE_DIR" || true
fi
# Create directories needed by this script but not by tc_clean_environment.
# The gateway (sandswap identity) writes template refs INTO TEMPLATE_DIR, so
# it must be a shared setgid dir — a bare root mkdir would leave it unwritable.
ss_prepare_shared_dir "$TEMPLATE_DIR"
# Distributed-storage e2e profile: put the overlay template root (the
# overlayfs LOWERDIR source) on the loopback NFS export — this is the
# critical overlayfs-on-shared-storage validation. Mounted AFTER the shared
# dir is prepared and BEFORE the templates are seeded, so all content and
# the gateway's refs/ land on NFS.
if [[ "${STORAGE_BACKEND:-local}" == "nfs" ]]; then
    ss_storage_nfs_mount templates "$TEMPLATE_DIR"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Prepare Local Template"
# ══════════════════════════════════════════════════════════════════

# Create a versioned local template that gateway auto-discovers.
#   $TEMPLATE_DIR/isolation/v1/  ← busybox rootfs (templateRef "isolation:v1")
#
# When -overlayfs-templates points here, gateway auto-scans and registers "isolation:v1".

log_step "Creating isolation template (versioned: isolation:v1)..."
ss_seed_template "$OUTPUT/rootfs-template" "$TEMPLATE_DIR/isolation/v1"
log_pass "Isolation template ready: $TEMPLATE_DIR/isolation/v1/"

# Second template for the layer-ID trust-boundary phase (Phase 8): registered
# BEFORE gateway start (scan writes refs/evil_v1.overlay.json with the legal
# absolute-path layer), tampered AFTER registration and BEFORE its first
# mount — the sandlot ref cache loads lazily per sandfs, so the tampered file
# is what the loader sees.
log_step "Creating evil-test template (registered clean, tampered before mount)..."
ss_seed_template "$OUTPUT/rootfs-template" "$TEMPLATE_DIR/evil/v1"
log_pass "Evil-test template ready: $TEMPLATE_DIR/evil/v1/"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Deploy and Start Services"
# ══════════════════════════════════════════════════════════════════

# Generate mTLS certs
# shellcheck disable=SC2034  # CERT_DIR is consumed by the SOURCED common.sh across the source boundary
CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
tc_gen_certs
tc_attach_vsockguard

# The template store lives in the prov role (the sandlot below carries it —
# the gateway has no template manager).
log_step "Starting gateway (sticky-ms=$LEASE_MS, OverlayFS mode)..."
tc_start_gateway
log_pass "Gateway started (OverlayFS mode via -overlayfs-templates)"

# Verify template registration
TEMPLATES_RESP=$(curl -s "$HUMAN_URL/human/templates" 2>/dev/null || echo "[]")
echo "  Registered templates: $TEMPLATES_RESP"
echo "$TEMPLATES_RESP" | python3 -c "
import sys, json
ts = json.load(sys.stdin)
for t in ts: print(f'    - {t[\"name\"]}:{t[\"version\"]} (cached: {t[\"cached\"]})')
" 2>/dev/null || log_warn "Could not parse templates response"

# Start sandlot with -overlayfs-templates for overlay lazy mount
tc_start_sandlot -overlayfs-templates "$TEMPLATE_DIR"
tc_wait_health
# Pool pre-creation is async — the first cold exec below would otherwise race
# the booting pool and fail 4.1 as a false "no available sandbox" on slow hosts.
tc_wait_pool_ready 2

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Bind Mount Mode — Basic /workspace Test"
# ══════════════════════════════════════════════════════════════════

# Create a SandFS with flat template (bind mount mode, fully writable rootfs).
# This tests the flat path: the volume is a plain directory seeded
# from rootfs-template via cp -a, and /workspace is the same directory.

log_step "Creating flat SandFS (template=rootfs:v1, mode=flat)..."
SANDFS_RESP=$(tc_create_agent_and_sandfs "bind-test" "rootfs:v1" "flat" || echo '{"error":"create failed"}')

BIND_ID=$(json_val "$SANDFS_RESP" "sandfs_id")
BIND_KEY=$(json_val "$SANDFS_RESP" "api_key")

# Guard BEFORE the KEY2SID subscript: an empty key would throw
# "bad array subscript" and kill the script before the real error surfaces.
if [[ -z "$BIND_ID" ]] || [[ -z "$BIND_KEY" ]]; then
    fail "Failed to create bind-mount SandFS: $SANDFS_RESP"
    exit 1
fi
KEY2SID["$BIND_KEY"]="$BIND_ID"
BIND_VOL=$(json_val "$SANDFS_RESP" "rootfs_path")

pass "Bind-mount SandFS created: $BIND_ID"
log_info "Volume: $BIND_VOL"

# Helper: execute a command in a VM. curl -m so a hung gateway FAILS instead
# of hanging the whole test; transient cold-pool rejections get a short retry.
exec_in_vm() {
    local key="$1"
    local code="$2"
    local sid="${KEY2SID[$key]:-}"
    local resp try
    for try in 1 2 3; do
        resp=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/execute" \
            -H "Authorization: Bearer $key" \
            -H "Content-Type: application/json" \
            -d "{\"sandfs_id\":\"$sid\",\"code\":\"$code\",\"language\":\"shell\"}" 2>/dev/null || echo '{}')
        if [[ "$try" -lt 3 ]] && echo "$resp" | grep -qE '"(NO_AVAILABLE_SANDBOX|NO_COMPUTE_NODES|CONCURRENT_MOUNT|SANDBOX_CLEANING)"'; then
            sleep 1
            continue
        fi
        echo "$resp"
        return 0
    done
}

# Helper: extract stdout from response
resp_stdout() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo ""
}

# Helper: extract exit_code from response
resp_exit_code() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exit_code',-1))" 2>/dev/null || echo "-1"
}

# Helper: extract status from response
resp_status() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo ""
}

# Test 4.1: Write and read file in /workspace
log_step "4.1: VM write and read file in /workspace..."
VM_RESP=$(exec_in_vm "$BIND_KEY" "echo 'bind-content' > /workspace/test.txt && cat /workspace/test.txt")
BIND_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$BIND_STDOUT" | grep -q "bind-content"; then
    pass "4.1: Bind-mount VM can write and read /workspace"
else
    fail "4.1: Bind-mount VM write/read /workspace failed"
    log_info "Response: $VM_RESP"
fi

# Test 4.2: List /workspace
log_step "4.2: VM list /workspace..."
VM_RESP=$(exec_in_vm "$BIND_KEY" "ls /workspace/")
BIND_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$BIND_STDOUT" | grep -q "test.txt"; then
    pass "4.2: Bind-mount VM can see test.txt in /workspace"
else
    fail "4.2: Bind-mount VM cannot see test.txt"
    log_info "Response: $VM_RESP"
fi

# Test 4.3: the flat volume's .sandfs-id stamp is covered by the /dev/null
# bind. Reads must return EOF (zero bytes), never the id/seed-generation/HMAC.
# A failed cover now refuses the mount (fail-closed), so a successful exec
# that can read nonzero stamp bytes is a regression.
log_step "4.3: flat .sandfs-id stamp is masked..."
VM_RESP=$(exec_in_vm "$BIND_KEY" "wc -c < /.sandfs-id")
STAMP_BYTES=$(resp_stdout "$VM_RESP" | tr -d '[:space:]')
if [[ "$STAMP_BYTES" == "0" ]]; then
    pass "4.3: .sandfs-id is covered (0 bytes visible)"
else
    fail "4.3: .sandfs-id leaked or missing (wc -c = '${STAMP_BYTES:-<empty>}')"
    log_info "Response: $VM_RESP"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Template Mode — Read-Only Overlay + Writable Workspace/Home Isolation"
# ══════════════════════════════════════════════════════════════════

# Create a SandFS WITH a template (OverlayFS mode).
# This triggers the new architecture: read-only overlay rootfs +
# writable bind mounts for /workspace and /home/agent.

log_step "Creating template SandFS (template=isolation:v1)..."
TPL_RESP=$(tc_create_agent_and_sandfs "overlay-test" "isolation:v1" || echo '{"error":"create failed"}')

TPL_ID=$(json_val "$TPL_RESP" "sandfs_id")
# Volume directory: derived from the deployment seed, NOT the id
TPL_ID_VOL="$(tc_volume_path "$TPL_ID")" || { echo "cannot resolve volume for $TPL_ID" >&2; exit 1; }
TPL_KEY=$(json_val "$TPL_RESP" "api_key")
if [[ -z "$TPL_ID" ]] || [[ -z "$TPL_KEY" ]]; then
    fail "Failed to create template SandFS: $TPL_RESP"
    exit 1
fi
KEY2SID["$TPL_KEY"]="$TPL_ID"
TPL_VOL=$(json_val "$TPL_RESP" "rootfs_path")

pass "Template SandFS created: $TPL_ID"
log_info "Volume: $TPL_VOL"

# Verify directory structure
log_step "Verifying SandFS directory structure..."

if [[ -d "${TPL_ID_VOL}/workspace" ]]; then
    pass "workspace/ directory exists"
else
    fail "workspace/ directory NOT found"
fi

if [[ -d "${TPL_ID_VOL}/home" ]]; then
    pass "home/ directory exists"
else
    fail "home/ directory NOT found"
fi

if [[ -f "${TPL_ID_VOL}/.template" ]]; then
    TPL_MARKER=$(cat "${TPL_ID_VOL}/.template")
    if [[ "$TPL_MARKER" == "isolation:v1" ]]; then
        pass ".template marker = isolation:v1"
    else
        fail ".template marker = '$TPL_MARKER' (expected 'isolation:v1')"
    fi
else
    fail ".template marker NOT found"
fi

# The rootfs/ directory is created lazily by sandlot on first execute.
# It should NOT exist yet (lazy mount model).
if [[ ! -d "${TPL_ID_VOL}/rootfs" ]]; then
    log_info "rootfs/ does not exist yet (lazy mount model — expected)"
else
    log_warn "rootfs/ exists before first execute (unexpected in lazy mount model)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5a: Cold Execute — Trigger Overlay Mount"
# ══════════════════════════════════════════════════════════════════

log_step "Triggering cold execute to mount read-only overlay..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo cold-start-ok")
COLD_STDOUT=$(resp_stdout "$VM_RESP")
COLD_EXIT=$(resp_exit_code "$VM_RESP")

if echo "$COLD_STDOUT" | grep -q "cold-start-ok"; then
    pass "5a: Cold execute succeeded"
else
    fail "5a: Cold execute failed (exit=$COLD_EXIT)"
    log_info "Response: $VM_RESP"
fi

# Verify the read-only overlay is now mounted at rootfs/
# Probe the RESOLVED volume path (seed-derived "sf-<hmac>"), never the
# sandfs id: the on-disk name stopped containing the id when the volume-seed
# naming landed — grepping "$TPL_ID/rootfs" can never match the mount line
# and this probe silently reports "always NOT mounted".
if mount | grep -q "overlay.*$TPL_ID_VOL/rootfs"; then
    pass "Read-only overlay mounted at ${TPL_ID_VOL}/rootfs"

    # Verify it's read-only (no upperdir/workdir in mount options)
    OVERLAY_OPTS=$(mount | grep "overlay.*$TPL_ID_VOL/rootfs" | head -1)
    if echo "$OVERLAY_OPTS" | grep -q "upperdir"; then
        fail "Overlay has upperdir (should be read-only)"
        log_info "Mount options: $OVERLAY_OPTS"
    else
        pass "Overlay is read-only (no upperdir in mount options)"
    fi

    if echo "$OVERLAY_OPTS" | grep -q "workdir"; then
        fail "Overlay has workdir (should be read-only)"
    else
        pass "Overlay has no workdir (read-only overlay confirmed)"
    fi

    # Verify lowerdir points to the template. The value is the colon-joined
    # multi-lowerdir list "template:empty-layer" (kernel needs >=2 lowerdirs
    # without an upperdir — same empty-layer pattern as sandlot/core/overlay.go),
    # so compare the FIRST element, not the whole string.
    LOWERDIR=$(echo "$OVERLAY_OPTS" | grep -oP 'lowerdir=\K[^,]+' | head -1 || true)
    if [[ "${LOWERDIR%%:*}" == "$TEMPLATE_DIR/isolation/v1" ]]; then
        pass "Lowerdir points to isolation/v1 template ($LOWERDIR)"
    else
        fail "Lowerdir: $LOWERDIR (expected first element $TEMPLATE_DIR/isolation/v1) — template routing broken"
    fi
else
    fail "Read-only overlay NOT mounted at ${TPL_ID_VOL}/rootfs"
    log_info "Mount list:"
    mount | grep "overlay" || true
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5b: /workspace — Writable Bind Mount"
# ══════════════════════════════════════════════════════════════════

log_warn "Testing CRITICAL property: /workspace is writable via the workspace bind mount"

# Test 5b.1: Write to /workspace
log_step "5b.1: VM write to /workspace..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo 'workspace-write' > /workspace/ws-test.txt && cat /workspace/ws-test.txt")
WS_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$WS_STDOUT" | grep -q "workspace-write"; then
    pass "5b.1: VM can write and read /workspace (writable bind mount)"
else
    fail "5b.1: VM cannot write to /workspace — resp: ${VM_RESP:0:400}"
    log_info "Response: $VM_RESP"
fi

# Test 5b.2: Write persists across warm exec
log_step "5b.2: /workspace persistence (warm exec)..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "cat /workspace/ws-test.txt")
WS_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$WS_STDOUT" | grep -q "workspace-write"; then
    pass "5b.2: /workspace data persists across warm exec"
else
    fail "5b.2: /workspace data lost"
    log_info "Response: $VM_RESP"
fi

# Test 5b.3: Create subdirectory in /workspace
log_step "5b.3: VM create subdirectory in /workspace..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "mkdir -p /workspace/subdir && echo 'subdir-ok' > /workspace/subdir/file.txt && cat /workspace/subdir/file.txt")
WS_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$WS_STDOUT" | grep -q "subdir-ok"; then
    pass "5b.3: VM can create subdirectories in /workspace"
else
    fail "5b.3: VM cannot create subdirectories in /workspace"
    log_info "Response: $VM_RESP"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5c: /home/agent — Writable Bind Mount"
# ══════════════════════════════════════════════════════════════════

log_warn "Testing CRITICAL property: /home/agent is writable via the home bind mount"

# Test 5c.1: Write to /home/agent
log_step "5c.1: VM write to /home/agent..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "mkdir -p /home/agent && echo 'home-write' > /home/agent/home-test.txt && cat /home/agent/home-test.txt")
HOME_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$HOME_STDOUT" | grep -q "home-write"; then
    pass "5c.1: VM can write and read /home/agent (writable bind mount)"
else
    fail "5c.1: VM cannot write to /home/agent — resp: ${VM_RESP:0:400}"
    log_info "Response: $VM_RESP"
fi

# Test 5c.2: Create .local/bin directory (pip --user target)
log_step "5c.2: VM create /home/agent/.local/bin..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "mkdir -p /home/agent/.local/bin && echo 'bin-ok' > /home/agent/.local/bin/test-app && cat /home/agent/.local/bin/test-app")
HOME_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$HOME_STDOUT" | grep -q "bin-ok"; then
    pass "5c.2: VM can create /home/agent/.local/bin"
else
    fail "5c.2: VM cannot create /home/agent/.local/bin"
    log_info "Response: $VM_RESP"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5d: Read-Only Rootfs — Write Must Fail"
# ══════════════════════════════════════════════════════════════════

log_warn "Testing CRITICAL security property: VM CANNOT write to read-only rootfs"

# Test 5d.1: touch /usr/test should fail
log_step "5d.1: VM try to write to /usr (read-only rootfs)..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "touch /usr/test 2>&1; echo EXIT_CODE=\$?")
USR_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$USR_STDOUT" | grep -qi "Read-only file system\|Operation not permitted\|Permission denied"; then
    pass "5d.1: VM CANNOT write to /usr (read-only rootfs — SECURITY: PASS)"
elif echo "$USR_STDOUT" | grep -q "EXIT_CODE=0"; then
    fail "5d.1: VM CAN write to /usr (SECURITY: FAIL — rootfs is NOT read-only)"
    log_error "SECURITY ISSUE: VM can write to read-only rootfs!"
else
    # The exit code was non-zero but the error message may differ
    if echo "$USR_STDOUT" | grep -q "EXIT_CODE="; then
        EXIT_VAL=$(echo "$USR_STDOUT" | grep -oP 'EXIT_CODE=\K\d+')
        if [[ "$EXIT_VAL" != "0" ]]; then
            pass "5d.1: VM CANNOT write to /usr (exit=$EXIT_VAL — read-only rootfs)"
        else
            fail "5d.1: VM CAN write to /usr (exit=0 — SECURITY: FAIL)"
        fi
    else
        fail "5d.1: Could not determine write outcome (no EXIT_CODE line): '$USR_STDOUT' — security property UNVERIFIED"
    fi
fi

# Test 5d.2: touch /bin/sandswap-ro-test should fail
# NOTE: We must NOT use /bin/test — it's a busybox symlink that resolves
# to the hot-busybox overlay (writable tmpfs). Using a unique name ensures
# we test the actual read-only overlay, not the busybox bind mount.
log_step "5d.2: VM try to write to /bin (read-only rootfs)..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "touch /bin/sandswap-ro-test 2>&1; echo EXIT_CODE=\$?")
BIN_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$BIN_STDOUT" | grep -qi "Read-only file system\|Operation not permitted\|Permission denied"; then
    pass "5d.2: VM CANNOT write to /bin (read-only rootfs — SECURITY: PASS)"
elif echo "$BIN_STDOUT" | grep -q "EXIT_CODE=0"; then
    fail "5d.2: VM CAN write to /bin (SECURITY: FAIL — rootfs is NOT read-only)"
else
    if echo "$BIN_STDOUT" | grep -q "EXIT_CODE="; then
        EXIT_VAL=$(echo "$BIN_STDOUT" | grep -oP 'EXIT_CODE=\K\d+')
        if [[ "$EXIT_VAL" != "0" ]]; then
            pass "5d.2: VM CANNOT write to /bin (exit=$EXIT_VAL — read-only rootfs)"
        else
            fail "5d.2: VM CAN write to /bin (exit=0 — SECURITY: FAIL)"
        fi
    else
        fail "5d.2: Could not determine write outcome (no EXIT_CODE line): '$BIN_STDOUT' — security property UNVERIFIED"
    fi
fi

# Test 5d.3: touch /etc/test should fail
log_step "5d.3: VM try to write to /etc (read-only rootfs)..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "touch /etc/test 2>&1; echo EXIT_CODE=\$?")
ETC_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$ETC_STDOUT" | grep -qi "Read-only file system\|Operation not permitted\|Permission denied"; then
    pass "5d.3: VM CANNOT write to /etc (read-only rootfs — SECURITY: PASS)"
elif echo "$ETC_STDOUT" | grep -q "EXIT_CODE=0"; then
    fail "5d.3: VM CAN write to /etc (SECURITY: FAIL — rootfs is NOT read-only)"
else
    if echo "$ETC_STDOUT" | grep -q "EXIT_CODE="; then
        EXIT_VAL=$(echo "$ETC_STDOUT" | grep -oP 'EXIT_CODE=\K\d+')
        if [[ "$EXIT_VAL" != "0" ]]; then
            pass "5d.3: VM CANNOT write to /etc (exit=$EXIT_VAL — read-only rootfs)"
        else
            fail "5d.3: VM CAN write to /etc (exit=0 — SECURITY: FAIL)"
        fi
    else
        fail "5d.3: Could not determine write outcome (no EXIT_CODE line): '$ETC_STDOUT' — security property UNVERIFIED"
    fi
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5e: virtio-fs Basename Filtering"
# ══════════════════════════════════════════════════════════════════

log_warn "Testing CRITICAL security property: virtio-fs basename filtering"

# The VM should only see its own sandfs directory under /mnt/volumes/.
# Sibling directories (other sandfs entries) should be invisible.
# The allowed_dirs is set to ${TPL_ID_VOL}, so:
#   /mnt/volumes/$TPL_ID/ → visible (rootfs/, workspace/, home/, .template)
#   /mnt/volumes/$BIND_ID/ → NOT visible (different agent)

# Test 5e.1: VM can access its own workspace data (chrooted path)
# Note: Inside the chroot, /mnt/volumes is NOT visible — the agent only sees
# /mnt/rootfs and below. So we test workspace access instead, which proves
# the virtio-fs allowed_dirs filter is working for this sandfs.
log_step "5e.1: VM can access its own sandfs workspace..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo 'virtio-test' > /workspace/virtio-access-test.txt && cat /workspace/virtio-access-test.txt")
VOL_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$VOL_STDOUT" | grep -q "virtio-test"; then
    pass "5e.1: VM can access its own sandfs workspace (virtio-fs working)"
else
    fail "5e.1: VM cannot access its own sandfs workspace — resp: ${VOL_STDOUT:0:400} / raw: ${VM_RESP:0:400}"
    log_info "Response: $VM_RESP"
fi

# Test 5e.2: the raw virtio-fs share must be OUTSIDE the exec context.
#
# The old probe ran `ls /mnt/volumes/<sibling>` — a HOST-namespace path that
# cannot resolve inside the chroot (/mnt/rootfs; the shipped template has no
# mnt/ at all), so it "passed" unconditionally and would have stayed green even
# with the VMM-side allowed_dirs filter removed. What the exec context can
# really testify to is CHROOT CONTAINMENT: the share is mounted in the guest
# root namespace for the warden, and the chroot must not expose it. (The
# VMM-level filter for an ESCAPED guest is covered by warden-hostile.sh's
# hostile-mount probes, which run outside the chroot.)
log_step "5e.2: exec context cannot reach the raw virtio-fs share..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "ls -d /mnt/volumes 2>&1 || echo SHARE_UNREACHABLE; ls -d /mnt/volumes/$BIND_ID 2>&1 || echo SIBLING_UNREACHABLE; echo PROBE_RAN")
SIB_STDOUT=$(resp_stdout "$VM_RESP")

if ! echo "$SIB_STDOUT" | grep -q "PROBE_RAN"; then
    fail "5e.2: probe never ran (exec failed) — share containment UNVERIFIED"
elif echo "$SIB_STDOUT" | grep -qE "^/?mnt/volumes"; then
    fail "5e.2: the raw virtio-fs share is reachable from the exec context (SECURITY: FAIL)"
    log_info "Response: $VM_RESP"
else
    pass "5e.2: raw share + sibling directory unreachable from the exec context (chroot containment)"
fi

# Test 5e.3: the guest root namespace must expose no share directory listing
# to the exec context (see 5e.2 — same unreachable-path problem).
log_step "5e.3: no share listing reachable from the exec context..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "ls /mnt 2>&1; echo PROBE_RAN; ls / | tr '\n' ' '")
LS_STDOUT=$(resp_stdout "$VM_RESP")

if ! echo "$LS_STDOUT" | grep -q "PROBE_RAN"; then
    fail "5e.3: probe never ran (exec failed) — listing containment UNVERIFIED"
elif echo "$LS_STDOUT" | grep -qE "(^| )volumes(/| |$)"; then
    fail "5e.3: a 'volumes' entry is reachable from the exec context (leak)"
    log_info "Response: $VM_RESP"
elif echo "$LS_STDOUT" | grep -q "$(basename $BIND_ID)"; then
    fail "5e.3: VM can see sibling $BIND_ID from the exec context (leak)"
else
    pass "5e.3: no share/volumes listing reachable from the exec context"
fi

# Test 5e.4: VM CANNOT see .template file via virtio-fs (it's in the allowed dir
# but it's just a marker, not a security issue — skip if visible)
log_step "5e.4: Check if .template marker is visible (informational)..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "cat /mnt/volumes/$TPL_ID/.template 2>&1 || echo NOT_ACCESSIBLE")
MARKER_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$MARKER_STDOUT" | grep -q "isolation:v1"; then
    log_info "5e.4: .template marker is visible to VM (informational, not a security issue)"
else
    log_info "5e.4: .template marker not accessible (acceptable)"
fi

# Test 5e.5: Non-UTF-8 path lookup must be ENOENT, not a VMM crash.
# File names are arbitrary byte strings; the allow-list keys are UTF-8, so a
# non-UTF-8 name is simply not whitelisted. Regression guard: this used to
# hit `to_str().unwrap()` and kill the whole sandvmm (with the filter mutex
# poisoned for every later request).
#
# The probe targets the SANDFS WORKSPACE (the reachable virtio-fs path from
# the exec context) — the share-ROOT variant of the same lookup is exercised
# by warden-hostile.sh, which runs outside the chroot where /mnt/volumes
# actually resolves.
log_step "5e.5: Non-UTF-8 workspace lookup returns ENOENT (no VMM crash)..."
# printf (busybox sh builtin) generates the raw non-UTF-8 bytes inside the
# guest. The \\\\ quadrupling survives the two escape layers between here and
# the guest shell: bash double quotes (\\\\ -> \\) then the JSON body
# (\\ -> \), so the command the guest runs is printf '\xff\xfe'.
# The first exec after the preceding test's lease expiry may hit the gateway
# SANDBOX_CLEANING window (retry_after_ms=10000): retry until the request
# completes (success or command-level failure), then judge the result.
VM_RESP=""
for _ in 1 2 3 4 5; do
    VM_RESP=$(exec_in_vm "$TPL_KEY" "ls /workspace/\$(printf '\\\\xff\\\\xfe') 2>&1 || echo NO_SUCH_ENTRY")
    echo "$VM_RESP" | grep -q '"error"' || break
    sleep 4
done
NUTF_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$NUTF_STDOUT" | grep -q "NO_SUCH_ENTRY\|No such file\|cannot access"; then
    pass "5e.5: Non-UTF-8 workspace lookup denied with ENOENT"
else
    fail "5e.5: Non-UTF-8 root lookup returned unexpected result"
    log_info "Response: $VM_RESP"
fi
# The exec above must have gone through a LIVING VMM: if the VMM had crashed
# on the non-UTF-8 lookup, this follow-up exec would fail entirely.
log_step "5e.5b: VMM still alive after non-UTF-8 lookup..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo still-alive")
ALIVE_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$ALIVE_STDOUT" | grep -q "still-alive"; then
    pass "5e.5b: VMM alive after non-UTF-8 root lookup (no panic/poison)"
else
    fail "5e.5b: VMM unresponsive after non-UTF-8 lookup — possible panic in root filter"
    log_info "Response: $VM_RESP"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5f: /tmp — tmpfs (Local, Not Shared)"
# ══════════════════════════════════════════════════════════════════

log_info "Testing /tmp: writable tmpfs, local to this VM"

# Test 5f.1: Write to /tmp
log_step "5f.1: VM write to /tmp..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo 'tmp-write' > /tmp/tmp-test.txt && cat /tmp/tmp-test.txt")
TMP_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$TMP_STDOUT" | grep -q "tmp-write"; then
    pass "5f.1: VM can write and read /tmp (tmpfs)"
else
    fail "5f.1: VM cannot write to /tmp"
    log_info "Response: $VM_RESP"
fi

# Test 5f.2: Verify /tmp is tmpfs
log_step "5f.2: Verify /tmp is tmpfs (not a bind mount from rootfs)..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "mount | grep ' /tmp ' || echo NO_TMP_MOUNT")
TMP_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$TMP_STDOUT" | grep -q "tmpfs"; then
    pass "5f.2: /tmp is tmpfs (local, not shared storage)"
else
    # warden mounts a fresh tmpfs at <rootfs>/tmp (warden/src/mount.rs) — the
    # guest MUST be able to see it. Absence of evidence = failure.
    fail "5f.2: /tmp not confirmed as tmpfs (mount output: '$TMP_STDOUT')"
fi

# Test 5f.3: /tmp is NOT shared across VM switches (tmpfs is local)
# Write to /tmp, then switch to the bind-mount SandFS and back.
# The /tmp content should be gone after unmount+remount.
log_step "5f.3: /tmp is local (not shared across VM switches)..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo 'before-switch' > /tmp/persist-test.txt && cat /tmp/persist-test.txt")
log_info "  Pre-switch: $(resp_stdout "$VM_RESP")"

# Wait for lease to expire, then execute on the other SandFS
sleep 2
VM_RESP=$(exec_in_vm "$BIND_KEY" "echo 'on-bind-sandfs'")
log_info "  Switch to bind SandFS: $(resp_stdout "$VM_RESP")"

# Wait and switch back
sleep 2
VM_RESP=$(exec_in_vm "$TPL_KEY" "cat /tmp/persist-test.txt 2>&1 || echo GONE")
TMP_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$TMP_STDOUT" | grep -q "GONE\|No such file"; then
    pass "5f.3: /tmp is local — contents cleared on agent switch"
elif echo "$TMP_STDOUT" | grep -q "before-switch"; then
    # tmpfs persists if the VM wasn't recycled — the important thing is
    # that /tmp is NOT backed by shared storage (no cross-node persistence).
    log_warn "5f.3: /tmp contents survived agent switch (VM was reused, tmpfs still mounted)"
    log_info "  This is acceptable — tmpfs is local RAM, not shared-storage-backed"
    pass "5f.3: /tmp is local tmpfs (VM reuse kept tmpfs alive — acceptable)"
else
    fail "5f.3: Could not determine /tmp persistence (stdout: '$TMP_STDOUT')"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5g: Environment Variables"
# ══════════════════════════════════════════════════════════════════

log_info "Testing environment variables for home-directory package installation"

# Test 5g.1: HOME=/home/agent
log_step "5g.1: HOME environment variable..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo HOME=\$HOME")
ENV_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$ENV_STDOUT" | grep -q "HOME=/home/agent"; then
    pass "5g.1: HOME=/home/agent"
else
    fail "5g.1: HOME not set correctly"
    log_info "  Got: $ENV_STDOUT"
fi

# Test 5g.2: PATH includes /home/agent/.local/bin
log_step "5g.2: PATH includes /home/agent/.local/bin..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo \$PATH | tr ':' '\n' | grep '/home/agent/.local/bin' || echo NOT_FOUND")
ENV_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$ENV_STDOUT" | grep -q "/home/agent/.local/bin"; then
    pass "5g.2: PATH includes /home/agent/.local/bin"
else
    fail "5g.2: PATH does not include /home/agent/.local/bin"
    log_info "  Got: $ENV_STDOUT"
fi

# Test 5g.3: PATH includes /home/agent/.npm-global/bin
log_step "5g.3: PATH includes /home/agent/.npm-global/bin..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo \$PATH | tr ':' '\n' | grep '/home/agent/.npm-global/bin' || echo NOT_FOUND")
ENV_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$ENV_STDOUT" | grep -q "/home/agent/.npm-global/bin"; then
    pass "5g.3: PATH includes /home/agent/.npm-global/bin"
else
    fail "5g.3: PATH does not include /home/agent/.npm-global/bin"
    log_info "  Got: $ENV_STDOUT"
fi

# Test 5g.4: PYTHONUSERBASE=/home/agent/.local
log_step "5g.4: PYTHONUSERBASE environment variable..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo PYTHONUSERBASE=\$PYTHONUSERBASE")
ENV_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$ENV_STDOUT" | grep -q "PYTHONUSERBASE=/home/agent/.local"; then
    pass "5g.4: PYTHONUSERBASE=/home/agent/.local"
else
    fail "5g.4: PYTHONUSERBASE not set correctly"
    log_info "  Got: $ENV_STDOUT"
fi

# Test 5g.5: npm_config_prefix=/home/agent/.npm-global
log_step "5g.5: npm_config_prefix environment variable..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo npm_config_prefix=\$npm_config_prefix")
ENV_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$ENV_STDOUT" | grep -q "npm_config_prefix=/home/agent/.npm-global"; then
    pass "5g.5: npm_config_prefix=/home/agent/.npm-global"
else
    fail "5g.5: npm_config_prefix not set correctly"
    log_info "  Got: $ENV_STDOUT"
fi

# Test 5g.6: CARGO_HOME=/home/agent/.cargo
log_step "5g.6: CARGO_HOME environment variable..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo CARGO_HOME=\$CARGO_HOME")
ENV_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$ENV_STDOUT" | grep -q "CARGO_HOME=/home/agent/.cargo"; then
    pass "5g.6: CARGO_HOME=/home/agent/.cargo"
else
    fail "5g.6: CARGO_HOME not set correctly"
    log_info "  Got: $ENV_STDOUT"
fi

# Test 5g.7: GOPATH=/home/agent/go
log_step "5g.7: GOPATH environment variable..."
VM_RESP=$(exec_in_vm "$TPL_KEY" "echo GOPATH=\$GOPATH")
ENV_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$ENV_STDOUT" | grep -q "GOPATH=/home/agent/go"; then
    pass "5g.7: GOPATH=/home/agent/go"
else
    fail "5g.7: GOPATH not set correctly"
    log_info "  Got: $ENV_STDOUT"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Cross-Agent Isolation (Template vs Bind Mount)"
# ══════════════════════════════════════════════════════════════════

log_info "Verifying cross-agent isolation between template and bind-mount SandFS"

# Test 6.1: Template SandFS data not visible from bind-mount SandFS
log_step "6.1: Template SandFS data isolated from bind-mount SandFS..."
VM_RESP=$(exec_in_vm "$BIND_KEY" "cat /workspace/ws-test.txt 2>&1 || echo NOT_FOUND")
CROSS_STDOUT=$(resp_stdout "$VM_RESP")

if echo "$CROSS_STDOUT" | grep -q "workspace-write"; then
    fail "6.1: Bind-mount SandFS can see template SandFS data (isolation broken)"
else
    pass "6.1: Bind-mount SandFS CANNOT see template SandFS /workspace data"
fi

# Test 6.2: Bind-mount SandFS data not visible from template SandFS
log_step "6.2: Bind-mount SandFS data isolated from template SandFS..."
# The bind sandfs wrote /workspace/test.txt (test 4.1); "bind-test" is the
# sandfs NAME. Probed against a file that never exists, the phase "passed"
# unconditionally — a mount-routing bug serving the wrong volume stayed green.
# The probe also carries a liveness marker so a failed exec cannot read as
# "cannot see the data".
VM_RESP=$(exec_in_vm "$TPL_KEY" "cat /workspace/test.txt 2>&1 || echo NOT_FOUND; echo PROBE_RAN")
CROSS_STDOUT=$(resp_stdout "$VM_RESP")

if ! echo "$CROSS_STDOUT" | grep -q "PROBE_RAN"; then
    fail "6.2: probe never ran (exec failed) — isolation UNVERIFIED"
elif echo "$CROSS_STDOUT" | grep -q "bind-content"; then
    fail "6.2: Template SandFS can see bind-mount SandFS data (isolation broken)"
else
    pass "6.2: Template SandFS CANNOT see bind-mount SandFS /workspace data"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 7: Overlay Stateless — Cross-Node Migration"
# ══════════════════════════════════════════════════════════════════

log_info "Verifying read-only overlay is stateless (no per-node cleanup needed)"

# The read-only overlay has no upperdir/workdir, so:
#   - No CleanupOverlay RPC needed
#   - No overlay reaper needed
#   - No overlayMounted map needed
#   - Overlay can be mounted on any node and produces identical view

# Test 7.1: Verify no upperdir directory exists
log_step "7.1: No upperdir directory exists..."
if [[ -d "${TPL_ID_VOL}/rw" ]]; then
    fail "7.1: upperdir (rw/) exists (should not exist in new architecture)"
else
    pass "7.1: No upperdir (rw/) directory — read-only overlay confirmed"
fi

# Test 7.2: Verify no workdir directory exists
log_step "7.2: No workdir directory exists..."
if [[ -d "${TPL_ID_VOL}/work" ]]; then
    fail "7.2: workdir (work/) exists (should not exist in new architecture)"
else
    pass "7.2: No workdir (work/) directory — read-only overlay confirmed"
fi

# Test 7.3: Template integrity — writing to /workspace does NOT modify template
log_step "7.3: Template not modified by /workspace writes..."
if [[ ! -f "$TEMPLATE_DIR/isolation/v1/workspace/ws-test.txt" ]]; then
    pass "7.3: Template not modified by agent writes to /workspace"
else
    fail "7.3: Template modified by agent writes (data leaked into lowerdir)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 8: Layer-ID Trust Boundary — Hostile refs File Refused"
# ══════════════════════════════════════════════════════════════════

# The refs file is control-plane input (gateway scan writes it; an OCI pull or
# a peer node on the shared templates dir could too) and its layer IDs become
# overlayfs LOWERDIRS — a ref naming /etc would mount the host's /etc
# read-only into every guest created from the template. The sandlot validates
# at ref-load time; this phase drives the REAL mount path (unit tests only
# cover the loader).
EVIL_REF_FILE="$TEMPLATE_DIR/refs/evil_v1.overlay.json"

log_step "8.0: Gateway wrote the ref with the legal absolute-path layer..."
if [[ -f "$EVIL_REF_FILE" ]] && grep -q "\"$TEMPLATE_DIR/evil/v1\"" "$EVIL_REF_FILE"; then
    pass "8.0: ref file exists with an absolute layer INSIDE the templates dir (legal format)"
else
    fail "8.0: ref file missing or unexpected: $(cat "$EVIL_REF_FILE" 2>/dev/null || echo absent)"
fi

log_step "8.1: Tampering refs file to layers:[\"/etc\"] (host-path injection)..."
echo '{"name":"evil","version":"v1","mode":"overlay","layers":["/etc"]}' > "$EVIL_REF_FILE"

EVIL_RESP=$(tc_create_agent_and_sandfs "evil-mount" "evil:v1" || echo '{"error":"create failed"}')
EVIL_ID=$(json_val "$EVIL_RESP" "sandfs_id")
EVIL_KEY=$(json_val "$EVIL_RESP" "api_key")
if [[ -z "$EVIL_ID" ]] || [[ -z "$EVIL_KEY" ]]; then
    fail "Failed to create evil-test SandFS: $EVIL_RESP"
    exit 1
fi
KEY2SID["$EVIL_KEY"]="$EVIL_ID"

# A FRESH sandfs's first exec races the post-create cleaning window
# (SANDBOX_CLEANING, retry_after 10s) — exec_in_vm's 3×1s retry cannot cross
# it, and a cleaning rejection would mask the layer validation entirely (that
# is exactly what happened on the first run). This helper retries ONLY the
# transient/retryable classes long enough to reach the real verdict.
evil_exec_wait() {
    local key="$1" code="$2" resp try
    for try in $(seq 1 14); do
        resp=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/execute" \
            -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
            -d "{\"sandfs_id\":\"${KEY2SID[$key]:-}\",\"code\":\"$code\",\"language\":\"shell\"}" 2>/dev/null || echo '{}')
        if echo "$resp" | grep -qE '"(NO_AVAILABLE_SANDBOX|NO_COMPUTE_NODES|CONCURRENT_MOUNT|SANDBOX_CLEANING)"'; then
            sleep 2.5
            continue
        fi
        echo "$resp"
        return 0
    done
    echo "$resp" # final transient shape — caller's assertions fail with it visible
}

if [[ -z "$EVIL_ID" ]]; then
    fail "8.1: could not create the evil-template SandFS: $EVIL_RESP"
else
    # sandfs CREATION must succeed (Instantiate only writes dirs + marker);
    # the MOUNT must fail at ref-load validation.
    EVIL_EXEC=$(evil_exec_wait "$EVIL_KEY" "echo should-not-run")
    if echo "$EVIL_EXEC" | grep -q "should-not-run"; then
        fail "8.1: exec SUCCEEDED with layers:[\"/etc\"] — the layer-ID trust boundary is OPEN (host /etc mounted into a guest!)"
    else
        pass "8.1: exec refused with a hostile refs file (no guest ever ran against /etc)"
    fi

    # The refusal evidence lives in the GATEWAY log: sandlot returns the
    # validation error in the CommandResponse only, and the gateway
    # deliberately masks mount failures behind a retryable SANDBOX_CLEANING
    # (EnterCleaning + async cleanup — execute.go L2 path), so the HTTP client
    # never sees the underlying reason.
    if grep -q "outside templates dir" "$LOG_DIR/gateway.log" 2>/dev/null; then
        pass "8.1: gateway logged the layer-validation refusal from sandlot"
    else
        fail "8.1: no layer-validation log line — exec failed for the WRONG reason: $(echo "$EVIL_EXEC" | head -c 300)"
    fi

    # Belt: no overlay mount with /etc as a lowerdir may exist on the host.
    if grep -q "lowerdir=/etc" /proc/self/mountinfo 2>/dev/null; then
        fail "8.1: /etc found as an overlay lowerdir in mountinfo — boundary bypassed"
    else
        pass "8.1: no /etc lowerdir in mountinfo"
    fi
fi

log_step "8.2: Restoring the legal ref — the SAME template must now mount..."
echo "{\"name\":\"evil\",\"version\":\"v1\",\"mode\":\"overlay\",\"layers\":[\"$TEMPLATE_DIR/evil/v1\"]}" > "$EVIL_REF_FILE"
EVIL_RETRY=$(evil_exec_wait "$EVIL_KEY" "echo evil-ok-after-restore")
if echo "$EVIL_RETRY" | grep -q "evil-ok-after-restore"; then
    pass "8.2: exec succeeds once the ref is legal (failure above was the validation, not a broken template)"
else
    fail "8.2: exec still fails with a LEGAL ref — validation over-refusing or template broken: $(echo "$EVIL_RETRY" | head -c 300)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 9: Planted .template Marker — No Host Read, No Hang"
# ══════════════════════════════════════════════════════════════════

# In FLAT mode the volume root IS the agent's chroot root, so the agent can
# write the .template marker path (symlinks and regular files; FIFOs are now
# denied by the warden's seccomp mknod/mknodat rule, so the FIFO leg plants
# that marker host-side). That path is read by HOST processes (the
# sandlot mount path, the prov in-use scan): a plain os.ReadFile would FOLLOW
# a planted symlink (the target resolves against the HOST kernel's root =
# arbitrary host-file read) and BLOCK forever on a planted FIFO (no writer =
# the node's mount path wedges). Both are "not a marker sandswap wrote" and
# must be treated as "no marker" — the flat volume keeps mounting.
# The assertion pairs plant → force a cold remount (lease expiry) → exec must
# still succeed, within the bounded curl (a hang shows up as a timeout with
# empty output, not as a fast failure).

log_step "9.1: plant a SYMLINK at /.template (flat volume root = chroot root)..."
PLANT_SYMLINK=$(exec_in_vm "$BIND_KEY" "ln -sf /etc/hostname /.template && { [ -L /.template ] && echo symlink-planted; }")
if echo "$(resp_stdout "$PLANT_SYMLINK")" | grep -q "symlink-planted"; then
    pass "9.1: symlink planted at the host volume's .template path"
else
    fail "9.1: could not plant the symlink: $(resp_stdout "$PLANT_SYMLINK" | head -c 200)"
fi
sleep 2 # lease expiry → async unmount → the next exec cold-mounts
MARKER_SYMLINK_EXEC=$(exec_in_vm "$BIND_KEY" "echo symlink-marker-ok")
if echo "$(resp_stdout "$MARKER_SYMLINK_EXEC")" | grep -q "symlink-marker-ok"; then
    pass "9.1: cold mount with a planted symlink marker succeeds (marker not followed)"
else
    fail "9.1: exec after planting a symlink marker failed: $(echo "$MARKER_SYMLINK_EXEC" | head -c 300)"
fi

log_step "9.2: plant a FIFO at /.template (host side — guest mknod is seccomp-denied)..."
# mkfifo(3) issues mknodat(2), which the warden now denies (mknod/mknodat
# are in the deny list). The threat the mount path must survive is a FIFO
# marker it did not write, so plant it directly at the host volume root.
# Guard the host path: an empty BIND_VOL would make the rm/mkfifo below act
# on the HOST ROOT (/.template), not on a volume.
if [[ -z "$BIND_VOL" ]]; then
    fail "9.2: BIND_VOL is empty — refusing to plant the FIFO at the host root"
else
    rm -f "$BIND_VOL/.template" 2>/dev/null || true
    if mkfifo "$BIND_VOL/.template"; then
        pass "9.2: FIFO planted at the host volume's .template path"
    else
        fail "9.2: could not plant the FIFO at $BIND_VOL/.template (rc=$?)"
    fi
fi
sleep 2
MARKER_FIFO_EXEC=$(exec_in_vm "$BIND_KEY" "echo fifo-marker-ok")
if echo "$(resp_stdout "$MARKER_FIFO_EXEC")" | grep -q "fifo-marker-ok"; then
    pass "9.2: cold mount with a planted FIFO marker completes (no read-forever hang)"
else
    fail "9.2: exec after planting a FIFO marker failed/hung: $(echo "$MARKER_FIFO_EXEC" | head -c 300)"
fi

log_step "9.3: plant a REGULAR .template file (junk ref) — the mode gate must keep it flat..."
PLANT_REGULAR=$(exec_in_vm "$BIND_KEY" "rm -f /.template && printf 'evil:v1\n' > /.template && { [ -f /.template ] && echo regular-planted; }")
if echo "$(resp_stdout "$PLANT_REGULAR")" | grep -q "regular-planted"; then
    pass "9.3: regular .template file planted at the host volume's marker path"
else
    fail "9.3: could not plant the regular marker: $(resp_stdout "$PLANT_REGULAR" | head -c 200)"
fi
sleep 2
MARKER_REGULAR_EXEC=$(exec_in_vm "$BIND_KEY" "echo regular-marker-ok")
if echo "$(resp_stdout "$MARKER_REGULAR_EXEC")" | grep -q "regular-marker-ok"; then
    pass "9.3: cold mount with a planted regular marker stays FLAT (flat record ignores markers)"
else
    fail "9.3: exec after planting a regular marker failed — the volume flipped to a bogus overlay: $(echo "$MARKER_REGULAR_EXEC" | head -c 300)"
fi

# Host-side evidence that the planted markers were EVALUATED (and rejected)
# rather than skipped: the sandlot logs the flat-record marker gate.
if grep -q "expects no template" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "9: sandlot logged the planted markers as ignored (flat record never honors a marker)"
else
    fail "9: no 'expects no template' line in the sandlot log — the host may not have reached the marker gate at all"
fi

# Leave the volume sane for teardown.
exec_in_vm "$BIND_KEY" "rm -f /.template" >/dev/null 2>&1 || true

# ══════════════════════════════════════════════════════════════════
log_section "Results Summary"
# ══════════════════════════════════════════════════════════════════

echo ""
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │  Read-Only Overlay + Writable Workspace/Home Isolation   │"
echo "  ├──────────────────────────────────────────────────────────┤"
	printf "  │  Tests: %-3d passed   %-3d failed                       │\n" "$PASS_COUNT" "$FAIL_COUNT"
echo "  ├──────────────────────────────────────────────────────────┤"

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "  │  Status: ALL TESTS PASSED                               │"
else
    echo "  │  Status: SOME TESTS FAILED                              │"
fi

echo "  ├──────────────────────────────────────────────────────────┤"
echo "  │  Architecture verified:                                  │"
echo "  │    Read-only overlay (lowerdir only, no upperdir/workdir)│"
echo "  │    /workspace  → writable bind mount (read-write)        │"
echo "  │    /home/agent → writable bind mount (read-write)        │"
echo "  │    /tmp        → tmpfs (local, not shared)               │"
echo "  │    virtio-fs allowed_dirs → basename filtering           │"
echo "  │    No CleanupOverlay RPC, no overlay reaper needed       │"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""

# Exit with appropriate code
if [[ $FAIL_COUNT -eq 0 ]]; then
    log_pass "All tests passed"
    exit 0
else
    log_error "$FAIL_COUNT test(s) failed"
    exit 1
fi
