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
# single-node-multi-agent.sh — self-contained single-node (MemoryStore,
# background-process) stack + the eino multi-agent acceptance test (VM reuse,
# cross-agent isolation). Deploy-tree libraries via $ROOT; the e2e battery
# runs it with the kvm+llm tags.
# The STACK is not hand-rolled here: deploy-single-node.sh owns it (systemd
# units, MemoryStore gateway, merged exec,prov sandlot, TLS, pool wait) — the
# same delegation shape as deploy-egress-enabler.sh. This script adds exactly
# the multi-agent part on top:
#   1. Delegates the deployment (flags pass through; --pool small:2 default)
#   2. Swaps the busybox rootfs:v1 template for the Ubuntu one (the eino
#      test's agents need a real userland; hot rescan, no restart)
#   3. Creates 4 agents + 4 sandfs via /human API, runs the eino multi-agent
#      piped test, verifies VM reuse and cross-agent isolation
# Embedded mode: 1 gateway, 1 sandlot, 2 VMs in pool. No etcd, no Kubernetes.
# Shared phases (waits/agents/eino/analyze/honest-exit) live in deploy-lib.sh.
# Prerequisites:
#   - KVM available (/dev/kvm)
#   - Root access
#   - DEEPSEEK_API_KEY or OPENAI_API_KEY set
# Usage:
#   sudo DEEPSEEK_API_KEY=sk-xxx bash e2e/single-node-multi-agent.sh
#   sudo DEEPSEEK_API_KEY=sk-xxx bash e2e/single-node-multi-agent.sh --skip-build
#   sudo DEEPSEEK_API_KEY=sk-xxx bash e2e/single-node-multi-agent.sh --no-tls
#   (--no-tls: plaintext HTTP listeners; the node stream always carries mTLS)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/deploy/baremetal/common.sh"
source "$ROOT/deploy/baremetal/deploy-lib.sh"

# ── Configuration ──────────────────────────────────────────────────

DEPLOY_DIR="${DEPLOY_DIR:-/var/lib/sandswap}"
VOL_ROOT="${VOL_ROOT:-/var/lib/sandswap/volumes}"
# The deploy-tree libraries hard-bind SANDSWAP_VAR to the production root at
# source time. This row deploys into $DEPLOY_DIR (the e2e root under the
# matrix), and sandswap_apply_prov_plane provisions whatever SANDSWAP_VAR
# names — the gateway's state/ directory included. Left unbound, the prov
# plane provisions the production root while the gateway reads $DEPLOY_DIR,
# and the gateway dies EACCES creating its identity-store directory unless a
# sibling row happened to leave state/ behind. Bind the two roots together.
export SANDSWAP_VAR="$DEPLOY_DIR"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
AGENT_COUNT=4
POOL_SIZE=2
# Pool spec name (built-in table: small=2vCPU/256MB/3 slots, medium=4vCPU/1GB).
# Default small — a medium pool of 2 VMs reserves 2 GB guest RAM, which small
# development hosts don't have; override with POOL_SPEC=medium for big hosts.
POOL_SPEC="${POOL_SPEC:-small}"
SKIP_BUILD=false
NO_TLS=false
KEEP_ON_EXIT=false
# Total wall-clock budget (seconds) for the entire eino piped test to complete —
# NOT a per-command or per-LLM-call timeout. Covers piped prompt sleeps (140s
# fixed) + all DeepSeek LLM round-trips (2 per prompt × 8 prompts). Slow LLM
# environments need the higher default; the sandbox exec itself is sub-second.
EINO_TEST_BUDGET_SECS="${EINO_TEST_BUDGET_SECS:-900}"

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --no-tls)     NO_TLS=true ;;
        --keep)       KEEP_ON_EXIT=true ;;
        *) log_warn "unknown flag: $arg" ;;
    esac
done

# Protocol for agent/human API requests. The node stream ALWAYS carries
# certificates: the gateway refuses a certificate-less stream (the listener
# requires a client cert and binds its CN to the hello's node_id), so
# --no-tls makes only the HTTP listeners plaintext — certificates are still
# minted per node and wired to the gateway's stream listener + the sandlot.
if [[ "$NO_TLS" == "true" ]]; then
    PROTO="http"
else
    PROTO="https"
fi
CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
# CA for the HTTP listeners only — the stream's mTLS verification never
# depends on this script's HTTP scheme.
CA_CERT_ARG=""
[[ "$NO_TLS" != "true" ]] && CA_CERT_ARG="$CERT_DIR/ca.crt"

if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
    LLM_BACKEND="deepseek"
elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
    LLM_BACKEND="openai"
else
    LLM_BACKEND="gemini"
fi

# Preflight context: this script REQUIRES an LLM key (the 4-agent model test is
# part of what "deployed and verified" means here). BM_* are cross-file globals
# consumed by deploy-lib.sh functions in this shell (invisible to shellcheck).
# shellcheck disable=SC2034
BM_MODE_DESC="baremetal embedded (single-node gateway+sandlot, no etcd, HTTP TLS=$([[ $NO_TLS == true ]] && echo off || echo on), stream mTLS always)"
# shellcheck disable=SC2034
BM_REQUIRE_LLM=1
# shellcheck disable=SC2034
BM_WIPE_RUN=1

# ── Clean previous deployment ────────────────────────────────────────
log_step "Cleaning previous deployment..."
bash "$ROOT/deploy/baremetal/cleanup.sh"

# Track PIDs for cleanup
GATEWAY_PID=""
SANDLOT_PID=""

cleanup() {
    log_step "Cleaning up..."
    for pid in $GATEWAY_PID $SANDLOT_PID; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    tc_kill_sandswap_procs "trap-cleanup"
    if [[ "$KEEP_ON_EXIT" != "true" ]]; then
        bash "$ROOT/deploy/baremetal/cleanup.sh"
    else
        log_info "Processes and state preserved (--keep)"
    fi
    log_pass "Cleanup done"
}
bm_traps cleanup

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Preflight + Build"
# ══════════════════════════════════════════════════════════════════

bm_preflight

if [[ "$SKIP_BUILD" == "false" ]]; then
    log_step "Building all artifacts..."
    bm_build_artifacts 2>&1 | tail -5
    log_pass "All artifacts built"
else
    log_info "Skipping build (--skip-build)"
fi

tc_check_artifacts
if [[ "$SKIP_BUILD" == "true" ]]; then
    ss_verify_kernel_artifact "$ROOT/output/vmlinux.bin" "$ROOT/kernel/build.sh" \
        || { log_error "Refusing --skip-build with a non-pinned kernel under output/ — run bash build/build.sh kernel"; exit 1; }
fi

# Ubuntu rootfs — build automatically if missing
ROOTFS_UBUNTU="${ROOTFS_UBUNTU:-$OUTPUT/rootfs-ubuntu}"
if [[ ! -d "$ROOTFS_UBUNTU" ]] || [[ ! -d "$ROOTFS_UBUNTU/bin" ]]; then
    log_warn "Ubuntu rootfs template not found — building automatically..."
    bash "$ROOT/build/build-ubuntu-rootfs.sh"
    log_pass "Ubuntu rootfs template built"
fi
log_pass "Ubuntu rootfs template present: $ROOTFS_UBUNTU/"

tc_check_tools curl python3

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Host Preparation"
# ══════════════════════════════════════════════════════════════════

log_step "Deploying artifacts to $DEPLOY_DIR ..."
tc_deploy_artifacts

# Replace busybox rootfs with Ubuntu rootfs
log_step "Deploying Ubuntu rootfs template (replacing default busybox)..."
rm -rf "$DEPLOY_DIR/flat-templates/rootfs/v1"
mkdir -p "$DEPLOY_DIR/flat-templates/rootfs/v1"
cp -a "$ROOTFS_UBUNTU/." "$DEPLOY_DIR/flat-templates/rootfs/v1/"
# Template must be readable by the SEED identity (prov); the ubuntu-base tree
# carries 0000-mode oddballs (/etc/.pwd.lock) only root could read → seeding
# would EACCES. Normalize to the template contract through the shared group
# (docs/operations/template-contract.md) with the canonical tool — the old
# `chmod -R a+rX` widened to world-readable instead of the group grant.
TEMPLATE_TOOL="$ROOT/output/template-tool"
[[ -x "$TEMPLATE_TOOL" ]] || { log_error "output/template-tool missing — run: bash build/build.sh go"; exit 1; }
chgrp -R "$SS_SHARED_GROUP" "$DEPLOY_DIR/flat-templates"
"$TEMPLATE_TOOL" normalize "$DEPLOY_DIR/flat-templates"
if [[ ! -d "$DEPLOY_DIR/flat-templates/rootfs/v1/bin" ]]; then
    log_error "Ubuntu rootfs-template directory copy failed"
    exit 1
fi
log_pass "Ubuntu rootfs template deployed ($(du -sh "$DEPLOY_DIR/flat-templates/rootfs/v1" | cut -f1))"

ss_prepare_dirs   # /run/sandswap (3770 root:<shared>, sticky) + the shared roots
chmod a+r "$DEPLOY_DIR/vmlinux.bin" "$DEPLOY_DIR/initramfs.cpio.gz" 2>/dev/null || true

# Host security sysctls — single shared implementation (common.sh), which
# writes perf_event_paranoid only when the running value is below the floor.
sandswap_install_sysctls

# Host bridge for microVM outbound networking
log_step "Setting up host network bridge..."
if bash "$ROOT/deploy/setup-network.sh" 2>&1; then
    log_pass "Host network bridge ready"
else
    log_error "Host network bridge setup failed — refusing to deploy without the guest egress guard"
    exit 1
fi

# Host security check (best-effort)
log_step "Checking host security invariants..."
if [[ -x "$ROOT/security/verify-host-security.sh" ]]; then
    if bash "$ROOT/security/verify-host-security.sh" >/dev/null 2>&1; then
        log_pass "Host security invariants verified"
    else
        log_warn "Host security invariants NOT met — vsockguard may not be active"
        log_warn "  Harden: sudo bash security/setup-bpf-lsm.sh (enables bpf LSM; reboot) + sudo bash deploy/baremetal/setup-host.sh --role all"
    fi
else
    log_info "verify-host-security.sh not found — skipping host security check"
fi

tc_ensure_dev_nodes

# Attach vsockguard pinned to the sandlot service identity (the only local
# user allowed to reach the warden vsock port). tc_attach_vsockguard's
# default resolves the sandlot uid from the dedicated-identity model.
tc_attach_vsockguard

log_pass "Host preparation complete"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Generate TLS Certificates"
# ══════════════════════════════════════════════════════════════════

if [[ "$NO_TLS" == "true" ]]; then
    log_info "HTTP listeners will be plaintext (--no-tls); the node stream still uses mTLS"
fi
log_step "Generating TLS certificates (stream mTLS is mandatory — the gateway refuses certificate-less streams)..."
mkdir -p "$CERT_DIR"
# SANDLOT_NODE_ID IS the node id this sandlot declares (below: "node-1"):
# the gateway binds the stream hello's node_id to the client certificate's
# CN by exact match, so the pair minted here has CN=node-1. Change one of
# the two and the sandlot is refused at the handshake (by name).
SANDLOT_NODE_ID=node-1 \
    bash "$ROOT/deploy/baremetal/gen-baremetal-certs.sh" "$CERT_DIR" \
        --client-roles exec,prov
ss_own_tls_keys "$CERT_DIR"
# The minted CN must be the node id the config below declares — assert it
# here (the gateway refuses a mismatched pair by name at the handshake).
sandswap_verify_client_cert_cn "$CERT_DIR/sandlot.crt" node-1 \
    || { log_error "stream client cert does not carry the node id this sandlot declares (node-1)"; exit 1; }
log_pass "TLS certificates generated in $CERT_DIR (keys scoped per service identity)"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Start Services"
# ══════════════════════════════════════════════════════════════════

# Dedicated-identity model (same privilege shape as the systemd units):
# services run as non-root via ss_service_exec (setpriv exec — the recorded
# PID IS the service). This script itself stays root ONLY for host prep
# (bridge, sysctl, udev, vsockguard) which the service identities must not
# need.
ss_ensure_service_users
ss_prepare_dirs
# THE prov-side contract for this merged background shape, in ONE call —
# BEFORE any service starts (the gateway dies EACCES on the identity-store
# lock if the state-dir ownership lands late; the sandlot refuses to start
# without the seed): seed mint + template store + volumes root + state-dir
# ownership (sandswap_apply_prov_plane), then persist the shape for the units.
SS_PROV_USER=sandlot sandswap_write_prov_user_env
sandswap_apply_prov_plane
mkdir -p "$LOG_DIR"

GW_ARGS=(
    -agent-addr :3000
    # Anonymous control plane: loopback only (reach it through an SSH tunnel,
    # or configure authn.issuer). Exposing it on a LAN address requires both
    # -allow-anonymous-human and -allow-anonymous-human-public.
    -human-addr 127.0.0.1:3100
    -stream-addr :9998
    -vol-root "$VOL_ROOT"
    # H-03: the state root is root-owned; the gateway's identity store lives
    # in the gateway-owned state/ subdirectory.
    -identity-store "$DEPLOY_DIR/state/identity-store.json"
    -sticky-ms 100
    -max-sticky-sec 5
    -default-exec-timeout-sec 30
    -max-exec-timeout-sec 180
    # The human listener carries no OIDC issuer in this dev deploy shape; the
    # explicit opt-out is required (the shipped systemd unit passes the same
    # flag), otherwise the gateway refuses to start the human listener.
    -allow-anonymous-human
    # NB: no -flat-templates here — that flag moved to the sandlot (prov role)
    # with the storage split; the gateway mounts no storage and rejects the
    # unknown flag with a usage-exit.
)
# The stream listener ALWAYS gets certificates — a certificate-less stream is
# refused at the handshake, so --no-tls never removes these. Only the HTTP
# listeners (agent/human) follow --no-tls.
GW_ARGS+=(
    -stream-tls-cert "$CERT_DIR/stream.crt"
    -stream-tls-key "$CERT_DIR/stream.key"
    -stream-tls-ca "$CERT_DIR/ca.crt"
)
if [[ "$NO_TLS" != "true" ]]; then
    GW_ARGS+=(
        -agent-tls-cert "$CERT_DIR/mcp.crt"
        -agent-tls-key "$CERT_DIR/mcp.key"
        -human-tls-cert "$CERT_DIR/admin.crt"
        -human-tls-key "$CERT_DIR/admin.key"
    )
fi

log_step "Starting gateway (single-node mode, user=sandserv)..."
ss_service_exec sandserv -- "$DEPLOY_DIR/gateway" "${GW_ARGS[@]}" \
    > "$LOG_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
log_info "Gateway PID: $GATEWAY_PID"

log_step "Waiting for gateway to start..."
GW_READY=false
for _ in $(seq 1 30); do
    if ss -tlnp 2>/dev/null | grep -q ":9998 "; then
        GW_READY=true
        break
    fi
    if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
        log_error "Gateway process died unexpectedly"
        tail -30 "$LOG_DIR/gateway.log" 2>/dev/null || true
        exit 1
    fi
    sleep 1
done
if [[ "$GW_READY" != "true" ]]; then
    log_error "Gateway not listening after 30s"
    tail -30 "$LOG_DIR/gateway.log" 2>/dev/null || true
    exit 1
fi
log_pass "Gateway listening on :3000 ($PROTO), :3100 ($PROTO), :9998 (gRPC)"


# Merged exec,prov roles: this is a single-node deployment (MemoryStore
# gateway) — the ONE sandlot is both the exec node and the storage plane.
# Without "prov" every sandfs/template op would 503 (the gateway holds no
# storage of its own). The template store defaults to the volumes-dir sibling.
# SC2054: the commas are flag VALUES, not element separators — -roles takes a
# CSV (exec,prov) and -network-dns a comma-joined resolver list.
# shellcheck disable=SC2054
# Config-FILE mode (not flags): the prov half carries the volume-name seed, and
# a rotation opens its window by EDITING this file — a flag-only instance has
# nothing for the hot-reload watcher to watch and cannot be staged (the sandlot
# warns about exactly that at startup). The seed itself never travels on argv:
# the file names its PATH (world-readable argv would leak the value).
SANDLOT_CONFIG="${SANDSWAP_ETC}/sandlot.yaml"
SANDSWAP_SANDLOT_ROLES="exec,prov" \
SANDSWAP_DEFAULT_VCPUS=2 \
SANDSWAP_DEFAULT_MEMORY_MB=256 \
SANDSWAP_VOLUME_SEED_FILE="${SANDSWAP_VOLUME_SEED_FILE:-${SANDSWAP_ETC}/volume-seed}" \
SANDSWAP_PROVISION_TEMPLATES_DIR="$(dirname "$VOL_ROOT")/templates" \
SANDSWAP_FLAT_TEMPLATES_DIR="$DEPLOY_DIR/flat-templates" \
    sandswap_generate_sandlot_config "$SANDLOT_CONFIG" "localhost:9998" "node-1" \
        "$POOL_SPEC:$POOL_SIZE" "10.188.0.0/16" "10.188.0.1" "$VOL_ROOT" \
        "$CERT_DIR"
# Same scoping as the other generated configs: the provision block may name the
# seed path (not a secret) and the file is read by the sandlot identity.
ss_protect_config "$SANDLOT_CONFIG" sandlot 2>/dev/null || true

SL_ARGS=(-config "$SANDLOT_CONFIG")
# This drill runs under the e2e battery root (SANDSWAP_E2E_ROOT/volumes),
# which is an ordinary directory on /, not the hardened storage mount a
# production deploy requires. The e2e tree's sandlot launcher admits that
# explicitly; this row must do the same or the sandlot refuses to start
# (invariant 8).
SL_ARGS+=(-allow-insecure-volumes)
# The vmlinux/initramfs/vmm binary live in DEPLOY_DIR here, not in the generic
# generator's ${SANDSWAP_VAR} layout — flags override the file (documented
# precedence) and are the one thing a rotation never edits.
SL_ARGS+=(
    -vmm-binary "$DEPLOY_DIR/sandvmm"
    -kernel "$DEPLOY_DIR/vmlinux.bin"
    -initramfs "$DEPLOY_DIR/initramfs.cpio.gz"
)

log_step "Starting sandlot (config-file mode: rotatable; embedded mode, user=sandlot + kubelet caps, pool=$POOL_SPEC:$POOL_SIZE)..."
ss_service_exec sandlot -- "$DEPLOY_DIR/sandlot" "${SL_ARGS[@]}" \
    > "$LOG_DIR/sandlot-1.log" 2>&1 &
SANDLOT_PID=$!
log_info "Sandlot PID: $SANDLOT_PID"

sleep 2
if ! kill -0 "$SANDLOT_PID" 2>/dev/null; then
    log_error "Sandlot process died unexpectedly"
    tail -30 "$LOG_DIR/sandlot-1.log" 2>/dev/null || true
    exit 1
fi
log_pass "Sandlot started"

if ! bm_wait_http "${PROTO}://localhost:3000/health" 30; then
    log_error "Gateway health check failed after 60s"
    tail -30 "$LOG_DIR/gateway.log" 2>/dev/null || true
    exit 1
fi
log_pass "Gateway healthy"

log_step "Waiting for sandlot pool to be ready (need $POOL_SIZE CLEAN VMs)..."
if ! CLEAN="$(bm_wait_pool "${PROTO}://localhost:3100/stats" "$POOL_SIZE" 120)"; then
    log_error "Pool not ready after 360s (need $POOL_SIZE)"
    tail -30 "$LOG_DIR/sandlot-1.log" 2>/dev/null || true
    exit 1
fi
# Sandlot must still be alive after the pool wait (a mid-wait crash is the
# classic memory-pressure failure; report the log, not a timeout).
if ! kill -0 "$SANDLOT_PID" 2>/dev/null; then
    log_error "Sandlot process died during pool creation"
    tail -30 "$LOG_DIR/sandlot-1.log" 2>/dev/null || true
    exit 1
fi
log_pass "Sandlot pool ready (CLEAN=$CLEAN VMs)"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Create $AGENT_COUNT Agents + SandFS"
# ══════════════════════════════════════════════════════════════════

GATEWAY_URL="${PROTO}://localhost:3000"
HUMAN_URL="${PROTO}://localhost:3100"

bm_create_agents "$HUMAN_URL" "$AGENT_COUNT"

# Embedded mode: MemoryStore is immediate, no etcd watch sync — but verify key
# resolution anyway (cheap, and catches auth breakage before the LLM run).
if ! bm_verify_watch_sync "$GATEWAY_URL" "${BM_API_KEYS[0]}" 15; then
    log_error "Gateway cannot resolve API keys"
    exit 1
fi

log_step "Waiting for compute node to be reachable via gateway..."
if ! bm_wait_compute "$GATEWAY_URL" "${BM_API_KEYS[0]}" "${BM_SANDFS_IDS[0]}" 90; then
    log_error "Compute node not reachable after 180s"
    tail -30 "$LOG_DIR/sandlot-1.log" 2>/dev/null || true
    tail -30 "$LOG_DIR/gateway.log" 2>/dev/null || true
    exit 1
fi
log_pass "Compute node reachable (execute succeeded)"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Run 4-Agent Eino Test"
# ══════════════════════════════════════════════════════════════════

log_step "Building Eino example binary..."
EINO_BIN="$LOG_DIR/eino-sandswap-baremetal"
bm_build_eino "$EINO_BIN"
log_pass "Eino example binary built"

log_step "Running $AGENT_COUNT-agent piped test (pool size=$POOL_SIZE, budget=${EINO_TEST_BUDGET_SECS}s)..."
echo ""
bm_run_eino "$EINO_BIN" "$LOG_DIR/eino-baremetal-test.log" "$EINO_TEST_BUDGET_SECS" \
    "$CA_CERT_ARG" "$GATEWAY_URL/mcp" "${BM_API_KEYS[@]}"
echo ""

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Analyze Results"
# ══════════════════════════════════════════════════════════════════

bm_analyze_eino "$LOG_DIR/eino-baremetal-test.log" "$AGENT_COUNT"

log_step "Checking VM reuse across agents..."
SANDLOT_LOGS=$(cat "$LOG_DIR/sandlot-1.log" 2>/dev/null || true)
VM_CREATE_COUNT=$(echo "$SANDLOT_LOGS" | grep -ci "created VM\|VM created\|new VM" || true)
if [[ "$VM_CREATE_COUNT" -le "$POOL_SIZE" ]]; then
    pass "VM reuse confirmed: $VM_CREATE_COUNT VMs created (pool size=$POOL_SIZE)"
else
    log_warn "VM create count ($VM_CREATE_COUNT) exceeds pool size ($POOL_SIZE) — check sandlot logs"
fi

# MCP path: stateless server (no sessions to count — see gateway/mcp/server.go);
# tool-call count is the positive signal the request path served all agents.
TOOL_CALLS=$(grep -cE 'tool call|tool result|"tools/call"' "$LOG_DIR/eino-baremetal-test.log" 2>/dev/null || true)
if [[ "$TOOL_CALLS" -ge "$AGENT_COUNT" ]]; then
    pass "MCP tool-call path served $TOOL_CALLS invocations (stateless, >= $AGENT_COUNT agents)"
else
    log_warn "Only $TOOL_CALLS MCP tool calls observed (expected >= $AGENT_COUNT)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 7: Results Summary"
# ══════════════════════════════════════════════════════════════════

echo ""
echo "┌─────────────────────────────────────────────────────────┐"
echo "│  Sandswap Bare-Metal Deployment Results (embedded mode) │"
echo "├─────────────────────────────────────────────────────────┤"
echo "│  Mode:           embedded (single-node, no etcd)"
echo "│  Gateway PID:    $GATEWAY_PID"
echo "│  Sandlot PID:    $SANDLOT_PID"
echo "│  Agents:         $AGENT_COUNT"
echo "│  Pool Size:      $POOL_SIZE VMs"
echo "│  LLM Backend:    $LLM_BACKEND"
echo "│  TLS:            HTTP $([ "$NO_TLS" == "true" ] && echo "plaintext" || echo "enabled"); stream mTLS always"
echo "│  Eino Exit Code: $BM_EINO_EXIT"
echo "│  Test Log:       $LOG_DIR/eino-baremetal-test.log"
echo "└─────────────────────────────────────────────────────────┘"
echo ""

# Honest exit: FAIL_COUNT (any [FAIL] above) AND the eino exit code must both
# be green — a red log with exit 0 is how regressions hide.
bm_exit_honest "$BM_EINO_EXIT"
