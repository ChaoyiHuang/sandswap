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
# verify-k8s.sh — post-deploy verification drill against a RUNNING k3s
# deployment (the state deploy-k8s-embedded.sh / deploy-k8s-boxout.sh leave
# behind in their default keep mode). Auto-detects the deployed mode from
# the sandlot DaemonSet, then runs the full drill from deploy-lib.sh:
#   readiness waits → host reachability (human port-forward + gateway pin)
#   → 4 agents + 4 sandfs → affinity self-test → eino 4-agent run + analysis
#   → [--failover] gateway-pod kill drill → honest summary
# The deployment itself is NEVER torn down here: cleanup reverts only this
# run's host-side access aids (port-forward watchdog, /etc/hosts pin).
# Remove the deployment afterwards with:
#   sudo bash deploy/k8s/k8s-cleanup.sh
# Prerequisites:
#   - a kept deployment on this cluster (namespace "sandswap")
#   - root (port-forward pinning, /etc/hosts)
#   - DEEPSEEK_API_KEY or OPENAI_API_KEY or GOOGLE_API_KEY (the eino run)
# Usage:
#   sudo env DEEPSEEK_API_KEY=sk-xxx bash deploy/k8s/verify-k8s.sh [--failover]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/e2e/common.sh"
source "$ROOT/deploy/k8s/deploy-lib.sh"

[[ "$(id -u)" -eq 0 ]] || { echo "error: must run as root (sudo)" >&2; exit 1; }

k8s_parse_flags "$@"

# verify-k8s.sh never tears the deployment down — a stray --verify (a
# deploy-script drill flag that flips cleanup into teardown mode) must not
# change that.
if [[ "$VERIFY_MODE" == "true" ]]; then
    log_warn "--verify is a deploy-script flag (drill + teardown there); ignoring it — this script always keeps the deployment"
    VERIFY_MODE=false
fi
KEEP_ON_EXIT=true

# ── Preconditions ────────────────────────────────────────────────────
# A missing cluster/deployment is an ENVIRONMENT fact, not a defect of this
# drill: report it through the suite-skip channel (the script matrix records
# the reason) so a bare exit-1 cannot be read as a product failure. This is
# the same rule the baremetal verifiers follow — and the case is real: the
# egress-enabler leg finishes with its own "zero residue" cleanup, so a
# verifier scheduled after it finds nothing to verify.
if ! command -v "$KUBECTL" &>/dev/null; then
    tc_skip_suite "needs-k3s: kubectl not found — verify runs against an existing k3s cluster"
fi
export KUBECONFIG="${KUBECONFIG:-$K3S_KUBECONFIG}"
if [[ ! -f "$KUBECONFIG" ]]; then
    tc_skip_suite "needs-k3s: kubeconfig not found at $KUBECONFIG — no k3s cluster on this host"
fi
if ! $KUBECTL get namespace "$NAMESPACE" &>/dev/null; then
    tc_skip_suite "needs-k3s: namespace $NAMESPACE not found — no Sandswap deployment on this cluster (deploy first: deploy-k8s-embedded.sh | deploy-k8s-boxout.sh)"
fi

# ── Mode autodetect from the sandlot DaemonSet ───────────────────────
# The deploy entry scripts set this context; against a live cluster the
# deployed DaemonSet is the source of truth (exactly one of the two exists).
if $KUBECTL get daemonset sandlot-boxout -n "$NAMESPACE" &>/dev/null; then
    MODE_NAME="boxout"
    MODE_DESC="boxout (privileged sidecar + unprivileged UID 65536 sandlot)"
    SANDLOT_DS="sandlot-boxout"
    SANDLOT_SELECTOR="app=sandlot-boxout"
    SANDLOT_DS_LOG_CONTAINERS="boxout sandlot"
    VM_REUSE_LOGS=(-l app=sandlot-boxout -c boxout)
    VM_REUSE_PATTERN='created VM\|VM created\|new VM\|create_vm'
    EINO_BIN_NAME="eino-sandswap-k8s-boxout"
    VERIFY_SANDBOX_UID=true
    SANDBOX_UID=65536
    log_info "Detected mode: boxout (DaemonSet sandlot-boxout)"
elif $KUBECTL get daemonset sandlot -n "$NAMESPACE" &>/dev/null; then
    MODE_NAME="embedded"
    MODE_DESC="embedded (sandlot runs as UID 0, privileged — owns VM lifecycle)"
    SANDLOT_DS="sandlot"
    SANDLOT_SELECTOR="app=sandlot"
    SANDLOT_DS_LOG_CONTAINERS="sandlot"
    VM_REUSE_LOGS=(-l app=sandlot)
    VM_REUSE_PATTERN='created VM\|VM created\|new VM\|create_vm'
    EINO_BIN_NAME="eino-sandswap-k8s"
    VERIFY_SANDBOX_UID=false
    log_info "Detected mode: embedded (DaemonSet sandlot)"
else
    log_error "neither sandlot nor sandlot-boxout DaemonSet found in $NAMESPACE — incomplete deployment?"
    exit 1
fi
EINO_LOG_NAME="${EINO_BIN_NAME}-test.log"

# LLM key: hard requirement — the eino run is part of what "verified" means
# (same policy as the deploy --verify drill).
if [[ -z "${DEEPSEEK_API_KEY:-}" ]] && [[ -z "${OPENAI_API_KEY:-}" ]] && [[ -z "${GOOGLE_API_KEY:-}" ]]; then
    log_error "no LLM API key set (DEEPSEEK_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY)"
    log_info "run: sudo env DEEPSEEK_API_KEY=sk-... bash $0 [--failover]"
    exit 1
fi
if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
    LLM_BACKEND="deepseek"
elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
    LLM_BACKEND="openai"
else
    LLM_BACKEND="gemini"
fi

if [[ "$TEST_FAILOVER" == "true" ]]; then
    log_warn "--failover will kill one gateway pod on the live deployment (opt-in disruption)"
fi

mkdir -p "$LOG_DIR"

# ── Traps ─────────────────────────────────────────────────────────────
# cleanup with KEEP_ON_EXIT=true reverts only this run's host-side access
# aids (port-forward watchdog, /etc/hosts pin) — the deployment stays.
PF_PIDS=()
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

# ── The drill (all phases are the deploy-lib.sh shared implementations) ──
k8s_phase_wait_ready
k8s_phase_security_invariants
# Per-node stream identities survive a keep/redeploy cycle? (Secret per node +
# this node's hostPath pair) — the check the deploy runs, re-asserted here.
k8s_phase_stream_certs
k8s_phase_reachability
k8s_phase_agents
k8s_phase_affinity
k8s_phase_eino
k8s_phase_analyze
k8s_phase_failover
k8s_phase_summary
