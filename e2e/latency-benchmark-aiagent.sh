#!/usr/bin/env bash
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
# latency-benchmark-aiagent.sh — Sandswap AI-agent latency benchmark driven by
# the openai-sandswap example (SANDSWAP_BENCH_MODE=http|mcp).
# The benchmark reads the gateway's OWN metrics — gateway_duration_ns /
# sandlot_duration_ns / exec_duration_ns — straight from the API response, plus
# (HTTP mode) the X-Sandbox-Lease header for warm/cold ground-truth
# classification. The MCP mode additionally times the LLM round trip and the
# MCP tool round trip, so every segment of the path is benchmarked. This is
# the designated replacement for the deleted log-scraping latency.sh /
# latency-baremetal.sh benchmarks.
# Benchmark cases: 1 warmup (excluded) + WARM_N
# back-to-back `echo hi` (sticky lease) + COLD_N alternating rounds of
# `echo a`/`echo b` with SWITCH_GAP_MS (> sticky-ms 100) so each cross-agent
# call cold-mounts. Each round produces two cold samples (A and B), so the
# reported cold count is 2 x COLD_N; the default 50 rounds = 100 cold samples.
# Usage:
#   bash e2e/latency-benchmark-aiagent.sh [http|mcp|both] [single|distributed]
#   $1 selects the benchmark mode (default: http):
#     http   HTTP agent API mode (no LLM needed)
#     mcp    MCP tool mode — also times the LLM round trip
#     both   run http, then mcp
#   $2 selects the deployment topology (default: single; env DEPLOY_MODE):
#     single       one combined gateway (agent + human listeners) + sandlot —
#                  the same layout as quick-start Mode 1
#     distributed  etcd + exec gateway (-mode exec, /agent/* on GATEWAY_URL)
#                  + human gateway (-mode human, /human/* CRUD on HUMAN_URL)
#                  + sandlot — the same layout as quick-start Mode 2. State is
#                  shared via etcd; etcd is downloaded if missing and torn
#                  down again on exit.
# Env:
#   DEEPSEEK_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY  — required for mcp mode
#   WARM_N=100 COLD_N=50 (100 warm + 100 cold samples)
#   WARM_GAP_MS=5 SWITCH_GAP_MS=300 SWITCH_SETTLE_MS=1000 BENCH_VERBOSE=0
#   POOL_SIZE=3 (sandlot VM pool)   NETWORK_BACKEND=bridge   DEPLOY_MODE=single|distributed
# Prerequisites: /dev/kvm, /dev/vhost-vsock (modprobe vhost_vsock), a built
# output/ (bash build/build.sh all — includes output/openai-sandswap),
# root or kvm group member.
# Self-cleaning: the script deploys its own throwaway stack (binaries to
# $DEPLOY_DIR, volumes, certs, logs, etcd data) and removes ALL of it on exit
# — processes are killed and every temp artifact/log is deleted, so no manual
# cleanup is needed before running sandctl-based modes.

set -euo pipefail
# Latency measurement must isolate the PATH from VM recycling: the e2e
# harness default TC_MAX_USES=50 recycles a VM mid-run (boot-cold samples
# 26-32ms dominate cold P95 — the docs' benchmark conditions state 100000
# for exactly this reason). Benchmarks opt out unless the caller overrides.
export TC_MAX_USES="${TC_MAX_USES:-100000}"


# Locate the repo root (the directory holding output/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT=""
for cand in "$SCRIPT_DIR" "$SCRIPT_DIR/.."; do
    if [[ -d "$cand/output" ]]; then ROOT="$cand"; break; fi
done
if [[ -z "$ROOT" ]]; then
    echo "Cannot locate output/ near $SCRIPT_DIR" >&2; exit 1
fi
OUTPUT="$ROOT/output"

# Config defaults — set BEFORE sourcing common.sh
DEPLOY_DIR="${DEPLOY_DIR:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}}"
VOL_ROOT="${VOL_ROOT:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
POOL_SIZE="${POOL_SIZE:-3}"
# Bare-metal CPU/NUMA pinning (auto: on for bare metal, off under any
# hypervisor). Stack cores = one CPU per whole physical core; each VM
# slice is BENCH_VCPUS+2 cores on the same NUMA node.
PIN_STACK_CORES="${PIN_STACK_CORES:-8}"
PIN_SLICE_CPUS="${PIN_SLICE_CPUS:-2}"
PIN_SLICE_CPUS="${PIN_SLICE_CPUS:-2}"
SANDLOT_POOL="${SANDLOT_POOL:-small:${POOL_SIZE}}"
VM_MEMORY_MB="${VM_MEMORY_MB:-256}"
WARM_N="${WARM_N:-100}"
COLD_N="${COLD_N:-50}"   # rounds; the reported cold sample count is 2 x COLD_N
WARM_GAP_MS="${WARM_GAP_MS:-5}"
SWITCH_GAP_MS="${SWITCH_GAP_MS:-300}"
SWITCH_SETTLE_MS="${SWITCH_SETTLE_MS:-1000}"
BENCH_VERBOSE="${BENCH_VERBOSE:-0}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"

# Distributed-topology knobs (only used when TOPOLOGY=distributed).
# Binary resolution is tc_ensure_etcd's job ($ETCD_DIR cache → PATH → download).
ETCD_ENDPOINT="${ETCD_ENDPOINT:-http://127.0.0.1:2379}"
ETCD_DATA="${ETCD_DATA:-/tmp/sandswap-aiagent-etcd-data}"
GW_ID_EXEC="${GW_ID_EXEC:-gw-exec-bench}"
GW_ID_HUMAN="${GW_ID_HUMAN:-gw-human-bench}"

source "$ROOT/e2e/common.sh"
source "$ROOT/e2e/pin.sh"

# Benchmark binary: built by build.sh to output/ (consistent with gateway/sandlot).
BENCH_BIN="$OUTPUT/openai-sandswap"

# Mode selector: $1 = http|mcp|both (default http). MCP needs an LLM API key.
MODE="${1:-http}"
case "$MODE" in
    http|mcp|both) ;;
    *) echo "Usage: $0 [http|mcp|both] [single|distributed]   (defaults: http single)" >&2; exit 1 ;;
esac

# Topology selector: $2 = single|distributed (default single; env DEPLOY_MODE).
TOPOLOGY="${2:-${DEPLOY_MODE:-single}}"
case "$TOPOLOGY" in
    single|distributed) ;;
    *) echo "Usage: $0 [http|mcp|both] [single|distributed]   (defaults: http single)" >&2; exit 1 ;;
esac

LLM_KEY_SET=0
for v in DEEPSEEK_API_KEY OPENAI_API_KEY GOOGLE_API_KEY; do
    [[ -n "${!v:-}" ]] && LLM_KEY_SET=1
done

HUMAN_PID=""
ETCD_PID=""

# tc_start_human_gateway — start a second gateway process in human mode on
# HUMAN_ADDR sharing the same etcd. CRUD (agent/sandfs creation via
# tc_create_agent_and_sandfs) goes through it; execution stays on the exec
# gateway. Sets HUMAN_PID.
tc_start_human_gateway() {
    log_step "Starting human gateway ($HUMAN_ADDR, mode=human, shared etcd)..."
    # Distinct stream listen port: the exec gateway already owns $STREAM_ADDR
    # (:9998); the human gateway's prov-role listener must not collide with it.
    local human_stream="${HUMAN_STREAM_ADDR:-localhost:9999}"
    "$DEPLOY_DIR/gateway" \
        -mode human \
        -human-addr "$HUMAN_ADDR" \
        -stream-addr "$human_stream" \
        -gateway-id "$GW_ID_HUMAN" \
        -gateway-url "$HUMAN_URL" \
        -gateway-stream-addr "$human_stream" \
        -etcd "$ETCD_ENDPOINT" \
        -vol-root "$VOL_ROOT" \
        -stream-tls-cert "$CERT_DIR/gateway.crt" \
        -stream-tls-key "$CERT_DIR/gateway.key" \
        -stream-tls-ca "$CERT_DIR/ca.crt" \
        -allow-anonymous-human \
        > "$LOG_DIR/gateway-human.log" 2>&1 &
    HUMAN_PID=$!
    tc_wait_component_ready "$HUMAN_URL" "human gateway" "$HUMAN_PID" "$LOG_DIR/gateway-human.log"
}

# tc_wait_component_ready — wait for an EtcdStore gateway's /ready to
# return 200 (the initial snapshot load must land before business routes stop
# returning 503). Exits if the process dies while waiting.
tc_wait_component_ready() {
    local url="$1" name="$2" pid="${3:-}" logfile="${4:-}"
    local code=""
    for _ in $(seq 1 120); do
        code=$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$url/ready" 2>/dev/null || true)
        if [[ "$code" == "200" ]]; then
            log_pass "$name ready ($url)"
            return 0
        fi
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
            log_error "$name died while waiting for readiness (last /ready=$code)"
            [[ -n "$logfile" ]] && tail -20 "$logfile"
            exit 1
        fi
        sleep 0.5
    done
    log_error "$name never became ready (last /ready=$code) — $url/ready"
    [[ -n "$logfile" ]] && tail -20 "$logfile"
    exit 1
}

cleanup() {
    # Kill this script's OWN PIDs FIRST (the human gateway starts via
    # tc_start_human_gateway, which sets HUMAN_PID — NOT GATEWAY_PID — and
    # etcd), then run the shared cleanup.
    # tc_kill_etcd inside tc_cleanup_default waits out the ports; that only
    # works if this etcd isn't still being SIGTERM'd after that wait.
    for pid in "${HUMAN_PID:-}" "${ETCD_PID:-}"; do
        [[ -n "$pid" ]] && { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    done
    tc_cleanup_default
    # Self-clean the artifacts THIS benchmark deployed (surgical: never the
    # shared $DEPLOY_DIR itself — see tc_cleanup_deployed_artifacts).
    tc_cleanup_deployed_artifacts
    # …and this benchmark's etcd DATA DIR. This call used to be
    # `tc_cleanup_deployed_artifacts "$ETCD_DATA"`: the argument was silently
    # ignored (that function takes none), so the artifacts were cleaned but
    # the etcd data dir leaked in /tmp on every run.
    tc_cleanup_etcd "$ETCD_DATA"
}
trap cleanup EXIT INT TERM

# ── Phase 0: environment detection (bare metal vs nested virt) ──────
log_section "Phase 0: Environment detection (bare metal vs nested virt)"

VIRT_TYPE="$(systemd-detect-virt 2>/dev/null || true)"
VIRT_TYPE="${VIRT_TYPE//$'\n'/}"   # drop any stray newline
HYPER_FLAG=$(grep -c -m1 '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null) || true
NESTED=0
if [[ "$VIRT_TYPE" == "none" || -z "$VIRT_TYPE" ]] && [[ "${HYPER_FLAG:-0}" -eq 0 ]]; then
    log_pass "Bare-metal detected: systemd-detect-virt=none and no cpuinfo hypervisor flag -> bare-metal KVM host"
elif [[ "$VIRT_TYPE" != "none" && -n "$VIRT_TYPE" ]] || [[ "${HYPER_FLAG:-0}" -gt 0 ]]; then
    NESTED=1
    log_warn "Nested virtualization detected: systemd-detect-virt=$VIRT_TYPE, hypervisor flag=$HYPER_FLAG"
    log_warn "  Results are labeled [NESTED-VIRT]; re-run on bare metal for true steady state."
fi

# Bare-metal CPU/NUMA pinning: re-exec under taskset so the gateway, sandlot
# and benchmark client all inherit the stack cores. The per-VM shim is
# generated after deploy (tc_pin_setup). Nested virt is never pinned.
PIN_MODE="$(tc_pin_resolve_mode "$NESTED")" || exit 1
if [[ "$PIN_MODE" == "1" ]]; then
    PIN_SLICES="${PIN_SLICES:-$POOL_SIZE}"
    tc_pin_reexec_if_needed "$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")" "$@" || exit 1
else
    unset TC_VMM_BINARY 2>/dev/null || true
fi
echo "    CPU cores: $(nproc)    load: $(uptime | sed 's/.*load average:/load:/')"
echo "    Pinning:   PIN_MODE=$PIN_MODE (${PIN_STACK_CPUS:-auto} stack cores, ${PIN_SLICE_SPECS:-auto} VM slices)"

if [[ ! -e /dev/kvm ]]; then
    log_error "/dev/kvm missing — KVM required"; exit 1
fi
log_pass "/dev/kvm available"

if [[ ! -r /dev/vhost-vsock ]]; then
    log_warn "/dev/vhost-vsock not readable, trying modprobe vhost_vsock..."
    modprobe vhost_vsock 2>/dev/null || true
fi
if [[ ! -r /dev/vhost-vsock ]]; then
    log_error "/dev/vhost-vsock not readable — run modprobe vhost_vsock and retry."; exit 1
fi
log_pass "/dev/vhost-vsock readable"

tc_check_root
# go is only needed to BUILD the benchmark binary. A release package ships
# output/openai-sandswap prebuilt (.release-stamp) — no toolchain required.
if [[ -f "$OUTPUT/.release-stamp" ]]; then
    tc_check_tools curl python3
else
    tc_check_tools curl go python3
fi

# Freshness gate: every output/ artifact (incl. the example binaries) must be
# newer than its source; stale artifacts auto-rebuild (AUTO_REBUILD=1).
tc_check_freshness

# ── Phase 1: Deploy ─────────────────────────────────────────────────
log_section "Phase 1: Deploy"
tc_clean_environment
tc_ensure_dev_nodes
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — microVMs will be offline"
fi
tc_deploy_artifacts
if [[ "$PIN_MODE" == "1" ]]; then
    tc_pin_setup "$DEPLOY_DIR" "$DEPLOY_DIR/sandvmm" "$POOL_SIZE" || exit 1
fi
tc_gen_certs
tc_attach_vsockguard

# ── Phase 2: Start gateway (topology-dependent) ─────────────────────
if [[ "$TOPOLOGY" == "single" ]]; then
    log_section "Phase 2: Start gateway (single-node: agent+human in one process)"
    tc_start_gateway
else
    log_section "Phase 2: Start etcd + gateways (distributed: exec $GATEWAY_URL, human $HUMAN_URL)"
    tc_ensure_etcd
    tc_start_etcd aiagent-bench "$ETCD_DATA"
    # Exec gateway: serves /agent/* on GATEWAY_URL and the gRPC stream for
    # sandlots; auth/sandfs records live in etcd.
    tc_start_gateway \
        -mode exec \
        -etcd "$ETCD_ENDPOINT" \
        -gateway-id "$GW_ID_EXEC" \
        -gateway-url "$GATEWAY_URL" \
        -gateway-stream-addr "localhost$STREAM_ADDR"
    tc_wait_component_ready "$GATEWAY_URL" "exec gateway" "$GATEWAY_PID" "$LOG_DIR/gateway.log"
    # Human gateway: /human/* CRUD on HUMAN_URL, same etcd.
    tc_start_human_gateway
fi

# ── Phase 3: Start sandlot ──────────────────────────────────────────
log_section "Phase 3: Start sandlot (connects to gateway, mTLS)"
# Benchmark VM shape: exactly 1 vCPU / 256 MiB / 3 exec slots. It is
# injected as a named `bench` spec so the benchmark never inherits the
# sandlot's built-in `small` defaults (2 vCPU/256 MiB). One vCPU leaves the
# second SMT thread of the VM's physical core for its vhost/virtiofs
# threads, so each microVM can own one whole physical core without
# cross-core scheduling.
AIAGENT_CFG="$DEPLOY_DIR/sandlot-aiagent.yaml"
tc_gen_sandlot_config "$AIAGENT_CFG"
python3 - "$AIAGENT_CFG" "$POOL_SIZE" <<'PY'
import re, sys
path, pool = sys.argv[1], sys.argv[2]
s = open(path).read()
s = s.replace("specs:\n",
              "specs:\n  bench:\n    vcpus: 1\n    memory_mb: 256\n    exec_slots: 3\n", 1)
s = re.sub(r'(?m)^pool:.*$', 'pool: "bench:%s"' % pool, s, count=1)
open(path, "w").write(s)
PY
export TC_SANDLOT_CONFIG="$AIAGENT_CFG"
# SANDLOT_EXTRA_FLAGS: extra CLI flags for the sandlot under test (e.g.
# enabler on/off comparisons: "-binding-backend=shm -egress-baseline on").
tc_start_sandlot ${SANDLOT_EXTRA_FLAGS:-}
tc_wait_health
if [[ "$TOPOLOGY" == "distributed" ]]; then
    # Prov-role sandlot (storage plane) → human gateway stream, so the human
    # gateway's sandfs creation has a provisioner. Mirrors the blessed split
    # shape from lifecycle-split-gateway.sh; the colocated escape hatch is
    # required because this simulation runs two instances on one host. The
    # stream is mTLS like every other path — the gateway refuses a stream
    # that presents no client certificate.
    tc_ensure_volume_seed
    ss_service_exec sandlot -- "$DEPLOY_DIR/sandlot" \
        -gateway-addr "${HUMAN_STREAM_ADDR:-localhost:9999}" \
        -node-id "aiagent-bench-prov" \
        -volumes-dir "$VOL_ROOT" -allow-insecure-volumes -allow-missing-vsockguard \
        -roles prov \
        -volume-seed-file "$DEPLOY_DIR/volume-seed" \
        -flat-templates "${TC_FLAT_TEMPLATES:-$DEPLOY_DIR/flat-templates}" \
        -tls-cert "$(tc_node_cert aiagent-bench-prov prov).crt" \
        -tls-key "$(tc_node_cert aiagent-bench-prov prov).key" \
        -tls-ca "$CERT_DIR/ca.crt" \
        -allow-colocated-instances \
        > "$LOG_DIR/sandlot-prov.log" 2>&1 &
    PROV_PID=$!
    sleep 1
    kill -0 "$PROV_PID" 2>/dev/null || {
        tc_log_error "prov sandlot died"; tail -10 "$LOG_DIR/sandlot-prov.log"; exit 1; }
    # Storage plane ready = the human gateway sees >=1 provisioner.
    # The counter is served by /health (human.go's health handler), not
    # /stats — polling /stats always reads 0 and burns the full 30s loop,
    # which pushes the benchmark past the warden's 30s first-frame timeout
    # and produces 50ms retry outliers on the pre-warmed vsock connections.
    for _ in $(seq 1 60); do
        provs=$(curl -s -m 2 "$HUMAN_URL/health" 2>/dev/null \
            | python3 -c 'import sys,json;print(json.load(sys.stdin).get("provisioners",0))' 2>/dev/null || echo 0)
        [[ "${provs:-0}" -ge 1 ]] && break
        sleep 0.5
    done
    # Pool state lives in the exec gateway's pool manager; its own /stats is
    # authoritative here.
    tc_wait_pool_ready "$POOL_SIZE" "$GATEWAY_URL"
else
    tc_wait_pool_ready
fi

# ── Phase 4: create agents ──────────────────────────────────────────
log_section "Phase 4: Create agents A/B (busybox template)"
if [[ "$TOPOLOGY" == "distributed" ]]; then
    log_info "CRUD goes through the human gateway ($HUMAN_URL/human/*); execution hits the exec gateway ($GATEWAY_URL/agent/execute)"
fi
RESP_A=$(tc_create_agent_and_sandfs "aiagent-A" || echo '{"error":"create failed"}')
RESP_B=$(tc_create_agent_and_sandfs "aiagent-B" || echo '{"error":"create failed"}')
KEY_A=$(json_val "$RESP_A" "api_key")
KEY_B=$(json_val "$RESP_B" "api_key")
SANDFS_A=$(json_val "$RESP_A" "sandfs_id")
SANDFS_B=$(json_val "$RESP_B" "sandfs_id")
[[ -n "$KEY_A" && -n "$KEY_B" ]] || { log_error "agent creation failed"; exit 1; }
log_pass "agents A/B created (sandfs $SANDFS_A / $SANDFS_B)"

# ── Phase 5: run benchmark ──────────────────────────────────────────
log_section "Phase 5: Run benchmark (mode=$MODE)"
if [[ ! -x "$BENCH_BIN" ]]; then
    log_error "missing benchmark binary $BENCH_BIN — run bash build/build.sh examples (dev tree), or use a release package that ships it prebuilt"
    exit 1
fi
log_pass "benchmark binary: $BENCH_BIN"

export SANDSWAP_API_KEY_A="$KEY_A"
export SANDSWAP_API_KEY_B="$KEY_B"
export SANDSWAP_SANDFS_A="$SANDFS_A"
export SANDSWAP_SANDFS_B="$SANDFS_B"
export GATEWAY_URL WARM_N COLD_N WARM_GAP_MS SWITCH_GAP_MS SWITCH_SETTLE_MS BENCH_VERBOSE

run_bench() {
    local mode="$1"
    log_section "Benchmark — mode=$mode"
    export SANDSWAP_BENCH_MODE="$mode"
    "$BENCH_BIN"
    echo
}

case "$MODE" in
    http)
        run_bench http
        ;;
    mcp)
        if [[ "$LLM_KEY_SET" -eq 1 ]]; then
            run_bench mcp
        else
            # An EXPLICITLY requested mode must not silently degrade to a
            # green no-op — say so and fail (use MODE=both to run http-only
            # when no key is available).
            log_error "mcp mode requires an LLM API key (DEEPSEEK_API_KEY/OPENAI_API_KEY/GOOGLE_API_KEY)"
            exit 1
        fi
        ;;
    both)
        run_bench http
        if [[ "$LLM_KEY_SET" -eq 1 ]]; then
            run_bench mcp
        else
            log_warn "mcp mode skipped — no LLM API key (DEEPSEEK_API_KEY/OPENAI_API_KEY/GOOGLE_API_KEY)"
        fi
        ;;
esac

# ── Phase 6: Verdict ────────────────────────────────────────────────
log_section "Phase 6: Verdict"
# The ranges below are REFERENCE figures from past runs (not gated asserts —
# the quality gate lives in the bench binary: ≥90% samples must succeed and
# durations must be non-zero, or the run fails).
if [[ $NESTED -eq 1 ]]; then
    echo -e "  ${TC_YELLOW}[NESTED-VIRT] Host is nested virtualization ($VIRT_TYPE); results include guest-scheduling tail jitter.${TC_NC}"
    echo -e "  ${TC_YELLOW}  Expected: warm P50 3-7ms (tail 4-15ms), switch P50 15-25ms (tail 20-40ms).${TC_NC}"
else
    echo -e "  ${TC_GREEN}[BARE-METAL] Bare-metal KVM; results reflect true steady-state latency.${TC_NC}"
    echo -e "  ${TC_GREEN}  Expected: warm P50 ~0.7-1ms (tail <3ms), switch P50 ~3-5ms (tail <8ms).${TC_NC}"
fi

echo
log_section "Summary"
echo -e "  Environment: $([ $NESTED -eq 0 ] && echo 'bare-metal KVM' || echo "nested virtualization ($VIRT_TYPE)")"
echo -e "  Mode:       $MODE"
echo -e "  Topology:   $TOPOLOGY$([ "$TOPOLOGY" == "distributed" ] && echo " (etcd $ETCD_ENDPOINT, exec gw $GATEWAY_URL, human gw $HUMAN_URL)")"
echo -e "  Warm/Cold:  WARM_N=$WARM_N COLD_N=$COLD_N  warm_gap_ms=$WARM_GAP_MS  switch_gap_ms=$SWITCH_GAP_MS  settle_ms=$SWITCH_SETTLE_MS"
echo -e "  Gateway:    $GATEWAY_URL"
echo -e "  Temp dirs:  deploy=$DEPLOY_DIR logs=$LOG_DIR (all removed on exit)"
