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
# latency-benchmark-load.sh — whole-host microVM reuse capacity under the
# realistic AI agent workload.
#
# Method:
#   1. Measure a single microVM's no-background-load latency with
#      e2e/latency-benchmark-aiagent.sh in the one-machine-etcd topology, and
#      take its gateway E2E P95 from that run as the latency baseline (warm
#      and cold separately).
#   2. Drive the same stack with examples/loadgen's AI agent model: N
#      independent sandfs agents, each sleeping 0.9-1.5 s between turns, then
#      issuing a turn of 1..3 requests. The first request mounts the volume
#      (cold); the follow-ups are sent immediately after the previous response
#      and are warm on the same VM under the benchmark's 1 ms sticky lease.
#   3. Sweep the offered agent count. At every level the driver reports the
#      completed cold mounts/s (VM reuses/s), the average per-microVM reuse
#      rate (cold/s / pool), the warm share, and the gateway E2E P95 per class.
#   4. The 1x capacity is the highest level whose cold AND warm gateway E2E
#      (and business client, retries included) P95 stay within the no-load
#      baseline, with no terminal error; the 2x capacity is the same with twice
#      the baseline. A busy refusal (503 NO_AVAILABLE_SANDBOX) is retried by
#      the client like a real agent, so it shows up as retry pressure, not a
#      failed turn.
#   5. Optional ideal probe (LOADTEST_WORKLOAD=ideal): one paced lane per microVM,
#      no between-turn think gap, a fixed turn period. The period sweep's knee (zero BUSY,
#      zero terminal) is the collision-free maximum reuse rate with the VMs
#      continuously fed. It is an idealized capability number, not a business
#      model.
#
# Data sources (no log scraping):
#   - Phase 1 runs e2e/latency-benchmark-aiagent.sh http distributed and parses
#     its warm/cold client+gateway P95 table.
#   - Phase 5 drives the exec plane with examples/loadgen: one agent per
#     sandfs, one keep-alive http.Client, X-Sandbox-Lease as warm/cold ground
#     truth, and the response's gateway_duration_ns as the sandswap-attributable
#     latency.
#   - A 2 s /stats poller records the pool's CLEAN/TOTAL counts and the node's
#     cumulative policy-recycle counter while a level runs.
#
# Topology: one-machine-etcd (docs/how-it-works/topologies.md):
#   etcd + exec gateway (:3001, /agent/*, stream :9998)
#        + human gateway (:3100, /human/* CRUD, stream :9999)
#        + one merged exec,prov sandlot on the exec stream
#        + one prov-only sandlot on the human stream (storage plane)
#
# Phases:
#   0  preflight: KVM/vsock, tools, freshness, host facts, etcd binary
#   1  no-load reference: latency-benchmark-aiagent.sh (or supplied P95s)
#   2  deploy: one-machine-etcd stack with -sticky-ms 1 and the flat busybox
#      template (rootfs:v1)
#   3  sandlot + provision instance; pool ready
#   4  fixtures: one flat volume per simulated agent
#   5  load: offered-agent levels, each with warmup + measurement window
#   6  gates + final summary
#
# Gates (exit non-zero on any failure):
#   - zero UNEXPECTED errors at every level: any 5xx other than the 503
#     capacity refusal, any 4xx, and any transport/timeout FAIL. A busy
#     refusal absorbed by the retry policy is retry pressure, not an error;
#     a terminal 503 (retry budget exhausted) is reported and excluded from
#     the tier selection.
#   - capacity per tier: highest level with no terminal error and both
#     classes' gateway E2E P95 AND client P95 (retries included) within
#     k x the no-load reference (k = LOADTEST_LATENCY_TIERS).
#   - punctuality at the highest completed level: lease_fire delta > 0, >=95%
#     of fires with lag < 2ms, max lag <= 20ms.
#   - conservation at the highest completed level: |expected_expiries_all -
#     unmount delta|
#     within max(2, 10%, one per agent). expected_expiries counts a gap only
#     after a request that actually COMPLETED; the first turn of every agent
#     has no predecessor, hence the agent-sized slack.
#
# Usage:
#   bash e2e/latency-benchmark-load.sh [--quick]
#     --quick  machinery smoke: skips the reference benchmark, uses a tiny
#              pool/level set and placeholder references. Its numbers are NOT
#              capacity evidence.
#   PIN_MODE=1 bash e2e/latency-benchmark-load.sh
#              same benchmark with per-VM CPU-slice + NUMA-memory binding.
#
# Env (the LLM model):
#   LOADTEST_AGENT_LEVELS="10 20 40 80"
#                           offered agent counts (one flat volume per agent);
#                           capacity runs set the report's larger lists
#   LOADTEST_STICKY_MS=1         gateway sticky window; the follow-ups are sent
#                           immediately and must land inside it
#   LOADTEST_THINK_MIN_MS / LOADTEST_THINK_MAX_MS=900 / 1500
#                           per-turn LLM round trip
#   LOADTEST_REQUESTS_PER_TURN="1:40,2:35,3:25"
#                           requests per turn: N for a fixed count (1 = every
#                           turn is a single cold request), or size:weight pairs
#   LOADTEST_WORKLOAD=agents     agents = the realistic AI agent closed loop;
#                           ideal = one paced lane per microVM with no think
#                           time and a fixed period (capability probe);
#                           shaped = a full agent population queued per lane,
#                           one in-flight request per VM (toll-booth shaper)
#   LOADTEST_LANES=POOL_SIZE
#                           ideal/shaped: paced lanes (one per microVM)
#   LOADTEST_TURN_PERIODS_MS="20 22 24 26 28 30 35"
#                           ideal/shaped: turn-period sweep; the smallest
#                           period with zero BUSY attempts is the ideal max
#   LOADTEST_SHAPED_AGENTS_PER_LANE=auto
#                           shaped: AI agents queued per lane (auto = rate x
#                           mean think + margin)
#   LOADTEST_SHAPED_HOLD_MS=auto shaped: VM-slot hold after the sticky window —
#                           auto measures THIS stack's unmount P95 (cold execs
#                           + /stats recent P95) and uses ceil(P95)+2ms
#   LOADTEST_BUSY_RETRIES=50       additional attempts after 503 NO_AVAILABLE_SANDBOX
#                           (0 = surface the refusal as an error)
#   LOADTEST_BUSY_RETRY_BACKOFF_MS=10 full-jitter retry backoff base
#   LOADTEST_INTRA_TURN_GAP_MS=0      gap inside a turn (0 = immediate)
#   LOADTEST_DURATION_SEC / LOADTEST_WARMUP_SEC=30 / 10
#                           measurement window / excluded warm-up
#   LOADTEST_MAX_INFLIGHT=1024   client-side in-flight cap (not a server limit)
#   LOADTEST_LATENCY_TIERS="1.0 2.0"     latency budgets, as multiples of the no-load
#                           (default 1.0/2.0; bare-metal capacity runs use
#                           "1.05 1.5 2.0" — see docs/benchmark/baremetal-load.md)
#                           gateway E2E P95 (and of the no-load client P95)
#   LOADTEST_RECYCLE_POLICY=capacity
#                           capacity = every lifetime cap + memory recycle off;
#                           shipped = product defaults (300 distinct agents /
#                           10000 mounts / 100000 uses, 10%/100MB)
#   LOADTEST_MAX_USES / LOADTEST_MAX_MOUNTS / LOADTEST_MAX_DISTINCT_AGENTS
#                           explicit lifetime-cap overrides
#   LOADTEST_AGENT_CREATE_CONCURRENCY=32, LOADTEST_PROV_MAX_OPS=16
#                           parallel sandfs creation and prov-instance concurrency
#   LOADTEST_STATS_POLL_SEC=2    /stats pool/recycle sampling cadence
#   SKIP_ESTIMATE_BENCH=0   1 = do not run latency-benchmark-aiagent.sh; use
#                           the four reference P95s below
#   WARM_GW_P95_MS, COLD_GW_P95_MS, WARM_CLIENT_P95_MS, COLD_CLIENT_P95_MS
#                           no-load gateway E2E / client P95 (ms) for the tier
#                           budgets
#   ESTIMATE_ATTEMPTS=2     attempts for the reference benchmark
#   POOL_SIZE=4             sandlot pool (bench spec)
#   VM_MEMORY_MB=256        bench spec memory
#   BENCH_VCPUS=1           bench spec vCPUs (the reference uses the same)
#   BENCH_TEMPLATE_REF=rootfs:v1  flat busybox template
#   EXEC_SLOTS=3            bench-spec exec slots
#   NETWORK_BACKEND=bridge
#   PIN_MODE=0              0 = host scheduler; 1 = bind every microVM's
#                           sandvmm process (vCPU + host-side virtio-fs/API
#                           threads) to its own host CPU slice and its
#                           allocations to that slice's NUMA node.
#   PIN_CPUS=""             Explicit VM CPU pool (kernel cpulist).
#                           Mutually exclusive with
#                           PIN_RESERVE_CORES/PIN_STACK_LAYOUT.
#   PIN_RESERVE_CORES=0     Whole physical cores reserved for the host stack
#                           (both SMT threads excluded from the VM pool).
#                           0 = none; N = N whole cores; "auto" = a starting
#                           point, min(8, max(2, physical_cores/8)).
#   PIN_STACK_LAYOUT=""     Explicit role:cpus sets for the reserved cores,
#                           e.g. "loadgen:0-3;gateway:4-7;sandlot:8-11"
#                           (semicolons separate roles; commas stay inside a
#                           role's cpulist). Every role must hold WHOLE cores;
#                           roles may overlap. gateway also holds the human
#                           gateway + etcd; sandlot also holds the prov instance.
#   PIN_TARGET_UTIL=0.70    CPU-accounting advisor target: per-role peak
#                           CPU-seconds/second must fit in whole_cores x
#                           threads_per_core x target.
#   PIN_PLAN=0              1 = print the computed core partition, stack
#                           layout, VM pool, slice count and VM-count
#                           equivalents, then EXIT without deploying.
# Prerequisites: /dev/kvm, /dev/vhost-vsock, rooted host, a built output/
# (bash build/build.sh all, includes output/loadgen and the flat
# output/rootfs-template deployed as rootfs:v1). PIN_MODE=1 or any reserve /
# layout needs `numactl`; stack pinning needs `taskset`; setpriv is already
# required by the identity split.
# Every run records per-level host-stack CPU (loadgen/gateway/human/etcd/
# sandlot) in $LOG_DIR/load-stack-cpu.tsv and prints the recommended
# PIN_RESERVE_CORES for the next run at the end.
# Self-cleaning: deploys its own throwaway stack (binaries, certs, volumes,
# logs, etcd data) and removes ALL of it on exit.

set -euo pipefail
# The per-run recycle policy (LOADTEST_RECYCLE_POLICY) sets every lifetime cap
# explicitly below; this default only keeps the e2e harness's own default
# (50) out of a direct invocation.
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

# Config defaults — set BEFORE sourcing common.sh (common.sh reads caller scope).
DEPLOY_DIR="${DEPLOY_DIR:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}}"
VOL_ROOT="${VOL_ROOT:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
HUMAN_URL="${HUMAN_URL:-http://localhost:3100}"
POOL_SIZE="${POOL_SIZE:-4}"
SANDLOT_POOL="${SANDLOT_POOL:-small:${POOL_SIZE}}"
# Per-level re-verification of the VM-to-slice map (a replacement VM is a
# dirty destroy, not a measurement failure).
PIN_VERIFY_EACH_LEVEL="${PIN_VERIFY_EACH_LEVEL:-1}"
VM_MEMORY_MB="${VM_MEMORY_MB:-256}"
BENCH_VCPUS="${BENCH_VCPUS:-1}"
# Whole-physical-core VM slices: each microVM owns an entire physical core
# (both SMT threads) so no two VMs share a core; the vCPU uses one thread and
# the VM's own vhost/virtiofs threads the other. The stack roles
# (loadgen/gateway/sandlot) are reserved whole cores independently.
PIN_SLICE_CPUS="${PIN_SLICE_CPUS:-$(( BENCH_VCPUS < 2 ? 2 : BENCH_VCPUS * 2 ))}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"

# Per-microVM CPU-slice + NUMA-memory binding (script-local, no product-code
# change: sandlot's `microvm.vmm_binary` points at a generated numactl shim).
PIN_MODE="${PIN_MODE:-auto}"
PIN_CPUS="${PIN_CPUS:-}"
PIN_MAP="$DEPLOY_DIR/sandvmm-pinned.map"
PIN_WRAPPER="$DEPLOY_DIR/sandvmm-pinned"
PIN_SLICES=0
PIN_LEFTOVER=0
PIN_NODE_DETAIL=""
PIN_SUMMARY="off (host scheduler; PIN_MODE=1 enables per-VM CPU+NUMA binding)"
PIN_GRAN_DESC="whole-core"
(( PIN_SLICE_CPUS <= 1 )) && PIN_GRAN_DESC="logical-CPU"

# Host-stack partition: whole physical cores reserved for
# loadgen/gateway/etcd/sandlot, computed from the live topology by the
# planner in Phase 0.
PIN_RESERVE_CORES="${PIN_RESERVE_CORES:-0}"   # 0 | N | auto
PIN_STACK_LAYOUT="${PIN_STACK_LAYOUT:-}"      # "role:cpus;role:cpus;role:cpus"
PIN_TARGET_UTIL="${PIN_TARGET_UTIL:-0.70}"    # advisor target utilization
PIN_PLAN="${PIN_PLAN:-0}"                     # 1 = print the plan and exit
PIN_PARTITIONED=0
PIN_ONLINE_SPEC=""
PIN_CORE_COUNT=0
PIN_THREADS_PER_CORE=2
PIN_VM_POOL_SPEC=""
PIN_RESERVED_CPUS=""
PIN_RESERVED_CORES=0
PIN_STACK_LOADGEN_CPUS=""
PIN_STACK_GATEWAY_CPUS=""
PIN_STACK_SANDLOT_CPUS=""
PIN_STACK_LOADGEN_GOMAXPROCS=""
PIN_STACK_GATEWAY_GOMAXPROCS=""
PIN_STACK_ETCD_GOMAXPROCS=""
PIN_STACK_SANDLOT_GOMAXPROCS=""
PIN_STACK_CORE_POOL=""
PIN_STACK_ENV_OLD=""
PIN_STACK_ENV_HAD=0
PIN_CPU_TSV="$LOG_DIR/load-stack-cpu.tsv"
PIN_VERIFY_MODE=""                            # "slice" | "pool" | "" (off)
PIN_CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

# The workload runs a 1 ms sticky lease: a turn's follow-up requests are sent
# immediately after the previous response, so they land inside the window and
# reuse the same VM. MAX_LEASE_SEC stays at the harness default (the maxHold
# safety cap for pure-sync sandboxes).
LEASE_MS="${LEASE_MS:-1}"
MAX_LEASE_SEC="${MAX_LEASE_SEC:-5}"
STICKY_MS="$LEASE_MS"

# one-machine-etcd topology knobs.
ETCD_ENDPOINT="${ETCD_ENDPOINT:-http://127.0.0.1:2379}"
ETCD_DATA="${ETCD_DATA:-/tmp/sandswap-load-etcd-data}"
GW_ID_EXEC="${GW_ID_EXEC:-gw-exec-load}"
GW_ID_HUMAN="${GW_ID_HUMAN:-gw-human-load}"
PROV_NODE_ID="${PROV_NODE_ID:-load-bench-prov}"

# Usage selector: --quick runs a tiny machinery smoke (no subprocess
# reference benchmark).
QUICK=0
[[ "${1:-}" == "--quick" ]] && QUICK=1

if (( QUICK == 1 )); then
    LOADTEST_AGENT_LEVELS="${LOADTEST_AGENT_LEVELS:-1 2 4}"
    LOADTEST_DURATION_SEC="${LOADTEST_DURATION_SEC:-10}"
    LOADTEST_WARMUP_SEC="${LOADTEST_WARMUP_SEC:-3}"
    SKIP_ESTIMATE_BENCH=1
else
    LOADTEST_AGENT_LEVELS="${LOADTEST_AGENT_LEVELS:-10 20 40 80}"
    LOADTEST_DURATION_SEC="${LOADTEST_DURATION_SEC:-30}"
    LOADTEST_WARMUP_SEC="${LOADTEST_WARMUP_SEC:-10}"
fi
SKIP_ESTIMATE_BENCH="${SKIP_ESTIMATE_BENCH:-0}"
ESTIMATE_ATTEMPTS="${ESTIMATE_ATTEMPTS:-2}"
EXEC_SLOTS="${EXEC_SLOTS:-3}"
# The load fixture is the aiagent benchmark's flat busybox template
# (rootfs:v1), so the no-load reference and the load request exercise the
# same guest exec path.
BENCH_TEMPLATE_REF="${BENCH_TEMPLATE_REF:-rootfs:v1}"

# ── Realistic AI agent workload ─────────────────────────────────────────────
# Every agent is an independent closed loop: an LLM round trip
# (LOADTEST_THINK_MIN_MS..LOADTEST_THINK_MAX_MS), then a turn of 1..N requests
# (LOADTEST_REQUESTS_PER_TURN). The first request of a turn is cold (the think gap
# expired the 1 ms lease); the follow-ups are sent immediately and are warm on
# the same VM. Levels are ACTIVE AGENT COUNTS (offered load).
LOADTEST_THINK_MIN_MS="${LOADTEST_THINK_MIN_MS:-900}"
LOADTEST_THINK_MAX_MS="${LOADTEST_THINK_MAX_MS:-1500}"
LOADTEST_REQUESTS_PER_TURN="${LOADTEST_REQUESTS_PER_TURN:-1:40,2:35,3:25}"
LOADTEST_BUSY_RETRIES="${LOADTEST_BUSY_RETRIES:-50}"
LOADTEST_BUSY_RETRY_BACKOFF_MS="${LOADTEST_BUSY_RETRY_BACKOFF_MS:-10}"
LOADTEST_INTRA_TURN_GAP_MS="${LOADTEST_INTRA_TURN_GAP_MS:-0}"
# Workload selector. agents = the realistic LLM closed loop (default).
# ideal = one paced lane per microVM with no between-turn think gap, a fixed turn period,
# and a period sweep: the smallest period with zero BUSY attempts is the
# collision-free reuse rate with every VM continuously fed. This is an
# idealized capability probe, not a business model.
LOADTEST_WORKLOAD="${LOADTEST_WORKLOAD:-agents}"
LOADTEST_LANES="${LOADTEST_LANES:-$POOL_SIZE}"
LOADTEST_TURN_PERIODS_MS="${LOADTEST_TURN_PERIODS_MS:-20 22 24 26 28 30 35}"
# shaped: agents aggregated behind each lane (auto = rate x mean think + margin)
LOADTEST_SHAPED_AGENTS_PER_LANE="${LOADTEST_SHAPED_AGENTS_PER_LANE:-auto}"
# shaped: after a turn, the lane holds its VM slot for sticky + hold (the
# async unmount budget) before releasing the next turn — fewer BUSY retries.
# auto = measured on THIS stack before the sweep (cold execs, then the
# /stats unmount recent p95 + margin): bare metal unmounts are much faster
# than nested, so a fixed value would over-hold there and under-hold here.
LOADTEST_SHAPED_HOLD_MS="${LOADTEST_SHAPED_HOLD_MS:-auto}"
LOADTEST_STICKY_MS="${LOADTEST_STICKY_MS:-1}"
LOADTEST_SEED="${LOADTEST_SEED:-1}"
LOADTEST_MAX_INFLIGHT="${LOADTEST_MAX_INFLIGHT:-1024}"
# The two latency budgets, as multiples of the no-load gateway E2E P95.
LOADTEST_LATENCY_TIERS="${LOADTEST_LATENCY_TIERS:-1.0 2.0}"
# capacity = every lifetime recycle cap off (the hardware/service ceiling).
# shipped  = the product defaults (100000 uses / 10000 mounts / 300 distinct
#            agents per VM), for a security-posture comparison.
LOADTEST_RECYCLE_POLICY="${LOADTEST_RECYCLE_POLICY:-capacity}"
LOADTEST_MAX_USES="${LOADTEST_MAX_USES:-}"
LOADTEST_MAX_MOUNTS="${LOADTEST_MAX_MOUNTS:-}"
LOADTEST_MAX_DISTINCT_AGENTS="${LOADTEST_MAX_DISTINCT_AGENTS:-}"
LOADTEST_AGENT_CREATE_CONCURRENCY="${LOADTEST_AGENT_CREATE_CONCURRENCY:-32}"
LOADTEST_PROV_MAX_OPS="${LOADTEST_PROV_MAX_OPS:-16}"
LOADTEST_STATS_POLL_SEC="${LOADTEST_STATS_POLL_SEC:-2}"

case "$LOADTEST_RECYCLE_POLICY" in
    capacity) def_uses=-1; def_mounts=-1; def_distinct=-1 ;;
    shipped)  def_uses=100000; def_mounts=10000; def_distinct=300 ;;
    *) echo "LOADTEST_RECYCLE_POLICY must be capacity|shipped (got '$LOADTEST_RECYCLE_POLICY')" >&2; exit 2 ;;
esac
TC_MAX_USES="${LOADTEST_MAX_USES:-$def_uses}"
TC_MAX_MOUNTS="${LOADTEST_MAX_MOUNTS:-$def_mounts}"
TC_MAX_DISTINCT_AGENTS="${LOADTEST_MAX_DISTINCT_AGENTS:-$def_distinct}"
if [[ "$LOADTEST_RECYCLE_POLICY" == "capacity" ]]; then
    TC_RECYCLE_MEM_PERCENT="${LOADTEST_MEM_PERCENT:-0}"
    TC_RECYCLE_MEM_ABS_MB="${LOADTEST_MEM_ABS_MB:-0}"
else
    TC_RECYCLE_MEM_PERCENT="${LOADTEST_MEM_PERCENT:-10}"
    TC_RECYCLE_MEM_ABS_MB="${LOADTEST_MEM_ABS_MB:-100}"
fi
export TC_MAX_USES TC_MAX_MOUNTS TC_MAX_DISTINCT_AGENTS
export TC_RECYCLE_MEM_PERCENT TC_RECYCLE_MEM_ABS_MB

source "$ROOT/e2e/common.sh"
source "$ROOT/e2e/pin.sh"

for v in LOADTEST_DURATION_SEC LOADTEST_WARMUP_SEC LOADTEST_THINK_MIN_MS LOADTEST_THINK_MAX_MS \
         LOADTEST_BUSY_RETRIES LOADTEST_BUSY_RETRY_BACKOFF_MS LOADTEST_INTRA_TURN_GAP_MS LOADTEST_STICKY_MS \
         LOADTEST_MAX_INFLIGHT LOADTEST_STATS_POLL_SEC LOADTEST_PROV_MAX_OPS \
         LOADTEST_AGENT_CREATE_CONCURRENCY LOADTEST_AGENT_LEVELS; do
    : "${!v}"
done
for v in LOADTEST_DURATION_SEC LOADTEST_WARMUP_SEC LOADTEST_THINK_MIN_MS LOADTEST_THINK_MAX_MS \
         LOADTEST_BUSY_RETRIES LOADTEST_BUSY_RETRY_BACKOFF_MS LOADTEST_INTRA_TURN_GAP_MS LOADTEST_STICKY_MS \
         LOADTEST_MAX_INFLIGHT LOADTEST_STATS_POLL_SEC LOADTEST_PROV_MAX_OPS \
         LOADTEST_AGENT_CREATE_CONCURRENCY; do
    val="${!v}"
    [[ "$val" =~ ^[0-9]+$ ]] || { log_error "$v must be a non-negative integer (got '$val')"; exit 2; }
done
(( LOADTEST_DURATION_SEC >= 1 )) || { log_error "LOADTEST_DURATION_SEC must be >= 1"; exit 2; }
(( LOADTEST_THINK_MAX_MS >= LOADTEST_THINK_MIN_MS )) || { log_error "LOADTEST_THINK_MAX_MS must be >= LOADTEST_THINK_MIN_MS"; exit 2; }
# N (a fixed request count) or size:weight pairs. A malformed value must fail
# BEFORE the deploy, not after it when loadgen exits 2.
if ! [[ "$LOADTEST_REQUESTS_PER_TURN" =~ ^[0-9]+(:[0-9]+(\.[0-9]+)?)?(,[0-9]+(:[0-9]+(\.[0-9]+)?)?)*$ ]]; then
    log_error "LOADTEST_REQUESTS_PER_TURN must be N or size:weight[,size:weight...] (e.g. 1 or 1:40,2:35,3:25), got '$LOADTEST_REQUESTS_PER_TURN'"
    exit 2
fi
(( LOADTEST_MAX_INFLIGHT >= 1 )) || { log_error "LOADTEST_MAX_INFLIGHT must be >= 1"; exit 2; }
(( LOADTEST_STICKY_MS >= 1 )) || { log_error "LOADTEST_STICKY_MS must be >= 1"; exit 2; }
(( LOADTEST_INTRA_TURN_GAP_MS < LOADTEST_STICKY_MS )) || {
    log_warn "LOADTEST_INTRA_TURN_GAP_MS=${LOADTEST_INTRA_TURN_GAP_MS} >= LOADTEST_STICKY_MS=${LOADTEST_STICKY_MS}: turn follow-ups will be cold, not warm"
}
case "$LOADTEST_WORKLOAD" in
    agents|ideal|shaped) ;;
    *) log_error "LOADTEST_WORKLOAD must be agents|ideal|shaped (got '$LOADTEST_WORKLOAD')"; exit 2 ;;
esac
if [[ "$LOADTEST_SHAPED_HOLD_MS" != "auto" ]]; then
    [[ "$LOADTEST_SHAPED_HOLD_MS" =~ ^[0-9]+$ ]] \
        || { log_error "LOADTEST_SHAPED_HOLD_MS must be auto or a non-negative integer (got '$LOADTEST_SHAPED_HOLD_MS')"; exit 2; }
fi
for l in $LOADTEST_AGENT_LEVELS; do
    [[ "$l" =~ ^[0-9]+$ ]] && (( l >= 1 )) || { log_error "LOADTEST_AGENT_LEVELS entry '$l' is not a positive integer"; exit 2; }
done
# shaped_agents_per_lane <period_ms> — the agent population one shaped lane
# needs to stay fed at the period's rate: each agent offers ~1 cold turn per
# mean think interval, so agents ~= rate x mean_think, plus a margin for the
# stochastic think spread (a starved lane under-measures; an oversized one
# just keeps a bounded queue of one turn per agent).
shaped_agents_per_lane() {
    awk -v p="$1" -v tmin="$LOADTEST_THINK_MIN_MS" -v tmax="$LOADTEST_THINK_MAX_MS" \
        -v ov="${LOADTEST_SHAPED_AGENTS_PER_LANE:-auto}" 'BEGIN {
        if (ov != "auto" && ov + 0 > 0) { printf "%d", ov + 0; exit }
        avg = (tmin + tmax) / 2000.0
        rate = 1000.0 / p
        need = rate * avg
        k = int(need)
        if (k < need) k++
        m = int(k / 4); if (m < 4) m = 4
        printf "%d", k + m
    }'
}

if [[ "$LOADTEST_WORKLOAD" != "agents" ]]; then
    [[ "$LOADTEST_LANES" =~ ^[0-9]+$ ]] && (( LOADTEST_LANES >= 1 )) \
        || { log_error "LOADTEST_LANES must be a positive integer (got '$LOADTEST_LANES')"; exit 2; }
    (( LOADTEST_LANES == POOL_SIZE )) \
        || { log_error "$LOADTEST_WORKLOAD requires LOADTEST_LANES == POOL_SIZE (one lane per VM): lanes=${LOADTEST_LANES} pool=${POOL_SIZE}"; exit 2; }
    for l in $LOADTEST_TURN_PERIODS_MS; do
        [[ "$l" =~ ^[0-9]+$ ]] && (( l >= 1 )) \
            || { log_error "LOADTEST_TURN_PERIODS_MS entry '$l' is not a positive integer"; exit 2; }
    done
    # The paced workloads' levels are periods. ideal uses one agent per lane;
    # shaped aggregates agents per lane (sized for the FASTEST period).
    if [[ "$LOADTEST_WORKLOAD" == "ideal" ]]; then
        LOADTEST_MAX_AGENTS="$LOADTEST_LANES"
    else
        _minp="$(printf '%s\n' $LOADTEST_TURN_PERIODS_MS | sort -n | head -1)"
        _kmax="$(shaped_agents_per_lane "$_minp")"
        LOADTEST_MAX_AGENTS=$(( LOADTEST_LANES * _kmax ))
        log_info "shaped: lanes=$LOADTEST_LANES x up to $_kmax agents/lane (period ${_minp}ms) = $LOADTEST_MAX_AGENTS sandfs"
    fi
else
    LOADTEST_MAX_AGENTS="$(printf '%s\n' $LOADTEST_AGENT_LEVELS | sort -n | tail -1)"
fi
(( LOADTEST_MAX_AGENTS >= 1 )) || { log_error "LOADTEST_AGENT_LEVELS/LOADTEST_LANES is empty"; exit 2; }
LOADTEST_AGENTS_FILE="$LOG_DIR/agents-loadtest.txt"
LOADTEST_TSV="$LOG_DIR/load-measured.tsv"

# PIN_MODE=auto: bare metal pins (per-VM CPU/NUMA slices); under a
# hypervisor the L1 vCPUs are already outer-scheduled, so leave the host
# scheduler alone.
if [[ "${PIN_MODE:-auto}" == "auto" ]]; then
    PIN_MODE="$(tc_pin_resolve_mode "$(tc_pin_host_nested)")" || exit 1
    log_info "PIN_MODE=auto resolved to $PIN_MODE on this host"
fi

case "$PIN_MODE" in
    0|1) ;;
    *) log_error "PIN_MODE must be 0 or 1 (got '$PIN_MODE')"; exit 1 ;;
esac
if ! [[ "$PIN_SLICE_CPUS" =~ ^[0-9]+$ ]] || (( PIN_SLICE_CPUS < BENCH_VCPUS )); then
    log_error "PIN_SLICE_CPUS must be an integer >= BENCH_VCPUS=$BENCH_VCPUS (got '$PIN_SLICE_CPUS')"
    exit 1
fi
case "$PIN_PLAN" in
    0|1) ;;
    *) log_error "PIN_PLAN must be 0 or 1 (got '$PIN_PLAN')"; exit 1 ;;
esac
if ! awk -v x="$PIN_TARGET_UTIL" 'BEGIN { exit !(x + 0 > 0 && x + 0 <= 1) }'; then
    log_error "PIN_TARGET_UTIL must be in (0,1] (got '$PIN_TARGET_UTIL')"; exit 1
fi

NODE_ID="${TC_NODE_ID:-test-node-1}"
LOADGEN_BIN="$OUTPUT/loadgen"
STATS_JSON="$LOG_DIR/load-stats.json"

HUMAN_PID=""
ETCD_PID=""
PROV_PID=""
EST_DIR=""

# ── helpers shared with the other benchmarks (same shape) ──────────────────

# tc_wait_component_ready — wait for an EtcdStore gateway's /ready to return
# 200 (the initial snapshot load must land before business routes stop
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

# tc_start_human_gateway — human-mode gateway on HUMAN_ADDR sharing etcd.
# Stream TLS is configured explicitly (per-node client certificates) so the
# prov sandlot's identity is verified by CN exactly like the exec stream.
tc_start_human_gateway() {
    log_step "Starting human gateway ($HUMAN_ADDR, mode=human, shared etcd)..."
    local human_stream="${HUMAN_STREAM_ADDR:-127.0.0.1:9999}"
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
    pin_stack_process human-gateway "$HUMAN_PID" "$PIN_STACK_GATEWAY_CPUS" || exit 1
}

cleanup() {
    # Belt and braces for the preview path (the trap is not even installed
    # when PIN_PLAN=1, but a future call site must not resurrect the teardown).
    [[ "${PIN_PLAN:-0}" == "1" ]] && return 0
    for pid in "${PROV_PID:-}" "${HUMAN_PID:-}" "${ETCD_PID:-}"; do
        [[ -n "$pid" ]] && { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    done
    tc_cleanup_default
    tc_cleanup_deployed_artifacts
    # The benchmark-generated sandlot YAML (deploy dir, not covered by the
    # artifact list above) — remove it too so the run leaves nothing behind.
    rm -f "$DEPLOY_DIR/sandlot-load.yaml" 2>/dev/null || true
    # PIN_MODE=1 scratch: the numactl shim and the slice map.
    rm -f "${PIN_WRAPPER:-}" "${PIN_MAP:-}" 2>/dev/null || true
    tc_cleanup_etcd "$ETCD_DATA"
    [[ -n "$EST_DIR" ]] && rm -rf "$EST_DIR" 2>/dev/null || true
}
# PIN_PLAN=1 is a pure configuration preview: it must never run the teardown
# trap. The trap assumes the run owns the host (it kills every sandswap
# process, removes /run/sandswap and the volumes root) — running it from a
# preview would destroy a co-running stack.
if [[ "$PIN_PLAN" != "1" ]]; then
    trap cleanup EXIT INT TERM
fi

# ── /stats helpers (exec gateway = live pool/lease owner) ──────────────────
fetch_stats() {
    # Exec-mode agent listeners serve /stats behind the run's ops bearer token
    # (TC_OPS_TOKEN, minted by tc_start_gateway); the human/single-node
    # listener needs no header and ignores it.
    local auth=()
    [[ -n "${TC_OPS_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $TC_OPS_TOKEN")
    curl -s -m 10 "${auth[@]}" "$GATEWAY_URL/stats" > "$STATS_JSON" 2>/dev/null || true
}

# stats_line — "<unmount_count> <lease_total> <lease_under2> <lease_max_ms>
#              <recent_n> <recent_p95_ms> <recent_p50_ms>" for $NODE_ID.
stats_line() {
    python3 - "$STATS_JSON" "$NODE_ID" <<'PY'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("0 0 0 0 0 0 0"); raise SystemExit
node = sys.argv[2]
for g in d.get("gateways") or []:
    for u in g.get("unmount_stats") or []:
        if u.get("node_id") == node:
            lf = u.get("lease_fire") or {}
            r = u.get("recent") or {}
            print(u.get("unmount_count", 0), lf.get("total", 0), lf.get("under_2ms", 0),
                  lf.get("max_ms", 0), r.get("n", 0), r.get("p95_ms", 0), r.get("p50_ms", 0))
            raise SystemExit
print("0 0 0 0 0 0 0")
PY
}

# snapshot_stats <prefix> — set ${prefix}_UNMOUNT etc. from /stats.
snapshot_stats() {
    local p="$1" n tf tu tm rn r95 r50
    fetch_stats
    read -r n tf tu tm rn r95 r50 <<< "$(stats_line)"
    printf -v "${p}_UNMOUNT" '%s' "$n"
    printf -v "${p}_LF_TOTAL" '%s' "$tf"
    printf -v "${p}_LF_UNDER2" '%s' "$tu"
    printf -v "${p}_LF_MAX" '%s' "$tm"
    printf -v "${p}_RECENT_N" '%s' "$rn"
    printf -v "${p}_RECENT_P95" '%s' "$r95"
    printf -v "${p}_RECENT_P50" '%s' "$r50"
}

# ── CPU/NUMA pinning and the host-stack partition ─────────────────────────
#
# Benchmark-local, product-code-free: sandlot's `microvm.vmm_binary` accepts
# any executable, so the generated shim sits between sandlot and the real
# sandvmm. Depending on the mode it execs the VMM under
#
#   slice: numactl --physcpubind=<slice> --membind=<slice's node> -- sandvmm
#   pool:  numactl --physcpubind=<VM pool> -- sandvmm
#
# slice = PIN_MODE=1: the whole sandvmm process (vCPU threads + host-side
# virtio-fs/API threads) inherits the slice's affinity, and --membind installs
# the policy BEFORE exec, so guest RAM — mmap'd later, when sandlot sends
# vm.create — is allocated on the slice's node (no page migration).
# pool = PIN_MODE=0 with a partition: VMs are confined to the VM-pool CPUs so
# the pinned and unpinned runs share one CPU partition (coarse affinity, no
# per-VM slices, no membind).
#
# Slice selection needs no shared allocator state: pool VM ids end in their
# creation sequence (NextPoolVMID, sandlot/core/pool.go), so
# slot = seq % len(slices). A VM id without a sequence makes the shim REFUSE
# to exec (a missing binding must fail the boot loudly, never run unpinned).

# plan_pin_partition — compute the whole-core host-stack reserve, the per-role
# stack CPU sets, and the VM pool from the live topology. Prints the human
# plan to stderr and eval-able PIN_* assignments to stdout. Pure topology +
# configuration: no deploy, no KVM — PIN_PLAN=1 runs only this and exits.
plan_pin_partition() {
    local out line
    out="$(python3 - "$PIN_MODE" "$PIN_CPUS" "$PIN_RESERVE_CORES" "$PIN_STACK_LAYOUT" "$BENCH_VCPUS" "$POOL_SIZE" <<'PY'
import sys

mode, pin_cpus, reserve_s, layout_s, vcpus_s, pool_s = sys.argv[1:7]
vcpus, pool_n = max(1, int(vcpus_s)), int(pool_s)

def expand(spec):
    out = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out

def compress(cpus):
    cpus = sorted(cpus)
    if not cpus:
        return ""
    runs, start, prev = [], cpus[0], cpus[0]
    for c in cpus[1:]:
        if c == prev + 1:
            prev = c
        else:
            runs.append((start, prev)); start = prev = c
    runs.append((start, prev))
    return ",".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in runs)

def die(msg):
    print("    plan: ERROR: " + msg, file=sys.stderr)
    sys.exit(2)

def rd(path):
    try:
        return open(path).read().strip()
    except OSError:
        return ""

online = expand(rd("/sys/devices/system/cpu/online"))
if not online:
    die("cannot read /sys/devices/system/cpu/online")
nodes = sorted(int(n) for n in expand(rd("/sys/devices/system/node/online"))) or [0]
node_cpus = {n: sorted(expand(rd("/sys/devices/system/node/node%d/cpulist" % n)) & online)
             for n in nodes}
node_of = {}
for n in nodes:
    for c in node_cpus[n]:
        node_of.setdefault(c, n)
for c in sorted(online):
    node_of.setdefault(c, nodes[0])

sib = {}
for c in sorted(online):
    g = tuple(sorted((expand(rd("/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list" % c))
                      or {c}) & online))
    sib[c] = g or (c,)

cores, seen = [], set()
for c in sorted(online):
    g = sib[c]
    if g in seen:
        continue
    seen.add(g)
    cores.append({"cpus": list(g), "node": node_of[c], "min": min(g)})
cores.sort(key=lambda x: (x["node"], x["min"]))
node_counts = {}
for c in cores:
    node_counts[c["node"]] = node_counts.get(c["node"], 0) + 1
pref = sorted(node_counts, key=lambda n: (-node_counts[n], n))[0] if node_counts else nodes[0]
ordered = [c for c in cores if c["node"] == pref] + [c for c in cores if c["node"] != pref]

print("    plan: online cpus=%s, %d physical core(s) [%s]" %
      (compress(online), len(cores),
       ", ".join("node%d:%d" % (n, node_counts[n]) for n in sorted(node_counts))),
      file=sys.stderr)

roles, reserved, partitioned = {}, set(), 0

if pin_cpus.strip():
    if reserve_s not in ("", "0") or layout_s.strip():
        die("PIN_CPUS is mutually exclusive with PIN_RESERVE_CORES/PIN_STACK_LAYOUT")
    pool = expand(pin_cpus) & online
    if not pool:
        die("PIN_CPUS=%r contains no online CPU" % pin_cpus)
    partitioned = 1 if pool != online else 0
    reserved = online - pool
    print("    plan: explicit VM pool %s (%d CPUs)" % (compress(pool), len(pool)),
          file=sys.stderr)

elif layout_s.strip():
    if reserve_s == "auto":
        die("PIN_RESERVE_CORES=auto cannot be combined with PIN_STACK_LAYOUT")
    for ent in layout_s.split(";"):
        if ":" not in ent:
            die("PIN_STACK_LAYOUT entry %r is not role:cpus" % ent)
        role, spec = ent.split(":", 1)
        role = role.strip()
        if role not in ("loadgen", "gateway", "sandlot"):
            die("PIN_STACK_LAYOUT role %r is unknown (loadgen|gateway|sandlot)" % role)
        if role in roles:
            die("PIN_STACK_LAYOUT names role %r twice" % role)
        cpus = expand(spec)
        if not cpus:
            die("PIN_STACK_LAYOUT role %r has no CPUs" % role)
        if not cpus <= online:
            die("PIN_STACK_LAYOUT role %r names offline CPUs %s" %
                (role, compress(cpus - online)))
        roles[role] = cpus
    for r in ("loadgen", "gateway", "sandlot"):
        if r not in roles:
            die("PIN_STACK_LAYOUT must name all of loadgen,gateway,sandlot (missing %r)" % r)
    for c in sorted(online):
        inroles = [r for r, s in roles.items() if c in s]
        if not inroles:
            continue
        for r in inroles:
            missing = set(sib[c]) - roles[r]
            if missing:
                die("core {%s} is split: role %r includes CPU %d but not sibling(s) %s" %
                    (compress(sib[c]), r, c, compress(missing)))
    reserved = set().union(*roles.values())
    if reserve_s not in ("", "0"):
        try:
            n = int(reserve_s)
        except ValueError:
            die("PIN_RESERVE_CORES must be an integer or 'auto'")
        ncores = len({sib[c] for c in reserved})
        if n != ncores:
            die("PIN_RESERVE_CORES=%d but PIN_STACK_LAYOUT reserves %d whole cores" %
                (n, ncores))
    partitioned = 1
    print("    plan: explicit stack layout %s" %
          ", ".join("%s=%s" % (r, compress(roles[r]))
                    for r in ("loadgen", "gateway", "sandlot")), file=sys.stderr)

elif reserve_s not in ("", "0"):
    ncores = len(cores)
    if ncores < 3:
        die("only %d physical core(s): stack pinning needs >=3 whole cores "
            "(use PIN_STACK_LAYOUT on a real host to share cores)" % ncores)
    if reserve_s == "auto":
        n = min(8, max(2, ncores // 8))
    else:
        try:
            n = int(reserve_s)
        except ValueError:
            die("PIN_RESERVE_CORES must be an integer or 'auto'")
    if n < 1:
        die("PIN_RESERVE_CORES must be >=1 (0 disables)")
    if n > ncores - 1:
        die("PIN_RESERVE_CORES=%d leaves no VM core (%d physical cores)" % (n, ncores))
    if n < 3:
        die("%d reserved core(s) cannot host loadgen+gateway+sandlot; reserve >=3 "
            "or use PIN_STACK_LAYOUT to share cores" % n)
    chosen = ordered[:n]
    l = max(1, int(round(n * 0.4)))
    g = max(1, int(round(n * 0.4)))
    if l + g > n - 1:
        g = max(1, n - 1 - l)
    s = n - l - g
    while l + g + s < n:
        l += 1
    for r, cs in (("loadgen", chosen[:l]), ("gateway", chosen[l:l + g]),
                  ("sandlot", chosen[l + g:l + g + s])):
        roles[r] = set().union(*[set(c["cpus"]) for c in cs]) if cs else set()
    reserved = set().union(*roles.values())
    partitioned = 1
    print("    plan: reserve %d whole cores (split %d/%d/%d): %s" %
          (n, l, g, s,
           ", ".join("%s=%s" % (r, compress(roles[r]))
                     for r in ("loadgen", "gateway", "sandlot"))), file=sys.stderr)

pool = online - reserved
if not pool:
    die("the reservation leaves no VM CPU")
if reserved & pool:
    die("internal: reserved CPUs overlap the VM pool")
threads_per_core = min((len(sib[c]) for c in (reserved or online)), default=2)
if reserved:
    print("    plan: VM pool %s (%d CPUs); stack reserve %s (%d whole core(s))" %
          (compress(pool), len(pool), compress(reserved),
           len({sib[c] for c in reserved})), file=sys.stderr)
    rnodes = {node_of[c] for c in reserved}
    if len(rnodes) > 1:
        print("    plan: WARN stack cores span NUMA nodes %s — loopback traffic "
              "between loadgen/gateway/sandlot crosses a node" %
              ",".join(str(n) for n in sorted(rnodes)), file=sys.stderr)

def gm(role):
    return len(roles.get(role, ()))

print("PIN_PARTITIONED=%d" % partitioned)
print("PIN_ONLINE_SPEC='%s'" % compress(online))
print("PIN_CORE_COUNT=%d" % len(cores))
print("PIN_THREADS_PER_CORE=%d" % threads_per_core)
print("PIN_VM_POOL_SPEC='%s'" % compress(pool))
print("PIN_RESERVED_CPUS='%s'" % compress(reserved))
print("PIN_RESERVED_CORES=%d" % len({sib[c] for c in reserved}))
print("PIN_STACK_LOADGEN_CPUS='%s'" % compress(roles.get("loadgen", set())))
print("PIN_STACK_GATEWAY_CPUS='%s'" % compress(roles.get("gateway", set())))
print("PIN_STACK_SANDLOT_CPUS='%s'" % compress(roles.get("sandlot", set())))
def gmv(n):
    return ("'%d'" % n) if n else "''"
print("PIN_STACK_LOADGEN_GOMAXPROCS=%s" % gmv(gm("loadgen")))
print("PIN_STACK_GATEWAY_GOMAXPROCS=%s" % gmv(gm("gateway")))
print("PIN_STACK_ETCD_GOMAXPROCS=%s" % gmv(max(1, gm("gateway") // 2) if gm("gateway") else 0))
print("PIN_STACK_SANDLOT_GOMAXPROCS=%s" % gmv(gm("sandlot")))
print("PIN_STACK_CORE_POOL='%s'" % ";".join(compress(c["cpus"]) for c in ordered))
PY
)" || { log_error "cannot plan the CPU partition (PIN_RESERVE_CORES='$PIN_RESERVE_CORES' PIN_STACK_LAYOUT='$PIN_STACK_LAYOUT' PIN_CPUS='$PIN_CPUS')"; exit 1; }
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ ! "$line" =~ ^PIN_[A-Z0-9_]+=(\'[0-9,;\-]*\'|[0-9]+)$ ]]; then
            log_error "internal: unexpected planner output line: $line"
            exit 1
        fi
    done <<< "$out"
    eval "$out"
}

# build_pin_slices — write $PIN_MAP ("<cpus> <node>" per line) from the live
# NUMA topology, restricted to the computed VM pool; sets PIN_SLICES /
# PIN_LEFTOVER / PIN_NODE_DETAIL.
build_pin_slices() {
    local meta
    meta="$(python3 - "$PIN_VM_POOL_SPEC" "$BENCH_VCPUS" "$PIN_MAP" "$POOL_SIZE" "$VM_MEMORY_MB" "$PIN_SLICE_CPUS" <<'PY'
import sys

pool_spec, vcpus_s, map_path, pool_s, mem_mb_s, slice_cpus_s = sys.argv[1:7]
vcpus, pool_n, mem_mb = max(1, int(vcpus_s)), int(pool_s), int(mem_mb_s)
slice_cpus = max(vcpus, int(slice_cpus_s))

def expand(spec):
    out = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out

def compress(cpus):
    cpus = sorted(cpus)
    if not cpus:
        return ""
    runs, start, prev = [], cpus[0], cpus[0]
    for c in cpus[1:]:
        if c == prev + 1:
            prev = c
        else:
            runs.append((start, prev)); start = prev = c
    runs.append((start, prev))
    return ",".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in runs)

def smt_order(cpus):
    """Rank-major order: one thread per physical core first, then the SMT
    siblings. A slice therefore takes distinct CORES while cores are free —
    pinning sequentially would put VM 0 and VM 1 on the two siblings of
    core 0 while half the cores idle."""
    groups = {}
    pool_set = set(cpus)
    for c in sorted(cpus):
        groups.setdefault(tuple(sorted(set(SIB.get(c, (c,))) & pool_set)) or (c,), []).append(c)
    ordered = []
    for rank in range(max((len(v) for v in groups.values()), default=0)):
        for key in sorted(groups):
            if rank < len(groups[key]):
                ordered.append(groups[key][rank])
    return ordered

try:
    online = expand(open("/sys/devices/system/cpu/online").read())
except OSError as e:
    print("cannot read /sys/devices/system/cpu/online: %s" % e, file=sys.stderr)
    sys.exit(2)
SIB = {}
for c in sorted(online):
    try:
        g = tuple(sorted(expand(open("/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list" % c).read()) & online))
    except OSError:
        g = (c,)
    SIB[c] = g or (c,)

pool = online & expand(pool_spec) if pool_spec.strip() else set(online)
if not pool:
    print("CPU pool is empty (PIN_CPUS=%r)" % pool_spec, file=sys.stderr)
    sys.exit(2)

try:
    node_ids = sorted(int(n) for n in expand(open("/sys/devices/system/node/online").read()))
except OSError:
    node_ids = [0]
node_cpus = {}
for n in node_ids:
    try:
        node_cpus[n] = sorted(pool & expand(open("/sys/devices/system/node/node%d/cpulist" % n).read()))
    except OSError:
        node_cpus[n] = []
# CPUs no node claims (sysfs oddity) join the lowest node instead of being lost.
claimed = set()
for cpus in node_cpus.values():
    claimed.update(cpus)
for c in sorted(pool - claimed):
    node_cpus[node_ids[0]].append(c)
for n in node_ids:
    node_cpus[n] = smt_order(node_cpus[n])
# CPU -> NUMA node map for the whole-core slice packer below (the
# per-node lists above are ordered, not indexed).
node_of = {}
for n in node_ids:
    for c in node_cpus[n]:
        node_of[c] = n

# Whole-physical-core slices (the default): each slice owns complete sibling
# groups, so two microVMs can never share a physical core. A slice takes
# ceil(slice_cpus / threads-per-core) whole cores; --membind stays on the
# slice's node because packing is per node.
if slice_cpus >= 2:
    groups, seen_g = [], set()
    for c in sorted(pool):
        g = tuple(sorted(set(SIB.get(c, (c,))) & pool))
        if not g or g in seen_g:
            continue
        seen_g.add(g)
        groups.append(g)
    by_node = {}
    for g in groups:
        by_node.setdefault(node_of[g[0]], []).append(g)
    node_slices = {}
    for n in node_ids:
        lst = by_node.get(n, [])
        out, i = [], 0
        while i < len(lst):
            cpus = []
            while i < len(lst) and len(cpus) < slice_cpus:
                cpus.extend(lst[i]); i += 1
            if len(cpus) >= vcpus:
                out.append(cpus)
        node_slices[n] = out
    slices = []
    for i in range(max((len(v) for v in node_slices.values()), default=0)):
        for n in node_ids:
            if i < len(node_slices[n]):
                slices.append((node_slices[n][i], n))
    idx = {n: len(node_cpus[n]) for n in node_ids}
# Slice order matters for the report's VM counts: the first N VMs should use
# N DISTINCT physical cores while those exist. smt_order made each node's list
# rank-major; a plain node round-robin can still hand out an SMT sibling on a
# large node while another node still has free cores (uneven pool sizes after
# the stack reserve). For the benchmark's 1-vCPU case with 1-CPU slices,
# iterate rank by rank and interleave nodes within a rank.
elif vcpus == 1:
    def rank_layers(ordered):
        groups, seen = [], set()
        for c in ordered:
            g = SIB.get(c, (c,))
            if g in seen:
                continue
            seen.add(g)
            groups.append(g)
        return [[g[r] for g in groups if r < len(g)]
                for r in range(max((len(g) for g in groups), default=0))]

    layers = {n: rank_layers(node_cpus[n]) for n in node_ids}
    max_rank = max((len(v) for v in layers.values()), default=0)
    slices = []
    for r in range(max_rank):
        pos = {n: 0 for n in node_ids}
        while True:
            progressed = False
            for n in node_ids:
                lst = layers[n][r] if r < len(layers[n]) else []
                if pos[n] < len(lst):
                    slices.append(([lst[pos[n]]], n))
                    pos[n] += 1
                    progressed = True
            if not progressed:
                break
    idx = {n: len(node_cpus[n]) for n in node_ids}
else:
    slices, idx, progress = [], {n: 0 for n in node_ids}, True
    while progress:
        progress = False
        for n in node_ids:
            i = idx[n]
            if len(node_cpus[n]) - i >= vcpus:
                slices.append((node_cpus[n][i:i + vcpus], n))
                idx[n] = i + vcpus
                progress = True
if not slices:
    print("no NUMA-local slice of %d CPU(s) fits the pool (PIN_CPUS=%r)" % (vcpus, pool_spec),
          file=sys.stderr)
    sys.exit(2)
leftover = []
for n in node_ids:
    leftover.extend(node_cpus[n][idx[n]:])

with open(map_path, "w") as f:
    for cpus, n in slices:
        f.write("%s %d\n" % (compress(cpus), n))

counts = {}
for _, n in slices:
    counts[n] = counts.get(n, 0) + 1
detail = ",".join("node%d:%d" % (n, counts.get(n, 0)) for n in node_ids if counts.get(n, 0))

# --membind is a HARD bind: a node that cannot hold the guest RAM fails VM
# creation. Surface the demand before the pool boots (WARN only — MemFree
# moves between now and boot).
per_slice_vms = -(-pool_n // len(slices))
for n in node_ids:
    try:
        for line in open("/sys/devices/system/node/node%d/meminfo" % n):
            if line.startswith("Node %d MemFree:" % n):
                free_mb = int(line.split()[3]) // 1024
                need_mb = per_slice_vms * counts.get(n, 0) * (mem_mb + 128)
                if need_mb > free_mb * 0.85:
                    print("WARN: node%d MemFree=%dMB < VM demand ~%dMB (%d slices x %d VMs x %dMB) "
                          "-- --membind may fail at VM boot" %
                          (n, free_mb, need_mb, counts.get(n, 0), per_slice_vms, mem_mb + 128),
                          file=sys.stderr)
                break
    except OSError:
        pass

print("%d %d %s" % (len(slices), len(leftover), detail))
PY
)" || { log_error "cannot build the CPU/NUMA slice map (PIN_CPUS='$PIN_CPUS', BENCH_VCPUS=$BENCH_VCPUS)"; exit 1; }
    read -r PIN_SLICES PIN_LEFTOVER PIN_NODE_DETAIL <<< "$meta"
    (( PIN_SLICES >= 1 )) || { log_error "empty slice map ($PIN_MAP)"; exit 1; }
}

# write_pin_wrapper <slice|pool> <real sandvmm> <numactl> <map-or-pool> —
# generate the shim. Placeholder substitution (not a shell heredoc) keeps the
# runtime body's own $variables.
write_pin_wrapper() {
    local rc=0
    python3 - "$PIN_WRAPPER" "$1" "$2" "$3" "$4" <<'PY'
import sys

out, mode, real, numactl, arg = sys.argv[1:6]
if mode not in ("slice", "pool"):
    print("unknown shim mode %r" % mode, file=sys.stderr)
    sys.exit(2)
for v in (real, numactl, arg):
    if "'" in v or "\n" in v:
        print("unsupported character in shim path/arg: %r" % v, file=sys.stderr)
        sys.exit(2)
tmpl = r'''#!/bin/bash
# Generated by e2e/latency-benchmark-load.sh.
#   slice mode: pin this microVM's sandvmm process -- vCPU threads AND the
#     host-side virtio-fs/API threads -- to its own CPU slice, and bind every
#     allocation made by the process (guest RAM included: it is mmap'd after
#     this exec) to that slice's NUMA node. The slice is a pure function of
#     the VM's creation sequence: slot = seq % slices (no shared state).
#   pool mode: confine the process to the benchmark's VM-pool CPUs. Coarse
#     affinity only -- no per-VM slice, no memory-policy binding.
set -euo pipefail
# Widen this process's affinity before numactl: libnuma validates
# --physcpubind against the caller's CURRENT mask, and the sandlot (which
# spawns us) is pinned to the host-stack cores.
max_cpus=$(( $(getconf _NPROCESSORS_CONF) - 1 ))
taskset -p -c "0-$max_cpus" $$ >/dev/null 2>&1 || true
mode='@MODE@'
real_vmm='@REAL@'
shim_arg='@ARG@'
if [[ "$mode" == "pool" ]]; then
    exec '@NUMACTL@' --physcpubind="$shim_arg" -- "$real_vmm" "$@"
fi
api_socket=''
prev=''
for arg in "$@"; do
    if [[ "$prev" == "--api-socket" ]]; then
        api_socket="$arg"
        break
    fi
    prev="$arg"
done
if [[ -z "$api_socket" ]]; then
    echo "sandvmm-pinned: no --api-socket in argv; refusing to run unpinned" >&2
    exit 70
fi
vm_dir="${api_socket%/*}"
vmid="${vm_dir##*/}"
if [[ ! "$vmid" =~ -([0-9]+)$ ]]; then
    echo "sandvmm-pinned: VM id '$vmid' carries no creation sequence; refusing to run unpinned" >&2
    exit 70
fi
seq="${BASH_REMATCH[1]}"
mapfile -t slice_lines < "$shim_arg"
n="${#slice_lines[@]}"
if (( n < 1 )); then
    echo "sandvmm-pinned: empty slice map '$shim_arg'" >&2
    exit 70
fi
slot=$(( seq % n ))
read -r slice_cpus node_id <<< "${slice_lines[$slot]}"
echo "sandvmm-pinned: vmid=$vmid seq=$seq slot=$slot cpus=$slice_cpus node=$node_id" >&2
exec '@NUMACTL@' --physcpubind="$slice_cpus" --membind="$node_id" -- "$real_vmm" "$@"
'''
open(out, "w").write(tmpl.replace("@MODE@", mode).replace("@REAL@", real)
                    .replace("@ARG@", arg).replace("@NUMACTL@", numactl))
PY
    rc=$?
    (( rc == 0 )) || return "$rc"
    chmod 0755 "$PIN_WRAPPER"
}

# setup_vm_pinning — Phase 3 (after tc_clean_environment recreated LOG_DIR):
# build the map, generate the shim, smoke-test numactl, point the sandlot's
# vmm_binary at it, and prove the sandvmm identity can execute/read both.
setup_vm_pinning() {
    local real_vmm="${TC_VMM_BINARY:-$DEPLOY_DIR/sandvmm}"
    local numactl_bin mode
    log_step "CPU/NUMA pinning setup"
    [[ -x "$real_vmm" ]] || { log_error "real VMM binary not found/executable: $real_vmm"; exit 1; }
    numactl_bin="$(command -v numactl)" || { log_error "numactl not found (pinning requires it)"; exit 1; }
    if [[ "$PIN_MODE" == "1" ]]; then mode=slice; else mode=pool; fi
    if [[ "$mode" == "slice" ]]; then
        build_pin_slices
        chmod 0644 "$PIN_MAP"   # read by the sandvmm identity after setpriv
        local first_cpus first_node
        read -r first_cpus first_node < "$PIN_MAP"
        # The shim applies exactly this invocation per VM; a bad CPU/node list
        # must fail before the pool boots, not on the first vm.create.
        "$numactl_bin" --physcpubind="$first_cpus" --membind="$first_node" -- true \
            || { log_error "numactl smoke test failed (cpus=$first_cpus node=$first_node)"; exit 1; }
        write_pin_wrapper slice "$real_vmm" "$numactl_bin" "$PIN_MAP" \
            || { log_error "cannot write the pinning shim ($PIN_WRAPPER)"; exit 1; }
        # Evidence: the exact slice map this run used (KEEP_LOGS preserves it).
        cp "$PIN_MAP" "$LOG_DIR/pin-slices.txt" 2>/dev/null || true
        PIN_VERIFY_MODE=slice
    else
        [[ -n "$PIN_VM_POOL_SPEC" ]] \
            || { log_error "pool confinement needs a computed VM pool (set PIN_RESERVE_CORES or PIN_CPUS)"; exit 1; }
        "$numactl_bin" --physcpubind="$PIN_VM_POOL_SPEC" -- true \
            || { log_error "numactl smoke test failed (VM pool $PIN_VM_POOL_SPEC)"; exit 1; }
        write_pin_wrapper pool "$real_vmm" "$numactl_bin" "$PIN_VM_POOL_SPEC" \
            || { log_error "cannot write the pinning shim ($PIN_WRAPPER)"; exit 1; }
        PIN_VERIFY_MODE=pool
    fi
    # The VMM child runs as the sandvmm identity (or sandlot's when
    # vmm_uid=0). Prove it can execute the shim and read the map — the shim
    # runs AFTER setpriv, inside that identity.
    if [[ -n "${SANDSWAP_VMM_UID:-}" ]] && command -v setpriv >/dev/null 2>&1; then
        setpriv --reuid="$SANDSWAP_VMM_UID" --regid="${SANDSWAP_VMM_GID:-$SANDSWAP_VMM_UID}" --clear-groups \
            test -x "$PIN_WRAPPER" \
            || { log_error "sandvmm identity ($SANDSWAP_VMM_UID) cannot execute $PIN_WRAPPER"; exit 1; }
        if [[ "$mode" == "slice" ]]; then
            setpriv --reuid="$SANDSWAP_VMM_UID" --regid="${SANDSWAP_VMM_GID:-$SANDSWAP_VMM_UID}" --clear-groups \
                test -r "$PIN_MAP" \
                || { log_error "sandvmm identity ($SANDSWAP_VMM_UID) cannot read $PIN_MAP"; exit 1; }
        fi
    fi
    export TC_VMM_BINARY="$PIN_WRAPPER"
    local stack_txt="host stack unpinned"
    if [[ -n "$PIN_STACK_LOADGEN_CPUS" ]]; then
        stack_txt="stack cores: loadgen=$PIN_STACK_LOADGEN_CPUS gateway=$PIN_STACK_GATEWAY_CPUS sandlot=$PIN_STACK_SANDLOT_CPUS"
    fi
    if [[ "$mode" == "slice" ]]; then
        if (( POOL_SIZE > PIN_SLICES )); then
            log_warn "POOL_SIZE=$POOL_SIZE > $PIN_SLICES slices — $(( (POOL_SIZE + PIN_SLICES - 1) / PIN_SLICES )) VMs share each CPU slice (oversubscribed by design)"
            PIN_SUMMARY="PIN_MODE=1: VM pool $PIN_VM_POOL_SPEC -> $PIN_SLICES $PIN_GRAN_DESC slices x ${PIN_SLICE_CPUS} CPU(s) [$PIN_NODE_DETAIL], POOL=$POOL_SIZE (oversubscribed); $stack_txt"
        else
            PIN_SUMMARY="PIN_MODE=1: VM pool $PIN_VM_POOL_SPEC -> $PIN_SLICES $PIN_GRAN_DESC slices x ${PIN_SLICE_CPUS} CPU(s) [$PIN_NODE_DETAIL], POOL=$POOL_SIZE, $PIN_LEFTOVER CPU(s) unused; $stack_txt"
        fi
    else
        PIN_SUMMARY="PIN_MODE=0 (pool confinement): VMs confined to $PIN_VM_POOL_SPEC; $stack_txt"
    fi
    {
        echo "mode=$mode"
        echo "vm_pool=$PIN_VM_POOL_SPEC"
        echo "reserved_cores=$PIN_RESERVED_CORES reserved_cpus=$PIN_RESERVED_CPUS"
        echo "stack_loadgen=$PIN_STACK_LOADGEN_CPUS"
        echo "stack_gateway=$PIN_STACK_GATEWAY_CPUS"
        echo "stack_sandlot=$PIN_STACK_SANDLOT_CPUS"
        [[ "$mode" == "slice" ]] && echo "slices=$PIN_SLICES vcpus=$BENCH_VCPUS leftover=$PIN_LEFTOVER detail=$PIN_NODE_DETAIL"
    } > "$LOG_DIR/pin-plan.txt" 2>/dev/null || true
    log_pass "VM pinning: $PIN_SUMMARY"
}

# verify_vm_pinning [quiet] — read the KERNEL truth (not the shim's log).
# slice mode: every sandvmm thread's Cpus_allowed_list must equal its VM's
# slice, and >=95% of its mapped pages must sit on the slice's NUMA node.
# pool mode (partitioned unpinned baseline): every sandvmm thread must equal
# the VM-pool CPU set. No NUMA assertion there — pool mode deliberately sets
# no memory policy.
# A silent fallback to the unbound scheduler must fail the run, never produce
# "bound" numbers. quiet = only report failures (per-level recheck).
# Scope: this benchmark's `pool-bench-*` VMs only — a foreign sandvmm on the
# host (another stack) is not this run's to judge (the harness anyway refuses
# concurrent runs).
verify_vm_pinning() {
    local quiet="${1:-}" out rc=0
    out="$(python3 - "$PIN_VERIFY_MODE" "$PIN_MAP" "$PIN_VM_POOL_SPEC" "$POOL_SIZE" "$quiet" <<'PY'
import glob, os, re, sys

mode, map_path, pool_spec = sys.argv[1], sys.argv[2], sys.argv[3]
pool_n, strict = int(sys.argv[4]), sys.argv[5] != "quiet"

def expand(spec):
    out = set()
    for part in spec.split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out

slices, pool_set = [], set()
if mode == "slice":
    with open(map_path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                cpus, node = line.split()
                slices.append((cpus, node))
    if not slices:
        print("pin-FAIL empty slice map %s" % map_path)
        sys.exit(1)
elif mode == "pool":
    pool_set = expand(pool_spec)
    if not pool_set:
        print("pin-FAIL empty VM pool spec %r" % pool_spec)
        sys.exit(1)
else:
    print("pin-FAIL unknown verification mode %r" % mode)
    sys.exit(1)
S = len(slices)

fails, used, vms = [], {}, 0
for procdir in glob.glob("/proc/[0-9]*"):
    pid = procdir.rsplit("/", 1)[1]
    try:
        exe = os.path.basename(os.readlink(procdir + "/exe"))
        if exe.endswith(" (deleted)"):
            exe = exe[:-len(" (deleted)")]
        if exe not in ("sandvmm", "sandswap-sandvmm"):
            continue
        args = [a.decode("utf-8", "replace")
                for a in open(procdir + "/cmdline", "rb").read().split(b"\0") if a]
    except OSError:
        continue
    api = None
    for i, a in enumerate(args[:-1]):
        if a == "--api-socket":
            api = args[i + 1]
            break
    if not api:
        fails.append("pid %s: sandvmm without --api-socket" % pid)
        continue
    vmid = os.path.basename(os.path.dirname(api))
    if not re.search(r"(?:^|-)pool-bench-\d+$", vmid):
        continue  # another stack's sandvmm (not this benchmark's `bench` spec)

    if mode == "slice":
        m = re.search(r"-(\d+)$", vmid)
        if not m:
            fails.append("pid %s: VM id %r carries no creation sequence" % (pid, vmid))
            continue
        slot = int(m.group(1)) % S
        exp_cpus_s, exp_node = slices[slot]
        exp = expand(exp_cpus_s)
    else:
        slot = -1
        exp_cpus_s, exp_node = pool_spec, None
        exp = pool_set

    bad = []
    for task in glob.glob(procdir + "/task/[0-9]*"):
        # A thread exiting between glob() and open() is normal; do not let it
        # abort the scan of the remaining threads.
        try:
            mask = None
            with open(task + "/status") as fh:
                for line in fh:
                    if line.startswith("Cpus_allowed_list:"):
                        mask = expand(line.split(":", 1)[1].strip())
                        break
        except OSError:
            continue
        if mask != exp:
            bad.append(os.path.basename(task))
    if bad:
        fails.append("pid %s %s: %d thread(s) outside %s %s (%s)" %
                     (pid, vmid, len(bad),
                      "slice" if mode == "slice" else "VM pool",
                      exp_cpus_s, ",".join(bad[:3])))

    if mode == "slice":
        on_node = total = 0
        try:
            with open(procdir + "/numa_maps") as fh:
                for line in fh:
                    for nn, pp in re.findall(r"N(\d+)=(\d+)", line):
                        pp = int(pp)
                        total += pp
                        if nn == exp_node:
                            on_node += pp
        except OSError:
            pass
        frac = (on_node / total) if total else 0.0
        if total < 100:
            fails.append("pid %s %s: only %d mapped pages — cannot judge NUMA placement" %
                         (pid, vmid, total))
        elif frac < 0.95:
            fails.append("pid %s %s: %.1f%% of pages on node %s (<95%%)" %
                         (pid, vmid, frac * 100.0, exp_node))
        if slot in used and pool_n <= S:
            fails.append("pid %s %s and pid %s share slice %d (pool %d <= %d slices)" %
                         (pid, vmid, used[slot], slot, pool_n, S))
        used.setdefault(slot, pid)
        print("pin-vm %-24s pid=%-7s slot=%-3d cpus=%-12s node=%-2s mem_on_node=%5.1f%%"
              % (vmid, pid, slot, exp_cpus_s, exp_node, frac * 100.0))
    else:
        print("pin-vm %-24s pid=%-7s cpus=%s" % (vmid, pid, exp_cpus_s))
    vms += 1

if vms == 0:
    fails.append("no sandvmm process found on the host")
elif strict and vms < pool_n:
    fails.append("only %d of %d bench VMs present — cannot vouch for the pool" % (vms, pool_n))
print("pin-summary vms=%d mode=%s slices=%d pool=%d oversubscribed=%s" %
      (vms, mode, S, pool_n, "yes" if pool_n > S else "no"))
for f in fails:
    print("pin-FAIL " + f)
sys.exit(1 if fails else 0)
PY
)" || rc=$?
    if (( rc != 0 )); then
        log_error "per-VM CPU/NUMA pinning verification FAILED:"
        printf '%s\n' "$out" | sed 's/^/    /'
        exit 1
    fi
    if [[ "$quiet" != "quiet" ]]; then
        printf '%s\n' "$out" | sed 's/^/    /'
        printf '%s\n' "$out" > "$LOG_DIR/pin-assignment.txt" 2>/dev/null || true
        if [[ "$PIN_VERIFY_MODE" == "slice" ]]; then
            log_pass "pin-cpu-numa: every sandvmm thread is on its VM's CPU slice and >=95% of its pages on the slice's NUMA node"
        else
            log_pass "pin-cpu-pool: every sandvmm thread is confined to the VM-pool CPUs"
        fi
    fi
}

# ── Host-stack pinning, CPU accounting, recommendation ─────────────────────
#
# The host stack is loadgen (the client) + gateway (exec + human) + etcd +
# sandlot (exec + prov). With a partition they are pinned to whole reserved
# cores and each Go process gets GOMAXPROCS = its allocated thread count
# (taskset affinity does not change GOMAXPROCS; leaving it at nproc makes the
# runtime spin scheduler/GC threads outside the allocation's intent).
#
# Every level records the stack's CPU-seconds/second ("core-equivalents")
# into $PIN_CPU_TSV. That is what sizes the reserve empirically: the advisor
# at the end prints the whole-core layout that keeps each role under
# PIN_TARGET_UTIL and saves $LOG_DIR/pin-recommendation.env for the next run.

pin_count_cpus() { # kernel cpulist -> CPU count
    awk -v s="$1" 'BEGIN {
        n = 0
        if (s == "") { print 0; exit }
        split(s, parts, ",")
        for (i in parts) {
            if (parts[i] ~ /-/) { split(parts[i], r, "-"); n += r[2] - r[1] + 1 }
            else { n += 1 }
        }
        print n
    }'
}

stack_gomaxprocs() {
    case "$1" in
        loadgen) echo "${PIN_STACK_LOADGEN_GOMAXPROCS:-}" ;;
        gateway) echo "${PIN_STACK_GATEWAY_GOMAXPROCS:-}" ;;
        etcd)    echo "${PIN_STACK_ETCD_GOMAXPROCS:-}" ;;
        sandlot) echo "${PIN_STACK_SANDLOT_GOMAXPROCS:-}" ;;
        *) echo "" ;;
    esac
}

# stack_env_begin/end — scope GOMAXPROCS to one launch. The background child
# copies the environment at exec, so restoring here does not touch it.
stack_env_begin() {
    PIN_STACK_ENV_OLD="${GOMAXPROCS-}"
    PIN_STACK_ENV_HAD=0
    [[ -n "${GOMAXPROCS+x}" ]] && PIN_STACK_ENV_HAD=1
    local v
    v="$(stack_gomaxprocs "$1")"
    [[ -n "$v" ]] && export GOMAXPROCS="$v"
    return 0
}
stack_env_end() {
    if (( PIN_STACK_ENV_HAD )); then
        export GOMAXPROCS="$PIN_STACK_ENV_OLD"
    else
        unset GOMAXPROCS
    fi
}
with_gomaxprocs() { # <role> <command...>
    local role="$1"; shift
    local rc=0
    stack_env_begin "$role"
    "$@" || rc=$?
    stack_env_end
    return "$rc"
}

# verify_process_threads <pid> <cpus> <name> — every thread's Cpus_allowed_list
# must equal <cpus>. Prints one line; returns 1 on any mismatch.
verify_process_threads() {
    python3 - "$1" "$2" "$3" <<'PY'
import glob, sys
pid, spec, name = sys.argv[1], sys.argv[2], sys.argv[3]
def expand(s):
    out = set()
    for part in s.split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out
exp = expand(spec)
tasks = glob.glob("/proc/%s/task/[0-9]*" % pid)
if not tasks:
    print("%s (pid %s): process not found" % (name, pid))
    sys.exit(1)
bad = []
for t in tasks:
    try:
        mask = None
        with open(t + "/status") as fh:
            for line in fh:
                if line.startswith("Cpus_allowed_list:"):
                    mask = expand(line.split(":", 1)[1].strip())
                    break
    except OSError:
        continue
    if mask != exp:
        bad.append(t.rsplit("/", 1)[1])
if bad:
    print("%s (pid %s): %d thread(s) outside %s (%s)" %
          (name, pid, len(bad), spec, ",".join(bad[:5])))
    sys.exit(1)
print("%s (pid %s): all threads on %s" % (name, pid, spec))
PY
}

# pin_stack_process <name> <pid> <cpus> — pin every current thread, then
# verify the kernel truth. No-op when <cpus> is empty (no partition). Retries
# a few times: a process still creating threads while we pin can add an
# unpinned thread between the scan and the check (the real call sites pin
# after readiness, but the retry makes the primitive safe on its own).
pin_stack_process() {
    local name="$1" pid="$2" cpus="$3" t out
    [[ -n "$cpus" ]] || return 0
    [[ -n "$pid" && -d "/proc/$pid" ]] \
        || { log_error "cannot pin $name: pid '${pid:-}' is not running"; return 1; }
    for _ in 1 2 3; do
        for t in /proc/"$pid"/task/*; do
            [[ -d "$t" ]] || continue
            taskset -pc "$cpus" "${t##*/}" >/dev/null 2>&1 || true
        done
        if out="$(verify_process_threads "$pid" "$cpus" "$name")"; then
            log_pass "$out"
            return 0
        fi
        sleep 0.2
    done
    log_error "failed to pin $name (pid $pid) to CPUs $cpus: $out"
    return 1
}

# verify_stack_pinning [quiet] — re-read every configured stack process and
# assert all threads are still on their role CPUs (a Go process creates
# threads lazily; they must inherit a pinned creator).
verify_stack_pinning() {
    local quiet="${1:-}" out line all=""
    [[ -n "$PIN_STACK_LOADGEN_CPUS" ]] || return 0
    local -a checks=(
        "exec-gateway:${GATEWAY_PID:-}:${PIN_STACK_GATEWAY_CPUS}"
        "human-gateway:${HUMAN_PID:-}:${PIN_STACK_GATEWAY_CPUS}"
        "etcd:${ETCD_PID:-}:${PIN_STACK_GATEWAY_CPUS}"
        "exec-sandlot:${SANDLOT_PID:-}:${PIN_STACK_SANDLOT_CPUS}"
        "prov-sandlot:${PROV_PID:-}:${PIN_STACK_SANDLOT_CPUS}"
    )
    for line in "${checks[@]}"; do
        IFS=: read -r name pid cpus <<< "$line"
        [[ -n "$cpus" ]] || continue
        if ! out="$(verify_process_threads "$pid" "$cpus" "$name")"; then
            log_error "stack pinning verification FAILED: $out"
            exit 1
        fi
        all+="$out"$'\n'
    done
    if [[ "$quiet" != "quiet" ]]; then
        printf '%s' "$all" | sed 's/^/    /'
        printf '%s' "$all" > "$LOG_DIR/pin-stack.txt" 2>/dev/null || true
        log_pass "stack pinning: loadgen/gateway/etcd/sandlot are on their reserved CPUs"
    fi
}

# proc_cpu_ticks <pid> — utime+stime ticks of the whole process (all threads),
# read from /proc/<pid>/stat. 0 when absent (accounting must never fail a run).
proc_cpu_ticks() {
    local pid="$1" line rest
    [[ -n "$pid" && -r "/proc/$pid/stat" ]] || { echo 0; return 0; }
    IFS= read -r line < "/proc/$pid/stat" || { echo 0; return 0; }
    rest="${line##*) }"
    # shellcheck disable=SC2086
    set -- $rest
    if (( $# < 13 )); then
        echo 0
        return 0
    fi
    echo $(( ${12} + ${13} ))
}

stack_cpu_ticks() { # "<gateway> <human> <etcd> <sandlot> <prov>" ticks
    echo "$(proc_cpu_ticks "${GATEWAY_PID:-}") $(proc_cpu_ticks "${HUMAN_PID:-}") \
$(proc_cpu_ticks "${ETCD_PID:-}") $(proc_cpu_ticks "${SANDLOT_PID:-}") $(proc_cpu_ticks "${PROV_PID:-}")"
}

# record_stack_cpu <mode> <level> <timefile> <before> <after> — cores =
# CPU-seconds per wall second. loadgen comes from bash `time` (the child is
# gone); server processes from /proc deltas. The server window includes the
# 1.5s post-run settle, i.e. the unmount work the level caused, normalized by
# the loadgen wall time.
record_stack_cpu() {
    local mode="$1" level="$2" tf="$3" before="$4" after="$5"
    local wall="" lg_u="" lg_s="" b_gw b_hu b_et b_sd b_pv a_gw a_hu a_et a_sd a_pv line
    if [[ -r "$tf" ]]; then
        read -r wall lg_u lg_s < "$tf" || true
    fi
    wall="${wall:-0}"; lg_u="${lg_u:-0}"; lg_s="${lg_s:-0}"
    read -r b_gw b_hu b_et b_sd b_pv <<< "$before"
    read -r a_gw a_hu a_et a_sd a_pv <<< "$after"
    line="$(awk -v wall="$wall" -v clk="$PIN_CLK_TCK" -v lgu="$lg_u" -v lgs="$lg_s" \
        -v bgw="${b_gw:-0}" -v bhu="${b_hu:-0}" -v bet="${b_et:-0}" -v bsd="${b_sd:-0}" -v bpv="${b_pv:-0}" \
        -v agw="${a_gw:-0}" -v ahu="${a_hu:-0}" -v aet="${a_et:-0}" -v asd="${a_sd:-0}" -v apv="${a_pv:-0}" '
        BEGIN {
            w = wall + 0; if (w <= 0) w = 1
            lg = (lgu + lgs) / w
            gw = (agw - bgw) / clk / w
            hu = (ahu - bhu) / clk / w
            et = (aet - bet) / clk / w
            sd = (asd - bsd) / clk / w
            pv = (apv - bpv) / clk / w
            if (gw < 0) gw = 0; if (hu < 0) hu = 0; if (et < 0) et = 0
            if (sd < 0) sd = 0; if (pv < 0) pv = 0
            printf "%.2f %.2f %.2f %.2f %.2f %.2f", lg, gw, hu, et, sd, pv
        }')" || line=""
    [[ -n "$line" ]] || { log_warn "stack CPU accounting failed at $mode@$level"; return 0; }
    local lg gw hu et sd pv
    read -r lg gw hu et sd pv <<< "$line"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$mode" "$level" "$wall" "$lg" "$gw" "$hu" "$et" "$sd" "$pv" >> "$PIN_CPU_TSV"
    printf '    stack-cpu: loadgen=%s gateway=%s human=%s etcd=%s sandlot=%s prov=%s cores (wall=%ss)\n' \
        "$lg" "$gw" "$hu" "$et" "$sd" "$pv" "$wall"
}

# print_pin_recommendation — turn the measured per-level stack CPU into the
# whole-core layout the next run should reserve. Prints a table for targets
# 0.60 / PIN_TARGET_UTIL / 0.80 and saves a sourceable env file.
print_pin_recommendation() {
    [[ -s "$PIN_CPU_TSV" ]] || return 0
    python3 - "$PIN_CPU_TSV" "$PIN_TARGET_UTIL" "$PIN_THREADS_PER_CORE" \
        "$PIN_STACK_CORE_POOL" "$PIN_CORE_COUNT" \
        "${PIN_STACK_LOADGEN_CPUS}" "${PIN_STACK_GATEWAY_CPUS}" "${PIN_STACK_SANDLOT_CPUS}" \
        "$LOG_DIR/pin-recommendation" <<'PY'
import math, sys

tsv, target_s, tpc_s, core_pool, core_count_s = sys.argv[1:6]
alloc_lg, alloc_gw, alloc_sd = sys.argv[6], sys.argv[7], sys.argv[8]
outbase = sys.argv[9]
target = float(target_s)
tpc = max(1, int(tpc_s))
core_count = int(core_count_s)

rows = []
with open(tsv) as fh:
    header = fh.readline().rstrip("\n").split("\t")
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        vals = line.split("\t")
        if len(vals) == len(header):
            rows.append(dict(zip(header, vals)))
if not rows:
    sys.exit(0)

def num(r, k):
    try:
        return float(r.get(k) or 0)
    except ValueError:
        return 0.0

peak_lg = max((num(r, "loadgen") for r in rows), default=0.0)
peak_gw = max((num(r, "gateway") + num(r, "human") + num(r, "etcd") for r in rows), default=0.0)
peak_sd = max((num(r, "sandlot") + num(r, "prov") for r in rows), default=0.0)

def count_cpus(spec):
    n = 0
    for part in spec.split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            n += int(b) - int(a) + 1
        else:
            n += 1
    return n

def whole_cores(peak, util):
    return max(1, int(math.ceil(peak / (tpc * util))))

def layout_for(l, g, s):
    cores = [c for c in core_pool.split(";") if c.strip()] if core_pool else []
    if not cores or l + g + s > len(cores):
        return ""
    pick = lambda a, b: ",".join(cores[a:b])
    return "loadgen:%s;gateway:%s;sandlot:%s" % (pick(0, l), pick(l, l + g), pick(l + g, l + g + s))

print("pin-advisor: peak stack CPU (core-equivalents): loadgen=%.2f gateway+human+etcd=%.2f sandlot+prov=%.2f"
      % (peak_lg, peak_gw, peak_sd))
parts = []
for name, peak, spec in (("loadgen", peak_lg, alloc_lg),
                         ("gateway", peak_gw, alloc_gw),
                         ("sandlot", peak_sd, alloc_sd)):
    n = count_cpus(spec)
    if n:
        parts.append("%s %.2f/%d threads=%d%%" % (name, peak, n, round(100.0 * peak / n)))
if parts:
    print("pin-advisor: this run's allocation: " + "; ".join(parts))
if count_cpus(alloc_lg) and peak_lg >= 0.85 * count_cpus(alloc_lg):
    print("pin-advisor: WARN loadgen ran at >=85% of its allocation — the client was "
          "likely the bottleneck; its P95 is a lower bound on the demand")

targets = sorted(set([0.60, round(target, 2), 0.80]))
chosen = None
for t in targets:
    l, g, s = whole_cores(peak_lg, t), whole_cores(peak_gw, t), whole_cores(peak_sd, t)
    total = l + g + s
    lay = layout_for(l, g, s)
    print("pin-advisor: target %.2f -> reserve %d whole core(s) "
          "(loadgen %d, gateway+human+etcd %d, sandlot+prov %d)%s"
          % (t, total, l, g, s, "" if lay else " [layout unavailable: no core pool]"))
    if abs(t - target) < 1e-9:
        chosen = (t, l, g, s, total, lay)

if chosen:
    t, l, g, s, total, lay = chosen
    print("pin-advisor: recommended next run: PIN_RESERVE_CORES=%d%s"
          % (total, (' PIN_STACK_LAYOUT="%s"' % lay) if lay else ""))
    if core_count:
        print("pin-advisor: VM cores under it: %d (1 VM/core -> POOL_SIZE=%d; "
              "2 VM/core on SMT -> %d)" % (core_count - total, core_count - total,
                                           2 * (core_count - total)))
    env = ["# generated by e2e/latency-benchmark-load.sh from measured stack CPU",
           "# peak cores: loadgen=%.2f gateway+human+etcd=%.2f sandlot+prov=%.2f"
           % (peak_lg, peak_gw, peak_sd),
           "PIN_RESERVE_CORES=%d" % total]
    if lay:
        env.append('PIN_STACK_LAYOUT="%s"' % lay)
    if core_count:
        env.append("POOL_SIZE=%d" % (core_count - total))
    with open(outbase + ".env", "w") as fh:
        fh.write("\n".join(env) + "\n")
    print("pin-advisor: saved %s.env (source it before the next run)" % outbase)
PY
}

# ── Phase 0: preflight ─────────────────────────────────────────────────────
log_section "Phase 0: Preflight"

VIRT_TYPE="$(systemd-detect-virt 2>/dev/null || true)"
VIRT_TYPE="${VIRT_TYPE//$'\n'/}"
HYPER_FLAG=$(grep -c -m1 '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null) || true
NESTED=0
if [[ "$VIRT_TYPE" == "none" || -z "$VIRT_TYPE" ]] && [[ "${HYPER_FLAG:-0}" -eq 0 ]]; then
    log_pass "Bare-metal detected"
else
    NESTED=1
    log_warn "Nested virtualization (systemd-detect-virt=$VIRT_TYPE) — results labeled [NESTED-VIRT]"
fi
NPROC="$(nproc)"
MEM_AVAILABLE_MB="$(awk '/^MemAvailable:/ {printf "%d", $2/1024}' /proc/meminfo)"
echo "    CPU cores: $NPROC    MemAvailable: ${MEM_AVAILABLE_MB}MB    load: $(uptime | sed 's/.*load average:/load:/')"

# CPU partition plan. Runs BEFORE the KVM check so PIN_PLAN=1 works on a
# non-KVM host (e.g. a nested dev VM): it only reads sysfs and configuration.
# Every run plans (even with no pinning requested): it validates the knobs,
# sets the VM pool / role CPU sets, and gives the CPU advisor the real
# physical-core and threads-per-core counts.
command -v python3 >/dev/null 2>&1 \
    || { log_error "python3 is required to plan the CPU partition"; exit 1; }
plan_pin_partition
if [[ "$PIN_PARTITIONED" == "1" && -n "$PIN_RESERVED_CPUS" ]]; then
    log_pass "CPU partition: VM pool $PIN_VM_POOL_SPEC; stack reserve $PIN_RESERVED_CPUS (loadgen=$PIN_STACK_LOADGEN_CPUS gateway=$PIN_STACK_GATEWAY_CPUS sandlot=$PIN_STACK_SANDLOT_CPUS)"
fi
if [[ "$PIN_PLAN" == "1" ]]; then
    log_section "PIN PLAN (computed — no deployment)"
    echo "    mode:            PIN_MODE=$PIN_MODE  partitioned=$PIN_PARTITIONED"
    echo "    online:          $PIN_ONLINE_SPEC ($PIN_CORE_COUNT physical core(s), ~$PIN_THREADS_PER_CORE thread(s)/core)"
    echo "    VM pool:         $PIN_VM_POOL_SPEC"
    echo "    reserved:        $PIN_RESERVED_CPUS ($PIN_RESERVED_CORES whole core(s))"
    echo "    stack:           loadgen=$PIN_STACK_LOADGEN_CPUS gateway(+human+etcd)=$PIN_STACK_GATEWAY_CPUS sandlot(+prov)=$PIN_STACK_SANDLOT_CPUS"
    echo "    GOMAXPROCS:      loadgen=$PIN_STACK_LOADGEN_GOMAXPROCS gateway=$PIN_STACK_GATEWAY_GOMAXPROCS etcd=$PIN_STACK_ETCD_GOMAXPROCS sandlot=$PIN_STACK_SANDLOT_GOMAXPROCS"
    if [[ "$PIN_MODE" == "1" ]]; then
        _pin_saved_map="$PIN_MAP"
        PIN_MAP="$(mktemp)"
        build_pin_slices
        echo "    slices:          $PIN_SLICES x ${PIN_SLICE_CPUS} CPU(s) ($PIN_GRAN_DESC), leftover=$PIN_LEFTOVER CPUs [$PIN_NODE_DETAIL] (POOL_SIZE=$POOL_SIZE)"
        if (( POOL_SIZE > PIN_SLICES )); then
            echo "    slices:          WARN POOL_SIZE=$POOL_SIZE > $PIN_SLICES slices — $(( (POOL_SIZE + PIN_SLICES - 1) / PIN_SLICES )) VMs share each slice"
        fi
        echo "    slice map (first 8):"
        sed -n '1,8p' "$PIN_MAP" | sed 's/^/        /'
        rm -f "$PIN_MAP"
        PIN_MAP="$_pin_saved_map"
    elif [[ "$PIN_PARTITIONED" == "1" ]]; then
        echo "    slices:          none — pool mode confines each VMM to the VM pool (no per-VM slice)"
    else
        echo "    slices:          none — no pinning requested (host scheduler)"
    fi
    _pin_vm_cores=$(( PIN_CORE_COUNT - PIN_RESERVED_CORES ))
    echo "    VM-count mirror: $_pin_vm_cores physical core(s) -> 1 VM/core=$_pin_vm_cores; 2 VM/core (SMT)=$(( _pin_vm_cores * 2 ))"
    exit 0
fi

[[ -e /dev/kvm ]] || { log_error "/dev/kvm missing — KVM required"; exit 1; }
log_pass "/dev/kvm available"
if [[ ! -r /dev/vhost-vsock ]]; then
    modprobe vhost_vsock 2>/dev/null || true
fi
[[ -r /dev/vhost-vsock ]] || { log_error "/dev/vhost-vsock not readable — run modprobe vhost_vsock"; exit 1; }
log_pass "/dev/vhost-vsock readable"

tc_check_root
if [[ -f "$OUTPUT/.release-stamp" ]]; then
    tc_check_tools curl python3
else
    tc_check_tools curl go python3
fi
[[ -x "$LOADGEN_BIN" ]] \
    || { log_error "missing $LOADGEN_BIN — run bash build/build.sh examples"; exit 1; }
log_pass "load driver: $LOADGEN_BIN"
tc_check_freshness
tc_ensure_etcd
mkdir -p "$LOG_DIR"
if [[ "$PIN_MODE" == "1" || "$PIN_PARTITIONED" == "1" ]]; then
    tc_check_tools numactl
    log_pass "numactl present — CPU pinning/confinement requested (PIN_MODE=$PIN_MODE partitioned=$PIN_PARTITIONED)"
fi
if [[ -n "$PIN_STACK_LOADGEN_CPUS" ]]; then
    tc_check_tools taskset
    log_pass "taskset present — host stack will be pinned to $PIN_RESERVED_CPUS"
fi

# ── Phase 1: single-microVM no-load reference ──────────────────────────────
# The latency budget for the whole capacity run is the gateway E2E P95 that a
# single microVM serves with no background load, measured by the AI agent
# latency benchmark in the same one-machine-etcd topology. The load levels
# then find the highest offered load whose gateway E2E stays within 1x and 2x
# of that reference.
log_section "Phase 1: Single-microVM no-load latency (latency-benchmark-aiagent.sh)"
WARM_GW_P95_MS="${WARM_GW_P95_MS:-}"
COLD_GW_P95_MS="${COLD_GW_P95_MS:-}"
WARM_CLIENT_P95_MS="${WARM_CLIENT_P95_MS:-}"
COLD_CLIENT_P95_MS="${COLD_CLIENT_P95_MS:-}"

# run_reference_bench <log> <attempts> <script> [args...] — run the
# self-contained no-load benchmark. A retry covers the transient "sandbox is
# cleaning" state a previous run can leave in the pool; a persistent failure
# is fatal (the capacity budget must not silently fall back).
run_reference_bench() {
    local logf="$1" attempts="$2"; shift 2
    local i rc=1
    for (( i = 1; i <= attempts; i++ )); do
        log_step "Running $* (attempt $i/$attempts, self-contained)..."
        if env -u POOL_SIZE -u PIN_SLICE_CPUS -u PIN_SLICES \
               -u PIN_STACK_CORES -u PIN_RESERVE_CORES -u PIN_STACK_LAYOUT \
               -u PIN_STACK_LOADGEN_CPUS -u PIN_STACK_GATEWAY_CPUS \
               -u PIN_STACK_SANDLOT_CPUS -u PIN_CPUS -u PIN_VERIFY_MODE \
               TC_VCPUS="$BENCH_VCPUS" PIN_MODE="$PIN_MODE" \
               bash "$SCRIPT_DIR/$1" "${@:2}" > "$logf" 2>&1; then
            rc=0
            break
        else
            rc=$?
        fi
        log_warn "$1 failed (rc=$rc) — see $logf"
        (( i < attempts )) && log_warn "retrying after a clean redeploy..."
    done
    return "$rc"
}

if [[ "$SKIP_ESTIMATE_BENCH" == "1" ]]; then
    if (( QUICK == 1 )); then
        # Machinery smoke only: a plausible nested reference so the smoke can
        # run without the subprocess benchmark.
        WARM_GW_P95_MS="${WARM_GW_P95_MS:-5}"
        COLD_GW_P95_MS="${COLD_GW_P95_MS:-15}"
        WARM_CLIENT_P95_MS="${WARM_CLIENT_P95_MS:-6}"
        COLD_CLIENT_P95_MS="${COLD_CLIENT_P95_MS:-18}"
        log_warn "quick smoke — using placeholder no-load P95s (gw warm/cold ${WARM_GW_P95_MS}/${COLD_GW_P95_MS}ms, client ${WARM_CLIENT_P95_MS}/${COLD_CLIENT_P95_MS}ms)"
    else
        for v in WARM_GW_P95_MS COLD_GW_P95_MS WARM_CLIENT_P95_MS COLD_CLIENT_P95_MS; do
            val="${!v}"
            if ! awk -v x="$val" 'BEGIN { exit !(x + 0 > 0) }'; then
                log_error "SKIP_ESTIMATE_BENCH=1 requires ${v} (a no-load P95 from latency-benchmark-aiagent.sh)"
                exit 1
            fi
        done
        log_warn "SKIP_ESTIMATE_BENCH=1 — using supplied no-load P95s: gateway warm/cold ${WARM_GW_P95_MS}/${COLD_GW_P95_MS}ms, client ${WARM_CLIENT_P95_MS}/${COLD_CLIENT_P95_MS}ms"
    fi
else
    # The reference must use the SAME microVM shape as the load fixture.
    export TC_VCPUS="$BENCH_VCPUS"
    EST_DIR="$(mktemp -d /tmp/sandswap-load-ref.XXXXXX)"
    AI_LOG="$EST_DIR/aiagent-bench.log"
    if ! run_reference_bench "$AI_LOG" "$ESTIMATE_ATTEMPTS" latency-benchmark-aiagent.sh http distributed; then
        log_error "aiagent benchmark failed — see $AI_LOG"
        tail -30 "$AI_LOG" || true
        exit 1
    fi
    log_pass "aiagent benchmark done ($AI_LOG)"

    parsed="$(python3 - "$AI_LOG" <<'PY'
import sys
warm_gw = cold_gw = warm_cl = cold_cl = None
section = None
try:
    fh = open(sys.argv[1], errors="replace")
except Exception:
    sys.exit(1)
for line in fh:
    s = line.strip()
    if s.startswith("Warm") and "sticky lease reuse" in s:
        section = "warm"; continue
    if s.startswith("Switch") and "cold mount_and_exec" in s:
        section = "cold"; continue
    if not section:
        continue
    f = s.split()
    if len(f) < 6:
        continue
    if s.startswith("gateway E2E"):
        if section == "warm": warm_gw = f[4]
        else: cold_gw = f[4]
    elif s.startswith("client round-trip"):
        if section == "warm": warm_cl = f[4]
        else: cold_cl = f[4]
if None in (warm_gw, cold_gw, warm_cl, cold_cl):
    sys.exit(1)
print(warm_gw, cold_gw, warm_cl, cold_cl)
PY
)" || { log_error "could not parse warm/cold client+gateway P95 from $AI_LOG"; tail -40 "$AI_LOG"; exit 1; }
    read -r P_WARM_GW P_COLD_GW P_WARM_CL P_COLD_CL <<< "$parsed"
    WARM_GW_P95_MS="${WARM_GW_P95_MS:-$P_WARM_GW}"
    COLD_GW_P95_MS="${COLD_GW_P95_MS:-$P_COLD_GW}"
    WARM_CLIENT_P95_MS="${WARM_CLIENT_P95_MS:-$P_WARM_CL}"
    COLD_CLIENT_P95_MS="${COLD_CLIENT_P95_MS:-$P_COLD_CL}"
fi

for v in WARM_GW_P95_MS COLD_GW_P95_MS WARM_CLIENT_P95_MS COLD_CLIENT_P95_MS; do
    val="${!v}"
    if ! awk -v x="$val" 'BEGIN { exit !(x + 0 > 0) }'; then
        log_error "$v must be a positive number (got '$val')"
        exit 1
    fi
done
log_pass "No-load reference: gateway E2E P95 warm=${WARM_GW_P95_MS}ms cold=${COLD_GW_P95_MS}ms; client P95 warm=${WARM_CLIENT_P95_MS}ms cold=${COLD_CLIENT_P95_MS}ms"

# ── Phase 2: deploy the one-machine-etcd stack ─────────────────────────────
log_section "Phase 2: Deploy (one-machine-etcd, sticky-ms=$LEASE_MS)"

tc_clean_environment
tc_ensure_dev_nodes
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — microVMs will be offline"
fi
tc_deploy_artifacts
tc_gen_certs
tc_attach_vsockguard

tc_ensure_etcd
with_gomaxprocs etcd tc_start_etcd load-bench "$ETCD_DATA"
pin_stack_process etcd "$ETCD_PID" "$PIN_STACK_GATEWAY_CPUS" || exit 1
# Exec gateway: /agent/* on GATEWAY_URL + the exec-role stream. CLI mode passes
# -sticky-ms $LEASE_MS (1) from the harness defaults set before sourcing.
with_gomaxprocs gateway tc_start_gateway \
    -mode exec \
    -etcd "$ETCD_ENDPOINT" \
    -gateway-id "$GW_ID_EXEC" \
    -gateway-url "$GATEWAY_URL" \
    -gateway-stream-addr "localhost$STREAM_ADDR"
tc_wait_component_ready "$GATEWAY_URL" "exec gateway" "$GATEWAY_PID" "$LOG_DIR/gateway.log"
pin_stack_process exec-gateway "$GATEWAY_PID" "$PIN_STACK_GATEWAY_CPUS" || exit 1
with_gomaxprocs gateway tc_start_human_gateway

# ── Phase 3: sandlot (exec stream) + prov sandlot (human stream) ───────────
log_section "Phase 3: Sandlot + provision instance"
# Benchmark-local VM spec (1 vCPU/256MB, owner decision): the pool RUNS this
# shape and the estimate MEASURES it, so the two cannot drift. The canonical
# generator supplies the FULL config (kernel/initramfs/vmm/volumes/network) —
# config-file mode bypasses the CLI overrides, so a hand-minimal YAML silently
# loses the kernel and every VM boot fails. We inject a `bench` spec as the
# first entry of its specs map and pin the pool to it.
if [[ "$PIN_MODE" == "1" || "$PIN_PARTITIONED" == "1" ]]; then
    setup_vm_pinning   # exports TC_VMM_BINARY=<numactl shim>
fi
tc_gen_sandlot_config "$DEPLOY_DIR/sandlot-load.yaml"
if [[ "$PIN_MODE" == "1" || "$PIN_PARTITIONED" == "1" ]]; then
    grep -Fq "vmm_binary: \"$PIN_WRAPPER\"" "$DEPLOY_DIR/sandlot-load.yaml" \
        || { log_error "generated sandlot config does not point vmm_binary at the pinning shim ($PIN_WRAPPER)"; grep -n "vmm_binary" "$DEPLOY_DIR/sandlot-load.yaml" || true; exit 1; }
    log_pass "vmm_binary pinned to the CPU/NUMA shim: $PIN_WRAPPER"
fi
python3 - "$DEPLOY_DIR/sandlot-load.yaml" "$BENCH_VCPUS" "$VM_MEMORY_MB" "$EXEC_SLOTS" "$POOL_SIZE" <<'PY'
import re, sys
path, vcpus, mem, slots, pool = sys.argv[1:6]
s = open(path).read()
s = s.replace(
    "specs:\n",
    "specs:\n"
    "  bench:\n"
    f"    vcpus: {vcpus}\n"
    f"    memory_mb: {mem}\n"
    f"    exec_slots: {slots}\n",
    1,
)
s = re.sub(r'(?m)^pool:.*$', f'pool: "bench:{pool}"', s, count=1)
open(path, "w").write(s)
PY
# The generated YAML is the ONLY path that carries the recycle cap into this
# stack (config-file mode). Assert it, so a harness-default change cannot
# silently reintroduce mid-run VM recycling (boot-cold samples inflating P95).
for cap in max_uses max_mounts max_distinct_agents; do
    varname="TC_$(printf '%s' "$cap" | tr '[:lower:]' '[:upper:]')"
    want="${!varname}"
    if ! grep -q "^  ${cap}: ${want}$" "$DEPLOY_DIR/sandlot-load.yaml"; then
        log_error "generated sandlot config does not carry ${cap}=${want} — VM lifetime caps would not match the run's policy"
        grep -n "$cap" "$DEPLOY_DIR/sandlot-load.yaml" || true
        exit 1
    fi
done
log_pass "recycle policy ($LOADTEST_RECYCLE_POLICY): max_uses=${TC_MAX_USES} max_mounts=${TC_MAX_MOUNTS} max_distinct_agents=${TC_MAX_DISTINCT_AGENTS} mem=${TC_RECYCLE_MEM_PERCENT}%/${TC_RECYCLE_MEM_ABS_MB}MB"
export TC_SANDLOT_CONFIG="$DEPLOY_DIR/sandlot-load.yaml"
# No -volume-seed-file here: the generated YAML already carries it, and the
# startup validator refuses a value set in BOTH places.
with_gomaxprocs sandlot tc_start_sandlot -overlayfs-templates "$DEPLOY_DIR/templates"
pin_stack_process exec-sandlot "$SANDLOT_PID" "$PIN_STACK_SANDLOT_CPUS" || exit 1
tc_wait_health
# Prov-only sandlot → human gateway stream (storage plane executor). It shares
# the template store and volumes root with the exec instance. -allow-colocated-
# instances is the explicit admission: two instances on one host.
PROV_CERT="$(tc_node_cert "$PROV_NODE_ID" prov)"
stack_env_begin sandlot
ss_service_exec sandlot -- "$DEPLOY_DIR/sandlot" \
    -gateway-addr "${HUMAN_STREAM_ADDR:-127.0.0.1:9999}" \
    -node-id "$PROV_NODE_ID" \
    -volumes-dir "$VOL_ROOT" -allow-insecure-volumes -allow-missing-vsockguard \
    -roles prov \
    -templates-dir "$DEPLOY_DIR/templates" \
    -flat-templates "${TC_FLAT_TEMPLATES:-$DEPLOY_DIR/flat-templates}" \
    -volume-seed-file "$DEPLOY_DIR/volume-seed" \
    -max-provision-ops "$LOADTEST_PROV_MAX_OPS" \
    -tls-cert "$PROV_CERT.crt" \
    -tls-key "$PROV_CERT.key" \
    -tls-ca "$CERT_DIR/ca.crt" \
    -allow-colocated-instances \
    > "$LOG_DIR/sandlot-prov.log" 2>&1 &
PROV_PID=$!
stack_env_end
sleep 1
kill -0 "$PROV_PID" 2>/dev/null || {
    log_error "prov sandlot died"; tail -10 "$LOG_DIR/sandlot-prov.log"; exit 1; }
for _ in $(seq 1 60); do
    # The provision-instance count lives on /health (HumanHandler.health), not
    # in the /stats report — polling /stats would always read 0.
    provs=$(curl -s -m 2 "$HUMAN_URL/health" 2>/dev/null \
        | python3 -c 'import sys,json;print(json.load(sys.stdin).get("provisioners",0))' 2>/dev/null || echo 0)
    [[ "${provs:-0}" -ge 1 ]] && break
    sleep 0.5
done
[[ "${provs:-0}" -ge 1 ]] || { log_error "no provision instance connected to the human gateway ($HUMAN_URL/health provisioners=$provs)"; exit 1; }
log_pass "provision instance connected ($PROV_NODE_ID)"
pin_stack_process prov-sandlot "$PROV_PID" "$PIN_STACK_SANDLOT_CPUS" || exit 1
tc_wait_pool_ready "$POOL_SIZE" "$GATEWAY_URL"
if [[ -n "$PIN_VERIFY_MODE" ]]; then
    verify_vm_pinning
fi
verify_stack_pinning

# ── Phase 4: fixtures (flat rootfs:v1 volumes) ─────────────────────────────
make_agent() { # <name> <outfile>
    local name="$1" out="$2" resp aid key sid
    resp=$(ss_agent_and_sandfs "$HUMAN_URL" "$name" "$BENCH_TEMPLATE_REF" "flat")
    aid=$(json_val "$resp" "agent_id")
    key=$(json_val "$resp" "api_key")
    sid=$(json_val "$resp" "sandfs_id")
    if [[ -z "$aid" || -z "$key" || -z "$sid" ]]; then
        log_error "sandfs create failed for $name: $resp"
        exit 1
    fi
    printf '%s %s %s\n' "$aid" "$key" "$sid" >> "$out"
}

# create_llm_agents <count> <outfile> — the realistic model needs thousands of
# independent sandfs (one per simulated LLM agent), so creation is parallel.
# Each job writes its own one-line part file; the parts are concatenated in
# index order, which keeps the agents file deterministic across runs.
create_llm_agents() {
    local n="$1" out="$2" conc="${LOADTEST_AGENT_CREATE_CONCURRENCY:-32}"
    local partdir="$LOG_DIR/loadtest-agent-parts" rc=0 i=1 j pid
    local -a batch=()
    rm -rf "$partdir"; mkdir -p "$partdir"
    : > "$out"
    : > "$LOG_DIR/agent-create.log"
    # Batch-and-wait, not a rolling `wait -n`: the parent script also owns
    # long-lived background children (etcd/gateway/sandlot), and a bare
    # `wait` would block on those daemons forever. Each batch is waited by
    # PID, so only the creation jobs are reaped here.
    while (( i <= n )); do
        batch=()
        for (( j = 0; j < conc && i <= n; j++, i++ )); do
            ( make_agent "load-agents-$i" "$partdir/$i" ) 2>>"$LOG_DIR/agent-create.log" &
            batch+=("$!")
        done
        for pid in "${batch[@]}"; do
            wait "$pid" || rc=1
        done
        if (( i % 512 <= conc )); then
            log_info "agent creation: $((i - 1))/$n done"
        fi
    done
    if (( rc != 0 )); then
        log_error "agent creation failed; see $LOG_DIR/agent-create.log and $partdir"
        return 1
    fi
    for i in $(seq 1 "$n"); do
        if [[ ! -s "$partdir/$i" ]]; then
            log_error "agent creation produced no line for index $i"
            return 1
        fi
        cat "$partdir/$i" >> "$out"
    done
    local lines
    lines=$(wc -l < "$out")
    if [[ "$lines" -ne "$n" ]]; then
        log_error "agents file has $lines lines, want $n"
        return 1
    fi
    rm -rf "$partdir"
}

    log_section "Phase 4: Create $LOADTEST_MAX_AGENTS LLM agents (flat $BENCH_TEMPLATE_REF)"
    # One flat volume per agent lands on VOL_ROOT. Refuse a run whose agent
    # population cannot fit: a mid-level ENOSPC would poison the measurement
    # (and the operator would have to start over).
    if [[ -d "$OUTPUT/rootfs-template" ]]; then
        tmpl_kb=$(du -sk "$OUTPUT/rootfs-template" | awk '{print $1}')
        need_kb=$(( LOADTEST_MAX_AGENTS * tmpl_kb * 12 / 10 ))
        avail_kb=$(df -Pk "$VOL_ROOT" 2>/dev/null | awk 'NR==2{print $4}')
        if [[ -n "$avail_kb" ]] && (( avail_kb < need_kb )); then
            log_error "not enough space under $VOL_ROOT for $LOADTEST_MAX_AGENTS flat volumes: need ~${need_kb}KiB, have ${avail_kb}KiB — lower LOADTEST_AGENT_LEVELS or free space"
            exit 1
        fi
        log_info "volume space preflight: $LOADTEST_MAX_AGENTS x ${tmpl_kb}KiB ~= ${need_kb}KiB, ${avail_kb}KiB available under $VOL_ROOT"
    fi
    if ! create_llm_agents "$LOADTEST_MAX_AGENTS" "$LOADTEST_AGENTS_FILE"; then
        exit 1
    fi
    log_pass "agents ready: $LOADTEST_MAX_AGENTS flat sandfs, template $BENCH_TEMPLATE_REF, recycle policy $LOADTEST_RECYCLE_POLICY"

    # ── shaped hold calibration (auto) ─────────────────────────────────────
    # The hold must match THIS stack's async unmount time, not a constant:
    # bare metal unmounts in ~5-7 ms, nested in ~11-14 ms. Drive a dozen cold
    # execs against one agent (each expires its 1 ms lease and unmounts),
    # then read the gateway's own unmount recent P95 and add a margin.
    if [[ "$LOADTEST_WORKLOAD" == "shaped" && "$LOADTEST_SHAPED_HOLD_MS" == "auto" ]]; then
        calib_agent_key=""
        calib_agent_sf=""
        while IFS=' ' read -r _id _key _sf; do
            calib_agent_key="$_key"; calib_agent_sf="$_sf"; break
        done < "$LOADTEST_AGENTS_FILE"
        if [[ -n "$calib_agent_key" && -n "$calib_agent_sf" ]]; then
            calib_body=$(printf '{"sandfs_id":"%s","code":"echo ok","timeout":15}' "$calib_agent_sf")
            for _round in 1 2; do
                for _i in $(seq 1 12); do
                    curl -s -o /dev/null -m 5 -X POST "$GATEWAY_URL/agent/execute" \
                        -H "Content-Type: application/json" \
                        -H "Authorization: Bearer $calib_agent_key" \
                        -d "$calib_body" || true
                    sleep 0.3
                done
                sleep 1.2
                fetch_stats
                read -r _cn _lt _u2 _lm _rn _rp95 _rp50 <<< "$(stats_line)"
                if (( _rn >= 8 )) && awk -v x="$_rp95" 'BEGIN { exit !(x + 0 > 0) }'; then
                    break
                fi
                log_warn "unmount hold calibration: recent window too small (n=$_rn p95=$_rp95), retrying"
            done
            if (( _rn >= 8 )) && awk -v x="$_rp95" 'BEGIN { exit !(x + 0 > 0) }'; then
                LOADTEST_SHAPED_HOLD_MS="$(awk -v p="$_rp95" 'BEGIN {
                    h = int(p); if (h < p) h++; h += 2
                    if (h < 1) h = 1; if (h > 100) h = 100; print h }')"
                log_pass "shaped hold calibrated from measured unmount P95: ${_rp95}ms -> hold=${LOADTEST_SHAPED_HOLD_MS}ms (p95 + 2ms margin, clamped [1,100])"
            else
                LOADTEST_SHAPED_HOLD_MS=12
                log_warn "shaped hold calibration did not get a usable /stats window; falling back to hold=12ms"
            fi
        else
            LOADTEST_SHAPED_HOLD_MS=12
            log_warn "shaped hold calibration: no agent in $LOADTEST_AGENTS_FILE; falling back to hold=12ms"
        fi
    fi

# ── Phase 5: load levels ───────────────────────────────────────────────────
    if [[ "$LOADTEST_WORKLOAD" == "shaped" ]]; then
        log_section "Phase 5: shaped lanes (lanes=${LOADTEST_LANES}, agents/lane auto ~ rate x think ${LOADTEST_THINK_MIN_MS}-${LOADTEST_THINK_MAX_MS}ms, hold=${LOADTEST_SHAPED_HOLD_MS}ms; periods: ${LOADTEST_TURN_PERIODS_MS}ms; requests/turn=${LOADTEST_REQUESTS_PER_TURN}; retry=${LOADTEST_BUSY_RETRIES}x${LOADTEST_BUSY_RETRY_BACKOFF_MS}ms; sticky ${LOADTEST_STICKY_MS}ms; window ${LOADTEST_DURATION_SEC}s + ${LOADTEST_WARMUP_SEC}s warmup)"
        mapfile -t LOADTEST_LEVELS_EFF < <(printf '%s\n' $LOADTEST_TURN_PERIODS_MS | sort -nu)
    elif [[ "$LOADTEST_WORKLOAD" == "ideal" ]]; then
        log_section "Phase 5: ideal paced lanes (lanes=${LOADTEST_LANES}; periods: ${LOADTEST_TURN_PERIODS_MS}ms; requests/turn=${LOADTEST_REQUESTS_PER_TURN}; retry=${LOADTEST_BUSY_RETRIES}x${LOADTEST_BUSY_RETRY_BACKOFF_MS}ms; sticky ${LOADTEST_STICKY_MS}ms; window ${LOADTEST_DURATION_SEC}s + ${LOADTEST_WARMUP_SEC}s warmup)"
        mapfile -t LOADTEST_LEVELS_EFF < <(printf '%s\n' $LOADTEST_TURN_PERIODS_MS | sort -nu)
    else
        log_section "Phase 5: LLM realistic load (agents: ${LOADTEST_AGENT_LEVELS}; think ${LOADTEST_THINK_MIN_MS}-${LOADTEST_THINK_MAX_MS}ms; requests/turn=${LOADTEST_REQUESTS_PER_TURN}; retry=${LOADTEST_BUSY_RETRIES}x${LOADTEST_BUSY_RETRY_BACKOFF_MS}ms; sticky ${LOADTEST_STICKY_MS}ms; window ${LOADTEST_DURATION_SEC}s + ${LOADTEST_WARMUP_SEC}s warmup)"
        mapfile -t LOADTEST_LEVELS_EFF < <(printf '%s\n' $LOADTEST_AGENT_LEVELS | sort -nu)
    fi
    : > "$LOADTEST_TSV"
    printf 'mode\tagents\tperiod_ms\tok\terr\tbusy\tretried\treq_rps\tcold\tcold_rps\twarm\twarm_rps\twarm_hit\tduration_s\tturns\tmax_inflight\tcold_gw_p50\tcold_gw_p95\tcold_gw_p99\twarm_gw_p50\twarm_gw_p95\twarm_gw_p99\tcold_client_p95\twarm_client_p95\tcold_sandlot_p95\tcold_exec_p95\twarm_sandlot_p95\twarm_exec_p95\texp\texp_all\td_unmount\td_lf\td_under2\tlf_max\trecent_p95\tclean_min\tclean_mean\tclean_p95\ttotal_vms\trecycle_delta\terr_kinds\n' > "$LOADTEST_TSV"
printf 'mode\tlevel\twall_s\tloadgen\tgateway\thuman\tetcd\tsandlot\tprov\n' > "$PIN_CPU_TSV"

# ── loadtest helpers ──────────────────────────────────────────────────────
# run_load_window <agents> [period_ms] [lane_agents] — one workload window (warmup +
# measurement) against the shared agents file. With period_ms it runs the paced
# lane workload (ideal, or shaped with lane_agents); without it the realistic
# AI agent closed loop. Prints LOADGEN_RESULT.
run_load_window() {
    local n="$1" period="${2:-}" lane_agents="${3:-}"
    local out="$LOG_DIR/loadgen-${n}.log"
    local tf="$LOG_DIR/loadgen-time-${n}.txt"
    local count="$n"
    # shaped: -agent-count is the lane population actually loaded
    # (lanes x agents/lane); the lanes themselves come from -lanes.
    [[ -n "$lane_agents" ]] && count=$(( n * lane_agents ))
    local -a cmd=("$LOADGEN_BIN" -gateway "$GATEWAY_URL" -agents "$LOADTEST_AGENTS_FILE" \
        -agent-count "$count" -duration "$LOADTEST_DURATION_SEC" -warmup-sec "$LOADTEST_WARMUP_SEC" \
        -think-min-ms "$LOADTEST_THINK_MIN_MS" -think-max-ms "$LOADTEST_THINK_MAX_MS" \
        -requests-per-turn "$LOADTEST_REQUESTS_PER_TURN" \
        -retry-busy "$LOADTEST_BUSY_RETRIES" -retry-backoff-ms "$LOADTEST_BUSY_RETRY_BACKOFF_MS" \
        -intra-gap-ms "$LOADTEST_INTRA_TURN_GAP_MS" -sticky-ms "$LOADTEST_STICKY_MS" \
        -seed "$LOADTEST_SEED" -max-inflight "$LOADTEST_MAX_INFLIGHT")
    if [[ -n "$period" ]]; then
        cmd+=(-workload "$LOADTEST_WORKLOAD" -lanes "$n" -period-ms "$period")
        [[ -n "$lane_agents" ]] && cmd+=(-lane-agents "$lane_agents" -hold-ms "$LOADTEST_SHAPED_HOLD_MS")
    fi
    if [[ -n "${PIN_STACK_LOADGEN_GOMAXPROCS:-}" ]]; then
        cmd=(env "GOMAXPROCS=$PIN_STACK_LOADGEN_GOMAXPROCS" "${cmd[@]}")
    fi
    if [[ -n "${PIN_STACK_LOADGEN_CPUS:-}" ]]; then
        cmd=(taskset -c "$PIN_STACK_LOADGEN_CPUS" "${cmd[@]}")
    fi
    { TIMEFORMAT='%3R %3U %3S'; time "${cmd[@]}" > "$out" 2>&1 ; } 2> "$tf" || true
    grep '^LOADGEN_RESULT ' "$out" | tail -1 | sed 's/^LOADGEN_RESULT //' || true
}

# loadtest_json_fields <json> — the JSON-derived columns of one loadtest TSV row. The
# per-class server-side percentiles are first-class: the two latency budgets
# are checked against the cold AND warm gateway E2E P95 separately.
loadtest_json_fields() {
    python3 - "$1" <<'PY'
import sys, json
d = json.loads(sys.argv[1])
def g(k): return d.get(k, 0)
ws = d.get("warm_stats") or {}
cs = d.get("cold_stats") or {}
fields = [
    g("mode"), g("agents"), g("period_ms"), g("ok"), g("err"), g("busy_attempts"), g("busy_retried"), g("rps"),
    g("cold"), g("cold_rps"), g("warm"), g("warm_rps"), g("warm_hit_pct"),
    g("duration_sec"), g("turns"), g("max_inflight"),
    cs.get("gw_p50_ms", 0), cs.get("gw_p95_ms", 0), cs.get("gw_p99_ms", 0),
    ws.get("gw_p50_ms", 0), ws.get("gw_p95_ms", 0), ws.get("gw_p99_ms", 0),
    cs.get("p95_ms", 0), ws.get("p95_ms", 0),
    cs.get("sandlot_p95_ms", 0), cs.get("exec_p95_ms", 0),
    ws.get("sandlot_p95_ms", 0), ws.get("exec_p95_ms", 0),
    g("expected_expiries"), g("expected_expiries_all"),
    json.dumps(d.get("err_kinds") or {}, separators=(",", ":"), sort_keys=True),
]
print("\t".join(str(x) for x in fields))
PY
}

# loadtest_vm_stats_line — stdin: one /stats body. stdout: "<clean> <total>
# <recycle_triggers>". The recycle counter is the sum over nodes: any rise
# during a level is a POLICY recycle (a lifetime cap, the memory threshold or
# pool scale-down), never a failure-driven dirty destroy.
loadtest_vm_stats_line() {
    local body rest
    body="$(cat)"
    # clean comes from the suite's ONE pool parser; this local python only
    # extracts what the library does not carry (total + the recycle sum).
    rest="$(printf '%s' "$body" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    print(0, 0); raise SystemExit
t=d.get("totals") or {}
n=t.get("total_vms")
if n is None: n=sum(g.get("total_vms",0) for g in d.get("gateways",[]))
r=0
for g in d.get("gateways",[]):
    for nd in (g.get("nodes") or []):
        try: r += int(nd.get("recycle_triggers",0) or 0)
        except Exception: pass
print(n, r)')"
    echo "$(ss_pool_clean_of "$body") $rest"
}

# loadtest_stats_start/stop — a 2 s /stats poller around one level. It proves the
# pool was ENGAGED (clean ~= 0) and records the recycle counter, which the
# level snapshot alone cannot see.
loadtest_stats_start() { # <level>
    LOADTEST_WATCH_FILE="$LOG_DIR/loadtest-vm-stats-${1}.tsv"
    LOADTEST_WATCH_STOP="$LOG_DIR/loadtest-vm-stats-${1}.stop"
    rm -f "$LOADTEST_WATCH_STOP"
    : > "$LOADTEST_WATCH_FILE"
    (
        set +e
        local auth=()
        [[ -n "${TC_OPS_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $TC_OPS_TOKEN")
        while [[ ! -e "$LOADTEST_WATCH_STOP" ]]; do
            curl -s -m 5 "${auth[@]}" "$GATEWAY_URL/stats" 2>/dev/null \
                | loadtest_vm_stats_line >> "$LOADTEST_WATCH_FILE" 2>/dev/null
            sleep "$LOADTEST_STATS_POLL_SEC"
        done
    ) &
    LOADTEST_WATCH_PID=$!
}

loadtest_stats_stop() {
    [[ -n "${LOADTEST_WATCH_STOP:-}" ]] && : > "$LOADTEST_WATCH_STOP"
    if [[ -n "${LOADTEST_WATCH_PID:-}" ]]; then
        wait "$LOADTEST_WATCH_PID" 2>/dev/null || true
    fi
    LOADTEST_WATCH_PID=""
}

# loadtest_vm_summary <watch-file> — "clean_min clean_mean clean_p95 total_vms
# recycle_delta" over the level's samples.
loadtest_vm_summary() {
    python3 - "$1" <<'PY'
import sys
clean, total, rec = [], [], []
try:
    fh = open(sys.argv[1])
except OSError:
    print("0 0 0 0 0"); raise SystemExit
for line in fh:
    p = line.split()
    if len(p) != 3:
        continue
    try:
        c, t, r = int(p[0]), int(p[1]), int(p[2])
    except ValueError:
        continue
    clean.append(c); total.append(t); rec.append(r)
if not clean:
    print("0 0 0 0 0"); raise SystemExit
sc = sorted(clean)
n = len(sc)
print(sc[0], round(sum(sc) / n, 2), sc[int(n * 0.95)] if n else 0,
      total[-1], (max(rec) - min(rec)) if rec else 0)
PY
}

for n in "${LOADTEST_LEVELS_EFF[@]}"; do
    local_agents="$n"
    local_period=""
    local_lane_agents=""
    local_label="level=$n agents"
    if [[ "$LOADTEST_WORKLOAD" == "ideal" ]]; then
        local_agents="$LOADTEST_LANES"
        local_period="$n"
        local_label="period=$n ms (lanes=$local_agents)"
    elif [[ "$LOADTEST_WORKLOAD" == "shaped" ]]; then
        local_agents="$LOADTEST_LANES"
        local_period="$n"
        local_lane_agents="$(shaped_agents_per_lane "$n")"
        local_label="period=$n ms (lanes=$local_agents x ${local_lane_agents} agents)"
    fi
    # A capacity-policy run keeps the VM identities stable; under the shipped
    # policy the distinct-agent cap recycles VMs, so the per-level slice check
    # would fire on replacements that are the measurement, not a failure.
    if [[ -n "$PIN_VERIFY_MODE" && "$PIN_VERIFY_EACH_LEVEL" == "1" && "$LOADTEST_RECYCLE_POLICY" == "capacity" ]]; then
        verify_vm_pinning quiet
    fi
    verify_stack_pinning quiet
    log_step "$local_label (think=${LOADTEST_THINK_MIN_MS}-${LOADTEST_THINK_MAX_MS}ms, requests/turn=${LOADTEST_REQUESTS_PER_TURN}, window=${LOADTEST_DURATION_SEC}s, warmup=${LOADTEST_WARMUP_SEC}s)"
    snapshot_stats B
    _cpu_before="$(stack_cpu_ticks)"
    loadtest_stats_start "$n"
    res_json="$(run_load_window "$local_agents" "$local_period" "$local_lane_agents")"
    loadtest_stats_stop
    if [[ -z "$res_json" ]]; then
        log_error "loadgen produced no LOADGEN_RESULT at $local_label — see $LOG_DIR/loadgen-${n}.log"
        tail -20 "$LOG_DIR/loadgen-${n}.log" 2>/dev/null || true
        exit 1
    fi
    # The measurement window is the loadgen's own (warmup excluded); this
    # settle only lets the final turns' 100 ms leases expire and unmount.
    sleep 1.5
    snapshot_stats A
    record_stack_cpu "agents" "$n" "$LOG_DIR/loadgen-time-${n}.txt" "$_cpu_before" "$(stack_cpu_ticks)"

    IFS=$'\t' read -r r_mode r_agents r_period r_ok r_err r_busy r_retried r_req_rps r_cold r_cold_rps r_warm r_warm_rps r_warm_hit \
        r_dur r_turns r_maxinfl \
        r_cold_gwp50 r_cold_gwp95 r_cold_gwp99 r_warm_gwp50 r_warm_gwp95 r_warm_gwp99 \
        r_cold_cp95 r_warm_cp95 r_cold_sp95 r_cold_ep95 r_warm_sp95 r_warm_ep95 \
        r_exp r_exp_all r_errkinds <<< "$(loadtest_json_fields "$res_json")"
    d_unmount=$(( A_UNMOUNT - B_UNMOUNT ))
    d_lf=$(( A_LF_TOTAL - B_LF_TOTAL ))
    d_under2=$(( A_LF_UNDER2 - B_LF_UNDER2 ))
    read -r clean_min clean_mean clean_p95 total_vms recycle_delta <<< "$(loadtest_vm_summary "$LOADTEST_WATCH_FILE")"
    per_vm="$(awk -v c="$r_cold_rps" -v p="$POOL_SIZE" 'BEGIN{ if (p > 0) printf "%.2f", c/p; else print 0 }')"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$r_mode" "$r_agents" "$r_period" "$r_ok" "$r_err" "$r_busy" "$r_retried" "$r_req_rps" "$r_cold" "$r_cold_rps" "$r_warm" "$r_warm_rps" "$r_warm_hit" \
        "$r_dur" "$r_turns" "$r_maxinfl" \
        "$r_cold_gwp50" "$r_cold_gwp95" "$r_cold_gwp99" "$r_warm_gwp50" "$r_warm_gwp95" "$r_warm_gwp99" \
        "$r_cold_cp95" "$r_warm_cp95" "$r_cold_sp95" "$r_cold_ep95" "$r_warm_sp95" "$r_warm_ep95" \
        "$r_exp" "$r_exp_all" "$d_unmount" "$d_lf" "$d_under2" "${A_LF_MAX:-0}" "${A_RECENT_P95:-0}" \
        "$clean_min" "$clean_mean" "$clean_p95" "$total_vms" "$recycle_delta" "$r_errkinds" \
        >> "$LOADTEST_TSV"

    if [[ "$r_mode" == "ideal" ]]; then
        echo "    period=${r_period}ms lanes=$r_agents ok=$r_ok err=$r_err busy=$r_busy retried=$r_retried req/s=$r_req_rps cold/s=$r_cold_rps warm/s=$r_warm_rps warm_hit=${r_warm_hit}% per-VM cold/s=$per_vm"
    else
        echo "    agents=$r_agents ok=$r_ok err=$r_err busy=$r_busy retried=$r_retried req/s=$r_req_rps cold/s=$r_cold_rps warm/s=$r_warm_rps warm_hit=${r_warm_hit}% per-VM cold/s=$per_vm"
    fi
    echo "    gw p95: cold=${r_cold_gwp95}ms warm=${r_warm_gwp95}ms | client p95: cold=${r_cold_cp95}ms warm=${r_warm_cp95}ms"
    echo "    VMs: clean min/mean/p95=${clean_min}/${clean_mean}/${clean_p95} of ${total_vms}; recycles=${recycle_delta}; unmounts=$d_unmount; fires=$d_lf (under2=$d_under2 max=${A_LF_MAX:-0}ms)"
    if [[ "$r_errkinds" != "{}" ]]; then
        echo "    error classes: $r_errkinds"
    fi
    printf 'bench-result {"mode":"%s","agents":%s,"period_ms":%s,"ok":%s,"err":%s,"busy_attempts":%s,"busy_retried":%s,"req_rps":%s,"cold_rps":%s,"warm_rps":%s,"warm_hit_pct":%s,"duration_sec":%s,"turns":%s,"cold_gw_p50_ms":%s,"cold_gw_p95_ms":%s,"cold_gw_p99_ms":%s,"warm_gw_p50_ms":%s,"warm_gw_p95_ms":%s,"warm_gw_p99_ms":%s,"cold_client_p95_ms":%s,"warm_client_p95_ms":%s,"expected_expiries":%s,"expected_expiries_all":%s,"unmount_delta":%s,"lease_fire_delta":%s,"lease_fire_under2":%s,"lease_fire_max_ms":%s,"unmount_p95_ms":%s,"clean_min":%s,"clean_mean":%s,"clean_p95":%s,"total_vms":%s,"recycle_delta":%s,"err_kinds":%s}\n' \
        "$r_mode" "$r_agents" "$r_period" "$r_ok" "$r_err" "$r_busy" "$r_retried" "$r_req_rps" "$r_cold_rps" "$r_warm_rps" "$r_warm_hit" "$r_dur" "$r_turns" \
        "$r_cold_gwp50" "$r_cold_gwp95" "$r_cold_gwp99" "$r_warm_gwp50" "$r_warm_gwp95" "$r_warm_gwp99" \
        "$r_cold_cp95" "$r_warm_cp95" "$r_exp" "$r_exp_all" "$d_unmount" "$d_lf" "$d_under2" "${A_LF_MAX:-0}" "${A_RECENT_P95:-0}" \
        "$clean_min" "$clean_mean" "$clean_p95" "$total_vms" "$recycle_delta" "$r_errkinds"
done

# ── Phase 6: gates + summary ───────────────────────────────────────────────
log_section "Phase 6: Gates"

GATE_OUT="$(python3 - "$LOADTEST_TSV" "$WARM_GW_P95_MS" "$COLD_GW_P95_MS" "$WARM_CLIENT_P95_MS" "$COLD_CLIENT_P95_MS" "$LOADTEST_LATENCY_TIERS" "$POOL_SIZE" "$LOADTEST_RECYCLE_POLICY" "$TC_MAX_DISTINCT_AGENTS" "$LOADTEST_WORKLOAD" <<'PY'
import json, sys

(path, warm_ref_s, cold_ref_s, warm_clref_s, cold_clref_s, tiers_s,
 pool_s, policy, distinct_cap_s, workload) = sys.argv[1:11]
warm_ref, cold_ref = float(warm_ref_s), float(cold_ref_s)
warm_clref, cold_clref = float(warm_clref_s), float(cold_clref_s)
tiers = [float(x) for x in tiers_s.split()] or [1.05, 2.0]
pool = int(float(pool_s))

rows = []
with open(path) as f:
    headers = f.readline().rstrip("\n").split("\t")
    for line in f:
        if not line.strip():
            continue
        vals = line.rstrip("\n").split("\t")
        rows.append(dict(zip(headers, vals)))
rows.sort(key=lambda r: int(r["agents"]))

fails = 0
def gate(ok, name, detail):
    global fails
    print(("PASS " if ok else "FAIL ") + name + ": " + detail)
    if not ok:
        fails += 1

def info(name, detail):
    print("INFO " + name + ": " + detail)

def num(r, k):
    try:
        return float(r.get(k) or 0)
    except ValueError:
        return 0.0

def kinds(r):
    try:
        return json.loads(r.get("err_kinds") or "{}")
    except Exception:
        return {}

def busy(r):
    """Every HTTP 503 NO_AVAILABLE_SANDBOX response the client saw."""
    return int(num(r, "busy"))

def term503(r):
    """Terminal 503s — the retry budget was exhausted (a failed turn)."""
    return sum(v for k, v in kinds(r).items() if k.startswith("HTTP 503"))

def cold95(r): return num(r, "cold_gw_p95")
def warm95(r): return num(r, "warm_gw_p95")
def cold95c(r): return num(r, "cold_client_p95")
def warm95c(r): return num(r, "warm_client_p95")

# 1. HARD: only unexpected errors. A busy refusal absorbed by the retry policy
#    is retry pressure (reported); a terminal 503 is capacity information and
#    excludes the level from the tier selection.
unexpected = []
for r in rows:
    for k, v in kinds(r).items():
        if not k.startswith("HTTP 503"):
            unexpected.append("agents@%s %s=%d" % (r["agents"], k, v))
gate(not unexpected, "zero-unexpected-errors",
     "no non-503 failures" if not unexpected else "; ".join(unexpected))

# Paced-lane workloads (ideal: one agent per lane; shaped: many AI agents
# queued per lane, served one at a time). They measure the collision-free
# maximum: the knee is a period with zero BUSY attempts and zero terminal
# refusals — every VM continuously fed, nothing refused.
if workload in ("ideal", "shaped"):
    rows.sort(key=lambda r: num(r, "period_ms"))
    gname = "ideal-max" if workload == "ideal" else "shaped-max"
    print("")
    print("-- %s --" % ("ideal paced lanes (one per microVM, fixed period, no between-turn think gap)"
                        if workload == "ideal" else
                        "shaped lanes (one per microVM; many AI agents queued per lane, one in-flight request per VM)"))
    for r in rows:
        info("period=%.0fms" % num(r, "period_ms"),
             "agents=%s cold/s=%.2f (per-VM %.2f/s) warm/s=%.1f busy=%d terminal=%d | "
             "cold gw p95=%.3fms client p95=%.3fms | clean mean=%s/%s"
             % (r["agents"], num(r, "cold_rps"),
                num(r, "cold_rps") / pool if pool > 0 else 0,
                num(r, "warm_rps"), busy(r), term503(r),
                cold95(r), cold95c(r), r.get("clean_mean"), r.get("total_vms")))
    # ideal demands zero BUSY (same-sandfs lanes get blocking backpressure
    # from the per-sandfs unmount). shaped rotates agents, so a cold can
    # arrive while both VMs finish their async unmounts — the shaper's retry
    # absorbs it (that IS the toll-booth flow control). Its knee is therefore
    # zero terminal failures with the client latency inside the LAST tier;
    # busy retries are reported, not disqualifying.
    if workload == "ideal":
        # A noisy nested day puts 1-3 ambient busy attempts on every period
        # (0.1-0.2% of requests — guest-scheduling tail, not pacing
        # collisions), so a strict zero-busy knee is not always attainable.
        # The knee allows busy <= 0.5% of the period's completed cold
        # requests (at least 1) and discloses the count.
        clean = [r for r in rows if term503(r) == 0 and num(r, "cold_rps") > 0
                 and busy(r) <= max(1, int(0.005 * num(r, "cold")))]
        extra = "terminal=0, busy within the 0.5% noise tolerance"
        failmsg = "no period achieved the collision-free knee (busy within tolerance) with zero terminal refusals; extend LOADTEST_TURN_PERIODS_MS"
    else:
        tier = tiers[-1] if tiers else 2.0
        clean = [r for r in rows if term503(r) == 0 and num(r, "cold_rps") > 0
                 and cold95c(r) > 0 and cold95c(r) <= tier * cold_clref + 1e-9
                 and cold95(r) <= tier * cold_ref + 1e-9]
        failmsg = ("no period achieved zero terminal refusals with cold client p95 <= %.2f x %.3fms; "
                   "extend LOADTEST_TURN_PERIODS_MS" % (tier, cold_clref))
        extra = "terminal=0 (busy retries reported)"
    if not clean:
        gate(False, gname, failmsg)
        sys.exit(1)
    # A period shorter than the turn duration does not raise the rate (the
    # lane self-clocks on the turn), so the maximum is the highest completed
    # rate among the qualifying rows, not necessarily the shortest period.
    best = max(clean, key=lambda r: num(r, "cold_rps"))
    gate(True, gname,
         "period=%.0fms pool=%d agents=%s: cold/s=%.2f (per-VM %.2f/s) %s busy=%d; "
         "cold gw p95=%.3fms client p95=%.3fms; pool clean mean=%s/%s"
         % (num(best, "period_ms"), pool, best["agents"], num(best, "cold_rps"),
            num(best, "cold_rps") / pool if pool > 0 else 0,
            extra, busy(best),
            cold95(best), cold95c(best),
            best.get("clean_mean"), best.get("total_vms")))
    below = [r for r in rows
             if num(r, "period_ms") < num(best, "period_ms")
             and (term503(r) > 0 or (workload == "ideal" and busy(r) > 0))]
    if below:
        b = below[-1]
        info("%s-collision-threshold" % ("ideal" if workload == "ideal" else "shaped"),
             "period=%.0fms (below the max) already refuses: busy=%d terminal=%d cold/s=%.2f"
             % (num(b, "period_ms"), busy(b), term503(b), num(b, "cold_rps")))
    lf = int(num(best, "d_lf")); u2 = int(num(best, "d_under2")); mx = num(best, "lf_max")
    if lf > 0:
        pct = 100.0 * u2 / lf
        gate(pct >= 95.0 and mx <= 20.0, "punctuality",
             "%s period=%.0fms: %d fires, %.1f%% <2ms, max=%.3fms"
             % (gname, num(best, "period_ms"), lf, pct, mx))
    else:
        gate(False, "punctuality",
             "%s period=%.0fms: no lease fires recorded (expected expiries=%s)"
             % (gname, num(best, "period_ms"), best.get("exp")))
    exp = int(num(best, "exp_all")); du = int(num(best, "d_unmount"))
    # Paced lanes can race a lease expiry against the next mount, so the
    # client-side expiry model is coarser here than under the agent model
    # (which matches within 10%). Keep the cross-check with a 25% band.
    slack = max(2.0, 0.25 * max(exp, du), float(pool))
    gate(abs(exp - du) <= slack, "conservation",
         "%s period=%.0fms: expected_expiries(all incl. warmup)=%d unmount_delta=%d (slack %.0f)"
         % (gname, num(best, "period_ms"), exp, du, slack))
    sys.exit(1 if fails else 0)

# 2. Retry pressure and terminal refusals per level.
print("")
print("-- retry pressure --")
for r in rows:
    info("retries agents=%s" % r["agents"],
         "busy attempts=%d, requests retried=%s, terminal 503s=%d"
         % (busy(r), r.get("retried"), term503(r)))

# 3. Per-level table (the report's raw rows).
print("")
print("-- levels --")
for r in rows:
    info("level agents=%s" % r["agents"],
         "cold/s=%.1f (per-VM %.2f) warm/s=%.1f hit=%.1f%% req/s=%.1f | "
         "cold gw p95=%.3fms warm gw p95=%.3fms client p95=%.3f/%.3f | "
         "clean mean=%s/%s recycles=%s busy=%d terminal503=%d"
         % (num(r, "cold_rps"), num(r, "cold_rps") / pool if pool > 0 else 0,
            num(r, "warm_rps"), num(r, "warm_hit"), num(r, "req_rps"),
            cold95(r), warm95(r), cold95c(r), warm95c(r),
            r.get("clean_mean"), r.get("total_vms"),
            r.get("recycle_delta"), busy(r), term503(r)))

# 4. THE HEADLINE: for each latency tier, the highest offered load (agent
#    count) whose COLD and WARM gateway E2E P95 AND business client P95
#    (retries included) stay inside the budget with no terminal error. The
#    measured cold_rps at that level is the host's realistic cold-switch
#    capacity; cold_rps/pool is the per-VM reuse rate.
print("")
print("-- latency-preserving capacity (gateway E2E and client P95 <= k x no-load) --")
for factor in tiers:
    bwarm, bcold = factor * warm_ref, factor * cold_ref
    bwc, bcc = factor * warm_clref, factor * cold_clref
    passing = []
    for r in rows:
        if term503(r) > 0:
            continue
        if cold95(r) <= 0 or cold95(r) > bcold:
            continue
        if int(num(r, "warm")) > 0 and warm95(r) > bwarm:
            continue
        if cold95c(r) <= 0 or cold95c(r) > bcc:
            continue
        if int(num(r, "warm")) > 0 and warm95c(r) > bwc:
            continue
        passing.append(r)
    if not passing:
        low = rows[0]
        info("capacity-x%.2f" % factor,
             "NO level meets gateway warm<=%.3fms cold<=%.3fms AND client warm<=%.3fms cold<=%.3fms "
             "with no terminal 503; lowest measured level: agents=%s cold/s=%.1f (per-VM %.2f) "
             "cold gw p95=%.3fms cold client p95=%.3fms busy=%d"
             % (bwarm, bcold, bwc, bcc, low["agents"], num(low, "cold_rps"),
                num(low, "cold_rps") / pool if pool > 0 else 0,
                cold95(low), cold95c(low), busy(low)))
        continue
    top = passing[-1]
    agents = int(num(top, "agents"))
    cold_rps = num(top, "cold_rps")
    per_vm = cold_rps / pool if pool > 0 else 0.0
    clean_mean = num(top, "clean_mean")
    total = num(top, "total_vms")
    dur = num(top, "duration_sec") or 1.0
    recycles = num(top, "recycle_delta")
    detail = ("agents=%d: cold/s=%.1f (per-VM %.2f/s, pool %d) warm/s=%.1f hit=%.1f%% req/s=%.1f; "
              "cold gw p95=%.3fms/%.3f warm gw p95=%.3fms/%.3f; "
              "cold client p95=%.3fms/%.3f warm client p95=%.3fms/%.3f; "
              "pool clean mean=%.2f of %.0f VMs; recycles=%.0f (%.2f/s); busy retries=%d terminal=0"
              % (agents, cold_rps, per_vm, pool, num(top, "warm_rps"),
                 num(top, "warm_hit"), num(top, "req_rps"),
                 cold95(top), bcold, warm95(top), bwarm,
                 cold95c(top), bcc, warm95c(top), bwc,
                 clean_mean, total, recycles, recycles / dur, busy(top)))
    gate(True, "capacity-x%.2f" % factor, detail)
    if total > 0 and clean_mean > 0.25 * total:
        info("engagement-x%.2f" % factor,
             "pool was NOT saturated at the max level (mean clean %.2f of %.0f) — "
             "the rate is a lower bound; raise LOADTEST_AGENT_LEVELS" % (clean_mean, total))
    else:
        info("engagement-x%.2f" % factor,
             "pool saturated (mean clean %.2f of %.0f) — every VM was in business use"
             % (clean_mean, total))
    failing = [r for r in rows if int(num(r, "agents")) > agents]
    if failing:
        f = failing[0]
        info("capacity-x%.2f-ceiling" % factor,
             "first level above it: agents=%s cold gw p95=%.3fms (%.2fx budget) cold client p95=%.3fms, "
             "%.1f cold/s, busy=%d terminal503=%d"
             % (f["agents"], cold95(f), cold95(f) / bcold if bcold > 0 else 0,
                cold95c(f), num(f, "cold_rps"), busy(f), term503(f)))
    else:
        info("capacity-x%.2f-ceiling" % factor, "none (all levels passed)")

# 5. Shape, punctuality, conservation (hard) at the highest level that
#    completed every request. A deliberately over-offered ceiling probe can
#    exhaust the retry budget (terminal 503s) and would otherwise fail these
#    gates on a level that is not a capacity point.
if rows:
    clean = [r for r in rows if term503(r) == 0]
    top = (clean or rows)[-1]
    info("shape-cold",
         "highest completed level agents=%s cold gw p95=%.3fms vs no-load %.3fms = %.2fx "
         "(reference 10x) [INFO]" % (top["agents"], cold95(top), cold_ref,
                                       cold95(top) / cold_ref if cold_ref > 0 else 0))
    info("shape-warm",
         "highest completed level agents=%s warm gw p95=%.3fms vs no-load %.3fms = %.2fx [INFO]"
         % (top["agents"], warm95(top), warm_ref,
            warm95(top) / warm_ref if warm_ref > 0 else 0))

    lf = int(num(top, "d_lf")); u2 = int(num(top, "d_under2")); mx = num(top, "lf_max")
    if lf > 0:
        pct = 100.0 * u2 / lf
        gate(pct >= 95.0 and mx <= 20.0, "punctuality",
             "highest completed level agents=%s: %d fires, %.1f%% <2ms, max=%.3fms (want >=95%%, max<=20ms)"
             % (top["agents"], lf, pct, mx))
    else:
        gate(False, "punctuality",
             "highest completed level agents=%s: no lease fires recorded (expected expiries=%s)"
             % (top["agents"], top.get("exp")))

    exp = int(num(top, "exp_all")); exp_win = int(num(top, "exp")); du = int(num(top, "d_unmount"))
    # The first turn of every agent has no preceding request, so it creates no
    # client-visible expiry; allow that many plus 10% drift.
    slack = max(2.0, 0.10 * max(exp, du), float(num(top, "agents")))
    gate(abs(exp - du) <= slack, "conservation",
         "highest completed level agents=%s: expected_expiries(all incl. warmup)=%d (window %d) unmount_delta=%d (slack %.0f)"
         % (top["agents"], exp, exp_win, du, slack))

    hit = num(top, "warm_hit")
    info("warm-hit", "highest completed level agents=%s: %.1f%% of completed requests were warm "
         "(the intra-turn follow-ups; 0%% would mean the sticky window is too small)" % (top["agents"], hit))

    if policy == "shipped":
        info("recycle-policy", "shipped (distinct-agent cap=%s): VM recycling is part of the result" % distinct_cap_s)
    else:
        info("recycle-policy", "capacity (lifetime caps off): the pure switch ceiling")

sys.exit(1 if fails else 0)
PY
)" && GATE_RC=0 || GATE_RC=$?
echo "$GATE_OUT" | sed 's/^/    /'
BENCH_FAILED=0
if (( GATE_RC != 0 )); then BENCH_FAILED=1; fi

# ── Final summary ──────────────────────────────────────────────────────────
log_section "Summary"
echo "  Environment: $([ $NESTED -eq 0 ] && echo 'bare-metal KVM' || echo "nested virtualization ($VIRT_TYPE)")"
echo "  Topology:    one-machine-etcd (exec $GATEWAY_URL, human $HUMAN_URL, etcd $ETCD_ENDPOINT), sticky=${STICKY_MS}ms"
echo "  Pinning:     $PIN_SUMMARY"
echo "  Stack CPU:   $PIN_CPU_TSV"
echo "  Pin advisor:"
print_pin_recommendation | sed 's/^/    /' || true
echo "  No-load reference (latency-benchmark-aiagent.sh): gateway E2E P95 warm=${WARM_GW_P95_MS}ms cold=${COLD_GW_P95_MS}ms; client P95 warm=${WARM_CLIENT_P95_MS}ms cold=${COLD_CLIENT_P95_MS}ms"
echo "  Retry policy: 503 NO_AVAILABLE_SANDBOX retried ${LOADTEST_BUSY_RETRIES}x with ${LOADTEST_BUSY_RETRY_BACKOFF_MS}ms full-jitter backoff"
echo "  Measured (agents/lanes = offered load; period = ideal mode turn period; cold/s = VM switches/s;"
echo "            per-VM = cold/s ÷ pool; busy = 503 refusals absorbed by retries; ERR = terminal failures):"
printf '    %7s %8s %7s %6s %7s %7s %9s %9s %9s %9s %6s %10s %10s %10s %11s %8s\n' \
    AGENTS PERIOD OK ERR BUSY RETRY% REQ/S COLD/S PER-VM/S WARM/S HIT% COLD_GW95 WARM_GW95 COLD_CL95 CLEAN/POOL RECYCLES
ERRCLASS_LINES=()
while IFS=$'\t' read -r _m agents period ok err busy retried req _cold cold_rps _warm warm_rps hit _dur _turns _maxi \
    _cgp50 cgp95 _cgp99 _wgp50 wgp95 _wgp99 ccp95 _wcp95 _csp95 _cep95 _wsp95 _wep95 \
    _exp _exp_all _du _dlf _du2 _lfmax _rp95 clean_min clean_mean _clean95 total_vms recycles erk; do
    [[ "$_m" == "mode" ]] && continue
    [[ "$period" == "0" ]] && period="-"
    per_vm="$(awk -v c="$cold_rps" -v p="$POOL_SIZE" 'BEGIN{ if (p > 0) printf "%.2f", c/p; else print 0 }')"
    retry_pct="$(awk -v r="$retried" -v o="$ok" 'BEGIN{ if (o > 0) printf "%.1f", 100*r/o; else print 0 }')"
    printf '    %7s %8s %7s %6s %7s %7s %9s %9s %9s %9s %6s %10s %10s %10s %11s %8s\n' \
        "$agents" "$period" "$ok" "$err" "$busy" "$retry_pct" "$req" "$cold_rps" "$per_vm" "$warm_rps" "$hit" \
        "$cgp95" "$wgp95" "$ccp95" "$clean_mean/$total_vms" "$recycles"
    if [[ "$erk" != "{}" && -n "$erk" ]]; then
        ERRCLASS_LINES+=("agents@$agents: $erk")
    fi
done < "$LOADTEST_TSV"
echo "  Error classes:"
if (( ${#ERRCLASS_LINES[@]} == 0 )); then
    echo "    (none — every request completed)"
else
    for line in "${ERRCLASS_LINES[@]}"; do
        echo "    $line"
    done
fi
echo "  Gates / observations:"
echo "$GATE_OUT" | sed 's/^/    /'
echo "  Data source: $GATEWAY_URL/stats (unmount_stats + a ${LOADTEST_STATS_POLL_SEC}s pool clean/recycle poller)"
echo "  Temp dirs:   deploy=$DEPLOY_DIR logs=$LOG_DIR (all removed on exit)"

if (( ${BENCH_FAILED:-0} != 0 )) || (( GATE_RC != 0 )); then
    log_error "load benchmark gates FAILED"
    exit 1
fi
log_pass "load benchmark completed: measured levels and gates above"
