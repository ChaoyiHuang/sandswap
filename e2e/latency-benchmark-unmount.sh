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
# latency-benchmark-unmount.sh — unmount full-path latency benchmark.
# The gateway ALREADY records per-unmount three-layer latency (warden /
# sandlot / gateway E2E — gateway/pool/sandlot.go UnmountResult) in
# UnmountStats and exposes it via GET /stats → unmount_stats (counters + top-10
# slowest entries, each carrying gateway_ms/sandlot_ms/warden_ms). This
# benchmark drives unmounts under contrasting workloads and takes ALL
# measurements from that existing collection — no log scraping, zero new
# instrumentation in gateway/sandlot/warden.
# Per iteration: exec returns → sticky lease (100ms) expires → the gateway's
# lease-expiry worker sends UnmountRootfs (8s ctx) → sandlot: warden unmount
# (cgroup.kill + teardown mounts + umount + global drop_caches) + vmm set-fs
# clear allowed_dirs → VM back to CLEAN. Iterations are serialized by polling
# the node's unmount_count in /stats: +1 means the unmount finished AND its
# three-layer latency was recorded (RecordUnmount runs on both success and
# failure paths).
# Scenarios (single agent + single sandfs; every iteration cold-mounts):
#   baseline  `echo ok` (shell)                       — floor: fixed costs only
#   cache16m  python3 writes FILE_MB MB to /workspace + fsync + reads back →
#             clean page cache → drop_caches scales with cache size
#   dirty16m  python3 writes FILE_MB MB, NO fsync → umount(2) writeback over
#             virtio-fs (FILE_MB stays dirty: dirty_background ≈25MB @256MB VM)
# Attribution: every workload's first line is a `# bench:<scenario>` marker.
# It becomes part of the cold-mount exec command that UnmountStats remembers
# (RecordMount stores the wrapped command), so top_slow[].command identifies
# the scenario that produced the entry.
# Metric boundary (existing collection — read before interpreting):
#   - under_5ms/under_10ms are strict thresholds on the GATEWAY layer only.
#   - top_slow keeps only the 10 slowest entries GLOBALLY per node. This
#     script snapshots top_slow after each scenario and differences, so a
#     later (slower) scenario cannot evict an earlier scenario's entries.
#   - recent/recent_warden are ROLLING-WINDOW percentile summaries (the
#     gateway keeps the last N=1024 samples per layer). They answer the
#     per-sample P50/P95 question the counters and top-10 could not; the
#     window is cumulative across scenarios (it is a window, not a per-
#     scenario ledger), so the per-scenario lines are labeled as such and
#     the final summary prints the run-wide P95 for both layers.
# Usage:
#   bash e2e/latency-benchmark-unmount.sh [baseline|cache16m|dirty16m|all]
#   (default: all = baseline + cache16m + dirty16m)
# Env:
#   ITER_N=20          samples per scenario (1 extra warmup each, discarded)
#   FILE_MB=16         workload file size (page-cache / dirty-page volume)
#   UNMOUNT_WAIT_S=90  per-iteration timeout waiting for the unmount to land
#   BENCH_VERBOSE=0    1 = print per-iteration progress
#   POOL_SIZE=3 VM_MEMORY_MB=256 NETWORK_BACKEND=bridge
# Data source: in single-node mode /stats lives on the HUMAN listener
# ($HUMAN_URL, default :3100) — the unmount recorder there is in-memory and
# real-time. The guest rootfs must be Ubuntu WITH python3: output/rootfs-ubuntu
# is auto-built via build/build-ubuntu-rootfs.sh when missing or when
# it lacks python3 (ubuntu-base does not ship python3).
# Prerequisites: /dev/kvm, /dev/vhost-vsock, built output/ (build.sh all),
# root, and network access for the first Ubuntu rootfs download (~80MB).
# Self-cleaning: deploys its own throwaway stack (binaries, certs, volumes,
# logs) and removes ALL of it on exit. output/rootfs-ubuntu is kept and reused.

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

# Config defaults — set BEFORE sourcing common.sh (common.sh reads caller scope).
DEPLOY_DIR="${DEPLOY_DIR:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}}"
VOL_ROOT="${VOL_ROOT:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
HUMAN_URL="${HUMAN_URL:-http://localhost:3100}"
POOL_SIZE="${POOL_SIZE:-3}"
# Bare-metal CPU/NUMA pinning (auto: on for bare metal, off under any
# hypervisor). See e2e/pin.sh.
PIN_STACK_CORES="${PIN_STACK_CORES:-8}"
PIN_SLICE_CPUS="${PIN_SLICE_CPUS:-2}"
PIN_SLICE_CPUS="${PIN_SLICE_CPUS:-2}"
SANDLOT_POOL="${SANDLOT_POOL:-small:${POOL_SIZE}}"
VM_MEMORY_MB="${VM_MEMORY_MB:-256}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
ROOTFS_UBUNTU="${ROOTFS_UBUNTU:-$OUTPUT/rootfs-ubuntu}"

# Benchmark knobs.
ITER_N="${ITER_N:-20}"
FILE_MB="${FILE_MB:-16}"
UNMOUNT_WAIT_S="${UNMOUNT_WAIT_S:-90}"
BENCH_VERBOSE="${BENCH_VERBOSE:-0}"

source "$ROOT/e2e/common.sh"
source "$ROOT/e2e/pin.sh"

# Scenario selector: $1 = baseline|cache16m|dirty16m|all (default all).
SCENARIO_SEL="${1:-all}"
case "$SCENARIO_SEL" in
    all) SCEN_LIST=(baseline cache16m dirty16m) ;;
    baseline|cache16m|dirty16m) SCEN_LIST=("$SCENARIO_SEL") ;;
    *) echo "Usage: $0 [baseline|cache16m|dirty16m|all]   (default: all)" >&2; exit 1 ;;
esac

NODE_ID="${TC_NODE_ID:-test-node-1}"
STATS_JSON="$LOG_DIR/unmount-stats.json"
SLOW_TSV="$LOG_DIR/unmount-slow.tsv"

LAST_COUNT=0    # last observed unmount_count for the node (iteration watermark)
UNMOUNT_MS=0    # wall ms from wait_unmount() call to the counter increment

cleanup() {
    tc_cleanup_default
    # Self-clean the artifacts THIS benchmark deployed (surgical: never the
    # shared $DEPLOY_DIR itself — see tc_cleanup_deployed_artifacts).
    tc_cleanup_deployed_artifacts
}
trap cleanup EXIT INT TERM

# ── Stats helpers (the ONLY measurement channel: GET $HUMAN_URL/stats) ──────

# fetch_stats — refresh $STATS_JSON from the single-node human listener.
fetch_stats() {
    curl -s -m 10 "$HUMAN_URL/stats" > "$STATS_JSON" 2>/dev/null || true
}

# unmount_counters — echo "<unmount_count> <success> <fail> <under_5ms>
# <under_10ms> <mount_count>" for $NODE_ID (zeros when absent/undecodable).
unmount_counters() {
    python3 - "$STATS_JSON" "$NODE_ID" <<'PY'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("0 0 0 0 0 0"); raise SystemExit
node = sys.argv[2]
for g in d.get("gateways") or []:
    for u in g.get("unmount_stats") or []:
        if u.get("node_id") == node:
            print(u.get("unmount_count", 0), u.get("unmount_success", 0),
                  u.get("unmount_fail", 0), u.get("under_5ms", 0),
                  u.get("under_10ms", 0), u.get("mount_count", 0))
            raise SystemExit
print("0 0 0 0 0 0")
PY
}

# snapshot_counters <array-name> — refresh $STATS_JSON and read the node's
# counters into a 6-element array (count success fail under5 under10 mounts).
# Nameref: bash 4.3+. Aborts on malformed output (stats shape drift).
snapshot_counters() {
    local -n arr="$1"
    fetch_stats
    local line
    line=$(unmount_counters)
    read -ra arr <<< "$line"
    if (( ${#arr[@]} != 6 )); then
        log_error "malformed unmount counters: '$line' — /stats shape changed?"
        exit 1
    fi
}

# recent_p95 — echo the node's rolling-window percentiles:
#   "<gw_n> <gw_p50> <gw_p95> <gw_p99> <gw_max> <wd_n> <wd_p50> <wd_p95> <wd_p99> <wd_max>"
# from unmount_stats[].recent / .recent_warden (the gateway's per-sample ring;
# values are milliseconds, µs resolution). Zeros when absent/undecodable.
recent_p95() {
    python3 - "$STATS_JSON" "$NODE_ID" <<'PY'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("0 0 0 0 0 0 0 0 0 0"); raise SystemExit
node = sys.argv[2]
for g in d.get("gateways") or []:
    for u in g.get("unmount_stats") or []:
        if u.get("node_id") == node:
            r = u.get("recent") or {}
            w = u.get("recent_warden") or {}
            print(r.get("n", 0), r.get("p50_ms", 0), r.get("p95_ms", 0),
                  r.get("p99_ms", 0), r.get("max_ms", 0),
                  w.get("n", 0), w.get("p50_ms", 0), w.get("p95_ms", 0),
                  w.get("p99_ms", 0), w.get("max_ms", 0))
            raise SystemExit
print("0 0 0 0 0 0 0 0 0 0")
PY
}

# dump_top_slow <out.json> — snapshot the node's full top_slow list.
dump_top_slow() {
    python3 - "$STATS_JSON" "$NODE_ID" "$1" <<'PY'
import sys, json
res = []
try:
    d = json.load(open(sys.argv[1]))
    node = sys.argv[2]
    for g in d.get("gateways") or []:
        for u in g.get("unmount_stats") or []:
            if u.get("node_id") == node:
                res = u.get("top_slow") or []
except Exception:
    pass
json.dump(res, open(sys.argv[3], "w"))
PY
}

# wait_unmount <prev_count> — poll /stats until unmount_count passes prev.
# Updates LAST_COUNT and UNMOUNT_MS. Returns 1 on timeout.
wait_unmount() {
    local prev="$1" cur t0 now
    t0=$(date +%s%N)
    local deadline=$(( $(date +%s) + UNMOUNT_WAIT_S ))
    while (( $(date +%s) < deadline )); do
        fetch_stats
        cur=$(unmount_counters | awk '{print $1}')
        if (( cur > prev )); then
            now=$(date +%s%N)
            UNMOUNT_MS=$(( (now - t0) / 1000000 ))
            LAST_COUNT="$cur"
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# ── Workload helpers ────────────────────────────────────────────────────────

# gen_cache_code — python workload: write FILE_MB MB to /workspace + fsync +
# read back → clean page cache (isolates drop_caches growth).
gen_cache_code() {
    python3 - "$FILE_MB" <<'PY'
import sys
mb = int(sys.argv[1])
print("# bench:cache16m")
print("import os")
print("data = os.urandom(1024 * 1024)")
print('with open("/workspace/bench.bin", "wb") as f:')
print(f"    for _ in range({mb}):")
print("        f.write(data)")
print("    f.flush()")
print("    os.fsync(f.fileno())")
print('with open("/workspace/bench.bin", "rb") as f:')
print("    while f.read(1024 * 1024):")
print("        pass")
print('print("ok")')
PY
}

# gen_dirty_code — python workload: write FILE_MB MB, NO fsync → pages stay
# dirty past exec return (dirty_background ≈25MB @256MB VM), so umount(2)
# pays the writeback over virtio-fs.
gen_dirty_code() {
    python3 - "$FILE_MB" <<'PY'
import sys
mb = int(sys.argv[1])
print("# bench:dirty16m")
print("import os")
print("data = os.urandom(1024 * 1024)")
print('with open("/workspace/bench.bin", "wb") as f:')
print(f"    for _ in range({mb}):")
print("        f.write(data)")
print('print("ok")')
PY
}

# gen_baseline_code — shell floor.
gen_baseline_code() {
    printf '# bench:baseline\necho ok\n'
}

# exec_workload <code> <language> — POST /agent/execute; echoes the body.
exec_workload() {
    local body
    body=$(CODE="$1" BLANG="$2" SANDFS_ID_S="$SANDFS_ID" python3 -c '
import os, json
print(json.dumps({"sandfs_id": os.environ["SANDFS_ID_S"],
                  "code": os.environ["CODE"],
                  "language": os.environ["BLANG"],
                  "timeout": 60}))')
    curl -s -m 120 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$body" || echo '{"error":"exec request failed (curl timeout/connection)"}'
}

# pct <part> <total> — integer percentage (n/a when total is 0).
pct() {
    if (( $2 == 0 )); then echo "n/a"; else
        python3 -c "print(f'{$1 / $2 * 100:.0f}%')"
    fi
}

# ── Scenario runner ─────────────────────────────────────────────────────────

# run_scenario <name> — warmup (discarded) → before-snapshot → ITER_N
# serialized iterations → after-snapshot → counter deltas + new top_slow
# entries attributed by the workload's `# bench:<scenario>` marker.
run_scenario() {
    local name="$1" code lang marker
    case "$name" in
        baseline) code="$(gen_baseline_code)"; lang="shell"; marker="# bench:baseline" ;;
        cache16m) code="$(gen_cache_code)";    lang="python"; marker="# bench:cache16m" ;;
        dirty16m) code="$(gen_dirty_code)";    lang="python"; marker="# bench:dirty16m" ;;
        *) log_error "unknown scenario $name"; exit 1 ;;
    esac

    log_section "Scenario: $name (ITER_N=$ITER_N + 1 warmup, FILE_MB=$FILE_MB)"
    log_info "data source: $HUMAN_URL/stats unmount_stats (node $NODE_ID); workload lang=$lang"

    # Warmup (discarded): proves the path end-to-end and creates the node's
    # unmount_stats entry before the before-snapshot.
    local resp err out
    resp=$(exec_workload "$code" "$lang")
    err=$(json_val "$resp" "error")
    if [[ -n "$err" ]]; then
        log_error "warmup exec failed: $err — stack is unhealthy, aborting"
        exit 1
    fi
    if ! wait_unmount "$LAST_COUNT"; then
        log_warn "warmup unmount not recorded within ${UNMOUNT_WAIT_S}s — continuing"
    fi

    fetch_stats
    local before
    snapshot_counters before
    dump_top_slow "$LOG_DIR/slow-before-$name.json"

    local i exec_err=0 badout=0 timeouts=0
    SCEN_BROKEN=0
    for i in $(seq 1 "$ITER_N"); do
        resp=$(exec_workload "$code" "$lang")
        err=$(json_val "$resp" "error")
        if [[ -n "$err" ]]; then
            exec_err=$((exec_err + 1))
            log_warn "iter $i: exec error: $err"
            continue
        fi
        out=$(json_val "$resp" "stdout")
        if [[ "$out" != *ok* ]]; then
            badout=$((badout + 1))
            log_warn "iter $i: unexpected stdout: ${out:0:60}"
        fi
        if wait_unmount "$LAST_COUNT"; then
            (( BENCH_VERBOSE == 1 )) && log_info "iter $i: unmount recorded (+${UNMOUNT_MS}ms after exec return)"
        else
            timeouts=$((timeouts + 1))
            log_warn "iter $i: unmount not recorded within ${UNMOUNT_WAIT_S}s"
        fi
    done

    fetch_stats
    local after
    snapshot_counters after
    dump_top_slow "$LOG_DIR/slow-after-$name.json"

    local n=$(( after[0] - before[0] ))
    local succ=$(( after[1] - before[1] ))
    local fail=$(( after[2] - before[2] ))
    local u5=$(( after[3] - before[3] ))
    local u10=$(( after[4] - before[4] ))
    local mounts=$(( after[5] - before[5] ))

    local nslow
    nslow=$(python3 - "$LOG_DIR/slow-before-$name.json" "$LOG_DIR/slow-after-$name.json" "$marker" "$name" "$SLOW_TSV" <<'PY'
import sys, json
with open(sys.argv[1]) as f:
    before = {json.dumps(e, sort_keys=True) for e in json.load(f)}
marker, name, tsv = sys.argv[3], sys.argv[4], sys.argv[5]
new = [e for e in json.load(open(sys.argv[2]))
       if json.dumps(e, sort_keys=True) not in before
       and marker in (e.get("command") or "")]
with open(tsv, "a") as f:
    for e in new:
        f.write("\t".join([name, str(e.get("gateway_ms", 0)), str(e.get("sandlot_ms", 0)),
                           str(e.get("warden_ms", 0)), e.get("reason", ""),
                           e.get("timestamp", "")]) + "\n")
print(len(new))
PY
)

    if (( mounts != ITER_N )); then
        log_error "$name: mount_count delta ($mounts) != ITER_N ($ITER_N) — cold-mount accounting broken"
        SCEN_BROKEN=1
    fi
    log_pass "$name: n=$n success=$succ fail=$fail timeout=$timeouts exec_err=$exec_err badout=$badout"
    echo "    under_5ms:  $u5 ($(pct "$u5" "$n"))    under_10ms: $u10 ($(pct "$u10" "$n"))    new top_slow entries: $nslow"
    local -a REC
    read -ra REC <<< "$(recent_p95)"
    echo "    recent ring (cumulative window): gateway n=${REC[0]} P50=${REC[1]}ms P95=${REC[2]}ms P99=${REC[3]}ms max=${REC[4]}ms | warden n=${REC[5]} P50=${REC[6]}ms P95=${REC[7]}ms P99=${REC[8]}ms max=${REC[9]}ms"

    SCEN_SUMMARY+=("$name|$n|$succ|$fail|$timeouts|$exec_err|$badout|$u5|$u10|$nslow")
    if (( SCEN_BROKEN == 1 )); then
        log_error "$name: scenario accounting broken (see above)"
        BENCH_FAILED=1
    fi
}

# max_warden_for <scenario> — slowest recorded warden-layer unmount (0 if none).
max_warden_for() {
    awk -F'\t' -v s="$1" '$1 == s && $4 + 0 > m { m = $4 + 0 } END { print m + 0 }' "$SLOW_TSV"
}

print_slow_table() {
    if [[ ! -s "$SLOW_TSV" ]]; then
        echo "  (no top_slow entries recorded — unmounts were all faster than the"
        echo "   entries already present, or the 10-slot list was full of faster ones)"
        return
    fi
    printf "  %-9s %11s %11s %10s  %-22s %s\n" "scenario" "gateway_ms" "sandlot_ms" "warden_ms" "reason" "timestamp"
    sort -t$'\t' -k1,1 -k2,2nr "$SLOW_TSV" | while IFS=$'\t' read -r s g sl w r ts; do
        printf "  %-9s %11s %11s %10s  %-22s %s\n" "$s" "$g" "$sl" "$w" "$r" "$ts"
    done
}

# ── Ubuntu rootfs (guest needs python3; ubuntu-base does not ship it) ───────

ensure_ubuntu_rootfs() {
    local need_build=0
    if [[ ! -d "$ROOTFS_UBUNTU/bin" ]]; then
        need_build=1
    elif [[ ! -x "$ROOTFS_UBUNTU/usr/bin/python3" ]]; then
        log_warn "Ubuntu rootfs lacks python3 — rebuilding with python3 included..."
        need_build=1
    fi
    if (( need_build )); then
        log_step "Building Ubuntu rootfs (UBUNTU_PACKAGES includes python3)..."
        # Explicit OUTPUT: the builder's own default is this path, but do not
        # let our (unexported) OUTPUT variable ever leak into it.
        OUTPUT="$ROOTFS_UBUNTU" UBUNTU_PACKAGES="ca-certificates,locales,apt-utils,python3" \
            bash "$ROOT/build/build-ubuntu-rootfs.sh" \
            || { log_error "Ubuntu rootfs build failed"; exit 1; }
    fi
    [[ -x "$ROOTFS_UBUNTU/usr/bin/python3" ]] \
        || { log_error "Ubuntu rootfs missing /usr/bin/python3 — cannot run python workloads"; exit 1; }
    log_pass "Ubuntu rootfs with python3: $ROOTFS_UBUNTU ($(du -sh "$ROOTFS_UBUNTU" | cut -f1))"
}

deploy_ubuntu_template() {
    # tc_deploy_artifacts already laid down the busybox template; replace it —
    # the agent volume is seeded from flat-templates/rootfs/v1 at sandfs
    # creation (Phase 4), so this must run before that.
    log_step "Deploying Ubuntu rootfs template (replacing default busybox)..."
    rm -rf "$DEPLOY_DIR/flat-templates/rootfs/v1"
    mkdir -p "$DEPLOY_DIR/flat-templates/rootfs/v1"
    cp -a "$ROOTFS_UBUNTU/." "$DEPLOY_DIR/flat-templates/rootfs/v1/"
    # Group grant + contract check (see tc_conform_template_tree).
    tc_conform_template_tree "$DEPLOY_DIR/flat-templates"
    [[ -d "$DEPLOY_DIR/flat-templates/rootfs/v1/bin" ]] \
        || { log_error "Ubuntu template copy failed (no bin/)"; exit 1; }
    [[ -d "$DEPLOY_DIR/flat-templates/rootfs/v1/workspace" ]] \
        || { log_error "Ubuntu template missing /workspace"; exit 1; }
    [[ -x "$DEPLOY_DIR/flat-templates/rootfs/v1/usr/bin/python3" ]] \
        || { log_error "Deployed Ubuntu template missing /usr/bin/python3"; exit 1; }
    log_pass "Ubuntu template deployed: $DEPLOY_DIR/flat-templates/rootfs/v1/ ($(du -sh "$DEPLOY_DIR/flat-templates/rootfs/v1" | cut -f1))"
}

# ════════════════════════════════════════════════════════════════════════════
# Phase 0: environment detection
# ════════════════════════════════════════════════════════════════════════════
log_section "Phase 0: Environment detection (bare metal vs nested virt)"

VIRT_TYPE="$(systemd-detect-virt 2>/dev/null || true)"
VIRT_TYPE="${VIRT_TYPE//$'\n'/}"
HYPER_FLAG=$(grep -c -m1 '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null) || true
NESTED=0
if [[ "$VIRT_TYPE" == "none" || -z "$VIRT_TYPE" ]] && [[ "${HYPER_FLAG:-0}" -eq 0 ]]; then
    log_pass "Bare-metal detected -> bare-metal KVM host"
elif [[ "$VIRT_TYPE" != "none" && -n "$VIRT_TYPE" ]] || [[ "${HYPER_FLAG:-0}" -gt 0 ]]; then
    NESTED=1
    log_warn "Nested virtualization detected (systemd-detect-virt=$VIRT_TYPE) — results labeled [NESTED-VIRT]"
fi

# Bare-metal CPU/NUMA pinning: re-exec under taskset so the gateway, sandlot
# and benchmark client all inherit the stack cores. Nested virt is never
# pinned. The per-VM shim is generated after deploy (tc_pin_setup).
PIN_MODE="$(tc_pin_resolve_mode "$NESTED")" || exit 1
if [[ "$PIN_MODE" == "1" ]]; then
    PIN_SLICES="${PIN_SLICES:-$POOL_SIZE}"
    tc_pin_reexec_if_needed "$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")" "$@" || exit 1
else
    unset TC_VMM_BINARY 2>/dev/null || true
fi
echo "    CPU cores: $(nproc)    load: $(uptime | sed 's/.*load average:/load:/')"
echo "    Pinning:   PIN_MODE=$PIN_MODE (${PIN_STACK_CPUS:-auto} stack cores, ${PIN_SLICE_SPECS:-auto} VM slices)"

[[ -e /dev/kvm ]] || { log_error "/dev/kvm missing — KVM required"; exit 1; }
log_pass "/dev/kvm available"

if [[ ! -r /dev/vhost-vsock ]]; then
    log_warn "/dev/vhost-vsock not readable, trying modprobe vhost_vsock..."
    modprobe vhost_vsock 2>/dev/null || true
fi
[[ -r /dev/vhost-vsock ]] || { log_error "/dev/vhost-vsock not readable — run modprobe vhost_vsock and retry"; exit 1; }
log_pass "/dev/vhost-vsock readable"

tc_check_tools curl python3
tc_check_freshness

# ════════════════════════════════════════════════════════════════════════════
# Phase 1: Deploy (+ Ubuntu rootfs with python3)
# ════════════════════════════════════════════════════════════════════════════
log_section "Phase 1: Deploy"
ensure_ubuntu_rootfs
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
deploy_ubuntu_template
tc_gen_certs
tc_attach_vsockguard

# ════════════════════════════════════════════════════════════════════════════
# Phase 2: Start gateway (single-node: agent+human in one process)
# ════════════════════════════════════════════════════════════════════════════
log_section "Phase 2: Start gateway (single-node)"
tc_start_gateway

# ════════════════════════════════════════════════════════════════════════════
# Phase 3: Start sandlot
# ════════════════════════════════════════════════════════════════════════════
log_section "Phase 3: Start sandlot (connects to gateway, mTLS)"
# SANDLOT_EXTRA_FLAGS: extra CLI flags for the sandlot under test (e.g.
# enabler on/off comparisons: "-binding-backend=shm -egress-baseline on").
# Benchmark VM shape: exactly 1 vCPU / 256 MiB / 3 exec slots, injected as
# a named `bench` spec (same as the aiagent/load benchmarks) so the unmount
# measurements use the same microVM shape. One vCPU leaves the second SMT
# thread of its physical core for the vhost/virtiofs threads.
UNMOUNT_CFG="$DEPLOY_DIR/sandlot-unmount.yaml"
tc_gen_sandlot_config "$UNMOUNT_CFG"
python3 - "$UNMOUNT_CFG" "$POOL_SIZE" <<'PY'
import re, sys
path, pool = sys.argv[1], sys.argv[2]
s = open(path).read()
s = s.replace("specs:\n",
              "specs:\n  bench:\n    vcpus: 1\n    memory_mb: 256\n    exec_slots: 3\n", 1)
s = re.sub(r'(?m)^pool:.*$', 'pool: "bench:%s"' % pool, s, count=1)
open(path, "w").write(s)
PY
export TC_SANDLOT_CONFIG="$UNMOUNT_CFG"
tc_start_sandlot ${SANDLOT_EXTRA_FLAGS:-}
tc_wait_health
tc_wait_pool_ready

# ════════════════════════════════════════════════════════════════════════════
# Phase 4: create agent + sandfs (seeded from the Ubuntu template)
# ════════════════════════════════════════════════════════════════════════════
log_section "Phase 4: Create agent + sandfs (Ubuntu rootfs)"
RESP_A=$(tc_create_agent_and_sandfs "unmount-bench" || echo '{"error":"create failed"}')
API_KEY=$(json_val "$RESP_A" "api_key")
SANDFS_ID=$(json_val "$RESP_A" "sandfs_id")
[[ -n "$API_KEY" && -n "$SANDFS_ID" ]] || { log_error "agent/sandfs creation failed"; exit 1; }
log_pass "agent created (sandfs $SANDFS_ID)"

# ════════════════════════════════════════════════════════════════════════════
# Phase 5: run scenarios (all measurements from $HUMAN_URL/stats)
# ════════════════════════════════════════════════════════════════════════════
log_section "Phase 5: Run unmount scenarios (data source: /stats unmount_stats)"

fetch_stats
if ! python3 -c 'import sys,json; d=json.load(open(sys.argv[1])); assert d.get("gateways") is not None' "$STATS_JSON" 2>/dev/null; then
    log_error "/stats at $HUMAN_URL did not return the expected gateways[] report"
    exit 1
fi
log_pass "/stats reachable at $HUMAN_URL (node: $NODE_ID)"

# Fresh slow-sample ledger for this run (the dir was wiped by tc_clean_environment).
: > "$SLOW_TSV"

SCEN_SUMMARY=()
BENCH_FAILED=0   # scenarios above may already flag accounting breakage
for s in "${SCEN_LIST[@]}"; do
    run_scenario "$s"
done
if (( ${#SCEN_SUMMARY[@]} != ${#SCEN_LIST[@]} )); then
    log_error "only ${#SCEN_SUMMARY[@]}/${#SCEN_LIST[@]} scenarios produced a summary — a scenario aborted mid-run"
    exit 1
fi

# ════════════════════════════════════════════════════════════════════════════
# Phase 6: Verdict
# ════════════════════════════════════════════════════════════════════════════
log_section "Phase 6: Slow unmount samples (top_slow, attributed by workload marker)"
print_slow_table

log_section "Phase 6: Verdict"
if [[ $NESTED -eq 1 ]]; then
    echo -e "  ${TC_YELLOW}[NESTED-VIRT] results include guest-scheduling tail jitter.${TC_NC}"
fi

# Sanity: every scenario must have delivered its full sample count with no
# failures; everything below that is informational, not a hard gate.
for row in "${SCEN_SUMMARY[@]}"; do
    IFS='|' read -r sname n succ fail timeouts exec_err badout u5 u10 nslow <<< "$row"
    if (( n != ITER_N )); then
        log_error "$sname: only $n/$ITER_N unmounts recorded (timeouts=$timeouts exec_err=$exec_err)"
        BENCH_FAILED=1
    fi
    if (( fail > 0 || timeouts > 0 )); then
        log_error "$sname: fail=$fail timeout=$timeouts (unmount RPC failed or exceeded ${UNMOUNT_WAIT_S}s)"
        BENCH_FAILED=1
    fi
    if (( exec_err > 0 )); then
        # exec_err still advances unmount_count (RecordUnmount runs on the
        # failure path too), so the n-gate above alone would PASS a system
        # where every exec errored after mounting.
        log_error "$sname: exec_err=$exec_err — workload execs failed (latency over a broken path is meaningless)"
        BENCH_FAILED=1
    fi
    if (( badout > 0 )); then
        log_error "$sname: badout=$badout — workload stdout wrong (workload did not run as written)"
        BENCH_FAILED=1
    fi
    if (( u5 + u10 == 0 )); then
        # ALL-zero under_5/under_10 is only proof of BROKEN fields when the
        # rolling ring is empty too: the ring fills on the very same code
        # path (RecordUnmount → recent.add), so samples present + zero
        # buckets = genuinely slower than 10ms (a nested-virt or loaded
        # host — informational), not a plumbing break. A false "broken"
        # here once failed the whole benchmark on a nested host whose
        # baseline unmounts legitimately measured 12-19ms.
        ring_n=$(recent_p95 | cut -d' ' -f1)
        if [[ "$sname" == "baseline" ]] && [[ "${ring_n:-0}" -eq 0 ]]; then
            log_error "$sname: under_5ms + under_10ms = 0 AND the recent ring is empty across $n unmounts — latency fields look broken (all-zero), not fast"
            BENCH_FAILED=1
        else
            log_warn "$sname: no unmount landed under 10ms (ring n=${ring_n:-0}: genuinely slow — loaded or nested-virt host, fields are live)"
        fi
    fi
done

# Interpretation per layer (informational):
# baseline  — the floor: expect under_5ms ≈ n on bare metal (every fixed cost
#             combined stays under the 5ms gateway-layer threshold).
# cache16m  — grows the warden layer via drop_caches (clean FILE_MB cache).
# dirty16m  — grows the warden layer further via umount(2) writeback.
for row in "${SCEN_SUMMARY[@]}"; do
    IFS='|' read -r sname n succ fail timeouts exec_err badout u5 u10 nslow <<< "$row"
    echo "  $sname: n=$n  under_5ms=$u5 ($(pct "$u5" "$n"))  under_10ms=$u10 ($(pct "$u10" "$n"))  exec_err=$exec_err badout=$badout  slow_entries=$nslow  max_warden_ms=$(max_warden_for "$sname")"
done
BASE_MAX=$(max_warden_for baseline)
CACHE_MAX=$(max_warden_for cache16m)
DIRTY_MAX=$(max_warden_for dirty16m)
# max_warden_for reports float milliseconds (the top_slow fields now keep
# microsecond resolution), so compare with awk rather than shell arithmetic.
if awk -v a="$CACHE_MAX" -v b="$BASE_MAX" 'BEGIN { exit !(a > b) }'; then
    log_pass "cache16m warden-layer max (${CACHE_MAX}ms) > baseline (${BASE_MAX}ms) — drop_caches scales with page cache, as expected"
else
    log_info "cache16m warden-layer max (${CACHE_MAX}ms) <= baseline (${BASE_MAX}ms) — interpretation not observed (fast cache drop, or top_slow slots filled by faster entries)"
fi
if awk -v d="$DIRTY_MAX" -v c="$CACHE_MAX" 'BEGIN { exit !(d > 0 && c > 0 && d >= c) }'; then
    log_pass "dirty16m warden-layer max (${DIRTY_MAX}ms) ≥ cache16m (${CACHE_MAX}ms) — umount writeback adds on top of drop_caches"
else
    log_info "dirty16m≥cache16m interpretation not observed (dirty=${DIRTY_MAX}ms cache=${CACHE_MAX}ms)"
fi
if awk -v b="$BASE_MAX" -v c="$CACHE_MAX" 'BEGIN { exit !(b > 0 && c == 0) }'; then
    log_warn "cache16m produced no top_slow entry — either all its unmounts were fast (cache drop cheap) or faster entries filled the 10-slot list"
fi

echo
log_section "Summary"
echo -e "  Environment: $([ $NESTED -eq 0 ] && echo 'bare-metal KVM' || echo "nested virtualization ($VIRT_TYPE)")"
echo -e "  Scenarios:   ${SCEN_LIST[*]}  (ITER_N=$ITER_N, FILE_MB=$FILE_MB, sticky lease=${LEASE_MS}ms)"
echo -e "  Data source: $HUMAN_URL/stats unmount_stats — counters + top-10 slow + rolling P50/P95/P99"
echo -e "  Layers:      gateway_ms = RPC E2E · sandlot_ms = handler total (incl. set-fs clear) · warden_ms = kill+teardown+umount+drop_caches"
# The run-wide P95 columns (the rolling window covers the whole run; the ring
# is capped at 1024 samples, so this is the last 1024 unmounts).
fetch_stats
REC_SUM=()
read -ra REC_SUM <<< "$(recent_p95)"
echo -e "  P95 columns: gateway P95=${REC_SUM[2]}ms (n=${REC_SUM[0]}, P50=${REC_SUM[1]}ms, P99=${REC_SUM[3]}ms, max=${REC_SUM[4]}ms)  warden P95=${REC_SUM[7]}ms (n=${REC_SUM[5]}, P50=${REC_SUM[6]}ms, P99=${REC_SUM[8]}ms, max=${REC_SUM[9]}ms)"
echo "bench-p95 gateway_ms=${REC_SUM[2]} warden_ms=${REC_SUM[7]} n=${REC_SUM[0]} warden_n=${REC_SUM[5]}"
echo -e "  Gateway:     $GATEWAY_URL (exec) / $HUMAN_URL (stats)"
echo -e "  Temp dirs:   deploy=$DEPLOY_DIR logs=$LOG_DIR (removed on exit; output/rootfs-ubuntu kept)"

(( BENCH_FAILED == 0 )) && log_pass "unmount benchmark completed cleanly" || { log_error "unmount benchmark had failures"; exit 1; }
