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
# latency-benchmark-alloc-sweep.sh — find the disjoint whole-core split
# between loadgen / gateway(+human+etcd) / sandlot(+prov) and the microVM
# pool that maximizes host cold reuse.
#
# The normal load benchmark fixes one allocation. This driver is the
# allocation search around it:
#
#   calibration run  -> per-role peak CPU at a generous split
#   candidate split  -> whole cores per role at a target utilization
#   validation run   -> measure host/per-VM cold/s at that split
#   pick the best    -> largest host cold/s with zero terminal failures,
#                       latency inside the tier, and no role over its cores
#
# INVARIANT: the four sets (loadgen, gateway, sandlot, VM pool) are DISJOINT
# whole physical cores. No role shares a core with another role or with a VM.
# Within a role, its processes (exec/human/etcd or exec/prov) share the role's
# cores; size the role for their sum.
#
# PRODUCTION NOTE: a real fleet runs the agents (loadgen) remotely and usually
# the gateway on a separate host. This same-host split is therefore a
# CONSERVATIVE lower bound for the VM host's capacity; the per-VM rate is the
# number that transfers. A production-faithful run needs a multi-host layout
# (remote loadgen/gateway; sandlot + VMs on the compute host).
#
# Modes:
#   --plan   read a stack-CPU TSV (or --peaks) and a core pool, print candidate
#            splits + the exact load-benchmark command. No root, no KVM.
#   --run    bare metal only: calibration + validation runs + best split.
#            Requires root (it drives latency-benchmark-load.sh).
#
# Examples:
#   # plan from a previous run's advisor line (no benchmark executed)
#   bash e2e/latency-benchmark-alloc-sweep.sh --plan \
#     --peaks "0.80,1.72,0.97" --cold-per-vm 35
#
#   # plan from a kept CPU TSV (KEEP_LOGS=1 run)
#   bash e2e/latency-benchmark-alloc-sweep.sh --plan \
#     --cpu-tsv /tmp/sandswap-logs/load-stack-cpu.tsv --cold-per-vm 35
#
#   # bare metal: calibration + validation sweep (inherits LOADTEST_* / POOL_SIZE-
#   # independent env from the caller; set SKIP_ESTIMATE_BENCH=1 + the four
#   # *_P95_MS refs to avoid re-running the baseline per allocation).
#   # Each candidate is a full deploy+levels run (minutes); calibrate grows
#   # the reserve up to 3 times if a role is pinned at its allocation.
#   sudo bash e2e/latency-benchmark-alloc-sweep.sh --run
#
# Env (the wrapper):
#   ALLOC_TARGETS="0.60 0.70 0.80"   per-role utilization targets to try
#   ALLOC_TIER=2.0                   latency tier for the validation gate
#   ALLOC_CALIB_RESERVE=auto         calibration reserve (auto | N)
#   ALLOC_LOG_DIR=/tmp/sandswap-alloc-sweep
# The underlying load-benchmark env (LOADTEST_AGENT_LEVELS, LOADTEST_DURATION_SEC, LOADTEST_WARMUP_SEC,
# SKIP_ESTIMATE_BENCH, *_P95_MS, recycle policy, ...) is inherited unchanged.
# LOADTEST_AGENT_LEVELS must include a level that saturates the LARGEST candidate pool;
# otherwise the validation under-measures and the sweep can pick the wrong split.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT=""
for cand in "$SCRIPT_DIR" "$SCRIPT_DIR/.."; do
    if [[ -d "$cand/output" ]]; then ROOT="$cand"; break; fi
done
[[ -n "$ROOT" ]] || { echo "alloc-sweep: cannot locate output/ near $SCRIPT_DIR" >&2; exit 1; }
LOAD="$ROOT/e2e/latency-benchmark-load.sh"
[[ -x "$LOAD" || -f "$LOAD" ]] || { echo "alloc-sweep: missing $LOAD" >&2; exit 1; }

MODE=""
CPU_TSV=""
PEAKS=""
CORE_POOL=""
CORES=""
THREADS_PER_CORE=""
SLICE_CPUS="${PIN_SLICE_CPUS:-2}"
COLD_PER_VM=""
TARGETS="${ALLOC_TARGETS:-0.60 0.70 0.80}"
TIER="${ALLOC_TIER:-2.0}"
CALIB_RESERVE="${ALLOC_CALIB_RESERVE:-auto}"
LOG_DIR="${ALLOC_LOG_DIR:-/tmp/sandswap-alloc-sweep}"

die() { echo "alloc-sweep: $*" >&2; exit 1; }
log() { echo "alloc-sweep: $*" >&2; }

usage() {
    cat <<'EOF'
usage: latency-benchmark-alloc-sweep.sh --plan|--run [options]

  --plan                 print candidate disjoint core splits (no benchmark)
  --run                  bare metal: calibration + validation + best split

  --cpu-tsv FILE         --plan: load-stack-cpu.tsv (loadgen/gateway/human/
                         etcd/sandlot/prov columns)
  --peaks "LG,GW,SD"     --plan: peak core-equivalents (loadgen,
                         gateway+human+etcd, sandlot+prov); overrides --cpu-tsv
  --core-pool "0-1;2-3"  whole-core cpulists (default: live topology)
  --cores N              synthetic contiguous pool (testing; default 2 threads/core)
  --threads-per-core N   override the topology's threads per core
  --slice-cpus N         CPUs per microVM (2 = whole core, 1 = logical CPU)
  --cold-per-vm R        --plan: measured per-VM cold/s for the host projection
  --targets "u1 u2"     per-role utilization targets (default 0.60 0.70 0.80)
  --tier K               validation latency tier (default 2.0)
  --calib-reserve N|auto calibration reserve (default auto)

The load benchmark env (LOADTEST_AGENT_LEVELS, LOADTEST_DURATION_SEC, LOADTEST_WARMUP_SEC,
SKIP_ESTIMATE_BENCH, *_P95_MS, recycle policy, ...) is inherited. Include a
level that saturates the largest candidate pool or the validation under-measures.
EOF
    exit 0
}

while (( $# > 0 )); do
    case "$1" in
        --plan) MODE=plan ;;
        --run) MODE=run ;;
        --cpu-tsv) CPU_TSV="${2:-}"; shift ;;
        --peaks) PEAKS="${2:-}"; shift ;;
        --core-pool) CORE_POOL="${2:-}"; shift ;;
        --cores) CORES="${2:-}"; shift ;;
        --threads-per-core) THREADS_PER_CORE="${2:-}"; shift ;;
        --slice-cpus) SLICE_CPUS="${2:-}"; shift ;;
        --cold-per-vm) COLD_PER_VM="${2:-}"; shift ;;
        --targets) TARGETS="${2:-}"; shift ;;
        --tier) TIER="${2:-}"; shift ;;
        --calib-reserve) CALIB_RESERVE="${2:-}"; shift ;;
        -h|--help) usage ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done
[[ -n "$MODE" ]] || die "choose --plan or --run (try --help)"
[[ "$SLICE_CPUS" =~ ^[0-9]+$ ]] && (( SLICE_CPUS >= 1 )) || die "--slice-cpus must be >= 1"
awk -v x="$TIER" 'BEGIN { exit !(x + 0 > 0) }' || die "--tier must be > 0"

# ── topology: ordered whole physical cores ─────────────────────────────────
# Prints "<core-pool>" where each ';' entry is one whole core's cpulist, in
# the same node-first order the load benchmark's planner uses. Empty on error.
topology_core_pool() {
    python3 - <<'PY'
import sys

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

try:
    online = expand(open("/sys/devices/system/cpu/online").read().strip())
except OSError:
    sys.exit(1)
if not online:
    sys.exit(1)
try:
    nodes = sorted(int(n) for n in expand(open("/sys/devices/system/node/online").read().strip())) or [0]
except OSError:
    nodes = [0]
node_cpus = {}
for n in nodes:
    try:
        node_cpus[n] = sorted(expand(open("/sys/devices/system/node/node%d/cpulist" % n).read().strip()) & online)
    except OSError:
        node_cpus[n] = []
node_of = {}
for n in nodes:
    for c in node_cpus[n]:
        node_of.setdefault(c, n)
for c in sorted(online):
    node_of.setdefault(c, nodes[0])
sib = {}
for c in sorted(online):
    try:
        spec = open("/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list" % c).read().strip()
    except OSError:
        spec = str(c)
    sib[c] = tuple(sorted((expand(spec) or {c}) & online)) or (c,)
cores, seen = [], set()
for c in sorted(online):
    g = sib[c]
    if g in seen:
        continue
    seen.add(g)
    cores.append({"cpus": list(g), "node": node_of[c], "min": min(g)})
node_counts = {}
for c in cores:
    node_counts[c["node"]] = node_counts.get(c["node"], 0) + 1
pref = sorted(node_counts, key=lambda n: (-node_counts[n], n))[0] if node_counts else nodes[0]
ordered = [c for c in cores if c["node"] == pref] + [c for c in cores if c["node"] != pref]
ordered.sort(key=lambda c: (0 if c["node"] == pref else 1, c["node"], c["min"]))
print(";".join(compress(c["cpus"]) for c in ordered))
PY
}

# ── candidate math ─────────────────────────────────────────────────────────
# plan_candidates <peaks "lg,gw,sd"> <core-pool> <tpc> <slice-cpus> <targets>
#                 <cold-per-vm|->
# Emits one line per target:
#   target=<u> loadgen=<L> gateway=<G> sandlot=<S> reserve=<R> vm_cores=<V>
#   pool=<P> host=<H|-> per_vm=<r|-> layout=<...> valid=1|0
plan_candidates() {
    python3 - "$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import math, sys
peaks_s, pool_s, tpc_s, slice_s, targets_s, per_vm_s = sys.argv[1:7]
try:
    peaks = [float(x) for x in peaks_s.split(",")]
except ValueError:
    print("alloc-sweep: --peaks must be three comma-separated numbers", file=sys.stderr)
    sys.exit(2)
if len(peaks) != 3 or any(p < 0 for p in peaks):
    print("alloc-sweep: --peaks must be loadgen,gateway+human+etcd,sandlot+prov (non-negative)", file=sys.stderr)
    sys.exit(2)
cores = [c.strip() for c in pool_s.split(";") if c.strip()]
if not cores:
    print("alloc-sweep: empty core pool", file=sys.stderr)
    sys.exit(2)
tpc = max(1, int(tpc_s))
slice_cpus = max(1, int(slice_s))
per_vm = None
if per_vm_s not in ("", "-"):
    try:
        per_vm = float(per_vm_s)
    except ValueError:
        print("alloc-sweep: --cold-per-vm must be a number", file=sys.stderr)
        sys.exit(2)
n = len(cores)
for t_s in targets_s.split():
    try:
        t = float(t_s)
    except ValueError:
        print("alloc-sweep: target %r is not a number" % t_s, file=sys.stderr)
        sys.exit(2)
    if not (0 < t <= 1):
        print("alloc-sweep: target %r must be in (0,1]" % t_s, file=sys.stderr)
        sys.exit(2)
    def role(peak):
        return max(1, int(math.ceil(peak / (tpc * t)))) if peak > 0 else 1
    L, G, S = role(peaks[0]), role(peaks[1]), role(peaks[2])
    R = L + G + S
    valid = 1
    if R >= n:
        valid = 0
        V = 0
    else:
        V = n - R
    pool = (V * tpc) // slice_cpus
    if pool < 1:
        valid = 0
    layout = ""
    if valid:
        pick = lambda a, b: ",".join(cores[a:b])
        layout = "loadgen:%s;gateway:%s;sandlot:%s" % (
            pick(0, L), pick(L, L + G), pick(L + G, L + G + S))
    host = "-" if (per_vm is None or not valid) else ("%.2f" % (pool * per_vm))
    pv = "-" if per_vm is None else ("%.2f" % per_vm)
    print("target=%s loadgen=%d gateway=%d sandlot=%d reserve=%d vm_cores=%d pool=%d host=%s per_vm=%s layout=%s valid=%d"
          % (t_s, L, G, S, R, V, pool, host, pv, layout, valid))
PY
}

# ── measured inputs for --plan ─────────────────────────────────────────────
peaks_from_tsv() {
    python3 - "$1" <<'PY'
import sys
lg = gw = sd = 0.0
rows = 0
try:
    fh = open(sys.argv[1])
except OSError as e:
    print("alloc-sweep: cannot read %s: %s" % (sys.argv[1], e), file=sys.stderr)
    sys.exit(1)
header = fh.readline().rstrip("\n").split("\t")
for line in fh:
    vals = line.rstrip("\n").split("\t")
    if len(vals) != len(header):
        continue
    r = dict(zip(header, vals))
    try:
        lg = max(lg, float(r.get("loadgen") or 0))
        gw = max(gw, float(r.get("gateway") or 0) + float(r.get("human") or 0) + float(r.get("etcd") or 0))
        sd = max(sd, float(r.get("sandlot") or 0) + float(r.get("prov") or 0))
    except ValueError:
        continue
    rows += 1
if rows == 0:
    print("alloc-sweep: no rows in %s" % sys.argv[1], file=sys.stderr)
    sys.exit(1)
print("%.4f,%.4f,%.4f" % (lg, gw, sd))
PY
}

resolve_core_pool() {
    if [[ -n "$CORE_POOL" ]]; then
        printf '%s' "$CORE_POOL"
        return 0
    fi
    if [[ -n "$CORES" ]]; then
        [[ "$CORES" =~ ^[0-9]+$ ]] && (( CORES >= 1 )) || die "--cores must be >= 1"
        local tpc="${THREADS_PER_CORE:-2}"
        [[ "$tpc" =~ ^[0-9]+$ ]] && (( tpc >= 1 )) || die "--threads-per-core must be >= 1"
        local out="" i start end
        for (( i = 0; i < CORES; i++ )); do
            start=$(( i * tpc )); end=$(( start + tpc - 1 ))
            out+="${out:+;}${start}-${end}"
        done
        printf '%s' "$out"
        return 0
    fi
    topology_core_pool
}

core_pool_threads() {
    local pool="$1"
    if [[ -n "$THREADS_PER_CORE" ]]; then
        printf '%s' "$THREADS_PER_CORE"
        return 0
    fi
    local first="${pool%%;*}"
    python3 - "$first" <<'PY'
import sys
n = 0
for part in sys.argv[1].replace(" ", "").split(","):
    if not part:
        continue
    if "-" in part:
        a, b = part.split("-", 1)
        n += int(b) - int(a) + 1
    else:
        n += 1
print(max(1, n))
PY
}

plan_mode() {
    local peaks="$PEAKS"
    if [[ -z "$peaks" ]]; then
        [[ -n "$CPU_TSV" ]] || die "--plan needs --peaks or --cpu-tsv"
        peaks="$(peaks_from_tsv "$CPU_TSV")" || exit 1
    fi
    if ! awk -F, '{s = 0; for (i = 1; i <= NF; i++) s += $i + 0; exit !(s > 0)}' <<< "$peaks"; then
        die "the measured peaks are all zero; run the calibration with a saturating level first"
    fi
    local pool; pool="$(resolve_core_pool)" || exit 1
    [[ -n "$pool" ]] || die "cannot determine the core pool; pass --core-pool or --cores"
    local tpc; tpc="$(core_pool_threads "$pool")"
    log "core pool: $(awk -F';' '{print NF}' <<< "$pool") whole cores, $tpc threads/core, slice=$SLICE_CPUS CPUs/VM"
    log "peaks (core-equivalents): loadgen / gateway+human+etcd / sandlot+prov = $peaks"
    local c
    while IFS= read -r c; do
        echo "$c" | sed 's/^/    /'
    done < <(plan_candidates "$peaks" "$pool" "$tpc" "$SLICE_CPUS" "$TARGETS" "$COLD_PER_VM")
    # Best: max projected host cold/s when --cold-per-vm was given; otherwise
    # the smallest stack reserve (largest VM pool) among valid rows.
    local best
    best="$(plan_candidates "$peaks" "$pool" "$tpc" "$SLICE_CPUS" "$TARGETS" "$COLD_PER_VM" | awk '
        BEGIN { besthost = -1e18; bestr = "" }
        /valid=1/ {
            host = -1
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^host=/) { v = substr($i, 6); host = (v == "-") ? -1 : v + 0 }
                if ($i ~ /^reserve=/) { r = substr($i, 9) + 0 }
            }
            if (host > besthost || (host == besthost && (bestr == "" || r < bestr))) {
                besthost = host; bestr = r; line = $0
            }
        }
        END { if (line != "") print line }')"
    if [[ -z "$best" ]]; then
        die "no valid candidate: the host has too few whole cores for three roles + a VM"
    fi
    echo
    echo "best: $best"
    local layout; layout="$(sed -n 's/.*layout=\([^ ]*\).*/\1/p' <<< "$best")"
    local reserve pool_n
    reserve="$(sed -n 's/.*reserve=\([0-9]*\).*/\1/p' <<< "$best")"
    pool_n="$(sed -n 's/.*pool=\([0-9]*\).*/\1/p' <<< "$best")"
    [[ -n "$layout" ]] || die "internal: no layout in the best candidate"
    echo
    echo "run it with (bare metal):"
    echo "  PIN_MODE=1 PIN_STACK_LAYOUT=\"$layout\" PIN_RESERVE_CORES=$reserve \\"
    echo "    POOL_SIZE=$pool_n PIN_SLICE_CPUS=$SLICE_CPUS \\"
    echo "    bash e2e/latency-benchmark-load.sh"
}

# ── --run: calibration + validation ────────────────────────────────────────
is_bare_metal() {
    local virt hyper
    virt="$(systemd-detect-virt 2>/dev/null || true)"; virt="${virt//$'\n'/}"
    hyper=$(grep -c -m1 '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null) || true
    [[ ( "$virt" == "none" || -z "$virt" ) && "${hyper:-0}" -eq 0 ]]
}

run_peaks() { # <log> -> "lg,gw,sd"
    python3 - "$1" <<'PY'
import re, sys
lg = gw = sd = 0.0
pat = re.compile(r"stack-cpu: loadgen=([\d.]+) gateway=([\d.]+) human=([\d.]+) etcd=([\d.]+) sandlot=([\d.]+) prov=([\d.]+)")
for line in open(sys.argv[1], errors="replace"):
    m = pat.search(line)
    if not m:
        continue
    v = [float(x) for x in m.groups()]
    lg = max(lg, v[0]); gw = max(gw, v[1] + v[2] + v[3]); sd = max(sd, v[4] + v[5])
print("%.4f,%.4f,%.4f" % (lg, gw, sd))
PY
}

run_best_row() { # <log> -> tab-separated best zero-terminal row
    python3 - "$1" <<'PY'
import json, sys
best = None
for line in open(sys.argv[1], errors="replace"):
    line = line.strip()
    if not line.startswith("bench-result "):
        continue
    try:
        d = json.loads(line[len("bench-result "):])
    except json.JSONDecodeError:
        continue
    if int(d.get("err") or 0) != 0:
        continue
    if best is None or float(d.get("cold_rps") or 0) > float(best.get("cold_rps") or 0):
        best = d
if best is None:
    print("-\t-\t-\t-\t-\t-\t-\t-\t-")
    raise SystemExit(0)
print("\t".join(str(best.get(k, "-")) for k in
                ("agents", "cold_rps", "cold_gw_p95_ms", "cold_client_p95_ms",
                 "busy_attempts", "err", "recycle_delta", "clean_mean", "total_vms")))
PY
}

run_refs() { # <log> -> four refs or empty
    python3 - "$1" <<'PY'
import re, sys
pat = re.compile(r"No-load reference[^:]*: gateway E2E P95 warm=([\d.]+)ms cold=([\d.]+)ms;\s*client P95 warm=([\d.]+)ms cold=([\d.]+)ms")
for line in open(sys.argv[1], errors="replace"):
    m = pat.search(line)
    if m:
        print(" ".join(m.groups()))
        raise SystemExit(0)
PY
}

run_load() { # tag reserve layout pool slice target log
    local tag="$1" reserve="$2" layout="$3" pool="$4" slice="$5" target="$6" log="$7"
    local -a e=(env -u PIN_CPUS -u PIN_STACK_LAYOUT PIN_MODE=1
        PIN_RESERVE_CORES="$reserve" POOL_SIZE="$pool"
        PIN_SLICE_CPUS="$slice" PIN_TARGET_UTIL="$target" PIN_PLAN=0)
    [[ -n "$layout" ]] && e+=(PIN_STACK_LAYOUT="$layout")
    # The paced-lane workloads (ideal AND shaped) require one lane per VM;
    # the pool size is the candidate's, not the caller's fixed LOADTEST_LANES
    # (a stale value would fail the load script's lanes==pool validation).
    if [[ "${LOADTEST_WORKLOAD:-agents}" == "ideal" || "${LOADTEST_WORKLOAD:-agents}" == "shaped" ]]; then
        e+=(LOADTEST_LANES="$pool")
    fi
    log "running $tag (reserve=$reserve pool=$pool target=$target)..."
    "${e[@]}" bash "$LOAD" > "$log" 2>&1
}

run_mode() {
    [[ $EUID -eq 0 ]] || die "--run needs root (it drives the benchmark)"
    is_bare_metal || die "--run needs bare metal (nested virt cannot partition whole cores)"
    local pool; pool="$(resolve_core_pool)" || exit 1
    [[ -n "$pool" ]] || die "cannot determine the core pool"
    local tpc; tpc="$(core_pool_threads "$pool")"
    local n; n="$(awk -F';' '{print NF}' <<< "$pool")"
    (( n >= 4 )) || die "need >=4 whole cores for loadgen/gateway/sandlot/VM (have $n)"
    mkdir -p "$LOG_DIR"
    if [[ "${SKIP_ESTIMATE_BENCH:-0}" == "1" ]]; then
        for v in WARM_GW_P95_MS COLD_GW_P95_MS WARM_CLIENT_P95_MS COLD_CLIENT_P95_MS; do
            [[ -n "${!v:-}" ]] || die "SKIP_ESTIMATE_BENCH=1 requires $v"
        done
    fi
    # Calibration: start from a generous split and GROW it until no role is
    # pinned at its allocation. A capped role reports its allocation, not its
    # demand; sizing the candidates from that would under-reserve the stack.
    # The load script's integer-reserve split is 40/40/20 whole cores.
    local R="$CALIB_RESERVE"
    if [[ "$R" == "auto" ]]; then
        R=$(( n / 8 )); (( R < 2 )) && R=2; (( R > 8 )) && R=8
    fi
    [[ "$R" =~ ^[0-9]+$ ]] && (( R >= 3 && R < n )) || die "calibration reserve $R invalid (need 3..$((n-1)))"
    local attempt calib calib_pool peaks rc cl cg cs refs_done=0
    for attempt in 1 2 3; do
        calib_pool=$(( (n - R) * tpc / SLICE_CPUS ))
        (( calib_pool >= 1 )) || die "calibration reserve $R leaves no VM"
        calib="$LOG_DIR/calibration-$attempt.log"
        rc=0
        run_load "calibration-$attempt" "$R" "" "$calib_pool" "$SLICE_CPUS" "${TARGETS%% *}" "$calib" || rc=$?
        [[ -s "$calib" ]] || die "calibration produced no log"
        peaks="$(run_peaks "$calib")"
        [[ "$peaks" != "0.0000,0.0000,0.0000" ]] || die "calibration has no stack-cpu measurements; see $calib"
        # The planner's integer-reserve split: loadgen 40%, gateway 40%,
        # sandlot the remainder (whole cores, each role at least one).
        read -r cl cg cs <<< "$(awk -v n="$R" 'BEGIN {
            l = int(n * 0.4 + 0.5); if (l < 1) l = 1
            g = int(n * 0.4 + 0.5); if (g < 1) g = 1
            if (l + g > n - 1) { g = n - 1 - l; if (g < 1) { g = 1; l = n - 2 } }
            s = n - l - g; print l, g, s }')"
        local capped=0
        awk -v lg="${peaks%%,*}" -v rest="${peaks#*,}" \
            -v cl="$cl" -v cg="$cg" -v cs="$cs" -v tpc="$tpc" 'BEGIN {
                split(rest, a, ","); gw = a[1]; sd = a[2];
                if (lg >= 0.85 * cl * tpc) exit 1
                if (gw >= 0.85 * cg * tpc) exit 1
                if (sd >= 0.85 * cs * tpc) exit 1
            }' || capped=1
        log "calibration attempt $attempt: reserve=$R (L/G/S=$cl/$cg/$cs cores) peaks=$peaks pool=$calib_pool rc=$rc"
        if [[ "$refs_done" == "0" && "${SKIP_ESTIMATE_BENCH:-0}" != "1" ]]; then
            local refs; refs="$(run_refs "$calib")"
            if [[ -n "$refs" ]]; then
                read -r WARM_GW_P95_MS COLD_GW_P95_MS WARM_CLIENT_P95_MS COLD_CLIENT_P95_MS <<< "$refs"
                export WARM_GW_P95_MS COLD_GW_P95_MS WARM_CLIENT_P95_MS COLD_CLIENT_P95_MS SKIP_ESTIMATE_BENCH=1
                refs_done=1
                log "reusing calibration baseline refs: $refs"
            fi
        fi
        if (( capped == 0 )); then
            break
        fi
        (( attempt == 3 )) && die "calibration roles stay at their allocation after 3 growth steps; set ALLOC_CALIB_RESERVE larger"
        local grow=$(( R / 4 )); (( grow < 2 )) && grow=2
        R=$(( R + grow ))
        (( R >= n )) && die "calibration needs $R cores but the host has $n"
    done
    local calib_row; calib_row="$(run_best_row "$calib")"
    local calib_per_vm="-"
    calib_per_vm="$(awk -F'\t' -v p="$calib_pool" '$2 != "-" && p > 0 { printf "%.2f", $2 / p; exit }' <<< "$calib_row")"
    log "calibration best row (agents/cold/s/cold_gw95/client95/busy/err/recycles/clean/POOL): $calib_row"
    log "calibration per-VM cold/s: $calib_per_vm"
    local calib_clean calib_total
    calib_clean="$(cut -f8 <<< "$calib_row")"; calib_total="$(cut -f9 <<< "$calib_row")"
    if [[ "$calib_clean" != "-" && "$calib_total" != "-" ]] && \
       awk -v c="$calib_clean" -v t="$calib_total" 'BEGIN { exit !(c + 0 > 0.25 * (t + 0)) }'; then
        log "WARNING: calibration pool was not saturated (clean mean $calib_clean of $calib_total); the role peaks and per-VM rate are a lower bound. Add higher LOADTEST_AGENT_LEVELS."
    fi

    local candidates; candidates="$(plan_candidates "$peaks" "$pool" "$tpc" "$SLICE_CPUS" "$TARGETS" "$calib_per_vm")"
    echo
    printf '%-8s %-5s %-5s %-5s %-7s %-6s %-10s %-10s %-10s %-10s %-8s\n' \
        TARGET L G S RESERVE POOL HOST/S PER-VM COLD_GW95 CLIENT95 RESULT
    local best_line="" best_host=-1 best_pv_line="" best_pv=-1
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        local t L G S R V P layout valid host pv
        t="$(sed -n 's/.*target=\([^ ]*\).*/\1/p' <<< "$line")"
        L="$(sed -n 's/.*loadgen=\([0-9]*\).*/\1/p' <<< "$line")"
        G="$(sed -n 's/.*gateway=\([0-9]*\).*/\1/p' <<< "$line")"
        S="$(sed -n 's/.*sandlot=\([0-9]*\).*/\1/p' <<< "$line")"
        R="$(sed -n 's/.*reserve=\([0-9]*\).*/\1/p' <<< "$line")"
        V="$(sed -n 's/.*vm_cores=\([0-9]*\).*/\1/p' <<< "$line")"
        P="$(sed -n 's/.*pool=\([0-9]*\).*/\1/p' <<< "$line")"
        layout="$(sed -n 's/.*layout=\([^ ]*\).*/\1/p' <<< "$line")"
        valid="$(sed -n 's/.*valid=\([0-9]*\).*/\1/p' <<< "$line")"
        if [[ "$valid" != "1" ]]; then
            printf '%-8s %-5s %-5s %-5s %-7s %-6s %-10s %-10s %-10s %-10s %-8s\n' \
                "$t" "$L" "$G" "$S" "$R" "-" "-" "-" "-" "-" "invalid"
            continue
        fi
        local logf="$LOG_DIR/target-$t.log"
        local rcs=0
        run_load "target-$t" "$R" "$layout" "$P" "$SLICE_CPUS" "$t" "$logf" || rcs=$?
        local vpeaks row
        vpeaks="$(run_peaks "$logf")"
        log "target=$t validation peaks: loadgen/gateway/sandlot = $vpeaks"
        row="$(run_best_row "$logf")"
        local a cold cg95 cc95 busy err recycles clean_mean total_vms
        IFS=$'\t' read -r a cold cg95 cc95 busy err recycles clean_mean total_vms <<< "$row"
        local pv_now="-"
        [[ "$cold" != "-" ]] && pv_now="$(awk -v c="$cold" -v p="$P" 'BEGIN { if (p > 0) printf "%.2f", c / p; else print "-" }')"
        # Role utilization: the validation's measured peaks must fit the
        # candidate's role cores at the target.
        local roleok=1
        awk -v lg="${vpeaks%%,*}" \
            -v rest="${vpeaks#*,}" -v L="$L" -v G="$G" -v S="$S" \
            -v tpc="$tpc" -v t="$t" 'BEGIN {
                split(rest, a, ","); gw = a[1]; sd = a[2];
                if (lg > L * tpc * t + 1e-9) exit 1
                if (gw > G * tpc * t + 1e-9) exit 1
                if (sd > S * tpc * t + 1e-9) exit 1
            }' || roleok=0
        local latok=1
        if [[ -n "${COLD_GW_P95_MS:-}" && "$cg95" != "-" ]]; then
            awk -v x="$cg95" -v r="$COLD_GW_P95_MS" -v k="$TIER" 'BEGIN { exit !(x + 0 <= k * (r + 0) + 1e-9) }' || latok=0
        fi
        if [[ -n "${COLD_CLIENT_P95_MS:-}" && "$cc95" != "-" ]]; then
            awk -v x="$cc95" -v r="$COLD_CLIENT_P95_MS" -v k="$TIER" 'BEGIN { exit !(x + 0 <= k * (r + 0) + 1e-9) }' || latok=0
        fi
        # A pool that is mostly CLEAN was not saturated: its measured host
        # cold/s is a lower bound, so it cannot be compared with a saturated
        # candidate (a larger pool would be unfairly penalized).
        local satok=1
        if [[ "$clean_mean" != "-" && "$total_vms" != "-" ]]; then
            awk -v c="$clean_mean" -v t="$total_vms" 'BEGIN { exit !(c + 0 > 0.25 * (t + 0)) }' && satok=0
        fi
        local result=ok
        if (( rcs != 0 )); then result="rc=$rcs"; fi
        if [[ "$cold" == "-" ]]; then result="no-zero-terminal-row"; fi
        if (( roleok == 0 )); then result="role-over-target"; fi
        if (( latok == 0 )); then result="latency-over-tier"; fi
        if (( satok == 0 )); then result="not-saturated"; fi
        printf '%-8s %-5s %-5s %-5s %-7s %-6s %-10s %-10s %-10s %-10s %-8s\n' \
            "$t" "$L" "$G" "$S" "$R" "$P" "${cold:--}" "$pv_now" "${cg95:--}" "${cc95:--}" "$result"
        if [[ "$result" == "ok" && "$cold" != "-" ]]; then
            local h; h="$(awk -v c="$cold" 'BEGIN { printf "%.2f", c }')"
            if awk -v h="$h" -v b="$best_host" 'BEGIN { exit !(h + 0 > b + 0) }'; then
                best_host="$h"; best_line="$line"
            fi
            if [[ "$pv_now" != "-" ]] && awk -v p="$pv_now" -v b="$best_pv" 'BEGIN { exit !(p + 0 > b + 0) }'; then
                best_pv="$pv_now"; best_pv_line="$line"
            fi
        fi
    done <<< "$candidates"
    echo
    if [[ -z "$best_line" ]]; then
        die "no valid allocation: see the table and $LOG_DIR/target-*.log"
    fi
    local layout; layout="$(sed -n 's/.*layout=\([^ ]*\).*/\1/p' <<< "$best_line")"
    local R P
    R="$(sed -n 's/.*reserve=\([0-9]*\).*/\1/p' <<< "$best_line")"
    P="$(sed -n 's/.*pool=\([0-9]*\).*/\1/p' <<< "$best_line")"
    echo "alloc-sweep: BEST: $(sed -n 's/.*target=\([^ ]*\).*/target=\1/p' <<< "$best_line") host cold/s=$best_host"
    echo "  PIN_MODE=1 PIN_STACK_LAYOUT=\"$layout\" PIN_RESERVE_CORES=$R POOL_SIZE=$P PIN_SLICE_CPUS=$SLICE_CPUS"
    if [[ -n "$best_pv_line" ]]; then
        local pv_layout pv_reserve pv_pool
        pv_layout="$(sed -n 's/.*layout=\([^ ]*\).*/\1/p' <<< "$best_pv_line")"
        pv_reserve="$(sed -n 's/.*reserve=\([0-9]*\).*/\1/p' <<< "$best_pv_line")"
        pv_pool="$(sed -n 's/.*pool=\([0-9]*\).*/\1/p' <<< "$best_pv_line")"
        echo "alloc-sweep: BEST per-VM cold/s=$best_pv: $(sed -n 's/.*target=\([^ ]*\).*/target=\1/p' <<< "$best_pv_line")"
        echo "  PIN_MODE=1 PIN_STACK_LAYOUT=\"$pv_layout\" PIN_RESERVE_CORES=$pv_reserve POOL_SIZE=$pv_pool PIN_SLICE_CPUS=$SLICE_CPUS"
    fi
    echo "  logs: $LOG_DIR"
}

case "$MODE" in
    plan) plan_mode ;;
    run) run_mode ;;
esac
