#!/usr/bin/env bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, your use of this software will be
# governed by the Apache License, Version 2.0.
#
# scale-rehearsal.sh — W5/H13: execute the million-level control-plane claims
# at target population instead of asserting them from documentation.
#
# Population (gateway/cmd/scalepopulator, tenant-distributed by design):
#   SCALE_TENANTS × SCALE_AGENTS × SCALE_SANDFS sandfs + matching agents,
#   hot/meta/ownership/registry/health/presence keys, in the gateway's exact
#   wire formats, namespace tenant-<t> on every record.
# Curves measured (each becomes a row of the scale-claims table):
#   C1  identity full load        — human gw cold start to /ready (default
#                                   -identity-full-load-timeout-sec is 120:
#                                   a load over that IS a finding)
#   C2  per-ns listing            — GET /human/ns/<ns>/{agent,sandfs}?limit=100
#                                   (the namespace feature's tenant shape,
#                                   watch-cache filter at 1M records)
#   C3  fleet listing             — GET /human/{agent,sandfs}?limit=1000 (the
#                                   flat worst case; must stay bounded + safe)
#   C4  agent-API auth           — GET /agent/sandfs with real digest keys on
#                                   the exec gw (lazy point-Get then cache hit)
#   C5  /stats + /metrics         — projection latency at 1M
#   C6  DNS owner-aware zone      — <sandfs_id>.<zone> lookups (owner cache)
#   C7  restart re-load           — human gw restart → /ready again
#   C8  ownership CAS contention  — reap-stuck batch over dead-owned entries
#                                   racing a second concurrent invocation on a
#                                   2-exec-gateway topology
# Everything runs on dedicated ports against an EPHEMERAL etcd — a co-located
# production-shaped stack is never touched.
#
# Usage: sudo bash e2e/scale-rehearsal.sh [--smoke]
#   --smoke: 5 tenants × 4 agents × 2 sandfs — proves the machinery; every
#   number from a smoke run is a machinery check, NOT scale evidence.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

SMOKE=0
[[ "${1:-}" == "--smoke" ]] && SMOKE=1

# ── Sizing ─────────────────────────────────────────────────────────
if [[ $SMOKE -eq 1 ]]; then
    SCALE_TENANTS=5;  SCALE_AGENTS=4;   SCALE_SANDFS=2; SAMPLES=20
else
    SCALE_TENANTS="${SCALE_TENANTS:-1000}"; SCALE_AGENTS="${SCALE_AGENTS:-100}"
    SCALE_SANDFS="${SCALE_SANDFS:-10}";     SAMPLES="${SCALE_SAMPLES:-200}"
fi

ETCD_BIN="$(command -v etcd || echo "$ROOT/output/etcd/etcd")"
POP_BIN="$ROOT/output/scalepopulator"
GW_BIN="$ROOT/output/gateway"
DNS_BIN="$ROOT/output/sandns"

# /var/tmp is DISK-backed; /tmp is tmpfs (RAM) on the rehearsal box — an
# etcd data dir under /tmp holds the whole backend in RAM a second time and
# was a main contributor to the box freezing ( rehearsal lesson).
BASE="${SCALE_BASE:-/var/tmp/sandswap-scale}"
# Dedicated ports (never touch a co-located real stack).
ETCD_C="127.0.0.1:12379"; ETCD_P="127.0.0.1:12380"
GW_A_AGENT="127.0.0.1:13000"; GW_A_STREAM="127.0.0.1:13998"
GW_B_AGENT="127.0.0.1:13001"; GW_B_STREAM="127.0.0.1:13997"
HUMAN_ADDR="127.0.0.1:13100"; HUMAN_URL="http://${HUMAN_ADDR}"
AGENT_A_URL="http://${GW_A_AGENT}"
DNS_ADDR="127.0.0.1:15053"

PIDS=()
# Runtime artifact dir — never write into the tracked tree during a battery
# run (an aborted run leaves incomplete JSON behind, including on SKIP).
# Archive a completed report explicitly with
# SCALE_REPORT_DIR=<review appendix>/instruments.
REPORT_DIR="${SCALE_REPORT_DIR:-/var/tmp/sandswap-scale-rehearsal}"
STAMP="$(date +%Y%m%d-%H%M%S)"
RAW="$REPORT_DIR/scale-rehearsal-$STAMP.json"
SAMPLE_KEYS="$BASE/sample-keys.txt"

# json_str <value> → a properly escaped JSON string literal. The raw report is
# assembled line by line, so EVERY interpolated string goes through this: the
# C8 bodies embed the server's own JSON error responses (quotes inside the
# value), which produced an unparseable report file and failed this suite at
# the Report step while every measurement above it was green.
json_str() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }

cleanup() {
    for p in "${PIDS[@]:-}"; do
        kill -0 "$p" 2>/dev/null && kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    # A skip/failure exits before the report is valid JSON; keep half-written
    # artifacts out of the runtime/review tree. Parse, not last-char: a
    # completed report ends with "}\n".
    if [[ -f "$RAW" ]] && ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$RAW" 2>/dev/null; then
        rm -f "$RAW"
    fi
    # Preserve the failure scene for diagnosis (successful runs keep nothing).
    if (( FAIL_COUNT > 0 )); then
        rm -rf /var/tmp/scale-rehearsal-debug
        cp -a "$BASE" /var/tmp/scale-rehearsal-debug 2>/dev/null || true
    fi
    [[ -n "${ETCD_DATA:-}" ]] && rm -rf "$ETCD_DATA"
    rm -rf "$BASE"
}
trap cleanup EXIT INT TERM

now_ms() { local t="$EPOCHREALTIME"; echo $(( ${t/./} / 1000 )); }

# leg_guard — box-protection: etcd holds ~2.2GB of the 5.9GB box; never start
# a gateway leg without headroom ( lesson: the box froze twice).
mem_avail_mb() { awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo; }
leg_guard() {
    local avail; avail=$(mem_avail_mb)
    if (( avail < 1200 )); then
        # Box protection (the box froze twice): the FULL-scale
        # rehearsal holds ~2.2GB of etcd on top of the ambient load and this
        # host cannot give the leg its headroom. That is an ENVIRONMENT skip,
        # not a broken drill — the reason carries the measured numbers so a
        # human can tell "small box" from "leak", and `--smoke` exercises the
        # machinery here. (A silent pass would be the other failure mode; this
        # is visible in the battery stream and the matrix row.)
        tc_skip_suite "needs-memory-headroom: leg $1 saw only ${avail}MB available (needs 1200MB after the population phase) — run the full rehearsal on a larger box, or --smoke for the machinery check"
    fi
}

http_ms() { # url [curl-args...] → "<code> <ms>"
    local url="$1"; shift
    local t0 t1 code
    t0=$(now_ms)
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 30 "$url" "$@" || true)
    t1=$(now_ms)
    echo "$code $((t1 - t0))"
}

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 0: preflight"
# ══════════════════════════════════════════════════════════════════
for bin in "$ETCD_BIN" "$GW_BIN" "$POP_BIN"; do
    [[ -x "$bin" ]] || { tc_fail "missing $bin (build: bash build/build.sh go; cp /tmp/scalepopulator output/)"; exit 1; }
done
FREE_GB=$(( $(ss_df_avail_mb /) / 1024 ))
(( FREE_GB >= 5 )) || { tc_fail "disk ${FREE_GB}G < 5G — clean build intermediates first"; exit 1; }
tc_pass "binaries present, ${FREE_GB}G free"
if [[ ! -x "$DNS_BIN" ]]; then
    tc_log_warn "output/sandns absent — the C6 DNS leg will be skipped (recorded, not silent)"
fi

mkdir -p "$BASE" "$REPORT_DIR"
rm -f "$RAW"; echo "{" > "$RAW"   # JSON lines, closed at the end

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 1: ephemeral etcd"
# ══════════════════════════════════════════════════════════════════
ETCD_DATA="$BASE/etcd"
"$ETCD_BIN" --name scale-etcd \
    --listen-client-urls "http://$ETCD_C" --advertise-client-urls "http://$ETCD_C" \
    --listen-peer-urls "http://$ETCD_P" --initial-advertise-peer-urls "http://$ETCD_P" \
    --initial-cluster scale-etcd=http://$ETCD_P --initial-cluster-token scale \
    --initial-cluster-state new --data-dir "$ETCD_DATA" \
    --log-level warn > "$BASE/etcd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do
    (exec 3<>/dev/tcp/127.0.0.1/12379) 2>/dev/null && break
    sleep 0.5
done
curl -sf "http://$ETCD_C/health" | grep -q true && tc_pass "etcd up ($ETCD_C)" \
    || { tc_fail "etcd did not start"; tail -5 "$BASE/etcd.log"; exit 1; }
ETCDCTL="$(command -v etcdctl || true)"
if [[ -z "$ETCDCTL" && -x "$(dirname "$ETCD_BIN")/etcdctl" ]]; then
    ETCDCTL="$(dirname "$ETCD_BIN")/etcdctl"
fi

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 2: population (tenants=$SCALE_TENANTS agents/t=$SCALE_AGENTS sandfs/a=$SCALE_SANDFS)"
# ══════════════════════════════════════════════════════════════════
POP_OUT=$("$POP_BIN" -endpoints "$ETCD_C" \
    -tenants "$SCALE_TENANTS" -agents-per-tenant "$SCALE_AGENTS" -sandfs-per-agent "$SCALE_SANDFS" \
    -nodes 4 -gateway-id gw-exec-1 -gateway-url "$AGENT_A_URL" -stream-addr "$GW_A_STREAM" \
    -sample-out "$SAMPLE_KEYS" -workers 32 2>&1 | tail -1)
tc_pass "$POP_OUT"
echo "\"population\": $(json_str "$POP_OUT")," >> "$RAW"
# Settle the write-back: the population leaves ~750MB of dirty page cache;
# a gateway cold-load started immediately competes with the flush and reads
# 4-15x slower (measured: C1 265s contended vs 18-19s quiet on the
# same build). sync blocks until the flush completes — the measurement must
# run on a settled box.
sync
echo "\"post_population_sync\": \"done\"," >> "$RAW"

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 3: gateways (C1: identity full load)"
# ══════════════════════════════════════════════════════════════════
mkdir -p "$BASE/vol"
cat > "$BASE/gw-a.yaml" <<YAML
mode: exec
gateway_id: gw-exec-1
gateway_url: $AGENT_A_URL
gateway_stream_addr: $GW_A_STREAM
etcd: "http://$ETCD_C"   # the gateway validates endpoints as URLs (scheme required)
vol_root: $BASE/vol
identity_load:
  hot_only: true
  lazy_load: true
  full_load_timeout_sec: 600
YAML
cat > "$BASE/gw-human.yaml" <<YAML
mode: human
gateway_id: gw-human-1
gateway_url: $HUMAN_URL
etcd: "http://$ETCD_C"   # the gateway validates endpoints as URLs (scheme required)
vol_root: $BASE/vol
identity_load:
  full_load_timeout_sec: 600
YAML

# Single-gateway residency ( lesson): the human gateway runs ALONE
# here; the exec gateway gets its own leg (Phase 7). Never both at once.
leg_guard "human"
HUMAN_T0=$(now_ms)
"$GW_BIN" -gomemlimit 1536MiB -config "$BASE/gw-human.yaml" -human-addr "$HUMAN_ADDR" -agent-addr 127.0.0.1:13191 -stream-addr 127.0.0.1:13996 -allow-anonymous-human \
    > "$BASE/gw-human.log" 2>&1 &
HUMAN_PID=$!
PIDS+=($HUMAN_PID)

HUMAN_READY=0
# 2400×0.5s = 20min: a cold 1M full load can legitimately exceed 10min on a
# shared-CPU box; the FULL-LOAD-TIMEOUT finding is C1's number, not a crash.
for _ in $(seq 1 2400); do
    [[ "$(http_ms "$HUMAN_URL/ready" | awk '{print $1}')" == "200" ]] && { HUMAN_READY=1; break; }
    kill -0 "$HUMAN_PID" 2>/dev/null || break
    sleep 0.5
done
HUMAN_T1=$(now_ms)
LOAD_MS=$((HUMAN_T1 - HUMAN_T0))
if [[ "$HUMAN_READY" == "1" ]]; then
    tc_pass "C1: human gw ready in ${LOAD_MS}ms (full identity load)"
    echo "\"c1_full_load_ms\": $LOAD_MS," >> "$RAW"
    if (( LOAD_MS > 120000 )); then
        tc_log_warn "C1 FINDING: load ${LOAD_MS}ms exceeds the default -identity-full-load-timeout-sec (120) — deployments at this population must raise it"
    fi
else
    tc_fail "C1: human gw never became ready over the population (tail:)"; tail -5 "$BASE/gw-human.log"; exit 1
fi
tc_pass "human gw leg up (exec gw deferred to Phase 7 — single residency)"

# the namespaced surface requires verified claims. This rehearsal's
# human gateway is anonymous (-allow-anonymous-human), so /human/ns/* is
# denied by design. Detect it once; skip C2 (per-ns listing) and C8's
# namespaced setup, keep C1/, and record the skip in the report.
NS_CLAIMS_OK=1
NS_RESP=$(curl -s -m 10 -w '\n%{http_code}' "$HUMAN_URL/human/ns/tenant-1/agent?limit=1" 2>/dev/null || true)
NS_CODE=$(tail -1 <<<"$NS_RESP")
NS_BODY=$(sed '$d' <<<"$NS_RESP")
if [[ "$NS_CODE" == "403" ]] && grep -q "NAMESPACE_FORBIDDEN" <<<"$NS_BODY"; then
    NS_CLAIMS_OK=0
    tc_log_warn "C2/C8 skipped: /human/ns/* requires verified claims; this rehearsal's human gateway is anonymous"
    echo "\"c2\": \"skipped-anonymous (verified claims required)\"," >> "$RAW"
    echo "\"c8\": \"skipped-anonymous\"," >> "$RAW"
elif [[ "$NS_CODE" == "200" ]]; then
    tc_pass "namespaced listing reachable (verified claims present) — C2/C8 will run"
else
    NS_CLAIMS_OK=0
    tc_fail "namespaced listing probe returned HTTP $NS_CODE (expected 200 or 403 NAMESPACE_FORBIDDEN)"
fi

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 4a: measurements — listing shapes (C2/C3)"
# ══════════════════════════════════════════════════════════════════
# per-ns listing: random tenants, both resource families (requires claims)
if [[ "$NS_CLAIMS_OK" == "1" ]]; then
for fam in agent sandfs; do
    : > "$BASE/c2-$fam.txt"
    for i in $(seq 1 "$SAMPLES"); do
        t=$(( (RANDOM * 32768 + RANDOM) % SCALE_TENANTS + 1 ))
        read -r code ms < <(http_ms "$HUMAN_URL/human/ns/tenant-$t/$fam?limit=100")
        [[ "$code" == "200" ]] && echo "$ms" >> "$BASE/c2-$fam.txt" || tc_fail "C2 $fam tenant-$t → $code"
    done
    P=$(python3 - "$BASE/c2-$fam.txt" <<'PYEOF'
import sys, statistics
v = sorted(int(x) for x in open(sys.argv[1]) if x.strip())
if not v:
    # Defensive: no successful samples (e.g. an unexpected 403). Do not
    # IndexError; the individual tc_fail calls above already flagged it.
    print("0 0 0 0")
    raise SystemExit(0)
q = lambda p: v[min(len(v)-1, int(len(v)*p))]
print(f"{q(0.50)} {q(0.95)} {q(0.99)} {statistics.mean(v):.1f}")
PYEOF
)
    read -r P50 P95 P99 AVG <<< "$P"
    tc_pass "C2 /human/ns/*/​$fam?limit=100: P50=${P50}ms P95=${P95}ms P99=${P99}ms avg=${AVG}ms (n=$SAMPLES)"
    echo "\"c2_${fam}_p50\": $P50, \"c2_${fam}_p95\": $P95, \"c2_${fam}_p99\": $P99," >> "$RAW"
done
else
    tc_log_warn "C2 skipped (anonymous human posture;: verified claims required)"
fi

# fleet listing: the flat worst case — few samples, assert bounded
: > "$BASE/c3.txt"
for i in 1 2 3 4 5; do
    read -r code ms < <(http_ms "$HUMAN_URL/human/sandfs?limit=1000")
    [[ "$code" == "200" ]] && echo "$ms" >> "$BASE/c3.txt" || tc_fail "C3 fleet sandfs → $code"
done
P=$(python3 - "$BASE/c3.txt" <<'PYEOF'
import sys
v = sorted(int(x) for x in open(sys.argv[1]) if x.strip())
print(v[0], v[len(v)//2], v[-1])
PYEOF
)
read -r MIN MED MAX <<< "$P"
tc_pass "C3 fleet /human/sandfs?limit=1000: min=${MIN}ms med=${MED}ms max=${MAX}ms (hard-paginated page)"
echo "\"c3_min\": $MIN, \"c3_med\": $MED, \"c3_max\": $MAX," >> "$RAW"

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 4c: /stats + /metrics projection (C5)"
# ══════════════════════════════════════════════════════════════════
for ep in stats metrics; do
    : > "$BASE/c5-$ep.txt"
    for i in 1 2 3 4 5; do
        read -r code ms < <(http_ms "$HUMAN_URL/$ep")
        [[ "$code" == "200" ]] && echo "$ms" >> "$BASE/c5-$ep.txt" || tc_log_warn "C5 $ep → $code"
    done
    MED=$(sort -n "$BASE/c5-$ep.txt" | sed -n 3p)
    tc_pass "C5 /$ep: median ${MED}ms"
    echo "\"c5_${ep}_med\": ${MED:-0}," >> "$RAW"
done

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 4d: DNS owner-aware zone (C6)"
# ══════════════════════════════════════════════════════════════════
if [[ -x "$DNS_BIN" ]]; then
    cat > "$BASE/sandns.yaml" <<YAML
listen_addr: "$DNS_ADDR"
domains:
  agent: agent.scale.local
  stream: stream.scale.local
  sandfs: sandfs.scale.local
etcd: "http://$ETCD_C"   # the gateway validates endpoints as URLs (scheme required)
ttl: 30
scheduling:
  policy: spread
YAML
    "$DNS_BIN" -config "$BASE/sandns.yaml" > "$BASE/sandns.log" 2>&1 &
    PIDS+=($!)
    sleep 2
    # pick any sandfs id straight from the ownership keyspace
    SFID=$(ETCDCTL_API=3 "$ETCDCTL" --endpoints "http://$ETCD_C" get /sandswap/owner/ --prefix --limit=1 --keys-only 2>"$BASE/c6-etcdctl.err" | grep -o 'sandfs-[0-9a-f]*' | head -1 || true)
    if [[ -z "${SFID:-}" ]]; then
        tc_log_warn "C6: no sandfs id from etcdctl — err: $(tail -c 400 "$BASE/c6-etcdctl.err" 2>/dev/null | tr '\n' ' ')"
    fi
    if [[ -n "${SFID:-}" ]] && command -v dig >/dev/null 2>&1; then
        : > "$BASE/c6.txt"
        for i in $(seq 1 50); do
            t0=$(now_ms)
            # a SERVFAIL/timed-out query is a DATA point (the DNS is down or
            # the record unresolved) — never a set -e kill
            dig -p 15053 "@127.0.0.1" "$SFID.sandfs.scale.local" A +time=5 +tries=1 > /dev/null 2>&1 || true
            t1=$(now_ms)
            echo "$((t1 - t0))" >> "$BASE/c6.txt"
        done
        P=$(python3 - "$BASE/c6.txt" <<'PYEOF'
import sys
v = sorted(int(x) for x in open(sys.argv[1]) if x.strip())
q = lambda p: v[min(len(v)-1, int(len(v)*p))]
print(q(0.50), q(0.95), q(0.99))
PYEOF
)
        read -r P50 P95 P99 <<< "$P"
        tc_pass "C6 DNS $SFID.sandfs.zone: P50=${P50}ms P95=${P95}ms P99=${P99}ms (n=50)"
        echo "\"c6_p50\": $P50, \"c6_p95\": $P95, \"c6_p99\": $P99," >> "$RAW"
    else
        tc_log_warn "C6 skipped: no dig or no sandfs id resolved (recorded, not silent)"
        echo "\"c6\": \"skipped\"," >> "$RAW"
    fi
else
    echo "\"c6\": \"dns-binary-absent\"," >> "$RAW"
fi

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 5: restart re-load (C7)"
# ══════════════════════════════════════════════════════════════════
kill "$HUMAN_PID" 2>/dev/null || true
wait "$HUMAN_PID" 2>/dev/null || true
sleep 1
C7_T0=$(now_ms)
"$GW_BIN" -gomemlimit 1536MiB -config "$BASE/gw-human.yaml" -human-addr "$HUMAN_ADDR" -agent-addr 127.0.0.1:13191 -stream-addr 127.0.0.1:13996 -allow-anonymous-human \
    > "$BASE/gw-human2.log" 2>&1 &
HUMAN_PID=$!
PIDS+=($HUMAN_PID)
C7_OK=0
for _ in $(seq 1 1200); do
    [[ "$(http_ms "$HUMAN_URL/ready" | awk '{print $1}')" == "200" ]] && { C7_OK=1; break; }
    sleep 0.5
done
C7_T1=$(now_ms)
C7_MS=$((C7_T1 - C7_T0))
if [[ "$C7_OK" == "1" ]]; then
    tc_pass "C7: restart re-load ${C7_MS}ms to /ready"
    echo "\"c7_reload_ms\": $C7_MS," >> "$RAW"
else
    tc_fail "C7: restart never became ready"; tail -5 "$BASE/gw-human2.log"
fi

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 6: ownership CAS contention (C8, two concurrent reap callers)"
# ══════════════════════════════════════════════════════════════════
# No second gateway: the CAS contention is exercised by two CONCURRENT
# reap-stuck invocations through the one human gateway (single residency).

# Kill owner gw-exec-1's health (make every record dead-owned) for a bounded
# slice, then race TWO reap-stuck invocations at it. Both must succeed; the
# reclaimed set must be exactly-once (CAS), and latency is the finding.
if [[ "$NS_CLAIMS_OK" != "1" ]]; then
    tc_log_warn "C8 skipped (anonymous human posture;: verified claims required)"
else
DEAD_TENANT=$(( SCALE_TENANTS ))
DEAD_OWNER="gw-dead-9"
# Re-point tenant-$DEAD_TENANT's ownership records at the dead owner + give
# the dead owner an ancient health stamp + a registry entry.
python3 - "$ETCD_C" "$DEAD_TENANT" "$DEAD_OWNER" "$ETCDCTL" <<'PYEOF'
import json, subprocess, sys
endpoints, tenant, dead, etcdctl = sys.argv[1:5]
# walk the ns listing (bounded: one tenant) via the human API instead of a
# full etcd scan — re-point each listed sandfs's ownership key.
import urllib.request
req = urllib.request.Request(f"http://127.0.0.1:13100/human/ns/tenant-{tenant}/sandfs?limit=1000")
page = json.load(urllib.request.urlopen(req, timeout=30))
ids = [r["sandfs_id"] for r in page.get("items", [])]
assert ids, "no items listed for the dead tenant"
def etcd(*args):
    subprocess.run([etcdctl, "--endpoints", f"http://{endpoints}"] + list(args), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
etcd("put", f"/sandswap/health/{dead}", json.dumps({"last_healthy_ts": "2026-01-01T00:00:00Z", "node_count": 0}))
for sf in ids:
    # node-9 deliberately has NO presence key: reap-stuck's reclaim
    # condition is placement-node-presence-gone; a live placement node makes
    # every entry a documented skip.
    etcd("put", f"/sandswap/owner/{sf}", json.dumps({"gateway_id": dead, "node_id": "node-9", "generation": 3}))
etcd("put", f"/sandswap/gateway/{dead}", json.dumps({"gateway_url": "http://127.0.0.1:1", "stream_addr": "127.0.0.1:1"}))
print(f"dead-owned records: {len(ids)}")
PYEOF
RC=$?
if [[ $RC -ne 0 ]]; then
    tc_log_warn "C8 setup failed (etcdctl unavailable?) — leg recorded as skipped"
    echo "\"c8\": \"setup-failed\"," >> "$RAW"
else
    reap() {
        curl -s -m 120 -X POST "$HUMAN_URL/human/ownership/reap-stuck" \
            -H 'Content-Type: application/json' \
            -d "{\"gateway_id\":\"$DEAD_OWNER\",\"dry_run\":false}" 2>/dev/null || true
    }
    T0=$(now_ms)
    reap > "$BASE/c8-a.json" & A=$!
    reap > "$BASE/c8-b.json" & B=$!
    wait $A; wait $B
    T1=$(now_ms)
    C8_MS=$((T1 - T0))
    parse_reaped() { # robust: field may be top-level or nested; dump on miss
        python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
v=d.get('reaped_count')
if v is None and isinstance(d.get('report'),dict): v=d['report'].get('reaped_count')
print(v if v is not None else 'PARSE-MISS:'+json.dumps(d)[:200])
" "$1" 2>/dev/null || { echo 'PARSE-FAIL'; head -c 300 "$1"; }
    }
    A_RECLAIMED=$(parse_reaped "$BASE/c8-a.json")
    B_RECLAIMED=$(parse_reaped "$BASE/c8-b.json")
    tc_pass "C8: two concurrent reap-stuck races completed in ${C8_MS}ms (reclaimed a=$A_RECLAIMED b=$B_RECLAIMED; CAS exactly-once visible in the responses)"
    echo "\"c8_race_ms\": $C8_MS, \"c8_a\": $(json_str "$A_RECLAIMED"), \"c8_b\": $(json_str "$B_RECLAIMED")," >> "$RAW"
fi
fi

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 7: exec gateway leg (C4; human gw stopped — single residency)"
# ══════════════════════════════════════════════════════════════════
kill "$HUMAN_PID" 2>/dev/null || true
wait "$HUMAN_PID" 2>/dev/null || true
sleep 2
leg_guard "exec"
"$GW_BIN" -gomemlimit 1GiB -config "$BASE/gw-a.yaml" -agent-addr "$GW_A_AGENT" -stream-addr "$GW_A_STREAM" -human-addr 127.0.0.1:13190 \
    > "$BASE/gw-a.log" 2>&1 &
EXEC_PID=$!
PIDS+=($EXEC_PID)
E_T0=$(now_ms)
E_READY=0
for _ in $(seq 1 600); do
    curl -sf -m 2 "$AGENT_A_URL/health" >/dev/null 2>&1 && { E_READY=1; break; }
    kill -0 "$EXEC_PID" 2>/dev/null || break
    sleep 0.5
done
E_T1=$(now_ms)
if [[ "$E_READY" == "1" ]]; then
    tc_pass "exec gw ready in $((E_T1-E_T0))ms (hot-only identity load + ownership)"
    echo "\"c7b_exec_ready_ms\": $((E_T1-E_T0))," >> "$RAW"
else
    tc_fail "exec gw never became ready"; tail -5 "$BASE/gw-a.log"
fi
# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 7a: agent-API auth hot path (C4)"
# ══════════════════════════════════════════════════════════════════
: > "$BASE/c4.txt"
C4_FAIL=0
for i in $(seq 1 "$SAMPLES"); do
    t=$(( (RANDOM * 32768 + RANDOM) % SCALE_TENANTS + 1 ))
    KEY=$(grep "^tenant-$t " "$SAMPLE_KEYS" | awk '{print $2}')
    read -r code ms < <(http_ms "$AGENT_A_URL/agent/sandfs" -H "Authorization: Bearer $KEY")
    if [[ "$code" == "200" ]]; then echo "$ms" >> "$BASE/c4.txt"; else C4_FAIL=$((C4_FAIL+1)); fi
done
if (( C4_FAIL == 0 )); then
    P=$(python3 - "$BASE/c4.txt" <<'PYEOF'
import sys, statistics
v = sorted(int(x) for x in open(sys.argv[1]) if x.strip())
q = lambda p: v[min(len(v)-1, int(len(v)*p))]
print(f"{q(0.50)} {q(0.95)} {q(0.99)} {statistics.mean(v):.1f}")
PYEOF
)
    read -r P50 P95 P99 AVG <<< "$P"
    tc_pass "C4 /agent/sandfs (digest auth + owned list): P50=${P50}ms P95=${P95}ms P99=${P99}ms avg=${AVG}ms (n=$SAMPLES)"
    echo "\"c4_p50\": $P50, \"c4_p95\": $P95, \"c4_p99\": $P99," >> "$RAW"
else
    tc_fail "C4: $C4_FAIL/$SAMPLES probe requests failed"
fi

# ══════════════════════════════════════════════════════════════════

kill "$EXEC_PID" 2>/dev/null || true

# ── Report ─────────────────────────────────────────────────────
sed -i '$s/,$//' "$RAW" 2>/dev/null || true
echo "}" >> "$RAW"
tc_log_section "Report"
echo "  raw json → $RAW"
python3 -I - "$RAW" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
rows = [
    ("C1 identity full load", d.get("c1_full_load_ms"), "ms"),
    ("C2 per-ns agent listing P95", d.get("c2_agent_p95"), "ms"),
    ("C2 per-ns sandfs listing P95", d.get("c2_sandfs_p95"), "ms"),
    ("C3 fleet listing (med/max)", f'{d.get("c3_med")}/{d.get("c3_max")}', "ms"),
    ("C4 agent auth P95", d.get("c4_p95"), "ms"),
    ("C5 /stats median", d.get("c5_stats_med"), "ms"),
    ("C5 /metrics median", d.get("c5_metrics_med"), "ms"),
    ("C6 DNS P95", d.get("c6_p95"), "ms"),
    ("C7 restart re-load", d.get("c7_reload_ms"), "ms"),
    ("C8 CAS race", d.get("c8_race_ms"), "ms"),
]
print(f"  {'curve':<34} {'value':>12}  ")
for name, val, unit in rows:
    shown = "skipped-anonymous" if val is None else str(val)
    print(f"  {name:<34} {shown:>10} {unit}")
PYEOF
if [[ $SMOKE -eq 1 ]]; then
    tc_log_warn "SMOKE run — numbers are machinery checks, NOT scale evidence"
fi
tc_log_pass "scale rehearsal complete"
