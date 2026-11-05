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
# Real-gateway E2E for the manual reap-stuck tool (problem 4) + /stats staleness
# exposure (problem 5). Starts a real etcd + a real HUMAN gateway binary (no KVM,
# no auth — OIDC disabled so /human/* is passthrough), seeds dead-owner sandfs
# via etcdctl, and drives the POST /human/ownership/reap-stuck endpoint over HTTP.
# Covers: idle sandfs reaped; mounted sandfs reaped only when the node presence
# key is gone (else skipped); dry-run reports without deleting; a live owner is
# refused; /stats exposes StaleSec for the dead owner.
# Usage: bash e2e/staleness-gateway-e2e.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

ETCD_DATA="/tmp/sandswap-reapgw-e2e-etcd-data"
ETCD_ENDPOINT="http://127.0.0.1:2379"

GW_BIN="/tmp/sandswap-reapgw-gateway"
GW_ID="gw-human-reap"
GW_ADDR="127.0.0.1:13100"
GW_URL="http://${GW_ADDR}"
VOL_ROOT="/tmp/sandswap-reapgw-volroot"

DEAD_OWNER="" # set per-run in the seeding section (unique id)

GW_PID=""
cleanup() {
    [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null || true
    tc_cleanup_etcd "$ETCD_DATA"
    rm -rf "$VOL_ROOT"
}
trap cleanup EXIT INT TERM

# ── Start etcd ──────────────────────────────────────────────────
tc_ensure_etcd
if ss -tlnp 2>/dev/null | grep -q ":${GW_ADDR##*:}"; then
    tc_kill_port "${GW_ADDR##*:}"; sleep 0.5
fi
tc_start_etcd reapgw-e2e "$ETCD_DATA"

# ── Build + start human gateway ─────────────────────────────────
tc_log_section "Building + starting human gateway"
cd "$ROOT/gateway"
go build -o "$GW_BIN" ./cmd/ 2>&1 || { echo "FAIL: gateway build"; exit 1; }
tc_pass "gateway built"

mkdir -p "$VOL_ROOT"
"$GW_BIN" \
    -mode human -human-addr "$GW_ADDR" -gateway-id "$GW_ID" \
    -gateway-url "$GW_URL" -etcd "$ETCD_ENDPOINT" -vol-root "$VOL_ROOT" \
    -allow-anonymous-human \
    -route-stale-sec 2 -claim-dead-guard-sec 2 -alert-stale-sec 2 \
    -ownership-cache-ttl-sec 2 \
    >/tmp/sandswap-reapgw-gw.log 2>&1 &
GW_PID=$!
# shellcheck disable=SC2034  # poll loop counter
for i in $(seq 1 60); do curl -sf "$GW_URL/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$GW_URL/health" >/dev/null 2>&1 || { echo "FAIL: gateway did not start"; tail -20 /tmp/sandswap-reapgw-gw.log; exit 1; }
tc_pass "human gateway started (PID=$GW_PID, $GW_URL)"

# ── Seed dead-owner sandfs ──────────────────────────────────────
tc_log_section "Seeding dead-owner sandfs"
SUF=$(date +%s)
DEAD_OWNER="gw-reap-dead-${SUF}"
IDLE1="sandfs-reap-idle1-${SUF}"
IDLE2="sandfs-reap-idle2-${SUF}"
MOUNTED_ALIVE="sandfs-reap-mounted-alive-${SUF}"   # node presence present → skip
MOUNTED_GONE="sandfs-reap-mounted-gone-${SUF}"     # node presence absent → reap
NODE_ALIVE="node-reap-alive-${SUF}"

put_owner() { # sandfsID gwID nodeID
    "$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/owner/$1" \
        "{\"gateway_id\":\"$2\",\"node_id\":\"$3\",\"generation\":1}" >/dev/null
}
put_owner "$IDLE1"         "$DEAD_OWNER" ""
put_owner "$IDLE2"         "$DEAD_OWNER" ""
put_owner "$MOUNTED_ALIVE" "$DEAD_OWNER" "$NODE_ALIVE"
put_owner "$MOUNTED_GONE"  "$DEAD_OWNER" "node-reap-gone-${SUF}"
# node alive: presence present (names the dead owner — still "present", so skip)
"$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/node/${NODE_ALIVE}/presence" "$DEAD_OWNER" >/dev/null
# node gone: no presence key.
# DEAD_OWNER has NO health key → dead. GW_ID (this gateway) is alive via its own health loop.
tc_pass "seeded 4 sandfs owned by dead $DEAD_OWNER (2 idle, 1 mounted+presence, 1 mounted+no-presence)"

# ── Test 1: dry-run reports 3 reaped / 1 skipped, deletes nothing ─
tc_log_section "Test 1: dry-run reap-stuck"
DRY=$(curl -sf -X POST "$GW_URL/human/ownership/reap-stuck" \
    -H 'Content-Type: application/json' \
    -d "{\"gateway_id\":\"$DEAD_OWNER\",\"dry_run\":true,\"batch_size\":10}" 2>&1 || true)
[[ -n "$DRY" ]] || tc_fail "dry-run reap-stuck call failed (non-2xx)"
echo "$DRY" | grep -q '"reaped_count":3' && tc_pass "dry-run reports reaped_count=3" || { tc_fail "dry-run reaped_count != 3"; echo "$DRY"; }
echo "$DRY" | grep -q '"skipped_count":1' && tc_pass "dry-run reports skipped_count=1" || { tc_fail "dry-run skipped_count != 1"; echo "$DRY"; }
for sf in "$IDLE1" "$IDLE2" "$MOUNTED_ALIVE" "$MOUNTED_GONE"; do
    OUT=$("$ETCDCTL" --endpoints "$ETCD_ENDPOINT" get "/sandswap/owner/$sf" 2>/dev/null || true)
    [ -n "$OUT" ] && tc_pass "dry-run did not delete $sf" || tc_fail "dry-run deleted $sf"
done

# ── Test 2: real run deletes 3, MOUNTED_ALIVE survives ──────────
tc_log_section "Test 2: real reap-stuck"
REAL=$(curl -sf -X POST "$GW_URL/human/ownership/reap-stuck" \
    -H 'Content-Type: application/json' \
    -d "{\"gateway_id\":\"$DEAD_OWNER\",\"dry_run\":false,\"batch_size\":10}" 2>&1 || true)
[[ -n "$REAL" ]] || tc_fail "real reap-stuck call failed (non-2xx)"
echo "$REAL" | grep -q '"reaped_count":3' && tc_pass "real run reaped_count=3" || { tc_fail "real reaped_count != 3"; echo "$REAL"; }
for sf in "$IDLE1" "$IDLE2" "$MOUNTED_GONE"; do
    # `|| true` made a FAILED etcdctl read (etcd down / bad endpoint) yield
    # empty output — indistinguishable from "key deleted". Capture the rc:
    # 0 + empty = really reaped; non-zero = the read failed, no verdict.
    RCTL=0
    OUT=$("$ETCDCTL" --endpoints "$ETCD_ENDPOINT" get "/sandswap/owner/$sf" 2>/dev/null) || RCTL=$?
    if [ "$RCTL" -ne 0 ]; then
        tc_fail "$sf: etcdctl get failed (rc=$RCTL) — cannot distinguish 'reaped' from an unreadable key"
    elif [ -n "$OUT" ]; then
        tc_fail "$sf still present (should be reaped)"
    else
        tc_pass "$sf reaped"
    fi
done
OUT=$("$ETCDCTL" --endpoints "$ETCD_ENDPOINT" get "/sandswap/owner/$MOUNTED_ALIVE" 2>/dev/null || true)
[ -n "$OUT" ] && tc_pass "$MOUNTED_ALIVE survived (presence present → skipped)" || tc_fail "$MOUNTED_ALIVE was wrongly reaped"

# ── Test 3: live owner refused ──────────────────────────────────
tc_log_section "Test 3: live owner refused"
LIVE_OWNER="gw-reap-live-${SUF}"
"$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/health/$LIVE_OWNER" "{\"last_healthy_ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"node_count\":1}" >/dev/null
put_owner "sandfs-reap-live-${SUF}" "$LIVE_OWNER" ""
HTTP_CODE=$(curl -s -o /tmp/reap-live-resp.json -w '%{http_code}' -X POST "$GW_URL/human/ownership/reap-stuck" \
    -H 'Content-Type: application/json' \
    -d "{\"gateway_id\":\"$LIVE_OWNER\",\"dry_run\":false,\"batch_size\":10}" || true)
if [ "$HTTP_CODE" = "409" ]; then
    tc_pass "live owner refused with 409 Conflict"
else
    tc_fail "live owner: expected 409, got $HTTP_CODE"; cat /tmp/reap-live-resp.json
fi

# ── Test 4: /stats exposes staleness ────────────────────────────
tc_log_section "Test 4: /stats staleness exposure"
# /stats aggregates gateways from /sandswap/{health,gateway,load}/ keys. Seed a
# STALE gateway (registry key present + a health key with an old timestamp) so
# /stats lists it with healthy=false-ish + a non-zero stale_sec. The local human
# gateway (GW_ID) is alive → stale_sec≈0 (the fresh counterpoint).
STALE_GW="gw-stats-stale-${SUF}"
"$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/gateway/$STALE_GW" "{\"gateway_url\":\"https://10.0.0.99:3000\"}" >/dev/null
"$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/health/$STALE_GW" "{\"last_healthy_ts\":\"2020-01-01T00:00:00Z\",\"node_count\":1}" >/dev/null
STATS=$(curl -sf "$GW_URL/stats" 2>&1 || true)
[[ -n "$STATS" ]] || tc_fail "/stats call failed"
echo "$STATS" | grep -q "\"gateway_id\":\"$STALE_GW\"" && tc_pass "/stats lists stale gateway $STALE_GW" || tc_fail "/stats missing stale gateway"
echo "$STATS" | grep -o "\"gateway_id\":\"$STALE_GW\"[^}]*" | grep -q '"stale_sec":[1-9]' && tc_pass "/stats exposes stale_sec > 0 for stale gateway" || { tc_fail "/stats stale_sec not > 0 for stale gateway"; echo "$STATS" | head -c 400; echo; }
echo "$STATS" | grep -q "\"gateway_id\":\"$GW_ID\"" && tc_pass "/stats lists local live gateway $GW_ID" || tc_fail "/stats missing local live gateway"

# ── Summary ─────────────────────────────────────────────────────
tc_log_section "Summary"
echo "  pass=$PASS_COUNT fail=$FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    tc_log_error "$FAIL_COUNT test(s) FAILED"
    echo "  gateway log (last 15 lines):"; tail -15 /tmp/sandswap-reapgw-gw.log
    exit 1
fi
tc_log_pass "All reap-stuck real-gateway E2E tests PASSED"
