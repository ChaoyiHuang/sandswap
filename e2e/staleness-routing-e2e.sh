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
# Real-exec-gateway E2E for the 307-redirect staleness gate (problem 2) over the
# full HTTP auth chain. Starts a real etcd + a real EXEC gateway, seeds an agent
# + api_key + sandfs + a (fake) owner gateway directly in etcd, and drives
# POST /agent/execute over HTTP.
# Covers:
#   - Owner FRESH  → /agent/execute returns 307 to the owner's gateway_url
#     (the tolerance path: ownership unchanged, only the owner can serve).
#   - Owner DEAD   → /agent/execute returns 503 (NOT 307) — the staleness gate
#     refuses to bounce the request to a dead owner; the client re-resolves via
#     DNS to a live gateway instead.
# No KVM, no sandlot — the redirect is decided at the Claim stage (before any
# VM is acquired), so no execution actually happens.
# Usage: bash e2e/staleness-routing-e2e.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

ETCD_DATA="/tmp/sandswap-routing-e2e-etcd-data"
ETCD_ENDPOINT="http://127.0.0.1:2379"

GW_BIN="/tmp/sandswap-routing-gateway"
GW_ID="gw-exec-routing"
GW_AGENT_ADDR="127.0.0.1:13000"
GW_STREAM_ADDR="127.0.0.1:19998"
GW_URL="http://${GW_AGENT_ADDR}"
VOL_ROOT="/tmp/sandswap-routing-volroot"

FAKE_OWNER="gw-fake-owner"
FAKE_OWNER_URL="http://127.0.0.1:39999"
API_KEY="sk-sandswap-routing-test-key"
SANDFS_ID="sandfs-routing-e2e"
AGENT_ID="agent-routing-e2e"

GW_PID=""
cleanup() {
    [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null || true
    tc_cleanup_etcd "$ETCD_DATA"
    rm -rf "$VOL_ROOT"
}
trap cleanup EXIT INT TERM

# ── Start etcd ──────────────────────────────────────────────────
tc_ensure_etcd
for p in 13000 19998; do
    tc_kill_port "$p"; sleep 0.5
done
tc_start_etcd routing-e2e "$ETCD_DATA"

# ── Seed identity + ownership BEFORE the exec gateway starts (snapshot load) ──
tc_log_section "Seeding identity + ownership"
API_KEY_HASH=$(printf '%s' "$API_KEY" | sha256sum | cut -d' ' -f1)
"$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/identity/agent/${API_KEY_HASH}" \
    "{\"agent_id\":\"${AGENT_ID}\",\"name\":\"routing-e2e\",\"api_key_hash\":\"${API_KEY_HASH}\",\"created_at\":\"2026-08-30T00:00:00Z\"}" >/dev/null
"$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/identity/sandfs/${SANDFS_ID}" \
    "{\"sandfs_id\":\"${SANDFS_ID}\",\"agent_id\":\"${AGENT_ID}\",\"rootfs_path\":\"${VOL_ROOT}/${SANDFS_ID}\",\"mode\":\"flat\"}" >/dev/null
# Ownership: sandfs owned by the FAKE owner (idle).
"$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/owner/${SANDFS_ID}" \
    "{\"gateway_id\":\"${FAKE_OWNER}\",\"node_id\":\"\",\"generation\":1}" >/dev/null
# Fake owner registry (so OwnerGatewayURL can resolve a redirect target).
"$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/gateway/${FAKE_OWNER}" \
    "{\"gateway_url\":\"${FAKE_OWNER_URL}\"}" >/dev/null
tc_pass "seeded agent + sandfs + ownership(${FAKE_OWNER}) + registry"

seed_fresh_owner_health() {
    # Sub-second timestamp (RFC3339 with fractional seconds — parses fine as
    # RFC3339): a whole-second seed combined with -route-stale-sec 2 makes the
    # "fresh" key go stale ~1s after the second boundary, so a gateway startup
    # of ≥2s flakes the 307 test. Fractional seconds give the full 2s of slack.
    "$ETCDCTL" --endpoints "$ETCD_ENDPOINT" put "/sandswap/health/${FAKE_OWNER}" \
        "{\"last_healthy_ts\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\",\"node_count\":1}" >/dev/null
}
kill_owner_health() {
    "$ETCDCTL" --endpoints "$ETCD_ENDPOINT" del "/sandswap/health/${FAKE_OWNER}" >/dev/null
}
# NOTE: the fresh health key is seeded right before Test 1's request (below), NOT
# here. ownerStaleness reads live etcd at request time, so seeding right before
# the 307 test is what the test is really about (health fresh → redirect). Seeding
# before the build would make the health freshness window (route-stale-sec 2s)
# race the gateway build + startup latency — on a slow box / cold build cache that
# is >2s, flashing "fresh owner gives 307" into a 503.

# ── Build + start exec gateway ──────────────────────────────────
tc_log_section "Building + starting exec gateway"
cd "$ROOT/gateway"
go build -o "$GW_BIN" ./cmd/ 2>&1 || { echo "FAIL: gateway build"; exit 1; }
tc_pass "gateway built"
mkdir -p "$VOL_ROOT"
ss_service_exec sandserv -- "$GW_BIN" \
    -mode exec -agent-addr "$GW_AGENT_ADDR" -stream-addr "$GW_STREAM_ADDR" \
    -gateway-id "$GW_ID" -gateway-url "$GW_URL" -etcd "$ETCD_ENDPOINT" -vol-root "$VOL_ROOT" \
    -route-stale-sec 2 -claim-dead-guard-sec 30 -alert-stale-sec 2 \
    >/tmp/sandswap-routing-gw.log 2>&1 &
GW_PID=$!
for i in $(seq 1 60); do curl -sf "$GW_URL/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$GW_URL/health" >/dev/null 2>&1 || { echo "FAIL: exec gateway did not start"; tail -25 /tmp/sandswap-routing-gw.log; exit 1; }
tc_pass "exec gateway started (PID=$GW_PID, $GW_URL)"
# Wait for the identity snapshot load + ownership full-load to complete (/ready).
# shellcheck disable=SC2034  # poll loop counter
for i in $(seq 1 60); do curl -sf "$GW_URL/ready" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$GW_URL/ready" >/dev/null 2>&1 || tc_log_info "(warn: /ready not up yet; proceeding)"

exec_response() { # → "HTTPCODE<TAB>LOCATION" (Location value, empty if none).
    # DELETE the header file first: on a transport failure curl writes nothing,
    # and without this the PREVIOUS call's headers would be re-read — a
    # transport hiccup was then reported as "got 307 → staleness gate FAILED",
    # misattributing an infra error to a product regression. -m bounds a hung
    # gateway instead of hanging the whole script.
    rm -f /tmp/routing-exec-hdr.txt
    curl -s -m 15 -D /tmp/routing-exec-hdr.txt -o /dev/null \
        -X POST "$GW_URL/agent/execute" \
        -H "Authorization: Bearer $API_KEY" \
        -H 'Content-Type: application/json' \
        -d "{\"sandfs_id\":\"$SANDFS_ID\",\"code\":\"echo hi\",\"language\":\"shell\"}" 2>/dev/null || true
    if [[ ! -s /tmp/routing-exec-hdr.txt ]]; then
        printf 'TRANSPORT_ERROR\t'
        return 0
    fi
    local code
    code=$(grep -E '^HTTP/' /tmp/routing-exec-hdr.txt | tail -1 | awk '{print $2}')
    local loc
    loc=$(grep -i '^location:' /tmp/routing-exec-hdr.txt 2>/dev/null | tail -1 | sed 's/^[Ll]ocation:[[:space:]]*//' | tr -d '\r')
    printf '%s\t%s' "${code:-0}" "${loc:-}"
}

# ── Test 1: owner FRESH → 307 to the owner ──────────────────────
tc_log_section "Test 1: fresh owner → 307 redirect to owner"
seed_fresh_owner_health
tc_pass "seeded FRESH health for ${FAKE_OWNER}"
RESP=$(exec_response)
CODE=${RESP%%$'\t'*}
LOC=${RESP#*$'\t'}
if [ "$CODE" = "307" ] && echo "$LOC" | grep -qi "${FAKE_OWNER_URL}"; then
    tc_pass "fresh owner: 307 Location → ${FAKE_OWNER_URL}"
else
    tc_fail "fresh owner: expected 307 → ${FAKE_OWNER_URL}, got code=${CODE} loc=${LOC:-<none>}"
fi

# ── Test 2: owner DEAD → NOT 307 (staleness gate holds) ─────────
tc_log_section "Test 2: dead owner → 503 (no redirect to dead owner)"
kill_owner_health
sleep 0.5
RESP=$(exec_response)
CODE=${RESP%%$'\t'*}
LOC=${RESP#*$'\t'}
if [ "$CODE" = "307" ] && echo "$LOC" | grep -qi "${FAKE_OWNER_URL}"; then
    tc_fail "dead owner: got 307 → ${LOC} (redirect to dead owner — staleness gate FAILED)"
elif [ "$CODE" = "503" ]; then
    tc_pass "dead owner: 503, no redirect (staleness gate held)"
else
    tc_fail "dead owner: expected 503, got code=${CODE} loc=${LOC:-<none>}"
fi

# ── Summary ─────────────────────────────────────────────────────
tc_log_section "Summary"
echo "  pass=$PASS_COUNT fail=$FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    tc_log_error "$FAIL_COUNT test(s) FAILED"
    echo "  gateway log (last 15 lines):"; tail -15 /tmp/sandswap-routing-gw.log
    exit 1
fi
tc_log_pass "All staleness-routing real-gateway E2E tests PASSED"
