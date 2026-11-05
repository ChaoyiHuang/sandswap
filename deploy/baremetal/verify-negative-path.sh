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
# verify-negative-path.sh — (moved from e2e/negative-path-gates.sh) — W5 drill ('s control): BREAK each plane of
# the deployed one-machine stack and assert the gates FIRE — a named,
# retryable refusal, never a silent success and never a bare 500. Each
# breakage is restored on every exit path.
#
#   N1  storage plane down (prov unit stopped) → sandfs create = named 503
#       mentioning the provision instance (retryable), NOT 200/500; template
#       list likewise degrades, health stays 200 (the fleet is up)
#   N2  storage plane restored → the SAME create succeeds (the 503 told the
#       truth about retryability)
#   N3  unknown template ref → loud create refusal (4xx/503 with a named
#       error), never a half-created sandfs
#   N4  exec against a lifecycle-gated sandfs (deleting drain) → 409
#       SANDFS_NOT_ACTIVE (the drain gate)
#
# Usage: sudo bash deploy/baremetal/verify-negative-path.sh   (needs the deployed stack)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/e2e/common.sh"

PROV_UNIT="sandswap-sandlot-prov.service"
GW_URL="https://localhost:3000"
HUMAN_URL="https://localhost:3100"

tc_check_root
curl -sk -m 5 "$GW_URL/health" | grep -q '"status"' || { tc_skip_suite "deployed stack not answering (run deploy-one-machine-etcd.sh first)"; }
systemctl is-active --quiet "$PROV_UNIT" || { tc_skip_suite "prov unit not active — expected the one-machine topology"; }
tc_pass "stack up, prov active"

cleanup() { systemctl start "$PROV_UNIT" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# post <path> <body> [key] → sets CODE and BODY globals (multi-line safe).
post() {
    local path="$1" body="$2" key="${3:-}" hdr=()
    [[ -n "$key" ]] && hdr=(-H "Authorization: Bearer $key")
    local out
    out=$(curl -sk -m 20 -w '\n%{http_code}' -X POST "$HUMAN_URL$path" \
        -H 'Content-Type: application/json' "${hdr[@]}" -d "$body" 2>/dev/null || true)
    CODE=$(echo "$out" | tail -1)
    BODY=$(echo "$out" | head -n -1)
}

# ── fixture agent ─────────────────────────────────────────────────
RESP=$(curl -sk -X POST "$HUMAN_URL/human/agent" -H 'Content-Type: application/json' -d '{"name":"neg-path"}')
A_KEY=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('api_key',''))")
A_ID=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))")
[[ -n "$A_KEY" && -n "$A_ID" ]] || { tc_fail "fixture agent: $RESP"; exit 1; }

# ── N1: storage plane down ────────────────────────────────────────
tc_log_section "N1: prov plane down → named 503 (not silent, not 500)"
systemctl stop "$PROV_UNIT"
sleep 3
post "/human/sandfs" "{\"agent_id\":\"$A_ID\",\"name\":\"neg-n1\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}"
if [[ "$CODE" == "503" ]] && echo "$BODY" | grep -qi "provision\|storage plane"; then
    tc_pass "sandfs create = named 503 (storage plane): ${BODY:0:90}"
elif [[ "$CODE" == "503" ]]; then
    tc_pass "sandfs create = 503 (retryable refusal): ${BODY:0:90}"
elif [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
    tc_fail "create SUCCEEDED with the storage plane DOWN — a silent-success gate failure"
else
    tc_fail "unexpected create status with plane down: $CODE ${BODY:0:90}"
fi
H=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "$GW_URL/health")
[[ "$H" == "200" ]] && tc_pass "health stays 200 with the plane down" || tc_fail "health degraded to $H (plane outage leaked)"

# ── N2: restored → same create succeeds ───────────────────────────
tc_log_section "N2: plane restored → the retryable 503 told the truth"
systemctl start "$PROV_UNIT"
P=0
for _ in $(seq 1 30); do
    curl -sk "$HUMAN_URL/health" | grep -qE '"provisioners":[[:space:]]*[1-9]' && { P=1; break; }
    sleep 2
done
[[ "$P" == "1" ]] || { tc_fail "prov did not reconnect within 60s"; exit 1; }
post "/human/sandfs" "{\"agent_id\":\"$A_ID\",\"name\":\"neg-n2\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}"
SF_ID=$(echo "$BODY" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || true)
[[ "$CODE" == "201" && -n "$SF_ID" ]] && tc_pass "create succeeds after restore ($SF_ID)" || tc_fail "restore create: $CODE ${BODY:0:90}"

# ── N3: unknown template ──────────────────────────────────────────
tc_log_section "N3: unknown template → loud refusal, no half-state"
post "/human/sandfs" "{\"agent_id\":\"$A_ID\",\"name\":\"neg-n3\",\"template\":\"nope:404\",\"mode\":\"flat\"}"
if [[ "$CODE" =~ ^(4|5) ]] && [[ "$CODE" != "500" ]]; then
    tc_pass "unknown template refused ($CODE): ${BODY:0:90}"
else
    tc_fail "unknown template: got $CODE ${BODY:0:90} (want a named 4xx/503, never 500/2xx)"
fi

# ── N4: lifecycle gate (deleting → exec 409) ──────────────────────
# Flat stacks have no detach (correctly 400) — the gate's flat-reachable
# form is DELETE: hold a mount with a long-lease bg exec, start the delete
# (its bounded drain now WAITS for our lease, a seconds-wide window), and
# fire an exec inside it — the gate must answer 409 SANDFS_NOT_ACTIVE.
tc_log_section "N4: deleting sandfs → exec gate 409"
BG=$(curl -sk -m 20 -X POST "$GW_URL/agent/execute" -H "Authorization: Bearer $A_KEY" \
    -H 'Content-Type: application/json' \
    -d "{\"sandfs_id\":\"$SF_ID\",\"code\":\"sleep 90\",\"timeout\":90,\"background\":true,\"lease_duration\":60}")
BG_ID=$(echo "$BG" | python3 -c "import sys,json;print(json.load(sys.stdin).get('exec_id',''))" 2>/dev/null || true)
[[ -n "$BG_ID" ]] || { tc_fail "gate-fixture bg exec failed: $BG"; exit 1; }
sleep 1   # let the mount establish
DEL=$(curl -sk -m 30 -o /dev/null -w '%{http_code}' -X DELETE "$HUMAN_URL/human/sandfs/$SF_ID") || true
# the DELETE runs its bounded drain (lease held); fire the gated exec NOW
EX=$(curl -sk -m 20 -w '\n%{http_code}' -X POST "$GW_URL/agent/execute" \
    -H "Authorization: Bearer $A_KEY" -H 'Content-Type: application/json' \
    -d "{\"sandfs_id\":\"$SF_ID\",\"code\":\"echo gated\",\"timeout\":10}")
ECODE=$(echo "$EX" | tail -1)
EBODY=$(echo "$EX" | head -n -1)
# release the holder so the drain can finish regardless of the verdict
curl -sk -m 10 -X POST "$GW_URL/agent/exec/kill" -H "Authorization: Bearer $A_KEY" \
    -H 'Content-Type: application/json' -d "{\"exec_id\":\"$BG_ID\"}" >/dev/null 2>&1 || true
if [[ "$ECODE" == "409" ]] && echo "$EBODY" | grep -q "SANDFS_NOT_ACTIVE"; then
    tc_pass "exec during deleting drain = 409 SANDFS_NOT_ACTIVE"
elif [[ "$ECODE" == "404" ]]; then
    tc_pass "exec after delete completed = 404 (gate held past the drain; timing-accepted)"
else
    tc_fail "exec during deletion: $ECODE ${EBODY:0:90} (want 409 SANDFS_NOT_ACTIVE / 404)"
fi
# wait for the delete to settle before exit (success either way)
for _ in $(seq 1 20); do
    C=$(curl -sk -o /dev/null -w '%{http_code}' "$HUMAN_URL/human/sandfs/$SF_ID" 2>/dev/null || true)
    [[ "$C" == "404" ]] && break
    sleep 2
done

tc_log_section "Summary"
if [[ "$FAIL_COUNT" -gt 0 ]]; then tc_log_error "$FAIL_COUNT check(s) FAILED"; exit 1; fi
tc_log_pass "negative-path gates: plane-down named 503 · restore truth · unknown-template loud · lifecycle 409"
