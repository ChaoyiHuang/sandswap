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
# memory-identity-persistence.sh — MemoryStore identity persistence e2e.
# Verifies that a gateway restart no longer orphans agent api keys and
# sandfs volumes (gateway/identity/identity_store.go, config -identity-store):
#   1. First boot: agent + sandfs created; snapshot written to the gateway
#      state dir (VolRoot's parent by default; this test passes an explicit
#      -identity-store), mode 0600, hash-only
#      (no plaintext api key material), valid JSON.
#   2. Restart: the OLD api key still resolves; GET /agent/sandfs lists the
#      old sandfs; the volume directory and its data survived; execute passes
#      auth (fails later with a scheduling 503 — no sandlot is connected);
#      a bogus key is still 401.
#   3. flock guard: a second gateway process on the same snapshot path
#      (different ports, so only the lock can reject it) refuses to start.
#   4. Corrupt snapshot: gateway refuses to start (fail-fast) instead of
#      silently starting empty and orphaning every volume.
#   5. Deletions persist: agent deleted, restart, old key is 401 (no
#      resurrection of deleted identity).
#   6. Persistence is mandatory: an explicit empty -identity-store= refuses
#      to start instead of silently disabling the snapshot.
# Gateway + a prov-only sandlot (the storage plane — no KVM, no VMs, no
# etcd) — runs in the fast group.
# Usage: sudo bash e2e/memory-identity-persistence.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Isolated volume root: the snapshot file lands here and the whole tree is
# removed at exit, so this script never leaves identity residue in the shared
# /var/lib/sandswap/volumes for the next script's gateway to load.
VOL_ROOT="$(mktemp -d /tmp/sandswap-memident-vol-XXXX)"

source "$ROOT/e2e/common.sh"

# The identity store lives in the GATEWAY'S OWN state dir (VolRoot's parent
# by default) — this test roots its own: a sibling of its temp VOL_ROOT.
GATEWAY_STATE_DIR="$(mktemp -d /tmp/sandswap-memident-state-XXXX)"
STATE_FILE="$GATEWAY_STATE_DIR/identity-store.json"

cleanup() {
    [[ -n "${GATEWAY_PID:-}" ]] && kill "$GATEWAY_PID" 2>/dev/null || true
    [[ -n "${DUP_PID:-}" ]] && kill "$DUP_PID" 2>/dev/null || true
    [[ -n "${PROV_PID:-}" ]] && kill "$PROV_PID" 2>/dev/null || true
    rm -rf "$VOL_ROOT" "$GATEWAY_STATE_DIR"
}
trap cleanup EXIT INT TERM

# stop_gateway — TERM the gateway and wait until the stream port is actually
# RELEASED (a killed-but-listening socket would make the next start fail
# with "address already in use", indistinguishable from a real bug).
stop_gateway() {
    local pid="$1"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    wait "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
        ss -tln 2>/dev/null | grep -q "$STREAM_ADDR" || return 0
        sleep 0.1
    done
    tc_log_warn "stream port $STREAM_ADDR still bound after stop"
}

# snapshot_json — the snapshot file as parsed JSON ('.' on parse failure).
snapshot_json() {
    python3 -c "import json;print(json.dumps(json.load(open('$STATE_FILE'))))" 2>/dev/null || echo "."
}

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight & Deploy"
# ══════════════════════════════════════════════════════════════════

tc_check_root
tc_check_freshness
tc_clean_environment

# Dedicated-identity model helper: root-side phase mutations (preseed,
# deletion rewrite) re-root the store file — re-present it to the gateway
# identity before every boot (the 0600 mode assertions are unaffected by
# chown).
present_store_to_gateway() {
    chown -R "$(id -u sandserv):$(id -g sandserv)" "$GATEWAY_STATE_DIR" 2>/dev/null || true
}
present_store_to_gateway

tc_deploy_artifacts
tc_gen_certs

# The storage plane: a PROV-ONLY sandlot (no KVM duty — prov-only skips the
# vhost-vsock/caps preflight and carries no pool). SandFS creation is a named
# 503 without it: the gateway has no local storage mode; every volume op
# routes over the stream to a prov instance.
start_prov_sandlot() {
    # Seed: prov REQUIRES a seed since the
    # rotation feature — ensure + pass it.
    tc_ensure_volume_seed
    ss_service_exec sandlot -- "$DEPLOY_DIR/sandlot" \
        -gateway-addr "localhost$STREAM_ADDR" \
        -volume-seed-file "$DEPLOY_DIR/volume-seed" \
        -node-id "memident-prov" \
        -roles prov \
        -volumes-dir "$VOL_ROOT" -allow-insecure-volumes -allow-missing-vsockguard \
        -templates-dir "$VOL_ROOT/.templates" \
        -flat-templates "$DEPLOY_DIR/flat-templates" \
        -network-backend none \
        -tls-cert "$(tc_node_cert memident-prov prov).crt" \
        -tls-key "$(tc_node_cert memident-prov prov).key" \
        -tls-ca "$CERT_DIR/ca.crt" \
        > "$LOG_DIR/sandlot-prov.log" 2>&1 &
    PROV_PID=$!
    for _ in $(seq 1 40); do
        sleep 0.25
        kill -0 "$PROV_PID" 2>/dev/null || { tc_log_error "prov sandlot died: $(tail -3 "$LOG_DIR/sandlot-prov.log")"; exit 1; }
        # Connected once the gateway counts it (role routing is internal; a
        # successful templates listing proves the round trip).
        if curl -s "$HUMAN_URL/human/templates" 2>/dev/null | grep -q '"name"'; then
            return 0
        fi
    done
    tc_log_warn "prov sandlot did not register within 10s; continuing (create will surface it)"
}
# The volumes tree needs the shared-group layout the sandlot identity writes
# through (mktemp creates it 0700 root).
chown root:sandlot "$VOL_ROOT" 2>/dev/null || true
chmod 2770 "$VOL_ROOT" 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: First boot — create identity"
# ══════════════════════════════════════════════════════════════════

tc_start_gateway -identity-store "$STATE_FILE"
start_prov_sandlot
tc_create_agent_and_sandfs "identity-persist-e2e" "$TC_DEFAULT_TEMPLATE" "flat" > /dev/null

if [[ -n "${TC_API_KEY:-}" && -n "${TC_SANDFS_ID:-}" ]]; then
    tc_pass "agent + sandfs created ($TC_AGENT_ID / $TC_SANDFS_ID)"
else
    tc_fail "agent/sandfs creation failed"
    exit 1
fi

echo "precious-data" > "$TC_ROOTFS_PATH/data.txt"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Snapshot on disk"
# ══════════════════════════════════════════════════════════════════

stop_gateway "$GATEWAY_PID"

if [[ -f "$STATE_FILE" ]]; then
    tc_pass "snapshot exists at the default path"
else
    tc_fail "snapshot missing at $STATE_FILE"
    exit 1
fi

tc_assert_eq "snapshot mode is 0600" "$(stat -c %a "$STATE_FILE")" "600"
tc_assert_not_contains "no plaintext api key in snapshot" \
    "$(cat "$STATE_FILE")" "sk-sandswap-agent-"
tc_assert_contains "api key hash present in snapshot" \
    "$(snapshot_json)" "api_key_hash"
ver=$(python3 -c "import json;print(json.load(open('$STATE_FILE')).get('version'))" 2>/dev/null || echo "")
# gateway/identity/identity_store.go: IdentityStoreVersion (first released
# schema is 1; incompatible changes fold into it until a release boundary).
tc_assert_eq "snapshot version stamped" "$ver" "1"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Restart — old identity works"
# ══════════════════════════════════════════════════════════════════

present_store_to_gateway
tc_start_gateway -identity-store "$STATE_FILE"

listed=$(curl -s -H "Authorization: Bearer $TC_API_KEY" "$GATEWAY_URL/agent/sandfs")
tc_assert_contains "old key lists the old sandfs" "$listed" "$TC_SANDFS_ID"

if grep -q "precious-data" "$TC_ROOTFS_PATH/data.txt"; then
    tc_pass "volume data intact after restart"
else
    tc_fail "volume data lost after restart"
fi

# No sandlot is connected, so a request that passes auth + ownership must
# surface a SCHEDULING error (503 with an error_code), never 401/403/404.
exec_code=$(curl -s -o "$LOG_DIR/exec-resp.json" -w '%{http_code}' \
    -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $TC_API_KEY" \
    -d "{\"sandfs_id\":\"$TC_SANDFS_ID\",\"code\":\"echo hi\",\"language\":\"shell\"}")
exec_err=$(python3 -c "import json;print(json.load(open('$LOG_DIR/exec-resp.json')).get('error_code',''))" 2>/dev/null || echo "")
# The old check accepted ANY code except 401/403/404 — 200/400/500/502 (a
# broken path or a wrongly-authenticated one) also "reached the scheduler".
# The documented shape is exactly 503 + a structured error_code.
if [[ "$exec_code" == "401" || "$exec_code" == "403" || "$exec_code" == "404" ]]; then
    tc_fail "execute rejected at the auth/ownership layer (http $exec_code)"
elif [[ "$exec_code" != "503" || -z "$exec_err" ]]; then
    tc_fail "execute did not surface the documented scheduling error: http=$exec_code error_code='$exec_err' body=$(head -c 160 "$LOG_DIR/exec-resp.json")"
else
    tc_pass "execute reached the scheduler (http 503, error_code=$exec_err)"
fi

bogus_code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer sk-sandswap-agent-bogus" "$GATEWAY_URL/agent/sandfs")
tc_assert_eq "bogus key still 401" "$bogus_code" "401"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Second gateway locked out by flock"
# ══════════════════════════════════════════════════════════════════

# Different ports on purpose: if this process starts at all, the failure is
# not port contention — only the identity-store lock can explain the refusal.
set +e
"$DEPLOY_DIR/gateway" \
    -agent-addr 127.0.0.1:3205 -human-addr 127.0.0.1:3206 -stream-addr 127.0.0.1:3207 \
    -vol-root "$VOL_ROOT" \
    -identity-store "$STATE_FILE" \
    > "$LOG_DIR/gateway-dup.log" 2>&1
dup_rc=$?
set -e

if [[ $dup_rc -ne 0 ]] && grep -q "held by another gateway" "$LOG_DIR/gateway-dup.log"; then
    tc_pass "second gateway refused by the state lock (rc=$dup_rc)"
else
    tc_fail "second gateway was not locked out (rc=$dup_rc)"
    tail -3 "$LOG_DIR/gateway-dup.log" || true
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Corrupt snapshot refuses to start"
# ══════════════════════════════════════════════════════════════════

stop_gateway "$GATEWAY_PID"
cp "$STATE_FILE" "$STATE_FILE.bak"
echo "{corrupted" > "$STATE_FILE"

set +e
"$DEPLOY_DIR/gateway" \
    -agent-addr "$GATEWAY_ADDR" -human-addr "$HUMAN_ADDR" -stream-addr "$STREAM_ADDR" \
    -vol-root "$VOL_ROOT" -identity-store "$STATE_FILE" \
    > "$LOG_DIR/gateway-corrupt.log" 2>&1
corrupt_rc=$?
set -e

if [[ $corrupt_rc -ne 0 ]] && grep -qi "corrupt" "$LOG_DIR/gateway-corrupt.log"; then
    tc_pass "corrupt snapshot refused to start (rc=$corrupt_rc)"
else
    tc_fail "corrupt snapshot did not fail loudly (rc=$corrupt_rc)"
    tail -3 "$LOG_DIR/gateway-corrupt.log" || true
fi
mv "$STATE_FILE.bak" "$STATE_FILE"
# The root-side cp/echo re-rooted the store — re-present before boot 4.
present_store_to_gateway

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Deletions persist (no identity resurrection)"
# ══════════════════════════════════════════════════════════════════

tc_start_gateway -identity-store "$STATE_FILE"
curl -s -X DELETE "$HUMAN_URL/human/agent/$TC_AGENT_ID" > /dev/null
stop_gateway "$GATEWAY_PID"

tc_start_gateway -identity-store "$STATE_FILE"
res_code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TC_API_KEY" "$GATEWAY_URL/agent/sandfs")
tc_assert_eq "deleted agent's key is 401 after restart" "$res_code" "401"
stop_gateway "$GATEWAY_PID"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 7: Persistence cannot be disabled (-identity-store=)"
# ══════════════════════════════════════════════════════════════════

# An operator asking to disable persistence is asking for the identity-loss
# bug this feature fixes — the gateway must refuse, not silently comply.
set +e
"$DEPLOY_DIR/gateway" \
    -agent-addr "$GATEWAY_ADDR" -human-addr "$HUMAN_ADDR" -stream-addr "$STREAM_ADDR" \
    -vol-root "$VOL_ROOT" -identity-store= \
    > "$LOG_DIR/gateway-nopersist.log" 2>&1
nopersist_rc=$?
set -e

if [[ $nopersist_rc -ne 0 ]] && grep -q "persistence is mandatory" "$LOG_DIR/gateway-nopersist.log"; then
    tc_pass "explicit empty -identity-store refuses to start (rc=$nopersist_rc)"
else
    tc_fail "explicit empty -identity-store was accepted (rc=$nopersist_rc)"
    tail -3 "$LOG_DIR/gateway-nopersist.log" || true
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 8: node identity is BOUND to the stream certificate"
# ══════════════════════════════════════════════════════════════════

# The stream routes commands by node_id, so a node that can claim
# another node's id receives that node's commands. This is closed by
# binding the declared node_id to the client certificate CN (exact match) —
# proven here against a live gateway: the memident-prov certificate presented
# under a DIFFERENT node id must be refused with the named reason, and the
# process must keep running (it retries its next configured gateway address
# rather than crash-looping).
tc_start_gateway -identity-store "$STATE_FILE"
# The earlier phases' prov sandlot may still hold the one-instance-per-host
# role lock (its refusal would mask the identity gate we are testing here):
# stop it first, then start the imposter.
if [[ -n "${PROV_PID:-}" ]]; then
    kill "$PROV_PID" 2>/dev/null || true
    wait "$PROV_PID" 2>/dev/null || true
fi
sleep 1
# The imposter runs as the SAME identity a real node runs as (uid 985): it
# impersonates a NODE, not root, and the seed-file ownership contract (root or
# the reading identity — enforced since the seed-channel hardening) refuses a
# root process reading the battery's prov-owned seed.
ss_service_exec sandlot -- "$DEPLOY_DIR/sandlot" \
    -gateway-addr "localhost$STREAM_ADDR" \
    -volume-seed-file "$DEPLOY_DIR/volume-seed" \
    -node-id "impersonated-node" \
    -roles prov \
    -volumes-dir "$VOL_ROOT" -allow-insecure-volumes -allow-missing-vsockguard \
    -templates-dir "$VOL_ROOT/.templates" \
    -flat-templates "$DEPLOY_DIR/flat-templates" \
    -network-backend none \
    -tls-cert "$(tc_node_cert memident-prov prov).crt" \
    -tls-key "$(tc_node_cert memident-prov prov).key" \
    -tls-ca "$CERT_DIR/ca.crt" \
    > "$LOG_DIR/sandlot-impersonation.log" 2>&1 &
IMPOSTER_PID=$!
found=0
for _ in $(seq 1 40); do
    sleep 0.25
    if grep -q "does not match declared node_id" "$LOG_DIR/sandlot-impersonation.log"; then
        found=1
        break
    fi
    kill -0 "$IMPOSTER_PID" 2>/dev/null || break
done
kill "$IMPOSTER_PID" 2>/dev/null || true
wait "$IMPOSTER_PID" 2>/dev/null || true
if [[ "$found" == "1" ]]; then
    tc_pass "stream identity binding: a certificate for node memident-prov was refused under node-id impersonated-node"
else
    tc_fail "stream identity binding: no named refusal in sandlot-impersonation.log"
    tail -5 "$LOG_DIR/sandlot-impersonation.log" || true
fi
stop_gateway "$GATEWAY_PID"

# ══════════════════════════════════════════════════════════════════
log_section "Results"
# ══════════════════════════════════════════════════════════════════

echo ""
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │     Memory Identity Persistence E2E Results                 │"
echo "  ├──────────────────────────────────────────────────┤"
printf "  │ Tests: %2d passed  %2d failed                         │\n" "$PASS_COUNT" "$FAIL_COUNT"
echo "  └──────────────────────────────────────────────────┘"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "$FAIL_COUNT test(s) failed"
    log_info "Check logs: $LOG_DIR/"
    exit 1
else
    log_pass "All $PASS_COUNT tests passed"
fi
