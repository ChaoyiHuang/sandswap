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
# test-parallel-exec.sh — End-to-end: concurrent sync execs on one SandFS.
# Verifies the per-VM connection pool (spec `exec_slots`): N concurrent sync
# commands on the SAME sandfs run in PARALLEL (total wall time ≈ one command,
# not N×), and concurrent file reads are served in parallel too.
# Prerequisites (same as e2e/file-api.sh):
#   1. bash build/build.sh all         (binaries in output/)
#   2. bash build/build-rootfs-template.sh
#   3. KVM available (/dev/kvm)
#   4. Root or kvm group member
# Usage: ./e2e/parallel-exec.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POOL_SIZE="${POOL_SIZE:-2}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
# The VMs used here have a 3-slot warden connection pool (the "small"
# spec's exec_slots is 3, same as the generated config's).
N="${N:-3}"          # concurrent execs to run
CMD_SLEEP="${CMD_SLEEP:-2}" # per-command sleep (seconds)
# Sticky window wide enough that the mount established by the Phase 3 warm-up
# survives until the Phase 4 batch is launched. With the 100ms production
# default the lease lapses during the shell's batch setup, so the batch runs
# COLD — and a cold batch legitimately serializes its first command: the 1-RTT
# mount_and_exec holds the cold-mount lock for the WHOLE call (mount + the
# command), so the other N-1 requests block on it and only then run in
# parallel, giving ~2×CMD_SLEEP instead of ~CMD_SLEEP. That is correct
# behaviour, not a parallelism failure — but it is not what this test measures.
LEASE_MS="${LEASE_MS:-5000}"
source "$ROOT/e2e/common.sh"

cleanup() {
    if [[ -n "${KEY_A:-}" ]] && kill -0 "${GATEWAY_PID:-0}" 2>/dev/null; then
        tc_delete_sandfs "$ID_A"
        log_pass "Test agent deleted"
    fi
    rm -rf "${PAR_JSON_TMP:-}" 2>/dev/null || true
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

log_section "Phase 0: Pre-flight Checks"
tc_check_root
tc_preflight_standard
tc_ensure_dev_nodes

log_section "Phase 1: Deploy + start cluster"
# Bootstrap exactly like file-api.sh (whose prerequisites this test shares):
# deploy artifacts to $DEPLOY_DIR, generate the mTLS certs tc_start_gateway
# references, set up the host bridge, then bring up gateway + sandlot. Without
# these the gateway/sandlot binaries are absent from $DEPLOY_DIR, CERT_DIR is
# unbound, and no sandlot connects to fill the pool.
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network
tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready

log_section "Phase 2: Create test agent"
AGENT_RESP=$(tc_create_agent_and_sandfs "parallel-exec-test")
KEY_A=$(json_val "$AGENT_RESP" "api_key")
ID_A=$(json_val "$AGENT_RESP" "sandfs_id")
if [[ -z "$KEY_A" || "$KEY_A" == "None" ]]; then
    log_error "Failed to create agent: $AGENT_RESP"
    exit 1
fi
log_pass "Agent created: id=$ID_A"

# exec_once: one sync exec; returns the JSON response.
exec_once() { # <code>
    local code="$1"
    curl -s -X POST "$GATEWAY_URL/agent/execute" \
        --header "Authorization: Bearer $KEY_A" \
        --header "Content-Type: application/json" \
        -d "$(python3 -c "import sys,json; d={\"sandfs_id\":\"$ID_A\",\"code\":\"$code\",\"timeout\":15}; print(json.dumps(d))")"
}

log_section "Phase 3: Warm path (cold mount)"
# First call mounts the sandfs; not counted in the timing comparison.
WARM=$(exec_once "true")
assert_eq "warm exec succeeds" "$(json_val "$WARM" "status")" "done"

log_section "Phase 4: $N concurrent sync execs of 'sleep $CMD_SLEEP'"
PAR_JSON_TMP=$(mktemp -d)
pids=()
# Millisecond clock via bash's EPOCHREALTIME — this repo's CI hosts once ran
# uutils coreutils, whose `date +%s%N` emits garbage magnitudes and turned the
# parallel-bound assert into a false FAIL (same lesson as disconnect-tolerance's
# sat_now_ms).
now_ms() { local t="$EPOCHREALTIME"; echo $(( ${t/./} / 1000 )); }
start_ms=$(now_ms)
for i in $(seq 1 "$N"); do
    exec_once "sleep $CMD_SLEEP" > "$PAR_JSON_TMP/resp-$i.json" &
    pids+=("$!")
done
for p in "${pids[@]}"; do wait "$p"; done
end_ms=$(now_ms)
elapsed_ms=$(( end_ms - start_ms ))
log_pass "batch wall time: ${elapsed_ms}ms ($N × sleep ${CMD_SLEEP}s)"

# Every exec must succeed.
ok=1
for i in $(seq 1 "$N"); do
    st=$(json_val "$(cat "$PAR_JSON_TMP/resp-$i.json")" "status")
    ec=$(json_val "$(cat "$PAR_JSON_TMP/resp-$i.json")" "exit_code")
    if [[ "$st" != "done" || "$ec" != "0" ]]; then
        log_error "exec $i: status=$st exit_code=$ec resp=$(cat "$PAR_JSON_TMP/resp-$i.json")"
        ok=0
    fi
done
assert_eq "all $N execs done/exit0" "$ok" "1"

# Parallel bound: N serial sleeps of ${CMD_SLEEP}s would take >= N×${CMD_SLEEP}≤s
# (plus scheduling). We require the batch to complete in less than
# (N-1)*sleep*0.8 + sleep*1.5  — comfortably between parallel (~sleep) and serial.
serial_ns=$((N * CMD_SLEEP * 1000))
par_bound=$(( serial_ns / 2 )) # must be < half the serial sum
if (( elapsed_ms > par_bound )); then
    log_error "batch took ${elapsed_ms}ms; expected PARALLEL execs (<${par_bound}ms, serial would be ~${serial_ns}ms)"
    exit 1
fi
log_pass "parallel bound met: batch ${elapsed_ms}ms << serial ≈ ${serial_ns}ms"

log_section "Phase 5: Concurrent file reads"
# Same convention as e2e/file-api.sh's file_op: sandfs_id is REQUIRED on every
# per-sandfs endpoint, the write reply is {"ok":true,"size":N}, and a TEXT read
# comes back in "data" (only non-UTF-8 content uses "data_base64").
file_op() { # <json body>
    echo -n "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); d['sandfs_id']='$ID_A'; print(json.dumps(d))" \
      | curl -s -X POST "$GATEWAY_URL/agent/file" \
        --header "Authorization: Bearer $KEY_A" \
        --header "Content-Type: application/json" \
        -d @-
}
PAR_CONTENT="parallel-file-content"
WR=$(file_op "{\"action\":\"write\",\"path\":\"par.data\",\"data\":\"$PAR_CONTENT\"}")
assert_eq "file write succeeds" "$(json_val "$WR" "ok")" "True"

RD_TMP=$(mktemp -d)
rpids=()
for i in $(seq 1 "$N"); do
    file_op "{\"action\":\"read\",\"path\":\"par.data\"}" > "$RD_TMP/read-$i.json" &
    rpids+=("$!")
done
for p in "${rpids[@]}"; do wait "$p"; done
rok=1
for i in $(seq 1 "$N"); do
    got=$(json_val "$(cat "$RD_TMP/read-$i.json")" "data")
    if [[ "$got" != "$PAR_CONTENT" ]]; then
        log_error "parallel read $i returned wrong content: '$got'"
        rok=0
    fi
done
assert_eq "all $N parallel reads correct" "$rok" "1"
rm -rf "$RD_TMP"

log_section "Phase 6: Grayscale signals in /stats"
# /stats lives on the HUMAN listener (:3100); the agent port only serves /agent/*.
# The per-node metrics ride the sandlot HEARTBEAT (30s ticker, or immediately on
# a pool change), so they are not visible the instant the batch returns — poll
# for up to ~45s rather than reading once.
PEAK=0
for i in $(seq 1 90); do
    STATS=$(curl -s "$HUMAN_URL/stats")
    PEAK=$(echo "$STATS" | python3 -c "import sys,json; s=json.load(sys.stdin); print(max((n.get('peak_concurrent_execs',0) for g in s.get('gateways',[]) for n in g.get('nodes',[])), default=0))" 2>/dev/null || echo 0)
    (( PEAK >= 2 )) && break
    sleep 0.5
done
# The peak-concurrency metric must have observed the parallelism we just drove.
if (( PEAK < 2 )); then
    log_error "peak_concurrent_execs = $PEAK, want >= 2 (parallel execs were not observed by the metric)"
    exit 1
fi
log_pass "peak_concurrent_execs = $PEAK (>= 2)"
SLOTWAIT=$(echo "$STATS" | python3 -c "import sys,json; s=json.load(sys.stdin); print(max((n.get('slot_wait_events',0) for g in s.get('gateways',[]) for n in g.get('nodes',[])), default=0))" 2>/dev/null || echo 0)
# N concurrent execs against exec_slots=3 (the "small" spec) must NOT queue —
# a queued request would silently shrink the parallelism this test measures.
if [[ "$N" -le 3 ]]; then
    if [[ "$SLOTWAIT" -eq 0 ]]; then
        pass "slot_wait_events = 0 (N=$N <= exec_slots=3, no queuing)"
    else
        fail "slot_wait_events = $SLOTWAIT (expected 0: N=$N <= exec_slots=3)"
    fi
else
    log_info "slot_wait_events = $SLOTWAIT (N=$N > exec_slots=3 — queuing allowed)"
fi

log_pass "Done."
if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "$FAIL_COUNT test(s) failed"
    exit 1
fi
exit 0
