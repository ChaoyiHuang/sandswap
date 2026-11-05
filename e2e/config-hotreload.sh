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
# config-hotreload.sh — End-to-end test for config file hot-reload.
# Verifies that sandlot and gateway pick up config changes at runtime:
#   1. Start with config file, verify pool creates VMs
#   2. Hot-reload: scale up pool (medium:2 → small:1,medium:4)
#   3. Hot-reload: scale down pool (small:1,medium:4 → medium:2)
#   4. Hot-reload: change lease timeout in gateway (sticky_ms 100 → 500)
#   5. Verify restart-required fields (human addr) are warned and NOT applied
#   6. Scale-down while a VM is IN_USE (pendingDestroy deferred destroy)
# Every config rewrite goes through tc_gen_sandlot_config / tc_gen_gateway_config
# (the shared generators in common.sh) with the relevant variable overridden —
# the hot-reload only changes one field, so only that variable changes.
# Usage: sudo bash e2e/config-hotreload.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

cleanup() {
    kill ${SYNC_EXEC_PID:-} 2>/dev/null || true
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

# stats_total_vms — TOTAL VM count from GET /stats (totals.total_vms; legacy
# shapes fall back to summing the pool map). Empty output = UNKNOWN SHAPE —
# the old last-resort fallback summed EVERY int in the payload (unmount
# counters included), so a shape drift silently produced garbage numbers the
# gates happily compared. Poll loops treat empty as "not yet"; final gates
# fail with the empty value visible.
stats_total_vms() {
    curl -s -m 5 "$HUMAN_URL/stats" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
t=d.get('totals',{}).get('total_vms')
if t is None:
    t=d.get('total_vms')
if t is None and isinstance(d.get('pool'),dict):
    t=sum(d['pool'].values())
if t is None:
    sys.exit(3)
print(t)" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight Checks"
# ══════════════════════════════════════════════════════════════════

tc_check_root
tc_preflight_standard
tc_ensure_dev_nodes

if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — microVMs will be offline"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Deploy & Generate Config Files"
# ══════════════════════════════════════════════════════════════════

tc_clean_environment
tc_deploy_artifacts
tc_gen_certs

# Config file paths
SANDLOT_CONFIG="$LOG_DIR/sandlot.yaml"
GATEWAY_CONFIG="$LOG_DIR/gateway.yaml"

# Generate initial config files (pool override drives the generated pool spec)
SANDLOT_POOL="medium:2"
tc_gen_sandlot_config "$SANDLOT_CONFIG"
tc_gen_gateway_config "$GATEWAY_CONFIG"

# Set config mode for tc_start_gateway / tc_start_sandlot
TC_GATEWAY_CONFIG="$GATEWAY_CONFIG"
TC_SANDLOT_CONFIG="$SANDLOT_CONFIG"

log_info "Sandlot config: $SANDLOT_CONFIG"
log_info "Gateway config: $GATEWAY_CONFIG"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Start Gateway & Sandlot (config-file mode)"
# ══════════════════════════════════════════════════════════════════

tc_start_gateway
tc_attach_vsockguard
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready 2

log_info "Verifying initial pool (2 medium VMs)..."
INITIAL_CLEAN=$(tc_stats_clean_vms)
INITIAL_CLEAN="${INITIAL_CLEAN//[[:space:]]/}"

if [[ "$INITIAL_CLEAN" -ge 2 ]] 2>/dev/null; then
    pass "Initial pool has $INITIAL_CLEAN CLEAN VM(s) (≥ 2, target: 2)"
else
    fail "Initial pool too small: $INITIAL_CLEAN CLEAN VM(s) (target: 2)"
fi

# Verify config hot-reload watchers started
if grep -q "config hot-reload watcher started" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "Sandlot hot-reload watcher started"
else
    fail "Sandlot hot-reload watcher NOT started"
fi

if grep -q "config hot-reload watcher started" "$LOG_DIR/gateway.log" 2>/dev/null; then
    pass "Gateway hot-reload watcher started"
else
    fail "Gateway hot-reload watcher NOT started"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Create Agent & Verify Execution"
# ══════════════════════════════════════════════════════════════════

AGENT_A=$(tc_create_agent_and_sandfs "hotreload-test")
KEY_A=$(echo "$AGENT_A" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('api_key',''))" 2>/dev/null || echo "")
SANDFS_ID_A=$(echo "$AGENT_A" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sandfs_id',''))" 2>/dev/null || echo "")

if [[ -z "$KEY_A" ]]; then
    fail "Failed to create test agent"
    exit 1
fi
pass "Test agent created"

# Simple execution to verify the system works
EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $KEY_A" \
    -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$SANDFS_ID_A\",\"code\":\"echo hello-hotreload\",\"language\":\"shell\"}" 2>&1 || echo '{"error":"curl failed"}')
EXEC_STDOUT=$(echo "$EXEC_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo "")

if echo "$EXEC_STDOUT" | grep -q "hello-hotreload"; then
    pass "Basic execution works: $EXEC_STDOUT"
else
    fail "Basic execution failed: $EXEC_RESP"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Hot-Reload Pool Scale-Up (medium:2 → small:1,medium:4)"
# ══════════════════════════════════════════════════════════════════

log_step "Editing sandlot config: pool = small:1,medium:4..."
SANDLOT_POOL="small:1,medium:4"
tc_gen_sandlot_config "$SANDLOT_CONFIG"

log_info "Waiting for hot-reload to create new VMs (target: small:1 + medium:4 = 5 total)..."

# Wait for pool to grow (fsnotify debounce + VM boot time). Budget 120s:
# common.sh gives the INITIAL 2-VM pool 150s because a hung first batch
# self-heals via destroy+replace — 3 fresh boots deserve at least that.
SCALEUP_OK=0
TOTAL=0
for i in $(seq 1 120); do
    sleep 1
    TOTAL=$(stats_total_vms)
    TOTAL="${TOTAL//[[:space:]]/}"
    log_info "  poll #$i: clean=$(tc_stats_clean_vms) total=$TOTAL"
    if [[ "$TOTAL" -ge 5 ]] 2>/dev/null; then
        SCALEUP_OK=1
        break
    fi
done

if [[ "$SCALEUP_OK" -eq 1 ]]; then
    pass "Pool scaled up: $TOTAL total VM(s) (target: 5)"
else
    fail "Pool did not scale up within 120s (total=$TOTAL, target: 5)"
    log_info "Sandlot log tail:"
    tail -30 "$LOG_DIR/sandlot.log"
fi

# Verify ResizePool was logged
if grep -q "ResizePool" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "ResizePool logged in sandlot"
else
    fail "ResizePool NOT logged in sandlot"
fi

# Verify the small-spec scale-up was logged (ResizePool logs the spec name:
# "ResizePool: scaling up small: 0 → 1 ..." — sandlot/core/pool.go).
if grep -q "ResizePool: scaling up small" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "Small spec scale-up logged in sandlot"
else
    fail "Small spec scale-up NOT logged in sandlot (ResizePool never scaled the small spec)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Hot-Reload Pool Scale-Down (small:1,medium:4 → medium:2)"
# ══════════════════════════════════════════════════════════════════

log_step "Editing sandlot config: pool = medium:2..."
SANDLOT_POOL="medium:2"
tc_gen_sandlot_config "$SANDLOT_CONFIG"

log_info "Waiting for hot-reload to destroy excess VMs (target: medium:2 = 2 total)..."

# Wait for pool to shrink toward medium:2 (destroy takes a few seconds per
# VM, plus gateway reconciliation via heartbeat). The gate must be a REAL
# shrink: the pre-change total is 5 (scale-up target), so "decreased" means
# ≤ 3 — the old `< 7` was satisfied by the untouched 5-VM pool, making a
# hot-reload that did nothing pass in ~4s.
SCALEDOWN_OK=0
PREV_TOTAL=999
STABLE_COUNT=0
TOTAL=0
for i in $(seq 1 60); do
    sleep 1
    TOTAL=$(stats_total_vms)
    TOTAL="${TOTAL//[[:space:]]/}"
    log_info "  poll #$i: total=$TOTAL"
    # Success: pool shrunk to ≤3 (was ≥5) AND stable for 3 consecutive polls
    if [[ "$TOTAL" -le 3 ]] 2>/dev/null; then
        if [[ "$TOTAL" -eq "$PREV_TOTAL" ]]; then
            STABLE_COUNT=$((STABLE_COUNT + 1))
        else
            STABLE_COUNT=0
        fi
        if [[ "$STABLE_COUNT" -ge 3 ]]; then
            SCALEDOWN_OK=1
            break
        fi
    fi
    PREV_TOTAL="$TOTAL"
done

if [[ "$SCALEDOWN_OK" -eq 1 ]]; then
    pass "Pool scaled down and stabilized: $TOTAL total VM(s)"
else
    fail "Pool did not scale down within 60s (total=$TOTAL, target: 2)"
    log_info "Sandlot log tail:"
    tail -30 "$LOG_DIR/sandlot.log"
fi

# Verify the scale-down was logged ("ResizePool: scaling down ..." — pool.go).
if grep -q "ResizePool: scaling down" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "Scale-down logged in sandlot"
else
    fail "Scale-down NOT logged in sandlot (ResizePool never removed excess VMs)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Verify Execution Still Works After Resize"
# ══════════════════════════════════════════════════════════════════

# Wait for gateway to reconcile pool state after scale-down.
# The gateway's ReconcileNode runs on heartbeat, so we need to wait
# for the next heartbeat cycle plus pool cleanup.
log_info "Waiting for gateway to reconcile pool state..."
sleep 5

# Retry execution a few times (pool may still be settling)
EXEC_OK=0
for attempt in $(seq 1 5); do
    EXEC_RESP2=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" \
        -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$SANDFS_ID_A\",\"code\":\"echo post-resize\",\"language\":\"shell\"}" 2>&1 || echo '{"error":"curl failed"}')
    EXEC_STDOUT2=$(echo "$EXEC_RESP2" | python3 -c "import sys,json;print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo "")

    if echo "$EXEC_STDOUT2" | grep -q "post-resize"; then
        EXEC_OK=1
        break
    fi
    log_info "  attempt #$attempt: not ready yet, retrying in 2s..."
    sleep 2
done

if [[ "$EXEC_OK" -eq 1 ]]; then
    pass "Execution works after pool resize: $EXEC_STDOUT2"
else
    fail "Execution failed after pool resize: $EXEC_RESP2"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 7: Hot-Reload Gateway Lease Timeout"
# ══════════════════════════════════════════════════════════════════

log_step "Editing gateway config: lease sticky_ms = 500..."
LEASE_MS=500
tc_gen_gateway_config "$GATEWAY_CONFIG"

# Wait for hot-reload to pick up the change, then require the evidence.
# NB: grep for the APPLIED FIELD — the bare "config hot-reload" string also
# appears in the STARTUP line "config hot-reload watcher started" (asserted
# in Phase 2), which passes even if no reload ever fired.
sleep 2
if grep -q "lease.sticky_ms" "$LOG_DIR/gateway.log" 2>/dev/null; then
    pass "Gateway hot-reload applied lease.sticky_ms (logged)"
else
    fail "Gateway hot-reload of lease.sticky_ms NOT logged (watcher saw no change)"
fi

# Verify the lease change BEHAVIORALLY — and make the test actually able to
# distinguish 500ms from the old 100ms: an immediate back-to-back call hits
# the lease under BOTH configs (vacuous); the discriminator is a ~350ms gap,
# which lands inside the hot-reloaded 500ms window but outside the old 100ms.
log_step "Verifying lease timeout behavior (500ms — gap discrimination)..."

# Warm the lease.
curl -s -o /dev/null -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$SANDFS_ID_A\",\"code\":\"echo warm-test\",\"language\":\"shell\"}" 2>&1 || true

# Immediate second call must hit under ANY sticky config (sanity that the
# lease mechanism works at all).
RESP_WARM2=$(curl -s -D- -o /dev/null -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$SANDFS_ID_A\",\"code\":\"echo warm-test2\",\"language\":\"shell\"}" 2>&1 || echo "")

LEASE_HITS=$(echo "$RESP_WARM2" | grep -c "X-Sandbox-Lease: hit" || true)
if [[ "$LEASE_HITS" -gt 0 ]]; then
    pass "Sticky lease works on a back-to-back call (lease hit detected)"
else
    fail "No lease hit header on a back-to-back call (sticky lease broken?)"
fi

# 350ms-gap calls: ≥2 of 3 must hit. With 100ms these would all miss (that's
# how this proves the reload took effect); with 500ms they hit. Sampling 3x
# absorbs scheduler jitter around the gap boundary.
GAP_HITS=0
for i in 1 2 3; do
    curl -s -o /dev/null -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$SANDFS_ID_A\",\"code\":\"echo gap-warm-$i\",\"language\":\"shell\"}" 2>/dev/null || true
    sleep 0.35
    HDR=$(curl -s -D- -o /dev/null -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$SANDFS_ID_A\",\"code\":\"echo gap-test-$i\",\"language\":\"shell\"}" 2>/dev/null || echo "")
    echo "$HDR" | grep -q "X-Sandbox-Lease: hit" && GAP_HITS=$((GAP_HITS + 1))
done
if [[ "$GAP_HITS" -ge 2 ]]; then
    pass "350ms gap still within the sticky window ($GAP_HITS/3 hit) — 500ms reload IS in effect (old 100ms would have missed)"
else
    fail "350ms gap missed the sticky window ($GAP_HITS/3 hit) — reload to 500ms NOT in effect (old 100ms behavior?)"
fi

# Now change back to original and verify restart-required warning for addr change
log_step "Editing gateway config with restart-required field (human addr change)..."
HUMAN_ADDR_SAVE="$HUMAN_ADDR"
LEASE_MS=100
HUMAN_ADDR=":3101"
tc_gen_gateway_config "$GATEWAY_CONFIG"
HUMAN_ADDR="$HUMAN_ADDR_SAVE"

sleep 2

# Verify gateway logged the restart-required warning
# ("config change requires restart" — gateway/config/reload.go).
if grep -q "config change requires restart" "$LOG_DIR/gateway.log" 2>/dev/null; then
    pass "Gateway logged restart-required warning for addr change"
else
    fail "Restart-required warning NOT logged for the human-addr change"
fi

# Verify the human addr did NOT actually change (restart required). Poll for a
# few seconds: if :3101 EVER comes up, the restart-required field was wrongly
# applied; 5s of confirmed absence is the pass condition.
ADDR_APPLIED=0
for i in $(seq 1 10); do
    if ss -tln 2>/dev/null | grep -q ":3101 "; then
        ADDR_APPLIED=1
        break
    fi
    sleep 0.5
done
if [[ "$ADDR_APPLIED" -eq 1 ]]; then
    fail "Human addr changed without restart (should be restart-required!)"
else
    pass "Human addr unchanged (restart-required field correctly NOT applied)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 8: Scale-Down While VM is IN_USE (pendingDestroy)"
# ══════════════════════════════════════════════════════════════════

# Strategy: scale up to medium:2, start a long-running sync exec
# to keep one VM IN_USE, then remove the "medium" spec from the pool
# entirely (scale to no pool). This forces ResizePool to destroy ALL
# medium VMs: the 1 idle VM is destroyed immediately, and the 1 busy
# VM is marked as pendingDestroy (to be destroyed on next unmount).
# When the sync exec completes, the VM is unmounted and the
# pendingDestroy flag triggers the deferred destroy.

# First, scale up to medium:2.
log_step "Scaling up to medium:2 for pending-destroy test..."
SANDLOT_POOL="medium:2"
tc_gen_sandlot_config "$SANDLOT_CONFIG"

# Wait for pool to reach 2
PENDING_SCALE_OK=0
TOTAL=0
for i in $(seq 1 90); do
    sleep 1
    TOTAL=$(stats_total_vms)
    TOTAL="${TOTAL//[[:space:]]/}"
    if [[ "$TOTAL" -ge 2 ]] 2>/dev/null; then
        PENDING_SCALE_OK=1
        break
    fi
done

SYNC_EXEC_PID=""
IN_USE_OK=0
if [[ "$PENDING_SCALE_OK" -eq 1 ]]; then
    pass "Pool scaled to $TOTAL medium VMs for pending-destroy test"

    # Start a long-running SYNC exec in the background to keep ONE VM IN_USE.
    # Using sync exec because it holds the VM IN_USE via execMu for the entire
    # duration of the command. This prevents ResizePool's destroyIdleVMs from
    # treating the VM as idle (it will be blocked on execMu until the exec
    # completes, at which point the VM will have Volumes set).
    log_step "Starting sync exec (sleep 30) in background to hold a VM IN_USE..."
    # `exec` replaces the subshell with curl, so $! IS the curl pid — the old
    # subshell wrapper made the trap's kill kill the wrapper and orphan the
    # curl for up to 30s.
    ( exec curl -s -m 70 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" \
        -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$SANDFS_ID_A\",\"code\":\"sleep 30\",\"language\":\"shell\",\"timeout\":60}" > "$LOG_DIR/sync-exec-result.json" 2>&1 ) &
    SYNC_EXEC_PID=$!
    log_info "Sync exec running in background (PID=$SYNC_EXEC_PID)"

    # Verify the VM actually went IN_USE (bounded poll on /stats — a fixed
    # sleep can't distinguish "mounted" from "mount still in flight").
    IN_USE_OK=0
    for i in $(seq 1 20); do
        IN_USE=$(curl -s -m 5 "$HUMAN_URL/stats" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('totals',{}).get('in_use_vms',0))" 2>/dev/null || echo "")
        if [[ "${IN_USE:-0}" -ge 1 ]] 2>/dev/null; then
            IN_USE_OK=1
            break
        fi
        sleep 0.5
    done
    if [[ "$IN_USE_OK" -eq 1 ]]; then
        pass "Sync exec holds a VM IN_USE (in_use_vms=$IN_USE)"
    else
        # Fail, not warn: without a genuinely IN_USE VM the pending-destroy
        # path below is never exercised, and the phase would silently
        # degrade to an idle scale-down test that cannot catch the regression.
        fail "No VM went IN_USE within 10s (in_use_vms='$IN_USE') — pending-destroy path NOT exercised"
    fi
else
    fail "Pool did not reach 2 VMs (got $TOTAL), skipping pending-destroy test"
    log_warn "Skipping pending-destroy sub-tests (pool too small)"
fi

if [[ "$PENDING_SCALE_OK" -eq 1 && "$IN_USE_OK" -eq 1 ]]; then
    # Now remove the medium spec from the pool entirely.
    # With 2 medium VMs (1 busy + 1 idle) and target 0:
    # - destroy the 1 idle VM immediately
    # - mark the 1 busy VM as pendingDestroy
    # When the sync exec finishes, the unmount will trigger the deferred destroy.
    log_step "Removing medium spec from pool while VM is IN_USE (pendingDestroy)..."
    SANDLOT_POOL=""
    tc_gen_sandlot_config "$SANDLOT_CONFIG"
fi

# Wait for the pool to eventually shrink after the deferred destroy.
# Skipped when the setup above didn't complete — otherwise TOTAL is already
# below 3 and this would "pass" without the pending-destroy path ever running.
PENDING_SHRINK_OK=0
if [[ "$PENDING_SCALE_OK" -eq 1 && "$IN_USE_OK" -eq 1 ]]; then
    log_step "Waiting for deferred destroy to trigger after sync exec completes..."
    PREV_TOTAL=999
    STABLE_COUNT=0
    TOTAL=0
    for i in $(seq 1 90); do
        sleep 1
        TOTAL=$(stats_total_vms)
        TOTAL="${TOTAL//[[:space:]]/}"
        # Success: pool drained to the configured target (pool="" → 0) AND is
        # stable for 3 consecutive polls. The old `< 3` was satisfied by the
        # UNTOUCHED 2-VM pool — a sandlot that destroyed nothing passed here.
        if [[ "$TOTAL" -eq 0 ]] 2>/dev/null; then
            if [[ "$TOTAL" -eq "$PREV_TOTAL" ]]; then
                STABLE_COUNT=$((STABLE_COUNT + 1))
            else
                STABLE_COUNT=0
            fi
            if [[ "$STABLE_COUNT" -ge 3 ]]; then
                PENDING_SHRINK_OK=1
                break
            fi
        fi
        PREV_TOTAL="$TOTAL"
    done

    if [[ "$PENDING_SHRINK_OK" -eq 1 ]]; then
        pass "Pool drained after pending-destroy: $TOTAL total VM(s) (target: 0)"
        # The /stats total only reflects sandlot's bookkeeping — the regression
        # (embeddedManager.DestroyVM re-looking-up a deleted map entry) shrank the
        # count while LEAKING the sandvmm process. With BOTH VMs destroyed the
        # honest process count is 0: 1 leaked process = destroy-kill regression.
        # Scope: this run's VMs via its own state records (tc_run_vm_pids) — a
        # host-wide pgrep also counts foreign/leaked sandvmm and misattributes
        # them. Bounded poll: destroy() drops bookkeeping before the process
        # fully exits, so a one-shot count can catch our own VM mid-teardown
        # and false-fail.
        vms_drained() { (( $(tc_run_vm_pids | wc -l) == 0 )); }
        if tc_wait_until 20 vms_drained; then
            pass "pending-destroy killed the sandvmm PROCESSes (0 running)"
        else
            fail "pending-destroy left $(tc_run_vm_pids | wc -l) sandvmm process(es) running (target 0) — destroy-kill regression"
        fi
    else
        fail "Pool did not drain after pending-destroy within 90s (total=$TOTAL, target: 0)"
        log_info "Sandlot log tail:"
        tail -30 "$LOG_DIR/sandlot.log"
    fi

    # Verify deferred destroy was logged
    if grep -q "pending-destroy\|destroyAndReplaceVM" "$LOG_DIR/sandlot.log" 2>/dev/null; then
        pass "Deferred destroy was logged in sandlot"
    else
        fail "Deferred destroy NOT logged (pending-destroy path never executed)"
    fi
fi

# Restore the pool to medium:2 so subsequent execution tests can work.
# (The pool was set to "" to test pendingDestroy; we need VMs back.)
log_step "Restoring pool to medium:2 for post-destroy execution test..."
SANDLOT_POOL="medium:2"
tc_gen_sandlot_config "$SANDLOT_CONFIG"

# Check if gateway/sandlot are still alive (the pending-destroy + pool="" path
# may have killed them if all VMs were destroyed during the 90s poll). Restart
# if needed so the post-destroy execution test can succeed.
if ! kill -0 "${GATEWAY_PID:-}" 2>/dev/null || ! kill -0 "${SANDLOT_PID:-}" 2>/dev/null; then
    log_warn "Gateway or sandlot died during pending-destroy test — restarting..."
    # Restart both to ensure a clean state
    kill "${GATEWAY_PID:-}" 2>/dev/null || true
    kill "${SANDLOT_PID:-}" 2>/dev/null || true
    wait "${GATEWAY_PID:-}" 2>/dev/null || true
    wait "${SANDLOT_PID:-}" 2>/dev/null || true
    tc_kill_sandswap_procs "pre-restart"

    # Re-read the latest config (which has pool: medium:2) and start fresh
    tc_start_gateway
    tc_start_sandlot
    tc_wait_health
    tc_wait_pool_ready 2
fi

# Verify execution still works after pending-destroy
PENDING_EXEC_OK=0
for attempt in $(seq 1 5); do
    PENDING_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" \
        -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$SANDFS_ID_A\",\"code\":\"echo post-pending-destroy\",\"language\":\"shell\"}" 2>&1 || echo '{"error":"curl failed"}')
    PENDING_OUT=$(echo "$PENDING_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo "")

    if echo "$PENDING_OUT" | grep -q "post-pending-destroy"; then
        PENDING_EXEC_OK=1
        break
    fi
    sleep 2
done

if [[ "$PENDING_EXEC_OK" -eq 1 ]]; then
    pass "Execution works after pending-destroy: $PENDING_OUT"
else
    fail "Execution failed after pending-destroy: $PENDING_RESP"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 9: Recycle by max_uses (hot-reloaded, real destroy+replace)"
# ══════════════════════════════════════════════════════════════════

# No benchmark or prior e2e ever drives a REAL use-count recycle (they all
# keep max_uses far above the sample count). This phase hot-reloads
# max_uses down to 1 on a 1-VM pool: agent A execs (VM useCount ≥ 1), agent
# B's exec steals the same VM — the switch unmount must recycle it
# (destroy+replace) instead of returning it to CLEAN. Observed via the
# /stats recycle_triggers counter (wired end-to-end) and the
# pool returning to target.

# Shrink to a single VM so agent B's mount MUST steal A's VM (no clean spare).
log_step "Scaling pool to medium:1 for a deterministic recycle..."
SANDLOT_POOL="medium:1"
tc_gen_sandlot_config "$SANDLOT_CONFIG"

RECYCLE_SCALE_OK=0
TOTAL=0
for i in $(seq 1 60); do
    sleep 1
    TOTAL=$(stats_total_vms)
    TOTAL="${TOTAL//[[:space:]]/}"
    if [[ "$TOTAL" -eq 1 ]] 2>/dev/null; then
        RECYCLE_SCALE_OK=1
        break
    fi
done
if [[ "$RECYCLE_SCALE_OK" -eq 1 ]]; then
    pass "Pool scaled to exactly 1 VM for the recycle test"
else
    fail "Pool did not scale to 1 VM (total=$TOTAL) — recycle test setup failed"
fi

RECYCLE_TRIGGERS_BEFORE=$(curl -s -m 5 "$HUMAN_URL/stats" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
ns=(d.get('gateways') or [{}])[0].get('nodes') or []
print(ns[0].get('recycle_triggers',0) if ns else 0)" 2>/dev/null || echo 0)

if [[ "$RECYCLE_SCALE_OK" -eq 1 ]]; then
    log_step "Hot-reloading max_uses: 50 → 1, then driving A→B switch..."
    TC_MAX_USES=1
    tc_gen_sandlot_config "$SANDLOT_CONFIG"
    sleep 2
    if grep -q '"maxUses":1,' "$LOG_DIR/sandlot.log" 2>/dev/null; then
        pass "max_uses=1 hot-reload applied (logged)"
    else
        fail "max_uses=1 hot-reload NOT applied (no recycle config log line)"
    fi

    # A execs: the VM's useCount becomes ≥ 1 (≥ max_uses).
    EXEC_A=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$SANDFS_ID_A\",\"code\":\"echo recycle-a\",\"language\":\"shell\"}" 2>&1 || echo '{"error":"curl failed"}')
    echo "$EXEC_A" | grep -q "recycle-a" \
        && pass "agent A exec ok (VM useCount now ≥ max_uses)" \
        || fail "agent A exec failed before recycle: $EXEC_A"

    # B execs: no clean spare → steals A's VM; the switch unmount must recycle.
    AGENT_B=$(tc_create_agent_and_sandfs "recycle-test")
    KEY_B=$(echo "$AGENT_B" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
    SANDFS_ID_B=$(echo "$AGENT_B" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")
    if [[ -z "$KEY_B" ]]; then
        fail "Failed to create agent B for the recycle test"
    else
        # B's exec may land INSIDE the recycle window (old VM destroyed,
        # replacement still booting → retryable NO_AVAILABLE_SANDBOX). Retry
        # across it: the assertion is that B is ultimately served (by the
        # replacement), which is exactly the service-continuity property a
        # recycle must preserve.
        EXEC_B=""
        for try in $(seq 1 15); do
            EXEC_B=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/execute" \
                -H "Authorization: Bearer $KEY_B" -H "Content-Type: application/json" \
                -d "{\"sandfs_id\":\"$SANDFS_ID_B\",\"code\":\"echo recycle-b\",\"language\":\"shell\"}" 2>&1 || echo '{"error":"curl failed"}')
            echo "$EXEC_B" | grep -qE '"(NO_AVAILABLE_SANDBOX|NO_COMPUTE_NODES|CONCURRENT_MOUNT|SANDBOX_CLEANING)"' || break
            sleep 2
        done
        echo "$EXEC_B" | grep -q "recycle-b" \
            && pass "agent B exec ok (recycled VM's replacement serves it)" \
            || fail "agent B exec failed across the recycle: $EXEC_B"
    fi

    # The recycle must show in /stats recycle_triggers and the pool must
    # return to target (destroy+replace, not shrink).
    RECYCLE_SEEN=0
    TOTAL=0
    for i in $(seq 1 40); do
        sleep 1.5
        CUR=$(curl -s -m 5 "$HUMAN_URL/stats" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
ns=(d.get('gateways') or [{}])[0].get('nodes') or []
t=ns[0].get('recycle_triggers',0) if ns else 0
tv=d.get('totals',{}).get('total_vms',0)
print(t, tv)" 2>/dev/null || echo "")
        RT=$(echo "$CUR" | awk '{print $1}')
        TOTAL=$(echo "$CUR" | awk '{print $2}')
        if [[ "${RT:-0}" -gt "${RECYCLE_TRIGGERS_BEFORE:-0}" ]] 2>/dev/null; then
            RECYCLE_SEEN=1
            [[ "$TOTAL" -eq 1 ]] 2>/dev/null && break
        fi
    done
    if [[ "$RECYCLE_SEEN" -eq 1 ]]; then
        pass "recycle_triggers advanced ($RECYCLE_TRIGGERS_BEFORE → $RT) — use-count recycle fired"
    else
        fail "recycle_triggers never advanced after a useCount≥max_uses unmount (max-uses recycle broken)"
    fi
    if [[ "$TOTAL" -eq 1 ]] 2>/dev/null; then
        pass "pool back at target after recycle (total=1, replacement created)"
    else
        fail "pool did not return to 1 VM after recycle (total=$TOTAL)"
    fi
    if grep -q "recycle policy" "$LOG_DIR/sandlot.log" 2>/dev/null; then
        pass "sandlot logged the recycle-policy destroy"
    else
        fail "no 'recycle policy' log line — destroy happened for another reason?"
    fi
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 9b: Invalid max_uses rejected, -1 (unlimited) accepted"
# ══════════════════════════════════════════════════════════════════

# -2 must be REFUSED at reload ingestion (same rule as startup) with the
# previous config kept; -1 is the unlimited sentinel and must apply.
log_step "Hot-reloading max_uses: -2 (invalid — must be rejected)..."
TC_MAX_USES=-2
tc_gen_sandlot_config "$SANDLOT_CONFIG"
sleep 2
if grep -q "invalid values; keeping previous config" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "invalid max_uses=-2 rejected at reload ingestion (logged)"
else
    fail "max_uses=-2 was NOT rejected (no invalid-config log line) — validation gap"
fi

log_step "Hot-reloading max_uses: -1 (unlimited sentinel — must apply)..."
TC_MAX_USES=-1
tc_gen_sandlot_config "$SANDLOT_CONFIG"
sleep 2
if grep -q '"maxUses":-1,' "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "max_uses=-1 (unlimited) hot-reload applied"
else
    fail "max_uses=-1 hot-reload NOT applied (unlimited sentinel broken)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 9c: min-idle floor is part of the standing pool"
# ══════════════════════════════════════════════════════════════════

# The floor expands BOTH scale directions: target 2 at frac 0.5 → effective 3
# (2 + floor(1.0)=1... exactly max(1, floor(2*0.5))=1 → 3). Then scale DOWN to
# target 1 → effective 2 (1 + max(1, floor(0.5))=1). The pool must settle at 2
# and the 60s reconcile must NOT churn it back up (the old raw-target
# scale-down destroyed to 1 and reconcile re-created to 3 — one wasted
# destroy+boot cycle per scale-down).
log_step "Enabling floor 0.5 with pool medium:2 (effective target 3)..."
TC_MIN_IDLE_FLOOR=0.5
SANDLOT_POOL="medium:2"
tc_gen_sandlot_config "$SANDLOT_CONFIG"

FLOOR_UP_OK=0
TOTAL=0
for i in $(seq 1 90); do
    sleep 1
    TOTAL=$(stats_total_vms)
    TOTAL="${TOTAL//[[:space:]]/}"
    if [[ "$TOTAL" -ge 3 ]] 2>/dev/null; then
        FLOOR_UP_OK=1
        break
    fi
done
if [[ "$FLOOR_UP_OK" -eq 1 ]]; then
    pass "floor-expanded scale-up reached $TOTAL VMs (target 2 + floor 1)"
else
    fail "pool never reached the floor-expanded target 3 (total=$TOTAL)"
fi

log_step "Scaling down to medium:1 (effective target 2 — floor kept)..."
SANDLOT_POOL="medium:1"
tc_gen_sandlot_config "$SANDLOT_CONFIG"

FLOOR_DOWN_OK=0
TOTAL=0
for i in $(seq 1 60); do
    sleep 1
    TOTAL=$(stats_total_vms)
    TOTAL="${TOTAL//[[:space:]]/}"
    if [[ "$TOTAL" -eq 2 ]] 2>/dev/null; then
        FLOOR_DOWN_OK=1
        break
    fi
done
if [[ "$FLOOR_DOWN_OK" -eq 1 ]]; then
    pass "floor-aware scale-down settled at exactly 2 VMs (target 1 + floor 1, NOT raw 1)"
else
    fail "scale-down with floor did not settle at 2 (total=$TOTAL — raw-target math or over-shrink?)"
fi

# Reconcile regression anchor: a full 60s self-heal tick must leave the pool
# untouched at 2 (the old churn destroyed to 1, then reconcile rebuilt to 3).
log_step "Waiting 70s (one reconcile tick) to assert no floor churn..."
sleep 70
TOTAL=$(stats_total_vms)
TOTAL="${TOTAL//[[:space:]]/}"
if [[ "$TOTAL" -eq 2 ]] 2>/dev/null; then
    pass "pool stable at 2 after a reconcile tick (floor is standing, no churn)"
else
    fail "pool drifted after reconcile (total=$TOTAL, want 2) — scale-down/reconcile floor churn"
fi

# Reset the floor for a clean end state.
TC_MIN_IDLE_FLOOR=0
SANDLOT_POOL="medium:2"
tc_gen_sandlot_config "$SANDLOT_CONFIG"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 9d: warden cmdline fields are restart-gated (debug NOT hot-loadable)"
# ══════════════════════════════════════════════════════════════════

# microvm.warden_log / warden_max_exec_timeout_sec are restart-REQUIRED by
# design: warden debug lines drain the guest console (hvc0 now; historically
# the serial UART) on the measured path, and an online flip would enable them
# across every new VM at fleet scale. The edit must therefore produce a
# restart-required warning and reach NO VM — not even one created after it.
log_step "Editing microvm.warden_log=debug + warden_max_exec_timeout_sec=299 (must NOT hot-apply)..."
TC_WARDEN_MAX_EXEC=299
TC_WARDEN_LOG=debug
tc_gen_sandlot_config "$SANDLOT_CONFIG"
sleep 2
if grep -q '"field":"microvm.warden_log"' "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "warden_log edit logged as restart-required (debug stays restart-gated)"
else
    fail "no restart-required warning for microvm.warden_log (classification regressed?)"
fi
if grep -q '"field":"microvm.warden_max_exec_timeout_sec"' "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "warden_max_exec_timeout_sec edit logged as restart-required"
else
    fail "no restart-required warning for microvm.warden_max_exec_timeout_sec"
fi

# A VM created after the edit must still carry NEITHER value: scale the pool
# up by one and inspect the persisted kernel cmdline of every state.json.
log_step "Scaling pool to medium:3 and asserting no VM cmdline carries the edited warden values..."
SANDLOT_POOL="medium:3"
tc_gen_sandlot_config "$SANDLOT_CONFIG"

SCALE3_OK=0
for i in $(seq 1 90); do
    sleep 1
    TOTAL=$(stats_total_vms)
    TOTAL="${TOTAL//[[:space:]]/}"
    [[ "$TOTAL" -eq 3 ]] 2>/dev/null && { SCALE3_OK=1; break; }
done
if [[ "$SCALE3_OK" -ne 1 ]]; then
    fail "pool never reached 3 VMs for the warden-cmdline assertion (total=$TOTAL)"
elif grep -q 'cmdline=\[[^]]*warden\.log=debug' "$LOG_DIR/sandlot.log" 2>/dev/null; then
    fail "warden.log=debug REACHED a VM kernel cmdline (debug logging hot-applied — restart gate broken)"
else
    pass "no VM cmdline carries warden.log=debug (restart gate held for warden_log)"
fi
if grep -q 'cmdline=\[[^]]*warden\.max_exec_timeout=299' "$LOG_DIR/sandlot.log" 2>/dev/null; then
    fail "warden.max_exec_timeout=299 REACHED a VM kernel cmdline (restart gate broken)"
else
    pass "no VM cmdline carries the edited warden.max_exec_timeout"
fi
# POSITIVE CONTROL: the pattern must be matchable at all. The warden cmdline is
# assembled by the launcher into the vm.create body and printed on the
# "launching VMM … cmdline=[…]" line — it is NEVER persisted into state.json, so
# the previous state.json grep could not match under ANY behavior (both negative
# assertions were unconditional). A live VM must show the BASE cmdline.
if grep -q 'cmdline=\[[^]]*' "$LOG_DIR/sandlot.log" 2>/dev/null; then
    pass "positive control: launch lines carry a cmdline= field (pattern matchable)"
else
    fail "no 'launching VMM … cmdline=[…]' line in sandlot.log — the warden-cmdline assertions above are vacuous"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 10: Verify No Crashes or Errors"
# ══════════════════════════════════════════════════════════════════

VMM_CRASHES=$(grep -hE "panic|SIGSEGV|fatal" "$LOG_DIR/sandlot.log" "$LOG_DIR/gateway.log" 2>/dev/null | grep -vc "non-fatal" || true)
VMM_CRASHES=${VMM_CRASHES:-0}

if [[ "${VMM_CRASHES:-0}" -eq 0 ]]; then
    pass "No crashes in sandlot/gateway logs during hot-reload test"
else
    fail "Crashes detected: $VMM_CRASHES"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Results Summary"
# ══════════════════════════════════════════════════════════════════

echo ""
echo "  ┌──────────────────────────────────────────────────────┐"
echo "  │    Sandswap Config Hot-Reload E2E Test Results       │"
echo "  ├──────────────────────────────────────────────────────┤"
printf "  │ Pool scale-up:   %-37s │\n" "TESTED (medium:2 → small:1,medium:4)"
printf "  │ Pool scale-down: %-37s │\n" "TESTED (small:1,medium:4 → medium:2)"
printf "  │ Pending-destroy: %-37s │\n" "TESTED (medium:2 → pool=\"\" w/ busy VM)"
printf "  │ Lease timeout:   %-37s │\n" "TESTED (100ms → 500ms)"
printf "  │ Restart-required: %-36s │\n" "TESTED (human addr change)"
printf "  │ Recycle by max_uses: %-33s │\n" "TESTED (1-VM pool, A→B switch)"
printf "  │ Invalid max_uses: %-35s │\n" "TESTED (-2 rejected, -1 applied)"
printf "  │ Min-idle floor:  %-37s │\n" "TESTED (standing pool, no churn)"
printf "  │ Warden fields:   %-37s │\n" "TESTED (restart-gated: debug NOT hot-loadable)"
echo "  ├──────────────────────────────────────────────────────┤"
printf "  │ Tests: %2d passed  %2d failed                             │\n" "$PASS_COUNT" "$FAIL_COUNT"
echo "  └──────────────────────────────────────────────────────┘"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "$FAIL_COUNT test(s) failed"
    exit 1
else
    log_pass "All $PASS_COUNT tests passed"
fi
