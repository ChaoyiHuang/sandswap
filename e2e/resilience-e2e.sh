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
# test-resilience-e2e.sh - Sandswap resilience end-to-end test (real KVM deployment)
# Runs the integration scenarios from docs/how-it-works/resilience.md (§8.1
# sandlot tolerance/connect-clean, §8.8 request-path machinery) against a
# live gateway + sandlot + microVM stack:
#   #2  concurrent cold mount -> MountLock (503 CONCURRENT_MOUNT or both 200, no leak)
#   #3  bg exec + sync exec concurrent -> both 200, sync lease hit
#   #8  bg exec lost: start bg -> kill sandlot -> reconnect -> status not running
#   #4  sandlot disconnect mid-exec -> fail -> restart -> retry succeeds
#   #3b multi-sandfs concurrent exec -> both 200
#   #25 body size limit -> 10MB execute rejected
# Requires KVM (nested virt OK). Missing KVM or artifacts fail the run (exit 1)
# — a silent skip would read as green. Run unit tests separately via
# e2e/resilience.sh.
# Usage: sudo bash e2e/resilience-e2e.sh

set -euo pipefail

# Ensure cargo/go are in PATH under sudo.
for p in "$HOME/.cargo/bin" "$HOME/go/bin" /usr/local/go/bin; do
    [[ -d "$p" ]] && case ":$PATH:" in *":$p:"*) ;; *) PATH="$p:$PATH" ;; esac
done
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VOL_ROOT="${VOL_ROOT:-/var/lib/sandswap/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
DEPLOY_DIR="${DEPLOY_DIR:-/var/lib/sandswap}"
# 3 VMs so concurrent requests for different sandfs (or racing cold mounts) can
# each acquire a CLEAN VM without artificial contention.
SANDLOT_POOL="${SANDLOT_POOL:-small:3}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
source "$ROOT/e2e/common.sh"

# Run directly from $OUTPUT (no separate deploy step) + shared template install.
tc_use_output_binaries
tc_install_flat_template

# ── Helpers (gw_exec / gw_exec_headers / gw_status / gw_kill /
#    http_code_of / body_of / json_field come from common.sh) ────

restart_sandlot() {
    tc_log_step "Restarting sandlot..."
    # Kill ONLY the sandlot process. Do NOT call tc_kill_sandswap_procs - it
    # would kill the gateway (breaking all subsequent requests) AND the sandvmm
    # microVMs (preventing re-adopt). sandlot has no Pdeathsig, so its sandvmm
    # children stay alive and are re-adopted by the new sandlot via state.json.
    kill "${SANDLOT_PID:-}" 2>/dev/null || true
    wait "${SANDLOT_PID:-}" 2>/dev/null || true
    sleep 2
    # Re-start ONLY sandlot (gateway must stay up) with the SAME flags as the
    # initial start — tc_start_sandlot is the single source of that flag list.
    tc_start_sandlot
    # Wait for the gateway to see the reconnected node's re-adopted VMs.
    for i in $(seq 1 30); do
        sleep 0.5
        local clean
        clean=$(tc_stats_clean_vms)
        if [[ "${clean:-0}" -ge 1 ]]; then
            tc_log_pass "sandlot restarted, pool repopulated (CLEAN=$clean, PID $SANDLOT_PID)"
            return 0
        fi
    done
    # FAIL instead of returning 0: all three call sites are
    # `restart_sandlot || { tc_log_error …; exit 1; }` — returning 0 made those
    # guards dead code, and every caller continues into scenarios that NEED a
    # running sandlot, so the follow-ups would fail for the wrong reason.
    tc_log_error "sandlot restarted but pool not repopulated (CLEAN=0) after 15s"
    return 1
}

# ── Pre-flight: KVM + artifacts required (hard fail, not a silent SKIP) ──
# A missing KVM or a broken build must show up as a FAILED run, not a green
# one — a silent exit-0 here would mask real breakage as a passing suite.
tc_check_root
if [[ ! -e /dev/kvm ]] || [[ ! -r /dev/kvm ]]; then
    tc_log_error "/dev/kvm not available - resilience E2E requires KVM."
    tc_log_info "Run: sudo chmod 666 /dev/kvm   or add user to kvm group"
    tc_log_info "Unit tests only: bash e2e/resilience.sh"
    exit 1
fi

if [[ ! -f "$OUTPUT/gateway" ]] || [[ ! -f "$OUTPUT/sandlot" ]] || [[ ! -f "$OUTPUT/sandvmm" ]]; then
    tc_log_error "build artifacts missing in output/ - run 'bash build/build.sh all' first."
    exit 1
fi

tc_log_section "Resilience E2E (real KVM deployment)"

# ── Deploy & start ────────────────────────────────────────────
tc_check_tools curl python3
tc_clean_environment
# Deploy binaries to DEPLOY_DIR (tc_start_gateway/tc_start_sandlot default to $DEPLOY_DIR).
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network
tc_attach_vsockguard

tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready "${POOL_SIZE:-3}"

# Trap cleanup on exit.
cleanup() {
    rm -f "${T1:-}" "${T2:-}" "${BIG_FILE:-}" 2>/dev/null || true
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

# Create one agent; reuse across scenarios (each scenario creates its own sandfs).
# Call WITHOUT command substitution so the tc_* side-effect variables
# (TC_AGENT_ID, TC_API_KEY) are set in this shell, not a subshell.
tc_create_agent_and_sandfs "resilience-e2e" "rootfs:v1" "flat" >/dev/null
API_KEY="$TC_API_KEY"
[[ -n "$API_KEY" ]] || { tc_log_error "failed to create agent"; exit 1; }
tc_log_pass "agent created (api_key present, agent_id=$TC_AGENT_ID)"

new_sandfs() { # name -> sandfs_id (empty on failure — NEVER a dead pipeline:
# under set -e a failing python here would abort the caller before its
# `[[ -n "$SA" ]] || exit 1` guard could even run)
    local name="$1"
    local resp
    resp=$(curl -s -X POST "$HUMAN_URL/human/sandfs" -H "Content-Type: application/json" \
        -d "{\"agent_id\":\"$TC_AGENT_ID\",\"name\":\"$name\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}")
    echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo ""
}

# ═══ Scenario A: Concurrent cold mount (#2) ═══
tc_log_section "Scenario A: concurrent cold mount (MountLock, #2)"
SA=$(new_sandfs "conc-mount")
[[ -n "$SA" ]] || { tc_log_error "create sandfs A"; exit 1; }

# Fire 2 concurrent executes on the SAME sandfs. MountLock should serialize:
# either one gets 503 CONCURRENT_MOUNT, or both succeed (first mount completes
# fast and the second hits the sticky lease). Key invariant: no IN_USE leak.
T1=$(mktemp); T2=$(mktemp)
gw_exec "$API_KEY" "$SA" "echo a" > "$T1" &
P1=$!
gw_exec "$API_KEY" "$SA" "echo b" > "$T2" &
P2=$!
wait "$P1" "$P2"
R1=$(cat "$T1"); R2=$(cat "$T2")
rm -f "$T1" "$T2"
C1=$(http_code_of "$R1"); C2=$(http_code_of "$R2")
if [[ "$C1" == "200" || "$C2" == "200" ]]; then
    tc_pass "concurrent mount: at least one succeeded ($C1/$C2)"
else
    tc_fail "concurrent mount: neither succeeded ($C1/$C2) R1=$(body_of "$R1" | head -c 120)"
fi
# No IN_USE leak: after both complete, no VM should be stuck IN_USE.
# EMPTY ≠ 0: a failed fetch/parse must NOT read as "no leak" — distinguish
# them so a /stats shape change fails here instead of passing vacuously.
sleep 1
IN_USE=$(curl -s -m 5 "$HUMAN_URL/stats" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('totals',{}).get('in_use_vms',0))" 2>/dev/null || echo "")
if [[ -z "$IN_USE" ]]; then
    tc_fail "could not read in_use_vms from /stats — leak check UNVERIFIED"
elif [[ "$IN_USE" == "0" ]]; then
    tc_pass "no IN_USE leak after concurrent mount"
else
    tc_fail "IN_USE leak: $IN_USE VMs stuck"
fi

# ═══ Scenario B: bg exec + sync exec concurrent (#3) ═══
tc_log_section "Scenario B: bg exec + sync exec concurrent (#3)"
SB=$(new_sandfs "bg-sync")
[[ -n "$SB" ]] || { tc_log_error "create sandfs B"; exit 1; }

# Start a background exec (returns immediately, VM -> LEASED).
BG=$(gw_exec "$API_KEY" "$SB" "sleep 60" '"background":true,"lease_duration":120')
BG_CODE=$(http_code_of "$BG")
BG_ID=$(body_of "$BG" | json_field "exec_id")
if [[ "$BG_CODE" == "200" && -n "$BG_ID" ]]; then
    tc_pass "bg exec started (exec_id=$BG_ID)"
else
    tc_fail "bg exec start failed ($BG_CODE): $(body_of "$BG")"
fi

# Sync exec on the same sandfs -> should hit the sticky lease (LEASED by bg).
SYNC=$(gw_exec_headers "$API_KEY" "$SB" "echo hello")
SYNC_LEASE=$(echo "$SYNC" | grep '^LEASE:' | cut -d: -f2)
if [[ "$SYNC_LEASE" == "hit" ]]; then
    tc_pass "sync exec during bg exec hit sticky lease (warm path)"
else
    tc_fail "sync exec did not hit lease (got '$SYNC_LEASE') - cold mount during bg exec"
fi

# Cleanup the bg exec.
gw_kill "$API_KEY" "$SB" "$BG_ID" >/dev/null 2>&1 || true
sleep 1

# ═══ Scenario E: multi-sandfs concurrent (#3b) ═══
tc_log_section "Scenario E: multi-sandfs concurrent exec (#3b)"
SE1=$(new_sandfs "multi-1"); SE2=$(new_sandfs "multi-2")
[[ -n "$SE1" && -n "$SE2" ]] || { tc_log_error "create multi sandfs"; exit 1; }
T1=$(mktemp); T2=$(mktemp)
gw_exec "$API_KEY" "$SE1" "echo m1" > "$T1" &
P1=$!
gw_exec "$API_KEY" "$SE2" "echo m2" > "$T2" &
P2=$!
wait "$P1" "$P2"
ME1=$(cat "$T1"); ME2=$(cat "$T2")
rm -f "$T1" "$T2"
MC1=$(http_code_of "$ME1"); MC2=$(http_code_of "$ME2")
if [[ "$MC1" == "200" && "$MC2" == "200" ]]; then
    tc_pass "multi-sandfs concurrent exec both succeeded"
else
    tc_fail "multi-sandfs concurrent failed ($MC1/$MC2)"
fi

# ═══ Scenario F: body size limit (#25) ═══
tc_log_section "Scenario F: execute body size limit (#25)"
# Build an 11MB JSON body in a file (passing 11MB as a curl arg exceeds
# ARG_MAX). The execute handler caps the body at 10MB via io.LimitReader, so
# the truncated body fails JSON parse -> 400 (or 413).
BIG_FILE=$(mktemp)
python3 -c "import json;print(json.dumps({'code':'x'*11000000}))" > "$BIG_FILE"
BIG_RESP=$(curl -s -m 60 -w $'\nHTTPCODE:%{http_code}' -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
    -d @"$BIG_FILE" 2>&1)
rm -f "$BIG_FILE"
BIG_CODE=$(http_code_of "$BIG_RESP")
# io.LimitReader truncates at 10MB -> invalid JSON -> 400. (413 would also be
# acceptable if MaxBytesReader were used.)
if [[ "$BIG_CODE" == "400" || "$BIG_CODE" == "413" ]]; then
    tc_pass "oversized body rejected ($BIG_CODE)"
else
    tc_fail "oversized body NOT rejected (got $BIG_CODE)"
fi

# ═══ Scenario C: bg exec lost after sandlot crash (#8) ═══
tc_log_section "Scenario C: bg exec lost after sandlot crash (#8)"
SC=$(new_sandfs "bg-lost")
[[ -n "$SC" ]] || { tc_log_error "create sandfs C"; exit 1; }
BG2=$(gw_exec "$API_KEY" "$SC" "sleep 300" '"background":true,"lease_duration":300')
BG2_ID=$(body_of "$BG2" | json_field "exec_id")
if [[ -z "$BG2_ID" ]]; then
    tc_fail "bg exec C start failed: $(body_of "$BG2")"
else
    # Confirm it's running.
    ST=$(gw_status "$API_KEY" "$SC" "$BG2_ID")
    ST_STATUS=$(echo "$ST" | json_field "status")
    if [[ "$ST_STATUS" == "running" ]]; then
        tc_pass "bg exec running before crash"
    else
        tc_fail "bg exec not running before crash (status=$ST_STATUS)"
    fi

    # Kill sandlot -> bg exec metadata is gateway-in-memory; on disconnect the
    # lease is released, so the bg exec is lost.
    restart_sandlot || { tc_log_error "sandlot restart failed"; exit 1; }
    sleep 1

    ST2=$(gw_status "$API_KEY" "$SC" "$BG2_ID")
    ST2_STATUS=$(echo "$ST2" | json_field "status")
    # After disconnect+reconnect the lease is gone -> "expired", or sandlot lost
    # the exec -> "not_found". Either way it must NOT be "running".
    # An EMPTY status (5xx body / JSON parse failure) is not evidence of loss —
    # the old `!= running` check counted it as lost.
    if [[ -z "$ST2_STATUS" ]]; then
        tc_fail "bg exec status unreadable after restart (empty/decode failure: $(echo "$ST2" | head -c 200)) — loss NOT demonstrated"
    elif [[ "$ST2_STATUS" == "running" ]]; then
        tc_fail "bg exec still 'running' after sandlot crash (should be lost)"
    else
        tc_pass "bg exec lost after sandlot crash (status=$ST2_STATUS)"
    fi
fi

# ═══ Scenario D: sandlot disconnect mid-exec -> recover (#4) ═══
tc_log_section "Scenario D: sandlot disconnect mid-exec -> recover (#4)"
SD=$(new_sandfs "disconnect")
[[ -n "$SD" ]] || { tc_log_error "create sandfs D"; exit 1; }

# Start a long sync exec in the background (curl), then kill sandlot mid-exec.
( curl -s -m 30 -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$SD\",\"code\":\"sleep 8\",\"language\":\"shell\",\"timeout\":20}" \
    > "$LOG_DIR/long-exec.out" 2>&1 || true ) &
LONG_PID=$!
sleep 2
# Kill sandlot while the long exec is in flight.
kill "${SANDLOT_PID:-}" 2>/dev/null || true
wait "$LONG_PID" 2>/dev/null || true
LONG_OUT=$(cat "$LOG_DIR/long-exec.out" 2>/dev/null || echo "")
# The in-flight exec must NOT have succeeded cleanly (sandlot died). The pass
# needs EVIDENCE: a real failure response. Empty output = no evidence either
# way (gateway unreachable / curl never wrote) — that is a failure of the
# test, not a pass; and an actual success means the kill landed too late and
# the scenario never ran.
if echo "$LONG_OUT" | grep -q '"exit_code":0' && echo "$LONG_OUT" | grep -q '"stdout"'; then
    tc_fail "long exec SUCCEEDED — sandlot did not die in time, disconnect scenario never exercised"
elif [[ -z "$LONG_OUT" ]]; then
    tc_fail "no response captured for the in-flight exec (gateway unreachable?) — scenario UNVERIFIED"
else
    tc_pass "in-flight exec failed while sandlot was down (evidence: $(echo "$LONG_OUT" | head -c 100))"
fi

# Restart sandlot and verify recovery: a fresh exec succeeds.
restart_sandlot || { tc_log_error "sandlot restart failed (D)"; exit 1; }
sleep 1
RETRY=$(gw_exec "$API_KEY" "$SD" "echo recovered")
RETRY_CODE=$(http_code_of "$RETRY")
if [[ "$RETRY_CODE" == "200" ]]; then
    tc_pass "recovery: exec succeeds after sandlot reconnect ($RETRY_CODE)"
else
    tc_fail "recovery failed after reconnect ($RETRY_CODE): $(body_of "$RETRY")"
fi

# ═══ Scenario G: stale mount released after sandlot death (v2 tolerance-first) ═══
tc_log_section "Scenario G: stale mount released after sandlot death"
SG=$(new_sandfs "re-adopt")
[[ -n "$SG" ]] || { tc_log_error "create sandfs G"; exit 1; }

# Hold the mount with a bg exec and CONFIRM the VM is IN_USE at kill time:
# a plain sync exec's mount survives only the 100ms sticky window, so the old
# version raced the async unmount and often killed an already-CLEAN VM —
# degenerating into a plain restart test while claiming to cover the
# stale-mount re-adopt path.
GBG=$(gw_exec "$API_KEY" "$SG" "sleep 120" '"background":true,"lease_duration":300')
GBG_ID=$(body_of "$GBG" | json_field "exec_id")
GBG_OK=0
if [[ -n "$GBG_ID" ]]; then
# shellcheck disable=SC2034  # poll loop counter
    for i in $(seq 1 20); do
        IN_USE_G=$(curl -s -m 5 "$HUMAN_URL/stats" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('totals',{}).get('in_use_vms',0))" 2>/dev/null || echo "")
        [[ "${IN_USE_G:-0}" -ge 1 ]] 2>/dev/null && { GBG_OK=1; break; }
        sleep 0.5
    done
fi
if [[ "$GBG_OK" -eq 1 ]]; then
    tc_pass "sandfs mounted (VM IN_USE) before sandlot disconnect"
else
    tc_fail "could not hold a VM IN_USE before the kill — stale-mount re-adopt scenario NOT exercised"
fi

# Kill sandlot while the VM is still mounted. In v2 the warden does NOT fast-
# release (v2 warden single countdown, T_warden = 300s): last-resort backstop
# is the backstop for when the sandlot never restarts. Here the sandlot DOES
# restart — its ReadoptVMs re-adopts the surviving VM, resets allowed_dirs([])
# and best-effort unmounts the stale rootfs (re-adopt-light), so the VM is CLEAN
# before the gateway reconciles. Recovery therefore succeeds via re-adopt, not
# the warden.
#
# Snapshot the live VM IDs before the kill. The re-adopt path must UNMOUNT
# first and clear allowed_dirs second; the reverse order trips the VMM's reuse
# tripwire (the bind mount pins FUSE inode references), dirty-destroys every
# mounted survivor, and shows up here as a changed ID set.
VM_IDS_BEFORE="$(tc_run_vm_ids | tr '\n' ' ')"
kill "${SANDLOT_PID:-}" 2>/dev/null || true
tc_log_info "sandlot killed; restarting (re-adopt clears the stale mount)..."
sleep 3

# Restart sandlot. ReadoptVMs re-adopts the surviving VM and unmounts the stale
# rootfs, so a fresh mount+exec should succeed.
restart_sandlot || { tc_log_error "sandlot restart failed (G)"; exit 1; }
sleep 1

VM_IDS_AFTER="$(tc_run_vm_ids | tr '\n' ' ')"
MISSING_VMS=""
for id in $VM_IDS_BEFORE; do
    case " $VM_IDS_AFTER " in
        *" $id "*) ;;
        *) MISSING_VMS="$MISSING_VMS $id" ;;
    esac
done
if [[ -n "$VM_IDS_BEFORE" && -z "$MISSING_VMS" ]]; then
    tc_pass "re-adopt preserved every pre-kill VM (no dirty destroy): before=[$VM_IDS_BEFORE] after=[$VM_IDS_AFTER]"
else
    tc_fail "re-adopt destroyed/replaced VM(s) instead of reusing them (before=[$VM_IDS_BEFORE] after=[$VM_IDS_AFTER] missing=[$MISSING_VMS]) — cleanup ordering or reuse-tripwire regression"
fi

RECOVER=$(gw_exec "$API_KEY" "$SG" "echo after-re-adopt")
RECOVER_CODE=$(http_code_of "$RECOVER")
if [[ "$RECOVER_CODE" == "200" ]]; then
    tc_pass "exec succeeds after sandlot death + re-adopt ($RECOVER_CODE)"
else
    tc_fail "exec failed after sandlot death + re-adopt ($RECOVER_CODE): $(body_of "$RECOVER")"
fi

# ── Summary ───────────────────────────────────────────────────
tc_log_section "Resilience E2E Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}Resilience E2E FAILED${NC}"
    exit 1
fi
echo -e "${GREEN}Resilience E2E PASSED${NC}"
exit 0
