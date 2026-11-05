#!/bin/bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# readopt-restart-id-unique.sh — startup pre-creation vs re-adopted survivors
# Covers two restart-path regressions that unit tests cannot reach:
#   PoolIDUnique  startup pre-create must NEVER generate a VM ID that collides
#       with a live re-adopted survivor. The old scheme derived IDs from the
#       survivor COUNT ("<count>+i"), so whenever recycle/scale-down left holes
#       in the survivor seq set, the pre-created VM re-landed on a LIVE seq:
#       the collision unlinked the live VM's API socket (os.Remove in Launch),
#       launched a second sandvmm on the same path, and overwrote the registry
#       entry — the original sandvmm leaked forever (orphan sweep spares it:
#       its socket path is "live"). Fix: IDs come from the shared nextPoolSeq
#       counter (already advanced past every survivor), plus a duplicate-ID
#       refusal guard in CreateVerifiedVM.
#   ReconnectClean  after the restart the node must serve execs again with the
#       survivors verifiably CLEAN before NodeHello (the reconnect path waits
#       out the async re-adopt unmounts).
# Scenario: pool small:3 live; delete ONE survivor's state.json while its
# sandvmm keeps running (deterministic seq hole: re-adopt = {0,2}, count 2 <
# target 3); restart sandlot. Under the old code the pre-create lands on the
# LIVE pool-small-2 (4 sandvmm processes / 2 enumerated); with the fix a fresh
# pool-small-3 boots (3 processes / 3 enumerated).
# Prerequisites: built artifacts in output/, /dev/kvm available, root.
# Usage: bash e2e/readopt-restart-id-unique.sh

set -euo pipefail

for p in "$HOME/.cargo/bin" "$HOME/go/bin" /usr/local/go/bin; do
    [[ -d "$p" ]] && case ":$PATH:" in *":$p:"*) ;; *) PATH="$p:$PATH" ;; esac
done
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VOL_ROOT="${VOL_ROOT:-/var/lib/sandswap/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
DEPLOY_DIR="${DEPLOY_DIR:-/var/lib/sandswap}"
POOL_SIZE=3
# shellcheck disable=SC2034  # SANDLOT_POOL is consumed by the SOURCED common.sh across the source boundary
SANDLOT_POOL="small:${POOL_SIZE}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
source "$ROOT/e2e/common.sh"

tc_use_output_binaries
tc_install_flat_template

tc_check_root
if [[ ! -e /dev/kvm ]] || [[ ! -r /dev/kvm ]]; then
    tc_log_error "/dev/kvm not available - this E2E requires KVM."
    exit 1
fi
if [[ ! -f "$OUTPUT/sandlot" ]] || [[ ! -f "$OUTPUT/sandvmm" ]] || [[ ! -f "$OUTPUT/gateway" ]]; then
    tc_log_error "build artifacts missing in output/ - run 'bash build/build.sh all' first."
    exit 1
fi

tc_log_section "Re-adopt restart ID uniqueness E2E"

tc_check_tools curl python3
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network
tc_attach_vsockguard

tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready "$POOL_SIZE"

cleanup() { tc_cleanup_default; }
trap cleanup EXIT INT TERM

tc_create_agent_and_sandfs "restart-id-test"
tc_log_pass "agent=$TC_AGENT_ID sandfs=$TC_SANDFS_ID"

R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo before-restart")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "exec works before restart" \
    || tc_fail "exec failed before restart: $(body_of "$R")"

# ══════════════════════════════════════════════════════════════
# Carve a deterministic seq hole: stop sandlot, delete ONE survivor's
# state.json (its sandvmm keeps running). At restart the orphan-dir cleanup
# kills that sandvmm; re-adopt = {0,2} (count 2 < target 3).
# ══════════════════════════════════════════════════════════════
tc_log_section "Create survivor seq hole (delete pool-small-1 state.json)"

mapfile -t PIDS_BEFORE < <(tc_run_vm_pids)
[[ ${#PIDS_BEFORE[@]} -eq "$POOL_SIZE" ]] \
    || { tc_fail "expected $POOL_SIZE live VMs before restart, got ${#PIDS_BEFORE[@]}"; exit 1; }

kill "${SANDLOT_PID:-}" 2>/dev/null || true
wait "${SANDLOT_PID:-}" 2>/dev/null || true
sleep 1

STATE1=/run/sandswap-state/default/pool-small-1/state.json
[[ -f "$STATE1" ]] || { tc_fail "$STATE1 missing — pool seq layout changed?"; exit 1; }
rm -f "$STATE1"
tc_log_info "deleted $STATE1 (pool-small-1's sandvmm keeps running → orphan-dir cleanup)"

# ══════════════════════════════════════════════════════════════
# PoolIDUnique + ReconnectClean: restart and verify
# ══════════════════════════════════════════════════════════════
tc_log_section "Restart sandlot (re-adopt {0,2}, pre-create 1)"

tc_start_sandlot
tc_wait_pool_ready "$POOL_SIZE"

# Enumerated VMs (state.json-backed): the colliding old code leaves the leaked
# survivor's state.json overwritten by the new VM → 2 enumerated; fix → 3.
# Whole-host sandvmm count is the leak discriminator: old code → 4 (the
# original pool-small-2 sandvmm survives invisibly); fix → 3.
PIDS_OK=0
# shellcheck disable=SC2034  # poll loop counter
for i in $(seq 1 120); do
    mapfile -t PIDS_NOW < <(tc_run_vm_pids)
    HOST_TOTAL=$(pgrep -x sandvmm | wc -l)
    if [[ ${#PIDS_NOW[@]} -eq "$POOL_SIZE" && "$HOST_TOTAL" -eq "$POOL_SIZE" ]]; then
        PIDS_OK=1; break
    fi
    sleep 1
done
if [[ $PIDS_OK -eq 1 ]]; then
    tc_pass "exactly $POOL_SIZE VMs after restart (enumerated=${#PIDS_NOW[@]}, host sandvmm=$HOST_TOTAL) — no ID collision, no leaked process"
else
    mapfile -t PIDS_NOW < <(tc_run_vm_pids)
    tc_fail "expected $POOL_SIZE/$POOL_SIZE (enumerated/host) VMs, got ${#PIDS_NOW[@]}/$(pgrep -x sandvmm | wc -l) — colliding pre-create ID or leaked sandvmm"
fi

# Unique IDs: every state.json carries a distinct vm_id.
DUP_IDS=$(for s in /run/sandswap-state/default/*/state.json; do
    python3 -c "import json;print(json.load(open('$s'))['vm_id'])" 2>/dev/null
done | sort | uniq -d | wc -l)
[[ "$DUP_IDS" -eq 0 ]] \
    && tc_pass "all VM IDs unique" \
    || tc_fail "duplicate VM IDs in state records"

# The duplicate-ID guard must never have needed to fire (it is belt-and-braces,
# not the fix itself).
if grep -q "ID already registered" "$LOG_DIR/sandlot.log"; then
    tc_fail "duplicate-ID refusal guard fired at startup — ID allocation still collides"
else
    tc_pass "duplicate-ID guard never fired"
fi

# Collision signature: no startup pre-create may target an ID that this same
# start re-adopted. Under the old count-based scheme the pre-created ID landed
# on a LIVE survivor (socket unlink + offline relaunch + kill-by-PID fallback)
# — the pool eventually re-converged to the target, so a process-count check
# alone cannot catch it; the log signature can.
COLLIDING=$(python3 - "$LOG_DIR/sandlot.log" <<'PYEOF'
import re, sys
log = open(sys.argv[1], errors="replace").read()
readopted = set(re.findall(r"re-adopted VM (\S+)", log))
precreated = set(re.findall(r"pre-creating VM (\S+)", log))
print("\n".join(sorted(readopted & precreated)))
PYEOF
)
if [[ -n "$COLLIDING" ]]; then
    tc_fail "startup pre-create collided with re-adopted survivor ID(s): $COLLIDING"
else
    tc_pass "no pre-create ID collides with any re-adopted survivor"
fi

# Two survivors re-adopted, one fresh VM created.
READOPTED=$(grep -c "re-adopted VM" "$LOG_DIR/sandlot.log" || true)
[[ "$READOPTED" -eq 2 ]] \
    && tc_pass "re-adopted exactly 2 survivors (seq hole honored)" \
    || tc_log_warn "re-adopt log count = $READOPTED (want 2; non-fatal if log wording changed)"

# ReconnectClean observable: exec works right away with the survivors CLEAN.
R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo after-restart")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "exec works after restart (survivors re-adopted CLEAN before hello)" \
    || tc_fail "exec failed after restart: $(body_of "$R")"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "[FAIL] readopt-restart-id-unique E2E FAILED"
    exit 1
fi
echo "[OK] readopt-restart-id-unique E2E PASSED"
exit 0
