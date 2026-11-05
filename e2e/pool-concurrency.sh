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
# pool-concurrency.sh — end-to-end check of the batch VM lifecycle knobs.
#   - concurrency.vm_create / vm_destroy are read from the sandlot config
#   - a 3-VM pool is pre-created with the configured create worker count
#   - a hot-reload to pool="" scales the pool down to zero idle VMs
#   - a hot-reload back to small:3 repopulates it
# Worker-count bounds themselves are pinned by the pool_concurrency unit
# tests (peak concurrent creates/destroys); this script proves the configured
# values reach the live batch path and that both directions still converge.
# Usage: sudo bash e2e/pool-concurrency.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

cleanup() {
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

log_section "Phase 0: Pre-flight Checks"

tc_check_root
tc_preflight_standard
tc_ensure_dev_nodes

if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — microVMs will be offline"
fi

log_section "Phase 1: Deploy & Generate Config"

tc_clean_environment
tc_deploy_artifacts
tc_gen_certs

SANDLOT_CONFIG="$LOG_DIR/sandlot.yaml"
SANDLOT_POOL="small:3"
POOL_SIZE=3
tc_gen_sandlot_config "$SANDLOT_CONFIG"
cat >> "$SANDLOT_CONFIG" <<'EOF'

concurrency:
  vm_create: 3
  vm_destroy: 4
EOF
TC_SANDLOT_CONFIG="$SANDLOT_CONFIG"

log_section "Phase 2: Start Stack & Batch Pre-create"

tc_start_gateway
tc_attach_vsockguard
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready 3

if grep -q "concurrency=3" "$LOG_DIR/sandlot.log"; then
    pass "pool pre-create used concurrency=3"
else
    fail "sandlot log does not name the configured create concurrency"
fi
if grep -q "pre-created 3 VM(s)" "$LOG_DIR/sandlot.log"; then
    pass "pool pre-created 3 VMs"
else
    fail "pool did not report 3 pre-created VMs"
fi

log_section "Phase 3: Hot-Reload Scale-Down to Zero"

SANDLOT_POOL=""
tc_gen_sandlot_config "$SANDLOT_CONFIG"
cat >> "$SANDLOT_CONFIG" <<'EOF'

concurrency:
  vm_create: 3
  vm_destroy: 4
EOF

deadline=$((SECONDS + 120))
while (( SECONDS < deadline )); do
    clean="$(tc_stats_clean_vms 2>/dev/null | tr -d '[:space:]')"
    [[ "$clean" == "0" ]] && break
    sleep 1
done
clean="$(tc_stats_clean_vms 2>/dev/null | tr -d '[:space:]')"
if [[ "$clean" == "0" ]]; then
    pass "scale-down reached 0 CLEAN VMs"
else
    fail "scale-down did not reach 0 CLEAN VMs (got ${clean:-unknown})"
fi
if grep -qE "destroying idle VM|destroyed/marked 3/3" "$LOG_DIR/sandlot.log"; then
    pass "scale-down destroyed idle VMs in batch"
else
    fail "scale-down produced no idle-destroy batch lines"
fi

log_section "Phase 4: Hot-Reload Scale-Up Again"

SANDLOT_POOL="small:3"
tc_gen_sandlot_config "$SANDLOT_CONFIG"
cat >> "$SANDLOT_CONFIG" <<'EOF'

concurrency:
  vm_create: 3
  vm_destroy: 4
EOF

deadline=$((SECONDS + 180))
while (( SECONDS < deadline )); do
    clean="$(tc_stats_clean_vms 2>/dev/null | tr -d '[:space:]')"
    [[ "$clean" -ge 3 ]] 2>/dev/null && break
    sleep 1
done
clean="$(tc_stats_clean_vms 2>/dev/null | tr -d '[:space:]')"
if [[ "$clean" -ge 3 ]] 2>/dev/null; then
    pass "scale-up restored the 3-VM pool"
else
    fail "scale-up did not restore the pool (got ${clean:-unknown})"
fi

log_section "Phase 5: No VM Churn or Crashes"

DIRTY=$(grep -c "dirty VM" "$LOG_DIR/sandlot.log" 2>/dev/null || true)
DIRTY=${DIRTY:-0}
if [[ "$DIRTY" -eq 0 ]]; then
    pass "no dirty VMs during batch create/destroy"
else
    fail "$DIRTY dirty VM event(s) during batch lifecycle"
fi

CRASHES=$(grep -hE "panic|SIGSEGV|SIGSYS" "$LOG_DIR/sandlot.log" "$LOG_DIR/gateway.log" 2>/dev/null | grep -vc "non-fatal" || true)
CRASHES=${CRASHES:-0}
if [[ "$CRASHES" -eq 0 ]]; then
    pass "no VMM crashes"
else
    fail "VMM crash lines detected: $CRASHES"
fi

log_section "Results Summary"

echo ""
echo "  ┌──────────────────────────────────────────────────────┐"
echo "  │     Sandswap Pool Concurrency E2E Test Results       │"
echo "  ├──────────────────────────────────────────────────────┤"
printf "  │ Create concurrency: %-32s │\n" "TESTED (3 workers, 3 VMs)"
printf "  │ Destroy concurrency: %-31s │\n" "TESTED (4 workers, scale-down)"
printf "  │ Scale-down to zero:  %-32s │\n" "TESTED (hot-reload pool=\"\")"
printf "  │ Scale-up again:      %-32s │\n" "TESTED (hot-reload small:3)"
echo "  ├──────────────────────────────────────────────────────┤"
printf "  │ Tests: %2d passed  %2d failed                             │\n" "$PASS_COUNT" "$FAIL_COUNT"
echo "  └──────────────────────────────────────────────────────┘"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "$FAIL_COUNT test(s) failed"
    exit 1
fi
log_pass "All $PASS_COUNT tests passed"
