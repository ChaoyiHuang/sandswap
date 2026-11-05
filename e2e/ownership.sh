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
# Cross-gateway ownership E2E test using real etcd.
# Tests: CAS claim, health-key expiry takeover, watch conflict, disconnect-clear,
#         node_id lifecycle, placement semantics, staleness gates, reap-stuck.
# The -run list deliberately uses UNANCHORED regex prefixes (e.g.
# TestSandfsByAgent matches TestSandfsByAgentReverseIndex) so renames that keep
# the family prefix keep running; a rename away from the prefix trips the
# vacuous-pass guard below.
# Requirements: etcd + etcdctl (tc_ensure_etcd resolves/downloads them).
# No KVM needed — tests the etcd coordination layer only.
# Usage: bash e2e/ownership.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

ETCD_DATA="/tmp/sandswap-ownership-e2e-etcd-data"

cleanup() {
    tc_cleanup_etcd "$ETCD_DATA"
}
trap cleanup EXIT INT TERM

# ── Start etcd ──────────────────────────────────────────────────
tc_log_section "Ownership E2E (real etcd, no KVM)"
tc_ensure_etcd
tc_start_etcd ownership-e2e "$ETCD_DATA"

# ── Build gateway ───────────────────────────────────────────────
tc_log_section "Building gateway"
cd "$ROOT/gateway"
if go build ./... 2>&1; then
    tc_log_pass "gateway build succeeded"
else
    tc_log_error "gateway build failed"
    exit 1
fi

# ── Run ownership E2E tests ─────────────────────────────────────
tc_log_section "Running ownership E2E tests"

TOTAL_START=$(date +%s)

# Shared runner (common.sh): vacuous-pass guard + coverage floor. The -run
# list deliberately uses UNANCHORED regex prefixes (e.g. TestSandfsByAgent
# matches TestSandfsByAgentReverseIndex) so renames that keep the family
# prefix keep running; TC_MIN_TESTS catches a rename that drops one out.
# shellcheck disable=SC2034  # consumed by tc_run_go_suite (SOURCED common.sh) across the source boundary
TC_MIN_TESTS=35
if tc_run_go_suite gateway \
    'TestCASClaim|TestOwnershipNoLease|TestMigratedTakeover|TestWatchConflict|TestFaultStateOwnerTolerated|TestNodeIDLifecycle|TestOwnerReleaseThreePartChain|TestOwnerReleaseCanceled|TestOwnershipPersistsAcrossRestart|TestHealthKey|TestRegistryDecouplingPublishesAddressesInRegisterOnly|TestPresenceKeyLifecycle|TestLookupOwnerGatewayID|TestOwnerGatewayURLFromRegistry|TestSandfsByAgent|TestListAllSandFS|TestOwnershipCloseIdempotent|TestOwnerStalenessE2E|TestSelfHealthyStalenessE2E|TestOwnerDeadStalenessE2E|TestStalenessAlertScanE2E|TestClaimDeadIdleTimeGuardE2E|TestClaimDeadIdleRevivalClearsClockE2E|TestClaimDeadIdleWritesCandidatePlacement|TestClaimDeadIdlePreservesNonEmptyPlacement|TestReapStuckOwnershipE2E|TestReapStuckNodeOwnershipE2E|TestClaimCorruptValueOverwriteE2E|TestWatchKeepaliveResubscribeDeliversNewEventsE2E|TestWatchDeleteCompensatesMountedEntryE2E|TestPublishForeignRecordCompensatesE2E|TestClaimNoOwnerRacesE2E|TestReapDeleteCAS_SkipsMovedRecord|TestClaimRefreshPreservesDispatching|TestReleaseOwnershipCAS' \
    "./lease/" -v -tags ownership_e2e -timeout 120s; then
    tc_pass "ownership E2E suite passed"
else
    tc_fail "ownership E2E suite FAILED"
fi
TOTAL_END=$(date +%s)
TOTAL_SECS=$((TOTAL_END - TOTAL_START))

# ── Summary ─────────────────────────────────────────────────────
tc_log_section "Summary"
echo "  Total time: ${TOTAL_SECS}s"
echo ""
if [[ $FAIL_COUNT -gt 0 ]]; then
    tc_log_error "$FAIL_COUNT problem(s) detected"
    exit 1
fi
tc_log_pass "All ownership E2E tests PASSED"
