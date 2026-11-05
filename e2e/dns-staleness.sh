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
# DNS staleness-routing E2E test using real etcd.
# Tests: owner-branch staleness gate (fresh owner resolves, dead owner does
#         not), presence-directed routing (dead owner + mounted node whose
#         presence names a live peer routes to the peer), idle dead-owner
#         fall-through, dead-presence fall-through.
# Requirements: etcd + etcdctl (tc_ensure_etcd resolves/downloads them).
# No KVM needed — tests the etcd-coupled DNS coordination layer only.
# Usage: bash e2e/dns-staleness.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

ETCD_DATA="/tmp/sandswap-dns-staleness-e2e-etcd-data"

cleanup() {
    tc_cleanup_etcd "$ETCD_DATA"
}
trap cleanup EXIT INT TERM

# ── Start etcd ──────────────────────────────────────────────────
tc_log_section "DNS staleness-routing E2E (real etcd, no KVM)"
tc_ensure_etcd
tc_start_etcd dns-staleness-e2e "$ETCD_DATA"

# ── Build dns ───────────────────────────────────────────────────
tc_log_section "Building dns"
cd "$ROOT/dns"
if go build ./... 2>&1; then
    tc_log_pass "dns build succeeded"
else
    tc_log_error "dns build failed"
    exit 1
fi

# ── Run DNS staleness-routing E2E tests ─────────────────────────
tc_log_section "Running DNS staleness-routing E2E tests"
TOTAL_START=$(date +%s)

# Shared runner (common.sh): vacuous-pass guard + coverage floor. Packages are
# "." (the dns root) — ./... would include dns/wire, which has no TestE2E tests
# and would trip the vacuous-pass guard spuriously.
# shellcheck disable=SC2034  # TC_MIN_TESTS is consumed by the SOURCED common.sh across the source boundary
TC_MIN_TESTS=6
if tc_run_go_suite dns \
    'TestE2E' \
    "." -v -tags dns_e2e -timeout 120s; then
    tc_pass "DNS staleness-routing E2E suite passed"
else
    tc_fail "DNS staleness-routing E2E suite FAILED"
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
tc_log_pass "All DNS staleness-routing E2E tests PASSED"
