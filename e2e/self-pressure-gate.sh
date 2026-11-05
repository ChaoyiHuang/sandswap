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
# Gateway self-pressure routing-gate E2E using real etcd (no KVM needed).
# The self-pressure signal makes the DNS stop placing NEW traffic on a gateway
# whose own process is under sustained resource pressure (published
# self_pressured in /sandswap/load/{gw}), while owned sandfs keep routing to
# their owner. These tests drive the REAL machinery end to end:
#   gateway: the real 1s sampler loop with the default /proc + runtime readers
#            (a real CPU burn flips pressured; a hot threshold raise releases),
#            and the real load publisher (lease grant + self_* fields in etcd,
#            recovery re-publish).
#   dns    : the real DNSServer state against etcd — pressured gateway excluded
#            from no-owner fallback / agent / stream placement, owner affinity
#            preserved, recovery + bootstrap (no load record) behavior.
#   stats  : the /stats cluster report surfaces the self_* fields.
# Requirements: etcd + etcdctl (tc_ensure_etcd resolves/downloads them).
# Usage: bash e2e/self-pressure-gate.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

ETCD_DATA="/tmp/sandswap-selfpressure-e2e-etcd-data"

cleanup() {
    tc_cleanup_etcd "$ETCD_DATA"
}
trap cleanup EXIT INT TERM

# ── Start etcd ──────────────────────────────────────────────────
tc_log_section "Gateway self-pressure routing-gate E2E (real etcd, no KVM)"
tc_ensure_etcd
tc_start_etcd selfpressure-e2e "$ETCD_DATA"

# ── Build gateway + dns ─────────────────────────────────────────
tc_log_section "Building gateway + dns"
cd "$ROOT/gateway"
if go build ./... 2>&1; then
    tc_log_pass "gateway build succeeded"
else
    tc_log_error "gateway build failed"
    exit 1
fi
cd "$ROOT/dns"
if go build ./... 2>&1; then
    tc_log_pass "dns build succeeded"
else
    tc_log_error "dns build failed"
    exit 1
fi

# ── Run the self-pressure E2E suites ────────────────────────────
tc_log_section "Running self-pressure E2E tests"
TOTAL_START=$(date +%s)

# Gateway side: sampler loop + publisher chain (cmd) — 2 tests.
TC_MIN_TESTS=2
tc_run_go_suite gateway \
    'TestSelfLoadE2E' \
    "./app/" -v -tags selfload_e2e -timeout 120s || exit 1

# /stats surfacing (handler, stats_e2e tag shares the same etcd).
TC_MIN_TESTS=1
tc_run_go_suite gateway \
    'TestEtcdStatsReportAggregate' \
    "./handler/" -v -tags stats_e2e -timeout 120s || exit 1

# DNS side: routing gates against etcd — 1 e2e test (+ suite floor from the
# dns_e2e pattern used by dns-staleness.sh runs only TestE2E*; here we run the
# single new test with its own floor).
# shellcheck disable=SC2034  # TC_MIN_TESTS is consumed by the SOURCED common.sh across the source boundary
TC_MIN_TESTS=1
tc_run_go_suite dns \
    'TestE2ESelfPressureRouting' \
    "." -v -tags dns_e2e -timeout 120s || exit 1

TOTAL_END=$(date +%s)
TOTAL_SECS=$((TOTAL_END - TOTAL_START))
tc_log_pass "self-pressure E2E suites passed in ${TOTAL_SECS}s"
