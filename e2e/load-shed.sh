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
# Voluntary load-shed rebalance E2E test using real etcd (no KVM needed).
# The saturation-rebalance feature moves a cold-path sandfs off a sustained-
# saturated owner gateway onto an idle peer: the owner releases ownership in
# etcd and returns a raw 503 + Connection: close so the client re-resolves the
# sandfs DNS name to the peer, which claims it. These tests drive the REAL
# etcd-backed coordination machinery (OwnershipCache, PoolManager,
# PeerLoadMonitor, ShedController) plus the real /agent/execute HTTP path:
#   lease  : full shed lifecycle across two gateway instances — release in
#            etcd, cooldown refuse-to-reclaim, peer CAS takeover, watch
#            ClearShed — plus the no-peer / disabled / not-sustained /
#            cooldown-expiry negative paths.
#   handler: raw 503 + Retry-After + Connection: close (empty body), ownership
#            released in etcd, cooldown 503 on a DNS-cache-window retry, then
#            the idle peer claims.
# Requirements: etcd + etcdctl (downloaded on first run if missing).
# Usage: bash e2e/load-shed.sh
# Design: docs/how-it-works/resilience.md (load balancing and saturation rebalance).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

ETCD_DATA="/tmp/sandswap-shed-e2e-etcd-data"

cleanup() {
    tc_cleanup_etcd "$ETCD_DATA"
}
trap cleanup EXIT INT TERM

# ── Start etcd ──────────────────────────────────────────────────
tc_log_section "Voluntary load-shed rebalance E2E (real etcd, no KVM)"
tc_ensure_etcd
tc_start_etcd shed-e2e "$ETCD_DATA"

# ── Build gateway ───────────────────────────────────────────────
cd "$ROOT/gateway"
if go build ./... 2>&1; then
    tc_log_pass "gateway build succeeded"
else
    tc_log_error "gateway build failed"
    exit 1
fi

# ── Run shed E2E tests ──────────────────────────────────────────
# Shared runner (common.sh): vacuous-pass guard + coverage floor. A single
# -run covers both packages: TestShed* (lease: unit + coordination e2e) and
# TestShedHTTP* (handler: transport e2e). -p 1 serializes the two packages:
# they share one etcd and each clears /sandswap/load/* at start, so running
# them concurrently would let one package's wipe race the other's seeded peer.
TOTAL_START=$(date +%s)
# shellcheck disable=SC2034  # TC_MIN_TESTS is consumed by the SOURCED common.sh across the source boundary
TC_MIN_TESTS=12
if ! tc_run_go_suite gateway 'TestShed' "./lease/ ./handler/" -p 1 -v -tags shed_e2e -timeout 120s; then
    tc_log_error "shed E2E FAILED"
    exit 1
fi
TOTAL_END=$(date +%s)

tc_log_section "Summary"
echo "  Total time: $((TOTAL_END - TOTAL_START))s"
tc_log_pass "All load-shed rebalance E2E tests PASSED"
exit 0
