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
# test-resilience.sh — Sandswap resilience automated test suite
# Tests the resilience design's key invariants from docs/how-it-works/resilience.md:
#  1. Concurrent cold mount → 503 CONCURRENT_MOUNT
#  2. sandfsState CLEANING → 503 SANDBOX_CLEANING → recovery
#  3. L1 retry on transport error
#  4. L2 cleanup after failure (EnterCleaning → ExitCleaning)
#  5. resilienceError structured response (error_code, retryable, retry_after_ms)
#  6. MountLock failure releases microVM
#  7. onExpiry panic recovery
#  8. Body size limit (10MB execute, 50MB file)
#  9. Multiple sandfs concurrent execution allowed
# 10. PreferredNode routing in Acquire
# 11. RemoveNode cleans up bySandfsID
# 12. SandfsState double-enter protection
# 13. bg exec + sync exec concurrent
# 14. Pool per-spec-per-node Acquire O(1) with preferredNode
# 15. Stats() O(1) atomic counters
# (tolerance-first): warden single countdown, sandlot tolerance state machine,
#     gateway owner-release three-part chain + presence key + nodeSandfs, no ownership lease.
# This script runs both Go unit tests and (optionally) integration tests
# against a live gateway+sandlot deployment.
# Usage:
#   bash e2e/resilience.sh             # Run Go unit tests only
#   bash e2e/resilience.sh --e2e       # Also run E2E integration tests
#   bash e2e/resilience.sh --verbose    # Verbose output

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

SKIP=0

# log_skip — unique to this script (not in common.sh)
log_skip() {
    echo -e "  ${TC_YELLOW}⊘${TC_NC} $1"
    SKIP=$((SKIP+1))
}

# GATEWAY_RACE: -race for the direct suite invocations below, on by default
# (TC_GO_RACE=0 opts out on a slow machine). The lease/ownership/mount-lock
# suites are exactly where latent data races hide — a plain `go test` lets
# them ship unnoticed.
GATEWAY_RACE="-race"
[[ "${TC_GO_RACE:-1}" == "0" ]] && GATEWAY_RACE=""

# run_strict_test runs a single `go test -run <pattern>` and FAILS if the
# pattern matched no tests (vacuous pass). Without this, a typo'd or stale
# test name silently exits 0 and the invariant appears "verified" when it
# actually ran nothing. Args: pkg test_pattern description.
# -race is on by default (TC_GO_RACE=0 opts out): concurrency-invariant tests
# here (lease/ownership/mount-lock) are exactly where races hide.
run_strict_test() {
    local pkg="$1" pattern="$2" desc="$3"
    local out rc=0 raceargs=""
    [[ "${TC_GO_RACE:-1}" != "0" ]] && raceargs="-race"
    out=$( (cd "$ROOT/gateway" && go test $raceargs "$pkg/" -run "$pattern" $VERBOSE -count=1 -timeout 60s) 2>&1 ) || rc=$?
    printf '%s\n' "$out"
    if [[ $rc -ne 0 ]]; then
        tc_fail "$desc (test failed, rc=$rc)"
    elif printf '%s\n' "$out" | grep -q "no tests to run"; then
        tc_fail "$desc (pattern '$pattern' matched NO tests - vacuous pass)"
    else
        tc_pass "$desc"
    fi
}

# go_suite_verdict <label> <captured-output-file> <rc> — verdict for the direct
# `go test` blocks in Phase 1. rc == 0 is NOT sufficient evidence: `go test`
# exits 0 with ZERO tests run — "no tests to run" (a -run pattern matching
# nothing) or "[no test files]" (a package without test files) — so a renamed
# test or a stale entry would read green. Same vacuous-pass guard Phase 2's
# strict runner applies.
go_suite_verdict() {
    local label="$1" outfile="$2" rc="$3"
    if [[ "$rc" -ne 0 ]]; then
        tc_fail "$label failed"
    elif grep -qE "no tests to run|\[no test files\]" "$outfile"; then
        tc_fail "$label: ran NO tests (vacuous pass — stale pattern or empty package?)"
    else
        tc_pass "$label passed"
    fi
}

# ── Parse args ────────────────────────────────────────────────
E2E=false
VERBOSE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --e2e) E2E=true; shift ;;
        --verbose|-v) VERBOSE="-v"; shift ;;
        --help|-h)
            echo "Usage: $0 [--e2e] [--verbose]"
            echo "  --e2e      Run E2E integration tests (requires live deployment)"
            echo "  --verbose  Verbose Go test output"
            exit 0
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Phase 1: Go Unit Tests ────────────────────────────────────
log_section "Phase 1: Resilience Go Unit Tests"

# 1.1 Build check
log_step "Building gateway..."
if ! (cd gateway && go build ./... 2>&1); then
    tc_fail "Gateway build failed"
    echo "ERROR: Gateway build failed. Fix compilation errors before running tests."
    exit 1
fi
tc_pass "Gateway builds successfully"

# 1.2 Resilience-specific unit tests
log_step "Running resilience handler tests..."
RESILIENCE_TESTS=(
    "TestConcurrentColdMount503"
    "TestSandfsCleaning503"
    "TestL2CleanupOnFailure"
    "TestL1RetryOnTransportError"
    "TestResilienceErrorStructure"
    "TestMountLockAcquireWaitSemantics"
    "TestExecuteBodySizeLimit"
    "TestMultipleSandfsConcurrentExecution"
    "TestOnExpiryPanicRecovery"
    "TestBgExecAndSyncExecConcurrent"
)

TEST_PATTERN=$(IFS='|'; echo "${RESILIENCE_TESTS[*]}")
TMPFILE=$(mktemp)
RESULT=0
# `|| RESULT=$?` keeps the script alive under set -e so the FAIL verdict prints
(cd "$ROOT/gateway" && go test $GATEWAY_RACE ./handler/ -run "$TEST_PATTERN" $VERBOSE -count=1 -timeout 120s) > "$TMPFILE" 2>&1 || RESULT=$?
cat "$TMPFILE"
go_suite_verdict "All resilience handler tests" "$TMPFILE" "$RESULT"
rm -f "$TMPFILE"

# 1.3 Lease package tests
log_step "Running lease package tests..."
TMPFILE=$(mktemp)
RESULT=0
(cd "$ROOT/gateway" && go test $GATEWAY_RACE ./lease/ $VERBOSE -count=1 -timeout 120s) > "$TMPFILE" 2>&1 || RESULT=$?
cat "$TMPFILE"
go_suite_verdict "Lease package tests" "$TMPFILE" "$RESULT"
rm -f "$TMPFILE"

# 1.4 Pool manager tests
log_step "Running pool manager tests..."
TMPFILE=$(mktemp)
RESULT=0
(cd "$ROOT/gateway" && go test $GATEWAY_RACE ./pool/ $VERBOSE -count=1 -timeout 120s) > "$TMPFILE" 2>&1 || RESULT=$?
cat "$TMPFILE"
go_suite_verdict "Pool manager tests" "$TMPFILE" "$RESULT"
rm -f "$TMPFILE"

# 1.5 Full handler test suite (includes existing + resilience tests)
log_step "Running full handler test suite..."
TMPFILE=$(mktemp)
RESULT=0
(cd "$ROOT/gateway" && go test $GATEWAY_RACE ./handler/ $VERBOSE -count=1 -timeout 120s) > "$TMPFILE" 2>&1 || RESULT=$?
cat "$TMPFILE"
go_suite_verdict "Full handler test suite" "$TMPFILE" "$RESULT"
rm -f "$TMPFILE"

# ── Phase 2: Invariant Verification (strict: vacuous -run = FAIL) ──
log_section "Phase 2: Resilience Invariant Verification"

# Verify key resilience invariants. run_strict_test FAILS if the -run pattern
# matches no tests, so a stale/typo'd test name can no longer pass vacuously.

log_step "Verifying: MountLock prevents concurrent cold mounts..."
run_strict_test ./lease "TestMountLockConcurrentMountBlocked" "MountLock blocks concurrent cold mounts"
run_strict_test ./lease "TestMountLockAcquireWaitBlocksUntilRelease" "MountLock AcquireWait wakes immediately on release ()"
run_strict_test ./lease "TestMountLockAcquireWaitTimeout" "MountLock AcquireWait 503 on timeout ()"

log_step "Verifying: SandfsState double-enter returns error..."
run_strict_test ./lease "TestSandfsStateDoubleEnter" "SandfsState double-enter returns ErrSandfsCleaning"

log_step "Verifying: RemoveNode drops node capacity cleanly (delegation)..."
run_strict_test ./pool "TestStatsAndRemoveNode" "RemoveNode drops node capacity cleanly"

log_step "Verifying: Stats reflect per-node capacity..."
run_strict_test ./pool "TestAcquireNoNodes" "Stats reflect per-node capacity"

log_step "Verifying: PreferredNode routing in Acquire..."
run_strict_test ./pool "TestAcquirePrefersNodeWithMostCapacity" "Acquire(preferredNode) routes correctly"

# Ownership invariants (core safety logic).
log_step "Verifying: Ownership Claim fast path + placement lifecycle..."
run_strict_test ./lease "TestOwnershipClaimFastPath" "Ownership Claim fast path"
run_strict_test ./lease "TestOwnershipPlacementLifecycle" "Ownership placement lifecycle (mount/move/conflict-clear)"
run_strict_test ./lease "TestOwnershipNoteNodeReconnected" "Ownership reconnect preserves placement (affinity)"
run_strict_test ./lease "TestOwnershipClearNodeIDByNodeDoesNotRefreshClaimTime" "Ownership reconnect doesn't refresh claimTime (stale fast-path guard)"
run_strict_test ./lease "TestOwnershipWatchConflict" "Ownership watch conflict invalidates cache"
run_strict_test ./lease "TestOwnershipCloseIdempotent" "Ownership Close idempotent ()"
run_strict_test ./lease "TestOwnershipNoteMountedNilClientNoPanic" "Ownership nil-client async paths don't panic ()"

# ── Phase 3: Code Structure Verification ─────────────────────
log_section "Phase 3: Code Structure Verification"

# Verify that key resilience files exist
log_step "Checking resilience implementation files..."
RESILIENCE_FILES=(
    "gateway/lease/mount_lock.go"
    "gateway/lease/mount_lock_test.go"
    "gateway/lease/ownership.go"
    "gateway/lease/ownership_test.go"
    "gateway/lease/sandfs_state.go"
    "gateway/lease/sandfs_state_test.go"
    "gateway/handler/resilience_test.go"
)

for f in "${RESILIENCE_FILES[@]}"; do
    if [[ -f "$ROOT/$f" ]]; then
        tc_pass "File exists: $f"
    else
        tc_fail "File missing: $f"
    fi
done

# Verify key types/functions exist in the code
log_step "Checking resilience type definitions..."
CHECKS=(
    "gateway/lease/mount_lock.go:ErrConcurrentMount"
    "gateway/lease/mount_lock.go:AcquireWait"
    "gateway/lease/mount_lock.go:MountLockWaitTimeout"
    "gateway/lease/sandfs_state.go:ErrSandfsCleaning"
    "gateway/lease/sandfs_state.go:DefaultRetryAfterMs"
    "gateway/lease/ownership.go:ErrOwnerNodeDown"
    "gateway/lease/ownership.go:closeOnce"
    "gateway/lease/ownership.go:OnNodeDisconnect"
    "gateway/lease/ownership.go:OnNodeConnect"
    "gateway/lease/ownership.go:OnNodeHeartbeat"
    "gateway/lease/ownership.go:nodeSandfs"
    "gateway/lease/ownership.go:pendingOwnerRelease"
    "gateway/lease/sticky.go:func (l *Lease) Close()"
    "gateway/handler/auth_resolve.go:resilienceError"
    "gateway/handler/auth_resolve.go:writeResilienceError"
    "gateway/handler/auth_resolve.go:IsTransportError"
    "gateway/handler/execute.go:cleanupAfterFailure"
    "gateway/handler/file.go:cleanupAfterFileFailure"
    "gateway/identity/etcd.go:func (s *EtcdStore) Client()"
)

for check in "${CHECKS[@]}"; do
    file="${check%%:*}"
    symbol="${check##*:}"
    # grep -F: fixed-string match so signatures with '*' (e.g. "func (l *Lease)")
    # are matched literally, not as regex.
    if grep -Fq "$symbol" "$ROOT/$file" 2>/dev/null; then
        tc_pass "Symbol exists: $symbol in $file"
    else
        tc_fail "Symbol missing: $symbol in $file"
    fi
done

# Verify onExpiry panic recovery exists
log_step "Checking onExpiry panic recovery..."
if grep -q "recover()" "$ROOT/gateway/lease/sticky.go"; then
    tc_pass "onExpiry panic recovery (defer recover()) implemented"
else
    tc_fail "onExpiry panic recovery NOT implemented ( missing)"
fi

# Verify writeLoop timeout exists
log_step "Checking gRPC stream write timeout..."
if grep -q "writeSendTimeout" "$ROOT/gateway/stream/server.go"; then
    tc_pass "gRPC stream writeLoop timeout implemented"
else
    tc_fail "gRPC stream writeLoop timeout NOT implemented ( missing)"
fi

# Verify file handler body size limit
log_step "Checking file handler body size limit..."
if grep -q "MaxBytesReader.*MaxFileRequestBodyBytes" "$ROOT/gateway/handler/file.go"; then
    tc_pass "File handler body size limit (50MB, MaxBytesReader) implemented"
else
    tc_fail "File handler body size limit NOT implemented ( missing)"
fi

# Verify execute handler body size limit
log_step "Checking execute handler body size limit..."
if grep -q "MaxBytesReader.*MaxExecuteRequestBodyBytes" "$ROOT/gateway/handler/execute.go"; then
    tc_pass "Execute handler body size limit (10MB, MaxBytesReader) implemented"
else
    tc_fail "Execute handler body size limit NOT implemented ( missing)"
fi

# Verify etcd watch timeout
log_step "Checking etcd watch per-batch timeout..."
if grep -q "30 \* time.Second" "$ROOT/gateway/lease/ownership.go" && grep -q "watchTimer" "$ROOT/gateway/lease/ownership.go"; then
    tc_pass "etcd watch per-batch timeout (30s) implemented"
else
    tc_fail "etcd watch per-batch timeout NOT implemented ( missing)"
fi

# Verify ownership is wired into exec mode (was dead code passing nil).
# NB: wiring lives in gateway/app/exec.go (cmd/main.go was split into app/).
log_step "Checking ownership wired into exec mode..."
if grep -q "NewOwnershipCache" "$ROOT/gateway/app/exec.go" && \
   grep -q "ownership.StartHealthLoop" "$ROOT/gateway/app/exec.go" && \
   grep -q "wireStreamCallbacks(streamSrv, pm, lm, sandlotClient, ownership," "$ROOT/gateway/app/exec.go"; then
    tc_pass "ownership wired into exec mode (NewOwnershipCache + StartHealthLoop + wireStreamCallbacks)"
else
    tc_fail "ownership NOT wired into exec mode - still dead code"
fi

# Verify the orphan-VM release implementation: sandlot cleanup state machine +
# warden countdown + gateway owner-release / presence.
log_step "Checking tolerance-first release implementation..."
if grep -q "ResetSurvivorsToClean" "$ROOT/sandlot/core/readopt.go" && \
   grep -q "CleanupPhaseTolerating" "$ROOT/sandlot/core/runner.go" && \
   grep -q "SaveCleanupState" "$ROOT/sandlot/core/cleanup_state.go"; then
    tc_pass "sandlot tolerance state machine (TOLERATING/CLEANING/DONE) persisted"
else
    tc_fail "sandlot tolerance state machine missing"
fi
if grep -q "spawn_warden_countdown" "$ROOT/warden/src/raw_server.rs" && \
   grep -q "COUNTDOWN_TICK" "$ROOT/warden/src/raw_server.rs" && \
   grep -q "last_heartbeat" "$ROOT/warden/src/raw_server.rs"; then
    tc_pass "warden single countdown (heartbeat-anchored last-resort release)"
else
    tc_fail "warden single countdown missing"
fi
if grep -q "OnNodeDisconnect" "$ROOT/gateway/app/stream.go" && \
   grep -q "OnNodeHeartbeat" "$ROOT/gateway/app/stream.go"; then
    tc_pass "gateway presence key wired (OnNodeConnect/OnNodeDisconnect/OnNodeHeartbeat)"
else
    tc_fail "gateway presence key NOT wired into stream callbacks"
fi
# Verify the timer invariants: ownership AND health keys have NO lease (plain
# keys — health death is judged by last_healthy_ts staleness), T_safe =
# tolerance + warden + margin.
log_step "Checking timer invariants (no ownership/health lease)..."
if ! grep -q "healthLeaseTTL" "$ROOT/gateway/lease/ownership.go" && \
   grep -q "healthRefreshInterval" "$ROOT/gateway/lease/ownership.go" && \
   grep -q "safeMarginSec = 60" "$ROOT/gateway/lease/ownership.go" && \
   ! grep -q "ownershipLeaseTTL" "$ROOT/gateway/lease/ownership.go"; then
    tc_pass "timers: ownership+health have NO lease; health judged by refresh staleness; T_safe = tol+warden+margin"
else
    tc_fail "timer invariants incorrect (a lease is still present, or margins wrong)"
fi

# Verify shared MountLock + SandfsState across handlers (execute+file see the
# same CLEANING state)
log_step "Checking shared MountLock/SandfsState across handlers..."
if grep -q "ml := lease.NewMountLock()" "$ROOT/gateway/app/exec.go" && \
   grep -q "ss := lease.NewSandfsState()" "$ROOT/gateway/app/exec.go"; then
    tc_pass "shared MountLock + SandfsState across handlers"
else
    tc_fail "MountLock/SandfsState not shared across handlers (CLEANING state could be bypassed)"
fi

# Verify warden single countdown has unit tests.
log_step "Checking warden countdown unit tests..."
if grep -q '#\[cfg(test)\]' "$ROOT/warden/src/raw_server.rs" && \
   grep -q 'test_should_exit_vm_expired_and_mounted' "$ROOT/warden/src/raw_server.rs" && \
   grep -q 'test_heartbeat_op_resets_countdown' "$ROOT/warden/src/raw_server.rs"; then
    tc_pass "warden countdown Rust unit tests exist (heartbeat reset / expiry exit)"
else
    tc_fail "warden countdown unit tests missing in raw_server.rs"
fi

# Verify sandlot ResetSurvivorsToClean has unit tests ( trigger 1).
log_step "Checking sandlot ResetSurvivorsToClean unit tests..."
if grep -q 'TestResetSurvivorsToClean_ClearsVolumes' "$ROOT/sandlot/core/monitor_test.go" && \
   grep -q 'TestResetSurvivorsToClean_NilWardenNoPanic' "$ROOT/sandlot/core/monitor_test.go"; then
    tc_pass "sandlot ResetSurvivorsToClean Go unit tests exist (5 tests)"
else
    tc_fail "sandlot ResetSurvivorsToClean unit tests missing"
fi

# Verify sandlot state-machine timing decision has unit tests.
log_step "Checking sandlot state-machine unit tests..."
if [[ -f "$ROOT/sandlot/core/runner_test.go" ]] && \
   grep -q 'TestToleranceElapsed' "$ROOT/sandlot/core/runner_test.go" && \
   grep -q 'TestIsolationRemaining' "$ROOT/sandlot/core/runner_test.go"; then
    tc_pass "sandlot state-machine unit tests exist (toleranceElapsed / isolationRemaining)"
else
    tc_fail "sandlot state-machine unit tests missing"
fi

# ── Phase 4: E2E Integration Tests (optional) ────────────────
if [[ "$E2E" == "true" ]]; then
    log_section "Phase 4: E2E Integration Tests"

    GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
    HUMAN_URL="${HUMAN_URL:-$GATEWAY_URL}"

    log_step "Checking gateway availability at $GATEWAY_URL..."
    if curl -sf "$GATEWAY_URL/health" > /dev/null 2>&1; then
        tc_pass "Gateway is running at $GATEWAY_URL"
    else
        # --e2e was EXPLICITLY requested: a down gateway is a FAILED run, not a
        # silent degrade to unit-only that still exits 0 (the SKIP went into the
        # counter, not the verdict).
        tc_fail "Gateway not running at $GATEWAY_URL — --e2e requested but E2E tests cannot run"
        GATEWAY_URL=""
    fi

    if [[ -n "$GATEWAY_URL" ]]; then
        # Test 1: Health endpoint returns structured response
        log_step "E2E: Testing health endpoint..."
        HEALTH=$(curl -sf "$GATEWAY_URL/health" 2>&1 || echo "FAILED")
        if echo "$HEALTH" | grep -q '"status"'; then
            tc_pass "Health endpoint returns structured response"
        else
            tc_fail "Health endpoint returned unexpected response: $HEALTH"
        fi

        # Test 2: Execute without auth returns 401
        log_step "E2E: Testing execute without auth returns 401..."
        # NB: NO -f here — curl --fail exits 22 on the very 401 we EXPECT (and
        # the `|| echo 000` fallback then overwrites the status), so a correct
        # gateway used to report "000 != 401". Without -f curl still prints
        # %{http_code}; a connection failure prints 000.
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY_URL/agent/execute" -d '{"code":"echo hi"}' 2>&1)
        if [[ "$STATUS" == "401" ]]; then
            tc_pass "Execute without auth returns 401"
        else
            tc_fail "Execute without auth returned $STATUS (expected 401)"
        fi

        # Test 3: Stats endpoint returns pool stats
        log_step "E2E: Testing stats endpoint..."
        STATS=$(curl -sf "$HUMAN_URL/stats" 2>&1 || echo "FAILED")
        if echo "$STATS" | grep -q '"clean_vms"'; then
            tc_pass "Stats endpoint returns pool statistics"
        else
            tc_fail "Stats endpoint returned unexpected response: $STATS"
        fi

        # Test 4: Resilience error structure (need a sandfs to test cleaning state)
        log_step "E2E: Testing resilience error structure..."
        # This would require creating an agent + sandfs + triggering a failure.
        # For now, verify the endpoint structure exists.
        log_skip "Resilience error structure E2E test requires agent setup (run manually)"
    fi
fi

# ── Phase 4: Ownership E2E (etcd required) ────────────────────
if [[ "$E2E" == "true" ]]; then
    log_section "Phase 4: Ownership E2E (etcd coordination)"
    # ownership.sh resolves etcd itself (tc_ensure_etcd: cache → PATH → download).
    log_step "Running ownership E2E tests with real etcd..."
    OWN_OUT=$(mktemp)
    if bash e2e/ownership.sh >"$OWN_OUT" 2>&1; then
        tc_pass "Ownership E2E passed (CAS claim, no-lease persistence, owner-release three-part chain, migrated takeover, presence key, node_id lifecycle, placement semantics, staleness gates)"
    else
        tc_fail "Ownership E2E tests failed"
        sed 's/^/    /' "$OWN_OUT" | tail -40
    fi
    rm -f "$OWN_OUT"
fi

# ── Summary ──────────────────────────────────────────────────
log_section "Summary"
echo ""
echo -e "  ${TC_GREEN}PASS${TC_NC}: ${PASS_COUNT:-0}"
echo -e "  ${TC_RED}FAIL${TC_NC}: ${FAIL_COUNT:-0}"
echo -e "  ${TC_YELLOW}SKIP${TC_NC}: $SKIP"
echo ""

if [[ "${FAIL_COUNT:-0}" -gt 0 ]]; then
    echo -e "${TC_RED}Resilience test suite FAILED${TC_NC}"
    exit 1
else
    echo -e "${TC_GREEN}Resilience test suite PASSED${TC_NC}"
    exit 0
fi
