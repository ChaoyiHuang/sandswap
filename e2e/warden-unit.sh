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
# warden-unit.sh — run the warden (Rust) unit suite as a suite-visible step.
# The warden binary's build script already gates on `cargo test`, but nothing
# else in the e2e world executes the Rust tests — without this entry a broken
# or rotted warden test is invisible in the run-all summary. This script:
#   1. runs the CI suite (cargo test — unprivileged-safe),
#   2. runs the root-gated #[ignore] suite (cargo test -- --ignored) when
#      running as root (the chroot/mount/seccomp machinery tests).
# No KVM, no deployment — same tier as resilience.sh's Go unit tests.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

# run_cargo_suite <label> <min_passed> [cargo test args...] — run a cargo suite
# and enforce a parsed floor. `cargo test` exits 0 when ZERO tests ran (every
# test #[ignore]d, or every test renamed/removed): the rc alone cannot tell
# "all green" from "nothing ran" — the same vacuous-pass class tc_run_go_suite
# guards with TC_MIN_TESTS.
run_cargo_suite() {
    local label="$1" floor="$2"; shift 2
    local out rc=0 npass
    out=$( (cd "$ROOT/warden" && cargo test --quiet "$@") 2>&1 ) || rc=$?
    printf '%s\n' "$out" | tail -5
    if [[ $rc -ne 0 ]]; then
        fail "$label FAILED (cd warden && cargo test $*)"
        return
    fi
    npass=$(printf '%s\n' "$out" | grep -oE '[0-9]+ passed' | awk '{s+=$1} END {print s+0}')
    if [[ "${npass:-0}" -lt "$floor" ]]; then
        fail "$label: only ${npass:-0} test(s) passed (< floor $floor) — a zero/renamed/all-ignored suite must not read green"
    else
        pass "$label green ($npass tests passed)"
    fi
}

log_step "warden unit tests: CI suite (cargo test)"
# Floor, not an exact count (~194 non-ignored tests today): a legitimate test
# removal must not false-fail, a collapsed suite must.
run_cargo_suite "warden CI unit suite" "${WARDEN_CI_MIN:-150}"

if [[ "$(id -u)" == "0" ]]; then
    log_step "warden unit tests: root-gated suite (cargo test -- --ignored)"
    # The 13 root-gated #[ignore] tests (chroot/mount/seccomp machinery).
    run_cargo_suite "warden root-gated unit suite" "${WARDEN_ROOT_MIN:-5}" -- --ignored
else
    log_warn "not root — skipping root-gated (#[ignore]) warden tests"
fi

log_step "warden unit tests: done"

# ── Verdict ─────────────────────────────────────────────────────────
# e2e/run-all.sh judges this script by EXIT CODE alone — a failed cargo
# suite recorded via `fail` must become the exit status (a false-green class).
if [[ "${FAIL_COUNT:-0}" -gt 0 ]]; then
    log_error "warden unit tests FAILED ($FAIL_COUNT suite(s))"
    exit 1
fi
log_pass "warden unit tests PASSED (${PASS_COUNT:-0} suite(s))"
exit 0
