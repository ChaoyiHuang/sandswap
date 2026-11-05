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
# vsockguard-verify-modes.sh — pin the verifier's SAFE refusal modes without
# touching a production pin (VSOCKGUARD_PIN_DIR points the script at a scratch
# directory):
#   1. no pin + default mode  → FAIL "not attached" (never attach implicitly)
#   2. pin present + --self-test → FAIL "refusing --self-test" (never replace
#      a production pin)
#   3. no pin + --self-test without artifacts → FAIL "artifacts missing"
#      (never attach a half-built program)
# The old attach-uid0-then-detach flow would pass none of these; a revert to it
# turns this suite red. Requires root only because the verifier checks it.
#
# Usage: sudo bash e2e/vsockguard-verify-modes.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFIER="$ROOT/security/vsockguard-verify.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

run_verify() { # <pin-dir> <extra args...>
    local pin="$1"; shift
    VSOCKGUARD_PIN_DIR="$pin" bash "$VERIFIER" "$@" >/tmp/vsockguard-verify-modes.out 2>&1 || true
}

expect_refusal() { # <label> <pin-dir> <needle> <extra args...>
    local label="$1" pin="$2" needle="$3"; shift 3
    run_verify "$pin" "$@"
    if grep -q "$needle" /tmp/vsockguard-verify-modes.out; then
        echo "  ✓ $label"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $label (missing '$needle'): $(tail -3 /tmp/vsockguard-verify-modes.out | tr '\n' ' ')"
        FAIL=$((FAIL + 1))
    fi
}

echo "═══ vsockguard-verify safe refusal modes ═══"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "  skip: the verifier requires root (run this test as root)"
    exit 0
fi
if ! grep -qE '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
    echo "  skip: the bpf LSM is not active on this host"
    exit 0
fi

mkdir -p "$TMP/no-pin"
expect_refusal "no pin + default mode refuses (no implicit attach)" \
    "$TMP/no-pin" "not attached"

mkdir -p "$TMP/has-pin"
: > "$TMP/has-pin/link"
expect_refusal "production pin + --self-test refuses (never replaces it)" \
    "$TMP/has-pin" "refusing --self-test" --self-test

export VSOCKGUARD_OBJ="$TMP/no-such-object"
expect_refusal "no pin + --self-test without artifacts refuses" \
    "$TMP/no-pin" "vsockguard artifacts missing" --self-test
unset VSOCKGUARD_OBJ

rm -f /tmp/vsockguard-verify-modes.out
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then
    echo "[FAIL] vsockguard-verify-modes failed"
    exit 1
fi
echo "[OK] vsockguard-verify-modes passed"
