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
# host-id-check.sh — pin the four-value (real/effective/saved/fs) uid/gid
# parser used by security/verify-host-security.sh check 7. Feeds synthetic
# /proc/<pid>/status bodies through the script's SANDSWAP_VERIFY_IDS_PROBE
# mode: a saved-uid 0 or a mismatched fs gid must fail, so reverting the
# verifier to a CapEff-only check cannot pass this suite. No KVM/BPF/root
# needed.
#
# Usage: bash e2e/host-id-check.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFIER="$ROOT/security/verify-host-security.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

probe() { # <status-file> <want-uid> <want-gid>
    SANDSWAP_VERIFY_IDS_PROBE="$1" \
    SANDSWAP_VERIFY_IDS_UID="$2" \
    SANDSWAP_VERIFY_IDS_GID="$3" \
        bash "$VERIFIER" >/dev/null 2>&1
}

expect_ok() { # <fixture> <uid> <gid> <label>
    if probe "$1" "$2" "$3"; then
        echo "  ✓ $4"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $4 (expected pass, got refusal: $(probe "$1" "$2" "$3" 2>&1 || true))"
        FAIL=$((FAIL + 1))
    fi
}

expect_refuse() { # <fixture> <uid> <gid> <label>
    if probe "$1" "$2" "$3"; then
        echo "  ✗ $4 (expected refusal, parser accepted)"
        FAIL=$((FAIL + 1))
    else
        echo "  ✓ $4"
        PASS=$((PASS + 1))
    fi
}

mk() { # <name> <uid-line> <gid-line>
    local f="$TMP/$1"
    printf 'Name:\tsandvmm\n%s\n%s\n' "$2" "$3" > "$f"
    printf '%s' "$f"
}

echo "═══ host-id-check: four-value uid/gid parser ═══"

GOOD=$(mk good $'Uid:\t987\t987\t987\t987' $'Gid:\t987\t987\t987\t987')
expect_ok "$GOOD" 987 987 "all four uid/gid values match"

CUSTOM=$(mk custom $'Uid:\t4242\t4242\t4242\t4242' $'Gid:\t4242\t4242\t4242\t4242')
expect_ok "$CUSTOM" 4242 4242 "the expected identity is the configured one, not a hard-coded 987"
expect_refuse "$CUSTOM" 987 987 "a clean 4242 process is not accepted for a 987 sandvmm"

SAVED_UID=$(mk saved-uid $'Uid:\t987\t987\t0\t987' $'Gid:\t987\t987\t987\t987')
expect_refuse "$SAVED_UID" 987 987 "saved-uid 0 is refused"

SAVED_GID=$(mk saved-gid $'Uid:\t987\t987\t987\t987' $'Gid:\t987\t987\t0\t987')
expect_refuse "$SAVED_GID" 987 987 "saved-gid 0 is refused"

FS_GID=$(mk fs-gid $'Uid:\t987\t987\t987\t987' $'Gid:\t987\t987\t987\t0')
expect_refuse "$FS_GID" 987 987 "fs-gid mismatch is refused"

MALFORMED=$(mk malformed $'Uid:\t987\t987' $'Gid:\t987\t987\t987\t987')
expect_refuse "$MALFORMED" 987 987 "a truncated uid line is refused"

MISSING="$TMP/does-not-exist"
expect_refuse "$MISSING" 987 987 "a missing status file is refused"

echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then
    echo "[FAIL] host-id-check failed"
    exit 1
fi
echo "[OK] host-id-check passed"
