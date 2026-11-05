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
# build-gate-selftest.sh — pins the build/release supply-chain gates that are
# cheap to test without a network or a real build:
#   - install-deps checksum gate: an UNPINNED etcd version and a checksum
#     MISMATCH are both refused before extraction (behavioral, via
#     --verify-selftest);
#   - Ubuntu template: the base tarball/mirror must be HTTPS and SHA256-pinned,
#     and the apt sources may not carry trusted=yes (static regression pins —
#     the real build is exercised by the release/template drills);
#   - release packager: ALLOW_NO_IPV6_KERNEL cannot skip the kernel gate, and
#     build.sh check + the seccomp census + kernel/build.sh check are present
#     (static regression pins).
# No root/KVM/network required.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0

ok() { echo "  ✓ $1"; PASS=$((PASS + 1)); }
bad() { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

has() { # <file> <needle> <label>
    if grep -q -- "$2" "$1"; then ok "$3"; else bad "$3 (missing pattern: $2)"; fi
}
hasnt() { # <file> <pattern> <label>
    if grep -qE -- "$2" "$1"; then bad "$3 (forbidden pattern found: $2)"; else ok "$3"; fi
}

echo "═══ build-gate-selftest ═══"

if bash "$ROOT/build/install-deps.sh" --verify-selftest >/tmp/build-gate-selftest.out 2>&1; then
    ok "install-deps checksum gate: unpinned version and mismatch refused"
else
    bad "install-deps checksum self-test failed: $(tail -3 /tmp/build-gate-selftest.out | tr '\n' ' ')"
fi
rm -f /tmp/build-gate-selftest.out

UBUNTU="$ROOT/build/build-ubuntu-rootfs.sh"
has "$UBUNTU" "UBUNTU_BASE_URL must be https" "Ubuntu base tarball enforces HTTPS"
has "$UBUNTU" "UBUNTU_BASE_SHA256 is not a lowercase hex SHA256" "Ubuntu base tarball requires a pinned SHA256"
has "$UBUNTU" "base tarball SHA256 mismatch" "Ubuntu base tarball checksum mismatch is refused"
has "$UBUNTU" "UBUNTU_MIRROR must be https" "Ubuntu apt mirror enforces HTTPS"
hasnt "$UBUNTU" '^deb .*trusted=yes' "Ubuntu apt sources carry no trusted=yes"
has "$UBUNTU" '^deb \$UBUNTU_MIRROR' "Ubuntu apt sources use the validated mirror variable"

RELEASE="$ROOT/build/package-release.sh"
has "$RELEASE" "ALLOW_NO_IPV6_KERNEL is ignored" "release packager cannot skip the kernel gate via ALLOW_NO_IPV6_KERNEL"
has "$RELEASE" "Running build.sh check" "release packager runs build.sh check"
has "$RELEASE" "seccomp syscall census FAILED" "release packager gates on the seccomp census"
has "$RELEASE" "kernel/build.sh check" "release packager gates on kernel/build.sh check"

# The census universe must be the pinned file in the repo, not the CI runner's
# linux-libc-dev header: an older runner header makes newer decision rows look
# stale (mseal/*xattrat/listns/...). The freshness scan must also not use
# `head` after `sort` — SIGPIPE under pipefail aborted the release check.
CENSUS="$ROOT/security/seccomp-syscall-census.sh"
UNIVERSE="$ROOT/security/syscall-universe-x86_64.h"
has "$CENSUS" "security/syscall-universe-x86_64.h" "seccomp census uses the vendored pinned universe"
has "$UNIVERSE" "__NR_mseal " "pinned universe contains mseal"
has "$UNIVERSE" "__NR_open_tree_attr " "pinned universe contains open_tree_attr"
has "$UNIVERSE" "__NR_listns " "pinned universe contains listns"
has "$UNIVERSE" "__NR_rseq_slice_yield " "pinned universe contains rseq_slice_yield"
has "$ROOT/build/build.sh" "sort -rn | sed -n '1p'" "build freshness uses sed instead of head (no SIGPIPE)"

echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then
    echo "[FAIL] build-gate-selftest failed"
    exit 1
fi
echo "[OK] build-gate-selftest passed"
