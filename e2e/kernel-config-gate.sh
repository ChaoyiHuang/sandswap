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
# kernel-config-gate.sh — unit test for kernel/build.sh's guest-kernel
# attack-surface gate. No root, KVM, kernel build, or network required: the
# gate is exercised against synthetic .config files.
#
# It pins:
#   - a policy-compliant config passes;
#   - an enforced-disabled symbol re-enabled (=y or =m) FAILS, naming it;
#   - a required symbol missing (=n / absent) FAILS, naming it.
#
# Usage: bash e2e/kernel-config-gate.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/kernel/build.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sandswap-kcfg-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
pass() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }

# The required set mirrors kernel/build.sh's KERNEL_REQUIRED_OPTS; the
# disabled set mirrors KERNEL_DISABLED_OPTS. A drift in either list makes the
# "good" config here fail the gate — a deliberate tripwire that sends the
# maintainer to this file (and build.sh) rather than silently weakening the
# test.
write_good() {
    local f="$1"
    : > "$f"
    for opt in CONFIG_VIRTIO_FS CONFIG_FUSE_FS CONFIG_VIRTIO_NET \
               CONFIG_VIRTIO_CONSOLE CONFIG_VSOCKETS CONFIG_VIRTIO_PCI \
               CONFIG_IPV6 CONFIG_INET_DIAG CONFIG_INET_DIAG_DESTROY \
               CONFIG_HARDENED_USERCOPY CONFIG_HARDENED_USERCOPY_DEFAULT_ON \
               CONFIG_KMALLOC_PARTITION_CACHES CONFIG_KMALLOC_PARTITION_RANDOM \
               CONFIG_INIT_ON_ALLOC_DEFAULT_ON CONFIG_INIT_ON_FREE_DEFAULT_ON \
               CONFIG_STRICT_KERNEL_RWX CONFIG_X86_KERNEL_IBT \
               CONFIG_RANDOMIZE_BASE CONFIG_VMAP_STACK \
               CONFIG_STACKPROTECTOR CONFIG_FORTIFY_SOURCE \
               CONFIG_SLAB_FREELIST_HARDENED CONFIG_SLAB_FREELIST_RANDOM \
               CONFIG_MITIGATION_PAGE_TABLE_ISOLATION CONFIG_X86_UMIP; do
        printf '%s=y\n' "$opt" >> "$f"
    done
    for opt in CONFIG_USER_NS CONFIG_TUN CONFIG_VETH CONFIG_KVM \
               CONFIG_DEBUG_FS CONFIG_USERFAULTFD CONFIG_IO_URING \
               CONFIG_BPF_SYSCALL CONFIG_CGROUP_BPF \
               CONFIG_OVERLAY_FS CONFIG_POSIX_MQUEUE CONFIG_VSOCKETS_DIAG \
               CONFIG_DEVMEM CONFIG_X86_MSR CONFIG_PROC_KCORE \
               CONFIG_FUSE_DAX CONFIG_FUSE_PASSTHROUGH CONFIG_FUSE_IO_URING \
               CONFIG_PACKET CONFIG_ZSWAP CONFIG_ZRAM CONFIG_ZSMALLOC \
               CONFIG_ZSMALLOC_STAT CONFIG_IKCONFIG CONFIG_IKCONFIG_PROC; do
        printf '# %s is not set\n' "$opt" >> "$f"
    done
}

run_gate() { # run_gate <config> -> rc
    bash "$BUILD" config-check "$1" >"$WORK/out" 2>"$WORK/err"
}

echo "=== kernel config gate unit test ==="

GOOD="$WORK/good.config"
write_good "$GOOD"
if run_gate "$GOOD"; then
    pass "policy-compliant config accepted"
else
    fail "policy-compliant config rejected: $(cat "$WORK/err")"
fi

# The memory-hardening baseline is part of the required set: a config missing
# one INIT_ON_* symbol (the KERNEL_INIT_HARDENING selector's units) must be
# refused BY NAME.
MISSING_HARDENING="$WORK/no-initfree.config"
write_good "$MISSING_HARDENING"
grep -v 'CONFIG_INIT_ON_FREE_DEFAULT_ON' "$MISSING_HARDENING" > "$MISSING_HARDENING.tmp" && mv "$MISSING_HARDENING.tmp" "$MISSING_HARDENING"
if run_gate "$MISSING_HARDENING"; then
    fail "missing CONFIG_INIT_ON_FREE_DEFAULT_ON was accepted"
else
    if grep -q "CONFIG_INIT_ON_FREE_DEFAULT_ON" "$WORK/err"; then
        pass "missing INIT_ON_FREE refused and named"
    else
        fail "missing INIT_ON_FREE refused without naming it: $(cat "$WORK/err")"
    fi
fi

DIRTY="$WORK/userns.config"
write_good "$DIRTY"
printf 'CONFIG_USER_NS=y\n' >> "$DIRTY"
if run_gate "$DIRTY"; then
    fail "re-enabled CONFIG_USER_NS was accepted"
else
    if grep -q CONFIG_USER_NS "$WORK/err"; then
        pass "re-enabled CONFIG_USER_NS rejected and named"
    else
        fail "CONFIG_USER_NS rejected without naming it: $(cat "$WORK/err")"
    fi
fi

MODULE="$WORK/packet-module.config"
write_good "$MODULE"
printf 'CONFIG_PACKET=m\n' >> "$MODULE"
if run_gate "$MODULE"; then
    fail "=m spelling of a disabled symbol was accepted"
else
    if grep -q CONFIG_PACKET "$WORK/err"; then
        pass "=m spelling of CONFIG_PACKET rejected and named"
    else
        fail "CONFIG_PACKET rejected without naming it"
    fi
fi

MISSING="$WORK/no-virtiofs.config"
write_good "$MISSING"
sed -i 's/^CONFIG_VIRTIO_FS=y/# CONFIG_VIRTIO_FS is not set/' "$MISSING"
if run_gate "$MISSING"; then
    fail "missing required CONFIG_VIRTIO_FS was accepted"
else
    if grep -q CONFIG_VIRTIO_FS "$WORK/err"; then
        pass "missing required CONFIG_VIRTIO_FS rejected and named"
    else
        fail "missing CONFIG_VIRTIO_FS rejected without naming it: $(cat "$WORK/err")"
    fi
fi

# The gate must accept a config where a required symbol appears alongside the
# policy lines in any order (the real .config is sorted, but a hand-edited
# dev config may not be).
echo "=== summary: $PASS pass, $FAIL fail ==="
if [[ "$FAIL" -gt 0 ]]; then
    echo "[FAIL] kernel config gate unit test FAILED"
    exit 1
fi
echo "[OK] kernel config gate unit test PASSED"
