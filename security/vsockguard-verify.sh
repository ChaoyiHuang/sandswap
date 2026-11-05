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
# vsockguard-verify.sh — verify the vsockguard BPF LSM hook actually DENIES
# connect() to AF_VSOCK port 1024 for a non-allowed UID.
#
# DEFAULT IS READ-ONLY: it reads the allowed_uid from the EXISTING pinned map
# and probes the hook with that uid; it never attaches or detaches a
# production pin. Run it on a deployed node without touching the protection.
#
# --self-test attaches a temporary pin ONLY when no pin exists, probes it, and
# detaches only the pin it created. It refuses to run when a production pin is
# already present.
#
# The probe connects to CID 2 (VMADDR_CID_HOST), port 1024. Nothing listens
# there, so an ALLOWED connect proceeds past the hook to the transport lookup
# and fails with ENODEV/ECONNREFUSED — the point is it is NOT EPERM. A DENIED
# connect returns EPERM from the LSM hook before the transport is touched.
#
# Usage: sudo bash security/vsockguard-verify.sh [--self-test [--uid N]]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOADER="${VSOCKGUARD_LOADER:-$ROOT/output/vsockguardctl}"
OBJ="${VSOCKGUARD_OBJ:-$ROOT/output/vsockguard.bpf.o}"

PIN_DIR="${VSOCKGUARD_PIN_DIR:-/sys/fs/bpf/vsockguard}"
PROG_PIN="$PIN_DIR/prog"
LINK_PIN="$PIN_DIR/link"
MAP_PIN="$PIN_DIR/allowed_uid"

SELF_TEST=0
SELF_UID=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --self-test) SELF_TEST=1; shift ;;
        --uid) SELF_UID="${2:?--uid requires a number}"; shift 2 ;;
        -h|--help)
            echo "usage: sudo bash $0 [--self-test [--uid N]]"
            echo "  (default)   read the existing pin and probe it; never attach/detach"
            echo "  --self-test attach a temporary pin only when none exists (uid N, default 0)"
            exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root" >&2; exit 1
fi

echo "=== 1. check bpf LSM active ==="
if grep -qE '(^|,)bpf(,|$)' /sys/kernel/security/lsm; then
    echo "  OK: $(cat /sys/kernel/security/lsm)"
else
    echo "  FAIL: bpf not in /sys/kernel/security/lsm"
    echo "  Run: sudo bash security/setup-bpf-lsm.sh && sudo reboot"
    exit 1
fi

CREATED=0
ALLOW_UID=""
if [[ -e "$LINK_PIN" ]]; then
    if [[ "$SELF_TEST" -eq 1 ]]; then
        echo "  FAIL: a vsockguard pin already exists at $LINK_PIN; refusing --self-test (it would replace production protection)" >&2
        exit 1
    fi
    ALLOW_UID="$("$LOADER" status "$MAP_PIN" 2>/dev/null | head -1 || true)"
    if [[ -z "$ALLOW_UID" ]]; then
        echo "  FAIL: vsockguard is pinned but its allowed_uid map cannot be read ($MAP_PIN)" >&2
        exit 1
    fi
    echo "=== 2. using existing pin (allowed_uid=$ALLOW_UID); no attach/detach ==="
else
    if [[ "$SELF_TEST" -eq 0 ]]; then
        echo "  FAIL: vsockguard is not attached (no pin at $LINK_PIN)" >&2
        echo "  Attach it through the deployment (baremetal: security/vsockguard-attach.sh <sandlot-uid>; k8s: the host-setup unit)." >&2
        echo "  To test the program on a host with no production pin: $0 --self-test [--uid N]" >&2
        exit 1
    fi
    [[ -f "$OBJ" && -x "$LOADER" ]] || { echo "  FAIL: vsockguard artifacts missing (run: bash build/build.sh vsockguard)" >&2; exit 1; }
    echo "=== 2. self-test: no pin present; attaching a temporary pin (allowed_uid=$SELF_UID) ==="
    bash "$ROOT/security/vsockguard-attach.sh" "$SELF_UID"
    CREATED=1
    ALLOW_UID="$SELF_UID"
    trap 'if [[ "$CREATED" -eq 1 ]]; then bash "$ROOT/security/vsockguard-detach.sh" >/dev/null 2>&1 || true; fi' EXIT
fi

echo "=== 3. build AF_VSOCK connect probe ==="
# Use /var/tmp (not /tmp) — /tmp is often noexec/nodev on hardened hosts and
# the probe must be executable by the non-allowed uids too.
PROBE_DIR="$(mktemp -d -p /var/tmp)"
PROBE="$PROBE_DIR/vsgtest"
trap 'rm -rf "$PROBE_DIR"; if [[ "$CREATED" -eq 1 ]]; then bash "$ROOT/security/vsockguard-detach.sh" >/dev/null 2>&1 || true; fi' EXIT
cat > "$PROBE.c" <<'PROBE_EOF'
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
int main(void){
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 2; }
    struct sockaddr_vm sa = {0};
    sa.svm_family = AF_VSOCK; sa.svm_cid = 2; sa.svm_port = 1024;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        const char *name = (errno == EPERM) ? "EPERM"
                         : (errno == EACCES) ? "EACCES" : "OTHER";
        int denied = (errno == EPERM || errno == EACCES);
        printf("connect_errno=%d name=%s denied=%d\n", errno, name, denied);
        return denied ? 10 : 0;
    }
    printf("connected\n"); return 0;
}
PROBE_EOF
gcc -O2 -o "$PROBE" "$PROBE.c"
chmod 755 "$PROBE_DIR" "$PROBE"

run_as_uid() {
    local uid="$1"; shift
    if [[ "$uid" -eq 0 ]]; then "$@"; return $?; fi
    local name gid
    name="$(getent passwd "$uid" | cut -d: -f1)"
    gid="$(getent passwd "$uid" | cut -d: -f4)"
    [[ -n "$gid" ]] || gid="$uid"
    if command -v setpriv >/dev/null 2>&1; then
        setpriv --reuid="$uid" --regid="$gid" --clear-groups -- "$@"
    elif [[ -n "$name" ]] && command -v runuser >/dev/null 2>&1; then
        runuser -u "$name" -- "$@"
    else
        echo "no setpriv/runuser to switch to uid $uid" >&2
        return 125
    fi
}

echo "=== 4. probe as allowed uid ($ALLOW_UID) → expect NOT denied ==="
allow_out="$(run_as_uid "$ALLOW_UID" "$PROBE" 2>&1 || true)"
echo "  allowed: $allow_out"
allow_denied=0
echo "$allow_out" | grep -q "denied=1" && allow_denied=1
if echo "$allow_out" | grep -q "socket:"; then
    echo "  FAIL: allowed uid $ALLOW_UID cannot open AF_VSOCK ($allow_out) — check /dev/vsock ownership/mode" >&2
    allow_denied=2
fi

echo "=== 5. probe as nobody (uid 65534, denied) → expect EPERM/EACCES ==="
nobody_out="$(run_as_uid 65534 "$PROBE" 2>&1 || true)"
echo "  nobody:  $nobody_out"
nobody_denied=0
echo "$nobody_out" | grep -q "denied=1" && nobody_denied=1

echo "=== 5b. probe as sandvmm (the VMM identity, denied) → must NEVER reach the warden port ==="
sandvmm_denied=1
if id sandvmm >/dev/null 2>&1; then
    vm_uid="$(id -u sandvmm)"
    if [[ "$vm_uid" == "$ALLOW_UID" ]]; then
        echo "  sandvmm is the allowed uid — skipped (unexpected configuration)" >&2
    else
        vm_out="$(run_as_uid "$vm_uid" "$PROBE" 2>&1 || true)"
        echo "  sandvmm: $vm_out"
        sandvmm_denied=0
        echo "$vm_out" | grep -q "denied=1" && sandvmm_denied=1
    fi
else
    echo "  sandvmm account absent — skipped (host prep not run)"
fi

echo ""
echo "=== RESULT ==="
if [[ "$CREATED" -eq 1 ]]; then
    echo "  (temporary self-test pin; it will be detached on exit)"
else
    echo "  (read-only check of the existing production pin; nothing was attached/detached)"
fi
if [[ "$allow_denied" -eq 0 && "$nobody_denied" -eq 1 && "$sandvmm_denied" -eq 1 ]]; then
    echo "✅ PASS: allowed uid ($ALLOW_UID) NOT denied, non-allowed uids DENIED with EPERM."
    echo "   vsockguard is enforcing."
    exit 0
fi
echo "❌ FAIL: allowed_denied=$allow_denied nobody_denied=$nobody_denied sandvmm_denied=$sandvmm_denied"
[[ "$allow_denied" -eq 1 ]] && echo "   - the allowed uid was WRONGLY denied (hook too broad?)"
[[ "$allow_denied" -eq 2 ]] && echo "   - the allowed uid could not even open AF_VSOCK (device ownership/mode)"
[[ "$nobody_denied" -eq 0 ]] && echo "   - nobody was NOT denied (hook not firing — bpf LSM really active?)"
[[ "$sandvmm_denied" -eq 0 ]] && echo "   - sandvmm was NOT denied — the VMM identity must never reach the warden port"
exit 1
