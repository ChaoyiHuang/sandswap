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
# vsockguard-attach.sh — load + attach the vsockguard BPF LSM program.
# Attaches a BPF LSM hook that denies connect() to AF_VSOCK port 1024 (the
# warden port) for every UID except <uid> (the sandlot service UID). This closes
# the local-user → warden attack path on a multi-user sandlot host.
# Usage:  sudo bash security/vsockguard-attach.sh [--uid <uid> | <uid>]
#   With no argument the allowed uid is the sandlot SERVICE ACCOUNT's uid
#   (the only identity that runs the warden client). It is never the invoking
#   operator's uid — an attach for the wrong identity silently fences the real
#   sandlot out of its own warden. Pass an explicit uid only for a test/dev
#   identity that is genuinely the warden client.
# Prereqs: the `bpf` LSM must be active (cat /sys/kernel/security/lsm lists
# 'bpf'). If not, run security/setup-bpf-lsm.sh once and reboot. The loader
# refuses to attach otherwise (a silent no-op is worse than a loud failure).
# Idempotent: re-running first detaches any existing attachment.
# Counterpart: security/vsockguard-detach.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OBJ="${VSOCKGUARD_OBJ:-$ROOT/output/vsockguard.bpf.o}"
LOADER="${VSOCKGUARD_LOADER:-$ROOT/output/vsockguardctl}"

PIN_DIR="/sys/fs/bpf/vsockguard"
PROG_PIN="$PIN_DIR/prog"
LINK_PIN="$PIN_DIR/link"
MAP_PIN="$PIN_DIR/allowed_uid"
# The sandlot (service uid) cannot read bpffs (/sys/fs/bpf is root-only), so
# this root-run tool writes the attestation it validates at startup. The
# systemd unit re-runs the same check in ExecStartPre; the file is removed by
# detach.
RUN_DIR="${SANDSWAP_RUN_DIR:-/run/sandswap}"
ATTEST="$RUN_DIR/vsockguard.allowed_uid"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (needs CAP_BPF + CAP_SYS_ADMIN to load BPF)" >&2
    exit 1
fi

# Resolve the allowed uid: explicit `--uid N` / positional N > the sandlot
# service account's uid. There is deliberately NO SUDO_UID fallback: the
# invoking operator's uid is never the identity that runs the warden client,
# and attaching for the wrong uid silently leaves the real sandlot fenced out
# of its own warden (or the operator admitted). When the sandlot account
# cannot be resolved, fail and require an explicit uid — never guess.
UID_ALLOW=""
if [ "${1:-}" = "--uid" ]; then
    UID_ALLOW="${2:-}"
    shift 2 2>/dev/null || true
elif [ $# -ge 1 ]; then
    UID_ALLOW="$1"
fi
if [ -z "$UID_ALLOW" ]; then
    UID_ALLOW="${SANDSWAP_VSOCKGUARD_UID:-}"
fi
if [ -z "$UID_ALLOW" ]; then
    UID_ALLOW="$(id -u "${SS_SERVICE_USER_SL:-sandlot}" 2>/dev/null || true)"
fi
if [ -z "$UID_ALLOW" ]; then
    echo "error: cannot resolve the sandlot service account (${SS_SERVICE_USER_SL:-sandlot});" >&2
    echo "       pass the identity explicitly: $0 --uid <sandlot-uid>" >&2
    exit 1
fi
case "$UID_ALLOW" in
    ''|*[!0-9]*) echo "error: allowed uid '$UID_ALLOW' is not a number" >&2; exit 1 ;;
esac

if [ ! -f "$OBJ" ]; then
    echo "error: $OBJ not found. Run: bash build/build.sh vsockguard" >&2
    exit 1
fi
if [ ! -x "$LOADER" ]; then
    echo "error: $LOADER not found. Run: bash build/build.sh vsockguard" >&2
    exit 1
fi

mkdir -p "$PIN_DIR"

# Idempotent: detach any prior attachment first.
if [ -e "$LINK_PIN" ]; then
    "$LOADER" detach "$LINK_PIN" "$PROG_PIN" "$MAP_PIN" >/dev/null 2>&1 || true
fi

echo "Attaching vsockguard (allowed uid=$UID_ALLOW)..."
"$LOADER" attach "$OBJ" "$UID_ALLOW" "$PROG_PIN" "$LINK_PIN" "$MAP_PIN"

# Attestation for the non-root sandlot: root-owned, non-writable, written
# only after a successful attach. /run is tmpfs, so a reboot clears it and
# the unit's ExecStartPre re-validates the live pin before every start.
mkdir -p "$RUN_DIR"
tmp="$ATTEST.tmp.$$"
printf '%s\n' "$UID_ALLOW" > "$tmp"
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$ATTEST"
echo "vsockguard attestation written: $ATTEST (allowed_uid=$UID_ALLOW)"
