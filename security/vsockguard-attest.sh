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
# vsockguard-attest.sh — write /run/sandswap/vsockguard.allowed_uid from the
# LIVE pinned map. Run as root by the sandlot systemd unit's ExecStartPre (the
# sandlot service uid cannot read bpffs: /sys/fs/bpf is root-only). A missing
# pin or unreadable map exits non-zero, so the unit refuses to start instead of
# serving without the guard. Installed as
# /usr/local/bin/sandswap-vsockguard-attest.
#
# The file is root-owned 0644 and lives in the sticky /run/sandswap, so the
# sandlot group can read but not replace it. /run is tmpfs: a reboot clears it
# and this helper rewrites it before every start.
set -euo pipefail

PIN="${VSOCKGUARD_MAP_PIN:-/sys/fs/bpf/vsockguard/allowed_uid}"
CTL="${VSOCKGUARD_LOADER:-/usr/local/bin/vsockguardctl}"
RUN_DIR="${SANDSWAP_RUN_DIR:-/run/sandswap}"
ATTEST="$RUN_DIR/vsockguard.allowed_uid"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "vsockguard-attest: must run as root" >&2
    exit 1
fi
if [[ ! -e "$PIN" ]]; then
    echo "vsockguard-attest: no pin at $PIN — attach the guard (security/vsockguard-attach.sh) before starting the sandlot" >&2
    exit 1
fi
if [[ ! -x "$CTL" ]]; then
    echo "vsockguard-attest: $CTL is missing or not executable" >&2
    exit 1
fi
allowed="$("$CTL" status "$PIN")"
if [[ ! "$allowed" =~ ^[0-9]+$ ]]; then
    echo "vsockguard-attest: cannot read the allowed uid from $PIN (got '${allowed:-}')" >&2
    exit 1
fi

mkdir -p "$RUN_DIR"
tmp="$RUN_DIR/.vsockguard.$$"
printf '%s\n' "$allowed" > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$ATTEST"
echo "vsockguard-attest: wrote $ATTEST (allowed_uid=$allowed)"
