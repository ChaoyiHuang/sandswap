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
# vsockguard-detach.sh — detach the vsockguard BPF LSM program and remove pins.
# Counterpart to vsockguard-attach.sh. After this runs, connect() to the warden
# vsock port is no longer UID-filtered — only run this when tearing down the
# sandlot node or after the test cycle.
# Usage:  sudo bash security/vsockguard-detach.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOADER="${VSOCKGUARD_LOADER:-$ROOT/output/vsockguardctl}"

PIN_DIR="/sys/fs/bpf/vsockguard"
PROG_PIN="$PIN_DIR/prog"
LINK_PIN="$PIN_DIR/link"
MAP_PIN="$PIN_DIR/allowed_uid"
RUN_DIR="${SANDSWAP_RUN_DIR:-/run/sandswap}"
ATTEST="$RUN_DIR/vsockguard.allowed_uid"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root" >&2
    exit 1
fi

if [ ! -e "$LINK_PIN" ]; then
    echo "vsockguard not attached (no pin at $LINK_PIN). Nothing to do."
    exit 0
fi

"$LOADER" detach "$LINK_PIN" "$PROG_PIN" "$MAP_PIN"
# The attestation must not outlive the pin: the sandlot would otherwise start
# on a guard that is no longer attached.
rm -f "$ATTEST"
# Best-effort: remove the now-empty pin dir.
rmdir "$PIN_DIR" 2>/dev/null || true
echo "vsockguard detached (attestation removed)."
