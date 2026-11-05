#!/usr/bin/env bash
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
# setup-network.sh — one-time host setup for Sandswap microVM outbound networking
# (bridge + kernel NAT backend).
# Creates a host bridge, enables IP forwarding, and installs a single nftables
# masquerade rule so pooled microVMs (each with a virtio-net TAP enslaved to
# the bridge) can reach the outside world. No dnsmasq, no per-VM daemon —
# microVMs use static IPs assigned by sandlot; the TAP lifecycle is owned by
# sandlot/VMM, this script only sets up the shared bridge + NAT once.
# Idempotent: safe to re-run. Override defaults via env vars:
#   BRIDGE=br-sandswap SUBNET=10.188.0.0/16 GATEWAY=10.188.0.1 UPLINK=eth0 \
#     bash deploy/setup-network.sh
# Run once per host (and on boot if the bridge/NAT do not persist).

set -euo pipefail

# ──── Parameters ────
#   BRIDGE=br-sandswap SUBNET=10.188.0.0/16 GATEWAY=10.188.0.1 UPLINK=eth0 \
#     bash deploy/setup-network.sh
#   EXTRA_ADDRS — extra gateway CIDRs for a host running SEVERAL sandlot
#   instances (each gets its own subnet, so the bridge must answer ARP for
#   every configured gateway).
# The implementation is ss_host_network_setup (common/sh/runtime.sh) — the SAME
# function the e2e suite and the deploy scripts call, so a host prepped by any
# of them has identical bridge/NAT/forwarding state. SS_NET_PERSIST=1 adds the
# reboot persistence this script has always done.
#
# Two layouts must resolve, and BOTH are shipped by the installers:
#   * the repo tree (`deploy/../common/sh/runtime.sh` beside this copy);
#   * the INSTALLED copy (/usr/local/bin/sandswap-setup-network, run by
#     sandswap-network.service at boot, where the repo tree may not exist):
#     the installers place the library at /usr/local/lib/sandswap/runtime.sh.
# A copy that predates the library must fail with a named diagnosis, never a
# bare bash "No such file or directory" (that failure was invisible at boot).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_CANDIDATES=("$ROOT/common/sh/runtime.sh" "${SANDSWAP_SH_LIB_DIR:-/usr/local/lib/sandswap}/runtime.sh")
RUNTIME=""
for _cand in "${RUNTIME_CANDIDATES[@]}"; do
    if [[ -f "$_cand" ]]; then
        RUNTIME="$_cand"
        break
    fi
done
if [[ -z "$RUNTIME" ]]; then
    echo "sandswap-setup-network: shared runtime not found (looked at ${RUNTIME_CANDIDATES[0]}, ${RUNTIME_CANDIDATES[1]}) — reinstall or set SANDSWAP_SH_LIB_DIR" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$RUNTIME"

BRIDGE="${BRIDGE:-br-sandswap}"
SUBNET="${SUBNET:-10.188.0.0/16}"
GATEWAY="${GATEWAY:-10.188.0.1}"
UPLINK="${UPLINK:-$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')}"

if [ -z "$UPLINK" ]; then
    echo "error: could not determine default-route uplink interface." >&2
    echo "set UPLINK=<iface> explicitly." >&2
    exit 1
fi

echo "Sandswap host networking:"
echo "  bridge : $BRIDGE  ($GATEWAY/${SUBNET##*/})"
echo "  subnet : $SUBNET"
echo "  uplink : $UPLINK"

SS_NET_PERSIST=1 ss_host_network_setup "$BRIDGE" "$SUBNET" "$GATEWAY" "$UPLINK"

echo "done. VMs on $SUBNET will be NATed out via $UPLINK."
echo "verify:  ip -br link show $BRIDGE ; sysctl net.ipv4.ip_forward ; nft list table inet sandswap"
