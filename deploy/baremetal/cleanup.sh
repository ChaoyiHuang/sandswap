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
# cleanup.sh — Clean all Sandswap bare-metal processes and host state.
# Removes everything left by a previous e2e/single-node-multi-agent.sh or
# deploy-single-node.sh run so the next deployment starts from a
# clean slate. Safe to run when nothing is deployed (all steps are
# best-effort / || true).
# What it cleans:
#   1. All sandswap processes (sandvmm, sandlot, gateway, boxout, etcd)
#   2. vsockguard BPF pins
#   3. Host TAP devices + network bridge (br-sandswap) + nftables table
#   4. Overlay mounts under /var/lib/sandswap/volumes
#   5. Runtime state (/run/sandswap, /var/lib/sandswap, logs)
#   6. Stale udev rules from previous deploys
#   7. Sysctl file (/etc/sysctl.d/99-sandswap.conf)
#   8. Etcd data directory
#   1b. /etc/hosts pins (sandswap.local / stream / gateway FQDN)
# What it does NOT clean (by design):
#   - Etcd binary (/tmp/etcd-v3.6.13-linux-amd64/) — expensive to re-download
#   - sandlot service account — one-time host setup
#   - /dev/net/tun device node — host-level requirement
#   - vhost_vsock kernel module — host-level requirement
# Usage:
#   sudo bash deploy/baremetal/cleanup.sh
# Called automatically by e2e/single-node-multi-agent.sh before deploying.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Must be root for BPF, overlay unmount, /run cleanup, etc.
if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root (sudo)" >&2
    exit 1
fi

echo "═══ Sandswap Bare-Metal Cleanup ═══"
echo "  Host: $(uname -n)"
echo ""

# ── 0. Stop + disable systemd services FIRST ─────────────────────────
# The units use Restart=on-failure: killing the process alone would just have
# systemd respawn it (and it would reconnect to the next deployment). Stop and
# disable before killing.
echo "[0/9] Systemd services"
source "$ROOT/deploy/baremetal/common.sh"
# deploy-lib (side-effect ledger) — deploy/test scripts record every host
# mutation; replaying here reverses whatever a CRASHED run left behind.
source "$ROOT/deploy/baremetal/deploy-lib.sh"
sandswap_stop_services

# ── 1. Kill all sandswap processes ───────────────────────────────────
echo "[1/9] Processes"
killed=0
# Match the full command line — comm names are truncated to 15 chars
# ("sandswap-sandvmm" -> "sandswap-sandvm"), so pkill -x by bare name misses them.
# IMPORTANT: -f patterns must stay SPECIFIC. A bare -f 'etcd'/'boxout' matches
# every unrelated process whose command line merely contains the word (editors,
# invoking shells, test scripts) and kills them.
for proc in 'sandswap-sandvmm' 'sandswap-sandlot' 'sandswap-gateway' 'sandns' 'sandswap-boxout'; do
    # path-scoped — a cmdline merely CONTAINING the name is never killed.
    pids="$(pgrep -f "/usr/local/bin/$proc" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
        echo "  Killing $proc: $pids"
        echo "$pids" | xargs -r kill -9 2>/dev/null || true
        killed=$((killed + 1))
    fi
done
# kill ONLY sandswap-managed processes — never a foreign etcd (the
# docs explicitly support pointing at an existing cluster via etcd.endpoints,
# and this host's own k3s etcd matched the old `pgrep -x etcd`). Scope:
#   (a) processes running OUR binaries (path-scoped -f match), and
#   (b) the port sweep below, restricted to ports whose listener belongs to
#       one of our binaries (checked via the /proc/<pid>/exe path) — a foreign
#       service on :2379 is left alone.
for proc in sandswap-gateway sandswap-sandlot sandswap-sandvmm sandns sandswap-boxout; do
    pids="$(pgrep -f "/usr/local/bin/$proc" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
        echo "  Killing $proc: $pids"
        echo "$pids" | xargs -r kill -9 2>/dev/null || true
    fi
done
# Port stragglers — only when the listener is one of OUR binaries. NOTE: :53
# is deliberately NOT in this list (systemd-resolved owns it on most hosts;
# sandns is already matched above).
for port in 3000 3001 3100 9998 9997 2379; do
    pids="$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u || true)"
    for pid in $pids; do
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
        case "$exe" in
            */sandswap-gateway|*/sandswap-sandlot|*/sandswap-sandvmm|*/sandns|*/sandswap-boxout)
                echo "  Killing our process on port $port: $pid ($exe)"
                kill -9 "$pid" 2>/dev/null || true
                ;;
            *)
                if [[ -n "$exe" ]]; then
                    echo "  NOT touching foreign listener on port $port: $pid ($exe)"
                fi
                ;;
        esac
    done
done


if [[ $killed -gt 0 ]]; then
    # Give processes a moment to exit
    sleep 1
    # Reload vhost_vsock to free stale CIDs
    modprobe -r vhost_vsock 2>/dev/null || true
    modprobe vhost_vsock 2>/dev/null || true
    echo "  ✓ Killed $killed process type(s), vhost_vsock reloaded"
else
    echo "  ✓ No sandswap processes running"
fi

# ── 1b. Remove /etc/hosts pins the deploys/tests add ─────────────────
# /etc/hosts takes precedence over DNS: a stale sandswap.local pin (multi-gw
# sim) or gateway FQDN pin (k8s harness) silently reroutes later tests. Only
# sandswap-owned names are touched.
echo "[1b/9] /etc/hosts pins"
if grep -qE 'sandswap\.local|sandswap-stream\.local|gateway-exec\.sandswap\.svc\.cluster\.local' /etc/hosts 2>/dev/null; then
    sed -i -E '/sandswap\.local|sandswap-stream\.local|gateway-exec\.sandswap\.svc\.cluster\.local/d' /etc/hosts 2>/dev/null || true
    echo "  ✓ removed stale sandswap /etc/hosts pin(s)"
else
    echo "  ✓ no /etc/hosts pins"
fi

# ── 2. Detach vsockguard BPF ─────────────────────────────────────────
echo "[2/9] vsockguard BPF"
if [[ -e /sys/fs/bpf/vsockguard/link ]]; then
    VSOCKGUARD_LOADER="${VSOCKGUARD_LOADER:-$ROOT/output/vsockguardctl}"
    if [[ -x "$VSOCKGUARD_LOADER" ]]; then
        "$VSOCKGUARD_LOADER" detach \
            /sys/fs/bpf/vsockguard/link \
            /sys/fs/bpf/vsockguard/prog \
            /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null || true
        rmdir /sys/fs/bpf/vsockguard 2>/dev/null || true
        echo "  ✓ vsockguard detached"
    else
        # Fallback: just remove the pins (kernel auto-detaches when all refs gone)
        rm -f /sys/fs/bpf/vsockguard/link /sys/fs/bpf/vsockguard/prog /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null || true
        rmdir /sys/fs/bpf/vsockguard 2>/dev/null || true
        echo "  ✓ vsockguard pins removed (loader not found, fallback)"
    fi
else
    echo "  ✓ vsockguard not attached (already clean)"
fi

# ── 3. Remove host TAP devices + network bridge + nftables ──────────
echo "[3/9] TAP devices + network bridge"
tap_count=0
for tap in $(ip -br link show 2>/dev/null | awk '/^tap-/{print $1}'); do
    ip link del "$tap" 2>/dev/null || true
    tap_count=$((tap_count + 1))
done
if [[ $tap_count -gt 0 ]]; then
    echo "  ✓ Removed $tap_count TAP device(s)"
else
    echo "  ✓ No TAP devices to remove"
fi

# Remove the network bridge (deploy scripts recreate it)
if ip link show br-sandswap &>/dev/null; then
    ip link del br-sandswap 2>/dev/null || true
    echo "  ✓ br-sandswap removed"
else
    echo "  ✓ br-sandswap not present"
fi

# Also remove the nftables tables if present — the main table plus the egress
# identity enabler tables (baseline anti-spoof, routed-ipv6 stamps)
nft list table inet sandswap &>/dev/null && {
    nft delete table inet sandswap 2>/dev/null || true
    echo "  ✓ nftables table removed"
} || true
# Legacy-version cleanup: older setup-network.sh versions installed two
# iptables FORWARD rules (guest subnet accept + established/related return).
# The guest forward policy now lives in the `inet sandswap` nft forward chain
# removed above, so these rules are residue from an upgraded host; sweep them
# so a downgrade/upgrade cycle leaves no unexplained netfilter state.
# Use the addressing the deploy RECORDED (setup-host.sh writes
# /etc/sandswap/network.env): the rules carry that subnet, and removing only the
# built-in default left the live pair behind.
if [[ -z "${SUBNET:-}" && -r /etc/sandswap/network.env ]]; then
    # shellcheck disable=SC1091
    . /etc/sandswap/network.env 2>/dev/null || true
fi
REMOVE_SUBNETS=("${SUBNET:-10.188.0.0/16}")
[[ " ${REMOVE_SUBNETS[*]} " == *" 10.188.0.0/16 "* ]] || REMOVE_SUBNETS+=("10.188.0.0/16")
for subnet in "${REMOVE_SUBNETS[@]}"; do
for rulespec in "-s ${subnet} -j ACCEPT" "-d ${subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"; do
    # shellcheck disable=SC2086  # deliberate word splitting of the rule spec
    while iptables -C FORWARD $rulespec 2>/dev/null; do
        # shellcheck disable=SC2086
        iptables -D FORWARD $rulespec 2>/dev/null || break
    done
done
done
rm -f /etc/sandswap/network.env 2>/dev/null || true

for tbl in "netdev sandswap_baseline" "bridge sandswap_baseline" "inet sandswap_baseline" "inet sandswap_routed6"; do
    nft list table $tbl &>/dev/null && {
        nft delete table $tbl 2>/dev/null || true
        echo "  ✓ nftables table $tbl removed"
    } || true
done
# Binding-region carriers (shm file + bpffs pin) — same zero-residue rule.
# The bpffs ROOT mode (setup-host.sh widens it to 0711 for the bpf carrier)
# is restored to the stock 0700 once the pin directory is gone.
rm -f /dev/shm/sandswap-bindings 2>/dev/null && echo "  ✓ shm binding region removed" || true
rm -f /sys/fs/bpf/sandswap/bindings 2>/dev/null && echo "  ✓ bpf binding pin removed" || true
if rmdir /sys/fs/bpf/sandswap 2>/dev/null; then
    chmod 0700 /sys/fs/bpf 2>/dev/null || true
fi

# ── 4. Unmount overlays ─────────────────────────────────────────────
echo "[4/9] Overlay mounts"
VOL_ROOT="/var/lib/sandswap/volumes"
overlay_count=0
if [[ -d "$VOL_ROOT" ]]; then
    while IFS= read -r mountpoint; do
        if [[ -n "$mountpoint" ]]; then
            umount -l "$mountpoint" 2>/dev/null || true
            overlay_count=$((overlay_count + 1))
        fi
    done < <(findmnt -R "$VOL_ROOT" -t overlay -n -o TARGET 2>/dev/null | tac || true)
fi
if [[ $overlay_count -gt 0 ]]; then
    echo "  ✓ Unmounted $overlay_count overlay mount(s)"
else
    echo "  ✓ No overlay mounts to remove"
fi

# ── 5. Remove runtime state directories ──────────────────────────────
echo "[5/9] Runtime state"
rm -rf /run/sandswap /run/sandswap-state 2>/dev/null || true
# follow-up: /var/lib/sandswap's VOLUMES ROOT is a self-bind carrying
# nosuid,nodev (invariant 8; ss_harden_volumes_mount). A mountpoint cannot be
# removed by rm -rf, so unmount it (and the parent if it is bound) BEFORE the
# delete. Lazy fallback for a wedged backing store.
# A lazy unmount detaches from the namespace but a still-referenced mount can
# keep the path un-removable for a moment; retry the unmount+delete as a unit
# instead of deleting a still-mounted tree (rm -rf then fails silently and the
# residue check finds var-lib=1).
for _attempt in 1 2 3 4 5; do
    for mp in "$VOL_ROOT" /var/lib/sandswap; do
        if mountpoint -q "$mp" 2>/dev/null; then
            umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
        fi
    done
    sed -i -E '\|^[^#]*[[:space:]]/var/lib/sandswap(/volumes)?[[:space:]]+.*[[:space:]]bind|d' /etc/fstab 2>/dev/null || true
    rm -rf /var/lib/sandswap 2>/dev/null || true
    [[ ! -e /var/lib/sandswap ]] && break
    sleep 1
done
[[ -e /var/lib/sandswap ]] && echo "  ⚠ /var/lib/sandswap survived removal (still mounted?)"
rm -rf /tmp/sandswap-logs 2>/dev/null || true
# Also clean cert output directories
rm -rf "$ROOT/output/baremetal-certs" 2>/dev/null || true
rm -rf "$ROOT/output/certs" 2>/dev/null || true
echo "  ✓ /run/sandswap + /var/lib/sandswap + logs removed"

# NEVER strip the SHARED host-setup artifacts on a host that is
# (or was) k8s-managed — k8s-cleanup deliberately KEEPS the udev vsock rule
# and the device modes (the pods depend on them; the k8s host-setup sysctl
# files are the tell-tale). Running a baremetal cleanup on such a host
# silently degraded its isolation (probed live on this very host).
_k8s_managed() {
    [[ -f /etc/sysctl.d/99-sandswap-ptrace.conf ]] \
        || [[ -f /etc/sysctl.d/99-sandswap-perf.conf ]] \
        || [[ -d /etc/rancher/k3s ]] \
        || [[ -d /var/lib/rancher/k3s ]]
}
if _k8s_managed; then
    K8S_MANAGED=1
    echo "  ⚠ k8s-managed host detected: keeping the udev vsock rule + device modes (k8s-cleanup owns them)"
else
    K8S_MANAGED=0
fi
# ── 6. Remove stale udev rules ───────────────────────────────────────
echo "[6/9] Stale udev rules"
udev_removed=0
# setup-host.sh writes 99-sandswap.rules (tun → 0660 sandlot) and installs
# 99-sandswap-vsock.rules (vsock device lockdown); the "kvm/vhost-vsock"
# names match nothing but are kept for backwards compatibility with very
# old installs.
# The egress-enabler's bpf-carrier syscall-filter drop-in (installed only by
# deploy-egress-enabler.sh; harmless when absent — an additive allow for bpf(2)).
if [[ -f /etc/systemd/system/sandswap-sandlot.service.d/egress-bpf.conf ]]; then
    rm -f /etc/systemd/system/sandswap-sandlot.service.d/egress-bpf.conf
    rmdir /etc/systemd/system/sandswap-sandlot.service.d 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    echo "  ✓ egress-bpf syscall-filter drop-in removed"
fi

for rule in /etc/udev/rules.d/99-sandswap.rules \
            /etc/udev/rules.d/99-sandswap-vsock.rules \
            /etc/udev/rules.d/99-sandswap-kvm.rules \
            /etc/udev/rules.d/99-sandswap-vhost-vsock.rules; do
    if [[ -f "$rule" ]]; then
        if [[ "$K8S_MANAGED" == "1" && "$rule" == *vsock* ]]; then
            continue #: k8s keeps the vsock lockdown rule
        fi
        rm -f "$rule"
        udev_removed=$((udev_removed + 1))
    fi
done
rm -f /etc/modules-load.d/sandswap.conf 2>/dev/null || true
if [[ $udev_removed -gt 0 ]]; then
    udevadm control --reload-rules 2>/dev/null || true
    echo "  ✓ Removed $udev_removed stale udev rule(s) + modules-load config"
else
    echo "  ✓ No stale udev rules"
fi

# ── 7. Remove sysctl file ───────────────────────────────────────────
echo "[7/9] Sysctl file"
SYSCTL_FILE="/etc/sysctl.d/99-sandswap.conf"
if [[ -f "$SYSCTL_FILE" ]]; then
    rm -f "$SYSCTL_FILE"
    sysctl --system 2>/dev/null || true
    echo "  ✓ Removed $SYSCTL_FILE"
else
    echo "  ✓ No sysctl file to remove"
fi

# ── 8. Remove etcd data directory ────────────────────────────────────
echo "[8/9] Etcd data"
ETCD_DATA_CLEANED=0
# Match the etcd data-dir patterns the cluster deploys/sims use
for etcd_data in /tmp/sandswap-*-etcd-data /tmp/etcd-data; do
    if [[ -d "$etcd_data" ]]; then
        rm -rf "$etcd_data"
        ETCD_DATA_CLEANED=$((ETCD_DATA_CLEANED + 1))
    fi
done
if [[ $ETCD_DATA_CLEANED -gt 0 ]]; then
    echo "  ✓ Removed $ETCD_DATA_CLEANED etcd data directory(ies)"
else
    echo "  ✓ No etcd data to remove"
fi

# Reverse ledger-tracked ephemeral side effects (hosts pins, resolv.conf,
# systemd units, instance state, etcd pidfiles) from this or prior runs.
se_replay_ephemeral

echo ""
echo "═══ Cleanup Complete ═══"
echo "  Processes:       killed"
echo "  vsockguard:      detached"
echo "  TAP devices:     removed"
echo "  br-sandswap:     removed"
echo "  Overlay mounts:  unmounted"
echo "  /run/sandswap:   removed"
echo "  /var/lib/sandswap: removed"
echo "  udev rules:      cleaned"
echo "  sysctl file:     removed"
echo "  etcd data:       removed"
echo ""
