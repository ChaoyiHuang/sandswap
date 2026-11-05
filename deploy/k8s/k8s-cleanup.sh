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
# k8s-cleanup.sh — Clean all Sandswap K8s resources and host state.
# Removes everything left by a previous deploy-k8s-embedded.sh or
# deploy-k8s-boxout.sh run — including a deployment kept running by the
# default keep mode and any verify-k8s.sh access aids — so the next
# deployment starts from a clean slate. Safe to run when
# nothing is deployed (all steps are --ignore-not-found / || true).
# What it cleans:
#   1. K8s namespace + all resources (pods, PVCs, secrets, etc.)
#   2. Port-forward processes on ports 3000/3100
#   3. vsockguard BPF pins (so the next deploy re-attaches with the correct UID)
#   4. Host TAP devices + network bridge (br-sandswap)
#   5. Seccomp profile installed on the host
#   6. Sandswap runtime state (/run/sandswap, /var/lib/sandswap — includes binaries)
#   7. Overlay mounts under /var/lib/sandswap/volumes (unmount before rm)
#   8. Stale port-forward PID files
#   9. Stale udev rules from previous deploys (kvm/vhost-vsock only — the
#      vsock rule is one-time host-setup material and is deliberately kept)
#  10. The bridge/NAT persistence unit + its installed script + network.env
# What it does NOT clean (by design):
#   - k3s installation itself (use k3s-uninstall.sh for that)
#   - Host sysctls, service account (one-time setup by k8s-host-setup.sh)
# Usage:
#   sudo bash deploy/k8s/k8s-cleanup.sh
# Called automatically by deploy-k8s-embedded.sh / deploy-k8s-boxout.sh before deploying.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NAMESPACE="sandswap"
KUBECTL="kubectl"

# Must be root for BPF, overlay unmount, /run cleanup, etc.
if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root (sudo)" >&2
    exit 1
fi

echo "═══ Sandswap K8s Cleanup ═══"
echo "  Host: $(uname -n)"
echo ""


# ── Revert the coredns Corefile zone added by the deploys ────────────
# The deploys merge-patch kube-system/coredns with a
# "sandfs.sandswap.local:53 { forward . <sandns-ClusterIP> }" zone. Once the
# sandswap namespace is gone that forwards to a blackholed ClusterIP
# (~5s timeout then SERVFAIL for every *.sandfs.sandswap.local query,
# cluster-wide). Strip the zone and restart coredns. No-op when absent.
revert_coredns_zone() {
    if ! $KUBECTL get configmap coredns -n kube-system >/dev/null 2>&1; then
        return 0
    fi
    if ! $KUBECTL get configmap coredns -n kube-system -o jsonpath='{.data.Corefile}' 2>/dev/null | grep -q 'sandfs\.sandswap\.local'; then
        echo "  ✓ coredns Corefile has no sandswap zone (already clean)"
        return 0
    fi
    echo "  Removing stale sandfs.sandswap.local zone from coredns Corefile..."
    $KUBECTL get configmap coredns -n kube-system -o jsonpath='{.data.Corefile}' 2>/dev/null \
        | python3 -c "
import re, sys
text = sys.stdin.read()
text = re.sub(r'\nsandfs\.sandswap\.local:53 \{[^}]*\}\n?', '\n', text)
sys.stdout.write(text)" > /tmp/sandswap-coredns-revert.yaml
    local patch
    patch=$(python3 -c "import json; print(json.dumps({'data': {'Corefile': open('/tmp/sandswap-coredns-revert.yaml').read()}}))")
    if $KUBECTL patch configmap coredns -n kube-system --type merge -p "$patch" >/dev/null 2>&1; then
        $KUBECTL rollout restart deployment/coredns -n kube-system >/dev/null 2>&1 || true
        echo "  ✓ coredns zone reverted + coredns restarted"
    else
        echo "  ⚠ could not patch coredns (cluster unreachable?) — remove the sandfs.sandswap.local zone manually"
    fi
    rm -f /tmp/sandswap-coredns-revert.yaml
}

# ── Remove the /etc/hosts pin the deploys add for the exec gateway FQDN ──
remove_hosts_pin() {
    if grep -q 'gateway-exec\.sandswap\.svc\.cluster\.local' /etc/hosts 2>/dev/null; then
        sed -i '/gateway-exec\.sandswap\.svc\.cluster\.local/d' /etc/hosts 2>/dev/null || true
        echo "  ✓ removed stale /etc/hosts gateway FQDN pin"
    fi
}

# ── 1. Delete K8s namespace (all pods, PVCs, secrets, etc.) ──────────
echo "[1/9] K8s namespace"
if $KUBECTL get namespace "$NAMESPACE" &>/dev/null; then
    # the volume-name seed Secret must SURVIVE teardown (deploy-lib's
    # own contract: "kept as-is even across teardown/redeploy cycles") — the
    # namespace delete below would destroy it, and with external/Retain
    # storage every old volume directory would orphan (names unresolvable).
    # Back it up to /etc/sandswap; deploy-lib restores it before minting.
    if $KUBECTL -n "$NAMESPACE" get secret sandswap-volume-seed &>/dev/null; then
        mkdir -p /etc/sandswap
        # EVERY key is a generation file (the Secret holds one key per naming
        # generation; the ConfigMap names which is current). Backing up only
        # the legacy key would drop a staged or newer generation and strand a
        # half-rotated tree on the next deploy.
        while IFS= read -r _key; do
            [[ -n "$_key" ]] || continue
            if [[ "$_key" == "volume-seed" ]]; then
                _out=/etc/sandswap/volume-seed
            else
                _out="/etc/sandswap/volume-seed.$_key"
            fi
            $KUBECTL -n "$NAMESPACE" get secret sandswap-volume-seed \
                -o jsonpath="{.data.${_key//./\\.}}" | base64 -d > "$_out"
            chmod 0640 "$_out"
            echo "  ✓ volume-name generation '$_key' backed up to $_out (restored on next deploy)"
        done < <($KUBECTL -n "$NAMESPACE" get secret sandswap-volume-seed -o jsonpath='{.data}' \
            | python3 -c 'import json,sys; print("\n".join(sorted(json.load(sys.stdin).keys())))')
    fi
    echo "  Deleting namespace $NAMESPACE..."
    # --wait=false + explicit poll: a stuck finalizer (local-path PV release,
    # privileged pod) must not hang this cleanup (and with it the next deploy).
    $KUBECTL delete namespace "$NAMESPACE" --wait=false --ignore-not-found=true 2>/dev/null || true
    for _ in $(seq 1 36); do
        $KUBECTL get namespace "$NAMESPACE" >/dev/null 2>&1 || break
        sleep 5
    done
    if $KUBECTL get namespace "$NAMESPACE" >/dev/null 2>&1; then
        echo "  ⚠ namespace $NAMESPACE still terminating after 180s (stuck finalizer) — continuing; check: kubectl get ns $NAMESPACE -o yaml"
    else
        echo "  ✓ Namespace deleted"
    fi
else
    echo "  ✓ Namespace $NAMESPACE does not exist (already clean)"
fi
# PVs whose claim lived in this namespace. Local-path PVs normally die with
# their PVC, but an interrupted run can leave one stuck Released — and the
# next deploy's PVC would re-bind it (with the OLD volume's data). Delete
# explicitly so every deploy starts from a clean slate.
for pv in $($KUBECTL get pv -o json 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
for item in d.get('items',[]):
    ns=(item.get('spec',{}).get('claimRef',{}) or {}).get('namespace','')
    if ns=='$NAMESPACE':
        print(item['metadata']['name'])
" 2>/dev/null); do
    $KUBECTL delete pv "$pv" --wait=false 2>/dev/null && echo "  ✓ stale PV $pv deleted" || true
done

revert_coredns_zone
remove_hosts_pin

# ── 2. Kill port-forward processes ────────────────────────────────────
# ss-based port kill: lsof is not part of the base install set and its
# absence turns every `lsof ... || true` into a silent no-op.
kill_port() {
    local pids
    pids=$(ss -tlnp 2>/dev/null | grep ":$1 " | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u || true)
    if [[ -n "$pids" ]]; then
        echo "  Killing processes on port $1: $pids"
        echo "$pids" | xargs -r kill 2>/dev/null || true
    fi
    return 0
}
echo "[2/9] Port-forward processes"
for port in 3000 3100; do
    kill_port "$port"
done
# Kill the port-forward WATCHDOGS first: each watchdog loop kills whatever
# holds :3100 and restarts its own port-forward, so two of them fight forever.
# The pid files hold the watchdog PIDs (start_port_forward records them), so
# kill by recorded PID — verifying /proc/<pid>/cmdline still names the pf
# script so a reused PID can never be hit — with the path pattern only as a
# backstop for a lost pid file. Delete the handles only after the watchdogs
# are dead.
for pf in /tmp/sandswap-pf-*.pid; do
    [[ -f "$pf" ]] || break
    wpid="$(cat "$pf" 2>/dev/null || true)"
    if [[ -n "$wpid" ]] && grep -qa 'sandswap-pf-' "/proc/$wpid/cmdline" 2>/dev/null; then
        kill "$wpid" 2>/dev/null || true
    fi
done
pkill -f '/tmp/sandswap-pf-.*\.sh' 2>/dev/null || true
rm -f /tmp/sandswap-pf-*.pid /tmp/sandswap-pf-*.sh
echo "  ✓ Port-forwards cleaned"

# ── 3. Detach vsockguard BPF ─────────────────────────────────────────
echo "[3/9] vsockguard BPF"
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

# ── 4. Remove host TAP devices + network bridge ─────────────────────
echo "[4/9] TAP devices + network bridge"
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

# Also remove the nftables table if present
nft list table inet sandswap &>/dev/null && {
    nft delete table inet sandswap 2>/dev/null || true
    echo "  ✓ nftables table removed"
}
# Egress identity enabler tables (baseline anti-spoof, routed-ipv6 stamps)
for tbl in "netdev sandswap_baseline" "bridge sandswap_baseline" "inet sandswap_routed6"; do
    nft list table $tbl &>/dev/null && {
        nft delete table $tbl 2>/dev/null || true
        echo "  ✓ nftables table $tbl removed"
    } || true
done
# Binding-region carriers (shm file + bpffs pin) — zero-residue rule.
rm -f /dev/shm/sandswap-bindings 2>/dev/null && echo "  ✓ shm binding region removed" || true
rm -f /sys/fs/bpf/sandswap/bindings 2>/dev/null && echo "  ✓ bpf binding pin removed" || true
rmdir /sys/fs/bpf/sandswap 2>/dev/null || true

# ── 5. Remove stale udev rules ────────────────────────────────────────
echo "[5/9] Stale udev rules"
udev_removed=0
# 99-sandswap-vsock.rules is NOT here on purpose: k8s-host-setup.sh installs it
# as ONE-TIME host hardening (its --verify step hard-fails without it, and
# security/verify-host-security.sh names it as the fix for the device-ownership
# invariant). Removing it — while step 8's `modprobe -r vhost_vsock` (or a
# reboot) recreates /dev/vhost-vsock with the distro default owner — leaves the
# next EMBEDDED deploy with a device owned by the wrong uid, and the sandlot
# fatal-exits on that check (crash-loop until an operator reinstalls the rule).
for rule in /etc/udev/rules.d/99-sandswap-kvm.rules \
            /etc/udev/rules.d/99-sandswap-vhost-vsock.rules; do
    if [[ -f "$rule" ]]; then
        rm -f "$rule"
        udev_removed=$((udev_removed + 1))
    fi
done
if [[ $udev_removed -gt 0 ]]; then
    udevadm control --reload-rules 2>/dev/null || true
    echo "  ✓ Removed $udev_removed stale udev rule(s)"
else
    echo "  ✓ No stale udev rules"
fi

# ── 5b. Remove the bridge/NAT persistence unit ────────────────────────
# k8s-host-setup.sh installs /usr/local/bin/sandswap-setup-network and enables
# sandswap-network.service (the boot-time bridge re-creator). Left enabled, a
# "cleaned" node keeps re-creating br-sandswap + the postrouting masquerade at
# every future boot — and the unit is ordered Before= other sandswap units, so
# it silently pre-empts whatever configures that bridge next.
echo "[5b/9] Network persistence unit"
if systemctl list-unit-files sandswap-network.service 2>/dev/null | grep -q sandswap-network; then
    systemctl disable --now sandswap-network.service 2>/dev/null || true
    echo "  ✓ sandswap-network.service disabled"
fi
rm -f /etc/systemd/system/sandswap-network.service /usr/local/bin/sandswap-setup-network 2>/dev/null || true
rm -f /etc/sandswap/network.env 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

# ── 5c. Remove this node's stream client certificate ─────────────────
# The pair is per NODE (the gateway binds hello.node_id == the client
# certificate's CN by exact match) and is re-materialized by
# k8s-host-setup.sh --stream-certs-only after the next deploy's PKI is
# applied — leaving it behind would strand a key that can claim this node's
# identity to whatever gateway comes next.
if [[ -d /etc/sandswap/stream-certs ]]; then
    rm -rf /etc/sandswap/stream-certs
    echo "  ✓ Removed /etc/sandswap/stream-certs (re-fetch after the next deploy)"
else
    echo "  ✓ No stream client certificate to remove"
fi

# ── 6. Remove seccomp profile ────────────────────────────────────────
echo "[6/9] Seccomp profile"
SECCOMP_DIR="/var/lib/kubelet/seccomp/sandswap"
if [[ -d "$SECCOMP_DIR" ]]; then
    rm -rf "$SECCOMP_DIR"
    echo "  ✓ Removed $SECCOMP_DIR"
else
    echo "  ✓ No seccomp profile to remove"
fi

# ── 7. Unmount overlays + remove runtime state ────────────────────────
echo "[7/9] Host runtime state"

# Unmount overlay filesystems under /var/lib/sandswap/volumes before rm -rf
# (stale mounts reference deleted paths and cause EBUSY)
VOL_ROOT="/var/lib/sandswap/volumes"
if [[ -d "$VOL_ROOT" ]]; then
    overlay_count=0
    while IFS= read -r mountpoint; do
        if [[ -n "$mountpoint" ]]; then
            umount -l "$mountpoint" 2>/dev/null || true
            overlay_count=$((overlay_count + 1))
        fi
    done < <(findmnt -R "$VOL_ROOT" -t overlay -n -o TARGET 2>/dev/null | tac || true)
    if [[ $overlay_count -gt 0 ]]; then
        echo "  Unmounted $overlay_count overlay mount(s)"
    fi
fi

# Remove runtime state dirs (including binaries — deploy scripts will re-deploy)
rm -rf /run/sandswap /run/sandswap-state /var/lib/sandswap 2>/dev/null || true
echo "  ✓ /run/sandswap + /var/lib/sandswap removed"

# ── 8. Kill any remaining sandswap processes ──────────────────────────
echo "[8/9] Remaining processes"
killed=0
for proc in sandvmm sandlot gateway boxout; do
    pids="$(pgrep -x "$proc" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
        echo "  Killing $proc: $pids"
        echo "$pids" | xargs -r kill -9 2>/dev/null || true
        killed=$((killed + 1))
    fi
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

echo ""
echo "═══ Cleanup Complete ═══"
echo "  K8s namespace:  deleted"
echo "  Port-forwards:  killed"
echo "  vsockguard:     detached"
echo "  TAP devices:    removed"
echo "  br-sandswap:    removed"
echo "  Seccomp:        removed"
echo "  udev rules:     cleaned"
echo "  /run/sandswap:  removed"
echo "  /var/lib/sandswap: removed"
echo ""
