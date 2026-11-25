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
# uninstall.sh - Uninstall Sandswap bare-metal deployment (systemd-based)
# Removes everything installed by deploy-single-node.sh / deploy-cluster-*.sh:
#   1. Stops + disables systemd services
#   2. Kills any leftover sandswap processes
#   3. Detaches vsockguard BPF
#   4. Removes TAP devices + bridge + nftables
#   5. Unmounts overlays
#   6. Removes config files (/etc/sandswap/)
#   7. Removes binaries (/usr/local/bin/sandswap-* + the guest TCB + the
#      installed runtime helpers under /usr/local/lib/sandswap/)
#   8. Removes runtime state (/var/lib/sandswap, /run/sandswap, /var/log/sandswap)
#   9. Removes systemd units (+ drop-in dirs + legacy empty slices)
#  10. Removes udev rules + sysctl + tmpfiles.d (restores device nodes)
#  11. Removes etcd data (if local etcd)
# Deliberately KEPT (never removed by this script):
#   - the service users/groups (sandlot, sandprov, sandvmm, sandserv) — the
#     identity split is uid-pinned and load-bearing; identity drift is always
#     fatal, so accounts are never userdel'd (a re-deploy must find the same
#     uids)
#   - the host etcd binary (/usr/local/bin/etcd) — a shared toolchain
#     dependency installed by build/install-deps.sh; only the deployment's
#     data dir is ours to remove (step 11)
#   - operator hooks under /usr/local/lib/sandswap/ (e.g. seed-fetch.sh, a
#     credential helper) — not ours to delete; the deployer removes only the
#     files it installed (runtime.sh, apply-prov-ownership, guest TCB)
#   - the operator-installed sandswap-seed-fetch.service (docs/integration/
#     volume-seed.md instructs the operator to enable it; no deploy path
#     installs it), so the self-verification below excludes it
# Usage:
#   sudo bash deploy/baremetal/uninstall.sh
#   sudo bash deploy/baremetal/uninstall.sh --keep-data  # keep /var/lib/sandswap volumes

set -euo pipefail

KEEP_DATA=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-data) KEEP_DATA=1; shift ;;
        -h|--help)
            echo "Usage: $0 [--keep-data]"
            echo "  --keep-data  Keep /var/lib/sandswap volumes (agent data)"
            exit 0
            ;;
        *) ;;
    esac
done

[[ "$(id -u)" -ne 0 ]] && { echo "error: must run as root (sudo)" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "═══ Sandswap Bare-Metal Uninstall ═══"
echo "  Host: $(uname -n)"
echo "  Keep data: $([ $KEEP_DATA -eq 1 ] && echo 'yes' || echo 'no')"
echo ""

# ── 1. Stop + disable systemd services ──────────────────────────────
echo "[1/11] Systemd services"
source "$ROOT/deploy/baremetal/common.sh"
source "$ROOT/deploy/baremetal/deploy-lib.sh"
sandswap_stop_services
echo "  ✓ Systemd services stopped"

# ── 1b. Reverse the side-effect ledger ──────────────────────────────
# The ledger journals every host mutation the deploy scripts made; EPHEMERAL
# entries (hosts pins, resolv.conf swap, units, etcd pidfile, instance state,
# tmpfiles) are reversed here — uninstall is otherwise blind to a CRASHED
# deploy's leftovers (its own sweep only covers the well-known paths). KEEP
# entries are observability-only. The ledger itself is retained as a log
# (renamed .done) — it never blocks the next clean run.
echo "[1b/11] Side-effect ledger replay"
se_replay_ephemeral
echo "  ✓ EPHEMERAL entries reversed (ledger retained as .done)"

# ── 2. Kill leftover processes ───────────────────────────────────────
# PID-exact kill (deploy-lib): unit-cgroup survivors + kernel-verified exe
# identity — never a cmdline-text match. Foreign etcd is protected: the
# shared etcd binary only dies with one of OUR instance markers in argv
# (the docs explicitly support pointing at an existing cluster via
# etcd.endpoints; a foreign service on :2379 is left alone).
echo "[2/11] Processes"
bm_kill_leftover_processes
killed=${BM_LEFTOVER_KILLS:-0}
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
    sleep 1
    modprobe -r vhost_vsock 2>/dev/null || true
    modprobe vhost_vsock 2>/dev/null || true
    echo "  ✓ Killed $killed process type(s), vhost_vsock reloaded"
else
    echo "  ✓ No leftover processes"
fi

# ── 3. Detach vsockguard BPF ─────────────────────────────────────────
echo "[3/11] vsockguard BPF"
if [[ -e /sys/fs/bpf/vsockguard/link ]]; then
    VSOCKGUARDCTL="/usr/local/bin/vsockguardctl"
    if [[ -x "$VSOCKGUARDCTL" ]]; then
        # detach REQUIRES the three pin paths (argc==5) — a bare `detach`
        # prints usage and exits 1 (suppressed here), silently skipping the
        # real detach and falling through to pin removal alone.
        "$VSOCKGUARDCTL" detach \
            /sys/fs/bpf/vsockguard/link \
            /sys/fs/bpf/vsockguard/prog \
            /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null || true
    fi
    rm -f /sys/fs/bpf/vsockguard/link /sys/fs/bpf/vsockguard/prog \
          /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null || true
    rmdir /sys/fs/bpf/vsockguard 2>/dev/null || true
    echo "  ✓ vsockguard detached"
else
    echo "  ✓ vsockguard not attached"
fi

# ── 4. Remove TAP devices + bridge + nftables ───────────────────────
# (bpffs restore: the bpf binding carrier's host prep sets the bpffs ROOT to
#  0711 so the sandlot identity can traverse to its pin — see setup-host.sh.
#  With the pin and its directory gone, restore the stock 0700 so the
#  uninstall leaves no widened surface behind. The vsockguard pins under
#  /sys/fs/bpf/vsockguard are root-owned and unaffected by the mode.)
echo "[4/11] TAP devices + bridge"
tap_count=0
for tap in $(ip -br link show 2>/dev/null | awk '/^tap-/{print $1}'); do
    ip link del "$tap" 2>/dev/null || true
    tap_count=$((tap_count + 1))
done
if ip link show br-sandswap &>/dev/null; then
    ip link del br-sandswap 2>/dev/null || true
    echo "  ✓ br-sandswap removed"
fi
nft list table inet sandswap &>/dev/null && {
    nft delete table inet sandswap 2>/dev/null || true
} || true
# setup-network.sh also installs two iptables FORWARD rules (guest subnet
# accept + established/related return). They are netfilter state that outlives
# the bridge: left behind, a firewall audit finds unexplained FORWARD ACCEPTs
# for a subnet that no longer exists on the host.
# The deploy writes its addressing to /etc/sandswap/network.env (setup-host.sh)
# and the rules carry THAT subnet — removing only the built-in default left the
# live pair behind (observed: -A FORWARD -s/-d 10.188.1.0/24 after a clean
# uninstall). Read the recorded addressing first, and sweep the default too so
# a host that moved subnets loses both.
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
# Egress identity enabler tables (baseline anti-spoof — all THREE families
# the sandlot creates: netdev, bridge, inet — plus the routed-ipv6 stamps)
nft delete table netdev sandswap_baseline 2>/dev/null || true
nft delete table bridge sandswap_baseline 2>/dev/null || true
nft delete table inet sandswap_baseline 2>/dev/null || true
nft delete table inet sandswap_routed6 2>/dev/null || true
# Binding-region carriers (shm file + bpffs pin)
rm -f /dev/shm/sandswap-bindings 2>/dev/null || true
rm -f /sys/fs/bpf/sandswap/bindings 2>/dev/null || true
if rmdir /sys/fs/bpf/sandswap 2>/dev/null; then
    chmod 0700 /sys/fs/bpf 2>/dev/null || true
fi
echo "  ✓ Network cleanup done ($tap_count TAP removed)"

# ── 5. Unmount overlays ─────────────────────────────────────────────
echo "[5/11] Overlay mounts"
overlay_count=0
for vol_root in /var/lib/sandswap/volumes /mnt/sandswap/volumes; do
    if [[ -d "$vol_root" ]]; then
        while IFS= read -r mountpoint; do
            if [[ -n "$mountpoint" ]]; then
                umount -l "$mountpoint" 2>/dev/null || true
                overlay_count=$((overlay_count + 1))
            fi
        done < <(findmnt -R "$vol_root" -t overlay -n -o TARGET 2>/dev/null | tac || true)
    fi
done
# Also unmount shared storage if it was mounted by our scripts
mountpoint -q /mnt/sandswap 2>/dev/null && {
    umount /mnt/sandswap 2>/dev/null || umount -l /mnt/sandswap 2>/dev/null || true
    # Remove from fstab
    sed -i '\|/mnt/sandswap|d' /etc/fstab 2>/dev/null || true
}
echo "  ✓ Unmounted $overlay_count overlay(s) + shared storage"

# ── 6. Remove config files ──────────────────────────────────────────
echo "[6/11] Config files"
rm -rf /etc/sandswap 2>/dev/null || true
echo "  ✓ /etc/sandswap removed"

# ── 7. Remove binaries ──────────────────────────────────────────────
echo "[7/11] Binaries"
for bin in sandswap-gateway sandswap-sandlot sandswap-sandvmm sandns vsockguardctl sandswap-setup-network; do
    rm -f "/usr/local/bin/$bin" "/usr/local/bin/${bin}.prev" 2>/dev/null || true
done
# The shared runtime the installed sandswap-setup-network copy resolves
# (sandswap-network.service runs it at boot, where the repo tree does not
# exist). The same rule governs everything here: remove the files the
# DEPLOYER installed, item by item, and never `rm -rf` the directory — the
# operator's own hooks in /usr/local/lib/sandswap/ (seed-fetch.sh, a
# credential helper) are not ours to delete.
rm -f /usr/local/lib/sandswap/runtime.sh 2>/dev/null || true
# The prov-side ownership re-assert helper (deploy/baremetal/common.sh
# installs it beside runtime.sh).
rm -f /usr/local/lib/sandswap/apply-prov-ownership 2>/dev/null || true
# The guest TCB (sandswap_install_guest_artifacts installs exactly these
# three files; a re-deploy re-copies them from output/ in seconds — this is
# NOT a rebuild). Item-wise delete + rmdir so anything an operator added to
# the directory survives visibly instead of being silently swept.
# $SANDSWAP_GUEST_DIR (from common.sh) is the same variable the deployer
# installed under: a TCB deployed with SANDSWAP_GUEST_DIR=<dir> is removed by
# uninstalling with the same value — the default location otherwise.
for tcb in vmlinux.bin initramfs.cpio.gz SHA256SUMS; do
    rm -f "$SANDSWAP_GUEST_DIR/$tcb" 2>/dev/null || true
done
rmdir "$SANDSWAP_GUEST_DIR" 2>/dev/null || true
echo "  ✓ Binaries removed"

# ── 8. Remove runtime state ─────────────────────────────────────────
echo "[8/11] Runtime state"
if [[ $KEEP_DATA -eq 0 ]]; then
# /var/lib/sandswap may be a bind mount (nosuid,nodev) — unmount it BEFORE
# removing the tree, or the delete leaves a dangling mount point (and the
# fstab bind entry would resurrect it empty on next boot).
# The volumes subtree carries its own self-bind (ss_harden_volumes_mount) — a
# bind on a SUBDIRECTORY is invisible to `mountpoint /var/lib/sandswap`. The
# CHILD comes off first: while a sub-mount exists the parent bind answers
# EBUSY, so the reverse order leaves the parent mounted and rm -rf can never
# remove it. RETRY as a unit (mirrors cleanup.sh): a single-shot umount was
# observed failing silently at row teardown and the self-bind survived a
# "clean" uninstall — unmount+delete until the tree is really gone. The lazy
# fallback detaches a wedged backing store; the fstab scrub also drops a
# volumes bind line so neither entry resurrects an empty tree on next boot.
sed -i -E '\|^[^#]*[[:space:]]/var/lib/sandswap(/volumes)?[[:space:]]+.*[[:space:]]bind|d' /etc/fstab 2>/dev/null || true
for _attempt in 1 2 3 4 5; do
    if mountpoint -q /var/lib/sandswap/volumes 2>/dev/null; then
        umount /var/lib/sandswap/volumes 2>/dev/null \
            || umount -l /var/lib/sandswap/volumes 2>/dev/null || true
    fi
    if mountpoint -q /var/lib/sandswap 2>/dev/null; then
        umount /var/lib/sandswap 2>/dev/null || umount -l /var/lib/sandswap 2>/dev/null || true
    fi
    rm -rf /var/lib/sandswap 2>/dev/null || true
    [[ ! -e /var/lib/sandswap ]] && break
    sleep 1
done
unset _attempt
if [[ -e /var/lib/sandswap ]]; then
    echo "  ⚠ /var/lib/sandswap survived removal (still mounted?)"
else
    echo "  ✓ /var/lib/sandswap removed"
fi
else
    echo "  ✓ /var/lib/sandswap kept (--keep-data)"
fi
rm -rf /run/sandswap /run/sandswap-state 2>/dev/null || true
rm -rf /var/log/sandswap 2>/dev/null || true
rm -rf /tmp/sandswap-logs 2>/dev/null || true

# ── 9. Remove systemd units ─────────────────────────────────────────
echo "[9/11] Systemd units"
for unit in sandswap-gateway.service sandswap-gateway@.service \
            sandswap-sandlot.service sandswap-sandlot-prov.service \
            sandswap-sandns.service \
            sandswap-etcd.service \
            sandswap-network.service \
            sandswap-sandlot-instance@.service \
            sandswap-vsock-retune.service; do
    rm -f "/etc/systemd/system/$unit" 2>/dev/null || true
done
# Drop-in dir: deploy-single-node writes sandprov.conf (merged exec,prov
# shape) and deploy-egress-enabler writes egress-bpf.conf (bpf-carrier
# syscall allow) into the sandlot unit's .d/ — every drop-in there is ours,
# so remove the known files and sweep the directory (rm -f each + rmdir: an
# operator's own drop-in would block the rmdir and stay visible).
for dropin in sandprov.conf egress-bpf.conf; do
    rm -f "/etc/systemd/system/sandswap-sandlot.service.d/$dropin" 2>/dev/null || true
done
rmdir /etc/systemd/system/sandswap-sandlot.service.d 2>/dev/null || true
# Legacy empty slices: units from older deploys carried Slice= directives
# (none of the current units do), and systemd keeps the implicitly-created
# system-sandswap-*.slice cgroups loaded forever after the units are gone.
# Stop them so the daemon-reload below can actually retire them.
systemctl stop system-sandswap-gateway.slice system-sandswap-sandlot-instance.slice 2>/dev/null || true
# Generated per-instance units (sims/cluster deploys write these): without this
# the daemon-reload below keeps them loaded, pointing at now-deleted configs.
rm -f /etc/systemd/system/sandswap-gateway-*.service 2>/dev/null || true
# Template-instance wants symlinks (sandswap-gateway@exec/@human from the
# one-gw cluster deploy) — the glob above can't match the '@' instances.
rm -f /etc/systemd/system/*.wants/sandswap-gateway@*.service 2>/dev/null || true
rm -f /etc/systemd/system/sandswap-sandlot-instance@*.service 2>/dev/null || true
# Co-located one-gw etcd: the data dir holds the identity store (delete per
# the same full-clear doctrine as identity-store.json), and only when that
# dir existed do we remove the binary — its presence proves our deploy
# installed it (a system etcd used via etcd.endpoints never touches this
# path pattern).
if [[ -d /var/lib/sandswap-etcd ]]; then
    rm -rf /var/lib/sandswap-etcd 2>/dev/null || true
    # The etcd BINARY is a host toolchain dependency (build/install-deps.sh
    # installs the pinned release to /usr/local/bin) and is shared with every
    # later deployment — only the deployment's data dir is ours to remove.
    echo "  ✓ co-located etcd data removed (host etcd binary left in place)"
fi
# Remove instance-specific config files
rm -f /etc/sandswap/sandlot-*.yaml 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
echo "  ✓ Systemd units removed"

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
# ── 10. Remove udev rules + sysctl ──────────────────────────────────
echo "[10/11] udev rules + sysctl"
for rule in /etc/udev/rules.d/99-sandswap.rules \
            /etc/udev/rules.d/99-sandswap-vsock.rules \
            /etc/udev/rules.d/99-sandswap-kvm.rules \
            /etc/udev/rules.d/99-sandswap-vhost-vsock.rules; do
    rm -f "$rule" 2>/dev/null || true
done
udevadm control --reload-rules 2>/dev/null || true
# Restore device nodes the removed rules had pinned (devtmpfs keeps the old
# owner/group/mode until something rewrites them — the same explicit-restore
# doctrine setup-host applies in the other direction). Stock modes: kvm +
# vhost-vsock ship root:kvm 0660; vsock and tun ship world-accessible.
chgrp kvm /dev/kvm /dev/vhost-vsock 2>/dev/null || true
chmod 660 /dev/kvm /dev/vhost-vsock 2>/dev/null || true
chgrp root /dev/vsock /dev/net/tun 2>/dev/null || true
if [[ "${K8S_MANAGED:-0}" == "1" ]]; then
    echo " ⚠ k8s-managed host: leaving /dev/vsock + /dev/net/tun modes as k8s set them "
else
    chmod 666 /dev/vsock /dev/net/tun 2>/dev/null || true
fi
# capture whether OUR file was the ip_forward setter BEFORE removal
# (the removal leaves live values untouched — sysctl --system cannot un-set a
# key no remaining file covers).
_WAS_IP_FWD_SETTER=0
if [[ -f /etc/sysctl.d/99-sandswap.conf ]] && grep -qE '^net\.ipv4\.ip_forward[[:space:]]*=' /etc/sysctl.d/99-sandswap.conf; then
    _WAS_IP_FWD_SETTER=1
fi
rm -f /etc/sysctl.d/99-sandswap.conf 2>/dev/null || true
sysctl --system 2>/dev/null || true
if [[ "$_WAS_IP_FWD_SETTER" == "1" ]] && ! grep -rqsE '^net\.ipv4\.ip_forward[[:space:]]*=' /etc/sysctl.d/ 2>/dev/null; then
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
    echo "  ✓ restored net.ipv4.ip_forward=0 (no other sysctl file sets it)"
fi
rm -f /etc/modules-load.d/sandswap.conf 2>/dev/null || true
# tmpfiles.d entry (recreates /run/sandswap at every boot — setup-host.sh
# installs it; without this the uninstall leaves a boot-time resurrection).
rm -f /usr/lib/tmpfiles.d/sandswap.conf /etc/tmpfiles.d/sandswap.conf 2>/dev/null || true
echo "  ✓ udev + sysctl + tmpfiles cleaned"

# ── 11. Remove etcd data ────────────────────────────────────────────
echo "[11/11] Etcd data"
etcd_cleaned=0
# /var/lib/etcd/data removed from the list — NO sandswap component
# ever creates it (grep-verified); deleting it could destroy a FOREIGN etcd's
# data on a host that also runs one (the docs support external clusters).
for etcd_data in /tmp/sandswap-*-etcd-data /tmp/etcd-data; do
    if [[ -d "$etcd_data" ]]; then
        rm -rf "$etcd_data"
        etcd_cleaned=$((etcd_cleaned + 1))
    fi
done
echo "  ✓ Removed $etcd_cleaned etcd data dir(s)"

# ── Verify clean ────────────────────────────────────────────────────
echo ""
echo "═══ Uninstall Complete ═══"
echo ""
echo "  Verification:"
# NB: trailing `|| true` + the [x] character-class idiom — pgrep exits 1 on
# no match and pipefail turns that into a set -e kill of this verification
# block (the uninstall itself had succeeded), and a literal pattern would
# self-match this script's own process tree.
remaining_procs=$(pgrep -f "sandswap-sandvm[m]|sandswap-sandlo[t]|sandswap-gatewa[y]|sandswap-dn[s]" 2>/dev/null | wc -l | tr -d ' ' || true)
echo "    Remaining processes: $remaining_procs"
remaining_ports=$(ss -tlnp 2>/dev/null | grep -cE ':(3000|3001|3100|9998|9997) ' || true)
echo "    Port 3000/3001/3100/9998/9997 in use: $remaining_ports"
# Processes/ports alone printed a false "Environment is clean" while unit
# files, drop-in dirs, empty slices and the guest TCB survived (observed
# after a quick-start uninstall). Verify every artifact class this script
# owns — all baremetal-owned; the e2e battery root is NOT ours to assert.
# The operator-installed seed-fetch unit is deliberately kept (see the
# header) and must not count as residue.
remaining_units=$(ls -d /etc/systemd/system/sandswap-*.service /etc/systemd/system/sandswap-*.service.d 2>/dev/null \
    | grep -v '/sandswap-seed-fetch\.service$' | wc -l | tr -d ' ' || true)
echo "    Remaining unit files / drop-in dirs: $remaining_units"
remaining_slices=$(systemctl list-units 'system-sandswap-*.slice' --all --no-legend --no-pager 2>/dev/null | grep -c . || true)
echo "    Loaded sandswap slices: $remaining_slices"
remaining_libart=0
for _p in "$SANDSWAP_GUEST_DIR" \
          /usr/local/lib/sandswap/runtime.sh \
          /usr/local/lib/sandswap/apply-prov-ownership; do
    [[ -e "$_p" ]] && remaining_libart=$((remaining_libart + 1))
done
echo "    Remaining installed-lib artifacts (guest TCB / runtime helpers): $remaining_libart"
unset _p
# Mounts: a surviving nosuid,nodev self-bind on the volumes root outlived a
# "clean" uninstall verdict (the step-8 single-shot umount failed silently),
# so the check names it instead of laundering it.
remaining_mounts=$(grep -cE ' /(var/lib/sandswap|mnt/sandswap)' /proc/mounts 2>/dev/null || true)
echo "    Remaining sandswap mounts: $remaining_mounts"
echo ""
if [[ "$remaining_procs" == "0" && "$remaining_ports" == "0" \
      && "$remaining_units" == "0" && "$remaining_slices" == "0" \
      && "$remaining_libart" == "0" && "$remaining_mounts" == "0" ]]; then
    echo "  ✓ Environment is clean"
else
    echo "  ⚠ Some residue remains - manual cleanup may be needed"
fi
