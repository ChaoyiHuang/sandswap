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
# verify-host-security.sh — verify the host invariants that make a sandlot
# node resist a non-root local user: the sandlot↔warden vhost-vsock transport
# (active impersonation via vsockguard AND passive sniffing) and, when the
# egress identity enabler is on, the binding region (shm / bpffs) whose write
# integrity the vendor enforcers trust.
# See docs/deployment/prerequisites.md for the full rationale. This script is a
# machine-checkable form of that page's invariant table. Run as root (so it can
# read sysctls/device perms reliably) on every node after setup and after any
# kernel/sysctl change. Exits non-zero if any invariant fails (advisory
# warnings never affect the exit code).

set -u

PASS=0
FAIL=0
WARN=0

ok()   { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL+1)); }
warn() { echo "  ⚠ $1"; WARN=$((WARN+1)); }

# check_status_ids <status-file> <want-uid> <want-gid> prints a space-prefixed
# mismatch list (empty = all four uid/gid values match). Shared by the live
# sandvmm check and the SANDSWAP_VERIFY_IDS_PROBE self-test so the parsing
# cannot drift from what the deployment check actually enforces.
check_status_ids() {
    local file="$1" want_uid="$2" want_gid="$3" bad=""
    local ruid euidv suid fsuid rgid egidv sgid fsgid v
    read -r ruid euidv suid fsuid < <(awk '/^Uid:/{print $2, $3, $4, $5}' "$file" 2>/dev/null) || true
    read -r rgid egidv sgid fsgid < <(awk '/^Gid:/{print $2, $3, $4, $5}' "$file" 2>/dev/null) || true
    for v in "${ruid:-}" "${euidv:-}" "${suid:-}" "${fsuid:-}"; do
        [[ "$v" == "$want_uid" ]] || bad="$bad uid=$v"
    done
    for v in "${rgid:-}" "${egidv:-}" "${sgid:-}" "${fsgid:-}"; do
        [[ "$v" == "$want_gid" ]] || bad="$bad gid=$v"
    done
    printf '%s' "$bad"
}

# Pin-harness mode for the four-value identity parser: classify one status
# fixture without touching the live host. Exit 0 = all four uid/gid values
# match, 1 = mismatch (printed), 2 = bad invocation.
if [[ -n "${SANDSWAP_VERIFY_IDS_PROBE:-}" ]]; then
    if [[ -z "${SANDSWAP_VERIFY_IDS_UID:-}" || -z "${SANDSWAP_VERIFY_IDS_GID:-}" ]]; then
        echo "SANDSWAP_VERIFY_IDS_UID/SANDSWAP_VERIFY_IDS_GID are required" >&2
        exit 2
    fi
    _ids_bad="$(check_status_ids "$SANDSWAP_VERIFY_IDS_PROBE" "$SANDSWAP_VERIFY_IDS_UID" "$SANDSWAP_VERIFY_IDS_GID")"
    if [[ -z "$_ids_bad" ]]; then
        exit 0
    fi
    printf '%s\n' "$_ids_bad"
    exit 1
fi

# The DEDICATED provision group the volume-name seed is scoped to in every
# deployment shape (see the seed section below; overridable for a fleet that
# renamed the identity).
SANDPROV_GROUP="${SANDPROV_GROUP:-sandprov}"

# ── seed read predicate: ONE implementation, two callers ────────────────────
# seed_read_verdict <file> <user> prints exactly one of:
#   readable | denied | inconclusive: <why>
# It runs the REAL read as <user>, with that user's real group set from this
# host's identity table (setpriv --reuid/--regid/--groups) — the mode alone is
# never the point, the READ is. Callers below: the deployment check (as the
# daemon identity and as the prov identity) and the pin harness
# (e2e/deploy-tree-pins.sh) through SANDSWAP_VERIFY_SEED_PROBE, so the harness
# exercises THIS classification and can never drift from it.
seed_read_verdict() {
    local file="$1" user="$2" groups out rc
    if ! id -u "$user" >/dev/null 2>&1; then
        printf 'inconclusive: no such identity: %s' "$user"
        return 0
    fi
    if ! command -v setpriv >/dev/null 2>&1; then
        printf 'inconclusive: setpriv (util-linux) not installed'
        return 0
    fi
    groups="$(id -G "$user" 2>/dev/null | tr ' ' ',')"
    out="$(setpriv --reuid="$user" --regid="$(id -gn "$user" 2>/dev/null || echo "$user")" \
        --groups="$groups" -- cat "$file" 2>&1)"; rc=$?
    if [[ $rc -eq 0 ]]; then
        printf 'readable'
    elif [[ "$out" == *"Permission denied"* ]]; then
        printf 'denied'
    else
        printf 'inconclusive: %s' "${out:-empty probe output}"
    fi
}

# Pin-harness mode: classify ONE file with the same predicate and exit
# 0 (denied) / 1 (readable) / 2 (could not classify). Scratch seed files fed
# through this are how the pin proves a readable seed is a FAIL, not a "warn"
# or an accident of string matching.
if [[ -n "${SANDSWAP_VERIFY_SEED_PROBE:-}" ]]; then
    _probe_verdict="$(seed_read_verdict "$SANDSWAP_VERIFY_SEED_PROBE" "${SANDSWAP_VERIFY_SEED_PROBE_USER:-sandvmm}")"
    printf '%s\n' "$_probe_verdict"
    case "$_probe_verdict" in
        readable) exit 1 ;;
        denied)   exit 0 ;;
        *)        exit 2 ;;
    esac
fi

# ── configured storage paths ───────────────────────────────────────────────
# Checks 8/9 resolve the share root / template stores from the deployment's
# sandlot configs (a dedicated-prov host may mount /mnt/sandswap), not from
# the default /var/lib/sandswap. Parse the configs with the Go loader's YAML
# semantics and check every path they name; an unparsable config is
# surfaced, never silently skipped.
_sandlot_config_paths() {
    local cfg
    for cfg in /etc/sandswap/sandlot*.yaml; do
        [[ -f "$cfg" ]] || continue
        python3 - "$cfg" <<'PY' 2>/dev/null || printf 'unparsed\t%s\n' "$cfg"
import os, sys
try:
    import yaml
except Exception:
    sys.exit(3)
cfg = sys.argv[1]
with open(cfg) as f:
    doc = yaml.safe_load(f) or {}
def emit(kind, v):
    if not v:
        return
    v = str(v).strip()
    if not os.path.isabs(v):
        v = os.path.join(os.path.dirname(os.path.abspath(cfg)), v)
    print("%s\t%s" % (kind, v))
emit("volroot", (doc.get("microvm") or {}).get("volumes_dir"))
emit("tpl", doc.get("overlayfs_templates"))
prov = doc.get("provision") or {}
emit("tpl", prov.get("templates_dir"))
emit("flat", prov.get("flat_templates_dir"))
PY
    done
}
_CFG_VOLROOTS=()
_CFG_TPLDIRS=()
_CFG_PATH_WARN=""
if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
    while IFS=$'\t' read -r _kind _path; do
        case "$_kind" in
            volroot) _CFG_VOLROOTS+=("$_path") ;;
            tpl|flat) _CFG_TPLDIRS+=("$_path") ;;
            unparsed) _CFG_PATH_WARN="$_CFG_PATH_WARN $_path" ;;
        esac
    done < <(_sandlot_config_paths)
else
    _CFG_PATH_WARN="(python3/PyYAML unavailable)"
fi

echo "=== host security invariants: vsock transport + egress identity binding region ==="
echo "(see docs/deployment/prerequisites.md)"
echo

# ── 1. ptrace_scope ≥ 1 ─────────────────────────────────────────────────────
echo "[1/13] kernel.yama.ptrace_scope ≥ 1  (blocks cross-UID ptrace of sandlot)"
ps="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo '')"
if [[ "$ps" =~ ^[0-9]+$ ]] && (( ps >= 1 )); then
    ok "ptrace_scope=$ps"
else
    bad "ptrace_scope='${ps:-unset}' (< 1)"
    echo "      fix: echo 'kernel.yama.ptrace_scope = 1' > /etc/sysctl.d/99-sandswap-ptrace.conf; sysctl -w kernel.yama.ptrace_scope=1"
fi

# ── 2. perf_event_paranoid ≥ 2 ──────────────────────────────────────────────
echo "[2/13] kernel.perf_event_paranoid ≥ 2  (blocks non-root eBPF payload tracing)"
pp="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo '')"
if [[ "$pp" =~ ^-?[0-9]+$ ]] && (( pp >= 2 )); then
    ok "perf_event_paranoid=$pp"
else
    bad "perf_event_paranoid='${pp:-unset}' (< 2)"
    echo "      fix: echo 'kernel.perf_event_paranoid = 4' > /etc/sysctl.d/99-sandswap-perf.conf; sysctl -w kernel.perf_event_paranoid=4"
fi

# ── 3. dedicated sandlot service account exists ─────────────────────────────
echo "[3/13] dedicated sandlot service UID  (blocks same-UID ptrace by untrusted users)"
if id sandlot >/dev/null 2>&1; then
    shell="$(getent passwd sandlot | cut -d: -f7)"
    if [[ "$shell" == */nologin || "$shell" == */false ]]; then
        ok "sandlot account exists (shell=$shell, non-login)"
    else
        bad "sandlot account exists but shell='$shell' is a login shell — use /sbin/nologin"
        echo "      fix: usermod -s /sbin/nologin sandlot"
    fi
else
    bad "no 'sandlot' service account"
    echo "      fix: groupadd -r sandlot; useradd -r -s /sbin/nologin -g sandlot sandlot"
fi

# ── 4. /dev/kvm and /dev/vhost-vsock not world-accessible ───────────────────
echo "[4/13] device admissions: /dev/kvm exactly 660 root:kvm + sandlot in kvm; other devices not world-writable"
check_dev() {
    local dev="$1"
    if [[ ! -e "$dev" ]]; then
        bad "$dev missing"
        return
    fi
    local mode
    mode="$(stat -c '%a' "$dev")"
    # world-writable bit (last octal digit & 2) means others can write => too open
    if (( 8#$mode & 002 )); then
        bad "$dev is world-writable (mode=$mode)"
        echo "      fix: install deploy/udev/99-sandswap-vsock.rules; udevadm trigger"
    else
        ok "$dev mode=$mode (not world-writable)"
    fi
}
check_dev /dev/vhost-vsock
check_dev /dev/vsock
# /dev/net/tun is host interface-creation capability (TAPs): it must never be
# world-writable (the deploy udev rule scopes it 0660 root:kvm; runtime.sh
# leaves 0666 only on identity-less dev hosts, where the shared group does
# not exist yet).
check_dev /dev/net/tun

# /dev/kvm gets the EXACT-shape assertion: the others-write bit alone
# passes 0660 root:root, 0620, 0664 and any extra group — all of which admit
# identities to VM creation that the threat model does not ("in group kvm" IS
# the VM-creation admission). 0660 root:kvm is the shipped shape, and the
# running sandlot identity must be a kvm member or every VM creation fails.
if [[ ! -e /dev/kvm ]]; then
    bad "/dev/kvm missing"
else
    kvm_spec="$(stat -c '%a %U:%G' /dev/kvm)"
    kvm_mode="${kvm_spec%% *}"; kvm_own="${kvm_spec##* }"
    if [[ "$kvm_mode" == "660" && "$kvm_own" == "root:kvm" ]]; then
        ok "/dev/kvm mode=660 root:kvm (exact)"
    else
        bad "/dev/kvm is $kvm_mode $kvm_own, expected exactly 660 root:kvm — every deviation admits identities to VM creation (kvm group membership); stock Ubuntu ships 660 root:kvm"
        echo "      fix: chown root:kvm /dev/kvm && chmod 660 /dev/kvm  (and check udev/systemd overrides)"
    fi
fi
if id sandlot >/dev/null 2>&1; then
    if id -nG sandlot 2>/dev/null | tr ' ' '\n' | grep -qx kvm; then
        ok "the sandlot identity is a kvm-group member (VM creation admission)"
    else
        bad "the sandlot identity is NOT a kvm-group member — VM creation fails (add: usermod -aG kvm sandlot)"
    fi
fi

# ── 5. egress identity binding region, shm carrier ─────────────────────────
# Only meaningful when the enabler is on: an absent region means
# -binding-backend=off (default) — or a k8s pod-local /dev/shm that this
# host-level script cannot see (check inside the pod instead).
SHM_REGION=/dev/shm/sandswap-bindings
BPF_PIN=/sys/fs/bpf/sandswap/bindings
BPF_DIR=/sys/fs/bpf/sandswap

echo "[5/13] binding region (shm) owner + mode  (write integrity = sandlot owner only)"
if [[ ! -e "$SHM_REGION" ]]; then
    echo "  – not in use ($SHM_REGION absent: -binding-backend=off, or pod-local under k8s)"
else
    mode="$(stat -c '%a' "$SHM_REGION")"
    owner="$(stat -c '%u' "$SHM_REGION")"
    if (( (8#$mode & 8#022) != 0 )); then
        bad "$SHM_REGION is group/world-writable (mode=$mode) — any local user could forge identities"
        echo "      fix: chmod 0640 $SHM_REGION (the write set must be the sandlot owner only)"
    else
        ok "$SHM_REGION mode=$mode (not group/world-writable)"
    fi
    sandlot_uid="$(id -u sandlot 2>/dev/null || true)"
    if [[ "$owner" == "0" || "$owner" == "$sandlot_uid" ]]; then
        ok "$SHM_REGION owned by uid $owner (root/sandlot)"
    else
        bad "$SHM_REGION owned by uid $owner — neither root nor the sandlot account (pre-creation squatting pattern: that uid could read and forge every published identity)"
        echo "      fix: rm $SHM_REGION and restart sandlot (it recreates the file as itself; enforcers must watch st_ino — see docs/how-it-works/egress-enabler.md)"
    fi
    if (( (8#$mode & 8#004) != 0 )); then
        warn "$SHM_REGION is world-readable — tenant topology (which TAP carries which agent) readable by all; restrict to the vendor enforcer group"
    fi
fi
# Advisory (the bindreg writer already hard-checks ownership at open; this
# sysctl is the system-wide depth for the symlink/hardlink family).
psl="$(cat /proc/sys/fs/protected_symlinks 2>/dev/null || echo '')"
if [[ "$psl" =~ ^[0-9]+$ ]] && (( psl >= 1 )); then
    ok "fs.protected_symlinks=$psl (sticky-dir symlink planting restricted)"
else
    warn "fs.protected_symlinks='${psl:-unset}' (< 1) — symlink planting in world-writable dirs unrestricted"
fi

# ── 6. egress identity binding region, bpf carrier ─────────────────────────
echo "[6/13] binding region (bpf) pin + bpffs dir  (bpffs DAC gates mmap write)"
if [[ ! -e "$BPF_PIN" ]]; then
    echo "  – not in use ($BPF_PIN absent: other carrier, or pod-local under k8s)"
else
    pin_mode="$(stat -c '%a' "$BPF_PIN")"
    if (( (8#$pin_mode & 8#002) != 0 )); then
        bad "$BPF_PIN is world-writable (mode=$pin_mode) — any local user could forge identities"
        echo "      fix: chown <sandlot-uid>:<gid> + chmod 0660 (the k8s boxout handoff shape) or 0640 with a vendor read group; NEVER 0666"
    else
        ok "$BPF_PIN mode=$pin_mode (not world-writable)"
    fi
    if (( (8#$pin_mode & 8#020) != 0 )); then
        warn "$BPF_PIN is group-writable (mode=$pin_mode) — the ONLY way to share a pin (BPF_OBJ_GET opens O_RDWR; group bits are write grants, no read-only fd exists). Acceptable while the group is the dedicated sandlot gid (k8s boxout handoff shape)"
    fi
    if [[ -d "$BPF_DIR" ]]; then
        dir_mode="$(stat -c '%a' "$BPF_DIR")"
        if (( (8#$dir_mode & 8#022) != 0 )); then
            bad "$BPF_DIR is group/world-writable (mode=$dir_mode) — the pin beneath it could be replaced"
        else
            ok "$BPF_DIR mode=$dir_mode"
        fi
        # Reachability of the pin's DIRECTORY for the embedded (non-root)
        # writer: capabilities do not bypass DAC, so the bpffs ROOT must be
        # traversable (0711, setup-host.sh's bpf-carrier prep) or every
        # sandlot start dies with "bindreg: pin ...: permission denied".
        root_mode="$(stat -c '%a' /sys/fs/bpf)"
        if (( (8#$root_mode & 8#001) == 0 )); then
            bad "/sys/fs/bpf mode=$root_mode — the sandlot identity cannot traverse to $BPF_DIR (pin $BPF_PIN exists but is unreachable). fix: re-run host prep with the bpf carrier enabled (deploy/baremetal/setup-host.sh under SANDSWAP_BINDING_BACKEND=bpf)"
        else
            ok "/sys/fs/bpf mode=$root_mode (traversable for the embedded writer)"
        fi
    fi
    ubpf="$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo '')"
    if [[ "$ubpf" =~ ^[0-9]+$ ]] && (( ubpf >= 1 )); then
        ok "kernel.unprivileged_bpf_disabled=$ubpf (bpf() map access gated)"
        if (( ubpf >= 2 )); then
            warn "unprivileged_bpf_disabled=2 can also block the BPF_OBJ_GET the unprivileged k8s sandlot writer needs — verify TestBPFUnprivilegedWrite on this exact kernel"
        fi
    else
        warn "kernel.unprivileged_bpf_disabled='${ubpf:-unset}' — unprivileged bpf() map access possible (forging still requires a bpffs DAC bypass)"
    fi
fi

# ── 7. service identities + per-owner vsock device isolation ───────────────
echo "[7/13] service identities + vsock device owners  (VMM separate from the warden-trusted uid)"
# The identity numbers are CONFIGURABLE (occupied-slot adoption/auto-pick in
# common/sh/runtime.sh; SS_UID_*/SS_GID_* pin them for fleets). The verifier
# therefore asserts the SECURITY property — the four accounts exist, are
# pairwise DISTINCT and nonzero (the identity SPLIT is the load-bearing
# control) — and reports each resolved number, rather than the historical
# literals 985/986/987/983.
if id sandserv >/dev/null 2>&1; then
    gwuid="$(id -u sandserv)"
    ok "sandserv account exists (uid=$gwuid, gateway + dns identity)"
else
    gwuid=""
    bad "no 'sandserv' service account (gateway + dns identity) — host prep predates the rename? re-run deploy/baremetal/setup-host.sh"
fi
# The external-facing identity must hold NO supplementary groups: it accesses
# no shared storage (the storage plane lives in the prov instances) and a
# shared-group grant would be exactly the write access this split removes.
if id sandserv >/dev/null 2>&1; then
    if id -nG sandserv | tr ' ' '\n' | grep -qx sandlot; then
        bad "sandserv is a member of the sandlot shared group — it must access no shared storage (run host prep to drop the legacy membership)"
    else
        ok "sandserv holds no shared-group membership (accesses no storage)"
    fi
fi
if id sandprov >/dev/null 2>&1; then
    puid="$(id -u sandprov)"
    ok "sandprov account exists (uid=$puid, provision identity; storage grant carrier)"
else
    puid=""
    bad "no 'sandprov' service account (sandfs/template lifecycle identity) — re-run deploy/baremetal/setup-host.sh"
fi
if id sandvmm >/dev/null 2>&1; then
    vmuid="$(id -u sandvmm)"
    vmgid="$(id -g sandvmm)"
    ok "sandvmm account exists (uid=$vmuid, VMM + FUSE daemon identity)"
    [[ "$(getent passwd sandvmm | cut -d: -f7)" == *nologin* ]] && ok "sandvmm shell is nologin" || bad "sandvmm has a login shell"
else
    vmuid=""
    vmgid=""
    bad "no 'sandvmm' service account (the VMM + FUSE daemon identity)"
    echo "      fix: re-run host prep (deploy/baremetal/setup-host.sh) with an up-to-date common/sh/runtime.sh"
fi
# Pairwise-distinct + nonzero across the four service uids (sandlot is
# checked earlier in this section or resolves here when present). A shared
# number collapses the identity split — always a failure, independent of any
# configuration.
_sluid="$(id -u sandlot 2>/dev/null || true)"
for _pair in "sandlot:$_sluid" "sandserv:$gwuid" "sandprov:$puid" "sandvmm:$vmuid"; do
    _n="${_pair%%:*}"; _v="${_pair#*:}"
    [[ -z "$_v" ]] && continue
    [[ "$_v" =~ ^[0-9]+$ && "$_v" -ne 0 ]] || bad "service uid for $_n is not a nonzero number ($_v)"
done
if [[ -n "$_sluid" && -n "$gwuid" && "$_sluid" == "$gwuid" ]]    || [[ -n "$_sluid" && -n "$puid" && "$_sluid" == "$puid" ]]    || [[ -n "$_sluid" && -n "$vmuid" && "$_sluid" == "$vmuid" ]]    || [[ -n "$gwuid" && -n "$puid" && "$gwuid" == "$puid" ]]    || [[ -n "$gwuid" && -n "$vmuid" && "$gwuid" == "$vmuid" ]]    || [[ -n "$puid" && -n "$vmuid" && "$puid" == "$vmuid" ]]; then
    bad "service identities are NOT pairwise distinct (sandlot=$_sluid sandserv=$gwuid sandprov=$puid sandvmm=$vmuid) — the identity split is broken; re-provision with distinct SS_UID_* values"
else
    ok "service identities pairwise distinct (sandlot=$_sluid sandserv=$gwuid sandprov=$puid sandvmm=$vmuid)"
fi
check_dev_owner() {
    local dev="$1" want_user="$2"
    if [[ ! -e "$dev" ]]; then
        warn "$dev absent on this host"
        return
    fi
    local owner mode
    owner="$(stat -c '%U' "$dev")"; mode="$(stat -c '%a' "$dev")"
    if [[ "$owner" == "$want_user" && "$mode" == "600" ]]; then
        ok "$dev owner=$owner mode=0600 (exactly one process identity)"
    else
        bad "$dev owner=$owner mode=$mode, want OWNER=$want_user 0600"
        echo "      fix: reinstall deploy/udev/99-sandswap-vsock.rules + udevadm trigger, or re-run host prep"
    fi
}
check_dev_owner /dev/vhost-vsock sandvmm
check_dev_owner /dev/vsock sandlot
# Live check when a stack is running: every sandvmm process must be uid 987
# with ZERO capabilities. The network provider pre-creates the persistent TAP
# owned by that uid and pre-configures it (MTU/bridge/up); the VMM's attach is
# an owner-match TUNSETIFF, so no capability is needed.
# The VMM binaries are named `sandvmm` (build output / k8s image) or
# `sandswap-sandvmm` (the bare-metal install name, which microvm.vmm_binary
# points at); enumerate by the /proc exe image, never by comm (truncated) or
# argv (forgeable).
_sandvmm_pids() {
    local _p _pid _exe _base
    for _p in /proc/[0-9]*; do
        _pid="${_p#/proc/}"
        [[ "$_pid" =~ ^[0-9]+$ ]] || continue
        _exe="$(readlink "$_p/exe" 2>/dev/null)" || continue
        _base="${_exe##*/}"; _base="${_base% (deleted)}"
        case "$_base" in
            sandvmm|sandswap-sandvmm) echo "$_pid" ;;
        esac
    done
}
SVMM_PIDS="$(_sandvmm_pids)"
if [[ -n "$SVMM_PIDS" ]]; then
    bad_pids=""
    seed_leak_pids=""
    seed_gid="$(getent group "$SANDPROV_GROUP" | cut -d: -f3)"
    for pid in $SVMM_PIDS; do
        uid="$(ps -o uid= -p "$pid" 2>/dev/null | tr -d ' ')"
        eff="$(grep '^CapEff:' "/proc/$pid/status" 2>/dev/null | awk '{print $2}')"
        # Compare against the ACCOUNT's uid (id -u sandvmm) — the number is
        # configurable per host; the invariant is that the live process runs
        # as the sandvmm ACCOUNT with zero capabilities.
        if [[ -z "$vmuid" ]]; then vmuid="$(id -u sandvmm 2>/dev/null || echo '?')"; fi
        if [[ -z "$vmgid" ]]; then vmgid="$(id -g sandvmm 2>/dev/null || echo '?')"; fi
        # All FOUR uid/gid values (real, effective, saved, fs) must be the
        # sandvmm account. A process left with saved-uid 0 — a setpriv
        # oddity, or a spawn that did not transition cleanly — passes a
        # CapEff-only check but can later setresuid(-1,0,-1) back to root,
        # collapsing the identity split the FUSE daemon depends on.
        bad_ids="$(check_status_ids "/proc/$pid/status" "$vmuid" "$vmgid")"
        if [[ "$uid" != "$vmuid" || $((16#${eff:-0})) -ne 0 || -n "$bad_ids" ]]; then
            bad_pids="$bad_pids $pid(uid=$uid,capeff=${eff:-?}${bad_ids})"
        fi
        # The seed's dedicated group must not be in a sandvmm process's
        # supplementary set: with it, the FUSE daemon reads the seed and every
        # tenant's derived name (the same hole the file-mode check catches
        # statically — this is the live form, and it also catches a
        # microvm.vmm_groups config that hands the group down).
        #
        # /proc/<pid>/status separates the gid list from "Groups:" with a TAB,
        # so parsing with cut and matching " $gid " missed the FIRST gid of
        # every process (the sorted 983-led list a leak actually produces).
        # awk splits on all whitespace; the printf pads each gid with a space
        # so the membership test is exact.
        if [[ -n "$seed_gid" ]]; then
            grp="$(awk '/^Groups:/{for(i=2;i<=NF;i++) printf " %s", $i}' "/proc/$pid/status" 2>/dev/null)"
            [[ " $grp " == *" $seed_gid "* ]] && seed_leak_pids="$seed_leak_pids $pid"
        fi
    done
    if [[ -z "$bad_pids" ]]; then
        ok "running sandvmm processes: uid/gid four-value == sandvmm (uid=$vmuid), CapEff=0 (zero capabilities; identity split live)"
    else
        bad "sandvmm processes outside the split identity:$bad_pids"
        echo "      fix: restart sandlot (stale same-identity processes from before the split)"
    fi
    if [[ -n "$seed_leak_pids" ]]; then
        bad "sandvmm process(es) carry the seed's group $SANDPROV_GROUP:$seed_leak_pids — the FUSE daemon could read the volume-name seed"
        echo "      fix: the sandvmm spawn must set its supplementary groups EXPLICITLY (sandlot/vmm/launcher.go: setpriv --groups = microvm.vmm_groups only, --clear-groups when empty) and microvm.vmm_groups must not name the seed group; restart sandlot"
    elif [[ -n "$seed_gid" ]]; then
        ok "running sandvmm processes do not carry the seed's group ($SANDPROV_GROUP)"
    fi
else
    echo "  – no sandvmm running (live identity check skipped)"
fi
unset SVMM_PIDS

# ── 8. volumes/template mounts carry nosuid,nodev ──────────────────────────
# The virtio-fs passthrough stores guest-requested mode bits (incl. setuid)
# and mknod verbatim on the host volume, and guest-created files are owned by
# the sandvmm identity (987) — NOT the uid vsockguard trusts on the warden
# vsock port, so the identity split already breaks the escalation chain. A
# setuid binary planted by a guest and executed by any host user therefore
# escalates to an identity with no warden access (still a boundary crossing),
# and planted device nodes would be live host devices. The mount flags make
# both inert host-side; the guest side is covered by the warden's
# NO_NEW_PRIVS + nosuid share mounts (asserted in e2e/seccomp.sh).
#
# Checked for EVERY storage path the deployment config names (the share root
# and each template store), not only the default tree: a dedicated-prov host
# mounts its storage at a different path, and a check that only ever looked at
# /var/lib/sandswap reported "absent" while the real tree went unexamined.
_verify_mount_nosuid_nodev() {
    local _path="$1"
    if [[ ! -d "$_path" ]]; then
        echo "  – $_path absent on this host (not this shape's storage root)"
        return
    fi
    local mnt_target mnt_opts missing
    mnt_target="$(findmnt -T "$_path" -n -o TARGET 2>/dev/null || true)"
    mnt_opts="$(findmnt -T "$_path" -n -o OPTIONS 2>/dev/null || true)"
    if [[ -z "$mnt_target" ]]; then
        warn "cannot resolve the mount containing $_path (findmnt failed)"
    elif [[ "$mnt_target" == "/" && ",$mnt_opts," == *,nosuid,* && ",$mnt_opts," == *,nodev,* ]]; then
        # The setup-host bind-remount: a bind instance of the same directory
        # carries the contract flags while the data stays on the root
        # filesystem — full compliance for local-disk dev shapes.
        ok "$_path on a root-fs bind mount with nosuid,nodev (setup-host bind-remount)"
    elif [[ "$mnt_target" == "/" ]]; then
        # LOCAL-DISK DEVELOPMENT shapes accept this deviation knowingly;
        # PRODUCTION shared-storage shapes must satisfy storage-contract row 9.
        warn "$_path sits on the root filesystem without the bind-remount flags — run setup-host.sh (bind-remounts nosuid,nodev), or accept the dev-shape deviation; production storage shapes must mount a dedicated filesystem nosuid,nodev (docs/operations/storage.md)"
    else
        missing=""
        [[ ",$mnt_opts," == *,nosuid,* ]] || missing="nosuid"
        [[ ",$mnt_opts," == *,nodev,* ]] || missing="${missing:+$missing }nodev"
        if [[ -z "$missing" ]]; then
            ok "$_path on $mnt_target mounted nosuid,nodev"
        else
            bad "$_path on $mnt_target missing mount option(s): $missing (options: $mnt_opts)"
            echo "      fix: remount -o remount,nosuid,nodev $mnt_target  and add the options to its fstab/NFS-export entry (must hold on EVERY consumer host of shared storage)"
        fi
    fi
}
VOL_CHECK_PATH="${VOL_CHECK_PATH:-${_CFG_VOLROOTS[0]:-/var/lib/sandswap/volumes}}"
echo "[8/13] storage mounts nosuid,nodev  (guest-planted setuid bits / device nodes inert host-side)"
if [[ -n "$_CFG_PATH_WARN" ]]; then
    warn "some sandlot config paths could NOT be resolved for this check:$_CFG_PATH_WARN — only the default/overridden paths below were examined"
fi
declare -A _mount_checked=()
for _mp in "$VOL_CHECK_PATH" ${_CFG_VOLROOTS[@]+"${_CFG_VOLROOTS[@]}"} ${_CFG_TPLDIRS[@]+"${_CFG_TPLDIRS[@]}"}; do
    [[ -n "$_mp" ]] || continue
    [[ -n "${_mount_checked[$_mp]:-}" ]] && continue
    _mount_checked[$_mp]=1
    _verify_mount_nosuid_nodev "$_mp"
done
unset _mp _mount_checked

# ── 9. the virtio-fs share root is read-only for the daemon identity ───────
# The fourth isolation layer. The FUSE daemon runs as the sandvmm identity
# (987), a member of the shared group, so host DAC alone cannot separate one
# tenant's directory from another's — the allow-list does that. But the SHARE
# ROOT itself has exactly one legitimate writer (the prov instance), so it can
# additionally be closed in the KERNEL: owner = prov, group = shared with
# TRAVERSE only (mode 2710 — no list, no write). Reaching a volume needs
# TRAVERSE on the root, never write,
# so guest read/write inside a sandfs is untouched; what this buys is that a
# guest-driven escape naming something AT the share root (mkdir/unlink/rename
# beside the allowed directory) fails with EACCES even if the daemon's own root
# gate is ever regressed away.
# See docs/operations/storage.md and docs/how-it-works/isolation-and-swap.md §4.
# Template-store metadata tree: refs/ is 2750 and belongs to the template
# metadata group (sandtmpl), NOT the shared volume group — the FUSE daemon
# (sandvmm) reads layer CONTENT through the shared group and must not be able
# to enumerate or read refs. Advisory when the group is absent (a host that
# predates the group keeps the shared group; the mode still hides every other
# local user).
TPL_DIR_CHECK="${TPL_DIR_CHECK:-${_CFG_TPLDIRS[0]:-${TEMPLATES_DIR:-/var/lib/sandswap/templates}}}"
if [[ -d "$TPL_DIR_CHECK/refs" ]]; then
    _refs="$TPL_DIR_CHECK/refs"
    _rmode="$(stat -c '%a' "$_refs" 2>/dev/null || echo '?')"
    _rgrp="$(stat -c '%G' "$_refs" 2>/dev/null || echo '?')"
    _rgid="$(stat -c '%g' "$_refs" 2>/dev/null || echo '?')"
    if [[ "$_rmode" == 2750 || "$_rmode" == 750 ]]; then
        ok "template refs dir mode $_rmode (no other bits)"
    else
        bad "template refs dir mode $_rmode — want 2750 (world-hidden)"
    fi
    if [[ "$_rgrp" == "${SS_GROUP_TPL:-sandtmpl}" || "$_rgid" == "${SS_GID_TPL:-982}" ]]; then
        ok "template refs dir is in the metadata group ($_rgrp)"
    else
        warn "template refs dir group is $_rgrp, expected ${SS_GROUP_TPL:-sandtmpl} — re-run host prep / the prov instance so refs is chgrp'd (otherwise sandvmm can enumerate refs)"
    fi
    _rf="$(find "$_refs" -maxdepth 1 -type f -name '*.json' -print -quit 2>/dev/null)"
    if [[ -n "$_rf" ]] && id -u sandvmm >/dev/null 2>&1 && command -v setpriv >/dev/null 2>&1; then
        _rv="$(seed_read_verdict "$_rf" sandvmm)"
        case "$_rv" in
            denied) ok "sandvmm cannot read a ref file ($(basename "$_rf"))" ;;
            readable) bad "sandvmm CAN read $(basename "$_rf") — refs must be in the metadata group, not the shared volume group" ;;
            *) warn "sandvmm ref-read probe inconclusive: $_rv" ;;
        esac
    fi
else
    warn "no template store refs/ under $TPL_DIR_CHECK (nothing to check)"
fi

VOL_ROOT_CHECK="${VOL_ROOT_CHECK:-${_CFG_VOLROOTS[0]:-/var/lib/sandswap/volumes}}"
echo "[9/13] virtio-fs share root not writable by the FUSE daemon  ($VOL_ROOT_CHECK)"
if [[ -d "$VOL_ROOT_CHECK" ]]; then
    root_mode="$(stat -c '%a' "$VOL_ROOT_CHECK" 2>/dev/null || echo '')"
    root_owner="$(stat -c '%U:%G' "$VOL_ROOT_CHECK" 2>/dev/null || echo '')"
    perms="${root_mode: -3}"   # %a prints the setgid as a leading digit
    if [[ ! "$perms" =~ ^[0-7]{3}$ ]]; then
        warn "cannot parse the mode of $VOL_ROOT_CHECK (got '$root_mode')"
    else
        g=$(( 8#${perms:1:1} ))
        if (( g & 2 )); then
            bad "$VOL_ROOT_CHECK is group-writable ($root_mode $root_owner) — the FUSE daemon identity (a shared-group member) can create entries at the share root"
            echo "      fix: chown <prov-user>:${SS_SHARED_GROUP:-sandlot} $VOL_ROOT_CHECK && chmod 2710 $VOL_ROOT_CHECK  (ss_prepare_dirs / sandswap_create_dirs do this)"
        else
            ok "$VOL_ROOT_CHECK: the shared group has no write ($root_mode $root_owner)"
        fi
        if (( g & 4 )); then
            bad "$VOL_ROOT_CHECK is group-READABLE ($root_mode) — the daemon identity could list the root and enumerate every tenant's directory name"
            echo "      fix: chmod 2710 $VOL_ROOT_CHECK  (traverse-only: guests reach their own volume, nobody lists the root)"
        else
            ok "$VOL_ROOT_CHECK: the shared group cannot list the root (traverse-only)"
        fi
        if (( (g & 1) == 0 )); then
            bad "$VOL_ROOT_CHECK has no group traverse bit ($root_mode) — the daemon could not reach any volume"
        fi
    fi
    if [[ "${root_mode:0:1}" == "2" || "${root_mode:0:1}" == "6" ]]; then
        ok "$VOL_ROOT_CHECK: setgid kept (volumes created inside inherit the shared group)"
    else
        bad "$VOL_ROOT_CHECK lacks the setgid bit ($root_mode) — volumes created inside would not inherit the shared group"
        echo "      fix: chmod g+s $VOL_ROOT_CHECK"
    fi

    # Shape contract: the
    # share root's OWNER must be THIS deployment's prov identity, which the
    # deployer pins in /etc/sandswap/prov-user.env (sandprov for a dedicated
    # prov instance, sandlot for the merged exec,prov shape). A mismatched
    # owner means the prov instance cannot create volumes (EACCES) — or, worse,
    # a shape flip silently widened the root. Live assertion of the
    # sandswap_apply_prov_plane contract.
    expected_prov="sandprov"
    [[ -f /etc/sandswap/prov-user.env ]] && . /etc/sandswap/prov-user.env && expected_prov="${SS_PROV_USER:-sandprov}"
    owner_user="${root_owner%%:*}"
    if [[ "$owner_user" == "$expected_prov" ]]; then
        ok "$VOL_ROOT_CHECK: owner matches the deployment shape's prov identity ($expected_prov)"
    else
        bad "$VOL_ROOT_CHECK owner is '$owner_user', but prov-user.env says the prov identity is '$expected_prov' — the prov plane cannot create volumes (or the shape flip was not applied)"
        echo "      fix: re-run the deployer (sandswap_apply_prov_plane) or: chown $expected_prov:${SS_SHARED_GROUP:-sandlot} $VOL_ROOT_CHECK"
    fi
    # Live probe with the daemon identity itself: write must be REFUSED, and
    # traversal must still work. Both are asserted on the actual error, not on
    # an exit code: a probe that failed for any other reason (setpriv unable to
    # switch, a missing binary) must not be able to masquerade as "the layer
    # holds" — measured while writing this check: coreutils' `test -x` reports
    # false for a directory this identity can clearly cd into, which is exactly
    # the kind of ambiguity a security check must not paper over.
    if id -u sandvmm >/dev/null 2>&1 && command -v setpriv >/dev/null 2>&1; then
        dgrp="$(id -G sandvmm 2>/dev/null | tr ' ' ',')"
        probe_err="$(setpriv --reuid=sandvmm --regid=sandvmm --groups="$dgrp" -- \
            touch "$VOL_ROOT_CHECK/.verify-host-security-write-probe" 2>&1)"
        probe_rc=$?
        if (( probe_rc == 0 )); then
            rm -f "$VOL_ROOT_CHECK/.verify-host-security-write-probe"
            bad "the sandvmm identity CREATED a file at $VOL_ROOT_CHECK — the layer is not in force"
        elif [[ "$probe_err" == *"Permission denied"* ]]; then
            ok "sandvmm cannot create an entry at the share root (kernel EACCES)"
        else
            warn "write probe did not run (or failed for a non-permission reason): ${probe_err:-rc=$probe_rc}"
        fi
        list_err="$(setpriv --reuid=sandvmm --regid=sandvmm --groups="$dgrp" -- ls "$VOL_ROOT_CHECK" 2>&1)"
        list_rc=$?
        if (( list_rc == 0 )); then
            # Exit 0 means the listing SUCCEEDED — including on an empty
            # root, where there is simply no output. The old branch keyed on
            # empty output and therefore reached `bad` only for an EMPTY
            # directory: the populated-root failure fell into `warn`.
            bad "the sandvmm identity LISTED $VOL_ROOT_CHECK (exit 0) — every tenant's directory name is enumerable"
        elif [[ "$list_err" == *"Permission denied"* ]]; then
            ok "sandvmm cannot LIST the share root (tenant names are not enumerable, kernel EACCES)"
        else
            warn "list probe did not run: $list_err"
        fi

        # The template store: the daemon READS layers (overlay lowerdirs) and
        # must never be able to write, replace or rename template content —
        # the store is shared across nodes, so a compromised daemon could
        # otherwise swap layers/ or refs/ out for every tenant.
        for tpl in "${TEMPLATES_CHECK:-/var/lib/sandswap/templates}" "${FLAT_TEMPLATES_CHECK:-/var/lib/sandswap/flat-templates}"; do
            [[ -d "$tpl" ]] || continue
            tpl_err="$(setpriv --reuid=sandvmm --regid=sandvmm --groups="$dgrp" -- \
                touch "$tpl/.verify-host-security-write-probe" 2>&1)"
            if (( $? == 0 )); then
                rm -f "$tpl/.verify-host-security-write-probe"
                bad "the sandvmm identity WROTE into $tpl — template content is replaceable by a compromised daemon"
            elif [[ "$tpl_err" == *"Permission denied"* ]]; then
                ok "sandvmm cannot write $tpl (template content is daemon-read-only)"
            else
                warn "template probe on $tpl did not run: $tpl_err"
            fi
        done
        if setpriv --reuid=sandvmm --regid=sandvmm --groups="$dgrp" -- \
                sh -c "cd '$VOL_ROOT_CHECK'" 2>/dev/null; then
            ok "sandvmm can still traverse the share root (guest access to its own volume unaffected)"
        else
            bad "sandvmm cannot traverse $VOL_ROOT_CHECK — guests could not reach their own volumes at all"
        fi
    else
        warn "sandvmm identity or setpriv unavailable — live probe skipped (mode checks above still apply)"
    fi
else
    echo "  – $VOL_ROOT_CHECK absent on this host (no volumes here yet; re-run after deploy)"
fi

# The stream client key is this NODE's identity toward the gateway. At 0640
# group-sandlot it was readable by the sandvmm identity (987 is in that group):
# a compromised FUSE daemon could impersonate the node. Owner-only, always.
# PER-NODE pairs (sandlot-<node-id>.key) are the shape on every node whose
# node id is not the default: check every stream client key present, not one
# hard-coded name. An ABSENT key is a silent-pass hazard of its own (a node
# with no key at all would report "nothing to check"), so the check reports
# what it examined either way.
KEY_CHECK="${KEY_CHECK:-/etc/sandswap/certs/sandlot.key}"
key_checked=0
for keyf in "$KEY_CHECK" /etc/sandswap/certs/sandlot-*.key; do
    [[ -f "$keyf" ]] || continue
    key_checked=$((key_checked + 1))
    kmode="$(stat -c '%a' "$keyf" 2>/dev/null || echo '?')"
    if [[ "$kmode" == 600 || "$kmode" == 400 ]]; then
        ok "$keyf is owner-only ($kmode)"
    else
        bad "$keyf is $kmode — group/other readable: the sandvmm identity (same group) can steal this node's stream identity"
        echo "      fix: chown sandlot:sandlot $keyf && chmod 600 $keyf  (ss_own_tls_keys does this)"
    fi
done
if [[ "$key_checked" == 0 ]]; then
    warn "no stream client key found at $KEY_CHECK (or sandlot-*.key beside it) — on a node that runs a sandlot this means the node has no stream identity; on a gateway-only host it is expected"
fi

# The CA PRIVATE key must never live on a node: whoever reads it can mint a
# client certificate for ANY node id (the stream binds node identity to
# the certificate CN), i.e. impersonate any node toward the gateway. Only
# ca.crt belongs here; the reference generator deletes the key after signing.
CA_KEY_CHECK="${CA_KEY_CHECK:-/etc/sandswap/certs/ca.key}"
if [[ -e "$CA_KEY_CHECK" ]]; then
    bad "$CA_KEY_CHECK exists — a CA private key on a node can mint a client certificate for any node id (fleet impersonation)"
    echo "      fix: remove it (the reference generator deletes it after signing); keep the CA key only on the issuing machine"
else
    ok "no CA private key in the service certificate directory"
fi

# The volume-name SEED is what makes tenant directory names unguessable
# (isolation §4.6): every name is sf- + HMAC-SHA256(seed, id), so a seed the
# FUSE daemon can read collapses the name space back to guessable. It must be
# readable by the provision identity ONLY. Checked here as a live read probe
# with the daemon identity — the mode alone is not the point; the READ is.
SEED_CHECK="${SEED_CHECK:-/etc/sandswap/volume-seed}"
# A config may point elsewhere — and during a rotation TWO paths are configured
# at once (current + staged), so every path either key names is checked, not
# just the first one. Relative paths resolve against the config dir.
#
# Parsed with the Go loader's YAML semantics (gopkg.in/yaml.v3), not a regex:
# quotes and trailing comments are YAML syntax, and a hand-rolled strip left
# single-quoted values quoted or glued "# note" onto the path — either way the
# path missed `-f`, the loop skipped it silently, and the run ended on the
# "no seed found" line: a skip dressed as a clean check. A config that cannot
# be parsed is WARNed loudly here (never skipped silently).
SEED_PATHS=("$SEED_CHECK")
seed_cfg_unparsed=""
seed_cfg_pyyaml_missing=0
# The configs to scan: the two standard prov/sandlot paths. Overridable so the
# pin harness can drive the parser against scratch configs without touching a
# live deployment's /etc/sandswap.
SEED_CONFIGS="${SANDSWAP_VERIFY_SEED_CONFIGS:-/etc/sandswap/sandlot-prov.yaml:/etc/sandswap/sandlot.yaml}"
for _cfg in ${SEED_CONFIGS//:/ }; do
    [[ -f "$_cfg" ]] || continue
    _parsed="$(python3 - "$_cfg" <<'PY' 2>/dev/null
import os, sys
try:
    import yaml
except Exception:
    sys.exit(3)
try:
    with open(sys.argv[1]) as f:
        doc = yaml.safe_load(f) or {}
except Exception:
    sys.exit(4)
prov = doc.get("provision") or {}
out = []
for key in ("volume_seed_file", "volume_seed_next_file"):
    v = prov.get(key)
    if not v:
        continue
    v = str(v).strip()
    out.append(v if os.path.isabs(v) else os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), v))
seen = set()
for p in out:
    if p not in seen:
        seen.add(p)
        print(p)
PY
)"; _prc=$?
    if [[ $_prc -eq 3 ]]; then
        seed_cfg_pyyaml_missing=1
    elif [[ $_prc -ne 0 ]]; then
        seed_cfg_unparsed="$seed_cfg_unparsed $_cfg"
    else
        while IFS= read -r _line; do
            [[ -n "$_line" ]] && SEED_PATHS+=("$_line")
        done <<< "$_parsed"
    fi
done
mapfile -t SEED_PATHS < <(printf '%s\n' "${SEED_PATHS[@]}" | awk '!seen[$0]++')

if [[ $seed_cfg_pyyaml_missing -eq 1 ]]; then
    warn "cannot parse the seed-file keys of the prov/sandlot configs: python3 has no PyYAML (install python3-yaml) — only ${SEED_PATHS[0]} is checked, a config pointing elsewhere is NOT"
fi
if [[ -n "$seed_cfg_unparsed" ]]; then
    warn "cannot parse the prov/sandlot config(s):$seed_cfg_unparsed — their seed-file keys were NOT checked (fix the YAML, then re-run)"
fi
# Every path a config NAMED must now be a readable file: a named path that is
# not one is a finding, not a skip (silently dropping it was the hole).
SEED_NAMED_MISSING=()

seed_checked=0
for SEED_CHECK in "${SEED_PATHS[@]}"; do
    if [[ ! -f "$SEED_CHECK" ]]; then
        # The default path is a probe, not a claim: an exec-only host carries
        # no seed at all. A path the CONFIG names is a claim — report it.
        [[ "$SEED_CHECK" != "${SEED_PATHS[0]}" ]] && SEED_NAMED_MISSING+=("$SEED_CHECK")
        continue
    fi
    seed_checked=1
    smode="$(stat -c '%a' "$SEED_CHECK" 2>/dev/null || echo '')"
    sowner="$(stat -c '%U:%G' "$SEED_CHECK" 2>/dev/null || echo '')"
    if [[ ! "$smode" =~ ^[0-7]{3,4}$ ]]; then
        warn "cannot parse the mode of $SEED_CHECK ('$smode') — its scope was NOT checked"
        smode=""
    fi
    # A seed in tmpfs (a fetched/credential generation) is only as private as
    # its DIRECTORY: a WRITABLE parent lets an identity that is not the file's
    # owner replace it outright (directory write alone is enough to unlink an
    # entry), whatever the file's own mode says. Group-write counts exactly as
    # much as world-write here (check 4/9's `& 8#022` idiom) — EXCEPT under a
    # root-owned STICKY bit, where only an entry's owner (or root) may remove
    # it: that is the /run/sandswap shape (3770 root:sandlot, the shared-group
    # runtime dir). The owner assertion matters: a non-root owner could
    # chmod the sticky bit away.
    _pdir="$(dirname "$SEED_CHECK")"
    if [[ "$_pdir" == /run/* || "$_pdir" == /dev/shm/* ]]; then
        _pmode="$(stat -c '%a' "$_pdir" 2>/dev/null || echo '')"
        # Unparsable mode = NOT checked: a FAIL/warn, never the ok branch. The
        # old arithmetic `(( 8#${_pmode: -1} & 2 ))` failed on an empty value
        # and fell through to "ok not world-writable" — a pass from a check
        # that examined nothing (same guard idiom as check 9).
        if [[ ! "$_pmode" =~ ^[0-7]{3,4}$ ]]; then
            warn "cannot parse the mode of $_pdir (the seed's tmpfs directory, got '$_pmode') — the replacement check was NOT performed"
        elif (( (8#${_pmode} & 8#022) == 0 )); then
            ok "the seed's tmpfs directory is not world-writable ($_pdir, $_pmode)"
        elif (( (8#${_pmode} & 8#1000) != 0 )) && [[ "$(stat -c '%U' "$_pdir" 2>/dev/null || echo '')" == "root" ]]; then
            ok "the seed's tmpfs directory is group-writable but STICKY and root-owned ($_pdir, $_pmode) — only an entry's owner (or root) can remove it"
        else
            bad "$_pdir (the seed's directory on tmpfs) is group/world-writable ($_pmode) without a root-owned sticky bit — any member of its group could replace the seed file"
            echo "      fix: chmod 0750 $_pdir && chown root:<prov group> $_pdir  (or a SHARED dir: chmod 3770 $_pdir, sticky so only an entry's owner can remove it)"
        fi
    fi
    # ── the daemon identity must NOT read it ──
    # A live read probe through seed_read_verdict (the ONE predicate): a
    # successful read is a FAIL — a seed the FUSE daemon can read makes every
    # tenant's directory name computable. An inconclusive probe is a warn: it
    # must never be confused with a pass.
    _verdict="$(seed_read_verdict "$SEED_CHECK" sandvmm)"
    case "$_verdict" in
        denied)
            ok "the sandvmm identity cannot read the volume-name seed ($SEED_CHECK, $smode $sowner)"
            ;;
        readable)
            bad "the sandvmm identity READ the volume-name seed ($SEED_CHECK, $smode $sowner) — every tenant's directory name becomes guessable"
            echo "      fix: chown root:$SANDPROV_GROUP $SEED_CHECK && chmod 0640 $SEED_CHECK  (re-run the deployer; the seed's group is the DEDICATED provision group, never the shared group the sandvmm identity belongs to)"
            ;;
        *)
            warn "seed read probe did not run cleanly: ${_verdict#inconclusive: }"
            ;;
    esac

    # ── the seed's GROUP must be the dedicated provision group ──
    # sandprov in EVERY shape — never the shape's prov identity's primary
    # group: the merged shape's prov identity is sandlot, whose primary group
    # IS the shared group the sandvmm identity belongs to, so a seed at
    # root:sandlot 0640 hands the FUSE daemon the whole name space (the same
    # rule scopes every injected generation file —
    # seed-fetch.sh.template).
    if [[ -n "$sowner" && "${sowner##*:}" != "$SANDPROV_GROUP" ]]; then
        bad "$SEED_CHECK group is '${sowner##*:}', but the volume-name seed must be scoped root:$SANDPROV_GROUP 0640 (the dedicated provision group)"
        echo "      fix: chown root:$SANDPROV_GROUP $SEED_CHECK && chmod 0640 $SEED_CHECK  (re-run the deployer); the prov process carries the group — SupplementaryGroups=$SANDPROV_GROUP on the sandlot units, the primary group on the dedicated sandprov unit"
    else
        # ── the prov identity MUST read it ──
        # Live probe with the prov identity as the units grant it: its own
        # groups plus the seed's group (the grant the units provide). Kept
        # from the original check for the class — a shape flip that
        # leaves the prov role locked out of its own seed.
        _prov="${SS_PROV_USER:-sandprov}"
        [[ -f /etc/sandswap/prov-user.env ]] && . /etc/sandswap/prov-user.env && _prov="${SS_PROV_USER:-sandprov}"
        _seed_gid="$(getent group "$SANDPROV_GROUP" | cut -d: -f3)"
        _prov_probe="$(setpriv --reuid="$_prov" --regid="$(id -gn "$_prov" 2>/dev/null || echo "$_prov")" \
            --groups="$(id -G "$_prov" 2>/dev/null | tr ' ' ',')${_seed_gid:+,$_seed_gid}" \
            -- cat "$SEED_CHECK" 2>&1)" || true
        if [[ "$_prov_probe" == *"Permission denied"* ]]; then
            bad "the prov identity '$_prov' cannot read the volume-name seed ($SEED_CHECK, $smode $sowner) — the prov role dies at startup without a readable CURRENT generation"
            echo "      fix: re-run the deployer (sandswap_ensure_volume_seed scopes it root:$SANDPROV_GROUP 0640); for the merged shape confirm the unit grants the group: systemctl show sandswap-sandlot -p SupplementaryGroups"
        elif [[ "$_prov_probe" == *"cannot set"* || "$_prov_probe" == *"no such user"* ]]; then
            warn "the prov-identity read probe did not run: $_prov_probe"
        else
            ok "the prov identity '$_prov' reads the volume-name seed through the $SANDPROV_GROUP group ($SEED_CHECK, $smode $sowner)"
        fi
    fi
done
if (( ${#SEED_NAMED_MISSING[@]} > 0 )); then
    bad "the prov/sandlot config names seed path(s) that are not readable files: ${SEED_NAMED_MISSING[*]} — the prov role refuses to start without them, and a silently skipped path here would hide that"
    echo "      fix: materialize the generation file (see docs/deployment/install-baremetal.md, seed injection channels) or fix the config's volume_seed_file/volume_seed_next_file"
fi
if (( seed_checked == 0 )); then
    echo "  – no volume-name seed found at ${SEED_PATHS[*]} (exec-only hosts carry none; prov hosts: run the deploy or sandswap_ensure_volume_seed)"
fi
unset _cfg _line _parsed _prc _verdict _prov_probe SEED_NAMED_MISSING seed_cfg_unparsed

# ── 10. vsockguard active-impersonation layer is ATTACHED ───────────────────
# The header of this script (and docs/deployment/prerequisites.md) claims
# layer 1 = vsockguard. A host where the pin is absent — attach never run, a
# kernel upgrade dropped bpf from CONFIG_LSM, cleanup.sh deleted the pin —
# has the connect() door to the warden vsock port open for every local UID,
# and without this check the script exited 0. Read-only inspection (the live
# denial probe lives in security/vsockguard-verify.sh).
echo "[10/13] vsockguard BPF LSM hook attached (connect() to warden :1024 denied for non-sandlot UIDs)"
vsockguard_allowed_uid() { # → pinned allowed uid, or "" when unreadable
    # allowed_uid is a PINNED BPF MAP, not a regular file: `cat` prints the
    # kernel's debug banner followed by "key: value" lines (same parse as
    # deploy/baremetal/deploy-lib.sh read_allowed_uid).
    local out
    out="$(cat /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null || true)"
    echo "$out" | grep -E '^[0-9]+:' | head -1 | sed 's/^[0-9]*:[[:space:]]*//'
}
if ! grep -qE '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
    bad "the bpf LSM is not active — vsockguard cannot enforce (the warden port is open to every local UID); run: sudo bash security/setup-bpf-lsm.sh && reboot"
elif [[ ! -e /sys/fs/bpf/vsockguard/link ]]; then
    bad "vsockguard is NOT attached (no /sys/fs/bpf/vsockguard/link pin) — any local UID can connect() the warden vsock port; run: sudo bash security/vsockguard-attach.sh \$(id -u sandlot)"
else
    _pinned="$(vsockguard_allowed_uid)"
    # The expected UID depends on the DEPLOYMENT MODE, not on the account:
    # embedded k8s pods run the sandlot as UID 0 (the trust root), boxout pods
    # as the reserved sandbox UID / the bare-metal sandlot account. The mode is
    # persisted by k8s-host-setup.sh (SANDSWAP_DEPLOY_MODE) and can be pinned
    # explicitly with SANDSWAP_VSOCKGUARD_UID.
    _want="${SANDSWAP_VSOCKGUARD_UID:-}"
    _mode="boxout"
    if [[ -f /etc/sandswap/deploy-mode.env ]]; then
        # shellcheck disable=SC1091
        . /etc/sandswap/deploy-mode.env
        _mode="${SANDSWAP_DEPLOY_MODE:-boxout}"
    fi
    if [[ -z "$_want" ]]; then
        if [[ "$_mode" == "embedded" ]]; then
            _want=0
        else
            _want="$(id -u sandlot 2>/dev/null || echo '')"
        fi
    fi
    if [[ -z "$_want" ]]; then
        warn "vsockguard attached (allowed_uid=${_pinned:-unreadable}) but the expected identity is unknown (no sandlot account and no deployment mode) — cannot compare the pinned UID"
    elif [[ -n "$_pinned" && "$_pinned" == "$_want" ]]; then
        ok "vsockguard attached; allowed_uid=$_pinned matches the deployment mode ($_mode, uid $_want)"
    else
        bad "vsockguard pinned for UID ${_pinned:-?} but this deployment's mode ($_mode) needs uid $_want — the warden port is open to the WRONG identity. Re-attach for the right identity (do NOT detach to silence this): sudo bash security/vsockguard-attach.sh --uid $_want"
    fi
fi
unset _pinned _want _mode

# ── 11. boxout lifecycle socket is scoped to the sandlot identity ───────────
# In boxout (k8s) mode the privileged sidecar drives sandvmm lifecycle, host
# overlay mounts and /proc re-adopt over /run/sandswap/boxout.sock. The socket
# is minted 0600 + chown <allowedUID> (boxout/main.go), and the sidecar
# double-checks SO_PEERCRED — but nothing pinned the FILES on the node after
# deployment, so a drift (a redeploy without the chown, a widened mode) would
# silently hand privileged lifecycle control to every local UID. Check only
# when the socket exists (embedded/bare-metal hosts have no boxout).
echo "[11/13] boxout lifecycle socket scoped to the sandlot identity (boxout-mode hosts)"
if [[ -S /run/sandswap/boxout.sock ]]; then
    _bo_mode="$(stat -c '%a' /run/sandswap/boxout.sock)"
    _bo_uid="$(stat -c '%u' /run/sandswap/boxout.sock)"
    _sandlot_uid="$(id -u sandlot 2>/dev/null || echo '')"
    if [[ "$_bo_mode" != "600" ]]; then
        bad "boxout.sock mode=$_bo_mode, want 0600 (only the sandlot identity may connect the privileged lifecycle socket)"
        echo "      fix: restart the boxout sidecar (it re-mints the socket 0600+chown at startup)"
    else
        # Accept root, the bare-metal sandlot account, or the k8s reserved
        # sandbox identity (65536, passed explicitly via -allowed-uid).
        _bo_owner_ok=0
        [[ "$_bo_uid" == "0" ]] && _bo_owner_ok=1
        [[ -n "$_sandlot_uid" && "$_bo_uid" == "$_sandlot_uid" ]] && _bo_owner_ok=1
        [[ "$_bo_uid" == "65536" ]] && _bo_owner_ok=1
        if (( ! _bo_owner_ok )); then
            bad "boxout.sock owned by uid=$_bo_uid — neither root, the sandlot identity (uid ${_sandlot_uid:-absent}) nor the k8s reserved identity 65536"
            echo "      fix: restart the boxout sidecar with -allowed-uid set to the sandlot service UID"
        else
            ok "boxout.sock mode=0600 owner=uid:$_bo_uid (root-minted or the scoped service identity; SO_PEERCRED gates the rest)"
        fi
        unset _bo_owner_ok
    fi
    # The parent dir is SHARED by design: bare metal ships 3770 root:sandlot
    # (group-write for the service identities, sticky so one cannot remove
    # another's entries); k8s creates it per-run. World-write is never
    # acceptable, and group-write is only acceptable WITH the sticky bit.
    _pd_mode="$(stat -c '%a' /run/sandswap 2>/dev/null || echo '')"
    _pd_owner="$(stat -c '%u' /run/sandswap 2>/dev/null || echo '')"
    if [[ -n "$_pd_mode" ]]; then
        _pd_world=$(( 8#$_pd_mode & 002 ))
        _pd_group=$(( 8#$_pd_mode & 020 ))
        _pd_sticky=$(( 8#$_pd_mode & 01000 ))
        _pd_grp_name="$(stat -c '%G' /run/sandswap 2>/dev/null || echo '?')"
        if (( _pd_world )); then
            bad "/run/sandswap mode=$_pd_mode is world-writable — any local user could squat the boxout socket name"
        elif (( _pd_group )) && (( ! _pd_sticky )) && [[ "$_pd_grp_name" != "root" ]]; then
            # Group-write is by design for the service identities (bare metal:
            # 3770 root:sandlot WITH sticky). Group root (the k8s per-run dir)
            # admits no other identity, so no sticky bit is needed there.
            bad "/run/sandswap mode=$_pd_mode is group-writable (group=$_pd_grp_name) WITHOUT the sticky bit — a shared-group identity could remove another's entries (want 3770 root:sandlot)"
        else
            ok "/run/sandswap mode=$_pd_mode owner=uid:$_pd_owner group=$_pd_grp_name (shared-group write, sticky-protected where the group is shared)"
        fi
        unset _pd_world _pd_group _pd_sticky
    fi
    unset _bo_mode _bo_uid _sandlot_uid _pd_mode _pd_owner _pd_grp_name
else
    ok "no boxout socket on this host (embedded/bare-metal shape) — nothing to check"
fi

# ── 11b. guest FORWARD policy: effective order + packet probe ───────────────
# The egress half of the host network posture: metadata DROP -> uplink-scoped
# ACCEPT -> established return -> terminal guest drop, installed by
# setup-network.sh in `inet sandswap forward`. A grep for "a rule exists" is
# not enough (the historical bug was an ACCEPT inserted AHEAD of the metadata
# DROP, making it dead while both rules were present), so the order is read
# from the kernel's handle listing AND — when the host can run one — a packet
# probe proves the counters actually moved: metadata probes must hit the
# metadata rule, non-uplink probes the terminal rule, and neither may be
# ACCEPTed by the uplink rule.
_fwd_count() { # _fwd_count <listing> <comment> → packets counter ("" when absent)
    printf '%s\n' "$1" | awk -v c="comment \"$2\"" 'index($0, c) { if (match($0, /packets [0-9]+/)) { print substr($0, RSTART + 8, RLENGTH - 8); exit } }'
}

_probe_forward_drops() { # _probe_forward_drops <listing>
    local listing="$1"
    if [[ "$(id -u)" != "0" ]]; then
        warn "forward-drop packet probe skipped (needs root to build a probe netns)"
        return
    fi
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]]; then
        warn "forward-drop packet probe skipped (net.ipv4.ip_forward is not 1 — packets never reach the FORWARD hook)"
        return
    fi
    command -v ip >/dev/null 2>&1 || { warn "forward-drop packet probe skipped (ip not found)"; return; }
    command -v python3 >/dev/null 2>&1 || { warn "forward-drop packet probe skipped (python3 not found)"; return; }
    local subnet
    subnet="$(printf '%s\n' "$listing" | sed -nE 's/.*ip saddr ([0-9.]+(\/[0-9]+)?) counter packets [0-9]+ bytes [0-9]+ drop comment "sandswap-guest-egress-deny".*/\1/p' | head -1)"
    if [[ -z "$subnet" ]]; then
        warn "forward-drop packet probe skipped (cannot read the guest subnet from the terminal drop rule)"
        return
    fi
    local _uplink
    _uplink="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"
    if [[ -z "$_uplink" ]]; then
        warn "forward-drop packet probe skipped (no default route — nothing would be forwarded)"
        return
    fi
    local guest_ip
    guest_ip="$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False)[-2])' "$subnet" 2>/dev/null)" || guest_ip=""
    if [[ -z "$guest_ip" ]]; then
        warn "forward-drop packet probe skipped (subnet $subnet is too small to pick a probe address from)"
        return
    fi
    if ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$guest_ip"; then
        warn "forward-drop packet probe skipped ($guest_ip is already assigned on this host)"
        return
    fi
    local prefix="${subnet##*/}"
    # The probe guest is built as a REAL bridge port (host veth enslaved to
    # br-sandswap), exactly like a tenant TAP: the packet then enters the host
    # IP stack on br-sandswap, so the reverse-path lookup and the FORWARD hook
    # see the production shape (a bare veth would be dropped by rp_filter
    # because the guest subnet is also a local subnet of the bridge). The port
    # lives for the probe only and is removed immediately afterwards.
    local gw
    gw="$(ip -4 -o addr show dev br-sandswap 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
    if [[ -z "$gw" ]]; then
        warn "forward-drop packet probe skipped (br-sandswap has no IPv4 address to use as the probe gateway)"
        return
    fi
    local ns="ssp$RANDOM" hv="svh$RANDOM" nv="svn$RANDOM" dv="dvm$RANDOM"
    local setup_ok=1
    ip netns add "$ns" >/dev/null 2>&1 || setup_ok=0
    if (( setup_ok )); then ip link add "$hv" type veth peer name "$nv" >/dev/null 2>&1 || setup_ok=0; fi
    if (( setup_ok )); then ip link set "$nv" netns "$ns" >/dev/null 2>&1 || setup_ok=0; fi
    # A second, NON-uplink host interface with its own connected route: the
    # terminal-drop probe must egress THERE (a public destination would
    # legitimately match the uplink ACCEPT). This stands in for the storage /
    # cluster VLANs the terminal rule exists to keep guests off.
    if (( setup_ok )); then ip link add "$dv" type dummy >/dev/null 2>&1 || setup_ok=0; fi
    if (( setup_ok )); then
        ip addr add 198.51.100.1/24 dev "$dv" >/dev/null 2>&1 || setup_ok=0
        ip link set "$dv" up >/dev/null 2>&1 || setup_ok=0
        ip link set "$hv" master br-sandswap >/dev/null 2>&1 || setup_ok=0
        ip link set "$hv" up >/dev/null 2>&1 || setup_ok=0
        ip netns exec "$ns" ip addr add "$guest_ip/$prefix" dev "$nv" >/dev/null 2>&1 || setup_ok=0
        ip netns exec "$ns" ip link set "$nv" up >/dev/null 2>&1 || setup_ok=0
        ip netns exec "$ns" ip link set lo up >/dev/null 2>&1 || setup_ok=0
        ip netns exec "$ns" ip route add default via "$gw" dev "$nv" >/dev/null 2>&1 || setup_ok=0
    fi
    # Emit three probe packets from the probe guest: ICMP when ping exists,
    # otherwise three bound UDP datagrams (any L3 packet traverses the same
    # FORWARD hook; nothing is expected back).
    _probe_emit() { # <ns> <src> <dst>
        local _i
        if command -v ping >/dev/null 2>&1; then
            for _i in 1 2 3; do
                ip netns exec "$1" ping -c1 -W1 -I "$2" "$3" >/dev/null 2>&1 || true
            done
            return 0
        fi
        ip netns exec "$1" python3 - "$2" "$3" <<'PY' >/dev/null 2>&1 || true
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
for _ in range(3):
    try:
        s.sendto(b"probe", (sys.argv[2], 9))
    except OSError:
        pass
PY
    }
    local meta_before term_before up_before meta_after term_after up_after
    if (( setup_ok )); then
        meta_before="$(_fwd_count "$listing" sandswap-v4-metadata-deny)"
        term_before="$(_fwd_count "$listing" sandswap-guest-egress-deny)"
        up_before="$(_fwd_count "$listing" sandswap-guest-uplink-accept)"
        _probe_emit "$ns" "$guest_ip" 169.254.169.254
        # 198.51.100.2 is routed out the NON-uplink dummy: the terminal drop
        # (not the uplink accept) must catch it.
        _probe_emit "$ns" "$guest_ip" 198.51.100.2
        listing="$(nft -a list chain inet sandswap forward 2>/dev/null || true)"
        meta_after="$(_fwd_count "$listing" sandswap-v4-metadata-deny)"
        term_after="$(_fwd_count "$listing" sandswap-guest-egress-deny)"
        up_after="$(_fwd_count "$listing" sandswap-guest-uplink-accept)"
    fi
    ip netns del "$ns" >/dev/null 2>&1 || true
    ip link del "$hv" >/dev/null 2>&1 || true
    ip link del "$dv" >/dev/null 2>&1 || true
    if (( ! setup_ok )); then
        warn "forward-drop packet probe skipped (could not build the probe netns/veth on this host)"
        return
    fi
    local meta_delta=$(( ${meta_after:-0} - ${meta_before:-0} ))
    local term_delta=$(( ${term_after:-0} - ${term_before:-0} ))
    local up_delta=$(( ${up_after:-0} - ${up_before:-0} ))
    if (( meta_delta >= 3 )); then
        ok "packet probe: metadata probes were DROPPED by the metadata rule (counter +$meta_delta)"
    else
        bad "packet probe: 3 metadata probes did NOT hit the metadata DROP (counter +$meta_delta) — the drop is dead or an ACCEPT runs ahead of it; re-run setup-network.sh"
    fi
    if (( term_delta >= 3 )); then
        ok "packet probe: non-uplink probes were DROPPED by the terminal guest drop (counter +$term_delta)"
    else
        bad "packet probe: probes toward a non-uplink destination were NOT dropped by the terminal rule (counter +$term_delta) — guest egress is not default-deny; re-run setup-network.sh"
    fi
    if (( up_delta > 0 )); then
        bad "packet probe: the uplink ACCEPT counted probe packets (+$up_delta) — an ACCEPT is running before the drops (order broken)"
    else
        ok "packet probe: no probe was accepted by the uplink rule (order holds)"
    fi
}

_verify_forward_egress_policy() {
    local listing
    if ! listing="$(nft -a list chain inet sandswap forward 2>/dev/null)"; then
        bad "inet sandswap forward is MISSING while the sandbox bridge exists — guest egress falls back to the host FORWARD policy (ACCEPT on a plain bare-metal host): a guest can reach the node's other networks and the cloud metadata endpoints through the host's identity; re-run setup-network.sh"
        return
    fi
    local meta first_accept n_meta n_up n_est n_term
    meta="$(printf '%s\n' "$listing" | grep -n 'comment "sandswap-v4-metadata-deny"' | head -1 | cut -d: -f1)"
    first_accept="$(printf '%s\n' "$listing" | grep -nE 'comment "sandswap-guest-(uplink|established)-accept"' | head -1 | cut -d: -f1)"
    n_meta="$(printf '%s\n' "$listing" | grep -c 'comment "sandswap-v4-metadata-deny"')"
    n_up="$(printf '%s\n' "$listing" | grep -c 'comment "sandswap-guest-uplink-accept"')"
    n_est="$(printf '%s\n' "$listing" | grep -c 'comment "sandswap-guest-established-accept"')"
    n_term="$(printf '%s\n' "$listing" | grep -c 'comment "sandswap-guest-egress-deny"')"
    if [[ "$n_meta" != "1" || "$n_up" == "0" || "$n_up" != "$n_est" || "$n_up" != "$n_term" ]]; then
        bad "inet sandswap forward is not the expected shape (metadata=$n_meta uplink=$n_up established=$n_est terminal=$n_term): want exactly one metadata drop and one accept/established/terminal triple per guest subnet — re-run setup-network.sh"
        return
    fi
    if [[ -z "$meta" || -z "$first_accept" ]] || (( meta >= first_accept )); then
        bad "inet sandswap forward ORDER is wrong (metadata rule at line ${meta:-?}, first accept at ${first_accept:-?}): an ACCEPT ahead of the metadata DROP makes the DROP dead — re-run setup-network.sh"
    else
        ok "inet sandswap forward order: metadata drop first, then the per-subnet accept/established/terminal rules ($n_up guest subnet(s))"
    fi
    # A leftover legacy iptables accept can bypass the nft chain depending on
    # hook order at equal priority.
    if command -v iptables >/dev/null 2>&1; then
        local _subnet _uplink
        _subnet="$(printf '%s\n' "$listing" | sed -nE 's/.*ip saddr ([0-9.]+(\/[0-9]+)?) counter packets [0-9]+ bytes [0-9]+ drop comment "sandswap-guest-egress-deny".*/\1/p' | head -1)"
        _uplink="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"
        if [[ -n "$_subnet" && -n "$_uplink" ]] && iptables -C FORWARD -s "$_subnet" -o "$_uplink" -j ACCEPT 2>/dev/null; then
            bad "a LEGACY iptables FORWARD accept for $_subnet -> $_uplink is still installed — its order relative to the nft chain is not guaranteed, so it can bypass the metadata/terminal drops; remove it: iptables -D FORWARD -s $_subnet -o $_uplink -j ACCEPT"
        else
            ok "no legacy iptables FORWARD accept for the guest subnet"
        fi
    fi
    _probe_forward_drops "$listing"
}

# ── 12. network isolation baseline present on VM-serving hosts ──────────────
# Every tenant TAP is enslaved to ONE shared L2 bridge: without the per-TAP
# source anti-spoof and the bridge-forward VM-to-VM deny, a tenant can
# ARP-poison and directly attack other tenants' guest network stacks, and
# without the guest→host input rules every host listener is tenant-reachable.
# The sandlot REFUSES to start when it cannot enforce the baseline (network/
# factory.go), so a VM-serving host (detected by the sandbox bridge existing)
# with missing tables means: the bridge was created by an older deploy, or
# someone deleted the tables at runtime. Read-only inspection of nftables.
echo "[12/13] network isolation baseline (anti-spoof + VM-to-VM deny + guest→host filter) on VM-serving hosts"
# "VM-serving host" = a LOCAL bare-metal sandlot that is SERVING (unit active
# or a sandlot process running). On a k8s node the baseline is installed
# per-TAP by the boxout sidecar while pods run — with the pods gone the tables
# are legitimately absent even though the boot-persistence bridge exists, and
# demanding them here false-failed every k8s-posture check. The same holds
# for an installed-but-idle baremetal unit (a swept or combined development
# host between deploys): an inactive unit serves no tenants, so its absent
# tables are a note, not a finding.
_bm_sandlot=0
systemctl is-active --quiet sandswap-sandlot 2>/dev/null && _bm_sandlot=1
pgrep -x sandlot >/dev/null 2>&1 && _bm_sandlot=1
_bm_sandlot_idle=0
if (( ! _bm_sandlot )) && systemctl list-unit-files 2>/dev/null | grep -q "^sandswap-sandlot"; then
    _bm_sandlot_idle=1
fi
if (( ! _bm_sandlot )); then
    ok "no local sandlot unit/process (k8s or gateway-only posture) — the per-TAP baseline is the sidecar's job while pods run"
fi
if (( _bm_sandlot_idle )); then
    warn "a baremetal sandlot unit is installed but not running — no tenants are being served; the baseline tables may legitimately be absent until the next deploy starts it"
fi
if ! command -v nft >/dev/null 2>&1; then
    if ip link show br-sandswap >/dev/null 2>&1; then
        bad "nft(8) not installed but the sandbox bridge exists — a sandlot on this host cannot start with the baseline on; an OLD instance may still be serving tenants WITHOUT network isolation"
        echo "      fix: apt install nftables && restart the sandlot (it re-installs the baseline tables)"
    else
        ok "no nft(8) and no sandbox bridge on this host (gateway/provision-only shape)"
    fi
elif ! ip link show br-sandswap >/dev/null 2>&1; then
    ok "no sandbox bridge on this host (backend=none / gateway-only) — the network baseline is not required"
elif (( _bm_sandlot )); then
    # The host serves tenants over the bridge: all three layers must exist.
    if nft list table netdev sandswap_baseline >/dev/null 2>&1; then
        ok "netdev table sandswap_baseline exists (per-TAP source anti-spoof installed at provision)"
    else
        bad "netdev table sandswap_baseline MISSING while br-sandswap exists — tenant TAPs run without source anti-spoof (address=identity broken, VM-to-VM spoofing possible)"
        echo "      fix: restart the sandlot (or re-run setup-network.sh + sandswap-setup-network) — with nftables present it refuses to run without the baseline"
    fi
    if nft list chain bridge sandswap_baseline fwdgate 2>/dev/null | grep -q "sandswap-vm2vm-deny"; then
        ok "bridge forward VM-to-VM deny rule present (tenant↔tenant L2/L3 traffic dropped)"
    else
        bad "bridge fwdgate carries no sandswap-vm2vm-deny rule while br-sandswap exists — tenants can reach each other's guest network stacks directly (unless network.vm_to_vm=allow was deliberately configured)"
        echo "      fix: restore the deny posture (restart the sandlot; it re-syncs the rule at every TAP attach)"
    fi
    if nft list chain inet sandswap input 2>/dev/null | grep -q "iifname"; then
        ok "inet input chain sandswap filters guest→host traffic on the bridge interface"
    else
        bad "inet input chain sandswap carries no bridge-scoped rule — every host listener (gateway planes, future services) is tenant-reachable over the bridge IP"
        echo "      fix: re-run setup-network.sh (sandswap-setup-network at boot) — it recreates the input chain with the guest default-deny allowlist"
    fi
fi

# Guest FORWARD policy: checked whenever the sandbox bridge exists (the
# policy polices forwarded guest traffic, in k8s and bare-metal alike).
if command -v nft >/dev/null 2>&1 && ip link show br-sandswap >/dev/null 2>&1; then
    _verify_forward_egress_policy
fi

# ── Egress destination policy (ADVISORY, never a failure) ───────────────────
# Sandswap's host-side controls enforce SOURCE identity (host input guard +
# per-TAP anti-spoof + optional binding region); the DESTINATION policy
# (cloud metadata, the storage network, cluster CIDRs) belongs to the
# deployer's egress enforcer. This probe only points out the obvious gap: on
# a cloud node, no rule mentioning the metadata range means 169.254.169.254
# is reachable from sandbox guests unless the enforcer blocks it elsewhere
# (a CNI/host-endpoint policy, not nft on this host).
if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q '169\.254\.0\.0/16'; then
        ok "an nft rule references the cloud metadata range (169.254.0.0/16)"
    else
        warn "no nft rule mentions 169.254.0.0/16 — if this host runs cloud guests, make sure the egress enforcer blocks the metadata VIP (docs/how-it-works/egress-enabler.md)"
    fi
fi

# ── 13. guest TCB lives outside service-writable paths ─────────────────────
# The guest kernel + initramfs ARE the TCB: an identity that can replace them
# decides what the next tenant boots (a boundary breach, not an in-sandbox
# event). The pinned home is /usr/local/lib/sandswap/guest — root:root 0755
# with a SHA256SUMS pin written by the deployer; a legacy copy under the state
# root is reported by name so the drift is visible.
echo "[13/13] guest TCB (kernel + initramfs) not writable by any service identity"
_tcb_checked=0
_tcb_found=0
for _tdir in /usr/local/lib/sandswap/guest /var/lib/sandswap; do
    for _tf in vmlinux.bin initramfs.cpio.gz; do
        _tpath="$_tdir/$_tf"
        [[ -f "$_tpath" ]] || continue
        _tcb_found=1
        _tcb_checked=$((_tcb_checked + 1))
        _towner="$(stat -c '%U:%G' "$_tpath" 2>/dev/null || echo '?')"
        _tmode="$(stat -c '%a' "$_tpath" 2>/dev/null || echo '')"
        if [[ "${_towner%%:*}" == "root" ]] && [[ "$_tmode" =~ ^[0-7]{3,4}$ ]] && (( (8#$_tmode & 8#022) == 0 )); then
            ok "$_tpath is root-owned and not group/world-writable ($_towner $_tmode)"
        else
            bad "$_tpath is $_towner $_tmode — a writable guest kernel/initramfs lets that identity decide what the next tenant boots"
        fi
        _dpath="$(dirname "$_tpath")"
        _downer="$(stat -c '%U' "$_dpath" 2>/dev/null || echo '?')"
        _dmode="$(stat -c '%a' "$_dpath" 2>/dev/null || echo '')"
        if [[ "$_downer" == "root" ]] && [[ "$_dmode" =~ ^[0-7]{3,4}$ ]] && (( (8#$_dmode & 8#022) == 0 )); then
            ok "$_dpath (TCB directory) is root-owned, not group/world-writable ($_dmode)"
        else
            bad "$_dpath (TCB directory) is owned by $_downer mode $_dmode — directory write alone is enough to RENAME/REPLACE the TCB; fix: chown root:root $_dpath && chmod 0755 $_dpath"
        fi
    done
done
if [[ -f /usr/local/lib/sandswap/guest/SHA256SUMS ]]; then
    if ( cd /usr/local/lib/sandswap/guest && sha256sum -c --quiet SHA256SUMS ) >/dev/null 2>&1; then
        ok "guest TCB matches its SHA256SUMS pin"
    else
        bad "guest TCB does NOT match /usr/local/lib/sandswap/guest/SHA256SUMS — a kernel/initramfs was modified or replaced outside the deployer"
    fi
else
    warn "no /usr/local/lib/sandswap/guest/SHA256SUMS pin — the TCB hash check was NOT performed (run the current deployer to install it)"
fi
if (( _tcb_found == 0 )); then
    echo "  – no guest kernel/initramfs found in the known locations (gateway/provision-only host without a TCB copy)"
fi
unset _tcb_checked _tcb_found _tdir _tf _tpath _towner _tmode _dpath _downer _dmode

# ── 13b. sandlot units still restrict namespace creation ────────────────────
# The unit-level SystemCallFilter deliberately allows `unshare` so the
# in-process FUSE worker can call unshare(CLONE_FS). The security-relevant
# namespace flags are denied by RestrictNamespaces=yes; dropping that directive
# (or a drop-in that clears it) would let a compromised non-root sandlot create
# user/mount/net namespaces. This is the static twin of the runtime posture the
# unit comments describe.
echo "[13b/13] sandlot units deny namespace creation (RestrictNamespaces=yes)"
_unit_seen=0
for _u in /etc/systemd/system/sandswap-sandlot.service /etc/systemd/system/sandswap-sandlot-instance@.service; do
    [[ -f "$_u" ]] || continue
    _unit_seen=1
    if grep -qE '^[[:space:]]*RestrictNamespaces=yes([[:space:]]|$)' "$_u"; then
        ok "$_u carries RestrictNamespaces=yes"
    else
        bad "$_u does NOT carry RestrictNamespaces=yes — a compromised non-root sandlot could create namespaces (fix: re-run the deployer or restore the shipped unit)"
    fi
done
if (( _unit_seen == 0 )); then
    echo "  – no bare-metal sandlot units installed (k8s/gateway-only host)"
fi
unset _unit_seen _u

echo
echo "=== RESULT: $PASS passed, $FAIL failed, $WARN warnings ==="
[[ $FAIL -eq 0 ]] && echo "✅ all host security invariants hold" || echo "❌ some invariants FAIL — vsock impersonation/sniffing or binding-region forgery surface may be open"
exit $FAIL

