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
# setup-host.sh — One-time host preparation for Sandswap bare-metal deployment
# Usage:
#   sudo bash setup-host.sh --role gateway
#   sudo bash setup-host.sh --role sandlot [--subnet 10.188.X.0/24] [--gateway-ip 10.188.X.1]
#   sudo bash setup-host.sh --role all

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# ──── Parse Args ────

ROLE=""
SUBNET=""
GATEWAY_IP=""
EXTRA_ADDRS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)     ROLE="$2"; shift 2 ;;
        --subnet)   SUBNET="$2"; shift 2 ;;
        --gateway-ip) GATEWAY_IP="$2"; shift 2 ;;
        --extra-addrs) EXTRA_ADDRS="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --role {gateway|sandlot|provision|all} [--subnet CIDR] [--gateway-ip IP] [--extra-addrs \"CIDR CIDR\"]"
            exit 0
            ;;
        *) err "Unknown argument: $1" ;;
    esac
done

[[ -z "$ROLE" ]] && err "--role is required (gateway|sandlot|provision|all)"
[[ "$ROLE" != "gateway" && "$ROLE" != "sandlot" && "$ROLE" != "provision" && "$ROLE" != "all" ]] && err "Invalid role: $ROLE"

log "Setting up host for role: $ROLE"

# ──── Common (all roles) ────

# Identities FIRST: the seed scoping (root:<sandprov>) and every device
# chown target the service groups. On a fresh host the previous order called
# the seed verification before the groups existed, which aborted the documented
# install flow with "group 'sandprov' does not exist".
# Dedicated service identities (kubelet privilege model — services never run
# as root and never sudo). Both roles need them, so create unconditionally:
#   sandserv — gateway + dns: credential state only, NO shared group (it
#              accesses no storage; the storage plane is sandprov/sandvmm)
#   sandlot  — sandlot + sandvmm: kvm group (devices); the shared volumes
#              group is sandlot's PRIMARY group (nothing uses the sandserv group)
#   sandprov — sandfs/template lifecycle identity (storage grant carrier;
#              no capabilities, no kvm, no vsock devices; pinned 983:
#              988-995 are distro-occupied, see runtime.sh)
ss_ensure_service_users

# Deployment SHAPE, exported before any ss_apply_share_plane call so this host prep
# agrees with the units it installs: a dedicated provision host runs the prov
# role as the sandprov identity (the shared-storage grant carrier), and a
# gateway/provision-only host routes nothing for guests (ip_forward stays off).
# The automatic deployers already export SS_PROV_USER per shape; the manual
# `--role provision` path did not, silently leaving the volumes/template trees
# owned by sandlot (the wrong identity for a dedicated prov host).
case "$ROLE" in
    provision) export SS_PROV_USER=sandprov ;;
esac
case "$ROLE" in
    sandlot|all) export SANDSWAP_ENABLE_IP_FORWARD=1 ;;
    *)           export SANDSWAP_ENABLE_IP_FORWARD=0 ;;
esac

# The guest TCB directory: root-owned 0755, never a service identity's. The
# deployer installs the kernel/initramfs here (sandswap_install_guest_artifacts)
# so they are not replaceable by the gateway/sandlot identities.
install -d -m 0755 -o root -g root /usr/local/lib/sandswap/guest

# Exec-only hosts do NOT mint a volume seed: the seed must be minted once and
# distributed fleet-wide (a local mint derives a different volume-name
# generation, so every mount on this host would address different names). The
# seed scope is verified instead; `provision`/`all`/`gateway` mint when absent.
if [[ "$ROLE" == "sandlot" ]]; then
    export SANDSWAP_SEED_MINT=0
fi

sandswap_create_dirs
sandswap_install_sysctls
sandswap_setup_dev_nodes

# Device lockdown for the vsock transport (anti-sniff invariant): per-OWNER
# isolation — /dev/vhost-vsock → sandvmm 0600 (the VMM is its only user),
# /dev/vsock → sandlot 0600. Complements the vsockguard BPF LSM (active
# impersonation defense).
for _cand in "$SCRIPT_DIR/../udev/99-sandswap-vsock.rules" \
             "$SCRIPT_DIR/udev/99-sandswap-vsock.rules" \
             "$SCRIPT_DIR/deploy/udev/99-sandswap-vsock.rules"; do
    [[ -f "$_cand" ]] && { UDEV_RULE_SRC="$_cand"; break; }
done
UDEV_RULE_SRC="${UDEV_RULE_SRC:-$SCRIPT_DIR/../udev/99-sandswap-vsock.rules}"
if [[ -f "$UDEV_RULE_SRC" ]]; then
    install -m 644 "$UDEV_RULE_SRC" /etc/udev/rules.d/99-sandswap-vsock.rules
    udevadm control --reload-rules 2>/dev/null || true
    udevadm trigger 2>/dev/null || true
    log "udev vsock lockdown installed (vhost-vsock sandvmm 0600, vsock sandlot 0600)"
else
    warn "deploy/udev/99-sandswap-vsock.rules not found — vsock device lockdown skipped"
fi

# ── Local-disk volumes hardening (storage-contract row 8/9, follow-up) ──
# Owner ruling: local-disk DEV shapes accept the deviation; owner decision:
# harden them anyway via a zero-disk bind-remount. The whole /var/lib/sandswap
# tree is data directories (volumes,
# identity, instance-*) — nothing there needs setuid or device nodes, so
# nosuid,nodev on a bind instance of the same directory is pure tightening:
# data stays where it is (persistence unchanged), no extra filesystem, no
# extra disk. Two-step bind+remount is the standard container technique (a
# plain `mount -o bind,nosuid,nodev` silently drops the flags).
if [[ -d /var/lib/sandswap ]] && ! findmnt -T /var/lib/sandswap -n -o OPTIONS | grep -qE '(^|,)nosuid(,|$)'; then
    if mount --bind /var/lib/sandswap /var/lib/sandswap 2>/dev/null \
       && mount -o remount,bind,nosuid,nodev /var/lib/sandswap 2>/dev/null; then
        # Boot persistence: fstab bind entry (systemd-fstab handles the
        # remount flags; duplicate-guarded).
        if ! grep -qE '^[^#]*\s+/var/lib/sandswap\s+none\s+bind' /etc/fstab 2>/dev/null; then
            echo "/var/lib/sandswap /var/lib/sandswap none bind,nosuid,nodev 0 0" >> /etc/fstab
        fi
        log "var/lib/sandswap bind-remounted nosuid,nodev (fstab entry added — survives reboots)"
    else
        warn "could not bind-remount /var/lib/sandswap nosuid,nodev — volumes remain on the root fs (dev-shape deviation, )"
    fi
else
    [[ -d /var/lib/sandswap ]] && log "var/lib/sandswap already nosuid (bind or dedicated fs)"
fi

# Runtime directories handed to the service identities (idempotent).
ss_prepare_dirs

# The template store defaults to the volumes-dir sibling (same filesystem —
# shared storage in clustered deployments). Shared-group setgid so the prov
# role writes layers/refs; harmless when a deployment overrides the path.
# Shape-derived via the ONE planner (ss_apply_share_plane): a literal
# `-o sandprov` here would be wrong for every merged-shape deployment, which
# is exactly the drift class the deploy guard exists for.
ss_apply_share_plane /var/lib/sandswap "$VOL_ROOT" /var/lib/sandswap/templates >/dev/null 2>&1
# The planner swallows individual chown/chmod failures, so the RESULT is
# asserted: a host whose state root is owned by a service identity (or whose
# shared root lost the traverse-only contract) cannot serve storage safely.
_state_own="$(stat -c '%U:%a' /var/lib/sandswap 2>/dev/null || echo '?')"
if [[ "${_state_own%%:*}" != "root" ]]; then
    err "state root /var/lib/sandswap is '$_state_own' after host prep, want root-owned 0755 (the guest TCB and the gateway's state split depend on it)"
fi
if [[ -d "$VOL_ROOT" ]]; then
    _vol_mode="$(stat -c '%a' "$VOL_ROOT" 2>/dev/null || echo '')"
    if [[ "$_vol_mode" != "2710" ]]; then
        err "volumes root $VOL_ROOT is mode '$_vol_mode' after host prep, want 2710 (setgid, owner-only create, shared-group traverse)"
    fi
fi
unset _state_own _vol_mode

# /run/sandswap for the systemd units: tmpfiles.d is the native mechanism
# (runs at every boot; /run is tmpfs). The gateway/sandns units deliberately do
# NOT declare RuntimeDirectory=sandswap — that would chown the directory to
# the unit's own user (sandserv) and lock the sandlot identity out.
# Sticky bit (3770): the directory is shared by identities that must NOT be
# able to remove each other's entries — without it a sandvmm-identity process
# (987, the compromised-daemon adversary) can unlink or replace the role lock
# and any seed generation placed here, because directory write is enough to
# unlink an entry the writer does not own. With the sticky bit only an entry's
# owner (or the directory owner / root) may remove it.
# Stage through a seekable temp file, NOT `install /dev/stdin`: bash 5.3
# feeds heredocs through a pipe, and GNU install cannot copy a FIFO source
# onto an EXISTING destination — the first run lands, every re-run dies with
# "install: No such file or directory" (broken idempotency).
_tmpfiles_conf="$(mktemp)"
cat > "$_tmpfiles_conf" <<'EOF'
# Sandswap runtime state (vm/<id>, instance-*, the role lock) shared by the
# sandlot and sandserv service identities. 3770: sticky, so a shared-group
# identity can create its own entries but never remove another identity's
# (the role lock and staged seed generations). See deploy/baremetal/setup-host.sh.
d /run/sandswap 3770 root sandlot - -
# The one-sandlot-per-host role lock: root-owned 0660 shared-group so BOTH the
# sandlot (985, exec instances) and sandprov (983, prov instances) identities
# can open it O_RDWR — created by an instance instead, it would belong to
# whichever started first with umask-stripped group bits.
f /run/sandswap/sandlot.role 0660 root sandlot - -
EOF
install -m 644 "$_tmpfiles_conf" /usr/lib/tmpfiles.d/sandswap.conf
rm -f "$_tmpfiles_conf"
# A failure to apply is a HARD error: silently continuing would leave the
# runtime dir without the sticky bit (the isolation the row above exists for)
# or missing entirely, and every later step would "succeed" against the wrong
# shape.
systemd-tmpfiles --create /usr/lib/tmpfiles.d/sandswap.conf \
    || err "systemd-tmpfiles refused /usr/lib/tmpfiles.d/sandswap.conf — /run/sandswap 3770 root:sandlot was NOT created/updated"
# Assert what actually landed. The sticky bit is what stops one shared-group
# identity (e.g. sandvmm 987) from unlinking another identity's entries here;
# a filesystem or tmpfiles that silently dropped it must fail the setup, not
# warn.
_run_mode="$(stat -c '%a' /run/sandswap 2>/dev/null || echo '?')"
[[ "$_run_mode" == "3770" ]] \
    || err "/run/sandswap is mode $_run_mode, expected 3770 (sticky: only an entry's owner, or root, may remove it) — refusing to leave the shared runtime dir without the sticky bit"
log "tmpfiles.d entry installed (/run/sandswap → root:sandlot 3770, sticky)"

# ──── Sandlot-specific ────

setup_sandlot() {
    # KVM check
    sandswap_check_kvm

    # vhost_vsock: load it now if needed, and ALWAYS assert the boot-time
    # persistence. The persistence write must NOT live inside the
    # "module not loaded" branch: when the module happened to be loaded at
    # install time (a previous deploy loaded it), the file was never written
    # — and after a reboot the module was absent, /dev/vhost-vsock a stale
    # node, and the exec sandlot crash-looped on "owned by uid 0, want the
    # sandvmm identity 987".
    grep -qx vhost_vsock /etc/modules-load.d/sandswap.conf 2>/dev/null \
        || echo "vhost_vsock" >> /etc/modules-load.d/sandswap.conf
    if ! lsmod | grep -q '^vhost_vsock'; then
        modprobe vhost_vsock
        log "vhost_vsock module loaded (persistent via /etc/modules-load.d/)"
    fi

    # Egress identity binding region, bpf carrier — bpffs DAC preparation.
    # Embedded sandlot runs as the sandlot account (with ambient CAP_SYS_ADMIN,
    # which is what lets it BPF_MAP_CREATE + BPF_OBJ_PIN), but the bpffs ROOT
    # is 0700 root:root: DAC denies uid 985 the traverse before the capability
    # ever matters, and every sandlot start dies with "bindreg: pin ...:
    # permission denied". Give the carrier its documented shape (docs/
    # deployment/prerequisites.md invariants 5–7):
    #   /sys/fs/bpf            → 0711  traverse-only for others (no listing)
    #   /sys/fs/bpf/sandswap   → sandlot:sandlot 0750 — owner-writable (the
    #     write set = the sandlot identity), group/other no write. The pinned
    #     map lands owned by sandlot; bindreg re-verifies owner+mode at open.
    # The bpffs mode does NOT survive reboot → re-applied on every host prep.
    # Gated on the same env sandswap_generate_sandlot_config consumes (default
    # off changes no host posture).
    if [[ "${SANDSWAP_BINDING_BACKEND:-}" == "bpf" ]]; then
        if [[ "$(stat -c '%a' /sys/fs/bpf)" != "711" ]]; then
            chmod 0711 /sys/fs/bpf
            log "bpffs root → 0711 (traverse-only; bpf binding carrier)"
        fi
        install -d -m 0750 -o "$SS_SERVICE_USER_SL" -g "$SS_SERVICE_USER_SL" /sys/fs/bpf/sandswap
        # A stale pin the sandlot cannot open (root-era deploys, a pre-identity-
        # split run) would wedge every start on "open pinned region: permission
        # denied" — bindreg treats an existing pin as the live region. Clear
        # pins NOT owned by the sandlot identity so the fresh create path runs;
        # a sandlot-owned pin is left in place (restart re-attach, by design).
        if [[ -e /sys/fs/bpf/sandswap/bindings && "$(stat -c '%U' /sys/fs/bpf/sandswap/bindings 2>/dev/null)" != "sandlot" ]]; then
            rm -f /sys/fs/bpf/sandswap/bindings
            log "stale binding pin (foreign-owned) removed — the sandlot recreates it"
        fi
        log "binding pin dir ready: /sys/fs/bpf/sandswap (sandlot:sandlot 0750)"
    fi

    # Bridge + nftables NAT via the canonical implementation (setup-network.sh;
    # same path e2e/single-node-multi-agent.sh and the k8s deploys use). Keeping ONE NAT
    # implementation means cleanup.sh's `nft delete table inet sandswap` reverses
    # exactly what was installed — the old iptables MASQUERADE here was a second,
    # untracked copy no cleanup could remove.
    # Script resolution for BOTH layouts: the repo tree (SCRIPT_DIR/../.. →
    # deploy/) and the remote-install layout where deploy-cluster-*.sh scp the
    # scripts into /tmp (no ../.. repo exists there — the old bare repo_root
    # resolution ran `//deploy/setup-network.sh: No such file`).
    local repo_root net_script
    repo_root="$(cd "$SCRIPT_DIR/../.." 2>/dev/null && pwd || echo /)"
    if [[ -f "$SCRIPT_DIR/setup-network.sh" ]]; then
        net_script="$SCRIPT_DIR/setup-network.sh"
    else
        net_script="$repo_root/deploy/setup-network.sh"
    fi
    local subnet="${SUBNET:-10.188.0.0/16}"
    local gw_ip="${GATEWAY_IP:-10.188.0.1}"
    # ALWAYS run the canonical script (idempotent), not only when the bridge
    # is missing: an upgraded host already has br-sandswap but no guest FORWARD
    # policy, and skipping the script would leave its egress unpoliced forever.
    if BRIDGE=br-sandswap SUBNET="$subnet" GATEWAY="$gw_ip" EXTRA_ADDRS="$EXTRA_ADDRS" \
        bash "$net_script"; then
        log "Bridge + NAT ready: br-sandswap (${subnet}, gw=${gw_ip})"
    else
        # A non-zero result now means nft is missing or the guest FORWARD
        # policy could not be installed: guest egress would bypass the
        # metadata/terminal drops, so this is a hard failure.
        err "setup-network.sh failed — the guest FORWARD/NAT policy is not installed (install nftables, then re-run)"
    fi

    # Persist the bridge + NAT across reboots. Both are runtime kernel state
    # (ip link add / nft add) that does NOT survive a reboot, while the
    # sandlot units are ENABLED — a rebooted node otherwise crash-loops on
    # "bridge br-sandswap missing" until an operator re-runs the script.
    # Install the script to a stable path (the
    # repo tree may not exist at boot) and enable the oneshot unit; it is
    # idempotent, ordered Before= the sandlot units, and re-creating an
    # intact bridge is a no-op.
    install -m 0755 "$net_script" /usr/local/bin/sandswap-setup-network
    # The installed copy resolves its shared runtime from
    # /usr/local/lib/sandswap (its $ROOT is /usr/local, where no repo tree
    # exists at boot). Install the very library THIS script is running on
    # (common.sh resolves it the same two ways), mode 0644: without it the
    # boot-time unit dies with a bare ENOENT and a rebooted node loses
    # br-sandswap.
    runtime_src=""
    for _cand in "$SCRIPT_DIR/../../common/sh/runtime.sh" "$SCRIPT_DIR/runtime.sh"; do
        [[ -f "$_cand" ]] && { runtime_src="$_cand"; break; }
    done
    if [[ -n "$runtime_src" ]]; then
        install -D -m 0644 "$runtime_src" /usr/local/lib/sandswap/runtime.sh
    else
        warn "shared runtime not found beside $SCRIPT_DIR — /usr/local/lib/sandswap/runtime.sh NOT installed; the boot-time unit will fail"
    fi
    # Persist the ADDRESSING too, not just the intent to re-create the bridge:
    # the unit runs the installed script with no arguments, so without this file
    # a host configured with a non-default subnet would come back from a reboot
    # speaking the defaults (10.188.0.0/16 / 10.188.0.1) while every sandlot on
    # it still hands guests the configured gateway — an unreachable default
    # route inside every microVM, silently.
    install -d -m 0755 /etc/sandswap
    printf 'BRIDGE=br-sandswap\nSUBNET=%s\nGATEWAY=%s\nEXTRA_ADDRS=%s\n' "$subnet" "$gw_ip" "$EXTRA_ADDRS" \
        > /etc/sandswap/network.env
    chmod 0644 /etc/sandswap/network.env
    install -m 0644 "$SCRIPT_DIR/systemd/sandswap-network.service" /etc/systemd/system/sandswap-network.service
    systemctl daemon-reload
    systemctl enable sandswap-network.service >/dev/null 2>&1 || warn "enable sandswap-network.service failed"
    systemctl start sandswap-network.service 2>/dev/null || warn "start sandswap-network.service failed"
    log "Network persistence unit enabled (bridge + NAT re-created at boot)"

    # vsock ownership boot-ordering fix: the udev rule is correct but the
    # device nodes can be created before the rule set is in effect, and udev
    # never re-processes existing nodes — every reboot left /dev/vhost-vsock
    # root-owned and the exec sandlot crash-looped. The oneshot re-triggers
    # the two devices after udevd, before any sandlot starts.
    install -m 0644 "$SCRIPT_DIR/systemd/sandswap-vsock-retune.service" /etc/systemd/system/sandswap-vsock-retune.service
    systemctl daemon-reload
    systemctl enable sandswap-vsock-retune.service >/dev/null 2>&1 || warn "enable sandswap-vsock-retune.service failed"
    log "vsock re-tune unit enabled (device ownership repaired at boot)"

    # vsockguard BPF attach (if available) — pinned to the sandlot identity.
    # The attest helper is installed for the sandlot unit's root ExecStartPre:
    # the service uid cannot read bpffs, so the root-side helper proves the
    # live pin and writes the file the sandlot validates.
    local attest_script="$repo_root/security/vsockguard-attest.sh"
    if [[ -f "$attest_script" ]]; then
        install -m 0755 "$attest_script" /usr/local/bin/sandswap-vsockguard-attest
        log "vsockguard attest helper installed"
    fi
    local attach_script="$repo_root/security/vsockguard-attach.sh"
    if [[ -x "$attach_script" ]]; then
        # Check BPF LSM is active
        if grep -qE '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
            bash "$attach_script" "$(id -u sandlot)" 2>&1 || warn "vsockguard attach failed (non-fatal)"
            log "vsockguard BPF attached (UID=$(id -u sandlot), sandlot)"
        else
            warn "BPF LSM not active. Run: bash security/setup-bpf-lsm.sh (requires reboot)"
        fi
    else
        warn "vsockguard attach script not found at $attach_script"
    fi

    # /dev/net/tun access for the sandlot identity (sandvmm opens it to create
    # TAP devices). /dev/kvm and /dev/vhost-vsock need NO rule: stock Ubuntu
    # ships them root:kvm 0660 and the sandlot user is in the kvm group
    # (ss_ensure_service_users); the vsock lockdown lives in
    # 99-sandswap-vsock.rules (installed above, common section). The old
    # 0666-everything rule is gone — world-writable devices would defeat the
    # dedicated-identity model.
    cat > /etc/udev/rules.d/99-sandswap.rules << 'EOF'
# Sandswap: TUN/TAP access for the sandlot service identity only
KERNEL=="tun", MODE="0660", GROUP="sandlot"
EOF
    udevadm control --reload-rules 2>/dev/null || true
    udevadm trigger 2>/dev/null || true
    log "udev rules installed (tun → 0660 root:sandlot; kvm/vhost-vsock via kvm group)"
}

if [[ "$ROLE" == "sandlot" || "$ROLE" == "all" ]]; then
    setup_sandlot
fi

# ──── Provision-host-specific ────
# A provision host runs ONLY the prov-role sandlot (sandfs + template
# lifecycle): no KVM, no vhost-vsock, no bridge, no vsockguard — the common
# section (identities + shared storage dirs + device modes) is the whole
# story. This block exists to say that explicitly and keep the role matrix
# greppable.
setup_provision() {
    log "Provision host setup complete (identities + shared dirs only: no KVM/vsock/bridge duty)"
}

if [[ "$ROLE" == "provision" || "$ROLE" == "all" ]]; then
    setup_provision
fi

# ──── Gateway-specific ────

setup_gateway() {
    # Gateway doesn't need special host setup beyond the common steps
    log "Gateway host setup complete (no extra steps needed)"
}

if [[ "$ROLE" == "gateway" || "$ROLE" == "all" ]]; then
    setup_gateway
fi

log "Host setup complete for role: $ROLE"
