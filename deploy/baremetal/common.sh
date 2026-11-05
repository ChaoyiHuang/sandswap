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
# common.sh — Shared functions for Sandswap bare-metal deployment scripts
# Source this file: source "$(dirname "$0")/common.sh"

set -euo pipefail

# ──── Shared runtime library (local-first resolution) ────
# e2e and deploy share ONE runtime implementation (logging, pass/fail
# counters, path defaults, process/artifact/tool/dev-node/vsockguard
# helpers, dedicated-service-identity helpers) in common/sh/runtime.sh.
# Resolution: a tree-local copy (independent or trimmed deploy trees that
# ship runtime.sh next to this file) wins; the development tree has no local
# copy and sources the repo-wide file. The release package ships common/sh/
# so the second branch resolves inside the extracted package root.
_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$_LIB_DIR/runtime.sh" ]]; then
    # shellcheck disable=SC1090
    source "$_LIB_DIR/runtime.sh"
    if [[ -f "$_LIB_DIR/stack.sh" ]]; then
        # shellcheck disable=SC1090
        source "$_LIB_DIR/stack.sh"
    fi
else
    # shellcheck disable=SC1090
    source "$_LIB_DIR/../../common/sh/runtime.sh"
    # shellcheck disable=SC1090
    source "$_LIB_DIR/../../common/sh/stack.sh"
fi
unset _LIB_DIR

# ──── curl TLS posture for the shared stack helpers ────
# Every bare-metal stack serves TLS with a self-signed/internal CA, and the
# deploy scripts' probes have always passed -k (bm_wait_http, the health/pool
# waits). The shared helpers (common/sh/stack.sh) read this variable, so
# defaulting it HERE means a call site that is rewired onto a shared helper
# cannot silently lose the flag — which is exactly how bm_wait_pool broke the
# legacy deploy (HTTPS probe without -k → "clean=0" forever → a 6-minute pool
# timeout). Harmless for the --no-tls/http shapes.
SS_CURL_TLS="${SS_CURL_TLS:--k}"

# ──── Constants ────

SANDSWAP_ETC="/etc/sandswap"
SANDSWAP_VAR="/var/lib/sandswap"
# Guest TCB (kernel + initramfs). Root-owned 0755 and OUTSIDE the state root:
# /var/lib/sandswap is traversable by the service identities and the gateway's
# state lives there, so a service identity owning/mutating the TCB directory
# would let a compromised gateway replace the next tenant's guest kernel —
# a boundary breach, not an in-sandbox event. Deployment installs the pair here;
# verify-host-security.sh asserts the ownership and a SHA256SUMS pin.
SANDSWAP_GUEST_DIR="${SANDSWAP_GUEST_DIR:-/usr/local/lib/sandswap/guest}"
SANDSWAP_RUN="/run/sandswap"
SANDSWAP_LOG="/var/log/sandswap"
SANDSWAP_BIN="/usr/local/bin"
SANDSWAP_SYSCTL="/etc/sysctl.d/99-sandswap.conf"

# ──── Logging ────

log()  { echo -e "\033[1;34m[sandswap]\033[0m $*"; }
warn() { echo -e "\033[1;33m[warn]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[error]\033[0m $*" >&2; exit 1; }

# ──── Directory Setup ────

sandswap_create_dirs() {
    mkdir -p "$SANDSWAP_ETC/certs"
    mkdir -p "$SANDSWAP_VAR"/{volumes,flat-templates,overlay-templates}
    mkdir -p "$SANDSWAP_RUN"
    mkdir -p "$SANDSWAP_LOG"
    mkdir -p "$SANDSWAP_VAR/sandns"
    sandswap_apply_prov_plane
    log "Directories created: $SANDSWAP_ETC, $SANDSWAP_VAR, $SANDSWAP_RUN"
}

# sandswap_install_guest_artifacts <output_dir> — install the guest TCB
# (vmlinux.bin + initramfs.cpio.gz) into SANDSWAP_GUEST_DIR, root:root 0755
# directory with 0644 files, and write a SHA256SUMS pin beside them. A
# replacement of either file (or a permissions drift) is then visible to
# `sha256sum -c` and to verify-host-security.sh's TCB check. The directory is
# created here so a fresh host does not depend on host prep ordering.
sandswap_install_guest_artifacts() {
    local output="$1"
    local f
    install -d -m 0755 -o root -g root "$SANDSWAP_GUEST_DIR" \
        || err "cannot create the guest TCB directory $SANDSWAP_GUEST_DIR"
    for f in vmlinux.bin initramfs.cpio.gz; do
        [[ -f "$output/$f" ]] || err "guest artifact missing: $output/$f"
        install -m 0644 -o root -g root "$output/$f" "$SANDSWAP_GUEST_DIR/$f" \
            || err "cannot install $f into $SANDSWAP_GUEST_DIR"
    done
    ( cd "$SANDSWAP_GUEST_DIR" && sha256sum vmlinux.bin initramfs.cpio.gz > SHA256SUMS ) \
        || err "cannot write $SANDSWAP_GUEST_DIR/SHA256SUMS"
    chmod 0644 "$SANDSWAP_GUEST_DIR/SHA256SUMS"
    log "Guest TCB installed: $SANDSWAP_GUEST_DIR (root:root 0755, SHA256SUMS pinned)"
}

# sandswap_guest_artifact <name> — resolve where the guest TCB file lives.
# The pinned location is authoritative; a legacy copy in the state root is
# accepted ONLY when the pinned one is absent (deployers outside this file
# still install there), with a loud warning so the drift is visible.
sandswap_guest_artifact() {
    local name="$1"
    if [[ -f "$SANDSWAP_GUEST_DIR/$name" ]]; then
        printf '%s\n' "$SANDSWAP_GUEST_DIR/$name"
        return 0
    fi
    if [[ -f "$SANDSWAP_VAR/$name" ]]; then
        warn "guest TCB $name resolves to the LEGACY location $SANDSWAP_VAR/$name — that directory is traversable by the service identities; run the current deployer to install it under root-only $SANDSWAP_GUEST_DIR"
        printf '%s\n' "$SANDSWAP_VAR/$name"
        return 0
    fi
    printf '%s\n' "$SANDSWAP_GUEST_DIR/$name"
}

# ──── THE prov-side contract (single source of truth) ─────────────────────
#
# Every path that the storage plane touches has a REQUIRED owner/mode, and the
# owner depends on the deployment SHAPE — who carries the prov role:
#
#   merged          one sandlot process, roles [exec,prov], runs as `sandlot`
#                   (deploy-single-node.sh, e2e/single-node-multi-agent.sh, e2e shapes)
#   dedicated-prov  a SEPARATE prov-role instance runs as `sandprov`
#                   (one-machine-etcd, the cluster shapes, verify-binpack)
#
# The shape is named by ONE variable, SS_PROV_USER (runtime.sh defines the
# merged default; dedicated shapes export SS_PROV_USER=sandprov AND call
# sandswap_write_prov_user_env so the systemd units' ExecStartPost re-assert
# sees the same answer).
#
# Why this function exists: the storage-plane split, the four identities, the
# per-OWNER device model and the volume-name seed each added a dimension to
# this contract, and every deploy path used to re-derive it BY HAND — so each
# one drifted differently. The drift bill:
# single-node broke on three stacked hardcodings (seed file, template store,
# volumes root) plus a fourth in the units' ExecStartPost; the legacy
# background-process shape broke on the missing /etc/sandswap, a root-owned
# state dir, and the missing template store; verify-binpack broke on the seed
# key and the volumes owner. All of them are the SAME defect: no single
# implementation of "who owns what, per shape".
#
# THE CONTRACT (asserted live by security/verify-host-security.sh):
#   /etc/sandswap                      root:root       0755  (+ certs/, seed)
#   /etc/sandswap/volume-seed          root:sandprov   0640  (mint-once)
#   /var/lib/sandswap                  root:root        0755
#                                      (the directory may carry the guest TCB in
#                                       some shapes; the gateway's writable
#                                       state lives in the private state/
#                                       subdirectory, 0700 <gateway-id>)
#   /var/lib/sandswap/volumes          <prov>:<shared> 2710  (create only)
#   /var/lib/sandswap/<tpl stores>     <prov>:<shared> 2750  (read-only peers)
#
# The seed's group is the DEDICATED provision group (sandprov) in EVERY shape,
# never the prov identity's primary group: in the merged shape the prov identity
# is sandlot, and the sandvmm identity (every VMM + the FUSE passthrough
# daemon) is a member of group sandlot — a seed at root:sandlot 0640 is
# readable by the guest-data-facing daemon, which makes every tenant's
# directory name computable again. The prov process carries sandprov instead:
# SupplementaryGroups= on
# the sandlot units for the merged shape, the primary group for the dedicated
# sandprov unit.
# shellcheck disable=SC2034
SANDPROV_GROUP="${SANDPROV_GROUP:-sandprov}"
sandswap_apply_prov_plane() {
    # ESTABLISH the paths, then shape them: the prov manager creates layers/
    # under the template store at startup and dies EACCES if the store itself
    # does not exist under the root-owned 0755 state root — the legacy
    # background shape never called the dirs step.
    mkdir -p "$SANDSWAP_VAR"/{volumes,templates,flat-templates} 2>/dev/null || true
    # Invariant 8 made TRUE BY CONSTRUCTION (the sandlot refuses to start on
    # a volumes tree without nosuid,nodev — the passthrough stores guest
    # setuid/mknod verbatim and only the mount flags make them inert):
    # self-bind + remount applies the per-mount flags with no dedicated
    # filesystem. Idempotent; fatal on failure (a deployer that cannot
    # harden the tree must not ship it soft).
    ss_harden_volumes_mount "$SANDSWAP_VAR/volumes" || {
        echo "FATAL: cannot harden $SANDSWAP_VAR/volumes with nosuid,nodev (invariant 8) — refusing to deploy a soft volumes tree" >&2
        exit 1
    }
    # The ownership half is the SHARED implementation (common/sh/runtime.sh) —
    # the same one the e2e tree applies, so a shape can no longer drift between
    # the two trees. owner/mode contract: see ss_apply_share_plane.
    ss_apply_share_plane "$SANDSWAP_VAR" "$SANDSWAP_VAR/volumes" \
        "$SANDSWAP_VAR/templates" "$SANDSWAP_VAR/flat-templates" "$SANDSWAP_VAR/overlay-templates"
    # One-time state move: the gateway's identity store used to live at the
    # state-root TOP LEVEL (a directory every service identity can traverse and
    # that previously BELONGED to the gateway identity — owner-write was enough
    # to replace it). It now lives in the private state/ subdirectory; migrate
    # an existing store instead of silently starting from an empty one.
    local _gw_user="${SS_SERVICE_USER_GW:-sandserv}"
    local _legacy_store="$SANDSWAP_VAR/identity-store.json"
    local _state_store="$SANDSWAP_VAR/state/identity-store.json"
    if [[ -f "$_legacy_store" && ! -e "$_state_store" ]]; then
        mv -f "$_legacy_store" "$_state_store" \
            && chown "$_gw_user":"$_gw_user" "$_state_store" 2>/dev/null \
            && chmod 0600 "$_state_store" 2>/dev/null \
            && log "identity store migrated: $_legacy_store → $_state_store"
        _legacy_store="" _state_store=""
    fi
    # SANDSWAP_SEED_MINT=0 (exec-only hosts): never mint locally — require the
    # fleet-distributed seed and verify its scope. A local mint would derive a
    # DIFFERENT volume-name generation, so this host would address names that
    # no provisioned volume carries.
    if [[ "${SANDSWAP_SEED_MINT:-1}" == "1" ]]; then
        sandswap_ensure_volume_seed
    else
        local seed_file="${SANDSWAP_VOLUME_SEED_FILE:-${SANDSWAP_ETC}/volume-seed}"
        if [[ ! -s "$seed_file" ]]; then
            log "ERROR: volume-name seed $seed_file is missing on this exec-only host — the seed must be minted once and distributed fleet-wide (or set SANDSWAP_SEED_MINT=1 to designate this host as the minter)"
            exit 1
        fi
        sandswap_verify_volume_seed_scope "$seed_file" || exit 1
    fi
}

# ss_harden_volumes_mount — ensure the volumes tree carries the nosuid,nodev
# per-mount flags (invariant 8). A self-bind followed by a bind-remount sets
# per-mount flags on exactly this subtree without a dedicated filesystem and
# works over any backing (local fs, NFS bind). No-op when findmnt already
# reports both flags (idempotent across re-deploys and unit restarts).
ss_harden_volumes_mount() {
    local dir="$1"
    [[ -d "$dir" ]] || mkdir -p "$dir"
    local opts
    opts="$(findmnt -n -o OPTIONS "$dir" 2>/dev/null || true)"
    if [[ "$opts" == *nosuid* && "$opts" == *nodev* ]]; then
        return 0
    fi
    mount --bind "$dir" "$dir" || return 1
    mount -o remount,bind,nosuid,nodev "$dir" || return 1
}

# sandswap_write_prov_user_env — persist the deployment's prov-side SHAPE for
# the systemd units' ExecStartPost ownership re-assert (see the unit comment).
# Called by every deployer after it knows its shape: sandprov (dedicated prov
# instance) or sandlot (merged exec,prov). The file is deployment state, not a
# secret; units read it with EnvironmentFile=- (missing = default sandprov).
sandswap_write_prov_user_env() {
    install -d -m 0755 "$SANDSWAP_ETC"
    printf 'SS_PROV_USER=%s\n' "$SS_PROV_USER" > "$SANDSWAP_ETC/prov-user.env"
    chmod 0644 "$SANDSWAP_ETC/prov-user.env"
}

# sandswap_write_sandctl_env <gateway_url> <human_url> <tls|plain> [ca_path] [etcd_url]
# — publish the client contract sandctl reads (/etc/sandswap/sandctl.env).
# PUBLIC material only: listener URLs, the CA trust anchor and the TLS toggle.
# It NEVER names a private key: the deployers scope every service key to the
# identity that loads it, and a client command must not be handed one. Called
# only after the deployment's health gate, so a failed deploy does not
# advertise a dead stack. CLI flags always override these values.
sandswap_write_sandctl_env() {
    local gateway_url="$1" human_url="$2" tls_mode="$3"
    local ca_path="${4:-}" etcd_url="${5:-}"
    [[ -n "$gateway_url" && -n "$human_url" ]] \
        || err "sandctl env: gateway_url and human_url are required"
    case "$tls_mode" in
        tls|plain) ;;
        *) err "sandctl env: mode must be tls|plain (got '$tls_mode')" ;;
    esac
    if [[ "$tls_mode" == "tls" ]]; then
        [[ -n "$ca_path" && -f "$ca_path" ]] \
            || err "sandctl env: a TLS contract requires an existing CA certificate (got '$ca_path')"
        [[ "$ca_path" == /* ]] || err "sandctl env: the CA path must be absolute (got '$ca_path')"
    fi
    install -d -m 0755 "$SANDSWAP_ETC"
    local tmp
    tmp="$(mktemp "$SANDSWAP_ETC/.sandctl.env.XXXXXX")" \
        || err "sandctl env: cannot create a temp file under $SANDSWAP_ETC"
    {
        echo "# Generated by the Sandswap deployer — sandctl client contract."
        echo "# Public endpoints and the CA trust anchor only. No private keys."
        echo "# Re-run the deployer to regenerate. CLI flags override these values."
        printf 'gateway_url=%s\n' "$gateway_url"
        printf 'human_url=%s\n' "$human_url"
        if [[ "$tls_mode" == "tls" ]]; then
            printf 'tls=true\n'
            printf 'ca=%s\n' "$ca_path"
        else
            printf 'tls=false\n'
        fi
        [[ -n "$etcd_url" ]] && printf 'etcd=%s\n' "$etcd_url"
    } > "$tmp"
    # Defence in depth: the contract is world-readable, so a private-key path
    # in it would advertise a credential the caller must never use.
    if grep -q '\.key' "$tmp"; then
        rm -f "$tmp"
        err "sandctl env: refusing to publish a contract that names a private key"
    fi
    chown root:root "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$SANDSWAP_ETC/sandctl.env"
    log "Client contract written: $SANDSWAP_ETC/sandctl.env (public URLs + CA only)"
}

# ──── Sysctls ────

sandswap_install_sysctls() {
    # perf_event_paranoid: only write the floor (2) if the RUNNING value is
    # below it. k8s-host-setup.sh pins 4 in 99-sandswap-perf.conf; an
    # unconditional 2 here would silently downgrade the host at next boot
    # ("99-sandswap.conf" sorts AFTER "99-sandswap-perf.conf", so the weaker
    # value wins). Same rule as the k8s deploy scripts.
    local paranoid_line="kernel.perf_event_paranoid = 2"
    if [[ "$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 2)" -ge 2 ]]; then
        paranoid_line=""
    fi
    {
        echo "# Sandswap host sysctls"
        # Forwarding is a BRIDGE-ROLE setting: a gateway/provision-only host
        # routes nothing for guests, and leaving ip_forward on made every
        # multi-homed node a router for its guests. setup-host.sh exports
        # SANDSWAP_ENABLE_IP_FORWARD=0 per role; the default keeps the
        # deployers that do not know their role (and DO serve VMs) working.
        if [[ "${SANDSWAP_ENABLE_IP_FORWARD:-1}" == "1" ]]; then
            echo "net.ipv4.ip_forward = 1"
        fi
        echo "kernel.yama.ptrace_scope = 1"
        if [[ -n "$paranoid_line" ]]; then
            echo "$paranoid_line"
        fi
    } > "$SANDSWAP_SYSCTL"
    sysctl --system > /dev/null 2>&1 || true
    log "Sysctls installed: $SANDSWAP_SYSCTL"
}

# ──── Device Nodes ────

sandswap_check_kvm() {
    if [[ ! -e /dev/kvm ]]; then
        err "/dev/kvm not found. Enable KVM in BIOS/VM settings."
    fi
    if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
        warn "/dev/kvm not readable/writable. Consider: chmod 666 /dev/kvm"
    fi
    log "KVM available: /dev/kvm"
}

sandswap_setup_dev_nodes() {
    # ONE implementation, shared with the e2e tree (ss_ensure_dev_nodes): the
    # per-OWNER device model, the /dev/kvm 0660 root:kvm re-assert, and the
    # vhost_vsock load. Explicit-restore doctrine: never gamble on udev timing
    # — a module reload recreates devtmpfs nodes without guaranteeing the rule
    # reapplies, and sandlot's startup owner-check fails fast on a stale node
    # ("vhost-vsock owned by uid 0, want the sandvmm identity 987").
    ss_ensure_dev_nodes
    if [[ ! -e /dev/vhost-vsock ]]; then
        warn "/dev/vhost-vsock not found. vhost_vsock module may not be loaded."
    fi
}

# ──── Binary Installation ────

sandswap_install_binary() {
    local src="$1" dest="$2"
    if [[ -e "$dest" ]]; then
        # Backup previous version
        cp "$dest" "${dest}.prev"
    fi
    cp "$src" "$dest"
    chmod 755 "$dest"
    log "Installed: $(basename "$dest") → $dest"
}

# sandswap_fetch_etcd <etcd-output-dir> — download the pinned etcd release
# into <dir> (etcd + etcdctl), digest-verified. The same discipline the
# template store applies to every registry blob: a control-plane binary is
# never installed from an unverified download. A checksum mismatch aborts the
# deploy (set -e) instead of installing whatever the mirror served.
ETCD_RELEASE_SHA256="b414b27a5ad05f7cb01395c447c85d3227e3fb1c176e51757a283b817f645ccc"
sandswap_fetch_etcd() {
    local out_dir="$1"
    mkdir -p "$out_dir"
    log "Downloading etcd (sha256-pinned)..."
    (cd /tmp && wget -q https://github.com/etcd-io/etcd/releases/download/v3.5.16/etcd-v3.5.16-linux-amd64.tar.gz && \
        echo "${ETCD_RELEASE_SHA256}  etcd-v3.5.16-linux-amd64.tar.gz" | sha256sum -c - && \
        tar xzf etcd-v3.5.16-linux-amd64.tar.gz && \
        cp etcd-v3.5.16-linux-amd64/etcd "$out_dir/etcd" && \
        cp etcd-v3.5.16-linux-amd64/etcdctl "$out_dir/etcdctl")
}

# ──── Systemd ────

sandswap_install_systemd_unit() {
    local src="$1"
    local name
    name="$(basename "$src")"
    cp "$src" /etc/systemd/system/"$name"
    # The units' ExecStartPost calls ONE installed implementation of the
    # prov-side ownership re-assert (see sandswap-apply-prov-ownership.sh and
    # sandswap_apply_prov_plane in this file — keep them in lockstep).
    install -d -m 0755 /usr/local/lib/sandswap
    local helper
    helper="$(dirname "$src")/../sandswap-apply-prov-ownership.sh"
    [[ -f "$helper" ]] && install -m 0755 "$helper" /usr/local/lib/sandswap/apply-prov-ownership
    systemctl daemon-reload
    log "Systemd unit installed: $name"
}

sandswap_enable_service() {
    local name="$1"
    # Clear any start-limit failure state from previous runs (e.g., crash loops
    # during earlier deploys) — otherwise systemctl enable --now can be blocked.
    systemctl reset-failed "$name" 2>/dev/null || true
    systemctl enable --now "$name"
    log "Service enabled: $name"
}

# ──── Stop / Disable ────

# sandswap_stop_services — stop + disable every Sandswap systemd unit
# (gateway, gateway-<role> instances, sandlot, sandlot-instance@<N>, dns).
#
# MUST run BEFORE killing processes: the units use Restart=on-failure, so
# killing the process alone would just have systemd respawn it — and the
# respawned instance would reconnect to the NEXT deployment, polluting its
# health node_count / ports and making test results non-deterministic.
sandswap_stop_services() {
    log "Stopping Sandswap systemd services..."
    # Glob stop matches every loaded unit (gateway, gateway-execN/bpN, sandlot,
    # sandlot-instance@N, dns). list-unit-files only shows the template unit for
    # template instances, so enumerating it would miss the real instances.
    systemctl stop 'sandswap-*' 2>/dev/null || true
    # Disable — systemctl disable does NOT accept globs, so enumerate the
    # enabled units from the wants symlinks + any loaded unit.
    local unit
    for unit in $( { ls /etc/systemd/system/*.wants/sandswap-*.service 2>/dev/null; \
                     systemctl list-units 'sandswap-*' --all --no-legend 2>/dev/null; } \
                   | sed 's#.*/##' | sort -u); do
        systemctl disable "$unit" 2>/dev/null || true
    done
    systemctl daemon-reload
    log "Sandswap systemd services stopped + disabled"
    # Bare-metal deployers assume a dedicated host: a container runtime
    # (k3s/kube-router, docker) holds FORWARD-policy posture, ports and memory
    # that make every later verify nondeterministic. Stop it unless the
    # caller opted out (SANDSWAP_KEEP_CONTAINER_RUNTIME=1).
    ss_container_runtime_clean || err "cannot stop the container runtime — host not clean for a bare-metal deploy"
}

# sandswap_kill_port_processes — kill any process holding Sandswap's well-known
# ports (agent 3000, human 3100, stream 9998, etcd 2379). Catches leftovers that
# are NOT sandswap-named (kubectl port-forward from a k8s deploy, a stale admin
# gateway, etc.) which pkill -f 'sandswap' would miss — without this, a stale
# 3100 listener makes the new gateway's human server fail to bind and /stats
# never comes up (non-deterministic deploys).
sandswap_kill_port_processes() {
    # ss-based (ss_kill_ports, common/sh/runtime.sh): lsof is not part of the
    # base install set and its absence makes `lsof ... || true` a silent no-op
    # (ports stay held → random deploy fails).
    local pids port
    for port in ${SS_PORTS_PROD_STACK} ${SS_PORTS_ETCD}; do
        pids="$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u || true)"
        if [[ -n "$pids" ]]; then
            echo "  Killing process(es) on port $port: $pids"
        fi
    done
    ss_kill_ports ${SS_PORTS_PROD_STACK} ${SS_PORTS_ETCD}
    return 0
}

# ──── Health Checks ────

sandswap_wait_for_health() {
    local addr="${1:-localhost:3000}"
    local proto="https"
    local max_wait="${2:-30}"
    local elapsed=0

    # If --no-tls, use http
    if [[ "${NO_TLS:-}" == "1" ]]; then
        proto="http"
    fi

    log "Waiting for gateway health at ${proto}://${addr}/health (max ${max_wait}s)..."
    while (( elapsed < max_wait )); do
        if curl -sk "${proto}://${addr}/health" 2>/dev/null | grep -q "ok\|healthy\|200"; then
            log "Gateway is healthy (${elapsed}s)"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    err "Gateway did not become healthy within ${max_wait}s"
}

sandswap_wait_for_pool() {
    local addr="${1:-localhost:3100}"
    local target="${2:-1}"
    local proto="https"
    local max_wait="${3:-120}"
    local elapsed=0

    if [[ "${NO_TLS:-}" == "1" ]]; then
        proto="http"
    fi

    log "Waiting for pool ready (CLEAN >= ${target}) at ${proto}://${addr}/stats (max ${max_wait}s)..."
    while (( elapsed < max_wait )); do
        local clean
        # Stats JSON: new format {"totals":{"clean_vms":N,...}} (legacy: {"CLEAN":0,...})
        clean=$(curl -sk "${proto}://${addr}/stats" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('totals',{}).get('clean_vms') or d.get('clean_vms') or d.get('CLEAN', d.get('clean', 0)))" 2>/dev/null || echo "0")
        if (( clean >= target )); then
            log "Pool ready: CLEAN=${clean} (target=${target}, ${elapsed}s)"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    err "Pool did not reach target within ${max_wait}s"
}

# ──── Config Generation ────

sandswap_generate_gateway_config() {
    local output="$1"
    local mode="${2:-}"
    local vol_root="${3:-/var/lib/sandswap/volumes}"
    local agent_addr="${4:-0.0.0.0:3000}"
    local human_addr="${5:-127.0.0.1:3100}"
    local stream_addr="${6:-0.0.0.0:9998}"
    local tls_dir="${7:-}"
    # STREAM TLS is independent of the HTTP-listener TLS in tls_dir. The stream
    # listener ALWAYS requires a client certificate (the gateway refuses a
    # certificate-less stream and binds its CN to the hello's node_id), so a
    # --no-tls shape (plaintext HTTP listeners, empty tls_dir) still points the
    # stream block at a minted cert dir via SANDSWAP_STREAM_TLS_DIR. Unset →
    # same as tls_dir, so every full-TLS caller is byte-identical to before.
    local stream_tls_dir="${SANDSWAP_STREAM_TLS_DIR:-$tls_dir}"

    # the human control plane (agent minting, sandfs CRUD, template
    # ops, ownership reclamation) is only scoped by authn (OIDC) — which
    # these deployers do not configure. A non-loopback bind therefore
    # publishes an UNAUTHENTICATED full-control plane. Single-host shapes
    # pass 127.0.0.1; multi-host shapes keep the bind (remote ops need it)
    # but get this loud warning until an authn block is configured.
    case "$human_addr" in
        127.0.0.1:*|localhost:*|"[::1]":*) ;;
        *) log "WARNING: human listener on ${human_addr} with NO authn configured — the full control plane is reachable by anyone who can connect. Restrict the network (ACL/NetworkPolicy) or configure authn (issuer) in the gateway config." ;;
    esac

    cat > "$output" << YAML
mode: "${mode}"
vol_root: ${vol_root}
# The gateway's credential state lives under the private state/ subdirectory:
# the state-root directory itself is root-owned 0755 (it may carry the guest
# TCB), so the identity store must not be written at its top level.
identity_store: $(dirname "${vol_root}")/state/identity-store.json
YAML

    # Affinity fields — emitted ONLY in exec mode with values set.
    # Driven by env vars so single-node / small-cluster callers (which pass
    # positional args only) are unaffected; the production deploy scripts export
    # these per-gateway before generating exec configs.
    #   gateway_id           fixed unique identity (multi-GW must differ)
    #   gateway_url          https://<GW IP>:3000 — owner-aware DNS A target + 307 Location (registry key)
    #   gateway_stream_addr  <GW IP>:9998 — registered in registry key (sandlot last-gateway memory)
    #   idle_timeout_sec     long keep-alive so the connection = the affinity anchor
    if [[ "$mode" == "exec" ]]; then
        if [[ -n "${SANDSWAP_GATEWAY_ID:-}" ]]; then
            cat >> "$output" << YAML

gateway_id: ${SANDSWAP_GATEWAY_ID}
YAML
        fi
        if [[ -n "${SANDSWAP_GATEWAY_URL:-}" ]]; then
            cat >> "$output" << YAML

gateway_url: "${SANDSWAP_GATEWAY_URL}"
YAML
        fi
        if [[ -n "${SANDSWAP_GATEWAY_STREAM_ADDR:-}" ]]; then
            cat >> "$output" << YAML

gateway_stream_addr: "${SANDSWAP_GATEWAY_STREAM_ADDR}"
YAML
        fi
        if [[ -n "${SANDSWAP_IDLE_TIMEOUT_SEC:-}" ]]; then
            cat >> "$output" << YAML

idle_timeout_sec: ${SANDSWAP_IDLE_TIMEOUT_SEC}
YAML
        fi
    fi

    # etcd config for exec/human modes. The TLS fields follow tls_dir like the
    # HTTP listener blocks above: an empty tls_dir (--no-tls simulation deploys
    # with a plain-http etcd) must not emit dangling cert paths — the gateway
    # would fail to build its etcd client at startup. (The stream block below
    # does NOT follow tls_dir — see stream_tls_dir.)
    if [[ -n "${8:-}" ]]; then
        cat >> "$output" << YAML

etcd: "${8}"
YAML
        if [[ -n "$tls_dir" ]]; then
            cat >> "$output" << YAML
etcd_ca: ${tls_dir}/ca.crt
etcd_cert: ${tls_dir}/etcd-client.crt
etcd_key: ${tls_dir}/etcd-client.key
YAML
        fi
    fi

    # Agent listener
    cat >> "$output" << YAML

agent:
  addr: "${agent_addr}"
YAML
    if [[ -n "$tls_dir" ]]; then
        cat >> "$output" << YAML
  tls_cert: ${tls_dir}/mcp.crt
  tls_key: ${tls_dir}/mcp.key
YAML
    fi

    # Human listener (skip for exec mode)
    if [[ "$mode" != "exec" ]]; then
        cat >> "$output" << YAML

human:
  addr: "${human_addr}"
YAML
        if [[ -n "$tls_dir" ]]; then
            cat >> "$output" << YAML
  tls_cert: ${tls_dir}/human.crt
  tls_key: ${tls_dir}/human.key
YAML
        fi
    fi

    # Stream listener. Human mode needs one too under the RPC storage
    # backend: its prov-role instances dial THIS listener (a dedicated port —
    # the co-located exec gateway owns 9998). Single-node/exec unchanged.
    # Certificates are NOT optional here: a stream without a client certificate
    # is refused at the handshake, so this block is emitted whenever
    # stream_tls_dir is set — which --no-tls scripts now always set.
    cat >> "$output" << YAML

stream:
  addr: "${stream_addr}"
YAML
        if [[ -n "$stream_tls_dir" ]]; then
            cat >> "$output" << YAML
  tls_cert: ${stream_tls_dir}/stream.crt
  tls_key: ${stream_tls_dir}/stream.key
  tls_ca: ${stream_tls_dir}/ca.crt
YAML
        fi

    # Lease + exec defaults
    cat >> "$output" << YAML

lease:
  sticky_ms: 100
  max_sticky_sec: 5

exec:
  default_timeout_sec: 30
  max_timeout_sec: 180
YAML

    # Staleness thresholds (health-key staleness judgment — the health key has
    # NO lease; death is judged purely by how long since last_healthy_ts was
    # refreshed). Override only to tune detection speed vs false-death
    # tolerance. Applies to exec + human modes.
    #   SANDSWAP_ROUTE_STALE_SEC       DNS/307 reroute threshold (default 20)
    #   SANDSWAP_CLAIM_DEAD_GUARD_SEC  idle-claim protection window (default 45)
    #   SANDSWAP_ALERT_STALE_SEC       alert-scan warn threshold (default 30)
    cat >> "$output" << YAML

staleness:
  route_stale_sec: ${SANDSWAP_ROUTE_STALE_SEC:-20}
  claim_dead_guard_sec: ${SANDSWAP_CLAIM_DEAD_GUARD_SEC:-45}
  alert_stale_sec: ${SANDSWAP_ALERT_STALE_SEC:-30}
YAML

    # MCP agent guide: materialize the ops-editable instructions file from the
    # compiled-in default (single source of truth — the installed gateway
    # binary, not a second copy in this repo). Generate-once: a re-run of the
    # deploy never clobbers operator edits (edit the file directly; the gateway
    # hot-reloads it). The {{max_exec_timeout_sec}} / {{sticky_ms}} placeholders
    # render the
    # / {{sticky_ms}} placeholders render the live sync-exec cap / sticky
    # idleness window at serve time. Emit the config key only when the file
    # exists (staging generation on a build host without the binary installed
    # keeps the built-in default).
    local mcp_file="${SANDSWAP_ETC}/mcp-instructions.md"
    if [[ ! -s "$mcp_file" && -x "${SANDSWAP_BIN}/sandswap-gateway" ]]; then
        "${SANDSWAP_BIN}/sandswap-gateway" -print-mcp-instructions > "$mcp_file" \
            || warn "failed to generate $mcp_file (gateway serves the built-in default)"
    fi
    if [[ -s "$mcp_file" ]]; then
        cat >> "$output" << YAML

mcp:
  instructions_file: ${mcp_file}
YAML
    fi

    log "Gateway config generated: $output (mode=${mode:-single-node})"
}

# yaml_dq <value> — escape a value for a double-quoted YAML scalar. Backslash
# first (it is YAML's escape character), then the closing quote. Without this
# a password containing " or \ would corrupt the generated config.
yaml_dq() {
    local v="$1"
    v="${v//\\/\\\\}"
    printf '%s' "${v//\"/\\\"}"
}

sandswap_generate_sandlot_config() {
    local output="$1"
    local gateway_addr="${2:-localhost:9998}"
    local node_id="${3:-}"
    local pool="${4:-medium:3}"
    local subnet="${5:-10.188.0.0/16}"
    local gateway_ip="${6:-10.188.0.1}"
    local vol_root="${7:-/var/lib/sandswap/volumes}"
    local tls_dir="${8:-}"
    # Optional: instance id + CID range for multi-sandlot on one host
    local instance_id="${9:-}"
    local cid_start="${10:-}"
    local cid_end="${11:-}"

    cat > "$output" << YAML
gateway_addr: "${gateway_addr}"
node_id: "${node_id}"
vm_mode: embedded
vmm_binary: ${SANDSWAP_BIN}/sandswap-sandvmm

microvm:
  kernel: $(sandswap_guest_artifact vmlinux.bin)
  initramfs: $(sandswap_guest_artifact initramfs.cpio.gz)
  default_vcpus: ${SANDSWAP_DEFAULT_VCPUS:-2}
  default_memory_mb: ${SANDSWAP_DEFAULT_MEMORY_MB:-512}
  volumes_dir: ${vol_root}

specs:
  small:  { vcpus: 2, memory_mb: 256,  exec_slots: 3 }
  medium: { vcpus: 4, memory_mb: 1024, exec_slots: 4 }

pool: "${pool}"

recycle:
  mem_percent: 10
  mem_abs_mb: 100

network:
  backend: ${SANDSWAP_NETWORK_BACKEND:-bridge}
  bridge: br-sandswap
  subnet: ${subnet}
  gateway: ${gateway_ip}
  dns: "1.1.1.1,8.8.8.8"
YAML

    # Egress identity enabler (docs/how-it-works/egress-enabler.md). Everything is
    # opt-in via env — with none set the generated file is byte-identical to
    # the pre-enabler output and behavior is unchanged (all keys default off).
    #   SANDSWAP_BINDING_BACKEND  shm|bpf — publish (tap ifindex → agent/sandfs)
    #                             to the node-local binding region
    #   SANDSWAP_VM_TO_VM_POLICY  allow — open guest↔guest traffic (default deny)
    #   SANDSWAP_EGRESS_BASELINE  off — disable the nftables baseline (default on)
    #   SANDSWAP_NETWORK_BACKEND  routed-ipv6 — identity-in-address backend
    #   SANDSWAP_V6_PREFIX        routed-ipv6 site prefix (default fd00:5341:4e44::/48)
    #   SANDSWAP_IID_TEMPLATE     IID layout, e.g. "agent:32,sandfs:32"
    #                             (enables mount-time identity stamping)
    if [[ -n "${SANDSWAP_BINDING_BACKEND:-}" || -n "${SANDSWAP_VM_TO_VM_POLICY:-}" \
        || -n "${SANDSWAP_EGRESS_BASELINE:-}" || -n "${SANDSWAP_IID_TEMPLATE:-}" \
        || -n "${SANDSWAP_V6_PREFIX:-}" ]]; then
        cat >> "$output" << YAML
  egress_baseline: ${SANDSWAP_EGRESS_BASELINE:-on}
YAML
        # `|| true` guards set -e: a false [[ ]] guard must not kill the deploy.
        [[ -n "${SANDSWAP_VM_TO_VM_POLICY:-}" ]] && \
            echo "  vm_to_vm: ${SANDSWAP_VM_TO_VM_POLICY}" >> "$output" || true
        [[ -n "${SANDSWAP_BINDING_BACKEND:-}" ]] && \
            echo "  bind_backend: ${SANDSWAP_BINDING_BACKEND}" >> "$output" || true
        if [[ "${SANDSWAP_NETWORK_BACKEND:-}" == "routed-ipv6" || -n "${SANDSWAP_IID_TEMPLATE:-}" || -n "${SANDSWAP_V6_PREFIX:-}" ]]; then
            [[ "${SANDSWAP_NETWORK_BACKEND:-}" == "routed-ipv6" ]] && \
                echo "  v6_prefix: ${SANDSWAP_V6_PREFIX:-fd00:5341:4e44::/48}" >> "$output" || true
            [[ -n "${SANDSWAP_IID_TEMPLATE:-}" ]] && \
                echo "  iid_template: \"${SANDSWAP_IID_TEMPLATE}\"" >> "$output" || true
        fi
        # routed-ipv6 without the backend override would ignore v6 keys —
        # flip the backend too so a single env turn-on works.
        if [[ -n "${SANDSWAP_IID_TEMPLATE:-}" || -n "${SANDSWAP_V6_PREFIX:-}" ]] \
            && [[ -z "${SANDSWAP_NETWORK_BACKEND:-}" ]]; then
            sed -i 's/^  backend: bridge$/  backend: routed-ipv6/' "$output"
            echo "  v6_prefix: ${SANDSWAP_V6_PREFIX:-fd00:5341:4e44::/48}" >> "$output"
        fi
    fi

    # Multi-instance config (for multiple sandlots on one host)
    if [[ -n "$instance_id" ]]; then
        cat >> "$output" << YAML

instance:
  id: ${instance_id}
  base_dir: /run/sandswap/instance-${instance_id}
YAML
        if [[ -n "$cid_start" ]]; then
            cat >> "$output" << YAML
  cid_range_start: ${cid_start}
  cid_range_end: ${cid_end:-0}
YAML
        fi
    fi

    # Roles (exec | prov | exec,prov) + the provision-plane section. Driven by
    # env so existing callers are unaffected: unset SANDSWAP_SANDLOT_ROLES =
    # exec-only, byte-identical to the pre-roles output. "prov" in the set
    # emits the provision section (template store + flat scan dir + registry);
    # a prov-ONLY instance should use a pool of "" — the config validator
    # refuses exec machinery (pool/bridge/boxout) on prov-only instances.
    local roles="${SANDSWAP_SANDLOT_ROLES:-exec}"
    if [[ "$roles" != "exec" ]]; then
        cat >> "$output" << YAML

roles: [${roles}]
provision:
  templates_dir: ${SANDSWAP_PROVISION_TEMPLATES_DIR:-${SANDSWAP_VAR}/templates}
  flat_templates_dir: ${SANDSWAP_FLAT_TEMPLATES_DIR:-}
  oci_registry: "${SANDSWAP_PROVISION_OCI_REGISTRY:-}"
  volume_seed_file: ${SANDSWAP_VOLUME_SEED_FILE:-${SANDSWAP_ETC}/volume-seed}
YAML
        # Registry credentials, rendered ONLY when set (empty = anonymous).
        # Double-quoted YAML scalars: escape backslash and quote via yaml_dq.
        # The generated file may now carry a secret — the topology scripts
        # must ss_protect_config it (root:<service group> 0640) at install.
        if [[ -n "${SANDSWAP_PROVISION_REGISTRY_USERNAME:-}" ]]; then
            printf '  registry_username: "%s"\n' "$(yaml_dq "$SANDSWAP_PROVISION_REGISTRY_USERNAME")" >> "$output"
        fi
        if [[ -n "${SANDSWAP_PROVISION_REGISTRY_PASSWORD:-}" ]]; then
            printf '  registry_password: "%s"\n' "$(yaml_dq "$SANDSWAP_PROVISION_REGISTRY_PASSWORD")" >> "$output"
        fi
        if [[ -n "${SANDSWAP_PROVISION_REGISTRY_TOKEN:-}" ]]; then
            printf '  registry_token: "%s"\n' "$(yaml_dq "$SANDSWAP_PROVISION_REGISTRY_TOKEN")" >> "$output"
        fi
        if [[ -n "${SANDSWAP_PROVISION_REGISTRY_CERT:-}" ]]; then
            printf '  registry_cert: "%s"\n' "$(yaml_dq "$SANDSWAP_PROVISION_REGISTRY_CERT")" >> "$output"
        fi
        if [[ -n "${SANDSWAP_PROVISION_REGISTRY_KEY:-}" ]]; then
            printf '  registry_key: "%s"\n' "$(yaml_dq "$SANDSWAP_PROVISION_REGISTRY_KEY")" >> "$output"
        fi
        if [[ -n "${SANDSWAP_PROVISION_REGISTRY_CA:-}" ]]; then
            printf '  registry_ca: "%s"\n' "$(yaml_dq "$SANDSWAP_PROVISION_REGISTRY_CA")" >> "$output"
        fi
    fi

    if [[ -n "$tls_dir" ]]; then
        # SANDSWAP_SANDLOT_CERT_BASE names the stream client pair under
        # tls_dir (default "sandlot"). The gateway binds node_id == the
        # client certificate's CN, and ONE HOST MAY SERVE SEVERAL NODE IDS
        # (exec + prov, a simulation's N instances, a node_id composed with
        # an instance id) — each of those gets its own minted pair
        # (gen-baremetal-certs.sh --client-cn <node-id> →
        # sandlot-<node-id>.crt/.key), and the config must point at the pair
        # whose CN equals THIS instance's effective node id.
        local cert_base="${SANDSWAP_SANDLOT_CERT_BASE:-sandlot}"
        cat >> "$output" << YAML

tls:
  cert: ${tls_dir}/${cert_base}.crt
  key: ${tls_dir}/${cert_base}.key
  ca: ${tls_dir}/ca.crt
YAML
    fi

    log "Sandlot config generated: $output (gateway=${gateway_addr}, pool=${pool}, roles=${roles})"
}

# sandswap_verify_client_cert_cn <cert-file> <node-id> — assert the stream
# client certificate's CN IS the node id the instance declares. The gateway
# binds a stream hello's node_id to the presented client certificate's CN by
# exact match and refuses a mismatch by name at the handshake; this turns that
# first-connect failure into a DEPLOY-TIME failure that names the fix. Loud on
# purpose: the pair a host loads is chosen by a config path + a mint argument,
# and the two drifting apart is silent everywhere else.
sandswap_verify_client_cert_cn() {
    local cert="$1" node_id="$2" cn=""
    if [[ ! -s "$cert" ]]; then
        log "ERROR: stream client cert $cert is missing or empty (it must carry CN='$node_id')"
        return 1
    fi
    cn="$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
    if [[ "$cn" != "$node_id" ]]; then
        log "ERROR: $cert has CN='$cn' but this instance declares node id '$node_id' — the gateway binds CN == node_id exactly and will refuse the stream; mint a pair for THIS node id (gen-baremetal-certs.sh --client-cn '$node_id') and point the config at it"
        return 1
    fi
    log "Stream client cert verified: $(basename "$cert") CN='$cn' == node id"
}

# sandswap_prepare_provision_host makes a host ready for the prov-role
# instance (sandprov identity): the template store gets the shared-group
# setgid layout (NewManager's layers//refs/ land group-writable for every
# service identity), and the instance gets its own READABLE copy of the
# stream client key it must present (ss_own_tls_keys scopes keys per-identity
# — the sandlot user's pair is 0600 sandlot:sandlot, unreadable by sandprov;
# the material itself can be shared, the mTLS CA only checks the signature).
# <cert_base> is the prov node's client pair basename under cert_dir (the pair
# whose CN equals the prov instance's node id — see THE CN RULE in
# gen-baremetal-certs.sh); the copy lands as prov.key BESIDE it. Default
# "sandlot" only serves callers whose prov node IS the primary pair's node.
# sandswap_ensure_volume_seed mints ${SANDSWAP_ETC}/volume-seed if absent and
# re-asserts its scope. The seed derives every volume's on-disk directory name
# (sandlot/provision/volname): a REGENERATED seed would orphan every existing
# name, so an existing file is never touched. Scope 0640 root:sandprov — the
# DEDICATED provision group, never the shape's prov identity's primary group
# (the merged shape's is sandlot, and the sandvmm identity is a member — see
# the contract above). The scope is VERIFIED, not assumed: the shared helper
# swallows a failed chown/chmod, and a silent failure would leave the prov
# role unable to read its own seed (or worse, the daemon able to).
sandswap_ensure_volume_seed() {
    local seed_file="${SANDSWAP_VOLUME_SEED_FILE:-${SANDSWAP_ETC}/volume-seed}"
    install -d -m 0755 "$SANDSWAP_ETC" 2>/dev/null || true
    ss_ensure_volume_seed "$seed_file" "root:$SANDPROV_GROUP" 0640
    sandswap_verify_volume_seed_scope "$seed_file"
}

# sandswap_verify_volume_seed_scope <path> — assert the deployed scope of the
# volume-name seed: root:<sandprov> 0640. A failure is fatal to the deploy:
# every alternative (root:root = the prov role cannot start,
# root:<shared group> = the sandvmm identity can read the seed and every
# tenant's directory name is computable) is a broken deployment, and the
# verify-host-security check turns the second one into a FAIL on the next run.
sandswap_verify_volume_seed_scope() {
    local f="$1" owner group mode
    if [[ ! -s "$f" ]]; then
        log "ERROR: volume-name seed $f is missing or empty after ensure — the prov role refuses to start without a readable CURRENT generation"
        return 1
    fi
    if ! getent group "$SANDPROV_GROUP" >/dev/null 2>&1; then
        log "ERROR: group '$SANDPROV_GROUP' does not exist on this host — the seed cannot be scoped to the provision identity. Run host prep (setup-host.sh / ss_ensure_service_users) first."
        return 1
    fi
    owner="$(stat -c '%U' "$f" 2>/dev/null || echo '?')"
    group="$(stat -c '%G' "$f" 2>/dev/null || echo '?')"
    mode="$(stat -c '%a' "$f" 2>/dev/null || echo '?')"
    if [[ "$owner" != "root" || "$group" != "$SANDPROV_GROUP" || "$mode" != "640" ]]; then
        log "ERROR: volume-name seed $f is $owner:$group $mode — the contract is root:$SANDPROV_GROUP 640 (the prov process carries the sandprov group; the sandvmm identity must not read the seed). Fix: chown root:$SANDPROV_GROUP $f && chmod 0640 $f"
        return 1
    fi
}

sandswap_prepare_provision_host() {
    local templates_dir="$1" cert_dir="$2"
    local cert_base="${3:-sandlot}"
    mkdir -p "$templates_dir"
    sandswap_apply_prov_plane
    # The caller may pass a templates dir OUTSIDE $SANDSWAP_VAR (e2e shapes);
    # apply_prov_plane only shapes the standard paths — own the passed one too.
    chown "$SS_PROV_USER":"$SS_SHARED_GROUP" "$templates_dir" 2>/dev/null || true
    chmod 2750 "$templates_dir" 2>/dev/null || true
    if [[ -f "$cert_dir/${cert_base}.key" ]]; then
        # Always REFRESH the copy: certs are regenerated per run in test
        # harnesses (a stale copy fails with "private key does not match
        # public key"), and in production the source is static so re-copying
        # is a byte-identical no-op. The prov identity reads its OWN copy
        # (the source pair is scoped to the sandlot identity).
        cp -f "$cert_dir/${cert_base}.key" "$cert_dir/prov.key"
        chown "$SS_PROV_USER":"$SS_PROV_USER" "$cert_dir/prov.key" 2>/dev/null || true
        chmod 0600 "$cert_dir/prov.key" 2>/dev/null || true
    else
        # A silent skip here ships a prov instance that cannot present the
        # cert its config points at (or, worse, presents one whose CN is
        # another node's and is refused at the handshake). Name the pair.
        log "WARNING: provision host: $cert_dir/${cert_base}.key is missing — prov.key was NOT refreshed (mint the prov node's pair first: gen-baremetal-certs.sh --client-cn <prov-node-id>)"
    fi
    log "Provision host prepared: templates=${templates_dir} (${SS_PROV_USER}-owned, shared-group r-x), prov TLS key ready (from ${cert_base}.key)"
}

# ──── Shared Storage Mount ────

sandswap_mount_shared_storage() {
    local type="$1"
    local mount_point="$2"
    shift 2
    # Remaining args are type-specific parameters

    # Already mounted? Skip
    mountpoint -q "$mount_point" 2>/dev/null && { log "Shared storage already mounted: $mount_point"; return 0; }

    mkdir -p "$mount_point"

    # every mount must carry the storage contract's nosuid,nodev
    # (the virtio-fs passthrough stores guest-requested setuid bits verbatim;
    # only the mount flags make them inert) and the fstab line must be
    # duplicate-guarded (re-runs previously appended forever).
    case "$type" in
        nfs)
            local nfs_server="$1" nfs_export="$2"
            mount -t nfs -o nosuid,nodev,vers=4.2,_netdev "${nfs_server}:${nfs_export}" "$mount_point" \
                || mount -t nfs -o nosuid,nodev,_netdev "${nfs_server}:${nfs_export}" "$mount_point"
            grep -q " $mount_point nfs " /etc/fstab \
                || echo "${nfs_server}:${nfs_export} $mount_point nfs nosuid,nodev,_netdev,nofail 0 0" >> /etc/fstab
            ;;
        cfs)
            local cfs_server="$1"
            mount -t nfs -o nosuid,nodev,vers=4.0,noresvport "${cfs_server}:/" "$mount_point"
            grep -q " $mount_point nfs " /etc/fstab \
                || echo "${cfs_server}:/ $mount_point nfs nosuid,nodev,vers=4.0,noresvport,_netdev,nofail 0 0" >> /etc/fstab
            ;;
        cpfs)
            local cpfs_mount_cmd="$1"
            eval "$cpfs_mount_cmd"
            ;;
        cephfs)
            local ceph_mons="$1" ceph_user="$2" ceph_keyring="$3"
            mount -t ceph "${ceph_mons}:/" "$mount_point" -o "name=${ceph_user},secretfile=${ceph_keyring}"
            ;;
        pre-mounted)
            mountpoint -q "$mount_point" || err "pre-mounted: $mount_point is not a mount point"
            log "Shared storage pre-mounted: $mount_point"
            return 0
            ;;
        *)
            err "Unknown shared_storage type: $type"
            ;;
    esac

    # Create subdirectories
    mkdir -p "$mount_point"/{volumes,flat-templates,overlay-templates}
    log "Shared storage mounted: $mount_point (type=$type)"
}
