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
# k8s-host-setup.sh — One-time host setup for Sandswap K8s deployment.
# Must run as root on each KVM-capable node BEFORE deploying Sandswap to K8s.
# Some steps require a reboot (BPF LSM activation).
# This script implements the host setup documented in docs/deployment/prerequisites.md:
#   1. Checks/activates the bpf LSM (may require reboot)
#   2. Creates the sandlot service account (dedicated UID for vsockguard)
#   2b. Materializes THIS node's stream client certificate into
#       /etc/sandswap/stream-certs/ from its per-node Secret
#   3. Installs udev rules for vsock device lockdown
#   4. Pins anti-sniff sysctls (ptrace_scope, perf_event_paranoid)
#   5. Attaches vsockguard BPF program (allows sandlot UID to connect to warden)
#   6. Verifies all host security invariants
# The two-layer vsock transport protection:
#   Layer 1 (active impersonation): vsockguard BPF LSM denies connect() to
#     AF_VSOCK port 1024 for all UIDs except the sandlot service UID.
#   Layer 2 (passive sniffing): 4 host invariants (ptrace_scope, perf_event,
#     dedicated UID, device permissions) prevent observing existing connections.
# Both layers must hold. See docs/how-it-works/vsockguard.md and docs/deployment/prerequisites.md.
# Usage:
#   sudo bash deploy/k8s/k8s-host-setup.sh           # full setup
#   sudo bash deploy/k8s/k8s-host-setup.sh --verify   # verify only, no changes
#   sudo bash deploy/k8s/k8s-host-setup.sh --stream-certs-only
#       # (re-)fetch just this node's stream client certificate (step 2b):
#       # run after every PKI rotation and on a node whose sandlot pods die
#       # with a missing /etc/sandswap/stream-certs/client.crt
# Options:
#   --node <name>              this node's k8s node name (default: its hostname)
#   --stream-cert-owner <uid>  owner of the materialized client key
#                              (default: the sandlot service account's uid)
#   --mode embedded|boxout     which DaemonSet shape this host will run
#                              (default: boxout). It selects the UID vsockguard
#                              must allow: embedded pods run as UID 0, boxout
#                              pods as the reserved 65536. A pin for the wrong
#                              mode either fences the sandlot out of the warden
#                              (embedded) or leaves the port open to root only.
# Environment: SANDSWAP_K8S_NODE overrides the node name.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERIFY_ONLY=false
STREAM_CERTS_ONLY=false
K8S_NODE="${SANDSWAP_K8S_NODE:-}"
STREAM_CERT_OWNER=""
MODE="${SANDSWAP_K8S_MODE:-boxout}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verify)            VERIFY_ONLY=true; shift ;;
        --stream-certs-only) STREAM_CERTS_ONLY=true; shift ;;
        --mode)              MODE="${2:?--mode requires embedded|boxout}"; shift 2 ;;
        --node)              K8S_NODE="${2:?--node requires a name}"; shift 2 ;;
        --stream-cert-owner) STREAM_CERT_OWNER="${2:?--stream-cert-owner requires a uid}"; shift 2 ;;
        *) echo "error: unknown argument: $1" >&2; exit 1 ;;
    esac
done

case "$MODE" in
    embedded|boxout) ;;
    *) echo "error: --mode must be 'embedded' or 'boxout' (got '$MODE')" >&2; exit 1 ;;
esac

# Persist the deployment mode: security/verify-host-security.sh derives the
# expected vsockguard UID from it (embedded → 0, boxout → the sandlot account).
if [[ "$VERIFY_ONLY" == "false" ]]; then
    install -d -m 0755 /etc/sandswap
    printf 'SANDSWAP_DEPLOY_MODE=%s\n' "$MODE" > /etc/sandswap/deploy-mode.env
    chmod 0644 /etc/sandswap/deploy-mode.env
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (sudo)" >&2
    exit 1
fi

# ── Stream client certificate materialization (per node) ───────────
# THE CN RULE (deploy/k8s/gen-k8s-certs.sh): the gateway binds a stream
# hello's declared node_id to the presented client certificate's CN by EXACT
# match, and the sandlot pod declares node_id = its node name. The material is
# therefore PER NODE: this host fetches ITS OWN Secret (sandlot-certs-<node>)
# and writes it here; the DaemonSet mounts this directory (never a Secret
# shared across nodes). Ownership: the key is 0600 owned by the sandlot
# identity the boxout-shape pod runs as (the RESERVED uid 65536, pinned in the
# pod manifests) — the embedded
# pod runs as root and reads it regardless, while the in-pod sandvmm identity
# (987) and the prov pod (1000) must NOT: a readable stream key is an
# impersonation weapon (gateway/stream/server.go verifyNodeIdentity).
# Returns non-zero when the material could not be written.
STREAM_CERTS_DIR="/etc/sandswap/stream-certs"

stream_certs_kubectl() {
    if command -v kubectl >/dev/null 2>&1; then echo "kubectl"
    elif command -v k3s >/dev/null 2>&1; then echo "k3s kubectl"
    else echo ""; fi
}

# resolve_k8s_node <kubectl> <name-or-empty> — the cluster's node name for THIS
# host. The given name (or the hostname) is used when it names a real node;
# otherwise the cluster is asked which node carries this host's hostname(s) or
# IPs (a k8s node name need not equal the shell hostname — a kubeadm default
# often uses the FQDN). Empty when nothing matches.
resolve_k8s_node() {
    local kc="$1" node="${2:-}" cand addrs
    [[ -n "$kc" ]] || { echo ""; return 0; }
    local -a cands=("${node:-$(hostname)}" "$(hostname)" "$(hostname -f 2>/dev/null || true)")
    local ip
    for ip in $(hostname -I 2>/dev/null || true); do cands+=("$ip"); done
    local n
    for n in $($kc get nodes -o name 2>/dev/null | sed 's|^node/||'); do
        # The node's own name, first — the common case (k8s names the node
        # after the hostname, lowercased).
        for cand in "${cands[@]}"; do
            [[ -n "$cand" && "${n,,}" == "${cand,,}" ]] && { echo "$n"; return 0; }
        done
        # Else match the addresses the node reports (Hostname/InternalIP) —
        # covers a node named as its FQDN or an IP.
        addrs="$($kc get node "$n" -o jsonpath='{range .status.addresses[*]}{.address}{"\n"}{end}' 2>/dev/null || true)"
        while IFS= read -r cand; do
            [[ -n "$cand" ]] && printf '%s\n' "$addrs" | grep -qxF -- "$cand" && { echo "$n"; return 0; }
        done < <(printf '%s\n' "${cands[@]}")
    done
    echo ""
}

materialize_stream_certs() { # <node-name>
    local node="$1" kc secret tmp owner_uid owner_gid mode uid cn k
    kc="$(stream_certs_kubectl)"
    if [[ -n "$kc" ]] && ! $kc -n sandswap get secret "sandlot-certs-${node}" >/dev/null 2>&1; then
        # The name we were given has no Secret — this host may know its own
        # name differently from the cluster (FQDN node names). Resolve once.
        local resolved
        resolved="$(resolve_k8s_node "$kc" "$node")"
        if [[ -n "$resolved" && "$resolved" != "$node" ]]; then
            echo "  note: node name '$node' resolved to cluster node '$resolved' (addresses match this host)"
            node="$resolved"
        fi
    fi
    secret="sandlot-certs-${node}"
    if [[ -z "$kc" ]]; then
        echo "  ✗ no kubectl/k3s on this host — cannot fetch Secret $secret"
        echo "    Fix: re-run on a host with kubectl, or install the pair from output/k8s-certs/ by hand"
        return 1
    fi
    # Key owner: the sandlot service account the pods run as (boxout shape);
    # root (embedded shape) can read it regardless. Overridable for out-of-tree shapes.
    if [[ -n "$STREAM_CERT_OWNER" ]]; then
        owner_uid="$STREAM_CERT_OWNER"
    else
        owner_uid="$(id -u sandlot 2>/dev/null || echo 65536)"
    fi
    # install(1) resolves -g through the GROUP DATABASE: a bare numeric GID
    # with no group entry is rejected ("invalid group"). The sandlot group's
    # GID stays 985 (shared-storage contract) while the account's UID is the
    # reserved 65536, so -g "$owner_uid" broke every stream-cert install after
    #. The key is mode 0600 (owner-only), so the group is irrelevant to
    # access: use the account's primary group.
    owner_gid="$(id -g sandlot 2>/dev/null || echo 0)"
    if ! $kc -n sandswap get secret "$secret" >/dev/null 2>&1; then
        echo "  ✗ Secret $secret not found (the stream client pair for node '$node')"
        echo "    available: $($kc -n sandswap get secrets -o name 2>/dev/null | grep -o 'sandlot-certs-[^ ]*' | tr '\n' ' ')"
        echo "    Fix: deploy the PKI first (bash deploy/k8s/gen-k8s-certs.sh | kubectl apply -f -),"
        echo "         then re-run: bash deploy/k8s/k8s-host-setup.sh --stream-certs-only"
        echo "         (a node whose k8s name differs from its hostname needs --node <name>)"
        return 1
    fi
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/sandswap-stream-certs.XXXXXX")"
    # shellcheck disable=SC2064  # $tmp is expanded NOW: the trap must not depend on it still being set
    trap "rm -rf '$tmp'" RETURN
    for k in client.crt client.key ca.crt; do
        # go-template, not jsonpath: these Secret keys contain dots, and
        # jsonpath reads `{.data.client.crt}` as three nested fields (empty),
        # so every materialization failed with "missing key". `index` addresses
        # the literal key.
        if ! $kc -n sandswap get secret "$secret" -o "go-template={{index .data \"$k\"}}" 2>/dev/null | base64 -d > "$tmp/$k" 2>/dev/null || [[ ! -s "$tmp/$k" ]]; then
            echo "  ✗ Secret $secret is missing key '$k' (or it is empty) — refusing to install a partial cert set"
            return 1
        fi
    done
    install -d -m 0755 "$STREAM_CERTS_DIR"
    # install(1), not cp+chmod: restart-safe over a leftover 0600 key (cp cannot
    # truncate its own write-less file) and it sets owner+mode atomically.
    install -m 0644 -o root -g root "$tmp/ca.crt" "$STREAM_CERTS_DIR/ca.crt"
    install -m 0644 -o root -g root "$tmp/client.crt" "$STREAM_CERTS_DIR/client.crt"
    install -m 0600 -o "$owner_uid" -g "$owner_gid" "$tmp/client.key" "$STREAM_CERTS_DIR/client.key"
    # Verify what LANDED: the key must be owner-only, and its CN must be THIS
    # node (a wrong-node pair is refused at the handshake — named here, where
    # the fix is one command away).
    mode="$(stat -c '%a' "$STREAM_CERTS_DIR/client.key")"
    uid="$(stat -c '%u' "$STREAM_CERTS_DIR/client.key")"
    if [[ "$mode" != "600" || "$uid" != "$owner_uid" ]]; then
        echo "  ✗ $STREAM_CERTS_DIR/client.key landed mode=$mode uid=$uid (want 600 uid=$owner_uid)"
        return 1
    fi
    if command -v openssl >/dev/null 2>&1; then
        cn="$(openssl x509 -in "$STREAM_CERTS_DIR/client.crt" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
        if [[ "$cn" != "$node" ]]; then
            echo "  ✗ $STREAM_CERTS_DIR/client.crt carries CN='$cn' but this node's id is '$node' —"
            echo "    the gateway binds CN == the sandlot's declared node_id and refuses a mismatch by name."
            echo "    Fix: bash deploy/k8s/k8s-host-setup.sh --stream-certs-only --node <this node's name>"
            return 1
        fi
    fi
    echo "  ✓ stream client cert materialized: $STREAM_CERTS_DIR/{client.crt,client.key,ca.crt} (key 600 uid=$owner_uid, CN=$node)"
}

if [[ "$STREAM_CERTS_ONLY" == "true" ]]; then
    echo "═══ Sandswap K8s per-node stream certificates ═══"
    echo "  Node: ${K8S_NODE:-$(hostname)}"
    materialize_stream_certs "${K8S_NODE:-$(hostname)}"
    exit $?
fi

# verify_stream_certs <node-name> — read-only check of what is installed
# (mode/owner/CN). --verify must never mutate the host, so this is
# what the verify pass runs; materialize_stream_certs is the writing path.
verify_stream_certs() {
    local node="$1" owner_uid mode uid cn
    owner_uid="${STREAM_CERT_OWNER:-$(id -u sandlot 2>/dev/null || echo 65536)}"
    local k
    for k in client.crt client.key ca.crt; do
        if [[ ! -s "$STREAM_CERTS_DIR/$k" ]]; then
            echo "  ✗ $STREAM_CERTS_DIR/$k missing — sandlot pods cannot start without this node's stream certificate"
            echo "    Fix: bash deploy/k8s/k8s-host-setup.sh --stream-certs-only"
            return 1
        fi
    done
    mode="$(stat -c '%a' "$STREAM_CERTS_DIR/client.key")"
    uid="$(stat -c '%u' "$STREAM_CERTS_DIR/client.key")"
    if [[ "$mode" != "600" || "$uid" != "$owner_uid" ]]; then
        echo "  ✗ $STREAM_CERTS_DIR/client.key is mode=$mode uid=$uid (want 600 uid=$owner_uid) — the key must be owner-only"
        return 1
    fi
    if command -v openssl >/dev/null 2>&1; then
        cn="$(openssl x509 -in "$STREAM_CERTS_DIR/client.crt" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
        if [[ "$cn" != "$node" ]]; then
            echo "  ✗ $STREAM_CERTS_DIR/client.crt carries CN='$cn' but this node's id is '$node'"
            echo "    Fix: bash deploy/k8s/k8s-host-setup.sh --stream-certs-only --node '$node'"
            return 1
        fi
    fi
    echo "  ✓ stream client cert present: key 600 uid=$owner_uid, CN=$node"
}

echo "═══ Sandswap K8s Host Setup ═══"
echo "  Host:   $(uname -n)"
echo "  Kernel: $(uname -r)"
echo ""

# ── Step 1: bpf LSM ────────────────────────────────────────────────
echo "[1/6] bpf LSM (required for vsockguard enforcement)"

if grep -qE '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
    echo "  ✓ bpf LSM already active: $(cat /sys/kernel/security/lsm)"
else
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        echo "  ✗ bpf LSM NOT active — vsockguard will be a silent no-op!"
        echo "    Fix: sudo bash security/setup-bpf-lsm.sh && sudo reboot"
        exit 1
    fi

    echo "  bpf LSM not active — activating..."
    if [[ ! -x "$ROOT/security/setup-bpf-lsm.sh" ]]; then
        echo "  ✗ security/setup-bpf-lsm.sh not found" >&2
        exit 1
    fi
    bash "$ROOT/security/setup-bpf-lsm.sh"
    echo ""
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║  REBOOT REQUIRED to activate the bpf LSM.            ║"
    echo "  ║  After reboot, re-run this script to continue setup.  ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    exit 0
fi

# ── Step 2: Dedicated sandlot service UID ──────────────────────────
echo "[2/6] Dedicated sandlot service UID (anti-sniff invariant #3)"

if id sandlot &>/dev/null; then
    SANDLOT_UID=$(id -u sandlot)
    SANDLOT_GID=$(id -g sandlot)
    # The BOXOUT shape's pod identity IS this account: its manifests +
    # vsockguard pin the RESERVED sandbox uid (65536). A host account at a
    # different uid is NOT that identity — the per-node stream key would
    # land owned by a uid the pod does not run as, and the uid the
    # manifests do pin could be any ordinary account. Refuse by name with
    # the one-line fix.
    #
    # The embedded shape runs its pods as root and reaches the key through
    # the root certs-copy init container regardless of owner, so a
    # pre-existing account at another uid — e.g. the bare-metal fleet
    # identity (985) on a combined development host — is accepted with a
    # note; the reserved-uid scheme only binds the boxout fence.
    if [[ "$MODE" == "boxout" && "$SANDLOT_UID" != "65536" ]]; then
        echo "  ✗ 'sandlot' exists with UID=$SANDLOT_UID — the boxout manifests and vsockguard pin the reserved sandbox uid 65536"
        echo "    A different uid breaks the reserved-identity scheme (the pod cannot read a key owned by another uid, and"
        echo "    whoever holds 65536 instead is not the fenced identity the deploy asserts)."
        echo "    Fix: usermod -u 65536 sandlot && bash deploy/k8s/k8s-host-setup.sh --stream-certs-only"
        exit 1
    fi
    if [[ "$MODE" == "embedded" && "$SANDLOT_UID" != "65536" ]]; then
        echo "  ✓ sandlot account exists (UID=$SANDLOT_UID) — embedded pods run as root; a non-reserved uid does not break the embedded fence"
    fi
    SHELL=$(getent passwd sandlot | cut -d: -f7)
    if [[ "$SHELL" == */nologin || "$SHELL" == */false ]]; then
        echo "  ✓ sandlot account exists (UID=$SANDLOT_UID, GID=$SANDLOT_GID, shell=$SHELL)"
    else
        if [[ "$VERIFY_ONLY" == "true" ]]; then
            echo "  ✗ sandlot shell=$SHELL is a login shell — should be /sbin/nologin"
            exit 1
        fi
        echo "  Fixing sandlot shell to /sbin/nologin..."
        usermod -s /sbin/nologin sandlot
        echo "  ✓ sandlot shell fixed"
    fi
else
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        echo "  ✗ no 'sandlot' service account"
        echo "    Fix: groupadd -r sandlot; useradd -r -u 65536 -s /sbin/nologin -g sandlot sandlot"
        exit 1
    fi
    # Node exclusivity: the reserved uid must not already belong to another
    # account — whoever holds it would pass the vsockguard/boxout uid gate for
    # free. Refuse by name rather than let useradd fail cryptically.
    _holder="$(getent passwd 65536 | cut -d: -f1)"
    if [[ -n "$_holder" && "$_holder" != "sandlot" ]]; then
        echo "  ✗ UID 65536 (the reserved sandbox identity) is already taken on this host by '$_holder'"
        echo "    Fix: re-map or remove that account first — it would otherwise be inside the warden/boxout fence."
        exit 1
    fi
    groupadd -r sandlot
    # -u 65536: THE RESERVED SANDBOX IDENTITY (uid AND gid) the pod manifests
    # and vsockguard pin. useradd warns that 65536 is outside its ordinary
    # ranges — that is the point (no human, package or chart default claims
    # it), and letting useradd pick (often 999) would silently mismatch the
    # manifests. The group stays `sandlot` (its gid is irrelevant to the pod:
    # k8s runs on numeric ids; the key install below uses the uid for both).
    useradd -r -u 65536 -s /sbin/nologin -g sandlot sandlot
    SANDLOT_UID=$(id -u sandlot)
    SANDLOT_GID=$(id -g sandlot)
    echo "  ✓ sandlot account created (UID=$SANDLOT_UID, GID=$SANDLOT_GID)"
fi

# The sandvmm identity: the udev rule grants /dev/vhost-vsock to
# OWNER=sandvmm, which resolves by NAME, and deploy-lib injects the account's
# RESOLVED uid/gid into the manifests. The number is host-resolved, not
# pinned: the contract default is 987, and an occupied slot must never abort
# host setup. Adopt an existing account; otherwise let useradd pick a free
# system uid (the same adopt/auto-pick contract as common/sh/runtime.sh). The
# pod never runs as this uid — it exists purely so the device ownership is a
# real (never-loggable) identity.
if ! id sandvmm >/dev/null 2>&1; then
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        echo "  ✗ no 'sandvmm' service account (udev OWNER= won't resolve)"
        echo "    Fix: re-run without --verify (host setup adopts an existing account or auto-picks a free uid)"
        exit 1
    fi
    groupadd -r sandvmm 2>/dev/null || true
    useradd -r -s /sbin/nologin -g sandvmm sandvmm
    echo "  ✓ sandvmm account created (UID=$(id -u sandvmm), host-resolved; contract default 987)"
else
    echo "  ✓ sandvmm account exists (UID=$(id -u sandvmm), host-resolved)"
fi

# ── Step 2b: this node's stream client certificate ─────────────────
# Runs AFTER the sandlot account exists (the key's default owner is its uid).
# A first run on a fresh host legitimately precedes the deploy (no Secret
# yet): that is a WARNING with the exact re-run command, not a failed setup —
# but --verify and a node whose material is expected treat it as a finding,
# and the DaemonSet's certs-copy init container refuses to start without it.
echo "[2b/6] per-node stream client certificate (gateway binds CN == node_id)"
if [[ "$VERIFY_ONLY" == "true" ]]; then
    # verify-only never writes: check what is installed instead.
    verify_stream_certs "${K8S_NODE:-$(hostname)}" || exit 1
elif materialize_stream_certs "${K8S_NODE:-$(hostname)}"; then
    :
else
    echo "  ⚠ the node's stream certificate is NOT in place yet — sandlot pods cannot"
    echo "    start without it. After the PKI is deployed, re-run:"
    echo "      sudo bash deploy/k8s/k8s-host-setup.sh --stream-certs-only"
fi

# ── Step 3: udev rules for device lockdown ─────────────────────────
echo "[3/6] udev rules for device lockdown (anti-sniff invariant #4)"

UDEV_RULE="/etc/udev/rules.d/99-sandswap-vsock.rules"
if [[ -f "$UDEV_RULE" ]]; then
    echo "  ✓ udev rule already installed"
else
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        echo "  ✗ udev rule not installed"
        echo "    Fix: install deploy/udev/99-sandswap-vsock.rules to /etc/udev/rules.d/"
        exit 1
    fi
    install -m 644 "$ROOT/deploy/udev/99-sandswap-vsock.rules" "$UDEV_RULE"
    udevadm control --reload-rules
    echo "  ✓ udev rule installed + reloaded"
fi

# Ownership/MODE rules only bind to a device that EXISTS. On a host that has
# not loaded vhost_vsock since boot, /dev/vhost-vsock is either absent or a
# leftover devtmpfs node carrying the distro default
# (/usr/lib/tmpfiles.d/static-nodes-permissions.conf: root:kvm 0660) — the
# rules then have nothing to act on and the sandlot pod, which checks the
# OWNER before ever opening the device, crash-loops on "want the sandvmm
# identity 987". Load the module (persistently — baremetal's setup-host.sh
# does the same) and restore ownership explicitly, same explicit-restore
# doctrine as tc_ensure_dev_nodes: never gamble on udev timing.
if [[ "$VERIFY_ONLY" == "false" ]]; then
    modprobe vhost_vsock 2>/dev/null || true
    if ! grep -qx vhost_vsock /etc/modules-load.d/sandswap.conf 2>/dev/null; then
        echo "vhost_vsock" >> /etc/modules-load.d/sandswap.conf
    fi
    udevadm trigger --action=add --sysname-match='vhost-vsock' 2>/dev/null || true
    if [[ -e /dev/vhost-vsock ]]; then
        chown sandvmm /dev/vhost-vsock 2>/dev/null || true
        chmod 0600 /dev/vhost-vsock 2>/dev/null || true
    fi
    if [[ -e /dev/vsock ]]; then
        chown sandlot /dev/vsock 2>/dev/null || true
        chmod 0600 /dev/vsock 2>/dev/null || true
    fi
fi

# Verify device permissions
check_dev() {
    local dev="$1" expected_owner="$2"
    if [[ ! -e "$dev" ]]; then
        echo "  ✗ $dev missing"
        return 1
    fi
    local mode
    mode="$(stat -c '%a' "$dev")"
    if (( 8#$mode & 002 )); then
        echo "  ✗ $dev is world-writable (mode=$mode) — anti-sniff invariant #4 violated"
        return 1
    fi
    local actual_owner
    actual_owner="$(stat -c '%U:%G' "$dev")"
    if [[ "$actual_owner" != "$expected_owner" ]]; then
        # Advisory (callers use || true): a different group name is legitimate on
        # some distros (numeric GID when the group has no passwd entry), but the
        # operator must see it — the vsockguard UID allowlist assumes the device
        # is NOT reachable by arbitrary local users.
        echo "  ⚠ $dev mode=$mode owner=$actual_owner (expected $expected_owner)"
        return 1
    fi
    echo "  ✓ $dev mode=$mode owner=$actual_owner"
}
check_dev /dev/kvm "root:kvm" || true
check_dev /dev/vhost-vsock "sandvmm" || true
check_dev /dev/vsock "sandlot" || true

# ── Step 4: Anti-sniff sysctls ─────────────────────────────────────
echo "[4/6] Anti-sniff sysctls (invariants #1 and #2)"

set_sysctl() {
    local key="$1" value="$2" conf="$3"
    local current
    current="$(cat /proc/sys/$key 2>/dev/null || echo '')"

    # Check current value
    if [[ "$current" == "$value" ]] || [[ -n "$current" && "$current" -ge "$value" ]]; then
        echo "  ✓ $key = $current (≥ $value)"
        return
    fi

    if [[ "$VERIFY_ONLY" == "true" ]]; then
        echo "  ✗ $key = ${current:-unset} (need ≥ $value)"
        echo "    Fix: echo '$key = $value' > $conf; sysctl -w $key=$value"
        return 1
    fi

    # Set it
    echo "$key = $value" > "$conf"
    sysctl -w "$key=$value" >/dev/null 2>&1 || true
    echo "  ✓ $key set to $value (persisted in $conf)"
}

set_sysctl kernel.yama.ptrace_scope 1 /etc/sysctl.d/99-sandswap-ptrace.conf || true
set_sysctl kernel.perf_event_paranoid 4 /etc/sysctl.d/99-sandswap-perf.conf || true

# ── Step 4b: harden the PVC storage root (invariant 8) ─────────────
echo "[4b/6] Hardened volumes storage root (nosuid,nodev)"
LOCAL_PATH_ROOT="${K3S_STORAGE_ROOT:-/var/lib/rancher/k3s/storage}"
mkdir -p "$LOCAL_PATH_ROOT"
LP_OPTS="$(findmnt -n -o OPTIONS "$LOCAL_PATH_ROOT" 2>/dev/null || true)"
if [[ "$LP_OPTS" == *nosuid* && "$LP_OPTS" == *nodev* ]]; then
    echo "  ✓ $LOCAL_PATH_ROOT already nosuid,nodev"
else
    if mount --bind "$LOCAL_PATH_ROOT" "$LOCAL_PATH_ROOT" 2>/dev/null \
       && mount -o remount,bind,nosuid,nodev "$LOCAL_PATH_ROOT" 2>/dev/null; then
        echo "  ✓ $LOCAL_PATH_ROOT hardened (self-bind nosuid,nodev)"
    else
        echo "  ✗ could not harden $LOCAL_PATH_ROOT (invariant 8) — sandlot pods will refuse to start"
        exit 1
    fi
fi

# ── Step 5: vsockguard ─────────────────────────────────────────────
echo "[5/6] vsockguard BPF LSM (anti-impersonation)"

VSOCKGUARD_OBJ="${VSOCKGUARD_OBJ:-$ROOT/output/vsockguard.bpf.o}"
VSOCKGUARD_LOADER="${VSOCKGUARD_LOADER:-$ROOT/output/vsockguardctl}"

# The allowed UID is MODE-specific: embedded pods run as UID 0 (they own the
# vsock transport themselves), boxout pods as the reserved sandbox UID. A pin
# copied from the other mode either fences the sandlot out of its own warden
# or leaves the port reachable by root only — both are wrong.
if [[ "$MODE" == "embedded" ]]; then
    VSOCKGUARD_ALLOWED_UID=0
else
    VSOCKGUARD_ALLOWED_UID="$SANDLOT_UID"
fi

# Check if already attached
if [[ -e /sys/fs/bpf/vsockguard/link ]]; then
    pinned="$(cat /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null | grep -E '^[0-9]+:' | head -1 | sed 's/^[0-9]*:[[:space:]]*//')"
    if [[ -n "$pinned" && "$pinned" == "$VSOCKGUARD_ALLOWED_UID" ]]; then
        echo "  ✓ vsockguard already attached (allowed UID=$pinned, mode=$MODE)"
    else
        echo "  ✗ vsockguard is pinned for UID ${pinned:-unreadable}, but mode=$MODE needs $VSOCKGUARD_ALLOWED_UID"
        echo "    Fix: re-attach for this mode: bash security/vsockguard-attach.sh --uid $VSOCKGUARD_ALLOWED_UID"
        [[ "$VERIFY_ONLY" == "true" ]] && exit 1
        bash "$ROOT/security/vsockguard-detach.sh" >/dev/null 2>&1 || true
    fi
fi
if [[ ! -e /sys/fs/bpf/vsockguard/link ]]; then
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        echo "  ✗ vsockguard not attached"
        echo "    Fix: bash security/vsockguard-attach.sh --uid $VSOCKGUARD_ALLOWED_UID"
        exit 1
    fi

    # Ensure vsockguard is built
    if [[ ! -f "$VSOCKGUARD_OBJ" ]] || [[ ! -x "$VSOCKGUARD_LOADER" ]]; then
        echo "  Building vsockguard..."
        bash "$ROOT/build/build.sh" vsockguard
    fi

    if [[ ! -x "$ROOT/security/vsockguard-attach.sh" ]]; then
        echo "  ✗ security/vsockguard-attach.sh not found" >&2
        exit 1
    fi

    bash "$ROOT/security/vsockguard-attach.sh" --uid "$VSOCKGUARD_ALLOWED_UID"
    echo "  ✓ vsockguard attached (allowed UID=$VSOCKGUARD_ALLOWED_UID, mode=$MODE)"
fi

# ── Step 5b: microVM outbound networking (bridge + NAT) ────────────
# The sandlot pod runs hostNetwork and needs br-sandswap for TAP attachment;
# the bridge and the nftables masquerade are runtime kernel state that does
# NOT survive a node reboot (deploy-lib creates them per deploy, so a plain
# reboot of a running cluster leaves every sandlot pod crash-looping until a
# redeploy). Create them here (idempotent) and persist via the same oneshot
# unit the baremetal prep installs — one implementation, re-created per boot.
echo "[5b/6] microVM networking (bridge + NAT, persistent)"
SETUP_NET="$ROOT/deploy/setup-network.sh"
if [[ -f "$SETUP_NET" ]]; then
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        # --verify is documented as "verify only, no changes": report the
        # persistence state instead of installing/enabling it.
        if systemctl is-enabled --quiet sandswap-network.service 2>/dev/null; then
            echo "  ✓ sandswap-network.service enabled (boot persistence present)"
        else
            echo "  ✗ sandswap-network.service NOT enabled — a reboot will leave every sandlot pod without br-sandswap"
        fi
    else
        bash "$SETUP_NET" >/dev/null 2>&1 || echo "  ⚠ setup-network.sh reported a failure — check microVM egress"
        install -m 0755 "$SETUP_NET" /usr/local/bin/sandswap-setup-network
        # The installed copy resolves its shared runtime from
        # /usr/local/lib/sandswap (its $ROOT is /usr/local, where no repo tree
        # exists at boot). Ship the library beside it: without it the boot-time
        # unit dies with a bare ENOENT and a rebooted node loses br-sandswap.
        install -D -m 0644 "$ROOT/common/sh/runtime.sh" /usr/local/lib/sandswap/runtime.sh
        install -m 0644 "$ROOT/deploy/baremetal/systemd/sandswap-network.service" /etc/systemd/system/sandswap-network.service
        systemctl daemon-reload
        # Surface enable/start failures: swallowing them printed "boot
        # persistence unit enabled" on a host that had silently lost it.
        if systemctl enable sandswap-network.service >/dev/null 2>&1; then
            systemctl start sandswap-network.service 2>/dev/null \
                || echo "  ⚠ sandswap-network.service failed to start — check: systemctl status sandswap-network"
            echo "  ✓ br-sandswap ready; boot persistence unit enabled"
        else
            echo "  ✗ could not ENABLE sandswap-network.service — bridge/NAT will NOT survive a reboot"
        fi
    fi
else
    echo "  ⚠ deploy/setup-network.sh not found — create br-sandswap before deploying"
fi

# ── Step 6: Verify all invariants ──────────────────────────────────
echo "[6/6] Verify all host security invariants"

if [[ -x "$ROOT/security/verify-host-security.sh" ]]; then
    if bash "$ROOT/security/verify-host-security.sh"; then
        echo "  ✓ All vsock transport invariants hold"
    else
        echo "  ✗ Some invariants FAILED — vsock sniffing/impersonation surface may be open"
        exit 1
    fi
else
    echo "  ⚠ verify-host-security.sh not found, skipping full verification"
fi

# ── Summary ────────────────────────────────────────────────────────
echo ""
if ip link show br-sandswap &>/dev/null; then
    echo "  ✓ br-sandswap present (microVM egress) — persist unit: sandswap-network.service"
else
    echo "  ✗ br-sandswap MISSING — sandlot VMs will have no outbound networking"
    exit 1
fi
echo "═══ Host Setup Complete ═══"
echo "  sandlot UID:    $SANDLOT_UID"
echo "  sandlot GID:    $SANDLOT_GID"
echo "  bpf LSM:        active"
echo "  vsockguard:     attached (allowed UID=$VSOCKGUARD_ALLOWED_UID, mode=$MODE)"
echo "  udev rules:     installed"
echo "  sysctls:        set"
if [[ -s "$STREAM_CERTS_DIR/client.crt" ]]; then
    echo "  stream cert:    installed ($STREAM_CERTS_DIR, node ${K8S_NODE:-$(hostname)})"
else
    echo "  stream cert:    NOT INSTALLED — re-run: bash deploy/k8s/k8s-host-setup.sh --stream-certs-only"
fi
echo ""
echo "  Use these values in K8s manifests:"
echo "    sandlot securityContext.runAsUser: $SANDLOT_UID"
echo "    sandlot securityContext.runAsGroup: $SANDLOT_GID"

# Detect kvm group GID for supplementalGroups
KVM_GID=$(getent group kvm | cut -d: -f3 2>/dev/null || echo "")
if [[ -n "$KVM_GID" ]]; then
    echo "    sandlot securityContext.supplementalGroups: [$KVM_GID]  # kvm group for /dev/kvm"
fi
