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
# deploy-single-node.sh — One-click single-node Sandswap deployment
# Runs gateway (single-node, MemoryStore) + sandlot (embedded) on one machine
# Usage: sudo bash deploy-single-node.sh [--skip-build] [--no-tls] [--keep]
#   --no-tls makes only the HTTP listeners plaintext; the gateway<->sandlot
#   stream always carries per-node mTLS certificates.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/deploy-lib.sh"

# ──── Parse Args ────

SKIP_BUILD=0
NO_TLS=0
KEEP=0
POOL="${POOL:-medium:3}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1; shift ;;
        --no-tls)     NO_TLS=1; shift ;;
        # Accepted for CLI symmetry only: single-node is a leave-running deploy
        # and never deletes data, so there is nothing for --keep to do.
        --keep)       # shellcheck disable=SC2034
                      KEEP=1; shift ;;
        --pool)       POOL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--skip-build] [--no-tls] [--keep] [--pool SPEC]"
            echo "  --skip-build   Skip artifact build (use existing output/)"
            echo "  --no-tls       Plaintext HTTP listeners (development only); the node stream always uses mTLS certificates"
            echo "  --keep         Keep existing data on failure"
            echo "  --pool SPEC    Pool spec (default: medium:3)"
            exit 0
            ;;
        *) err "Unknown argument: $1" ;;
    esac
done

[[ $EUID -ne 0 ]] && err "This script must be run as root"

if [[ $NO_TLS -eq 1 ]]; then
    export NO_TLS=1
fi

# ──── [0/8] Stop existing services (avoid Text file busy on binary replace) ────

log "[0/8] Preclean + preflight..."
# One shared implementation (deploy-lib.sh): stops every Sandswap unit (incl.
# leftover gateway-execN / sandlot-instance@N / dns from cluster sims — the old
# inline copy here never stopped sandns), kills the process tree and
# non-sandswap port holders, strips /etc/hosts pins, and wipes /run/sandswap.
# The wipe matters: this script reuses the default (non-instance) sandlot state
# path, so a stale persisted gateway-state.json from an interrupted run would
# resume the OLD state machine instead of starting fresh.
# shellcheck disable=SC2034
BM_MODE_DESC="baremetal single-node (systemd gateway+sandlot, MemoryStore)"
# shellcheck disable=SC2034
BM_WIPE_RUN=1
bm_preclean
bm_preflight

# ──── [1/8] Build Artifacts ────

if [[ $SKIP_BUILD -eq 0 ]]; then
    log "[1/8] Building artifacts..."
    bm_build_artifacts
else
    log "[1/8] Skipping build (--skip-build)"
    # Verify artifacts exist
    for f in gateway sandlot sandvmm template-tool vmlinux.bin initramfs.cpio.gz; do
        [[ -f "$REPO_ROOT/output/$f" ]] || err "Missing artifact: output/$f. Run without --skip-build."
    done
    # The reused kernel must be the PINNED build: the dev-only download
    # variant (v6.2) lacks IPv6 and the warden's TIME_WAIT sweep, and ships
    # the expanded attack surface this deployment's whole threat model is
    # built against. A version mismatch refuses the deploy.
    ss_verify_kernel_artifact "$REPO_ROOT/output/vmlinux.bin" "$REPO_ROOT/kernel/build.sh" \
        || err "Refusing --skip-build with a non-pinned kernel under output/ — run bash build/build.sh kernel"
fi

OUTPUT="$REPO_ROOT/output"
DEPLOY_DIR="$REPO_ROOT/deploy/baremetal"

# ──── [2/8] Host Preparation ────

log "[2/8] Preparing host..."
bash "$SCRIPT_DIR/setup-host.sh" --role all

# ──── [3/8] TLS Certificates ────

# Stream certificates are minted in EVERY shape: the gateway refuses a
# certificate-less node stream (the listener requires a client cert and binds
# its CN to the hello's node_id). --no-tls therefore only makes the HTTP
# listeners plaintext; HTTP_TLS_DIR is the directory that flag controls.
CERT_DIR="${SANDSWAP_ETC}/certs"
HTTP_TLS_DIR=""
log "[3/8] Generating TLS certificates (stream mTLS is mandatory)..."
# SANDLOT_NODE_ID must equal the node id the sandlot below declares. The
# generated config leaves node_id empty, so the sandlot resolves it from
# its own hostname (sandlot/cmd/main.go) — the same default this mint
# uses, and the gateway binds node_id == the client cert's CN exactly.
# This shape runs ONE merged sandlot (roles exec,prov), and the certificate
# is the role grant: the primary pair must carry both role URIs.
SANDLOT_NODE_ID="$(hostname)" \
    bash "$SCRIPT_DIR/gen-baremetal-certs.sh" "$OUTPUT/baremetal-certs" \
        --client-roles exec,prov
mkdir -p "$CERT_DIR"
cp "$OUTPUT/baremetal-certs"/* "$CERT_DIR/"
# Dedicated-identity model: scope each private key to the identity that
# loads it (sandlot.key → sandlot, the rest → sandserv).
ss_own_tls_keys "$CERT_DIR"
# The pair's CN must be the node id the config below resolves (its
# node_id is empty → the sandlot's own hostname): the gateway binds
# node_id == the client cert's CN and refuses a mismatch by name.
sandswap_verify_client_cert_cn "$CERT_DIR/sandlot.crt" "$(hostname)" \
    || err "stream client cert does not carry the node id the sandlot will declare ($(hostname))"
if [[ $NO_TLS -eq 0 ]]; then
    HTTP_TLS_DIR="$CERT_DIR"
else
    log "  HTTP listeners plaintext (--no-tls); stream mTLS stays on"
fi

# ──── [4/8] Install Gateway ────

log "[4/8] Installing gateway..."
sandswap_install_binary "$OUTPUT/gateway" "$SANDSWAP_BIN/sandswap-gateway"

# Deploy rootfs template (gateway needs it for flat-templates)
# Layout flat-templates/rootfs/v1/ registers template ref "rootfs:v1" —
# the same convention used by e2e tests and examples.
if [[ -d "$OUTPUT/rootfs-template" ]]; then
    # Wipe any stale template dir first: a prior deploy/e2e may have left
    # symlinks (bin/sbin/lib/...) that cp -a cannot overwrite with directories.
    rm -rf "$SANDSWAP_VAR/flat-templates/rootfs/v1"
    mkdir -p "$SANDSWAP_VAR/flat-templates/rootfs/v1"
    cp -a "$OUTPUT/rootfs-template/." "$SANDSWAP_VAR/flat-templates/rootfs/v1/"
    # Public template readable by the seed identity (0000-mode oddballs in
    # distro trees would break seeding — see e2e/single-node-multi-agent.sh note).
    # Shared-group shape via the canonical tool (see e2e/single-node-multi-agent.sh).
    TEMPLATE_TOOL="$REPO_ROOT/output/template-tool"
    [[ -x "$TEMPLATE_TOOL" ]] || { err "output/template-tool missing — run: bash build/build.sh go"; }
    chgrp -R "$SS_SHARED_GROUP" "$SANDSWAP_VAR/flat-templates"
    "$TEMPLATE_TOOL" normalize "$SANDSWAP_VAR/flat-templates"
    log "Rootfs template deployed (rootfs:v1)"
fi

# Generate gateway config (HTTP listener TLS only when --no-tls is absent; the
# stream block always carries the minted mTLS paths).
SANDSWAP_STREAM_TLS_DIR="$CERT_DIR" \
sandswap_generate_gateway_config \
    "$SANDSWAP_ETC/gateway.yaml" \
    "" \
    "$SANDSWAP_VAR/volumes" \
    "0.0.0.0:3000" \
    "127.0.0.1:3100" \
    "0.0.0.0:9998" \
    "$HTTP_TLS_DIR"

# Install systemd unit
sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-gateway.service"
sandswap_enable_service sandswap-gateway

# ──── [5/8] Wait for Gateway ────

log "[5/8] Waiting for gateway to start..."
sandswap_wait_for_health "localhost:3000" 30

# ──── [6/8] Install Sandlot ────

log "[6/8] Installing sandlot..."
sandswap_install_binary "$OUTPUT/sandlot" "$SANDSWAP_BIN/sandswap-sandlot"
sandswap_install_binary "$OUTPUT/sandvmm" "$SANDSWAP_BIN/sandswap-sandvmm"

# Guest TCB into the root-only directory ($SANDSWAP_GUEST_DIR, root:root
# 0755) with a SHA256SUMS pin — never into the service-traversable state root.
sandswap_install_guest_artifacts "$OUTPUT"

# vsockguard
if [[ -f "$OUTPUT/vsockguard.bpf.o" ]]; then
    cp "$OUTPUT/vsockguard.bpf.o" "$SANDSWAP_VAR/"
fi
if [[ -f "$OUTPUT/vsockguardctl" ]]; then
    sandswap_install_binary "$OUTPUT/vsockguardctl" "$SANDSWAP_BIN/vsockguardctl"
fi

# Generate sandlot config. Merged exec,prov roles: single-node (MemoryStore
# gateway) — the one sandlot is both the exec node and the storage plane;
# without "prov" every sandfs/template op would 503. The template store sits
# beside the volumes tree (same filesystem, shared-group layout from
# setup-host); the flat scan dir is the rootfs-template staging above.
# THE prov-side contract for this merged shape, in ONE call
# (sandswap_apply_prov_plane: seed mint, template store, volumes root, state
# dir; SS_PROV_USER=sandlot is the merged default) + the stream's prov.key
# copy. The ownership matrix lives in that function's comment.
SS_PROV_USER=sandlot sandswap_write_prov_user_env
sandswap_prepare_provision_host "$SANDSWAP_VAR/templates" "$CERT_DIR"

SANDSWAP_SANDLOT_ROLES=exec,prov \
SANDSWAP_PROVISION_TEMPLATES_DIR="$SANDSWAP_VAR/templates" \
SANDSWAP_FLAT_TEMPLATES_DIR="$SANDSWAP_VAR/flat-templates" \
sandswap_generate_sandlot_config \
    "$SANDSWAP_ETC/sandlot.yaml" \
    "localhost:9998" \
    "" \
    "$POOL" \
    "10.188.0.0/16" \
    "10.188.0.1" \
    "$SANDSWAP_VAR/volumes" \
    "$CERT_DIR"
# The merged config may carry an OCI registry credential — scope it to the
# reading identity (the merged service runs as sandlot).
ss_protect_config "$SANDSWAP_ETC/sandlot.yaml" sandlot

# Install systemd unit
sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-sandlot.service"
# This shape is MERGED (exec,prov): grant the volume-name seed's group with a
# drop-in. The base unit is exec-only so an exec-only node can never read the
# seed; only a prov-bearing shape widens it.
mkdir -p /etc/systemd/system/sandswap-sandlot.service.d
cat > /etc/systemd/system/sandswap-sandlot.service.d/sandprov.conf <<'EOF'
[Service]
SupplementaryGroups=kvm sandprov sandtmpl
EOF
systemctl daemon-reload
sandswap_enable_service sandswap-sandlot

# ──── [7/8] Wait for Pool ────

log "[7/8] Waiting for pool to be ready..."
# Parse pool count from spec (e.g., "medium:3" → 3)
pool_target="${POOL##*:}"
sandswap_wait_for_pool "localhost:3100" "$pool_target" 120

# ──── [8/8] Verify ────

log "[8/8] Verification..."

log "Service status:"
systemctl status sandswap-gateway --no-pager -l 2>/dev/null || true
systemctl status sandswap-sandlot --no-pager -l 2>/dev/null || true

log "Health check:"
if [[ $NO_TLS -eq 1 ]]; then
    curl -s http://localhost:3000/health || true
    echo
    curl -s http://localhost:3100/stats || true
else
    curl -sk https://localhost:3000/health || true
    echo
    curl -sk https://localhost:3100/stats || true
fi
echo

# ──── Deployment gate: prove the stack ALIVE, not just installed ────
# The status/health output above is display-only; without a gate a gateway
# that died at startup still yields "deployment complete!" and exit 0 (the
# same false-pass class the multi-gw sim's DNS gate closed). Gate on the real
# chain: units active + pool reaching CLEAN >= N. CLEAN VMs can only exist if
# gateway ↔ sandlot ↔ sandvmm ↔ KVM all work end to end.
GW_DEAD=0
for unit in sandswap-gateway sandswap-sandlot; do
    if ! systemctl is-active --quiet "$unit"; then
        echo "[error] unit $unit is not active:" >&2
        journalctl -u "$unit" --no-pager 2>/dev/null | tail -20 >&2
        GW_DEAD=1
    fi
done
[[ $GW_DEAD -eq 0 ]] || err "gateway/sandlot unit not active — deployment incomplete (journal above)"
sandswap_wait_for_pool "localhost:3100" "$((${POOL##*:}))" 120

# Publish the client contract ONLY after the health gate: sandctl points at a
# deployment that is proven alive, and a failed deploy never advertises one.
if [[ $NO_TLS -eq 1 ]]; then
    sandswap_write_sandctl_env "http://127.0.0.1:3000" "http://127.0.0.1:3100" plain
else
    sandswap_write_sandctl_env "https://127.0.0.1:3000" "https://127.0.0.1:3100" tls "$CERT_DIR/ca.crt"
fi

log "============================================"
log "  Sandswap single-node deployment complete!"
log "============================================"
log ""
log "  Gateway:  ${SANDSWAP_ETC}/gateway.yaml"
log "  Sandlot:  ${SANDSWAP_ETC}/sandlot.yaml"
log "  Pool:     $POOL"
log "  TLS:      HTTP $([ $NO_TLS -eq 1 ] && echo 'plaintext' || echo 'enabled'); stream mTLS always"
log ""
log "  Commands:"
log "    systemctl status sandswap-gateway"
log "    systemctl status sandswap-sandlot"
log "    journalctl -u sandswap-gateway -f"
log "    journalctl -u sandswap-sandlot -f"
log ""
log "  Hot-reload pool:"
log "    sed -i 's/pool: \"medium:3\"/pool: \"medium:5\"/' ${SANDSWAP_ETC}/sandlot.yaml"
log ""
log "  Graceful restart (verifies re-adopt):"
log "    systemctl restart sandswap-sandlot"
