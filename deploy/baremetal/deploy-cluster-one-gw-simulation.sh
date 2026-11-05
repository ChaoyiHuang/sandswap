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
# deploy-cluster-one-gw-simulation.sh — Small cluster simulation on a single host
# Single-gateway etcd shape, simulated on one machine: a local etcd + 1 exec
# gateway (3000/9998) + 1 human gateway (3100) + N sandlot instances
# (multi-instance via instance.id). Mirrors what deploy-cluster-one-gw.sh
# installs across hosts, with a plain-http local etcd instead of the mTLS one.
#
# This is the REHEARSAL of the multi-host shape (N instances standing in for
# the N node hosts). The real single-machine etcd topology — that shape
# itself, one machine, mTLS etcd, exactly one exec + one prov instance — is
# deployed by deploy-one-machine-etcd.sh.
# Usage: sudo bash deploy-cluster-one-gw-simulation.sh [--no-tls] [--skip-build] [--sandlots N]
#   --no-tls makes only the HTTP listeners plaintext; every simulated node
#   still gets its own stream client certificate (CN = its node id).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/deploy-lib.sh"

# This is a LEAVE-RUNNING deploy (no teardown trap by design — the services are
# the deliverable); INT/TERM must still stop the run instead of resuming it
# mid-phase after bash handles the signal.
trap 'exit 130' INT TERM

NO_TLS=0
SKIP_BUILD=0
SANSLOT_COUNT=2
# Per-instance pool spec name (see common.sh sandswap_generate_sandlot_config
# for the spec table). Default small — N instances × 1 GB (medium) of guest RAM
# does not fit a small development host; override for big hosts.
SANDSWAP_POOL_SPEC="${SANDSWAP_POOL_SPEC:-small}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-tls)     NO_TLS=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --sandlots)   SANSLOT_COUNT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--no-tls] [--skip-build] [--sandlots N]"
            echo "  --no-tls       Plaintext HTTP listeners (dev only); the node stream always uses mTLS certificates"
            exit 0
            ;;
        *) err "Unknown argument: $1" ;;
    esac
done

[[ $EUID -ne 0 ]] && err "This script must be run as root"

if [[ $NO_TLS -eq 1 ]]; then
    export NO_TLS=1
fi

log "[0/6] Preclean + preflight..."
# Shared implementation (deploy-lib.sh). This script reuses instance ids
# sl1..slN across runs; BM_WIPE_RUN=1 wipes /run/sandswap INCLUDING the
# per-instance state dirs — the old inline copy here never did, so an
# interrupted run left a stale LastGatewayIP/tolerating phase that wedged the
# next run's reconnect ("preferred gateway X not in DNS").
# shellcheck disable=SC2034
BM_MODE_DESC="baremetal cluster simulation (etcd + exec GW + human GW + N sandlot instances)"
# shellcheck disable=SC2034
BM_WIPE_RUN=1
bm_preclean
bm_preflight
# Fresh etcd per run (identity state must not leak across simulations);
# bm_preclean already replayed the ledger and killed any surviving instance.
rm -rf /tmp/sandswap-onegw-etcd-data

# ──── [1/6] Build ────
if [[ $SKIP_BUILD -eq 0 ]]; then
    log "[1/6] Building artifacts..."
    bm_build_artifacts
else
    log "[1/6] Skipping build"
    for f in gateway sandlot sandvmm template-tool vmlinux.bin initramfs.cpio.gz; do
        [[ -f "$REPO_ROOT/output/$f" ]] || err "Missing artifact: output/$f"
    done
fi

OUTPUT="$REPO_ROOT/output"
DEPLOY_DIR="$REPO_ROOT/deploy/baremetal"

# ──── [2/6] Host prep ────
log "[2/6] Preparing host..."
# Each exec instance below gets its OWN subnet (10.188.${i}.0/24) because every
# instance carries a private guest-IP allocator — two instances on one subnet
# would hand the same address to two microVMs. The bridge therefore has to own
# every instance's gateway address, or the guests' default routes are dead.
SIM_EXTRA_ADDRS=""
for i in $(seq 1 "$SANSLOT_COUNT"); do
    SIM_EXTRA_ADDRS+="10.188.${i}.1/24 "
done
# Dedicated-prov shape: the host-prep ownership (volumes root, template
# stores) must follow the sandprov writer — see sandswap_apply_prov_plane.
SS_PROV_USER=sandprov bash "$SCRIPT_DIR/setup-host.sh" --role all --extra-addrs "$SIM_EXTRA_ADDRS"
# Persist the shape for the units' ExecStartPost (see sandswap_write_prov_user_env):
# this deployment runs a DEDICATED prov instance.
SS_PROV_USER=sandprov sandswap_write_prov_user_env


# ──── [3/6] etcd + gateways (exec + human) ────
log "[3/6] Installing etcd + gateways..."
sandswap_install_binary "$OUTPUT/gateway" "$SANDSWAP_BIN/sandswap-gateway"
rm -rf "$SANDSWAP_VAR/flat-templates/rootfs/v1"   # merge cp cannot replace a stale bin/ symlink
mkdir -p "$SANDSWAP_VAR/flat-templates/rootfs/v1"
cp -a "$OUTPUT/rootfs-template/." "$SANDSWAP_VAR/flat-templates/rootfs/v1/"
chgrp -R "$SS_SHARED_GROUP" "$SANDSWAP_VAR/flat-templates" 2>/dev/null || true
[[ -x "$OUTPUT/template-tool" ]] && "$OUTPUT/template-tool" normalize "$SANDSWAP_VAR/flat-templates" >/dev/null

# Certificates are minted in EVERY shape — the gateway refuses a
# certificate-less node stream, so --no-tls only keeps the HTTP listeners
# plaintext. HTTP_TLS_DIR is what --no-tls controls; CERT_DIR always holds the
# per-node stream pairs.
CERT_DIR="${SANDSWAP_ETC}/certs"
HTTP_TLS_DIR=""
[[ $NO_TLS -eq 0 ]] && HTTP_TLS_DIR="$CERT_DIR"
# STREAM IDENTITIES (see the CN rule in gen-baremetal-certs.sh): each exec
# instance's EFFECTIVE node id is `<node_id>-<instance.id>` — the sandlot
# composes the instance suffix before the hello — and the prov instance is
# its own node. The gateway binds hello.node_id == the client cert's CN by
# exact match, so every node id here gets its own pair: the first instance
# rides the primary pair, the rest + the prov node get --client-cn pairs.
PROV_NODE_ID="sandlot-prov"
PROV_CERT_BASE="sandlot-${PROV_NODE_ID}"
SIM_NODE_IDS=()
for i in $(seq 1 "$SANSLOT_COUNT"); do SIM_NODE_IDS+=("sandlot-${i}-sl${i}"); done
# The certificate is the role grant: the prov node id gets role/prov, every
# exec instance role/exec (the primary pair below is exec by default).
sim_cn_args=(--client-cn "${PROV_NODE_ID}:prov")
for i in $(seq 1 "$((SANSLOT_COUNT - 1))"); do sim_cn_args+=(--client-cn "${SIM_NODE_IDS[$i]}:exec"); done
SANDLOT_NODE_ID="${SIM_NODE_IDS[0]}" \
    bash "$SCRIPT_DIR/gen-baremetal-certs.sh" "$OUTPUT/baremetal-certs" \
    ${sim_cn_args[@]+"${sim_cn_args[@]}"}
mkdir -p "$CERT_DIR"
cp "$OUTPUT/baremetal-certs"/* "$CERT_DIR/"
# Scope each private key to the identity that loads it (same as
# deploy-single-node.sh) — the units run as dedicated users, and the
# generated keys are root-only 0600.
ss_own_tls_keys "$CERT_DIR"

# Local etcd — plain http on localhost, the simulation's stand-in for the
# cluster deploy's co-located mTLS etcd (the etcd: URL carries the scheme, and
# the generated configs carry no etcd TLS fields when HTTP_TLS_DIR is empty,
# i.e. under --no-tls).
# Binary from PATH → output/etcd → download; the pidfile goes to the
# side-effect ledger so the next run's bm_preclean kills it.
ETCD_BIN=$(command -v etcd || echo "$REPO_ROOT/output/etcd/etcd")
if [[ ! -x "$ETCD_BIN" ]]; then
    mkdir -p "$REPO_ROOT/output/etcd"
    log "Downloading etcd..."
    sandswap_fetch_etcd "$REPO_ROOT/output/etcd"
    ETCD_BIN="$REPO_ROOT/output/etcd/etcd"
fi
"$ETCD_BIN" \
    --name sandswap-onegw \
    --listen-client-urls http://127.0.0.1:2379 \
    --advertise-client-urls http://127.0.0.1:2379 \
    --listen-peer-urls http://127.0.0.1:2380 \
    --initial-advertise-peer-urls http://127.0.0.1:2380 \
    --initial-cluster sandswap-onegw=http://127.0.0.1:2380 \
    --initial-cluster-token sandswap-onegw \
    --initial-cluster-state new \
    --data-dir /tmp/sandswap-onegw-etcd-data \
    --log-level warn \
    > /tmp/sandswap-onegw-etcd.log 2>&1 &
ETCD_PID=$!
echo "$ETCD_PID" > /tmp/sandswap-onegw-etcd.pid
se_record EPHEMERAL etcd-proc /tmp/sandswap-onegw-etcd.pid
sleep 2
kill -0 "$ETCD_PID" 2>/dev/null || err "etcd failed to start: $(tail -5 /tmp/sandswap-onegw-etcd.log)"
log "etcd started (pid=$ETCD_PID, http://127.0.0.1:2379)"

# The co-located pair deploy-cluster-one-gw.sh installs across hosts: exec on
# 3000/9998 + human on 3100, both on EtcdStore, via template unit instances.
# HTTP_TLS_DIR (empty under --no-tls) drives the HTTP listeners; the stream
# listener always gets SANDSWAP_STREAM_TLS_DIR (the minted mTLS pairs).
GW_SCHEME="https"
[[ $NO_TLS -eq 1 ]] && GW_SCHEME="http"
SANDSWAP_GATEWAY_ID="gw-exec-1" \
SANDSWAP_GATEWAY_URL="${GW_SCHEME}://localhost:3000" \
SANDSWAP_GATEWAY_STREAM_ADDR="localhost:9998" \
SANDSWAP_IDLE_TIMEOUT_SEC=3600 \
SANDSWAP_STREAM_TLS_DIR="$CERT_DIR" \
    sandswap_generate_gateway_config \
    "$SANDSWAP_ETC/gateway-exec.yaml" "exec" "$SANDSWAP_VAR/volumes" \
    "0.0.0.0:3000" "127.0.0.1:3100" "0.0.0.0:9998" "$HTTP_TLS_DIR" "http://127.0.0.1:2379"
# Human gateway: every sandfs/template op routes to a prov-role sandlot
# instance connected to ITS stream listener (:9996 — 9998 is the co-located
# exec gateway's). This host runs NO gateway-side storage executor: the
# storage plane lives in the prov instance.
SANDSWAP_STREAM_TLS_DIR="$CERT_DIR" \
sandswap_generate_gateway_config \
    "$SANDSWAP_ETC/gateway-human.yaml" "human" "$SANDSWAP_VAR/volumes" \
    "0.0.0.0:3000" "127.0.0.1:3100" "0.0.0.0:9996" "$HTTP_TLS_DIR" "http://127.0.0.1:2379"

sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-gateway@.service"
# A previous run of the OLD single-process shape may have left the combined
# unit enabled — disable it so :3000/:3100/:9998 belong to the new instances.
systemctl disable --now sandswap-gateway 2>/dev/null || true
systemctl reset-failed sandswap-gateway@exec sandswap-gateway@human 2>/dev/null || true
systemctl enable --now sandswap-gateway@exec sandswap-gateway@human
sandswap_wait_for_health "localhost:3000" 30
sandswap_wait_for_health "localhost:3100" 30

# ──── [4/6] Install Sandlot binaries (shared) ────
log "[4/6] Installing sandlot binaries..."
sandswap_install_binary "$OUTPUT/sandlot" "$SANDSWAP_BIN/sandswap-sandlot"
sandswap_install_binary "$OUTPUT/sandvmm" "$SANDSWAP_BIN/sandswap-sandvmm"
cp "$OUTPUT/vmlinux.bin" "$SANDSWAP_VAR/"
chmod 0644 "$SANDSWAP_VAR/vmlinux.bin" 2>/dev/null || true
cp "$OUTPUT/initramfs.cpio.gz" "$SANDSWAP_VAR/"
if [[ -f "$OUTPUT/vsockguard.bpf.o" ]]; then
    cp "$OUTPUT/vsockguard.bpf.o" "$SANDSWAP_VAR/"
fi
# The sandlot units' ExecStartPre attestation shells out to vsockguardctl —
# without the binary every instance crash-loops after a full uninstall.
if [[ -f "$OUTPUT/vsockguardctl" ]]; then
    sandswap_install_binary "$OUTPUT/vsockguardctl" "$SANDSWAP_BIN/vsockguardctl"
fi

# ──── [5/6] Create + start N sandlot instances ────
log "[5/6] Starting $SANSLOT_COUNT sandlot instances..."

# Remove old instance configs
rm -f "$SANDSWAP_ETC"/sandlot-*.yaml

# The instance template is SHIPPED (deploy/baremetal/systemd/) — one source of
# truth with sandswap-sandlot.service for the identity block and capability
# set. An earlier revision inlined the unit here and drifted from the shipped
# one after the sandvmm identity split (missing CAP_SETUID/SETGID/KILL made
# every instance die at startup's checkCapsForVMMSpawn).
sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-sandlot-instance@.service"
# Simulation-only escape hatch for the one-sandlot-per-host rule (N exec
# instances + the prov instance share this host; the SHIPPED unit stays clean).
sed -i 's|-config /etc/sandswap/sandlot-%i.yaml|-config /etc/sandswap/sandlot-%i.yaml -allow-colocated-instances|' /etc/systemd/system/sandswap-sandlot-instance@.service
systemctl daemon-reload

for i in $(seq 1 "$SANSLOT_COUNT"); do
    INSTANCE="sl${i}"
    CID_START=$((3 + (i - 1) * 100))
    CID_END=$((CID_START + 99))

    # The tls block names the pair whose CN is THIS instance's effective node
    # id (sandlot-<i>-sl<i>) — see the mint above.
    SANDSWAP_SANDLOT_CERT_BASE="$([[ "$i" == "1" ]] && echo sandlot || echo "sandlot-${SIM_NODE_IDS[$((i - 1))]}")" \
    sandswap_generate_sandlot_config \
        "$SANDSWAP_ETC/sandlot-${INSTANCE}.yaml" \
        "localhost:9998" \
        "sandlot-${i}" \
        "$SANDSWAP_POOL_SPEC:1" \
        "10.188.${i}.0/24" \
        "10.188.${i}.1" \
        "$SANDSWAP_VAR/volumes" \
        "$CERT_DIR" \
        "$INSTANCE" "$CID_START" "$CID_END"
    sandswap_verify_client_cert_cn "$CERT_DIR/$([[ "$i" == "1" ]] && echo sandlot || echo "sandlot-${SIM_NODE_IDS[$((i - 1))]}").crt" \
        "${SIM_NODE_IDS[$((i - 1))]}" || err "instance ${INSTANCE}: stream pair does not carry its effective node id"

    systemctl reset-failed "sandswap-sandlot-instance@${INSTANCE}" 2>/dev/null || true
    systemctl enable --now "sandswap-sandlot-instance@${INSTANCE}"
    log "Started sandlot instance: $INSTANCE (node=sandlot-${i}, cid=${CID_START}-${CID_END})"
done

# ──── Provision instance (storage plane) ────
# One prov-role sandlot connected to the HUMAN gateway's stream (:9996). It is
# this host's ONLY storage executor: the human gateway holds no template
# manager and mounts no storage, so every sandfs create/delete and every
# template op crosses the stream to this instance. Runs as the sandprov
# identity (shared-storage group, zero caps, no KVM duty) via the SHIPPED
# sandswap-sandlot-prov.service unit.
# Dedicated-prov shape (the prov instance runs as sandprov): say so, or the
# helper defaults SS_PROV_USER=sandlot and the store lands sandlot-owned.
SS_PROV_USER=sandprov sandswap_prepare_provision_host "$SANDSWAP_VAR/templates" "$CERT_DIR" "$PROV_CERT_BASE"
SANDSWAP_SANDLOT_ROLES=prov \
SANDSWAP_NETWORK_BACKEND=none \
SANDSWAP_FLAT_TEMPLATES_DIR="$SANDSWAP_VAR/flat-templates" \
SANDSWAP_PROVISION_TEMPLATES_DIR="$SANDSWAP_VAR/templates" \
SANDSWAP_SANDLOT_CERT_BASE="$PROV_CERT_BASE" \
    sandswap_generate_sandlot_config \
    "$SANDSWAP_ETC/sandlot-prov.yaml" \
    "localhost:9996" \
    "$PROV_NODE_ID" \
    "" \
    "10.188.254.0/24" \
    "10.188.254.1" \
    "$SANDSWAP_VAR/volumes" \
    "$CERT_DIR"
# The prov instance runs as sandprov and must load ITS OWN key copy (prov.key,
# created + chowned by the provision-host preparation above, derived from the
# PROV node's pair). The pattern must match the EXPANDED path the generator
# wrote (${tls_dir} is a shell variable in the generator, so the YAML holds a
# real path — a pattern containing the literal "tls_dir}" never matches,
# silently leaving the sandlot-owned key in place, unreadable by sandprov).
# The assertion makes a future pattern drift loud instead of silent.
sed -i "s|\(/${PROV_CERT_BASE}\.key\)\$|/prov.key|" "$SANDSWAP_ETC/sandlot-prov.yaml"
grep -q 'prov\.key' "$SANDSWAP_ETC/sandlot-prov.yaml" || err "prov.key rewrite did not land in $SANDSWAP_ETC/sandlot-prov.yaml"
sandswap_verify_client_cert_cn "$CERT_DIR/${PROV_CERT_BASE}.crt" "$PROV_NODE_ID" \
    || err "prov stream pair does not carry the prov node id"
# The generator's empty-pool arg falls back to its default (medium:3) —
# strip the line instead: a prov-only instance must carry NO pool (the
# config validator refuses exec machinery on prov-only roles, loudly).
sed -i '/^pool:/d' "$SANDSWAP_ETC/sandlot-prov.yaml"
# The prov config may carry an OCI registry credential — scope it to the
# reading identity (sed -i above recreated it with umask-default perms).
ss_protect_config "$SANDSWAP_ETC/sandlot-prov.yaml" sandprov
sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-sandlot-prov.service"
# Simulation-only: this host runs N exec instances AND the prov instance — the
# one-sandlot-per-host rule needs its escape hatch here. The SHIPPED units
# never carry the flag; only this generated copy does.
sed -i 's|-config /etc/sandswap/sandlot-prov.yaml -roles prov|-config /etc/sandswap/sandlot-prov.yaml -roles prov -allow-colocated-instances|' /etc/systemd/system/sandswap-sandlot-prov.service
systemctl daemon-reload
systemctl reset-failed sandswap-sandlot-prov 2>/dev/null || true
systemctl enable --now sandswap-sandlot-prov
log "Started provision instance: sandlot-prov (roles=prov, human gw :9996)"

# ──── [6/6] Wait for pool + verify ────
log "[6/6] Waiting for pool..."
pool_target=$((SANSLOT_COUNT * 1))
# The exec gateway's /stats is gated by -ops-token-file (empty = DISABLED),
# so a fresh deploy reads the human gateway's etcd-aggregated fleet view and
# sums the healthy members' CLEAN counts.
pool_wait=0
clean_total=0
proto="https"
[[ "${NO_TLS:-}" == "1" ]] && proto="http"
while (( pool_wait < 120 )); do
    clean_total=$(ss_pool_clean "$proto://localhost:3100")
    if (( clean_total >= pool_target )); then
        log "Pool ready: aggregate CLEAN=${clean_total} (target=${pool_target}, ${pool_wait}s)"
        break
    fi
    sleep 2
    pool_wait=$((pool_wait + 2))
done
(( clean_total >= pool_target )) || err "Pool did not reach target within 120s (aggregate CLEAN=${clean_total}, target=${pool_target})"

log "Verification:"
# Scheme is picked from NO_TLS — a plain-http curl to the TLS port returns rc=0
# with "Client sent an HTTP request to an HTTPS server", so the https fallback
# never fires and the "stats" dump is that error line.
if [[ "$NO_TLS" == "1" ]]; then
    curl -s http://localhost:3100/stats 2>/dev/null || true
else
    curl -sk https://localhost:3100/stats 2>/dev/null || true
fi
echo ""
log "============================================"
log "  Small cluster simulation complete!"
log "  etcd + exec GW + human GW + $SANSLOT_COUNT sandlot instances"
log "============================================"
