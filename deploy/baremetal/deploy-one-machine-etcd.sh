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
# deploy-one-machine-etcd.sh — the "One machine — etcd" topology, deployed for
# real on a single host.
#
# Everything on one machine, production-like semantics: a co-located
# single-node etcd (mTLS, persistent data dir) + gateway(exec) on
# 3000/9998 + gateway(human) on 3100/9996 + ONE exec-role sandlot + ONE
# prov-role sandlot, local-disk volumes and templates. This is the real
# single-machine deployment of the "One machine — etcd" topology in
# docs/how-it-works/topologies.md — not a stand-in for a multi-host shape.
#
# NOT the same as deploy-cluster-one-gw-simulation.sh: that one rehearses the
# MULTI-HOST one-gw cluster (N node hosts) on a single machine, with a
# plain-http etcd and N exec instances. Here the footprint is the topology
# itself: exactly one exec instance + one prov instance, mTLS etcd, persistent
# identity.
#
# The exec + prov roles run as TWO sandlot processes: a merged exec,prov
# instance dials a single gateway address, and this shape's gateways are
# split (exec :9998, human :9996). That two-process one-machine layout is the
# one the role-lock's -allow-colocated-instances flag explicitly admits —
# both units below carry it (it only fires when the lock is contended; the
# second starter logs a warning and proceeds).
#
# Usage: sudo bash deploy-one-machine-etcd.sh [--pool SPEC:COUNT] [--skip-build] [--no-tls]
#   --no-tls keeps the HTTP listeners (and the co-located etcd) plaintext; the
#   gateway<->sandlot stream ALWAYS carries per-node mTLS certificates.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/deploy-lib.sh"

# LEAVE-RUNNING deploy (no teardown trap by design — the services are the
# deliverable); INT/TERM must still stop the run instead of resuming it
# mid-phase after bash handles the signal.
trap 'exit 130' INT TERM

NO_TLS=0
SKIP_BUILD=0
POOL="medium:2"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pool)       POOL="$2"; shift 2 ;;
        --no-tls)     NO_TLS=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help)
            echo "Usage: $0 [--pool SPEC:COUNT] [--no-tls] [--skip-build]"
            echo "  --no-tls       Plaintext HTTP listeners (dev only); the node stream always uses mTLS certificates"
            exit 0
            ;;
        *) err "Unknown argument: $1" ;;
    esac
done

[[ $EUID -ne 0 ]] && err "This script must be run as root"
[[ "$POOL" =~ ^[a-z]+:[0-9]+$ ]] || err "Invalid --pool '$POOL' (expected SPEC:COUNT, e.g. medium:2)"

if [[ $NO_TLS -eq 1 ]]; then
    export NO_TLS=1
fi

# Same rationale as the sibling scripts: stale /run/sandswap state (an
# interrupted run's LastGatewayIP / tolerating phase) wedges the next run's
# reconnect, so every deploy starts from a wiped run dir.
# shellcheck disable=SC2034
BM_MODE_DESC="baremetal one-machine etcd (mTLS etcd + exec GW + human GW + 1 exec sandlot + 1 prov sandlot)"
# shellcheck disable=SC2034
BM_WIPE_RUN=1
bm_preclean
bm_preflight

# ──── [1/6] Build ────
if [[ $SKIP_BUILD -eq 0 ]]; then
    log "[1/6] Building artifacts..."
    bm_build_artifacts
else
    log "[1/6] Skipping build"
    for f in gateway sandlot sandvmm template-tool vmlinux.bin initramfs.cpio.gz; do
        [[ -f "$REPO_ROOT/output/$f" ]] || err "Missing artifact: output/$f"
    done
    ss_verify_kernel_artifact "$REPO_ROOT/output/vmlinux.bin" "$REPO_ROOT/kernel/build.sh" \
        || err "Refusing --skip-build with a non-pinned kernel under output/ — run bash build/build.sh kernel"
fi

OUTPUT="$REPO_ROOT/output"
DEPLOY_DIR="$REPO_ROOT/deploy/baremetal"

# ──── [2/6] Host prep ────
log "[2/6] Preparing host..."
# The exec instance below is configured with 10.188.1.0/24 / gw 10.188.1.1, so
# the bridge must carry THAT gateway address (setup-host's default is
# 10.188.0.0/16 / 10.188.0.1; a mismatch leaves every microVM's default route
# pointing at an address nobody answers ARP for). setup-host persists the
# addressing into /etc/sandswap/network.env, which the boot-time
# sandswap-network.service reads back.
# +: this topology runs a DEDICATED prov instance as sandprov.
# EXPORT the shape once, so EVERY helper that derives ownership from
# SS_PROV_USER (setup-host, sandswap_apply_prov_plane, prepare_provision_host's
# templates/prov.key, the seed group) uses sandprov — a command-scoped prefix
# on the setup-host call alone left prepare_provision_host to its sandlot
# default and prov.key/templates landed sandlot-owned: the prov instance then
# died "open /etc/sandswap/certs/prov.key: permission denied" (a regression
# this drill catches).
export SS_PROV_USER=sandprov
bash "$SCRIPT_DIR/setup-host.sh" --role all --subnet 10.188.1.0/24 --gateway-ip 10.188.1.1
# Persist the shape for the units' ExecStartPost (see sandswap_write_prov_user_env):
# this deployment runs a DEDICATED prov instance.
SS_PROV_USER=sandprov sandswap_write_prov_user_env


# ──── [3/6] Certificates + etcd + gateways ────
log "[3/6] Installing etcd + gateways..."
sandswap_install_binary "$OUTPUT/gateway" "$SANDSWAP_BIN/sandswap-gateway"
rm -rf "$SANDSWAP_VAR/flat-templates/rootfs/v1"   # a merge cp cannot replace a stale bin/ symlink
mkdir -p "$SANDSWAP_VAR/flat-templates/rootfs/v1"
cp -a "$OUTPUT/rootfs-template/." "$SANDSWAP_VAR/flat-templates/rootfs/v1/"
# Template contract: group-readable via the shared group, normalized by the
# canonical tool (docs/operations/template-contract.md).
chgrp -R "$SS_SHARED_GROUP" "$SANDSWAP_VAR/flat-templates" 2>/dev/null || true
[[ -x "$OUTPUT/template-tool" ]] && "$OUTPUT/template-tool" normalize "$SANDSWAP_VAR/flat-templates" >/dev/null

# Stream certificates are minted in EVERY shape: the gateway refuses a
# certificate-less node stream (the listener requires a client cert and binds
# its CN to the hello's node_id), so --no-tls only keeps the HTTP listeners
# (and this topology's etcd) plaintext. HTTP_TLS_DIR is the flag --no-tls
# actually controls; CERT_DIR always holds the stream pairs + CA.
CERT_DIR="${SANDSWAP_ETC}/certs"
HTTP_TLS_DIR=""
ETCD_URL="http://127.0.0.1:2379"
# The two node ids this host's sandlots declare (the stream identity contract
# in step [5/6] below). Defined HERE because the certificates are minted from
# them: the gateway binds a stream hello's node_id to the client certificate's
# CN by exact match. The exec instance's EFFECTIVE node id is
# `<node_id>-<instance.id>` (sandlot/cmd/main.go composes the suffix before
# the hello), so its pair must carry the composed id, not the raw one.
INSTANCE="main"
NODE_ID="$(hostname)"
EXEC_CERT_CN="${NODE_ID}-${INSTANCE}"
PROV_NODE_ID="sandlot-prov"
# Name of the prov node's client pair in the certs dir (gen-baremetal-certs.sh
# --client-cn <node-id> writes sandlot-<node-id>.*). One variable so the mint,
# the generated config's tls block, the prov.key derivation and the sed that
# re-points the config's key line stay in lockstep.
PROV_CERT_BASE="sandlot-${PROV_NODE_ID}"
SANDLOT_NODE_ID="$EXEC_CERT_CN" \
    bash "$SCRIPT_DIR/gen-baremetal-certs.sh" "$OUTPUT/baremetal-certs" \
        --client-cn "${PROV_NODE_ID}:prov"
mkdir -p "$CERT_DIR"
cp "$OUTPUT/baremetal-certs"/* "$CERT_DIR/"
# Scope each private key to the identity that loads it (same as the other
# deployers) — the units run as dedicated users, and the generated keys
# are root-only 0600.
ss_own_tls_keys "$CERT_DIR"
# Both pairs must carry the node ids their instances declare (the gateway
# refuses a mismatch by name; fail the deploy here instead of at the
# handshake, where the unit just crash-loops).
sandswap_verify_client_cert_cn "$CERT_DIR/sandlot.crt" "$EXEC_CERT_CN" \
    || err "exec stream client cert does not carry the exec instance's effective node id ($EXEC_CERT_CN)"
sandswap_verify_client_cert_cn "$CERT_DIR/${PROV_CERT_BASE}.crt" "$PROV_NODE_ID" \
    || err "prov stream client cert does not carry the prov node id ($PROV_NODE_ID)"
if [[ $NO_TLS -eq 0 ]]; then
    HTTP_TLS_DIR="$CERT_DIR"
    ETCD_URL="https://127.0.0.1:2379"
fi

# Co-located single-node etcd. Unlike the simulation's ephemeral plain-http
# stand-in, this is the real thing: mTLS (generated etcd-server/client certs),
# persistent data dir (identity MUST survive reboots), localhost-only
# listener. Binary from PATH → output/etcd → download. A previous run of this
# deployer installs etcd at /usr/local/bin — command -v then resolves to our
# own install, and copying it onto itself fails; skip the copy in that case.
# Download goes through the shared sha256-pinned helper (common.sh).
ETCD_BIN=$(command -v etcd || echo "$REPO_ROOT/output/etcd/etcd")
if [[ ! -x "$ETCD_BIN" ]]; then
    sandswap_fetch_etcd "$REPO_ROOT/output/etcd"
    ETCD_BIN="$REPO_ROOT/output/etcd/etcd"
fi
if [[ "$(readlink -f "$ETCD_BIN")" != "/usr/local/bin/etcd" ]]; then
    sandswap_install_binary "$ETCD_BIN" /usr/local/bin/etcd
fi

ETCD_TLS_FLAGS=""
if [[ $NO_TLS -eq 0 ]]; then
    ETCD_TLS_FLAGS="--cert-file ${SANDSWAP_ETC}/certs/etcd-server.crt --key-file ${SANDSWAP_ETC}/certs/etcd-server.key --trusted-ca-file ${SANDSWAP_ETC}/certs/ca.crt --client-cert-auth"
fi
cat > /etc/systemd/system/sandswap-etcd.service << UNIT
[Unit]
Description=Sandswap co-located etcd (single node)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/etcd --name sandswap-etcd --listen-client-urls ${ETCD_URL} --advertise-client-urls ${ETCD_URL} --listen-peer-urls http://127.0.0.1:2380 --initial-advertise-peer-urls http://127.0.0.1:2380 --initial-cluster sandswap-etcd=http://127.0.0.1:2380 --initial-cluster-token sandswap-etcd --initial-cluster-state new --data-dir /var/lib/sandswap-etcd ${ETCD_TLS_FLAGS} --log-level warn
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now sandswap-etcd
for _ in $(seq 1 30); do
    (exec 3<>/dev/tcp/127.0.0.1/2379) 2>/dev/null && break
    sleep 1
done
systemctl is-active --quiet sandswap-etcd || err "etcd failed to start: $(journalctl -u sandswap-etcd -n 5 --no-pager 2>/dev/null | tail -3)"
log "etcd started (${ETCD_URL}, data-dir /var/lib/sandswap-etcd)"

# The split gateway pair, both on EtcdStore, via template unit instances.
# HTTP_TLS_DIR (empty under --no-tls) drives the agent/human listener TLS +
# the etcd client TLS; SANDSWAP_STREAM_TLS_DIR always points at the minted
# certs, so the stream listener is mTLS in every shape.
GW_SCHEME="https"
[[ $NO_TLS -eq 1 ]] && GW_SCHEME="http"
SANDSWAP_GATEWAY_ID="gw-exec-1" \
SANDSWAP_GATEWAY_URL="${GW_SCHEME}://localhost:3000" \
SANDSWAP_GATEWAY_STREAM_ADDR="localhost:9998" \
SANDSWAP_IDLE_TIMEOUT_SEC=3600 \
SANDSWAP_STREAM_TLS_DIR="$CERT_DIR" \
    sandswap_generate_gateway_config \
    "$SANDSWAP_ETC/gateway-exec.yaml" "exec" "$SANDSWAP_VAR/volumes" \
    "0.0.0.0:3000" "127.0.0.1:3100" "0.0.0.0:9998" "$HTTP_TLS_DIR" "$ETCD_URL"
# Human gateway: every sandfs/template op routes to a prov-role sandlot
# instance connected to ITS stream listener (:9996 — 9998 is the co-located
# exec gateway's). This host runs no gateway-side storage executor: the
# storage plane lives in the prov instance below.
SANDSWAP_STREAM_TLS_DIR="$CERT_DIR" \
sandswap_generate_gateway_config \
    "$SANDSWAP_ETC/gateway-human.yaml" "human" "$SANDSWAP_VAR/volumes" \
    "0.0.0.0:3000" "127.0.0.1:3100" "0.0.0.0:9996" "$HTTP_TLS_DIR" "$ETCD_URL"

# MCP agent guide (exec gateway only; human mode serves no MCP): materialize
# the ops-editable instructions file from the compiled-in default
# (generate-once), then point the exec gateway at it.
if [[ ! -s /etc/sandswap/mcp-instructions.md ]]; then
    "$SANDSWAP_BIN/sandswap-gateway" -print-mcp-instructions > /etc/sandswap/mcp-instructions.md
fi
grep -q "^mcp:" "$SANDSWAP_ETC/gateway-exec.yaml" || cat >> "$SANDSWAP_ETC/gateway-exec.yaml" << 'YAML'

mcp:
  instructions_file: /etc/sandswap/mcp-instructions.md
YAML

sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-gateway@.service"
# A previous run of the single-process shape may have left the combined unit
# enabled — disable it so :3000/:3100/:9998 belong to the new instances.
systemctl disable --now sandswap-gateway 2>/dev/null || true
systemctl reset-failed sandswap-gateway@exec sandswap-gateway@human 2>/dev/null || true
systemctl enable --now sandswap-gateway@exec sandswap-gateway@human
sandswap_wait_for_health "localhost:3000" 30
sandswap_wait_for_health "localhost:3100" 30

# ──── [4/6] Install sandlot binaries ────
log "[4/6] Installing sandlot binaries..."
sandswap_install_binary "$OUTPUT/sandlot" "$SANDSWAP_BIN/sandswap-sandlot"
sandswap_install_binary "$OUTPUT/sandvmm" "$SANDSWAP_BIN/sandswap-sandvmm"
sandswap_install_guest_artifacts "$OUTPUT"
if [[ -f "$OUTPUT/vsockguard.bpf.o" ]]; then
    cp "$OUTPUT/vsockguard.bpf.o" "$SANDSWAP_VAR/"
fi
if [[ -f "$OUTPUT/vsockguardctl" ]]; then
    sandswap_install_binary "$OUTPUT/vsockguardctl" "$SANDSWAP_BIN/vsockguardctl"
fi

# ──── [5/6] Exec instance + prov instance ────
log "[5/6] Starting the exec + prov sandlot pair..."

rm -f "$SANDSWAP_ETC"/sandlot-*.yaml

sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-sandlot-instance@.service"
# This shape's exec+prov roles are two processes (split gateways need one
# stream address each; a merged instance has only one). The explicit flag is
# the role-lock's admission for that layout — both units carry it so start
# order (now or across reboots) never matters; it only fires under contention.
sed -i 's|-config /etc/sandswap/sandlot-%i.yaml|-config /etc/sandswap/sandlot-%i.yaml -allow-colocated-instances|' /etc/systemd/system/sandswap-sandlot-instance@.service
systemctl daemon-reload

# INSTANCE/NODE_ID were fixed in [3/6] (the cert mint derives the client
# pair's CN from them: CN must equal the EFFECTIVE node id `<node_id>-<instance>`).
INSTANCE="main"
NODE_ID="$(hostname)"
CID_START=3
CID_END=102

# SANDSWAP_SANDLOT_CERT_BASE points this instance at the client pair whose CN
# is its effective node id (<hostname>-main): the primary pair minted above.
SANDSWAP_SANDLOT_CERT_BASE=sandlot \
sandswap_generate_sandlot_config \
    "$SANDSWAP_ETC/sandlot-${INSTANCE}.yaml" \
    "localhost:9998" \
    "$NODE_ID" \
    "$POOL" \
    "10.188.1.0/24" \
    "10.188.1.1" \
    "$SANDSWAP_VAR/volumes" \
    "$CERT_DIR" \
    "$INSTANCE" "$CID_START" "$CID_END"

systemctl reset-failed "sandswap-sandlot-instance@${INSTANCE}" 2>/dev/null || true
systemctl enable --now "sandswap-sandlot-instance@${INSTANCE}"
log "Started exec instance: ${INSTANCE} (node=${NODE_ID}, pool=${POOL}, cid=${CID_START}-${CID_END})"

# Provision instance (storage plane). One prov-role sandlot connected to the
# HUMAN gateway's stream (:9996). It is this host's ONLY storage executor:
# the human gateway holds no template manager and mounts no storage, so every
# sandfs create/delete and every template op crosses the stream to this
# instance. Runs as the sandprov identity (zero caps, no KVM duty) via the
# SHIPPED sandswap-sandlot-prov.service unit.
sandswap_prepare_provision_host "$SANDSWAP_VAR/templates" "$CERT_DIR" "$PROV_CERT_BASE"
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
# created + chowned by the provision-host preparation above, derived from THIS
# node's pair — not the exec node's). The pattern must match the EXPANDED path
# the generator wrote (${tls_dir} is a shell variable in the generator, so the
# YAML holds a real path — a pattern containing the literal "tls_dir}" never
# matches, silently leaving the sandlot-owned key in place, unreadable by
# sandprov). The cert line keeps pointing at the prov node's OWN pair: its CN
# is the prov node id the gateway binds (the shared sandlot.crt carries the
# exec node's CN and would be refused by name).
# The assertion makes a future pattern drift loud instead of silent.
sed -i "s|\(/${PROV_CERT_BASE}\.key\)\$|/prov.key|" "$SANDSWAP_ETC/sandlot-prov.yaml"
grep -q 'prov\.key' "$SANDSWAP_ETC/sandlot-prov.yaml" || err "prov.key rewrite did not land in $SANDSWAP_ETC/sandlot-prov.yaml"
# The generator's empty-pool arg falls back to its default (medium:3) —
# strip the line instead: a prov-only instance must carry NO pool (the
# config validator refuses exec machinery on prov-only roles, loudly).
sed -i '/^pool:/d' "$SANDSWAP_ETC/sandlot-prov.yaml"
# The prov config may carry an OCI registry credential — scope it to the
# reading identity (sed -i above recreated it with umask-default perms).
ss_protect_config "$SANDSWAP_ETC/sandlot-prov.yaml" sandprov
sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-sandlot-prov.service"
sed -i 's|-config /etc/sandswap/sandlot-prov.yaml -roles prov|-config /etc/sandswap/sandlot-prov.yaml -roles prov -allow-colocated-instances|' /etc/systemd/system/sandswap-sandlot-prov.service
systemctl daemon-reload
systemctl reset-failed sandswap-sandlot-prov 2>/dev/null || true
systemctl enable --now sandswap-sandlot-prov
log "Started provision instance: sandlot-prov (roles=prov, human gw :9996)"

# ──── [6/6] Wait for pool + verify ────
log "[6/6] Waiting for pool..."
pool_target="${POOL##*:}"
# The exec gateway's /stats is gated by -ops-token-file (empty = DISABLED on
# the agent listener), so a fresh deploy cannot read it. The human gateway's
# /stats is the etcd-aggregated fleet view; sum the healthy members' CLEAN
# counts. Scheme follows the HTTP-listener TLS shape.
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

# The prov instance is a SEPARATE process (sandswap-sandlot-prov): without it
# every sandfs/template op is a named 503 while the deploy still "succeeds".
# Gate on the human gateway's provisioners counter — the same signal the k8s
# deploy waits for (deploy-lib.sh).
PROV_HUMAN="http://localhost:3100"
[[ "$NO_TLS" == "1" ]] || PROV_HUMAN="https://localhost:3100"
prov_ok=0
for _ in $(seq 1 30); do
    body=$(curl -sk -m 5 "$PROV_HUMAN/health" 2>/dev/null || true)
    if echo "$body" | grep -qE '"provisioners":[[:space:]]*[1-9]'; then
        prov_ok=1; break
    fi
    sleep 2
done
if [[ "$prov_ok" == "1" ]]; then
    log "Provision plane ready (>=1 prov instance connected)"
else
    log "ERROR: no provision instance connected after 60s — every sandfs/template op will 503."
    log "       Check: systemctl status sandswap-sandlot-prov; journalctl -u sandswap-sandlot-prov -n 50"
    exit 1
fi

# Publish the client contract ONLY after both gates (pool + provision plane).
if [[ "$NO_TLS" == "1" ]]; then
    sandswap_write_sandctl_env "http://127.0.0.1:3000" "http://127.0.0.1:3100" plain "" "$ETCD_URL"
else
    sandswap_write_sandctl_env "https://127.0.0.1:3000" "https://127.0.0.1:3100" tls "$CERT_DIR/ca.crt" "$ETCD_URL"
fi

log "Verification:"
# Scheme is picked from NO_TLS — a plain-http curl to the TLS port returns rc=0
# with "Client sent an HTTP request to an HTTPS server", so the https fallback
# never fires and the "stats" dump is that error line.
if [[ "$NO_TLS" == "1" ]]; then
    curl -s http://localhost:3000/health || true
    echo ""
    curl -s http://localhost:3100/health || true
    echo ""
    curl -s http://localhost:3100/stats 2>/dev/null || true
else
    curl -sk https://localhost:3000/health || true
    echo ""
    curl -sk https://localhost:3100/health || true
    echo ""
    curl -sk https://localhost:3100/stats 2>/dev/null || true
fi
echo ""
log "============================================"
log "  One-machine etcd deployment complete!"
log "  etcd (mTLS) + exec GW + human GW + exec sandlot + prov sandlot"
log "============================================"
