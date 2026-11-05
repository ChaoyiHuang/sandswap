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
# deploy-cluster-multi-gw-simulation.sh — Production cluster simulation on a single host
# Simulates the full production topology on one machine:
#   etcd (2379) + 2 exec gateways (3000/9998, 3001/9997) + human gateway (3100)
#   + 2 sandlot instances + sandns (53)
# This exercises: multi-gateway EtcdStore, ownership via etcd, DNS routing.
# Usage: sudo bash deploy-cluster-multi-gw-simulation.sh [--skip-build]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/deploy-lib.sh"

SKIP_BUILD=0
KEEP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1; shift ;;
        --keep)       KEEP=1; shift ;;
        -h|--help)
            echo "Usage: $0 [--skip-build] [--keep]"
            echo "  --skip-build  Use existing output/ artifacts"
            echo "  --keep        Leave services running after the self-test (default: clean up)"
            exit 0
            ;;
        *) err "Unknown argument: $1" ;;
    esac
done

[[ $EUID -ne 0 ]] && err "This script must be run as root"

# cleanup tears down everything this script deployed (systemd units, etcd, DNS,
# bridge, nftables) so the host is left clean for the next run. It mirrors the
# [0/10] stop+kill block at the top. Registered as the EXIT/INT/TERM trap so a
# Ctrl-C or failure also cleans up; skipped with --keep (services stay up for
# manual inspection — re-running the script self-cleans via [0/10] either way).
cleanup() {
    if [[ "$KEEP" == "1" ]]; then
        log "Services preserved (--keep). Re-run without --keep, or:"
        log "  bash deploy/baremetal/uninstall.sh"
        return
    fi
    log "Cleaning up production-local deployment..."
    # Shared teardown (deploy-lib.sh): stop+disable units, kill process trees,
    # port sweep (incl. this sim's 3001/9997), strip the sandswap /etc/hosts
    # pins, wipe /run/sandswap (prod1/prod2 instance state incl.), replay the
    # side-effect ledger (etcd pidfile etc.).
    bm_preclean
    rm -rf /tmp/sandswap-prod-etcd-data
    # Bridge + nftables (best-effort; uninstall.sh is the canonical sweep)
    ip link del br-sandswap 2>/dev/null || true
    nft delete table inet sandswap 2>/dev/null || true
    # Egress identity enabler tables (baseline anti-spoof, routed-ipv6 stamps)
    nft delete table netdev sandswap_baseline 2>/dev/null || true
    nft delete table bridge sandswap_baseline 2>/dev/null || true
    nft delete table inet sandswap_routed6 2>/dev/null || true
    log "Cleanup done"
}
bm_traps cleanup

log "[0/10] Preclean + preflight..."
# Shared implementation (deploy-lib.sh) — replaces the inline copy (which, unlike
# this shared one, did not cover the ledger, the wider port sweep or the hosts
# pin patterns used by the other scripts). BM_WIPE_RUN=1 clears the prod1/prod2
# instance state the same ids as verify-binpack.sh reuse.
# shellcheck disable=SC2034
BM_MODE_DESC="baremetal production-cluster simulation (etcd + 2 exec GW + human GW + 2 sandlots + DNS)"
# shellcheck disable=SC2034
BM_WIPE_RUN=1
bm_preclean
bm_preflight
rm -rf /tmp/sandswap-prod-etcd-data

# ──── [1/10] Build ────
if [[ $SKIP_BUILD -eq 0 ]]; then
    log "[1/10] Building artifacts..."
    bm_build_artifacts
else
    log "[1/10] Skipping build"
fi

OUTPUT="$REPO_ROOT/output"
DEPLOY_DIR="$REPO_ROOT/deploy/baremetal"

# ──── [2/10] Host prep ────
log "[2/10] Preparing host..."
# Per-instance subnets (10.189.${i}.0/24) — see the one-gw simulation: the
# bridge must own each instance's gateway address.
SIM_EXTRA_ADDRS=""
for i in 1 2; do   # the two exec instances started below (prod1, prod2)
    SIM_EXTRA_ADDRS+="10.189.${i}.1/24 "
done
# Dedicated-prov shape: the host-prep ownership (volumes root, template
# stores) must follow the sandprov writer — see sandswap_apply_prov_plane.
SS_PROV_USER=sandprov bash "$SCRIPT_DIR/setup-host.sh" --role all --extra-addrs "$SIM_EXTRA_ADDRS"
# Persist the shape for the units' ExecStartPost (see sandswap_write_prov_user_env):
# this deployment runs a DEDICATED prov instance.
SS_PROV_USER=sandprov sandswap_write_prov_user_env


# ──── [3/10] Certificates (with DNS SANs) ────
log "[3/10] Generating certificates with DNS SANs..."
HOST_IP=$(hostname -I | awk '{print $1}')
# STREAM IDENTITIES of this simulation (see the CN rule in
# gen-baremetal-certs.sh): every sandlot declares an EFFECTIVE node id — the
# config's node_id plus `-<instance.id>` — and the gateway binds it to the
# client certificate's CN by exact match. One pair per node id: the first
# instance rides the primary pair, the rest + the prov node get their own.
# Two exec instances (prod1, prod2 — the loop below), each with its own
# gateway: their effective node ids are prod-sandlot-<i>-prod<i>.
PROV_NODE_ID="sandlot-prov"
PROV_CERT_BASE="sandlot-${PROV_NODE_ID}"
SIM_NODE_IDS=("prod-sandlot-1-prod1" "prod-sandlot-2-prod2")
SANDLOT_NODE_ID="${SIM_NODE_IDS[0]}" \
    bash "$SCRIPT_DIR/gen-baremetal-certs.sh" "$OUTPUT/baremetal-certs" \
    --sans-dns "sandswap.local,sandswap-stream.local,*.sandfs.sandswap.local" \
    --sans-ip "$HOST_IP" \
    --client-cn "${SIM_NODE_IDS[1]}:exec" \
    --client-cn "${PROV_NODE_ID}:prov"
CERT_DIR="${SANDSWAP_ETC}/certs"
mkdir -p "$CERT_DIR"
cp "$OUTPUT/baremetal-certs"/* "$CERT_DIR/"
# Scope each private key to the identity that loads it (same as
# deploy-single-node.sh) — the units run as dedicated users, and the
# generated keys are root-only 0600.
ss_own_tls_keys "$CERT_DIR"

# ──── [4/10] etcd ────
log "[4/10] Starting etcd..."
ETCD_BIN=$(command -v etcd || echo "$REPO_ROOT/output/etcd/etcd")
if [[ ! -x "$ETCD_BIN" ]]; then
    # Download etcd if not present
    mkdir -p "$REPO_ROOT/output/etcd"
    log "Downloading etcd..."
    sandswap_fetch_etcd "$REPO_ROOT/output/etcd"
    ETCD_BIN="$REPO_ROOT/output/etcd/etcd"
fi
ETCDCTL_BIN="${ETCDCTL_BIN:-$REPO_ROOT/output/etcd/etcdctl}"
[[ -x "$ETCDCTL_BIN" ]] || ETCDCTL_BIN="$(command -v etcdctl || echo "")"

"$ETCD_BIN" \
    --name sandswap-prod \
    --listen-client-urls http://127.0.0.1:2379 \
    --advertise-client-urls http://127.0.0.1:2379 \
    --listen-peer-urls http://127.0.0.1:2380 \
    --initial-advertise-peer-urls http://127.0.0.1:2380 \
    --initial-cluster sandswap-prod=http://127.0.0.1:2380 \
    --initial-cluster-token sandswap-prod \
    --initial-cluster-state new \
    --data-dir /tmp/sandswap-prod-etcd-data \
    --log-level warn \
    > /tmp/sandswap-etcd.log 2>&1 &
ETCD_PID=$!
echo "$ETCD_PID" > /tmp/sandswap-etcd.pid
se_record EPHEMERAL etcd-proc /tmp/sandswap-etcd.pid
sleep 2
if ! kill -0 "$ETCD_PID" 2>/dev/null; then
    err "etcd failed to start: $(tail -5 /tmp/sandswap-etcd.log)"
fi
log "etcd started (pid=$ETCD_PID)"

# ──── [5/10] Gateway binaries ────
log "[5/10] Installing gateway binary..."
sandswap_install_binary "$OUTPUT/gateway" "$SANDSWAP_BIN/sandswap-gateway"
# Flat template layout: flatTemplatesDir/<name>/<version>/ → ref "<name>:<version>".
# Copying the rootfs-template contents into rootfs/v1 makes "rootfs:v1" resolvable
# (ScanFlatTemplates: versioned dir). A bare `cp -a rootfs-template/ flat-templates/`
# would dump bin/dev/etc at the top level and register those as bogus templates.
# Clear any stale template dir first (a prior deploy may have left `bin` as a
# busybox-style symlink, which a merge `cp -a` cannot overwrite with a directory).
rm -rf "$SANDSWAP_VAR/flat-templates/rootfs/v1"
mkdir -p "$SANDSWAP_VAR/flat-templates/rootfs/v1"
cp -a "$OUTPUT/rootfs-template/." "$SANDSWAP_VAR/flat-templates/rootfs/v1/"
chgrp -R "$SS_SHARED_GROUP" "$SANDSWAP_VAR/flat-templates" 2>/dev/null || true
[[ -x "$OUTPUT/template-tool" ]] && "$OUTPUT/template-tool" normalize "$SANDSWAP_VAR/flat-templates" >/dev/null

# ──── [6/10] Exec gateway 1 (3000/9998) ────
log "[6/10] Exec gateway 1 (3000/9998)..."
cat > "$SANDSWAP_ETC/gateway-exec1.yaml" << YAML
mode: exec
vol_root: ${SANDSWAP_VAR}/volumes

# Affinity wiring: unique gateway_id (two exec GWs MUST differ),
# gateway_url for owner-aware DNS A-record target + 307 Location (registry key),
# stream_addr for the registry key, and a long idle timeout so the connection =
# the affinity anchor.
gateway_id: exec1
gateway_url: "https://${HOST_IP}:3000"
gateway_stream_addr: "${HOST_IP}:9998"
idle_timeout_sec: 3600

etcd: "http://127.0.0.1:2379"

agent:
  addr: "0.0.0.0:3000"
  tls_cert: ${CERT_DIR}/mcp.crt
  tls_key: ${CERT_DIR}/mcp.key
stream:
  addr: "0.0.0.0:9998"
  tls_cert: ${CERT_DIR}/stream.crt
  tls_key: ${CERT_DIR}/stream.key
  tls_ca: ${CERT_DIR}/ca.crt

lease:
  sticky_ms: 100
  max_sticky_sec: 5

exec:
  default_timeout_sec: 30
  max_timeout_sec: 180

YAML

# Exec gateway uses sandswap-gateway@.service template with %i=exec1
sed 's/gateway-%i.yaml/gateway-exec1.yaml/; s/%i/exec1/' \
    "$DEPLOY_DIR/systemd/sandswap-gateway@.service" > /etc/systemd/system/sandswap-gateway-exec1.service
systemctl daemon-reload
systemctl reset-failed sandswap-gateway-exec1 2>/dev/null || true
systemctl enable --now sandswap-gateway-exec1

# ──── [7/10] Exec gateway 2 (3001/9997) ────
log "[7/10] Exec gateway 2 (3001/9997)..."
sed -e 's/0.0.0.0:3000/0.0.0.0:3001/' \
    -e 's/0.0.0.0:9998/0.0.0.0:9997/' \
    -e 's/gateway_id: exec1/gateway_id: exec2/' \
    -e "s#https://${HOST_IP}:3000#https://${HOST_IP}:3001#" \
    -e "s#${HOST_IP}:9998#${HOST_IP}:9997#" \
    "$SANDSWAP_ETC/gateway-exec1.yaml" > "$SANDSWAP_ETC/gateway-exec2.yaml"
sed 's/gateway-%i.yaml/gateway-exec2.yaml/; s/%i/exec2/' \
    "$DEPLOY_DIR/systemd/sandswap-gateway@.service" > /etc/systemd/system/sandswap-gateway-exec2.service
systemctl daemon-reload
systemctl reset-failed sandswap-gateway-exec2 2>/dev/null || true
systemctl enable --now sandswap-gateway-exec2

# ──── [8/10] Human gateway (3100) ────
log "[8/10] Human gateway (3100)..."
cat > "$SANDSWAP_ETC/gateway-human.yaml" << YAML
mode: human
vol_root: ${SANDSWAP_VAR}/volumes

etcd: "http://127.0.0.1:2379"

human:
  addr: "127.0.0.1:3100"
  tls_cert: ${CERT_DIR}/human.crt
  tls_key: ${CERT_DIR}/human.key

stream:
  addr: "0.0.0.0:9996"
  tls_cert: ${CERT_DIR}/stream.crt
  tls_key: ${CERT_DIR}/stream.key
  tls_ca: ${CERT_DIR}/ca.crt
YAML

sed 's/gateway-%i.yaml/gateway-human.yaml/; s/%i/human/' \
    "$DEPLOY_DIR/systemd/sandswap-gateway@.service" > /etc/systemd/system/sandswap-gateway-human.service
systemctl daemon-reload
systemctl reset-failed sandswap-gateway-human 2>/dev/null || true
systemctl enable --now sandswap-gateway-human

# ──── [9/10] Sandlot instances ────
log "[9/10] Sandlot instances..."

# The sandlots connect to the gateway by DNS name (sandswap-stream.local). On a
# systemd-resolved host, ".local" names are answered locally (NXDOMAIN) and never
# reach the sandns upstream (even with a resolved.conf.d route). Pin the
# two sandswap domains in /etc/hosts so the single-host simulation connects —
# mirrors the production "point sandlot resolver at sandns" deploy step.
if ! grep -q 'sandswap-stream.local' /etc/hosts; then
    # our own pin carries a marker so cleanup strips OURS, never an
    # operator's hand-made pin for the same names.
    echo "$HOST_IP sandswap.local sandswap-stream.local # sandswap-managed" >> /etc/hosts
    se_record EPHEMERAL hosts-pin 'sandswap-managed'
    log "Routed sandswap domains in /etc/hosts → $HOST_IP"
fi

sandswap_install_binary "$OUTPUT/sandlot" "$SANDSWAP_BIN/sandswap-sandlot"
sandswap_install_binary "$OUTPUT/sandvmm" "$SANDSWAP_BIN/sandswap-sandvmm"
# The sandlot units' ExecStartPre attestation shells out to vsockguardctl —
# without the binary every instance crash-loops after a full uninstall.
if [[ -f "$OUTPUT/vsockguardctl" ]]; then
    sandswap_install_binary "$OUTPUT/vsockguardctl" "$SANDSWAP_BIN/vsockguardctl"
fi
cp "$OUTPUT/vmlinux.bin" "$SANDSWAP_VAR/"
chmod 0644 "$SANDSWAP_VAR/vmlinux.bin" 2>/dev/null || true
cp "$OUTPUT/initramfs.cpio.gz" "$SANDSWAP_VAR/"

# The instance template is SHIPPED (deploy/baremetal/systemd/) — one source of
# truth with sandswap-sandlot.service for the identity block and capability
# set. An earlier revision inlined the unit here and drifted from the shipped
# one after the sandvmm identity split (missing CAP_SETUID/SETGID/KILL made
# every instance die at startup's checkCapsForVMMSpawn).
sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-sandlot-instance@.service"
# Simulation-only escape hatch for the one-sandlot-per-host rule (exec
# instances + the prov instance share this host; the SHIPPED unit stays clean).
sed -i 's|-config /etc/sandswap/sandlot-%i.yaml|-config /etc/sandswap/sandlot-%i.yaml -allow-colocated-instances|' /etc/systemd/system/sandswap-sandlot-instance@.service
systemctl daemon-reload

for i in 1 2; do
    INSTANCE="prod${i}"
    CID_START=$((3 + (i - 1) * 100))
    CID_END=$((CID_START + 99))
    # Pin each sandlot to ITS gateway on this single host (gw-exec1=:9998,
    # gw-exec2=:9997) so the sim is a faithful "1 sandlot ↔ 1 gateway" topology.
    # Production uses the DNS name sandswap-stream.local for failover; the
    # single-host sim cannot distinguish gateways by IP so it pins by port.
    GW_STREAM_PORT=$((9999 - i))   # 9998, 9997
    # The tls block must name the pair whose CN is THIS instance's effective
    # node id (prod-sandlot-<i>-prod<i>) — see the mint above.
    SANDSWAP_SANDLOT_CERT_BASE="$([[ "$i" == "1" ]] && echo sandlot || echo "sandlot-${SIM_NODE_IDS[$((i - 1))]}")" \
    sandswap_generate_sandlot_config \
        "$SANDSWAP_ETC/sandlot-${INSTANCE}.yaml" \
        "127.0.0.1:${GW_STREAM_PORT}" \
        "prod-sandlot-${i}" \
        "${SANDSWAP_POOL_SPEC:-small}:1" \
        "10.189.${i}.0/24" \
        "10.189.${i}.1" \
        "$SANDSWAP_VAR/volumes" \
        "$CERT_DIR" \
        "$INSTANCE" "$CID_START" "$CID_END"
    sandswap_verify_client_cert_cn "$CERT_DIR/$([[ "$i" == "1" ]] && echo sandlot || echo "sandlot-${SIM_NODE_IDS[$((i - 1))]}").crt" \
        "${SIM_NODE_IDS[$((i - 1))]}" || err "instance ${INSTANCE}: stream pair does not carry its effective node id"
    systemctl reset-failed "sandswap-sandlot-instance@${INSTANCE}" 2>/dev/null || true
    systemctl enable --now "sandswap-sandlot-instance@${INSTANCE}"
done

# Provision instance (storage plane): one prov-role sandlot connected to the
# HUMAN gateway's stream (:9996). The exec instances above stay exec-only —
# this is the SPLIT-role topology (multi-gw production shape): compute hosts
# run exec instances, the provision capacity dials the human gateway.
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
    "127.0.0.1:9996" \
    "$PROV_NODE_ID" \
    "" \
    "10.189.254.0/24" \
    "10.189.254.1" \
    "$SANDSWAP_VAR/volumes" \
    "$CERT_DIR"
# The prov instance runs as sandprov and must load ITS OWN key copy (prov.key,
# created + chowned by the provision-host preparation above from the PROV
# node's pair). The pattern must match the EXPANDED path the generator wrote
# (${tls_dir} is a shell variable in the generator, so the YAML holds a real
# path — a pattern containing the literal "tls_dir}" never matches, silently
# leaving the sandlot-owned key in place, unreadable by sandprov). The cert
# line keeps naming the prov node's own pair (its CN is the prov node id the
# gateway binds).
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
sed -i 's|-config /etc/sandswap/sandlot-prov.yaml -roles prov|-config /etc/sandswap/sandlot-prov.yaml -roles prov -allow-colocated-instances|' /etc/systemd/system/sandswap-sandlot-prov.service
systemctl daemon-reload
systemctl reset-failed sandswap-sandlot-prov 2>/dev/null || true
systemctl enable --now sandswap-sandlot-prov
log "Started provision instance: sandlot-prov (roles=prov, human gw :9996)"

# ──── [10/10] sandns ────
log "[10/10] sandns..."
sandswap_install_binary "$OUTPUT/sandns" "$SANDSWAP_BIN/sandns"

cat > "$SANDSWAP_ETC/sandns.yaml" << YAML
listen_addr: "0.0.0.0:53"
# Sandbox guest ranges: a foreign-zone query from these sources is REFUSED
# (no open recursive relay behind the host egress identity). Update if the
# sandlot subnet is not the default.
guest_cidrs: ["10.188.0.0/16"]

domains:
  stream: sandswap-stream.local
  # Per-sandfs owner-aware zone. <sandfs_id>.sandfs.sandswap.local resolves
  # to the OWNER gateway (A record → its IP on baremetal). There is NO static
  # gateway list — candidates come entirely from each gateway's self-registered
  # /sandswap/gateway/{id} key (gateway_url + stream_addr).
  sandfs: sandfs.sandswap.local

etcd: "http://127.0.0.1:2379"

ttl: 10
sticky_expire: 1800
sticky_sync_interval: 5
sticky_sync_batch: 256

scheduling:
  policy: binpack
  duty_hard: 0.85

forwarders:
  - 8.8.8.8:53
  - 8.8.4.4:53
YAML

sandswap_install_systemd_unit "$DEPLOY_DIR/systemd/sandswap-sandns.service"
systemctl reset-failed sandswap-sandns 2>/dev/null || true
systemctl enable --now sandswap-sandns

# ──── DNS health gate: a REAL query, not a process glance ────
# `systemctl is-active` alone lies twice: a crash-looping unit reads
# "activating", and a stale dns process left over from an earlier run can hold
# :53 and ANSWER for it (a split-brain that once turned this whole self-test
# green while THIS unit had never bound — the stale process pointed at the
# same etcd, so every dig was answered correctly by the wrong server). Gate on
# the real thing: the unit must be active AND answer an actual query for the
# stream domain through 127.0.0.1. DNS is a load-bearing part of this
# topology (failover/binpack routing) — without it the deployment is not
# "deployed", it is degraded.
if ! systemctl is-active --quiet sandswap-sandns; then
    journalctl -u sandswap-sandns --no-pager 2>/dev/null | tail -20
    err "sandns unit is not active — DNS is mandatory for this topology (journal above)"
fi
DNS_GATE_ANSWER=""
for i in $(seq 1 15); do
    DNS_GATE_ANSWER="$(dig @127.0.0.1 sandswap-stream.local +short +time=2 +tries=1 2>/dev/null | head -1 || true)"
    [[ -n "$DNS_GATE_ANSWER" ]] && break
    # A first-answer miss can also mean a foreign :53 listener is serving
    # instead of us — re-assert the unit before the next retry.
    systemctl is-active --quiet sandswap-sandns || {
        journalctl -u sandswap-sandns --no-pager 2>/dev/null | tail -20
        err "sandns stopped answering — DNS is mandatory for this topology (journal above)"
    }
    sleep 2
done
if [[ -z "$DNS_GATE_ANSWER" ]]; then
    journalctl -u sandswap-sandns --no-pager 2>/dev/null | tail -20
    err "sandns never answered a real query for sandswap-stream.local — DNS is mandatory for this topology (journal above)"
fi
log "DNS gate passed: unit active, stream query answered → ${DNS_GATE_ANSWER}"

# ──── Verify ────
log "Verification..."
sleep 5
echo "  etcd:        $(curl -s http://127.0.0.1:2379/health 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("health","?"))' 2>/dev/null || echo '?')"
echo "  gw-exec1:    $(curl -sk https://localhost:3000/health 2>/dev/null || echo down)"
echo "  gw-exec2:    $(curl -sk https://localhost:3001/health 2>/dev/null || echo down)"
echo "  gw-human:    $(curl -sk https://localhost:3100/health 2>/dev/null || echo down)"
echo "  dns stream:  $(dig @127.0.0.1 sandswap-stream.local +short 2>/dev/null || echo '?')"

# ──── Affinity Self-Test (registry + redirect + owner-aware DNS + G1/G2, no LLM) ────
# Mirrors the k8s deploy's Phase 8 affinity self-check: verifies the per-sandfs
# owner-aware DNS zone, real microVM exec through the sandfs URL (wildcard cert),
# 307 redirect from a non-owner, and the G1/G2 fault-state signal + takeover.
# On this single-host sim both gateways share HOST_IP, so the owner-aware DNS
# A-record is the same IP either way — ownership is verified via etcd (gateway_id)
# and the 307 Location (owner port), which ARE distinguishable.
AFF_FAIL=0
aff_check() { # <name> <pass|fail> <detail>
    local name="$1" ok="$2" detail="$3"
    if [[ "$ok" == "1" ]]; then
        echo "  [PASS] $name"
    else
        echo "  [FAIL] $name — ${detail:-?}"
        AFF_FAIL=1
    fi
}
aff_etcd_get() { # <key> → value or ""
    if [[ -z "${ETCDCTL_BIN:-}" ]]; then echo ""; return; fi
    "$ETCDCTL_BIN" --endpoints=http://127.0.0.1:2379 get "$1" --print-value-only 2>/dev/null || echo ""
}
aff_health_field() { # <gateway_id> <field> → value or ""
    aff_etcd_get "/sandswap/health/$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" 2>/dev/null || echo ""
}
aff_registry_field() { # <gateway_id> <field> → value or "" (routing address lives in the registry key)
    aff_etcd_get "/sandswap/gateway/$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" 2>/dev/null || echo ""
}
aff_dig_first() { # <name> → first A record or ""
    # || true honors the "or empty" contract under set -o pipefail (see
    # aff_wait_field callers): a dig timeout must read as "", not as a
    # caller-killing non-zero status.
    dig @127.0.0.1 "$1" +short +time=2 +tries=1 2>/dev/null | head -1 || true
}
aff_wait_field() { # <gateway_id> <field> <want> [tries=15] — poll an etcd health
    # field until it equals <want>. Every state below is written by ANOTHER
    # process on its own refresh cadence; a single read after a fixed sleep is
    # a race bet (this flaked as the k8s boxout DNS self-test before retries).
    local gid="$1" field="$2" want="$3" tries="${4:-15}" v=""
    local i
    for i in $(seq 1 "$tries"); do
        v="$(aff_health_field "$gid" "$field")"
        [[ "$v" == "$want" ]] && return 0
        sleep 2
    done
    return 1
}

log "Creating agent + sandfs for affinity self-test..."
AFF_AGENT=$(curl -sk -X POST https://localhost:3100/human/agent -H 'Content-Type: application/json' -d '{"name":"affinity-agent"}' 2>/dev/null)
AFF_KEY=$(echo "$AFF_AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null)
AFF_AGENT_ID=$(echo "$AFF_AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null)
AFF_SF=$(curl -sk -X POST https://localhost:3100/human/sandfs -H 'Content-Type: application/json' \
    -d "{\"agent_id\":\"$AFF_AGENT_ID\",\"name\":\"affinity-sandfs\",\"description\":\"affinity self-test\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}" 2>/dev/null)
AFF_SF_ID=$(echo "$AFF_SF" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null)
if [[ -z "$AFF_KEY" || -z "$AFF_SF_ID" ]]; then
    err "affinity self-test: failed to create agent/sandfs: $AFF_AGENT $AFF_SF"
fi
log "  agent=$AFF_AGENT_ID sandfs=$AFF_SF_ID"
# etcd watch propagation to exec gateways: verify by CONDITION (the key
# actually resolving), not by a fixed sleep.
aff_exec1="https://localhost:3000"
if ! bm_verify_watch_sync "$aff_exec1" "$AFF_KEY" 15; then
    err "affinity self-test: API key never reached exec1 (etcd watch sync)"
fi

AFF_HOST="${AFF_SF_ID}.sandfs.sandswap.local"
AFF_EXEC="{\"sandfs_id\":\"$AFF_SF_ID\",\"code\":\"echo affinity_self_test_ok\",\"language\":\"shell\",\"timeout\":30}"

# 1. Registry keys registered with gateway_url + health node_count (G1).
# Bounded retries: both keys are written by the gateways on their own startup
# cadence; a single read after `sleep 5` raced the registration on loaded hosts.
bm_retry_nonempty AU1 10 2 aff_registry_field exec1 gateway_url || true
bm_retry_nonempty AU2 10 2 aff_registry_field exec2 gateway_url || true
aff_wait_field exec1 node_count 1 || true; NC1=$(aff_health_field exec1 node_count)
aff_wait_field exec2 node_count 1 || true; NC2=$(aff_health_field exec2 node_count)
aff_check "G1: exec1 registry gateway_url=$AU1 node_count=$NC1" \
    "$([[ "$AU1" == "https://${HOST_IP}:3000" && "$NC1" == "1" ]] && echo 1 || echo 0)" "got gateway_url=$AU1 node_count=$NC1"
aff_check "G1: exec2 registry gateway_url=$AU2 node_count=$NC2" \
    "$([[ "$AU2" == "https://${HOST_IP}:3001" && "$NC2" == "1" ]] && echo 1 || echo 0)" "got gateway_url=$AU2 node_count=$NC2"

# 2. Per-sandfs zone resolves + first exec forced to exec1 → ownership recorded.
# The DNS layer loads ownership via an ASYNC etcd watch — a single dig right
# after sandfs creation races that sync (this exact race failed the k8s boxout
# deploy once); retry until it answers.
bm_retry_nonempty DR 10 3 aff_dig_first "$AFF_HOST" || true
aff_check "per-sandfs zone resolves → $DR" "$([[ -n "$DR" ]] && echo 1 || echo 0)" "$DR"
E1=$(curl -sk --cacert "$CERT_DIR/ca.crt" --resolve "${AFF_HOST}:3000:${HOST_IP}" \
    -X POST "https://${AFF_HOST}:3000/agent/execute" \
    -H "Authorization: Bearer $AFF_KEY" -H 'Content-Type: application/json' -d "$AFF_EXEC" 2>/dev/null)
if echo "$E1" | grep -q "affinity_self_test_ok"; then
    aff_check "exec via sandfs URL on gw1 (wildcard cert + owner routing)" 1 ""
else
    aff_check "exec via sandfs URL on gw1" 0 "$(echo "$E1" | head -c 200)"
fi
OW_GW=$(aff_etcd_get "/sandswap/owner/$AFF_SF_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('gateway_id',''))" 2>/dev/null || echo "")
aff_check "sandfs owned by exec1 (gateway_id=$OW_GW)" \
    "$([[ "$OW_GW" == "exec1" ]] && echo 1 || echo 0)" "got $OW_GW"

# 3. 307 from non-owner exec2 (redirect)
LOC=$(curl -sk --cacert "$CERT_DIR/ca.crt" -o /dev/null -D - --resolve "${AFF_HOST}:3001:${HOST_IP}" \
    -X POST "https://${AFF_HOST}:3001/agent/execute" \
    -H "Authorization: Bearer $AFF_KEY" -H 'Content-Type: application/json' -d "$AFF_EXEC" 2>/dev/null | grep -i '^location:' | head -1 || true)
if echo "$LOC" | grep -q "${HOST_IP}:3000"; then
    aff_check "redirect: 307 from non-owner → $LOC" 1 ""
else
    aff_check "redirect: 307 from non-owner" 0 "$LOC"
fi

# 3b. 307 follow end-to-end: follow the redirect to the owner with the
# X-Sandswap-Api-Key header (Authorization is stripped cross-host by Go/curl) and
# verify the exec actually succeeds on the owner. --location-trusted forwards
# custom headers across the redirect.
FOLLOW=$(curl -skL --location-trusted --cacert "$CERT_DIR/ca.crt" \
    --resolve "${AFF_HOST}:3001:${HOST_IP}" --resolve "${HOST_IP}:3000:${HOST_IP}" \
    -X POST "https://${AFF_HOST}:3001/agent/execute" \
    -H "Authorization: Bearer $AFF_KEY" -H "X-Sandswap-Api-Key: $AFF_KEY" \
    -H 'Content-Type: application/json' -d "$AFF_EXEC" 2>/dev/null)
if echo "$FOLLOW" | grep -q "affinity_self_test_ok"; then
    aff_check "redirect: 307 follow + X-Sandswap-Api-Key auth -> exec on owner" 1 ""
else
    aff_check "redirect: 307 follow end-to-end" 0 "$(echo "$FOLLOW" | head -c 200)"
fi

# 4. Fault state (G1): stop exec1's sandlot → health node_count drops to 0.
# Poll for the drop (health refresh cadence ~10s; sleep 4 raced it).
systemctl stop sandswap-sandlot-instance@prod1
if aff_wait_field exec1 node_count 0 15; then NC1=0; else NC1=$(aff_health_field exec1 node_count); fi
aff_check "G1: exec1 fault after sandlot stop (node_count=$NC1)" \
    "$([[ "$NC1" == "0" ]] && echo 1 || echo 0)" "got $NC1"

# 5. G2 tolerance-first: exec2 does NOT take over while exec1 is alive.
#    Ownership is unchanged (exec1 still owns; its health key is alive), so
#    exec2 307-redirects to the owner exec1 instead of executing — no takeover
#    while the owner is healthy (see docs/how-it-works/resilience.md).
E2_CODE=$(curl -sk -o /tmp/g2-body.txt -D /tmp/g2-headers.txt -w "%{http_code}" --cacert "$CERT_DIR/ca.crt" \
    --resolve "${AFF_HOST}:3001:${HOST_IP}" \
    -X POST "https://${AFF_HOST}:3001/agent/execute" \
    -H "Authorization: Bearer $AFF_KEY" -H 'Content-Type: application/json' -d "$AFF_EXEC" 2>/dev/null)
# Location header lands in the -D headers dump (the -o body file has no headers);
# grep exits 1 on no match — guard so `set -e` doesn't kill the script (a 503
# response with no Location is a valid failure signal we must report, not crash on).
E2_LOC=$(grep -i '^location:' /tmp/g2-headers.txt 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)
if [[ "$E2_CODE" == "307" ]] && [[ "$E2_LOC" == *"https://${HOST_IP}:3000/agent/execute" ]]; then
    aff_check "G2: exec2 307 → owner exec1 while exec1 fault (no takeover while owner alive)" 1 ""
else
    aff_check "G2: exec2 redirect to owner exec1 (307) — got code=$E2_CODE loc=$E2_LOC" 0 ""
fi

# 6. Recovery: start exec1's sandlot → node_count back to 1 (poll, not a bet)
systemctl start sandswap-sandlot-instance@prod1
if aff_wait_field exec1 node_count 1 20; then NC1=1; else NC1=$(aff_health_field exec1 node_count); fi
aff_check "recovery: exec1 node_count back to 1 (node_count=$NC1)" \
    "$([[ "$NC1" == "1" ]] && echo 1 || echo 0)" "got $NC1"

if [[ "$AFF_FAIL" == "1" ]]; then
    err "Affinity self-test FAILED — see above"
fi
log "Affinity self-test PASSED (registry/redirect/owner-aware DNS/G1/G2)"

log "============================================"
log "  Production cluster simulation complete!"
log "  etcd + 2 exec GW + human GW + 2 sandlots + DNS"
log "============================================"
