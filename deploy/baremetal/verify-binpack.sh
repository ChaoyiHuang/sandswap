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
# verify-binpack.sh - DNS binpack concentration verification on a real topology.
# Proves that two external eino agents binpack onto ONE gateway: the DNS layer
# (policy=binpack) resolves each new/unowned sandfs's per-sandfs zone to the
# BUSIEST healthy gateway (highest agg_duty_long), so once one gateway has duty
# the next sandfs lands on the same gateway instead of spreading.
# Topology (single host, two loopback IPs so both gateways share the port, like
# verify-failover.sh):
#   etcd (127.0.0.1:2379)
#   exec1: 127.0.0.1:3000/9998   exec2: 127.0.0.2:3000/9998   human: 127.0.0.1:3100
#   sandns :53 (gateways = both loopback IPs, policy=binpack)
#   sandlot prod1 -> exec1 (127.0.0.1:9998), sandlot prod2 -> exec2 (127.0.0.2:9998)
#   2 eino instances (single-agent), each its own agent+sandfs.
# Why a load generator: binpack scores gateways by agg_duty_long (sync-exec duty
# EWMA). With both gateways idle (duty 0) the first sandfs lands on an arbitrary
# gateway (tie-break) and the second would be a coin flip - not reliable
# concentration. So we run a sustained sync exec on exec1 first to raise its
# duty, making exec1 the unambiguous binpack target. Both eino sandfs then
# resolve to exec1. This mirrors production: real workloads on one gateway make
# binpack pack new sandfs onto it.
# spec: small (1 vcpu / 128MB), pool small:3 per node (1 busy + clean headroom).
# Usage: sudo bash verify-binpack.sh [--skip-build]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/deploy-lib.sh"

OUTPUT="$REPO_ROOT/output"
CERT_DIR="${SANDSWAP_ETC}/certs-binpack"
RUN_DIR="/run/sandswap-binpack"
LOG_DIR="/tmp/sandswap-binpack-logs"
ETCD_PID=""
LOAD_PID=""
EINO_BIN="/tmp/sandswap-eino-binpack"
# Did a seed already exist before this drill? Its private topology BORROWS the
# production seed path, and a leftover test seed is what a later deployment's
# mint-once rule would happily adopt — so cleanup removes only what we minted.
SEED_PREEXISTED=0
[[ -e "${SANDSWAP_ETC}/volume-seed" ]] && SEED_PREEXISTED=1
ETCDCTL=$(command -v etcdctl || echo "$OUTPUT/etcd/etcdctl")

SKIP_BUILD=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help) echo "Usage: $0 [--skip-build]"; exit 0 ;;
        *) err "Unknown argument: $1" ;;
    esac
done

# Preflight BEFORE deploying the topology: the two eino agents need an LLM key.
# A missing key used to surface only after a full deploy as three downstream
# [FAIL]s — early and named beats late and mysterious.
if [[ -z "${DEEPSEEK_API_KEY:-}" && -z "${OPENAI_API_KEY:-}" && -z "${GOOGLE_API_KEY:-}" ]]; then
    err "no LLM API key set: the eino agents need DEEPSEEK_API_KEY (or OPENAI/GOOGLE); run: sudo env DEEPSEEK_API_KEY=sk-... bash $0"
fi
[[ $EUID -ne 0 ]] && err "This script must be run as root"

BP_FAIL=0
bp_check() { # <name> <pass|fail> <detail>
    if [[ "$2" == "1" ]]; then echo "  [PASS] $1"; else echo "  [FAIL] $1 - ${3:-?}"; BP_FAIL=1; fi
}
etcd_get() { "$ETCDCTL" --endpoints=http://127.0.0.1:2379 get "$1" --print-value-only 2>/dev/null || echo ""; }
health_field() { etcd_get "/sandswap/health/$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" 2>/dev/null || echo ""; }
load_field()   { etcd_get "/sandswap/load/$1"   | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" 2>/dev/null || echo ""; }
owner_gw()     { etcd_get "/sandswap/owner/$1"  | python3 -c "import sys,json; print(json.load(sys.stdin).get('gateway_id',''))" 2>/dev/null || echo ""; }

pre_clean() {
    # SAFETY GUARD (before ANY pkill): these patterns match the INSTALLED
    # binary paths, i.e. a production deployment's processes. Refuse on a host
    # with a live deployment — this script builds a PRIVATE topology and is only
    # sound on a quiet host.
    local active=""
    while read -r u; do
        [[ -n "$u" ]] || continue
        systemctl is-active --quiet "$u" 2>/dev/null && active+="$u "
    done <<'UNITS'
sandswap-gateway.service
sandswap-gateway@exec.service
sandswap-gateway@human.service
sandswap-sandlot.service
sandswap-sandlot-prov.service
sandswap-sandns.service
sandswap-sandlot-instance@sl1.service
sandswap-sandlot-instance@sl2.service
sandswap-sandlot-instance@prod1.service
sandswap-sandlot-instance@prod2.service
UNITS
    # Any other enabled @-instance also counts.
    if [[ -z "$active" ]]; then
        active="$(systemctl list-units --type=service --state=active --no-legend 'sandswap-sandlot-instance@*' 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
    fi
    if [[ -n "${active// /}" ]]; then
        echo "error: a sandswap deployment is ACTIVE on this host ($active) — this script is destructive (it pkills the installed sandswap binaries)." >&2
        echo "       Run it on a dedicated host, or stop/uninstall the deployment first." >&2
        exit 1
    fi
    for svc in sandswap-gateway-bp1 sandswap-gateway-bp2 sandswap-gateway-bph sandswap-sandns-bp \
               sandswap-sandlot-bp1 sandswap-sandlot-bp2 sandswap-sandlot-prov-bp; do
        systemctl stop "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
    systemctl daemon-reload 2>/dev/null || true
    # -x never matches sandswap-gateway/sandlot (comm truncated to 15 chars);
    # etcd scoped to OUR instances so an unrelated host etcd is never killed.
    pkill -9 -f '/usr/local/bin/sandswap-gateway' 2>/dev/null || true
    pkill -9 -f '/usr/local/bin/sandswap-sandlot' 2>/dev/null || true
    pkill -9 -x sandns 2>/dev/null || true
    pkill -9 -f 'sandswap-.*etcd' 2>/dev/null || true
    pkill -9 -f 'sandswap-sandvmm' 2>/dev/null || true
    sleep 1
    rm -rf "$RUN_DIR" /tmp/sandswap-binpack-etcd
    # Clear stale sandlot persisted state (gateway-state.json / cleanup-state.json)
    # from prior runs that reused instance ids prod1/prod2 (e.g. multi-gw-sim).
    # Otherwise a stale LastGatewayIP + tolerating phase makes the sandlot refuse
    # to connect to this run's gateway ("preferred gateway X not in DNS").
    rm -rf /run/sandswap/instance-prod1 /run/sandswap/instance-prod2 /run/sandswap-state/prod1 /run/sandswap-state/prod2
    # A volumes tree with no seed is unnameable: the prov startup guard
    # refuses a generation the configured seed does not derive (this drill
    # mints its own seed below). Remove the stale tree so the fresh seed owns
    # it. A preexisting seed is left untouched — the tree belongs to it.
    if [[ ! -e "$SANDSWAP_ETC/volume-seed" ]]; then
        rm -rf "${SANDSWAP_VAR:?}/volumes"/* 2>/dev/null || true
    fi
    # Stale /etc/hosts entries from the local production sim pin sandswap.local to
    # HOST_IP and would bypass DNS; remove them so dig @127.0.0.1 is authoritative.
    sed -i '/sandswap\.local\|sandswap-stream\.local/d' /etc/hosts 2>/dev/null || true
}
pre_clean

cleanup() {
    log "cleanup..."
    [[ -n "$LOAD_PID" ]] && kill "$LOAD_PID" 2>/dev/null || true
    for svc in sandswap-gateway-bp1 sandswap-gateway-bp2 sandswap-gateway-bph sandswap-sandns-bp \
               sandswap-sandlot-bp1 sandswap-sandlot-bp2 sandswap-sandlot-prov-bp; do
        systemctl stop "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
    systemctl daemon-reload 2>/dev/null || true
    pkill -9 -f 'sandswap-sandvmm' 2>/dev/null || true
    [[ -n "$ETCD_PID" ]] && kill "$ETCD_PID" 2>/dev/null || true
    rm -f "$EINO_BIN" 2>/dev/null || true
    rm -rf /run/sandswap/instance-prod1 /run/sandswap/instance-prod2 /run/sandswap-state/prod1 /run/sandswap-state/prod2
    rm -rf "$RUN_DIR" /tmp/sandswap-binpack-etcd "$LOG_DIR"
    # This drill's OWN residue: its private cert dir, and the borrowed seed only
    # when the drill minted it (never touch a seed that was already there).
    rm -rf "$CERT_DIR"
    if [[ "${SEED_PREEXISTED:-0}" == "0" ]]; then
        rm -f "${SANDSWAP_ETC}/volume-seed"
        # pre_clean removed any nameless tree before the mint, so every
        # volume here was created under this run's seed. Leaving them behind
        # makes the next run's fresh seed collide with their generation and
        # the prov instance refuses to start (startup guard).
        rm -rf "${SANDSWAP_VAR:?}/volumes"/* 2>/dev/null || true
    fi
    log "cleanup done"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ── Sequencing guard (order is part of the contract) ────────────────────
# This script builds its own PRIVATE topology (etcd 2379, exec1 127.0.0.1:3000,
# exec2 127.0.0.2:3000, human 3100, dns :53) and is only sound on a QUIET host.
# A foreign sandswap deployment holding these ports either kills the dns start
# silently or lets the health checks answer against the WRONG processes (silent
# false green). Refuse loudly and name the cleanup. Binpack also drives eino
# agents, so the LLM key is a hard prerequisite here.
# BM_REQUIRE_LLM is a cross-file global consumed by bm_preflight (deploy-lib.sh).
# shellcheck disable=SC2034
BM_REQUIRE_LLM=1
BM_PORTS="3000 3100 9998 9997 2379" bm_preflight
# systemd-resolved's stub listeners (127.0.0.53/54:53) coexist fine with a
# wildcard dns bind — only a non-stub holder actually blocks us.
port53_holders="$( { ss -H -ulnp 'sport = :53'; ss -H -tlnp 'sport = :53'; } 2>/dev/null | grep -vE '127\.0\.0\.5[34]|\[::1\]:53|127\.0\.0\.1:53' | grep -oE 'pid=[0-9]+' | sort -u | tr '\n' ' ' || true)"
if [[ -n "${port53_holders// /}" ]]; then
    err "port 53 already held by PID(s): ${port53_holders} — another dns (usually a kept sandswap deployment) owns it. Run: bash deploy/baremetal/uninstall.sh (or cleanup.sh), then retry"
fi

# ──── [1/10] Build ────
if [[ $SKIP_BUILD -eq 0 ]]; then
    # Freshness-gated: an unconditional `build.sh all` re-stamps every
    # artifact on every run, which churns artifact identity and invalidates
    # every recorded matrix verdict even when nothing changed. A green check
    # means the build would be a no-op — only build when something is stale.
    if bash "$REPO_ROOT/build/build.sh" check >/dev/null 2>&1; then
        log "[1/10] Artifacts fresh (build.sh check green) — skipping rebuild"
    else
        log "[1/10] Building artifacts..."
        bash "$REPO_ROOT/build/build.sh" all
    fi
else
    log "[1/10] Skipping build"
fi

# ──── [2/10] Certs (loopback IPs + per-sandfs wildcard) ────
# One client pair PER NODE ID: this drill runs two exec sandlots whose
# EFFECTIVE node ids are `bp-prod<i>-prod<i>` (config node_id `bp-prod<i>`
# plus the instance id the config carries — the sandlot composes the suffix
# before the hello) and one prov instance (`bp-prov`). The gateway binds
# hello.node_id == the client cert's CN by exact match, so each needs its own
# pair; the first exec node rides the primary pair.
log "[2/10] Generating certs (127.0.0.1, 127.0.0.2 + wildcard, one pair per node id)..."
BP_NODE_IDS=("bp-prod1-prod1" "bp-prod2-prod2")
BP_PROV_NODE_ID="bp-prov"
BP_PROV_CERT_BASE="sandlot-${BP_PROV_NODE_ID}"
SANDLOT_NODE_ID="${BP_NODE_IDS[0]}" \
    bash "$SCRIPT_DIR/gen-baremetal-certs.sh" "$OUTPUT/binpack-certs" \
    --sans-dns "sandswap.local,sandswap-stream.local,*.sandfs.sandswap.local" \
    --sans-ip "127.0.0.1,127.0.0.2" \
    --client-cn "${BP_NODE_IDS[1]}:exec" \
    --client-cn "${BP_PROV_NODE_ID}:prov" >/dev/null 2>&1
mkdir -p "$CERT_DIR"
cp "$OUTPUT/binpack-certs"/* "$CERT_DIR/"
# Scope each key to ONLY the identity that loads it (gateways run as the
# sandserv user, sandlots as the sandlot user) — 0600 root keys would make
# every service fail its TLS setup.
ss_own_tls_keys "$CERT_DIR"
# Assert the CN of every pair equals the node id that will declare it — the
# gateway refuses a mismatch by name at the handshake, and this drill would
# otherwise fail much later with no hint of the cause.
sandswap_verify_client_cert_cn "$CERT_DIR/sandlot.crt" "${BP_NODE_IDS[0]}" || err "primary pair CN mismatch"
sandswap_verify_client_cert_cn "$CERT_DIR/sandlot-${BP_NODE_IDS[1]}.crt" "${BP_NODE_IDS[1]}" || err "prod2 pair CN mismatch"
sandswap_verify_client_cert_cn "$CERT_DIR/${BP_PROV_CERT_BASE}.crt" "$BP_PROV_NODE_ID" || err "prov pair CN mismatch"

# ──── [3/10] etcd ────
log "[3/10] Starting etcd..."
rm -rf /tmp/sandswap-binpack-etcd
ETCD_BIN=$(command -v etcd || echo "$OUTPUT/etcd/etcd")
[[ -x "$ETCD_BIN" ]] || err "etcd binary not found (need output/etcd/etcd or system etcd)"
"$ETCD_BIN" --name binpack-etcd --data-dir /tmp/sandswap-binpack-etcd \
    --listen-client-urls http://127.0.0.1:2379 --advertise-client-urls http://127.0.0.1:2379 \
    --listen-peer-urls http://127.0.0.1:2380 --initial-advertise-peer-urls http://127.0.0.1:2380 \
    --initial-cluster binpack-etcd=http://127.0.0.1:2380 --initial-cluster-token ss-bp \
    --initial-cluster-state new --log-level warn >/tmp/binpack-etcd.log 2>&1 &
ETCD_PID=$!
sleep 2
curl -s http://127.0.0.1:2379/health >/dev/null || err "etcd failed to start"

# ──── [4/10] Flat template + binaries ────
log "[4/10] Installing binaries + flat template..."
# Runtime dirs for the DEDICATED IDENTITIES: /run/sandswap 3770 root:sandlot
# sticky (`ss_prepare_dirs`; the sandlot instances create instance-prod*/ under it) + the share root
# sandprov:sandlot 2710 (prov seeds volumes; sandlot/sandvmm traverse it and
# serve the volumes group-rw — the root itself is closed to them).
# SS_PROV_USER=sandprov: this drill runs a DEDICATED prov identity, and
# ss_prepare_dirs otherwise defaults the volumes owner to sandlot (the merged
# dev shape) — every volume create then dies mkdir EACCES in the prov instance.
SS_PROV_USER=sandprov ss_prepare_dirs
mkdir -p "$RUN_DIR"
# Always re-seed: prior deploys can leave bin/sbin/lib as symlinks, which
# `cp -a` cannot overwrite with directories.
rm -rf "$SANDSWAP_VAR/flat-templates/rootfs/v1"
mkdir -p "$SANDSWAP_VAR/flat-templates/rootfs/v1"
cp -a "$OUTPUT/rootfs-template/." "$SANDSWAP_VAR/flat-templates/rootfs/v1/"
# Template contract: content normalized through the shared group by the
# canonical tool (docs/operations/template-contract.md); the ROOT is
# prov-owned and read-only for everyone else — the FUSE daemon reads flat
# template content when seeding volumes and must never be able to modify it.
# Never rely on the seeder's umask; never widen to world-readable.
chown "${SS_PROV_USER:-sandprov}":"$SS_SHARED_GROUP" "$SANDSWAP_VAR/flat-templates"
chmod 2750 "$SANDSWAP_VAR/flat-templates"
TEMPLATE_TOOL="$REPO_ROOT/output/template-tool"
[[ -x "$TEMPLATE_TOOL" ]] || { log_error "output/template-tool missing — run: bash build/build.sh go"; exit 1; }
chgrp -R "$SS_SHARED_GROUP" "$SANDSWAP_VAR/flat-templates/rootfs"
"$TEMPLATE_TOOL" normalize "$SANDSWAP_VAR/flat-templates/rootfs"
sandswap_install_binary "$OUTPUT/gateway" "$SANDSWAP_BIN/sandswap-gateway" >/dev/null 2>&1
sandswap_install_binary "$OUTPUT/sandlot" "$SANDSWAP_BIN/sandswap-sandlot" >/dev/null 2>&1
sandswap_install_binary "$OUTPUT/sandvmm" "$SANDSWAP_BIN/sandswap-sandvmm" >/dev/null 2>&1
sandswap_install_binary "$OUTPUT/sandns" "$SANDSWAP_BIN/sandns" >/dev/null 2>&1
cp "$OUTPUT/vmlinux.bin" "$SANDSWAP_VAR/" 2>/dev/null || true
cp "$OUTPUT/initramfs.cpio.gz" "$SANDSWAP_VAR/" 2>/dev/null || true

# This script does NOT run setup-host.sh (unlike the cluster simulations) —
# repair the per-owner vsock device modes explicitly or sandlot's startup
# owner-check fails fast on a stale node (module reload / pre-split host).
sandswap_setup_dev_nodes
# Refresh the resolved-identity env (an uninstall removes it; the sandlot
# units' EnvironmentFile below consumes it). Idempotent when users exist.
ss_ensure_service_users >/dev/null 2>&1 || true

write_unit() { # <name> <binary> <config> — GATEWAY units (dedicated identity:
    # sandserv user + sandlot shared group, mirroring sandswap-gateway.service)
    cat > "/etc/systemd/system/$1.service" << EOF
[Unit]
Description=Sandswap ($1)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=sandserv
ExecStart=$SANDSWAP_BIN/$2 -config $3
Restart=no
KillMode=process
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$1
[Install]
WantedBy=multi-user.target
EOF
}

# ──── [5/10] 2 exec gateways + human gateway ────
log "[5/10] Starting exec1 (127.0.0.1:3000), exec2 (127.0.0.2:3000), human (3100)..."
for i in 1 2; do
    ip="127.0.0.$i"
    cat > "$RUN_DIR/gw-exec${i}.yaml" << YAML
mode: exec
gateway_id: exec${i}
gateway_url: "https://${ip}:3000"
gateway_stream_addr: "${ip}:9998"
idle_timeout_sec: 3600
vol_root: ${SANDSWAP_VAR}/volumes
etcd: "http://127.0.0.1:2379"
agent:
  addr: "${ip}:3000"
  tls_cert: ${CERT_DIR}/mcp.crt
  tls_key: ${CERT_DIR}/mcp.key
stream:
  addr: "${ip}:9998"
  tls_cert: ${CERT_DIR}/stream.crt
  tls_key: ${CERT_DIR}/stream.key
  tls_ca: ${CERT_DIR}/ca.crt
lease: { sticky_ms: 100, max_sticky_sec: 5 }
exec: { default_timeout_sec: 30, max_timeout_sec: 180 }
YAML
    write_unit "sandswap-gateway-bp${i}" "sandswap-gateway" "$RUN_DIR/gw-exec${i}.yaml"
done
cat > "$RUN_DIR/gw-human.yaml" << YAML
mode: human
vol_root: ${SANDSWAP_VAR}/volumes
etcd: "http://127.0.0.1:2379"
human:
  addr: "127.0.0.1:3100"
  tls_cert: ${CERT_DIR}/human.crt
  tls_key: ${CERT_DIR}/human.key
# The human gateway listens for PROV instances on a dedicated port: 9998/9997
# belong to the two exec gateways. (Split deployments must give the human
# gateway a stream port that no exec gateway holds.) TLS mirrors the exec
# gateways' stream listener — the prov client dials with mTLS.
stream:
  addr: "127.0.0.1:9996"
  tls_cert: ${CERT_DIR}/stream.crt
  tls_key: ${CERT_DIR}/stream.key
  tls_ca: ${CERT_DIR}/ca.crt
YAML
cat > /etc/systemd/system/sandswap-gateway-bph.service << EOF
[Unit]
Description=Sandswap (human)
After=network-online.target
[Service]
Type=simple
User=sandserv
# this drill configures no OIDC issuer, and the human listener now
# refuses to start without an explicit anonymous opt-out (same flag the
# shipped systemd templates carry).
ExecStart=$SANDSWAP_BIN/sandswap-gateway -config $RUN_DIR/gw-human.yaml -allow-anonymous-human
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sandswap-gateway-bph
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl reset-failed sandswap-gateway-bp1 sandswap-gateway-bp2 sandswap-gateway-bph 2>/dev/null || true
systemctl start sandswap-gateway-bp1 sandswap-gateway-bp2 sandswap-gateway-bph
sleep 3
curl -sk https://127.0.0.1:3000/health >/dev/null || err "exec1 not healthy"
curl -sk https://127.0.0.2:3000/health >/dev/null || err "exec2 not healthy"
curl -sk https://127.0.0.1:3100/health >/dev/null || err "human not healthy"
log "  3 gateways healthy"

# ──── [6/10] sandns (binpack) ────
log "[6/10] Starting sandns (policy=binpack)..."
cat > "$RUN_DIR/sandns.yaml" << YAML
listen_addr: "0.0.0.0:53"
# Sandbox guest ranges: a foreign-zone query from these sources is REFUSED
# (no open recursive relay behind the host egress identity). Update if the
# sandlot subnet is not the default.
guest_cidrs: ["10.188.0.0/16"]
domains:
  stream: sandswap-stream.local
  sandfs: sandfs.sandswap.local
etcd: "http://127.0.0.1:2379"
ttl: 5
sticky_expire: 1800
sticky_sync_interval: 5
sticky_sync_batch: 256
scheduling:
  policy: binpack
  duty_hard: 0.85
forwarders:
  - 8.8.8.8:53
YAML
cat > /etc/systemd/system/sandswap-sandns-bp.service << 'EOF'
[Unit]
Description=Sandswap DNS (binpack e2e)
After=network-online.target
[Service]
Type=simple
User=sandserv
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sandns -config /run/sandswap-binpack/sandns.yaml
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sandswap-sandns-bp
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl reset-failed sandswap-sandns-bp 2>/dev/null || true
systemctl start sandswap-sandns-bp
sleep 2
# Fail LOUDLY if the dns process died at startup (e.g. :53 grabbed between the
# preflight and here) instead of letting the dig loop expire unread.
systemctl is-active --quiet sandswap-sandns-bp \
    || err "sandswap-sandns-bp died at startup — port 53 conflict? Diagnose: journalctl -u sandswap-sandns-bp --no-pager | tail -20"
# Retry loop: the registry arrives via an async etcd watch, and a miss can
# forward upstream (dig times out non-zero — || true keeps set -o pipefail
# from killing the script silently before the err below can speak).
DR=""
for i in $(seq 1 10); do
    DR=$(dig @127.0.0.1 sandswap-stream.local +short +time=2 +tries=1 2>/dev/null | head -1 || true)
    [[ "$DR" == "127.0.0.1" || "$DR" == "127.0.0.2" ]] && break
    sleep 3
done
[[ "$DR" == "127.0.0.1" || "$DR" == "127.0.0.2" ]] || err "dns did not resolve stream domain (got '$DR')"
log "  dns resolves sandswap-stream.local -> $DR (binpack policy active)"

# ──── [7/10] 2 sandlots (pinned: prod1->exec1, prod2->exec2), pool small:3 ────
log "[7/10] Starting 2 sandlots (small:3 each, pinned to their gateway)..."
# Always re-run the idempotent host prep: an existing br-sandswap from a prior
# deployment can lack the current `inet sandswap input/forward` chains.
bash "$REPO_ROOT/deploy/setup-network.sh" >/dev/null 2>&1 \
    || err "host network prep failed (deploy/setup-network.sh)"
for i in 1 2; do
    ip="127.0.0.$i"
    inst="prod${i}"
    cid_start=$((3 + (i - 1) * 100))
    cid_end=$((cid_start + 99))
    cat > "$RUN_DIR/sandlot-${inst}.yaml" << YAML
gateway_addr: "${ip}:9998"
node_id: "bp-${inst}"
vm_mode: embedded
vmm_binary: ${SANDSWAP_BIN}/sandswap-sandvmm
microvm:
  kernel: ${SANDSWAP_VAR}/vmlinux.bin
  initramfs: ${SANDSWAP_VAR}/initramfs.cpio.gz
  default_vcpus: 1
  default_memory_mb: 128
  volumes_dir: ${SANDSWAP_VAR}/volumes
specs:
  small:  { vcpus: 1, memory_mb: 128, exec_slots: 1 }
pool: "small:3"
recycle: { mem_percent: 10, mem_abs_mb: 100 }
network:
  backend: bridge
  bridge: br-sandswap
  subnet: 10.189.${i}.0/24
  gateway: 10.189.${i}.1
  dns: "1.1.1.1"
instance:
  id: ${inst}
  base_dir: /run/sandswap/instance-${inst}
  cid_range_start: ${cid_start}
  cid_range_end: ${cid_end}
tls:
  # The pair whose CN is THIS instance's effective node id (bp-${inst}-${inst}).
  cert: ${CERT_DIR}/$([[ "$i" == "1" ]] && echo sandlot || echo "sandlot-${BP_NODE_IDS[$((i - 1))]}").crt
  key: ${CERT_DIR}/$([[ "$i" == "1" ]] && echo sandlot || echo "sandlot-${BP_NODE_IDS[$((i - 1))]}").key
  ca: ${CERT_DIR}/ca.crt
YAML
    cat > /etc/systemd/system/sandswap-sandlot-bp${i}.service << EOF
[Unit]
Description=Sandswap Sandlot ${inst} (binpack e2e)
After=network-online.target
ConditionPathExists=/dev/kvm
[Service]
Type=simple
# Dedicated identity (mirrors sandswap-sandlot.service): sandlot user, NOT
# root — vsockguard pins the warden vsock port to the sandlot UID with no
# uid-0 exemption, so a root sandlot is denied every connect() and every VM
# fails "warden did not become ready".
#   CAP_SETUID/SETGID  — spawn sandvmm as the dedicated VMM identity (uid 987);
#                        startup fail-fasts without them (checkCapsForVMMSpawn)
#   CAP_KILL           — cross-uid SIGKILL of sandvmm (destroy/teardown paths)
User=sandlot
SupplementaryGroups=kvm
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_KILL
# The resolved service identities flow in here (occupied-slot auto-pick on
# GCP-style hosts): without it the binary's contract defaults (vmm_uid 987)
# would mismatch the actual device owners and the start would fail-fast.
EnvironmentFile=-/etc/sandswap/identity.env
# -allow-colocated-instances: this test runs TWO sandlots on one host
# (binpack simulation class) — the one-sandlot-per-host role lock is bypassed
# for it, matching the cluster-simulation scripts.
ExecStart=$SANDSWAP_BIN/sandswap-sandlot -config $RUN_DIR/sandlot-${inst}.yaml -allow-colocated-instances -allow-missing-vsockguard
Restart=no
KillMode=process
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sandswap-sandlot-bp${i}
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
done
# ── Provision instance (storage plane) ───────────────────────────────
# One prov-role sandlot dialing the HUMAN gateway's stream (:9996). The two
# exec sandlots above cannot carry the storage plane: each is pinned to its
# own EXEC gateway, where a prov half would be unroutable.
# Dedicated-prov shape: say so, or the helper defaults SS_PROV_USER=sandlot
# and the store lands sandlot-owned — the sandprov writer would hold only r-x.
SS_PROV_USER=sandprov sandswap_prepare_provision_host "$SANDSWAP_VAR/templates" "$CERT_DIR" "$BP_PROV_CERT_BASE"
cat > "$RUN_DIR/sandlot-prov.yaml" << YAML
gateway_addr: "127.0.0.1:9996"
node_id: "${BP_PROV_NODE_ID}"
roles: [prov]
microvm:
  volumes_dir: ${SANDSWAP_VAR}/volumes
provision:
  flat_templates_dir: ${SANDSWAP_VAR}/flat-templates
  volume_seed_file: ${SANDSWAP_ETC}/volume-seed
network:
  backend: none
tls:
  # The prov node's own pair (cert CN == node_id; the key half is the
  # sandprov-owned prov.key copy derived above).
  cert: ${CERT_DIR}/${BP_PROV_CERT_BASE}.crt
  key: ${CERT_DIR}/prov.key
  ca: ${CERT_DIR}/ca.crt
YAML
cat > /etc/systemd/system/sandswap-sandlot-prov-bp.service << EOF
[Unit]
Description=Sandswap (prov, binpack e2e)
After=network-online.target
[Service]
Type=simple
# The provision identity: shared-storage group only (no caps, no kvm, no
# vsock) — the storage plane's least-privilege shape.
User=sandprov
SupplementaryGroups=sandlot
# The resolved service identities flow in here (occupied-slot auto-pick on
# GCP-style hosts): the prov process reads SANDSWAP_PROV_GID / SANDSWAP_TPL_GROUP
# from it, and the binary contract defaults would silently mismatch a
# host-resolved identity.
EnvironmentFile=-/etc/sandswap/identity.env
ExecStart=$SANDSWAP_BIN/sandswap-sandlot -config $RUN_DIR/sandlot-prov.yaml -allow-colocated-instances -allow-missing-vsockguard
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sandswap-sandlot-prov-bp
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl reset-failed sandswap-sandlot-bp1 sandswap-sandlot-bp2 sandswap-sandlot-prov-bp 2>/dev/null || true
systemctl start sandswap-sandlot-bp1 sandswap-sandlot-bp2 sandswap-sandlot-prov-bp

log "[8/10] Waiting for both sandlots to connect..."
NC1=""; NC2=""
for _ in $(seq 1 40); do
    sleep 2
    NC1=$(health_field exec1 node_count)
    NC2=$(health_field exec2 node_count)
    [[ "$NC1" == "1" && "$NC2" == "1" ]] && break
done
[[ "$NC1" == "1" && "$NC2" == "1" ]] || err "sandlots did not both connect (nc1=$NC1 nc2=$NC2). Logs: journalctl -u sandswap-sandlot-bp1 -u sandswap-sandlot-bp2"
log "  prod1->exec1, prod2->exec2 (both node_count=1)"

# Wait for clean VMs to publish in the load keys (capacity gate needs clean_vms>0).
log "  waiting for clean VMs to publish..."
for _ in $(seq 1 30); do
    sleep 2
    C1=$(load_field exec1 clean_vms); C2=$(load_field exec2 clean_vms)
    [[ "$C1" -ge 1 && "$C2" -ge 1 ]] 2>/dev/null && break
done
log "  clean_vms: exec1=${C1:-0} exec2=${C2:-0}"
# The connect loop above errs on timeout; this one must too — proceeding with
# 0 clean VMs just produces confusing downstream failures (capacity gate).
[[ "${C1:-0}" -ge 1 && "${C2:-0}" -ge 1 ]] 2>/dev/null \
    || err "clean VMs never published (exec1=$C1 exec2=$C2). Logs: journalctl -u sandswap-sandlot-bp1 -u sandswap-sandlot-bp2"

# The sandfs creates go through the human gateway's storage plane, which is
# served by the separate prov instance: the exec sandlots' node_count says
# nothing about it. Creating before it registers returns
# "storage plane unavailable: no provision instance connected" (a timing race
# seen live in the matrix run — the same gate the other deploy scripts use).
log "  waiting for the storage plane (provisioners)..."
PROV_UP=0
# 90s: systemd may start the prov unit well after the two exec sandlots (the
# 30s window was too tight on a loaded host).
for _ in $(seq 1 90); do
    sleep 1
    curl -sk https://127.0.0.1:3100/health 2>/dev/null \
        | grep -qE '"provisioners":[[:space:]]*[1-9]' && { PROV_UP=1; break; }
done
[[ "$PROV_UP" == "1" ]] \
    || err "provision instance did not register on the human gateway (health.provisioners<1). Logs: journalctl -u sandswap-sandlot-prov-bp"
log "  storage plane ready (provisioners >= 1)"

# ──── [9/10] Create agents + sandfs; pre-load exec1; run 2 eino instances ────
log "[9/10] Creating 3 agents + 3 sandfs (load, A, B) via human gateway..."
HUMAN="https://127.0.0.1:3100"
mk_agent() { curl -sk -X POST "$HUMAN/human/agent" -H 'Content-Type: application/json' -d "{\"name\":\"$1\"}" || echo '{}'; }
mk_sandfs() { # <agent_id> <name>
    curl -sk -X POST "$HUMAN/human/sandfs" -H 'Content-Type: application/json' \
        -d "{\"agent_id\":\"$1\",\"name\":\"$2\",\"description\":\"binpack e2e\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}" || echo '{}'
}
LOAD_AGENT=$(mk_agent bp-load); LOAD_KEY=$(echo "$LOAD_AGENT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null)
LOAD_ID=$(echo "$LOAD_AGENT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null)
A_AGENT=$(mk_agent bp-a);     A_KEY=$(echo "$A_AGENT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null)
A_ID=$(echo "$A_AGENT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null)
B_AGENT=$(mk_agent bp-b);     B_KEY=$(echo "$B_AGENT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null)
B_ID=$(echo "$B_AGENT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null)
[[ -z "$LOAD_KEY" || -z "$A_KEY" || -z "$B_KEY" ]] && err "failed to create agents: load=$LOAD_AGENT a=$A_AGENT b=$B_AGENT"
# Keep the RAW bodies: a named refusal (503 storage plane / 422 unknown
# template) must be visible in the failure line, not collapse into an empty
# field (e2e lesson: dump the body on a parse miss — the earlier one-liner
# printed `load= a= b=` and hid the actual refusal).
LOAD_SF_BODY=$(mk_sandfs "$LOAD_ID" bp-load-sandfs)
A_SF_BODY=$(mk_sandfs "$A_ID" bp-sandfs-a)
B_SF_BODY=$(mk_sandfs "$B_ID" bp-sandfs-b)
sid_of() { echo "$1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || true; }
LOAD_SF=$(sid_of "$LOAD_SF_BODY"); A_SF=$(sid_of "$A_SF_BODY"); B_SF=$(sid_of "$B_SF_BODY")
if [[ -z "$LOAD_SF" || -z "$A_SF" || -z "$B_SF" ]]; then
    err "failed to create sandfs: load=$LOAD_SF a=$A_SF b=$B_SF
       bodies: load=$(echo "$LOAD_SF_BODY" | head -c 200)
               a=$(echo "$A_SF_BODY" | head -c 200)
               b=$(echo "$B_SF_BODY" | head -c 200)"
fi
log "  load=$LOAD_SF  A=$A_SF  B=$B_SF"
# etcd watch propagation to exec gateways: verify by CONDITION (the key
# actually resolving on exec1) instead of a fixed sleep. The old `sleep 5` bet
# failed silently here — the pre-load exec below would 401, die quietly, and
# the run only died 90s later with a confusing "duty did not rise" error.
if ! bm_verify_watch_sync "https://127.0.0.1:3000" "$LOAD_KEY" 15; then
    err "exec1 cannot resolve the created API keys (etcd watch sync)"
fi

# Pre-load exec1: a sustained SYNC exec on the load sandfs, pinned to exec1. Runs
# in the background of this script; keeps exec1's duty elevated so binpack picks
# exec1 for the new eino sandfs. small:3 -> 1 VM busy here + 2 clean for eino.
log "  pre-loading exec1 (sustained sync exec on load sandfs -> exec1)..."
mkdir -p "$LOG_DIR"
curl -sk -X POST "https://127.0.0.1:3000/agent/execute" \
    -H "Authorization: Bearer $LOAD_KEY" -H 'Content-Type: application/json' \
    -d "{\"sandfs_id\":\"$LOAD_SF\",\"code\":\"sleep 200\",\"language\":\"shell\",\"timeout\":210}" \
    > "$LOG_DIR/load-exec.out" 2>&1 &
LOAD_PID=$!

# Wait for exec1's agg_duty_long to clearly exceed exec2's (duty_long EWMA, τ=5min,
# converges over ~30-60s). exec2 stays 0 (no execs).
log "  waiting for exec1 duty > exec2 duty (binpack signal)..."
DUTY_OK=0
for _ in $(seq 1 45); do
    sleep 2
    D1=$(load_field exec1 agg_duty_long); D2=$(load_field exec2 agg_duty_long)
    # Compare as floats; exec1 strictly greater AND a small floor for a clear margin.
    python3 -c "import sys; sys.exit(0 if (float('$D1' or 0) > float('$D2' or 0) and float('$D1' or 0) > 0.02) else 1)" 2>/dev/null && { DUTY_OK=1; break; }
done
D1=$(load_field exec1 agg_duty_long); D2=$(load_field exec2 agg_duty_long)
log "  duty: exec1=${D1} exec2=${D2} (ok=$DUTY_OK)"
[[ "$DUTY_OK" == "1" ]] || err "exec1 duty did not rise above exec2 (d1=$D1 d2=$D2). Check load exec: $LOG_DIR/load-exec.out"

# Build the eino example binary (single-agent mode).
log "  building eino example binary..."
( cd "$REPO_ROOT/examples/eino-sandswap" && go build -o "$EINO_BIN" . 2>&1 ) || err "eino build failed"

# Resolve each NEW sandfs's per-sandfs zone via sandns. For an unowned
# sandfs the DNS binpack fallback (pickAnyRegistered) returns the BUSIEST healthy
# gateway = exec1. We then point the eino instance at that gateway's MCP URL.
dig_first() { # <name> → first A record or ""
    # || true honors the "or empty" contract under set -o pipefail: a dig
    # timeout (forwarded query, unreachable upstream) must read as "", not as
    # a caller-killing non-zero status.
    dig @127.0.0.1 "$1" +short +time=2 +tries=1 2>/dev/null | head -1 || true
}

run_eino() { # <label> <api_key> <sandfs_id> <marker> <outfile>
    local label="$1" key="$2" sf="$3" marker="$4" out="$5"
    local vip
    # The DNS layer loads ownership via an ASYNC etcd watch — a single dig
    # races that sync and returned "" here, pointing eino at
    # "https://:3000/mcp" (a guaranteed false FAIL). Retry until it answers.
    bm_retry_nonempty vip 10 3 dig_first "${sf}.sandfs.sandswap.local" \
        || err "${label}: DNS never answered for ${sf}.sandfs.sandswap.local"
    echo "$vip" > "$LOG_DIR/${label}-vip.txt"
    log "  ${label}: DNS binpack resolved ${sf}.sandfs.sandswap.local -> ${vip}"
    if [[ "$vip" != "127.0.0.1" && "$vip" != "127.0.0.2" ]]; then
        log "  ${label}: WARN DNS returned '$vip' (expected a loopback IP)"
    fi
    # Single-agent eino: one trivial exec to claim ownership on the resolved gw.
    printf 'Use the execute tool to run this shell command: echo %s\n' "$marker" \
        | timeout 150 env \
            SANDSWAP_API_KEY="$key" \
            SANDSWAP_MCP_URL="https://${vip}:3000/mcp" \
            SANDSWAP_CA_CERT="$CERT_DIR/ca.crt" \
            DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}" \
            DEEPSEEK_MODEL="${DEEPSEEK_MODEL:-deepseek-flash}" \
            "$EINO_BIN" > "$out" 2>&1 || true
}

log "  launching 2 eino instances (concurrent)..."
run_eino eino-A "$A_KEY" "$A_SF" "binpack_eino_a_ok" "$LOG_DIR/eino-a.log" &
EINO_A_PID=$!
run_eino eino-B "$B_KEY" "$B_SF" "binpack_eino_b_ok" "$LOG_DIR/eino-b.log" &
EINO_B_PID=$!
wait $EINO_A_PID || true
wait $EINO_B_PID || true

# ──── [10/10] Verify binpack concentration ────
log "[10/10] Verifying binpack concentration..."
VIP_A=$(cat "$LOG_DIR/eino-A-vip.txt" 2>/dev/null)
VIP_B=$(cat "$LOG_DIR/eino-B-vip.txt" 2>/dev/null)
OW_A=$(owner_gw "$A_SF")
OW_B=$(owner_gw "$B_SF")
A_OK=$(grep -q "binpack_eino_a_ok" "$LOG_DIR/eino-a.log" 2>/dev/null && echo 1 || echo 0)
B_OK=$(grep -q "binpack_eino_b_ok" "$LOG_DIR/eino-b.log" 2>/dev/null && echo 1 || echo 0)

echo "  eino-A DNS -> $VIP_A ; exec marker present=$A_OK ; owner=$OW_A"
echo "  eino-B DNS -> $VIP_B ; exec marker present=$B_OK ; owner=$OW_B"

bp_check "eino-A: DNS binpack resolved sandfs-A to exec1 (127.0.0.1)" \
    "$([[ "$VIP_A" == "127.0.0.1" ]] && echo 1 || echo 0)" "got $VIP_A"
bp_check "eino-B: DNS binpack resolved sandfs-B to exec1 (127.0.0.1)" \
    "$([[ "$VIP_B" == "127.0.0.1" ]] && echo 1 || echo 0)" "got $VIP_B"
bp_check "eino-A: exec succeeded on its gateway (marker in log)" "$A_OK" "$(tail -3 "$LOG_DIR/eino-a.log" 2>/dev/null | head -c 200)"
bp_check "eino-B: exec succeeded on its gateway (marker in log)" "$B_OK" "$(tail -3 "$LOG_DIR/eino-b.log" 2>/dev/null | head -c 200)"
bp_check "binpack: sandfs-A owned by exec1" \
    "$([[ "$OW_A" == "exec1" ]] && echo 1 || echo 0)" "got $OW_A"
bp_check "binpack: sandfs-B owned by exec1" \
    "$([[ "$OW_B" == "exec1" ]] && echo 1 || echo 0)" "got $OW_B"
bp_check "binpack: BOTH eino instances concentrated on ONE gateway (exec1)" \
    "$([[ "$OW_A" == "exec1" && "$OW_B" == "exec1" ]] && echo 1 || echo 0)" "A=$OW_A B=$OW_B"

echo ""
if [[ "$BP_FAIL" == "0" ]]; then
    log "================================================================"
    log "  BINPACK E2E PASSED: 2 eino instances concentrated on exec1"
    log "  (DNS binpack + ownership both on one gateway)"
    log "================================================================"
    exit 0
else
    err "BINPACK E2E FAILED - see [FAIL] lines above. Logs in $LOG_DIR/"
fi
