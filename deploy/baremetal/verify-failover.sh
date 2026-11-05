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
# verify-failover.sh - sandlot cross-gateway failover verification
# Verifies that a sandlot using the DNS name (sandswap-stream.local) fails over
# to another gateway when its current gateway dies: the sandns health-gates
# the dead gateway out of the stream-domain resolution, so the sandlot's reconnect
# re-resolves and lands on a healthy gateway.
# Topology (single host, two loopback IPs so both gateways can share the port):
#   exec1: 127.0.0.1:3000/9998   exec2: 127.0.0.2:3000/9998
#   sandns :53 (gateways = both loopback IPs)
#   1 sandlot: gateway_addr = sandswap-stream.local:9998 (DNS name)
# The sandlot must resolve via sandns (not /etc/hosts) so the dead gateway
# is health-gated out. This script temporarily points /etc/resolv.conf at the
# sandns and restores it on exit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/deploy-lib.sh"

OUTPUT="$REPO_ROOT/output"
CERT_DIR="${SANDSWAP_ETC}/certs-failover"
RUN_DIR="/run/sandswap-failover"
ETCD_PID=""

# PRE-CLEAN: ensure a fresh slate before starting (no leftover processes/ports
# from a previous run or manual debugging). The post-test cleanup trap handles
# this run's artifacts; this handles anything that survived a prior aborted run.

# Restore /etc/resolv.conf preserving symlink-ness: on systemd-resolved hosts it
# IS a symlink (→ stub-resolv.conf); a content cp would leave a plain file that
# resolved never updates again. Used by pre_clean (prior-run leftovers) + cleanup.
restore_resolv() {
    if [[ -f /etc/resolv.conf.sandswap-bak ]]; then
        rm -f /etc/resolv.conf
        if [[ -f /etc/resolv.conf.sandswap-bak-target ]]; then
            ln -sfn "$(cat /etc/resolv.conf.sandswap-bak-target)" /etc/resolv.conf
        else
            cp /etc/resolv.conf.sandswap-bak /etc/resolv.conf
        fi
        rm -f /etc/resolv.conf.sandswap-bak /etc/resolv.conf.sandswap-bak-target
        log "restored /etc/resolv.conf"
    fi
}

pre_clean() {
    # SAFETY GUARD: the cleanup below uses broad pkill patterns against the
    # INSTALLED binary paths (/usr/local/bin/sandswap-gateway|sandlot|sandvmm),
    # which are exactly the production deployment's. On a host with a live
    # deployment that would kill production gateways/nodes. This script builds
    # a private topology; refuse to run beside one.
    for svc in sandswap-gateway.service sandswap-gateway@exec.service sandswap-gateway@human.service \
               sandswap-sandlot.service sandswap-sandlot-prov.service sandswap-sandns.service; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo "error: $svc is ACTIVE on this host — verify-failover.sh is destructive (it pkills the installed sandswap binaries)." >&2
            echo "       Run it on a dedicated host, or stop the deployment first." >&2
            exit 1
        fi
    done
    if systemctl list-units --type=service --state=active --no-legend 'sandswap-sandlot-instance@*' 2>/dev/null | grep -q .; then
        echo "error: a sandswap @-instance sandlot is ACTIVE on this host — verify-failover.sh is destructive. Stop it first." >&2
        exit 1
    fi
    for svc in sandswap-gateway-fail1 sandswap-gateway-fail2 sandswap-sandlot-fail sandswap-sandns-fail; do
        systemctl stop "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
    systemctl daemon-reload 2>/dev/null || true
    # -x never matches sandswap-gateway/sandlot (comm is truncated to 15 chars);
    # match the installed binary paths instead. etcd is scoped to OUR instances
    # (data dirs contain "sandswap-") so an unrelated host etcd is never killed.
    pkill -9 -f '/usr/local/bin/sandswap-gateway' 2>/dev/null || true
    pkill -9 -f '/usr/local/bin/sandswap-sandlot' 2>/dev/null || true
    pkill -9 -x sandns 2>/dev/null || true
    pkill -9 -f 'sandswap-.*etcd' 2>/dev/null || true
    pkill -9 -f 'sandswap-sandvmm' 2>/dev/null || true
    sleep 1
    rm -rf "$RUN_DIR" /tmp/sandswap-failover-etcd /tmp/fo-etcd 2>/dev/null
    # Wipe the sandlot's persisted reconnect state (node_id "failover-sl" is
    # reused across runs; a stale LastGatewayIP/phase would resume the OLD
    # state machine instead of starting fresh).
    rm -f /run/sandswap/gateway-state.json /run/sandswap/cleanup-state.json \
          /run/sandswap-state/default/gateway-state.json /run/sandswap-state/default/cleanup-state.json 2>/dev/null
    rm -rf /run/sandswap/vm /run/sandswap-state/default 2>/dev/null
    # Remove /etc/hosts entries left by the local production sim (it pins
    # sandswap.local / sandswap-stream.local to HOST_IP). /etc/hosts takes
    # precedence over DNS, so a stale entry makes the sandlot dial HOST_IP
    # instead of the health-gated 127.0.0.x this test needs.
    sed -i '/sandswap\.local\|sandswap-stream\.local/d' /etc/hosts 2>/dev/null || true
    # Restore /etc/resolv.conf if a prior run left it pointed at sandns.
    restore_resolv
    # Fail hard if a port we need is still held - do not silently build on a
    # contaminated environment (accumulated leftovers give false results).
    local held
    held=$(ss -ltn 2>/dev/null | grep -cE ':3000|:9998|:2379' || true)
    if [[ "$held" != "0" ]]; then
        err "pre-clean: ports 3000/9998/2379 still in use after cleanup - abort to avoid contaminated environment"
    fi
}
pre_clean

cleanup() {
    log "cleanup..."
    for svc in sandswap-gateway-fail1 sandswap-gateway-fail2 sandswap-sandlot-fail sandswap-sandns-fail; do
        systemctl stop "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
    systemctl daemon-reload 2>/dev/null || true
    pkill -9 -f 'sandswap-sandvmm' 2>/dev/null || true
    [[ -n "$ETCD_PID" ]] && kill "$ETCD_PID" 2>/dev/null || true
    rm -rf "$RUN_DIR" /tmp/sandswap-failover-etcd
    # Leave no sandlot reconnect state behind (node_id "failover-sl" is reused).
    rm -f /run/sandswap/gateway-state.json /run/sandswap/cleanup-state.json \
          /run/sandswap-state/default/gateway-state.json /run/sandswap-state/default/cleanup-state.json 2>/dev/null
    rm -rf /run/sandswap/vm /run/sandswap-state/default 2>/dev/null
    # Restore /etc/resolv.conf (recreating the systemd-resolved symlink if it was one)
    restore_resolv
}
trap cleanup EXIT
# INT/TERM: exit so the EXIT trap runs cleanup once; without the exit bash would
# resume the script after the handler and re-deploy into the just-cleaned host.
trap 'exit 130' INT TERM

# ── Sequencing guard (order is part of the contract) ────────────────────
# This script builds its own PRIVATE topology (etcd 2379, gateways 3000/9998 on
# the loopback aliases, dns :53) and is only sound on a QUIET host. A foreign
# sandswap deployment holding these ports either kills the dns start silently
# or — worse — lets the gateway health checks answer against the WRONG
# processes (silent false green). Refuse loudly instead and name the cleanup.
BM_PORTS="3000 9998 2379" bm_preflight
# systemd-resolved's stub listeners (127.0.0.53/54:53) coexist fine with a
# wildcard dns bind — only a non-stub holder actually blocks us.
port53_holders="$( { ss -H -ulnp 'sport = :53'; ss -H -tlnp 'sport = :53'; } 2>/dev/null | grep -vE '127\.0\.0\.5[34]|\[::1\]:53|127\.0\.0\.1:53' | grep -oE 'pid=[0-9]+' | sort -u | tr '\n' ' ' || true)"
if [[ -n "${port53_holders// /}" ]]; then
    err "port 53 already held by PID(s): ${port53_holders} — another dns (usually a kept sandswap deployment) owns it. Run: bash deploy/baremetal/uninstall.sh (or cleanup.sh), then retry"
fi

log "[1/8] Building certs (loopback IPs + wildcard)..."
# The stream client pair's CN must equal the node id this drill's sandlot
# declares ("failover-sl", below) — the gateway binds hello.node_id == the
# client cert's CN by exact match (a shared/CN-less pair is refused by name).
FO_NODE_ID="failover-sl"
SANDLOT_NODE_ID="$FO_NODE_ID" \
    bash "$SCRIPT_DIR/gen-baremetal-certs.sh" "$OUTPUT/failover-certs" \
    --sans-dns "sandswap.local,sandswap-stream.local,*.sandfs.sandswap.local" \
    --sans-ip "127.0.0.1,127.0.0.2" >/dev/null 2>&1
mkdir -p "$CERT_DIR"
cp "$OUTPUT/failover-certs"/* "$CERT_DIR/"
# Scope each key to ONLY the identity that loads it (gateways run as the
# sandserv user, the sandlot as the sandlot user) — 0600 root keys would make
# every service fail its TLS setup.
ss_own_tls_keys "$CERT_DIR"
sandswap_verify_client_cert_cn "$CERT_DIR/sandlot.crt" "$FO_NODE_ID" || err "stream pair CN does not match node id $FO_NODE_ID"

log "[2/8] Starting etcd..."
rm -rf /tmp/sandswap-failover-etcd
ETCD_BIN=$(command -v etcd || echo "$OUTPUT/etcd/etcd")
[[ -x "$ETCD_BIN" ]] || err "etcd binary not found (need output/etcd/etcd or system etcd)"
"$ETCD_BIN" --name failover-etcd --data-dir /tmp/sandswap-failover-etcd \
    --listen-client-urls http://127.0.0.1:2379 --advertise-client-urls http://127.0.0.1:2379 \
    --listen-peer-urls http://127.0.0.1:2380 --initial-advertise-peer-urls http://127.0.0.1:2380 \
    --initial-cluster failover-etcd=http://127.0.0.1:2380 --initial-cluster-token ss-fo \
    --initial-cluster-state new --log-level warn >/tmp/failover-etcd.log 2>&1 &
ETCD_PID=$!
sleep 2
curl -s http://127.0.0.1:2379/health >/dev/null || err "etcd failed to start"

ETCDCTL=$(command -v etcdctl || echo "$OUTPUT/etcd/etcdctl")
aff_health_field() { # <gid> <field>
    "$ETCDCTL" --endpoints=http://127.0.0.1:2379 get "/sandswap/health/$1" --print-value-only 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" 2>/dev/null || echo ""
}

log "[3/8] Starting 2 exec gateways (127.0.0.1 + 127.0.0.2, same port)..."
# Runtime dirs for the DEDICATED IDENTITIES: /run/sandswap 3770 root:sandlot
# sticky (`ss_prepare_dirs`; the sandlot instance creates its instance dir under it) + the share root
# <prov>:sandlot 2750 (prov seeds volumes; the FUSE daemon only traverses).
ss_prepare_dirs
mkdir -p "$RUN_DIR" "$SANDSWAP_VAR/flat-templates/rootfs/v1"
# Always re-seed: a prior deploy may have left bin/sbin/lib as symlinks, which
# `cp -a` cannot overwrite with directories (aborts the run mid-way).
rm -rf "$SANDSWAP_VAR/flat-templates/rootfs/v1"
mkdir -p "$SANDSWAP_VAR/flat-templates/rootfs/v1"
cp -a "$OUTPUT/rootfs-template/." "$SANDSWAP_VAR/flat-templates/rootfs/v1/"
chgrp -R "$SS_SHARED_GROUP" "$SANDSWAP_VAR/flat-templates" 2>/dev/null || true
[[ -x "$OUTPUT/template-tool" ]] && "$OUTPUT/template-tool" normalize "$SANDSWAP_VAR/flat-templates" >/dev/null
sandswap_install_binary "$OUTPUT/gateway" "$SANDSWAP_BIN/sandswap-gateway" >/dev/null 2>&1

write_gw_unit() { # <name> <config> — gateway units run as the dedicated
    # gateway identity (mirrors sandswap-gateway.service)
    cat > "/etc/systemd/system/$1.service" << EOF
[Unit]
Description=Sandswap Gateway ($1)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=sandserv
ExecStart=$SANDSWAP_BIN/sandswap-gateway -config $2
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$1
[Install]
WantedBy=multi-user.target
EOF
}

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
# The sandlot runs with -allow-short-resilience-timings (T_safe=70s), so the
# gateway max exec must satisfy 5s tick + max + 30s heartbeat < 70s.
exec: { default_timeout_sec: 30, max_timeout_sec: 30 }
# The gateway rejects nodes whose timings violate T_safe > fence + T_warden +
# heartbeat(30s). Shrinking the fence (test-only; prod default 180s) is what
# lets this test's small tolerance/warden/isolation pass that floor — see the
# resilience block in the sandlot config below.
staleness:
  etcd_fence_sec: 20
YAML
    write_gw_unit "sandswap-gateway-fail${i}" "$RUN_DIR/gw-exec${i}.yaml"
done
systemctl daemon-reload
systemctl reset-failed sandswap-gateway-fail1 sandswap-gateway-fail2 2>/dev/null || true
systemctl start sandswap-gateway-fail1 sandswap-gateway-fail2
# Poll, don't bet: a single curl 3s after systemctl start flakes on loaded hosts.
bm_wait_http "https://127.0.0.1:3000/health" 15 || err "exec1 not healthy"
bm_wait_http "https://127.0.0.2:3000/health" 15 || err "exec2 not healthy"
log "  both gateways healthy"

log "[4/8] Starting sandns..."
sandswap_install_binary "$OUTPUT/sandns" "$SANDSWAP_BIN/sandns" >/dev/null 2>&1
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
cat > /etc/systemd/system/sandswap-sandns-fail.service << 'EOF'
[Unit]
Description=Sandswap DNS (failover test)
After=network-online.target
[Service]
Type=simple
User=sandserv
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sandns -config /run/sandswap-failover/sandns.yaml
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sandswap-sandns-fail
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl reset-failed sandswap-sandns-fail 2>/dev/null || true
systemctl start sandswap-sandns-fail
# Fail LOUDLY if the dns process died at startup (e.g. :53 grabbed between the
# preflight and here) — a silent exit at this step once cost a full debug cycle.
sleep 1
systemctl is-active --quiet sandswap-sandns-fail \
    || err "sandswap-sandns-fail died at startup — port 53 conflict? Diagnose: journalctl -u sandswap-sandns-fail --no-pager | tail -20"
# Sanity: stream domain resolves to one of the gateways. sandns loads the
# registry via an async etcd watch at startup — retry until it answers.
DR=""
for i in $(seq 1 10); do
    # || true + explicit query bounds: dig exits non-zero on a timeout (e.g.
    # the async etcd watch hasn't loaded the registry and the query is
    # forwarded to an unreachable upstream); with set -o pipefail an unguarded
    # non-zero would kill the script SILENTLY before err below can speak.
    DR=$(dig @127.0.0.1 sandswap-stream.local +short +time=2 +tries=1 2>/dev/null | head -1 || true)
    [[ "$DR" == "127.0.0.1" || "$DR" == "127.0.0.2" ]] && break
    sleep 3
done
[[ "$DR" == "127.0.0.1" || "$DR" == "127.0.0.2" ]] || err "dns did not resolve stream domain (got '$DR')"
log "  dns resolves sandswap-stream.local -> $DR"

log "[5/8] Pointing /etc/resolv.conf at sandns (so the sandlot resolves via it)..."
# Remember symlink-ness: on systemd-resolved hosts /etc/resolv.conf IS a symlink
# (→ stub-resolv.conf). Recreate the link on restore, not a stale plain file.
rm -f /etc/resolv.conf.sandswap-bak-target
if [[ -L /etc/resolv.conf ]]; then readlink /etc/resolv.conf > /etc/resolv.conf.sandswap-bak-target; fi
cp --dereference /etc/resolv.conf /etc/resolv.conf.sandswap-bak
rm -f /etc/resolv.conf
cat > /etc/resolv.conf << 'EOF'
nameserver 127.0.0.1
EOF
log "  /etc/resolv.conf -> 127.0.0.1 (sandns); backed up"

log "[6/8] Starting 1 sandlot (gateway_addr = sandswap-stream.local:9998)..."
# Ensure the host bridge exists (the sandlot needs it for microVM networking;
# setup-network.sh is idempotent). The failover test only checks the sandlot's
# gRPC connection + failover, but the sandlot refuses to start without br-sandswap.
# The sandlot below is configured with subnet 10.190.1.0/24 / gw 10.190.1.1, so
# the bridge must carry that address (the script's defaults are 10.188.0.0/16 /
# 10.188.0.1) — otherwise the guest's default route is an ARP-blackhole.
# Always re-run the idempotent host prep: an existing br-sandswap from a prior
# deployment can lack the current `inet sandswap input/forward` chains.
SUBNET=10.190.1.0/24 GATEWAY=10.190.1.1 bash "$REPO_ROOT/deploy/setup-network.sh" >/dev/null 2>&1 \
    || err "host network prep failed (deploy/setup-network.sh)"
ip addr add 10.190.1.1/24 dev br-sandswap 2>/dev/null || true
# This script does NOT run setup-host.sh (unlike the cluster simulations) —
# repair the per-owner vsock device modes explicitly or sandlot's startup
# owner-check fails fast on a stale node (module reload / pre-split host).
sandswap_setup_dev_nodes
# Refresh the resolved-identity env (an uninstall removes it; the sandlot
# unit's EnvironmentFile below consumes it). Idempotent when users exist.
ss_ensure_service_users >/dev/null 2>&1 || true
sandswap_install_binary "$OUTPUT/sandlot" "$SANDSWAP_BIN/sandswap-sandlot" >/dev/null 2>&1
sandswap_install_binary "$OUTPUT/sandvmm" "$SANDSWAP_BIN/sandswap-sandvmm" >/dev/null 2>&1
cp "$OUTPUT/vmlinux.bin" "$SANDSWAP_VAR/" 2>/dev/null || true
cp "$OUTPUT/initramfs.cpio.gz" "$SANDSWAP_VAR/" 2>/dev/null || true
cat > "$RUN_DIR/sandlot.yaml" << YAML
gateway_addr: "sandswap-stream.local:9998"
node_id: "failover-sl"
vm_mode: embedded
vmm_binary: ${SANDSWAP_BIN}/sandswap-sandvmm
microvm:
  kernel: ${SANDSWAP_VAR}/vmlinux.bin
  initramfs: ${SANDSWAP_VAR}/initramfs.cpio.gz
  default_vcpus: 2
  default_memory_mb: 512
  volumes_dir: ${SANDSWAP_VAR}/volumes
specs:
  small:  { vcpus: 1, memory_mb: 128, exec_slots: 1 }
  medium: { vcpus: 2, memory_mb: 512 }
pool: "medium:1"
recycle: { mem_percent: 10, mem_abs_mb: 100 }
# v2 tolerance-first: failover is DELAYED-but-confirmed. The sandlot tolerates
# its dead gateway for T_tolerance (retrying only its IP), then cleans up, waits
# T_isolation, and only then re-resolves the DNS name (which by then health-gates
# the dead gateway out). Defaults are 300/300/720s — far beyond this test's
# window — so shrink them. The gateway validates BOTH model invariants at
# connect:
#   1. T_isolation > T_safe = T_tolerance + T_warden + 60s(safeMargin)
#   2. T_safe > etcd_fence + T_warden + heartbeat(30s)
# The test gateways run with etcd_fence_sec: 20 (see their config above), so
# floor 2 is 20+5+30 = 55s; T_safe = 5+5+60 = 70s satisfies it, and isolation
# 75s satisfies (1). Reconnect lands ~85s after the kill, which the [8/8]
# window covers. (No sandfs is mounted in this test, so the warden countdown
# clamp is moot.)
resilience:
  tolerance_sec: 5
  cleanup_sec: 5
  warden_countdown_sec: 5
  isolation_sec: 75
network:
  backend: bridge
  bridge: br-sandswap
  subnet: 10.190.1.0/24
  gateway: 10.190.1.1
  dns: "1.1.1.1"
tls:
  # The primary pair minted above carries CN=${FO_NODE_ID} — this sandlot's
  # declared node id (the gateway binds the two by exact match).
  cert: ${CERT_DIR}/sandlot.crt
  key: ${CERT_DIR}/sandlot.key
  ca: ${CERT_DIR}/ca.crt
YAML
cat > /etc/systemd/system/sandswap-sandlot-fail.service << 'EOF'
[Unit]
Description=Sandswap Sandlot (failover test)
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
ExecStart=/usr/local/bin/sandswap-sandlot -config /run/sandswap-failover/sandlot.yaml -roles exec -allow-insecure-volumes -allow-short-resilience-timings -allow-missing-vsockguard
Restart=no
KillMode=process
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sandswap-sandlot-fail
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl reset-failed sandswap-sandlot-fail 2>/dev/null || true
systemctl start sandswap-sandlot-fail

log "[7/8] Waiting for the sandlot to connect to one gateway..."
CONNECTED_GW=""
for _ in $(seq 1 30); do
    sleep 2
    NC1=$(aff_health_field exec1 node_count)
    NC2=$(aff_health_field exec2 node_count)
    if [[ "$NC1" == "1" ]]; then CONNECTED_GW="exec1"; break; fi
    if [[ "$NC2" == "1" ]]; then CONNECTED_GW="exec2"; break; fi
done
[[ -n "$CONNECTED_GW" ]] || err "sandlot did not connect to any gateway within 60s (nc1=$NC1 nc2=$NC2)"
log "  sandlot connected to $CONNECTED_GW"

# Kill the gateway the sandlot is connected to.
KILL_GW="$CONNECTED_GW"
KILL_IDX="${CONNECTED_GW#exec}"
OTHER_GW="exec$(( 3 - KILL_IDX ))"
log "  killing $KILL_GW (sandswap-gateway-fail${KILL_IDX}); expecting sandlot to fail over to $OTHER_GW"
systemctl stop "sandswap-gateway-fail${KILL_IDX}" 2>/dev/null || true
pkill -9 -f "sandswap-gateway.*gw-exec${KILL_IDX}" 2>/dev/null || true

log "[8/8] Waiting for the sandlot to fail over to $OTHER_GW (health poll + reconnect)..."
# The reconnect lands after T_tolerance(5s) + T_clean(5s) + T_isolation(75s)
# ≈ 85s post-kill (the isolation wait exists so the old presence key is
# provably expired before the node can re-present — see the timing invariant),
# so the window must cover it.
FAILOVER_OK=0
for _ in $(seq 1 60); do
    sleep 2
    NC_OTHER=$(aff_health_field "$OTHER_GW" node_count)
    if [[ "$NC_OTHER" == "1" ]]; then FAILOVER_OK=1; break; fi
done
if [[ "$FAILOVER_OK" == "1" ]]; then
    log "  [PASS] sandlot failed over to $OTHER_GW (node_count=1) after $KILL_GW died"
    exit 0
else
    err "sandlot did NOT fail over to $OTHER_GW within 120s (nc_other=$NC_OTHER). Logs: journalctl -u sandswap-sandlot-fail"
fi
