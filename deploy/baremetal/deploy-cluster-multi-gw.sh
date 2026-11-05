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
# deploy-cluster-multi-gw.sh — Production cluster deployment
# 2+ exec GW + 1 human GW + etcd + N sandlots + sandns + 1 prov instance
# (storage plane: the prov-role sandlot runs on the HUMAN gateway host — the
# compact-topology shape — dialing the human gateway's :9996 prov listener.
# Without it every sandfs create/delete and template op is the named 503 "no
# provision instance connected": the gateways mount no shared storage since
# the storage split.)
# Generates the affinity-wired per-node configs (unique gateway_id,
# gateway_url / gateway_stream_addr, idle_timeout, per-sandfs DNS zone,
# sandlot gateway_addr = DNS name) into output/baremetal-prod/, plus the TLS
# certs with the exec GW IPs + *.sandfs.sandswap.local wildcard SAN, and prints
# the per-node SSH install commands for the operator to run.
# Usage:
#   bash deploy-cluster-multi-gw.sh --config cluster-production.yaml [--dry-run] [--skip-build]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/common.sh"

CONFIG=""
DRY_RUN=0
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)     CONFIG="$2"; shift 2 ;;
        --dry-run)    DRY_RUN=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help)
            echo "Usage: $0 --config cluster-production.yaml [--dry-run] [--skip-build]"
            exit 0
            ;;
        *) err "Unknown argument: $1" ;;
    esac
done

[[ -z "$CONFIG" ]] && err "--config is required"
[[ ! -f "$CONFIG" ]] && err "Config file not found: $CONFIG"

# ──── Parse cluster YAML ────

CLUSTER_JSON=$(python3 -c "
import yaml, sys, json
with open('$CONFIG') as f:
    d = yaml.safe_load(f)
print(json.dumps(d))
" 2>/dev/null) || err "Failed to parse $CONFIG (requires python3 + PyYAML)"

log "Production Cluster Deployment"

# ──── Build ────

if [[ $SKIP_BUILD -eq 0 ]]; then
    log "[1/9] Building artifacts..."
    if [[ $DRY_RUN -eq 0 ]]; then
        bm_build_artifacts
    else
        log "  (dry-run: would run build.sh all)"
    fi
fi

OUTPUT="$REPO_ROOT/output"
if [[ $SKIP_BUILD -eq 1 ]]; then
    ss_verify_kernel_artifact "$OUTPUT/vmlinux.bin" "$REPO_ROOT/kernel/build.sh" \
        || err "Refusing --skip-build with a non-pinned kernel under output/ — run bash build/build.sh kernel"
fi
STAGE="$OUTPUT/baremetal-prod"

# ──── Extract config values ────

ETCD_ENDPOINTS=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(','.join(d.get('etcd',{}).get('endpoints',[])))")
SHARED_TYPE=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('shared_storage',{}).get('type','pre-mounted'))")
# The mount itself is a per-node ops step (see the SHARED_MOUNT check below) —
# but a typo'd type should fail here, at generation time, not on a node weeks later.
case "$SHARED_TYPE" in
    pre-mounted|nfs|cfs|cephfs) ;;
    *) err "shared_storage.type '$SHARED_TYPE' not one of: pre-mounted|nfs|cfs|cephfs" ;;
esac
SHARED_MOUNT=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('shared_storage',{}).get('mount_point','/mnt/sandswap'))")
if [[ "$SHARED_MOUNT" != "/mnt/sandswap" ]]; then
    err "shared_storage.mount_point must be /mnt/sandswap: the shipped systemd units grant ReadWritePaths only to /mnt/sandswap, so any other path leaves the gateway read-only under ProtectSystem=strict. (The shared-filesystem mount itself is a per-node ops step — see docs/deployment/install-baremetal.md.)"
fi
DNS_HOST=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('dns',{}).get('host',''))")
AGENT_DOMAIN=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('dns',{}).get('agent_domain','sandswap.local'))")
STREAM_DOMAIN=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('dns',{}).get('stream_domain','sandswap-stream.local'))")

# exec GWs: host + optional agent_port/stream_port (defaults 3000/9998), optional explicit ip
EXEC_GWS_JSON=$(echo "$CLUSTER_JSON" | python3 -c "
import json,sys
d = json.load(sys.stdin)
out=[]
for i,gw in enumerate(d.get('gateways',{}).get('exec',[]), start=1):
    host=gw.get('host','')
    out.append({'idx':i,'host':host,'ip':gw.get('ip',''),'agent_port':str(gw.get('agent_port',3000)),'stream_port':str(gw.get('stream_port',9998))})
print('\n'.join(json.dumps(o) for o in out))
")
HUMAN_GW_HOST=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('gateways',{}).get('human',[{}])[0].get('host',''))")
SANDFLOTS_JSON=$(echo "$CLUSTER_JSON" | python3 -c "
import json,sys
d = json.load(sys.stdin)
out=[]
for sl in d.get('sandlots',[]):
    out.append({'host':sl.get('host',''),'node_id':sl.get('node_id',''),'pool':sl.get('pool','medium:3'),'subnet':sl.get('subnet','10.188.0.0/16'),'net_gateway_ip':sl.get('net_gateway_ip','10.188.0.1')})
print('\n'.join(json.dumps(o) for o in out))
")

N_EXEC=$(echo "$EXEC_GWS_JSON" | grep -c . || true)
[[ "$N_EXEC" -lt 2 ]] && err "production cluster needs >= 2 exec gateways (got $N_EXEC)"

# ──── TLS certs with multi-node SANs ────

log "[2/9] Generating TLS certificates with multi-node SANs..."

# Resolve exec GW IPs (explicit `ip` field, else resolve the host). Fall back to
# the hostname itself when resolution fails (DNS may not exist yet).
SANS_IP=$(echo "$EXEC_GWS_JSON" | python3 -c "
import json,sys,socket
for line in sys.stdin:
    gw=json.loads(line)
    if gw['ip']:
        print(gw['ip']); continue
    try:
        print(socket.gethostbyname(gw['host']))
    except Exception:
        print(gw['host'])
")
# Agent-facing cert needs the per-sandfs wildcard + the two shared domains.
SANS_DNS="${AGENT_DOMAIN},${STREAM_DOMAIN},*.sandfs.sandswap.local"

# Stream identities of this fleet: one client pair PER NODE ID (the gateway
# binds hello.node_id == the client cert's CN by exact match — a shared pair
# is refused by name). The first sandlot entry rides the primary pair
# (sandlot.*); every other sandlot and the prov node get their own pair.
PROV_NODE_ID="sandlot-prov"
sandlot_node_ids() { # every exec node id in the cluster config, in order
    echo "$SANDFLOTS_JSON" | python3 -c "import json,sys
for line in sys.stdin:
    print(json.loads(line)['node_id'])"
}
sandlot_cert_base() { # <node-id> → the pair basename carrying it as CN
    local node="$1" first
    # First id without `| head -1` (a truncated pipeline can SIGPIPE a producer;
    # `pipefail` would then fail the assignment under `set -e`).
    first="$(sandlot_node_ids)"
    first="${first%%$'\n'*}"
    if [[ -n "$first" && "$node" == "$first" ]]; then
        echo "sandlot"
    else
        echo "sandlot-${node}"
    fi
}
PROV_CERT_BASE="$(sandlot_cert_base "$PROV_NODE_ID")"

if [[ $DRY_RUN -eq 0 ]]; then
    primary_node="$(sandlot_node_ids)"
    primary_node="${primary_node%%$'\n'*}"
    [[ -n "$primary_node" ]] || primary_node="$PROV_NODE_ID"
    extra_args=()
    # The certificate is the role grant: prov node ids get role/prov, exec
    # node ids role/exec.
    while IFS= read -r n; do
        [[ -n "$n" && "$n" != "$primary_node" ]] || continue
        if [[ "$n" == "$PROV_NODE_ID" ]]; then
            extra_args+=(--client-cn "${n}:prov")
        else
            extra_args+=(--client-cn "${n}:exec")
        fi
    done < <(sandlot_node_ids)
    if [[ "$primary_node" != "$PROV_NODE_ID" ]]; then
        extra_args+=(--client-cn "${PROV_NODE_ID}:prov")
    fi
    primary_roles="exec"
    [[ "$primary_node" == "$PROV_NODE_ID" ]] && primary_roles="prov"
    SANDLOT_NODE_ID="$primary_node" \
        bash "$SCRIPT_DIR/gen-baremetal-certs.sh" "$OUTPUT/baremetal-certs" \
        --sans-dns "$SANS_DNS" \
        --sans-ip "$(echo "$SANS_IP" | tr '\n' ',')" \
        --client-roles "$primary_roles" \
        ${extra_args[@]+"${extra_args[@]}"}
else
    log "  (dry-run: would generate certs with SANs: DNS=$SANS_DNS IP=$SANS_IP, one client pair per node id)"
fi

# ──── Generate affinity-wired per-node configs into $STAGE ────

log "[3/9] Generating per-node configs → $STAGE"
# dry-run still RUNS the config generation + validation: they ARE this
# script's deliverable (steps 4-7 are printed operator instructions, not
# ssh), and they are where the deploy drift of this round lived (prov
# presence, seed key, ports, DNS names). Only the PKI regeneration above is
# skipped under --dry-run (it would overwrite a fleet's live CA).
rm -rf "$STAGE"
mkdir -p "$STAGE"

TLS_DIR="/etc/sandswap/certs"

# 3a. exec gateways
while IFS= read -r gw_json; do
    idx=$(echo "$gw_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['idx'])")
    host=$(echo "$gw_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['host'])")
    ip=$(echo "$gw_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['ip'])")
    agent_port=$(echo "$gw_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['agent_port'])")
    stream_port=$(echo "$gw_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['stream_port'])")
    [[ -z "$ip" ]] && ip=$(getent hosts "$host" | awk '{print $1}' | head -1 || echo "$host")
    gid="gw-exec-${idx}"
    log "  exec gateway $gid (host=$host ip=$ip agent_port=$agent_port stream_port=$stream_port)"

    SANDSWAP_GATEWAY_ID="$gid" \
    SANDSWAP_GATEWAY_URL="https://${ip}:${agent_port}" \
    SANDSWAP_GATEWAY_STREAM_ADDR="${ip}:${stream_port}" \
    SANDSWAP_IDLE_TIMEOUT_SEC=3600 \
    sandswap_generate_gateway_config \
        "$STAGE/gateway-exec-${idx}.yaml" \
        "exec" \
        "$SHARED_MOUNT/volumes" \
        "0.0.0.0:${agent_port}" \
        "127.0.0.1:3100" \
        "0.0.0.0:${stream_port}" \
        "$TLS_DIR" \
        "$ETCD_ENDPOINTS"
done <<< "$EXEC_GWS_JSON"

# 3b. human gateway. Stream listener on :9996 (the prov-only listener — the
# dedicated port the sims and the one-gw deploy use; :9998 would collide the
# day human is co-located with an exec gateway).
log "  human gateway (host=$HUMAN_GW_HOST)"
# Both-dead recovery has no background reaper any more: the human gateway's
# Claim path reclaims on demand, and POST /human/ownership/reap-stuck (or
# reap-stuck-node) is the operator's manual backstop for stranded sandfs.
sandswap_generate_gateway_config \
    "$STAGE/gateway-human.yaml" \
    "human" \
    "$SHARED_MOUNT/volumes" \
    "0.0.0.0:3000" \
    "127.0.0.1:3100" \
    "0.0.0.0:9996" \
    "$TLS_DIR" \
    "$ETCD_ENDPOINTS"

# 3c. sandns with the per-sandfs owner-aware zone
log "  sandns (host=$DNS_HOST)"
# NO static gateway list: every gateway self-registers its routing addresses
# (gateway_url + stream_addr) into /sandswap/gateway/{id} at startup, and the
# DNS builds its candidate set entirely from etcd (registry = candidacy,
# health = liveness, load = scoring).
cat > "$STAGE/sandns.yaml" << YAML
listen_addr: "0.0.0.0:53"
# Sandbox guest ranges: a foreign-zone query from these sources is REFUSED
# (no open recursive relay behind the host egress identity). Update if the
# sandlot subnet is not the default.
guest_cidrs: ["10.188.0.0/16"]

domains:
  stream: ${STREAM_DOMAIN}
  # Per-sandfs owner-aware zone — <sandfs_id>.sandfs.sandswap.local resolves
  # to the OWNER gateway (A record → its IP on baremetal).
  sandfs: sandfs.sandswap.local

etcd: "${ETCD_ENDPOINTS}"
etcd_ca: ${TLS_DIR}/ca.crt
etcd_cert: ${TLS_DIR}/etcd-client.crt
etcd_key: ${TLS_DIR}/etcd-client.key

ttl: 10
sticky_expire: 1800
sticky_sync_interval: 5
sticky_sync_batch: 256

# Gateway routing policy (hot-reloadable via this file):
#   binpack (default) — new/unowned sandfs land on the busiest healthy gateway.
#   spread            — new/unowned sandfs land on the most idle gateway.
# duty_hard: gateway agg_duty_long cap (0..1); gateways at/above it are excluded.
scheduling:
  policy: binpack
  duty_hard: 0.85

forwarders:
  - 8.8.8.8:53
  - 8.8.4.4:53
YAML

# 3d. sandlots — gateway_addr uses the DNS name so a sandlot fails over to a
# healthy gateway when its own gateway is offline (soft affinity, not a dead IP).
while IFS= read -r sl_json; do
    host=$(echo "$sl_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['host'])")
    node_id=$(echo "$sl_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['node_id'])")
    pool=$(echo "$sl_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['pool'])")
    subnet=$(echo "$sl_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['subnet'])")
    gateway_ip=$(echo "$sl_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['net_gateway_ip'])")
    log "  sandlot $node_id (host=$host pool=$pool)"
    SANDSWAP_SANDLOT_CERT_BASE="$(sandlot_cert_base "$node_id")" \
    sandswap_generate_sandlot_config \
        "$STAGE/sandlot-${node_id}.yaml" \
        "${STREAM_DOMAIN}:9998" \
        "${node_id}" \
        "${pool}" \
        "${subnet}" \
        "${gateway_ip}" \
        "$SHARED_MOUNT/volumes" \
        "$TLS_DIR"
done <<< "$SANDFLOTS_JSON"

# 3e. prov instance (storage plane) — runs on the HUMAN gateway host (compact
# topology: that host runs no other sandlot, so the one-sandlot-per-host role
# lock holds without the simulation escape hatch). Template store + volumes on
# the shared mount; no pool, no KVM, no bridge — a provision host owes the
# compute machinery nothing (the config validator refuses exec machinery on
# prov-only roles, loudly).
log "  prov instance (host=$HUMAN_GW_HOST, storage plane)"
SANDSWAP_SANDLOT_ROLES=prov \
SANDSWAP_NETWORK_BACKEND=none \
SANDSWAP_FLAT_TEMPLATES_DIR="$SHARED_MOUNT/flat-templates" \
SANDSWAP_PROVISION_TEMPLATES_DIR="$SHARED_MOUNT/templates" \
SANDSWAP_SANDLOT_CERT_BASE="$PROV_CERT_BASE" \
    sandswap_generate_sandlot_config \
    "$STAGE/sandlot-prov.yaml" \
    "${HUMAN_GW_HOST}:9996" \
    "$PROV_NODE_ID" \
    "" \
    "10.190.254.0/24" \
    "10.190.254.1" \
    "$SHARED_MOUNT/volumes" \
    "$TLS_DIR"
# The generator's empty-pool arg falls back to its default — strip the line
# (prov-only must carry NO pool), and point the key at the sandprov-owned
# prov.key copy derived from the PROV NODE's pair (its cert line already names
# the pair carrying the prov node id as CN).
sed -i '/^pool:/d' "$STAGE/sandlot-prov.yaml"
sed -i "s|\(/${PROV_CERT_BASE}\.key\)\$|/prov.key|" "$STAGE/sandlot-prov.yaml"
grep -q 'prov\.key' "$STAGE/sandlot-prov.yaml" || err "prov.key rewrite did not land in $STAGE/sandlot-prov.yaml"

# ──── Validation (affinity wiring self-check) ────
log "[8/9] Validating generated configs..."
FAIL=0
for f in "$STAGE"/gateway-exec-*.yaml; do
    gid=$(grep '^gateway_id:' "$f" | awk '{print $2}')
    au=$(grep '^gateway_url:' "$f" | awk '{print $2}' | tr -d '"')
    sa=$(grep '^gateway_stream_addr:' "$f" | awk '{print $2}' | tr -d '"')
    it=$(grep '^idle_timeout_sec:' "$f" | awk '{print $2}')
    [[ -z "$gid" || -z "$au" || -z "$sa" || "$it" != "3600" ]] && { echo "  [FAIL] $f missing affinity fields (id=$gid au=$au sa=$sa it=$it)"; FAIL=1; continue; }
    echo "  [OK] $f → gateway_id=$gid gateway_url=$au stream_addr=$sa"
done
# gateway_id uniqueness across exec GWs
GID_COUNT=$(grep -h '^gateway_id:' "$STAGE"/gateway-exec-*.yaml | sort -u | wc -l)
[[ "$GID_COUNT" != "$N_EXEC" ]] && { echo "  [FAIL] gateway_id not unique ($GID_COUNT unique for $N_EXEC GWs)"; FAIL=1; }
grep -q 'sandfs: sandfs.sandswap.local' "$STAGE/sandns.yaml" || { echo "  [FAIL] sandns yaml missing sandfs zone"; FAIL=1; }
grep -q 'gateway_addr:.*sandswap-stream.local' "$STAGE"/sandlot-*.yaml || { echo "  [FAIL] sandlot yaml not using DNS-name gateway_addr"; FAIL=1; }
# Storage plane present: prov config exists, is prov-only (no pool), and
# targets the human gateway's :9996.
[[ -f "$STAGE/sandlot-prov.yaml" ]] || { echo "  [FAIL] sandlot-prov.yaml missing (storage plane absent — every sandfs op would 503)"; FAIL=1; }
if [[ -f "$STAGE/sandlot-prov.yaml" ]]; then
    grep -q '^roles: \[prov\]' "$STAGE/sandlot-prov.yaml" || { echo "  [FAIL] sandlot-prov.yaml not roles=[prov]"; FAIL=1; }
    grep -q '^pool:' "$STAGE/sandlot-prov.yaml" && { echo "  [FAIL] sandlot-prov.yaml carries a pool (prov-only refuses exec machinery)"; FAIL=1; }
    grep -q "gateway_addr:.*:9996" "$STAGE/sandlot-prov.yaml" || { echo "  [FAIL] sandlot-prov.yaml not dialing the human gateway :9996"; FAIL=1; }
    # The volume-name seed is REQUIRED for the prov role (rotation feature):
    # a config without the key makes the prov instance refuse to start — the
    # exact drift the bare-metal deploy matrix finds across five scripts.
    # Assert it at generation time, here.
    grep -q '^  volume_seed_file:' "$STAGE/sandlot-prov.yaml" || { echo "  [FAIL] sandlot-prov.yaml lacks provision.volume_seed_file (prov refuses to start without the seed)"; FAIL=1; }
fi
grep -q 'addr: "0.0.0.0:9996"' "$STAGE/gateway-human.yaml" || { echo "  [FAIL] human gateway stream listener not on :9996"; FAIL=1; }
[[ "$FAIL" == "1" ]] && err "config validation FAILED"
log "Config validation PASSED ($N_EXEC exec GWs, $GID_COUNT unique ids, sandfs zone enabled)"

# ──── Per-node SSH install commands (operator runs) ────
log "[4/9]-[7/9] Per-node install commands (scp $STAGE/* + certs, then):"
log " PROV HOST PREP: on the prov (storage) host run setup-host with"
log "  SS_PROV_USER=sandprov — the merged-dev default (sandlot) breaks the"
log "  dedicated prov instance's volume writes after any re-prep."
log " CERT SCOPING (stream identity): ship ca.key to NO node (the CA"
log "  signing key stays on the deploy host — it can mint fleet-trusted certs); each"
log "  node gets exactly ca.crt + ITS OWN client pair (sandlot.<crt,key> for the first"
log "  config entry, else sandlot-<node_id>.<crt,key>) — the gateway binds a stream"
log "  hello's node_id to the client cert's CN by exact match, so a pair shipped to"
log "  the wrong host is refused at the handshake by name; the prov host additionally"
log "  gets its prov pair + the prov.key copy; the volume-seed file ships ONLY to"
log "  prov hosts; the registry credential never rides argv (config file 0640"
log "  root:<group>)."
log "  exec gateway:    gateway-exec-<i>.yaml → /etc/sandswap/gateway-exec.yaml; sandswap-gateway@exec"
log "  human gateway:   gateway-human.yaml → /etc/sandswap/; sandswap-gateway@human"
log "  sandns:    sandns.yaml → /etc/sandswap/; sandswap-sandns.service"
log "  sandlot:         sandlot-<node>.yaml → /etc/sandswap/sandlot.yaml; sandswap-sandlot.service"
log "  prov (STORAGE):  sandlot-prov.yaml → HUMAN GW HOST /etc/sandswap/; sandswap-sandlot-prov.service"
log "                   (copy certs/${PROV_CERT_BASE}.key → certs/prov.key chown sandprov 0640 and ship"
log "                    certs/${PROV_CERT_BASE}.crt + certs/ca.crt — the config's cert line names that"
log "                    pair; mkdir -p"
log "                    $SHARED_MOUNT/templates chown sandprov:sandlot chmod 2750; install the"
log "                    sandlot binary; the human gw host must have the shared storage mounted)"
log "                   chown root:sandprov /etc/sandswap/sandlot-prov.yaml && chmod 0640 —"
log "                   the config may carry an OCI registry credential (scp does not"
log "                   preserve the staged file's mode)."
log "  (Follow docs/deployment/install-baremetal.md for the full SSH flow; configs are ready in $STAGE/)"

if [[ $DRY_RUN -eq 1 ]]; then
    log "Dry run COMPLETE: configs generated + validated in $STAGE (PKI generation skipped)."
fi

log "[9/9] Agent DNS configuration: point agent hosts at the sandns IP and use"
log "      MCP base URL https://<sandfs_id>.sandfs.sandswap.local:3000/mcp"
log "      (dnsmasq: server=/sandswap.local/<sandns-ip> covers the *.sandswap.local subdomains)"
