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
# deploy-cluster-one-gw.sh — Small cluster deployment (1 GW host + N sandlots).
#
# LOCAL-ONLY BY DESIGN (owner decision): this script contains NO
# ssh/scp. Remote rollout is the orchestrator's job (Ansible, a config
# manager, or plain rsync) — every earlier ssh payload bug class (heredoc
# variable expansion, remote directory creation, partial shipments) exists
# only because deployment travelled as ssh script text. The model now:
#
#   1. CONTROL HOST:  --prepare  → build + certs + per-node configs into a
#                      SELF-CONTAINED stage dir (default output/baremetal-onegw/)
#                      that includes a copy of the cluster config.
#   2. SHIP the release tree (or the repo) + the stage dir to every host.
#   3. EACH HOST:     run this script with --role <gateway|sandlot|all>.
#                      Roles auto-detect from the config when omitted
#                      (hostname/IP match against gateway.host / sandlots[].host;
#                      a single host matching both runs `all` — the blessed
#                      single-box rehearsal, with the colocated-instances
#                      admission applied to both units).
#
# Single-box one-command rehearsal: `--config <yaml>` alone = prepare + all +
# verify (the pre-split behavior, now role-composed).
#
# Topology: the gateway host runs exec + human gateways co-located
# (sandswap-gateway@exec on :3000/:9998, @human on :3100) against an etcd
# store — identity and SandFS records survive gateway restarts. With no
# etcd.endpoints in the config the script installs a co-located single-node
# etcd (mTLS) on the gateway host. No sandns — sandlots dial the
# gateway service address directly.
#
# Storage plane: the gateway host also runs the PROV-role sandlot instance
# (compact topology) connected to the HUMAN gateway's prov-only stream
# listener on :9996. Without it every sandfs/template op is the named 503
# "no provision instance connected". The human gateway's stream listener MUST
# NOT be :9998 (exec owns it on this host — a collision kills the human
# gateway at bind time).
#
# Usage:
#   # control host (prepares the stage; installs nothing):
#   bash deploy-cluster-one-gw.sh --config cluster-simple.yaml --prepare
#   # each target host (stage dir shipped alongside the tree):
#   bash deploy-cluster-one-gw.sh --stage /opt/sandswap/output/baremetal-onegw --role gateway
#   bash deploy-cluster-one-gw.sh --stage /opt/sandswap/output/baremetal-onegw --role sandlot
#   # single box, one command (prepare + all roles + verify):
#   bash deploy-cluster-one-gw.sh --config cluster-simple.yaml
#
# Flags: --config FILE | --role prepare|gateway|sandlot|all|auto | --stage DIR
#        | --dry-run | --skip-build
#        (--config may be omitted when the stage dir exists: it carries a copy
#         of the cluster config from --prepare)
#
# cluster-simple.yaml format:
#   gateway:
#     host: gateway1.example.com        # service address (DNS name or IP);
#                                        # ports are fixed at 3000/3100/9998
#   etcd:                               # optional — omit to have this script
#     endpoints:                        # install a co-located single-node
#       - "https://etcd1.example.com:2379"  # etcd on the gateway host
#   shared_storage:
#     type: nfs
#     mount_point: /mnt/sandswap
#     nfs_server: nfs1.example.com
#     nfs_export: /export/sandswap
#   sandlots:
#     - host: sandlot1.example.com
#       node_id: sandlot-1
#       pool: "medium:5"
#       subnet: "10.188.1.0/24"          # per-node guest VM subnet (optional)
#       net_gateway_ip: "10.188.1.1"     # guest-network bridge IP on this host
#                                        # (optional; IPv4 inside subnet, .1 by
#                                        # convention) — NOT the gateway service
#                                        # address, that is gateway.host above

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/common.sh"
# bm_build_artifacts (prepare's build step) lives here, not in common.sh.
source "$SCRIPT_DIR/deploy-lib.sh"

CONFIG=""
ROLE="auto"
STAGE=""
DRY_RUN=0
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)     CONFIG="$2"; shift 2 ;;
        --role)       ROLE="$2"; shift 2 ;;
        --stage)      STAGE="$2"; shift 2 ;;
        --dry-run)    DRY_RUN=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help)
            sed -n '/^# Usage:/,/^# cluster-simple/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) err "Unknown argument: $1" ;;
    esac
done

case "$ROLE" in
    auto|prepare|gateway|sandlot|all) ;;
    *) err "--role must be one of: auto|prepare|gateway|sandlot|all" ;;
esac

OUTPUT="$REPO_ROOT/output"
DEPLOY_DIR="$SCRIPT_DIR"
STAGE="${STAGE:-$OUTPUT/baremetal-onegw}"
TLS_DIR="/etc/sandswap/certs"

# ──── Config: explicit --config, else the stage copy (self-describing) ────

if [[ -z "$CONFIG" && -f "$STAGE/cluster.yaml" ]]; then
    CONFIG="$STAGE/cluster.yaml"
    log "Using the staged cluster config: $CONFIG"
fi
[[ -z "$CONFIG" ]] && err "--config is required (or run --prepare first so \$STAGE/cluster.yaml exists)"
[[ ! -f "$CONFIG" ]] && err "Config file not found: $CONFIG"

parse_yaml() {
    python3 -c "
import yaml, sys, json
with open('$CONFIG') as f:
    d = yaml.safe_load(f)
print(json.dumps(d))
" 2>/dev/null
}

CLUSTER_JSON=$(parse_yaml) || err "Failed to parse $CONFIG (requires python3 + PyYAML)"

GW_HOST=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('gateway',{}).get('host',''))")
[[ -z "$GW_HOST" ]] && err "gateway.host is required"
SHARED_TYPE=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('shared_storage',{}).get('type',''))")
SHARED_MOUNT=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('shared_storage',{}).get('mount_point','/mnt/sandswap'))")
NFS_SERVER=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('shared_storage',{}).get('nfs_server',''))")
NFS_EXPORT=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('shared_storage',{}).get('nfs_export',''))")

# etcd: explicit endpoints use an existing cluster; absent → this script
# installs a co-located single-node etcd on the gateway host (mTLS).
ETCD_ENDPOINTS=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(','.join(d.get('etcd',{}).get('endpoints',[])))")
DEPLOY_ETCD=0
if [[ -z "$ETCD_ENDPOINTS" ]]; then
    ETCD_ENDPOINTS="https://127.0.0.1:2379"
    DEPLOY_ETCD=1
fi

SL_COUNT=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('sandlots',[])))")

# ──── Role auto-detection (local identity vs the config) ────

LOCAL_NAMES=("$(hostname)" "localhost" "127.0.0.1")
while IFS= read -r ip; do [[ -n "$ip" ]] && LOCAL_NAMES+=("$ip"); done < <(hostname -I 2>/dev/null | tr ' ' '\n' || true)

matches_local() { # <configured host> — hostname, localhost, or a local IP
    local h="$1" n
    for n in "${LOCAL_NAMES[@]}"; do
        [[ "$h" == "$n" ]] && return 0
    done
    return 1
}

GW_IS_LOCAL=0; SL_LOCAL_INDICES=()
matches_local "$GW_HOST" && GW_IS_LOCAL=1
for i in $(seq 0 $((SL_COUNT - 1))); do
    h=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i]['host'])")
    matches_local "$h" && SL_LOCAL_INDICES+=("$i")
done

if [[ "$ROLE" == "auto" ]]; then
    if [[ "$GW_IS_LOCAL" == "1" && ${#SL_LOCAL_INDICES[@]} -gt 0 ]]; then
        ROLE="all"
    elif [[ "$GW_IS_LOCAL" == "1" ]]; then
        ROLE="gateway"
    elif [[ ${#SL_LOCAL_INDICES[@]} -gt 0 ]]; then
        ROLE="sandlot"
    else
        err "this host matches no role in $CONFIG (gateway=$GW_HOST, sandlots=$SL_COUNT entries).
       Pass --role <gateway|sandlot|all> explicitly if the config names another address for this host."
    fi
    log "Role auto-detected: $ROLE"
fi

log "Cluster Simple Deployment"
log "  Gateway host: $GW_HOST (exec :3000/:9998 + human :3100, EtcdStore)"
if [[ "$DEPLOY_ETCD" == "1" ]]; then
    log "  etcd: co-located single-node on $GW_HOST (mTLS)"
else
    log "  etcd: $ETCD_ENDPOINTS"
fi
log "  Shared storage: $SHARED_TYPE at $SHARED_MOUNT"
log "  Role: $ROLE${DRY_RUN:+ (dry-run $DRY_RUN)}"
log "  Stage: $STAGE"
log "  Dry run: $DRY_RUN"

# ──── Shared storage (per host, both roles) ────

mount_shared_storage() {
    # Type-scoped: nfs mounts with the storage contract's flags (nosuid,nodev)
    # and a duplicate-guarded fstab line so it survives reboots; anything else
    # refuses loudly (fail fast beats a silent private dir). Mirrors
    # sandswap_mount_shared_storage in common.sh.
    case "${SHARED_TYPE:-}" in
      nfs)
          local nfs_src="${NFS_SERVER}:${NFS_EXPORT}"
          [[ -n "$NFS_SERVER" && -n "$NFS_EXPORT" ]] || err "shared_storage.nfs_server/nfs_export required for type=nfs"
          mkdir -p "$SHARED_MOUNT"
          if ! mountpoint -q "$SHARED_MOUNT"; then
              mount -t nfs -o nosuid,nodev,vers=4.2,_netdev "$nfs_src" "$SHARED_MOUNT" \
                  || mount -t nfs -o nosuid,nodev,_netdev "$nfs_src" "$SHARED_MOUNT"
          fi
          grep -q " $SHARED_MOUNT nfs " /etc/fstab \
              || echo "$nfs_src $SHARED_MOUNT nfs nosuid,nodev,_netdev,nofail 0 0" >> /etc/fstab
          # A LOOPBACK rehearsal share is disposable: the previous rehearsal's
          # volumes carry stamps under a retired volume-seed generation, and
          # the prov's startup guard rightly refuses a share whose stamps are
          # ALL unverifiable. Reset the volumes tree so every rehearsal
          # starts clean. A real remote share is NEVER touched — its volumes
          # are live data; only 127.0.0.1 (the documented local-sample shape)
          # enters this branch.
          if [[ "$NFS_SERVER" == "127.0.0.1" ]]; then
              local vold="$SHARED_MOUNT/volumes" e
              if [[ -d "$vold" ]]; then
                  for e in "$vold"/* "$vold"/.*; do
                      [[ -e "$e" && "$(basename "$e")" != "." && "$(basename "$e")" != ".." ]] || continue
                      rm -rf -- "$e" || err "cannot reset the loopback rehearsal share ($e) — remove it and re-run"
                  done
              fi
              mkdir -p "$vold"
          fi
          ;;
      "")
          err "shared_storage.type missing from the cluster config" ;;
      *)
          err "shared_storage.type '${SHARED_TYPE}' is not implemented by this deployer (supported: nfs). Refusing to continue with a private empty dir." ;;
    esac
}

# ──── --prepare: build + certs + configs into the stage dir ────

# THE STREAM IDENTITY MAP of this deployment: the node id every sandlot
# instance declares ↔ the client certificate pair carrying it as CN. The
# gateway binds hello.node_id == the client cert's CN by exact match (a shared
# deployment-wide pair is refused by name), so the stage ships ONE PAIR PER
# NODE and each host installs only its own. `sandlot-<node>.crt/.key` names a
# pair; the FIRST config entry's node rides the primary pair (sandlot.*), so a
# single-node cluster keeps the plain filename. The prov instance is its own
# node ("sandlot-prov", running on the gateway host in this topology).
PROV_NODE_ID="sandlot-prov"
sandlot_node_ids() { # every exec node id in the cluster config, in order
    local i
    for i in $(seq 0 $((SL_COUNT - 1))); do
        echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i]['node_id'])"
    done
}
sandlot_cert_base() { # <node-id> → the pair basename carrying it as CN
    local node="$1" first
    # First id without `| head -1`: a truncated pipeline could SIGPIPE one of
    # the per-id producers, and `pipefail` would then fail the assignment and
    # abort the deploy (the id list is tiny — read it whole, take the first line).
    first="$(sandlot_node_ids)"
    first="${first%%$'\n'*}"
    if [[ -n "$first" && "$node" == "$first" ]]; then
        echo "sandlot"
    else
        echo "sandlot-${node}"
    fi
}
PROV_CERT_BASE="$(sandlot_cert_base "$PROV_NODE_ID")"

prepare_stage() {
    log "[prepare] Building artifacts into $STAGE ..."
    if [[ $DRY_RUN -eq 1 ]]; then
        log "  (dry-run: would run build.sh all)"
    elif [[ $SKIP_BUILD -eq 0 ]]; then
        # Fatal on failure: the old `[[ ... ]] && bm_build_artifacts || log`
        # form turned a missing function/build failure into a misleading
        # "(dry-run...)" note and deployed the stale output/ tree.
        bm_build_artifacts
    else
        ss_verify_kernel_artifact "$OUTPUT/vmlinux.bin" "$REPO_ROOT/kernel/build.sh" \
            || err "Refusing --skip-build with a non-pinned kernel under output/ — run bash build/build.sh kernel"
    fi

    # SANs: the gateway service address (agent/stream certs for TLS clients,
    # and the co-located etcd server cert so https://<host> dials verify).
    # Resolution failure falls back to the hostname itself.
    local gw_sans_ip
    gw_sans_ip=$(getent hosts "$GW_HOST" 2>/dev/null | awk '{print $1}' | head -1 || true)
    [[ -z "$gw_sans_ip" ]] && gw_sans_ip="$GW_HOST"

    log "[prepare] Generating TLS certificates (one client pair per node id)..."
    if [[ $DRY_RUN -eq 0 ]]; then
        # Mint: the primary pair for the first node + one --client-cn pair per
        # remaining node and for the prov node. Every node id the fleet will
        # declare must exist here BEFORE the configs are generated below.
        local -a node_ids=() extra_cn=() extra_args=() n
        while IFS= read -r n; do [[ -n "$n" ]] && node_ids+=("$n"); done < <(sandlot_node_ids)
        local primary="${node_ids[0]:-$PROV_NODE_ID}"
        for n in ${node_ids[@]+"${node_ids[@]}"}; do
            [[ "$n" == "$primary" ]] || extra_cn+=("$n")
        done
        [[ "$primary" == "$PROV_NODE_ID" ]] || extra_cn+=("$PROV_NODE_ID")
        # The certificate is the role grant: the prov node id gets role/prov,
        # every exec node id role/exec.
        for n in ${extra_cn[@]+"${extra_cn[@]}"}; do
            if [[ "$n" == "$PROV_NODE_ID" ]]; then
                extra_args+=(--client-cn "${n}:prov")
            else
                extra_args+=(--client-cn "${n}:exec")
            fi
        done
        primary_roles="exec"
        [[ "$primary" == "$PROV_NODE_ID" ]] && primary_roles="prov"
        SANDLOT_NODE_ID="$primary" \
            bash "$SCRIPT_DIR/gen-baremetal-certs.sh" "$OUTPUT/baremetal-certs" \
            --sans-dns "$GW_HOST" \
            --sans-ip "$gw_sans_ip" \
            --client-roles "$primary_roles" \
            ${extra_args[@]+"${extra_args[@]}"}
        # Ship-ready cert subset: the CA SIGNING key (ca.key) NEVER enters the
        # stage ( — it stays only on the control host and can mint
        # fleet-trusted certs).
        rm -rf "$STAGE/certs"
        mkdir -p "$STAGE/certs"
        local f
        for f in $(cd "$OUTPUT/baremetal-certs" && ls); do
            [[ "$f" == "ca.key" ]] && continue
            cp -a "$OUTPUT/baremetal-certs/$f" "$STAGE/certs/"
        done
    else
        log "  (dry-run: would generate certs with SANs: DNS=$GW_HOST IP=$gw_sans_ip)"
    fi

    log "[prepare] Generating per-node configs → $STAGE"
    [[ $DRY_RUN -eq 1 ]] && { log "  (dry-run: skipping config generation)"; return 0; }
    mkdir -p "$STAGE"

    # exec gateway: routing addresses (etcd registry key: 307 redirect target,
    # sandlot last-gateway reconnect target) are the gateway service address
    # itself — no DNS in this topology.
    SANDSWAP_GATEWAY_ID="gw-exec-1" \
    SANDSWAP_GATEWAY_URL="https://${GW_HOST}:3000" \
    SANDSWAP_GATEWAY_STREAM_ADDR="${GW_HOST}:9998" \
    SANDSWAP_IDLE_TIMEOUT_SEC=3600 \
        sandswap_generate_gateway_config \
        "$STAGE/gateway-exec.yaml" \
        "exec" \
        "$SHARED_MOUNT/volumes" \
        "0.0.0.0:3000" \
        "127.0.0.1:3100" \
        "0.0.0.0:9998" \
        "$TLS_DIR" \
        "$ETCD_ENDPOINTS"
    # Human gateway binds :3100 + its OWN prov-only stream listener on :9996
    # (never :9998 — the exec instance owns that port on this host, and a
    # collision kills the human gateway at bind time).
    sandswap_generate_gateway_config \
        "$STAGE/gateway-human.yaml" \
        "human" \
        "$SHARED_MOUNT/volumes" \
        "0.0.0.0:3000" \
        "127.0.0.1:3100" \
        "0.0.0.0:9996" \
        "$TLS_DIR" \
        "$ETCD_ENDPOINTS"

    # Prov instance: roles=prov dialing the HUMAN gateway's :9996; template
    # store under the shared mount; no KVM duty on the gateway host. Its tls
    # block points at the pair carrying ITS node id as CN (sandlot-prov) — the
    # key half is re-pointed at the sandprov-owned prov.key copy right below.
    SANDSWAP_SANDLOT_ROLES=prov \
    SANDSWAP_NETWORK_BACKEND=none \
    SANDSWAP_FLAT_TEMPLATES_DIR="$SHARED_MOUNT/flat-templates" \
    SANDSWAP_PROVISION_TEMPLATES_DIR="$SHARED_MOUNT/templates" \
    SANDSWAP_SANDLOT_CERT_BASE="$PROV_CERT_BASE" \
        sandswap_generate_sandlot_config \
        "$STAGE/sandlot-prov.yaml" \
        "127.0.0.1:9996" \
        "$PROV_NODE_ID" \
        "" \
        "10.189.254.0/24" \
        "10.189.254.1" \
        "$SHARED_MOUNT/volumes" \
        "$TLS_DIR"
    # The generator's empty-pool fallback would add medium:3 — a prov-only
    # instance must carry NO pool (the validator refuses exec machinery on
    # prov-only roles). Same for the TLS key: prov runs as sandprov and reads
    # prov.key (the sandswap_prepare_provision_host copy of THIS node's pair).
    sed -i '/^pool:/d' "$STAGE/sandlot-prov.yaml"
    sed -i "s|\(/${PROV_CERT_BASE}\.key\)\$|/prov.key|" "$STAGE/sandlot-prov.yaml"
    grep -q 'prov\.key' "$STAGE/sandlot-prov.yaml" || err "prov.key rewrite did not land in $STAGE/sandlot-prov.yaml"
    # the staged config may carry the OCI registry credential —
    # never leave it world-readable.
    chmod 0640 "$STAGE/sandlot-prov.yaml" 2>/dev/null || true

    # Per-sandlot exec configs (one file per node entry, shipped in the stage
    # so every host is self-contained and the config is reviewable BEFORE it
    # lands in /etc). Each config's tls block points at the pair whose CN is
    # that node's id.
    local i node pool subnet gw_ip node_base
    for i in $(seq 0 $((SL_COUNT - 1))); do
        node=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i]['node_id'])")
        pool=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i].get('pool','medium:3'))")
        subnet=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i].get('subnet','10.188.0.0/16'))")
        gw_ip=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i].get('net_gateway_ip','10.188.0.1'))")
        node_base="$(sandlot_cert_base "$node")"
        SANDSWAP_NETWORK_BACKEND=bridge \
        SANDSWAP_SANDLOT_CERT_BASE="$node_base" \
            sandswap_generate_sandlot_config \
            "$STAGE/sandlot-${node}.yaml" \
            "${GW_HOST}:9998" \
            "$node" \
            "$pool" \
            "$subnet" \
            "$gw_ip" \
            "$SHARED_MOUNT/volumes" \
            "$TLS_DIR"
    done

    # Self-describing stage: the cluster config travels with it, so a target
    # host needs only `--stage <dir> --role <role>`. The marker is the ONLY
    # completeness signal for the install path — a stage left by an older
    # deployer (configs but no certs/ dir) must not be consumed half-made.
    cp -f "$CONFIG" "$STAGE/cluster.yaml"
    date -u +%Y-%m-%dT%H:%M:%SZ > "$STAGE/.prepared"
    log "[prepare] Stage ready: $STAGE"
    log "  Ship this directory (plus the release tree/repo) to every host, then:"
    log "    gateway host:  bash deploy/baremetal/deploy-cluster-one-gw.sh --stage $STAGE --role gateway"
    for i in $(seq 0 $((SL_COUNT - 1))); do
        node=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i]['node_id'])")
        log "    $node: bash deploy/baremetal/deploy-cluster-one-gw.sh --stage $STAGE --role sandlot"
    done
}

# ──── Probe the local host for a usable etcd binary ────

etcd_binary() {
    if command -v etcd >/dev/null 2>&1; then
        command -v etcd; return 0
    fi
    if [[ -x "$OUTPUT/etcd/etcd" ]]; then
        echo "$OUTPUT/etcd/etcd"; return 0
    fi
    sandswap_fetch_etcd "$OUTPUT/etcd" >/dev/null 2>&1 || true
    [[ -x "$OUTPUT/etcd/etcd" ]] && { echo "$OUTPUT/etcd/etcd"; return 0; }
    return 1
}

# ──── Role: gateway (etcd + exec GW + human GW + prov instance) ────

install_gateway() {
    log "[gateway] Installing on THIS host ($GW_HOST): etcd + exec :3000/:9998 + human :3100 + prov"
    # DEDICATED-prov shape: every prov-side path — the local dirs,
    # the seed, prov-user.env for the units' ExecStartPost, and the shared
    # mount's volumes/template store — is owned by sandprov. Set BEFORE any
    # helper runs, so setup-host and sandswap_apply_prov_plane (the SINGLE
    # ownership implementation, ) all agree on the shape.
    export SS_PROV_USER=sandprov
    mount_shared_storage

    bash "$DEPLOY_DIR/setup-host.sh" --role gateway

    # Local prov-side contract (seed mint, /etc/sandswap, local dirs,
    # prov-user.env) — the shared implementation every deployer uses.
    sandswap_apply_prov_plane
    # ...and its SHARED-MOUNT half (cluster shapes keep volumes/templates on
    # the shared filesystem, not under /var/lib/sandswap): share root
    # traverse-only for the daemon, template stores prov-owned read-only
    # peers. Same modes as the local contract.
    mkdir -p "$SHARED_MOUNT"/{volumes,templates}
    chown "$SS_PROV_USER":"$SS_SHARED_GROUP" "$SHARED_MOUNT/volumes" 2>/dev/null || true
    chmod 2710 "$SHARED_MOUNT/volumes" 2>/dev/null || true
    chown "$SS_PROV_USER":"$SS_SHARED_GROUP" "$SHARED_MOUNT/templates" 2>/dev/null || true
    chmod 2750 "$SHARED_MOUNT/templates" 2>/dev/null || true
    chown "$SS_PROV_USER":"$SS_SHARED_GROUP" "$SHARED_MOUNT/flat-templates" 2>/dev/null || true
    chmod 2750 "$SHARED_MOUNT/flat-templates" 2>/dev/null || true

    # Binaries (from the tree; on a release-tree host these are prebuilt).
    install -m 0755 "$OUTPUT/gateway" /usr/local/bin/sandswap-gateway

    # Certs (ship-ready subset, no ca.key) + identity-scoped key ownership.
    # PER-NODE MATERIAL ONLY: this host gets the server material plus the
    # client pairs its own sandlot processes present — the prov pair always,
    # and (single-host rehearsal) the local exec node's pair. A pair that can
    # claim another node's stream identity stays in the stage.
    mkdir -p /etc/sandswap
    install -d -m 0755 "$TLS_DIR"
    local f
    local -a want=(ca.crt stream.crt stream.key mcp.crt mcp.key human.crt human.key admin.crt admin.key \
        etcd-server.crt etcd-server.key etcd-client.crt etcd-client.key \
        "${PROV_CERT_BASE}.crt" "${PROV_CERT_BASE}.key")
    for i in ${SL_LOCAL_INDICES[@]+"${SL_LOCAL_INDICES[@]}"}; do
        local n
        n=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i]['node_id'])")
        want+=("$(sandlot_cert_base "$n").crt" "$(sandlot_cert_base "$n").key")
    done
    for f in "${want[@]}"; do
        [[ -f "$STAGE/certs/$f" ]] || err "stage is missing ${f} (prepare it with this deployer — the stage must carry every client pair this host serves)"
        cp -a "$STAGE/certs/$f" "$TLS_DIR/"
    done
    # shellcheck disable=SC1090
    source "$REPO_ROOT/common/sh/runtime.sh"
    ss_own_tls_keys "$TLS_DIR"
    # The prov config's cert path must carry the prov node id — assert it here
    # (the shipped config is generated on the control host; a stale stage from
    # before the per-node scheme would present another node's CN and be
    # refused at the handshake with no hint of why).
    sandswap_verify_client_cert_cn "$TLS_DIR/${PROV_CERT_BASE}.crt" "$PROV_NODE_ID" \
        || err "prov stream client cert does not carry the prov node id"

    # Rootfs template store on the shared mount (template contract: group
    # grant + canonical normalize).
    mkdir -p "$SHARED_MOUNT"/{volumes,flat-templates}
    rm -rf "$SHARED_MOUNT/flat-templates/rootfs/v1"
    mkdir -p "$SHARED_MOUNT/flat-templates/rootfs/v1"
    cp -a "$OUTPUT/rootfs-template/." "$SHARED_MOUNT/flat-templates/rootfs/v1/"
    chgrp -R "$SS_SHARED_GROUP" "$SHARED_MOUNT/flat-templates" 2>/dev/null || true
    [[ -x "$OUTPUT/template-tool" ]] && "$OUTPUT/template-tool" normalize "$SHARED_MOUNT/flat-templates" >/dev/null

    # Gateway configs (staged on the control host; template units read
    # /etc/sandswap/gateway-<mode>.yaml).
    cp "$STAGE/gateway-exec.yaml" "$STAGE/gateway-human.yaml" /etc/sandswap/

    # MCP agent guide: materialize the ops-editable instructions file from the
    # compiled-in default (generate-once), then point the exec gateway at it —
    # append only when the staged config lacks the block (a duplicate mcp key
    # fails YAML decoding at startup).
    if [[ ! -s /etc/sandswap/mcp-instructions.md ]]; then
        /usr/local/bin/sandswap-gateway -print-mcp-instructions > /etc/sandswap/mcp-instructions.md
    fi
    grep -q "^mcp:" /etc/sandswap/gateway-exec.yaml || cat >> /etc/sandswap/gateway-exec.yaml << 'YAML'

mcp:
  instructions_file: /etc/sandswap/mcp-instructions.md
YAML

    # Co-located single-node etcd (mTLS with the generated certs; persistent
    # data dir — identity must survive reboots).
    if [[ "$DEPLOY_ETCD" == "1" ]]; then
        local bin
        bin=$(etcd_binary) || err "no etcd binary available (PATH, output/etcd, or download)"
        # Idempotent re-runs: etcd_binary() may resolve to the ALREADY INSTALLED
        # /usr/local/bin/etcd (PATH probe) — install(1) refuses src==dst.
        [[ "$bin" == /usr/local/bin/etcd ]] || install -m 0755 "$bin" /usr/local/bin/etcd
        cat > /etc/systemd/system/sandswap-etcd.service << 'UNIT'
[Unit]
Description=Sandswap co-located etcd (single node, mTLS)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/etcd --name sandswap-etcd --listen-client-urls https://127.0.0.1:2379 --advertise-client-urls https://127.0.0.1:2379 --listen-peer-urls http://127.0.0.1:2380 --initial-advertise-peer-urls http://127.0.0.1:2380 --initial-cluster sandswap-etcd=http://127.0.0.1:2380 --initial-cluster-token sandswap-etcd --initial-cluster-state new --data-dir /var/lib/sandswap-etcd --cert-file /etc/sandswap/certs/etcd-server.crt --key-file /etc/sandswap/certs/etcd-server.key --trusted-ca-file /etc/sandswap/certs/ca.crt --client-cert-auth --log-level warn
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable --now sandswap-etcd
    fi

    # Gateway instances (template unit). Disable the legacy combined unit if a
    # previous single-process deploy left it enabled.
    systemctl disable --now sandswap-gateway 2>/dev/null || true
    cp "$DEPLOY_DIR/systemd/sandswap-gateway@.service" /etc/systemd/system/
    install_vsock_retune_unit
    systemctl daemon-reload
    systemctl enable --now sandswap-gateway@exec sandswap-gateway@human

    # Prov-role sandlot instance (compact-topology storage plane), running as
    # the sandprov identity via the SHIPPED unit, dialing :9996.
    install -m 0755 "$OUTPUT/sandlot" /usr/local/bin/sandswap-sandlot
    # prov.key: sandprov's own readable copy of the prov NODE's client key
    # (derived from the pair whose CN is the prov node id — see
    # sandswap_prepare_provision_host; the shape ownership above already
    # shaped the shared mount).
    cp "$TLS_DIR/${PROV_CERT_BASE}.key" "$TLS_DIR/prov.key"
    chown "$SS_PROV_USER":"$SS_PROV_USER" "$TLS_DIR/prov.key" 2>/dev/null || true
    chmod 0640 "$TLS_DIR/prov.key" 2>/dev/null || true
    cp "$STAGE/sandlot-prov.yaml" /etc/sandswap/sandlot-prov.yaml
    # The prov config may carry an OCI registry credential — scope it to the
    # reading identity.
    ss_protect_config /etc/sandswap/sandlot-prov.yaml sandprov
    cp "$DEPLOY_DIR/systemd/sandswap-sandlot-prov.service" /etc/systemd/system/
    colocate_unit /etc/systemd/system/sandswap-sandlot-prov.service
    systemctl daemon-reload
    systemctl reset-failed sandswap-sandlot-prov 2>/dev/null || true
    systemctl enable --now sandswap-sandlot-prov
}

# ──── Role: sandlot (exec instance for THIS host's config entry) ────

install_sandlot() {
    [[ ${#SL_LOCAL_INDICES[@]} -eq 1 ]] || err "this host matches ${#SL_LOCAL_INDICES[@]} sandlot entries in the config — exactly one is required (one sandlot per host)"
    local i="${SL_LOCAL_INDICES[0]}"
    local node subnet gw_ip pool
    node=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i]['node_id'])")
    subnet=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i].get('subnet','10.188.0.0/16'))")
    gw_ip=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i].get('net_gateway_ip','10.188.0.1'))")
    pool=$(echo "$CLUSTER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['sandlots'][$i].get('pool','medium:3'))")
    log "[sandlot] Installing on THIS host: node=$node pool=$pool subnet=$subnet"

    mount_shared_storage
    bash "$DEPLOY_DIR/setup-host.sh" --role sandlot --subnet "$subnet" --gateway-ip "$gw_ip"

    install -m 0755 "$OUTPUT/sandlot" /usr/local/bin/sandswap-sandlot
    install -m 0755 "$OUTPUT/sandvmm" /usr/local/bin/sandswap-sandvmm
    sandswap_install_guest_artifacts "$OUTPUT"
    [[ -f "$OUTPUT/vsockguard.bpf.o" ]] && install -m 0644 "$OUTPUT/vsockguard.bpf.o" /var/lib/sandswap/
    [[ -x "$OUTPUT/vsockguardctl" ]] && install -m 0755 "$OUTPUT/vsockguardctl" /usr/local/bin/

    # Cert subset for an EXEC node: exactly the client material for THIS
    # node's id ( extended by the stream-identity rule) — never
    # ca.key, never etcd server material, never the volume-name seed, and
    # never another node's client pair.
    mkdir -p /etc/sandswap
    install -d -m 0755 "$TLS_DIR"
    local f node_base
    node_base="$(sandlot_cert_base "$node")"
    for f in ca.crt "${node_base}.crt" "${node_base}.key"; do
        [[ -f "$STAGE/certs/$f" ]] || err "stage is missing ${f} — the client pair for node '$node' (node_id) was not minted during prepare"
        cp -a "$STAGE/certs/$f" "$TLS_DIR/"
    done
    # shellcheck disable=SC1090
    source "$REPO_ROOT/common/sh/runtime.sh"
    ss_own_tls_keys "$TLS_DIR"
    # The CN of the pair the config points at must BE this node's id (the
    # gateway refuses a mismatch at the handshake; fail the deploy instead).
    sandswap_verify_client_cert_cn "$TLS_DIR/${node_base}.crt" "$node" \
        || err "stream client cert for node '$node' does not carry that node id"

    cp "$STAGE/sandlot-${node}.yaml" /etc/sandswap/sandlot.yaml
    cp "$DEPLOY_DIR/systemd/sandswap-sandlot.service" /etc/systemd/system/
    colocate_unit /etc/systemd/system/sandswap-sandlot.service
    install_vsock_retune_unit
    systemctl daemon-reload
    systemctl reset-failed sandswap-sandlot 2>/dev/null || true
    systemctl enable --now sandswap-sandlot
}

# ──── Boot-time device ownership ────
# udev applies the vsock ownership rules when it PROCESSES the device; a node
# whose /dev/vhost-vsock already exists at rule-load time (every reboot) keeps
# its distro default (root:kvm 0660) and the exec sandlot refuses to start
# ("owned by uid 0, want the sandvmm identity 987"). The oneshot unit
# re-triggers exactly
# the two devices after udevd, before any sandlot unit; installing it here
# gives every cluster node the same boot health the single-node deployers
# already have.
install_vsock_retune_unit() {
    cp "$DEPLOY_DIR/systemd/sandswap-vsock-retune.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now sandswap-vsock-retune.service
}

# ──── Single-host rehearsal admission ────
# When one host carries BOTH the exec sandlot and the prov instance (role
# `all` — the blessed single-box rehearsal, mirroring the one-machine-etcd
# deploy's exec+prov pair), the one-sandlot-per-host role lock needs its
# explicit admission on the installed units.
colocate_unit() { # <installed unit file>
    local f="$1"
    if [[ "$ROLE" == "all" ]] && ! grep -q "allow-colocated-instances" "$f"; then
        sed -i 's|^ExecStart=\(.*\)$|ExecStart=\1 -allow-colocated-instances|' "$f"
        log "  colocated-instances admission applied to $(basename "$f") (single-host rehearsal)"
    fi
}

# ──── Verification (local, role-scoped) ────

verify_local() {
    log "[verify] Cluster verification (local)..."
    if [[ "$ROLE" == "gateway" || "$ROLE" == "all" ]]; then
        if [[ "$DEPLOY_ETCD" == "1" ]]; then
            # is-active without `|| true`: a stopped unit is a failed deploy.
            systemctl is-active sandswap-etcd sandswap-gateway@exec sandswap-gateway@human sandswap-sandlot-prov
        fi
        sleep 3
        curl -sk -m 10 https://localhost:3100/stats | python3 -m json.tool 2>/dev/null || log "  human gateway not answering yet"
    fi
    # Provision-plane gate (the storage plane lives on the gateway host).
    if [[ "$ROLE" == "all" || "$ROLE" == "gateway" ]]; then
        local prov_ok=0 body
        for _ in $(seq 1 30); do
            body=$(curl -sk -m 5 https://localhost:3100/health 2>/dev/null || true)
            if echo "$body" | grep -qE '"provisioners":[[:space:]]*[1-9]'; then prov_ok=1; break; fi
            sleep 2
        done
        if [[ "$prov_ok" == "1" ]]; then
            log "  Provision plane ready (>=1 prov instance connected)"
        else
            err "no provision instance connected after 60s — every sandfs/template op will 503"
        fi
    fi
    # Sandlot presence: node_count on the gateway (reachable over plain https
    # from this host when it is not the gateway host itself).
    if [[ "$ROLE" == "all" || "$ROLE" == "sandlot" ]]; then
        # The exec gateway's /stats is gated by -ops-token-file (empty =
        # DISABLED); the human gateway serves the etcd-aggregated fleet view,
        # including every exec gateway's node_count.
        local gw_url="https://${GW_HOST}:3100" ok=0 nc
        for _ in $(seq 1 30); do
            # node_count lives on the GATEWAY object (the per-node objects
            # carry clean_vms/total_vms) — reading it off the node entries
            # counts zeros forever.
            nc=$(curl -sk -m 5 "$gw_url/stats" 2>/dev/null | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print(sum(g.get('node_count',0) for g in d.get('gateways',[])))
except Exception:
    print(0)" 2>/dev/null || echo 0)
            if [[ "${nc:-0}" -ge 1 ]]; then ok=1; break; fi
            sleep 2
        done
        if [[ "$ok" == "1" ]]; then
            log "  Sandlot connected (node_count=$nc)"
        else
            err "no sandlot node visible on the gateway after 60s"
        fi
    fi
}

# ──── Dispatch ────

if [[ "$ROLE" == "prepare" ]]; then
    prepare_stage
    [[ $DRY_RUN -eq 0 ]] && log "[prepare] Done — installs nothing on this host."
    exit 0
fi

# Installs consume the stage; prepare it first when missing (control-host
# convenience — the one-command single-box path).
if [[ ! -f "$STAGE/.prepared" && $DRY_RUN -eq 0 ]]; then
    log "Stage dir missing or incomplete (no .prepared marker) — running prepare first."
    prepare_stage
fi

if [[ $DRY_RUN -eq 1 ]]; then
    log "(dry-run: would install role $ROLE from $STAGE; nothing changed)"
    exit 0
fi

case "$ROLE" in
    gateway) install_gateway ;;
    sandlot) install_sandlot ;;
    all)     install_gateway; install_sandlot ;;
esac

verify_local

log "============================================"
log "  Small cluster deployment complete!  (role: $ROLE)"
log "============================================"
