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
# sandswap-ops.sh — Sandswap operations CLI for bare-metal clusters
# Usage:
#   sandswap-ops.sh status                          # Cluster status overview
#   sandswap-ops.sh health                          # Check all gateway /health
#   sandswap-ops.sh logs gateway [N]                # Recent journalctl lines
#   sandswap-ops.sh logs sandlot [N]                # Recent journalctl lines
#   sandswap-ops.sh start/stop/restart <svc>        # systemctl operations
#   sandswap-ops.sh pool list                       # List all sandlot pool status
#   sandswap-ops.sh pool resize <node> <spec>       # Hot-reload pool size
#   sandswap-ops.sh pool drain <node>               # Graceful shrink to 0
#   sandswap-ops.sh scale add-sandlot ...           # Add sandlot node
#   sandswap-ops.sh scale remove-sandlot ...        # Remove sandlot node
#   sandswap-ops.sh consolidate                     # Smart rebalance (min migration)
#   sandswap-ops.sh consolidate --full              # Full rebalance (clear all sticky)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# ──── Config Loading ────

CONFIG_FILE="${SANDSWAP_CONFIG:-/etc/sandswap/cluster.yaml}"
GW_ADDRS=()
HUMAN_GW_ADDR=""
DNS_ADDR=""

load_cluster_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        # Fall back to local single-node mode. Pool stats live on the human
        # listener (the exec listener's /stats is -ops-token-file gated).
        GW_ADDRS=("localhost:3000")
        HUMAN_GW_ADDR="localhost:3100"
        return
    fi
    # Minimal indentation-aware YAML walk (no PyYAML dependency). The old
    # heuristic (`host:.*gw-exec || host:.*gateway`) matched NEITHER shipped
    # sample: `gateways.exec` entries are plain `- host: gw1.example.com`, so
    # GW_ADDRS stayed empty and status/health/pool silently checked nothing
    # while exiting 0. Track the section (and the exec|human subsection under
    # `gateways:`) and take every host line in the right place.
    local section="" sub="" line host
    while IFS= read -r line; do
        line="${line%%#*}"
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        if [[ "$line" =~ ^([a-z_]+): ]]; then
            section="${BASH_REMATCH[1]}"; sub=""; continue
        fi
        if [[ "$line" =~ ^[[:space:]]+(exec|human):[[:space:]]*$ ]]; then
            sub="${BASH_REMATCH[1]}"; continue
        fi
        [[ "$line" =~ host:[[:space:]]*(.+)$ ]] || continue
        host="${BASH_REMATCH[1]}"
        host="$(echo "$host" | tr -d '"'"'"' ')"
        case "${section}:${sub}" in
            gateways:exec|gateway:) GW_ADDRS+=("$host:3000") ;;
            gateways:human)         HUMAN_GW_ADDR="$host:3100" ;;
            dns:)                   DNS_ADDR="$host" ;;
        esac
    done < "$CONFIG_FILE"
}

load_cluster_config

# ──── TLS verification ────
# The operator runs on the deployed host, so verify against the deployment CA
# instead of disabling verification. The cert SANs cover localhost/127.0.0.1;
# a multi-host config without the local CA falls back to -k with a warning.
SANDSWAP_CA="${SANDSWAP_CA:-/etc/sandswap/certs/ca.crt}"
CURL_TLS=()
if [[ "${NO_TLS:-}" != "1" ]]; then
    if [[ -f "$SANDSWAP_CA" ]]; then
        CURL_TLS=(--cacert "$SANDSWAP_CA")
    else
        CURL_TLS=(-k)
        warn "no CA at $SANDSWAP_CA — TLS verification disabled for this run (set SANDSWAP_CA)"
    fi
fi

# ──── Helper Functions ────

gw_health() {
    local addr="$1"
    local proto="https"
    if [[ "${NO_TLS:-}" == "1" ]]; then proto="http"; fi
    curl -s "${CURL_TLS[@]}" "${proto}://${addr}/health" 2>/dev/null
}

gw_stats() {
    local addr="$1"
    local proto="https"
    if [[ "${NO_TLS:-}" == "1" ]]; then proto="http"; fi
    curl -s "${CURL_TLS[@]}" "${proto}://${addr}/stats" 2>/dev/null
}

# ──── Commands ────

cmd_status() {
    log "Sandswap Cluster Status"
    log "========================"

    for addr in "${GW_ADDRS[@]}"; do
        local health
        health=$(gw_health "$addr")
        if [[ -n "$health" ]]; then
            log "  GW $addr: healthy"
            # The exec listener gates /stats behind -ops-token-file (disabled
            # by default); the human gateway serves the fleet view.
            local stats_addr="${HUMAN_GW_ADDR:-$addr}"
            gw_stats "$stats_addr" 2>/dev/null | python3 -m json.tool 2>/dev/null || \
                gw_stats "$stats_addr" 2>/dev/null || true
        else
            warn "  GW $addr: unreachable"
        fi
        echo
    done
}

cmd_health() {
    local ok=0 fail=0
    for addr in "${GW_ADDRS[@]}"; do
        if gw_health "$addr" >/dev/null 2>&1; then
            log "  $addr: OK"
            ok=$((ok+1))
        else
            warn "  $addr: FAIL"
            fail=$((fail+1))
        fi
    done
    log "Result: $ok OK, $fail FAIL"
    [[ $fail -eq 0 ]]
}

cmd_logs() {
    local service="${1:-gateway}"
    local lines="${2:-50}"

    case "$service" in
        gateway) journalctl -u "sandswap-gateway*" -n "$lines" --no-pager ;;
        sandlot) journalctl -u "sandswap-sandlot*" -n "$lines" --no-pager ;;
        sandns)  journalctl -u "sandswap-sandns.service" -n "$lines" --no-pager ;;
        *)       err "Unknown service: $service (gateway|sandlot|sandns)" ;;
    esac
}

cmd_pool_list() {
    for addr in "${GW_ADDRS[@]}"; do
        log "GW $addr:"
        gw_stats "$addr" 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin)
# new format: gateways[].nodes[] with clean_vms/total_vms/active_sandfs
for gw in d.get('gateways', []):
    for n in gw.get('nodes', []):
        print(f'  {n.get(\"node_id\",\"?\")}: CLEAN={n.get(\"clean_vms\",0)} TOTAL={n.get(\"total_vms\",0)} ACTIVE_SANDFS={n.get(\"active_sandfs\",0)}')
if not d.get('gateways'):
    # legacy format: nodes{} -> pool{}
    p = d.get('pool', {})
    nodes = d.get('nodes', {})
    for nid, n in nodes.items():
        pool = n.get('pool', {})
        print(f'  {nid}: IN_USE={pool.get(\"in_use\",0)} CLEAN={pool.get(\"clean\",0)} LEASED={pool.get(\"leased\",0)} RELEASING={pool.get(\"releasing\",0)}')
" 2>/dev/null || log "  (no data)"
    done
}

# Resolve the config file holding a node's pool line: single-node installs use
# /etc/sandswap/sandlot.yaml; the sims / cluster deploys write sandlot-<id>.yaml
# (or sandlot-<id>.yaml via the @.service template). Matching on node_id inside
# the file beats guessing paths.
resolve_sandlot_config() { # <node_id>
    local node_id="${1:-}"
    local f
    [[ -n "$node_id" ]] || { echo ""; return; }
    # Scan EVERY sandlot config and match the DECLARED node_id — the file NAME
    # scheme differs per deployer (`sandlot-<node_id>.yaml` in the simulations,
    # `sandlot-<instance>.yaml` in the systemd instance deploys, where the
    # declared node_id is `<host>-<instance>`), so a name-shaped lookup missed
    # the one-machine deployment entirely ("no config for node 'sandbox2-main'
    # found"). Matching the declaration is the only scheme-
    # proof rule, and it can never edit another node's config (which would
    # resize the WRONG pool and claim success). Prov-only configs carry no
    # pool — skipped.
    local base inst eff
    for f in /etc/sandswap/sandlot-*.yaml /etc/sandswap/sandlot.yaml; do
        [[ -f "$f" ]] || continue
        [[ "$(basename "$f")" == "sandlot-prov.yaml" ]] && continue
        base="$(sed -n 's/^node_id:[[:space:]]*"\?\([^"]*\)"\?.*/\1/p' "$f" | head -1)"
        [[ -n "$base" ]] || continue
        # The EFFECTIVE node id the gateway reports is `<node_id>-<instance.id>`
        # for instance deploys (config `instance: id: main` over
        # node_id "sandbox2" ⇒ the gateway shows "sandbox2-main", and that is
        # what an operator copies into pool resize). Match BOTH the base id and
        # the composed one.
        inst="$(sed -n 's/^[[:space:]]*id:[[:space:]]*"\?\([^"]*\)"\?.*/\1/p' "$f" | head -1)"
        eff="$base"
        [[ -n "$inst" ]] && eff="${base}-${inst}"
        if [[ "$node_id" == "$base" || "$node_id" == "$eff" ]]; then
            echo "$f"; return
        fi
    done
    echo ""
}

cmd_pool_resize() {
    local node_id="${1:?node_id required}"
    local spec="${2:?spec required (e.g., medium:5)}"

    # Edit sandlot config on the target node
    local config
    config=$(resolve_sandlot_config "$node_id")
    if [[ -n "$config" ]]; then
        sed -i "s/^pool:.*/pool: \"${spec}\"/" "$config"
        log "Pool resized to $spec for $node_id (hot-reload: watcher will apply)"
    else
        err "no config for node '$node_id' found (looked for a sandlot-<id>.yaml, then a sandlot.yaml DECLARING that node_id)"
    fi
}

cmd_pool_drain() {
    local node_id="${1:?node_id required}"
    # Keep the configured spec, set only the count to 0 ("<node>:0" is not a
    # valid pool spec — the spec name must be preserved).
    local config
    config=$(resolve_sandlot_config "$node_id")
    local spec
    # `|| true` inside the pipeline: without it pipefail turns a grep no-match
    # into an assignment failure under set -e — silently exiting the script and
    # making the medium fallback below dead code.
    spec=$({ grep -E '^pool:' "$config" 2>/dev/null || true; } | sed 's/^pool:[[:space:]]*"\?\([^":]*\).*/\1/' | tr -d '[:space:]')
    [[ -z "$spec" ]] && spec="medium"
    cmd_pool_resize "$node_id" "${spec}:0"
    log "Pool draining for $node_id (set to ${spec}:0, graceful)"
}

cmd_consolidate() {
    local full="${1:-}"

    if [[ "$full" == "--full" ]]; then
        log "Full consolidation: releasing all ownership + clearing all DNS sticky..."
    else
        log "Smart consolidation: analyzing load + minimal migration..."
    fi

    # Step 1: Get stats from all exec GWs
    local -a gw_stats_output=()
    for addr in "${GW_ADDRS[@]}"; do
        gw_stats_output+=("$(gw_stats "$addr" 2>/dev/null || echo '{}')")
    done

    # Step 2: If human GW is configured, release ownership for consolidation
    if [[ -n "$HUMAN_GW_ADDR" ]]; then
        local proto="https"
        if [[ "${NO_TLS:-}" == "1" ]]; then proto="http"; fi

        # Get list of sandfs from human GW. The endpoint is CURSOR-PAGINATED
        # ({"items":[...],"next_cursor":...}) and the record's id field is
        # `sandfs_id` — the previous bare-array + `id` reading counted 2 items
        # for a paginated body, then released NOTHING (AttributeError swallowed
        # by 2>/dev/null) and still reported success.
        local sandfs_list
        sandfs_list=$(SANDSWAP_CA="$SANDSWAP_CA" curl -s "${CURL_TLS[@]}" "${proto}://${HUMAN_GW_ADDR}/human/sandfs?limit=1000" 2>/dev/null || echo '{"items":[]}')

        if [[ "$full" == "--full" ]]; then
            local count
            count=$(echo "$sandfs_list" | python3 -c "
import json,sys
d=json.load(sys.stdin)
items=d.get('items', d) if isinstance(d, dict) else d
print(len(items) if isinstance(items, list) else 0)
" 2>/dev/null) || { err "could not parse the sandfs list from $HUMAN_GW_ADDR/human/sandfs"; }
            log "Releasing ownership for $count sandfs via human GW..."
            local released
            released=$(echo "$sandfs_list" | SANDSWAP_CA="$SANDSWAP_CA" python3 -c "
import json, ssl, sys, urllib.request
# Verify against the deployment CA when it is available (SANDSWAP_CA); the
# -k fallback exists only for a multi-host run without the local CA.
import os
_ca = os.environ.get('SANDSWAP_CA', '')
if _ca and os.path.isfile(_ca):
    ctx = ssl.create_default_context(cafile=_ca)
else:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
d = json.load(sys.stdin)
items = d.get('items', []) if isinstance(d, dict) else d
ok = fail = 0
for s in items:
    sid = s.get('sandfs_id') or s.get('id') or ''
    if not sid:
        continue
    try:
        req = urllib.request.Request('${proto}://${HUMAN_GW_ADDR}/human/ownership/release/' + sid, method='POST')
        urllib.request.urlopen(req, context=ctx)
        ok += 1
    except Exception:
        fail += 1
print('%d %d' % (ok, fail))
" 2>/dev/null) || err "ownership release loop failed to run (python3 missing?)"
            log "  ownership released: ${released% *} (failed: ${released#* })"
            if [[ "${released#* }" != "0" ]]; then
                warn "some ownership releases FAILED (${released#* }) — re-run or check the human gateway's logs"
            fi
            if [[ -n "$(echo "$sandfs_list" | python3 -c "import json,sys; d=json.load(sys.stdin); print('more' if isinstance(d,dict) and d.get('truncated') else '')" 2>/dev/null)" ]]; then
                warn "the sandfs list was TRUNCATED (limit=1000) — re-run consolidate until it reports no truncation"
            fi
        else
            # Smart: only release ownership for over-loaded GWs
            # TODO: implement smart selection based on /stats data
            log "Smart consolidation: analyzing which sandfs to migrate..."
            log "(For now, using full consolidation)"
            cmd_consolidate --full
            return
        fi
    fi

    # Step 3: DNS sticky clear — INSTRUCTED, not executed.
    # The DNS is a pure :53 service (no control plane); clearing its sticky
    # cache is a local signal on the DNS host. The ownership release above is
    # what consolidation is FOR and it is already done; sticky is bounded —
    # dead/unregistered targets self-heal immediately and the rest expire at
    # sticky_expire — so the SIGHUP is an accelerator, not a requirement. This
    # script is local-only by design (owner decision): remote
    # execution belongs to the operator or the orchestrator (Ansible), so we
    # print the command instead of ssh-ing to it.
    if [[ -n "$DNS_ADDR" ]]; then
        log "To clear the DNS sticky cache NOW, run on the DNS host ($DNS_ADDR):"
        log "  systemctl kill -s SIGHUP sandns   # unit-scoped, clears all sticky records"
        log "  (without it, sticky entries self-heal on target loss and expire at sticky_expire)"
    fi

    log "Consolidation initiated. Agents will re-resolve DNS within TTL (${TTL:-10}s)"
}

cmd_scale_add_sandlot() {
    local host="${1:?host required}"
    local node_id="${2:?node_id required}"
    # Reserved for the future automation (the command currently prints manual
    # steps and errs — see below); keeping the documented signature stable.
    # shellcheck disable=SC2034
    local pool="${3:-medium:3}"
    # shellcheck disable=SC2034
    local subnet="${4:-}"
    # shellcheck disable=SC2034
    local gateway_ip="${5:-}"

    log "Adding sandlot node: $node_id at $host"
    log "  1. Mint this node's stream client pair on the PKI host: SANDLOT_NODE_ID=$node_id"
    log "     bash deploy/baremetal/gen-baremetal-certs.sh <certs-dir>  (the gateway binds"
    log "     node_id == the client cert's CN, so ship ONLY this node's pair + ca.crt)"
    log "  2. Run setup-host.sh --role sandlot on $host"
    log "  3. Install binary + generate sandlot.yaml (node_id: $node_id, tls.cert/key = this pair)"
    log "  4. systemctl enable --now sandswap-sandlot"
    log "  5. Sandlot auto-connects gateway → OnConnect → ReconcileNode"
    log "  6. DNS auto-discovers new sandlot (via GW /stats)"
    err "Not yet automated. Run the steps above manually on $host"
}

cmd_scale_remove_sandlot() {
    local node_id="${1:?node_id required}"
    log "Removing sandlot node: $node_id"
    log "  1. Drain pool: sandswap-ops.sh pool drain $node_id"
    log "  2. Wait for all VMs to drain (IN_USE → 0)"
    log "  3. systemctl stop sandswap-sandlot"
    log "  4. Gateway detects disconnect → ownership released after lease expiry"
    err "Not yet automated. Run the steps above manually"
}

# ──── Main ────

# No argument is NOT "help": a CLI that prints its usage and exits 0 looks
# like a successful run to any caller that checks only the exit code (the
# script matrix recorded exactly that as a PASS until it was caught). Help is
# explicit (`help`), and the no-argument form fails like every other tool in
# this tree.
if [[ $# -eq 0 ]]; then
    echo "Usage: sandswap-ops.sh <command> [args]  (commands: sandswap-ops.sh help)" >&2
    exit 2
fi
cmd="$1"
shift || true

case "$cmd" in
    status)              cmd_status ;;
    health)              cmd_health ;;
    logs)                cmd_logs "$@" ;;
    start|stop|restart)
        # Friendly names → REAL units. The deployed unit set is templated and
        # instance-scoped (sandswap-gateway@exec/@human, sandswap-sandlot,
        # sandswap-sandlot-instance@<id>, sandswap-sandlot-prov, sandswap-etcd,
        # sandns), so the old literal `systemctl $cmd sandswap-$1`
        # addressed a unit that never exists and every call failed with
        # "Unit sandswap-gateway.service not found".
        # Candidates are filtered by EXISTENCE, so one alias covers both the
        # single-node and the instance shapes.
        _svc_candidates() {
            case "$1" in
                gateway)       echo "sandswap-gateway.service sandswap-gateway@exec.service sandswap-gateway@human.service";;
                gateway-exec|exec)   echo "sandswap-gateway@exec.service";;
                gateway-human|human) echo "sandswap-gateway@human.service";;
                sandlot)       echo "sandswap-sandlot.service sandswap-sandlot-instance@main.service";;
                prov)          echo "sandswap-sandlot-prov.service";;
                etcd)          echo "sandswap-etcd.service";;
                sandns)        echo "sandswap-sandns.service";;
                *)             echo "sandswap-$1.service";;
            esac
        }
        _found=""
        for _u in $(_svc_candidates "$1"); do
            # `systemctl cat` resolves template INSTANCES too (list-unit-files
            # only shows the @.service template, so an instance probe via it
            # never matched and the restart silently never ran).
            if systemctl cat "$_u" >/dev/null 2>&1; then
                systemctl "$cmd" "$_u"
                _found="1"
            fi
        done
        if [[ -z "$_found" ]]; then
            err "no unit matches '$1'. Known sandswap units:
$(systemctl list-unit-files 'sandswap-*' --no-legend 2>/dev/null | awk '{print "  " $1}')"
        fi
        ;;
    pool)
        sub="${1:-list}"
        shift || true
        case "$sub" in
            list)   cmd_pool_list ;;
            resize) cmd_pool_resize "$@" ;;
            drain)  cmd_pool_drain "$@" ;;
            *)      err "Unknown pool subcommand: $sub" ;;
        esac
        ;;
    scale)
        sub="${1:-}"
        shift || true
        case "$sub" in
            add-sandlot)    cmd_scale_add_sandlot "$@" ;;
            remove-sandlot) cmd_scale_remove_sandlot "$@" ;;
            *)              err "Usage: scale {add-sandlot|remove-sandlot}" ;;
        esac
        ;;
    consolidate) cmd_consolidate "${1:-}" ;;
    help|*)
        echo "Sandswap Operations CLI"
        echo ""
        echo "Commands:"
        echo "  status                           Cluster status"
        echo "  health                           Check all gateway /health"
        echo "  logs gateway|sandlot|sandns [N]  Recent log lines"
        echo "  start|stop|restart <svc>         systemctl operation"
        echo "  pool list                        List pool status"
        echo "  pool resize <node> <spec>        Hot-reload pool"
        echo "  pool drain <node>                Graceful shrink to 0"
        echo "  scale add-sandlot ...            Add sandlot node"
        echo "  scale remove-sandlot ...         Remove sandlot node"
        echo "  consolidate [--full]              Rebalance traffic"
        ;;
esac
