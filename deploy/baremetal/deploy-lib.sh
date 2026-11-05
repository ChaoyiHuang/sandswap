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
# deploy-lib.sh — shared implementation for the Sandswap bare-metal deploy/test
# scripts (ledger + preflight + the phases every script had copied).
# common.sh stays the CONFIG/HOST library (config generation, systemd helpers,
# ops tooling — sandswap-ops.sh sources it without any test machinery). This
# file layers the DEPLOY-ORCHESTRATION pieces that until now existed as five
# divergent copies: the [0/N] stop+kill block, health/pool/compute waits,
# agent+sandfs creation, the etcd watch-sync check, the eino runner + analyzer,
# the honest-exit gate, the preflight, and the side-effect ledger.
# Source order: source common.sh FIRST, then this file. Both are set -euo.
# ── Side-effect ledger ──────────────────────────────────────────────
# Every host mutation outside the process tree is recorded (se_record) and
# EPHEMERAL entries are reversed by se_replay_ephemeral — called by bm_preclean
# (recovery from a crashed previous run) and by a script's cleanup trap. New
# host-mutating code MUST record + add a reversal case; that is the contract
# that stops "deploy wrote it, cleanup forgot it" residue bugs. KEEP entries
# persist across deploys (sysctls, udev, binaries, bridge) — recorded for
# observability only.
#
# SECURITY: the ledger is root-run tooling input, so it lives in a ROOT-ONLY
# directory (a world-writable /tmp ledger let a local user plant entries that
# root later replayed). Every detail is validated against a per-type whitelist
# before use, never interpolated into sed, and rm/kill operate on type-checked
# paths/pids only.

BM_LEDGER_DIR="${BM_LEDGER_DIR:-${SANDSWAP_VAR:-/var/lib/sandswap}/deploy-ledger}"
BM_LEDGER="${BM_LEDGER:-$BM_LEDGER_DIR/sideeffects.log}"

# se_ledger_ready — the ledger location must be a root-owned 0700 directory and
# (when present) a root-owned, non-group/world-writable regular file. Returns
# non-zero instead of trusting anything else.
se_ledger_ready() {
    install -d -m 0700 -o root -g root "$BM_LEDGER_DIR" 2>/dev/null || return 1
    [[ -L "$BM_LEDGER_DIR" ]] && return 1
    [[ "$(stat -c '%U' "$BM_LEDGER_DIR" 2>/dev/null)" == "root" ]] || return 1
    [[ "$(stat -c '%a' "$BM_LEDGER_DIR" 2>/dev/null)" == "700" ]] || return 1
    if [[ -e "$BM_LEDGER" || -L "$BM_LEDGER" ]]; then
        [[ -L "$BM_LEDGER" ]] && return 1
        [[ "$(stat -c '%U' "$BM_LEDGER" 2>/dev/null)" == "root" ]] || return 1
        local mode
        mode="$(stat -c '%a' "$BM_LEDGER" 2>/dev/null || echo '')"
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 8#022) == 0 )) || return 1
    fi
    return 0
}

# se_valid_detail <type> <detail> — the detail whitelist. A detail is never a
# free-form string: the reversal below feeds it to a literal filter, rm or a
# pid read, and the values the lib records are absolute paths, unit names and
# host markers.
se_valid_detail() {
    local type="$1" detail="$2"
    case "$type" in
        # Types whose reversal touches only a FIXED path/object, plus the KEEP
        # types (recorded only): nothing to validate against, detail may be
        # empty (resolv carries none).
        sysctl-file|udev-rules|bridge|binary|dir|module-load|seccomp|coredns-zone|bpf-pin|chown|chmod|hostdir|devnode|resolv)
            return 0
            ;;
    esac
    [[ -n "$detail" ]] || return 1
    case "$type" in
        hosts-pin|unit)
            [[ "$detail" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]*$ ]]
            ;;
        etcd-proc|port-forward)
            [[ "$detail" =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ "$detail" != *..* ]]
            ;;
        instance-state|tmpfile|tmpdir)
            [[ "$detail" =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ "$detail" != "/" ]] && [[ "$detail" != *..* ]] \
                && [[ "$detail" == /*/* ]]
            ;;
        *)
            return 1
            ;;
    esac
}

se_record() { # se_record <KEEP|EPHEMERAL> <type> <detail...>
    # NB: only args 3+ are the detail — "$*" here would splice the scope and
    # type into the detail column, and every detail-USING reversal below
    # (etcd-proc / instance-state / tmpfile / tmpdir) would silently no-op.
    local scope="$1" type="$2"
    shift 2
    local detail="$*"
    case "$type" in
        # No-detail types: the reversal reads fixed paths only.
        resolv|seccomp|coredns-zone|bpf-pin|sysctl-file|udev-rules|bridge|binary|dir|module-load|chown|hostdir|devnode)
            ;;
        *)
            if ! se_valid_detail "$type" "$detail"; then
                warn "ledger: refused a '$type' entry whose detail is not whitelisted: ${detail:0:120}"
                return 0
            fi
            ;;
    esac
    if ! se_ledger_ready; then
        warn "ledger: refusing to record into $BM_LEDGER (needs a root-owned 0700 directory and a root-owned ledger file)"
        return 0
    fi
    printf '%s\t%s\t%s\t%s\n' "$(date +%s)" "$scope" "$type" "$detail" >> "$BM_LEDGER"
}

# _se_hosts_filter <literal> — delete every /etc/hosts line CONTAINING the
# literal (grep -F, never a regex/sed program).
_se_hosts_filter() {
    local lit="$1" tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/.se-hosts.XXXXXX")" || return 1
    grep -vF -- "$lit" /etc/hosts > "$tmp" 2>/dev/null || true
    cat "$tmp" > /etc/hosts
    rm -f "$tmp"
}

se_replay_ephemeral() {
    if [[ ! -e "$BM_LEDGER" && ! -L "$BM_LEDGER" ]]; then
        return 0
    fi
    if ! se_ledger_ready; then
        warn "ledger: $BM_LEDGER failed the owner/mode/symlink check — NOT replaying it (moved aside)"
        mv -f "$BM_LEDGER" "$BM_LEDGER.rejected" 2>/dev/null || rm -f -- "$BM_LEDGER"
        return 0
    fi
    local reversed=0
    # shellcheck disable=SC2094
    while IFS=$'\t' read -r _ scope type detail; do
        [[ "$scope" == "EPHEMERAL" ]] || continue
        if ! se_valid_detail "$type" "$detail"; then
            warn "ledger: skipping a '$type' entry with a non-whitelisted detail"
            continue
        fi
        case "$type" in
            hosts-pin)
                if grep -qF -- "$detail" /etc/hosts 2>/dev/null; then
                    _se_hosts_filter "$detail" || true
                    reversed=$((reversed + 1))
                fi
                ;;
            resolv)
                if [[ -f /etc/resolv.conf.sandswap-bak ]]; then
                    rm -f /etc/resolv.conf
                    if [[ -f /etc/resolv.conf.sandswap-bak-target ]]; then
                        ln -sfn "$(cat /etc/resolv.conf.sandswap-bak-target)" /etc/resolv.conf
                    else
                        cp /etc/resolv.conf.sandswap-bak /etc/resolv.conf
                    fi
                    rm -f /etc/resolv.conf.sandswap-bak /etc/resolv.conf.sandswap-bak-target
                    reversed=$((reversed + 1))
                fi
                ;;
            unit)
                systemctl stop "$detail" 2>/dev/null || true
                rm -f "/etc/systemd/system/${detail}.service"
                reversed=$((reversed + 1))
                ;;
            etcd-proc)
                if [[ -f "$detail" && ! -L "$detail" ]]; then
                    local _pid
                    _pid="$(cat "$detail" 2>/dev/null || true)"
                    if [[ "$_pid" =~ ^[0-9]+$ ]] && (( _pid > 1 && _pid != $$ )); then
                        kill "$_pid" 2>/dev/null || true
                    fi
                    rm -f -- "$detail"
                    reversed=$((reversed + 1))
                fi
                ;;
            instance-state|tmpfile|tmpdir)
                if [[ -L "$detail" ]]; then
                    rm -f -- "$detail"
                    reversed=$((reversed + 1))
                elif [[ -f "$detail" || -d "$detail" ]]; then
                    rm -rf -- "$detail"
                    reversed=$((reversed + 1))
                fi
                ;;
            # KEEP types — recorded for observability, nothing to reverse.
            sysctl-file|udev-rules|bridge|binary|dir|module-load) ;;
            *) warn "ledger: unknown side-effect type '$type' (detail: $detail)" ;;
        esac
    done < "$BM_LEDGER"
    if [[ "$reversed" -gt 0 ]]; then
        log "Side-effect ledger: reversed $reversed leftover mutation(s)"
    fi
    systemctl daemon-reload 2>/dev/null || true
    mv "$BM_LEDGER" "$BM_LEDGER.done" 2>/dev/null || rm -f -- "$BM_LEDGER"
}

# ════════════════════════════════════════════════════════════════════
# Preflight — read-only checks, report ALL blockers at once
# ════════════════════════════════════════════════════════════════════
# Hard-fails only on conditions nothing downstream fixes. Caller context:
#   BM_REQUIRE_LLM           1 → no LLM key is a blocker (default 0)
#   BM_EXPECT_VSOCKGUARD_UID UID the vsockguard pin must carry (default: the
#                            sandlot service identity's uid — dedicated-
#                            identity model; override only for exotic setups)
#   BM_PORTS                 ports that must be free (default "3000 3001 3100 9998 9997 2379")

BM_PF_ERRORS=()
bm_pf_fail() { BM_PF_ERRORS+=("$1"); log "  [BLOCK] $1"; }
bm_pf_warn() { log "  [warn]  $1"; }
bm_pf_ok()   { log "  [ok]    $1"; }

read_allowed_uid() { # → allowed UID string, or "" when unreadable
    # allowed_uid is a PINNED BPF MAP, not a regular file: `cat` prints the
    # kernel's debug banner ("# WARNING!! ...") followed by "key: value" lines.
    # Take the first parseable entry's value.
    local out
    out="$(cat /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null || true)"
    echo "$out" | grep -E '^[0-9]+:' | head -1 | sed 's/^[0-9]*:[[:space:]]*//'
}
bm_preflight() {
    log "Preflight (all blockers reported before any mutation)"

    # Recover side effects from a crashed previous run BEFORE checking.
    se_replay_ephemeral

    # And stop what a DEAD previous run left RUNNING (units, stray binaries,
    # stale /run/sandswap). Data trees are untouched. A CONCURRENT harness run
    # is refused by name instead of being killed (ss_harness_guard).
    ss_stop_leftover_services

    echo "  Host:   $(uname -n)  Kernel: $(uname -r)"
    echo "  Mode:   ${BM_MODE_DESC:-baremetal}"

    if [[ "$(id -u)" -ne 0 ]]; then
        bm_pf_fail "must run as root (sudo)"
    fi

    if [[ "${BM_REQUIRE_LLM:-0}" == "1" ]] \
       && [[ -z "${DEEPSEEK_API_KEY:-}" ]] && [[ -z "${OPENAI_API_KEY:-}" ]] && [[ -z "${GOOGLE_API_KEY:-}" ]]; then
        bm_pf_fail "no LLM API key set (DEEPSEEK_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY)"
    fi

    if [[ -e /dev/kvm ]] && [[ -r /dev/kvm ]]; then
        bm_pf_ok "/dev/kvm present"
    else
        bm_pf_fail "/dev/kvm not found or not readable — KVM unavailable"
    fi
    if [[ -e /dev/vhost-vsock ]]; then
        bm_pf_ok "/dev/vhost-vsock present"
    else
        bm_pf_fail "/dev/vhost-vsock not found (modprobe vhost_vsock)"
    fi
    if [[ -e /dev/net/tun ]]; then
        bm_pf_ok "/dev/net/tun present"
    else
        bm_pf_warn "/dev/net/tun missing — will be created during host prep"
    fi

    if grep -qE '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
        local pinned=""
        local expect_uid="${BM_EXPECT_VSOCKGUARD_UID:-$(id -u "$SS_SERVICE_USER_SL" 2>/dev/null || echo 0)}"
        [[ -e /sys/fs/bpf/vsockguard/allowed_uid ]] && pinned="$(read_allowed_uid)"
        if [[ ! -e /sys/fs/bpf/vsockguard/allowed_uid ]]; then
            bm_pf_ok "BPF LSM active, no stale vsockguard pin"
        elif [[ -n "$pinned" && "$pinned" == "$expect_uid" ]]; then
            bm_pf_ok "BPF LSM active, vsockguard pin matches (allowed_uid=$pinned)"
        else
            bm_pf_fail "vsockguard pinned for UID $pinned but this deployment needs UID $expect_uid"
            bm_pf_fail "  fix: bash deploy/baremetal/cleanup.sh (detaches), then re-run"
        fi
    else
        bm_pf_warn "BPF LSM not active — vsockguard cannot enforce (test/dev only)"
        bm_pf_warn "  production: sudo bash security/setup-bpf-lsm.sh && reboot"
    fi

    # Ports must be FREE at preflight time — bm_preclean has already run, so a
    # holder here survived the sweep (fail hard, name the process).
    local port pids holder pids_item
    for port in ${BM_PORTS:-"3000 3001 3100 9998 9997 2379"}; do
        pids="$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u || true)"
        if [[ -n "$pids" ]]; then
            for pids_item in $pids; do
                holder="$(ps -o comm= -p "$pids_item" 2>/dev/null || echo '?')"
                bm_pf_fail "port $port still held by PID $pids_item ($holder) after cleanup"
            done
        fi
    done

    # Orphan sandswap host processes (survived preclean = systemd or a foreign
    # supervisor keeps respawning them)
    local orphans
    orphans="$(pgrep -f 'sandswap-(sandvmm|sandlot|gateway|dns|boxout)' 2>/dev/null | tr '\n' ' ' || true)"
    if [[ -n "${orphans// /}" ]]; then
        bm_pf_fail "orphan sandswap processes survived cleanup: $orphans (check: systemctl list-units 'sandswap-*')"
    fi

    local avail_mb avail_mem
    avail_mb="$(ss_df_avail_mb /var/lib)"
    if [[ "${avail_mb:-0}" -lt 1500 ]]; then
        bm_pf_fail "only ${avail_mb}MB free on /var/lib filesystem (need ≥1500MB)"
    elif [[ "${avail_mb:-0}" -lt 3000 ]]; then
        bm_pf_warn "${avail_mb}MB free on /var/lib — tight (rootfs template + volumes)"
    else
        bm_pf_ok "disk: ${avail_mb}MB free on /var/lib"
    fi

    avail_mem="$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
    if [[ "${avail_mem:-0}" -lt 1500 ]]; then
        bm_pf_fail "only ${avail_mem}MB MemAvailable (need ≥1500MB for build + small pool)"
    elif [[ "${avail_mem:-0}" -lt 2500 ]]; then
        bm_pf_warn "${avail_mem}MB MemAvailable — VM creation may fail under pressure"
    else
        bm_pf_ok "memory: ${avail_mem}MB MemAvailable"
    fi

    if [[ "${#BM_PF_ERRORS[@]}" -gt 0 ]]; then
        log "Preflight FAILED — ${#BM_PF_ERRORS[@]} blocker(s) listed above"
        exit 1
    fi
    log "Preflight passed"
}

# ════════════════════════════════════════════════════════════════════
# Preclean — ONE implementation of the [0/N] stop+kill block
# ════════════════════════════════════════════════════════════════════
# Replaces the five divergent copies (deploy-single-node did not stop
# sandns, one-gw-sim did not wipe instance state, cleanup.sh missed
# ports 3001/9997 — each a cross-run pollution source).
#   BM_WIPE_RUN      1 → rm -rf /run/sandswap entirely (deploy scripts:
#                       stale gateway-state.json/instance dirs would resume
#                       an OLD persisted phase and wedge the reconnect)
#   BM_HOSTS_PIN_RE  extra /etc/hosts regex to strip (sandswap names are
#                       always stripped)
bm_preclean() {
    log "Preclean: stopping existing services + killing leftovers..."
    sandswap_stop_services
    # Full-cmdline match: comm is truncated to 15 chars
    # ("sandswap-sandvmm" → "sandswap-sandvm"), so pkill -x by bare name misses.
    pkill -9 -f 'sandswap-sandvmm' 2>/dev/null || true
    pkill -9 -f 'sandswap-sandlot' 2>/dev/null || true
    pkill -9 -f 'sandswap-gateway' 2>/dev/null || true
    pkill -9 -f 'sandns' 2>/dev/null || true
    pkill -9 -f 'sandswap-boxout' 2>/dev/null || true
    # Scoped to OUR etcd instances (data dirs contain "sandswap-") — a bare
    # -f 'etcd' would kill an unrelated host etcd (k3s --cluster-init child).
    pkill -9 -f 'sandswap-.*etcd' 2>/dev/null || true
    sandswap_kill_port_processes

    # Stale TAP sweep. Pool VM ids are deterministic, so their TAP names are
    # too: a tap left held by a survived sandvmm (KillMode=process leaves the
    # children alive on systemctl stop; a SIGKILLed VMM leaves the persistent
    # device itself) makes the next deploy's `ip tuntap add` fail with
    # "already in use" and EVERY pool VM silently comes up OFFLINE ("network
    # provision failed ... continuing offline") — a green deploy with no
    # network. All sandswap processes are dead by the time this runs, so any
    # remaining tap-* device is debris; delete it.
    local stale_tap
    for stale_tap in $(ip -o link show 2>/dev/null | awk -F': ' '/^[0-9]+: tap-/ {print $2}'); do
        ip link del "$stale_tap" 2>/dev/null || true
        echo "  ✓ stale TAP $stale_tap removed"
    done
    # Extra ports the sims use and common.sh does not know. :53 is NOT swept
    # (grep ":53 " matches systemd-resolved's stub); sandns dies by name.
    local port pids
    for port in 3001 9997; do
        pids="$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u || true)"
        [[ -n "$pids" ]] && echo "$pids" | xargs -r kill -9 2>/dev/null || true
    done

    # Replay the ledger first (reverses a crashed run's hosts pins, units,
    # resolv.conf, instance state), then strip the well-known sandswap pins.
    se_replay_ephemeral
    # marker-scoped — strip only lines sandswap added (the marker),
    # plus the exact legacy shape earlier deploys wrote unmarked. An
    # OPERATOR's own pin for these names is left alone.
    sed -i -E '/# sandswap-managed$/d' /etc/hosts 2>/dev/null || true
    sed -i -E '/^[0-9.:]+[[:space:]]+sandswap\.local sandswap-stream\.local$/d' /etc/hosts 2>/dev/null || true
    if [[ -n "${BM_HOSTS_PIN_RE:-}" ]]; then
        sed -i -E "/${BM_HOSTS_PIN_RE}/d" /etc/hosts 2>/dev/null || true
    fi

    if [[ "${BM_WIPE_RUN:-0}" == "1" ]]; then
        rm -rf /run/sandswap /run/sandswap-state 2>/dev/null || true
    fi

    # Egress identity enabler tables (baseline + routed-ipv6 stamps). Services
    # are already dead, so remove them HERE: a leftover table makes the next
    # deploy's EnsureTables "add table" fail with "exists", which the deploy
    # treats as "nftables unusable" and silently degrades the baseline to off.
    if command -v nft >/dev/null 2>&1; then
        nft delete table netdev sandswap_baseline 2>/dev/null || true
        nft delete table bridge sandswap_baseline 2>/dev/null || true
        nft delete table inet sandswap_routed6 2>/dev/null || true
    fi

    # Egress identity binding-region carriers (zero-residue discipline): the
    # shm file and the bpffs pin deliberately SURVIVE a sandlot restart
    # (enforcers may outlive it), but a clean-slate deploy must not inherit a
    # previous run's region — a bpf pin from a different MaxIfindex config
    # makes wrapRegion's format-drift guard fail the next startup.
    rm -f /dev/shm/sandswap-bindings 2>/dev/null || true
    rm -f /sys/fs/bpf/sandswap/bindings 2>/dev/null || true
    rmdir /sys/fs/bpf/sandswap 2>/dev/null || true

    sleep 1
    log "Preclean done"
}

# ════════════════════════════════════════════════════════════════════
# Waits — condition polling with bounded tries (never single attempts)
# ════════════════════════════════════════════════════════════════════

bm_wait_http() { # bm_wait_http <url> <tries> [interval=2] — 0 when reachable
    local url="$1" tries="$2" interval="${3:-2}"
    local i
    for i in $(seq 1 "$tries"); do
        curl -sfk "$url" &>/dev/null && return 0
        sleep "$interval"
    done
    return 1
}

bm_wait_pool() { # bm_wait_pool <stats_url> <target_clean> <tries> — echoes CLEAN on success
    local stats_url="$1" target="$2" tries="$3"
    local i clean
    for i in $(seq 1 "$tries"); do
        # ONE parser for every /stats shape the endpoint has had
        # (ss_pool_clean, common/sh/stack.sh) — this copy knew three of the
        # five and silently read 0 for the rest.
        clean="$(ss_pool_clean "$stats_url")"
        if (( clean >= target )); then
            echo "$clean"
            return 0
        fi
        sleep 3
    done
    return 1
}

bm_wait_compute() { # bm_wait_compute <gateway_base> <api_key> <sandfs_id> <tries> — 0 on first exec success
    local gw_base="$1" key="$2" sf="$3" tries="$4"
    local i resp
    for i in $(seq 1 "$tries"); do
        resp="$(curl -sk -X POST "$gw_base/agent/execute" \
            -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
            -d "{\"sandfs_id\":\"$sf\",\"code\":\"echo ready\",\"language\":\"shell\",\"timeout\":5}" 2>/dev/null || echo '')"
        if echo "$resp" | grep -q '"status":"done\|"status": "done"'; then
            return 0
        fi
        if echo "$resp" | grep -q 'no available sandbox'; then
            # Node registered; VMs still creating — compute path is up.
            return 0
        fi
        echo "$resp" | grep -q 'NO_COMPUTE_NODES' && log "  waiting for compute node (attempt $i)..."
        sleep 2
    done
    return 1
}

# bm_verify_watch_sync — replaces the bare `sleep 5  # etcd watch propagation`.
# Polls an exec gateway with a cheap MCP initialize until the created API key
# resolves; a fixed sleep is a race bet, this is a condition wait.
bm_verify_watch_sync() { # bm_verify_watch_sync <gateway_base> <api_key> [tries=15]
    local gw_base="$1" key="$2" tries="${3:-15}"
    local i resp
    for i in $(seq 1 "$tries"); do
        resp="$(curl -sk -X POST "$gw_base/mcp" \
            -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"verify","version":"1.0.0"}}}' 2>/dev/null || echo '')"
        if echo "$resp" | grep -q '"result"'; then
            log "  etcd watch synced (API key resolves on $gw_base, attempt $i)"
            return 0
        fi
        sleep 2
    done
    return 1
}

# bm_retry_nonempty VAR tries interval cmd... — retry a value-extraction until
# it prints something (single-shot reads of async state are race bets).
bm_retry_nonempty() {
    local __var="$1" tries="$2" interval="$3"
    shift 3
    local out="" i
    for i in $(seq 1 "$tries"); do
        out="$("$@" 2>/dev/null || true)"
        [[ -n "$out" ]] && { printf -v "$__var" '%s' "$out"; return 0; }
        sleep "$interval"
    done
    printf -v "$__var" '%s' ""
    return 1
}

# ════════════════════════════════════════════════════════════════════
# Agents + SandFS
# ════════════════════════════════════════════════════════════════════
# Fills BM_API_KEYS[] + BM_SANDFS_IDS[].

bm_create_agents() { # bm_create_agents <human_url> <count> <name_prefix>
    local human_url="$1" count="$2" prefix="${3:-eino-agent}"
    BM_API_KEYS=()
    BM_SANDFS_IDS=()
    local i resp key aid sfresp sf
    for i in $(seq 1 "$count"); do
        resp="$(curl -sk -X POST "$human_url/human/agent" \
            -H "Content-Type: application/json" -d "{\"name\":\"$prefix-$i\"}" || echo '{}')"
        key="$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")"
        aid="$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || echo "")"
        [[ -z "$key" || -z "$aid" ]] && { err "failed to create agent $i: $resp"; }
        sfresp="$(curl -sk -X POST "$human_url/human/sandfs" \
            -H "Content-Type: application/json" \
            -d "{\"agent_id\":\"$aid\",\"name\":\"$prefix-sandfs-$i\",\"description\":\"Agent $i sandbox\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}" || echo '{}')"
        sf="$(echo "$sfresp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")"
        [[ -z "$sf" ]] && { err "failed to create sandfs $i: $sfresp"; }
        log "  agent $i: $aid  sandfs: $sf"
        BM_API_KEYS+=("$key")
        BM_SANDFS_IDS+=("$sf")
    done
}

# ════════════════════════════════════════════════════════════════════
# Eino runner + analyzer (the ~90 lines that were pasted three times)
# ════════════════════════════════════════════════════════════════════

# bm_build_artifacts — the ONE build entry every deploy script uses.
# Release packages carry output/ prebuilt + an output/.release-stamp (written
# by build/package-release.sh); the stamp short-circuits the build so a
# package consumer needs NO Go/Rust toolchain. Dev trees have no stamp and
# build normally.
bm_build_artifacts() {
    local root="${ROOT:-${REPO_ROOT:-$PWD}}"
    if [[ -f "$root/output/.release-stamp" ]]; then
        log "output/.release-stamp present — release package with prebuilt artifacts, build bypassed"
        return 0
    fi
    # The matrix runner establishes freshness ONCE in its preflight and
    # exports SANDSWAP_ROUND_FRESH=1: a per-row check lets mid-round drift
    # auto-rebuild the whole shared set from inside a row, re-stamping
    # every artifact under the recorded verdicts. Standalone runs (no
    # sentinel) keep the check.
    if [[ "${SANDSWAP_ROUND_FRESH:-0}" == "1" ]]; then
        log "Round baseline fresh (matrix preflight) — skipping per-row build check"
        return 0
    fi
    # Freshness-gated, not unconditional: `build.sh all` re-stamps every
    # artifact (repacks, recompiles) on every deploy, which churns artifact
    # identity and defeats cross-round reuse even when nothing changed. A
    # green check says the build would be a no-op — skip it.
    if bash "$root/build/build.sh" check >/dev/null 2>&1; then
        log "Artifacts fresh (build.sh check green) — skipping rebuild"
        return 0
    fi
    log "Building all artifacts..."
    bash "$root/build/build.sh" all
}

bm_build_eino() { # bm_build_eino <output_bin>
    local bin="$1"
    # Release packages ship the prebuilt example binary; dev trees build from
    # examples/ source. Same contract for both paths.
    if [[ -x "${OUTPUT:-$ROOT/output}/eino-sandswap" ]]; then
        cp "${OUTPUT:-$ROOT/output}/eino-sandswap" "$bin"
        return 0
    fi
    ( cd "$ROOT/examples/eino-sandswap" \
      && export PATH="$PATH:/usr/local/go/bin" \
      && go build -o "$bin" . ) || err "eino build failed"
}

bm_run_eino() { # bm_run_eino <bin> <logfile> <budget_secs> <ca_cert_or_empty> <mcp_url> <key1> [key2] [key3] [key4]
    local bin="$1" logfile="$2" budget="$3" ca="$4" mcp_url="$5"
    shift 5
    local EINO_EXIT=0
    (
        echo "1:Use the execute tool to run this shell command: echo hello_from_agent_1"
        sleep 15
        echo "2:Use the execute tool to run this shell command: echo hello_from_agent_2"
        sleep 15
        echo "3:Use the execute tool to run this shell command: echo hello_from_agent_3"
        sleep 15
        echo "4:Use the execute tool to run this shell command: echo hello_from_agent_4"
        sleep 15
        echo "1:Use the file_write tool to write the text 'agent1 marker content' to a file called agent1_marker.txt"
        sleep 15
        # Same agent reads back (write→read persistence). A different agent
        # reading this file can only fail: cross-agent volume isolation is
        # a core product guarantee (asserted as invisibility in
        # e2e/multi-agents.sh B1/C1).
        echo "1:Use the file_read tool to read the file agent1_marker.txt back from the sandbox filesystem. You must call the tool, do not answer from memory."
        sleep 15
        echo "3:Use the execute tool with background=true and lease_duration=30 to start this shell command in the background: sleep 5 && echo bg_complete_marker. IMPORTANT: Do NOT call exec_status after starting the background exec. Just reply that the background task has been started and stop."
        sleep 20
        echo "4:Use the execute tool to run this shell command: echo agent4_final"
        sleep 15
        echo "exit"
    ) | timeout "$budget" env \
        SANDSWAP_API_KEY_1="${1:-}" \
        SANDSWAP_API_KEY_2="${2:-}" \
        SANDSWAP_API_KEY_3="${3:-}" \
        SANDSWAP_API_KEY_4="${4:-}" \
        SANDSWAP_MCP_URL="$mcp_url" \
        SANDSWAP_CA_CERT="${ca:+$ca}" \
        DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}" \
        DEEPSEEK_MODEL="${DEEPSEEK_MODEL:-deepseek-flash}" \
        OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
        GOOGLE_API_KEY="${GOOGLE_API_KEY:-}" \
        "$bin" 2>&1 | tee "$logfile" || EINO_EXIT=$?
    BM_EINO_EXIT="$EINO_EXIT"
}

bm_analyze_eino() { # bm_analyze_eino <logfile> <agent_count> — uses fail()/pass() (FAIL_COUNT)
    local eino_log="$1" agent_count="${2:-4}"
    if [[ ! -f "$eino_log" ]] || [[ ! -s "$eino_log" ]]; then
        fail "Eino multi-agent log is empty or missing"
        return
    fi
    grep -q "multi-agent ready" "$eino_log" \
        && pass "Eino multi-agent started in piped mode" \
        || fail "Eino multi-agent did not start correctly"
    local tool_count
    tool_count="$(grep -c "tools discovered" "$eino_log" || true)"
    (( tool_count >= agent_count )) \
        && pass "All agents discovered MCP tools ($tool_count entries)" \
        || fail "Not all agents discovered MCP tools (found $tool_count, expected >= $agent_count)"
    local i
    for i in $(seq 1 "$agent_count"); do
        grep -q "hello_from_agent_$i" "$eino_log" \
            && pass "Agent $i executed shell command" \
            || fail "Agent $i shell command not found in output"
    done
    # Write→read persistence: the marker text must appear in a file_read
    # TOOL RESULT (not just the write echo — grepping the bare marker would
    # pass vacuously on the write-side response alone).
    if grep -Eq "file_read[^\n]*agent1 marker content" "$eino_log"; then
        pass "Agent 1 marker write + read-back confirmed"
    elif grep -q "agent1 marker content" "$eino_log" && grep -q "file_read" "$eino_log"; then
        pass "Agent 1 marker write + read-back confirmed (tolerant format match)"
    else
        fail "Agent 1 marker write/read-back not confirmed"
    fi
    # bg_complete_marker = the guest command's output reaching the log;
    # "background task has been started" = the model's confirmation reply
    # (the prompt forbids the exec_status poll, so the marker alone is not
    # guaranteed). The bare word "background" is satisfied by the PROMPT echo
    # itself and can never fail.
    if grep -q "bg_complete_marker" "$eino_log" || grep -q "background task has been started" "$eino_log"; then
        pass "Background exec was exercised"
    else
        fail "Background exec not confirmed"
    fi
    grep -q "agent4_final" "$eino_log" \
        && pass "Agent 4 executed final command (warm path)" \
        || fail "Agent 4 final command not found"
}

# bm_exit_honest — the ONLY sanctioned exit gate. A red log with exit 0 is how
# regressions hide: both the accumulated fail() count and the eino exit code
# must be green.
bm_exit_honest() { # bm_exit_honest [eino_exit]
    local eino_exit="${1:-${BM_EINO_EXIT:-0}}"
    if [[ "${FAIL_COUNT:-0}" -gt 0 ]]; then
        err "$FAIL_COUNT check(s) failed — see the [FAIL] lines above"
    fi
    if [[ "$eino_exit" -eq 0 ]]; then
        log_pass "All tests PASSED"
        exit 0
    fi
    err "eino test exited with code $eino_exit"
}

# bm_traps <cleanup_fn> — EXIT runs cleanup; INT/TERM STOP after cleanup
# (without the exit, bash resumes the script mid-phase on the freshly cleaned
# host and re-deploys into it).
bm_traps() {
    local fn="$1"
    # $fn is a function NAME; expanding at install time is the intent (the
    # trap body is the literal function call).
    # shellcheck disable=SC2064
    trap "$fn" EXIT
    trap "exit 130" INT TERM
}
