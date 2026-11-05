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
# stack.sh — the STACK layer: HTTP clients and waiters for a RUNNING Sandswap
# stack, shared by the e2e suite and the deploy verification scripts.
#
# Layers:
#   common/sh/runtime.sh  host level — identities, dirs, devices, seed, mount
#   common/sh/stack.sh    stack level — gateway/human API, pool, waits
#   e2e/common.sh         e2e tree conveniences (aliases, go suites, etcd)
#   deploy/**/deploy-lib.sh  deploy orchestration (ledger, preflight)
#
# Source AFTER runtime.sh (asserted below). Leaf semantics like runtime.sh: no
# shell options, no traps, no sourcing.
#
# Why this file exists: the stack-level calls were re-derived per script. The
# measured bill: 12 divergent exec clients (8 local copies, each drifted — one
# with no curl timeout at all), 7 pasted copies of the retryable-refusal regex,
# 8 pool parsers over 4 different JSON shapes, 3 agent/sandfs creators, ~12
# hand-rolled wait loops, and 3 inconsistent port sets. Each new feature
# (storage-plane 503, SANDBOX_CLEANING windows, retry_after_ms pacing) had to
# be added to every copy — and was not.

if ! declare -F tc_log_step >/dev/null 2>&1; then
    echo "common/sh/stack.sh: source common/sh/runtime.sh first" >&2
    return 1 2>/dev/null || exit 1
fi

# ── Endpoints (a caller-set value always wins) ─────────────────────────
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
HUMAN_URL="${HUMAN_URL:-http://localhost:3100}"
# Extra curl args for every call below: "-k" for an https stack with a
# private CA (the deploy verifiers), empty for plain http (e2e).
SS_CURL_TLS="${SS_CURL_TLS:-}"

# ═══════════════════════════════════════════════════════════════════════
# Retryable refusals — ONE token set and ONE predicate
# ═══════════════════════════════════════════════════════════════════════
# The server answers a busy window with a named, RETRYABLE refusal:
#   NO_AVAILABLE_SANDBOX  pool still booting / cleaning after a replace
#   NO_COMPUTE_NODES      no exec node connected yet
#   CONCURRENT_MOUNT      another mount of the same sandfs is in flight
#   SANDBOX_CLEANING      destroy-and-replace settle window
#   MAINTENANCE           runtime service-refusal switch (Retry-After)
#   STORAGE_UNAVAILABLE   storage plane: no prov instance connected
# The body carries `"retryable":true` (authoritative) and usually
# `retry_after_ms`; the token list covers older/other shapes.
SS_RETRYABLE_TOKENS="${SS_RETRYABLE_TOKENS:-NO_AVAILABLE_SANDBOX NO_COMPUTE_NODES CONCURRENT_MOUNT SANDBOX_CLEANING MAINTENANCE STORAGE_UNAVAILABLE}"
SS_RETRYABLE_RE="\"($(echo $SS_RETRYABLE_TOKENS | tr ' ' '|'))\"|no provision instance connected"
SS_RETRY_AFTER_DEFAULT_MS="${SS_RETRY_AFTER_DEFAULT_MS:-3000}"

# ss_body_retryable <body> — 0 when the response is a retryable refusal.
ss_body_retryable() {
    grep -q '"retryable":true' <<<"$1" && return 0
    grep -qE "$SS_RETRYABLE_RE" <<<"$1"
}

# ss_body_retry_after_ms <body> [default] — the server's pacing hint in ms.
# Always prints a number (never empty): callers divide it into a sleep.
ss_body_retry_after_ms() {
    local body="$1" default="${2:-$SS_RETRY_AFTER_DEFAULT_MS}" ms
    ms=$(grep -o '"retry_after_ms":[[:space:]]*[0-9]*' <<<"$body" | head -1 | grep -o '[0-9]*$')
    [[ -n "$ms" ]] || ms=$(grep -i -o '^Retry-After:[[:space:]]*[0-9]*' <<<"$body" | head -1 | grep -o '[0-9]*$')
    if [[ -z "$ms" ]]; then
        ms="$default"
    elif [[ "$ms" -lt 100000 ]]; then
        : # milliseconds as-is
    fi
    printf '%s' "$ms"
}

# ═══════════════════════════════════════════════════════════════════════
# JSON request building — no hand-rolled escaping
# ═══════════════════════════════════════════════════════════════════════
# ss_json_build <key=value|key:=jsonvalue>... — print a JSON object.
# Values travel as ARGV (never through a shell string), so a code snippet
# containing quotes, backslashes or newlines cannot corrupt the request —
# the class of bug that broke several suites when a payload gained a `"`.
# `k=v` is a string; `k:=v` is a raw JSON value (numbers, bools, objects).
ss_json_build() {
    python3 - "$@" <<'PY'
import json, sys
o = {}
for a in sys.argv[1:]:
    if ":=" in a and (a.index(":=") < a.index("=") if "=" in a else True):
        k, v = a.split(":=", 1)
        try:
            o[k] = json.loads(v)
        except Exception:
            o[k] = v
    else:
        k, _, v = a.partition("=")
        o[k] = v
print(json.dumps(o))
PY
}

# ss_json_field <field> — read JSON on stdin, print one field (empty on any
# failure; never fails the caller under set -e).
ss_json_field() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$1',''))" 2>/dev/null; return 0; }

# ss_json_merge_body <body> <extra-json-fragment> — fold the callers' raw
# fragment (the historical `extra` argument, e.g. '"timeout":30') into a built
# body. A fragment that does not parse falls back to the LEGACY concatenation
# on purpose: the request must go out malformed and be REJECTED by the server
# (the pre-framework behaviour), never silently drop the field — a dropped
# `"background":true` is a test that passes without testing what it names.
ss_json_merge_body() {
    local body="$1" extra="$2" merged
    [[ -n "$extra" ]] || { printf '%s' "$body"; return 0; }
    merged=$(python3 -c "
import json,sys
d=json.loads(sys.argv[1]); e=json.loads('{'+sys.argv[2]+'}'); d.update(e); print(json.dumps(d))" \
        "$body" "$extra" 2>/dev/null) || merged=""
    if [[ -n "$merged" ]]; then
        printf '%s' "$merged"
    else
        printf '%s' "${body%?},$extra}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# Agent API (/agent/*)
# ═══════════════════════════════════════════════════════════════════════

# ss_gw_exec <api_key> <sandfs_id> <code> [extra_json_fields]
# POST /agent/execute. Output: response body, then "HTTPCODE:<code>" on the
# last line (split with ss_http_code_of / ss_body_of).
ss_gw_exec() {
    local key="$1" sandfs="$2" code="$3" extra="${4:-}"
    local body
    body=$(ss_json_build "sandfs_id=$sandfs" "code=$code" "language=shell")
    body=$(ss_json_merge_body "$body" "$extra")
    # shellcheck disable=SC2086
    curl -s -m 60 $SS_CURL_TLS -w $'\nHTTPCODE:%{http_code}' -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d "$body" 2>&1
}

# ss_gw_exec_retry <key> <sandfs_id> <code> [extra] [attempts=6] — ss_gw_exec
# + bounded retry that HONORS retry_after_ms (a fixed sleep under-paces the
# 10s SANDBOX_CLEANING window and over-paces the 1s pool windows).
ss_gw_exec_retry() {
    local key="$1" sandfs="$2" code="$3" extra="${4:-}" attempts="${5:-6}"
    local r="" wait_ms i
    for ((i = 1; i <= attempts; i++)); do
        r=$(ss_gw_exec "$key" "$sandfs" "$code" "$extra")
        if ! ss_body_retryable "$r"; then
            printf '%s\n' "$r"
            return 0
        fi
        wait_ms=$(ss_body_retry_after_ms "$r")
        tc_log_warn "exec busy (attempt $i/$attempts) — honoring retry_after_ms=${wait_ms}ms"
        sleep "$(python3 -c "print($wait_ms / 1000)")"
    done
    printf '%s\n' "$r"
}

# ss_gw_exec_raw <key> <sandfs_id> <code> [timeout=60] [retries=3] — sync exec
# returning the RAW JSON body. The uniform replacement for the per-script
# exec_code/exec_in_vm helpers that had drifted apart:
#   - body built by ss_json_build (no quoting bugs)
#   - curl -m = exec timeout + 15s transport slack, so a stuck call FAILS
#     instead of hanging the suite
#   - retries ONLY retryable refusals, honoring retry_after_ms; everything
#     else returns verbatim so the caller's assertions see real behavior.
ss_gw_exec_raw() {
    local key="$1" sandfs="$2" code="$3" timeout="${4:-60}" retries="${5:-3}"
    local resp try wait_ms
    for try in $(seq 1 "$retries"); do
        resp=$(ss_json_build "sandfs_id=$sandfs" "code=$code" "language=shell" "timeout:=$timeout" \
            | curl -s -m $((timeout + 15)) $SS_CURL_TLS -X POST "$GATEWAY_URL/agent/execute" \
                -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
                -d @- 2>&1) || resp=""
        if [[ "$try" -lt "$retries" ]] && ss_body_retryable "$resp"; then
            wait_ms=$(ss_body_retry_after_ms "$resp" 1000)
            sleep "$(python3 -c "print(min($wait_ms,10000) / 1000)")"
            continue
        fi
        echo "$resp"
        return 0
    done
}

# ss_gw_exec_headers <key> <sandfs_id> <code> [extra] — like ss_gw_exec but the
# LAST output line is "LEASE:<hit|>" (the X-Sandbox-Lease response header).
ss_gw_exec_headers() {
    local key="$1" sandfs="$2" code="$3" extra="${4:-}"
    local body
    body=$(ss_json_build "sandfs_id=$sandfs" "code=$code" "language=shell")
    body=$(ss_json_merge_body "$body" "$extra")
    local hdr
    hdr=$(mktemp)
    # shellcheck disable=SC2086
    curl -s -m 60 $SS_CURL_TLS -D "$hdr" -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d "$body" 2>&1
    local lease
    lease=$(grep -i '^X-Sandbox-Lease:' "$hdr" | tr -d '\r' | awk '{print $2}')
    rm -f "$hdr"
    echo "LEASE:${lease:-}"
}

# ss_gw_status / ss_gw_kill — background-exec lifecycle.
ss_gw_status() {
    # shellcheck disable=SC2086
    curl -s -m 15 $SS_CURL_TLS -X POST "$GATEWAY_URL/agent/exec/status" \
        -H "Authorization: Bearer $1" -H "Content-Type: application/json" \
        -d "$(ss_json_build "sandfs_id=$2" "exec_id=$3")" 2>&1
}
ss_gw_kill() {
    # shellcheck disable=SC2086
    curl -s -m 15 $SS_CURL_TLS -X POST "$GATEWAY_URL/agent/exec/kill" \
        -H "Authorization: Bearer $1" -H "Content-Type: application/json" \
        -d "$(ss_json_build "sandfs_id=$2" "exec_id=$3")" 2>&1
}

# ss_http_code_of / ss_body_of — split an ss_gw_exec result.
ss_http_code_of() { echo "$1" | grep '^HTTPCODE:' | tail -1 | cut -d: -f2; }
ss_body_of()      { echo "$1" | grep -v '^HTTPCODE:'; }

# ss_json_stdout — stdout field of an exec response read from stdin.
ss_json_stdout() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('stdout',''))" 2>/dev/null; return 0; }

# ═══════════════════════════════════════════════════════════════════════
# Human API (/human/*) + pool
# ═══════════════════════════════════════════════════════════════════════

# ss_pool_clean [stats_url] — CLEAN VM count from GET /stats. ONE parser for
# every shape this endpoint has had (totals.clean_vms, clean_vms, CLEAN,
# pool.CLEAN, and the per-gateway gateways[].clean_vms sum), because eight
# copies had drifted across four of them. /stats is served on the HUMAN
# listener, not the agent one.
# ss_pool_clean_of <json> — the same parse for a /stats body the caller
# ALREADY holds (several suites fetch /stats once and read several fields out
# of it; re-fetching would change what they measure).
ss_pool_clean_of() {
    printf '%s' "$1" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print(0); raise SystemExit
t = d.get('totals')
if isinstance(t, dict) and 'clean_vms' in t:
    print(t['clean_vms'])
elif 'clean_vms' in d:
    print(d['clean_vms'])
elif 'CLEAN' in d:
    print(d['CLEAN'])
elif isinstance(d.get('pool'), dict):
    print(d['pool'].get('CLEAN', 0))
elif isinstance(d.get('gateways'), list):
    print(sum(g.get('clean_vms', 0) for g in d['gateways']))
else:
    print(0)" 2>/dev/null
}

ss_pool_clean() {
    # TWO call-site conventions exist and both must work: the e2e tree passes
    # a BASE url (`tc_stats_clean_vms [stats_url]`, default $HUMAN_URL) while
    # the deploy tree's bm_wait_pool passes the FULL url it used to curl
    # directly. Appending blindly turned the deploy call into
    # `https://host:3100/stats/stats` — a 404 whose body parses as 0, i.e. a
    # six-minute pool-wait timeout with a green-looking probe.
    local url="${1:-$HUMAN_URL}" body
    [[ "$url" == */stats ]] || url="$url/stats"
    # Exec-mode agent listeners serve /stats only behind the run's ops bearer
    # token (-ops-token-file; TC_OPS_TOKEN is exported by whatever started
    # the gateway — tc_start_gateway or a suite's own gateway launcher).
    # Single-node/human listeners need no token and no header.
    # shellcheck disable=SC2086
    local auth=()
    [[ -n "${TC_OPS_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $TC_OPS_TOKEN")
    # `( curl || true )`: under the callers' `set -o pipefail` a connection
    # refusal would otherwise make the whole pipeline non-zero and print the
    # python 0 AND a fallback 0 (an "0\n0" that only survived callers which
    # happened to strip whitespace).
    # shellcheck disable=SC2086
    body="$( curl -s -m 5 "${auth[@]}" $SS_CURL_TLS "$url" 2>/dev/null || true )"
    ss_pool_clean_of "$body"
}

# ss_wait_pool_ready <target> [stats_url] [budget_sec] — 0 when CLEAN >= target.
# Budget default 150s: on memory-tight hosts the first pool batch can stall in
# early boot and sandlot's hung-VM detector destroys+replaces it (60-90s).
ss_wait_pool_ready() {
    local target="$1" stats_url="${2:-$HUMAN_URL}" budget="${3:-150}"
    local clean deadline=$((SECONDS + budget))
    while (( SECONDS < deadline )); do
        clean=$(ss_pool_clean "$stats_url")
        clean="${clean//[[:space:]]/}"
        if [[ -n "$clean" ]] && [[ "$clean" -ge "$target" ]] 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# ss_wait_health [url] [budget_sec] — 0 when /health answers with a status body.
ss_wait_health() {
    local url="${1:-$GATEWAY_URL/health}" budget="${2:-15}"
    local deadline=$((SECONDS + budget)) body
    while (( SECONDS < deadline )); do
        # shellcheck disable=SC2086
        body=$(curl -s -m 3 $SS_CURL_TLS "$url" 2>/dev/null || true)
        grep -q '"status"' <<<"${body:-}" && return 0
        sleep 0.3
    done
    return 1
}

# ss_agent_create <human_url> <name> — create an agent; prints the raw JSON.
ss_agent_create() {
    local human="$1" name="$2"
    # shellcheck disable=SC2086
    curl -s -m 30 $SS_CURL_TLS -X POST "$human/human/agent" \
        -H "Content-Type: application/json" \
        -d "$(ss_json_build "name=$name")" 2>/dev/null || echo '{"error":"curl failed"}'
}

# ss_sandfs_create <human_url> <agent_id> <name> <template> <mode> [extra k=v...]
# Prints the raw JSON. Retries the storage plane's named 503: a sandfs create
# is a stream RPC to a prov instance, so a sandlot restart window answers
# "no provision instance connected" — every suite must tolerate it.
ss_sandfs_create() {
    local human="$1" agent_id="$2" name="$3" template="$4" mode="$5"; shift 5
    local args=("agent_id=$agent_id" "name=$name" "template=$template")
    [[ -n "$mode" ]] && args+=("mode=$mode")
    local kv
    for kv in "$@"; do args+=("$kv"); done
    local body resp i
    body=$(ss_json_build "${args[@]}")
    for i in $(seq 1 15); do
        # shellcheck disable=SC2086
        resp=$(curl -s -m 60 $SS_CURL_TLS -X POST "$human/human/sandfs" \
            -H "Content-Type: application/json" -d "$body" 2>/dev/null || echo '{"error":"curl failed"}')
        if ! grep -q "no provision instance connected" <<<"$resp"; then
            break
        fi
        # stderr: this function's STDOUT is its return payload (the caller
        # captures it as JSON). A log line on stdout corrupted the response
        # and made a retry that eventually SUCCEEDS look like a failed create
        # ("failed to create sandfs for 'swap-user': [!] sandfs create:
        # storage plane not connected yet (attempt 1/15)" — caught by the
        # framework re-run).
        tc_log_warn "sandfs create: storage plane not connected yet (attempt $i/15) — retrying" >&2
        sleep 2
    done
    printf '%s' "$resp"
}

# ss_delete_sandfs <human_url> <sandfs_id>
ss_delete_sandfs() {
    # shellcheck disable=SC2086
    curl -s -m 30 $SS_CURL_TLS -X DELETE "$1/human/sandfs/$2" >/dev/null 2>&1 || true
}

# ss_template_mode <human_url> <template_ref> — the registered mode of a
# template ("flat"/"overlay"); defaults to flat when the lookup fails.
ss_template_mode() {
    local human="$1" template="$2" tpl_json="" _try
    # The listing is served by the PROV storage plane, not the gateway: a
    # request that lands before the prov connection is admitted comes back as
    # an error object (503), and resolving that as "flat" picks a mode no ref
    # backs (TEMPLATE_NOT_FOUND on create). Wait for a REAL array answer —
    # bounded — before resolving; a genuine empty list still means "flat".
    for _try in $(seq 1 30); do
        # shellcheck disable=SC2086
        tpl_json=$(curl -s -m 15 $SS_CURL_TLS "$human/human/templates" 2>/dev/null || true)
        # A valid NON-EMPTY array is the settled answer. An array that is
        # still empty can be the first listing of a just-admitted prov
        # connection (the scan output is already on disk but the storage plane has not
        # served it yet) — retry for a bounded window before accepting it.
        if printf '%s' "$tpl_json" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if isinstance(d,list) and len(d)>0 else 1)' 2>/dev/null; then
            break
        fi
        if [ "$_try" -ge 15 ] && printf '%s' "$tpl_json" | grep -q '^\[\]'; then
            break   # settled empty: no templates in this store
        fi
        sleep 1
    done
    # A persistent error answer falls back to the flat default below.
    printf '%s' "$tpl_json" | grep -q '^\[' || tpl_json='[]'
    printf '%s' "$tpl_json" | python3 -c "
import sys, json
try:
    tpls = json.load(sys.stdin)
except Exception:
    print('flat'); raise SystemExit
name, _, ver = '$template'.rpartition(':')
for t in tpls:
    if t.get('name') == name and t.get('version') == ver:
        print(t.get('mode') or 'flat'); break
else:
    print('flat')" 2>/dev/null
}

# ss_agent_and_sandfs <human_url> <name> [template] [mode] — the two-step
# create every suite performs. Sets SS_AGENT_ID / SS_API_KEY / SS_SANDFS_ID /
# SS_ROOTFS_PATH and prints a combined JSON. Always returns 0: its stdout is
# command-substitution-captured by callers under `set -e`, so a non-zero
# return would kill the script before its error JSON could be read (callers
# detect failure by the empty id fields).
ss_agent_and_sandfs() {
    local human="$1" name="$2" template="${3:-rootfs:v1}" mode="${4:-}"
    local agent_resp sandfs_resp
    if [[ -z "$mode" ]]; then
        mode=$(ss_template_mode "$human" "$template")
        [[ -n "$mode" ]] || mode="flat"
        tc_log_info "mode not specified — resolved template '$template' to mode=$mode" >&2
    fi
    agent_resp=$(ss_agent_create "$human" "$name")
    SS_AGENT_ID=$(printf '%s' "$agent_resp" | ss_json_field agent_id)
    SS_API_KEY=$(printf '%s' "$agent_resp" | ss_json_field api_key)
    if [[ -z "$SS_AGENT_ID" || -z "$SS_API_KEY" ]]; then
        tc_log_error "failed to create agent '$name': $agent_resp" >&2
        echo "{\"error\":\"failed to create agent: $agent_resp\"}"
        return 0
    fi
    sandfs_resp=$(ss_sandfs_create "$human" "$SS_AGENT_ID" "$name" "$template" "$mode")
    SS_SANDFS_ID=$(printf '%s' "$sandfs_resp" | ss_json_field sandfs_id)
    SS_ROOTFS_PATH=$(printf '%s' "$sandfs_resp" | ss_json_field rootfs_path)
    if [[ -z "$SS_SANDFS_ID" ]]; then
        tc_log_error "failed to create sandfs for '$name': $sandfs_resp" >&2
        echo "{\"error\":\"failed to create sandfs: $sandfs_resp\"}"
        return 0
    fi
    python3 -c "
import json, sys
print(json.dumps({'sandfs_id': sys.argv[1], 'api_key': sys.argv[2],
                  'agent_id': sys.argv[3], 'rootfs_path': sys.argv[4]}))" \
        "$SS_SANDFS_ID" "$SS_API_KEY" "$SS_AGENT_ID" "$SS_ROOTFS_PATH"
}

# ss_volume_path <human_url> <sandfs_id> — the host-side volume directory of a
# sandfs. Volume names are DERIVED from the deployment seed
# (sandlot/provision/volname), so the directory is NOT "$VOL_ROOT/$id"; suites
# resolve it through the record. Prints nothing + returns 1 when unavailable,
# so `set -e` callers fail loudly instead of acting on an empty path.
ss_volume_path() {
    local human="$1" id="$2" resp path
    # shellcheck disable=SC2086
    resp=$(curl -s -m 20 $SS_CURL_TLS "$human/human/sandfs/$id" || true)
    path=$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("rootfs_path",""))' 2>/dev/null || true)
    [[ -n "$path" ]] || { tc_log_error "ss_volume_path: no rootfs_path for $id (response: ${resp:0:120})" >&2; return 1; }
    printf '%s' "$path"
}

# ═══════════════════════════════════════════════════════════════════════
# Preconditions for scripts that need an ALREADY-RUNNING stack
# ═══════════════════════════════════════════════════════════════════════

# ss_script_require_stack [health_url] [what] — verify a deployed stack is
# reachable before a verification script starts; otherwise SKIP the suite with
# the closed reason (never a silent exit-0 the battery would count as PASS).
ss_script_require_stack() {
    local health_url="${1:-$HUMAN_URL/health}"
    local what="${2:-deployed stack}"
    # shellcheck disable=SC2086
    if ! curl -sf -m 5 $SS_CURL_TLS "$health_url" >/dev/null 2>&1; then
        tc_skip_suite "needs-deployed-stack: no $what reachable at $health_url"
    fi
}

# ss_script_require_units <unit>... — the systemd deployment the script
# verifies must be installed and active.
ss_script_require_units() {
    local u
    for u in "$@"; do
        if ! systemctl is-active --quiet "$u" 2>/dev/null; then
            tc_skip_suite "needs-deployed-stack: unit $u is not active"
        fi
    done
}
