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
# exec-timeout-policy.sh — end-to-end verification of the exec-timeout edge
# policy driven by the gateway flags -default-exec-timeout-sec /
# -max-exec-timeout-sec. No other e2e ever passes non-default values for
# these flags, so the flag → ExecuteHandler → sandlot → warden chain was only
# exercised at its default settings. This script pins the three edge rules of
# gateway/handler/execute.go resolveTimeoutMs BEHAVIORALLY (observable status
# + timing, not internals), against a real KVM stack:
#   DefaultApplied    request omits timeout (or sends 0) → the DEFAULT fires:
#                     `sleep 30` is killed at ~default seconds (status
#                     timed_out, partial output kept)
#   OverMaxClamped    request timeout far above max is CLAMPED to max (not
#                     rejected): `sleep 30` + timeout 60 dies at ~max seconds,
#                     and measurably LATER than the default probe — the two
#                     flags are wired to different knobs
#   NegativeRejected  timeout < 0 is rejected up front with HTTP 400
#                     "timeout must be >= 0" (the only hard rejection; it must
#                     happen before any mount/lease resource is held)
#   OutOfRangeFlagsRefused
#                     startup flags max<=0 or max<default are REFUSED: the
#                     gateway exits with "invalid exec configuration" (the old
#                     silent normalization — which turned the config into one
#                     the operator did not write — is gone); a subsequent
#                     valid restart (default=5, max=6) proves max clamping is
#                     honored and the stack recovers
# The warden re-clamps to its own max_exec_timeout as the final floor; all
# values here sit far below it, so what each probe observes is exactly the
# gateway-configured bound.
# Prerequisites: built artifacts in output/, /dev/kvm, root.
# Usage: sudo bash e2e/exec-timeout-policy.sh

set -euo pipefail

for p in "$HOME/.cargo/bin" "$HOME/go/bin" /usr/local/go/bin; do
    [[ -d "$p" ]] && case ":$PATH:" in *":$p:"*) ;; *) PATH="$p:$PATH" ;; esac
done
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VOL_ROOT="${VOL_ROOT:-/var/lib/sandswap/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
DEPLOY_DIR="${DEPLOY_DIR:-/var/lib/sandswap}"
POOL_SIZE=1                     # single VM: every probe lands on the same guest
SANDLOT_POOL="small:${POOL_SIZE}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
source "$ROOT/e2e/common.sh"

tc_use_output_binaries
tc_install_flat_template

tc_check_root
if [[ ! -e /dev/kvm ]] || [[ ! -r /dev/kvm ]]; then
    tc_log_error "/dev/kvm not available - this E2E requires KVM."
    exit 1
fi
for f in gateway sandlot sandvmm; do
    if [[ ! -f "$OUTPUT/$f" ]]; then
        tc_log_error "build artifact missing: output/$f - run 'bash build/build.sh all' first."
        exit 1
    fi
done

tc_log_section "Exec Timeout Policy E2E"

tc_check_tools curl python3
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network
tc_attach_vsockguard

# Phase 1 gateway: default 3s / max 6s — small, well-separated values so each
# probe's kill time identifies WHICH bound fired.
tc_start_gateway -default-exec-timeout-sec 3 -max-exec-timeout-sec 6
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready "$POOL_SIZE"

cleanup() { tc_cleanup_default; }
trap cleanup EXIT INT TERM

tc_create_agent_and_sandfs "exec-timeout-a" "rootfs:v1" "flat" >/dev/null
A_KEY="$TC_API_KEY"; A_SANDFS="$TC_SANDFS_ID"
[[ -n "$A_KEY" && -n "$A_SANDFS" ]] || { tc_log_error "agent create failed"; exit 1; }

# exec_probe <code> <timeout_json> — POST /agent/execute with timeout as a raw
# JSON value ("null" omits the field entirely); echoes body + HTTPCODE line
# (split with http_code_of / body_of). Bounded retry on the transient
# cold-pool classes only — a 400 must come back verbatim, not be retried away.
exec_probe() {
    local code="$1" tjson="$2" resp try
    for try in 1 2 3 4 5; do
        resp=$(python3 -c "import json,sys
t = json.loads(sys.argv[2])
body = {'sandfs_id': sys.argv[1], 'code': sys.argv[3], 'language': 'shell'}
if t is not None:
    body['timeout'] = t
print(json.dumps(body))" "$A_SANDFS" "$tjson" "$code" \
            | curl -s -m 90 -w '\nHTTPCODE:%{http_code}' -X POST "$GATEWAY_URL/agent/execute" \
                -H "Authorization: Bearer $A_KEY" -H "Content-Type: application/json" \
                -d @- 2>&1) || resp=""
        if [[ "$try" -lt 5 ]] && echo "$resp" | grep -qE '"(NO_AVAILABLE_SANDBOX|NO_COMPUTE_NODES|CONCURRENT_MOUNT|SANDBOX_CLEANING)"'; then
            sleep 2
            continue
        fi
        echo "$resp"
        return 0
    done
}

# probe_field <body> <field> — JSON field value ('' on parse failure).
probe_field() { echo "$1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('$2',''))" 2>/dev/null || echo ""; }

# probe_exec_ms <body> — the warden-side exec duration in whole ms.
probe_exec_ms() { echo "$1" | python3 -c "import sys,json;print(int(json.load(sys.stdin).get('exec_duration_ns',0))//1000000)" 2>/dev/null || echo 0; }

# timedout_probe <desc> <marker> <code> <timeout_json> <lo_ms> <hi_ms> — the
# workhorse: a long sleep whose early echo must survive, status must be
# timed_out, and the observed exec duration must land in [lo, hi] — the window
# that identifies WHICH configured bound killed it (default 3s vs max 6s vs
# the Phase-2 restart's max 6s; a raw 60s or an unclamped request would blow
# far past hi).
# Sets TIMEDOUT_MS for the caller's cross-probe discrimination.
TIMEDOUT_MS=0
timedout_probe() {
    local desc="$1" marker="$2" code="$3" tjson="$4" lo="$5" hi="$6"
    local R body st out ms
    R=$(exec_probe "$code" "$tjson")
    body=$(body_of "$R")
    st=$(probe_field "$body" status)
    out=$(probe_field "$body" stdout)
    ms=$(probe_exec_ms "$body")
    TIMEDOUT_MS="$ms"
    if [[ "$st" != "timed_out" ]]; then
        tc_fail "$desc: expected status=timed_out, got '$st' (${body:0:160})"
        return 1
    fi
    if ! echo "$out" | grep -q "$marker"; then
        tc_fail "$desc: partial output lost (stdout: '$out')"
        return 1
    fi
    if (( ms < lo || ms > hi )); then
        tc_fail "$desc: exec duration ${ms}ms outside [${lo},${hi}] — wrong bound fired (default/max wiring?)"
        return 1
    fi
    tc_pass "$desc: timed_out at ${ms}ms (window [${lo},${hi}]), partial output kept"
    return 0
}

# ── Phase 1 probes: default=3 / max=6 ─────────────────────────────────
# Warm the mount first so later probes' exec_duration is not the first cold
# mount (the bounds have headroom either way, but warm keeps them tight).
R=$(exec_probe "echo p0-warm" 30)
if [[ "$(http_code_of "$R")" == "200" ]] && echo "$(body_of "$R")" | grep -q "p0-warm"; then
    tc_pass "warmup exec OK (gateway up with default=3s max=6s)"
else
    tc_fail "warmup exec failed: $(echo "$R" | head -c 200)"
fi

# In-range timeouts still pass through untouched: sleep 2 under timeout 4.
R=$(exec_probe "sleep 2; echo p1-done" 4)
if [[ "$(http_code_of "$R")" == "200" ]] \
   && [[ "$(probe_field "$(body_of "$R")" status)" == "done" ]] \
   && echo "$(body_of "$R")" | grep -q "p1-done"; then
    tc_pass "in-range timeout honored (timeout=4, sleep 2 completed)"
else
    tc_fail "in-range timeout broken: $(echo "$R" | head -c 200)"
fi

# Omitted timeout → DEFAULT (3s). Window (2500,15000): 3s + slack; a max-wired
# misconfiguration would fire at ~6s (still inside — caught by the P-default vs
# P-max delta below), an unhonored flag at ~180s+ (outside).
DEF_MS=0
if timedout_probe "omitted timeout → default (3s)" "p2-early" \
     "echo p2-early; sleep 30" null 2500 15000; then :; fi
DEF_MS="$TIMEDOUT_MS"

# Explicit timeout:0 → treated exactly like omitted (DEFAULT), not like "no
# limit": the request layer must not mistake 0 for infinity.
if timedout_probe "explicit timeout=0 → default (3s)" "p3-early" \
     "echo p3-early; sleep 30" 0 2500 15000; then :; fi

# timeout 60 ≫ max 6 → CLAMPED to max (never a reject), and measurably later
# than the default probe: the ≥1s delta is the discriminator that default and
# max are two different knobs end-to-end (absolute bounds alone could not tell
# 6s apart from a mis-wired 3s+slack on a slow host).
if timedout_probe "timeout=60 clamped to max (6s)" "p4-early" \
     "echo p4-early; sleep 30" 60 4500 20000; then :; fi
MAX_MS="$TIMEDOUT_MS"
if (( MAX_MS - DEF_MS >= 1000 )); then
    tc_pass "max probe fired later than default probe (+$((MAX_MS - DEF_MS))ms) — two distinct bounds wired"
else
    tc_fail "max(${MAX_MS}ms) vs default(${DEF_MS}ms) probes indistinguishable — max flag not reaching the clamp"
fi

# timeout < 0 → the one hard rejection: 400 with the named message, before any
# resource is held. NB the wire body carries `>` JSON-escaped (Go encoding/json
# HTML escaping emits backslash-u003e) — match both spellings so a future
# SetEscapeHTML(false) still passes; assert on the message NAME, not its
# byte-exact form.
R=$(exec_probe "echo never-runs" -1)
CODE=$(http_code_of "$R")
BODY=$(body_of "$R")
if [[ "$CODE" == "400" ]] && echo "$BODY" | grep -qE 'timeout must be (>=|\\u003e=) 0'; then
    tc_pass "negative timeout rejected: 400 'timeout must be >= 0'"
else
    tc_fail "negative timeout: expected 400 with named message, got http=$CODE body=${BODY:0:120}"
fi

# ── Phase 2: out-of-range startup flags are refused, not normalized ──────
# max=2 < default=5 → ValidateExec refuses at startup (the constructor's old
# silent normalization would have turned the config into one the operator did
# not write). The gateway must EXIT with the named error; then a VALID restart
# (default=5, max=60) proves the stack recovers and the flags are honored.
tc_log_step "restarting gateway with out-of-range flags (default=5, max=2 → must refuse)..."
kill "${GATEWAY_PID:-}" 2>/dev/null || true
wait "${GATEWAY_PID:-}" 2>/dev/null || true

local_gw_bin="${TC_GATEWAY_BIN:-$DEPLOY_DIR/gateway}"
if [[ -n "${TC_GATEWAY_CONFIG:-}" ]]; then
    "$local_gw_bin" \
        -config "$TC_GATEWAY_CONFIG" \
        -agent-addr "$GATEWAY_ADDR" \
        -human-addr "$HUMAN_ADDR" \
        -stream-addr "$STREAM_ADDR" \
        -allow-anonymous-human \
        -default-exec-timeout-sec 5 -max-exec-timeout-sec 2 \
        > "$LOG_DIR/gateway-refused.log" 2>&1 &
else
    "$local_gw_bin" \
        -agent-addr "$GATEWAY_ADDR" \
        -human-addr "$HUMAN_ADDR" \
        -stream-addr "$STREAM_ADDR" \
        -vol-root "$VOL_ROOT" \
        -sticky-ms "$LEASE_MS" \
        -max-sticky-sec "$MAX_LEASE_SEC" \
        -allow-anonymous-human \
        -default-exec-timeout-sec 5 -max-exec-timeout-sec 2 \
        > "$LOG_DIR/gateway-refused.log" 2>&1 &
fi
REFUSED_PID=$!

REFUSED=0
for i in $(seq 1 20); do
    sleep 0.3
    if ! kill -0 "$REFUSED_PID" 2>/dev/null; then
        REFUSED=1
        break
    fi
done
if [[ "$REFUSED" != "1" ]]; then
    kill "$REFUSED_PID" 2>/dev/null || true
    tc_fail "out-of-range exec-timeout flags did not refuse startup (process still running)"
    exit 1
fi
wait "$REFUSED_PID" 2>/dev/null || true
if grep -q "invalid exec configuration" "$LOG_DIR/gateway-refused.log" \
   && grep -q "max_timeout_sec" "$LOG_DIR/gateway-refused.log"; then
    tc_pass "out-of-range exec-timeout flags refused at startup with the named error"
else
    tc_fail "gateway exited but without the expected refusal message: $(tail -5 "$LOG_DIR/gateway-refused.log" | tr '\n' ' ')"
fi

tc_log_step "restarting gateway with valid flags (default=5, max=60)..."
tc_start_gateway -default-exec-timeout-sec 5 -max-exec-timeout-sec 60
tc_wait_health

# The sandlot reconnects on its own backoff (1s→…→60s cap); the agent's key
# survives the restart via the mandatory identity snapshot. Bounded poll on a
# real exec — proceeding without it would misattribute reconnect latency to
# the timeout policy below.
RECONNECTED=0
for i in $(seq 1 60); do
    R=$(exec_probe "echo p5-reconnected" null)
    if [[ "$(http_code_of "$R")" == "200" ]] && echo "$(body_of "$R")" | grep -q "p5-reconnected"; then
        RECONNECTED=1
        break
    fi
    sleep 2
done
if [[ "$RECONNECTED" -eq 1 ]]; then
    tc_pass "gateway restarted; sandlot reconnected; old api key still valid (identity snapshot)"
else
    tc_fail "stack did not recover after gateway restart: $(echo "$R" | head -c 200)"
    exit 1
fi

# BelowMaxHonored on the VALID config: request timeout (30) is BELOW max (60),
# so it is honored as-is — the probe dies at ~30s. The window excludes both
# the default=5s death (would prove the request timeout was ignored) and a
# max-clamped death (would prove clamping fires below max); sleep 90 makes
# the kill deterministic (no race against natural completion at timeout=30).
# The >max clamp itself is proven by Phase 1 (timeout=60 ≫ max=6).
if timedout_probe "timeout=30 below max (60) honored as-is: dies at ~30s, not default (5s), not clamped" "p6-early" \
     "echo p6-early; sleep 90" 30 24000 45000; then :; fi

# Sanity on the valid config: small explicit timeouts still pass through.
R=$(exec_probe "sleep 2; echo p7-done" 4)
if [[ "$(http_code_of "$R")" == "200" ]] \
   && [[ "$(probe_field "$(body_of "$R")" status)" == "done" ]] \
   && echo "$(body_of "$R")" | grep -q "p7-done"; then
    tc_pass "in-range timeout still honored on the valid config (timeout=4)"
else
    tc_fail "in-range timeout broken on the valid config: $(echo "$R" | head -c 200)"
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "Exec Timeout Policy Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo "[FAIL] Exec Timeout Policy E2E FAILED"
    exit 1
fi
echo "[OK] Exec Timeout Policy E2E PASSED"
exit 0
