#!/usr/bin/env bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# stream-tls-require-ca.sh — the stream listener MUST refuse to start without
# a verifying client CA.
#
# Without -stream-tls-ca the old builder used RequireAnyClientCert and bound
# node identity only to the hello's CN; any host reaching :9998 could present
# a self-signed `CN=<victim-node-id>` certificate and receive that node's
# VMCommands (tenant code, file data, HMAC volume paths). There is no no-CA
# mode now: the gateway exits at startup with a named error. No KVM needed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

tc_use_output_binaries
[[ -x "$OUTPUT/gateway" ]] || { log_error "missing output/gateway (bash build/build.sh go)"; exit 1; }
tc_check_root

CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
tc_gen_certs

TMP=$(mktemp -d)
cleanup() {
    local ec=$?
    # Kill the positive-case gateway if it is still up.
    [[ -n "${GW_PID:-}" ]] && kill "$GW_PID" 2>/dev/null || true
    rm -rf "$TMP"
    exit "$ec"
}
trap cleanup EXIT INT TERM

log_section "Negative: gateway stream without -stream-tls-ca must exit"
LOG="$TMP/no-ca.log"
set +e
timeout 8 "$OUTPUT/gateway" \
    -agent-addr 127.0.0.1:13201 \
    -human-addr 127.0.0.1:13101 \
    -stream-addr 127.0.0.1:13998 \
    -vol-root "$TMP/volumes" \
    -identity-store "$TMP/identity.json" \
    -stream-tls-cert "$CERT_DIR/gateway.crt" \
    -stream-tls-key "$CERT_DIR/gateway.key" \
    -allow-anonymous-human \
    >"$LOG" 2>&1
RC=$?
set -e
if [[ "$RC" -eq 124 ]]; then
    fail "gateway did NOT exit without -stream-tls-ca (timeout 8s)"
elif [[ "$RC" -eq 0 ]]; then
    fail "gateway exited 0 without -stream-tls-ca"
elif grep -q -- "-stream-tls-ca is required" "$LOG"; then
    pass "startup refused without a client CA (exit $RC)"
else
    fail "gateway exited $RC but not with the named -stream-tls-ca refusal: $(tail -5 "$LOG" | tr '\n' ' ')"
fi

log_section "Positive: with -stream-tls-ca the gateway serves /health"
"$OUTPUT/gateway" \
    -agent-addr 127.0.0.1:13202 \
    -human-addr 127.0.0.1:13102 \
    -stream-addr 127.0.0.1:13999 \
    -vol-root "$TMP/volumes" \
    -identity-store "$TMP/identity.json" \
    -stream-tls-cert "$CERT_DIR/gateway.crt" \
    -stream-tls-key "$CERT_DIR/gateway.key" \
    -stream-tls-ca "$CERT_DIR/ca.crt" \
    -allow-anonymous-human \
    >"$TMP/with-ca.log" 2>&1 &
GW_PID=$!
UP=0
for _ in $(seq 1 40); do
    if curl -sf -m 1 "http://127.0.0.1:13102/health" >/dev/null 2>&1; then UP=1; break; fi
    sleep 0.25
done
if [[ "$UP" == "1" ]]; then
    pass "gateway with a CA is up and serving /health"
else
    fail "gateway with a CA did not become ready: $(tail -5 "$TMP/with-ca.log" | tr '\n' ' ')"
fi
kill "$GW_PID" 2>/dev/null || true
GW_PID=""

log_section "Verdict"
if [[ "$FAIL_COUNT" -eq 0 ]]; then
    log_pass "ALL $PASS_COUNT checks passed — the stream plane is mTLS-only"
else
    log_error "$FAIL_COUNT check(s) failed"
fi
exit $((FAIL_COUNT > 0))
