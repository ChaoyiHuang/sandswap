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
# sticky-default-window.sh — the BUILT-IN sticky window keeps same-agent
# back-to-back calls warm on one keep-alive HTTP connection.
#
# The other warm-hit suites pin LEASE_MS=100 because each curl invocation
# costs more than the 3 ms default (process spawn + connect). This suite is
# deliberately the opposite: LEASE_MS stays UNSET, so the gateway runs its
# production default, and the requests are issued in-process over ONE
# persistent connection (http.client) so the gap is the gateway round trip,
# not a process spawn. It guards the documented claim that "back-to-back
# calls from one client stay warm" at the default window; a zero (or
# near-zero) hit rate means the default no longer bridges them.
#
# Usage: sudo bash e2e/sticky-default-window.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Small pool: the test only needs one VM. LEASE_MS is intentionally NOT set.
POOL_SIZE="${POOL_SIZE:-1}"
SANDLOT_POOL="${SANDLOT_POOL:-small:1}"
source "$ROOT/e2e/common.sh"

cleanup() {
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

# ── Phase 0: pre-flight ──────────────────────────────────────────────
tc_check_root
tc_preflight_standard python3
tc_ensure_dev_nodes
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    tc_log_info "NETWORK_BACKEND=$NETWORK_BACKEND — tinyVMs will be offline"
fi

# ── Phase 1: deploy + stack ──────────────────────────────────────────
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_start_gateway
tc_attach_vsockguard
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready

tc_create_agent_and_sandfs "default-window" >/dev/null
[[ -n "$TC_API_KEY" && -n "$TC_SANDFS_ID" ]] \
    || { tc_log_error "agent/SandFS creation returned no id"; exit 1; }

# ── Phase 2: one keep-alive connection, back-to-back execs ────────────
set +e
python3 - "$GATEWAY_URL" "$TC_API_KEY" "$TC_SANDFS_ID" <<'PY'
import http.client
import json
import sys
import time
import urllib.parse

base, key, sandfs_id = sys.argv[1:4]
u = urllib.parse.urlsplit(base)
if u.scheme != "http":
    print("unexpected gateway scheme %r (e2e agent listener is plain HTTP)" % u.scheme)
    sys.exit(2)
conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=30)
headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json"}

def one_call():
    body = json.dumps({"sandfs_id": sandfs_id, "code": "true", "language": "shell"})
    conn.request("POST", "/agent/execute", body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    return resp.status, resp.getheader("X-Sandbox-Lease"), data

def call():
    # A lease expiry can catch a request during the async unmount; that is a
    # retryable 503 and not the warm-hit signal under test.
    for _ in range(4):
        status, lease, data = one_call()
        if status != 503:
            return status, lease, data
        time.sleep(0.05)
    return status, lease, data

status, lease, data = call()
if status != 200:
    print("warm-up execute failed: %d %s" % (status, data[:300]))
    sys.exit(1)
if lease == "hit":
    print("warm-up reported a lease hit (first call must be cold)")
    sys.exit(1)

tries = hits = 0
for _ in range(10):
    status, lease, data = call()
    if status != 200:
        print("execute failed: %d %s" % (status, data[:300]))
        sys.exit(1)
    tries += 1
    if lease == "hit":
        hits += 1

print("default sticky window: %d/%d back-to-back calls warm (one keep-alive connection)" % (hits, tries))
# Majority tolerates one scheduler preemption between two in-process calls; a
# broken default (e.g. a zero window) yields zero hits.
if hits < max(1, tries // 2):
    sys.exit(1)
PY
RC=$?
set -e
if [[ $RC -eq 0 ]]; then
    tc_pass "built-in sticky window kept the back-to-back burst warm"
else
    tc_fail "built-in sticky window did not bridge back-to-back calls (see the hit count above)"
    exit 1
fi
