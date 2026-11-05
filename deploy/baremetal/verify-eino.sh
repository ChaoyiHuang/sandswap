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
# verify-eino.sh - eino multi-agent verification for a deployed bare-metal install
# Creates agents + sandfs, builds + runs the eino multi-agent workload,
# analyzes results. Works with systemd-based single-node deployment.
# Usage:
#   bash verify-eino.sh [--no-tls] [--agent-count N]
#   --no-tls: the deployed stack's HTTP listeners are plaintext (a stack
#   deployed with --no-tls); the node stream it verifies through is always mTLS.
# Env:
#   DEEPSEEK_API_KEY  - LLM API key (required for the eino run)
#   DEEPSEEK_MODEL    - Model name (default: deepseek-flash)

set -euo pipefail

# sudo resets PATH (secure_path), dropping the toolchain install locations —
# this script `go build`s the eino test program. Prepend the well-known dirs
# when absent (same repair build.sh applies).
for pdir in /usr/local/go/bin "${HOME:-/root}/.cargo/bin" /usr/local/cargo/bin; do
    if [[ -d "$pdir" ]] && [[ ":$PATH:" != *":$pdir:"* ]]; then
        PATH="$pdir:$PATH"
    fi
done
export PATH

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# Preflight before any work: the eino test program needs an LLM key — fail
# named and early instead of mid-run.
if [[ -z "${DEEPSEEK_API_KEY:-}" && -z "${OPENAI_API_KEY:-}" && -z "${GOOGLE_API_KEY:-}" ]]; then
    err "no LLM API key set: the eino agents need DEEPSEEK_API_KEY (or OPENAI/GOOGLE); run: sudo env DEEPSEEK_API_KEY=sk-... bash $0"
fi

NO_TLS=0
AGENT_COUNT=2
EINO_TEST_BUDGET_SECS="${EINO_TEST_BUDGET_SECS:-300}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-tls)     NO_TLS=1; shift ;;
        --agent-count) AGENT_COUNT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--no-tls] [--agent-count N]"
            echo "  --no-tls       The stack's HTTP listeners are plaintext (dev deploys); the node stream is still mTLS"
            exit 0
            ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# Protocol selection for the HTTP (agent/human) endpoints. --no-tls means the
# stack was deployed with plaintext HTTP listeners; the gateway<->sandlot
# stream this drill exercises is always mTLS and needs no client-side flag.
if [[ $NO_TLS -eq 1 ]]; then
    PROTO="http"
else
    PROTO="https"
fi
GATEWAY_URL="${PROTO}://localhost:3000"
HUMAN_URL="${PROTO}://localhost:3100"

# Private working dir (mktemp): the shared /tmp/sandswap-logs belongs to the
# service identities (root:sandlot 2775) — a verification run as a PLAIN
# user must not need to write there. Cleaned on exit.
WORK_DIR="$(mktemp -d /tmp/sandswap-verify-eino-XXXX)"
LOG_DIR="$WORK_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT

pass() { echo -e "\033[1;32m[PASS]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; TEST_FAILED=1; }
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }

TEST_FAILED=0

echo "═══ Sandswap Eino Multi-Agent Test ═══"
echo "  Gateway URL: $GATEWAY_URL"
echo "  Human URL:   $HUMAN_URL"
echo "  Agent count: $AGENT_COUNT"
echo "  HTTP TLS:    $([ $NO_TLS -eq 1 ] && echo 'disabled' || echo 'enabled') (stream mTLS always on)"
echo ""

# ── Check prerequisites ───
info "Checking prerequisites..."

# Check gateway health. A missing stack is an ENVIRONMENT fact, not a defect
# of this drill: report it through the suite-skip channel (the script matrix
# records the reason) instead of a bare exit-1 that reads as a product failure
# (otherwise the row reads as a FAIL while its siblings are honest SKIPs).
if ! curl -sk "${PROTO}://localhost:3000/health" 2>/dev/null | grep -qi "ok\|healthy\|200"; then
    tc_skip_suite "needs-deployed-stack: gateway not healthy at ${PROTO}://localhost:3000/health (run deploy-one-machine-etcd.sh first)"
fi
pass "Gateway is healthy"

# Check compute node — single-node mode has /stats on :3100; exec mode does not
# (nodes verified via actual execution in Phase 3). Treat missing stats as
# "unknown" and let Phase 3 validate.
STATS=$(curl -sk "${PROTO}://localhost:3100/stats" 2>/dev/null || echo '{}')
NODE_COUNT=$(echo "$STATS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('totals',{}).get('node_count') or d.get('node_count',0))" 2>/dev/null || echo "0")
if [[ "$NODE_COUNT" != "0" ]]; then
    pass "Compute nodes connected: $NODE_COUNT"
else
    info "Compute node count not available via /stats (exec mode or no data) — will verify via execution in Phase 3"
fi

# Check DEEPSEEK_API_KEY
if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
    fail "DEEPSEEK_API_KEY not set"
    exit 1
fi
pass "DEEPSEEK_API_KEY is set"

# ── Phase 1: Create Agents + SandFS ───
echo ""
info "Phase 1: Creating $AGENT_COUNT agents + sandfs..."

API_KEYS=()
SANDFS_IDS=()

# Figure out the template ref — flat template dir layout:
#   flatTemplatesDir/<name>/<version>/ → template ref is "<name>:<version>"
# (ScanFlatTemplates registers name:version from the two-level subdir layout.)
TEMPLATE_NAME=""
# Local flat templates (single-node deploy) first; shared-storage topologies
# (cluster rehearsals / k8s) keep them on the shared mount instead.
FT_DIR="${FLAT_TEMPLATES_DIR:-/var/lib/sandswap/flat-templates}"
if [[ -z "$(ls -A "$FT_DIR" 2>/dev/null)" && -d /mnt/sandswap/flat-templates ]]; then
    FT_DIR="/mnt/sandswap/flat-templates"
fi
if [[ -d "$FT_DIR" ]]; then
    # Glob-based scan (ls output breaks on spaces and is flagged by shellcheck)
    for dir in "$FT_DIR"/*/; do
        [[ -d "$dir" ]] || continue
        name=$(basename "$dir")
        for sub in "$dir"*/; do
            [[ -d "$sub" ]] || continue
            TEMPLATE_NAME="$name:$(basename "$sub")"
            break 2
        done
    done
fi

info "Using template: ${TEMPLATE_NAME:-none}"

for i in $(seq 1 "$AGENT_COUNT"); do
    AGENT_NAME="test-agent-$i"
    SANDFS_NAME="test-sandfs-$i"

    # Create agent
    AGENT_RESP=$(curl -sk -X POST "$HUMAN_URL/human/agent" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"$AGENT_NAME\"}" 2>/dev/null || echo '{}')
    AGENT_KEY=$(echo "$AGENT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
    AGENT_ID=$(echo "$AGENT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || echo "")

    if [[ -z "$AGENT_KEY" ]] || [[ -z "$AGENT_ID" ]]; then
        fail "Failed to create agent $i: $AGENT_RESP"
        exit 1
    fi
    pass "Agent $i created: $AGENT_ID"

    # Create sandfs
    SANDFS_BODY="{\"agent_id\":\"$AGENT_ID\",\"name\":\"$SANDFS_NAME\",\"description\":\"Test sandbox $i\",\"mode\":\"flat\""
    if [[ -n "$TEMPLATE_NAME" ]]; then
        SANDFS_BODY="$SANDFS_BODY,\"template\":\"$TEMPLATE_NAME\""
    fi
    SANDFS_BODY="$SANDFS_BODY}"

    SANDFS_RESP=$(curl -sk -X POST "$HUMAN_URL/human/sandfs" \
        -H "Content-Type: application/json" \
        -d "$SANDFS_BODY" 2>/dev/null || echo '{}')
    SANDFS_ID=$(echo "$SANDFS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")

    if [[ -z "$SANDFS_ID" ]]; then
        fail "Failed to create sandfs $i: $SANDFS_RESP"
        exit 1
    fi
    pass "SandFS $i created: $SANDFS_ID"

    API_KEYS+=("$AGENT_KEY")
    SANDFS_IDS+=("$SANDFS_ID")
done

# ── Phase 2: Verify API key resolution ───
echo ""
info "Phase 2: Verifying API key resolution..."
VERIFY_RESP=$(curl -sk -X POST "$GATEWAY_URL/mcp" \
    -H "Authorization: Bearer ${API_KEYS[0]}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"verify","version":"1.0.0"}}}' 2>/dev/null || echo '')

if echo "$VERIFY_RESP" | grep -q '"result"'; then
    pass "API key resolved (MCP initialize works)"
else
    fail "API key resolution failed: $VERIFY_RESP"
    exit 1
fi

# ── Phase 3: Verify compute node reachable ───
echo ""
info "Phase 3: Verifying compute node reachable..."
NODE_READY=false
for _ in $(seq 1 60); do
    TEST_RESP=$(curl -sk -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer ${API_KEYS[0]}" \
        -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"${SANDFS_IDS[0]}\",\"code\":\"echo ready\",\"language\":\"shell\",\"timeout\":10}" 2>/dev/null || echo '')
    if echo "$TEST_RESP" | grep -q '"status":"done\|"status": "done"'; then
        NODE_READY=true
        pass "Compute node reachable (execute succeeded)"
        break
    fi
    sleep 3
done
if [[ "$NODE_READY" != "true" ]]; then
    fail "Compute node not reachable after 180s"
    info "Last response: $TEST_RESP"
    info "Sandlot logs:"
    journalctl -u sandswap-sandlot --no-pager -n 20 2>/dev/null || true
    exit 1
fi

# ── Phase 4: Build + Run Eino Multi-Agent Test ───
echo ""
info "Phase 4: Building + running eino multi-agent test..."

EINO_DIR="$REPO_ROOT/examples/eino-sandswap"
EINO_BIN="$LOG_DIR/eino-sandswap-test"

# Release packages ship the prebuilt example binary; dev trees build from
# examples/ source. Same contract for both paths (mirrors bm_build_eino).
if [[ -x "$REPO_ROOT/output/eino-sandswap" ]]; then
    cp "$REPO_ROOT/output/eino-sandswap" "$EINO_BIN"
    pass "Eino binary ready (prebuilt from output/)"
else
    if ! command -v go >/dev/null 2>&1 && [ ! -x /usr/local/go/bin/go ]; then
        fail "No prebuilt eino binary at $REPO_ROOT/output/eino-sandswap and no Go toolchain on this host."
        fail "  → Use the release package (output/ ships the prebuilt binary), or install Go and retry."
        exit 1
    fi
    info "Building eino binary from examples/ source..."
    cd "$EINO_DIR"
    export PATH="$PATH:/usr/local/go/bin"
    # -buildvcs=false: the checkout may be owned by a different user (root
    # vs the plain user running this verification) — VCS stamping would then
    # fail with "error obtaining VCS status" and abort an otherwise fine
    # build. We do not embed VCS info in this test binary.
    if ! go build -buildvcs=false -o "$EINO_BIN" . 2>&1; then
        fail "Failed to build eino binary"
        exit 1
    fi
    pass "Eino binary built"
fi

info "Running $AGENT_COUNT-agent piped test (budget=${EINO_TEST_BUDGET_SECS}s)..."

# Build the piped prompts based on agent count
build_prompts() {
    local count=$1
    for i in $(seq 1 "$count"); do
        echo "${i}:Use the execute tool to run this shell command: echo hello_from_agent_${i}"
        sleep 15
    done
    # File write test with agent 1
    echo "1:Use the file_write tool to write the text 'agent1 marker content' to a file called agent1_marker.txt"
    sleep 15
    # File read-back test with agent 1 (same volume: write→read persistence).
    # NOTE: agent 2 must NOT read agent 1's file — each sandfs is an isolated
    # volume by design (cross-agent invisibility is the product, asserted in
    # multi-agents.sh B1).
    echo "1:Use the file_read tool to read the file agent1_marker.txt back from the sandbox filesystem. You must call the tool, do not answer from memory."
    sleep 15
    # Background exec test with agent 1
    if [[ $count -ge 1 ]]; then
        echo "1:Use the execute tool with background=true and lease_duration=30 to start this shell command in the background: sleep 3 && echo bg_complete_marker. IMPORTANT: Do NOT call exec_status after starting the background exec. Just reply that the background task has been started and stop."
        sleep 15
    fi
    # Final command
    echo "${count}:Use the execute tool to run this shell command: echo agent${count}_final"
    sleep 10
    echo "exit"
}

EINO_EXIT=0
export SANDSWAP_MCP_URL="$GATEWAY_URL/mcp"
export DEEPSEEK_API_KEY
export DEEPSEEK_MODEL="${DEEPSEEK_MODEL:-deepseek-flash}"

# Set per-agent API keys
for i in $(seq 0 $((AGENT_COUNT - 1))); do
    export "SANDSWAP_API_KEY_$((i+1))=${API_KEYS[$i]}"
done

if [[ $NO_TLS -eq 0 ]]; then
    export SANDSWAP_CA_CERT="/etc/sandswap/certs/ca.crt"
fi

# The eino process exit code is part of the verdict: a mid-run crash that
# happens to leave matching markers in the log must not read as PASS.
EINO_EXIT=0
(build_prompts "$AGENT_COUNT") | timeout "$EINO_TEST_BUDGET_SECS" "$EINO_BIN" 2>&1 | tee "$LOG_DIR/eino-test.log" || EINO_EXIT=$?

# ── Phase 5: Analyze Results ───
echo ""
info "Phase 5: Analyzing results..."

EINO_LOG="$LOG_DIR/eino-test.log"

if [[ ! -f "$EINO_LOG" ]] || [[ ! -s "$EINO_LOG" ]]; then
    fail "Eino test log is empty or missing"
    exit 1
fi

# Multi-agent startup
if grep -q "multi-agent ready" "$EINO_LOG"; then
    pass "Multi-agent started"
else
    fail "Multi-agent did not start"
fi

# Tool discovery
TOOL_COUNT=$(grep -c "tools discovered" "$EINO_LOG" || true)
if [[ "$TOOL_COUNT" -ge "$AGENT_COUNT" ]]; then
    pass "All agents discovered tools ($TOOL_COUNT entries)"
else
    fail "Tool discovery incomplete ($TOOL_COUNT/$AGENT_COUNT)"
fi

# Agent execution
for i in $(seq 1 "$AGENT_COUNT"); do
    if grep -q "hello_from_agent_$i" "$EINO_LOG"; then
        pass "Agent $i executed shell command"
    else
        fail "Agent $i shell command not found"
    fi
done

# File write + read-back persistence (agent 1, same volume)
if grep -q "agent1 marker content" "$EINO_LOG"; then
    pass "Agent 1 marker write + read-back confirmed"
else
    fail "Agent 1 marker write/read-back not confirmed"
fi

# Background exec
if grep -q "bg_complete_marker" "$EINO_LOG" || grep -q "background task has been started" "$EINO_LOG"; then
    pass "Background exec works"
else
    fail "Background exec not confirmed"
fi

# Final command
if grep -q "agent${AGENT_COUNT}_final" "$EINO_LOG"; then
    pass "Final agent command executed"
else
    fail "Final agent command not found"
fi

# ── Summary ───
echo ""
echo "═══ Test Summary ═══"
if [[ $TEST_FAILED -eq 0 ]] && [[ "${EINO_EXIT:-0}" -eq 0 ]]; then
    pass "ALL TESTS PASSED"
    exit 0
else
    if [[ "${EINO_EXIT:-0}" -ne 0 ]]; then
        fail "eino process exited with code $EINO_EXIT"
    fi
    fail "SOME TESTS FAILED"
    info "Full log: $EINO_LOG"
    info "Sandlot logs: journalctl -u sandswap-sandlot -n 50"
    info "Gateway logs: journalctl -u 'sandswap-gateway*' -n 50"
    exit 1
fi
