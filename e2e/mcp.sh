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
# test-mcp-e2e.sh — End-to-end test for the Sandswap MCP server.
# Starts the full stack (gateway + sandlot + KVM microVMs), creates an agent
# and sandfs, then runs the Go MCP e2e test binary that connects to the
# gateway's MCP endpoint (POST /mcp) and exercises all 12 MCP tools
# (incl. sandswap_guide). Then restarts the gateway with
# -mcp-instructions-file and proves offline customization + hot reload
# (initialize + sandswap_guide must serve the file's text, and pick up an
# in-place edit within the ~30s watcher poll).
# This test covers the full chain: MCP client → gateway → gRPC stream →
# sandlot → vmm → warden → microVM.
# Prerequisites:
#   1. bash build/build.sh all        (all binaries in output/)
#   2. bash build/build-rootfs-template.sh   (rootfs template in output/)
#   3. KVM available (/dev/kvm)
#   4. Root or kvm group member
# Usage: bash e2e/mcp.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# MCP e2e test binary
MCP_E2E_DIR="$ROOT/gateway/mcp/e2e"
MCP_E2E_BIN="/tmp/sandswap-mcp-e2e"

cleanup() {
    tc_cleanup_default
    rm -f "$MCP_E2E_BIN"
}
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight Checks"
# ══════════════════════════════════════════════════════════════════

tc_check_root
tc_preflight_standard go
tc_ensure_dev_nodes

if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — microVMs will be offline"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Deploy"
# ══════════════════════════════════════════════════════════════════

tc_clean_environment
tc_deploy_artifacts
tc_gen_certs

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Start Gateway + Sandlot"
# ══════════════════════════════════════════════════════════════════

tc_start_gateway
tc_attach_vsockguard
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Create Agent + SandFS"
# ══════════════════════════════════════════════════════════════════

# Create agent via /human/agent
log_step "Creating test agent..."
AGENT_RESP=$(curl -s -X POST "$HUMAN_URL/human/agent" \
    -H "Content-Type: application/json" \
    -d '{"name":"mcp-test-agent"}' || echo '{}')
AGENT_API_KEY=$(echo "$AGENT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
AGENT_ID=$(echo "$AGENT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || echo "")

if [[ -z "$AGENT_API_KEY" ]] || [[ -z "$AGENT_ID" ]]; then
    log_error "Failed to create agent: $AGENT_RESP"
    exit 1
fi
log_pass "Agent created: $AGENT_ID"

# Create sandfs via /human/sandfs (flat mode with default template)
log_step "Creating test sandfs (flat mode, template=rootfs:v1)..."
SANDFS_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"name\":\"mcp-test-sandfs\",\"description\":\"MCP e2e test sandfs\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}" || echo '{}')
SANDFS_ID=$(echo "$SANDFS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")

if [[ -z "$SANDFS_ID" ]]; then
    log_error "Failed to create sandfs: $SANDFS_RESP"
    exit 1
fi
log_pass "SandFS created: $SANDFS_ID"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Build & Run MCP E2E Test"
# ══════════════════════════════════════════════════════════════════

log_step "Building MCP e2e test binary..."
cd "$MCP_E2E_DIR"
go build -o "$MCP_E2E_BIN" . 2>&1
log_pass "MCP e2e test binary built"

log_step "Running MCP e2e test..."
echo ""

MCP_EXIT=0
"$MCP_E2E_BIN" \
    -gateway-url "$GATEWAY_URL" \
    -api-key "$AGENT_API_KEY" \
    -sandfs-id "$SANDFS_ID" \
    -timeout 120s || MCP_EXIT=$?

echo ""

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Instructions File (offline customization + hot reload)"
# ══════════════════════════════════════════════════════════════════

# Restart the gateway with -mcp-instructions-file. The agent's API key
# survives via the mandatory single-node identity store persistence; the pool
# is irrelevant here (initialize + sandswap_guide make no backend calls).
GUIDE_FILE="$LOG_DIR/mcp-guide.md"
INSTR_FAIL=0

log_step "Restarting gateway with -mcp-instructions-file..."
# Preserve the first run's log: tc_start_gateway truncates gateway.log, and
# if Phase 5 failed this is the gateway-side evidence needed to debug it.
mv "$LOG_DIR/gateway.log" "$LOG_DIR/gateway-phase1.log" 2>/dev/null || true
kill "${GATEWAY_PID:-0}" 2>/dev/null || true
wait "${GATEWAY_PID:-0}" 2>/dev/null || true
printf 'CUSTOM GUIDE MARKER alpha-123 — deployment-specific agent guidance.\n' > "$GUIDE_FILE"
tc_start_gateway -mcp-instructions-file "$GUIDE_FILE"
tc_wait_health

mcp_post() {  # initialize or tools/call via curl; echoes the payload text
    local method="$1" params="$2"
    curl -s -X POST "$GATEWAY_URL/mcp" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AGENT_API_KEY" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

log_step "initialize + sandswap_guide must serve the custom file..."
INIT_TEXT=$(mcp_post "initialize" '{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['result'].get('instructions',''))" 2>/dev/null || echo "")
GUIDE_TEXT=$(mcp_post "tools/call" '{"name":"sandswap_guide","arguments":{}}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['content'][0]['text'])" 2>/dev/null || echo "")
if [[ "$INIT_TEXT" == *"CUSTOM GUIDE MARKER alpha-123"* ]] && [[ "$GUIDE_TEXT" == "$INIT_TEXT" ]]; then
    log_pass "custom instructions served on initialize + sandswap_guide (identical)"
else
    log_error "custom instructions mismatch: init=${INIT_TEXT:0:60}... guide=${GUIDE_TEXT:0:60}..."
    INSTR_FAIL=1
fi

# Hot reload: edit the file in place; the event-driven watcher (~200ms
# debounce) must pick up the new text without a restart. Wait well past the
# debounce for robustness on a loaded CI box.
log_step "Editing file in place; waiting for the watcher (~200ms debounce)..."
printf 'CUSTOM GUIDE MARKER beta-456 — edited in place.\n' > "$GUIDE_FILE"
sleep 3
INIT_TEXT=$(mcp_post "initialize" '{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['result'].get('instructions',''))" 2>/dev/null || echo "")
if [[ "$INIT_TEXT" == *"CUSTOM GUIDE MARKER beta-456"* ]]; then
    log_pass "hot reload: edited text served without restart"
else
    log_error "hot reload failed: init=${INIT_TEXT:0:60}..."
    INSTR_FAIL=1
fi

[[ $INSTR_FAIL -eq 0 ]] || MCP_EXIT=1

# ══════════════════════════════════════════════════════════════════
log_section "Phase 7: Post-test Cleanup"
# ══════════════════════════════════════════════════════════════════

# Process teardown itself runs once in the EXIT trap (cleanup →
# tc_cleanup_default). Here we only verify the RESULT is visible before the
# summary prints (the trap runs after this point).
FINAL_REMAINING=$(ps aux 2>/dev/null | grep -E "(^|/)(sandvmm|sandlot|gateway) |(^|/)sandswap-(sandvmm|sandlot|gateway) " | grep -vE "grep|bash" || true)
if [[ -n "$FINAL_REMAINING" ]]; then
    log_warn "sandswap processes still alive before the exit trap (the trap will kill them):"
    echo "$FINAL_REMAINING"
fi

# Clean up the MCP e2e test binary
rm -f "$MCP_E2E_BIN" 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
log_section "Results Summary"
# ══════════════════════════════════════════════════════════════════

echo ""
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │        Sandswap MCP E2E Test Results             │"
echo "  ├──────────────────────────────────────────────────┤"
printf "  │ Mode:        REAL KVM (%-12s)            │\n" "$KVM_MODULE"
printf "  │ Gateway:     %-37s │\n" "$GATEWAY_URL"
printf "  │ Volumes:     %-37s │\n" "$VOL_ROOT"
printf "  │ Sandlot PID: %-5d  Gateway PID: %-5d         │\n" "${SANDLOT_PID:-0}" "${GATEWAY_PID:-0}"
echo "  ├──────────────────────────────────────────────────┤"
printf "  │ Agent ID:   %-41s │\n" "${AGENT_ID:-n/a}"
printf "  │ SandFS ID:  %-41s │\n" "${SANDFS_ID:-n/a}"
echo "  ├──────────────────────────────────────────────────┤"

if [[ $MCP_EXIT -eq 0 ]]; then
    echo "  │ MCP E2E:     PASSED                             │"
    log_pass "MCP e2e test PASSED"
else
    echo "  │ MCP E2E:     FAILED (exit code $MCP_EXIT)              │"
    log_error "MCP e2e test FAILED (exit code $MCP_EXIT)"
fi

echo "  └──────────────────────────────────────────────────┘"
echo ""
echo "  Logs:  $LOG_DIR/"
echo "  Deploy:$DEPLOY_DIR/"
echo ""

exit $MCP_EXIT
