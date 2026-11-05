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
# test-eino-e2e.sh — End-to-end test for the Sandswap Eino dual-agent example.
# Starts the full stack (gateway + sandlot + KVM microVMs), creates TWO agents
# with TWO sandfs (both backed by Ubuntu rootfs), then runs the Eino program
# in dual-agent mode where both agents exercise the same microVM pool.
# This test validates:
#   1. Both agents connect to the MCP server and discover tools
#   2. Each agent executes code in its own sandbox
#   3. The microVM is reused across agents (virtio-fs allowed_dirs hot-swap)
#   4. File isolation: Agent A's files are not visible to Agent B
#   5. Sequential agent operations on the same VM work correctly
# Architecture under test:
#   Eino Agent A ──┐
#                  ├─→ Gateway (MCP) → gRPC → Sandlot → VMM → microVM (shared)
#   Eino Agent B ──┘
# Prerequisites:
#   1. bash build/build.sh all        (all binaries in output/)
#   2. bash build/build-ubuntu-rootfs.sh  (Ubuntu rootfs in output/rootfs-ubuntu/)
#   3. KVM available (/dev/kvm)
#   4. Root or kvm group member
#   5. DEEPSEEK_API_KEY or OPENAI_API_KEY set (for the LLM backend)
# Usage:
#   export DEEPSEEK_API_KEY=sk-xxx
#   bash e2e/eino-agent-mcp.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Override defaults before sourcing
POOL_SIZE="${POOL_SIZE:-1}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-eino-logs}"
GATEWAY_ADDR="${GATEWAY_ADDR:-:3001}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
source "$ROOT/e2e/common.sh"

# Ubuntu rootfs template
ROOTFS_UBUNTU="${ROOTFS_UBUNTU:-$OUTPUT/rootfs-ubuntu}"

# Eino example (override EINO_DIR to test the openai-go + go-sdk twin at
# examples/openai-sandswap — it emits the same log lines this script greps for)
EINO_DIR="${EINO_DIR:-$ROOT/examples/eino-sandswap}"
EINO_BIN="/tmp/sandswap-eino-e2e"

# LLM API key: require at least one to be set
if [[ -z "${DEEPSEEK_API_KEY:-}" ]] && [[ -z "${OPENAI_API_KEY:-}" ]] && [[ -z "${GOOGLE_API_KEY:-}" ]]; then
    echo "Error: No LLM API key set. Set one of:" >&2
    echo "  export DEEPSEEK_API_KEY=sk-xxx   (recommended)" >&2
    echo "  export OPENAI_API_KEY=sk-xxx" >&2
    echo "  export GOOGLE_API_KEY=xxx" >&2
    exit 1
fi

# Determine which backend is active (for display)
if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
    LLM_BACKEND="deepseek"
elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
    LLM_BACKEND="openai"
else
    LLM_BACKEND="gemini"
fi

cleanup() {
    tc_cleanup_default
    # Restore the busybox rootfs template this run replaced with Ubuntu:
    # $DEPLOY_DIR persists across runs BY DESIGN, so without this the next
    # script silently inherits a multi-GB Ubuntu image as rootfs:v1.
    if [[ -d "$OUTPUT/rootfs-template" && -d "${DEPLOY_DIR:-/nonexistent}" && -d "$DEPLOY_DIR/flat-templates" ]]; then
        rm -rf "$DEPLOY_DIR/flat-templates/rootfs/v1"
        mkdir -p "$DEPLOY_DIR/flat-templates/rootfs/v1"
        cp -a "$OUTPUT/rootfs-template/." "$DEPLOY_DIR/flat-templates/rootfs/v1/" 2>/dev/null || true
        tc_conform_template_tree "$DEPLOY_DIR/flat-templates" 2>/dev/null || true
    fi
    # Clean up the eino test binary
    rm -f "$EINO_BIN" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight Checks"
# ══════════════════════════════════════════════════════════════════

echo "  Host:     $(uname -n)"
echo "  Arch:     $(uname -m)"
echo "  Kernel:   $(uname -r)"
echo "  LLM:      $LLM_BACKEND"

tc_check_root
tc_check_kvm
tc_check_artifacts
tc_check_freshness
tc_check_tools curl go python3
tc_ensure_dev_nodes

# Ubuntu rootfs template — build automatically if missing
if [[ ! -d "$ROOTFS_UBUNTU" ]] || [[ ! -d "$ROOTFS_UBUNTU/bin" ]]; then
    log_warn "Ubuntu rootfs template not found — building automatically..."
    if ! bash "$ROOT/build/build-ubuntu-rootfs.sh"; then
        log_error "Ubuntu rootfs build failed"
        exit 1
    fi
    if [[ ! -d "$ROOTFS_UBUNTU/bin" ]]; then
        log_error "Ubuntu rootfs build succeeded but /bin missing — check $ROOTFS_UBUNTU/"
        exit 1
    fi
fi
log_pass "Ubuntu rootfs template present: $ROOTFS_UBUNTU/"

# Host networking setup
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — microVMs will be offline"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Deploy (with pre-test cleanup)"
# ══════════════════════════════════════════════════════════════════

tc_clean_environment
tc_deploy_artifacts

# Ubuntu rootfs template directory — copy into the flat-templates structure
# (tc_deploy_artifacts already created $DEPLOY_DIR/flat-templates/rootfs/v1/ with busybox)
# Replace it with the Ubuntu rootfs for this test.
log_step "Deploying Ubuntu rootfs template (replacing default busybox)..."
rm -rf "$DEPLOY_DIR/flat-templates/rootfs/v1"
mkdir -p "$DEPLOY_DIR/flat-templates/rootfs/v1"
cp -a "$ROOTFS_UBUNTU/." "$DEPLOY_DIR/flat-templates/rootfs/v1/"
# Group grant + contract check (see tc_conform_template_tree): the ubuntu tree
# carries 0640 root:root files the non-root seed identity cannot read.
tc_conform_template_tree "$DEPLOY_DIR/flat-templates"
if [[ ! -d "$DEPLOY_DIR/flat-templates/rootfs/v1/bin" ]]; then
    log_error "Ubuntu rootfs-template directory copy failed (no bin/ subdir)"
    exit 1
fi
if [[ ! -d "$DEPLOY_DIR/flat-templates/rootfs/v1/workspace" ]]; then
    log_error "Ubuntu rootfs-template missing /workspace directory"
    exit 1
fi
log_info "Ubuntu rootfs template deployed: $DEPLOY_DIR/flat-templates/rootfs/v1/ ($(du -sh "$DEPLOY_DIR/flat-templates/rootfs/v1" | cut -f1))"

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
log_section "Phase 3: Create Two Agents + Two SandFS"
# ══════════════════════════════════════════════════════════════════

# --- Agent A ---
log_step "Creating agent A..."
AGENT_A_RESP=$(curl -s -X POST "$HUMAN_URL/human/agent" \
    -H "Content-Type: application/json" \
    -d '{"name":"eino-agent-a"}' || echo '{}')
AGENT_A_KEY=$(echo "$AGENT_A_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
AGENT_A_ID=$(echo "$AGENT_A_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || echo "")

if [[ -z "$AGENT_A_KEY" ]] || [[ -z "$AGENT_A_ID" ]]; then
    log_error "Failed to create agent A: $AGENT_A_RESP"
    exit 1
fi
log_pass "Agent A created: $AGENT_A_ID"

log_step "Creating sandfs for agent A (install_packages=true, flat mode)..."
SANDFS_A_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_A_ID\",\"name\":\"eino-sandfs-a\",\"description\":\"Agent A sandbox\",\"template\":\"rootfs:v1\",\"mode\":\"flat\",\"install_packages\":true}" || echo '{}')
SANDFS_A_ID=$(echo "$SANDFS_A_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")

if [[ -z "$SANDFS_A_ID" ]]; then
    log_error "Failed to create sandfs A: $SANDFS_A_RESP"
    exit 1
fi
log_pass "SandFS A created: $SANDFS_A_ID"

# --- Agent B ---
log_step "Creating agent B..."
AGENT_B_RESP=$(curl -s -X POST "$HUMAN_URL/human/agent" \
    -H "Content-Type: application/json" \
    -d '{"name":"eino-agent-b"}' || echo '{}')
AGENT_B_KEY=$(echo "$AGENT_B_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
AGENT_B_ID=$(echo "$AGENT_B_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || echo "")

if [[ -z "$AGENT_B_KEY" ]] || [[ -z "$AGENT_B_ID" ]]; then
    log_error "Failed to create agent B: $AGENT_B_RESP"
    exit 1
fi
log_pass "Agent B created: $AGENT_B_ID"

log_step "Creating sandfs for agent B (flat mode)..."
SANDFS_B_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_B_ID\",\"name\":\"eino-sandfs-b\",\"description\":\"Agent B sandbox\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}" || echo '{}')
SANDFS_B_ID=$(echo "$SANDFS_B_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")

if [[ -z "$SANDFS_B_ID" ]]; then
    log_error "Failed to create sandfs B: $SANDFS_B_RESP"
    exit 1
fi
log_pass "SandFS B created: $SANDFS_B_ID"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Dual-Agent E2E Test (VM Reuse)"
# ══════════════════════════════════════════════════════════════════

log_step "Building Eino example binary..."
cd "$EINO_DIR"
go build -o "$EINO_BIN" . 2>&1
log_pass "Eino example binary built"

log_step "Running dual-agent test (piped mode, pool size=$POOL_SIZE)..."
echo ""

# The dual-agent test exercises VM reuse across agents.
#
# Test flow:
#   1. Agent A writes a marker file (agent_a_marker.txt) with unique content
#   2. Agent B writes a different marker file (agent_b_marker.txt)
#   3. Agent A reads back its marker file
#   4. Agent B reads back its marker file
#   5. Agent A starts a background exec (sleep + echo, no network needed)
#   6. Agent A verifies it can still execute commands after the background exec
#   7. Agent B executes a final shell command
#   8. Exit
#
# With POOL_SIZE=1, both agents MUST share the same microVM.
# The gateway will perform virtio-fs allowed_dirs hot-swap between them.

# Total wall-clock budget for the ENTIRE piped test to finish (not a per-op
# timeout): covers the piped prompt sleeps + all DeepSeek LLM round-trips +
# background exec wait. 300s default.
EINO_TEST_BUDGET_SECS="${EINO_TEST_BUDGET_SECS:-300}"

EINO_EXIT=0

# Run the Eino dual-agent with piped input.
# Prompts prefixed with "A:" route to agent A, "B:" to agent B.
# Sequential processing: each prompt completes before the next starts,
# ensuring clean VM switching between agents.
#
# Prompt design: every prompt explicitly instructs the agent to use a
# specific MCP tool, preventing the LLM from fabricating results from
# conversation history instead of actually calling the tool.
(
    echo "A:Use the execute tool to run this shell command: echo hello_from_agent_a"
    sleep 15
    echo "B:Use the execute tool to run this shell command: echo hello_from_agent_b"
    sleep 15
    echo "A:Use the file_write tool to write the text 'marker file from agent A' to a file called agent_a_marker.txt"
    sleep 15
    echo "B:Use the file_write tool to write the text 'marker file from agent B' to a file called agent_b_marker.txt"
    sleep 15
    echo "A:Use the file_read tool to read the file agent_a_marker.txt from the sandbox filesystem. You must call the tool, do not answer from memory."
    sleep 15
    echo "B:Use the file_read tool to read the file agent_b_marker.txt from the sandbox filesystem. You must call the tool, do not answer from memory."
    sleep 15
    echo "A:Use the execute tool with background=true and lease_duration=30 to start this shell command in the background: sleep 5 && echo bg_exec_complete_marker. IMPORTANT: Do NOT call exec_status after starting the background exec. Just reply that the background task has been started and stop."
    sleep 20
    echo "A:Use the execute tool to run this shell command: echo post_bg_check_ok"
    sleep 15
    echo "B:Use the execute tool to run this shell command: echo hello_from_b_final"
    sleep 15
    echo "exit"
) | timeout "$EINO_TEST_BUDGET_SECS" env \
    SANDSWAP_API_KEY_A="$AGENT_A_KEY" \
    SANDSWAP_API_KEY_B="$AGENT_B_KEY" \
    SANDSWAP_MCP_URL="$GATEWAY_URL/mcp" \
    DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}" \
    DEEPSEEK_MODEL="${DEEPSEEK_MODEL:-deepseek-flash}" \
    OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
    GOOGLE_API_KEY="${GOOGLE_API_KEY:-}" \
    "$EINO_BIN" 2>&1 | tee "$LOG_DIR/eino-dual-agent.log" || EINO_EXIT=$?

echo ""

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Analyze Results"
# ══════════════════════════════════════════════════════════════════

EINO_LOG="$LOG_DIR/eino-dual-agent.log"

if [[ ! -f "$EINO_LOG" ]] || [[ ! -s "$EINO_LOG" ]]; then
    fail "Eino dual-agent log is empty or missing"
else
    # ── MCP connection ──────────────────────────────────────────
    if grep -q "dual-agent ready" "$EINO_LOG"; then
        pass "Eino dual-agent started in piped mode"
    else
        fail "Eino dual-agent did not start correctly"
    fi

    # Both agents should discover tools
    TOOL_COUNT=$(grep -c "tools discovered" "$EINO_LOG" || true)
    if [[ "$TOOL_COUNT" -ge 2 ]]; then
        pass "Both agents discovered MCP tools ($TOOL_COUNT tool entries found)"
    else
        fail "Not all agents discovered MCP tools (found $TOOL_COUNT, expected >= 2)"
    fi

    # ── Agent A shell execution ─────────────────────────────────
    # Check for successful execution output, NOT the prompt text.
    # The prompt contains "echo hello_from_agent_a" so grepping for
    # hello_from_agent_a matches the prompt too. Instead, look for
    # non-prompt lines (not starting with "user prompt:") that contain
    # the expected output, or check for LLM errors.
    if grep -v "user prompt:" "$EINO_LOG" | grep -qi "hello_from_agent_a"; then
        pass "Agent A executed shell command (found 'hello_from_agent_a' in output)"
    elif grep -qi "NodeRunError\|invalid_request_error\|HTTP [45][0-9][0-9]" "$EINO_LOG"; then
        fail "Agent A LLM call failed (API error) — check DEEPSEEK_MODEL env var"
        log_info "First error line:"
        grep -m1 "NodeRunError\|invalid_request_error" "$EINO_LOG" | sed 's/^/    /'
    else
        fail "Agent A did not execute shell command (expected 'hello_from_agent_a')"
        log_info "Agent A related lines:"
        grep "\[A\]" "$EINO_LOG" | tail -10 | sed 's/^/    /'
    fi

    # ── Agent B shell execution ─────────────────────────────────
    if grep -v "user prompt:" "$EINO_LOG" | grep -qi "hello_from_agent_b"; then
        pass "Agent B executed shell command (found 'hello_from_agent_b' in output)"
    elif grep -qi "NodeRunError\|invalid_request_error\|HTTP [45][0-9][0-9]" "$EINO_LOG"; then
        fail "Agent B LLM call failed (API error) — check DEEPSEEK_MODEL env var"
    else
        fail "Agent B did not execute shell command (expected 'hello_from_agent_b')"
        log_info "Agent B related lines:"
        grep "\[B\]" "$EINO_LOG" | tail -10 | sed 's/^/    /'
    fi

    # ── Agent A/B file operations, bg exec, post-bg, B final ────
    # These greps look for TOOL-RESULT content in non-prompt lines (the prompts
    # instruct explicit tool use) — deterministic evidence, not "LLM response
    # format". A run where the tool calls never happened must FAIL, not warn.
    if grep -v "user prompt:" "$EINO_LOG" | grep -qi "\[A\].*marker.*agent.*A\|agent_a_marker"; then
        pass "Agent A performed file operations (marker file confirmed)"
    else
        fail "Agent A file operation evidence not found (file_write/file_read tool call never surfaced)"
    fi

    if grep -v "user prompt:" "$EINO_LOG" | grep -qi "\[B\].*marker.*agent.*B\|agent_b_marker"; then
        pass "Agent B performed file operations (marker file confirmed)"
    else
        fail "Agent B file operation evidence not found (file_write/file_read tool call never surfaced)"
    fi

    if grep -v "user prompt:" "$EINO_LOG" | grep -qi "bg_exec_complete_marker"; then
        pass "Agent A background exec completed (found bg_exec_complete_marker)"
    else
        fail "Agent A background exec marker not found (bg exec never ran or never completed)"
    fi

    if grep -v "user prompt:" "$EINO_LOG" | grep -qi "post_bg_check_ok"; then
        pass "Agent A executed post-background verification command"
    else
        fail "Agent A post-background verification not found (exec after bg failed?)"
    fi

    if grep -v "user prompt:" "$EINO_LOG" | grep -qi "hello_from_b_final"; then
        pass "Agent B executed final shell command"
    else
        fail "Agent B final shell result not found (final execute tool call never surfaced)"
    fi

    # ── VM reuse evidence ───────────────────────────────────────
    # Check the gateway log for evidence of VM reuse / agent switching.
    # With POOL_SIZE=1, the same VM should be acquired, attached, released,
    # then re-acquired for the other agent (allowed_dirs hot-swap).
    if [[ -f "$LOG_DIR/gateway.log" ]]; then
        SWITCH_COUNT=$(grep -c "attach\|IN_USE\|RELEASE\|LEASED\|acquired" "$LOG_DIR/gateway.log" 2>/dev/null || true)
        if [[ "$SWITCH_COUNT" -gt 0 ]]; then
            log_info "Gateway log shows $SWITCH_COUNT attach/release events (VM reuse activity)"
        fi

        # Check that only the pool's VMs were created (proving reuse). The
        # spawn log line is sandlot's "launching VMM" (vmm/launcher.go) — the
        # old pattern ("creating VM|create vm") matched NOTHING either binary
        # logs, so the count was always 0 and the <=2 gate always passed
        # (vacuous). Bound BOTH ways now: 0 = pattern drifted (must FAIL, not
        # pass); > pool+2 = per-agent churn beyond one legitimate crash/memory
        # recycle replacement.
        VM_CREATE_COUNT=$(grep -c "launching VMM" "$LOG_DIR/sandlot.log" 2>/dev/null || true)
        VM_CREATE_COUNT=${VM_CREATE_COUNT:-0}
        if (( VM_CREATE_COUNT >= 1 && VM_CREATE_COUNT <= POOL_SIZE + 2 )); then
            pass "VM reuse confirmed: $VM_CREATE_COUNT VM launch(es) for 2 agents (pool size $POOL_SIZE)"
        elif (( VM_CREATE_COUNT == 0 )); then
            fail "no 'launching VMM' lines in sandlot.log — log pattern drifted? VM reuse UNVERIFIED"
        else
            fail "$VM_CREATE_COUNT VM launches — VM reuse BROKEN (expected <= $((POOL_SIZE + 2)) for pool size $POOL_SIZE)"
        fi
    fi
fi


# ================================================================================
log_section "Phase 6: Capability Policy + Background Exec Verification"
# ================================================================================

# Wait for the pool to recover after the Eino test (background exec leases
# may still hold the VM with pool_size=1).  Poll until all VMs are CLEAN.
log_step "Waiting for VM pool to recover after Eino test..."
for i in $(seq 1 60); do
    POOL_STATE=$(curl -s "$HUMAN_URL/stats" 2>/dev/null || echo '{}')
    # /stats shape: {"gateways":[...],"totals":{"clean_vms":N,"total_vms":N,"in_use_vms":N}}
    INUSE_COUNT=$(echo "$POOL_STATE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('totals',{}).get('in_use_vms',0))" 2>/dev/null || echo "1")
    CLEAN_COUNT=$(echo "$POOL_STATE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('totals',{}).get('clean_vms',0))" 2>/dev/null || echo "0")
    if [[ "$INUSE_COUNT" == "0" ]] && [[ "$CLEAN_COUNT" -ge 1 ]]; then
        log_pass "Pool fully recovered: $CLEAN_COUNT CLEAN VM(s), no IN_USE"
        break
    fi
    if [[ "$i" -eq 60 ]]; then
        log_warn "Pool still not fully recovered after 300s (IN_USE=$INUSE_COUNT CLEAN=$CLEAN_COUNT), proceeding anyway..."
    fi
    sleep 5
done

# Brief settling delay after pool recovery — the VM may be CLEAN but
# the first exec after recovery can still race with lease cleanup.
sleep 3

# Verify capability policy and background exec lifecycle:
#   - Package-install policy is derived from sandfs MODE (docs/integration/agent-http.md):
#     flat → install profile (ambient caps); overlay → strict (zero caps).
#   - Both agents are flat, so both run the install profile; seccomp still
#     blocks mount/unshare for both.

log_step "Testing install_packages flag and background exec lifecycle..."

# Helper: execute a command for an agent (sync, timeout in seconds)
# Returns the raw JSON response from the gateway.
exec_code() {
    local key="$1"; shift
    local sandfs_id="$1"; shift
    local timeout_sec="${1:-60}"; shift
    local code="$*"
    # Escape double quotes and backslashes in code for JSON
    local escaped_code
    escaped_code=$(echo "$code" | sed 's/\\/\\\\/g; s/"/\\"/g')
    curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        -d "{\"code\":\"$escaped_code\",\"language\":\"shell\",\"timeout\":$timeout_sec,\"sandfs_id\":\"$sandfs_id\"}" 2>/dev/null
}

# Helper: extract stdout from exec_code JSON response
exec_stdout() {
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('stdout',''))" 2>/dev/null || echo ""
}

# Helper: start a background exec (returns exec_id)
exec_background() {
    local key="$1"; shift
    local sandfs_id="$1"; shift
    local lease_sec="${1:-120}"; shift
    local code="$*"
    local escaped_code
    escaped_code=$(echo "$code" | sed 's/\\/\\\\/g; s/"/\\"/g')
    curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        -d "{\"code\":\"$escaped_code\",\"language\":\"shell\",\"background\":true,\"lease_duration\":$lease_sec,\"sandfs_id\":\"$sandfs_id\"}" 2>/dev/null
}

# Helper: poll background exec status
exec_status() {
    local key="$1"; shift
    local sandfs_id="$1"; shift
    local exec_id="$1"; shift
    curl -s -X POST "$GATEWAY_URL/agent/exec/status" \
        -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        -d "{\"exec_id\":\"$exec_id\",\"sandfs_id\":\"$sandfs_id\"}" 2>/dev/null
}

# ── Agent A: install_packages=true ──────────────────────────────
# NOTE: With POOL_SIZE=1, the VM from Phase 5's bg exec may still be
# occupied. We need to wait for it to complete before running these checks.
# The "pool recovered" wait above should have handled that.

# Step 1: Verify Agent A has ambient capabilities (flat mode → install
# profile retains ambient caps; the create-time install_packages field is
# no longer the switch — docs/integration/agent-http.md).
log_step "Agent A (flat mode → install profile): checking ambient capabilities..."
A_CAPS_RESP=$(exec_code "$AGENT_A_KEY" "$SANDFS_A_ID" 30 "cat /proc/self/status | grep CapEff")
A_CAPS=$(echo "$A_CAPS_RESP" | exec_stdout)
# Check for error first
A_CAPS_ERR=$(echo "$A_CAPS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "")
if [[ -n "$A_CAPS_ERR" ]]; then
    log_warn "Agent A: CapEff check failed (may be VM contention): $A_CAPS_ERR"
elif echo "$A_CAPS" | grep -qiE "CapEff.*[1-9a-f]"; then
    pass "Agent A: ambient capabilities present (flat-mode install profile)"
else
    fail "Agent A: no ambient capabilities detected (flat-mode install profile not applied?)"
fi

# Step 2: Background exec — lightweight async test (no network needed).
# This tests the full background exec lifecycle: start → poll → done,
# without relying on apt-get (which is slow and flaky under nested KVM).
log_step "Agent A: starting background exec (async lifecycle test)..."
A_BG_RESP=$(exec_background "$AGENT_A_KEY" "$SANDFS_A_ID" 30 "sleep 3 && echo bg_exec_test_complete")
A_EXEC_ID=$(echo "$A_BG_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('exec_id',''))" 2>/dev/null || echo "")

# Retry if VM contention
if [[ -z "$A_EXEC_ID" ]]; then
    A_BG_ERR=$(echo "$A_BG_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "")
    log_warn "Agent A: first background exec attempt failed ($A_BG_ERR), retrying after 5s..."
    sleep 5
    A_BG_RESP=$(exec_background "$AGENT_A_KEY" "$SANDFS_A_ID" 30 "sleep 3 && echo bg_exec_test_complete")
    A_EXEC_ID=$(echo "$A_BG_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('exec_id',''))" 2>/dev/null || echo "")
fi

if [[ -z "$A_EXEC_ID" ]]; then
    fail "Agent A: could not start background exec"
else
    log_step "Agent A: background exec started (exec_id=$A_EXEC_ID), polling..."
    # Poll up to 90s for the background exec (sleep 3 + echo) to complete —
    # nested-KVM VM contention can stretch the first status transitions.
    A_BG_DONE=false
    for i in $(seq 1 18); do
        sleep 5
        A_STATUS_RESP=$(exec_status "$AGENT_A_KEY" "$SANDFS_A_ID" "$A_EXEC_ID")
        A_BG_STATUS=$(echo "$A_STATUS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
        if [[ "$A_BG_STATUS" == "done" ]]; then
            A_BG_DONE=true
            # Note: gateway's ExecStatusResponse uses `json:"exit_code,omitempty"`
            # which omits exit_code when it's 0 (Go zero-value). So missing
            # exit_code in JSON means success (0), not failure (-1).
            A_BG_EXIT=$(echo "$A_STATUS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('exit_code',0))" 2>/dev/null || echo "0")
            A_BG_STDOUT=$(echo "$A_STATUS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('stdout',''))" 2>/dev/null || echo "")
            if [[ "$A_BG_EXIT" == "0" ]] && echo "$A_BG_STDOUT" | grep -q "bg_exec_test_complete"; then
                pass "Agent A: background exec completed successfully (exit_code=0, output=bg_exec_test_complete)"
            elif [[ "$A_BG_EXIT" == "0" ]]; then
                pass "Agent A: background exec completed (exit_code=0)"
            else
                fail "Agent A: background exec finished with exit_code=$A_BG_EXIT (stdout: $(echo "$A_BG_STDOUT" | head -c 200))"
            fi
            break
        elif [[ "$A_BG_STATUS" == "killed" || "$A_BG_STATUS" == "not_found" || "$A_BG_STATUS" == "expired" ]]; then
            fail "Agent A: background exec ended with status=$A_BG_STATUS (expected done)"
            break
        fi
    done
    if [[ "$A_BG_DONE" != "true" ]]; then
        fail "Agent A: background exec not done after 90s (sleep 3 + echo — budget exhausted)"
    fi
fi

# Step 3: Verify Agent A can still execute commands after background exec
# (confirms the VM is in a good state and the lease was properly managed)
log_step "Agent A: verifying exec works after background exec..."
A_POST_BG=$(exec_code "$AGENT_A_KEY" "$SANDFS_A_ID" 10 "echo post_bg_exec_ok")
A_POST_BG_OUT=$(echo "$A_POST_BG" | exec_stdout)
A_POST_BG_ERR=$(echo "$A_POST_BG" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "")
if echo "$A_POST_BG_OUT" | grep -q "post_bg_exec_ok"; then
    pass "Agent A: exec works after background exec (VM state healthy)"
elif [[ -n "$A_POST_BG_ERR" ]]; then
    fail "Agent A: post-bg exec failed ($A_POST_BG_ERR)"
else
    fail "Agent A: post-bg exec output unexpected: '$A_POST_BG_OUT'"
fi

# Step 4: seccomp still blocks mount/unshare even in install mode
log_step "Agent A: verifying seccomp deny-list still blocks mount/unshare..."
for _attempt in 1 2 3; do
    A_MOUNT_RESP=$(exec_code "$AGENT_A_KEY" "$SANDFS_A_ID" 15 "mount /dev/sda1 /mnt 2>&1; echo EXIT_CODE_\$")
    A_MOUNT=$(echo "$A_MOUNT_RESP" | exec_stdout)
    A_MOUNT_ERR=$(echo "$A_MOUNT_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "")
    if [[ -n "$A_MOUNT_ERR" ]]; then
        if [[ $_attempt -lt 3 ]]; then
            log_warn "Agent A: mount check attempt $_attempt failed (VM contention), retrying in 3s..."
            sleep 3; continue
        fi
        fail "Agent A: mount check failed after 3 attempts (exec path broken, not 'contention'): $A_MOUNT_ERR"
    elif echo "$A_MOUNT" | grep -qiE "Operation not permitted|permission denied|EPERM|MOUNT_EPERM"; then
        pass "Agent A: mount blocked by seccomp (EPERM)"
    elif [[ -z "$A_MOUNT" ]]; then
        if [[ $_attempt -lt 3 ]]; then
            log_warn "Agent A: mount check attempt $_attempt returned empty, retrying in 3s..."
            sleep 3; continue
        fi
        fail "Agent A: mount check returned empty after 3 attempts — seccomp property UNVERIFIED"
    else
        fail "Agent A: mount was NOT blocked - seccomp deny list may be missing"
    fi
    break
done

for _attempt in 1 2 3; do
    A_UNSHARE_RESP=$(exec_code "$AGENT_A_KEY" "$SANDFS_A_ID" 15 "unshare -m -- /bin/true 2>&1; echo EXIT_CODE_\$")
    A_UNSHARE=$(echo "$A_UNSHARE_RESP" | exec_stdout)
    A_UNSHARE_ERR=$(echo "$A_UNSHARE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "")
    if [[ -n "$A_UNSHARE_ERR" ]]; then
        if [[ $_attempt -lt 3 ]]; then
            log_warn "Agent A: unshare check attempt $_attempt failed (VM contention), retrying in 3s..."
            sleep 3; continue
        fi
        fail "Agent A: unshare check failed after 3 attempts (exec path broken, not 'contention'): $A_UNSHARE_ERR"
    elif echo "$A_UNSHARE" | grep -qiE "Operation not permitted|permission denied|EPERM|UNSHARE_EPERM"; then
        pass "Agent A: unshare blocked by seccomp (EPERM)"
    elif [[ -z "$A_UNSHARE" ]]; then
        if [[ $_attempt -lt 3 ]]; then
            log_warn "Agent A: unshare check attempt $_attempt returned empty, retrying in 3s..."
            sleep 3; continue
        fi
        fail "Agent A: unshare check returned empty after 3 attempts — seccomp property UNVERIFIED"
    else
        fail "Agent A: unshare was NOT blocked - seccomp deny list may be missing"
    fi
    break
done

# ── Agent B: flat-mode capability policy ────────────────────────
# Per docs/reference/human-api.md (POST /human/sandfs), the package-installation policy is DERIVED from
# the sandfs mode (flat → install profile retains ambient caps; overlay → all
# caps dropped). The create-time install_packages field is no longer honored.
# Both agents here are flat, so Agent B runs the install profile too.

# Step 1: Verify Agent B reports a valid CapEff line (non-empty — guards
# against false-passing on an error response) and has the flat-mode caps.
log_step "Agent B (flat mode): checking capability profile..."
B_CAPS=""
for _attempt in 1 2 3; do
    B_CAPS=$(exec_code "$AGENT_B_KEY" "$SANDFS_B_ID" 15 "cat /proc/self/status | grep CapEff" | exec_stdout)
    [[ -n "$B_CAPS" ]] && break
    log_warn "Agent B capability probe attempt $_attempt empty — retrying in 3s"
    sleep 3
done
if [[ -z "$B_CAPS" ]]; then
    fail "Agent B: no CapEff output — exec failed unexpectedly"
elif echo "$B_CAPS" | grep -qiE "CapEff[[:space:]]*:[[:space:]]*0+$"; then
    fail "Agent B: zero capabilities in flat mode (expected install-profile caps)"
else
    pass "Agent B: flat-mode install profile active ($B_CAPS)"
fi

# Step 2: Verify seccomp deny-list still blocks dangerous operations even with
# the permissive flat profile (chown is allowed by design in flat mode).
log_step "Agent B: verifying seccomp deny-list blocks dangerous syscalls..."
B_MOUNT_RAW=$(exec_code "$AGENT_B_KEY" "$SANDFS_B_ID" 30 "mount -t tmpfs none /mnt 2>&1; echo EXIT_CODE_\$?")
B_MOUNT=$(echo "$B_MOUNT_RAW" | exec_stdout)
if echo "$B_MOUNT" | grep -qiE "Operation not permitted|permission denied|EPERM"; then
    pass "Agent B: mount blocked by seccomp (EPERM)"
else
    fail "Agent B: mount NOT blocked — seccomp deny list missing"
fi
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

# ══════════════════════════════════════════════════════════════════
log_section "Results Summary"
# ══════════════════════════════════════════════════════════════════

echo ""
echo "  ┌──────────────────────────────────────────────────────┐"
echo "  │      Sandswap Eino Dual-Agent E2E Test Results       │"
echo "  ├──────────────────────────────────────────────────────┤"
printf "  │ Mode:        REAL KVM (%-14s)              │\n" "$KVM_MODULE"
printf "  │ Gateway:     %-39s │\n" "$GATEWAY_URL"
printf "  │ Volumes:     %-39s │\n" "$VOL_ROOT"
printf "  │ Pool size:   %-39d │\n" "$POOL_SIZE"
printf "  │ Sandlot PID: %-5d  Gateway PID: %-5d           │\n" "${SANDLOT_PID:-0}" "${GATEWAY_PID:-0}"
echo "  ├──────────────────────────────────────────────────────┤"
printf "  │ Agent A:     %-39s │\n" "$AGENT_A_ID"
printf "  │ SandFS A:    %-39s │\n" "$SANDFS_A_ID"
printf "  │ Agent B:     %-39s │\n" "$AGENT_B_ID"
printf "  │ SandFS B:    %-39s │\n" "$SANDFS_B_ID"
printf "  │ LLM:         %-39s │\n" "$LLM_BACKEND"
printf "  │ Rootfs:      Ubuntu (%-32s) │\n" "$(du -sh "$ROOTFS_UBUNTU" 2>/dev/null | cut -f1)"
echo "  ├──────────────────────────────────────────────────────┤"
printf "  │ Tests: %2d passed  %2d failed                             │\n" "$PASS_COUNT" "$FAIL_COUNT"
echo "  └──────────────────────────────────────────────────────┘"
echo ""
echo "  Logs:  $LOG_DIR/"
echo "  Deploy:$DEPLOY_DIR/"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "$FAIL_COUNT test(s) failed"
    exit 1
elif [[ "${EINO_EXIT:-0}" -ne 0 ]]; then
    # The eino binary's own exit code is a gate too: a crash/timeout that
    # happened to leave matching log lines behind must not read as green.
    log_error "eino test binary exited non-zero (rc=$EINO_EXIT)"
    exit 1
else
    log_pass "All $PASS_COUNT tests passed"
fi
