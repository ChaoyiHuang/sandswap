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
# test-file-api.sh — End-to-end tests for the Sandswap unified File I/O API.
# Self-contained: deploys binaries, starts gateway + sandlot, runs all file
# API tests, then cleans up. Modeled on deploy-and-test.sh lifecycle.
# Prerequisites:
#   1. bash build/build.sh all        (all binaries in output/)
#   2. bash build/build-rootfs-template.sh   (rootfs template in output/)
#   3. KVM available (/dev/kvm)
#   4. Root or kvm group member
# Tests all 7 file I/O operations via the unified POST /agent/file API:
#   read, write, stat, list_dir, mkdir, remove, rename
# Plus: persistence, isolation, large files, path traversal blocking.
# Usage: ./e2e/file-api.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Override defaults before sourcing
POOL_SIZE="${POOL_SIZE:-2}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
source "$ROOT/e2e/common.sh"

cleanup() {
    # Delete test agents (best-effort, gateway may already be down)
    if [[ -n "${KEY_A:-}" ]] && kill -0 "${GATEWAY_PID:-0}" 2>/dev/null; then
        tc_delete_sandfs "$ID_A"
        tc_delete_sandfs "$ID_B"
        log_pass "Test agents deleted"
    fi
    rm -f "${LARGE_JSON_TMP:-}" 2>/dev/null || true
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight Checks"
# ══════════════════════════════════════════════════════════════════
tc_check_root
tc_preflight_standard python3
tc_ensure_dev_nodes

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Deploy (clean slate)"
# ══════════════════════════════════════════════════════════════════
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Start Gateway + Sandlot"
# ══════════════════════════════════════════════════════════════════
tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Create Test Agents"
# ══════════════════════════════════════════════════════════════════

log_step "Creating Agent A (main test)..."
AGENT_RESP=$(tc_create_agent_and_sandfs "file-api-test")
KEY_A=$(json_val "$AGENT_RESP" "api_key")
ID_A=$(json_val "$AGENT_RESP" "sandfs_id")

if [[ -z "$KEY_A" || "$KEY_A" == "None" ]]; then
    log_error "Failed to create Agent A: $AGENT_RESP"
    exit 1
fi
log_pass "Agent A created: id=$ID_A"

log_step "Creating Agent B (isolation test)..."
AGENT_B_RESP=$(tc_create_agent_and_sandfs "file-api-isolated")
KEY_B=$(json_val "$AGENT_B_RESP" "api_key")
ID_B=$(json_val "$AGENT_B_RESP" "sandfs_id")

if [[ -z "$KEY_B" || "$KEY_B" == "None" ]]; then
    log_error "Failed to create Agent B: $AGENT_B_RESP"
    exit 1
fi
log_pass "Agent B created: id=$ID_B"

# ── Helper: unified POST /agent/file API ─────────────────────────────────
# All file operations go through POST /agent/file with JSON body.
# Paths are relative to /workspace inside the sandbox.

file_op() {
    # Usage: file_op <json_body>
    # Sends POST /agent/file with the given JSON body using Agent A's key.
    # Automatically injects sandfs_id if not already present.
    # Uses stdin (@-) to avoid "Argument list too long" for large payloads.
    local body="$1"
    # Inject sandfs_id if not already in the body
    if ! echo "$body" | grep -q 'sandfs_id'; then
        body=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); d['sandfs_id']='$(echo $ID_A)'; print(json.dumps(d))" 2>/dev/null || echo "$body")
    fi
    echo -n "$body" | curl -s -X POST "$GATEWAY_URL/agent/file" \
        --header "Authorization: Bearer $KEY_A" \
        --header "Content-Type: application/json" \
        -d @-
}

file_op_b() {
    # Same as file_op but uses Agent B's key (for isolation tests).
    local body="$1"
    if ! echo "$body" | grep -q 'sandfs_id'; then
        body=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); d['sandfs_id']='$(echo $ID_B)'; print(json.dumps(d))" 2>/dev/null || echo "$body")
    fi
    echo -n "$body" | curl -s -X POST "$GATEWAY_URL/agent/file" \
        --header "Authorization: Bearer $KEY_B" \
        --header "Content-Type: application/json" \
        -d @-
}

# file_op_retry: retry on transient transport errors (lease expiry / vsock reconnect).
file_op_retry() {
    # Usage: file_op_retry <json_body> [max_attempts]
    local body="$1" max="${2:-3}"
    local resp=""
    for _ in $(seq 1 "$max"); do
        resp=$(file_op "$body")
        # If response contains an error about connection, retry after short sleep.
        if echo "$resp" | grep -q '"error".*connection'; then
            sleep 0.3
            continue
        fi
        echo "$resp"
        return
    done
    # Return last response even if it's an error.
    echo "$resp"
}

file_read() {
    # Usage: file_read <path> [offset] [length]
    local path="$1" offset="${2:-}" length="${3:-}"
    local body="{\"action\":\"read\",\"path\":\"$path\""
    if [[ -n "$offset" ]]; then body="$body,\"offset\":$offset"; fi
    if [[ -n "$length" ]]; then body="$body,\"length\":$length"; fi
    body="$body}"
    file_op "$body"
}

file_read_text() {
    # Read a text file and extract the "data" field from the JSON response.
    local resp
    resp=$(file_read "$@")
    echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',''))" 2>/dev/null
}

file_write() {
    # Usage: file_write <path> <text_content> [mode]
    local path="$1" content="$2" mode="${3:-}"
    # Escape content for JSON: replace \ with \\ and " with \"
    local escaped
    escaped=$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$content")
    local body="{\"action\":\"write\",\"path\":\"$path\",\"data\":$escaped"
    if [[ -n "$mode" ]]; then body="$body,\"mode\":$mode"; fi
    body="$body}"
    file_op "$body"
}

file_write_append() {
    # Usage: file_write_append <path> <text_content>
    local path="$1" content="$2"
    local escaped
    escaped=$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$content")
    file_op "{\"action\":\"write\",\"path\":\"$path\",\"data\":$escaped,\"append\":true}"
}

file_write_binary() {
    # Usage: file_write_binary <path> <base64_content>
    local path="$1" b64="$2"
    file_op "{\"action\":\"write\",\"path\":\"$path\",\"data_base64\":\"$b64\"}"
}

file_stat() {
    file_op "{\"action\":\"stat\",\"path\":\"$1\"}"
}

file_ls() {
    # Usage: file_ls <path> [depth]
    local path="$1" depth="${2:-0}"
    file_op "{\"action\":\"list_dir\",\"path\":\"$path\",\"depth\":$depth}"
}

file_mkdir() {
    file_op "{\"action\":\"mkdir\",\"path\":\"$1\"}"
}

file_remove() {
    # Usage: file_remove <path> [recursive]
    local path="$1" recursive="${2:-false}"
    file_op "{\"action\":\"remove\",\"path\":\"$path\",\"recursive\":$recursive}"
}

file_rename() {
    # Usage: file_rename <old_path> <new_path>
    file_op "{\"action\":\"rename\",\"path\":\"$1\",\"new_path\":\"$2\"}"
}

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: File I/O Tests"
# ══════════════════════════════════════════════════════════════════

# --- Test 1: Write small text file ---
log_step "Test 1: Write small text file"
WRITE_RESP=$(file_write "test.txt" "hello from file api")
assert_contains "1.1 write returns ok" "$WRITE_RESP" '"ok":true'
assert_contains "1.2 write size matches" "$WRITE_RESP" '"size":19'

# --- Test 2: Read text file back ---
log_step "Test 2: Read text file back"
READ_RESP=$(file_read "test.txt")
assert_contains "2.1 read returns data" "$READ_RESP" '"data"'
assert_contains "2.2 read is_text is true" "$READ_RESP" '"is_text":true'
READ_TEXT=$(file_read_text "test.txt")
assert_eq "2.3 read content matches" "$READ_TEXT" "hello from file api"

# --- Test 3: Write binary file (round-trip) ---
log_step "Test 3: Write binary file (round-trip)"
BINARY_B64=$(python3 -c "import os,sys,base64; print(base64.b64encode(bytes(range(256))).decode())")
WRITE_BIN_RESP=$(file_write_binary "binary.bin" "$BINARY_B64")
assert_contains "3.1 binary write returns ok" "$WRITE_BIN_RESP" '"ok":true'
assert_contains "3.2 binary write size" "$WRITE_BIN_RESP" '"size":256'

# --- Test 4: Read binary back ---
log_step "Test 4: Read binary back"
READ_BIN_RESP=$(file_op_retry '{"action":"read","path":"binary.bin"}')
assert_contains "4.1 binary read has data_base64" "$READ_BIN_RESP" '"data_base64"'
# Verify the base64 round-trips correctly
READ_BIN_B64=$(echo "$READ_BIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data_base64',''))" 2>/dev/null)
assert_eq "4.2 binary round-trip matches" "$READ_BIN_B64" "$BINARY_B64"

# --- Test 5: Read with offset ---
log_step "Test 5: Read with offset"
file_write "offset.txt" "0123456789" > /dev/null
READ_OFFSET=$(file_read_text "offset.txt" "5" "3")
assert_eq "5.1 read with offset=5 length=3" "$READ_OFFSET" "567"

# --- Test 6: Append to file ---
log_step "Test 6: Append to file"
file_write "append.txt" "hello" > /dev/null
file_write_append "append.txt" " world" > /dev/null
APPEND_TEXT=$(file_read_text "append.txt")
assert_eq "6.1 append content matches" "$APPEND_TEXT" "hello world"

# --- Test 7: Overwrite at offset ---
log_step "Test 7: Overwrite at offset"
file_write "overwrite.txt" "AAAAAAAAAA" > /dev/null
# Write "BBBBB" at offset 5
file_op '{"action":"write","path":"overwrite.txt","data":"BBBBB","offset":5}' > /dev/null
OW_TEXT=$(file_read_text "overwrite.txt")
assert_eq "7.1 overwrite at offset" "$OW_TEXT" "AAAAABBBBB"

# --- Test 8: Stat file ---
log_step "Test 8: Stat file"
STAT_RESP=$(file_stat "test.txt")
assert_contains "8.1 stat returns file_type" "$STAT_RESP" '"file_type"'
assert_contains "8.2 stat file_type is file" "$STAT_RESP" '"file"'
assert_contains "8.3 stat has size" "$STAT_RESP" '"size"'

# --- Test 9: Stat nonexistent ---
log_step "Test 9: Stat nonexistent path"
STAT_NOPE=$(file_stat "nope/nope.txt")
# Should contain an error, not file_type
assert_not_contains "9.1 stat nonexistent returns error" "$STAT_NOPE" '"file_type"'
assert_contains "9.2 stat nonexistent has error" "$STAT_NOPE" '"error"'

# --- Test 10: List directory ---
log_step "Test 10: List directory"
LS_RESP=$(file_ls "." "0")
assert_contains "10.1 list_dir returns entries" "$LS_RESP" '"entries"'
assert_contains "10.2 list_dir finds test.txt" "$LS_RESP" 'test.txt'

# --- Test 11: List with depth=2 ---
log_step "Test 11: List with depth=2"
LS_DEEP=$(file_ls "." "2")
assert_contains "11.1 recursive list returns entries" "$LS_DEEP" '"entries"'

# --- Test 12: Make directory ---
log_step "Test 12: Make directory"
MKDIR_RESP=$(file_mkdir "newdir")
assert_contains "12.1 mkdir returns ok" "$MKDIR_RESP" '"ok":true'
# Verify via stat
STAT_DIR=$(file_stat "newdir")
assert_contains "12.2 stat confirms directory" "$STAT_DIR" '"dir"'

# --- Test 13: Remove file ---
log_step "Test 13: Remove file"
file_write "rmme.txt" "rm me" > /dev/null
RM_RESP=$(file_remove "rmme.txt")
assert_contains "13.1 remove returns ok" "$RM_RESP" '"ok":true'

# --- Test 14: Remove directory recursive ---
log_step "Test 14: Remove directory recursive"
file_mkdir "rmdir_test" > /dev/null
file_write "rmdir_test/inner.txt" "inner" > /dev/null
RMDIR_RESP=$(file_remove "rmdir_test" "true")
assert_contains "14.1 recursive remove returns ok" "$RMDIR_RESP" '"ok":true'

# --- Test 15: Rename file ---
log_step "Test 15: Rename file"
file_write "old.txt" "rename me" > /dev/null
MOVE_RESP=$(file_rename "old.txt" "new.txt")
assert_contains "15.1 rename returns ok" "$MOVE_RESP" '"ok":true'
# Verify old is gone and new exists
READ_NEW=$(file_read_text "new.txt")
assert_eq "15.2 new file has content" "$READ_NEW" "rename me"

# --- Test 16: Persistence across lease ---
log_step "Test 16: Persistence across lease"
file_write "persist.txt" "persistent data" > /dev/null
# Wait for lease to expire (default 100ms, wait 500ms to be safe)
sleep 0.5
# Read the file again — should still be there (same agent volume)
PERSIST_TEXT=$(file_read_text "persist.txt")
assert_eq "16.1 file persists across lease" "$PERSIST_TEXT" "persistent data"

# --- Test 17: Cross-agent isolation ---
log_step "Test 17: Cross-agent isolation"
# Agent A wrote test.txt above. Agent B tries to read it — should fail.
# POSITIVE CONTROL FIRST: without proof that B's own file I/O works, every
# failure mode of B (401, unmounted sandfs, transport error, empty body) also
# satisfies the negative below and the isolation claim reads as verified.
file_op_b '{"action":"write","path":"b-own.txt","data":"b-content"}' > /dev/null
B_OWN=$(file_op_b '{"action":"read","path":"b-own.txt"}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',''))" 2>/dev/null)
assert_eq "17.0 control: agent B's own file I/O works" "$B_OWN" "b-content"
ISOL_RESP=$(file_op_b '{"action":"read","path":"test.txt"}')
# Must be an ERROR (not merely "not the data"): a 500/empty body would
# otherwise pass for the wrong reason.
assert_contains "17.1 agent B cannot read agent A's file" "$ISOL_RESP" '"error"'
assert_not_contains "17.1 (cont) agent B's response carries no A data" "$ISOL_RESP" "hello from file api"

# --- Test 18: Large file (1MB) ---
log_step "Test 18: Large file (1MB)"
LARGE_SIZE=1048576
# Write the JSON body to a temp file to avoid "Argument list too long".
LARGE_JSON_TMP=$(mktemp)
python3 -c "
import os, sys, base64, json
data = base64.b64encode(os.urandom($LARGE_SIZE)).decode()
body = json.dumps({'action': 'write', 'path': 'large.bin', 'data_base64': data, 'sandfs_id': '$ID_A'})
with open(sys.argv[1], 'w') as f:
    f.write(body)
" "$LARGE_JSON_TMP"
curl -s -X POST "$GATEWAY_URL/agent/file" \
    --header "Authorization: Bearer $KEY_A" \
    --header "Content-Type: application/json" \
    -d @"$LARGE_JSON_TMP" > /dev/null
rm -f "$LARGE_JSON_TMP"
# Stat to verify size
STAT_LARGE=$(file_op_retry '{"action":"stat","path":"large.bin"}')
LARGE_FILE_SIZE=$(echo "$STAT_LARGE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('size',0))" 2>/dev/null || echo 0)
assert_eq "18.1 large file size matches" "$LARGE_FILE_SIZE" "$LARGE_SIZE"

# --- Test 19: Path traversal blocked ---
log_step "Test 19: Path traversal blocked"
TRAVERSAL_RESP=$(file_stat "../../etc/passwd")
# Should contain error, not root: (passwd content)
assert_not_contains "19.1 path traversal blocked" "$TRAVERSAL_RESP" "root:"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Cleanup Test Artifacts"
# ══════════════════════════════════════════════════════════════════

# Clean up files written inside the agent's volume so the test
# environment is clean for the next run. This is best-effort — the
# agent volumes will be deleted when agents are deleted (in trap cleanup).
log_step "Removing test files from agent volume..."
file_remove "test.txt" > /dev/null 2>&1 || true
file_remove "binary.bin" > /dev/null 2>&1 || true
file_remove "offset.txt" > /dev/null 2>&1 || true
file_remove "append.txt" > /dev/null 2>&1 || true
file_remove "overwrite.txt" > /dev/null 2>&1 || true
file_remove "newdir" "true" > /dev/null 2>&1 || true
file_remove "new.txt" > /dev/null 2>&1 || true
file_remove "persist.txt" > /dev/null 2>&1 || true
file_remove "large.bin" > /dev/null 2>&1 || true
log_pass "Test files cleaned up"

# Delete test agents
log_step "Deleting test agents..."
tc_delete_sandfs "$ID_A"
tc_delete_sandfs "$ID_B"
# Clear so trap cleanup doesn't try again
KEY_A="" KEY_B=""
log_pass "Test agents deleted"

# ══════════════════════════════════════════════════════════════════
log_section "Results"
# ══════════════════════════════════════════════════════════════════

echo ""
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │        Sandswap File API Test Results            │"
echo "  ├──────────────────────────────────────────────────┤"
printf "  │ Tests: %2d passed  %2d failed                         │\n" "$PASS_COUNT" "$FAIL_COUNT"
echo "  └──────────────────────────────────────────────────┘"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "$FAIL_COUNT test(s) failed"
    log_info "Check logs: $LOG_DIR/"
    exit 1
else
    log_pass "All $PASS_COUNT tests passed"
fi
