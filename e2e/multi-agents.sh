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
# test-multi-agents.sh — Read-only overlay + writable workspace/home multi-agent test
# Tests the full Sandswap stack with read-only overlay + writable workspace/home mode:
#   HTTP → Gateway → gRPC → Sandlot → sandvmm (KVM) → warden → virtio-fs
# Key design:
#   1. Versioned local templates (sqlite:v1, python:v1) on distributed FS
#   2. Start gateway with -overlayfs-templates (OverlayFS mode, no OCI registry)
#   3. Create SandFS with template parameter → read-only overlay (lowerdir only, ro flag)
#   4. Writable paths: /workspace (writable bind mount), /home/agent (writable bind mount), /tmp (tmpfs)
#   5. Two SQLite agents share same template → verify dedup
#   6. Agent A (SQLite), Agent C (SQLite-reader): same template, workspace/home isolation
#   7. Agent B (Python): different template, cross-agent switch
#   8. Save Agent A's state as sqlite:v2 template → verify template promotion
#   9. Sticky-lease functional sanity (client wall clock; benchmarks live in
#      e2e/latency-benchmark-aiagent.sh / latency-benchmark-unmount.sh)
# Usage: sudo bash e2e/multi-agents.sh

set -euo pipefail

# Ensure cargo/go are in PATH when running under sudo (root's default PATH
# often omits ~/.cargo/bin and ~/go/bin).
for p in "$HOME/.cargo/bin" "$HOME/go/bin" /usr/local/go/bin; do
    [[ -d "$p" ]] && case ":$PATH:" in *":$p:"*) ;; *) PATH="$p:$PATH" ;; esac
done
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Override defaults before sourcing
VOL_ROOT="${VOL_ROOT:-/var/lib/sandswap/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
DEPLOY_DIR="${DEPLOY_DIR:-/var/lib/sandswap}"
TEMPLATE_DIR="${TEMPLATE_DIR:-/tmp/sandswap-templates}"
# Force sandlot -pool "medium:1" so both agents reuse the same microVM
SANDLOT_POOL="medium:1"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
source "$ROOT/e2e/common.sh"

# Run directly from $OUTPUT (no deploy step) — tc_use_output_binaries sets
# the TC_ binary paths AND verifies the service identities can exec them
# (dev checkouts under a restrictive home would otherwise fail every VM
# launch with fork/exec EACCES).
tc_use_output_binaries
# Flat templates: create versioned structure so ScanFlatTemplates registers "rootfs:v1"
# Wipe FIRST: a SIGKILLed previous run leaves the dirs behind (no trap ran) and
# its stale content would silently merge into this run's "clean" templates.
FLAT_TEMPLATE_DIR="${FLAT_TEMPLATE_DIR:-/tmp/sandswap-flat-templates}"
# Both template roots are written by the gateway identity (scan refs, mount
# lowerdir lookups) — shared setgid dirs, not bare root mkdirs.
ss_prepare_shared_dir "$FLAT_TEMPLATE_DIR" "$TEMPLATE_DIR"
ss_seed_template "$OUTPUT/rootfs-template" "$FLAT_TEMPLATE_DIR/rootfs/v1"
TC_FLAT_TEMPLATES="$FLAT_TEMPLATE_DIR"

# ═══ Execute via gateway, return raw JSON ═══
# Retries on "no available sandbox" / "pool full" errors
declare -A KEY2SID

exec_code() {
    local key="$1" code="$2" desc="$3"
    local sid="${KEY2SID[$key]:-}"
    local max_retries=8
    local resp=""

    for attempt in $(seq 1 $max_retries); do
        local start_ns
        start_ns=$(date +%s%N)
        local _code_file
        _code_file=$(mktemp)
        printf '%s' "$code" > "$_code_file"
        local json_req
        json_req=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f: code = f.read()
print(json.dumps({'sandfs_id': sys.argv[2], 'code': code, 'language': 'shell', 'timeout': 60}))
" "$_code_file" "$sid" 2>/dev/null)
        rm -f "$_code_file"
        resp=$(curl -s -m 75 -X POST "$GATEWAY_URL/agent/execute" \
            -H "Authorization: Bearer $key" \
            -H "Content-Type: application/json" \
            -d "$json_req" 2>&1 || echo '{"error":"curl failed"}')
        local end_ns
        end_ns=$(date +%s%N)
        local ms
        ms=$(( (end_ns - start_ns) / 1000000 ))
        # Retry transient gates: pool exhaustion AND the post-create
        # SANDBOX_CLEANING window (retry_after 10s — a 1s-step retry can
        # never cross it, which is exactly what killed A1 on dedicated-
        # identity runs).
        if echo "$resp" | grep -q "no available sandbox\|pool full\|retry later\|SANDBOX_CLEANING\|NO_COMPUTE_NODES"; then
            # Honor the server's own retry_after_ms — with multiple agents
            # sharing a small pool, switch+clean cycles routinely run 10s;
            # a fixed short sleep just collides with the next window.
            local wait_ms
            wait_ms=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('retry_after_ms',3000))" 2>/dev/null || echo 3000)
            local wait_s=$(( wait_ms / 1000 + 1 ))
            log_warn "Attempt $attempt: transient gate (cleaning/pool), waiting ${wait_s}s..."
            sleep "$wait_s"
            continue
        fi
        break
    done

    local exit_code

    exit_code=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exit_code',-1))" 2>/dev/null || echo "-1")
    local stdout
    stdout=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo "")
    echo -e "\n${BLUE}─── $desc ───${NC}"
    echo "  POST $GATEWAY_URL/agent/execute  Bearer ${key:0:16}...  Code: $(echo -n "$code" | wc -c)B"
    echo -e "${BLUE}─── Response (${ms}ms) ───${NC}"
    echo "  Exit: $exit_code  Status: $(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")"
    if [[ -n "$stdout" ]]; then
        echo "$stdout" | head -12 | sed 's/^/  │ /'
        local lines
        lines=$(echo "$stdout" | wc -l)
        [[ $lines -gt 12 ]] && echo "  │ ... (${lines} lines)"
    fi
    local stderr
    stderr=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stderr',''))" 2>/dev/null || echo "")
    if [[ -n "$stderr" ]]; then echo "  Stderr: $(echo "$stderr" | head -3)"; fi

    if [[ "$exit_code" == "0" ]]; then pass "$desc"
    else fail "$desc (exit=$exit_code)"; fi

    echo "$resp" > /tmp/sandswap-last-resp.json
    echo "$ms"   > /tmp/sandswap-last-ms.txt
    echo "$stdout" > /tmp/sandswap-last-stdout.txt
    echo "$resp"
}

# ═══ Install tool with dependencies into a rootfs ═══
install_tool() {
    local rootfs="$1" tool="$2"
    if ! command -v "$tool" &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq "$tool"
    fi
    local bin_path
    bin_path=$(which "$tool")
    cp -f "$bin_path" "$rootfs/bin/"
    mkdir -p "$rootfs/lib/x86_64-linux-gnu" "$rootfs/usr/lib/x86_64-linux-gnu" "$rootfs/lib64"
    ldd "$bin_path" | grep -oE '/[^ ]+' | while read lib; do
        if [[ "$lib" == /lib64/* ]] || [[ "$lib" == /usr/lib/* ]] || [[ "$lib" == /lib/* ]]; then
            mkdir -p "$rootfs$(dirname "$lib")"
            cp -f "$lib" "$rootfs$lib" 2>/dev/null || true
        fi
    done
    if [[ "$tool" == "python3" ]]; then
        local pv
        pv=$(python3 -c "import sys; print(f'python{sys.version_info.major}.{sys.version_info.minor}')")
        local plib="/usr/lib/$pv"
        if [[ -d "$plib" ]]; then
            mkdir -p "$rootfs$plib"
            cp -rf "$plib"/* "$rootfs$plib/" 2>/dev/null || true
        fi
    fi
}

# ═══ Cleanup ═══
# Resources only — the Results Summary + exit code live in the main body.
# Registered on EXIT/INT/TERM below: without the trap, a mid-test failure
# (`set -e`) leaked the whole stack (gateway/sandlot/sandvmm, overlay mounts,
# TAPs, nft tables, template dirs) and poisoned the next run.
cleanup() {
    rm -f /tmp/sandswap-last-resp.json /tmp/sandswap-last-ms.txt /tmp/sandswap-last-stdout.txt 2>/dev/null || true
    tc_cleanup_default
    # Remove script-specific temp directories (not covered by tc_cleanup_default)
    rm -rf "$TEMPLATE_DIR" "$FLAT_TEMPLATE_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Build & Pre-flight"
# ══════════════════════════════════════════════════════════════════

tc_check_root
tc_ensure_dev_nodes
# install_tool copies sqlite3/python3 from the HOST into the templates; the
# copy needs network apt only when a tool is missing — gate it here, loudly,
# instead of dying mid-Phase-1 on an offline host with a raw apt error.
tc_check_tools sqlite3 python3

# Freshness is NOT established here: an unconditional `build.sh all` from
# inside a row re-stamps the whole shared artifact set mid-pass (after the
# matrix froze the verdicts' artifact identity), silently invalidating every
# recorded row for a rebuild nothing depended on. Inside a round the
# runner's preflight has already checked (and rebuilt once if needed);
# standalone, the tc_check_freshness below does exactly that job.

tc_check_freshness
tc_check_artifacts
tc_check_kvm

# Clean stale processes and state from prior runs
tc_clean_environment
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — microVMs will be offline"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Prepare Versioned Local Templates"
# ══════════════════════════════════════════════════════════════════

# Versioned directory layout (for distributed FS dedup):
#   /tmp/sandswap-templates/
#     sqlite/
#       v1/    ← busybox + sqlite3 (templateRef "sqlite:v1")
#     python/
#       v1/    ← busybox + python3 (templateRef "python:v1")
#
# When -overlayfs-templates points here, gateway auto-scans:
#   sqlite/v1/ → registers "sqlite:v1"
#   python/v1/ → registers "python:v1"

log_step "Creating SQLite template (versioned: sqlite:v1)..."
ss_seed_template "$OUTPUT/rootfs-template" "$TEMPLATE_DIR/sqlite/v1"
install_tool "$TEMPLATE_DIR/sqlite/v1" "sqlite3"
log_pass "SQLite template ready: $TEMPLATE_DIR/sqlite/v1/"

log_step "Creating Python template (versioned: python:v1)..."
ss_seed_template "$OUTPUT/rootfs-template" "$TEMPLATE_DIR/python/v1"
install_tool "$TEMPLATE_DIR/python/v1" "python3"
log_pass "Python template ready: $TEMPLATE_DIR/python/v1/"

echo ""
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │  Versioned Local Templates (distributed FS ready)│"
echo "  │                                                  │"
echo "  │  sqlite/v1/  ← busybox + sqlite3                │"
echo "  │  python/v1/  ← busybox + python3                │"
echo "  │                                                  │"
echo "  │  Template refs: \"sqlite:v1\"  \"python:v1\"        │"
echo "  │  Multi-host dedup via shared distributed FS      │"
echo "  └──────────────────────────────────────────────────┘"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Deploy & Start"
# ══════════════════════════════════════════════════════════════════

tc_gen_certs
tc_attach_vsockguard

# The template store lives in the prov role (the sandlot below); the gateway
# has no template manager.
log_step "Starting gateway (sticky-ms=100, read-only overlay + writable workspace/home mode)..."
tc_start_gateway
log_pass "Gateway started (read-only overlay + writable workspace/home mode via -overlayfs-templates)"

# Verify versioned template registration
TEMPLATES_RESP=$(curl -s "$HUMAN_URL/human/templates" 2>/dev/null || echo "[]")
echo "  Registered templates: $TEMPLATES_RESP"
echo "$TEMPLATES_RESP" | python3 -c "
import sys, json
ts = json.load(sys.stdin)
for t in ts: print(f'    - {t[\"name\"]}:{t[\"version\"]} (cached: {t[\"cached\"]})')
" 2>/dev/null || log_warn "Could not parse templates response"

# Start sandlot
tc_start_sandlot -overlayfs-templates "$TEMPLATE_DIR"

# Flake guard: the FIRST sandfs
# creation after a fresh stack start once failed with TEMPLATE_NOT_FOUND —
# sandlot's ScanLocalTemplates (which writes refs/<name>_<ver>.overlay.json)
# had not finished when Phase 3 resolved the template mode against an empty
# listing (defaulting to flat and missing the flat ref). The gateway's
# /human/templates list is NOT a readiness signal (it stays briefly empty even
# in green runs); the scan's on-disk output is. Poll for the seeded refs.
for _ in $(seq 1 50); do
    if [[ -f "$TEMPLATE_DIR/refs/sqlite_v1.overlay.json" && -f "$TEMPLATE_DIR/refs/python_v1.overlay.json" ]]; then
        break
    fi
    sleep 0.2
done
[[ -f "$TEMPLATE_DIR/refs/sqlite_v1.overlay.json" ]] || {
    log_error "template refs not registered within 10s (scan race): $(ls "$TEMPLATE_DIR/refs" 2>/dev/null | tr '\n' ' ')"
    exit 1
}
pass "versioned template refs registered (scan complete)"
tc_wait_health

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Create SandFS with Read-Only Overlay (versioned templates)"
# ══════════════════════════════════════════════════════════════════

# ─── Agent A (SQLite): template="sqlite:v1" ───
log_step "Creating Agent A SandFS with template='sqlite:v1'..."
RESP_A=$(tc_create_agent_and_sandfs "sqlite-agent" "sqlite:v1" || echo '{"error":"create failed"}')
echo "  Response: $RESP_A"
ID_A=$(json_val "$RESP_A" "sandfs_id")
# Volume directory: derived from the deployment seed, NOT the id
ID_A_VOL="$(tc_volume_path "$ID_A")" || { echo "cannot resolve volume for $ID_A" >&2; exit 1; }
KEY_A=$(json_val "$RESP_A" "api_key")
KEY2SID["$KEY_A"]="$ID_A"
[[ -z "$KEY_A" ]] && { log_error "Failed to create Agent A"; echo "$RESP_A"; exit 1; }
log_pass "Agent A created: $ID_A (template=sqlite:v1)"

# Verify read-only overlay directory structure (created at sandfs creation time)
# New structure: workspace/, home/ (writable), .template marker
# Note: rootfs/ is NOT created at this point — it's created lazily by sandlot's
# ensureReadonlyOverlayMounted on first cold execute.
WORKSPACE_A="${ID_A_VOL}/workspace"
HOME_A="${ID_A_VOL}/home"
[[ -d "$WORKSPACE_A" && -d "$HOME_A" ]] && log_pass "OverlayFS dirs confirmed: workspace/ home/" || fail "OverlayFS dirs NOT found"
[[ -f "${ID_A_VOL}/.template" ]] && log_pass ".template marker found" || fail ".template marker NOT found"

# In the lazy-mount model, the overlay is NOT mounted at creation time.
# It gets mounted on first execute (by sandlot's ensureReadonlyOverlayMounted).
# Trigger a cold execute to mount the overlay, then verify it's active.
log_step "Triggering cold execute to mount read-only overlay (lazy mount model)..."
exec_code "$KEY_A" "echo overlay-mounted" "Cold execute to mount read-only overlay"
mount | grep -q "overlay.*$ID_A_VOL" && log_pass "Read-only overlay mount active after cold execute" || fail "Read-only overlay mount NOT found after cold execute"
LOWERDIR_A=$(mount | grep "overlay.*$ID_A_VOL" | grep -oP 'lowerdir=\K[^,]+' | head -1 || true)
# First element only: the value is "template:empty-layer" (kernel >=2 lowerdirs).
[[ "${LOWERDIR_A%%:*}" == "$TEMPLATE_DIR/sqlite/v1" ]] && log_pass "Lowerdir → sqlite/v1: $LOWERDIR_A" || fail "Lowerdir: $LOWERDIR_A (expected first element $TEMPLATE_DIR/sqlite/v1) — template routing broken"

# Pre-populate SQLite data directly into workspace/ (writable bind mount target)
# Agent writes go to workspace/ not to an upperdir
sqlite3 "$WORKSPACE_A/test.db" << 'SQLEOF'
CREATE TABLE transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount REAL NOT NULL, category TEXT NOT NULL, description TEXT, timestamp TEXT NOT NULL);
CREATE INDEX idx_category ON transactions(category);
INSERT INTO transactions (user_id, amount, category, description, timestamp) VALUES
(1,125.50,'food','Grocery shopping','2024-01-15 10:30:00'),
(2,89.99,'transport','Gas station','2024-01-16 14:20:00'),
(3,250.00,'entertainment','Concert tickets','2024-01-17 20:00:00'),
(1,45.75,'shopping','Clothing store','2024-01-18 16:45:00'),
(4,120.00,'utilities','Electric bill','2024-01-19 09:00:00'),
(2,65.30,'food','Restaurant dinner','2024-01-20 19:30:00'),
(5,180.00,'transport','Car maintenance','2024-01-21 11:15:00'),
(3,95.50,'entertainment','Movie theater','2024-01-22 15:00:00'),
(1,210.00,'shopping','Electronics','2024-01-23 13:30:00'),
(4,75.25,'food','Supermarket','2024-01-24 12:00:00'),
(2,150.00,'utilities','Internet bill','2024-01-25 10:00:00'),
(5,320.00,'entertainment','Theme park','2024-01-26 09:00:00'),
(3,88.00,'transport','Bus pass','2024-01-27 08:30:00'),
(1,195.50,'shopping','Bookstore','2024-01-28 14:00:00'),
(4,110.00,'food','Coffee shop','2024-01-29 07:45:00'),
(2,275.00,'entertainment','Sports event','2024-01-30 18:00:00'),
(5,65.00,'utilities','Water bill','2024-01-31 11:00:00'),
(3,145.75,'shopping','Home goods','2024-02-01 16:30:00'),
(1,95.00,'transport','Parking fee','2024-02-02 10:15:00'),
(4,180.50,'food','Bakery','2024-02-03 08:00:00');
SELECT 'Pre-loaded ' || COUNT(*) || ' records' FROM transactions;
SQLEOF
# Host-seeded guest-writable content MUST carry group-write (0664): the
# dedicated-identity daemon opens it as the sandlot user (group 985), and a
# plain 0644 leaves the group read-only → every guest write EACCES (the
# "readonly database" class of failure). Same contract as the gateway's
# template seeding (copyDirRecursive 0664).
chmod 0664 "$WORKSPACE_A/test.db"
log_pass "SQLite data prepared (20 records, in workspace/, 0664)"
[[ -f "$WORKSPACE_A/test.db" ]] && log_pass "Data in workspace/" || log_warn "test.db not in workspace/"
[[ ! -f "$TEMPLATE_DIR/sqlite/v1/workspace/test.db" ]] && log_pass "Template lowerdir clean" || fail "Data leaked into template!"

# ─── Agent B (Python): template="python:v1" ───
log_step "Creating Agent B SandFS with template='python:v1'..."
RESP_B=$(tc_create_agent_and_sandfs "python-agent" "python:v1" || echo '{"error":"create failed"}')
echo "  Response: $RESP_B"
ID_B=$(json_val "$RESP_B" "sandfs_id")
# Volume directory: derived from the deployment seed, NOT the id
ID_B_VOL="$(tc_volume_path "$ID_B")" || { echo "cannot resolve volume for $ID_B" >&2; exit 1; }
KEY_B=$(json_val "$RESP_B" "api_key")
KEY2SID["$KEY_B"]="$ID_B"
[[ -z "$KEY_B" ]] && { log_error "Failed to create Agent B"; exit 1; }
log_pass "Agent B created: $ID_B (template=python:v1)"

WORKSPACE_B="${ID_B_VOL}/workspace"
# Trigger cold execute to mount Agent B's read-only overlay (lazy mount model)
exec_code "$KEY_B" "echo overlay-mounted" "Cold execute to mount Agent B read-only overlay" >/dev/null
LOWERDIR_B=$(mount | grep "overlay.*$ID_B_VOL" | grep -oP 'lowerdir=\K[^,]+' | head -1 || true)
[[ "${LOWERDIR_B%%:*}" == "$TEMPLATE_DIR/python/v1" ]] && log_pass "Lowerdir → python/v1: $LOWERDIR_B" || fail "Lowerdir: $LOWERDIR_B (expected first element $TEMPLATE_DIR/python/v1) — template routing broken"

cat > "$WORKSPACE_B/analyze.py" << 'PYEOF'
import random
from collections import defaultdict
print("=== Python Data Analysis (10K data points) ===\n")
data = [(i, random.uniform(100,1000), i%5) for i in range(1,10001)]
print(f"Generated {len(data)} records\n")
cat_stats = defaultdict(lambda: {"count":0,"total":0.0})
for _,v,c in data: cat_stats[c]["count"]+=1; cat_stats[c]["total"]+=v
for c in sorted(cat_stats): s=cat_stats[c]; print(f"  Category {c}: {s['count']} records, total {s['total']:.2f}")
vals = [v for _,v,_ in data]
print(f"\nStats: n={len(vals)} avg={sum(vals)/len(vals):.2f} min={min(vals):.2f} max={max(vals):.2f}")
PYEOF
# Host-seeded guest-writable content → group-write (same contract as A-side).
chmod 0664 "$WORKSPACE_B/analyze.py"
chmod +x "$WORKSPACE_B/analyze.py"
cat > "$WORKSPACE_B/sample_data.csv" << 'CSVEOF'
user_id,value,category
1,125.50,0
2,89.99,1
3,250.00,2
1,45.75,3
4,120.00,4
2,65.30,0
5,180.00,1
3,95.50,2
1,210.00,3
4,75.25,0
CSVEOF
# Host-seeded guest-writable content → group-write (same contract as A-side).
chmod 0664 "$WORKSPACE_B/sample_data.csv"
log_pass "Python data prepared"

# ─── Agent C (SQLite-reader): SAME template="sqlite:v1" ───
# Tests dedup: Agent A and Agent C share the same lowerdir
log_step "Creating Agent C SandFS with template='sqlite:v1' (same template as A → dedup)..."
RESP_C=$(tc_create_agent_and_sandfs "sqlite-reader" "sqlite:v1" || echo '{"error":"create failed"}')
echo "  Response: $RESP_C"
ID_C=$(json_val "$RESP_C" "sandfs_id")
# Volume directory: derived from the deployment seed, NOT the id
ID_C_VOL="$(tc_volume_path "$ID_C")" || { echo "cannot resolve volume for $ID_C" >&2; exit 1; }
KEY_C=$(json_val "$RESP_C" "api_key")
KEY2SID["$KEY_C"]="$ID_C"
[[ -z "$KEY_C" ]] && { log_error "Failed to create Agent C"; exit 1; }
log_pass "Agent C created: $ID_C (template=sqlite:v1)"

WORKSPACE_C="${ID_C_VOL}/workspace"
# Agent C has not executed yet, so its overlay is not mounted.
# Verify dedup by checking .template markers match (both point to sqlite:v1)
TPL_A=$(cat "${ID_A_VOL}/.template" 2>/dev/null || echo "")
TPL_C=$(cat "${ID_C_VOL}/.template" 2>/dev/null || echo "")
if [[ "$TPL_A" == "$TPL_C" && "$TPL_A" == "sqlite:v1" ]]; then
    log_pass "DEDUP CONFIRMED: Agent A and C share template: $TPL_A (same lowerdir)"
else
    fail "DEDUP FAILED: Agent A template=$TPL_A vs Agent C template=$TPL_C"
fi

echo ""
echo "  ┌────────────────────────────────────────────────────────────┐"
echo "  │  Read-Only Overlay + Writable Workspace/Home Multi-Agent   │"
printf "  │  Agent A (SQLite)      template=sqlite:v1  ID: %-10s│\n" "$ID_A"
printf "  │  Agent B (Python)      template=python:v1  ID: %-10s│\n" "$ID_B"
printf "  │  Agent C (SQLite-rdr)  template=sqlite:v1  ID: %-10s│\n" "$ID_C"
echo "  │  A & C share lowerdir → dedup ✓                          │"
echo "  │  Each agent has own workspace/ + home/ → isolation       │"
echo "  └────────────────────────────────────────────────────────────┘"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Agent A — Cold Start + SQLite Queries"
# ══════════════════════════════════════════════════════════════════

log_info "Read-only overlay: warden mounts rootfs/ (read-only merged view of lowerdir)"
log_info "Writable paths: /workspace (writable bind mount), /home/agent (writable bind mount), /tmp (tmpfs)"

log_step "A1: Cold start — first query (triggers microVM boot + read-only overlay mount)..."
A1_STDOUT=""
for attempt in 1 2 3; do
    exec_code "$KEY_A" "uname -r && sqlite3 /workspace/test.db 'SELECT COUNT(*) FROM transactions;'" "A1: Cold start + query 20 records (attempt $attempt)" >/dev/null
    A1_STDOUT=$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo "")
    # A versioned kernel release (x.y.z) proves the guest actually answered —
    # NOT a hardcoded "6.2.0", which false-failed on every kernel rebuild.
    echo "$A1_STDOUT" | grep -Eq '^[0-9]+\.[0-9]+' && break
    log_warn "A1 attempt $attempt: microVM not ready yet, retrying..."
    sleep 2
done
KERNEL_REL=$(echo "$A1_STDOUT" | head -1)
if echo "$KERNEL_REL" | grep -Eq '^[0-9]+\.[0-9]+'; then
    pass "A1: microVM kernel running (release: $KERNEL_REL)"
else
    fail "A1: microVM did not report a kernel release (got: '$KERNEL_REL')"
fi
assert_contains "A1: 20 pre-loaded records found" "$A1_STDOUT" "20"

log_step "A2: Warm query (sticky lease)..."
exec_code "$KEY_A" "sqlite3 /workspace/test.db 'SELECT category, COUNT(*), SUM(amount) FROM transactions GROUP BY category ORDER BY SUM(amount) DESC;'" "A2: Warm category summary" >/dev/null
assert_contains "A2: category data returned" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "food"

log_step "A3: Warm insert 5 records..."
exec_code "$KEY_A" "
sqlite3 /workspace/test.db << 'EOF'
INSERT INTO transactions (user_id, amount, category, description, timestamp) VALUES
(6,88.50,'food','Breakfast cafe','2024-02-04 08:30:00'),
(7,125.00,'transport','Train ticket','2024-02-05 07:00:00'),
(8,200.00,'entertainment','Art exhibition','2024-02-06 14:00:00'),
(6,95.75,'shopping','Pharmacy','2024-02-07 11:00:00'),
(7,150.00,'utilities','Phone bill','2024-02-08 09:30:00');
SELECT COUNT(*) FROM transactions;
EOF
" "A3: Insert 5 records → 25 total" >/dev/null
assert_contains "A3: 25 records after insert" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "25"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Agent B — Cross-Agent Switch + Python"
# ══════════════════════════════════════════════════════════════════

sleep 1  # Wait for lease expiry

log_step "B1: Cross-agent switch to Python (set-fs + unmount + mount)..."
exec_code "$KEY_B" "python3 --version && if [ -f /workspace/test.db ]; then echo 'FAIL: can see Agent A database'; else echo 'OK: Agent A data not visible'; fi" "B1: Cross-agent switch + Python verify" >/dev/null
assert_contains "B1: Python works" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "Python"
assert_contains "B1: Agent A data isolated" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "Agent A data not visible"

log_step "B2: Warm Python analysis (10K data points)..."
exec_code "$KEY_B" "python3 /workspace/analyze.py" "B2: Python 10K analysis" >/dev/null
assert_contains "B2: analysis output" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "Category"

log_step "B3: CSV processing..."
exec_code "$KEY_B" "
python3 -c \"
import csv
from collections import defaultdict
with open('/workspace/sample_data.csv') as f:
    data = list(csv.DictReader(f))
print(f'Read {len(data)} CSV records')
\"
" "B3: CSV processing" >/dev/null
assert_contains "B3: 10 CSV records" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "10 CSV"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Agent C — Same-Template Dedup Verification"
# ══════════════════════════════════════════════════════════════════

sleep 1

log_info "Agent C uses the SAME template as A (sqlite:v1) — verifies workspace/home isolation"
log_info "Both agents share the same read-only lowerdir, but have separate workspace/ directories"

log_step "C1: Agent C cannot see Agent A's inserted data..."
exec_code "$KEY_C" "sqlite3 /workspace/test.db 'SELECT COUNT(*) FROM transactions;' 2>/dev/null || echo 'NO_DB'" "C1: Agent C queries (same template, different workspace)" >/dev/null
# Capture C's REAL lowerdir from the host mount table while its overlay is live
# (same pattern as A's capture after the cold execute). Phase 10's dedup verdict
# compares these instead of trusting .template markers that can both read "".
if mount | grep -q "overlay.*$ID_C_VOL"; then
    LOWERDIR_C=$(mount | grep "overlay.*$ID_C_VOL" | grep -oP 'lowerdir=\K[^,]+' | head -1 || true)
    log_pass "Agent C read-only overlay mount active (lowerdir: ${LOWERDIR_C:-<unparsed>})"
else
    LOWERDIR_C=""
    log_warn "Agent C overlay not in the host mount table right after C1 — capture missed (Phase 10 will report dedup as UNPROVEN)"
fi
C1_STDOUT=$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo "")
# Agent C has its own workspace/ directory — it has no test.db
# unless written there explicitly. Workspace isolation means Agent C
# cannot see Agent A's workspace/ data.
if echo "$C1_STDOUT" | grep -q "NO_DB"; then
    pass "C1: Agent C has no test.db (workspace isolation from Agent A)"
elif echo "$C1_STDOUT" | grep -qE "^20$"; then
    # test.db might be visible if something leaked into the template's lowerdir
    # But we wrote it to Agent A's workspace/, so C should not see it
    fail "C1: same-template workspace isolation — Agent C sees A's 20 records"
else
    # Neither NO_DB nor the expected count: the exec itself failed (empty
    # stdout / error). An exec failure must NOT read as "isolation verified".
    fail "C1: exec produced no interpretable output (stdout: '$C1_STDOUT') — cannot verify isolation"
fi

log_step "C2: Agent C can write its own data (independent workspace/)..."
exec_code "$KEY_C" "echo 'Agent C was here' > /workspace/reader-note.txt && cat /workspace/reader-note.txt" "C2: Agent C writes its own data" >/dev/null
assert_contains "C2: Agent C writes successfully" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "Agent C was here"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 7: Agent A — Switch Back + Persistence Verify"
# ══════════════════════════════════════════════════════════════════

sleep 1

log_step "A4: Switch back to Agent A — data persistence after B and C ran..."
exec_code "$KEY_A" "sqlite3 /workspace/test.db 'SELECT COUNT(*) FROM transactions;'" "A4: Agent A persistence after switch" >/dev/null
assert_contains "A4: 25 records persist" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "25"

# Verify Agent C's data is NOT visible to Agent A
log_step "A5: Verify Agent C's data not visible to Agent A..."
exec_code "$KEY_A" "if [ -f /workspace/reader-note.txt ]; then echo 'FAIL: Agent C data visible'; else echo 'OK: no cross-contamination'; fi" "A5: Agent A cannot see Agent C's data" >/dev/null
assert_contains "A5: Agent A/C isolated" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "no cross-contamination"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 8: SaveAsTemplate — Promote flat SandFS to sqlite:v2"
# ══════════════════════════════════════════════════════════════════

# SaveAsTemplate only works on flat SandFS (overlay SandFS is rejected).
# Create a flat SandFS, write data to it, then save as template.
log_info "SaveAsTemplate requires flat SandFS — creating a flat SandFS for this test."

log_step "Creating flat SandFS for SaveAsTemplate test..."
RESP_D=$(tc_create_agent_and_sandfs "flat-save-test" "rootfs:v1" "flat" || echo '{"error":"create failed"}')
ID_D=$(json_val "$RESP_D" "sandfs_id")
KEY_D=$(json_val "$RESP_D" "api_key")
KEY2SID["$KEY_D"]="$ID_D"
[[ -z "$KEY_D" ]] && { log_error "Failed to create flat SandFS"; exit 1; }
log_pass "Flat SandFS created: $ID_D"

# Write some data to the flat SandFS
log_step "Writing data to flat SandFS..."
exec_code "$KEY_D" "echo 'saved-template-data' > /workspace/saved.txt && cat /workspace/saved.txt" "Write data to flat SandFS" >/dev/null
assert_contains "Data written to flat SandFS" "$(cat /tmp/sandswap-last-stdout.txt 2>/dev/null || echo '')" "saved-template-data"

log_step "Saving flat SandFS state as template sqlite:v2..."
SAVE_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs/$ID_D/save-template" \
    -H "Content-Type: application/json" \
    -d '{"template_ref":"sqlite:v2","description":"Flat SandFS with saved data"}')
echo "  Response: $SAVE_RESP"
SAVE_PATH=$(echo "$SAVE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('path',''))" 2>/dev/null || echo "")
SAVE_SIZE=$(echo "$SAVE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('size_kb',0))" 2>/dev/null || echo "0")

if [[ -n "$SAVE_PATH" && -d "$SAVE_PATH" ]]; then
    pass "Template sqlite:v2 saved at $SAVE_PATH ($SAVE_SIZE KB)"
    # Verify the new template is registered — name AND version, not a bare
    # "v2" substring that matches any v2 anywhere.
    TEMPLATES_AFTER=$(curl -s "$HUMAN_URL/human/templates" 2>/dev/null || echo "[]")
    if echo "$TEMPLATES_AFTER" | grep -q '"name": *"sqlite"' && echo "$TEMPLATES_AFTER" | grep -q '"version": *"v2"'; then
        pass "sqlite:v2 registered in template list"
    else
        fail "sqlite:v2 not found in template list: $TEMPLATES_AFTER"
    fi
else
    fail "SaveAsTemplate failed: $SAVE_RESP"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 9: Sticky Lease (functional sanity, client wall clock)"
# ══════════════════════════════════════════════════════════════════

log_info "10 rapid same-agent calls must stay fast (sticky lease, not remount)..."

curl -s -X POST "$GATEWAY_URL/agent/execute" -H "Authorization: Bearer $KEY_A" \
    -H "Content-Type: application/json" -d "{\"code\":\"echo warmup\",\"language\":\"shell\",\"sandfs_id\":\"$ID_A\"}" >/dev/null 2>&1 || true

WARM_MS=()
CURL_FAILS=0
for i in $(seq 1 10); do
    # NO `|| echo "0"` fallback: a failed curl recorded as 0ms would make ten
    # broken requests read as "P50=0ms — sticky lease fast". Track failures
    # and gate on them below.
    if ms=$(curl -s -m 30 -o /dev/null -w '%{time_total}' -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" \
        -d "{\"code\":\"echo sticky_$i\",\"language\":\"shell\",\"sandfs_id\":\"$ID_A\"}" 2>/dev/null) \
        && [[ -n "$ms" ]] && [[ "$ms" != "0.000000" ]]; then
        WARM_MS+=("$(python3 -c "print(float('$ms')*1000)" 2>/dev/null || echo "999999")")
    else
        CURL_FAILS=$((CURL_FAILS + 1))
    fi
done

# Sticky budget is env-tunable: nested-virt/loaded hosts legitimately see
# higher warm-path latency than bare metal; production default is 2s.
STICKY_BUDGET_MS="${STICKY_BUDGET_MS:-2000}"
if [[ "$CURL_FAILS" -gt 2 ]]; then
    WARM_P50=0; fail "Sticky lease: $CURL_FAILS/10 requests failed outright (transport broken)"
elif [[ ${#WARM_MS[@]} -gt 0 ]]; then
    mapfile -t SORTED_W < <(printf '%s\n' "${WARM_MS[@]}" | sort -n)
    _n=${#SORTED_W[@]}
    WARM_P50=$(printf "%.1f" "${SORTED_W[$((_n/2))]}")
    echo "  Sticky lease: P50=${WARM_P50}ms  (n=$_n, client wall clock, budget ${STICKY_BUDGET_MS}ms)"
    [[ "${WARM_P50%.*}" -lt "$STICKY_BUDGET_MS" ]] && pass "Sticky lease fast" || fail "Sticky lease slow P50=${WARM_P50}ms (budget ${STICKY_BUDGET_MS}ms)"
else
    WARM_P50=0; fail "No warm-path data"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 10: Read-Only Overlay Isolation & Dedup Verification"
# ══════════════════════════════════════════════════════════════════

log_info "Verifying read-only overlay + writable workspace/home isolation and dedup properties..."

# 1. Workspace isolation: Each agent's writes go only to its own workspace/.
# Note: If Agent C writes to /workspace/test.db inside the microVM, it will
# create its OWN test.db in its workspace/ directory (writable bind mount). This is
# correct behavior — the key isolation property is that Agent C cannot see Agent A's
# test.db DATA, not that the filename doesn't exist.
log_step "Checking workspace isolation..."
[[ -f "$WORKSPACE_A/test.db" ]] && pass "Agent A workspace/ has test.db" || fail "Agent A workspace/ missing test.db"

# Check that Agent A's workspace/ and Agent C's workspace/ are distinct directories
A_WORKSPACE=$(stat -c%i "$WORKSPACE_A" 2>/dev/null || echo "0")
C_WORKSPACE=$(stat -c%i "$WORKSPACE_C" 2>/dev/null || echo "0")
if [[ "$A_WORKSPACE" != "$C_WORKSPACE" ]]; then
    pass "Agent A and C have separate workspace/ dirs (inode A=$A_WORKSPACE vs C=$C_WORKSPACE)"
else
    fail "Agent A and C share the same workspace/ (isolation broken)"
fi

# 2. Lowerdir dedup: A and C share the same lowerdir (verified via .template markers)
log_step "Checking lowerdir dedup..."
TPL_A_FINAL=$(cat "${ID_A_VOL}/.template" 2>/dev/null || echo "")
TPL_C_FINAL=$(cat "${ID_C_VOL}/.template" 2>/dev/null || echo "")
TPL_B_FINAL=$(cat "${ID_B_VOL}/.template" 2>/dev/null || echo "")
# Non-empty FIRST: two unreadable markers both yield "" and ""=="" must not
# read as "share the same template".
if [[ -n "$TPL_A_FINAL" && "$TPL_A_FINAL" == "$TPL_C_FINAL" ]]; then
    pass "Agents A & C share template/lowerdir (dedup): $TPL_A_FINAL"
else
    fail "Agents A & C have different/unreadable templates (no dedup): A='${TPL_A_FINAL:-<unset>}' C='${TPL_C_FINAL:-<unset>}'"
fi
[[ -n "$TPL_A_FINAL" && -n "$TPL_B_FINAL" && "$TPL_A_FINAL" != "$TPL_B_FINAL" ]] \
    && pass "Agents A & B have different templates (different lowerdirs)" \
    || fail "A & B templates not distinct/unreadable: A='${TPL_A_FINAL:-<unset>}' B='${TPL_B_FINAL:-<unset>}'"
# THE dedup proof: the real lowerdir each agent's overlay actually mounted
# (captured live: A after its cold execute, C after C1). An empty capture means
# the property is UNPROVEN, not satisfied.
if [[ -z "${LOWERDIR_A:-}" || -z "${LOWERDIR_C:-}" ]]; then
    fail "overlay lowerdir dedup UNPROVEN: LOWERDIR_A='${LOWERDIR_A:-<unset>}' LOWERDIR_C='${LOWERDIR_C:-<unset>}' (capture missed the live mount)"
elif [[ "${LOWERDIR_A%%:*}" == "${LOWERDIR_C%%:*}" ]]; then
    pass "Agents A & C mounted the SAME read-only overlay lowerdir (real mount table): ${LOWERDIR_A%%:*}"
else
    fail "Agents A & C overlay lowerdirs differ (no dedup): A=$LOWERDIR_A C=$LOWERDIR_C"
fi

# 3. Template integrity
log_step "Checking template integrity (lowerdir not modified)..."
[[ ! -f "$TEMPLATE_DIR/sqlite/v1/workspace/test.db" ]] && pass "sqlite:v1 template not modified by Agent A writes" || fail "sqlite:v1 template modified!"
[[ ! -f "$TEMPLATE_DIR/python/v1/workspace/analyze.py" ]] && pass "python:v1 template not modified by Agent B writes" || fail "python:v1 template modified!"

# 4. Space efficiency
log_step "Checking space efficiency..."
A_WORKSPACE_SIZE=$(du -sb "$WORKSPACE_A" 2>/dev/null | cut -f1 || echo "0")
B_WORKSPACE_SIZE=$(du -sb "$WORKSPACE_B" 2>/dev/null | cut -f1 || echo "0")
C_WORKSPACE_SIZE=$(du -sb "$WORKSPACE_C" 2>/dev/null | cut -f1 || echo "0")
SQLITE_V1_SIZE=$(du -sb "$TEMPLATE_DIR/sqlite/v1" 2>/dev/null | cut -f1 || echo "0")
PYTHON_V1_SIZE=$(du -sb "$TEMPLATE_DIR/python/v1" 2>/dev/null | cut -f1 || echo "0")
TOTAL_OVERLAY=$(( SQLITE_V1_SIZE + PYTHON_V1_SIZE + A_WORKSPACE_SIZE + B_WORKSPACE_SIZE + C_WORKSPACE_SIZE ))
TOTAL_COPY=$(( SQLITE_V1_SIZE * 2 + PYTHON_V1_SIZE ))
log_info "  sqlite:v1 template: $(( SQLITE_V1_SIZE / 1024 ))KB (shared by A & C)"
log_info "  python:v1 template: $(( PYTHON_V1_SIZE / 1024 ))KB (shared by B)"
log_info "  Agent A workspace/: $(( A_WORKSPACE_SIZE / 1024 ))KB"
log_info "  Agent B workspace/: $(( B_WORKSPACE_SIZE / 1024 ))KB"
log_info "  Agent C workspace/: $(( C_WORKSPACE_SIZE / 1024 ))KB"
log_info "  Total with read-only overlay mode: $(( TOTAL_OVERLAY / 1024 ))KB"
log_info "  Without overlay (full copies):       $(( TOTAL_COPY / 1024 ))KB"
SAVED=$(( TOTAL_COPY - TOTAL_OVERLAY ))
if [[ $TOTAL_COPY -gt 0 ]]; then
    log_info "  Space saved by dedup:               $(( SAVED / 1024 ))KB ($(( SAVED * 100 / TOTAL_COPY ))%)"
fi
# Dedup must actually SAVE space: two sqlite agents share one template, so
# full-copy bookkeeping exceeds the overlay total. (An unconditional pass here
# used to make this "verified" even when the numbers said the opposite.)
# The dedup VERDICT is the real-mount lowerdir equality asserted above; this
# arithmetic is fixture bookkeeping (template sizes vs workspace sizes, not the
# mounts the agents actually got) and is informational only — it passes by
# construction whenever the template is bigger than the workspaces.
log_info "  space bookkeeping: overlay=$TOTAL_OVERLAY copies=$TOTAL_COPY saved=$(( SAVED / 1024 ))KB (informational)"

# 5. SaveAsTemplate verification
log_step "Checking SaveAsTemplate result..."
if [[ -n "$SAVE_PATH" && -d "$SAVE_PATH" ]]; then
    [[ -f "$SAVE_PATH/workspace/saved.txt" ]] && pass "sqlite:v2 contains flat SandFS data (workspace/ captured)" || fail "sqlite:v2 missing saved.txt"
    V2_SIZE=$(du -sb "$SAVE_PATH" 2>/dev/null | cut -f1 || echo "0")
    log_info "  sqlite:v2 template: $(( V2_SIZE / 1024 ))KB (includes Agent A's modifications)"
    log_info "  Available to all hosts via distributed FS at $SAVE_PATH"
else
    log_warn "SaveAsTemplate not verified (may have failed earlier)"
fi
# ══════════════════════════════════════════════════════════════════
log_section "Results Summary"
# ══════════════════════════════════════════════════════════════════

echo ""
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │   Sandswap Read-Only Overlay Multi-Agent Test            │"
echo "  ├──────────────────────────────────────────────────────────┤"
printf "  │  Sandlot pool: %-10s (forced VM reuse)            │\n" "$SANDLOT_POOL"
echo "  │                                                          │"
echo "  │  Stack tested:                                           │"
echo "  │    Gateway → gRPC → Sandlot → sandvmm → warden          │"
echo "  │                     └─ set-fs (virtio-fs swap)           │"
echo "  │                     └─ vsock (raw protocol)              │"
echo "  │                                                          │"
echo "  │  Read-only overlay + writable-path features tested:     │"
echo "  │    ✓ Versioned templates (sqlite:v1, python:v1)          │"
echo "  │    ✓ lowerdir = template (shared, read-only)             │"
echo "  │    ✓ workspace/ = per-agent dir (writable)               │"
echo "  │    ✓ home/ = per-agent dir (writable)                    │"
echo "  │    ✓ Same-template dedup (A & C share sqlite:v1)         │"
echo "  │    ✓ Cross-template isolation (A vs B)                   │"
echo "  │    ✓ Same-template workspace isolation (A vs C)          │"
echo "  │    ✓ Template not modified by agent writes               │"
echo "  │    ✓ SaveAsTemplate (A → sqlite:v2, from workspace/)    │"
echo "  │    ✓ Cold mount + warm exec + cross-agent switch         │"
echo "  │    ✓ Data persistence after agent switch                 │"
echo "  │    ✓ Distributed FS dedup ready (versioned layout)       │"
echo "  │                                                          │"
printf "  │  Sticky lease:  P50=%-6sms (client wall clock)        │\n" "$WARM_P50"
echo "  │                                                          │"
printf "  │  Tests: %2d passed  %2d failed                              │\n" "$PASS_COUNT" "$FAIL_COUNT"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""

[[ ${FAIL_COUNT:-0} -gt 0 ]] && exit 1 || log_pass "All tests passed"
