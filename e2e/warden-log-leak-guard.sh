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
# warden-log-leak-guard.sh — verify the warden never writes its bookkeeping logs
# into the mounted SandFS or the shared volumes directory.
# Background (the bug this test guards against):
#   - The warden previously redirected a background exec's stdout/stderr to
#     /tmp/.sandswap-bg-<id>.log INSIDE the chroot (/mnt/rootfs). In flat /
#     bind-mount mode the whole agent directory is the read-write rootfs, so
#     that log persisted into the agent's SandFS volume — polluting persistent
#     agent storage with warden internals.
#   - A countdown debug block also appended to /mnt/volumes/warden-dbg.log,
#     i.e. the virtio-fs export of the host volumes dir — shared, cross-agent,
#     cross-node storage. Pure debug leftover.
# Both are warden bookkeeping and must NEVER land in agent-owned or shared
# persistent storage. The fix moves bg logs to the warden's initramfs tmpfs
# (RAM) via inherited fds, and removes the countdown debug block entirely.
# This test:
#   FlatMode  flat mode: start a bg exec that writes output; poll status to confirm
#       the log IS captured (positive — the log mechanism still works), then
#       assert the host SandFS volume dir contains NO .sandswap-bg-*.log and
#       NO warden-dbg.log anywhere under it.
#   SharedVolumesRoot  shared volumes root: after sync execs (heartbeats flowing, countdown
#       ticking every 1s) + an unmount, assert $VOL_ROOT/warden-dbg.log is
#       never created on the host.
#   OverlayMode  overlay mode (best-effort): if an overlay template is registered, run
#       the same bg-exec + absence check under an overlay sandfs dir.
# Prerequisites: built artifacts in output/, /dev/kvm, root (or kvm).
# Usage: sudo bash e2e/warden-log-leak-guard.sh

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
POOL_SIZE="${POOL_SIZE:-1}"
# shellcheck disable=SC2034  # consumed by the SOURCED common.sh across the source boundary
SANDLOT_POOL="small:${POOL_SIZE}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
source "$ROOT/e2e/common.sh"

# Run directly from $OUTPUT (no separate deploy step) + shared template install.
tc_use_output_binaries
tc_install_flat_template

# gw_exec / gw_status / http_code_of / body_of / json_field come from common.sh.

# find_any <dir> <pattern>: print matching paths (one per line), empty if none.
find_any() { find "$1" -name "$2" 2>/dev/null; }

# SKIP_COUNT/skip — a phase that cannot run must be REPORTED and COUNTED in the
# summary, not disappear into a bare warn: OverlayMode never runs in a standard
# run (the suite installs only a FLAT template, so GET /human/templates has no
# overlay entry) while the header still presents it as coverage.
SKIP_COUNT=0
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); tc_log_warn "$@"; }

# Pre-flight: hard fail (a missing KVM or a broken build must show up as a
# FAILED run, not as a silent exit-0 "skip" that CI reads as green).
tc_check_root
if [[ ! -e /dev/kvm ]] || [[ ! -r /dev/kvm ]]; then
    tc_log_error "/dev/kvm not available - this E2E requires KVM."
    tc_log_info "Run: sudo chmod 666 /dev/kvm   or add user to kvm group"
    exit 1
fi
if [[ ! -f "$OUTPUT/gateway" ]] || [[ ! -f "$OUTPUT/sandlot" ]] || [[ ! -f "$OUTPUT/sandvmm" ]]; then
    tc_log_error "build artifacts missing in output/ - run 'bash build/build.sh all' first."
    exit 1
fi

tc_log_section "Warden Log Isolation E2E"

tc_check_tools curl python3
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network
tc_attach_vsockguard

tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready "$POOL_SIZE"

cleanup() { tc_cleanup_default; }
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════
# FlatMode: flat mode — bg exec log must NOT land in the SandFS volume
# ══════════════════════════════════════════════════════════════
tc_log_section "FlatMode: flat mode bg-exec log isolation"

tc_create_agent_and_sandfs "log-iso-flat" "rootfs:v1" "flat" >/dev/null
F_KEY="$TC_API_KEY"; F_SANDFS="$TC_SANDFS_ID"; F_VOL="$TC_ROOTFS_PATH"
[[ -n "$F_KEY" && -n "$F_SANDFS" && -n "$F_VOL" ]] || { tc_log_error "flat agent/sandfs create failed"; exit 1; }
tc_log_info "flat sandfs volume dir: $F_VOL"

# Start a background exec that emits identifiable output. The warden captures it
# to its log file; status poll returns the tail.
BG=$(gw_exec "$F_KEY" "$F_SANDFS" \
    'for i in 1 2 3 4 5; do echo bgline$i; sleep 1; done' \
    '"background":true,"lease_duration":30')
BG_ID=$(body_of "$BG" | json_field "exec_id")
[[ -n "$BG_ID" ]] \
    && tc_pass "FlatMode: bg exec started ($BG_ID)" \
    || { tc_fail "FlatMode: bg exec start failed: $(body_of "$BG")"; exit 1; }

# Wait for output to be produced, then poll status. The positive assertion: the
# warden-side log IS being written and its tail is returned over vsock.
sleep 4
ST=$(gw_status "$F_KEY" "$F_SANDFS" "$BG_ID")
ST_TAIL=$(echo "$ST" | json_field "stdout")
if echo "$ST_TAIL" | grep -q "bgline"; then
    tc_pass "FlatMode: bg exec log captured via status tail (warden-side log works)"
else
    tc_fail "FlatMode: bg exec log not captured in status tail: $ST"
fi

# While the bg exec is still running (mount live), check the host SandFS volume
# dir for leaked warden logs. The bg log must NOT be here — it lives in the
# warden's initramfs tmpfs, readable only via the status tail.
# GUARD: $F_VOL must EXIST — a missing volume dir (rootfs_path semantics drift)
# would make every absence check below vacuously pass on `find` errors.
if [[ ! -d "$F_VOL" ]]; then
    tc_fail "FlatMode: volume dir $F_VOL does not exist — leak assertions would be vacuous"
    tc_log_info "rootfs_path=$F_VOL sandfs=$F_SANDFS"
    exit 1
fi
tc_pass "FlatMode: volume dir exists ($F_VOL) — leak assertions are meaningful"
LEAK_BG=$(find_any "$F_VOL" '.sandswap-bg-*.log' | head -1 || true)
LEAK_DBG=$(find_any "$F_VOL" 'warden-dbg.log' | head -1 || true)
if [[ -z "$LEAK_BG" ]]; then
    tc_pass "FlatMode: no .sandswap-bg-*.log leaked into flat SandFS volume"
else
    tc_fail "FlatMode: bg log leaked into SandFS: $LEAK_BG"
fi
if [[ -z "$LEAK_DBG" ]]; then
    tc_pass "FlatMode: no warden-dbg.log in flat SandFS volume"
else
    tc_fail "FlatMode: warden-dbg.log leaked into SandFS: $LEAK_DBG"
fi

# Also check the chrooted /tmp path the old code used (flat mode = $F_VOL/tmp).
if [[ -e "$F_VOL/tmp/.sandswap-bg-$BG_ID.log" ]]; then
    tc_fail "FlatMode: old leak path present: $F_VOL/tmp/.sandswap-bg-$BG_ID.log"
else
    tc_pass "FlatMode: old chrooted /tmp leak path absent"
fi

# Kill the bg exec so the mount releases and we move on. The kill does not
# instantly expire the LEASE (lease_duration=30 below), and the pool here is a
# SINGLE VM — SharedVolumesRoot's sync execs all 503'd until it expired. Wait
# (bounded) for the VM to come back CLEAN instead of sleeping blind.
tc_gw_kill "$F_KEY" "$F_SANDFS" "$BG_ID" >/dev/null 2>&1 || true
POOL_CLEAN=0
for _i in $(seq 1 45); do
    c=$(tc_stats_clean_vms 2>/dev/null | tr -d '[:space:]')
    if [[ -n "$c" && "$c" -ge "$POOL_SIZE" ]] 2>/dev/null; then POOL_CLEAN=1; break; fi
    sleep 1
done
if [[ "$POOL_CLEAN" -eq 1 ]]; then
    tc_log_pass "pool CLEAN again after bg-exec kill (${_i}s)"
else
    tc_log_warn "pool not CLEAN 45s after bg-exec kill — SharedVolumesRoot execs may 503"
fi

# ══════════════════════════════════════════════════════════════
# SharedVolumesRoot: shared volumes root — countdown debug log must never appear
# ══════════════════════════════════════════════════════════════
tc_log_section "SharedVolumesRoot: no warden-dbg.log in shared volumes root"

# Drive several sync execs (each triggers mount, heartbeat probes reset the
# countdown, the countdown task ticks every 1s). If the debug block were still
# present, $VOL_ROOT/warden-dbg.log would appear within a few ticks.
SYNC_FAILS=0
for n in 1 2 3 4 5; do
    R=$(gw_exec "$F_KEY" "$F_SANDFS" "echo tick$n")
    if [[ "$(http_code_of "$R")" != "200" ]]; then
        tc_log_warn "SharedVolumesRoot: sync exec #$n http=$(http_code_of "$R")"
        SYNC_FAILS=$((SYNC_FAILS + 1))
    fi
    sleep 1
done
# All five execs failing means NO heartbeat/countdown activity ran, so the
# warden-dbg.log absence check below would pass without exercising anything.
if [[ "$SYNC_FAILS" -ge 5 ]]; then
    tc_fail "SharedVolumesRoot: all 5 sync execs failed — countdown never exercised, absence check would be vacuous"
elif [[ "$SYNC_FAILS" -gt 0 ]]; then
    tc_log_warn "SharedVolumesRoot: $SYNC_FAILS/5 sync execs failed (enough succeeded to exercise the countdown)"
fi
# Let the sticky lease release + async unmount run (countdown keeps ticking).
sleep 3

if [[ -e "$VOL_ROOT/warden-dbg.log" ]]; then
    tc_fail "SharedVolumesRoot: warden-dbg.log leaked into shared volumes root: $VOL_ROOT/warden-dbg.log"
    tc_log_info "contents: $(cat "$VOL_ROOT/warden-dbg.log" 2>/dev/null | head -5)"
else
    tc_pass "SharedVolumesRoot: no warden-dbg.log in shared volumes root after countdown activity"
fi

# Re-check the flat volume dir after unmount: cleanup_bg_logs runs at unmount,
# but even before that the logs were never on the host. Assert still clean.
LEAK_AFTER=$(find_any "$F_VOL" '.sandswap-bg-*.log' | head -1 || true)
if [[ -z "$LEAK_AFTER" ]]; then
    tc_pass "SharedVolumesRoot: flat SandFS volume still clean of bg logs after unmount"
else
    tc_fail "SharedVolumesRoot: bg log present after unmount: $LEAK_AFTER"
fi

# ══════════════════════════════════════════════════════════════
# OverlayMode: overlay mode (best-effort) — same guarantee under overlay SandFS
# ══════════════════════════════════════════════════════════════
tc_log_section "OverlayMode: overlay mode bg-exec log isolation (best-effort)"

# Find an overlay-mode template registered with the gateway; skip if none.
OV_TPL=$(curl -s "$HUMAN_URL/human/templates" 2>/dev/null | python3 -c "
import sys,json
try: tpls=json.load(sys.stdin)
except Exception: print(''); raise SystemExit
for t in tpls:
    if (t.get('mode') or '') == 'overlay':
        n=t.get('name',''); v=t.get('version','')
        print(f'{n}:{v}' if v else n); break
else: print('')" 2>/dev/null || echo "")

if [[ -z "$OV_TPL" ]]; then
    skip "OverlayMode: no overlay template registered — SKIPPED (flat coverage from FlatMode/SharedVolumesRoot only)"
else
    tc_log_info "overlay template found: $OV_TPL"
    O_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs" -H "Content-Type: application/json" \
        -d "{\"agent_id\":\"$TC_AGENT_ID\",\"name\":\"log-iso-ov\",\"template\":\"$OV_TPL\",\"mode\":\"overlay\"}")
    O_SANDFS=$(echo "$O_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")
    O_VOL=$(echo "$O_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('rootfs_path',''))" 2>/dev/null || echo "")
    if [[ -z "$O_SANDFS" || -z "$O_VOL" ]]; then
        skip "OverlayMode: overlay sandfs create failed: $O_RESP — SKIPPED"
    else
        tc_log_info "overlay sandfs volume dir: $O_VOL"
        O_BG=$(gw_exec "$F_KEY" "$O_SANDFS" \
            'for i in 1 2 3; do echo ovline$i; sleep 1; done' \
            '"background":true,"lease_duration":30')
        O_BG_ID=$(body_of "$O_BG" | json_field "exec_id")
        if [[ -z "$O_BG_ID" ]]; then
            skip "OverlayMode: overlay bg exec start failed: $(body_of "$O_BG") — SKIPPED"
        else
            sleep 4
            O_ST=$(gw_status "$F_KEY" "$O_SANDFS" "$O_BG_ID")
            if echo "$O_ST" | json_field "stdout" | grep -q "ovline"; then
                tc_pass "OverlayMode: overlay bg exec log captured via status tail"
            else
                tc_fail "OverlayMode: overlay bg exec log not captured: $O_ST"
            fi
            # In overlay mode the read-only overlay is at $O_VOL/rootfs, and
            # workspace/home are $O_VOL/workspace, $O_VOL/home. None should hold
            # warden bg logs.
            O_LEAK_BG=$(find_any "$O_VOL" '.sandswap-bg-*.log' | head -1 || true)
            O_LEAK_DBG=$(find_any "$O_VOL" 'warden-dbg.log' | head -1 || true)
            [[ -z "$O_LEAK_BG" ]] \
                && tc_pass "OverlayMode: no .sandswap-bg-*.log in overlay SandFS dir" \
                || tc_fail "OverlayMode: bg log leaked into overlay SandFS: $O_LEAK_BG"
            [[ -z "$O_LEAK_DBG" ]] \
                && tc_pass "OverlayMode: no warden-dbg.log in overlay SandFS dir" \
                || tc_fail "OverlayMode: warden-dbg.log leaked into overlay SandFS: $O_LEAK_DBG"
            tc_gw_kill "$F_KEY" "$O_SANDFS" "$O_BG_ID" >/dev/null 2>&1 || true
            sleep 2
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════
# BGLogBound: the relay keeps only the configured tail and does NOT impose an
# RLIMIT_FSIZE on the agent's own files.
# ══════════════════════════════════════════════════════════════
tc_log_section "BGLogBound: flood bounded; large agent file untouched"

wait_bg() {
    local key=$1 sandfs=$2 id=$3 st
    for _ in $(seq 1 60); do
        st=$(gw_status "$key" "$sandfs" "$id")
        if [[ "$(echo "$st" | json_field "status")" != "running" ]]; then
            echo "$st"
            return 0
        fi
        sleep 1
    done
    return 1
}

BG=$(gw_exec "$F_KEY" "$F_SANDFS" \
    'timeout 6 yes 2>/dev/null; echo flood-done' \
    '"background":true,"lease_duration":60')
BG_ID=$(body_of "$BG" | json_field "exec_id")
if [[ -z "$BG_ID" ]]; then
    tc_fail "BGLogBound: flood bg exec start failed: $(body_of "$BG")"
else
    if ST=$(wait_bg "$F_KEY" "$F_SANDFS" "$BG_ID"); then
        TAIL=$(echo "$ST" | json_field "stdout")
        if echo "$TAIL" | grep -q "flood-done"; then
            tc_pass "BGLogBound: the tail keeps the LAST line after a yes-flood"
        else
            tc_fail "BGLogBound: flood tail lost the final line: $TAIL"
        fi
        TAIL_LEN=${#TAIL}
        if [[ "$TAIL_LEN" -le 9000 ]]; then
            tc_pass "BGLogBound: status tail bounded (${TAIL_LEN} bytes, cap 8192 + envelope)"
        else
            tc_fail "BGLogBound: status tail unbounded (${TAIL_LEN} bytes)"
        fi
    else
        tc_fail "BGLogBound: flood bg exec never finished (VM wedged?)"
    fi
    # The VM must still serve a sync exec: the flood must not have OOM'd it.
    ALIVE=$(gw_exec "$F_KEY" "$F_SANDFS" 'echo alive-after-flood' '')
    if body_of "$ALIVE" | grep -q "alive-after-flood"; then
        tc_pass "BGLogBound: VM still serves sync execs after the flood"
    else
        tc_fail "BGLogBound: VM died after the flood: $(body_of "$ALIVE")"
    fi
fi

BG=$(gw_exec "$F_KEY" "$F_SANDFS" \
    'dd if=/dev/zero of=/tmp/bgbig bs=1M count=8 2>/dev/null; echo size=$(wc -c </tmp/bgbig); rm -f /tmp/bgbig' \
    '"background":true,"lease_duration":60')
BG_ID=$(body_of "$BG" | json_field "exec_id")
if [[ -z "$BG_ID" ]]; then
    tc_fail "BGLogBound: large-file bg exec start failed: $(body_of "$BG")"
else
    if ST=$(wait_bg "$F_KEY" "$F_SANDFS" "$BG_ID"); then
        if echo "$ST" | json_field "stdout" | grep -q "size=8388608"; then
            tc_pass "BGLogBound: an 8 MiB agent file is uncut (no RLIMIT_FSIZE)"
        else
            tc_fail "BGLogBound: agent file was truncated: $(echo "$ST" | json_field "stdout")"
        fi
    else
        tc_fail "BGLogBound: large-file bg exec never finished"
    fi
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "Warden Log Isolation Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo "  SKIP: $SKIP_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo "[FAIL] Warden Log Isolation E2E FAILED"
    exit 1
fi
echo "[OK] Warden Log Isolation E2E PASSED"
exit 0
