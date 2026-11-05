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
# disconnect-tolerance.sh — Sandlot↔Gateway disconnect-resilience E2E (real KVM deployment)
# Covers the integration-check paths that unit tests cannot reach (see
# docs/how-it-works/resilience.md §8.1–§8.2):
#   FlashDisconnect  gateway blip: the stream connection is cut but the gateway stays alive → sandlot
#       enters TOLERATING, reconnects to the same gateway within seconds, ownership unchanged, exec works after recovery.
#   PartitionCleanup  partition lasting beyond T_tolerance: gateway unreachable for good → TOLERATING →
#       CLEANING (heartbeats stop, all mounts unmounted within the budget) → DONE → after T_isolation the
#       reconnect rebuilds the pool; agent data persists (files written before the partition read back after recovery).
#   WardenCountdown  warden countdown backstop: with a mount alive, kill -9 sandlot (no cleanup)
#       → heartbeats stop → warden POWER_OFFs at ~T_warden; the guest ACPI shutdown triggers
#       sandvmm process exit (serial.log as evidence) and the mount releases quickly with the VM's death.
#       If sandlot is not restarted the mount is already released; if restarted, the liveness probe fails → destroyAndReplace rebuilds.
#       Reverse invariant: while healthy, heartbeats keep resetting the countdown; a bg exec survives far beyond T_warden.
#   CountdownNoopOnCleanVM  mount_active guard: an already-unmounted CLEAN VM survives heartbeat silence
#       > T_warden (the countdown is a no-op) — complementary to WardenCountdown, proving the countdown
#       only executes a VM with a live mount and never kills a CLEAN VM by mistake. This is what lets a CLEAN VM
#       survive sandlot's isolation window (heartbeat silence may exceed T_warden) until the probe loop recovers after reconnect.
# Timing modes (the FAST switch):
#   The default FAST mode validates the same state machine with seconds-level timings. FAST timings violate the production floor
#   (T_tolerance/T_clean/T_warden each ≥ 300s — the production floor in docs/how-it-works/resilience.md),
#   so sandlot rejects short timings unless -allow-short-resilience-timings is passed explicitly. This script's
#   FAST mode adds that flag automatically (test-only); a production deployment must NEVER pass it, or the short timings
#   collapse the tolerance window and reintroduce the dual-mount race.
#   FULL=1 uses the production default timings (T_tolerance=T_clean=T_warden=300s — the real "disconnected longer
#   than 5 minutes" scenario; no -allow-short-resilience-timings; takes ~15-20 minutes).
# Prerequisites: built artifacts in output/, /dev/kvm, root, iptables, ss -K.
# Usage:   bash e2e/disconnect-tolerance.sh            # FAST (minutes, test-only)
#          FULL=1 bash e2e/disconnect-tolerance.sh     # production timings (~20min)

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
POOL_SIZE=1                     # One VM: unambiguous VM↔process mapping for the warden countdown
SANDLOT_POOL="small:${POOL_SIZE}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
STREAM_PORT="${STREAM_PORT:-9998}"

if [[ "${FULL:-0}" == "1" ]]; then
    # Production timings (defaults per docs/how-it-works/resilience.md)
    # Note: T_isolation=30s is intentionally BELOW T_safe(=tol+wd+60=660s). Those two timing invariants
    # (isolation>T_safe, T_safe>fence+wd+heartbeat) are only validated at gateway connect in exec mode
    # (ownership wired up); this script uses single-node mode (ownership=nil), so they do not fire.
    # If this topology moves to -mode exec, ISOLATION_SEC must rise and -etcd-fence-sec must shrink at the same time.
    TOLERANCE_SEC=300; CLEANUP_SEC=300; WARDEN_SEC=300; ISOLATION_SEC=30
    WARDEN_MAX_EXEC=0   # 0 = do not pass; warden uses its own default of 180s
    MODE_TAG="FULL (production timings 300/300/300)"
else
    # FAST timings: the same state machine, waits in seconds. The invariant T_clean <= T_warden holds.
    # warden clamps the countdown to max_exec_timeout (default 180s), so FAST mode
    # must also lower max_exec_timeout (every exec in this script is a seconds-level echo/cat).
    TOLERANCE_SEC="${TOLERANCE_SEC:-10}"
    CLEANUP_SEC="${CLEANUP_SEC:-5}"
    WARDEN_SEC="${WARDEN_SEC:-12}"
    ISOLATION_SEC="${ISOLATION_SEC:-6}"
    WARDEN_MAX_EXEC="${WARDEN_MAX_EXEC:-5}"
    MODE_TAG="FAST(${TOLERANCE_SEC}/${CLEANUP_SEC}/${WARDEN_SEC})"
fi

source "$ROOT/e2e/common.sh"

# Run directly from $OUTPUT (no separate deploy step) + shared template install.
tc_use_output_binaries
tc_install_flat_template

# gw_exec / http_code_of / body_of / clean_vms come from common.sh.
wait_clean() { # target timeout_s
    for _ in $(seq 1 $(($2 / 1))); do
        [[ "$(clean_vms)" -ge "$1" ]] 2>/dev/null && return 0
        sleep 1
    done
    return 1
}
# block_stream / unblock_stream — cut the sandlot→gateway gRPC stream with iptables
# (bidirectional DROP on loopback), simulating a gateway hang/partition without killing the process.
block_stream() {
    iptables -I OUTPUT -p tcp --dport "$STREAM_PORT" -j DROP 2>/dev/null
    iptables -I INPUT  -p tcp --sport "$STREAM_PORT" -j DROP 2>/dev/null
}
unblock_stream() {
    iptables -D OUTPUT -p tcp --dport "$STREAM_PORT" -j DROP 2>/dev/null || true
    iptables -D INPUT  -p tcp --sport "$STREAM_PORT" -j DROP 2>/dev/null || true
}
# Optional-args wrapper: most call sites invoke it bare; the "$@" tail exists
# for the ones that forward extras (SC2120 fires because none of THIS file's
# call sites currently do).
# shellcheck disable=SC2120
start_sandlot_short() {
    local extra=(-tolerance-sec "$TOLERANCE_SEC" \
                 -cleanup-sec "$CLEANUP_SEC" \
                 -warden-countdown-sec "$WARDEN_SEC" \
                 -isolation-sec "$ISOLATION_SEC" \
                 -warden-log debug)
    # ^ debug: this suite locates the bg-exec VM by grepping the warden's
    # serial.log for "start_exec … exec_id=<BG_ID>", which lives at debug
    # level (hot-path lines were demoted off info).
    [[ "$WARDEN_MAX_EXEC" -gt 0 ]] && extra+=(-warden-max-exec-timeout-sec "$WARDEN_MAX_EXEC")
    # FAST timings are sub-300s and would be rejected by the sandlot's production
    # floor check. Opt in explicitly: this flag is TEST/DEBUG ONLY and must never
    # appear in a production deployment.
    if [[ "${FULL:-0}" != "1" ]]; then
        extra+=(-allow-short-resilience-timings)
    fi
    # Caller extras (e.g. SaturationDetect's -max-concurrent-commands 2)
    # forward verbatim; existing no-arg call sites are unaffected.
    tc_start_sandlot "${extra[@]}" "$@"
}

# Pre-flight: hard fail (a missing KVM or a broken build must show up as a
# FAILED run, not as a silent exit-0 "skip" that CI reads as green).
tc_check_root
if [[ ! -e /dev/kvm ]] || [[ ! -r /dev/kvm ]]; then
    tc_log_error "/dev/kvm not available - this E2E requires KVM."
    tc_log_info "Run: sudo chmod 666 /dev/kvm   or add user to kvm group"
    exit 1
fi
if [[ ! -f "$OUTPUT/gateway" ]] || [[ ! -f "$OUTPUT/sandlot" ]] || [[ ! -f "$OUTPUT/sandvmm" ]]; then
    tc_log_error "build artifacts missing in output/. Run 'bash build/build.sh all' first."
    exit 1
fi

tc_log_section "Stream Resilience E2E [$MODE_TAG]"

tc_check_tools curl python3 iptables ss
# PRE-CLEAN: a SIGKILLed previous run leaves the OUTPUT/INPUT DROP rules in
# place (only this script's trap calls unblock_stream; tc_clean_environment
# does not touch iptables). Stale rules blackhole the new sandlot's stream and
# tc_wait_pool_ready then fails confusingly. Delete ALL matching rules —
# duplicates accumulate when unblock_stream raced a kill.
while iptables -D OUTPUT -p tcp --dport "$STREAM_PORT" -j DROP 2>/dev/null; do :; done
while iptables -D INPUT  -p tcp --sport "$STREAM_PORT" -j DROP 2>/dev/null; do :; done
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network
tc_attach_vsockguard

tc_start_gateway

cleanup() {
    unblock_stream
    tc_cleanup_default
    # Restore /etc/hosts (the DNS eviction from the GatewayIPDNSEviction section; if that section never ran there is no backup, so this is a no-op).
    if [[ -f /etc/hosts.sandswap-bak ]]; then
        cp /etc/hosts.sandswap-bak /etc/hosts
        rm -f /etc/hosts.sandswap-bak
    fi
}
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════
# FlashDisconnect: blip — cut the stream TCP connection, gateway stays alive
# ══════════════════════════════════════════════════════════════
tc_log_section "FlashDisconnect: blip (stream cut, recovery < T_tolerance)"

start_sandlot_short
tc_wait_health
tc_wait_pool_ready "$POOL_SIZE"
# SandFS creation is a stream RPC to the prov role (the sandlot started just
# above carries it — merged exec,prov): create AFTER the sandlot is up.
tc_create_agent_and_sandfs "stream-resil"

R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo f1-before && date > /workspace/f1-marker")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "FlashDisconnect: exec OK before flash-cut" \
    || tc_fail "FlashDisconnect: exec failed before flash-cut: $(body_of "$R")"

FLASH_METHOD=""
if ss -K state established "( sport = :$STREAM_PORT or dport = :$STREAM_PORT )" 2>/dev/null; then
    FLASH_METHOD="ss -K"
else
    tc_log_warn "ss -K unavailable; fallback: quick gateway restart (< T_tolerance)"
fi

if [[ "$FLASH_METHOD" == "ss -K" ]]; then
    # Wait for sandlot to notice the EOF and enter TOLERATING (driven by heartbeat/write timeout, seconds).
    # Budget = 2×T_tolerance: 0.5s × (4×TOL) iterations is the real 2×TOL seconds — the old form
    # (2×TOL iterations × 0.5s) actually only waited TOL seconds, half the budget the failure message claimed.
    SAW_TOL=0
    for _ in $(seq 1 $((TOLERANCE_SEC * 4))); do
        grep -q "entering TOLERATING" "$LOG_DIR/sandlot.log" && { SAW_TOL=1; break; }
        sleep 0.5
    done
    [[ $SAW_TOL -eq 1 ]] \
        && tc_pass "FlashDisconnect: sandlot entered TOLERATING after stream cut" \
        || tc_fail "FlashDisconnect: no TOLERATING within $((TOLERANCE_SEC * 2))s of stream cut"
else
    # fallback: kill the gateway and restart it immediately (< T_tolerance). MemoryStore loses agent
    # records; verify recovery after the rebuild.
    kill "${GATEWAY_PID:-}" 2>/dev/null || true
    wait "${GATEWAY_PID:-}" 2>/dev/null || true
    sleep 0.5
    tc_start_gateway
    tc_wait_health
    tc_create_agent_and_sandfs "stream-resil-f1"
fi

# Seconds-level recovery: reconnect to the same gateway within T_tolerance and exec works again. T_REC counts from the END of
# the detection phase — the old form counted from T_CUT, folding the detection wait (up to TOL seconds) into the recovery budget,
# so correct behavior on slow hosts was misjudged as a timeout. Detection itself is already covered by the previous step's budget.
T_REC_START=$(date +%s)
RECOVERED=0
for _ in $(seq 1 "$TOLERANCE_SEC"); do
    R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo f1-recovered" 2>/dev/null) || true
    if [[ "$(http_code_of "$R")" == "200" ]]; then RECOVERED=1; break; fi
    sleep 1
done
T_REC=$(( $(date +%s) - T_REC_START ))
if [[ $RECOVERED -eq 1 ]] && [[ $T_REC -le $TOLERANCE_SEC ]]; then
    tc_pass "FlashDisconnect: recovered in ${T_REC}s of retrying (< T_tolerance=${TOLERANCE_SEC}s), same gateway reconnected"
else
    tc_fail "FlashDisconnect: recovery took ${T_REC}s (recovered=$RECOVERED, tolerance=${TOLERANCE_SEC}s)"
fi

# A blip must not trigger cleanup: CLEANING must not appear
grep -q "entering CLEANING" "$LOG_DIR/sandlot.log" \
    && tc_fail "FlashDisconnect: unexpected CLEANING on flash disconnect" \
    || tc_pass "FlashDisconnect: no cleanup triggered by flash disconnect (tolerance-first)"

# ══════════════════════════════════════════════════════════════
# PartitionCleanup: partition beyond T_tolerance → CLEANING cleanup → recovery after the isolation window
# ══════════════════════════════════════════════════════════════
tc_log_section "PartitionCleanup: cleanup after partition timeout (TOLERATING → CLEANING → DONE)"

# Write a persistence marker before the partition (flat mode lands it directly in the agent volume directory)
R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo persistence-check > /workspace/f2-marker")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "PartitionCleanup: marker written before partition" \
    || tc_fail "PartitionCleanup: marker write failed: $(body_of "$R")"

T_DISC=$(date +%s)
block_stream
tc_log_info "stream blocked at t=0 (iptables DROP :$STREAM_PORT); T_tolerance=${TOLERANCE_SEC}s"

# TOLERATING must appear before CLEANING
SAW_CLEANING=0; SAW_DONE=0
T_CLEAN_DEADLINE=$(( T_DISC + TOLERANCE_SEC + CLEANUP_SEC + 60 ))
while [[ $(date +%s) -lt $T_CLEAN_DEADLINE ]]; do
    if grep -q "entering CLEANING" "$LOG_DIR/sandlot.log"; then SAW_CLEANING=1; fi
    if [[ $SAW_CLEANING -eq 1 ]] && grep -q "cleanup complete; entering DONE" "$LOG_DIR/sandlot.log"; then
        SAW_DONE=1; break
    fi
    sleep 1
done

[[ $SAW_CLEANING -eq 1 ]] \
    && tc_pass "PartitionCleanup: entered CLEANING after ToleranceSec expired" \
    || tc_fail "PartitionCleanup: never entered CLEANING (deadline ${T_CLEAN_DEADLINE}s)"
[[ $SAW_DONE -eq 1 ]] \
    && tc_pass "PartitionCleanup: cleanup completed within budget (entered DONE)" \
    || tc_fail "PartitionCleanup: cleanup did not complete (budget ${CLEANUP_SEC}s)"

# Cleanup evidence: cleanup-state.json should record done/deleted (the file the tolerance clock persists)
CS=/run/sandswap-state/default/cleanup-state.json
if [[ -f "$CS" ]]; then
    tc_log_info "cleanup-state.json: $(cat "$CS")"
else
    tc_log_info "cleanup-state.json removed after DONE (expected)"
fi

# Lift the block, wait out the isolation window, reconnect → pool rebuilt + data persists
unblock_stream
tc_log_info "stream unblocked; waiting ≤${ISOLATION_SEC}+60s isolation & reconnect..."
HEALED=0
for _ in $(seq 1 $((ISOLATION_SEC + 90))); do
    R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "cat /workspace/f2-marker" 2>/dev/null) || true
    if [[ "$(http_code_of "$R")" == "200" ]] && echo "$(body_of "$R")" | grep -q "persistence-check"; then
        HEALED=1; break
    fi
    sleep 2
done
if [[ $HEALED -eq 1 ]]; then
    tc_pass "PartitionCleanup: reconnected after isolation; agent data persisted across cleanup"
else
    tc_fail "PartitionCleanup: no recovery after unblock (clean=$(clean_vms))"
    tail -30 "$LOG_DIR/sandlot.log" || true
fi

# ══════════════════════════════════════════════════════════════
# WardenCountdown: the warden countdown backstop — kill -9 sandlot; warden POWER_OFFs at ~T_warden.
# The guest ACPI shutdown fires sandvmm's exit event → the sandvmm process exits → the mount releases (design intent:
# the mount releases with the VM's death; no dual-mount risk). This section asserts: sandvmm exits within ~T_warden (authoritative)
# + serial-log corroboration + the reverse invariant (heartbeat reset) + self-healing after restart.
# ══════════════════════════════════════════════════════════════
tc_log_section "WardenCountdown: warden countdown backstop (T_warden=${WARDEN_SEC}s)"

# Restart a clean sandlot (WardenCountdown needs a mounted state)
kill "${SANDLOT_PID:-}" 2>/dev/null || true
wait "${SANDLOT_PID:-}" 2>/dev/null || true
sleep 1
rm -f "$LOG_DIR/sandlot.log"
start_sandlot_short
wait_clean "$POOL_SIZE" 120 || tc_log_warn "pool not ready before the countdown phase; continuing"

# Key point: after a sync exec finishes, the ~100ms sticky lease expires and the gateway unmounts asynchronously,
# so at kill time the VM is already clean (the countdown is a no-op for clean VMs by design). A background exec must hold
# the lease and the mount — which is exactly the truly dangerous production case (a node dying under live load).
BG=$(curl -s -m 30 -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $TC_API_KEY" -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$TC_SANDFS_ID\",\"code\":\"sleep 300\",\"language\":\"shell\",\"background\":true,\"lease_duration\":600}")
BG_ID=$(echo "$BG" | python3 -c "import sys,json;print(json.load(sys.stdin).get('exec_id',''))" 2>/dev/null || echo "")
[[ -n "$BG_ID" ]] \
    && tc_pass "WardenCountdown: bg exec started ($BG_ID), mount+lease held open" \
    || tc_fail "WardenCountdown: bg exec failed to start: $BG"

sleep 2
ST=$(curl -s -m 15 -X POST "$GATEWAY_URL/agent/exec/status" \
    -H "Authorization: Bearer $TC_API_KEY" -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$TC_SANDFS_ID\",\"exec_id\":\"$BG_ID\"}")
echo "$ST" | grep -q '"running"' \
    && tc_pass "WardenCountdown: bg exec running (cgroup live => warden 'mounted' true)" \
    || tc_fail "WardenCountdown: bg exec NOT running before the kill (precondition) — countdown test would misattribute: $ST"

# Reverse invariant: while healthy, heartbeats (probe loop, every 3s) keep resetting the warden countdown —
# with the mount alive and heartbeats flowing, warden must survive past T_warden. The bg exec state is the evidence:
# if the countdown were not heartbeat-reset and fired at ~T_warden, warden would POWER_OFF and the bg exec status poll
# would fail (warden dead). So "bg exec still running after T_warden" proves the heartbeat resets the countdown.
T_HB_BASE=$(date +%s)
HOLD=$(( WARDEN_SEC + 4 ))
tc_log_info "Reverse invariant: heartbeats held for ${HOLD}s (> T_warden=${WARDEN_SEC}s); asserting bg exec still running..."
sleep "$HOLD"
ST2=$(curl -s -m 15 -X POST "$GATEWAY_URL/agent/exec/status" \
    -H "Authorization: Bearer $TC_API_KEY" -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$TC_SANDFS_ID\",\"exec_id\":\"$BG_ID\"}" 2>/dev/null) || true
HELD=$(( $(date +%s) - T_HB_BASE ))
# NB: HELD >= WARDEN_SEC holds by construction (we slept WARDEN_SEC+4), so the
# informative assertion is ONLY "bg exec still running" — the old conjunction's
# second half could never be false.
if echo "$ST2" | grep -q '"running"'; then
    tc_pass "WardenCountdown: heartbeat reset keeps warden alive beyond T_warden (bg exec still running after ${HELD}s > ${WARDEN_SEC}s)"
else
    tc_fail "WardenCountdown: bg exec not running after ${HELD}s (warden died under healthy heartbeats? status=$ST2) — countdown not reset?"
fi

# kill -9 sandlot: no cleanup, no last words; heartbeats stop → the warden countdown is the last line of defense.
# At this point the guest holds a live mount + a live cgroup (sleep 300 still running).
# First pin the VM carrying this bg exec (match the start_exec_id line in its
# console.log, the warden's hvc0 sink; serial.log is the earlyprintk fallback),
# then take that VM's sandvmm pid (from state.json). The countdown only executes the "mounted" VM —
# never pgrep an arbitrary sandvmm: the pool may hold several, and only the mounted one gets executed.
TARGET_SERIAL=""
for f in /run/sandswap/vm/*/console.log /run/sandswap/vm/*/serial.log; do
    if grep -q "start_exec.*exec_id=$BG_ID" "$f" 2>/dev/null; then TARGET_SERIAL="$f"; break; fi
done
TARGET_VMM_PID=""; TARGET_LOGS=()
if [[ -n "$TARGET_SERIAL" ]]; then
    VM_DIR="$(dirname "$TARGET_SERIAL")"
    TARGET_LOGS=("$VM_DIR/console.log" "$VM_DIR/serial.log")
    TARGET_VMM_PID=$(python3 -c "import os,json;d=json.load(open('/run/sandswap-state/default/'+os.path.basename('$VM_DIR')+'/state.json'));print(d.get('pid',''))" 2>/dev/null || echo "")
fi
[[ -n "$TARGET_VMM_PID" ]] \
    && tc_log_info "WardenCountdown: target VM log=$TARGET_SERIAL sandvmm pid=$TARGET_VMM_PID" \
    || tc_log_warn "WardenCountdown: could not pin target VM pid; will fall back to console/serial log evidence"

kill -9 "${SANDLOT_PID:-}" 2>/dev/null || true
T_KILL=$(date +%s)

# After the countdown fires, warden POWER_OFFs: the guest ACPI shutdown writes the S5 register → AcpiShutdownDevice
# fires exit_evt → sandvmm's control_loop exits → the sandvmm process exits → the virtio-fs connection drops
# → the mount releases. This is the direct implementation of the design intent "the mount releases with the VM's death"; no dual-mount risk.
# The positive assertion uses two pieces of evidence:
#   (a) the target sandvmm process exits within ~T_warden (authoritative — the necessary and sufficient condition for mount release; only the
#       target VM's pid is checked, never an arbitrary sandvmm, avoiding interference from other pool VMs)
#   (b) the console/serial logs show "warden countdown expired" / "reboot: Power down" (corroborates the cause)
VM_DIED=0; COUNTDOWN_FIRED=0
POLL_END=$(( T_KILL + WARDEN_SEC + 30 ))
while [[ $(date +%s) -lt $POLL_END ]]; do
    if [[ -n "$TARGET_VMM_PID" ]]; then
        kill -0 "$TARGET_VMM_PID" 2>/dev/null || VM_DIED=1
    else
        # Fallback: no pinned pid — infer from the logs (Power down printed) +
        # the target VM's logs going quiet. Less authoritative.
        if [[ ${#TARGET_LOGS[@]} -gt 0 ]]; then
            grep -q "reboot: Power down" "${TARGET_LOGS[@]}" 2>/dev/null && VM_DIED=1
        fi
    fi
    if [[ ${#TARGET_LOGS[@]} -gt 0 ]]; then
        grep -qE "warden countdown expired|reboot: Power down" "${TARGET_LOGS[@]}" 2>/dev/null && COUNTDOWN_FIRED=1
    fi
    [[ $VM_DIED -eq 1 ]] && break
    sleep 1
done
DELTA=$(( $(date +%s) - T_KILL ))
if [[ $VM_DIED -eq 1 ]]; then
    # Heartbeats run every 3s, so the last heartbeat before the kill is ≤3s old; the countdown fires within [T_warden-3, T_warden+margin].
    LO=$(( WARDEN_SEC / 2 )); HI=$(( WARDEN_SEC + 30 ))
    if [[ $DELTA -ge $LO ]] && [[ $DELTA -le $HI ]]; then
        tc_pass "WardenCountdown: sandvmm exited at +${DELTA}s after POWER_OFF (window ${LO}-${HI}s, T_warden=${WARDEN_SEC}s)"
    else
        tc_log_warn "WardenCountdown: sandvmm exited at +${DELTA}s (outside ${LO}-${HI}s window, non-fatal)"
    fi
    [[ $COUNTDOWN_FIRED -eq 1 ]] \
        && tc_pass "WardenCountdown: console/serial logs confirm warden countdown fired before exit" \
        || tc_log_warn "WardenCountdown: console/serial countdown line not found (VM exited anyway)"
else
    tc_fail "WardenCountdown: target sandvmm (pid=$TARGET_VMM_PID) did NOT exit within ${DELTA}s (countdown POWER_OFF failed)"
    # Dump the target VM's logs for diagnosis.
    [[ ${#TARGET_LOGS[@]} -gt 0 ]] && grep -E "countdown|Power down|panic|Attempted" "${TARGET_LOGS[@]}" 2>/dev/null | tail -3 || true
fi

# Self-healing after the backstop: a fresh sandlot starts → the pool rebuilds usable (the mount already released with sandvmm's exit).
start_sandlot_short
if wait_clean "$POOL_SIZE" 180; then
    R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo warden-countdown-recovered")
    [[ "$(http_code_of "$R")" == "200" ]] \
        && tc_pass "WardenCountdown: system self-heals after warden backstop (pool rebuilt, exec OK)" \
        || tc_fail "WardenCountdown: exec failed after backstop recovery: $(body_of "$R")"
else
    tc_fail "WardenCountdown: pool did not rebuild after backstop"
fi

# ══════════════════════════════════════════════════════════════
# CountdownNoopOnCleanVM: an already-unmounted CLEAN VM survives heartbeat silence > T_warden
#
# Reverse verification complementary to WardenCountdown: WardenCountdown proves "live mount + heartbeat silence
# → countdown fires POWER_OFF → the VM dies"; this section proves "already unmounted (mount_active=false)
# + heartbeat silence > T_warden → countdown no-op → the VM lives". Together they validate the mount_active
# guard: the countdown only executes a VM with a live mount and never kills a CLEAN VM by mistake — the key to
# sandlot not wasting warm VMs across disconnect → isolation → reconnect to a (possibly new) gateway (during isolation, heartbeat silence
# may exceed T_warden, but the CLEAN VM must survive until the probe loop recovers after reconnect).
# ══════════════════════════════════════════════════════════════
tc_log_section "CountdownNoopOnCleanVM: unmounted CLEAN VM survives heartbeat silence > T_warden"

# Precondition: make sure the pool is fully CLEAN (rebuilt at the end of WardenCountdown, but confirm once more).
wait_clean "$POOL_SIZE" 60 || tc_log_warn "CountdownNoopOnCleanVM: pool not fully CLEAN; continuing"

# Run one sync exec: mount → exec → sticky(100ms) expiry → gateway async OP_UNMOUNT
# → warden unmount_workspace → mount_active=false → VM back to CLEAN. This flips the VM from
# "mount_active=true" back to "mount_active=false" — the precondition state for this section.
R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo clean-vm-probe")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "CountdownNoopOnCleanVM: sync exec OK (will auto-unmount back to CLEAN)" \
    || tc_fail "CountdownNoopOnCleanVM: sync exec failed: $(body_of "$R")"

# Wait for the async unmount to finish and confirm the VM is back to CLEAN (mount_active=false). Within the timeout it must
# reach the target CLEAN count, otherwise the precondition does not hold and the later assertions are meaningless.
if ! wait_clean "$POOL_SIZE" 30; then
    tc_fail "CountdownNoopOnCleanVM: VM did not return to CLEAN within 30s (unmount incomplete; precondition not established)"
else
    tc_pass "CountdownNoopOnCleanVM: VM unmounted back to CLEAN (mount_active=false)"
fi

# Pin all current sandvmm pids (all CLEAN, all expected to survive). After sandlot is killed nobody sends
# heartbeats and the warden countdown starts running; if the mount_active guard failed, any VM would be POWER_OFFed at ~T_warden.
# Assert: after waiting > T_warden, all those pids are still alive + the serial logs show no new countdown lines.
# PID source: this run's state.json (tc_run_vm_pids) — pgrep -x sandvmm would also count any
# same-named process on the host (leftovers from earlier runs, parallel instances), polluting the survival/kill assertions.
CLEAN_PIDS="$(tc_run_vm_pids | tr '\n' ' ')"
CLEAN_COUNT=$(tc_run_vm_pids | wc -l)
tc_log_info "CountdownNoopOnCleanVM: CLEAN sandvmm pids=[$CLEAN_PIDS] (count=$CLEAN_COUNT)"
if [[ $CLEAN_COUNT -lt 1 ]]; then
    tc_fail "CountdownNoopOnCleanVM: no sandvmm to test (precondition failed)"
else
    # Pin the console/serial logs of the surviving VMs (matched by state.json
    # pid) and record the baseline countdown line count. Only these VMs' logs
    # are checked, so dead VMs left behind by the previous section
    # (WardenCountdown) cannot pollute the assertions. The baseline count feeds
    # a delta: with a correct guard, the kill must add no lines.
    declare -a TARGET_CLEAN_LOGS
    declare -A BASELINE_COUNT
    for pid in $CLEAN_PIDS; do
        vm_dir=""
        for st in /run/sandswap-state/default/*/state.json; do
            sp=$(python3 -c "import json;print(json.load(open('$st')).get('pid',''))" 2>/dev/null || echo "")
            [[ "$sp" == "$pid" ]] && { vm_dir="$(dirname "$st")"; break; }
        done
        if [[ -n "$vm_dir" ]]; then
            for lf in "$vm_dir/console.log" "$vm_dir/serial.log"; do
                [[ -f "$lf" ]] || continue
                TARGET_CLEAN_LOGS+=("$lf")
                BASELINE_COUNT["$lf"]=$(grep -cE "warden countdown expired|reboot: Power down" "$lf" 2>/dev/null) || true
            done
        fi
    done

    # kill -9 sandlot: heartbeats stop. All VMs are CLEAN at this point (mount_active=false).
    kill -9 "${SANDLOT_PID:-}" 2>/dev/null || true

    # Wait T_warden + margin: if the guard failed, the countdown should fire POWER_OFF within this window.
    SILENCE=$(( WARDEN_SEC + 6 ))
    tc_log_info "CountdownNoopOnCleanVM: heartbeat silence ${SILENCE}s (> T_warden=${WARDEN_SEC}s); asserting CLEAN VMs still alive..."
    sleep "$SILENCE"

    # Assertion 1: all originally-CLEAN sandvmm pids still alive (the mount_active guard prevented the kill).
    SURVIVED=0; DIED_PIDS=""
    for pid in $CLEAN_PIDS; do
        if kill -0 "$pid" 2>/dev/null; then SURVIVED=$((SURVIVED+1)); else DIED_PIDS="$DIED_PIDS $pid"; fi
    done
    if [[ $SURVIVED -eq $CLEAN_COUNT ]]; then
        tc_pass "CountdownNoopOnCleanVM: all $SURVIVED/$CLEAN_COUNT CLEAN VMs still alive after ${SILENCE}s of heartbeat silence (> T_warden=${WARDEN_SEC}s)"
    else
        tc_fail "CountdownNoopOnCleanVM: CLEAN VM killed (survived $SURVIVED/$CLEAN_COUNT, dead pids:$DIED_PIDS) — mount_active guard failed?"
    fi

    # Assertion 2: the surviving VMs' console/serial logs show no new countdown / Power down (with a correct guard, the countdown is a no-op).
    # Judged by delta (count after kill − baseline), excluding historical leftover lines.
    NEW_COUNTDOWN=0
    for f in "${TARGET_CLEAN_LOGS[@]}"; do
        # grep -c exits 1 (and prints "0") when there are no matches; capture
        # stdout first, then fall back to 0 on non-zero exit to avoid "0\n0".
        after=$(grep -cE "warden countdown expired|reboot: Power down" "$f" 2>/dev/null) || after=0
        before="${BASELINE_COUNT[$f]:-0}"
        if [[ "$after" -gt "$before" ]]; then NEW_COUNTDOWN=1; break; fi
    done
    [[ $NEW_COUNTDOWN -eq 0 ]] \
        && tc_pass "CountdownNoopOnCleanVM: surviving VMs' console/serial logs show no new countdown traces (mount_active=false makes the countdown a no-op)" \
        || tc_fail "CountdownNoopOnCleanVM: surviving VMs' console/serial logs show new countdown expired / Power down (CLEAN VM executed by mistake)"
fi

# This section killed sandlot; restore a clean sandlot for any following sections/cleanup (the trap also backstops).
start_sandlot_short
wait_clean "$POOL_SIZE" 120 || tc_log_warn "CountdownNoopOnCleanVM: pool not rebuilt at the end (non-fatal; the trap backstops)"

# ══════════════════════════════════════════════════════════════
# GatewayIPDNSEviction: gateway restart on a new IP / endpoint propagation delay — TOLERATING dials the remembered IP
# (see docs/how-it-works/resilience.md)
#
# Fault: after sandlot records preferredIP, a gateway restart can hit a k8s endpoint-propagation window that drops the
# old IP from the Service DNS answer. The old logic required "DNS must still list preferredIP as a candidate before dialing",
# so it refused to dial and idled through the whole T_tolerance (then destroyed every VM and waited out T_isolation before returning to the
# same gateway). Fix: during TOLERATING, dial the remembered IP directly — the no-switch rule itself (dial preferredIP only,
# never another IP) is already the safety guarantee; re-checking DNS adds no safety.
#
# Trigger lever: temporarily point localhost in /etc/hosts at a non-existent IP. sandlot's TLS
# ServerName is always the host of gateway-addr (localhost; the certificate SAN matches), and after the fix, dialing preferredIP does not depend on localhost resolving —
# this isolates exactly the "remembered IP absent from the DNS answer" case:
#   localhost → 127.0.0.1   (connected; preferredIP=127.0.0.1)
#   localhost → 10.255.255.1 (127.0.0.1 no longer in the DNS answer)
#   ss -K cuts the stream → TOLERATING; assert sandlot still dials 127.0.0.1 to reconnect and does not idle into CLEANING.
# ══════════════════════════════════════════════════════════════
tc_log_section "GatewayIPDNSEviction: TOLERATING dials the remembered IP"

# Reuse the currently running main sandlot (just restarted by the previous section, fresh log, preferredIP=127.0.0.1) and only
# do the "DNS eviction" at the /etc/hosts level. The EXIT trap's cleanup() also restores /etc/hosts as a backstop.
HOSTS_BAK="/etc/hosts.sandswap-bak"
if [[ ! -f "$HOSTS_BAK" ]]; then
    cp /etc/hosts "$HOSTS_BAK"
fi
restore_hosts() {
    [[ -f "$HOSTS_BAK" ]] && cp "$HOSTS_BAK" /etc/hosts
}

# Baseline: sandlot is connected and serving (gw_exec uses localhost HTTP, still pointing at 127.0.0.1).
R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo dns-evict-baseline" 2>/dev/null) || true
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "GatewayIPDNSEviction: sandlot connected (exec OK), preferredIP=127.0.0.1" \
    || tc_fail "GatewayIPDNSEviction: baseline exec failed: $(body_of "$R")"

# Record the baseline: the count of "connecting 127.0.0.1" lines in this sandlot instance's log.
BASE_DIAL_127=$(grep -c "connecting to gateway at 127.0.0.1:$STREAM_PORT" "$LOG_DIR/sandlot.log" 2>/dev/null) || BASE_DIAL_127=0

# Simulate the DNS eviction: temporarily point localhost at a non-existent IP — preferredIP(127.0.0.1) is no longer in
# the DNS answer. This is exactly the trigger condition for that gap (armed before the stream is cut, so the reconnect hits it).
sed -i '/^127\.0\.0\.1[[:space:]]\+localhost$/d' /etc/hosts
echo "10.255.255.1 localhost   # sandswap-dns-evict-test" >> /etc/hosts
# VERIFY the rewrite: on hosts with extra aliases ("127.0.0.1 localhost.localdomain
# localhost", "::1 localhost") the exact-line sed above removes nothing and
# localhost still resolves to 127.0.0.1 — the "preferredIP not in DNS" precondition
# never holds and the section passes with the bug present.
if getent hosts localhost 2>/dev/null | grep -q '127\.0\.0\.1'; then
    tc_fail "GatewayIPDNSEviction: /etc/hosts rewrite ineffective (localhost still resolves to 127.0.0.1) — precondition NOT established"
else
    tc_pass "GatewayIPDNSEviction: localhost no longer resolves to 127.0.0.1 (DNS eviction in effect)"
fi

# Cut the stream (ss -K kills established connections; the gateway survives). localhost no longer resolves to 127.0.0.1,
# so sandlot's reconnect can only take the "dial the remembered IP" branch; the old logic would have refused to dial.
ss -K state established "( sport = :$STREAM_PORT or dport = :$STREAM_PORT )" 2>/dev/null || true
DNS_SAW_TOL=0
for _ in $(seq 1 $((TOLERANCE_SEC * 4))); do
    grep -q "entering TOLERATING" "$LOG_DIR/sandlot.log" 2>/dev/null && { DNS_SAW_TOL=1; break; }
    sleep 0.5
done
[[ $DNS_SAW_TOL -eq 1 ]] \
    && tc_pass "GatewayIPDNSEviction: entered TOLERATING after the stream was cut (localhost no longer resolves to 127.0.0.1)" \
    || tc_fail "GatewayIPDNSEviction: did not enter TOLERATING within $((TOLERANCE_SEC * 2))s"

# Assert: while TOLERATING, dialing the remembered IP 127.0.0.1 reconnects successfully (one more "connecting 127.0.0.1" than baseline).
# The old logic would have refused to dial ("preferred gateway not in DNS") → the count does not rise → the refusal assertion below fires.
DNS_RECOVERED=0
for _ in $(seq 1 "$TOLERANCE_SEC"); do
    CUR=$(grep -c "connecting to gateway at 127.0.0.1:$STREAM_PORT" "$LOG_DIR/sandlot.log" 2>/dev/null) || CUR=0
    if [[ "$CUR" -gt "$BASE_DIAL_127" ]]; then DNS_RECOVERED=1; break; fi
    sleep 1
done
[[ $DNS_RECOVERED -eq 1 ]] \
    && tc_pass "GatewayIPDNSEviction: with preferredIP absent from the DNS answer, TOLERATING still dials the remembered IP 127.0.0.1 to reconnect" \
    || { tc_fail "GatewayIPDNSEviction: did not reconnect via the remembered IP (may be idling into CLEANING)"; tail -30 "$LOG_DIR/sandlot.log" || true; }

# Reverse assertions (regression anchors): the old logic's dial refusal must not appear, and it must not enter CLEANING.
if grep -q "preferred gateway.*not in DNS\|holding affinity" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    tc_fail "GatewayIPDNSEviction: 'preferred gateway not in DNS' dial-refusal log still present (fix not effective)"
else
    tc_pass "GatewayIPDNSEviction: no 'preferred gateway not in DNS' dial-refusal log (fix effective)"
fi
if grep -q "entering CLEANING" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    tc_fail "GatewayIPDNSEviction: entered CLEANING by mistake (should recover within seconds by dialing the remembered IP, without cleanup)"
else
    tc_pass "GatewayIPDNSEviction: did not enter CLEANING (dials the remembered IP and recovers within seconds; tolerance-first)"
fi

# Restore /etc/hosts. sandlot has reconnected (the fix path dials 127.0.0.1 directly); the restore does not disturb the live connection.
restore_hosts
wait_clean "$POOL_SIZE" 60 || tc_log_warn "GatewayIPDNSEviction: pool not ready at the end (non-fatal; the trap backstops)"

# ══════════════════════════════════════════════════════════════
# SaturationDetect: disconnect detection under a full cmdSem (regression anchor).
#
# Property under test: runServeLoop's cmdSem acquire changed from a bare blocking send to
# select {acquire, Done, ctx.Done}. The old code's failure signature: all slots held by long commands
# + the N+1th command already arrived → the serve loop parks on acquire → when the stream dies, the
# loop cannot reach the Done branch → "entering TOLERATING" is delayed until the longest command finishes.
# New code: the parked acquire itself selects on Done and returns immediately after EOF.
#
# Design — four premises, each with evidence observable inside the test, no assumptions:
# ① The 3rd command parks the loop: -max-concurrent-commands 2 + 3 concurrent execs on [DIFFERENT
#    sandfs instances] (3-VM pool; one-SandFS-one-microVM binds each to its own VM). It must span
#    sandfs instances: the gateway serializes cold mounts of the same sandfs behind a per-sandfs MountLock
#    (execute.go "needsColdMount := !leaseHit") — while sleep-60 is in flight, the lease
#    is never established, so later requests for the same sandfs all queue at the gateway and are never dispatched — the
#    single-sandfs variant was A/B-verified against the old code as a vacuous pass (the old code also passed in 267ms).
#    Evidence = three curls hanging simultaneously (≥3s without a response): their MountLocks do not block each other,
#    the gateway dispatches on receipt, and curl hanging ⟺ the command reached sandlot ⟺ the cmdSem token is
#    held (the token is held from dispatch until the response returns; no reliance on warden log formats).
#    (With only 2 commands, the old code also does not park — no discriminating power.)
# ② The placeholder outlasts the assertion threshold: sleep 60 + explicit timeout. warden's
#    max_exec_timeout is baked into the guest kernel cmdline (fixed at VM start); FAST mode's
#    5s clamp would cut the placeholder off at 5s — so this section first kills sandvmm to force a full pool
#    rebuild, then starts sandlot with explicit flags [without -warden-max-exec-timeout-sec],
#    and greps sandvmm's /proc/cmdline to prove max_exec_timeout=5 is absent.
# ③ The cut deterministically produces EOF: kill -9 gateway (process death → kernel closes the socket →
#    readLoop EOFs immediately). Not ss -K (this host's kernel lacks INET_DIAG_DESTROY; it fails silently);
#    not an iptables DROP (no EOF; detection latency at the mercy of keepalive).
#    After the gateway dies, this suite no longer needs it through Summary; the trap cleans up.
# ④ A discriminating assertion: the new code shows TOLERATING within ~1s of the EOF (poll granularity 250ms);
#    the old code waits for slot release (sleep 60 ends ≈ 50s+ after the cut). Window 20s, threshold
#    15s — margins >2× on both sides.
# ══════════════════════════════════════════════════════════════
tc_log_section "SaturationDetect: disconnect detection under a full cmdSem is not delayed by long commands"

# Counting helper: grep -c prints 0 itself and exits 1 on no match, so `|| true` suffices;
# a missing file yields empty output, covered by ${n:-0}. NEVER use `|| echo 0` (you would get "0\n0").
sat_tol_count() {
    local n
    n=$(grep -c "entering TOLERATING" "$LOG_DIR/sandlot.log" 2>/dev/null || true)
    echo "${n:-0}"
}
# Millisecond clock: bash≥5's EPOCHREALTIME (µs floating-point string). Not date +%s%3N — this repo's
# CI host once shipped uutils coreutils, whose %s%3N combined format printed garbage large numbers.
sat_now_ms() {
    local t=${EPOCHREALTIME/./}
    echo $(( t / 1000 ))
}
# ── A. Rebuild the environment: fresh VM (no 5s warden clamp) + rate-limited sandlot ──
tc_log_step "A: kill sandlot + sandvmm, rebuild with explicit flags (fresh VM, no warden-max-exec clamp)..."
# First pin this run's sandvmm processes (state.json is this run's authoritative record; the tc_clean_environment
# at the top of the script already cleared /run/sandswap, so everything listed belongs to this run).
# Must capture BEFORE killing sandlot: once sandlot dies, these processes are adopted by init, the parent-child
# relationship disappears, and enumeration would fall back to pgrep by name — which would also kill same-named host processes.
mapfile -t SAT_OLD_VMS < <(tc_run_vm_pids)
kill "${SANDLOT_PID:-}" 2>/dev/null || true
wait "${SANDLOT_PID:-}" 2>/dev/null || true
if (( ${#SAT_OLD_VMS[@]} > 0 )); then
    kill "${SAT_OLD_VMS[@]}" 2>/dev/null || true
fi
# Deterministically wait for the processes to really exit (hard-earned lesson: under nested virtualization sandvmm can take >1s to exit —
# while the old process is still around, its vhost-vsock CID binding is held, and the new sandlot's CID counter,
# starting fresh, allocates CID 3 again → VHOST_VSOCK_SET_GUEST_CID EADDRINUSE → the pool-rebuild loop wedges,
# and sandlot reports "no available VM on node" (true at that point). Wait + SIGKILL escalation +
# settle — all three stages complete before continuing.
sat_vms_alive() {
    local p
    for p in "${SAT_OLD_VMS[@]:-}"; do
        kill -0 "$p" 2>/dev/null && return 0
    done
    return 1
}
SAT_VM_GONE=0
for i in $(seq 1 30); do
    if ! sat_vms_alive; then
        SAT_VM_GONE=1
        break
    fi
    sleep 0.5
done
if [[ "$SAT_VM_GONE" -ne 1 ]]; then
    tc_log_warn "A: sandvmm did not exit within 15s; escalating to SIGKILL"
    if (( ${#SAT_OLD_VMS[@]} > 0 )); then
        kill -9 "${SAT_OLD_VMS[@]}" 2>/dev/null || true
    fi
    for i in $(seq 1 10); do
        sat_vms_alive || { SAT_VM_GONE=1; break; }
        sleep 0.5
    done
fi
sleep 2   # vhost-vsock CID release settle (fds close as soon as the process is gone; 2s is jitter margin)
# Clear the sandbox directory: a leftover state.json points at a dead VMM; let re-adopt go straight to its judged-dead cleanup,
# and the pool pre-creates fresh from the new cmdline (one less wait than "relying on Ping failure to judge death").
rm -rf /run/sandswap/vm /run/sandswap-state/default

# warden-countdown uses 300 (the production value) instead of FAST's $WARDEN_SEC: the countdown is also
# sandlot's read-timeout ceiling for warden RPCs (the execReadTimeout cap) — FAST's 12s
# would read-timeout the sleep-60 placeholder at ~12s, releasing the token early, and the old code would then also
# "detect" the disconnect within the window (old-code A/B measured a 3.1s pass = vacuous pass). With countdown=300,
# the read timeout = min(60+30, 300) = 90s, so the old code can only wait for the exec to actually finish (~51s after the cut,
# A/B measured 51342ms) → guaranteed FAIL outside the 20s window; the new code passes instantly. The invariant
# T_clean(5) ≤ T_warden(300) still holds.
SAT_EXTRA=(-tolerance-sec "$TOLERANCE_SEC"
           -cleanup-sec "$CLEANUP_SEC"
           -warden-countdown-sec 300
           -isolation-sec "$ISOLATION_SEC"
           -warden-log debug
           -max-concurrent-commands 2)
if [[ "${FULL:-0}" != "1" ]]; then
    SAT_EXTRA+=(-allow-short-resilience-timings)
fi
# Pool = 3: three sandfs each bound to one VM (cmdSem=2 → the 3rd command parks). tc_start_sandlot
# reads the pool spec from $SANDLOT_POOL; temporarily overridden here (the suite no longer depends on the pool size at the end).
SANDLOT_POOL_SAVE="$SANDLOT_POOL"
SANDLOT_POOL="small:3"
tc_start_sandlot "${SAT_EXTRA[@]}"
SANDLOT_POOL="$SANDLOT_POOL_SAVE"
# SANDLOT_PID is the $! recorded by tc_start_sandlot (a process this script started itself) — NEVER
# overwrite it by reverse-lookup with pgrep -f: any other sandlot on the host (leftovers/parallel instances) would make head -1
# pin the wrong process, and the cmdline self-check below and the later kill would hit the wrong target.
tc_wait_pool_ready 3

# Premise self-checks (FAIL, not WARN — this phase's meaning depends on both):
# (1) the sandlot rate-limit flag is really on the cmdline;
# (2) no surviving sandvmm's cmdline contains the warden short timeout (the placeholder cannot be cut at 5s).
SAT_SETUP_OK=1
SAT_SL_CMDLINE=""
if [[ -n "$SANDLOT_PID" ]]; then
    SAT_SL_CMDLINE=$(tr '\0' ' ' < "/proc/$SANDLOT_PID/cmdline" 2>/dev/null || true)
fi
if [[ "$SAT_SL_CMDLINE" == *"-max-concurrent-commands 2"* ]] \
   && [[ "$SAT_SL_CMDLINE" != *"warden-max-exec-timeout"* ]]; then
    tc_pass "A: sandlot cmdline self-check (-max-concurrent-commands 2, no warden-max-exec clamp)"
else
    tc_fail "A: sandlot cmdline mismatch (rate-limit/timeout premise not established): ${SAT_SL_CMDLINE:-<unreadable>}"
    SAT_SETUP_OK=0
fi
# The warden's kernel cmdline is assembled by the sandlot and PRINTED by the
# launcher ("launching VMM: … cmdline=[…]", sandlot/vmm/launcher.go
# buildCmdline) — it is NOT in sandvmm's argv (/proc/<sandvmm>/cmdline carries
# only --kernel/--initramfs PATHS), so the old sandvmm-cmdline grep could never
# match and passed vacuously. Grep the log, with a POSITIVE CONTROL: SAT_EXTRA
# passes -warden-countdown-sec 300, which must appear on the same cmdline=
# lines — only then does "max_exec_timeout=5 absent" mean the clamp is gone.
SAT_CTRL=$(grep -c 'cmdline=\[.*warden\.warden_countdown_sec=300' "$LOG_DIR/sandlot.log" 2>/dev/null || true)
SAT_BAD_VM=$(grep -cE 'cmdline=\[.*warden\.max_exec_timeout=5([^0-9]|$)' "$LOG_DIR/sandlot.log" 2>/dev/null || true)
if [[ "${SAT_CTRL:-0}" -lt 3 ]]; then
    tc_fail "A: positive control failed — ${SAT_CTRL:-0} post-restart launch line(s) carry warden_countdown_sec=300 (log unread or VMs not relaunched); the absence check would be vacuous"
    SAT_SETUP_OK=0
elif [[ "${SAT_BAD_VM:-0}" -ne 0 ]]; then
    tc_fail "A: a VM was launched with the 5s warden timeout ($SAT_BAD_VM launch line(s)) — the placeholder would be cut early; discriminating power lost"
    SAT_SETUP_OK=0
else
    tc_pass "A: all 3 pool VMs relaunched without the 5s clamp ($SAT_CTRL launch lines with warden_countdown_sec=300)"
fi

# ── B. Preconditions: sanity → wait CLEAN → three placeholder commands (staggered + evidenced) ──
SAT_PRE_OK=0
if [[ "$SAT_SETUP_OK" -eq 1 ]]; then
    # Bounded retry for the sanity exec: the node was just rebuilt (all sandvmm killed + reconnect) and the gateway's
    # capacity/mount bookkeeping needs a heartbeat or two to converge; the first request often returns a retryable
    # NO_AVAILABLE_SANDBOX (1s interval) — a single shot without retries would misreport the settle window as a failure.
    SAT_R=""
    for try in $(seq 1 10); do
        SAT_R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo sat-before")
        [[ "$(http_code_of "$SAT_R")" == "200" ]] && break
        sleep 2
    done
    if [[ "$(http_code_of "$SAT_R")" == "200" ]]; then
        tc_pass "B: exec works after the rate-limited restart (including the settle retry)"
    else
        tc_fail "B: exec did not recover within 20s after the rate-limited restart: $(body_of "$SAT_R")"
        # Forensics: NO_AVAILABLE has two production paths — the gateway's selectNode refusal (log shows
        # "no available sandbox on node; retry on another" with nothing dispatched) or a sandlot
        # error mapping (gateway log shows a MountRootfsAndExecute failure + "no available VM").
        # The two need completely different remedies; localize first, then fix.
        tc_log_info "B: gateway no-available context (last 8 lines):"
        grep -E "no available|selected node|MountRootfsAndExecute" "$LOG_DIR/gateway.log" 2>/dev/null | tail -8 || true
        tc_log_info "B: /stats: $(curl -s -m 5 "$HUMAN_URL/stats" 2>/dev/null | head -c 500)"
        tc_log_info "B: tail of sandlot.log:"
        tail -8 "$LOG_DIR/sandlot.log" 2>/dev/null || true
    fi
    # The sanity exec's lease expiry triggers an async unmount; wait for the VMs to return to CLEAN before launching placeholders,
    # so the mount/unmount race cannot turn a placeholder into a retryable error (the source of earlier SANDBOX_CLEANING rounds).
    wait_clean 3 30 || tc_log_warn "B: VMs not all CLEAN after sanity; placeholders may hit an unmount window"

    # Three sandfs: agent A is the suite's existing one; B/C are created now (the gateway is still up; creation is
    # a pure control-plane operation, sandlot not involved). The three sandfs cold mounts each hold an independent
    # MountLock → the three RPCs are truly dispatched concurrently (the premise of this phase's discriminating power).
    SAT_AGENT_B=$(tc_create_agent_and_sandfs "sat-b")
    SAT_AGENT_C=$(tc_create_agent_and_sandfs "sat-c")
    SAT_KEY_B=$(echo "$SAT_AGENT_B" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
    SAT_SID_B=$(echo "$SAT_AGENT_B" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")
    SAT_KEY_C=$(echo "$SAT_AGENT_C" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
    SAT_SID_C=$(echo "$SAT_AGENT_C" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")
    if [[ -z "$SAT_KEY_B" ]] || [[ -z "$SAT_KEY_C" ]]; then
        tc_fail "B: auxiliary agent creation failed (b=$SAT_AGENT_B c=$SAT_AGENT_C)"
    fi

    # Placeholder curl: sleep 60 + explicit timeout 120s; -m 90 covers the whole span.
    # Retryable errors it returns (cleaning window/concurrent mount) are re-sent with bounds; surviving 3s is taken as
    # accepted by the gateway and parked on the stream (rejected requests return in milliseconds).
    sat_launch() { # $1 = key, $2 = sandfs_id, $3 = outfile; emits the curl pid
        local key="$1" sid="$2" out="$3" pid try resp
# shellcheck disable=SC2034  # poll loop counter
        for try in 1 2 3 4 5; do
            curl -s -m 90 -X POST "$GATEWAY_URL/agent/execute" \
                -H "Authorization: Bearer $key" \
                -H "Content-Type: application/json" \
                -d "{\"sandfs_id\":\"$sid\",\"code\":\"sleep 60\",\"language\":\"shell\",\"timeout\":120000}" \
                > "$out" 2>&1 &
            pid=$!
            sleep 3
            if kill -0 "$pid" 2>/dev/null; then
                echo "$pid"
                return 0
            fi
            resp=$(head -c 200 "$out" 2>/dev/null || true)
            if echo "$resp" | grep -qE '"(NO_AVAILABLE_SANDBOX|NO_COMPUTE_NODES|CONCURRENT_MOUNT|SANDBOX_CLEANING)"'; then
                sleep 2
                continue
            fi
            echo "$pid"   # non-retryable fast failure: let the liveness assertion report it
            return 0
        done
        echo ""
    }

    # Dispatch one by one (sat_launch has the "alive for 3s = parked" check built in); the three target three
    # different sandfs instances; then, right before the cut, assert all three hang simultaneously.
    SAT_C1=$(sat_launch "$TC_API_KEY" "$TC_SANDFS_ID" "$LOG_DIR/sat-c1.json")
    SAT_C2=$(sat_launch "$SAT_KEY_B" "$SAT_SID_B" "$LOG_DIR/sat-c2.json")
    # cmd3: the third command — the one that parks the serve loop on the cmdSem acquire.
    SAT_C3=$(sat_launch "$SAT_KEY_C" "$SAT_SID_C" "$LOG_DIR/sat-c3.json")

    SAT_ALIVE=0
    if [[ -n "$SAT_C1" ]] && [[ -n "$SAT_C2" ]] && [[ -n "$SAT_C3" ]] \
       && kill -0 "$SAT_C1" 2>/dev/null && kill -0 "$SAT_C2" 2>/dev/null \
       && kill -0 "$SAT_C3" 2>/dev/null; then
        SAT_ALIVE=1
    fi
    if [[ "$SAT_ALIVE" -ne 1 ]]; then
        tc_fail "B: the three placeholder commands did not all hang (c1='$SAT_C1' c2='$SAT_C2' c3='$SAT_C3') — the cmdSem-parking premise does not hold; the cut measurement is meaningless; c1=$(head -c 120 "$LOG_DIR/sat-c1.json" 2>/dev/null) c2=$(head -c 120 "$LOG_DIR/sat-c2.json" 2>/dev/null) c3=$(head -c 120 "$LOG_DIR/sat-c3.json" 2>/dev/null)"
    else
        tc_pass "B: the three placeholder commands hang simultaneously — 2 slots held + the 3rd parked; the cmdSem-parking premise holds"
        SAT_PRE_OK=1
    fi
fi

# ── C. Cut + assert ──
if [[ "$SAT_PRE_OK" -eq 1 ]]; then
    SAT_BASE_TOL=$(sat_tol_count)
    T_CUT_MS=$(sat_now_ms)
    kill -9 "${GATEWAY_PID:-}" 2>/dev/null || true
    wait "${GATEWAY_PID:-}" 2>/dev/null || true
    tc_log_info "C: gateway SIGKILL at t=0 (deterministic EOF cut)"

    SAT_SEEN=0
    SAT_DETECT_MS=-1
# shellcheck disable=SC2034  # poll loop counter
    for i in $(seq 1 80); do
        sleep 0.25
        if [[ "$(sat_tol_count)" -gt "$SAT_BASE_TOL" ]]; then
            SAT_DETECT_MS=$(( $(sat_now_ms) - T_CUT_MS ))
            SAT_SEEN=1
            break
        fi
    done
    # The three curls error out on their own as the gateway dies; no need to wait.
    kill "${SAT_C1:-}" "${SAT_C2:-}" "${SAT_C3:-}" 2>/dev/null || true

    if [[ "$SAT_SEEN" -eq 1 ]] && [[ "$SAT_DETECT_MS" -lt 15000 ]]; then
        tc_pass "C: under full load (2/2 slots + the 3rd parked), entered TOLERATING within ${SAT_DETECT_MS}ms (< 15s; the old blocking implementation waited for sleep-60 to end ≈ 50s+ after the cut)"
    else
        tc_fail "C: disconnect detection under full load failed (seen=$SAT_SEEN, ${SAT_DETECT_MS}ms) — is the serve loop still blocked by long commands?"
        tc_log_info "C: evidence — tail of sandlot.log:"
        tail -15 "$LOG_DIR/sandlot.log" 2>/dev/null || true
        tc_log_info "C: evidence — placeholder responses: c1=$(head -c 150 "$LOG_DIR/sat-c1.json" 2>/dev/null) c2=$(head -c 150 "$LOG_DIR/sat-c2.json" 2>/dev/null) c3=$(head -c 150 "$LOG_DIR/sat-c3.json" 2>/dev/null)"
    fi
else
    tc_log_warn "C: premise not established; skipping the cut measurement (the upstream step already FAILED with evidence)"
fi
# The gateway is dead and sandlot is in its resilience flow — the suite no longer needs any process through Summary;
# cleanup is left entirely to the trap (tc_cleanup_default).

# ══════════════════════════════════════════════════════════════
tc_log_section "Stream Resilience Summary [$MODE_TAG]"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo "[FAIL] Stream Resilience E2E FAILED"
    exit 1
fi
echo "[OK] Stream Resilience E2E PASSED"
exit 0
