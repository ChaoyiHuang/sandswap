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
# vmm-crash-selfheal.sh — Sandswap VMM crash detection & orphan cleanup E2E
# Covers the two sandlot paths that unit tests cannot reach (they require real
# KVM processes):
#   VmmCrashDetect  sandvmm crash detection -> handleVMDied -> destroy-and-replace self-heal
#       (monitor.go: monitorVMCore/pidfd monitor/handleVMDied; pool.go:
#       destroyAndReplaceVM)
#   RecycleCleanup  pool scale-down must destroy the excess sandvmm PROCESS +
#       remove its state/dir (pins the destroy-kill regression in
#       embeddedManager.DestroyVM — the old map re-lookup skipped the kill)
#   OrphanSweep  orphan sandvmm sweep on restart: a sandvmm process whose --api-socket
#       is NOT referenced by any state.json is killed by killOrphanSandvmmStatic
#       and its sandbox dir removed (readopt.go orphan sweep)
# Prerequisites: built artifacts in output/, /dev/kvm available, root (or kvm).
# Usage: bash e2e/vmm-crash-selfheal.sh

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
POOL_SIZE="${POOL_SIZE:-2}"
SANDLOT_POOL="small:${POOL_SIZE}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
source "$ROOT/e2e/common.sh"

# Run directly from $OUTPUT (no separate deploy step) + shared template install.
tc_use_output_binaries
tc_install_flat_template

# Enumerate THIS run's VMs from its own state records (/run/sandswap was wiped
# at script start, so every state.json belongs to this run; tc_run_vm_pids also
# guards against PID reuse). pgrep -x sandvmm cannot tell this run's VMs from
# a leaked previous-run process or a concurrent instance — every count below
# feeds a pass/fail assertion, so the scope must be exact. This also survives
# sandlot restarts: re-adopted VMs are no longer children of the new sandlot
# process, so parent-scoped enumeration would undercount in RecycleCleanup.
sandvmm_pids() { tc_run_vm_pids; }

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

tc_log_section "VM Crash Recovery E2E"

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

tc_create_agent_and_sandfs "crash-test"
tc_log_pass "agent=$TC_AGENT_ID sandfs=$TC_SANDFS_ID"

# ══════════════════════════════════════════════════════════════
# VmmCrashDetect: sandvmm crash -> detect -> destroy-and-replace -> pool heals
# ══════════════════════════════════════════════════════════════
tc_log_section "VmmCrashDetect: sandvmm process crash -> self-heal"

R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo before-crash")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "exec works before crash" \
    || tc_fail "exec failed before crash: $(body_of "$R")"

mapfile -t PIDS_BEFORE < <(sandvmm_pids)
if [[ ${#PIDS_BEFORE[@]} -lt 1 ]]; then
    tc_log_error "no sandvmm processes found; aborting"
    exit 1
fi
VICTIM="${PIDS_BEFORE[0]}"
# Pin the victim's sandbox dir (state.json pid) so the crash teardown can be
# asserted to remove BOTH guest log files (serial.log + console.log).
# state.json lives in the PRIVATE state root, OUTSIDE the sandbox tree; the
# sandbox dir that carries the guest logs is recorded in the state itself.
VICTIM_DIR=""
for st in /run/sandswap-state/default/*/state.json; do
    sp=$(python3 -c "import json;print(json.load(open('$st')).get('pid',''))" 2>/dev/null || true)
    if [[ "$sp" == "$VICTIM" ]]; then
        VICTIM_DIR=$(python3 -c "import json;print(json.load(open('$st')).get('sandbox_dir',''))" 2>/dev/null || true)
        break
    fi
done
if [[ -n "$VICTIM_DIR" && -f "$VICTIM_DIR/console.log" && -f "$VICTIM_DIR/serial.log" ]]; then
    tc_pass "VM logs present before crash: console.log + serial.log in $VICTIM_DIR"
else
    tc_fail "VM logs missing before crash (dir='$VICTIM_DIR') — console.log/serial.log not created by the VMM"
fi
tc_log_info "Killing sandvmm pid $VICTIM (SIGKILL)..."
T_KILL=$(date +%s)
kill -9 "$VICTIM"

# The monitor (cmd.Wait / pidfd) must fire handleVMDied -> CRASHED event ->
# destroyAndReplaceVM. Pool returns to target with a NEW pid. Nested-virt cold
# boots are slow, so budget generously (135s).
HEALED=0
for i in $(seq 1 90); do
    sleep 1.5
    mapfile -t NOW < <(sandvmm_pids)
    CLEAN=$(clean_vms)
    # Healed = target reached AND victim gone AND a different pid exists.
    if [[ "$CLEAN" -ge "$POOL_SIZE" ]] \
        && [[ ! " ${NOW[*]} " == *" $VICTIM "* ]] \
        && [[ ${#NOW[@]} -ge "$POOL_SIZE" ]]; then
        HEALED=1
        break
    fi
done
T_HEAL=$(( $(date +%s) - T_KILL ))

grep -q "died unexpectedly\|CRASHED\|destroy-and-replace\|destroyAndReplace" "$LOG_DIR/sandlot.log" \
    && tc_pass "sandlot log shows crash handling" \
    || tc_log_warn "crash log line not found (non-fatal, behavior verified below)"

if [[ $HEALED -eq 1 ]]; then
    tc_pass "pool self-healed after VMM crash in ${T_HEAL}s (victim $VICTIM replaced by: ${NOW[*]})"
else
    tc_fail "pool did not heal within 135s (clean=$(clean_vms), pids=($(sandvmm_pids)))"
fi

# Crash teardown (monitor handleVMDied -> removeSandboxDir) must delete the
# victim's whole dir, including both guest logs; the replacement VM then has
# its own console.log.
if [[ -n "$VICTIM_DIR" ]]; then
    if [[ ! -d "$VICTIM_DIR" ]]; then
        tc_pass "crash teardown removed the victim sandbox dir (serial+console logs gone): $VICTIM_DIR"
    else
        tc_fail "victim sandbox dir survived crash teardown: $VICTIM_DIR"
    fi
    NEW_CONSOLE=$(find /run/sandswap/vm -name console.log 2>/dev/null | grep -v "^$VICTIM_DIR/" | wc -l)
    if [[ "$NEW_CONSOLE" -ge 1 ]]; then
        tc_pass "replacement VM has its own console.log ($NEW_CONSOLE replacement log(s))"
    else
        tc_fail "replacement VM has no console.log (hvc0 sink missing after crash replacement)"
    fi
fi

# Retry wrapper: the freshly replaced VM's sandbox may still be mid-clean
# (SANDBOX_CLEANING) — honor the server's retry_after_ms instead of a single
# shot that degrades into a false fail.
R=$(gw_exec_retry "$TC_API_KEY" "$TC_SANDFS_ID" "echo after-crash")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "exec works after VMM crash + replacement" \
    || tc_fail "exec failed after crash recovery: $(body_of "$R")"

# ══════════════════════════════════════════════════════════════
# WardenHangSelfheal: the VM is ALIVE but its warden is silent — the crash
# tests above kill the process (cmd.Wait/pidfd fires); THIS path freezes it
# (SIGSTOP) so the only detector left is the independent probe loop (3s
# MemStats probes, 3 consecutive failures ⇒ "declared hung" ⇒ handleVMDied ⇒
# destroy-and-replace). Zero e2e coverage before: monitor.go recordProbeFailure
# teardown was only reachable by unit-less real-vsock silence. SIGKILL kills a
# stopped process, so the destroy path completes normally.
# ══════════════════════════════════════════════════════════════
tc_log_section "WardenHangSelfheal: frozen VM (SIGSTOP) -> probe teardown -> self-heal"

mapfile -t HANG_CANDS < <(sandvmm_pids)
if [[ ${#HANG_CANDS[@]} -lt 1 ]]; then
    tc_log_error "no sandvmm processes to freeze; aborting WardenHangSelfheal"
    exit 1
fi
HANG_VICTIM="${HANG_CANDS[0]}"
tc_log_info "Freezing sandvmm pid $HANG_VICTIM (SIGSTOP — warden goes silent, VMM API dead)..."
T_STOP=$(date +%s)
kill -STOP "$HANG_VICTIM"

# Probe cadence: 3s interval × 3 failures ≈ 9-12s to declare hung, plus the
# kill/replace cycle (nested-virt boot ~20-40s). Budget 90s.
HANG_HEALED=0
for i in $(seq 1 60); do
    sleep 1.5
    mapfile -t HANG_NOW < <(sandvmm_pids)
    HANG_CLEAN=$(clean_vms)
    if [[ "$HANG_CLEAN" -ge "$POOL_SIZE" ]] \
        && [[ ! " ${HANG_NOW[*]} " == *" $HANG_VICTIM "* ]] \
        && [[ ${#HANG_NOW[@]} -ge "$POOL_SIZE" ]]; then
        HANG_HEALED=1
        break
    fi
done
T_HANG_HEAL=$(( $(date +%s) - T_STOP ))

# Safety net for failure paths: never leave a STOPPED process behind (it would
# poison the process-count assertions in the phases below).
kill -CONT "$HANG_VICTIM" 2>/dev/null || true

if grep -q "declared hung after" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    tc_pass "probe loop declared the frozen VM hung (log evidence)"
else
    tc_log_warn "'declared hung' log line not found (non-fatal, behavior verified below)"
fi

if [[ $HANG_HEALED -eq 1 ]]; then
    tc_pass "frozen VM torn down + pool self-healed in ${T_HANG_HEAL}s (victim $HANG_VICTIM replaced by: ${HANG_NOW[*]})"
else
    tc_fail "frozen VM not reclaimed within 90s (clean=$(clean_vms), pids=($(sandvmm_pids))) — probe-failure teardown broken"
fi

# Same retry contract as the crash-recovery exec above: the hang-replaced VM
# is often still in its SANDBOX_CLEANING window here.
R=$(gw_exec_retry "$TC_API_KEY" "$TC_SANDFS_ID" "echo after-hang-heal")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "exec works after warden-hang self-heal" \
    || tc_fail "exec failed after warden-hang self-heal: $(body_of "$R")"

# ══════════════════════════════════════════════════════════════
# RecycleCleanup: a pool scale-down must destroy the EXCESS SANDVMM PROCESS,
# not just drop it from bookkeeping. Pins the destroy-kill regression
# (39d6564): destroyVMByID deleted the map entry before delegating to
# embeddedManager.DestroyVM, whose h.vms re-lookup always missed, so the kill
# AND the state/dir removal were skipped — the process leaked silently until
# the next sandlot restart's orphan sweep. Under the old code this section is
# RED (process count stays 2); with the fix it passes (count returns to 1).
# ══════════════════════════════════════════════════════════════
tc_log_section "RecycleCleanup: scale-down destroys the sandvmm PROCESS"

mapfile -t PIDS_PRE < <(sandvmm_pids)
PRE_COUNT=${#PIDS_PRE[@]}
if [[ "$PRE_COUNT" -lt 2 ]]; then
    tc_log_warn "only $PRE_COUNT sandvmm process(es) (POOL_SIZE=$POOL_SIZE); scale-down destroy test needs ≥2 — skipping RecycleCleanup"
else
    # Let the last exec's sticky lease expire so no VM is mid-unmount when the
    # scale-down lands (a busy VM goes pendingDestroy and is destroyed only at
    # its NEXT unmount — that would look like the destroy-kill regression).
    sleep 2
    tc_log_step "Restarting sandlot with pool small:1 (was small:$POOL_SIZE) — scale-down must destroy one VM"
    kill "${SANDLOT_PID:-}" 2>/dev/null || true
    wait "${SANDLOT_PID:-}" 2>/dev/null || true
    sleep 1
    # SAVE the pool spec: the mutation is global, and OrphanSweep below restarts
    # sandlot again + waits for $POOL_SIZE VMs — with a leaked "small:1" the
    # pool can never reach POOL_SIZE and the wait times out (false fail).
    SAVED_POOL="$SANDLOT_POOL"
    SANDLOT_POOL="small:1"
    tc_start_sandlot
    tc_wait_pool_ready 1
    # Poll instead of a fixed sleep: scale-down destroys IDLE VMs immediately,
    # but a still-mounted VM is destroyed at its next unmount (pendingDestroy),
    # and nested-virt teardown is slow. Budget 60s.
    PIDS_POST=()
# shellcheck disable=SC2034  # poll loop counter
    for i in $(seq 1 60); do
        mapfile -t PIDS_POST < <(sandvmm_pids)
        [[ ${#PIDS_POST[@]} -eq 1 ]] && break
        sleep 1
    done
    if [[ ${#PIDS_POST[@]} -eq 1 ]]; then
        tc_pass "scale-down destroyed the excess sandvmm process (${PRE_COUNT} → ${#PIDS_POST[@]})"
    else
        tc_fail "scale-down left ${#PIDS_POST[@]} sandvmm processes running (want 1) — destroy-kill regression"
    fi

    # The destroyed VM's state record must be gone: exactly one VM's state
    # may remain (records live in the private state root, not the sandbox).
    STALE_STATES=$(find /run/sandswap-state/default -name state.json 2>/dev/null | wc -l)
    if [[ "$STALE_STATES" -eq 1 ]]; then
        tc_pass "no stale state residue after scale-down (state.json count = 1)"
    else
        tc_fail "stale state residue after scale-down (state.json count = $STALE_STATES, want 1)"
    fi
    # Destroy must also remove the excess VM's log files (removeSandboxDir
    # RemoveAll); exactly the surviving VM's console.log + serial.log remain.
    CONSOLE_LOGS=$(find /run/sandswap/vm -name console.log 2>/dev/null | wc -l)
    SERIAL_LOGS=$(find /run/sandswap/vm -name serial.log 2>/dev/null | wc -l)
    if [[ "$CONSOLE_LOGS" -eq 1 && "$SERIAL_LOGS" -eq 1 ]]; then
        tc_pass "destroy removed the excess VM's logs (1 console.log + 1 serial.log remain)"
    else
        tc_fail "log residue after scale-down (console.log=$CONSOLE_LOGS serial.log=$SERIAL_LOGS, want 1 each)"
    fi

    # Restore the pool spec for the OrphanSweep phase.
    SANDLOT_POOL="$SAVED_POOL"
fi

# ══════════════════════════════════════════════════════════════
# OrphanSweep: orphan sweep — sandvmm alive but absent from state.json is
# killed when a new sandlot starts (killOrphanSandvmmStatic)
# ══════════════════════════════════════════════════════════════
tc_log_section "OrphanSweep: orphan sandvmm sweep on restart"

tc_log_step "Simulating lost-state orphan: stop sandlot, drop one state.json..."
kill "${SANDLOT_PID:-}" 2>/dev/null || true
wait "${SANDLOT_PID:-}" 2>/dev/null || true
sleep 1

mapfile -t ORPHANS_BEFORE < <(sandvmm_pids)
if [[ ${#ORPHANS_BEFORE[@]} -lt 1 ]]; then
    tc_log_error "no live sandvmm to orphan; aborting OrphanSweep"
    exit 1
fi
ORPHAN_VICTIM="${ORPHANS_BEFORE[0]}"

# Find the sandbox dir of the orphan victim via its --api-socket argv, then
# delete its state.json so the restarting sandlot sees NO live owner for it.
ORPHAN_ARGV=$(tr '\0' ' ' < "/proc/$ORPHAN_VICTIM/cmdline")
ORPHAN_SOCK=$(echo "$ORPHAN_ARGV" | grep -oE '/run/sandswap[^ ]*sandvmm\.sock' | head -1 || true)
if [[ -z "$ORPHAN_SOCK" ]]; then
    tc_log_error "cannot parse api socket from cmdline: $ORPHAN_ARGV"
    exit 1
fi
ORPHAN_DIR="$(dirname "$ORPHAN_SOCK")"
rm -f "/run/sandswap-state/default/$(basename "$ORPHAN_DIR")/state.json"
tc_log_info "orphan candidate: pid=$ORPHAN_VICTIM sock=$ORPHAN_SOCK (state.json removed)"

# Restart sandlot: startup re-adopt scans sandbox dirs; the socket-less entry
# (no state.json) leaves the victim out of liveSockets -> orphan sweep kills it.
tc_start_sandlot
tc_wait_pool_ready "$POOL_SIZE"

sleep 2
if kill -0 "$ORPHAN_VICTIM" 2>/dev/null; then
    tc_fail "orphan sandvmm pid $ORPHAN_VICTIM still alive after restart sweep"
else
    tc_pass "orphan sandvmm pid $ORPHAN_VICTIM was swept (killed) on startup"
fi
# Embedded-mode re-adopt kills a state-less orphan via cleanupOrphanDir (logs
# "re-adopt: <dir>: ...; cleaning up"); boxout mode uses the /proc orphan sweep
# (logs "orphan sweep: killing sandvmm pid <pid>"). Accept either.
if grep -q "orphan sweep: killing sandvmm pid $ORPHAN_VICTIM" "$LOG_DIR/sandlot.log" \
   || grep -q "re-adopt: $ORPHAN_DIR.*cleaning up" "$LOG_DIR/sandlot.log"; then
    tc_pass "log confirms orphan cleanup ($ORPHAN_VICTIM)"
else
    tc_log_warn "orphan cleanup log line not found (behavior verified above)"
fi

if [[ ! -d "$ORPHAN_DIR" ]]; then
    tc_pass "stale sandbox dir removed: $ORPHAN_DIR"
else
    tc_log_warn "sandbox dir still present: $ORPHAN_DIR (may be re-created for new VM)"
fi

R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo post-sweep")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "exec works after orphan sweep" \
    || tc_fail "exec failed after orphan sweep: $(body_of "$R")"

# ══════════════════════════════════════════════════════════════
tc_log_section "Crash Recovery Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo "[FAIL] VM Crash Recovery E2E FAILED"
    exit 1
fi
echo "[OK] VM Crash Recovery E2E PASSED"
exit 0
