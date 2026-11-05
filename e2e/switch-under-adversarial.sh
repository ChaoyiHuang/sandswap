#!/usr/bin/env bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, your use of this software will be
# governed by the Apache License, Version 2.0.
#
# switch-under-adversarial.sh — W5 lifeline-2 drill: the directory-swap
# machinery (umount → set-fs → bind + the warden's kill(-pgid)/cgroup.kill
# residue sweep) must hold while the guest is HOSTILE and exec traffic is
# CONCURRENT. Against the LIVE stack, R rounds of:
#
#   1. plant adversarials on A: a background exec leaving straggler sleeps +
#      an A-marker file in A's workspace
#   2. under a concurrent sync-exec storm on A, switch to B (the cold path
#      with in-flight traffic — the MOUNT_GATE drain window)
#   3. on B: cross-tenant residue MUST be absent (A's marker invisible —
#      the isolation invariant, probed from inside the next tenant's VM)
#   4. switch back to A: the stragglers MUST be gone (ps probe — the residue
#      sweep held) and A's marker MUST persist (workspace survives)
#
# Usage: bash e2e/switch-under-adversarial.sh [ROUNDS]   (default 5)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

ROUNDS="${1:-5}"
case "$ROUNDS" in ''|*[!0-9]*) ROUNDS=5;; esac

# The drill OWNS its stack: a single-VM pool is the point — with two VMs the
# A→B transition is two cold VMs and every assertion would pass without the
# switch machinery ever running (the live-stack version of this drill got
# that exactly wrong; see the ledger).
# shellcheck disable=SC2034
SANDLOT_POOL="medium:1"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
GW="$GATEWAY_URL"
HUMAN="$HUMAN_URL"
now_ms() { local t="$EPOCHREALTIME"; echo $(( ${t/./} / 1000 )); }
acurl() { curl -s -m 35 "$@"; }   # battery stack: plain HTTP, no -k

tc_check_root
tc_preflight_standard
tc_check_artifacts gateway sandlot sandvmm vmlinux.bin initramfs.cpio.gz
tc_check_kvm
tc_ensure_dev_nodes
[[ "$NETWORK_BACKEND" == "bridge" ]] && tc_setup_host_network
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_attach_vsockguard
tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready 1
tc_pass "single-VM stack up ($GW)"

# The same-VM control (residue-drill lesson): a mid-run recycle would replace
# the VM between rounds and vacate every assertion. Pin the VM identity.
VM_PID_BEFORE=$(tc_run_vm_pids | head -n1)
[[ -n "$VM_PID_BEFORE" ]] || { tc_fail "no live sandvmm pid — cannot prove the rounds share one VM"; exit 1; }

mk_fixture() { # $1=name → KEY/SF (the standard battery helper; single-node store)
    local out
    out=$(tc_create_agent_and_sandfs "$1")
    KEY=$(json_val "$out" "api_key")
    SF=$(json_val "$out" "sandfs_id")
    [[ -n "$KEY" && -n "$SF" ]] || { tc_fail "fixture $1 create failed: $out"; exit 1; }
}
mk_fixture "adv-a"; A_KEY="$KEY"; A_SF="$SF"
mk_fixture "adv-b"; B_KEY="$KEY"; B_SF="$SF"
tc_pass "fixtures A=$A_SF B=$B_SF"

# xexec <key> <sf> <code> [bg] → response body ('' on transport failure).
# The code travels through python's json.dumps — a drill must not break on
# its own quoting.
xexec() {
    local key="$1" sf="$2" code="$3" bg="${4:-}"
    local payload
    payload=$(SYS_SF="$sf" SYS_CODE="$code" SYS_BG="$bg" python3 -c "
import os, json
d = {'sandfs_id': os.environ['SYS_SF'], 'code': os.environ['SYS_CODE'], 'timeout': 20}
if os.environ['SYS_BG'] == 'bg':
    d['background'] = True
    # ABSOLUTE run-time cap: without it the hold is the far-future
    # done-poll sentinel (by design) and nothing ever releases.
    d['lease_duration'] = 6
print(json.dumps(d))")
    acurl -X POST "$GW/agent/execute" -H "Authorization: Bearer $key" \
        -H 'Content-Type: application/json' -d "$payload" || true
}

# xexec_ok <key> <sf> <code> <expect-substr> — retry through the designed
# retryable refusals (NO_AVAILABLE_SANDBOX / SANDBOX_CLEANING / 503 during
# a switch) like a real client; returns the last body.
xexec_ok() {
    local key="$1" sf="$2" code="$3" want="$4" out=""
    for _ in $(seq 1 12); do
        out=$(xexec "$key" "$sf" "$code")
        [[ "$(jval "$out" "stdout")" == *"$want"* ]] && break
        sleep 2
    done
    echo "$out"
}

jval() { echo "$1" | SYS_K="$2" python3 -c "
import sys, json, os
try:
    print(json.load(sys.stdin).get(os.environ['SYS_K'],''))
except Exception:
    print('')"; }

plant_adversarials() { # $1=key $2=sf
    # The REAL adversarial shape: straggler processes that OUTLIVE their
    # lease. A long lease would (correctly) BLOCK the switch via the
    # dual-mount guard — so the bg exec carries a SHORT lease (6s) while
    # its sleeps run 90s. When the lease expires, the unmount's residue
    # sweep (cgroup.kill + kill(-pgid)) must clear them.
    xexec "$1" "$2" "echo a-marker > /workspace/a-marker.txt; sleep 90 & sleep 90 & sleep 90" bg > /dev/null
    # Wait out the lease: expiry runs the unmount + sweep (the event under
    # test). 10s = 6s lease + sweep margin.
    sleep 10
}

FAILS=0
tc_log_section "Adversarial switch rounds (R=$ROUNDS)"
for r in $(seq 1 "$ROUNDS"); do
    # 1. plant on A (first round: A is cold — this exec also mounts it)
    plant_adversarials "$A_KEY" "$A_SF"
    MARK=$(jval "$(xexec "$A_KEY" "$A_SF" "cat /workspace/a-marker.txt")" "stdout")
    if [[ "$MARK" == *"a-marker"* ]]; then
        tc_pass "round $r: A marker planted"
    else
        tc_fail "round $r: A marker missing before the switch (got '$MARK')"; FAILS=$((FAILS+1))
    fi

    # 2. concurrent storm on A while switching to B
    STORM_END=$(( $(now_ms) + 6000 ))
    (
        while (( $(now_ms) < STORM_END )); do
            acurl -X POST "$GW/agent/execute" -H "Authorization: Bearer $A_KEY" \
                -H 'Content-Type: application/json' -d \
                "{\"sandfs_id\":\"$A_SF\",\"code\":\"echo storm\",\"timeout\":10}" \
                > /dev/null 2>&1 || true
        done
    ) &
    STORM=$!
    # 3. switch to B under the storm (the drain + mount gate window).
    # The only VM is leased to A's storm, so B's cold request is answered
    # with a RETRYABLE refusal (NO_AVAILABLE_SANDBOX / SANDBOX_CLEANING /
    # CONCURRENT_MOUNT — the designed elasticity). A real client backs off
    # and retries; the drill must too, or it measures its own impatience.
    B_OUT=""
    for _ in $(seq 1 12); do
        B_OUT=$(xexec "$B_KEY" "$B_SF" "cat /workspace/a-marker.txt 2>/dev/null; echo B-OK")
        if [[ "$(jval "$B_OUT" "stdout")" == *"B-OK"* ]]; then break; fi
        sleep 2
    done
    B_MARKER=$(jval "$B_OUT" "stdout")
    if [[ "$B_MARKER" == *"B-OK"* && "$B_MARKER" != *"a-marker"* ]]; then
        tc_pass "round $r: B clean under storm (A's marker absent — isolation holds)"
    else
        tc_fail "round $r: CROSS-TENANT RESIDUE on B or B broken: '$B_MARKER' (last body: $(echo "$B_OUT" | head -c 200))"; FAILS=$((FAILS+1))
    fi
    wait "$STORM" 2>/dev/null || true

    # 4. switch back to A: residue sweep must have cleared the stragglers
    #    ([s]leep keeps the grep's own cmdline out of the count)
    A_PS=$(jval "$(xexec_ok "$A_KEY" "$A_SF" "ps | grep -c '[s]leep' || 0" "0")" "stdout")
    A_PS=$(echo "$A_PS" | tr -dc '0-9')
    if [[ "$A_PS" == "0" ]]; then
        tc_pass "round $r: A residue sweep clean (0 straggler sleeps survive the switch away)"
    else
        tc_fail "round $r: $A_PS straggler sleeps SURVIVED the switch away from A"; FAILS=$((FAILS+1))
    fi
    # 5. A's workspace persisted
    MARK2=$(jval "$(xexec_ok "$A_KEY" "$A_SF" "cat /workspace/a-marker.txt" "a-marker")" "stdout")
    if [[ "$MARK2" == *"a-marker"* ]]; then
        tc_pass "round $r: A workspace persisted across the round trip"
    else
        tc_fail "round $r: A marker LOST across the switch round (persistence broken)"; FAILS=$((FAILS+1))
    fi
done

# Same-VM control: the rounds must NOT have recycled the VM (a recycle would
# have vacated the residue/isolation assertions above).
VM_PID_AFTER=$(tc_run_vm_pids | head -n1)
if [[ "$VM_PID_AFTER" == "$VM_PID_BEFORE" ]]; then
    tc_pass "same-VM control: all rounds ran on one microVM (sandvmm pid $VM_PID_BEFORE)"
else
    tc_fail "VM RECYCLED mid-drill ($VM_PID_BEFORE → $VM_PID_AFTER) — the round assertions are vacuous; re-run"
fi

# ── Lying-warden leg: the set-fs reuse tripwire, end to end ──
#
# The honest rounds above prove the switch machinery under a hostile GUEST.
# This leg proves the last-resort control under a hostile WARDEN: a variant
# whose OP_UNMOUNT replies success WITHOUT any teardown (the lying-unmount
# shape). The skipped umount leaves the previous tenant's bind + dentry pins
# alive in the guest, so the follow-up vm.set-fs must be REFUSED by the VMM's
# reuse tripwire (previous-tenant-refs), the sandlot must dirty-destroy the
# VM, and the next tenant must run on the REPLACEMENT VM with the first
# tenant's data provably absent.
tc_log_section "Honest-leg control: no tripwire on clean handoffs"
if ! grep -q "previous-tenant-refs" "$LOG_DIR/sandlot.log" 2>/dev/null; then
    tc_pass "honest rounds: no set-fs tripwire refusal (no false positive on clean switches)"
else
    tc_fail "honest rounds logged previous-tenant-refs — false positive on a clean handoff"; FAILS=$((FAILS+1))
fi

tc_log_section "Building the lying-warden variant (cached)"
LV="${LV_DIR:-/tmp/lw-e2e}"
LV_KEY=$( (find "$ROOT/warden" -type f -name '*.rs' -print0 | sort -z | xargs -0 sha256sum 2>/dev/null; echo lying-unmount-v1) | sha256sum | cut -d' ' -f1)
if [[ -f "$LV/initramfs-lying.cpio.gz" && "$(cat "$LV/.built-key" 2>/dev/null || true)" == "$LV_KEY" ]]; then
    tc_pass "reusing lying-warden variant (source hash unchanged)"
else
    rm -rf "$LV/warden-lying" "$LV/wbuild" "$LV/initramfs-lying.cpio.gz"
    mkdir -p "$LV/warden-lying"
    tar -C "$ROOT/warden" --exclude=./target -cf - . | tar -C "$LV/warden-lying" -xf -
    # The lie: unmount_workspace answers Ok with zero teardown, PID-1-gated so
    # a host-side run of the same binary stays honest.
    LV_MOD="$LV/warden-lying/src/mount/mod.rs" python3 - <<'PYEOF' || { tc_fail "lying patch did not land"; exit 1; }
import os
p = os.environ["LV_MOD"]
s = open(p).read()
anchor = "    fallback_pgids: Vec<i32>,\n) -> Result<()> {"
lie = anchor + "\n    // LYING VARIANT (e2e only): report success with zero teardown.\n    if std::process::id() == 1 {\n        return Ok(());\n    }"
assert s.count(anchor) == 1, f"anchor count {s.count(anchor)} != 1"
open(p, "w").write(s.replace(anchor, lie, 1))
PYEOF
    (cd "$LV/warden-lying" && CARGO_TARGET_DIR="$LV/wbuild" cargo build --release --target x86_64-unknown-linux-musl --quiet) \
        || { tc_fail "lying warden build failed"; exit 1; }
    WARDEN_BIN="$LV/wbuild/x86_64-unknown-linux-musl/release/warden" \
        OUTPUT="$LV/initramfs-lying.cpio.gz" \
        bash "$ROOT/initramfs/build.sh" >"$LV/initramfs-build.log" 2>&1 \
        || { tc_fail "lying initramfs build failed"; tail -10 "$LV/initramfs-build.log"; exit 1; }
    echo "$LV_KEY" > "$LV/.built-key"
    tc_pass "lying-warden variant built (unmount_workspace = no-op Ok as PID 1)"
fi

tc_log_section "Relaunching the stack with the lying warden"
# Tear the honest stack down by its recorded PIDs + the standard residue
# clean (never pattern-based kills), then bring the same shape back up with
# TC_INITRAMFS pointing at the variant. The identity store persists under the
# run root, so leg-1 fixtures survive; this leg mints fresh ones anyway.
[[ -n "${GATEWAY_PID:-}" ]] && kill "$GATEWAY_PID" 2>/dev/null || true
[[ -n "${SANDLOT_PID:-}" ]] && kill "$SANDLOT_PID" 2>/dev/null || true
sleep 1
tc_cleanup_default || true
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_attach_vsockguard
[[ "$NETWORK_BACKEND" == "bridge" ]] && tc_setup_host_network
tc_start_gateway
TC_INITRAMFS="$LV/initramfs-lying.cpio.gz" tc_start_sandlot
tc_wait_health
tc_wait_pool_ready 1
VM_PID_LIE0=$(tc_run_vm_pids | head -n1)
[[ -n "$VM_PID_LIE0" ]] || { tc_fail "no live sandvmm pid after the lying relaunch"; exit 1; }
tc_pass "single-VM stack up with the lying warden (sandvmm pid $VM_PID_LIE0)"

mk_fixture "lie-a"; LA_KEY="$KEY"; LA_SF="$SF"
mk_fixture "lie-b"; LB_KEY="$KEY"; LB_SF="$SF"
A_CANARY="LIE-CANARY-A-$$"
B_CANARY="LIE-CANARY-B-$$"

# Plant A's canary and let its lease expire: the expiry unmount is LIED
# about, and the follow-up set-fs clear must trip. sleep 10 = lease + the
# dirty-destroy + replacement-boot margin.
xexec_ok "$LA_KEY" "$LA_SF" "echo $A_CANARY > /workspace/lie-marker.txt; echo A-UP" "A-UP" > /dev/null
sleep 10

TRIP=$(grep -c "previous-tenant-refs" "$LOG_DIR/sandlot.log" 2>/dev/null || true)
DIRTY=$(grep -c "dirty VM" "$LOG_DIR/sandlot.log" 2>/dev/null || true)
if (( TRIP > 0 )); then
    tc_pass "lying unmount: set-fs refused by the reuse tripwire (previous-tenant-refs x$TRIP)"
else
    tc_fail "NO tripwire refusal after a lied unmount — the reuse gate is gone"; FAILS=$((FAILS+1))
fi
if (( DIRTY > 0 )); then
    tc_pass "sandlot dirty-destroyed the VM holding the unreleased export"
else
    tc_fail "no dirty-destroy after the tripwire refusal"; FAILS=$((FAILS+1))
fi

# The next tenant must STILL be served: on the REPLACEMENT VM (fresh VM =
# empty export = tripwire-exempt first attach), with A's canary absent.
LB_OUT=""
for _ in $(seq 1 20); do
    LB_OUT=$(xexec "$LB_KEY" "$LB_SF" "echo $B_CANARY; cat /workspace/lie-marker.txt 2>/dev/null; echo B-DONE")
    [[ "$(jval "$LB_OUT" "stdout")" == *"B-DONE"* ]] && break
    sleep 2
done
LB_VIEW=$(jval "$LB_OUT" "stdout")
VM_PID_LIE1=$(tc_run_vm_pids | head -n1)
if [[ "$LB_VIEW" == *"$B_CANARY"* && "$LB_VIEW" != *"$A_CANARY"* ]]; then
    tc_pass "next tenant served clean on the replacement (A's canary absent)"
else
    tc_fail "CROSS-TENANT READ or broken serve under the lying warden: '$LB_VIEW'"; FAILS=$((FAILS+1))
fi
if [[ -n "$VM_PID_LIE1" && "$VM_PID_LIE1" != "$VM_PID_LIE0" ]]; then
    tc_pass "replacement VM is a NEW sandvmm ($VM_PID_LIE0 → $VM_PID_LIE1)"
else
    tc_fail "same sandvmm served the next tenant after a lied unmount ($VM_PID_LIE0)"; FAILS=$((FAILS+1))
fi

tc_log_section "Summary"
if (( FAILS > 0 )); then
    tc_fail "$FAILS adversarial-switch check(s) FAILED over $ROUNDS rounds (+ lying-warden leg)"
    exit 1
fi
tc_log_pass "switch-under-adversarial: $ROUNDS rounds clean (isolation + residue sweep + persistence under contention) + lying-warden leg (set-fs reuse tripwire)"
