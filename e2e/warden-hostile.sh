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
# warden-hostile.sh — hostile/edge coverage for the warden's exec, file and
# protocol layers. Complements the happy-path suites: every scenario here is a
# failure or boundary mode that production agents can trigger but no other e2e
# exercised by any other suite:
#   ExecTimeout          sync exec exceeding its timeout → status=timed_out,
#                        group killed, partial output preserved
#   PipeDeadlock         >64 KiB output (pipe capacity) completes with a real
#                        exit code (regression: drain-after-exit deadlocked
#                        such commands until the timeout killed them)
#   NonUtf8Output        binary stdout survives the chain as valid JSON
#                        (regression class: sanitizeExecOutput)
#   File16MBBoundary     16 MiB single-op write/read round-trips at the
#                        protocol cap; an over-cap write is rejected without
#                        wedging the VM
#   ForkSpawnStorm       200 background processes reaped at agent switch
#                        (unmount does not wedge, VM reusable)
#   ProtocolHardening    raw vsock frames via warden-probe: bad magic/version,
#                        unknown op, oversized body, truncated frames, >64
#                        fields, hostile mount_point steering — every one
#                        rejected, warden stays alive
#   ProcIsolation        chrooted exec cannot open /proc/1/mem or traverse
#                        /proc/1/root (PR_SET_DUMPABLE=0 gate, independent of
#                        the guest kernel's Yama config), and /proc/1/fd
#                        yields no obtainable warden fd (readdir filtered +
#                        opens refused) — the vsock fd cannot be stolen
#   InitProtection       agent-originated signals cannot kill OR stop PID 1:
#                        the warden's seccomp PID-1 target guard refuses the
#                        addressed signal with EPERM (kill exits 1), and the
#                        kernel's init rule would discard it anyway — warden
#                        keeps serving on the SAME VM
#   MemCap               sync-exec RLIMIT_AS is ENFORCED: one allocation past
#                        the cap is refused and the VM keeps serving
#   VolumeIdentity       a hostile mount-only raced into the agent-switch
#                        window does NOT shadow the next agent's mount:
#                        warden self-heals and the sandlot cross-checks the
#                        wire's mounted-volume assertion
#   StragglerSweep       a setsid'd sync-exec straggler is cleared by the
#                        unmount rule-A sweep — the VM is REUSED across the
#                        switch, not destroyed
# Prerequisites: built artifacts in output/ (incl. warden-probe), /dev/kvm, root.
# Companion suite: e2e/cross-tenant-residue.sh covers the OTHER adversary — the
# in-guest occupant itself (kernel-object residue across a real agent switch;
# kept separate: different adversary model, different fixture).
# Usage: sudo bash e2e/warden-hostile.sh

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
# shellcheck disable=SC2034  # SANDLOT_POOL is consumed by the SOURCED common.sh across the source boundary
SANDLOT_POOL="small:${POOL_SIZE}"
source "$ROOT/e2e/common.sh"

tc_use_output_binaries
tc_install_flat_template

tc_check_root
if [[ ! -e /dev/kvm ]] || [[ ! -r /dev/kvm ]]; then
    tc_log_error "/dev/kvm not available - this E2E requires KVM."
    exit 1
fi
for f in gateway sandlot sandvmm warden-probe; do
    if [[ ! -f "$OUTPUT/$f" ]]; then
        tc_log_error "build artifact missing: output/$f - run 'bash build/build.sh all' first."
        exit 1
    fi
done

tc_log_section "Warden Hostile Coverage E2E"

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

cleanup() { kill "${SILENT_PID:-}" 2>/dev/null || true; tc_cleanup_default; }
trap cleanup EXIT INT TERM

tc_create_agent_and_sandfs "hostile-a" "rootfs:v1" "flat" >/dev/null
A_KEY="$TC_API_KEY"; A_SANDFS="$TC_SANDFS_ID"
[[ -n "$A_KEY" && -n "$A_SANDFS" ]] || { tc_log_error "agent create failed"; exit 1; }

# vm_alive — the invariant after every hostile scenario: the VM still serves.
vm_alive() {
    # Patience, per the suite's documented pool-rebuild window: the hostile
    # scenarios (switch churn, DoS barrage) can push the single-node pool
    # into destroy-and-replace, where an immediate exec gets the RETRYABLE
    # NO_AVAILABLE_SANDBOX refusal while the replacement VM boots — a
    # real client backs off and retries (a one-shot
    # probe fails here while the very next scenario succeeds on the
    # rebuilt VM seconds later). A genuinely dead VM still fails: the loop
    # re-asserts on the SAME sandfs for ~30s and reports the last body.
    local desc="$1" resp="" attempt
    for attempt in $(seq 1 10); do
        resp=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "echo alive-marker" 20 3)
        if echo "$resp" | tc_json_stdout | grep -q "alive-marker"; then
            tc_pass "$desc (VM alive after scenario${attempt:+, attempt $attempt})"
            return 0
        fi
        sleep 3
    done
    tc_fail "$desc (VM NOT alive after scenario): $(echo "$resp" | head -c 200)"
    return 1
}

# ══════════════════════════════════════════════════════════════
tc_log_section "ExecTimeout: sync exec past its timeout is killed, partial output kept"

R=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "echo partial-out; sleep 60; echo never-out" 5 1)
ST=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('status',''))" 2>/dev/null || echo "")
OUT=$(echo "$R" | tc_json_stdout)
if [[ "$ST" == "timed_out" ]]; then
    tc_pass "ExecTimeout: status=timed_out"
else
    tc_fail "ExecTimeout: expected status=timed_out, got '$ST'"
fi
if echo "$OUT" | grep -q "partial-out"; then
    tc_pass "ExecTimeout: partial output preserved"
else
    tc_fail "ExecTimeout: partial output missing (stdout: '$OUT')"
fi
if echo "$OUT" | grep -q "never-out"; then
    tc_fail "ExecTimeout: output contains post-kill line (group kill failed)"
else
    tc_pass "ExecTimeout: no output past the kill point"
fi
vm_alive "ExecTimeout"

# ══════════════════════════════════════════════════════════════
tc_log_section "PipeDeadlock: >64KiB output completes with a real exit code"

# Regression: the drain used to run only after the child exited, so any
# command emitting more than the pipe capacity (~64KiB) blocked on write()
# until the exec timeout killed it. Now the drain runs concurrently. Proof of
# full draining = the command COMPLETES (status=done, exit 0) and its
# post-pipeline side effect (flag file) happened; the kept stdout is the FIRST
# max_output_bytes (1 MiB default) + truncation marker — the tail is beyond
# the cap and legitimately absent.
R=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "head -c 2097152 /dev/zero | tr '\\0' b; echo PIPELINE_DONE > pd.flag; echo tail-echo" 40 1)
ST=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('status',''))" 2>/dev/null || echo "")
OUT=$(echo "$R" | tc_json_stdout)
EC=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('exit_code',''))" 2>/dev/null || echo "")
if [[ "$ST" == "done" ]]; then
    tc_pass "PipeDeadlock: 2MiB-output command completed (status=done)"
else
    tc_fail "PipeDeadlock: expected done, got '$ST' (deadlock regression?)"
fi
if [[ "$EC" == "0" ]]; then
    tc_pass "PipeDeadlock: real exit code 0"
else
    tc_fail "PipeDeadlock: exit_code '$EC'"
fi
if echo "$OUT" | grep -q "output truncated: per-exec cap reached"; then
    tc_pass "PipeDeadlock: kept output is head+truncation marker (cap semantics)"
else
    tc_fail "PipeDeadlock: truncation marker missing"
fi
OUTLEN=$(echo -n "$OUT" | wc -c)
if [[ "$OUTLEN" -gt 100000 ]]; then
    tc_pass "PipeDeadlock: large output returned (${OUTLEN} bytes)"
else
    tc_fail "PipeDeadlock: output suspiciously small (${OUTLEN} bytes)"
fi
# The side effect proves the whole pipeline ran to completion past the pipe
# capacity (a deadlocked pipeline would never reach the redirect).
R2=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "cat pd.flag" 15 1)
if echo "$R2" | tc_json_stdout | grep -q "PIPELINE_DONE"; then
    tc_pass "PipeDeadlock: pipeline side-effect reached (fully drained)"
else
    tc_fail "PipeDeadlock: flag file missing — pipeline deadlocked mid-way"
fi
vm_alive "PipeDeadlock"

# ══════════════════════════════════════════════════════════════
tc_log_section "NonUtf8Output: binary stdout survives the chain"

# printf raw 0xff/0xfe bytes: the warden passes bytes through; the chain must
# return valid JSON, not a 500 / parse error (regression class of the
# sanitizeExecOutput bug fixed on the vmm/gateway side).
R=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "printf 'ok\\xff\\xfe\\x00bytes'" 15 1)
ST=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('status',''))" 2>/dev/null || echo "")
if [[ "$ST" == "done" ]]; then
    tc_pass "NonUtf8Output: status=done with binary stdout"
else
    tc_fail "NonUtf8Output: status '$ST', resp: $(echo "$R" | head -c 200)"
fi
if echo "$R" | grep -q '"stdout"'; then
    tc_pass "NonUtf8Output: stdout field present in JSON"
else
    tc_fail "NonUtf8Output: stdout field missing"
fi
vm_alive "NonUtf8Output"

# ══════════════════════════════════════════════════════════════
tc_log_section "File16MBBoundary: single-op caps"

# 15 MiB write (just under the 16 MiB single-op chain cap: the warden frame
# cap AND the gRPC max_msg_size both count proto/field overhead against the
# same 16 MiB budget, so an exactly-16MiB payload is over the line by design):
# must round-trip in full.
BIGREQ=$(mktemp)
python3 - "$BIGREQ" "$A_SANDFS" <<'PYEOF' >/dev/null
import base64, json, sys
data = bytes(range(256)) * 61440  # 15 MiB
body = json.dumps({"action": "write", "sandfs_id": sys.argv[2],
                   "path": "big15.bin", "data_base64": base64.b64encode(data).decode()})
open(sys.argv[1], "w").write(body)
PYEOF
W15=$(curl -s -m 120 -X POST "$GATEWAY_URL/agent/file" \
    -H "Authorization: Bearer $A_KEY" -H "Content-Type: application/json" \
    -d @"$BIGREQ")
if echo "$W15" | grep -q '"error"'; then
    tc_fail "File16MB: 15MiB write rejected: $(echo "$W15" | head -c 200)"
else
    tc_pass "File16MB: 15MiB write accepted"
fi

R15=$(curl -s -m 120 -X POST "$GATEWAY_URL/agent/file" \
    -H "Authorization: Bearer $A_KEY" -H "Content-Type: application/json" \
    -d "{\"action\":\"read\",\"sandfs_id\":\"$A_SANDFS\",\"path\":\"big15.bin\"}")
B64LEN=$(echo "$R15" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('data_base64','')))" 2>/dev/null || echo 0)
# base64 of 15 MiB = 15728640/3*4 = 20971520 chars
if [[ "$B64LEN" -ge 20971520 ]]; then
    tc_pass "File16MB: read back full 15MiB (b64 len $B64LEN)"
else
    tc_fail "File16MB: read back short (b64 len $B64LEN): $(echo "$R15" | head -c 120)"
fi

# Over-cap write (17 MiB data → ~22.7 MiB base64, under the gateway's 50 MiB
# HTTP body limit but over the 16 MiB chain cap): must be REJECTED with an
# error, not silently truncated — and the VM must survive it.
OVREQ=$(mktemp)
python3 - "$OVREQ" "$A_SANDFS" <<'PYEOF'
import base64, json, sys
data = b"x" * (17 * 1024 * 1024)
body = json.dumps({"action": "write", "sandfs_id": sys.argv[2],
                   "path": "over17.bin", "data_base64": base64.b64encode(data).decode()})
open(sys.argv[1], "w").write(body)
PYEOF
W17=$(curl -s -m 120 -X POST "$GATEWAY_URL/agent/file" \
    -H "Authorization: Bearer $A_KEY" -H "Content-Type: application/json" \
    -d @"$OVREQ")
if echo "$W17" | grep -qi '"error"\|"code"'; then
    tc_pass "File16MB: over-cap write rejected"
else
    tc_fail "File16MB: over-cap write NOT rejected: $(echo "$W17" | head -c 200)"
fi
rm -f "$BIGREQ" "$OVREQ"
vm_alive "File16MB"

# ══════════════════════════════════════════════════════════════
tc_log_section "ForkSpawnStorm: 200 background processes cleared at switch"

BG=$(gw_exec "$A_KEY" "$A_SANDFS" \
    'for i in $(seq 1 200); do sleep 60 & done; echo spawned-ok' \
    '"background":true,"lease_duration":30')
BG_ID=$(body_of "$BG" | json_field "exec_id")
[[ -n "$BG_ID" ]] && tc_pass "ForkStorm: bg spawner started" || tc_fail "ForkStorm: bg start failed"
sleep 3

# Force an agent switch on the same VM (pool=1): the unmount's cgroup.kill
# must clear all 200 sleeps within its budget and the VM must come back CLEAN.
# NOTE the retry window: the earlier scenarios can push guest memory past the
# recycle threshold, so the pool may destroy+rebuild the VM (~cold-boot time)
# before agent B lands — retry through that window rather than failing on it.
tc_create_agent_and_sandfs "hostile-b" "rootfs:v1" "flat" >/dev/null
B_KEY="$TC_API_KEY"; B_SANDFS="$TC_SANDFS_ID"
[[ -n "$B_KEY" ]] || { tc_log_error "agent B create failed"; exit 1; }
RB=""
SWITCH_OK=0
for attempt in $(seq 1 12); do
    RB=$(tc_gw_exec_raw "$B_KEY" "$B_SANDFS" "echo switched-ok" 60 3)
    if echo "$RB" | tc_json_stdout | grep -q "switched-ok"; then
        SWITCH_OK=1
        break
    fi
    tc_log_warn "  switch attempt $attempt: $(echo "$RB" | grep -o 'NO_AVAILABLE_SANDBOX\|SANDBOX_CLEANING' | head -1) — waiting for pool..."
    sleep 5
done
if [[ "$SWITCH_OK" == "1" ]]; then
    tc_pass "ForkStorm: agent switch under 200-process storm succeeded"
else
    tc_fail "ForkStorm: switch exec failed: $(echo "$RB" | head -c 200)"
fi
# The old bg exec must be gone (status not running).
sleep 2
S=$(gw_status "$A_KEY" "$A_SANDFS" "$BG_ID")
SST=$(echo "$S" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('status',''))" 2>/dev/null || echo "")
if [[ "$SST" == "running" ]]; then
    tc_fail "ForkStorm: bg exec still 'running' after switch (cgroup kill failed)"
else
    tc_pass "ForkStorm: bg exec not running after switch (status=$SST)"
fi
vm_alive "ForkStorm"

# ══════════════════════════════════════════════════════════════
tc_log_section "ProtocolHardening: malformed + hostile raw vsock frames"

# Discover the live VM's guest CID from sandlot state (pool=1 → exactly one).
VM_CID=""
for st in /run/sandswap-state/default/*/state.json; do
    PID=$(python3 -c "import json;print(json.load(open('$st')).get('pid',''))" 2>/dev/null || echo "")
    [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null || continue
    VM_CID=$(python3 -c "import json;print(json.load(open('$st')).get('cid',''))" 2>/dev/null || echo "")
    [[ -n "$VM_CID" ]] && break
done
if [[ -z "$VM_CID" ]]; then
    tc_fail "ProtocolHardening: no live VM found for raw vsock probe"
else
    tc_log_info "probing guest CID $VM_CID"
    PROBE="$OUTPUT/warden-probe"

    # The probe is the stand-in for a host-side peer reaching the warden.
    # vsockguard pins AF_VSOCK port 1024 to the sandlot UID (there is no
    # uid-0 exemption), so the legit path must run as the sandlot identity —
    # as root every connect would be LSM-denied and set -e would kill the
    # script inside the command substitution before any assertion runs.
    # The per-VM raw-protocol key lives in the VM's state.json
    # (config.warden_session_key); the state dir is owner-only sandlot, which
    # is exactly the identity the probe runs as. The probe delivers it with
    # OP_KEY_DELIVERY before any authenticated frame.
    probe_run() { setpriv --reuid=sandlot --regid=sandlot --clear-groups \
        "$PROBE" -cid "$VM_CID" -state "$st" -timeout 6s "$@" 2>&1; }

    # Key-delivery contract: the guest command line must NOT carry the key
    # (the kernel prints it at KERN_INFO), and the state must still carry it
    # for the probe to deliver.
    K_CMDLINE=$(python3 -c "import json;print(json.load(open('$st'))['config'].get('kernel_cmdline',''))" 2>/dev/null || true)
    K_STATE=$(python3 -c "import json;print(json.load(open('$st'))['config'].get('warden_session_key',''))" 2>/dev/null || true)
    if [[ "$K_CMDLINE" == *"warden.session_key="* ]]; then
        tc_fail "KeyDelivery: session key is still on the kernel command line"
    else
        tc_pass "KeyDelivery: session key absent from the guest command line"
    fi
    if [[ -n "$K_STATE" ]]; then
        tc_pass "KeyDelivery: state.json carries the per-VM key for delivery"
    else
        tc_fail "KeyDelivery: state.json has no warden_session_key"
    fi

    # Positive control first: the legit heartbeat op (the probe delivers the
    # key before this authenticated frame).
    OUT=$(probe_run memstats)
    if echo "$OUT" | grep -q '^resp code=0'; then
        tc_pass "Protocol: memstats works (code=0)"
    else
        tc_fail "Protocol: memstats failed: $OUT"
    fi

    # bad-version is the ONE malformed frame the warden answers: a single
    # transport-error frame carrying the warden's OWN version + supported
    # range (so an exact-match client classifies it ProtocolVersionError),
    # then the connection closes. A bare EOF would leave the operator with a
    # mystery transport flap instead of the actionable deploy mismatch (see
    # raw_server.rs read_request; scenarios live in protocol-version-e2e.sh).
    OUT=$(probe_run bad-version)
    if echo "$OUT" | grep -q '^resp code=2' \
       && echo "$OUT" | grep -q 'unsupported; this warden speaks \['; then
        tc_pass "Protocol: bad-version → versioned rejection frame (code=2 + range message)"
    else
        tc_fail "Protocol: bad-version → expected versioned rejection, got: $(echo "$OUT" | head -c 160)"
    fi

    # Every remaining malformed frame must be refused. The warden closes the
    # connection without a response (probe prints "eof") — except unknown-op,
    # which is a well-formed frame dispatched to an error response (code=2).
    for mode in bad-magic oversize short-body half-header field-past-end too-many-fields; do
        OUT=$(probe_run "$mode")
        if echo "$OUT" | grep -q '^eof$'; then
            tc_pass "Protocol: $mode → connection refused (eof)"
        else
            tc_fail "Protocol: $mode → expected eof, got: $(echo "$OUT" | head -c 160)"
        fi
    done

    OUT=$(probe_run unknown-op)
    if echo "$OUT" | grep -q '^resp code=2' && echo "$OUT" | grep -q 'unknown op'; then
        tc_pass "Protocol: unknown-op → transport error response"
    else
        tc_fail "Protocol: unknown-op unexpected: $(echo "$OUT" | head -c 160)"
    fi

    # Hostile mount_point steering: must be rejected by the warden's pin —
    # a successful /sys/fs/cgroup mount would defeat cgroup.kill at switch.
    OUT=$(probe_run mount-bad-mp)
    if echo "$OUT" | grep -q '^resp code=2' && echo "$OUT" | grep -q 'mount_point must be exactly'; then
        tc_pass "Protocol: hostile mount_point (/sys/fs/cgroup) refused"
    else
        tc_fail "Protocol: mount-bad-mp unexpected: $(echo "$OUT" | head -c 200)"
    fi
    OUT=$(probe_run unmount-bad-mp)
    if echo "$OUT" | grep -q '^resp code=2' && echo "$OUT" | grep -q 'mount_point must be exactly'; then
        tc_pass "Protocol: hostile unmount target (/proc) refused"
    else
        tc_fail "Protocol: unmount-bad-mp unexpected: $(echo "$OUT" | head -c 200)"
    fi
fi
# The warden (and the current agent's mount) must have survived the barrage.
vm_alive "Protocol"

# ── Transport DoS bounds (connection cap + in-flight body budget) ──
# A hostile peer that can reach the port — this host-side probe, or an
# in-guest process on a guest kernel with a vsock loopback transport (the
# shipped kernel has none: a guest's connect() to its own CID fails ENODEV,
# and other VMs' CIDs are not routed by the host) — can park resources:
# connections (task-per-conn) and pre-allocated request
# bodies (header claims N bytes, body never arrives). The warden bounds both:
# MAX_CONNS concurrent connections, BODY_BUDGET = 6×max_body_len reserved
# bytes (6 covers the largest exec_slots profile: five concurrent max-body
# slots + one). Each stalled probe holds its connection with -hold; an
# ACCEPTED stall parks (probe read times out, no "eof"), a REJECTED one is
# closed by the warden immediately (probe prints "eof").
if [[ -n "$VM_CID" ]]; then
    tc_log_info "DoS bounds: connection cap (16) + body budget (6×16MiB)"

    # A: connection cap (16, counting the sandlot's open pooled connections —
    # up to exec_slots of them — so the stall acceptance count is adaptive).
    # Open stalls one at a time until the warden rejects one, then assert the
    # accepted count is within the pool-corrected window and that rejection
    # happened at all.
    STALL_PIDS=()
    accepted=0
    rejected_at=0
    for i in $(seq 1 20); do
        setpriv --reuid=sandlot --regid=sandlot --clear-groups \
            "$PROBE" -cid "$VM_CID" -state "$st" -timeout 40s -hold 35s stall-body 64 \
            >/tmp/warden-hostile-stall-$i.out 2>&1 &
        STALL_PIDS+=($!)
        # Brief connect+settle window, then classify: accepted (parked, no
        # "eof") or rejected ("eof" already printed).
        sleep 0.6
        if grep -q '^eof$' /tmp/warden-hostile-stall-$i.out 2>/dev/null; then
            rejected_at=$i
            break
        fi
        accepted=$((accepted + 1))
    done
    # Late-eof rescue: a rejection whose "eof" print landed after the 0.6s
    # classify window leaves rejected_at=0 and over-counts accepted — a false
    # FAIL under load. By now (12+s in) every rejected probe has long printed
    # eof, while genuinely-parked probes hold for their full -hold with no
    # output, so re-classify from the recorded files before judging.
    if [[ "$rejected_at" -eq 0 ]]; then
        accepted=0
        for i in $(seq 1 20); do
            if grep -q '^eof$' /tmp/warden-hostile-stall-$i.out 2>/dev/null; then
                rejected_at=$i
                break
            fi
            accepted=$((accepted + 1))
        done
    fi
    # Cap 16 minus up to 3 open pool connections (small spec exec_slots):
    # acceptance must land in [13, 16], and rejection must have happened.
    if [[ "$rejected_at" -ge 14 && "$rejected_at" -le 17 && "$accepted" -ge 13 ]]; then
        tc_pass "DoS: connection cap enforced (accepted $accepted stalls, rejected #$rejected_at)"
    else
        tc_fail "DoS: cap window miss — accepted=$accepted rejected_at=$rejected_at (want 13-16 accepted)"
    fi

    # The sandlot's EXISTING pooled connections (opened before the stalls,
    # counted inside the cap) must be unaffected — verify via the gateway
    # exec path. A NEW connection while the attacker holds the cap is capped
    # too, by design: the boundary protects the pooled serving path.
    EXEC_OK=$(curl -s -m 10 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $A_KEY" -H 'Content-Type: application/json' \
        -d "{\"sandfs_id\":\"$A_SANDFS\",\"code\":\"echo dos-bounds-alive\"}" \
        | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('stdout','').strip())" 2>/dev/null || echo "")
    if [[ "$EXEC_OK" == "dos-bounds-alive" ]]; then
        tc_pass "DoS: gateway exec still served (existing pooled connections unaffected)"
    else
        tc_fail "DoS: gateway exec broken under connection stall: '$EXEC_OK'"
    fi
    # Release the stalls.
    for pid in "${STALL_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait "${STALL_PIDS[@]}" 2>/dev/null || true
    sleep 1

    # B: body budget. 6 stalls claiming 16 MiB each fill the 96 MiB budget;
    # the 7th must be closed (reservation denied) while under the conn cap.
    STALL_PIDS=()
    for i in $(seq 1 6); do
        setpriv --reuid=sandlot --regid=sandlot --clear-groups \
            "$PROBE" -cid "$VM_CID" -state "$st" -timeout 40s -hold 35s stall-body 16777216 \
            >/tmp/warden-hostile-bigstall-$i.out 2>&1 &
        STALL_PIDS+=($!)
    done
    sleep 3
    accepted=0
    for i in $(seq 1 6); do
        if ! grep -q '^eof$' /tmp/warden-hostile-bigstall-$i.out 2>/dev/null \
           && kill -0 "${STALL_PIDS[$((i-1))]}" 2>/dev/null; then
            accepted=$((accepted + 1))
        fi
    done
    if [[ "$accepted" -eq 6 ]]; then
        tc_pass "DoS: 6×16MiB stalled bodies all reserved (budget holds)"
    else
        tc_fail "DoS: expected 6 accepted big stalls, got $accepted"
    fi
    OUT=$(probe_run stall-body 16777216) || true
    if echo "$OUT" | grep -q '^eof$'; then
        tc_pass "DoS: 7th 16MiB claim closed by the body budget"
    else
        tc_fail "DoS: 7th big claim not rejected: $(echo "$OUT" | head -c 160)"
    fi
    # Budget released on close: after killing the stalls, a big claim is
    # accepted again (within a fresh small window — also proves release).
    for pid in "${STALL_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait "${STALL_PIDS[@]}" 2>/dev/null || true
    sleep 1
    # The probe parks (accepted) when the budget was released — its read
    # times out and it exits NONZERO, so guard the substitution against
    # set -e: only the "eof" output distinguishes the outcome.
    OUT=$(probe_run stall-body 16777216) || true
    if echo "$OUT" | grep -q '^eof$'; then
        tc_fail "DoS: budget not released after stalls closed"
    else
        tc_pass "DoS: body budget released after connection close"
    fi

    # A LEGITIMATE max-scale body must flow through the budget untouched:
    # acquire -> read_exact completion -> release. An 8 MiB random file write
    # through the gateway (sandlot -> OP_FILE body -> warden read_request ->
    # write_file), read back, sha256-compared. Proves the budget bounds only
    # PARKED reads, never completed legitimate traffic. The payload travels
    # via a temp file (an 11 MB base64 argv would exceed MAX_ARG_STRLEN).
    BIG_B64_FILE=/tmp/warden-hostile-big.b64
    python3 -c "import os,base64;open('$BIG_B64_FILE','wb').write(base64.b64encode(os.urandom(8*1024*1024)))"
    BIG_SUM=$(python3 -c "import hashlib,base64;print(hashlib.sha256(base64.b64decode(open('$BIG_B64_FILE','rb').read())).hexdigest())")
    W_RC=$(python3 -c "
import sys, json, urllib.request
b64 = open(sys.argv[1]).read()
req = urllib.request.Request(
    'http://localhost:3001/agent/file',
    data=json.dumps({'sandfs_id': sys.argv[2], 'action': 'write',
                     'path': 'big-legit.bin', 'data_base64': b64}).encode(),
    headers={'Authorization': 'Bearer ' + sys.argv[3],
             'Content-Type': 'application/json'},
    method='POST')
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print(r.read().decode()[:120])
except Exception as e:
    print('ERR:' + str(e)[:200])
" "$BIG_B64_FILE" "$A_SANDFS" "$A_KEY")
    if echo "$W_RC" | grep -q '"ok": *true'; then
        tc_pass "DoS: legit 8MiB file write accepted through the budget"
    else
        tc_fail "DoS: legit 8MiB write failed: $(echo "$W_RC" | head -c 160)"
    fi
    R_SUM=$(python3 -c "
import sys, json, hashlib, base64, urllib.request
req = urllib.request.Request(
    'http://localhost:3001/agent/file',
    data=json.dumps({'sandfs_id': sys.argv[1], 'action': 'read',
                     'path': 'big-legit.bin'}).encode(),
    headers={'Authorization': 'Bearer ' + sys.argv[2],
             'Content-Type': 'application/json'},
    method='POST')
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.loads(r.read())
        b64 = d.get('data_base64', '')
        if b64:
            print(hashlib.sha256(base64.b64decode(b64)).hexdigest())
except Exception:
    pass
" "$A_SANDFS" "$A_KEY")
    if [[ -n "$BIG_SUM" && "$BIG_SUM" == "$R_SUM" ]]; then
        tc_pass "DoS: legit 8MiB round-trip intact (sha256 match)"
    else
        tc_fail "DoS: big round-trip corrupted (write=$BIG_SUM read=$R_SUM)"
    fi
    rm -f "$BIG_B64_FILE"

    # C: recovery — a fresh normal exec round trip after the whole barrage.
    EXEC_OK=$(curl -s -m 10 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $A_KEY" -H 'Content-Type: application/json' \
        -d "{\"sandfs_id\":\"$A_SANDFS\",\"code\":\"echo dos-recovered\"}" \
        | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('stdout','').strip())" 2>/dev/null || echo "")
    if [[ "$EXEC_OK" == "dos-recovered" ]]; then
        tc_pass "DoS: normal exec recovered after DoS barrage"
    else
        tc_fail "DoS: exec did not recover: '$EXEC_OK'"
    fi
    vm_alive "DoS-bounds"

    # D: UNAUTHENTICATED slot holding is bounded by the 30s first-frame
    # timeout. Open silent AF_VSOCK connections (no KEY_DELIVERY, no frame) as
    # the sandlot uid until the 16-slot cap refuses one; the slots are held
    # only until the timeout, after which a fresh legitimate memstats must be
    # served. This is the unauthenticated half of the DoS bound: the earlier
    # stalls authenticate first, so they never exercise the first-frame timer.
    SILENT_PY=/tmp/warden-hostile-silent.py
    cat > "$SILENT_PY" <<'PY'
import socket, sys, time
cid = int(sys.argv[1]); limit = int(sys.argv[2]); n = 0
for _ in range(limit):
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((cid, 1024))
        n += 1
    except OSError:
        break
print(n, flush=True)
time.sleep(40)
PY
    setpriv --reuid=sandlot --regid=sandlot --clear-groups \
        python3 "$SILENT_PY" "$VM_CID" 20 >/tmp/warden-hostile-silent.out 2>&1 &
    SILENT_PID=$!
    sleep 2
    SILENT_N=$(head -1 /tmp/warden-hostile-silent.out 2>/dev/null || echo 0)
    if [[ "$SILENT_N" =~ ^[0-9]+$ && "$SILENT_N" -ge 10 && "$SILENT_N" -le 20 ]]; then
        tc_pass "DoS: unauthenticated silent connections accepted then capped ($SILENT_N)"
    else
        tc_fail "DoS: silent connection count unexpected: '$SILENT_N'"
    fi
    # The first-frame timeout is 30s; wait past it, then a NEW legitimate
    # connection must be served (slots released without any client close).
    sleep 33
    OUT=$(probe_run memstats) || true
    if echo "$OUT" | grep -q '^resp code=0'; then
        tc_pass "DoS: unauthenticated slots released by the first-frame timeout"
    else
        tc_fail "DoS: slots still occupied after the first-frame timeout: $(echo "$OUT" | head -c 160)"
    fi
    kill "$SILENT_PID" 2>/dev/null || true
    wait "$SILENT_PID" 2>/dev/null || true
    rm -f "$SILENT_PY" /tmp/warden-hostile-silent.out
fi


# ══════════════════════════════════════════════════════════════
# live_state_json — the state.json of the (single) live VM, for VM-identity
# (reuse vs destroy-and-replace) assertions.
live_state_json() {
    for st in /run/sandswap-state/default/*/state.json; do
        [[ -f "$st" ]] || continue
        PID=$(python3 -c "import json;print(json.load(open('$st')).get('pid',''))" 2>/dev/null || echo "")
        [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null || continue
        echo "$st"; return 0
    done
    return 1
}

# hostile_file_read — read <path> from a sandfs via the file API, decoded,
# with bounded retries: a read right after an agent switch can hit the
# retryable busy states (SANDBOX_CLEANING / lease windows) — the VolumeIdentity
# assertions read BOTH agents' volumes across two switches.
hostile_file_read() {
    # 10 x 3s ≈ the pool destroy-and-rebuild window this suite documents for
    # the scenarios that push guest memory (DoS barrage precedes these reads).
    # Both the retryable busy error AND the single-node no-available error are
    # waited out; a read that never succeeds in the window returns "" and the
    # CONTENT assertion fails honestly.
    local key="$1" sandfs="$2" path="$3" try resp
    for try in $(seq 1 10); do
        resp=$(curl -s -m 30 -X POST "$GATEWAY_URL/agent/file" \
            -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
            -d "{\"sandfs_id\":\"$sandfs\",\"action\":\"read\",\"path\":\"$path\"}" 2>&1)
        if grep -q '"retryable":true' <<<"$resp"; then sleep 1; continue; fi
        if grep -q 'no available sandbox' <<<"$resp"; then sleep 3; continue; fi
        [[ -n "${TC_FILE_READ_DEBUG:-}" ]] && echo "    [debug] file_read raw (try $try): $(echo "$resp" | head -c 300)" >&2
        { printf '%s' "$resp" \
          | python3 -c 'import sys,json,base64; d=json.load(sys.stdin); b=d.get("data_base64") or d.get("data") or ""; print(base64.b64decode(b).decode() if d.get("data_base64") else b)' 2>/dev/null; } || echo ""
        return 0
    done
    echo ""
}

tc_log_section "ProcIsolation: chrooted exec vs /proc/1 (dumpable gate)"

# The ptrace-syscall equivalents live behind ptrace_may_access: open+read on
# /proc/1/mem and traversal of /proc/1/root are NOT seccomp-deniable. The
# warden's boot-time PR_SET_DUMPABLE=0 must deny both to a same-uid exec
# child (no exec profile keeps CAP_SYS_PTRACE), regardless of Yama.
OUT=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" \
    'head -c 1 /proc/1/mem >/dev/null 2>&1; echo mem-rc=$?; ls /proc/1/root/ >/dev/null 2>&1; echo root-rc=$?; SELF=$(readlink /proc/self/fd/0 2>/dev/null); echo probe-self=$SELF; N=0; BAD=0; for f in /proc/1/fd/*; do [ -e "$f" ] || continue; N=$((N+1)); (exec 3<>"$f") 2>/dev/null && BAD=$((BAD+1)); done; echo fd-visible=$N fd-openable=$BAD' \
    15 3 || true)
MEM_RC=$(echo "$OUT" | tc_json_stdout | grep -o 'mem-rc=[0-9]*' | cut -d= -f2 || true)
ROOT_RC=$(echo "$OUT" | tc_json_stdout | grep -o 'root-rc=[0-9]*' | cut -d= -f2 || true)
PROBE_SELF=$(echo "$OUT" | tc_json_stdout | grep -o 'probe-self=.*' | head -1 | cut -d= -f2- || true)
FD_VISIBLE=$(echo "$OUT" | tc_json_stdout | grep -o 'fd-visible=[0-9]*' | cut -d= -f2 || true)
FD_BAD=$(echo "$OUT" | tc_json_stdout | grep -o 'fd-openable=[0-9]*' | cut -d= -f2 || true)
if [[ -n "$MEM_RC" && "$MEM_RC" != "0" ]]; then
    tc_pass "ProcIsolation: /proc/1/mem open denied to chrooted exec (rc=$MEM_RC)"
else
    tc_fail "ProcIsolation: /proc/1/mem OPENED by chrooted exec (rc=$MEM_RC) — dumpable gate missing; raw: $(echo "$OUT" | head -c 300)"
fi
if [[ -n "$ROOT_RC" && "$ROOT_RC" != "0" ]]; then
    tc_pass "ProcIsolation: /proc/1/root traversal denied to chrooted exec (rc=$ROOT_RC)"
else
    tc_fail "ProcIsolation: /proc/1/root traversed by chrooted exec (rc=$ROOT_RC); raw: $(echo "$OUT" | head -c 300)"
fi
# The fd channel feeds the response-forgery argument: the agent must not be
# able to obtain any of the warden's file descriptors. With PR_SET_DUMPABLE=0
# the kernel filters /proc/1/fd readdir by the ptrace check (the directory
# reads as EMPTY — asserted implicitly by fd-visible) and refusing the open of
# any entry that did appear; opening a SOCKET fd via /proc is additionally
# ENXIO by construction (sock_no_open), so the warden's vsock fd can never be
# stolen this way. The probe-self control proves the readlink probe itself
# works (a positive control for the empty result).
if [[ -z "$PROBE_SELF" ]]; then
    tc_fail "ProcIsolation: fd probe control failed (readlink /proc/self/fd/0 empty) — probe broken; raw: $(echo "$OUT" | head -c 300)"
elif [[ -n "$FD_BAD" && "$FD_BAD" == "0" ]]; then
    tc_pass "ProcIsolation: no warden fd obtainable via /proc/1/fd (visible=$FD_VISIBLE, openable=$FD_BAD)"
else
    tc_fail "ProcIsolation: $FD_BAD /proc/1 fd(s) OPENED by chrooted exec — fd channel not closed; raw: $(echo "$OUT" | head -c 300)"
fi
vm_alive "ProcIsolation"

# ══════════════════════════════════════════════════════════════
tc_log_section "InitProtection: agent signals cannot kill or stop PID 1"

# Defense in depth: the warden's seccomp filter refuses a signal whose
# target is PID 1 (args[0] == 1) with EPERM, so kill(2) exits 1 and the
# signal never reaches the kernel's init-immunity path. The follow-up exec
# proves BOTH not-killed and not-stopped (a stopped warden could not serve
# it), and the VM-identity check proves no destroy-and-replace masked it.
VM_IP_BEFORE=$(live_state_json || true)
OUT=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" \
    'kill -9 1; echo k9=$?; kill -TERM 1; echo kterm=$?; kill -STOP 1; echo kstop=$?' \
    15 3 || true)
K9=$(echo "$OUT" | tc_json_stdout | grep -o 'k9=[0-9]*' | cut -d= -f2 || true)
KTERM=$(echo "$OUT" | tc_json_stdout | grep -o 'kterm=[0-9]*' | cut -d= -f2 || true)
KSTOP=$(echo "$OUT" | tc_json_stdout | grep -o 'kstop=[0-9]*' | cut -d= -f2 || true)
if [[ "$K9" == "1" && "$KTERM" == "1" && "$KSTOP" == "1" ]]; then
    tc_pass "InitProtection: PID-1 signal guard refuses kill/tkill with EPERM (exit 1)"
else
    tc_fail "InitProtection: kill exit codes k9=$K9 kterm=$KTERM kstop=$KSTOP (want all 1 — the seccomp PID-1 target guard must refuse them)"
fi
# Survival: the warden must still serve on the SAME VM.
SURV=""
for attempt in $(seq 1 6); do
    RS=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "echo ward-still-here" 15 3)
    if echo "$RS" | tc_json_stdout | grep -q "ward-still-here"; then SURV=1; break; fi
    sleep 2
done
VM_IP_AFTER=$(live_state_json || true)
if [[ -z "$SURV" ]]; then
    tc_fail "InitProtection: warden not serving after agent kill -9/-TERM/-STOP 1: $(echo "$RS" | head -c 200)"
elif [[ -n "$VM_IP_BEFORE" && "$VM_IP_BEFORE" == "$VM_IP_AFTER" ]]; then
    tc_pass "InitProtection: warden survived kill -9/-TERM/-STOP from agent, same VM still serving"
else
    tc_fail "InitProtection: VM changed after kill attempts (before=$VM_IP_BEFORE after=$VM_IP_AFTER) — warden died and was replaced"
fi
vm_alive "InitProtection"

# ══════════════════════════════════════════════════════════════
tc_log_section "VolumeIdentity: hostile mount-only in the switch window self-heals"

# Shadow-mount drill: while agent A's volume is mounted, spam the warden with
# mount-only requests carrying a STALE / invented alias as the in-guest-
# attacker stand-in (same vsock reachability), then force a switch to agent B.
# The per-generation alias is the gate: a request that does not name the
# currently exported name cannot resolve, so the spam is refused with
# mount_target_not_exported and nothing is torn down. Pre-alias, a spam
# landing in the [unmount-done, set-fs(B)] window mounted A again and B's
# combined RPC dedup-SKIPPED. Observable: B's write lands in B's volume and
# A's file is untouched.
A_VAL="markA-$RANDOM$RANDOM"
B_VAL="markB-$RANDOM$RANDOM"
gw_exec "$A_KEY" "$A_SANDFS" "echo $A_VAL > /workspace/whoami.txt" '"timeout_ms":10000' >/dev/null 2>&1 || true

# Discover A's host volume path by its marker content (flat mode: the sandfs
# dir IS the rootfs; whoami.txt lives under its workspace/).
VOL_A=""
for f in "$VOL_ROOT"/*/workspace/whoami.txt; do
    [[ -f "$f" ]] || continue
    if grep -q "$A_VAL" "$f" 2>/dev/null; then VOL_A=$(dirname "$(dirname "$f")"); break; fi
done
if [[ -z "$VOL_A" ]]; then
    tc_fail "VolumeIdentity: could not locate agent A volume dir"
else
    tc_log_info "agent A volume: $VOL_A"
    # Spam loop in the background for ~8s, dense enough to cover the switch
    # window (sticky ~100ms). While A is legitimately mounted every request
    # is a dedup no-op; the one that matters lands right after the unmount.
    SPAM_PID=""
    STALE_ALIAS="$(openssl rand -hex 16)"
    (
        for i in $(seq 1 160); do
            probe_run mount-exec "$STALE_ALIAS" /mnt/rootfs "" >/dev/null 2>&1 || true
            sleep 0.05
        done
    ) &
    SPAM_PID=$!

    # Force the switch: B's exec must land in B's volume (self-heal behind it).
    SWITCHED=""
    for attempt in $(seq 1 12); do
        RB=$(tc_gw_exec_raw "$B_KEY" "$B_SANDFS" "echo $B_VAL > /workspace/whoami.txt" 30 3)
        if echo "$RB" | grep -q '"status":"done"'; then SWITCHED=1; break; fi
        sleep 3
    done
    wait "$SPAM_PID" 2>/dev/null || true
    if [[ -z "$SWITCHED" ]]; then
        tc_fail "VolumeIdentity: agent B exec never succeeded: $(echo "$RB" | head -c 200)"
    else
        # Cross-check via the FILE api (host-side view of each volume): A's
        # file must still hold A's marker, B's must hold B's. Under the old
        # dedup-skip bug B's exec wrote into A's volume.
        sleep 1
        AR=$(hostile_file_read "$A_KEY" "$A_SANDFS" "whoami.txt" | tr -d '\n')
        BR=$(hostile_file_read "$B_KEY" "$B_SANDFS" "whoami.txt" | tr -d '\n')
        if [[ "$AR" == "$A_VAL" ]]; then
            tc_pass "VolumeIdentity: A's volume untouched by B's switch exec"
        else
            tc_fail "VolumeIdentity: A's volume shows '$AR' (want $A_VAL) — B's exec landed in the WRONG volume"
        fi
        if [[ "$BR" == "$B_VAL" ]]; then
            tc_pass "VolumeIdentity: B's exec landed in B's own volume (generation gate + belt)"
        else
            tc_fail "VolumeIdentity: B's volume shows '$BR' (want $B_VAL)"
        fi
    fi
fi
# vm_alive with the suite's documented pool-rebuild patience: the DoS barrage
# + this scenario's switch churn can push the single-node pool into a
# destroy-and-rebuild window right here (the next scenario runs seconds later
# on the rebuilt VM — see the ForkSpawnStorm note).
VA_OK=""
for attempt in $(seq 1 8); do
    RV=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "echo alive-marker" 20 3)
    if echo "$RV" | tc_json_stdout | grep -q "alive-marker"; then VA_OK=1; break; fi
    sleep 3
done
if [[ -n "$VA_OK" ]]; then
    tc_pass "VolumeIdentity (VM alive after scenario)"
else
    tc_fail "VolumeIdentity (VM NOT alive after scenario): $(echo "$RV" | head -c 200)"
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "StragglerSweep: setsid straggler cleared, VM reused (not destroyed)"

# A setsid'd child of a SYNC exec escapes both the finish-tail kill(-pgid)
# and cgroup.kill (sync execs never join the cgroup). Pre-fix it pinned
# /mnt/rootfs via its chroot root → unmount EBUSY → VM destroyed on every
# switch. Post-fix the unmount's rule-A sweep kills it and the VM is reused.
VM_BEFORE=$(live_state_json || true)
# The template links no `setsid` in bin/ (busybox compiles the applet, so it is
# invoked THROUGH busybox) — a bare `setsid …` printed "not found", created no
# straggler at all, and the phase then "passed" without ever reproducing the
# EBUSY condition it exists for. Assert the sentinel AND an in-guest count so a
# silently-unspawned straggler is a FAIL, not a vacuous pass.
# Portable spawn: `setsid` may be a real binary (ubuntu-based guests) or only a
# busybox applet (the busybox template links none in bin/). Try PATH first, then
# the applet, and report explicitly when neither exists — an unspawned straggler
# must never read as a pass. Retry the exec too: a retryable busy state right
# after another phase is not evidence about setsid.
# tc_gw_exec_raw takes (timeout_sec, retries) and JSON-encodes the code itself;
# tc_gw_exec_retry's 4th arg is a JSON FRAGMENT, not a timeout — passing one
# there produced an invalid body and empty stdout (which then read as "setsid
# unavailable").
# The straggler MUST NOT inherit the exec's stdout pipe: a surviving child keeps
# the write end open, so the warden's capture ends without delivering stdout
# (observed: exit_code 0, no stdout field, ~3 s). Redirect its fds; the
# straggler still escapes kill(-pgid) via setsid, which is the property under
# test. The fallback chain (PATH setsid → busybox applet → explicit NO_SETSID)
# exists because the busybox template links no `setsid` in bin/ — the bare
# `setsid` this phase used before was "not found", so no straggler was ever
# created and the phase passed vacuously.
STRAG=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" \
    'if command -v setsid >/dev/null 2>&1; then setsid sleep 300 >/dev/null 2>&1 & elif busybox --list 2>/dev/null | grep -qx setsid; then busybox setsid sleep 300 >/dev/null 2>&1 & else echo NO_SETSID; exit 0; fi; echo straggler-spawned; sleep 1; ps | grep -c [s]leep' 30 6 | tc_json_stdout)
if echo "$STRAG" | grep -q "NO_SETSID"; then
    tc_fail "StragglerSweep: the guest offers neither a setsid binary nor the busybox applet — the EBUSY condition cannot be reproduced (phase would be vacuous)"
elif ! echo "$STRAG" | grep -q "straggler-spawned"; then
    tc_fail "StragglerSweep: straggler spawn did not run — output: $STRAG"
fi
STRAG_N=$(echo "$STRAG" | grep -oE '^[0-9]+$' | tail -1)
if [[ -z "$STRAG_N" || "$STRAG_N" -lt 1 ]]; then
    tc_fail "StragglerSweep: no live straggler process in the guest (count='${STRAG_N:-none}') — the unmount never faces EBUSY, phase would be vacuous. Output: $STRAG"
fi
sleep 1
# Switch away to B (mount A → mount B on the same pooled VM).
B_EXEC=""
for attempt in $(seq 1 12); do
    RB=$(tc_gw_exec_raw "$B_KEY" "$B_SANDFS" "echo sweep-ok" 30 3)
    if echo "$RB" | tc_json_stdout | grep -q "sweep-ok"; then B_EXEC=1; break; fi
    sleep 3
done
VM_AFTER=$(live_state_json || true)
if [[ -z "$B_EXEC" ]]; then
    tc_fail "StragglerSweep: post-straggler switch exec failed: $(echo "$RB" | head -c 200)"
elif [[ -n "$VM_BEFORE" && "$VM_BEFORE" == "$VM_AFTER" ]]; then
    tc_pass "StragglerSweep: same VM reused across switch with a live setsid straggler"
else
    tc_fail "StragglerSweep: VM destroyed for the switch (before=$VM_BEFORE after=$VM_AFTER) — rule-A sweep not effective"
fi
vm_alive "StragglerSweep"

# ══════════════════════════════════════════════════════════════
tc_log_section "MemCap: sync-exec RLIMIT_AS is enforced (not just inherited)"

# Every exec child gets RLIMIT_AS = agent_mem_percent% of VM RAM (sync execs
# are OUTSIDE the per-agent cgroup by design — this limit is their balloon
# guard). Inheritance is unit-tested; what is asserted HERE is that the limit
# BITES: a single allocation past /proc/self/limits' "Max address space"
# must be refused (malloc fails — the pages are never touched, so the guest
# sees no pressure), and the VM keeps serving afterwards.
MEMCAP_OUT=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" \
    'LIM=$(grep -m1 Max.address.space /proc/self/limits | tr -s " " | cut -d " " -f4); echo lim=$LIM; if [ "$LIM" = "unlimited" ] || [ -z "$LIM" ]; then echo cap=disabled; elif command -v dd >/dev/null 2>&1; then dd if=/dev/zero of=/dev/null bs=$((LIM*2)) count=1 >/dev/null 2>&1; echo dd-rc=$?; else echo cap=no-dd; fi' \
    30 3 || true)
MEMCAP_STDOUT=$(echo "$MEMCAP_OUT" | tc_json_stdout)
LIM=$(echo "$MEMCAP_STDOUT" | grep -o 'lim=[0-9]*' | cut -d= -f2 || true)
DD_RC=$(echo "$MEMCAP_STDOUT" | grep -o 'dd-rc=[0-9]*' | cut -d= -f2 || true)
if [[ "$MEMCAP_STDOUT" == *"cap=disabled"* ]]; then
    tc_log_warn "MemCap: RLIMIT_AS disabled by config (agent_mem_percent=0) — enforcement not exercised"
elif [[ "$LIM" =~ ^[0-9]+$ ]] && (( LIM > 0 )); then
    tc_pass "MemCap: RLIMIT_AS visible in guest (${LIM} bytes ≈ agent_mem_percent% of VM RAM)"
    if [[ "$MEMCAP_STDOUT" == *"cap=no-dd"* ]]; then
        tc_log_warn "MemCap: allocation probe skipped (no dd in template)"
    elif [[ -n "$DD_RC" && "$DD_RC" != "0" ]]; then
        tc_pass "MemCap: allocation past the cap refused (dd rc=$DD_RC)"
    else
        tc_fail "MemCap: allocated 2× the RLIMIT_AS (dd rc=$DD_RC) — the limit did not bite"
    fi
else
    tc_fail "MemCap: RLIMIT_AS not set (limits output: '$MEMCAP_STDOUT') — sync execs run uncapped"
fi
vm_alive "MemCap"

# ══════════════════════════════════════════════════════════════
tc_log_section "Warden Hostile Coverage Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo "[FAIL] Warden Hostile Coverage E2E FAILED"
    exit 1
fi
echo "[OK] Warden Hostile Coverage E2E PASSED"
exit 0
