#!/bin/bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# multi-instance-orphan-safety.sh — orphan sweep must not cross instances
# Covers the multi-instance restart regression:
#   OrphanScope  the startup orphan sweep (killOrphanSandvmmStatic) scans ALL of
#       /proc and used to kill every sandvmm whose --api-socket was not in ITS
#       OWN live set — on a multi-instance host (a supported deployment:
#       instance.id + per-instance CID ranges) that meant restarting instance B
#       SIGTERM+SIGKILLed instance A's ENTIRE VM fleet. The sweep now only ever
#       signals sandvmm whose socket lives under the instance's own sandbox
#       root; everything else is skipped with a log line.
# Scenario: instance A (default sandbox root) runs pool small:2 with a live
# exec; instance B (instance.id=ib, its own sandbox root + CID range) starts
# on the same host — B's startup sweep runs before B even connects. Under the
# old code A's sandvmm processes die at that moment; with the scoping fix they
# survive untouched and A keeps serving.
# Prerequisites: built artifacts in output/, /dev/kvm available, root.
# Usage: bash e2e/multi-instance-orphan-safety.sh

set -euo pipefail

for p in "$HOME/.cargo/bin" "$HOME/go/bin" /usr/local/go/bin; do
    [[ -d "$p" ]] && case ":$PATH:" in *":$p:"*) ;; *) PATH="$p:$PATH" ;; esac
done
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Honor the battery's isolated root (see e2e/seccomp.sh for the same
# defaulting bug: literal production paths here deployed into
# /var/lib/sandswap and made every inline spawn hit the production volumes
# tree, which the nosuid,nodev startup gate refuses).
VOL_ROOT="${VOL_ROOT:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
DEPLOY_DIR="${DEPLOY_DIR:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}}"
POOL_SIZE=2
# shellcheck disable=SC2034  # SANDLOT_POOL is consumed by the SOURCED common.sh across the source boundary
SANDLOT_POOL="small:${POOL_SIZE}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
source "$ROOT/e2e/common.sh"

tc_use_output_binaries
tc_install_flat_template

tc_check_root
if [[ ! -e /dev/kvm ]] || [[ ! -r /dev/kvm ]]; then
    tc_log_error "/dev/kvm not available - this E2E requires KVM."
    exit 1
fi
if [[ ! -f "$OUTPUT/sandlot" ]] || [[ ! -f "$OUTPUT/sandvmm" ]] || [[ ! -f "$OUTPUT/gateway" ]]; then
    tc_log_error "build artifacts missing in output/ - run 'bash build/build.sh all' first."
    exit 1
fi

# Instance-B VM pids, enumerated from B's OWN sandbox root (the default
# tc_run_vm_pids only reads the default root).
ib_vm_pids() {
    local st pid
    for st in /run/sandswap-state/ib/*/state.json; do
        [[ -f "$st" ]] || continue
        pid=$(python3 -c "import json;print(json.load(open('$st')).get('pid',''))" 2>/dev/null) || pid=""
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        if [[ -d "/proc/$pid" ]] && [[ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" == "sandvmm" ]]; then
            echo "$pid"
        fi
    done | sort -nu
    return 0
}

tc_log_section "Multi-instance orphan sweep safety E2E"

tc_check_tools curl python3
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network
tc_attach_vsockguard

tc_start_gateway
# Instance A: the default node (node id test-node-1, sandbox root
# /run/sandswap/vm, default CID range from 3).
TC_NODE_ID="mi-a" tc_start_sandlot
tc_wait_health
tc_wait_pool_ready "$POOL_SIZE"

# ══════════════════════════════════════════════════════════════
# Role-lock negative paths (one sandlot per host). Instance A already holds
# the lock and the lock is judged BEFORE any gateway contact, so all three
# probes race only A's lock. Refusal strings are asserted verbatim from
# acquireRoleLock — a regression that flips only the exit code must not pass.
# ══════════════════════════════════════════════════════════════
tc_log_section "Role lock: one sandlot per host"

# rl_wait_exit <pid> <timeout_s> — reap the child and ECHO its rc ("0"/"N"/
# "-1" still alive at the deadline); always returns 0 so `rc="$(...)"` is
# set -e safe (a plain `return $?` would kill the suite the moment a probe
# is refused — the very outcome under test). Polls /proc state because
# kill -0 succeeds on unreaped zombies (an exited-but-unwaited child would
# spin the poll forever).
rl_wait_exit() {
    local pid="$1" deadline="$2" n=0 rc
    while (( n < deadline * 5 )); do
        if [[ ! -d "/proc/$pid" ]] || [[ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" == "Z" ]]; then
            wait "$pid" 2>/dev/null
            rc=$?
            echo "$rc"
            return 0
        fi
        sleep 0.2
        n=$((n + 1))
    done
    echo -1
    return 0
}

RL_CONFIG="$LOG_DIR/sandlot-rolelock-probe.yaml"

# The role-lock probes are LOCAL assertions: they point at a dead gateway and
# each runs under its OWN instance id, so their sandbox root (and private
# state root) is isolated from instance A's. Without the instance id a
# co-located probe shares /run/sandswap/vm and its startup cleanup deletes the
# MAIN instance's state records / orphan-sweeps its VMs.
#
# NOTE: with instance mode active the EFFECTIVE node id is
# "<node_id>-<instance_id>" — the duplicate-node probe below composes "mi-a".
write_rl_config() {
    local node="$1" inst="$2" cert_prefix="$3"
    cat > "$RL_CONFIG" <<EOF
gateway_addr: "localhost:1"
node_id: "${node}"
vmm_binary: "${TC_VMM_BINARY}"

microvm:
  kernel: "${TC_KERNEL}"
  initramfs: "${TC_INITRAMFS}"
  volumes_dir: "${VOL_ROOT}"

instance:
  id: "${inst}"

roles: [exec]

network:
  backend: "none"

tls:
  cert: "${cert_prefix}.crt"
  key: "${cert_prefix}.key"
  ca: "${CERT_DIR}/ca.crt"
EOF
}

# expect_role_refusal <label> <required-log-string>
expect_role_refusal() {
    local label="$1" want="$2" rc
    rc="$(rl_wait_exit "$RL_PID" 8)"
    if [[ "$rc" == "-1" ]]; then
        tc_fail "role-lock: $label — probe still running, lock NOT enforced"
        kill "$RL_PID" 2>/dev/null || true
        wait "$RL_PID" 2>/dev/null || true
        return 0
    fi
    if (( rc == 0 )); then
        tc_fail "role-lock: $label — exited 0 (refusal expected)"
    elif ! grep -q "$want" "$RL_LOG"; then
        tc_fail "role-lock: $label — refused (rc=$rc) without the named reason '$want': $(tail -3 "$RL_LOG" | tr '\n' ' ')"
    else
        tc_pass "role-lock: $label"
    fi
}

PROBE_CERT="$(tc_node_cert rl-probe-probe)"

RL_LOG="$LOG_DIR/sandlot-rl1.log"
write_rl_config rl-probe probe "$PROBE_CERT"
"$TC_SANDLOT_BIN" -config "$RL_CONFIG" -allow-insecure-volumes -allow-missing-vsockguard >"$RL_LOG" 2>&1 &
RL_PID=$!
expect_role_refusal "second instance refused without the hatch" "already runs a sandlot instance"

RL_LOG="$LOG_DIR/sandlot-rl2.log"
write_rl_config mi a "$(tc_node_cert mi-a)"
"$TC_SANDLOT_BIN" -config "$RL_CONFIG" -allow-colocated-instances -allow-insecure-volumes -allow-missing-vsockguard >"$RL_LOG" 2>&1 &
RL_PID=$!
expect_role_refusal "duplicate node_id refused even with the hatch" "already running on this host"

RL_LOG="$LOG_DIR/sandlot-rl3.log"
write_rl_config rl-probe probe "$PROBE_CERT"
"$TC_SANDLOT_BIN" -config "$RL_CONFIG" -allow-colocated-instances -allow-insecure-volumes -allow-missing-vsockguard >"$RL_LOG" 2>&1 &
RL_PID=$!
rc="$(rl_wait_exit "$RL_PID" 3)"
if [[ "$rc" == "-1" ]]; then
    tc_pass "role-lock: -allow-colocated-instances admits a DISTINCT node id (simulation hatch works)"
    kill "$RL_PID" 2>/dev/null || true
    wait "$RL_PID" 2>/dev/null || true
else
    tc_fail "role-lock: escape hatch refused a distinct node id (rc=$rc): $(tail -3 "$RL_LOG" | tr '\n' ' ')"
fi

cleanup() {
    kill "${SANDLOT_B_PID:-}" 2>/dev/null || true
    wait "${SANDLOT_B_PID:-}" 2>/dev/null || true
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

tc_create_agent_and_sandfs "orphan-safety-test"
tc_log_pass "agent=$TC_AGENT_ID sandfs=$TC_SANDFS_ID"

R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo before-second-instance")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "instance A exec works before instance B starts" \
    || tc_fail "instance A exec failed: $(body_of "$R")"

mapfile -t A_PIDS < <(tc_run_vm_pids)
[[ ${#A_PIDS[@]} -eq "$POOL_SIZE" ]] \
    || { tc_fail "instance A expected $POOL_SIZE VMs, got ${#A_PIDS[@]}"; exit 1; }
tc_log_info "instance A VM pids: ${A_PIDS[*]}"

# ══════════════════════════════════════════════════════════════
# Start instance B on the SAME host: its startup runs the orphan sweep over
# the shared /proc. Offline backend (network: none) keeps B's IP allocator
# fully separate from A's bridge subnet; its own CID range avoids vsock
# collisions. B's sweep must skip A's sandvmm (sockets outside B's root).
# ══════════════════════════════════════════════════════════════
tc_log_section "Start instance B (same host, own sandbox root + CID range)"

# B must look like a RESTART, not a first-ever start: embedded re-adopt returns
# early when the sandbox root is absent (nothing of THIS instance exists to
# adopt or sweep), so the sweep — and therefore the regression — only fires
# when the root pre-exists. Pre-create it (a prior B run's leftover).
mkdir -p /run/sandswap/ib/vm

B_CONFIG="$LOG_DIR/sandlot-ib.yaml"
cat > "$B_CONFIG" <<EOF
gateway_addr: "localhost${STREAM_ADDR}"
node_id: "mi-b"
vmm_binary: "${TC_VMM_BINARY}"

microvm:
  kernel: "${TC_KERNEL}"
  initramfs: "${TC_INITRAMFS}"
  default_vcpus: 1
  default_memory_mb: 128
  volumes_dir: "${VOL_ROOT}"

specs:
  small:
    vcpus: 1
    memory_mb: 128
    exec_slots: 2

pool: "small:1"

network:
  backend: "none"

instance:
  id: "ib"
  base_dir: "/run/sandswap"
  cid_range_start: 200
  cid_range_end: 300

tls:
  # The stream CN must equal the EFFECTIVE node id (node_id + "-" + instance.id).
  cert: "$(tc_node_cert mi-b-ib).crt"
  key: "$(tc_node_cert mi-b-ib).key"
  ca: "${CERT_DIR}/ca.crt"
EOF
tc_log_pass "instance B config written to $B_CONFIG"

# -allow-colocated-instances: this test deliberately models the colocated
# multi-instance class (instance.id + per-instance CID ranges) — the
# one-sandlot-per-host role lock is bypassed for the second instance only.
# TLS comes from the config's per-node pair (CN == the effective node id);
# CLI -tls-cert/-key would override it with the default pair and the gateway
# would refuse the stream on the identity gate.
"$TC_SANDLOT_BIN" \
    -config "$B_CONFIG" \
    -allow-colocated-instances \
    -allow-insecure-volumes -allow-missing-vsockguard \
    -gateway-addr "localhost${STREAM_ADDR}" \
    > "$LOG_DIR/sandlot-b.log" 2>&1 &
SANDLOT_B_PID=$!
tc_log_pass "instance B starting (pid $SANDLOT_B_PID)"

# Wait for B's own pool VM to be live (boot budget: nested-virt-safe 150s).
B_OK=0
# shellcheck disable=SC2034  # poll loop counter
for i in $(seq 1 150); do
    sleep 1
    mapfile -t B_PIDS < <(ib_vm_pids)
    if [[ ${#B_PIDS[@]} -ge 1 ]] && kill -0 "$SANDLOT_B_PID" 2>/dev/null; then
        B_OK=1; break
    fi
    kill -0 "$SANDLOT_B_PID" 2>/dev/null || break
done
if [[ $B_OK -eq 1 ]]; then
    tc_pass "instance B bootstrapped its own VM (pid $(ib_vm_pids | head -1)) with A's fleet untouched"
else
    tc_fail "instance B did not come up (own VM missing or process died); see $LOG_DIR/sandlot-b.log"
fi

# CP1 discriminator: B's STREAM must be accepted (CN == effective node id).
# Before this assertion the suite only proved B started locally, so an
# identity-gate refusal (the exact CP1 regression class) stayed invisible.
# The load snapshot is published periodically; poll briefly instead of
# reading the instant B's own VM is up.
B_STREAM=0
for _ in $(seq 1 30); do
    B_STREAM=$(curl -s -m 10 "$HUMAN_URL/stats" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print(0); raise SystemExit
ns = []
for g in d.get('gateways', []):
    ns += (g.get('nodes') or [])
print(sum(1 for n in ns if 'mi-b' in str(n.get('node_id') or n.get('id') or '')))
" 2>/dev/null || echo 0)
    [[ "$B_STREAM" -ge 1 ]] && break
    sleep 1
done
if [[ "$B_STREAM" -ge 1 ]]; then
    tc_pass "instance B's node stream is accepted and visible in /stats (per-node CN matches the effective id)"
else
    tc_fail "instance B's stream is NOT visible in /stats — the identity gate refused it (see $LOG_DIR/sandlot-b.log)"
fi

# ══════════════════════════════════════════════════════════════
# The discriminator: EVERY instance-A sandvmm must still be alive after B's
# startup sweep ran. The old unscoped sweep killed them all here.
# ══════════════════════════════════════════════════════════════
tc_log_section "Instance A fleet survival"

ALIVE=0
for pid in "${A_PIDS[@]}"; do
    if [[ -d "/proc/$pid" ]] && [[ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" == "sandvmm" ]]; then
        ALIVE=$((ALIVE + 1))
    fi
done
if [[ "$ALIVE" -eq "${#A_PIDS[@]}" ]]; then
    tc_pass "all ${#A_PIDS[@]} instance-A sandvmm survived instance B's startup sweep"
else
    tc_fail "instance B's orphan sweep killed instance A VMs ($ALIVE/${#A_PIDS[@]} alive) — sweep not scoped to its sandbox root"
fi

# Scoping evidence in B's log: skips logged, no kills of foreign pids.
if grep -q "outside this instance's sandbox root" "$LOG_DIR/sandlot-b.log"; then
    tc_pass "instance B log shows foreign sandvmm skipped (scope evidence)"
else
    tc_log_warn "no skip line in B's log (non-fatal if wording changed; survival verified above)"
fi
for pid in "${A_PIDS[@]}"; do
    if grep -q "orphan sweep: killing sandvmm pid $pid" "$LOG_DIR/sandlot-b.log"; then
        tc_fail "instance B killed instance A's sandvmm pid $pid"
    fi
done

# Instance A keeps serving end-to-end.
R=$(gw_exec "$TC_API_KEY" "$TC_SANDFS_ID" "echo after-second-instance")
[[ "$(http_code_of "$R")" == "200" ]] \
    && tc_pass "instance A exec still works after instance B startup" \
    || tc_fail "instance A exec broken after instance B started: $(body_of "$R")"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "[FAIL] multi-instance-orphan-safety E2E FAILED"
    exit 1
fi
echo "[OK] multi-instance-orphan-safety E2E PASSED"
exit 0
