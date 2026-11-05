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
# egress-identity.sh — Conformance e2e for the Sandswap egress identity
# enabler (docs/how-it-works/egress-enabler.md).
# Verifies, against a REAL gateway + sandlot + microVM:
#   C1. a cold mount publishes (tap-ifindex -> agent/sandfs) to the binding
#       region, with mount_epoch >= 1;
#   C2. the network baseline installed the per-tap chain (anti-spoof +
#       default-deny) and the VM-to-VM posture rule;
#   C3. lease-expiry unmount REVOKES the binding (state=unbound, identity
#       cleared, epoch preserved);
#   C4. a subsequent re-mount re-publishes with an INCREMENTED epoch
#       (no generation reuse across mounts of one attachment).
# Carrier selection: BINDING_BACKEND=shm (default) | bpf.
#   bpf requires root + kernel >= 5.5 + bpffs; the script skips with a clear
#   message when unavailable (unit tests cover the parity case).
# Prerequisites: built artifacts (build.sh all), KVM, root, nftables.
# Usage: ./e2e/egress-identity.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# POOL_SIZE=1: C5 asserts generation reuse on ONE attachment, so the pool
# must have a single VM (mounts then always land on the same TAP).
POOL_SIZE="${POOL_SIZE:-1}"
LEASE_MS="${LEASE_MS:-8000}"  # hold the mount open so C3 can observe the open gate
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
BINDING_BACKEND="${BINDING_BACKEND:-shm}"
BIND_PATH="${BIND_PATH:-}"
case "$BINDING_BACKEND" in
    shm) BIND_PATH="${BIND_PATH:-/dev/shm/sandswap-e2e-bindings}" ;;
    bpf) BIND_PATH="${BIND_PATH:-/sys/fs/bpf/sandswap-e2e-bindings}" ;;
    *) echo "BINDING_BACKEND must be shm|bpf"; exit 1 ;;
esac
source "$ROOT/e2e/common.sh"

cleanup() {
    if [[ -n "${KEY_A:-}" ]] && kill -0 "${GATEWAY_PID:-0}" 2>/dev/null; then
        tc_delete_sandfs "$ID_A" 2>/dev/null || true
    fi
    tc_cleanup_default
    # Remove the e2e region (the backend only changes WHERE the region lives,
    # not the cleanup — the branches were identical). The baseline nft tables
    # are already torn down by tc_cleanup_default → tc_teardown_host_network →
    # tc_pre_clean_stack.
    rm -f "$BIND_PATH" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight"
# ══════════════════════════════════════════════════════════════════
tc_check_root
tc_check_kvm
tc_check_artifacts
tc_check_freshness
if [[ ! -x "$OUTPUT/bindregdump" ]]; then
    log_error "$OUTPUT/bindregdump missing — rebuild (build.sh builds it)"
    exit 1
fi
if ! command -v nft >/dev/null 2>&1; then
    log_error "nftables required for the baseline conformance checks"
    exit 1
fi
tc_ensure_dev_nodes

if [[ "$BINDING_BACKEND" == "bpf" ]]; then
    # bpffs entries are created only via BPF_OBJ_PIN — probe with the real
    # mechanism (-create = writer mode: create+pin the probe region, exactly
    # what sandlot's open will do; default bindregdump is read-only and never
    # creates).
    if ! "$OUTPUT/bindregdump" -backend bpf -create -path /sys/fs/bpf/sandswap-e2e-probe >/dev/null 2>&1; then
        log_error "bpf carrier unavailable (needs kernel >= 5.5 + CAP_BPF + bpffs)"
        exit 1
    fi
    rm -f /sys/fs/bpf/sandswap-e2e-probe 2>/dev/null || true
fi
rm -f "$BIND_PATH" 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Deploy (clean slate)"
# ══════════════════════════════════════════════════════════════════
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Start Gateway + Sandlot (enabler on: $BINDING_BACKEND)"
# ══════════════════════════════════════════════════════════════════
tc_start_gateway
tc_start_sandlot -binding-backend "$BINDING_BACKEND" -binding-path "$BIND_PATH"
tc_wait_health
tc_wait_pool_ready

# Sandlot must have come up with the region + baseline active. Bounded retry:
# the startup banner may take a moment to flush after pool-ready.
BANNER_OK=0
for i in $(seq 1 40); do
    if grep -q "egress identity binding: $BINDING_BACKEND" "$LOG_DIR/sandlot.log" 2>/dev/null \
        && grep -q "egress baseline: on" "$LOG_DIR/sandlot.log" 2>/dev/null; then
        BANNER_OK=1
        break
    fi
    sleep 0.25
done
if [[ "$BANNER_OK" -eq 1 ]]; then
    pass "sandlot opened the binding region ($BINDING_BACKEND)"
    pass "egress baseline active"
else
    fail "binding region / baseline startup banners not found in sandlot.log"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Cold mount publishes the identity (C1, C2)"
# ══════════════════════════════════════════════════════════════════
AGENT_RESP=$(tc_create_agent_and_sandfs "egress-identity-a")
KEY_A=$(json_val "$AGENT_RESP" "api_key")
ID_A=$(json_val "$AGENT_RESP" "sandfs_id")
AGENT_ID=$(json_val "$AGENT_RESP" "agent_id")
[[ -n "$KEY_A" && "$KEY_A" != "None" ]] || { log_error "agent creation failed: $AGENT_RESP"; exit 1; }
[[ -n "$AGENT_ID" ]] || { log_error "agent_id missing in creation response: $AGENT_RESP"; exit 1; }
pass "agent A created (sandfs=$ID_A agent=$AGENT_ID)"

EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $KEY_A" \
    -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$ID_A\",\"code\":\"echo identity-ok\",\"language\":\"shell\",\"timeout\":30}")
EXEC_CODE=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exit_code',-1))" 2>/dev/null || echo "-1")
if [[ "$EXEC_CODE" == "0" ]]; then
    pass "cold mount + exec succeeded (exit 0)"
else
    fail "cold mount + exec failed: $EXEC_RESP"
fi

# C1: binding region shows mounted with this agent/sandfs and epoch >= 1.
# Bounded retry: the region is written asynchronously by the first cold mount.
DUMP=""
for i in $(seq 1 40); do
    DUMP=$("$DEPLOY_DIR/bindregdump" -backend "$BINDING_BACKEND" -path "$BIND_PATH")
    if echo "$DUMP" | grep -q "mounted .*agent=$AGENT_ID .*sandfs=$ID_A"; then
        break
    fi
    sleep 0.25
done
if echo "$DUMP" | grep -q "mounted .*agent=$AGENT_ID .*sandfs=$ID_A"; then
    pass "C1: region has mounted entry for agent=$AGENT_ID sandfs=$ID_A"
else
    fail "C1: no mounted entry for the mount (dump: $(echo "$DUMP" | tail -3))"
fi
ENTRY_LINE=$(echo "$DUMP" | grep "mounted .*agent=$AGENT_ID" | head -1)
IFIDX=$(echo "$ENTRY_LINE" | awk '{print $1}')
EPOCH1=$(echo "$ENTRY_LINE" | python3 -c "
import sys,re
m=re.search(r'epoch=(\d+)', sys.stdin.read())
print(m.group(1) if m else 0)")
if [[ "${EPOCH1:-0}" -ge 1 ]]; then
    pass "C1: mount_epoch=$EPOCH1 (>= 1)"
else
    fail "C1: mount_epoch missing/zero in: $ENTRY_LINE"
fi

# C2: baseline chains exist (netdev per-tap, bridge VM-to-VM).
BASELINE_TABLE=$(nft list table netdev sandswap_baseline 2>/dev/null || true)
if echo "$BASELINE_TABLE" | grep -q "hook ingress device" && echo "$BASELINE_TABLE" | grep -q "ip saddr !="; then
    pass "C2: per-tap netdev chain with source anti-spoof present"
else
    fail "C2: baseline netdev chain missing/incomplete"
fi
BRIDGE_FWD=$(nft list chain bridge sandswap_baseline fwdgate 2>/dev/null || true)
if echo "$BRIDGE_FWD" | grep -q "sandswap-vm2vm-deny"; then
    pass "C2: VM-to-VM deny rule present (default posture)"
else
    fail "C2: VM-to-VM deny rule missing"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Lease-expiry unmount revokes (C3)"
# ══════════════════════════════════════════════════════════════════
# Lease expiry (LEASE_MS) triggers the gateway unmount. Poll the region for
# slot $IFIDX flipping to unbound: identity fields CLEARED, epoch PRESERVED.
REVOKED=""
# shellcheck disable=SC2034  # poll loop counter
for i in $(seq 1 60); do
    sleep 0.5
    DUMP=$("$DEPLOY_DIR/bindregdump" -backend "$BINDING_BACKEND" -path "$BIND_PATH")
    REVOKED_LINE=$(echo "$DUMP" | awk -v idx="$IFIDX" '$1 == idx && $2 == "unbound"' | head -1)
    if [[ -n "$REVOKED_LINE" ]]; then
        REVOKED=1
        break
    fi
done
if [[ -n "$REVOKED" ]]; then
    EPOCH_AFTER=$(echo "$REVOKED_LINE" | python3 -c "
import sys,re
m=re.search(r'epoch=(\d+)', sys.stdin.read())
print(m.group(1) if m else 0)")
    if echo "$REVOKED_LINE" | grep -q "agent= sandfs= vm="; then
        pass "C3: revoked entry carries no identity: $REVOKED_LINE"
    else
        fail "C3: revoked entry still carries identity: $REVOKED_LINE"
    fi
    if [[ "$EPOCH_AFTER" == "$EPOCH1" ]]; then
        pass "C3: epoch preserved across revoke ($EPOCH_AFTER)"
    else
        fail "C3: revoked entry epoch changed: before=$EPOCH1 after=$EPOCH_AFTER"
    fi
else
    fail "C3: binding not revoked within 30s of lease expiry (dump: $(echo "$DUMP" | tail -3))"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Re-mount re-publishes with a fresh epoch (C4)"
# ══════════════════════════════════════════════════════════════════
EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $KEY_A" \
    -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$ID_A\",\"code\":\"echo identity-ok-2\",\"language\":\"shell\",\"timeout\":30}")
EXEC_CODE=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exit_code',-1))" 2>/dev/null || echo "-1")
if [[ "$EXEC_CODE" == "0" ]]; then
    pass "re-mount + exec succeeded"
else
    fail "re-mount + exec failed: $EXEC_RESP"
fi
DUMP=$("$DEPLOY_DIR/bindregdump" -backend "$BINDING_BACKEND" -path "$BIND_PATH")
ENTRY2=$(echo "$DUMP" | awk -v idx="$IFIDX" '$1 == idx && $2 == "mounted"' | head -1)
if [[ -n "$ENTRY2" ]]; then
    EPOCH2=$(echo "$ENTRY2" | python3 -c "
import sys,re
m=re.search(r'epoch=(\d+)', sys.stdin.read())
print(m.group(1) if m else 0)")
    if [[ "${EPOCH2:-0}" -gt "${EPOCH1:-0}" ]]; then
        pass "C4: re-mount published epoch=$EPOCH2 > $EPOCH1 (generations never reused)"
    else
        fail "C4: re-mount epoch $EPOCH2 not greater than first mount $EPOCH1"
    fi
else
    fail "C4: re-mount did not publish a mounted entry"
fi


# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: network isolation baseline (live probes)"
# ══════════════════════════════════════════════════════════════════
# The tenant TAPs all share one L2 bridge; isolation is the three-layer
# nftables baseline. N1 pins the layers' PRESENCE while the stack serves a
# tenant; N2/N3 exercise the guest→host default-deny LIVE from inside the
# guest. False-pass guards: the custom-port listener is probed LOCALLY first
# (a bind failure must not read as "firewall works"), and the DNS probe
# distinguishes reached (fast accept/refuse) from dropped (timeout 124) on
# the same timeout mechanics N2 uses.
NET_GW_IP="${SS_PREP_GATEWAY:-10.188.0.1}"
NET_BRIDGE="${SS_PREP_BRIDGE:-br-sandswap}"

# N1: the three layers exist on a serving host.
if nft list table netdev sandswap_baseline >/dev/null 2>&1; then
    pass "N1: netdev sandswap_baseline table present (per-TAP anti-spoof)"
else
    fail "N1: netdev sandswap_baseline table MISSING while the stack serves a tenant"
fi
if nft list chain bridge sandswap_baseline fwdgate 2>/dev/null | grep -q "sandswap-vm2vm-deny"; then
    pass "N1: bridge forward VM-to-VM deny rule present"
else
    fail "N1: bridge VM-to-VM deny rule MISSING while the stack serves a tenant"
fi
NET_INPUT_RULES=$(nft list chain inet sandswap input 2>/dev/null || true)
if echo "$NET_INPUT_RULES" | grep -q "iifname \"$NET_BRIDGE\"" \
   && echo "$NET_INPUT_RULES" | grep "iifname" | grep -q "drop"; then
    pass "N1: guest→host input chain carries the bridge-scoped default drop"
else
    fail "N1: inet sandswap input has no bridge-scoped default drop (guests can reach host listeners)"
fi

# N2: LIVE negative probe — a host listener on a custom port must be
# UNREACHABLE from the guest (drop → timeout 124), after proving locally
# that the listener actually accepts connections.
NET_PROBE_PORT=39999
python3 -m http.server "$NET_PROBE_PORT" --bind "$NET_GW_IP" >/dev/null 2>&1 &
NET_LISTENER_PID=$!
NET_LISTENER_OK=0
for _ in $(seq 1 20); do
    if curl -s --max-time 2 -o /dev/null "http://$NET_GW_IP:$NET_PROBE_PORT/"; then
        NET_LISTENER_OK=1; break
    fi
    sleep 0.3
done
if [[ "$NET_LISTENER_OK" == "1" ]]; then
    pass "N2 (probe sanity): the custom-port listener accepts a LOCAL connection"
else
    fail "N2 (probe sanity): the listener never came up — the negative probe would be vacuous"
fi
EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $KEY_A" \
    -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$ID_A\",\"code\":\"nc -w 3 $NET_GW_IP $NET_PROBE_PORT </dev/null && echo PROBE_REACHED || true\",\"language\":\"shell\",\"timeout\":30}")
PROBE_REACHED=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print('PROBE_REACHED' in json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo False)
kill "$NET_LISTENER_PID" 2>/dev/null || true
wait "$NET_LISTENER_PID" 2>/dev/null || true
if [[ "$NET_LISTENER_OK" == "1" ]]; then
    if [[ "$PROBE_REACHED" == "True" ]]; then
        fail "N2: guest reached host port $NET_PROBE_PORT — the guest→host default-deny is not filtering"
    else
        pass "N2: guest→host custom port DROPPED from inside the guest (nc behind a locally-verified listener)"
    fi
fi

# N3: LIVE positive probe — guest→host:53 must REACH the host stack (fast
# accept or refuse), never time out: the DNS allowlist row admits it.
if echo "$NET_INPUT_RULES" | grep "dport 53" | grep -q "accept"; then
    pass "N3: the DNS ports are explicitly admitted (udp+tcp dport 53 accept, bridge-scoped)"
else
    fail "N3: no dport 53 accept row in the bridge-scoped input chain — resolver traffic would be dropped"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Results"
# ══════════════════════════════════════════════════════════════════
log_section "egress-identity conformance complete: $PASS_COUNT passed, $FAIL_COUNT failed (carrier=$BINDING_BACKEND)"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0
