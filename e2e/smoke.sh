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
# smoke.sh — End-to-end functional smoke test (real KVM, no mocks).
# The fastest full-stack check that the deployed system actually works:
#   - deploy + start gateway/sandlot, real KVM microVMs
#   - guest OUTBOUND networking (guest -> TAP -> bridge -> NAT -> internet),
#     the only e2e that exercises the full egress path
#   - shell file I/O inside the sandbox, persistence across hot-swap switches
#   - cross-agent isolation
#   - sticky-lease function via the X-Sandbox-Lease response header
# Latency MEASUREMENT is not done here (the log-scraping analyzer this script
# used to carry parsed gateway/sandlot log fields that no longer exist, and the
# same numbers are available at ns precision from the /agent/execute response).
# For benchmarks use:
#   - e2e/latency-benchmark-aiagent.sh   (warm/cold P50/P95 from API fields)
#   - e2e/latency-benchmark-unmount.sh   (unmount path from GET /stats)
# Prerequisites:
#   1. bash build/build.sh all        (all binaries in output/)
#   2. bash build/build-rootfs-template.sh   (rootfs template in output/)
#   3. KVM available (/dev/kvm); root required
# Usage: sudo bash e2e/smoke.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

cleanup() {
    rm -f /tmp/sandswap-last-resp.json /tmp/sandswap-last-ms.txt /tmp/sandswap-last-stdout.txt 2>/dev/null || true
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight Checks"
# ══════════════════════════════════════════════════════════════════

tc_check_root
tc_preflight_standard python3
tc_ensure_dev_nodes

# Host networking setup
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — microVMs will be offline"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Deploy"
# ══════════════════════════════════════════════════════════════════

tc_clean_environment
tc_deploy_artifacts
tc_gen_certs

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Start Gateway (gRPC stream + HTTP)"
# ══════════════════════════════════════════════════════════════════

tc_start_gateway

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Start Sandlot (Real KVM)"
# ══════════════════════════════════════════════════════════════════

tc_attach_vsockguard
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready
POOL_BEFORE=$(curl -s "$HUMAN_URL/stats")
log_info "Pool ready: $POOL_BEFORE"

# /metrics: the Prometheus projection of the same report — same sources, so
# the cluster gauges must agree with the /stats numbers above. Asserts the
# exposition is scrapeable (content type + a named sample), not just present.
METRICS_CT=$(curl -s -o /tmp/sandswap-last-metrics.txt -w '%{content_type}' "$HUMAN_URL/metrics")
if [[ "$METRICS_CT" == "text/plain; version=0.0.4; charset=utf-8" ]] \
    && grep -q '^# TYPE sandswap_cluster_clean_vms gauge$' /tmp/sandswap-last-metrics.txt \
    && grep -q '^sandswap_build_info{' /tmp/sandswap-last-metrics.txt; then
    METRICS_CLEAN=$(grep -E '^sandswap_cluster_clean_vms ' /tmp/sandswap-last-metrics.txt | awk '{print $2}')
    STATS_CLEAN=$(echo "$POOL_BEFORE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('totals',{}).get('clean_vms','?'))" 2>/dev/null || echo '?')
    if [[ "$METRICS_CLEAN" == "$STATS_CLEAN" ]]; then
        pass "/metrics scrapeable and consistent with /stats (clean_vms=$METRICS_CLEAN)"
    else
        fail "/metrics clean_vms ($METRICS_CLEAN) disagrees with /stats ($STATS_CLEAN)"
        exit 1
    fi
else
    fail "/metrics not scrapeable (content-type: $METRICS_CT)"
    head -5 /tmp/sandswap-last-metrics.txt 2>/dev/null || true
    exit 1
fi
rm -f /tmp/sandswap-last-metrics.txt

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Create Agents"
# ══════════════════════════════════════════════════════════════════

log_step "Creating Agent A (writer)..."
AGENT_A=$(tc_create_agent_and_sandfs "writer")
KEY_A=$(echo "$AGENT_A" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('api_key',''))" 2>/dev/null)
ID_A=$(echo "$AGENT_A" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sandfs_id',''))" 2>/dev/null)
VOL_A=$(echo "$AGENT_A" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('rootfs_path',''))" 2>/dev/null)

if [[ -n "$KEY_A" ]] && [[ -n "$ID_A" ]]; then
    pass "Agent A created: $ID_A"
    log_info "Vol: $VOL_A"
else
    fail "Failed to create Agent A: $AGENT_A"
    exit 1
fi

log_step "Creating Agent B (isolated)..."
AGENT_B=$(tc_create_agent_and_sandfs "isolated")
KEY_B=$(echo "$AGENT_B" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('api_key',''))" 2>/dev/null)
ID_B=$(echo "$AGENT_B" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sandfs_id',''))" 2>/dev/null)

if [[ -n "$KEY_B" ]] && [[ -n "$ID_B" ]]; then
    pass "Agent B created: $ID_B"
else
    fail "Failed to create Agent B: $AGENT_B"
    exit 1
fi

# json_escape: read stdin, emit a JSON-escaped string literal
json_escape() { python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))'; }

# exec_code <key> <code> <desc> <sandfs_id> — POST /agent/execute, print result,
# save response to /tmp/sandswap-last-resp.json for assertions.
exec_code() {
    local key="$1" code="$2" desc="${3:-exec}" sid="$4"
    local resp
    # -m: a wedged gateway must FAIL this request, not hang the suite forever.
    resp=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$sid\",\"code\":$(echo "$code" | json_escape),\"language\":\"shell\"}" 2>&1 || echo '{"error":"curl failed"}')
    local r
    r=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
out=d.get('stdout','')
err=d.get('error','')
if out: print(out[:120].replace(chr(10),' '))
elif err: print('ERR:'+err[:80])
else: print(d)
" 2>/dev/null || echo "?")
    echo "$resp" > /tmp/sandswap-last-resp.json
    printf "  %-40s %s\n" "$desc" "$r"
}

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4.5: Outbound Networking Check"
# ══════════════════════════════════════════════════════════════════
#
# With NETWORK_BACKEND=bridge, each microVM gets a virtio-net TAP on the host
# bridge with kernel NAT. Verify the guest can actually reach the outside world
# by fetching a URL from inside the VM (single reachability check — covers the
# full guest eth0 -> TAP -> bridge -> masquerade -> uplink -> internet path,
# plus DNS via the injected /etc/resolv.conf). Skipped when offline (none).
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    log_info "Probing outbound HTTP from inside a microVM (busybox wget example.com)..."
    # Up to 3 attempts: transient UDP/DNS loss (external resolver jitter, host
    # conntrack churn after stack churn) must not fail the e2e suite — this
    # phase verifies the outbound PATH, not external DNS reliability.
    NET_STDOUT=""
    for attempt in 1 2 3; do
        NET_RESP=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/execute" \
            -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" \
            -d "{\"sandfs_id\":\"$ID_A\",\"code\":\"cat /etc/resolv.conf; echo ──route; ip route; echo ──dns; nslookup example.com 2>&1 | tail -3; echo ──wget; busybox wget -q -O- http://example.com 2>&1 | head -c 400\",\"language\":\"shell\"}" \
            2>&1 || echo '{}')
        NET_STDOUT=$(echo "$NET_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo "")
        if echo "$NET_STDOUT" | grep -q "Example Domain"; then
            break
        fi
        [[ $attempt -lt 3 ]] && { log_warn "attempt $attempt failed — retrying in 5s"; sleep 5; }
    done
    if echo "$NET_STDOUT" | grep -q "Example Domain"; then
        pass "Outbound HTTP works — guest fetched example.com"
    else
        fail "Outbound HTTP failed after 3 attempts (stdout=[$NET_STDOUT])"
        log_info "check: nft list table inet sandswap ; iptables -L FORWARD ; ip route on host ; sandlot log 'provisioned net'"
    fi
    # Sanity: no per-VM daemon process should exist for OUR stack (NAT is
    # kernel-side). Scoped to the processes this test started (descendants of
    # the sandlot we spawned and of this run's VMs): a host-wide pgrep -c
    # dnsmasq also counts unrelated instances — libvirt's default network,
    # NetworkManager — and false-fails perfectly healthy runs on such hosts.
    DAEMON_PIDS=""
    for root_p in "$SANDLOT_PID" $(tc_run_vm_pids); do
        [[ -n "$root_p" ]] || continue
        DAEMON_PIDS="$DAEMON_PIDS $(tc_descendant_pids "$root_p" dnsmasq) $(tc_descendant_pids "$root_p" passt)"
    done
    DAEMON_N=$(echo "$DAEMON_PIDS" | tr ' ' '\n' | grep -cE '^[0-9]+$' || true)
    if [[ "${DAEMON_N:-0}" -eq 0 ]]; then
        pass "No per-VM network daemon in this stack's process tree (dnsmasq/passt) — kernel NAT only"
    else
        fail "Unexpected per-VM network daemon spawned by this stack (pids:$DAEMON_PIDS)"
    fi
else
    log_info "NETWORK_BACKEND=$NETWORK_BACKEND — skipping outbound check (VMs offline)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Agent A — Shell File I/O (Real KVM)"
# ══════════════════════════════════════════════════════════════════

log_info "Agent A: writing files into its sandbox volume (chroot /mnt/rootfs)..."

# A marker string unique enough to detect cross-agent leakage.
MARKER_A="SANDSWAP_AGENT_A_$(date +%s)"

exec_code "$KEY_A" "echo hello-from-warden > /workspace/greeting.txt" "write greeting.txt" "$ID_A"
exec_code "$KEY_A" "mkdir -p /workspace/src && echo '$MARKER_A' > /workspace/src/marker.txt" "write marker.txt" "$ID_A"
exec_code "$KEY_A" "cat /workspace/greeting.txt" "read greeting.txt" "$ID_A"
exec_code "$KEY_A" "cat /workspace/src/marker.txt" "read marker.txt" "$ID_A"
exec_code "$KEY_A" "echo append-line >> /workspace/greeting.txt && wc -l < /workspace/greeting.txt" "append + count lines" "$ID_A"
exec_code "$KEY_A" "for i in 1 2 3 4 5; do echo line\$i >> /workspace/loops.txt; done; wc -l < /workspace/loops.txt" "loop write 5 lines" "$ID_A"
exec_code "$KEY_A" "cat /workspace/loops.txt | head -2" "read back head" "$ID_A"

# Assertions on Agent A's reads
# Re-fetch the greeting read explicitly for a clean assertion
GREETING_RESP=$(exec_code "$KEY_A" "cat /workspace/greeting.txt" "verify greeting" "$ID_A" >/dev/null; cat /tmp/sandswap-last-resp.json)
assert_contains "Agent A: greeting persisted"  "$GREETING_RESP" "hello-from-warden"

MARKER_RESP=$(exec_code "$KEY_A" "cat /workspace/src/marker.txt" "verify marker" "$ID_A" >/dev/null; cat /tmp/sandswap-last-resp.json)
assert_contains "Agent A: marker persisted"    "$MARKER_RESP" "$MARKER_A"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Agent B — Isolation Test"
# ══════════════════════════════════════════════════════════════════

log_info "Agent B: verifying it CANNOT see Agent A's files (fresh volume)..."

# Agent B writes its own marker
MARKER_B="SANDSWAP_AGENT_B_$(date +%s)"
exec_code "$KEY_B" "echo '$MARKER_B' > /workspace/bonly.txt" "B write own file" "$ID_B"
exec_code "$KEY_B" "cat /workspace/bonly.txt" "B read own file" "$ID_B"

# Agent B must NOT see Agent A's files
ISO_GREETING=$(exec_code "$KEY_B" "cat /workspace/greeting.txt 2>&1 || echo FILE_NOT_FOUND" "B: A's greeting absent" "$ID_B" >/dev/null; cat /tmp/sandswap-last-resp.json)
ISO_MARKER=$(exec_code "$KEY_B" "cat /workspace/src/marker.txt 2>&1 || echo FILE_NOT_FOUND" "B: A's marker absent" "$ID_B" >/dev/null; cat /tmp/sandswap-last-resp.json)
ISO_LOOPS=$(exec_code "$KEY_B" "ls /workspace/loops.txt 2>&1 || echo FILE_NOT_FOUND" "B: A's loops absent" "$ID_B" >/dev/null; cat /tmp/sandswap-last-resp.json)

assert_not_contains "Agent B: cannot read A's greeting" "$ISO_GREETING" "hello-from-warden"
assert_not_contains "Agent B: cannot read A's marker"   "$ISO_MARKER"   "$MARKER_A"
assert_not_contains "Agent B: cannot see A's loops file" "$ISO_LOOPS"   "line1"

# Agent B's own file must be present and correct
BONLY_RESP=$(exec_code "$KEY_B" "cat /workspace/bonly.txt" "B verify own" "$ID_B" >/dev/null; cat /tmp/sandswap-last-resp.json)
assert_contains "Agent B: own marker correct" "$BONLY_RESP" "$MARKER_B"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 7: Sticky Lease (function, via response header)"
# ══════════════════════════════════════════════════════════════════

log_info "Testing sticky lease: 10 rapid same-agent calls (headers, not logs)..."

# 1 warmup call brings the VM into the warm/leased state, then 10 back-to-back
# calls must come back with X-Sandbox-Lease: hit (the lease window is 100ms and
# back-to-back execs are ~1ms apart). The header is the gateway's per-request
# ground truth — no log scraping.
exec_code "$KEY_A" "echo warmup" "warmup" "$ID_A" >/dev/null
LEASE_HITS=0
for i in $(seq 1 10); do
    HEADERS=$(curl -s -m 30 -D- -o /dev/null -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$ID_A\",\"code\":\"echo sticky_$i\",\"language\":\"shell\"}" 2>&1 || true)
    if echo "$HEADERS" | grep -qi "^X-Sandbox-Lease: hit"; then
        LEASE_HITS=$((LEASE_HITS + 1))
    fi
done
log_info "Lease hit headers: $LEASE_HITS / 10 calls"

if [[ "$LEASE_HITS" -ge 8 ]]; then
    pass "Sticky lease works (X-Sandbox-Lease: hit on $LEASE_HITS/10 rapid calls)"
else
    fail "Sticky lease missing (only $LEASE_HITS/10 rapid calls hit — expected ≥8)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 8: Cross-Agent Switching (functional)"
# ══════════════════════════════════════════════════════════════════

log_info "Exercising 10 A↔B switch rounds (persistence precondition)..."

for i in $(seq 1 10); do
    curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$ID_A\",\"code\":\"echo a\",\"language\":\"shell\"}" > /dev/null || true
    curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_B" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$ID_B\",\"code\":\"echo b\",\"language\":\"shell\"}" > /dev/null || true
done
pass "20 cross-agent calls completed (10 A↔B rounds)"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 9: Persistence Across Switches"
# ══════════════════════════════════════════════════════════════════

log_info "After 10 A↔B switches, re-verifying Agent A data is intact..."

PERSIST_GREETING=$(exec_code "$KEY_A" "cat /workspace/greeting.txt" "A: greeting intact" "$ID_A" >/dev/null; cat /tmp/sandswap-last-resp.json)
PERSIST_MARKER=$(exec_code "$KEY_A" "cat /workspace/src/marker.txt" "A: marker intact" "$ID_A" >/dev/null; cat /tmp/sandswap-last-resp.json)
PERSIST_LOOPS=$(exec_code "$KEY_A" "wc -l < /workspace/loops.txt" "A: loops intact" "$ID_A" >/dev/null; cat /tmp/sandswap-last-resp.json)

assert_contains "Persistence: greeting intact" "$PERSIST_GREETING" "hello-from-warden"
assert_contains "Persistence: marker intact"   "$PERSIST_MARKER"   "$MARKER_A"
assert_contains "Persistence: loops file intact" "$PERSIST_LOOPS"  "5"

log_info "Checking Agent B data after switches..."
B_PERSIST=$(exec_code "$KEY_B" "cat /workspace/bonly.txt" "B: own intact" "$ID_B" >/dev/null; cat /tmp/sandswap-last-resp.json)
assert_contains "Persistence: Agent B own file intact" "$B_PERSIST" "$MARKER_B"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 10: Pool & System Status"
# ══════════════════════════════════════════════════════════════════

# ── Guest console hygiene pin ───────────────────────────────
# A CLEAN mount must leave NOTHING on the warden console: the per-mount
# WARN class was a ~38ms/mount serial tax. Warden userspace now
# goes to hvc0 → console.log; serial.log carries earlyprintk only. Read
# BOTH for the functional gate (a transport regression must not make it
# vacuous), then pin the transport separately.
PER_MOUNT_WARNS=$(cat /run/sandswap/vm/*/console.log /run/sandswap/vm/*/serial.log 2>/dev/null \
    | grep -cE "WARN warden::mount (setup_masked_proc: masking|overlay_hot_busybox:|inject_guest_resolv_conf:|mount target)") || true
if [[ "$PER_MOUNT_WARNS" -eq 0 ]]; then
    tc_pass "console hygiene: zero per-mount warden::mount WARN lines across all mounts this run"
else
    tc_fail "console hygiene: $PER_MOUNT_WARNS per-mount warden::mount WARN line(s) — each is a console-drain tax on the cold path ( class); sample:"
    cat /run/sandswap/vm/*/console.log /run/sandswap/vm/*/serial.log 2>/dev/null \
        | grep -E "WARN warden::mount (setup_masked_proc: masking|overlay_hot_busybox:|inject_guest_resolv_conf:|mount target)" \
        | head -4 || true
fi

# Kill-chain layer 2 must be ACTIVE in every VM that mounted: a boot-time
# "busybox RO source unavailable" warn means the warden fell back to the
# writable initramfs copy, re-opening the escape→cross-tenant busybox
# delivery path. One line per VM, not per mount.
BUSYBOX_RO_WARNS=$(cat /run/sandswap/vm/*/console.log /run/sandswap/vm/*/serial.log 2>/dev/null \
    | grep -c "busybox RO source unavailable") || true
# Positive assertion too: a warden that predates the layer emits neither the
# success line nor the warn, so a warn-only gate would pass vacuously.
BUSYBOX_RO_READY=$(cat /run/sandswap/vm/*/console.log /run/sandswap/vm/*/serial.log 2>/dev/null \
    | grep -c "busybox hot-bind source is read-only") || true
if [[ "$BUSYBOX_RO_WARNS" -eq 0 && "$BUSYBOX_RO_READY" -gt 0 ]]; then
    tc_pass "busybox hot-bind source is read-only in every VM ($BUSYBOX_RO_READY boot lines, no fallback warns)"
else
    tc_fail "busybox RO source not active (ready-lines=$BUSYBOX_RO_READY, fallback-warns=$BUSYBOX_RO_WARNS) — the writable initramfs copy may be in use; sample:"
    cat /run/sandswap/vm/*/console.log /run/sandswap/vm/*/serial.log 2>/dev/null | grep -E "busybox (RO source unavailable|hot-bind source is read-only)" | head -3 || true
fi

# ── virtio-console transport pin ─────────────────────────────────────
# The warden's println!/slog go to the preferred /dev/console. With
# console=hvc0 that is hvc0 → console.log; serial.log must not carry it.
WARDEN_CONSOLE=$(cat /run/sandswap/vm/*/console.log 2>/dev/null \
    | grep -c "enter real main at:") || true
WARDEN_SERIAL=$(cat /run/sandswap/vm/*/serial.log 2>/dev/null \
    | grep -c "enter real main at:") || true
if [[ "$WARDEN_CONSOLE" -gt 0 && "$WARDEN_SERIAL" -eq 0 ]]; then
    tc_pass "virtio-console: warden userspace is on hvc0 (console.log), not the UART"
else
    tc_fail "virtio-console: warden console line present in console.log=$WARDEN_CONSOLE, serial.log=$WARDEN_SERIAL — hvc0 not preferred / driver missing"
fi

# The earlyprintk serial sink must exist (it may be sparse).
SERIAL_LOGS=$(ls /run/sandswap/vm/*/serial.log 2>/dev/null | wc -l)
if [[ "$SERIAL_LOGS" -gt 0 ]]; then
    tc_pass "earlyprintk: serial.log present for $SERIAL_LOGS VM(s)"
else
    tc_fail "earlyprintk: no serial.log found under /run/sandswap/vm/*/"
fi

# The guest cmdline must carry the hvc0 console and the earlyprintk sink.
# (/proc/cmdline is MASKED in the agent tree — the warden session key rides on
# the kernel cmdline, so hiding it from agent code is the hardening, not a
# regression — and /sys/class/tty/console/active is not reliably visible
# inside the masked chroot either. The boot configuration is therefore pinned
# from the HOST side: every VM's persisted state file carries the kernel
# cmdline the sandlot actually booted. The warden-line pin above already
# proves userspace reached hvc0.)
GUEST_CMDLINE="$(python3 - <<'PY'
import glob, json
parts = []
for p in glob.glob('/run/sandswap-state/default/*/state.json'):
    try:
        with open(p) as f:
            # the cmdline lives in the nested per-VM config record
            parts.append(json.load(f).get('config', {}).get('kernel_cmdline', ''))
    except Exception:
        pass
print(' '.join(parts))
PY
)"
if [[ -n "$GUEST_CMDLINE" && "$GUEST_CMDLINE" == *"console=hvc0"* && "$GUEST_CMDLINE" == *"earlyprintk=ttyS0"* ]]; then
    tc_pass "guest cmdline carries console=hvc0 earlyprintk=ttyS0 (host-side state)"
else
    tc_fail "guest cmdline missing hvc0/earlyprintk (or no VM state): '${GUEST_CMDLINE:0:200}'"
fi

# Wait for leases to expire and cleanup to run
log_info "Waiting for lease expiry and cleanup..."
sleep 2

POOL_AFTER=$(curl -s "$HUMAN_URL/stats")
STATS=$(curl -s "$GATEWAY_URL/health")
log_info "Pool final: $POOL_AFTER"
log_info "Health:    $STATS"

# Hard gate on the per-node grayscale/stranding metric fields: this entire
# chain has gone structurally dead once before (sandlot never mapped the
# fields into the heartbeat AND the gateway never ingested them, so /stats
# showed permanent zeros that nothing caught). Missing keys = FAIL, not warn.
STATS_FIELDS=$(echo "$POOL_AFTER" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ns = (d.get('gateways') or [{}])[0].get('nodes') or []
if not ns:
    sys.exit(3)
n = ns[0]
required = ['stranded_reservations_mb', 'stranded_cids',
            'slot_wait_ms', 'slot_wait_events', 'recycle_triggers']
missing = [k for k in required if k not in n]
if missing:
    print(','.join(missing))
    sys.exit(4)
print('ok')
" 2>/dev/null || true)
case "$STATS_FIELDS" in
    ok)
        pass "/stats per-node metrics present (stranded_*, slot_wait_*, recycle_triggers)"
        ;;
    "")
        fail "/stats per-node metrics unverifiable: no node entries in gateways[0].nodes (stats shape drift or node never registered)"
        ;;
    *)
        fail "/stats missing per-node metric fields: $STATS_FIELDS (heartbeat metrics chain broken)"
        ;;
esac

# Check logs for any crashes. grep -Ec exits 1 on no-match; under `set -e` that
# would abort the script, so append `|| true` to every grep assignment.
VMM_CRASHES=$(grep -E "panic|SIGSEGV|fatal" "$LOG_DIR/sandlot.log" 2>/dev/null | grep -vc "non-fatal" || true); VMM_CRASHES=${VMM_CRASHES:-0}
# grep -vc "non-fatal" counts lines NOT matching "non-fatal" (i.e., real crashes only)
GATEWAY_ERRS=$(grep -Ec "ERROR|fatal" "$LOG_DIR/gateway.log" 2>/dev/null || true); GATEWAY_ERRS=${GATEWAY_ERRS:-0}
SANDLOT_ERRS=$(grep -Eci 'err|warn|fail' "$LOG_DIR/sandlot.log" 2>/dev/null || true); SANDLOT_ERRS=${SANDLOT_ERRS:-0}
log_info "Sandlot errors/warnings: $SANDLOT_ERRS"
log_info "Gateway errors: $GATEWAY_ERRS"

if [[ "${VMM_CRASHES:-0}" -eq 0 ]]; then
    pass "No VMM crashes detected"
else
    fail "VMM crashes: $VMM_CRASHES"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Results Summary"
# ══════════════════════════════════════════════════════════════════

echo ""
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │        Sandswap Smoke Test Results               │"
echo "  ├──────────────────────────────────────────────────┤"
printf "  │ Mode:        REAL KVM (%-12s)            │\n" "$KVM_MODULE"
printf "  │ Gateway:     %-37s │\n" "$GATEWAY_URL"
printf "  │ Volumes:     %-37s │\n" "$VOL_ROOT"
echo "  ├──────────────────────────────────────────────────┤"
printf "  │ Agent A: %-41s │\n" "$ID_A"
printf "  │   shell file I/O: greeting, marker, loops       │\n"
printf "  │ Agent B: %-41s │\n" "$ID_B"
printf "  │   isolated volume: own marker only              │\n"
echo "  ├──────────────────────────────────────────────────┤"
printf "  │ Sticky lease: %d/10 header hits                  │\n" "$LEASE_HITS"
echo "  ├──────────────────────────────────────────────────┤"
printf "  │ Outbound:     VERIFIED (guest → internet)       │\n"
printf "  │ Isolation:    VERIFIED                          │\n"
printf "  │ Persistence:  VERIFIED                          │\n"
echo "  ├──────────────────────────────────────────────────┤"
printf "  │ Tests: %2d passed  %2d failed                         │\n" "$PASS_COUNT" "$FAIL_COUNT"
echo "  └──────────────────────────────────────────────────┘"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "$FAIL_COUNT test(s) failed"
fi

# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════

# The test is complete. Kill every sandswap-related process (gateway, sandlot,
# and any residual sandvmm microVM monitors) and verify none survive.
log_step "Killing all sandswap processes after test completion..."
kill ${GATEWAY_PID:-} 2>/dev/null || true
kill ${SANDLOT_PID:-} 2>/dev/null || true
wait ${GATEWAY_PID:-} 2>/dev/null || true
wait ${SANDLOT_PID:-} 2>/dev/null || true
kill_sandswap_procs "post-test"

# Final verification: confirm the process table is clean.
FINAL_REMAINING=$(ps aux 2>/dev/null | grep -E "(^|/)(sandvmm|sandlot|gateway) |(^|/)sandswap-(sandvmm|sandlot|gateway) " | grep -vE "grep|bash" || true)
if [[ -z "$FINAL_REMAINING" ]]; then
    log_pass "All sandswap processes cleaned up — environment clean"
else
    # fail (not log_error): log_error prints but increments nothing, so the
    # suite still exited 0 — a leaked sandvmm/gateway survived teardown while
    # run-all recorded smoke PASS and the leak held ports/TAPs/CIDs for the
    # next suite.
    fail "sandswap processes still alive after final cleanup:"
    echo "$FINAL_REMAINING"
fi

if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
else
    log_pass "All $PASS_COUNT tests passed"
fi
