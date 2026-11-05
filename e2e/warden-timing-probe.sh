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
# warden-timing-probe.sh — keep-logs stack for profiling the exec path at the
# warden level. Unlike the e2e benchmarks (which delete everything on exit),
# this deploys a throwaway stack to /tmp/ssdbg, runs warm + switch execs, and
# PRESERVES all logs in /tmp/ssdbg-logs — including every VM's console.log
# (hvc0) with warden's own timing lines ("exec done in Xms (spawn= wait=)",
# "mount_and_exec done (mount=)", "unmount_workspace done"); serial.log keeps
# the earlyprintk lines.
# This is the tool for localizing exec-latency issues (per-exec
# cgroup.procs migration, highres=off tick quantization, SIGCHLD wakeup chain)
# Usage:
#   sudo bash e2e/warden-timing-probe.sh [none|bridge]    (default: bridge)
# Env: WARM_N=30 SWITCH_ROUNDS=20 NETWORK_* (bridge params, defaults below)
# Output: /tmp/ssdbg-logs/{probe-samples.txt,serial/*.log,console/*.log,gateway.log,sandlot.log}
#
# The stack is assembled through the SHARED framework (e2e/common.sh →
# common/sh/{runtime,stack}.sh), exactly like every other suite: identities,
# runtime dirs, device owners, cert scoping, the flat-template tree, the
# volume-name seed and the template store are the framework's job. The probe
# hand-rolled all of it before and each hand-rolled piece drifted — the last
# one (a root-owned template store beside the volumes dir) made the prov role
# die at startup while the probe still "ran" and printed an all-zeros table.
# The health gate at the end exists for that reason.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
D=/tmp/ssdbg
VOLS=$D/volumes
LOGS=/tmp/ssdbg-logs
NET="${1:-bridge}"
WARM_N="${WARM_N:-30}"
SWITCH_ROUNDS="${SWITCH_ROUNDS:-20}"
NETWORK_BRIDGE="${NETWORK_BRIDGE:-br-sandswap}"
NETWORK_SUBNET="${NETWORK_SUBNET:-10.188.0.0/16}"
NETWORK_GATEWAY="${NETWORK_GATEWAY:-10.188.0.1}"
NETWORK_DNS="${NETWORK_DNS:-8.8.8.8}"

# The probe's own root and ports: a throwaway stack under $D that can run
# beside anything else on the box. KEEP_LOGS=1 is the point of the tool.
export DEPLOY_DIR="$D"
export VOL_ROOT="$VOLS"
export LOG_DIR="$LOGS"
export CERT_DIR="$D/certs"
export GATEWAY_ADDR=":3001" HUMAN_ADDR="127.0.0.1:3101" STREAM_ADDR=":9999"   # human must be loopback (anonymous gate)
export GATEWAY_URL="http://localhost:3001" HUMAN_URL="http://localhost:3101"
export TC_NODE_ID="probe-node"
export KEEP_LOGS=1
# shellcheck disable=SC1091
source "$ROOT/e2e/common.sh"

tc_check_root
tc_check_artifacts vmlinux.bin initramfs.cpio.gz sandvmm gateway sandlot
tc_check_tools curl python3 openssl

if [[ "$NET" == "bridge" ]]; then
    NETWORK_BACKEND="bridge"
else
    NETWORK_BACKEND="none"
fi

# Fresh stack: kills leftovers, wipes /run/sandswap, the volumes tree and the
# previous run's logs, then applies the identity/ownership contract (dirs,
# seed, template store, share root).
tc_clean_environment
tc_ensure_dev_nodes
tc_deploy_artifacts
tc_gen_certs

if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
fi

tc_start_gateway
tc_wait_health
# -warden-log debug is what makes the console logs carry the timing lines this
# probe reads back.
TC_SANDLOT_EXTRA_FLAGS="-warden-log debug"
tc_start_sandlot
if ! tc_wait_pool_ready; then
    tc_log_error "pool never reached $POOL_SIZE CLEAN VMs — probe cannot measure anything"
    echo "=== sandlot log (tail) ==="; tail -20 "$LOG_DIR/sandlot.log"
    tc_cleanup_default
    exit 1
fi

# Two sandfs on the same VM pool: alternating execs between them forces the
# mount/switch path instead of the warm path.
RA=$(ss_agent_and_sandfs "$HUMAN_URL" A "$TC_DEFAULT_TEMPLATE" flat)
RB=$(ss_agent_and_sandfs "$HUMAN_URL" B "$TC_DEFAULT_TEMPLATE" flat)
# Command substitution runs in a subshell, so ss_agent_and_sandfs's globals do
# NOT reach this shell — read the ids back out of its JSON.
KA=$(printf '%s' "$RA" | ss_json_field api_key)
FA=$(printf '%s' "$RA" | ss_json_field sandfs_id)
KB=$(printf '%s' "$RB" | ss_json_field api_key)
FB=$(printf '%s' "$RB" | ss_json_field sandfs_id)
echo "agents ready: sandfsA=$FA sandfsB=$FB"
if [[ -z "$FA" || -z "$FB" ]]; then
    tc_log_error "sandfs creation failed (A='$RA' B='$RB') — probe cannot measure anything"
    tc_cleanup_default
    exit 1
fi

exec1() { # key sandfs marker -> "client_s|gateway_ms|sandlot_ms|exec_ms"
  local out
  out=$(curl -s -o "$D/probe-resp.json" -w '%{time_total}' -X POST "$GATEWAY_URL/agent/execute" \
    -H "Content-Type: application/json" -H "X-Sandswap-Api-Key: $1" \
    -d "{\"sandfs_id\":\"$2\",\"language\":\"shell\",\"code\":\"echo $3\"}")
  python3 -c "
import json
d=json.load(open('$D/probe-resp.json'))
print(f\"{$out}s|{d.get('gateway_duration_ns',0)/1e6:.3f}|{d.get('sandlot_duration_ns',0)/1e6:.3f}|{d.get('exec_duration_ns',0)/1e6:.3f}\")"
}

exec1 "$KA" "$FA" warmup >/dev/null   # excluded

echo "idx class client gateway sandlot exec" | tee "$LOGS/probe-samples.txt"
i=0
for n in $(seq 1 "$WARM_N"); do
  i=$((i+1)); echo "$i warm $(exec1 "$KA" "$FA" a)" >> "$LOGS/probe-samples.txt"; sleep 0.005
done
sleep 1
for _ in $(seq 1 "$SWITCH_ROUNDS"); do
  i=$((i+1)); echo "$i cold $(exec1 "$KA" "$FA" a)" >> "$LOGS/probe-samples.txt"; sleep 0.3
  i=$((i+1)); echo "$i cold $(exec1 "$KB" "$FB" b)" >> "$LOGS/probe-samples.txt"; sleep 0.3
done

# Health gate: a sample whose server-side exec_ms is 0 is a REFUSED request
# (an error body carries no timings) — without this the probe happily printed
# an all-zeros table from a stack whose prov role had died at startup.
measured=$(awk -F'|' 'NR>1 && ($4+0) > 0' "$LOGS/probe-samples.txt" | wc -l)
total=$(( WARM_N + SWITCH_ROUNDS * 2 ))
echo "measured samples: $measured/$total"
if (( measured < total / 2 )); then
    tc_log_error "only $measured/$total samples carry server-side timings — the stack never served real execs"
    echo "=== sandlot log (tail) ==="; tail -20 "$LOG_DIR/sandlot.log"
    echo "=== gateway log (tail) ==="; tail -10 "$LOG_DIR/gateway.log"
    tc_cleanup_default
    exit 1
fi

# Serial logs are snapshotted by tc_cleanup_default (KEEP_LOGS=1) before
# /run/sandswap is removed.
tc_cleanup_default

echo "=== per-sample ==="
if command -v column >/dev/null 2>&1; then
    column -t "$LOGS/probe-samples.txt"
else
    # Minimal hosts lack `column` — tab-separate instead.
    sed 's/[[:space:]]\{2,\}/\t/g' "$LOGS/probe-samples.txt"
fi
echo; echo "=== warden timing lines (by frequency) ==="
grep -hE 'mount_and_exec done|exec done|workspace mounted|unmount_workspace done' "$LOGS"/serial/*.log "$LOGS"/console/*.log 2>/dev/null | sort | uniq -c | sort -rn | head -30
echo; echo "logs kept in $LOGS (NOT deleted)"
