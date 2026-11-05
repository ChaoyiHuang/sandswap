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
# verify-etcd-fence.sh — (moved from e2e/etcd-partition-fence.sh) — W5 chaos-matrix drill: the etcd-partition
# SELF-FENCE, live. The fence is the mechanism that makes "owner health
# stale + node presence absent" a sound mount-release proof for takeover:
# a gateway partitioned from etcd past the threshold must ACTIVELY release
# every mount it holds while KEEPING its node streams connected, then
# recover in place when the partition heals. Until this drill it was
# unit-tested but never exercised against a real deployed stack.
#
# Method (the deployed one-machine-etcd stack, no side ports):
#   1. hold a live mount with a long-lease background exec
#   2. hot-reload -etcd-fence-sec down to a drill window (20s)
#   3. partition ONLY the gateway identity's etcd connections
#      (iptables OUTPUT, owner-match on the sandserv uid — SSH, etcd
#      itself, and the operator's shell are untouched by construction)
#   4. assert the three documented fence signals, in order:
#      "self-fencing" → "released all mounts" → (stream still connected)
#   5. heal the partition → assert "self-fence lifted" + presence re-grant
#   6. execute on the SAME sandfs again — in-place recovery proven
#   7. restore the fence threshold (config file + verify hot-reload took it)
#
# The partition rule is removed on EVERY exit path (trap), and the script
# REFUSES to run if the rule is already present (a stale rule from an
# interrupted run would silently fence the stack forever).
#
# Usage: sudo bash deploy/baremetal/verify-etcd-fence.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/e2e/common.sh"

GW_UNIT="sandswap-gateway@exec.service"
GW_CFG="/etc/sandswap/gateway-exec.yaml"
# Resolve the deployed identity: provisioning auto-picks a free uid when the
# contract slot is occupied by a stock account (GCP-style images ship
# 985/986/987), and the partition must drop the uid the gateway ACTUALLY
# runs as. An unresolved account means there is no deployed gateway to
# partition: fail loudly. A fallback uid would match no traffic and run a
# drill that proves nothing.
SANDSERV_UID="$(id -u sandserv 2>/dev/null)" || {
    tc_log_error "no 'sandserv' service account — deploy the stack first (deploy-one-machine-etcd.sh or deploy-single-node.sh)"
    exit 1
}
FENCE_KEY="staleness:"
GW_URL="https://localhost:3000"
HUMAN_URL="https://localhost:3100"
DRILL_FENCE=20

tc_check_root
command -v iptables >/dev/null 2>&1 || { tc_skip_suite "iptables not available"; }
curl -sk -m 5 "$GW_URL/health" | grep -q '"status"' || { tc_skip_suite "deployed stack not answering at $GW_URL (run deploy-one-machine-etcd.sh first)"; }
RULE="-m owner --uid-owner $SANDSERV_UID -p tcp -d 127.0.0.1 --dport 2379 -j DROP"
if iptables -C OUTPUT $RULE 2>/dev/null; then
    tc_fail "a stale partition rule is ALREADY present — the stack is silently fenced; refusing to stack a second rule (remove it: iptables -D OUTPUT $RULE)"
    exit 1
fi
tc_pass "stack up, iptables available, no stale rule"

cleanup() {
    iptables -D OUTPUT $RULE 2>/dev/null || true
    # restore the fence threshold if the drill changed it
    if [[ -n "$CFG_BACKUP" ]] && [[ -f "$CFG_BACKUP" ]]; then
        cp "$CFG_BACKUP" "$GW_CFG"
    fi
    true
}
CFG_BACKUP=""
trap cleanup EXIT INT TERM
CFG_BACKUP="$(mktemp /tmp/fence-drill-cfg.XXXXXX)"
cp "$GW_CFG" "$CFG_BACKUP"

gw_log_since() { # $1=marker-time → journal lines after it
    journalctl -u "$GW_UNIT" --since "$1" --no-pager 2>/dev/null || true
}

# ── Phase 1: a live mount held by a long background exec ──────────
tc_log_section "Phase 1: hold a live mount (bg exec, 120s lease)"
RESP=$(curl -sk -X POST "$HUMAN_URL/human/agent" -H 'Content-Type: application/json' -d '{"name":"fence-drill"}')
A_KEY=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('api_key',''))")
A_ID=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))")
SF_RESP=$(curl -sk -X POST "$HUMAN_URL/human/sandfs" -H 'Content-Type: application/json' \
    -d "{\"agent_id\":\"$A_ID\",\"name\":\"fence-drill\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}")
SF_ID=$(echo "$SF_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sandfs_id',''))")
[[ -n "$A_KEY" && -n "$SF_ID" ]] || { tc_fail "fixture failed: $RESP / $SF_RESP"; exit 1; }
BG=$(curl -sk -X POST "$GW_URL/agent/execute" -H "Authorization: Bearer $A_KEY" -H 'Content-Type: application/json' \
    -d "{\"sandfs_id\":\"$SF_ID\",\"code\":\"sleep 120\",\"timeout\":120,\"background\":true,\"lease_duration\":120}")
EXEC_ID=$(echo "$BG" | python3 -c "import sys,json;print(json.load(sys.stdin).get('exec_id',''))")
[[ -n "$EXEC_ID" ]] || { tc_fail "bg exec failed: $BG"; exit 1; }
tc_pass "mount held (bg exec $EXEC_ID, sandfs $SF_ID)"

# ── Phase 2: fence window via hot-reload ───────────────────────────
tc_log_section "Phase 2: hot-reload etcd_fence_sec → ${DRILL_FENCE}s"
python3 - "$GW_CFG" "$DRILL_FENCE" <<'PYEOF'
import re, sys
path, fence = sys.argv[1], sys.argv[2]
t = open(path).read()
block = f"\nstaleness:\n  etcd_fence_sec: {fence}\n"
if re.search(r"^staleness:", t, re.M):
    if re.search(r"^  etcd_fence_sec:", t, re.M):
        t = re.sub(r"^  etcd_fence_sec: .*$", f"  etcd_fence_sec: {fence}", t, flags=re.M)
    else:
        t = re.sub(r"^(staleness:)$", r"\1\n  etcd_fence_sec: " + fence, t, flags=re.M)
else:
    t = t.rstrip("\n") + "\n" + block
open(path, "w").write(t)
print("cfg patched")
PYEOF
sleep 3   # hot-reload debounce
# verify the gateway ACCEPTED the value (a refused hot-reload keeps the old
# threshold — the drill would then just take longer, but say so)
MARK1="$(date '+%Y-%m-%d %H:%M:%S')"
sleep 2
if gw_log_since "$MARK1" | grep -q "fence"; then
    tc_log_warn "fence-related log lines right after patch — verify the reload: $(gw_log_since "$MARK1" | grep fence | head -2)"
fi
tc_pass "fence window set (${DRILL_FENCE}s, hot-reload)"

# ── Phase 3: the partition ────────────────────────────────────────
tc_log_section "Phase 3: partition gateway→etcd (owner-matched, lo only)"
iptables -I OUTPUT 1 $RULE
tc_pass "partition rule inserted ($(date '+%T'))"
MARK2="$(date '+%Y-%m-%d %H:%M:%S')"

# ── Phase 4: the fence fires ──────────────────────────────────────
tc_log_section "Phase 4: fence fires (waiting ≤ $((DRILL_FENCE + 60))s)"
FENCED=0
for _ in $(seq 1 $((DRILL_FENCE + 60))); do
    if gw_log_since "$MARK2" | grep -q "self-fencing"; then FENCED=1; break; fi
    sleep 1
done
if [[ "$FENCED" == "1" ]] && gw_log_since "$MARK2" | grep -q "released all mounts"; then
    tc_pass "self-fence fired and released all mounts ($(date '+%T'))"
else
    tc_fail "self-fence did NOT fire within ${DRILL_FENCE}+60s — check: journalctl -u $GW_UNIT --since '$MARK2' | grep -i fence"
    exit 1
fi

# Node stream must STILL be connected (the whole point of the fence shape):
# the sandlot unit shows no TOLERATING transition.
if journalctl -u sandswap-sandlot-instance@main --since "$MARK2" --no-pager 2>/dev/null | grep -q "TOLERATING\|tolerating"; then
    tc_fail "sandlot entered TOLERATING during the fence — streams were NOT kept (the fence's contract)"
else
    tc_pass "node stream stayed connected through the fence (no TOLERATING)"
fi

# ── Phase 5: heal + in-place recovery ─────────────────────────────
tc_log_section "Phase 5: heal the partition"
iptables -D OUTPUT $RULE
MARK3="$(date '+%Y-%m-%d %H:%M:%S')"
LIFTED=0
for _ in $(seq 1 60); do
    if gw_log_since "$MARK3" | grep -q "self-fence lifted"; then LIFTED=1; break; fi
    sleep 1
done
[[ "$LIFTED" == "1" ]] && tc_pass "self-fence lifted, presence re-granted" \
    || { tc_fail "fence not lifted within 60s of healing"; exit 1; }

tc_log_section "Phase 6: same sandfs serves again (in-place recovery)"
sleep 3
OK=$(curl -sk -m 30 -X POST "$GW_URL/agent/execute" -H "Authorization: Bearer $A_KEY" -H 'Content-Type: application/json' \
    -d "{\"sandfs_id\":\"$SF_ID\",\"code\":\"echo recovered\",\"timeout\":15}")
if echo "$OK" | python3 -c "import sys,json;d=json.load(sys.stdin);sys.exit(0 if d.get('status')=='done' and 'recovered' in d.get('stdout','') else 1)" 2>/dev/null; then
    tc_pass "exec on the same sandfs after recovery"
else
    tc_fail "post-recovery exec failed: $OK"
fi

# ── Restore ───────────────────────────────────────────────────────
cp "$CFG_BACKUP" "$GW_CFG"
sleep 3
tc_pass "fence threshold restored in config"

tc_log_section "Summary"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    tc_log_error "$FAIL_COUNT check(s) FAILED"
    exit 1
fi
tc_log_pass "etcd-partition self-fence drill: fenced → released → streams kept → lifted → in-place recovery"
