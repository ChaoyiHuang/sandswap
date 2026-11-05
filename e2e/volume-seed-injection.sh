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
# volume-seed-injection.sh — the seed INJECTION channels and the runtime guards
# that make them safe.
#
# The rotation drill (volume-seed-rotation.sh) proves the operator window:
# maintenance → drain → stage → run → promote. This drill proves the OTHER half
# — the properties an arbitrary injector (a Vault agent, an ESO, a systemd
# credential, a tmpfs fetch unit) depends on, none of which the config file can
# express:
#
#   1. the rotation window FREEZES creation fleet-wide: a sandfs created
#      mid-window would be named in the generation being retired, and `--run`
#      would have to chase it (per-instance staging only covers instances that
#      are themselves staged).
#   2. TAMPERING with the current generation is refused, never adopted: the
#      live namer keeps its generation, the storage plane keeps serving, and the
#      refusal lands in the adoption record.
#   3. the STAGED generation is frozen for the whole window: swapping it
#      mid-run would rename volumes toward a generation the promote gate
#      cannot see.
#   4. the daemon refuses a PREMATURE PROMOTE on its own — the completeness
#      gate is not just the tool's pre-flight (a config-driven promote, which
#      is what kubectl does on k8s, must be gated server-side).
#   5. a tmpfs seed channel works end to end: the generation files live in
#      /run, a full stage → run → promote rotation completes, and nothing of
#      the seed touches persistent storage.
#   6. the STARTUP GUARD refuses to start against a tree no configured
#      generation derives (an injected source replaced, a rollback, a botched
#      restore), and the escape hatch is the deliberate re-key path.
#
# Run: sudo bash e2e/volume-seed-injection.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=common.sh
source "$ROOT/e2e/common.sh"

SANDLOT_POOL="${SANDLOT_POOL:-medium:1}"
FAIL_COUNT=0
PASS_COUNT=0
TOOL="$ROOT/deploy/baremetal/rotate-volume-seed.sh"
TEMPLATE_TOOL="$OUTPUT/template-tool"
SANDLOT_CONFIG="$DEPLOY_DIR/sandlot-e2e.yaml"
STATE_FILE="${SANDSWAP_SEED_STATE_FILE:-/run/sandswap/volume-seed-state.json}"
SEED_FILE="$DEPLOY_DIR/volume-seed"

cleanup() {
    if [[ "${KEEP_ENV:-0}" == "1" ]]; then
        echo "KEEP_ENV=1: skipping teardown for live debugging (gateway/sandlot left running)" >&2
        return 0
    fi
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

human_post() { # path body
    curl -sk -m 30 -X POST "$HUMAN_URL$1" -H "Content-Type: application/json" -d "$2"
}
human_get() { curl -sk -m 20 "$HUMAN_URL$1"; }

rotate() { # [args...] — the production rotation tool, pointed at this stack
    bash "$TOOL" --prov-config "$SANDLOT_CONFIG" --human-url "$HUMAN_URL" \
        --template-tool "$TEMPLATE_TOOL" --state-file "$STATE_FILE" "$@"
}

# state_field FIELD -> the running instance's adoption record value (empty when
# absent). The record is the authority the tooling asserts on; the drill reads
# the same source instead of grepping the journal.
state_field() {
    [[ -f "$STATE_FILE" ]] || return 0
    python3 - "$STATE_FILE" "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
v = d.get(sys.argv[2])
if v is None:
    print("")
elif isinstance(v, bool):
    print("true" if v else "false")
else:
    print(v)
PY
}

wait_state_field() { # FIELD WANT TIMEOUT
    local field="$1" want="$2" timeout="$3" deadline
    deadline=$(( $(date +%s) + timeout ))
    while :; do
        [[ "$(state_field "$field")" == "$want" ]] && return 0
        [[ "$(date +%s)" -ge "$deadline" ]] && return 1
        sleep 0.3
    done
}

wait_log() { # PATTERN [TIMEOUT]
    local pattern="$1" timeout="${2:-15}" deadline
    deadline=$(( $(date +%s) + timeout ))
    while :; do
        grep -q "$pattern" "$LOG_DIR/sandlot.log" 2>/dev/null && return 0
        [[ "$(date +%s)" -ge "$deadline" ]] && return 1
        sleep 0.3
    done
}

log_has() { grep -q "$1" "$LOG_DIR/sandlot.log" 2>/dev/null; }

fp_current() { "$TEMPLATE_TOOL" volume-name --prov-config "$SANDLOT_CONFIG" --generation current --fingerprint; }
fp_next()    { "$TEMPLATE_TOOL" volume-name --prov-config "$SANDLOT_CONFIG" --generation next --fingerprint; }

exec_probe() { # <key> <sandfs_id> <shell-file>
    local key="$1" sid="$2" codefile="$3"
    python3 - "$sid" "$codefile" /tmp/vsi-body.json <<'PY'
import json, sys
sid, codefile, out = sys.argv[1:4]
json.dump({"sandfs_id": sid, "code": open(codefile).read(), "language": "shell"},
          open(out, "w"))
PY
    curl -s -m 90 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d @/tmp/vsi-body.json
}
agent_stdout() { python3 -c 'import sys,json; print(json.load(sys.stdin).get("stdout",""))'; }

# ── Phase 0: pre-flight ─────────────────────────────────────────────
log_section "Phase 0: Pre-flight"
tc_check_root
tc_preflight_standard python3
tc_check_artifacts gateway sandlot sandvmm vmlinux.bin initramfs.cpio.gz
tc_check_kvm
tc_ensure_dev_nodes
tc_setup_host_network
[[ -x "$TEMPLATE_TOOL" ]] || { fail "output/template-tool missing (run: bash build/build.sh go)"; exit 1; }

# ── Phase 1: stack up, with the seed delivered to a TMPFS path ──────
log_section "Phase 1: Stack up (seed injected into tmpfs, the L2 channel)"
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_attach_vsockguard

# The injection channel under test: the generation file lives in tmpfs, as a
# fetcher/credential would deliver it. Nothing of the seed touches persistent
# storage for the lifetime of this drill.
SEED_DIR="/run/sandswap/seed"
mkdir -p "$SEED_DIR"
chmod 0750 "$SEED_DIR"
SEED_FILE="$SEED_DIR/gen-1"
"$TEMPLATE_TOOL" seed-generate --out "$SEED_FILE" >/dev/null 2>&1
chmod 0640 "$SEED_FILE"
TC_VOLUME_SEED_FILE="$SEED_FILE"

tc_gen_sandlot_config "$SANDLOT_CONFIG"
TC_SANDLOT_CONFIG="$SANDLOT_CONFIG"
tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready 1

RESP_A=$(tc_create_agent_and_sandfs "vsi-A" "" flat || echo '{"error":"create failed"}')
KEY_A=$(json_val "$RESP_A" "api_key"); SID_A=$(json_val "$RESP_A" "sandfs_id")
[[ -n "$KEY_A" && -n "$SID_A" ]] || { fail "agent/sandfs creation failed: $RESP_A"; exit 1; }
VOL_A="$(tc_volume_path "$SID_A")" || { fail "cannot resolve the volume path for $SID_A"; exit 1; }
pass "tenant created on a tmpfs seed: $SID_A -> $(basename "$VOL_A")"

cat > /tmp/vsi-write.sh <<'CODE'
echo "injection-marker" > /workspace/injection-marker.txt && cat /workspace/injection-marker.txt
CODE
[[ "$(exec_probe "$KEY_A" "$SID_A" /tmp/vsi-write.sh | agent_stdout)" == *injection-marker* ]] \
    && pass "guest mounted and wrote its marker" \
    || { fail "warmup/guest write failed"; exit 1; }

[[ -f "$STATE_FILE" ]] && [[ "$(state_field current_fingerprint)" == "$(fp_current)" ]] \
    && pass "adoption record agrees with the config's current generation ($(fp_current))" \
    || fail "adoption record missing or disagreeing: $(state_field current_fingerprint) vs $(fp_current)"

# ── Phase 2: the rotation window freezes CREATION fleet-wide ────────
log_section "Phase 2: rotation window — creation is refused while it is open"
human_post /human/rotation '{"on":true,"reason":"injection drill"}' >/dev/null
human_get /stats | python3 -c 'import sys,json; sys.exit(0 if (json.load(sys.stdin).get("rotation") or {}).get("refusing") else 1)' \
    && pass "/stats reports the rotation window open" || fail "/stats does not report the rotation window"

STAGE_CREATE=$(tc_create_agent_and_sandfs "vsi-frozen" "" flat || true)
echo "$STAGE_CREATE" | grep -q "ROTATION_IN_PROGRESS" \
    && pass "creating a sandfs during the window is refused with ROTATION_IN_PROGRESS" \
    || fail "creation during the rotation window was not refused with the named code: ${STAGE_CREATE:0:200}"

# And the window closes again (this is also the convergence gate's happy path:
# one prov instance, on the current generation).
rotate --rotation off >/tmp/vsi-rot-off.log 2>&1 \
    && pass "window closed (convergence gate passed): $(grep -o 'fleet converged.*' /tmp/vsi-rot-off.log | head -1)" \
    || { fail "closing the window failed"; tail -3 /tmp/vsi-rot-off.log; }
RESP_B=$(tc_create_agent_and_sandfs "vsi-resumed" "" flat || echo '{"error":"create failed"}')
json_val "$RESP_B" "sandfs_id" | grep -q "sandfs-" && pass "creation resumed after the window closed" \
    || fail "creation still refused after the window closed: ${RESP_B:0:160}"

# ── Phase 3: tampering with the CURRENT generation is refused ───────
log_section "Phase 3: tamper drill — a rewritten current source is never adopted"
FP_BEFORE="$(state_field current_fingerprint)"
cp "$SEED_FILE" /tmp/vsi-seed-backup
"$TEMPLATE_TOOL" seed-generate --out /tmp/vsi-evil >/dev/null 2>&1
install -m 0640 /tmp/vsi-evil "$SEED_FILE"   # in-place replacement of the live generation

if wait_log "ERROR: provision seed change REFUSED" 15; then
    pass "the rewritten current source was REFUSED (logged, not adopted)"
else
    fail "no refusal was logged for the tampered current source"
fi
[[ "$(state_field current_fingerprint)" == "$FP_BEFORE" ]] \
    && pass "the live generation did not move (still $FP_BEFORE)" \
    || fail "the tampered generation was adopted: $(state_field current_fingerprint)"
[[ -n "$(state_field last_error)" ]] && pass "the refusal is recorded (last_error)" \
    || fail "the refusal was not recorded in the adoption record"
[[ "$(exec_probe "$KEY_A" "$SID_A" /tmp/vsi-write.sh | agent_stdout)" == *injection-marker* ]] \
    && pass "the storage plane keeps serving on the old generation" \
    || fail "the plane stopped serving after the tamper"

# Restore: the operator fixes the source; the refusal clears on the next apply.
install -m 0640 /tmp/vsi-seed-backup "$SEED_FILE"

# ── Phase 4: the STAGED generation is frozen for the window ─────────
log_section "Phase 4: staged-stability drill — the staged value cannot be swapped"
"$TEMPLATE_TOOL" seed-generate --out "$SEED_DIR/gen-2" >/dev/null 2>&1
chmod 0640 "$SEED_DIR/gen-2"
rotate --stage --seed-file "$SEED_DIR/gen-2" >/tmp/vsi-stage2.log 2>&1 \
    && pass "staged a second generation from tmpfs: $(grep -o 'staged AND adopted.*' /tmp/vsi-stage2.log | head -1)" \
    || { fail "staging the second generation failed"; tail -3 /tmp/vsi-stage2.log; }
FP_STAGED="$(state_field staged_fingerprint)"
cp "$SEED_DIR/gen-2" /tmp/vsi-staged-backup
"$TEMPLATE_TOOL" seed-generate --out /tmp/vsi-evil2 >/dev/null 2>&1
install -m 0640 /tmp/vsi-evil2 "$SEED_DIR/gen-2"   # swap the staged file under the window

if wait_log "the staged generation changed while the rotation window is open" 15; then
    pass "swapping the staged value mid-window was REFUSED"
else
    fail "the staged-value swap was not refused"
fi
[[ "$(state_field staged_fingerprint)" == "$FP_STAGED" ]] \
    && pass "the staged generation did not move (still $FP_STAGED)" \
    || fail "the staged generation moved: $(state_field staged_fingerprint)"
# Restore the staged file so the window still describes what it staged.
install -m 0640 /tmp/vsi-staged-backup "$SEED_DIR/gen-2"

# ── Phase 5: the DAEMON refuses a premature promote ─────────────────
log_section "Phase 5: promote gate drill — the daemon gates the promotion itself"
# $VOL_A has NOT been renamed, so a promotion now would make it permanently
# unresolvable. Promote through the CONFIG (what kubectl does on k8s) — the
# tool is not in the loop, so only the daemon's own gate can refuse it.
FP_CUR="$(fp_current)"
python3 - "$SANDLOT_CONFIG" "$SEED_DIR/gen-2" <<'PY'
import re, sys
cfg, staged = sys.argv[1], sys.argv[2]
src = open(cfg).read()
src = re.sub(r'^(\s*)volume_seed_file\s*:.*$', r'\1volume_seed_file: "%s"' % staged, src, count=1, flags=re.M)
src = re.sub(r'^\s*volume_seed_next_file\s*:.*$\n?', '', src, flags=re.M)
open(cfg, "w").write(src)
PY
if wait_log "provision seed promotion REFUSED" 15; then
    pass "the daemon REFUSED the premature promote (config-driven, no tool involved)"
else
    fail "the daemon did not refuse the premature promote"
fi
[[ "$(state_field current_fingerprint)" == "$FP_CUR" && "$(state_field staged)" == "true" ]] \
    && pass "live generations unchanged: still current=$FP_CUR with the window intact" \
    || fail "a refused promote moved the live generations (current=$(state_field current_fingerprint) staged=$(state_field staged))"

# ── Phase 6: the tmpfs channel completes a FULL rotation ────────────
log_section "Phase 6: full rotation on the tmpfs channel (stage → run → promote)"
rotate --maintenance on >/dev/null
sleep 1   # let the mounts drain (this drill's guest is idle)
# The promote drill left the window pointing at gen-2 while the daemon (rightly)
# refused to promote it. Abort that window cleanly: current stays gen-1, the
# staged key goes away, and the daemon drops the staging.
ABORT_PY=$(cat <<'ABORTPY'
import re, sys
cfg, cur = sys.argv[1], sys.argv[2]
src = open(cfg).read()
src = re.sub(r'^(\s*)volume_seed_file\s*:.*$', r'\1volume_seed_file: "%s"' % cur, src, count=1, flags=re.M)
src = re.sub(r'^\s*volume_seed_next_file\s*:.*$\n?', '', src, flags=re.M)
open(cfg, "w").write(src)
ABORTPY
)
printf '%s' "$ABORT_PY" > /tmp/vsi-abort.py
python3 /tmp/vsi-abort.py "$SANDLOT_CONFIG" "$SEED_FILE"
wait_state_field staged false 15 \
    && pass "aborted the refused window: the daemon cleared the staging" \
    || fail "the staging did not clear after the abort (staged=$(state_field staged))"
[[ "$(state_field current_fingerprint)" == "$(fp_current)" ]] \
    && pass "the abort left the current generation untouched ($(fp_current))" \
    || fail "the abort moved the current generation: $(state_field current_fingerprint)"
"$TEMPLATE_TOOL" seed-generate --out "$SEED_DIR/gen-3" >/dev/null 2>&1
chmod 0640 "$SEED_DIR/gen-3"
rotate --stage --seed-file "$SEED_DIR/gen-3" >/tmp/vsi-stage3.log 2>&1 \
    && pass "staged gen-3 from tmpfs (adoption verified before returning)" \
    || { fail "staging gen-3 failed"; tail -3 /tmp/vsi-stage3.log; }
rotate --run >/tmp/vsi-rotaterun.log 2>&1 \
    && pass "renamed the tree onto the staged generation: $(grep -o 'action=run total=[0-9]* moved=[0-9]*' /tmp/vsi-rotaterun.log | head -1)" \
    || { fail "the rename run failed"; tail -3 /tmp/vsi-rotaterun.log; }
rotate --promote >/tmp/vsi-promote.log 2>&1 \
    && pass "promoted on tmpfs: $(grep -o 'promoted AND adopted.*' /tmp/vsi-promote.log | head -1)" \
    || { fail "the promote failed"; tail -3 /tmp/vsi-promote.log; }
rotate --rotation off >/tmp/vsi-rot-off2.log 2>&1 \
    && pass "closed the rotation window: $(grep -o 'fleet converged.*' /tmp/vsi-rot-off2.log | head -1)" \
    || { fail "closing the rotation window failed"; tail -3 /tmp/vsi-rot-off2.log; }
rotate --maintenance off >/tmp/vsi-maint-off.log 2>&1 \
    && pass "maintenance resumed after the rotation" \
    || { fail "turning maintenance off failed"; tail -3 /tmp/vsi-maint-off.log; }

# The tenant survives a rotation whose generations never left memory.
cat > /tmp/vsi-check.sh <<'CODE'
cat /workspace/injection-marker.txt
CODE
POST_ROT=$(exec_probe "$KEY_A" "$SID_A" /tmp/vsi-check.sh)
[[ "$(echo "$POST_ROT" | agent_stdout)" == *injection-marker* ]] \
    && pass "the same tenant still executes; its data survived the tmpfs rotation" \
    || fail "the tenant did not survive the tmpfs rotation: ${POST_ROT:0:300}"
[[ "$(state_field current_fingerprint)" == "$(fp_current)" && "$(state_field staged)" == "false" ]] \
    && pass "adoption record shows the promoted generation as current" \
    || fail "adoption record disagrees after the rotation"

# ── Phase 7: the startup guard refuses a mismatched tree ────────────
log_section "Phase 7: startup guard — a tree no configured generation derives"
# Stop the RUNNING stack first (the guard is about a fresh start), then clear
# network residue. Restart output is NOT suppressed: a helper that gives up
# would otherwise take the drill's own summary with it.
kill "${SANDLOT_PID:-}" "${GATEWAY_PID:-}" 2>/dev/null || true
wait "${SANDLOT_PID:-}" "${GATEWAY_PID:-}" 2>/dev/null || true
tc_pre_clean_stack
sleep 1
# The stack cleanup purges /run/sandswap: the tmpfs channel is re-materialized
# by the fetcher at boot (here: by this line), which is exactly the property
# the channel is chosen for.
mkdir -p "$SEED_DIR" && chmod 0750 "$SEED_DIR"
# The seed source is replaced out of band (an injector pointed at the wrong
# generation, a rolled-back secret, a restored backup): the tree still carries
# the OLD generation's fingerprints.
"$TEMPLATE_TOOL" seed-generate --out "$SEED_DIR/gen-4" >/dev/null 2>&1
chmod 0640 "$SEED_DIR/gen-4"
python3 - "$SANDLOT_CONFIG" "$SEED_DIR/gen-4" <<'PY'
import re, sys
cfg, new = sys.argv[1], sys.argv[2]
src = open(cfg).read()
src = re.sub(r'^(\s*)volume_seed_file\s*:.*$', r'\1volume_seed_file: "%s"' % new, src, count=1, flags=re.M)
open(cfg, "w").write(src)
PY
tc_start_gateway
tc_wait_health
# The refusal is the EXPECTED outcome, and the helper exits the script when the
# process dies — so it runs in a subshell and the verdict comes from the log.
( tc_start_sandlot ) >/dev/null 2>&1 || true
# The guard has TWO refusal texts — one for stamps whose signature cannot
# be authenticated under the configured seed ("could silently split
# tenants"), one for generations no configured seed derives ("would
# silently split tenants"). Anchor on the phrase both share so the drill
# pins the REFUSAL, not one wording (a swapped seed file fails the
# authentication path first).
if wait_log "silently split tenants" 10; then
    pass "the startup guard refused to start and named the mismatch"
else
    fail "the sandlot did not refuse to start the way the guard must: $(tail -3 "$LOG_DIR/sandlot.log" 2>/dev/null)"
fi
# The escape hatch is the deliberate re-key path (paired with the migration):
# the instance must now COME UP — proven by the storage plane connecting.
( tc_start_sandlot -allow-seed-generation-mismatch ) >/dev/null 2>&1 || true
wait_log "allowed by -allow-seed-generation-mismatch" 10 \
    && pass "the allowed mismatch is logged loudly" || fail "the allowed mismatch was not logged"
PROV_UP=""
for _ in $(seq 1 40); do
    human_get /health | grep -q '"provisioners":[[:space:]]*[1-9]' && { PROV_UP=1; break; }
    sleep 0.5
done
[[ -n "$PROV_UP" ]] \
    && pass "-allow-seed-generation-mismatch started the instance (the storage plane connected)" \
    || fail "the escape hatch did not bring the instance up: $(tail -3 "$LOG_DIR/sandlot.log" 2>/dev/null)"

echo
log_section "volume-seed-injection Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ "$FAIL_COUNT" -eq 0 ]]; then
    pass "volume-seed-injection PASSED ($PASS_COUNT checks)"
    exit 0
fi
fail "volume-seed-injection FAILED ($FAIL_COUNT check(s))"
exit 1
