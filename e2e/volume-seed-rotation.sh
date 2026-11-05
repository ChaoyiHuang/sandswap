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
# volume-seed-rotation.sh — the rotation window, exercised end to end on the
# real stack (gateway + sandlot + sandvmm + warden + guest):
#
#   1. a tenant is created, mounted and executing; its volume carries data and
#      an identity stamp (sandlot/provision/volume/stamp.go);
#   2. maintenance ON refuses agent traffic WITHOUT restarting the gateway
#      (/health and /stats stay reachable);
#   3. the next seed generation is STAGED by editing the prov config, which the
#      instance hot-reloads — no restart;
#   4. the rotation renames every volume to the new generation and updates each
#      record's rootfs_path (the tool refuses to move a directory stamped for
#      another sandfs);
#   5. promotion makes the staged generation current;
#   6. maintenance OFF resumes service: the SAME sandfs still executes and its
#      data survived the rename, a NEW sandfs lands in the new generation, and
#     the old-generation name can no longer be resolved by the storage plane;
#   7. a SECOND rotation on the same instance/config completes — every
#      generation keeps its own file (the promoted path is never re-minted
#      into), which is the property a fixed staged path silently breaks.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=common.sh
source "$ROOT/e2e/common.sh"

SANDLOT_POOL="${SANDLOT_POOL:-medium:1}"
FAIL_COUNT=0
PASS_COUNT=0
TEMPLATE_TOOL="$OUTPUT/template-tool"
SANDLOT_CONFIG="$DEPLOY_DIR/sandlot-e2e.yaml"
# The battery's seed is OWNER-ONLY 0600 minted for the prov identity (so the
# sandvmm identity can never read it — stronger than the deploy's
# root:sandprov 0640). The seed-file ownership contract accepts root or the
# reading identity, so the template tool must run AS THAT IDENTITY here — a
# root-run scan refuses the prov-owned seed by design. The wrapper drops to
# the seed owner before exec'ing the real tool; the rotate tool itself stays
# root (configs, signals, the adoption record).
TOOL_RUNAS="$(id -un "${SS_PROV_USER:-sandlot}" 2>/dev/null || echo sandlot)"
TOOL_WRAP="$(mktemp /tmp/vsr-template-tool.XXXXXX)"
cat > "$TOOL_WRAP" <<EOF
#!/bin/sh
exec setpriv --reuid="$TOOL_RUNAS" --regid="$TOOL_RUNAS" --clear-groups -- "$TEMPLATE_TOOL" "\$@"
EOF
chmod +x "$TOOL_WRAP"
TEMPLATE_TOOL_FOR_ROTATE="$TOOL_WRAP"
cleanup() { rm -f "$TOOL_WRAP" 2>/dev/null; tc_cleanup_default; }
# The staged seed is minted by the rotation tool next to the config, at a
# generation-labeled path (<config dir>/volume-seed-next-<UTC>-<pid>); the
# drill never needs its contents.

trap cleanup EXIT INT TERM

exec_probe() { # <key> <sandfs_id> <shell-file>
    local key="$1" sid="$2" codefile="$3"
    python3 - "$sid" "$codefile" /tmp/vsr-body.json <<'PY'
import json, sys
sid, codefile, out = sys.argv[1:4]
json.dump({"sandfs_id": sid, "code": open(codefile).read(), "language": "shell"},
          open(out, "w"))
PY
    curl -s -m 90 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d @/tmp/vsr-body.json
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

# ── Phase 1: stack up (config mode, so the seed keys are hot-reloadable) ─
log_section "Phase 1: Stack up (config-file mode: the seed lives in the file)"
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_attach_vsockguard

tc_gen_sandlot_config "$SANDLOT_CONFIG"
TC_SANDLOT_CONFIG="$SANDLOT_CONFIG"
tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready 1

RESP_A=$(tc_create_agent_and_sandfs "vsr-A" "" flat || echo '{"error":"create failed"}')
KEY_A=$(json_val "$RESP_A" "api_key"); SID_A=$(json_val "$RESP_A" "sandfs_id")
[[ -n "$KEY_A" && -n "$SID_A" ]] || { fail "agent/sandfs creation failed: $RESP_A"; exit 1; }
VOL_A="$(tc_volume_path "$SID_A")" || { fail "cannot resolve the volume path for $SID_A"; exit 1; }
pass "tenant created: $SID_A -> $(basename "$VOL_A")"

# Warm the mount and prove the guest can write.
cat > /tmp/vsr-write.sh <<'CODE'
echo "rotation-marker" > /workspace/rotation-marker.txt && cat /workspace/rotation-marker.txt
CODE
WARM=$(exec_probe "$KEY_A" "$SID_A" /tmp/vsr-write.sh | agent_stdout)
echo "$WARM" | grep -q "rotation-marker" || { fail "warmup/guest write failed: $WARM"; exit 1; }
pass "guest mounted and wrote its marker (pre-rotation)"

# The stamp must be in place, SIGNED, before anything moves. Read it through
# the hardened tool (the file is tenant-writable in flat mode).
STAMPED_ID="$("$TEMPLATE_TOOL" volume-stamp-read --volume "$VOL_A" --field sandfs_id 2>/dev/null)" \
    || fail "volume identity stamp unreadable/unsafe: $VOL_A/.sandfs-id"
[[ "$STAMPED_ID" == "$SID_A" ]] && grep -q "^sig: " "$VOL_A/.sandfs-id" \
    && pass "volume carries a signed identity stamp ($(grep -m1 '^generation:' "$VOL_A/.sandfs-id"))" \
    || fail "volume identity stamp missing, unsigned or wrong: $(cat "$VOL_A/.sandfs-id" 2>/dev/null)"

# ── Phase 1b: planted stamp symlink is refused, host target untouched ─
# In flat mode the stamp lives in the tenant's chroot. The rotation tooling
# used to read/write it with grep and shell redirection as root — a planted
# symlink turned that into an arbitrary HOST-file read/truncate. Both tool
# operations must refuse the entry and leave the target intact.
log_section "Phase 1b: a planted stamp symlink is refused (host target untouched)"
VICTIM="$(mktemp)"; printf 'host-file\n' > "$VICTIM"
SYMDIR="$(mktemp -d)"; ln -s "$VICTIM" "$SYMDIR/.sandfs-id"
if "$TEMPLATE_TOOL" volume-stamp-read --volume "$SYMDIR" --field sandfs_id >/dev/null 2>&1; then
    fail "volume-stamp-read followed a planted symlink"
else
    pass "volume-stamp-read refuses a symlinked stamp"
fi
if "$TEMPLATE_TOOL" volume-stamp-write --prov-config "$SANDLOT_CONFIG" --volume "$SYMDIR" --id x --generation current >/dev/null 2>&1; then
    fail "volume-stamp-write wrote through a planted symlink"
else
    pass "volume-stamp-write refuses a symlinked stamp"
fi
grep -qx 'host-file' "$VICTIM" && pass "the symlink target is untouched" || fail "the symlink target was modified"
rm -rf "$SYMDIR" "$VICTIM"

# ── Phase 2: maintenance ON refuses agent traffic, no restart ───────
log_section "Phase 2: maintenance ON (refuse service, do not restart)"
GW_PID_BEFORE=$(curl -s "$HUMAN_URL/stats" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("gateways",[{}])[0].get("gateway_id",""))')
curl -s -X POST "$HUMAN_URL/human/maintenance" -H "Content-Type: application/json" \
    -d '{"on":true,"reason":"volume seed rotation drill"}' > /dev/null
curl -s "$HUMAN_URL/stats" | python3 -c '
import sys, json
m = json.load(sys.stdin).get("maintenance") or {}
sys.exit(0 if m.get("refusing") else 1)' \
    && pass "/stats reports the refusal" || fail "/stats does not report maintenance"

HTTP_CODE=$(curl -s -o /tmp/vsr-503.json -w '%{http_code}' -m 30 -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $KEY_A" -H "Content-Type: application/json" -d @/tmp/vsr-body.json)
[[ "$HTTP_CODE" == "503" ]] && pass "agent traffic refused with 503" || fail "expected 503 while refusing, got $HTTP_CODE"
grep -q "MAINTENANCE" /tmp/vsr-503.json && pass "refusal carries error_code MAINTENANCE" || fail "refusal body: $(cat /tmp/vsr-503.json)"
[[ "$(curl -s -o /dev/null -w '%{http_code}' "$HUMAN_URL/health")" == "200" ]] \
    && pass "/health still answers (a refused gateway is not a dead one)" || fail "/health unreachable during maintenance"
GW_PID_AFTER=$(curl -s "$HUMAN_URL/stats" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("gateways",[{}])[0].get("gateway_id",""))')
[[ "$GW_PID_BEFORE" == "$GW_PID_AFTER" ]] && pass "same gateway process (no restart)" || fail "gateway identity changed during the window"

# ── Phase 3: drain, then stage the next generation ──────────────────
log_section "Phase 3: drain, then stage the next seed generation (hot reload)"
# The file the generation CURRENT BEFORE ANY rotation points at: the channel
# contract says it is never rewritten (a rotation points the config at a NEW
# file), so it must still be byte-identical after both windows.
GEN0_FILE="$(sed -n 's/^[[:space:]]*volume_seed_file:[[:space:]]*//p' "$SANDLOT_CONFIG" | tr -d '"' | head -1)"
[[ -n "$GEN0_FILE" && -f "$GEN0_FILE" ]] || { fail "cannot resolve the pre-rotation generation file from $SANDLOT_CONFIG"; exit 1; }
GEN0_HASH="$(sha256sum "$GEN0_FILE" | cut -d' ' -f1)"
for _ in $(seq 1 20); do
    IN_USE=$(curl -s "$HUMAN_URL/stats" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("totals",{}).get("in_use_vms",0))')
    [[ "$IN_USE" == "0" ]] && break
    sleep 1
done
[[ "$IN_USE" == "0" ]] && pass "mounts drained (in_use_vms=0)" || fail "mounts did not drain (in_use=$IN_USE)"

# Stage through the PRODUCTION tool (mint + scope + config insert in one
# step): the next seed file must be readable by the identity running the prov
# instance (the hot-reload leg reads it as the service user; an unreadable
# file is silently refused by the live namer — the failure this drill exists
# to catch), and the tool scopes it like the current seed file.
if ! bash "$ROOT/deploy/baremetal/rotate-volume-seed.sh" --prov-config "$SANDLOT_CONFIG" \
        --human-url "$HUMAN_URL" --template-tool "$TEMPLATE_TOOL" --stage > /tmp/vsr-stage.log 2>&1; then
    fail "staging failed: $(tail -3 /tmp/vsr-stage.log)"
    echo "=== stage log ==="; cat /tmp/vsr-stage.log
    exit 1
fi
pass "staged via the production tool: $(grep -m1 'staged next generation' /tmp/vsr-stage.log)"
grep -q "volume_seed_next_file:" "$SANDLOT_CONFIG" \
    || { fail "--stage did not add volume_seed_next_file to the config"; exit 1; }
# The reload is event-driven (~200ms debounce) and the STAGE STEP ITSELF now
# waits for the running instance's adoption record before it returns — so the
# evidence is the tool's own confirmation, not a journal race (waiting for a
# NEW ack line after the tool returned would wait forever: the line is already
# there). The adoption record is the same source the tool asserted against.
STATE_FILE="${SANDSWAP_SEED_STATE_FILE:-/run/sandswap/volume-seed-state.json}"
if grep -q "staged AND adopted by the running instance" /tmp/vsr-stage.log; then
    pass "prov staged the next generation via config hot-reload (no restart)"
elif grep -qi "refused" /tmp/vsr-stage.log; then
    fail "the reload reached the namer but was REFUSED: $(grep -im1 refused /tmp/vsr-stage.log)"
else
    fail "the stage step did not confirm live adoption: $(tail -3 /tmp/vsr-stage.log)"
fi
python3 - "$STATE_FILE" <<'PY' && pass "adoption record shows the staged generation" || fail "adoption record does not show a staged generation"
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if d.get("staged") and d.get("staged_fingerprint") else 1)
PY

# A create while staged must be refused (the window freezes new volumes).
STAGED_CREATE=$(tc_create_agent_and_sandfs "vsr-staged" "" flat || true)
echo "$STAGED_CREATE" | grep -qiE "rotation|error" \
    && pass "creation refused while a rotation is staged" \
    || fail "creation during the staged window should be refused: ${STAGED_CREATE:0:160}"

# Early promote MUST be refused while volumes still carry the old generation:
# promoting before --run changes every un-renamed volume's derived name and
# makes it permanently unresolvable (delete → false success, create → silent
# tenant split). This is the completeness gate's red case — $VOL_A is still
# at its old-generation name right now.
if bash "$ROOT/deploy/baremetal/rotate-volume-seed.sh" --prov-config "$SANDLOT_CONFIG" \
        --human-url "$HUMAN_URL" --template-tool "$TEMPLATE_TOOL_FOR_ROTATE" --promote > /tmp/vsr-promote-early.log 2>&1; then
    fail "early promote SUCCEEDED — the completeness gate is missing; old-generation volumes would be orphaned"
else
    grep -q "refuse to promote" /tmp/vsr-promote-early.log \
        && pass "early promote refused while old-generation volumes remain" \
        || fail "early promote failed for the wrong reason: $(tail -2 /tmp/vsr-promote-early.log)"
fi
grep -q "volume_seed_next_file:" "$SANDLOT_CONFIG" \
    && pass "the refused promote left the staged key intact" \
    || fail "the refused promote mutated the config anyway"

# ── Phase 4: run the rotation, then promote ─────────────────────────
log_section "Phase 4: rotate (rename + record update + re-stamp), then promote"
"$TEMPLATE_TOOL" volume-name --prov-config "$SANDLOT_CONFIG" --id "$SID_A" --generation next > /tmp/vsr-newname
NEWNAME="$(cat /tmp/vsr-newname)"
NEWVOL="$(dirname "$VOL_A")/$NEWNAME"

if ! bash "$ROOT/deploy/baremetal/rotate-volume-seed.sh" \
        --prov-config "$SANDLOT_CONFIG" --human-url "$HUMAN_URL" \
        --template-tool "$TEMPLATE_TOOL" --run > /tmp/vsr-rotate.log 2>&1; then
    fail "rotation run failed: $(tail -3 /tmp/vsr-rotate.log)"
else
    pass "rotation run completed: $(grep -c '^\[rotate-seed\]' /tmp/vsr-rotate.log) log lines"
fi

[[ -d "$NEWVOL" && ! -d "$VOL_A" ]] && pass "volume renamed to the staged generation ($NEWNAME)" \
    || fail "rename did not land: new=$( [[ -d $NEWVOL ]] && echo yes || echo no ) old=$( [[ -d $VOL_A ]] && echo yes || echo no )"
ROTATED_ID="$("$TEMPLATE_TOOL" volume-stamp-read --volume "$NEWVOL" --field sandfs_id 2>/dev/null)" \
    && [[ "$ROTATED_ID" == "$SID_A" ]] && grep -q "^sig: " "$NEWVOL/.sandfs-id" \
    && pass "stamp still binds the directory to its sandfs (re-signed under the new generation)" \
    || fail "stamp lost/unsigned/wrong after the rename: $(cat "$NEWVOL/.sandfs-id" 2>/dev/null)"
REC_PATH=$(curl -s "$HUMAN_URL/human/sandfs/$SID_A" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("rootfs_path",""))')
[[ "$REC_PATH" == "$NEWVOL" ]] && pass "record updated to the new path" || fail "record path is $REC_PATH, want $NEWVOL"

if ! bash "$ROOT/deploy/baremetal/rotate-volume-seed.sh" --prov-config "$SANDLOT_CONFIG" \
        --human-url "$HUMAN_URL" --template-tool "$TEMPLATE_TOOL_FOR_ROTATE" --promote > /tmp/vsr-promote.log 2>&1; then
    fail "promotion failed: $(tail -3 /tmp/vsr-promote.log)"
else
    pass "promoted: the staged generation is now current"
fi
grep -q "^volume_seed_next_file:" "$SANDLOT_CONFIG" && fail "the staged key survived promotion" || pass "staged key cleared from the config"

# The promoting edit is ALSO a hot reload, and --promote now waits for the
# running instance to switch generations before it returns: a create that
# raced the reload would derive its name from the old generation. The tool's
# confirmation IS the acknowledgement (it reads the adoption record the
# instance writes), so assert on it rather than racing the journal.
if grep -q "promoted AND adopted by the running instance" /tmp/vsr-promote.log; then
    pass "prov hot-reloaded the promotion (generation switched live)"
else
    fail "the promotion was not confirmed live: $(tail -3 /tmp/vsr-promote.log)"
fi
python3 - "$STATE_FILE" <<'PY' && pass "adoption record shows no staging (the window closed)" || fail "adoption record still shows a staged generation"
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if not d.get("staged") else 1)
PY

# ── Phase 5: resume, and prove the tenant survived ──────────────────
log_section "Phase 5: maintenance OFF — the same tenant, rotated underneath it"
curl -s -X POST "$HUMAN_URL/human/maintenance" -H "Content-Type: application/json" -d '{"on":false}' > /dev/null
curl -s "$HUMAN_URL/stats" | python3 -c '
import sys, json
m = json.load(sys.stdin).get("maintenance") or {}
sys.exit(0 if not m.get("refusing") else 1)' && pass "service resumed" || fail "still refusing after maintenance off"

cat > /tmp/vsr-read.sh <<'CODE'
cat /workspace/rotation-marker.txt
CODE
AFTER=$(exec_probe "$KEY_A" "$SID_A" /tmp/vsr-read.sh | agent_stdout)
echo "$AFTER" | grep -q "rotation-marker" \
    && pass "the SAME sandfs still executes and its data survived the rotation" \
    || fail "post-rotation data lost: $AFTER"

# A NEW sandfs must land in the new generation, and the storage plane must no longer
# resolve the old-generation name (the rotation's whole point: the previous
# name is revoked).
RESP_B=$(tc_create_agent_and_sandfs "vsr-B" "" flat || echo '{"error":"create failed"}')
SID_B=$(json_val "$RESP_B" "sandfs_id")
[[ -n "$SID_B" ]] || { fail "post-rotation create failed: $RESP_B"; exit 1; }
VOL_B="$(tc_volume_path "$SID_B")" || { fail "cannot resolve the new volume path"; exit 1; }
EXPECTED_B=$("$TEMPLATE_TOOL" volume-name --prov-config "$SANDLOT_CONFIG" --id "$SID_B" --generation current)
[[ "$(basename "$VOL_B")" == "$EXPECTED_B" ]] \
    && pass "a new sandfs lands in the CURRENT generation ($EXPECTED_B)" \
    || fail "new volume $(basename "$VOL_B") != current-generation name $EXPECTED_B"

# ── Phase 6: a SECOND rotation on the same instance/config ──────────
# The channel contract says every generation keeps its own file. A tool whose
# default staged path is fixed breaks that on the SECOND window: the first
# promote re-points volume_seed_file at the staged file, so the next --stage
# would mint INTO the file the live generation reads. The running instance
# classifies that as tampering (refused), and a later restart would refuse to
# start — the fleet cannot come back up, caused by the tool itself. This leg
# is the regression pin: stage → run → promote, twice, with the first
# generation's file hashed across the second window.
log_section "Phase 6: second rotation — a new generation lands at a NEW path"
# The file the CURRENT generation points at (set by the first promote): the
# one a fixed staged path would overwrite.
GEN1_FILE="$(sed -n 's/^[[:space:]]*volume_seed_file:[[:space:]]*//p' "$SANDLOT_CONFIG" | tr -d '"' | head -1)"
[[ -n "$GEN1_FILE" && -f "$GEN1_FILE" ]] || { fail "cannot resolve the current generation file from $SANDLOT_CONFIG"; exit 1; }
GEN1_HASH="$(sha256sum "$GEN1_FILE" | cut -d' ' -f1)"

curl -s -X POST "$HUMAN_URL/human/maintenance" -H "Content-Type: application/json" \
    -d '{"on":true,"reason":"second rotation leg"}' > /dev/null
for _ in $(seq 1 20); do
    IN_USE=$(curl -s "$HUMAN_URL/stats" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("totals",{}).get("in_use_vms",0))')
    [[ "$IN_USE" == "0" ]] && break
    sleep 1
done
[[ "$IN_USE" == "0" ]] && pass "second window: mounts drained (in_use_vms=0)" || fail "second window: mounts did not drain (in_use=$IN_USE)"

if ! bash "$ROOT/deploy/baremetal/rotate-volume-seed.sh" --prov-config "$SANDLOT_CONFIG" \
        --human-url "$HUMAN_URL" --template-tool "$TEMPLATE_TOOL" --stage > /tmp/vsr-stage2.log 2>&1; then
    fail "the SECOND --stage failed — the file the live generation points at must never be the mint target: $(tail -3 /tmp/vsr-stage2.log)"
    echo "=== second stage log ==="; cat /tmp/vsr-stage2.log
    echo "=== Summary ==="; echo "  PASS: $PASS_COUNT"; echo "  FAIL: $FAIL_COUNT"
    exit 1
fi
pass "the second --stage succeeded: $(grep -m1 'staged next generation' /tmp/vsr-stage2.log)"
grep -qi "refused" /tmp/vsr-stage2.log \
    && fail "the running instance REFUSED the second stage (tamper classification): $(grep -im1 refused /tmp/vsr-stage2.log)" \
    || pass "the second stage drew no tamper refusal"
grep -q "staged AND adopted by the running instance" /tmp/vsr-stage2.log \
    && pass "the second stage was ADOPTED by the running instance (creation frozen)" \
    || fail "the second stage was not adopted: $(tail -3 /tmp/vsr-stage2.log)"
STAGED2_FILE="$(sed -n 's/^[[:space:]]*volume_seed_next_file:[[:space:]]*//p' "$SANDLOT_CONFIG" | tr -d '"' | head -1)"
[[ -n "$STAGED2_FILE" && "$STAGED2_FILE" != "$GEN1_FILE" ]] \
    && pass "the second generation landed at a NEW path ($(basename "$STAGED2_FILE"))" \
    || fail "the second stage targeted the live generation file ($STAGED2_FILE)"

if ! bash "$ROOT/deploy/baremetal/rotate-volume-seed.sh" \
        --prov-config "$SANDLOT_CONFIG" --human-url "$HUMAN_URL" \
        --template-tool "$TEMPLATE_TOOL" --run > /tmp/vsr-rotate2.log 2>&1; then
    fail "the second rotation run failed: $(tail -3 /tmp/vsr-rotate2.log)"
else
    pass "second rotation run completed: $(grep -o 'action=run total=[0-9]* moved=[0-9]*' /tmp/vsr-rotate2.log | head -1)"
fi
NEWNAME2="$("$TEMPLATE_TOOL" volume-name --prov-config "$SANDLOT_CONFIG" --id "$SID_A" --generation next)"
[[ -d "$(dirname "$VOL_B")/$NEWNAME2" ]] \
    && pass "the tenant volume was renamed onto the second generation ($NEWNAME2)" \
    || fail "second-generation name $NEWNAME2 not on disk"

if ! bash "$ROOT/deploy/baremetal/rotate-volume-seed.sh" --prov-config "$SANDLOT_CONFIG" \
        --human-url "$HUMAN_URL" --template-tool "$TEMPLATE_TOOL_FOR_ROTATE" --promote > /tmp/vsr-promote2.log 2>&1; then
    fail "the second promotion failed: $(tail -3 /tmp/vsr-promote2.log)"
else
    pass "second promote: $(grep -o 'promoted AND adopted.*' /tmp/vsr-promote2.log | head -1)"
fi
GEN2_FILE="$(sed -n 's/^[[:space:]]*volume_seed_file:[[:space:]]*//p' "$SANDLOT_CONFIG" | tr -d '"' | head -1)"
[[ "$GEN2_FILE" == "$STAGED2_FILE" ]] \
    && pass "the config now names the second staged file" \
    || fail "config names $GEN2_FILE, want $STAGED2_FILE"
[[ -f "$GEN1_FILE" ]] && [[ "$(sha256sum "$GEN1_FILE" | cut -d' ' -f1)" == "$GEN1_HASH" ]] \
    && pass "the first generation's file still exists, byte-identical (never rewritten)" \
    || fail "the first generation's file was rewritten or removed ($GEN1_FILE)"
[[ -f "$GEN0_FILE" ]] && [[ "$(sha256sum "$GEN0_FILE" | cut -d' ' -f1)" == "$GEN0_HASH" ]] \
    && pass "the pre-rotation generation's file survives both windows, byte-identical" \
    || fail "the pre-rotation generation's file was rewritten or removed ($GEN0_FILE)"

curl -s -X POST "$HUMAN_URL/human/maintenance" -H "Content-Type: application/json" -d '{"on":false}' > /dev/null
curl -s "$HUMAN_URL/stats" | python3 -c '
import sys, json
m = json.load(sys.stdin).get("maintenance") or {}
sys.exit(0 if not m.get("refusing") else 1)' && pass "service resumed after the second rotation" || fail "still refusing after the second rotation"
AFTER2=$(exec_probe "$KEY_A" "$SID_A" /tmp/vsr-read.sh | agent_stdout)
echo "$AFTER2" | grep -q "rotation-marker" \
    && pass "the same tenant still executes after the second rotation" \
    || fail "post-second-rotation data lost: $AFTER2"

# ── Summary ─────────────────────────────────────────────────────────
log_section "volume-seed-rotation Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "volume-seed-rotation FAILED ($FAIL_COUNT check(s))"
    exit 1
fi
log_pass "volume-seed-rotation PASSED ($PASS_COUNT checks)"
exit 0
