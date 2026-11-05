#!/usr/bin/env bash
# delete-lifecycle.sh — sandfs deletion under concurrency e2e: the delete path
# gates new execs via the lifecycle status, drains in-flight work, and leaves
# NO residue: volume dir gone, no host-side overlay mount left on the node, no
# lingering lease serving the deleted sandfs.
#
#   1. DELETE while a long sync exec runs: the exec finishes or fails cleanly
#      (never a hang), the volume is gone afterwards.
#   2. DELETE while a warm lease holds the VM (idle): clean teardown, no
#      overlay mount residue in the node's mountinfo.
#   3. Execs against the deleted sandfs resolve to 404 (record gone).
#   4. Agent cascade delete removes every owned sandfs volume.
#   5. DELETE converges on guest-planted directory trees: default-created
#      dirs (group-writable via the warden's umask) are removed directly with
#      NO orphan; deliberately restrictive modes (chmod 700) converge via the
#      prov side's orphan-rename fallback — 204 either way, id reusable.
#
# Companion coverage: template-swap.sh (the same status machinery driving
# detach/attach), staleness-gateway-e2e.sh (split-mode watch-driven drain).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
# shellcheck disable=SC2034  # consumed by the SOURCED common.sh across the source boundary
SANDLOT_POOL="small:2"
LEASE_MS="${LEASE_MS:-1000}"
TEMPLATE_DIR="${TEMPLATE_DIR:-/tmp/sandswap-tpl-delete}"
source "$ROOT/e2e/common.sh"

tc_use_output_binaries

cleanup() {
    local exit_code=$?
    tc_cleanup_default
    rm -rf "$TEMPLATE_DIR" 2>/dev/null || true
    exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log_section "Phase 0: Pre-flight"
tc_check_root
tc_check_artifacts gateway sandlot sandvmm vmlinux.bin initramfs.cpio.gz
tc_ensure_dev_nodes
[[ -d "$OUTPUT/rootfs-template" ]] || { log_error "missing output/rootfs-template (bash build/build.sh rootfs-template)"; exit 1; }
log_pass "artifacts present"
tc_check_kvm

log_section "Phase 1: Environment"
tc_clean_environment
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
fi
ss_prepare_shared_dir "$TEMPLATE_DIR"
ss_seed_template "$OUTPUT/rootfs-template" "$TEMPLATE_DIR/busy/v1"
# Overlay DNS fixture: the merged root is read-only, so the warden shadows an
# EXISTING /etc/resolv.conf with a read-only bind from its tmpfs. Ship a file
# with a DIFFERENT nameserver than the harness DNS, so phase 7 proves the
# warden's value won (a fallback that silently skipped would read 9.9.9.9).
printf 'nameserver 9.9.9.9\n' > "$TEMPLATE_DIR/busy/v1/etc/resolv.conf"
chmod 0644 "$TEMPLATE_DIR/busy/v1/etc/resolv.conf"
# The DAC-lock drill (phase 6d) needs a WRITABLE chroot root to plant mode 000
# on `/` — overlay's merged root is read-only (EROFS). Register the standard
# flat template so the drill can create a flat sandfs.
tc_install_flat_template

log_section "Phase 2: Start stack"
# shellcheck disable=SC2034  # consumed by tc_gen_certs (SOURCED common.sh)
CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
tc_gen_certs
tc_attach_vsockguard
tc_start_gateway
tc_start_sandlot -overlayfs-templates "$TEMPLATE_DIR"
tc_wait_health
log_pass "stack up (gateway + sandlot, small:2 pool)"

# ── helpers ─────────────────────────────────────────────────────────
exec_raw() {
    local key="$1" sid="$2" code="$3" extra="${4:-}"
    curl -s -m 120 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$sid\",\"code\":\"$code\",\"language\":\"shell\"$extra}" 2>/dev/null || echo '{"error":"curl failed"}'
}

resp_field() { tc_json_val "$1" "$2"; }

overlay_mounted() {
    # Any host-side overlay mount at <vol>/rootfs in this namespace?
    awk -v mp="$1/rootfs" '$5 == mp {found=1} END {exit !found}' /proc/self/mountinfo
}

log_section "Phase 3: DELETE while a long sync exec is in flight"
RESP=$(tc_create_agent_and_sandfs "del-user" "busy:v1" "overlay")
SID=$(tc_json_val "$RESP" "sandfs_id")
KEY=$(tc_json_val "$RESP" "api_key")
VOL=$(tc_json_val "$RESP" "rootfs_path")
[[ -n "$SID" ]] || { fail "3.1: create failed: $RESP"; exit 1; }
pass "3.1: overlay sandfs created ($SID)"

# Warm it up (mount + lease), then verify the overlay mount exists.
exec_raw "$KEY" "$SID" "true" >/dev/null
overlay_mounted "$VOL" && pass "3.2: host overlay mounted while sandfs live" || fail "3.2: expected overlay mount at $VOL/rootfs"

# Long exec in the background SHELL (a max-exec-timeout-bounded sleep), then
# delete concurrently. The lifecycle gate blocks new execs; the drain waits
# the in-flight one out via the node-side mount gate.
LONG_OUT=/tmp/sandswap-del-long.json
(exec_raw "$KEY" "$SID" "sleep 6 && echo long-done" > "$LONG_OUT" 2>&1) &
LONG_PID=$!
sleep 1.5   # let the exec actually start (mount + spawn)

DEL_CODE=$(curl -s -o /tmp/sandswap-del-del.json -w '%{http_code}' -m 120 \
    -X DELETE "$HUMAN_URL/human/sandfs/$SID" 2>/dev/null || echo 000)
if [[ "$DEL_CODE" == "204" ]]; then
    pass "3.3: DELETE returned 204 while exec in flight"
else
    fail "3.3: DELETE: expected 204, got $DEL_CODE: $(head -c 200 /tmp/sandswap-del-del.json)"
fi
wait "$LONG_PID"
LONG_STATUS=$(resp_field "$(cat "$LONG_OUT")" "status")
if [[ "$LONG_STATUS" == "done" ]]; then
    pass "3.4: in-flight exec completed (status=done — the drain waited it out via the node mount gate)"
else
    fail "3.4: in-flight exec outcome not 'done': status='$LONG_STATUS' body=$(head -c 200 "$LONG_OUT")"
fi
[[ -d "$VOL" ]] && fail "3.5: volume dir survived deletion: $VOL" || pass "3.5: volume dir removed"
sleep 0.5
overlay_mounted "$VOL" && fail "3.6: overlay mount residue at $VOL/rootfs" || pass "3.6: no overlay mount residue on the node"

AFTER_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 30 -X POST "$GATEWAY_URL/agent/execute" \
    -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$SID\",\"code\":\"true\",\"language\":\"shell\"}" 2>/dev/null || echo 000)
[[ "$AFTER_CODE" == "404" ]] && pass "3.7: exec on deleted sandfs → 404" || fail "3.7: expected 404, got $AFTER_CODE"

log_section "Phase 4: DELETE with a warm (idle) lease"
RESP=$(tc_create_agent_and_sandfs "warm-user" "busy:v1" "overlay")
SID2=$(tc_json_val "$RESP" "sandfs_id")
KEY2=$(tc_json_val "$RESP" "api_key")
VOL2=$(tc_json_val "$RESP" "rootfs_path")
exec_raw "$KEY2" "$SID2" "true" >/dev/null   # warm mount; lease holds ~LEASE_MS
if overlay_mounted "$VOL2"; then
    pass "4.1: warm overlay mount present before delete"
else
    fail "4.1: expected warm overlay mount at $VOL2/rootfs"
fi
DEL2=$(curl -s -o /dev/null -w '%{http_code}' -m 120 -X DELETE "$HUMAN_URL/human/sandfs/$SID2" 2>/dev/null || echo 000)
[[ "$DEL2" == "204" ]] && pass "4.2: DELETE under warm lease 204" || fail "4.2: DELETE: $DEL2"
sleep 0.5
overlay_mounted "$VOL2" && fail "4.3: overlay residue after warm-lease delete" || pass "4.3: warm-lease delete left no overlay mount"
[[ -d "$VOL2" ]] && fail "4.4: volume dir survived" || pass "4.4: volume dir removed"

log_section "Phase 5: agent cascade delete removes every volume"
RESP=$(tc_create_agent_and_sandfs "cascade-user" "busy:v1" "overlay")
CSID=$(tc_json_val "$RESP" "sandfs_id")
CAGENT=$(tc_json_val "$RESP" "agent_id")
CVOL=$(tc_json_val "$RESP" "rootfs_path")
# A second sandfs for the same agent (fresh call reuses nothing — agent pair).
RESP2=$(curl -s -X POST "$HUMAN_URL/human/sandfs" -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$CAGENT\",\"name\":\"cascade-2\",\"template\":\"busy:v1\",\"mode\":\"overlay\"}")
CSID2=$(tc_json_val "$RESP2" "sandfs_id")
CVOL2=$(tc_json_val "$RESP2" "rootfs_path")
[[ -n "$CSID2" ]] || { fail "5.1: second sandfs create failed: $RESP2"; exit 1; }
pass "5.1: agent owns two sandfs"
# Positive control: the SAME listing path must see both sandfs BEFORE the
# delete. Without this, the post-delete `REMAIN == 0` also holds when the list
# call breaks (empty body / parse failure -> items=[] -> 0 remain).
BEFORE=$(curl -s "$HUMAN_URL/human/sandfs" | python3 -c "
import sys,json
ids = {'$CSID','$CSID2'}
try: items = json.load(sys.stdin).get('items',[])
except Exception: items=[]
print(sum(1 for i in items if i.get('sandfs_id') in ids))" 2>/dev/null || true)
[[ "$BEFORE" == "2" ]] || { fail "5.1b: list endpoint did not list both sandfs before the delete (got '$BEFORE') — the post-delete count would be vacuous"; exit 1; }
pass "5.1b: list endpoint sees both sandfs before the delete (post-delete count is discriminating)"

DEL_AGENT=$(curl -s -o /dev/null -w '%{http_code}' -m 180 -X DELETE "$HUMAN_URL/human/agent/$CAGENT" 2>/dev/null || echo 000)
[[ "$DEL_AGENT" == "204" ]] && pass "5.2: agent delete 204" || fail "5.2: agent delete: $DEL_AGENT"
[[ -d "$CVOL" || -d "$CVOL2" ]] && fail "5.3: cascade left a volume behind ($CVOL / $CVOL2)" || pass "5.3: both volumes cascade-deleted"
REMAIN=$(curl -s "$HUMAN_URL/human/sandfs" | python3 -c "
import sys,json
ids = {'$CSID','$CSID2'}
try: items = json.load(sys.stdin).get('items',[])
except Exception: items=[]
print(sum(1 for i in items if i.get('sandfs_id') in ids))" 2>/dev/null)
[[ "$REMAIN" == "0" ]] && pass "5.4: no sandfs records remain" || fail "5.4: $REMAIN records survived the cascade"

log_section "Phase 6: DELETE converges on guest-planted directory trees"
# Guest-created entries land owner 987 (sandvmm) with the agent's modes; the
# deleting identity is sandprov (group sandlot, no caps). Two layers keep the
# delete convergent: the warden's umask 0002 makes DEFAULT-created dirs
# group-writable (removed directly — no orphan), and DeleteVolume's
# orphan-rename fallback converges deliberately restrictive modes (chmod 700)
# — rename needs only the volumes root's group write. Pre-fix, either tree
# failed the delete with a 500.
#
# Orphan names derive from the volume's ON-DISK directory name (the
# seed-derived "sf-<hmac>", see sandlot/provision/volume removeAllOrRename),
# NOT from the sandfs id: globbing ".$SID.orphan-*" can never match and both
# assertions below turn vacuous (6.6 always fails, 6.3 false-passes). The
# volume base name comes from rootfs_path — the same ground truth the mount
# probes use.

# 6a — defaults only: direct removal, NO orphan expected.
RESP=$(tc_create_agent_and_sandfs "mode-defaults-user" "busy:v1" "overlay")
D_SID=$(tc_json_val "$RESP" "sandfs_id")
D_KEY=$(tc_json_val "$RESP" "api_key")
D_VOL=$(tc_json_val "$RESP" "rootfs_path")
D_ROOT="$(dirname "$D_VOL")"
D_BASE="$(basename "$D_VOL")"
exec_raw "$D_KEY" "$D_SID" "cd /workspace && mkdir -p deep/a/b && echo x > deep/a/b/f" >/dev/null
D_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 120 -X DELETE "$HUMAN_URL/human/sandfs/$D_SID" 2>/dev/null || echo 000)
[[ "$D_CODE" == "204" ]] && pass "6.1: DELETE with default-created tree 204" || fail "6.1: DELETE: $D_CODE (default tree must not 500)"
[[ -d "$D_VOL" ]] && fail "6.2: volume dir survived: $D_VOL" || pass "6.2: volume dir gone"
D_ORPHAN=$(compgen -G "$D_ROOT/.$D_BASE.orphan-*" 2>/dev/null | head -1 || true)
[[ -z "$D_ORPHAN" ]] && pass "6.3: defaults removed directly (no orphan — umask made them group-writable)" \
    || fail "6.3: unexpected orphan for a default-mode tree: $D_ORPHAN"

# 6b — hostile modes: orphan-rename convergence expected.
RESP=$(tc_create_agent_and_sandfs "mode-hostile-user" "busy:v1" "overlay")
H_SID=$(tc_json_val "$RESP" "sandfs_id")
H_KEY=$(tc_json_val "$RESP" "api_key")
H_VOL=$(tc_json_val "$RESP" "rootfs_path")
H_ROOT="$(dirname "$H_VOL")"
H_BASE="$(basename "$H_VOL")"
exec_raw "$H_KEY" "$H_SID" "cd /workspace && mkdir -p sec && echo x > sec/f && chmod 700 sec" >/dev/null
H_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 120 -X DELETE "$HUMAN_URL/human/sandfs/$H_SID" 2>/dev/null || echo 000)
[[ "$H_CODE" == "204" ]] && pass "6.4: DELETE with chmod-700 tree 204 (converged, not 500)" || fail "6.4: DELETE: $H_CODE"
[[ -d "$H_VOL" ]] && fail "6.5: volume dir survived: $H_VOL" || pass "6.5: volume dir gone (id reusable)"
H_ORPHAN=$(compgen -G "$H_ROOT/.$H_BASE.orphan-*" 2>/dev/null | head -1 || true)
[[ -n "$H_ORPHAN" ]] && pass "6.6: hostile tree converged via orphan-rename: $H_ORPHAN" \
    || fail "6.6: expected an orphan beside the volumes root for the chmod-700 tree ($H_ROOT/.$H_BASE.orphan-*)"

# 6c — drill: the agent DAC-locks its OWN files (chmod 000 on the
# directory AND a file inside). This is agent-self-harm, not a cross-tenant
# boundary: the warden (PID 1, full capabilities) must still unmount, the prov
# delete must converge through the orphan-rename fallback, and a fresh sandfs
# must still execute afterwards. The guest mode is verified host-side so the
# drill cannot pass without actually planting the lock.
RESP=$(tc_create_agent_and_sandfs "daclock-subtree-user" "busy:v1" "overlay")
L_SID=$(tc_json_val "$RESP" "sandfs_id")
L_KEY=$(tc_json_val "$RESP" "api_key")
L_VOL=$(tc_json_val "$RESP" "rootfs_path")
L_ROOT="$(dirname "$L_VOL")"
L_BASE="$(basename "$L_VOL")"
L_OUT=$(exec_raw "$L_KEY" "$L_SID" "cd /workspace && mkdir -p lock && echo x > lock/f && chmod 000 lock/f && chmod 000 lock && stat -c '%a' lock")
L_MODE=$(tc_json_val "$L_OUT" "stdout" | tr -d '\n')
[[ "$L_MODE" == "0" || "$L_MODE" == "000" ]] && pass "6.7: agent DAC-locked its own dir (guest mode '$L_MODE'; self-harm only)" \
    || fail "6.7: guest chmod 000 did not land (stdout='$L_MODE' body=$(printf '%s' "$L_OUT" | head -c 200))"
L_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 120 -X DELETE "$HUMAN_URL/human/sandfs/$L_SID" 2>/dev/null || echo 000)
[[ "$L_CODE" == "204" ]] && pass "6.8: DELETE with chmod-000 subtree 204 (no wedge)" || fail "6.8: DELETE: $L_CODE"
[[ -d "$L_VOL" ]] && fail "6.9: volume dir survived the DAC-locked delete: $L_VOL" || pass "6.9: DAC-locked volume gone"
L_ORPHAN=$(compgen -G "$L_ROOT/.$L_BASE.orphan-*" 2>/dev/null | head -1 || true)
[[ -n "$L_ORPHAN" ]] && pass "6.10: chmod-000 tree converged via orphan-rename: $L_ORPHAN" \
    || fail "6.10: expected an orphan for the chmod-000 subtree ($L_ROOT/.$L_BASE.orphan-*)"

# 6d — the strongest form: chmod 000 on the CHROOT ROOT (the agent's `/`).
# FLAT mode is required: in overlay mode `/` is the read-only merged root
# (chmod → EROFS, tested separately above by 6.11's original shape), while a
# flat volume root is writable and can be DAC-locked. The warden's teardown
# must not hang or wedge the node even when the volume root is unreadable by
# the provision identity; delete must converge (the VM may be destroyed by the
# exclusive-ownership guard — that is a controlled outcome) and the stack must
# serve a NEW sandfs afterwards.
RESP=$(tc_create_agent_and_sandfs "daclock-root-user" "rootfs:v1" "flat")
R_SID=$(tc_json_val "$RESP" "sandfs_id")
R_KEY=$(tc_json_val "$RESP" "api_key")
R_VOL=$(tc_json_val "$RESP" "rootfs_path")
R_ROOT="$(dirname "$R_VOL")"
R_BASE="$(basename "$R_VOL")"
R_OUT=$(exec_raw "$R_KEY" "$R_SID" "chmod 000 / ; echo rc=\$?")
R_STDOUT=$(tc_json_val "$R_OUT" "stdout" | tr -d '\n')
R_STDERR=$(tc_json_val "$R_OUT" "stderr" | tr -d '\n')
R_MODE=$(stat -c '%a' "$R_VOL" 2>/dev/null || echo missing)
if [[ "$R_STDOUT" == *"rc=0"* ]]; then
    pass "6.11: agent chmod 000 on the chroot root succeeded (lock planted; self-harm only)"
    [[ "$R_MODE" == "0" || "$R_MODE" == "000" ]] && pass "6.11b: host volume root carries the planted mode '$R_MODE' (premise verified)" \
        || fail "6.11b: guest reported success but host volume root mode '$R_MODE' is not 000"
elif [[ "$R_STDOUT" == *"rc=1"* && "$R_STDERR" == *"Operation not permitted"* ]]; then
    # The share-root setattr is refused by the passthrough daemon (the root is
    # owned by the provision identity, the daemon is not). Pinned as a PASS:
    # the strongest DAC-lock form is unreachable from inside the chroot.
    pass "6.11: chroot-root chmod REFUSED (EPERM) — the agent cannot DAC-lock the volume root"
    [[ "$R_MODE" != "0" && "$R_MODE" != "000" ]] && pass "6.11b: host volume root mode '$R_MODE' unchanged (root lock not applied)" \
        || fail "6.11b: refusal reported, yet the host volume root is mode '$R_MODE'"
else
    fail "6.11: unexpected chmod-000-/ outcome (stdout='$R_STDOUT' stderr='$R_STDERR' body=$(printf '%s' "$R_OUT" | head -c 200))"
fi
R_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 180 -X DELETE "$HUMAN_URL/human/sandfs/$R_SID" 2>/dev/null || echo 000)
[[ "$R_CODE" == "204" ]] && pass "6.12: DELETE with chmod-000 chroot root 204 (no hang)" || fail "6.12: DELETE: $R_CODE"
[[ -d "$R_VOL" ]] && fail "6.13: volume dir survived the root-mode delete: $R_VOL" || pass "6.13: root-DAC-locked volume gone"
# Post-drill service: a fresh sandfs must mount+exec even if the previous VM
# was destroyed by the teardown guard. This is the assertion that separates
# "controlled VM replacement" from "node wedged".
RESP=$(tc_create_agent_and_sandfs "daclock-after-user" "busy:v1" "overlay")
A_SID=$(tc_json_val "$RESP" "sandfs_id")
A_KEY=$(tc_json_val "$RESP" "api_key")
A_OUT=$(exec_raw "$A_KEY" "$A_SID" "echo daclock-after-ok")
A_STATUS=$(tc_json_val "$A_OUT" "status")
A_STDOUT=$(tc_json_val "$A_OUT" "stdout" | tr -d '\n')
[[ "$A_STATUS" == "done" && "$A_STDOUT" == *"daclock-after-ok"* ]] \
    && pass "6.14: fresh sandfs execs after the DAC-lock drill (stack not wedged)" \
    || fail "6.14: post-drill exec failed: status='$A_STATUS' stdout='$A_STDOUT' body=$(printf '%s' "$A_OUT" | head -c 200)"
A_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 120 -X DELETE "$HUMAN_URL/human/sandfs/$A_SID" 2>/dev/null || echo 000)
[[ "$A_CODE" == "204" ]] && pass "6.15: post-drill sandfs deleted cleanly" || fail "6.15: post-drill DELETE: $A_CODE"

log_section "Phase 7: overlay DNS fallback (anchored read-only bind)"
# Overlay mode's merged root is read-only, so the warden shadows the template's
# /etc/resolv.conf with a read-only bind from its own tmpfs. The bind MUST go
# through the anchored fd + mount_setattr; the path-based MS_REMOUNT form the
# kernel answers EINVAL silently disabled overlay DNS (found by the FF review).
# The fixture ships `nameserver 9.9.9.9`; the harness DNS must win.
RESP=$(tc_create_agent_and_sandfs "overlay-dns-user" "busy:v1" "overlay")
O_SID=$(tc_json_val "$RESP" "sandfs_id")
O_KEY=$(tc_json_val "$RESP" "api_key")
O_OUT=$(exec_raw "$O_KEY" "$O_SID" "cat /etc/resolv.conf")
O_STATUS=$(tc_json_val "$O_OUT" "status")
O_STDOUT=$(tc_json_val "$O_OUT" "stdout" | tr -d '\n')
O_DNS="${NETWORK_DNS%%,*}"
[[ "$O_STATUS" == "done" && "$O_STDOUT" == *"nameserver ${O_DNS}"* ]] \
    && pass "7.1: overlay chroot reads the warden-injected DNS ($O_DNS), not the template stub" \
    || fail "7.1: overlay DNS fallback failed: status='$O_STATUS' stdout='$O_STDOUT' body=$(printf '%s' "$O_OUT" | head -c 200)"
# The bind must be read-only: the agent cannot rewrite the warden's tmpfs file
# through the chroot alias.
O_WRITE=$(exec_raw "$O_KEY" "$O_SID" "echo tamper >> /etc/resolv.conf; echo rc=\$?")
O_WSTDOUT=$(tc_json_val "$O_WRITE" "stdout" | tr -d '\n')
O_WERR=$(tc_json_val "$O_WRITE" "stderr" | tr -d '\n')
[[ "$O_WSTDOUT" == *"rc=1"* && "$O_WERR" == *"Read-only file system"* ]] \
    && pass "7.2: the injected resolv.conf bind is read-only (agent write refused EROFS)" \
    || fail "7.2: resolv.conf write was not refused: stdout='$O_WSTDOUT' stderr='$O_WERR'"
O_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 120 -X DELETE "$HUMAN_URL/human/sandfs/$O_SID" 2>/dev/null || echo 000)
[[ "$O_CODE" == "204" ]] && pass "7.3: overlay DNS sandfs deleted cleanly" || fail "7.3: DELETE: $O_CODE"

log_section "DONE: delete lifecycle"

# ── Verdict ─────────────────────────────────────────────────────────
# e2e/run-all.sh judges this script by EXIT CODE alone: a recorded failure
# MUST become the exit status, or the suite reports green while failing
# (the false-green class this gate closes).
tc_log_section "sandfs delete lifecycle Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "sandfs delete lifecycle FAILED ($FAIL_COUNT check(s))"
    exit 1
fi
log_pass "sandfs delete lifecycle PASSED ($PASS_COUNT checks)"
exit 0
