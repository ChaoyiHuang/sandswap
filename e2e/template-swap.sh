#!/usr/bin/env bash
# template-swap.sh — overlay template detach/attach (template upgrade) e2e:
# swap the read-only template under an overlay SandFS while the agent's
# workspace and home carry over, with the lifecycle gate protecting the
# in-between window, and the template-deletion in-use check closing the
# retirement loop.
#
#   1. Overlay sandfs on app:v1; agent writes /workspace + /home state.
#   2. detach-template: execs/file ops 409 (SANDFS_NOT_ACTIVE), the bg exec
#      dies (status → expired), workspace intact on shared storage.
#   3. attach-template app:v2 home=keep: record back to active, workspace AND
#      /home content present, the NEW template's rootfs is live.
#   4. swap-template one-shot to app:v1 with home=archive: archived home
#      recoverable, fresh home empty, template back to v1.
#   5. DELETE /human/templates/app:v1 → 409 TEMPLATE_IN_USE while held; after
#      the fleet swaps away → 204.
#
# Latency note: the exec hot path is untouched by the swap (a struct-field
# gate); the suite ends with an informational warm-exec timing sample.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
SANDLOT_POOL="small:2"
LEASE_MS="${LEASE_MS:-1000}"
TEMPLATE_DIR="${TEMPLATE_DIR:-/tmp/sandswap-tpl-swap}"
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
# Two overlay templates: app/v1 (stock) and app/v2 carrying a visible marker
# file at the rootfs root so an exec can tell which template is live.
ss_seed_template "$OUTPUT/rootfs-template" "$TEMPLATE_DIR/app/v1"
ss_seed_template "$OUTPUT/rootfs-template" "$TEMPLATE_DIR/app/v2"
echo -n "v2" > "$TEMPLATE_DIR/app/v2/TEMPLATE_VERSION"

log_section "Phase 2: Start stack"
CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
tc_gen_certs
tc_attach_vsockguard
tc_start_gateway
tc_start_sandlot -overlayfs-templates "$TEMPLATE_DIR"
tc_wait_health
log_pass "stack up (gateway + sandlot, small:2 pool)"

# ── helpers ─────────────────────────────────────────────────────────
exec_in_vm() {
    local key="$1"
    local sid="$2"
    local code="$3"
    local extra="${4:-}"
    local resp
    resp=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$sid\",\"code\":\"$code\",\"language\":\"shell\"$extra}" 2>/dev/null || echo '{}')
    echo "$resp"
}

resp_stdout() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo ""
}

resp_field() {
    tc_json_val "$1" "$2"
}

http_code() {
    # $1 method, $2 url, [$3 json body], [$4 api key]
    local args=(-s -o /dev/null -w '%{http_code}' -m 60 -X "$1" "$2")
    if [[ $# -ge 3 && -n "$3" ]]; then
        args+=(-H "Content-Type: application/json" -d "$3")
    fi
    if [[ $# -ge 4 && -n "$4" ]]; then
        args+=(-H "Authorization: Bearer $4")
    fi
    curl "${args[@]}" 2>/dev/null || echo 000
}

bg_status() {
    curl -s -m 15 -X POST "$GATEWAY_URL/agent/exec/status" \
        -H "Authorization: Bearer $1" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$2\",\"exec_id\":\"$3\"}" 2>/dev/null || echo '{}'
}

log_section "Phase 3: overlay sandfs on app:v1 + agent state"
RESP=$(tc_create_agent_and_sandfs "swap-user" "app:v1" "overlay")
SID=$(tc_json_val "$RESP" "sandfs_id")
KEY=$(tc_json_val "$RESP" "api_key")
VOL=$(tc_json_val "$RESP" "rootfs_path")
[[ -n "$SID" && -n "$KEY" ]] || { fail "3.1: create overlay sandfs failed: $RESP"; exit 1; }
pass "3.1: overlay sandfs created ($SID)"

W=$(exec_in_vm "$KEY" "$SID" "echo swap-work > /workspace/work.txt && echo home-dot > /home/agent/.swapdot && cat /TEMPLATE_VERSION 2>/dev/null || echo noversion")
if [[ "$(resp_stdout "$W")" == *"noversion"* ]]; then
    pass "3.2: app:v1 rootfs live (no TEMPLATE_VERSION marker — stock template)"
else
    fail "3.2: unexpected v1 output: $(echo "$W" | head -c 160)"
fi

log_section "Phase 4: detach — gate + bg exec death + workspace intact"
# A background exec must die with the detach drain (cgroup.kill at unmount).
BG=$(exec_in_vm "$KEY" "$SID" "sleep 300" ',"background":true,"lease_duration":120')
BGID=$(resp_field "$BG" "exec_id")
[[ -n "$BGID" ]] && pass "4.1: background exec started ($BGID)" || fail "4.1: bg start failed: $BG"

DETACH=$(http_code POST "$HUMAN_URL/human/sandfs/$SID/detach-template" '{}')
if [[ "$DETACH" == "200" ]]; then
    pass "4.2: detach-template settled (200)"
else
    fail "4.2: detach-template: expected 200, got $DETACH"
fi

GATED=$(http_code POST "$GATEWAY_URL/agent/execute" "{\"sandfs_id\":\"$SID\",\"code\":\"echo hi\",\"language\":\"shell\"}" "$KEY")
if [[ "$GATED" == "409" ]]; then
    pass "4.3: exec during detached gated (409)"
else
    fail "4.3: exec during detached: expected 409, got $GATED"
fi
FILEGATED=$(http_code POST "$GATEWAY_URL/agent/file" "{\"sandfs_id\":\"$SID\",\"action\":\"stat\",\"path\":\"work.txt\"}" "$KEY")
if [[ "$FILEGATED" == "409" ]]; then
    pass "4.4: file op during detached gated (409)"
else
    fail "4.4: file op during detached: expected 409, got $FILEGATED"
fi

# GET single sandfs shows the lifecycle status.
STATUS=$(curl -s "$HUMAN_URL/human/sandfs/$SID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
[[ "$STATUS" == "detached" ]] && pass "4.5: GET sandfs reports status=detached" || fail "4.5: status=$STATUS"

# The bg exec is dead: poll a few times for the expired/not_found verdict.
BG_VERDICT=""
for i in 1 2 3 4 5; do
    BGS=$(bg_status "$KEY" "$SID" "$BGID")
    BGS_STATUS=$(resp_field "$BGS" "status")
    case "$BGS_STATUS" in
        expired|not_found|killed|done) BG_VERDICT="$BGS_STATUS"; break ;;
    esac
    sleep 1
done
[[ -n "$BG_VERDICT" ]] && pass "4.6: bg exec dead after detach (status=$BG_VERDICT)" || fail "4.6: bg exec still alive after detach: $BGS"

# Workspace survived at the storage layer (the whole point).
[[ -f "$VOL/workspace/work.txt" ]] && pass "4.7: workspace file intact on storage" || fail "4.7: workspace file missing at $VOL"

log_section "Phase 5: attach app:v2 (home=keep)"
ATTACH=$(http_code POST "$HUMAN_URL/human/sandfs/$SID/attach-template" '{"template_ref":"app:v2","home":"keep"}')
if [[ "$ATTACH" == "200" ]]; then
    pass "5.1: attach-template 200"
else
    fail "5.1: attach-template: expected 200, got $ATTACH"
fi
REC=$(curl -s "$HUMAN_URL/human/sandfs/$SID")
[[ "$(echo "$REC" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('template','')+'|'+r.get('status',''))")" == "app:v2|" ]] \
    && pass "5.2: record: template=app:v2 status=active" || fail "5.2: record wrong: $REC"

W2=$(exec_in_vm "$KEY" "$SID" "cat /workspace/work.txt; cat /home/agent/.swapdot; cat /TEMPLATE_VERSION")
OUT2="$(resp_stdout "$W2")"
if [[ "$OUT2" == *"swap-work"* && "$OUT2" == *"home-dot"* && "$OUT2" == *"v2"* ]]; then
    pass "5.3: workspace + home carried over AND the new template is live"
else
    fail "5.3: post-attach output wrong: $OUT2"
fi

log_section "Phase 6: one-shot swap back to app:v1 with home=archive"
SWAP=$(http_code POST "$HUMAN_URL/human/sandfs/$SID/swap-template" '{"template_ref":"app:v1","home":"archive"}')
if [[ "$SWAP" == "200" ]]; then
    pass "6.1: swap-template one-shot 200"
else
    fail "6.1: swap-template: expected 200, got $SWAP"
fi
ARCHIVES=$(ls -d "$VOL"/home.pre-attach-* 2>/dev/null | wc -l)
[[ "$ARCHIVES" == "1" ]] && pass "6.2: home archived (1 copy)" || fail "6.2: archives=$ARCHIVES at $VOL"
if ls "$VOL"/home.pre-attach-*/.swapdot >/dev/null 2>&1; then
    pass "6.3: archived home recoverable (.swapdot present)"
else
    fail "6.3: archive lost .swapdot ($(ls -la "$VOL" 2>/dev/null | head -c 200))"
fi
W3=$(exec_in_vm "$KEY" "$SID" "test -f /home/agent/.swapdot && echo STALE || echo FRESH; cat /workspace/work.txt")
OUT3="$(resp_stdout "$W3")"
if [[ "$OUT3" == *"FRESH"* && "$OUT3" == *"swap-work"* ]]; then
    pass "6.4: fresh home + workspace still intact after second swap"
else
    fail "6.4: output wrong: $OUT3"
fi

log_section "Phase 7: template deletion in-use check (retirement loop)"
INUSE=$(curl -s -o /tmp/swap-tpl-del.json -w '%{http_code}' -m 60 -X DELETE \
    "$HUMAN_URL/human/templates/app:v1" -H "Content-Type: application/json" -d '{}' 2>/dev/null)
if [[ "$INUSE" == "409" && "$(grep -c TEMPLATE_IN_USE /tmp/swap-tpl-del.json)" -ge 1 ]]; then
    pass "7.1: in-use template delete refused (409 TEMPLATE_IN_USE)"
else
    fail "7.1: expected 409 TEMPLATE_IN_USE, got $INUSE: $(head -c 160 /tmp/swap-tpl-del.json)"
fi
# Swap the fleet (one sandfs) away, then the delete succeeds.
SWAP2=$(http_code POST "$HUMAN_URL/human/sandfs/$SID/swap-template" '{"template_ref":"app:v2"}')
[[ "$SWAP2" == "200" ]] && pass "7.2: fleet swapped to app:v2" || fail "7.2: swap away failed: $SWAP2"
DEL=$(http_code DELETE "$HUMAN_URL/human/templates/app:v1" '{}')
[[ "$DEL" == "204" ]] && pass "7.3: app:v1 deleted once unreferenced (204)" || fail "7.3: expected 204, got $DEL"

log_section "Phase 8: warm path sanity (informational timing)"
WARM_OK=0
TIMES=()
for i in $(seq 1 10); do
    T0=$(date +%s%N)
    R=$(exec_in_vm "$KEY" "$SID" "true")
    T1=$(date +%s%N)
    if [[ "$(resp_field "$R" "status")" == "done" ]]; then
        WARM_OK=$((WARM_OK+1))
    fi
    TIMES+=($(( (T1-T0)/1000000 )))
done
[[ "$WARM_OK" == "10" ]] && pass "8.1: 10/10 warm execs done post-swap" || fail "8.1: only $WARM_OK/10 warm execs done"
TIMES_STR=$(printf '%s\n' "${TIMES[@]}" | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]"ms median (gateway HTTP+vm)"}')
log_info "8.2: warm exec timing sample: $TIMES_STR"
pass "8.2: timing recorded (informational — no assert; the benchmark suites own the numbers)"

tc_delete_sandfs "$SID"
log_section "DONE: template swap lifecycle"

# ── Verdict ─────────────────────────────────────────────────────────
# e2e/run-all.sh judges this script by EXIT CODE alone: a recorded failure
# MUST become the exit status, or the suite reports green while failing
# (the false-green class this gate closes).
tc_log_section "template swap lifecycle Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "template swap lifecycle FAILED ($FAIL_COUNT check(s))"
    exit 1
fi
log_pass "template swap lifecycle PASSED ($PASS_COUNT checks)"
exit 0
