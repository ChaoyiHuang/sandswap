#!/usr/bin/env bash
# template-lifecycle.sh — template lifecycle without gateway restart:
# add / delete / re-add must all be reflected on the READ surfaces
# (listing, sandfs creation) with zero restarts.
#
# Covers the discovery contract introduced with lazy rescan:
#   1. A template directory dropped into a scan root AFTER startup is
#      discovered on first use (no restart) — overlay AND flat modes.
#   2. Deleting the template directory makes it disappear from the listing
#      and makes creation FAIL FAST (no ghost sandfs that would only fail
#      at mount time). The ref file itself survives (durable record).
#   3. Re-creating the directory at the same path restores the template
#      instantly via the kept ref (again no restart).
#   4. A never-existing template still fails (discovery is not magic).
#
# Companion guarantees pinned elsewhere: overlayfs-isolation.sh 8.1 (the
# rescan never REWRITES an existing ref — tampered refs reach the sandlot's
# mount-time layer validation), template/manager_test.go (all three rules).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
SANDLOT_POOL="small:2"
LEASE_MS="${LEASE_MS:-1000}"
TEMPLATE_DIR="${TEMPLATE_DIR:-/tmp/sandswap-tpl-lifecycle}"
source "$ROOT/e2e/common.sh"

tc_use_output_binaries

FLAT_TEMPLATE_DIR="${FLAT_TEMPLATE_DIR:-/tmp/sandswap-tpl-lifecycle-flat}"
rm -rf "$FLAT_TEMPLATE_DIR" "$TEMPLATE_DIR"
# Flat scan root starts with ONE template (rootfs:v1) so the stack boots
# with a known baseline; the lifecycle template is dropped later.
ss_seed_template "$OUTPUT/rootfs-template" "$FLAT_TEMPLATE_DIR/rootfs/v1"
TC_FLAT_TEMPLATES="$FLAT_TEMPLATE_DIR"

cleanup() {
    local exit_code=$?
    tc_cleanup_default
    rm -rf "$TEMPLATE_DIR" "$FLAT_TEMPLATE_DIR" 2>/dev/null || true
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
# The PROV role (running in the sandlot below) writes refs INTO TEMPLATE_DIR —
# it must be the shared setgid dir. The gateway mounts nothing.
ss_prepare_shared_dir "$TEMPLATE_DIR"

log_section "Phase 2: Start stack (one flat template only)"
CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
tc_gen_certs
tc_attach_vsockguard
tc_start_gateway
# The sandlot carries the template store (-overlayfs-templates = the prov
# role's templates_dir): the gateway has no template manager anymore.
tc_start_sandlot -overlayfs-templates "$TEMPLATE_DIR"
tc_wait_health
log_pass "stack up (gateway + sandlot, small:2 pool)"

# ── helpers ─────────────────────────────────────────────────────────
tpl_listed() {
    curl -s "$HUMAN_URL/human/templates" 2>/dev/null | python3 -c "
import sys, json
name, _, ver = '$1'.rpartition(':')
try:
    ts = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if any(t.get('name') == name and t.get('version') == ver for t in ts) else 1)
"
}

exec_in_vm() {
    # NOTE: separate local statements — in one `local` line every expansion
    # is evaluated BEFORE any assignment lands, so ${KEY2SID[$key]} would
    # see $key as unbound under set -u (overlayfs-isolation.sh hit this too).
    local key="$1"
    local code="$2"
    local sid="${KEY2SID[$key]:-}"
    local resp try
    for try in 1 2 3; do
        resp=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/execute" \
            -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
            -d "{\"sandfs_id\":\"$sid\",\"code\":\"$code\",\"language\":\"shell\"}" 2>/dev/null || echo '{}')
        if [[ "$try" -lt 3 ]] && echo "$resp" | grep -qE '"(NO_AVAILABLE_SANDBOX|NO_COMPUTE_NODES|CONCURRENT_MOUNT|SANDBOX_CLEANING)"'; then
            sleep 2
            continue
        fi
        break
    done
    echo "$resp"
}

resp_stdout() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo ""
}

declare -A KEY2SID

# ── Phase 3: ADD (overlay) after start — no restart ────────────────
log_step "3: dropping overlay template late:v1 AFTER start..."
if tpl_listed "late:v1"; then
    fail "late:v1 already listed before it exists?"
else
    pass "3.1: late:v1 absent before the drop (baseline)"
fi
ss_seed_template "$OUTPUT/rootfs-template" "$TEMPLATE_DIR/late/v1"
# Bounded poll, not a single shot: the contract is "a directory dropped into a
# scan root is found WITHOUT A RESTART", not "within the same microsecond".
# The discovery walk classifies a name directory by its children
# (isVersionedTemplateDir returns false for an EMPTY dir), so a listing that
# arrives while `late/` exists but `late/v1/` is not yet visible registers the
# parent as a flat template and misses `late:v1` — the next call sees it. A
# single-shot assertion fails roughly one run in three (PASS and FAIL
# alternate across runs).
if tc_wait_until 5 tpl_listed "late:v1"; then
    pass "3.2: late:v1 listed after the drop — no restart (lazy discovery)"
else
    fail "3.2: late:v1 NOT listed after the drop within 5s — lazy discovery broken"
fi

LATE_RESP=$(tc_create_agent_and_sandfs "late-user" "late:v1" "overlay")
LATE_ID=$(tc_json_val "$LATE_RESP" "sandfs_id")
LATE_KEY=$(tc_json_val "$LATE_RESP" "api_key")
if [[ -n "$LATE_ID" && -n "$LATE_KEY" ]]; then
    pass "3.3: sandfs created from the just-dropped template"
    KEY2SID[$LATE_KEY]="$LATE_ID"
    LATE_EXEC=$(exec_in_vm "$LATE_KEY" "echo lazy-overlay-ok")
    if [[ "$(resp_stdout "$LATE_EXEC")" == *"lazy-overlay-ok"* ]]; then
        pass "3.4: exec on the just-dropped overlay template works"
    else
        fail "3.4: exec failed: $(echo "$LATE_EXEC" | head -c 200)"
    fi
else
    fail "3.3: create from late:v1 failed: $LATE_RESP"
fi

# ── Phase 4: ADD (flat) after start — no restart ───────────────────
log_step "4: dropping flat template extra:9.9 AFTER start..."
ss_seed_template "$OUTPUT/rootfs-template" "$FLAT_TEMPLATE_DIR/extra/9.9"
EXTRA_RESP=$(tc_create_agent_and_sandfs "extra-user" "extra:9.9" "flat")
EXTRA_ID=$(tc_json_val "$EXTRA_RESP" "sandfs_id")
EXTRA_KEY=$(tc_json_val "$EXTRA_RESP" "api_key")
if [[ -n "$EXTRA_ID" && -n "$EXTRA_KEY" ]]; then
    pass "4.1: sandfs created from the just-dropped flat template (no restart)"
    KEY2SID[$EXTRA_KEY]="$EXTRA_ID"
    EXTRA_EXEC=$(exec_in_vm "$EXTRA_KEY" "echo lazy-flat-ok")
    if [[ "$(resp_stdout "$EXTRA_EXEC")" == *"lazy-flat-ok"* ]]; then
        pass "4.2: exec on the just-dropped flat template works"
    else
        fail "4.2: exec failed: $(echo "$EXTRA_EXEC" | head -c 200)"
    fi
else
    fail "4.1: create from extra:9.9 failed: $EXTRA_RESP"
fi

# ── Phase 5: DELETE — listing and creation must reflect reality ─────
log_step "5: deleting the overlay template directory..."
rm -rf "$TEMPLATE_DIR/late/v1"
sleep 0.2
if tpl_listed "late:v1"; then
    fail "5.1: late:v1 still listed after deletion — ghost template"
else
    pass "5.1: late:v1 gone from the listing after deletion"
fi
GHOST_RESP=$(tc_create_agent_and_sandfs "ghost-user" "late:v1" "overlay" || echo '{"error":"create failed"}')
GHOST_ID=$(tc_json_val "$GHOST_RESP" "sandfs_id")
if [[ -n "$GHOST_ID" ]]; then
    fail "5.2: creation SUCCEEDED for a deleted template — ghost sandfs that would only fail at mount time"
else
    pass "5.2: creation fails fast for a deleted template: $(echo "$GHOST_RESP" | head -c 160)"
fi
LATE_REF="$TEMPLATE_DIR/refs/late_v1.overlay.json"
if [[ -f "$LATE_REF" ]]; then
    pass "5.3: ref file survived deletion (durable record — re-add will be instant)"
else
    fail "5.3: ref file was pruned on deletion — refs are durable records"
fi

# ── Phase 6: RE-ADD at the same path — instant restore ─────────────
log_step "6: re-creating the template directory at the same path..."
ss_seed_template "$OUTPUT/rootfs-template" "$TEMPLATE_DIR/late/v1"
if tpl_listed "late:v1"; then
    pass "6.1: late:v1 listed again via the kept ref (no restart)"
else
    fail "6.1: late:v1 not listed after re-creating its directory"
fi
REDO_EXEC=$(exec_in_vm "$LATE_KEY" "echo reuse-after-restore")
if [[ "$(resp_stdout "$REDO_EXEC")" == *"reuse-after-restore"* ]]; then
    pass "6.2: the ORIGINAL sandfs (created in phase 3) execs again — same ref, same layer path"
else
    fail "6.2: exec after restore failed: $(echo "$REDO_EXEC" | head -c 200)"
fi

# ── Phase 7: never-existed template still fails ────────────────────
log_step "7: a never-existing template must still fail..."
BOGUS_RESP=$(tc_create_agent_and_sandfs "bogus-user" "nope:v1" "overlay" || echo '{"error":"create failed"}')
BOGUS_ID=$(tc_json_val "$BOGUS_RESP" "sandfs_id")
if [[ -n "$BOGUS_ID" ]]; then
    fail "7: creation succeeded for a template that never existed"
else
    pass "7: never-existing template refused: $(echo "$BOGUS_RESP" | head -c 140)"
fi

# ── Verdict ─────────────────────────────────────────────────────────
log_section "Verdict"
if [[ "$FAIL_COUNT" -eq 0 ]]; then
    log_pass "ALL $PASS_COUNT checks passed — template add/delete/re-add all reflected without restart"
else
    log_error "$FAIL_COUNT check(s) failed"
fi
exit $((FAIL_COUNT > 0))
