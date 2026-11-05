#!/usr/bin/env bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# template-ref-isolation.sh — cross-tenant template ref immutability.
#
# The ref->filename encoding is NOT injective (RefToFilename maps ':' to '_'),
# so "refiso_victim:v1" and "refiso:victim_v1" both name
# refs/refiso_victim_v1.overlay.json. Before the fix, a tenant could call
# save-template under the colliding (or the exact) ref and atomically replace
# another tenant's ref file; every volume mounting that ref then runs the
# attacker's rootfs (live-verified: /bin/sh became the attacker's script).
#
# This e2e pins the fixed behavior on a real stack:
#   1. Victim saves a legitimate flat sandfs as refiso_victim:v1.
#   2. Attacker plants a trojan /bin/sh, then tries to save under
#      refiso:victim_v1 (colliding) AND refiso_victim:v1 (exact).
#      Both must be 409 TEMPLATE_EXISTS; no attacker layer may be created.
#   3. The victim's ref file still names the victim's name:version/layer.
#   4. The victim creates an overlay SandFS from the ref; /bin/sh is the
#      template's (a symlink to busybox, NOT the 208-byte trojan), the
#      victim's secret is readable, and the attacker's marker never runs.
#   5. Warden seccomp: `setsid` succeeds (the stale i386 vm86 entries used to
#      deny x86_64 setsid/setreuid).
#
# Prerequisites: built artifacts (build.sh all), root, KVM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
SANDLOT_POOL="${SANDLOT_POOL:-small:1}"
LEASE_MS="${LEASE_MS:-3000}"
TEMPLATE_DIR="${TEMPLATE_DIR:-/tmp/sandswap-refiso-templates}"
FLAT_TEMPLATE_DIR="${FLAT_TEMPLATE_DIR:-/tmp/sandswap-refiso-flat}"
VICTIM_REF="refiso_victim:v1"       # the legitimate, victim-owned ref
COLLIDING_REF="refiso:victim_v1"    # different name:version, same ref file
source "$ROOT/e2e/common.sh"

tc_use_output_binaries

rm -rf "$TEMPLATE_DIR" "$FLAT_TEMPLATE_DIR"
ss_seed_template "$OUTPUT/rootfs-template" "$FLAT_TEMPLATE_DIR/rootfs/v1"
TC_FLAT_TEMPLATES="$FLAT_TEMPLATE_DIR"

cleanup() {
    local exit_code=$?
    # Delete test sandfs first (a live overlay mount pins the ref), then let
    # the generic teardown stop the stack. The ref files/layers live under
    # TEMPLATE_DIR, removed below.
    for sid in ${C_ID:-} ${V_ID:-} ${A_ID:-}; do
        [[ -n "$sid" ]] && tc_delete_sandfs "$sid" >/dev/null 2>&1 || true
    done
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
tc_check_kvm
tc_ensure_dev_nodes
[[ -d "$OUTPUT/rootfs-template" ]] || { log_error "missing output/rootfs-template (bash build/build.sh rootfs-template)"; exit 1; }
log_pass "artifacts present"

log_section "Phase 1: Environment"
tc_clean_environment
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
fi
ss_prepare_shared_dir "$TEMPLATE_DIR"

log_section "Phase 2: Start stack"
CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
tc_gen_certs
tc_attach_vsockguard
tc_start_gateway
tc_start_sandlot -overlayfs-templates "$TEMPLATE_DIR"
tc_wait_health
# Wait for the pool THIS script asked for (small:1), not tc_wait_pool_ready's
# default target ($POOL_SIZE = 3): one clean VM serves every exec below.
tc_wait_pool_ready 1
log_pass "stack up (gateway + sandlot, pool $SANDLOT_POOL)"

resp_stdout() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo ""
}

post_code() { # url body -> "<http_code> <body>"
    local out code
    out=$(mktemp)
    code=$(curl -s -o "$out" -w '%{http_code}' -X POST "$1" -H 'Content-Type: application/json' -d "$2")
    printf '%s %s' "$code" "$(cat "$out")"
    rm -f "$out"
}

# ── Phase 3: victim's legitimate flat sandfs + template snapshot ────
log_step "3: victim flat sandfs + save-template $VICTIM_REF"
V_RESP=$(tc_create_agent_and_sandfs "refiso-victim" "rootfs:v1" "flat")
V_ID=$(tc_json_val "$V_RESP" "sandfs_id")
V_KEY=$(tc_json_val "$V_RESP" "api_key")
[[ -n "$V_ID" && -n "$V_KEY" ]] || { fail "3.1: victim sandfs create failed: $V_RESP"; exit 1; }
pass "3.1: victim sandfs $V_ID"

SAVE=$(post_code "$HUMAN_URL/human/sandfs/$V_ID/save-template" "{\"template_ref\":\"$VICTIM_REF\"}")
SAVE_CODE=${SAVE%% *}
[[ "$SAVE_CODE" == "200" ]] || { fail "3.2: victim save-template returned $SAVE"; exit 1; }
VICTIM_REF_FILE="$TEMPLATE_DIR/refs/refiso_victim_v1.overlay.json"
[[ -f "$VICTIM_REF_FILE" ]] || { fail "3.2: victim ref file missing at $VICTIM_REF_FILE"; exit 1; }
VICTIM_LAYER=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["layers"][0])' "$VICTIM_REF_FILE")
pass "3.2: victim ref written (layer $VICTIM_LAYER)"

# ── Phase 4: attacker plants a trojan /bin/sh ───────────────────────
log_step "4: attacker flat sandfs + trojan /bin/sh"
A_RESP=$(tc_create_agent_and_sandfs "refiso-attacker" "rootfs:v1" "flat")
A_ID=$(tc_json_val "$A_RESP" "sandfs_id")
A_KEY=$(tc_json_val "$A_RESP" "api_key")
[[ -n "$A_ID" && -n "$A_KEY" ]] || { fail "4.1: attacker sandfs create failed: $A_RESP"; exit 1; }
TROJAN=$(cat <<'EOS'
rm -f /bin/sh
cat > /bin/sh <<'INNER'
#!/bin/busybox sh
{ echo "PWNED-BY-ATTACKER uid=$(id -u)"; cat /workspace/secret.txt 2>/dev/null; } > /workspace/.pwned-by-attacker
exec /bin/busybox sh -c "$2"
INNER
chmod 755 /bin/sh
ls -l /bin/sh
EOS
)
TROJAN_RESP=$(ss_gw_exec_raw "$A_KEY" "$A_ID" "$TROJAN" 30 12)
if [[ "$(resp_stdout "$TROJAN_RESP")" == *"PWNED"* || "$(resp_stdout "$TROJAN_RESP")" == *"-rwx"* ]]; then
    pass "4.1: attacker /bin/sh replaced (208-byte script is the payload)"
else
    fail "4.1: could not plant the trojan: $(echo "$TROJAN_RESP" | head -c 240)"
fi

# ── Phase 5: both overwrite attempts must be refused ────────────────
log_step "5: attacker save-template overwrite attempts"
for ref in "$COLLIDING_REF" "$VICTIM_REF"; do
    RESP=$(post_code "$HUMAN_URL/human/sandfs/$A_ID/save-template" "{\"template_ref\":\"$ref\"}")
    CODE=${RESP%% *}
    BODY=${RESP#* }
    if [[ "$CODE" == "409" && "$BODY" == *TEMPLATE_EXISTS* ]]; then
        pass "5: $ref refused with 409 TEMPLATE_EXISTS"
    else
        fail "5: $ref was NOT refused (got $CODE $BODY) — cross-tenant ref overwrite"
    fi
done
# The colliding attempt must not even have created its layer directory (the
# refusal happens BEFORE the copy).
if [[ -e "$TEMPLATE_DIR/layers/local-refiso-victim_v1" ]]; then
    fail "5.3: the refused colliding save still created an attacker layer dir"
else
    pass "5.3: no attacker layer was created by the refused save"
fi
# The victim's ref still carries the victim's identity and layer.
if python3 - "$VICTIM_REF_FILE" "$VICTIM_LAYER" <<'PY'
import json, sys
e = json.load(open(sys.argv[1]))
ok = (e.get("name") == "refiso_victim" and e.get("version") == "v1"
      and e.get("layers") == [sys.argv[2]])
sys.exit(0 if ok else 1)
PY
then
    pass "5.4: victim ref identity/layer unchanged"
else
    fail "5.4: victim ref was modified by the attacker: $(cat "$VICTIM_REF_FILE")"
fi

# ── Phase 6: victim overlay still serves the ORIGINAL template ──────
log_step "6: victim overlay SandFS from $VICTIM_REF"
C_RESP=$(tc_create_agent_and_sandfs "refiso-victim-overlay" "$VICTIM_REF" "overlay")
C_ID=$(tc_json_val "$C_RESP" "sandfs_id")
C_KEY=$(tc_json_val "$C_RESP" "api_key")
[[ -n "$C_ID" && -n "$C_KEY" ]] || { fail "6.1: victim overlay create failed: $C_RESP"; exit 1; }
pass "6.1: victim overlay sandfs $C_ID"

# The write must LAND: it goes through the same single-VM slot as the execs
# below, so a busy slot (retryable NO_AVAILABLE_SANDBOX) is retried and the
# result is asserted — discarding it here made the later "secret unreadable"
# failure look like a template bug instead of a skipped write.
write_retry() { # key sandfs path data -> response body
    local key="$1" sid="$2" _path="$3" data="$4" resp="" i w
    for i in $(seq 1 12); do
        resp=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/file" \
            -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
            -d "{\"sandfs_id\":\"$sid\",\"action\":\"write\",\"path\":\"$_path\",\"data\":\"$data\"}")
        ss_body_retryable "$resp" || break
        w=$(ss_body_retry_after_ms "$resp" 1000)
        sleep "$(python3 -c "print(min($w,10000) / 1000)")"
    done
    printf '%s' "$resp"
}
WRESP=$(write_retry "$C_KEY" "$C_ID" secret.txt REFISO-VICTIM-SECRET)
if [[ "$WRESP" == *'"ok":true'* ]]; then
    pass "6.0: victim workspace secret written"
else
    fail "6.0: victim secret write failed: $(echo "$WRESP" | head -c 240)"
fi
# 12 retryable attempts: the pool is deliberately ONE small VM with a 3s
# lease, so a busy slot (NO_AVAILABLE_SANDBOX, retryable) clears only after
# the lease expires — the default 3 tries can burn through before that.
VEXEC=$(ss_gw_exec_raw "$C_KEY" "$C_ID" \
    'ls -l /bin/sh; cat /workspace/secret.txt; /bin/busybox setsid true; echo SETSID_RC=$?; cat /workspace/.pwned-by-attacker 2>&1; echo REFISO-DONE' 60 12)
VOUT=$(resp_stdout "$VEXEC")
if [[ "$VOUT" == *"-> busybox"* ]]; then
    pass "6.2: victim /bin/sh is the template symlink (not the attacker script)"
else
    fail "6.2: victim /bin/sh is not the template's symlink: $(echo "$VOUT" | head -c 240) [raw: $(echo "$VEXEC" | head -c 300)]"
fi
if [[ "$VOUT" == *"REFISO-VICTIM-SECRET"* ]]; then
    pass "6.3: victim workspace readable under the original template"
else
    fail "6.3: victim secret unreadable: $(echo "$VOUT" | head -c 240) [raw: $(echo "$VEXEC" | head -c 300)]"
fi
if [[ "$VOUT" == *"PWNED-BY-ATTACKER"* ]]; then
    fail "6.4: the attacker's trojan ran inside the victim sandfs"
else
    pass "6.4: attacker marker absent — the victim's lowerdir is the victim's layer"
fi
if [[ "$VOUT" == *"SETSID_RC=0"* ]]; then
    pass "6.5: setsid succeeds under the warden seccomp profile (i386 vm86 entries removed)"
else
    fail "6.5: setsid failed inside the guest: $(echo "$VOUT" | head -c 240)"
fi

# ── Verdict ─────────────────────────────────────────────────────────
log_section "Verdict"
if [[ "$FAIL_COUNT" -eq 0 ]]; then
    log_pass "ALL $PASS_COUNT checks passed — template refs are immutable across tenants"
else
    log_error "$FAIL_COUNT check(s) failed"
fi
exit $((FAIL_COUNT > 0))
