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
# share-root-gate.sh —: the virtio-fs allow-list is a NAMESPACE control
# at the share root, not just a visibility filter.
#
# The fix (virtiofsd/src/server.rs) denies EVERY name-based op whose parent is
# the share root (mkdir/mknod/create/symlink/link/unlink/rmdir/rename/xattr —
# previously only Lookup and Readdir consulted the filter) and answers a real
# ENOENT (the deny path used to reply EIO, which told a guest that a hidden
# name EXISTS — a cross-tenant name-existence oracle).
#
# This suite runs the REAL stack (gateway + sandlot + sandvmm + warden + guest)
# and asserts the property from both ends:
#   1. the share root is UNREACHABLE from an agent (escape matrix) — the
#      reachability pin that makes layer 2 the only thing standing between an
#      escaped guest and its siblings' volumes;
#   2. the agent's own tree still works through the same real stack (the gate
#      is root-scoped, not a blanket denial) and leaves no residue at the root;
#   3. the API surface cannot widen the boundary: on the RUNNING VMM, the
#      `vm.add-fs` / `vm.add-net` routes (attach a second share with its own
#      allow-list, or a second NIC) answer 404, while `vm.set-fs` — the
#      one share's re-filter — stays routable;
#   4. the dispatch gate itself, driven over real FUSE requests against a real
#      PassthroughFs (the same code the running sandvmm executes) — root-level
#      mutations denied ENOENT with the on-disk tree unchanged, and the same
#      opcodes one level down still working;
#   5. the host-side layer under all of it: the share root is owned by the
#      prov instance with the shared group at x ONLY (no read, no write), so
#      the daemon's own identity can neither create nor LIST entries there even
#      if the gates above regressed — probed with setpriv as uid 987, plus the
#      template store being daemon-read-only and both positive controls (the
#      daemon still traverses its volume; prov still creates/removes at root).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=common.sh
source "$ROOT/e2e/common.sh"

SANDLOT_POOL="${SANDLOT_POOL:-medium:1}"
FAIL_COUNT=0
PASS_COUNT=0

cleanup() { tc_cleanup_default; }
trap cleanup EXIT INT TERM

# exec_probe <key> <sandfs_id> <shell-code-file> — run a shell snippet in the
# agent's sandbox and print its stdout (the execute API has no file field).
exec_probe() {
    local key="$1" sid="$2" codefile="$3"
    python3 - "$sid" "$codefile" /tmp/srg-body.json <<'PY'
import json, sys
sid, codefile, out = sys.argv[1:4]
json.dump({"sandfs_id": sid, "code": open(codefile).read(), "language": "shell"},
          open(out, "w"))
PY
    curl -s -m 90 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d @/tmp/srg-body.json \
        | python3 -c 'import sys,json; d=json.load(sys.stdin); sys.stdout.write(d.get("stdout",""))' 2>/dev/null
}

# ── Phase 0: pre-flight ─────────────────────────────────────────────
log_section "Phase 0: Pre-flight"
tc_check_root
tc_preflight_standard python3
tc_check_artifacts gateway sandlot sandvmm vmlinux.bin initramfs.cpio.gz
tc_check_kvm
tc_ensure_dev_nodes
tc_setup_host_network
command -v cargo >/dev/null || { log_error "cargo is required (phase 3 drives the virtiofsd dispatch pin)"; exit 1; }

# ── Phase 1: real stack up ──────────────────────────────────────────
log_section "Phase 1: Stack up (gateway + sandlot + sandvmm + warden, one VM)"
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_attach_vsockguard
tc_start_gateway
# This drill drives the VMM API socket directly (curl --unix-socket); the
# per-VM API token preface is curl-unreachable, so run the drill with the
# documented test-tooling escape hatch (-vmm-api-auth=false). Production keeps
# the default ON.
TC_SANDLOT_EXTRA_FLAGS="${TC_SANDLOT_EXTRA_FLAGS:-} -vmm-api-auth=false"
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready 1

# Agent A is the one this VM mounts; agent B's volume is a SIBLING on the same
# share — the directory the filter must hide.
RESP_A=$(tc_create_agent_and_sandfs "srg-A" "" flat || echo '{"error":"create failed"}')
RESP_B=$(tc_create_agent_and_sandfs "srg-B" "" flat || echo '{"error":"create failed"}')
KEY_A=$(json_val "$RESP_A" "api_key"); SID_A=$(json_val "$RESP_A" "sandfs_id")
KEY_B=$(json_val "$RESP_B" "api_key"); SID_B=$(json_val "$RESP_B" "sandfs_id")
# Volume directories are DERIVED from the deployment seed, not named after the
# ids: resolve them through the human API (tc_volume_path).
SID_A_VOL="$(tc_volume_path "$SID_A")" || { fail "cannot resolve volume for $SID_A"; exit 1; }
SID_B_VOL="$(tc_volume_path "$SID_B")" || { fail "cannot resolve volume for $SID_B"; exit 1; }
[[ -n "$KEY_A" && -n "$SID_A" && -n "$KEY_B" && -n "$SID_B" ]] || { fail "agent/sandfs creation failed: $RESP_A $RESP_B"; exit 1; }
pass "agents A/B created (A=$SID_A mounted, B=$SID_B sibling)"

# A host-side sentinel inside B's volume: any root-level rename/unlink from the
# guest would have to reach through this directory first.
B_SENTINEL="${SID_B_VOL}/sibling-sentinel.txt"
echo "b-data" > "$B_SENTINEL"
ROOT_BEFORE=$(ls "$VOL_ROOT" | sort | tr '\n' ' ')

# Warm the VM so A is mounted (the escape matrix runs inside that exec context).
echo 'echo warm-ok' > /tmp/srg-warm.sh
WARM=$(exec_probe "$KEY_A" "$SID_A" /tmp/srg-warm.sh)
echo "$WARM" | grep -q "warm-ok" || { fail "warmup exec failed: $WARM"; exit 1; }
pass "agent A mounted and executing in the real guest"

# ── Phase 2: the share root is unreachable from the agent ───────────
log_section "Phase 2: escape matrix — the share root must be unreachable"
cat > /tmp/srg-escape.sh <<'CODE'
fail=0
mark() { echo "MARK:$1"; }
# (a) the host-namespace mount point does not exist inside the chroot
if ls /mnt/volumes >/dev/null 2>&1; then echo "LEAK:mnt-volumes"; fail=1; fi
mark mnt_volumes_absent
# (b) procfs escape to PID 1's root (the warden's, i.e. the guest root ns)
if ls /proc/1/root/mnt/volumes >/dev/null 2>&1; then echo "LEAK:procroot"; fail=1; fi
mark procroot_denied
if readlink /proc/1/root >/dev/null 2>&1; then echo "LEAK:procroot-link"; fail=1; fi
mark procroot_link_denied
# (c) '..' at the chroot root must stay at the chroot root
if [ "$(ls /.. 2>/dev/null | tr '\n' ' ')" != "$(ls / 2>/dev/null | tr '\n' ' ')" ]; then echo "LEAK:dotdot"; fail=1; fi
mark dotdot_confined
# (d) no mount in the namespace exposes the share to this process
if grep -qE "virtiofs.* /mnt|/mnt/volumes" /proc/self/mountinfo 2>/dev/null; then echo "LEAK:mountinfo"; fail=1; fi
mark mountinfo_clean
# (d2) the filter presents the allowed directory under a canonical ALIAS, so
# NO real volume name may appear anywhere in the agent's mount table (not
# even the agent's own): names are seed-derived secrets, and ambient sandbox
# strings leak to third-party LLMs wholesale.
if grep -qE "sf-[a-z0-9]+" /proc/self/mountinfo 2>/dev/null; then echo "LEAK:mountinfo-volume-name"; fail=1; fi
mark mountinfo_name_free
# (d3) the volume's identity stamp is MASKED in flat mode: the warden covers
# the storage plane's .sandfs-id with a read-only /dev/null bind, so the sandbox
# cannot read the sandfs id / seed generation / HMAC (ambient strings leak to
# third-party LLMs wholesale). Absent stamp = also fine (nothing to mask).
_stamp=$(cat /.sandfs-id 2>/dev/null | head -c 64)
if [ -n "$_stamp" ]; then echo "LEAK:stamp-readable"; fail=1; fi
mark stamp_masked
# (e) the sibling's volume is not findable anywhere in the visible tree
if find / -maxdepth 4 -name "__SIBLING__" 2>/dev/null | grep -q .; then echo "LEAK:sibling-visible"; fail=1; fi
mark sibling_invisible
echo "ESCAPE_DONE fail=$fail"
CODE
sed "s/__SIBLING__/$SID_B/" /tmp/srg-escape.sh > /tmp/srg-escape-run.sh
ESCAPE=$(exec_probe "$KEY_A" "$SID_A" /tmp/srg-escape-run.sh)
echo "$ESCAPE" | grep -q "ESCAPE_DONE" || { fail "escape-matrix probe never completed: $(echo "$ESCAPE" | head -c 200)"; exit 1; }
for m in mnt_volumes_absent procroot_denied procroot_link_denied dotdot_confined mountinfo_clean mountinfo_name_free stamp_masked sibling_invisible; do
    if echo "$ESCAPE" | grep -q "MARK:$m"; then pass "escape matrix: $m"; else fail "escape matrix: $m not reached"; fi
done
if echo "$ESCAPE" | grep -q "LEAK:"; then
    fail "SHARE ROOT REACHABLE from the agent: $(echo "$ESCAPE" | grep LEAK: | tr '\n' ' ')"
else
    pass "share root unreachable from the agent by every probed route (layer 2 is the remaining barrier)"
fi

# ── Phase 3: the agent's own tree works; the root gains nothing ─────
log_section "Phase 3: positive control + root-level residue"
cat > /tmp/srg-own.sh <<'CODE'
set -e
mkdir /workspace/srg-dir && echo x > /workspace/srg-dir/f && mv /workspace/srg-dir/f /workspace/srg-dir/g
rm -rf /workspace/srg-dir
echo OWN_TREE_OK
CODE
OWN=$(exec_probe "$KEY_A" "$SID_A" /tmp/srg-own.sh)
echo "$OWN" | grep -q "OWN_TREE_OK" \
    && pass "mkdir/write/rename/rmdir inside the agent's own tree still work (gate is root-scoped)" \
    || fail "the agent's own tree broke: $(echo "$OWN" | head -c 200)"

ROOT_AFTER=$(ls "$VOL_ROOT" | sort | tr '\n' ' ')
[[ "$ROOT_BEFORE" == "$ROOT_AFTER" ]] \
    && pass "the share root's entry set is unchanged by a full agent workload" \
    || fail "share root changed: before='$ROOT_BEFORE' after='$ROOT_AFTER'"
[[ "$(cat "$B_SENTINEL" 2>/dev/null)" == "b-data" ]] \
    && pass "the sibling volume's sentinel is untouched" \
    || fail "the sibling's sentinel file was damaged or removed"

# ── Phase 4: no second share can be attached to the running VM ──────
log_section "Phase 4: the VMM API surface cannot widen the share (vm.add-fs is gone)"
VMM_SOCK=""
for s in /run/sandswap/vm/*/sandvmm.sock; do
    [[ -S "$s" ]] && { VMM_SOCK="$s"; break; }
done
if [[ -z "$VMM_SOCK" ]]; then
    fail "no live sandvmm API socket found under /run/sandswap/vm/*/ (cannot probe the API surface)"
else
    # A syntactically valid "attach a second share" request — pointing at a
    # directory the running VM's allow-list does NOT cover. Before this
    # was routable and would have hotplugged a second virtio-fs device whose
    # whitelist vm.set-fs (matched by device id) never touches.
    cat > /tmp/srg-addfs.json <<EOF
{"id": "vfs-extra", "tag": "extra", "backendfs_config": {"shared_dir": "$VOL_ROOT", "read_only": false, "allowed_dirs": ["$VOL_ROOT"]}}
EOF
    ADD_FS_CODE=$(curl -s -m 10 --unix-socket "$VMM_SOCK" -o /tmp/srg-addfs-resp.txt \
        -w '%{http_code}' -X PUT "http://localhost/api/v1/vm.add-fs" -d @/tmp/srg-addfs.json)
    if [[ "$ADD_FS_CODE" == "404" ]]; then
        pass "vm.add-fs is not routable on the running VMM (404) — no second share can be attached"
    else
        fail "vm.add-fs answered HTTP $ADD_FS_CODE (want 404): a second virtio-fs device may be attachable — $(head -c 200 /tmp/srg-addfs-resp.txt)"
    fi

    # The same class: a second NIC on a running VM would be a second,
    # unaccounted egress path. Removed like add-fs, so it is not routable.
    ADD_NET_CODE=$(curl -s -m 10 --unix-socket "$VMM_SOCK" -o /tmp/srg-addnet-resp.txt \
        -w '%{http_code}' -X PUT "http://localhost/api/v1/vm.add-net" \
        -d '{"tap":"nonexistent-tap"}')
    if [[ "$ADD_NET_CODE" == "404" ]]; then
        pass "vm.add-net is not routable on the running VMM (404) — no NIC can be attached at runtime"
    else
        fail "vm.add-net answered HTTP $ADD_NET_CODE (want 404): $(head -c 200 /tmp/srg-addnet-resp.txt)"
    fi

    # Positive control: the one legitimate mutator must still be ROUTABLE.
    #
    # Its success is not unconditional any more — and that is the security
    # contract: the reuse tripwire refuses ANY set-fs (an identical re-filter
    # included, because the swap revokes every non-root inode) while the live
    # export still has open handles or un-FORGOTTEN inode references, i.e.
    # while the mounted tenant is alive. Here the agent A mount IS live, so
    # the designed answers are 204 (refs already zero — async FORGETs done)
    # or 500 naming the tripwire. The honest/lying switch legs live in
    # switch-under-adversarial.sh; this row only pins that the endpoint is
    # routed and the tripwire is armed rather than a silent no-op.
    SRG_ALIAS="$(openssl rand -hex 16)"
    SET_FS_CODE=$(curl -s -m 10 --unix-socket "$VMM_SOCK" -o /tmp/srg-setfs-resp.txt \
        -w '%{http_code}' -X PUT "http://localhost/api/v1/vm.set-fs" \
        -d "{\"id\": \"vfs-rootfs\", \"tag\": \"sandswap\", \"backendfs_config\": {\"allowed_dirs\": [\"${SID_A_VOL}\"], \"alias\": \"${SRG_ALIAS}\"}}")
    # 204 is this API's success status for an action endpoint with no body
    # (`vm.boot`, `vm.shutdown`, and `vm.set-fs` alike — vmm/src/api/http).
    if [[ "$SET_FS_CODE" == "204" || "$SET_FS_CODE" == "200" ]]; then
        pass "vm.set-fs stays routable and applied (HTTP $SET_FS_CODE, re-filter of the one share)"
    elif [[ "$SET_FS_CODE" == "500" ]] && grep -q "previous-tenant-refs" /tmp/srg-setfs-resp.txt; then
        pass "vm.set-fs stays routable; the reuse tripwire refused it while the tenant is live (fail-closed)"
    else
        fail "vm.set-fs answered HTTP $SET_FS_CODE (want 204, or 500 with the named tripwire): $(head -c 200 /tmp/srg-setfs-resp.txt)"
    fi
    # The mount must have survived the re-filter (the API control is real, not
    # a no-op response).
    STILL=$(exec_probe "$KEY_A" "$SID_A" /tmp/srg-warm.sh)
    echo "$STILL" | grep -q "warm-ok" \
        && pass "agent A still executes after the API-surface probe (mount intact)" \
        || fail "the mount broke after the API probe: $(echo "$STILL" | head -c 200)"
fi

# ── Phase 5: the dispatch pin (the code the running sandvmm executes) ─
log_section "Phase 5: virtiofsd dispatch gate (real FUSE requests, real PassthroughFs)"
if [[ "${SANDLOT_SKIP_UNIT:-0}" == "1" ]]; then
    fail "SANDLOT_SKIP_UNIT=1 would skip the dispatch pin — this suite exists for it"
else
    CARGO_OUT=$( (cd "$ROOT/vmm" && cargo test -p virtiofsd --lib root_gate --quiet) 2>&1 )
    CARGO_RC=$?
    echo "$CARGO_OUT" | tail -6
    if [[ $CARGO_RC -ne 0 ]]; then
        fail "the dispatch tests FAILED (root-level mutations reachable again?)"
    else
        NPASS=$(printf '%s\n' "$CARGO_OUT" | grep -oE '[0-9]+ passed' | awk '{s+=$1} END {print s+0}')
        if [[ "${NPASS:-0}" -lt 4 ]]; then
            fail "only ${NPASS:-0} root-gate test(s) ran (floor 4) — the pin must not silently shrink"
        else
            pass " dispatch pin green ($NPASS tests: root mutations denied ENOENT,../ name escapes denied, tree unchanged, in-tree ops still work)"
        fi
    fi
fi

# ── Phase 6: the host-side layer — the share root is daemon-read-only ─
# The fourth layer: the share root is owned by the prov instance
# with the shared group at r-x only, so the FUSE daemon's own identity cannot
# create, remove or rename anything AT the root — the KERNEL refuses, not just
# the daemon's root gate. Guest read/write inside a volume is unaffected:
# reaching a volume needs traverse on the root, and the volume itself stays
# group-rw.
log_section "Phase 6: the share root is read-only for the daemon identity (kernel-enforced)"
if ! command -v setpriv >/dev/null 2>&1 || ! id -u sandvmm >/dev/null 2>&1; then
    fail "setpriv or the sandvmm identity is unavailable — cannot probe the host-side layer"
else
    # The daemon's RUNTIME group set, not the account's: the sandlot spawn
    # REPLACES the sandvmm child's supplementary groups with exactly kvm + the
    # shared (sandlot) group via setpriv --groups, so the account itself
    # deliberately carries no memberships (the identity split removes them).
    # The probe must replicate the spawn grant or the positive control below
    # fails on a correctly-provisioned host.
    DGRP="$(id -G sandvmm | tr ' ' ',')"
    if ! grep -qw "$(getent group kvm | cut -d: -f3)" <<<"$DGRP"; then
        DGRP="${DGRP:+$DGRP,}$(getent group kvm | cut -d: -f3)"
    fi
    if ! grep -qw "$(id -g sandlot)" <<<"$DGRP"; then
        DGRP="${DGRP:+$DGRP,}$(id -g sandlot)"
    fi
    ROOT_MODE=$(stat -c '%a' "$VOL_ROOT")
    ROOT_OWNER=$(stat -c '%U:%G' "$VOL_ROOT")

    if setpriv --reuid=sandvmm --regid=sandvmm --groups="$DGRP" -- \
            touch "$VOL_ROOT/srg-hostile-probe" 2>/dev/null; then
        rm -f "$VOL_ROOT/srg-hostile-probe"
        fail "the sandvmm identity CREATED an entry at the share root ($ROOT_MODE $ROOT_OWNER) — the fourth layer is not in force"
    else
        pass "the sandvmm identity cannot create an entry at the share root ($ROOT_MODE $ROOT_OWNER) — kernel EACCES"
    fi

    # The daemon must not be able to LIST the share root either (mode 2710,
    # group x-only): a compromised sandvmm cannot enumerate the other tenants'
    # directory names — the property the code-level filter only *policy*-holds.
    if setpriv --reuid=sandvmm --regid=sandvmm --groups="$DGRP" -- \
            ls "$VOL_ROOT" >/dev/null 2>&1; then
        fail "the sandvmm identity LISTED the share root ($ROOT_MODE $ROOT_OWNER) — tenant names are enumerable"
    else
        pass "the sandvmm identity cannot list the share root (traverse-only, kernel EACCES)"
    fi

    # The template store is daemon-read-only: layers are read as overlay
    # lowerdirs, but a compromised daemon must not be able to write, replace or
    # rename template content (it is shared across nodes and tenants).
    TEMPLATES_DIR="$(dirname "$VOL_ROOT")/templates"
    if [[ -d "$TEMPLATES_DIR" ]]; then
        TPL_MODE=$(stat -c '%a %U:%G' "$TEMPLATES_DIR")
        if setpriv --reuid=sandvmm --regid=sandvmm --groups="$DGRP" -- \
                touch "$TEMPLATES_DIR/srg-daemon-probe" 2>/dev/null; then
            rm -f "$TEMPLATES_DIR/srg-daemon-probe"
            fail "the sandvmm identity WROTE into $TEMPLATES_DIR ($TPL_MODE) — template content is replaceable by the daemon"
        else
            pass "the sandvmm identity cannot write the template store ($TPL_MODE)"
        fi
    fi

    # Positive control 1: the daemon can still traverse + read the volume it
    # serves (this is what guest read/write needs — never write on the root).
    if setpriv --reuid=sandvmm --regid=sandvmm --groups="$DGRP" -- \
            sh -c "ls '${SID_A_VOL}' >/dev/null 2>&1"; then
        pass "…and still traverses + reads its own volume (guest read/write untouched)"
    else
        fail "the daemon identity cannot read ${SID_A_VOL} — the layer broke legitimate access"
    fi

    # Positive control 2: provisioning still works — the owner can create and
    # remove an entry at the root (this is DeleteVolume's orphan-rename path).
    PGRP="$(id -G "$SS_PROV_USER" | tr ' ' ',')"
    PROV_ERR="$(setpriv --reuid="$SS_PROV_USER" --regid="$SS_SHARED_GROUP" --groups="$PGRP" -- \
            sh -c "mkdir '$VOL_ROOT/srg-prov-probe' && rmdir '$VOL_ROOT/srg-prov-probe'" 2>&1)"
    if [[ -z "$PROV_ERR" ]] && [[ ! -e "$VOL_ROOT/srg-prov-probe" ]]; then
        pass "the provision identity can still create/remove entries at the root (volume lifecycle intact)"
    else
        fail "the provision identity can no longer create/remove at $VOL_ROOT (${PROV_ERR:-probe left residue}) — volume create/delete would break"
    fi
fi

# ── Summary ─────────────────────────────────────────────────────────
log_section "share-root-gate Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "share-root-gate FAILED ($FAIL_COUNT check(s))"
    exit 1
fi
log_pass "share-root-gate PASSED ($PASS_COUNT checks)"
exit 0
