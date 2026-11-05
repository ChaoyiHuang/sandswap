#!/usr/bin/env bash
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
# mount-identity-race.sh — generation-bound mount identity drill.
#
# Proves the contract that closes the mount-identity race, against the LIVE
# stack (real sandvmm + warden, one pooled VM):
#
#   (a) a mount carrying a superseded generation's alias is refused with
#       mount_target_not_exported (code 7) and executes nothing;
#   (b) after another generation is mounted, the stale request is still
#       refused and the live tenant's warm exec keeps working;
#   (c) an unmount naming a different identity is answered MISMATCH (code 9)
#       and tears down nothing;
#   (d) set-fs refuses to reuse the previous generation's alias;
#   (e) the stale-mount probe does not disturb the live mount.
#
# The VM is driven directly through its VMM API socket and the warden-probe
# (the same vsock path the sandlot uses, as the sandlot identity). The drill
# does not depend on gateway traffic, so the interleavings are deterministic.
#
# Usage: bash e2e/mount-identity-race.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/e2e/common.sh"

# A single-VM pool is the point: every scenario must hit the SAME VM.
# shellcheck disable=SC2034
SANDLOT_POOL="medium:1"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"

tc_check_root
tc_preflight_standard
tc_check_artifacts gateway sandlot sandvmm warden-probe vmlinux.bin initramfs.cpio.gz
tc_check_kvm
tc_ensure_dev_nodes
[[ "$NETWORK_BACKEND" == "bridge" ]] && tc_setup_host_network
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_attach_vsockguard

cleanup() { tc_cleanup_default; }
trap cleanup EXIT INT TERM

tc_start_gateway
# This drill drives the VMM API socket directly (curl --unix-socket); the
# per-VM API token preface is curl-unreachable, so run the drill with the
# documented test-tooling escape hatch (-vmm-api-auth=false). Production keeps
# the default ON.
TC_SANDLOT_EXTRA_FLAGS="${TC_SANDLOT_EXTRA_FLAGS:-} -vmm-api-auth=false"
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready 1
tc_pass "single-VM stack up"

# ── Locate the live VM and its control surfaces ────────────────────
ST=""
for st in /run/sandswap-state/default/*/state.json; do
    [[ -f "$st" ]] || continue
    pid=$(python3 -c "import json;print(json.load(open('$st')).get('pid',''))" 2>/dev/null || true)
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [[ -d "/proc/$pid" && "$(cat "/proc/$pid/comm" 2>/dev/null || true)" == "sandvmm" ]] || continue
    ST="$st"
    break
done
if [[ -z "$ST" ]]; then
    tc_fail "no live VM state.json found"
    exit 1
fi
VM_ID=$(basename "$(dirname "$(dirname "$ST")")")
API=$(python3 -c "import json;print(json.load(open('$ST')).get('api_socket',''))" 2>/dev/null || true)
CID=$(python3 -c "import json;print(json.load(open('$ST')).get('cid',''))" 2>/dev/null || true)
[[ -n "$API" && -n "$CID" ]] || { tc_fail "state.json lacks api_socket/cid"; exit 1; }
tc_pass "VM $VM_ID discovered (cid=$CID)"

PROBE="$OUTPUT/warden-probe"
# The probe is the stand-in for the sandlot's vsock client: vsockguard pins
# AF_VSOCK port 1024 to the sandlot UID, so it must run as that identity.
probe_run() {
    setpriv --reuid=sandlot --regid=sandlot --clear-groups \
        "$PROBE" -cid "$CID" -state "$ST" -timeout 8s "$@" 2>&1
}

setfs() { # <host-dir-or-empty> <alias-or-empty> → 0 on HTTP 200
    local dir="$1" alias="$2" dirs body code
    if [[ -n "$dir" ]]; then dirs="[\"$dir\"]"; else dirs="[]"; fi
    body=$(SYS_DIRS="$dirs" SYS_ALIAS="$alias" python3 -c '
import json, os
d = {"id": "vfs-rootfs", "tag": "sandswap",
     "backendfs_config": {"allowed_dirs": json.loads(os.environ["SYS_DIRS"])}}
if os.environ["SYS_ALIAS"]:
    d["backendfs_config"]["alias"] = os.environ["SYS_ALIAS"]
print(json.dumps(d))')
    code=$(curl -s -m 15 -o "$LOG_DIR/mount-identity-setfs.out" -w '%{http_code}' \
        --unix-socket "$API" -X PUT http://localhost/api/v1/vm.set-fs \
        -H 'Content-Type: application/json' -d "$body")
    SETFS_BODY=$(cat "$LOG_DIR/mount-identity-setfs.out" 2>/dev/null || true)
    SETFS_CODE="$code"
    [[ "$code" == 2?? ]]
}

resp_code() { sed -n 's/^resp code=\([0-9]*\).*/\1/p' <<<"$1" | head -n1; }
resp_stdout() { sed -n 's/^stdout "\(.*\)"$/\1/p' <<<"$1" | head -n1; }

mkvol() { # <name> → absolute dir under the sandlot's volumes root
    # The volume must be a real flat rootfs (the drill execs /bin/sh inside
    # it) and must be writable by the sandvmm identity (the virtio-fs daemon
    # creates proc/dev/etc mount targets through the share).
    local d="$VOL_ROOT/$1" g
    mkdir -p "$d"
    cp -a "$ROOT/output/rootfs-template/." "$d/"
    g=$(stat -c %G "$VOL_ROOT")
    chgrp -R "$g" "$d" 2>/dev/null || true
    chmod -R g+rwX "$d"
    printf '%s' "$d"
}
VOL_A=$(mkvol "race-a")
VOL_B=$(mkvol "race-b")
VOL_C=$(mkvol "race-c")

ALIAS_A="$(openssl rand -hex 16)"
ALIAS_B="$(openssl rand -hex 16)"
ALIAS_C="$(openssl rand -hex 16)"
STALE_ALIAS="$(openssl rand -hex 16)"
WRONG_ALIAS="$(openssl rand -hex 16)"

# ── (a) generation A mounts and executes ───────────────────────────
if setfs "$VOL_A" "$ALIAS_A"; then
    tc_pass "set-fs A accepted (alias generation A)"
else
    tc_fail "set-fs A rejected: HTTP ${SETFS_CODE:-?} body=$(head -c 300 <<<"$SETFS_BODY")"
    exit 1
fi
OUT=$(probe_run mount-exec "$ALIAS_A" /mnt/rootfs "echo A_OK")
if [[ "$(resp_code "$OUT")" == "0" && "$(resp_stdout "$OUT")" == *"A_OK"* ]]; then
    tc_pass "mount-exec under generation A ran in the exported volume"
else
    tc_fail "mount-exec A unexpected: $(head -c 240 <<<"$OUT")"
fi

# Clear the mount through its own identity (the warden's REMOVED path).
OUT=$(probe_run unmount /mnt/rootfs "$ALIAS_A")
if [[ "$(resp_code "$OUT")" == "0" ]]; then
    tc_pass "identity-bound unmount of generation A removed the mount"
else
    tc_fail "unmount A unexpected: $(head -c 240 <<<"$OUT")"
fi
# The sandlot's switch sequence is umount → set-fs(clear) → set-fs(next).
if setfs "" ""; then
    tc_pass "filter cleared after the unmount"
else
    tc_fail "filter clear rejected: $(head -c 200 <<<"$SETFS_BODY")"
fi

# The alias is now retired: a mount with it must be refused with code 7 and
# must NOT execute the command.
OUT=$(probe_run mount-exec "$ALIAS_A" /mnt/rootfs "echo MUST_NOT_RUN")
if [[ "$(resp_code "$OUT")" == "7" ]] && ! grep -q "MUST_NOT_RUN" <<<"$OUT"; then
    tc_pass "stale alias after clear → code 7, no exec"
else
    tc_fail "stale alias after clear unexpected: $(head -c 240 <<<"$OUT")"
fi

# ── (b) generation B mounts; the stale request is still refused ────
if setfs "$VOL_B" "$ALIAS_B"; then
    tc_pass "set-fs B accepted (fresh generation alias)"
else
    tc_fail "set-fs B rejected: $(head -c 200 <<<"$SETFS_BODY")"
fi
OUT=$(probe_run mount-exec "$ALIAS_B" /mnt/rootfs "echo B_OK")
if [[ "$(resp_code "$OUT")" == "0" && "$(resp_stdout "$OUT")" == *"B_OK"* ]]; then
    tc_pass "mount-exec under generation B ran in the exported volume"
else
    tc_fail "mount-exec B unexpected: $(head -c 240 <<<"$OUT")"
fi

OUT=$(probe_run mount-exec "$STALE_ALIAS" /mnt/rootfs "echo MUST_NOT_RUN")
if [[ "$(resp_code "$OUT")" == "7" ]] && ! grep -q "MUST_NOT_RUN" <<<"$OUT"; then
    tc_pass "invented alias while B is live → code 7, no exec"
else
    tc_fail "invented alias unexpected: $(head -c 240 <<<"$OUT")"
fi

# The live tenant is untouched by the refused request (probe-first: the old
# mount was not torn down).
OUT=$(probe_run exec "echo VICTIM_OK" 10 "$ALIAS_B")
if [[ "$(resp_code "$OUT")" == "0" && "$(resp_stdout "$OUT")" == *"VICTIM_OK"* ]]; then
    tc_pass "live tenant warm exec still works after the stale mount"
else
    tc_fail "live tenant warm exec broken: $(head -c 240 <<<"$OUT")"
fi

# ── (c) unmount identity mismatch tears down nothing ───────────────
OUT=$(probe_run unmount /mnt/rootfs "$WRONG_ALIAS")
if [[ "$(resp_code "$OUT")" == "9" ]]; then
    tc_pass "unmount with a wrong identity → code 9, nothing torn down"
else
    tc_fail "wrong-identity unmount unexpected: $(head -c 240 <<<"$OUT")"
fi
OUT=$(probe_run exec "echo STILL_B" 10 "$ALIAS_B")
if [[ "$(resp_code "$OUT")" == "0" && "$(resp_stdout "$OUT")" == *"STILL_B"* ]]; then
    tc_pass "live mount survives the mismatched unmount"
else
    tc_fail "live mount was torn down by a mismatched unmount: $(head -c 240 <<<"$OUT")"
fi

# ── (d) alias reuse across generations is refused by the VMM ───────
OUT=$(probe_run unmount /mnt/rootfs "$ALIAS_B")
[[ "$(resp_code "$OUT")" == "0" ]] || tc_fail "unmount B unexpected: $(head -c 200 <<<"$OUT")"
# Clear first: the reuse check must survive a clear (the retired alias is
# remembered across the deny-all state).
if setfs "" ""; then
    tc_pass "filter cleared after generation B"
else
    tc_fail "filter clear after B rejected: $(head -c 200 <<<"$SETFS_BODY")"
fi
if setfs "$VOL_C" "$ALIAS_B"; then
    tc_fail "set-fs reused the previous generation's alias (must be refused)"
elif grep -qi "already used" <<<"$SETFS_BODY"; then
    tc_pass "alias reuse refused by name ($(head -c 80 <<<"$SETFS_BODY"))"
else
    tc_fail "alias reuse refused without the named reason: $(head -c 200 <<<"$SETFS_BODY")"
fi

# ── (e) clear state + a new generation; probe-first leaves it live ─
if setfs "" ""; then
    tc_pass "clear set-fs accepted (empty list, no alias)"
else
    tc_fail "clear set-fs rejected: $(head -c 200 <<<"$SETFS_BODY")"
fi
OUT=$(probe_run mount-exec "$ALIAS_C" /mnt/rootfs "echo MUST_NOT_RUN")
if [[ "$(resp_code "$OUT")" == "7" ]]; then
    tc_pass "mount under a cleared filter → code 7"
else
    tc_fail "mount under a cleared filter unexpected: $(head -c 240 <<<"$OUT")"
fi

if setfs "$VOL_C" "$ALIAS_C"; then
    tc_pass "set-fs C accepted after the clear"
else
    tc_fail "set-fs C rejected: $(head -c 200 <<<"$SETFS_BODY")"
fi
OUT=$(probe_run mount-exec "$ALIAS_C" /mnt/rootfs "echo C_OK")
if [[ "$(resp_code "$OUT")" == "0" && "$(resp_stdout "$OUT")" == *"C_OK"* ]]; then
    tc_pass "mount-exec under generation C ran in the exported volume"
else
    tc_fail "mount-exec C unexpected: $(head -c 240 <<<"$OUT")"
fi

OUT=$(probe_run mount-exec "$STALE_ALIAS" /mnt/rootfs "echo MUST_NOT_RUN")
if [[ "$(resp_code "$OUT")" == "7" ]] && ! grep -q "MUST_NOT_RUN" <<<"$OUT"; then
    tc_pass "stale alias while C is live → code 7, no exec"
else
    tc_fail "stale alias while C live unexpected: $(head -c 240 <<<"$OUT")"
fi
OUT=$(probe_run exec "echo C_STILL_LIVE" 10 "$ALIAS_C")
if [[ "$(resp_code "$OUT")" == "0" && "$(resp_stdout "$OUT")" == *"C_STILL_LIVE"* ]]; then
    tc_pass "probe-first left the live generation untouched"
else
    tc_fail "live generation damaged by the stale probe: $(head -c 240 <<<"$OUT")"
fi

# Cleanup the VM's guest mount and filter for the next script in the battery.
OUT=$(probe_run unmount /mnt/rootfs "$ALIAS_C")
[[ "$(resp_code "$OUT")" == "0" ]] || tc_log_warn "cleanup unmount returned: $(head -c 160 <<<"$OUT")"
setfs "" "" || tc_log_warn "cleanup set-fs clear failed"

tc_log_section "Summary"
if [[ ${FAIL_COUNT:-0} -gt 0 ]]; then
    tc_fail "$FAIL_COUNT mount-identity check(s) FAILED"
    exit 1
fi
tc_log_pass "mount-identity-race: generation alias binds set-fs to mount; stale/mismatched requests are inert"
