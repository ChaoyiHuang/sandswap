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
# warden-chroot-escape.sh — end-to-end pin for the agent-planted-symlink
# chroot escape: the warden resolves
# agent-controlled paths in ITS OWN mount namespace, and a FLAT SandFS volume
# is fully agent-writable — so the agent can plant entries the warden itself
# follows at mount time, and write through warden-owned files it binds in.
#
# Vector 1. The agent plants `rootfs -> /` at its volume root.
# The warden's mount-mode probe (warden/src/mount.rs detect_overlay_mode —
# `Path::exists()`, i.e. a FOLLOWING stat) sees the symlink resolve to the
# warden's own root and takes the overlay branch, binding the symlink TARGET
# (the warden's initramfs root: /init, /init.orig, /bin/busybox, /mnt/volumes)
# as the chroot root. The agent's next exec then runs INSIDE the warden's
# filesystem — from the escape, the busybox the warden hot-binds into every
# later tenant's chroot in this VM is writable (cross-tenant delivery).
# Vector 2. The agent plants `etc/resolv.conf -> /bin/busybox`.
# The warden's per-mount resolv.conf write (std::fs::write — no O_NOFOLLOW)
# follows the link and overwrites the WARDEN's /bin/busybox with fixed
# content: every later exec in the VM dies in execve (ENOEXEC).
# Vector 3. No escape needed: overlay_hot_busybox binds the
# warden's own /bin/busybox over `<root>/bin/busybox` with a bare MS_BIND, and
# the kernel drops per-mount flags passed in the same call — so the bound
# alias stayed READ-WRITE and the agent (euid 0 inside the chroot) could
# rewrite the very binary every later tenant in this VM executes. The bind is
# now two-step (bind, then MS_REMOUNT|MS_BIND|MS_RDONLY); this vector execs a
# write attempt against the chroot's /bin/busybox and requires it to FAIL with
# the file unchanged.
#
# The mode decision is cached per volume for the warden's lifetime, so vectors
# 1 and 2 are only reachable through a FRESH warden: the drill kills the
# sandvmm process of the (single) pool VM and waits for the pool's
# destroy-and-replace to boot a replacement (same pattern as
# vmm-crash-selfheal.sh), then execs the same sandfs — a cold mount whose mode
# probe runs on a warden that has never seen the volume.
#
# GREEN contract (fixed warden: lstat-based probe, symlinked bind sources
# refused, mount targets / mount-time writes anchored to O_NOFOLLOW fds,
# warden-owned binds remounted read-only):
#   v1 — the chroot root stays the agent's own volume (its planted marker is
#        visible), the warden's root is NOT the chroot (/mnt/volumes and /init
#        are unreachable) and the chroot's /bin/busybox hash is unchanged;
#   v2 — after the planted resolv.conf symlink and a fresh mount the agent
#        still executes and its OWN /etc/resolv.conf carries the DNS content;
#   v3 — a write attempt against the chroot's /bin/busybox is refused (EROFS)
#        and the binary's hash equals the pre-exploit baseline.
# RED contract (unfixed warden): v1 runs with the chroot at the warden's root
# (marker missing, /mnt/volumes + /init visible), v2's re-mount destroys
# the VM's busybox (the agent's exec fails), and v3's truncating write
# succeeds — the warden's shell is replaced for every later tenant in the VM.
# It prints `VERDICT: ESCAPED` and exits non-zero.
#
# The resolv.conf vector is only meaningful under bridge networking: the
# warden mounts resolv.conf into the chroot only when warden.net_dns is set
# (IP-assigning backends), so any other backend makes vector 2 vacuous — the
# script refuses to run one.
#
# Usage: sudo bash e2e/warden-chroot-escape.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# One microVM: the forced replacement (fresh warden) is deterministic and
# every exec lands on it — the whole drill depends on that.
# shellcheck disable=SC2034  # SANDLOT_POOL is consumed by the sourced common.sh
SANDLOT_POOL="medium:1"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"

if [[ "$NETWORK_BACKEND" != "bridge" ]]; then
    tc_log_error "NETWORK_BACKEND=$NETWORK_BACKEND: vector 2 needs warden.net_dns (set only for IP-assigning backends) — refusing to run a vacuous resolv.conf check"
    exit 1
fi

cleanup() {
    # The warden's console (hvc0 → console.log) carries the mount-time
    # evidence (mode probe, symlink refusal); serial.log keeps earlyprintk.
    # Rescue both before tc_cleanup_default removes /run/sandswap and $LOG_DIR.
    rm -rf /tmp/sandswap-chroot-escape-logs
    mkdir -p /tmp/sandswap-chroot-escape-logs/vm-console /tmp/sandswap-chroot-escape-logs/vm-serial
    cp -a "$LOG_DIR" /tmp/sandswap-chroot-escape-logs/ 2>/dev/null || true
    for f in /run/sandswap/vm/*/console.log; do
        [[ -f "$f" ]] || continue
        cp -a "$f" "/tmp/sandswap-chroot-escape-logs/vm-console/$(basename "$(dirname "$f")")-console.log" 2>/dev/null || true
    done
    for f in /run/sandswap/vm/*/serial.log; do
        [[ -f "$f" ]] || continue
        cp -a "$f" "/tmp/sandswap-chroot-escape-logs/vm-serial/$(basename "$(dirname "$f")")-serial.log" 2>/dev/null || true
    done
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

# ── Exec / parsing helpers ───────────────────────────────────────────

# gexec <key> <sandfs_id> <code> [timeout] [retries] — sync exec printing the
# RAW JSON body. tc_gw_exec_raw retries ONLY the designed retryable refusals
# (SANDBOX_CLEANING / NO_AVAILABLE_SANDBOX while a replacement VM boots),
# honoring retry_after_ms; everything else is returned verbatim.
gexec() { tc_gw_exec_raw "$1" "$2" "$3" "${4:-30}" "${5:-10}"; }

# jf <body> <field> — one field of an exec response; '' when absent (never
# fails, so `set -e` callers assert on the value).
jf() { printf '%s' "$1" | tc_json_field "$2"; }

# kv <stdout> <KEY> — value of the KEY=... line a probe printed.
kv() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n1; }

# oneline <text> — collapse a multi-line value for log lines.
oneline() { printf '%s' "$1" | tr '\n' ' ' | head -c 300; }

# force_fresh_vm — SIGKILL the (single) pool VM's sandvmm and wait for the
# pool's destroy-and-replace to boot a replacement. Sets FRESH_PID. Returns
# non-zero when the pool never heals (harness failure — callers abort).
force_fresh_vm() {
    local victim healed=0 clean
    local pids=()
    mapfile -t pids < <(tc_run_vm_pids)
    if [[ ${#pids[@]} -lt 1 ]]; then
        tc_log_error "no live sandvmm pid in /run/sandswap-state/default/*/state.json"
        return 1
    fi
    victim="${pids[0]}"
    tc_log_step "Killing sandvmm pid $victim (SIGKILL) — the pool must boot a replacement with a fresh warden"
    kill -9 "$victim" 2>/dev/null || true
    # Same heal shape as vmm-crash-selfheal.sh: target reached AND victim gone
    # AND a different pid live. Generous budget: nested-virt cold boots are slow.
    for _ in $(seq 1 90); do
        sleep 1.5
        mapfile -t pids < <(tc_run_vm_pids)
        clean=$(tc_stats_clean_vms)
        clean="${clean//[[:space:]]/}"
        case "$clean" in ''|*[!0-9]*) clean=0 ;; esac
        if [[ "$clean" -ge 1 ]] && [[ ! " ${pids[*]:-} " == *" $victim "* ]] && [[ ${#pids[@]} -ge 1 ]]; then
            healed=1
            break
        fi
    done
    if [[ "$healed" != "1" ]]; then
        tc_fail "pool did not replace the killed VM within 135s (clean=$clean, pids=(${pids[*]:-}))"
        return 1
    fi
    FRESH_PID="${pids[0]}"
    tc_pass "fresh VM booted (sandvmm $victim -> $FRESH_PID) — its warden has an empty mode cache"
    return 0
}

# ══════════════════════════════════════════════════════════════
tc_log_section "Phase 0: Pre-flight"
# ══════════════════════════════════════════════════════════════
tc_check_root
tc_preflight_standard
tc_check_artifacts gateway sandlot sandvmm vmlinux.bin initramfs.cpio.gz
tc_check_kvm
tc_ensure_dev_nodes
tc_setup_host_network

# ══════════════════════════════════════════════════════════════
tc_log_section "Phase 1: Stack up (gateway + sandlot + one microVM)"
# ══════════════════════════════════════════════════════════════
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_attach_vsockguard
tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready 1

# ══════════════════════════════════════════════════════════════
tc_log_section "Phase 2: Flat SandFS fixture"
# ══════════════════════════════════════════════════════════════
RESP_A=$(tc_create_agent_and_sandfs "chroot-escape" "" flat)
A_KEY=$(json_val "$RESP_A" "api_key")
A_SF=$(json_val "$RESP_A" "sandfs_id")
if [[ -z "$A_KEY" || -z "$A_SF" ]]; then
    tc_fail "agent/sandfs fixture creation failed: $(oneline "$RESP_A")"
    exit 1
fi
# Volume directories are DERIVED from the deployment seed — resolve the host
# path through the record, never assume "$VOL_ROOT/$id".
if ! A_VOL="$(tc_volume_path "$A_SF")"; then
    tc_fail "cannot resolve the host volume path of sandfs $A_SF"
    exit 1
fi
tc_pass "flat sandfs $A_SF ready (volume $A_VOL)"

# ══════════════════════════════════════════════════════════════
tc_log_section "Phase 3: Pre-exploit state (warm mount + busybox baseline + plant)"
# ══════════════════════════════════════════════════════════════

# Baselines taken through a real exec, BEFORE anything is planted: the
# chroot's /bin/busybox must be byte-identical after the exploit (a different
# binary at that path is the escape/tamper fingerprint).
CODE_WARM=$(cat <<'WARM'
bbh=$(/bin/busybox sha256sum /bin/busybox 2>/dev/null); bbh=${bbh%% *}
echo "WARM_OK"
echo "PRE_BBH=$bbh"
WARM
)
BODY_W=$(gexec "$A_KEY" "$A_SF" "$CODE_WARM")
OUT_W=$(jf "$BODY_W" stdout)
PRE_BBH=$(kv "$OUT_W" PRE_BBH)
if [[ "$OUT_W" != *WARM_OK* || ! "$PRE_BBH" =~ ^[0-9a-f]{64}$ ]]; then
    tc_fail "pre-exploit exec failed (stdout '$(oneline "$OUT_W")', body '$(oneline "$BODY_W")')"
    exit 1
fi
tc_pass "pre-exploit exec OK; baseline /bin/busybox sha256=${PRE_BBH:0:16}..."

# The plant itself (a legitimate write to the agent's own volume — / IS the
# volume in flat mode). workspace/home are created explicitly so the overlay
# branch the probe is about to force can bind them (its binds are fatal).
CODE_PLANT=$(cat <<'PLANT'
ln -sfn / /rootfs
mkdir -p /workspace /home
echo marker > /planted-marker
[ -L /rootfs ] && [ -f /planted-marker ] && echo PLANTED
PLANT
)
BODY_P=$(gexec "$A_KEY" "$A_SF" "$CODE_PLANT")
OUT_P=$(jf "$BODY_P" stdout)
PLANT_OK=1
if [[ "$OUT_P" != *PLANTED* ]]; then
    tc_fail "plant exec did not confirm (stdout '$(oneline "$OUT_P")', body '$(oneline "$BODY_P")')"
    PLANT_OK=0
fi
# Host-side view of the same volume — independent of anything the guest said.
if [[ "$(readlink "$A_VOL/rootfs" 2>/dev/null || true)" == "/" ]]; then
    tc_pass "planted: $A_VOL/rootfs -> / (host-side view)"
else
    tc_fail "the rootfs symlink is not on the host volume: '$(readlink "$A_VOL/rootfs" 2>/dev/null || echo '<none>')'"
    PLANT_OK=0
fi
if [[ "$(cat "$A_VOL/planted-marker" 2>/dev/null || true)" == "marker" ]]; then
    tc_pass "planted: $A_VOL/planted-marker reads back 'marker'"
else
    tc_fail "the control marker is not on the host volume"
    PLANT_OK=0
fi
if [[ "$PLANT_OK" != "1" ]]; then
    tc_log_error "the exploit precondition is not in place — aborting (a probe now would be vacuous)"
    exit 1
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "Phase 4: Force a fresh warden (VM destroy-and-replace)"
# ══════════════════════════════════════════════════════════════
FRESH_PID=""
if ! force_fresh_vm; then
    tc_log_error "cannot guarantee a fresh warden — aborting"
    exit 1
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "Phase 5: Vector 1 probe — planted rootfs symlink"
# ══════════════════════════════════════════════════════════════
CODE_P1=$(cat <<'P1'
if [ -f /planted-marker ]; then echo P1_MARKER=present; else echo P1_MARKER=missing; fi
if [ -e /mnt/volumes ]; then echo P1_MOUNTVOL=visible; else echo P1_MOUNTVOL=absent; fi
if [ -e /init ]; then echo P1_INIT=visible; else echo P1_INIT=absent; fi
bbh=$(/bin/busybox sha256sum /bin/busybox 2>/dev/null); bbh=${bbh%% *}
echo "P1_BBH=${bbh:-none}"
P1
)
BODY1=$(gexec "$A_KEY" "$A_SF" "$CODE_P1" 30 12)
OUT1=$(jf "$BODY1" stdout)
P1_MARKER=$(kv "$OUT1" P1_MARKER)
P1_MOUNTVOL=$(kv "$OUT1" P1_MOUNTVOL)
P1_INIT=$(kv "$OUT1" P1_INIT)
P1_BBH=$(kv "$OUT1" P1_BBH)
tc_log_info "probe stdout: $(oneline "$OUT1")"
tc_log_info "probe exit_code=$(jf "$BODY1" exit_code) stderr: '$(oneline "$(jf "$BODY1" stderr)")'"

VC1=1
if [[ -z "$OUT1" ]]; then
    tc_fail "v1: the probe exec produced no stdout — the sandfs is not usable after the exploit (body: $(oneline "$BODY1"))"
fi
if [[ "$P1_MARKER" == "present" ]]; then
    tc_pass "v1: chroot root is the agent's own volume (planted marker visible)"
else
    tc_fail "v1: planted marker NOT at the chroot root (got '$P1_MARKER') — the chroot root is not the agent's volume"
    VC1=0
fi
if [[ "$P1_MOUNTVOL" == "absent" ]]; then
    tc_pass "v1: /mnt/volumes (the warden's virtio-fs share) unreachable from the chroot"
else
    tc_fail "v1: /mnt/volumes IS visible ('$P1_MOUNTVOL') — the chroot is the warden's namespace"
    VC1=0
fi
if [[ "$P1_INIT" == "absent" ]]; then
    tc_pass "v1: /init (the warden initramfs) unreachable from the chroot"
else
    tc_fail "v1: /init IS visible ('$P1_INIT') — the chroot root is the warden's initramfs"
    VC1=0
fi
if [[ "$P1_BBH" == "$PRE_BBH" ]]; then
    tc_pass "v1: chroot /bin/busybox unchanged (sha256 ${P1_BBH:0:16}...)"
else
    tc_fail "v1: chroot /bin/busybox CHANGED ($PRE_BBH -> ${P1_BBH:-none}) — the chroot runs a foreign binary"
    VC1=0
fi
if [[ "$VC1" == "1" ]]; then
    tc_log_info "vector 1: CONTAINED"
else
    tc_log_info "vector 1: ESCAPED"
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "Phase 6: Vector 2 — planted resolv.conf symlink (mount-time write)"
# ══════════════════════════════════════════════════════════════

# The warden writes {volume}/etc/resolv.conf on EVERY mount
# (inject_guest_resolv_conf). Plant the hostile entry host-side — the volume
# is a plain host directory (same technique as share-root-gate's sentinel).
mkdir -p "$A_VOL/etc"
rm -f "$A_VOL/etc/resolv.conf"
ln -sfn /bin/busybox "$A_VOL/etc/resolv.conf"
if [[ "$(readlink "$A_VOL/etc/resolv.conf" 2>/dev/null || true)" == "/bin/busybox" ]]; then
    tc_pass "planted: $A_VOL/etc/resolv.conf -> /bin/busybox"
else
    tc_fail "resolv.conf symlink plant failed ('$(readlink "$A_VOL/etc/resolv.conf" 2>/dev/null || echo '<none>')')"
    exit 1
fi

# A RE-MOUNT is what runs the injection. Force another fresh VM: it makes the
# re-mount independent of lease/unmount timing and of any state the previous
# (possibly escaped) mount left in the old warden.
FRESH_PID=""
if ! force_fresh_vm; then
    tc_log_error "cannot guarantee a fresh mount for vector 2 — aborting"
    exit 1
fi

CODE_P2=$(cat <<'P2'
echo P2_EXEC=ok
if [ -f /planted-marker ]; then echo P2_MARKER=present; else echo P2_MARKER=missing; fi
if [ -r /etc/resolv.conf ]; then
    IFS= read -r line < /etc/resolv.conf
    case "$line" in
        nameserver*) echo "P2_RESOLV=$line" ;;
        *) echo "P2_RESOLV=other len=${#line}" ;;
    esac
else
    echo "P2_RESOLV=unreadable"
fi
P2
)
BODY2=$(gexec "$A_KEY" "$A_SF" "$CODE_P2" 30 12)
OUT2=$(jf "$BODY2" stdout)
P2_EXEC=$(kv "$OUT2" P2_EXEC)
P2_MARKER=$(kv "$OUT2" P2_MARKER)
P2_RESOLV=$(kv "$OUT2" P2_RESOLV)
tc_log_info "probe stdout: $(oneline "$OUT2")"
tc_log_info "probe exit_code=$(jf "$BODY2" exit_code) stderr: '$(oneline "$(jf "$BODY2" stderr)")'"

VC2=1
if [[ "$P2_EXEC" == "ok" ]]; then
    tc_pass "v2: the agent still executes in its sandfs after the resolv.conf re-mount"
else
    tc_fail "v2: the agent can NO LONGER execute after the resolv.conf symlink + fresh mount (body: $(oneline "$BODY2")) — the mount-time write destroyed the VM's busybox"
    VC2=0
fi
if [[ "$P2_MARKER" == "present" ]]; then
    tc_pass "v2: chroot root is still the agent's own volume (planted marker visible)"
else
    tc_fail "v2: planted marker NOT at the chroot root (got '$P2_MARKER')"
    VC2=0
fi
WANT_DNS="${NETWORK_DNS%%,*}"
if [[ "$P2_RESOLV" == nameserver* && ( -z "$WANT_DNS" || "$P2_RESOLV" == *"$WANT_DNS"* ) ]]; then
    tc_pass "v2: the agent's own /etc/resolv.conf reads back the DNS content ('$P2_RESOLV') — the warden did not follow the planted link"
else
    tc_fail "v2: /etc/resolv.conf does not carry the DNS content (got '$P2_RESOLV', want nameserver ${WANT_DNS:-<dns>}) — the planted symlink was followed"
    VC2=0
fi
if [[ "$VC2" == "1" ]]; then
    tc_log_info "vector 2: CONTAINED"
else
    tc_log_info "vector 2: ESCAPED"
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "Phase 7: Vector 3 — write-through against the hot-busybox bind "
# ══════════════════════════════════════════════════════════════

# No escape needed for this one: overlay_hot_busybox binds the WARDEN's own
# /bin/busybox over the chroot's /bin/busybox on every mount. The agent (euid
# 0 inside its chroot) opening that entry for writing reaches the warden's
# inode unless the bind was remounted read-only — and that inode is the shell
# every later tenant in this VM executes.
#
# The write attempt is made by a COPY of the busybox, exec'd over the probe
# shell: a process that IS the bound inode cannot be used as the writer, since
# the kernel refuses write access to a file that is currently executing
# (ETXTBSY — verified on this kernel: an rw bind being executed still refuses
# the open with "Text file busy", which would mask the fix). After `exec
# /tmp/v3bb` no process executes the warden's inode, so the open can only be
# stopped by the bind's read-only flag — write succeeds on an unfixed warden,
# EROFS on a fixed one. The mechanism is additionally asserted directly from
# the guest's own mount table (`ro` on the <root>/bin/busybox entry).
CODE_P3=$(cat <<'P3'
/bin/busybox mkdir -p /tmp
if /bin/busybox cp /bin/busybox /tmp/v3bb && /bin/busybox chmod 755 /tmp/v3bb; then
    :
else
    echo V3_WRITE=setup-failed
    exit 0
fi
line=$(/bin/busybox grep -E ' /[^ ]+/bin/busybox ' /proc/self/mountinfo | /bin/busybox head -n 1)
# awk, not grep+cut: field 5 is the mount target, field 6 the per-mount
# options; V3_MI makes a mismatch self-explaining.
line=$(/bin/busybox awk '$5 ~ /\/bin\/busybox$/ {print; exit}' /proc/self/mountinfo)
echo "V3_MI=${line:-none}"
opts=$(/bin/busybox awk '$5 ~ /\/bin\/busybox$/ {print $6; exit}' /proc/self/mountinfo)
case ",$opts," in
    *,ro,*) echo "V3_MOUNT=ro" ;;
    *)      echo "V3_MOUNT=${opts:-absent}" ;;
esac
/bin/busybox ln -sf v3bb /tmp/sh
# argv[0] must NAME an applet (`sh`): a busybox invoked as `/tmp/v3bb` answers
# "v3bb: applet not found" (exit 127 — the applet table is keyed on the
# invoked name).
exec /tmp/sh -c 'if ( : > /bin/busybox ) 2>/tmp/v3err; then echo V3_WRITE=ok; else echo V3_WRITE=denied; fi; if [ -s /tmp/v3err ]; then echo "V3_ERR=$(/bin/busybox head -c 160 /tmp/v3err | /bin/busybox tr "\n" " ")"; fi'
P3
)
BODY3=$(gexec "$A_KEY" "$A_SF" "$CODE_P3" 30 12)
OUT3=$(jf "$BODY3" stdout)
V3_MOUNT=$(kv "$OUT3" V3_MOUNT)
V3_WRITE=$(kv "$OUT3" V3_WRITE)
V3_ERR=$(kv "$OUT3" V3_ERR)
tc_log_info "probe stdout: $(oneline "$OUT3")"
tc_log_info "probe exit_code=$(jf "$BODY3" exit_code) stderr: '$(oneline "$(jf "$BODY3" stderr)")'"

# The binary must still be the baseline one AFTER the attempted write — read
# through an exec (any tampering surfaces as a missing/other hash).
CODE_P3B=$(cat <<'P3B'
bbh=$(/bin/busybox sha256sum /bin/busybox 2>/dev/null); bbh=${bbh%% *}
echo "V3_BBH=${bbh:-none}"
P3B
)
BODY3B=$(gexec "$A_KEY" "$A_SF" "$CODE_P3B" 30 12)
OUT3B=$(jf "$BODY3B" stdout)
V3_BBH=$(kv "$OUT3B" V3_BBH)

VC3=1
if [[ "$V3_MOUNT" == "ro" ]]; then
    tc_pass "v3: the chroot's /bin/busybox bind carries 'ro' in the guest's own mountinfo"
else
    tc_fail "v3: the /bin/busybox bind is NOT read-only in the guest's mountinfo (opts='$V3_MOUNT') — a write-through reaches the warden's own shell"
    VC3=0
fi
if [[ "$V3_WRITE" == "denied" ]]; then
    tc_pass "v3: writing through the chroot's /bin/busybox was refused (${V3_ERR:-no stderr})"
else
    tc_fail "v3: the chroot's /bin/busybox is WRITABLE through the warden's bind (V3_WRITE='$V3_WRITE') — the warden's own shell is a cross-tenant payload"
    VC3=0
fi
if [[ -n "$PRE_BBH" && "$V3_BBH" == "$PRE_BBH" ]]; then
    tc_pass "v3: /bin/busybox unchanged after the write attempt (sha256 ${V3_BBH:0:16}...)"
else
    tc_fail "v3: /bin/busybox CHANGED by the write attempt ($PRE_BBH -> ${V3_BBH:-none})"
    VC3=0
fi
if [[ "$VC3" == "1" ]]; then
    tc_log_info "vector 3: CONTAINED"
else
    tc_log_info "vector 3: ESCAPED"
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "Result"
# ══════════════════════════════════════════════════════════════
V1TXT="CONTAINED"; [[ "$VC1" == "1" ]] || V1TXT="ESCAPED"
V2TXT="CONTAINED"; [[ "$VC2" == "1" ]] || V2TXT="ESCAPED"
V3TXT="CONTAINED"; [[ "$VC3" == "1" ]] || V3TXT="ESCAPED"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ "$VC1" == "1" && "$VC2" == "1" && "$VC3" == "1" ]]; then
    echo "VERDICT: CONTAINED"
else
    echo "VERDICT: ESCAPED"
fi
if [[ "$VC1" != "1" || "$VC2" != "1" || "$VC3" != "1" || "$FAIL_COUNT" -gt 0 ]]; then
    tc_log_error "warden-chroot-escape FAILED (vector1=$V1TXT, vector2=$V2TXT, vector3=$V3TXT, FAIL_COUNT=$FAIL_COUNT)"
    tc_log_info "logs rescued to /tmp/sandswap-chroot-escape-logs (per-VM warden console/serial logs under vm-console/ and vm-serial/)"
    exit 1
fi
tc_log_pass "warden-chroot-escape PASSED: every planted-symlink vector stayed inside the agent's volume and the warden's busybox stayed read-only"
exit 0
