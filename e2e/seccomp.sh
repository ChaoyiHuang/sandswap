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
# seccomp.sh — deterministic seccomp deny-list verification over the full
# stack (gateway → sandlot → warden → chrooted exec).
# The only previous e2e asserting seccomp lived in eino-agent-mcp.sh, which is
# LLM-key-gated and dropped by `run-all.sh --fast` — so the deny list had NO
# deterministic coverage. This script extracts and widens those assertions:
#   DenyList    mount / umount2 / unshare return EPERM inside the chroot
#               (deny-list fires in BOTH exec profiles)
#   CapEff      flat-mode (install profile) exec reports EXACTLY the 10-cap
#               ambient set (warden INSTALL_CAPS; CAP_SETPCAP and CAP_MKNOD
#               trimmed by owner ruling) — no CAP_SYS_ADMIN (21) /
#               CAP_SYS_PTRACE (19) / CAP_SYS_RAWIO (17) / CAP_NET_RAW (13)
#   BoundingSet the capability bounding set excludes the dangerous caps even
#               in install mode (CapBnd from /proc/self/status)
#   SUID neutrality: the FUSE passthrough stores guest-requested setuid bits
#               verbatim on the host volume (present-as-root), so the share
#               can carry hostile bits — asserted INERT via both layers:
#               pre_exec NO_NEW_PRIVS (status line) AND nosuid,nodev on the
#               guest rootfs mount (mount flags), plus the bit demonstrably
#               reaching the host file (the threat is real, the flags are the
#               containment)
# Prerequisites: built artifacts in output/, /dev/kvm, root.
# Usage: sudo bash e2e/seccomp.sh

set -euo pipefail

for p in "$HOME/.cargo/bin" "$HOME/go/bin" /usr/local/go/bin; do
    [[ -d "$p" ]] && case ":$PATH:" in *":$p:"*) ;; *) PATH="$p:$PATH" ;; esac
done
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Honor the battery's isolated root (run-all/run-matrix export it): the
# literal production defaults made this suite deploy into /var/lib/sandswap
# and its throwaway prov instance hit the production volumes tree — which the
# startup nosuid,nodev gate (correctly) refuses.
VOL_ROOT="${VOL_ROOT:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
DEPLOY_DIR="${DEPLOY_DIR:-${SANDSWAP_E2E_ROOT:-/var/lib/sandswap}}"
POOL_SIZE="${POOL_SIZE:-1}"
# shellcheck disable=SC2034  # SANDLOT_POOL is consumed by the SOURCED common.sh across the source boundary
SANDLOT_POOL="small:${POOL_SIZE}"
source "$ROOT/e2e/common.sh"

tc_use_output_binaries
tc_install_flat_template

tc_check_root
if [[ ! -e /dev/kvm ]] || [[ ! -r /dev/kvm ]]; then
    tc_log_error "/dev/kvm not available - this E2E requires KVM."
    exit 1
fi
for f in gateway sandlot sandvmm; do
    if [[ ! -f "$OUTPUT/$f" ]]; then
        tc_log_error "build artifact missing: output/$f - run 'bash build/build.sh all' first."
        exit 1
    fi
done

tc_log_section "Seccomp Deny-List E2E"

tc_check_tools curl python3 gcc
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network
tc_attach_vsockguard

tc_start_gateway
tc_start_sandlot
tc_wait_health
tc_wait_pool_ready "$POOL_SIZE"

cleanup() { tc_cleanup_default; }
trap cleanup EXIT INT TERM

tc_create_agent_and_sandfs "seccomp-a" "rootfs:v1" "flat" >/dev/null
A_KEY="$TC_API_KEY"; A_SANDFS="$TC_SANDFS_ID"
A_SANDFS_VOL="$(tc_volume_path "$A_SANDFS")" || { echo "cannot resolve volume for $A_SANDFS" >&2; exit 1; }
[[ -n "$A_KEY" && -n "$A_SANDFS" ]] || { tc_log_error "agent create failed"; exit 1; }

# upload_bin <key> <sandfs_id> <local> <workspace-relative-name> — write a
# binary into the agent's workspace through the file API (base64 payload).
# Same helper the residue suite uses; the probe is static so it runs in the
# template without any in-guest compiler.
upload_bin() {
    local key="$1" sid="$2" src="$3" remote="$4"
    python3 - "$sid" "$src" "$remote" > /tmp/sandswap-file-payload.json <<'PYEOF'
import base64, json, sys
sid, path, remote = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "rb") as f:
    data = base64.b64encode(f.read()).decode()
json.dump({"sandfs_id": sid, "action": "write", "path": remote, "data_base64": data}, sys.stdout)
PYEOF
    curl -s -m 60 -X POST "$GATEWAY_URL/agent/file" \
        -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        --data-binary @/tmp/sandswap-file-payload.json
}

# deny_check <desc> <command> — the command must produce an EPERM-flavored
# error (seccomp deny-list returns EPERM), with retries only for cold-pool
# contention (mirrors the eino-agent-mcp pattern).
deny_check() {
    local desc="$1" cmd="$2" attempt resp out
    for attempt in 1 2 3; do
        resp=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "$cmd" 15 1)
        out=$(echo "$resp" | tc_json_stdout)
        if echo "$out" | grep -qiE "Operation not permitted|Permission denied|EPERM"; then
            tc_pass "$desc: denied (EPERM)"
            return 0
        fi
        if [[ -z "$out" ]] && [[ $attempt -lt 3 ]]; then
            tc_log_warn "  attempt $attempt empty (VM contention), retrying..."
            sleep 3
            continue
        fi
        tc_fail "$desc: NOT denied (stdout: '$out')"
        return 1
    done
    tc_fail "$desc: empty after 3 attempts — seccomp property UNVERIFIED"
    return 1
}

# ── DenyList ────────────────────────────────────────────────────
# The flat template ships busybox (with mount/umount applets as symlinks, but
# no standalone unshare symlink — hence "busybox unshare").
deny_check "DenyList: mount(2)" "mount /dev/sda1 /mnt 2>&1; echo EXIT_\$?"
deny_check "DenyList: mount -t tmpfs" "mount -t tmpfs none /mnt 2>&1; echo EXIT_\$?"
deny_check "DenyList: umount2" "umount /mnt 2>&1; echo EXIT_\$?"
deny_check "DenyList: unshare(CLONE_NEWNS)" "busybox unshare -m -- /bin/echo x 2>&1; echo EXIT_\$?"
deny_check "DenyList: unshare(CLONE_NEWUSER)" "busybox unshare -U -- /bin/echo x 2>&1; echo EXIT_\$?"

# ── CapEff / CapBnd (flat mode = install profile) ──────────────
CAPS=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "cat /proc/self/status | grep -E 'CapEff|CapBnd|CapPrm'" 15 1 | tc_json_stdout)
if [[ -z "$CAPS" ]]; then
    tc_fail "CapEff: no capability output (exec failed?)"
else
    tc_pass "CapEff: capability lines readable"
    # Parse the hex masks and assert the profile. The Install profile is the
    # EXACT 10-cap set pinned in warden/src/exec.rs INSTALL_CAPS (owner
    # ruling: CAP_SETPCAP and CAP_MKNOD are trimmed). Exact equality, not
    # "contains":
    # a widened profile must fail loudly, whichever cap is added.
    python3 -c "
import re, sys
caps = dict(re.findall(r'(Cap\w+):\s+([0-9a-f]+)', '''$CAPS'''))
eff = int(caps.get('CapEff', '0'), 16)
bnd = int(caps.get('CapBnd', '0'), 16)
NAMES = {0:'CAP_CHOWN',1:'CAP_DAC_OVERRIDE',2:'CAP_DAC_READ_SEARCH',3:'CAP_FOWNER',
         4:'CAP_FSETID',5:'CAP_KILL',6:'CAP_SETGID',7:'CAP_SETUID',8:'CAP_SETPCAP',
         10:'CAP_NET_BIND_SERVICE',13:'CAP_NET_RAW',16:'CAP_SYS_MODULE',17:'CAP_SYS_RAWIO',
         18:'CAP_SYS_CHROOT',19:'CAP_SYS_PTRACE',21:'CAP_SYS_ADMIN',22:'CAP_SYS_BOOT',
         27:'CAP_MKNOD',29:'CAP_AUDIT_WRITE',31:'CAP_SETFCAP'}
expected = [0, 1, 2, 3, 4, 5, 6, 7, 10, 29]
mask = sum(1 << b for b in expected)
errs = []
if eff != mask:
    extra = [NAMES.get(b, 'cap%d' % b) for b in range(64) if eff & (1 << b) and b not in expected]
    missing = [NAMES.get(b, 'cap%d' % b) for b in expected if not (eff & (1 << b))]
    errs.append('CapEff 0x%x != install-profile 0x%x (extra: %s; missing: %s)'
                % (eff, mask, ','.join(extra) or '-', ','.join(missing) or '-'))
for name, bit in [('CAP_NET_RAW', 13), ('CAP_SYS_RAWIO', 17),
                  ('CAP_SYS_PTRACE', 19), ('CAP_SYS_ADMIN', 21),
                  ('CAP_SYS_BOOT', 22), ('CAP_SYS_MODULE', 16),
                  ('CAP_SETPCAP', 8), ('CAP_MKNOD', 27)]:
    if eff & (1 << bit):
        errs.append('%s present in CapEff' % name)
    if bnd & (1 << bit):
        errs.append('%s present in CapBnd' % name)
if errs:
    print('CAPFAIL ' + '; '.join(errs)); sys.exit(1)
print('CAPOK')
" && tc_pass "CapEff: flat-mode profile is exactly the 10-cap install set (no SETPCAP/MKNOD/SYS_ADMIN/PTRACE/RAWIO/NET_RAW in Eff or Bnd)" \
      || tc_fail "CapEff: profile wrong (see lines above)"
fi

# ── SUID neutrality on the share ────────────────────────────────
# Flat mode: the whole agent directory is bind-mounted at /mnt/rootfs, so a
# file written at / lands on the host volume via the FUSE passthrough.
tc_log_section "SUID neutrality: NNP + nosuid mount"

# 1. The guest rootfs mount carries nosuid,nodev (warden mount.rs flags).
#    The agent is chrooted INTO the rootfs bind, so inside the chroot the
#    bind (host path /mnt/rootfs) appears as the mount at " / ".
MSHF=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "grep ' / ' /proc/mounts" 15 1 | tc_json_stdout)
if echo "$MSHF" | grep -q " / "; then
    if echo "$MSHF" | grep " / " | grep -q nosuid \
        && echo "$MSHF" | grep " / " | grep -q nodev; then
        tc_pass "SUIDNeutrality: rootfs mount is nosuid,nodev (guest layer)"
    else
        tc_fail "SUIDNeutrality: rootfs mount missing nosuid/nodev: $MSHF"
    fi
else
    tc_fail "SUIDNeutrality: rootfs mount not found in /proc/mounts: $MSHF"
fi

# 2. NO_NEW_PRIVS is set on the exec'd process (execve ignores suid + file
#    capabilities for the whole child tree — the primary exec-time layer).
NNP=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "grep NoNewPrivs /proc/self/status" 15 1 | tc_json_stdout)
if echo "$NNP" | grep -q "NoNewPrivs:\s*1"; then
    tc_pass "SUIDNeutrality: NoNewPrivs=1 (exec-time layer)"
else
    tc_fail "SUIDNeutrality: NoNewPrivs not 1: $NNP"
fi

# 3. The setuid bit CAN be planted and REACHES the host file — this is the
#    threat made visible: only the two layers above (and the host-side
#    nosuid,nodev on the volumes mount) keep it inert.
PLANT=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" \
    "cp /bin/busybox /sh && chmod u+s /sh && [ -u /sh ] && echo PLANTED" 15 1 | tc_json_stdout)
if echo "$PLANT" | grep -q PLANTED; then
    tc_pass "SUIDNeutrality: setuid bit planted in-guest (threat vector is real)"
    HOST_SX="${A_SANDFS_VOL}/sh"
    if [[ -f "$HOST_SX" ]]; then
        HM=$(stat -c %a "$HOST_SX" 2>/dev/null || echo 0)
        if (( (8#$HM & 8#4000) != 0 )); then
            tc_pass "SUIDNeutrality: host volume file carries the setuid bit (mode $HM) — host mount flags are the containment"
        else
            tc_fail "SUIDNeutrality: host file mode $HM lacks setuid (passthrough behavior changed?)"
        fi
    else
        tc_fail "SUIDNeutrality: $HOST_SX not found on host"
    fi
else
    tc_fail "SUIDNeutrality: setuid plant failed: $PLANT"
fi

# 4. Exec of the planted setuid binary still works and elevates nothing:
#    capabilities and euid are identical to a plain exec (NNP + nosuid).
NEUT=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" \
    "/sh -c 'grep -e CapEff -e CapPrm /proc/self/status; id -u; echo EXECOK'" 15 1 | tc_json_stdout)
if echo "$NEUT" | grep -q EXECOK; then
    BASE=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" \
        "busybox sh -c 'grep -e CapEff -e CapPrm /proc/self/status; id -u'" 15 1 | tc_json_stdout)
    if [[ "$(echo "$NEUT" | grep -E 'CapEff|CapPrm|^0$' | tr -d ' ')" \
       == "$(echo "$BASE" | grep -E 'CapEff|CapPrm|^0$' | tr -d ' ')" ]]; then
        tc_pass "SUIDNeutrality: exec of planted setuid binary granted NOTHING (caps+euid identical to plain exec)"
    else
        tc_fail "SUIDNeutrality: setuid exec changed privileges:\n  suid: $(echo "$NEUT" | grep -E 'CapEff|CapPrm|^0$' | tr '\n' ' ')\n  base: $(echo "$BASE" | grep -E 'CapEff|CapPrm|^0$' | tr '\n' ' ')"
    fi
else
    tc_fail "SUIDNeutrality: exec of the setuid binary failed (executables on the share must still run): $NEUT"
fi

# ── Identity forgery: guest uid passthrough must be dead ──────────
# The passthrough daemon switches its effective uid/gid to the GUEST
# requester's ctx.uid/ctx.gid on create/mkdir/mknod/symlink. The dedicated
# identity model gives sandvmm NO CAP_SETUID/CAP_CHOWN, so:
#   - the normal path (guest uid 0) never switches: files land owned by the
#     daemon identity (sandlot, 985), never root;
#   - a guest that drops to a non-zero uid (the Install profile keeps
#     guest-side CAP_SETUID for dpkg) and then creates a file gets EPERM —
#     the daemon cannot become that uid on the host;
#   - guest-side "useradd -u 985" is a line in the sandbox's own /etc/passwd
#     the host never reads; the only guest→host uid channel is ctx.uid.
tc_log_section "Identity forgery: uid passthrough"

# The FUSE daemon runs as the dedicated sandvmm identity (uid 987) — NOT
# the vsockguard-trusted sandlot uid. Planted files carry 987; even a
# setuid file owned by it escalates to a uid with no warden access.
SANDVMM_UID="$(id -u sandvmm 2>/dev/null || echo 987)"
# Host sandlot uid BY NAME (identities are configurable — occupied-slot
# adoption/auto-pick in common/sh/runtime.sh; literal is only the absent-account
# fallback). The forge probe below forges THIS uid: a stale literal would test
# nothing on a host whose sandlot resolved elsewhere.
SL_UID="$(id -u sandlot 2>/dev/null || echo 985)"

# 1. Create users inside the sandbox (the literal question: "create a
#    985/986 user in warden") and write files AS them. The guest-side
#    useradd is just a passwd line the host never reads; the only
#    guest→host uid channel is the FUSE ctx.uid — and the daemon has no
#    CAP_SETUID, so both creates (uid 65534 AND uid 985) must be refused.
#    The probe must actually RUN: the shipped template links no `su` (busybox
#    compiles it, but bin/ has no symlink), so the old `su nobody -c …` lines
#    printed "su: not found", created nothing, and fell through to a PASS that
#    claimed evidence never produced. `busybox setpriv` is invoked through the
#    applet (no symlink needed) and every attempt echoes its rc so a missing
#    prober is a FAIL, not a silent pass.
FORGE=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" \
    "echo 'nobody:x:65534:65534::/:/bin/sh' >> /etc/passwd; echo \"forgedsl:x:$SL_UID:$SL_UID::/:/bin/sh\" >> /etc/passwd; \
     busybox su nobody -c 'echo a > /forged-65534' 2>&1; echo \"P65534 rc=\$?\"; \
     busybox su forgedsl -c 'echo b > /forged-sl' 2>&1; echo \"P$SL_UID rc=\$?\"" 15 1 | tc_json_stdout)
# NB: the guest is the BUSYBOX template — its setpriv applet has no --reuid
# (util-linux syntax is unavailable), and bin/ links no `su`; the applet is
# reachable as `busybox su`, which is what the probe uses. Every attempt echoes
# its rc so a probe that silently fails to run is a FAIL, not a pass.
FORGE_OK=0
PROBE_RAN=1
for u in 65534 "$SL_UID"; do
    echo "$FORGE" | grep -q "P$u rc=" || PROBE_RAN=0
done
if [[ "$PROBE_RAN" == "0" ]]; then
    tc_fail "IdentityForge: the forged-uid probe never ran (no rc marker) so the uid-passthrough question is UNTESTED. Output: $FORGE"
    FORGE_OK=1
fi
for f in forged-65534 forged-sl; do
    HF="${A_SANDFS_VOL}/$f"
    if [[ -f "$HF" ]]; then
        OW=$(stat -c %u "$HF")
        if [[ "$OW" == "$SANDVMM_UID" ]]; then
            : # landed as daemon identity — acceptable, the refusal path
        else
            tc_fail "IdentityForge: $f landed as host uid $OW (expected daemon identity $SANDVMM_UID) — uid passthrough is LIVE"
            FORGE_OK=1
        fi
    fi
done
if [[ "$FORGE_OK" == "0" ]]; then
    if echo "$FORGE" | grep -qiE "permission denied|operation not permitted|not permitted"; then
        tc_pass "IdentityForge: writes under forged guest uids (65534 and $SL_UID) refused — daemon lacks CAP_SETUID, guest users never reach host creds"
    else
        tc_fail "IdentityForge: the forged-uid attempts neither created a file nor reported a refusal — identity outcome is UNVERIFIED. Output: $FORGE"
    fi
fi

# 2. Belt: no root-owned file may exist anywhere in the agent's volume.
ROOT_OWNED=$(find "${A_SANDFS_VOL}" -uid 0 2>/dev/null | head -3)
if [[ -z "$ROOT_OWNED" ]]; then
    tc_pass "IdentityForge: no root-owned file in the volume (all daemon identity)"
else
    tc_fail "IdentityForge: root-owned files in the volume: $ROOT_OWNED"
fi

# 3. Symlink jail: a guest-planted symlink must not let the daemon resolve
#    outside the share (openat2 RESOLVE_IN_ROOT). /etc/shadow as a target
#    can only "exist" if the daemon escaped the share root.
JAIL=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" \
    "ln -s /etc/shadow /jail-l 2>&1; cat /jail-l 2>&1; echo RC=\$?" 15 1 | tc_json_stdout)
if echo "$JAIL" | grep -qE "^root:|\$6\$"; then
    tc_fail "IdentityForge: symlink escaped the share — host shadow readable: $JAIL"
else
    tc_pass "IdentityForge: guest symlink cannot resolve outside the share (RESOLVE_IN_ROOT)"
fi

# ── Identity split: sandvmm process + device isolation ───────────
tc_log_section "Identity split: sandvmm process and vsock devices"

# 1. Every sandvmm process runs as uid 987 with ZERO capabilities: the TAP
#    is pre-created/owned/pre-configured by the network provider, so the
#    VMM's attach is an owner-match TUNSETIFF and needs no capability.
#    Everything, including CAP_SYS_ADMIN and CAP_NET_ADMIN, is dropped by
#    the setpriv spawn. This is the core guarantee: the guest-data-parsing
#    daemon is NOT the warden-trusted identity and holds no privileges.
SPLIT_OK=0
SPLIT_TOTAL=0
for pid in $(pgrep -x sandvmm); do
    SPLIT_TOTAL=$((SPLIT_TOTAL + 1))
    uid="$(ps -o uid= -p "$pid" | tr -d ' ')"
    eff="$(grep '^CapEff:' "/proc/$pid/status" 2>/dev/null | awk '{print $2}')"
    # eff is 16 hex digits with leading zeros — compare numerically.
    if [[ "$uid" != "$SANDVMM_UID" || $((16#${eff:-0})) -ne 0 ]]; then
        tc_fail "IdentitySplit: sandvmm pid $pid uid=$uid CapEff=${eff:-?} (want $SANDVMM_UID / 0x0 = zero capabilities)"
        SPLIT_OK=1
    fi
done
if [[ "$SPLIT_OK" == "0" && "$SPLIT_TOTAL" -gt 0 ]]; then
    tc_pass "IdentitySplit: all $SPLIT_TOTAL sandvmm processes run uid=$SANDVMM_UID CapEff=0 (zero capabilities)"
elif [[ "$SPLIT_TOTAL" == "0" ]]; then
    tc_fail "IdentitySplit: no sandvmm processes found (stack not running?)"
fi

# 2. Device isolation probes: each vsock device reachable by exactly one
#    identity (owner 0600). setpriv drops to the target uid for the open.
if [[ "$(id -u)" == "0" ]]; then
    if setpriv --reuid="$SANDVMM_UID" --regid="$SANDVMM_UID" --clear-groups         sh -c 'exec 3<>/dev/vsock' 2>/dev/null; then
        tc_fail "IdentitySplit: sandvmm CAN open /dev/vsock (owner isolation broken)"
    else
        tc_pass "IdentitySplit: sandvmm denied /dev/vsock (owner=sandlot 0600)"
    fi
    SL_UID="$(id -u sandlot 2>/dev/null || echo 985)"
    if setpriv --reuid="$SL_UID" --regid="$SL_UID" --clear-groups         sh -c 'exec 3<>/dev/vhost-vsock' 2>/dev/null; then
        tc_fail "IdentitySplit: sandlot CAN open /dev/vhost-vsock (owner isolation broken)"
    else
        tc_pass "IdentitySplit: sandlot denied /dev/vhost-vsock (owner=sandvmm 0600)"
    fi
else
    tc_log_warn "IdentitySplit: device probes skipped (not root)"
fi

# ── Identity split: sandprov storage-plane identity ──────────────
tc_log_section "Identity split: sandprov storage identity"

# The storage plane runs as its OWN identity (sandprov, uid 983): member of
# the shared group for volume/store writes, ZERO capabilities, no KVM, no
# vsock. The merged e2e topology runs prov in-process inside the privileged
# exec,prov sandlot, so the dedicated identity is asserted here with a
# THROWAWAY prov instance in the exact production shape — setpriv to 983,
# every capability dropped, only the shared group added — and the gateway's
# prov-role stream gate must ACCEPT it (health provisioners +1). This is the
# live-form assertion the merged suite cannot make anywhere else.
health_provisioners() {
    # provisioners is an ops signal and lives on the HUMAN listener's
    # /health (HUMAN_URL) — the agent-side /health stays minimal by design.
    curl -s "$HUMAN_URL/health" 2>/dev/null | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("provisioners", 0))
except Exception: print(0)'
}

if [[ "$(id -u)" == "0" ]]; then
    PROV_UID="$(id -u sandprov 2>/dev/null || echo 983)"
    PROV_TMP="$(mktemp -d /tmp/sandswap-prov-identity.XXXXXX)"
    # mktemp -d lands 0700 root — the sandprov uid must TRAVERSE the dir to
    # reach the 0644 config/certs staged inside.
    chmod 755 "$PROV_TMP"

    # 1. vsock device probes (no live instance needed): both devices are
    #    owner-isolated 0600 (vhost-vsock → sandvmm, vsock → sandlot) and
    #    the storage identity holds neither owner nor any granting group.
    for dev in /dev/vhost-vsock /dev/vsock; do
        if setpriv --reuid="$PROV_UID" --regid="$PROV_UID" --clear-groups \
                --bounding-set=-all -- sh -c "exec 3<>$dev" 2>/dev/null; then
            tc_fail "IdentityProv: sandprov CAN open $dev (device isolation broken)"
        else
            tc_pass "IdentityProv: sandprov denied $dev (owner-isolated 0600)"
        fi
    done

    # 2. Throwaway prov instance. Pre-stage everything it must read: the
    #    role lock (root:sandlot 0660 — the shared group IS the sandlot
    #    group), a readable copy of the stream certs, an empty private
    #    flat-template dir, the template store (read-only refs scan), and —
    #    this probe is the ONE e2e spawner running as SANDPROV, which the
    #    shared $DEPLOY_DIR/volume-seed (owner = SS_PROV_USER, default
    #    sandlot) is not readable by — a probe-PRIVATE seed. The value is
    #    irrelevant to a throwaway instance; mutating the shared seed's
    #    owner here would break every later suite that reads it as sandlot
    #    (an EACCES then kills this probe mid-suite).
    SL_GID="$(id -g sandlot 2>/dev/null || echo 985)"
    if [[ ! -e /run/sandswap/sandlot.role ]]; then
        install -m 660 -g "$SL_GID" /dev/null /run/sandswap/sandlot.role 2>/dev/null || : > /run/sandswap/sandlot.role
    fi
    chgrp "$SL_GID" /run/sandswap/sandlot.role 2>/dev/null || true
    install -d -m 755 "$(dirname "$VOL_ROOT")/templates" 2>/dev/null || true
    mkdir -p "$PROV_TMP/certs" "$PROV_TMP/flat"
    # The stream binds node_id == certificate CN (per-node pairs), and the
    # generated config resolves its pair under this probe's CERT_DIR. Mint
    # the probe's OWN pair (not the generic test-node-1 one), then copy it
    # under the name the config will look for.
    PROV_CERT="$(tc_node_cert "seccomp-prov-probe" prov)"
    cp "$CERT_DIR/ca.crt" "$PROV_CERT.crt" "$PROV_CERT.key" "$PROV_TMP/certs/" 2>/dev/null || true
    PROV_BEFORE="$(health_provisioners)"
    # Mint + scope through the shared primitive (owner = the prov identity
    # running this probe, mode 0600).
    ss_ensure_volume_seed "$PROV_TMP/volume-seed" "$PROV_UID" 0600
    TC_NODE_ID="seccomp-prov-probe" \
    TC_SANDLOT_ROLES="prov" \
    TC_FLAT_TEMPLATES="$PROV_TMP/flat" \
    TC_VOLUME_SEED_FILE="$PROV_TMP/volume-seed" \
    NETWORK_BACKEND="none" \
    CERT_DIR="$PROV_TMP/certs" \
        tc_gen_sandlot_config "$PROV_TMP/sandlot-prov.yaml"
    # tc_gen_sandlot_config re-runs tc_node_cert, which scopes every
    # sandlot-*.key to the sandlot identity at 0600. That is right for a
    # normal node and wrong for this probe: it runs as SANDPROV. Re-apply
    # the probe's readable mode AFTER the config generation.
    chmod 644 "$PROV_TMP"/certs/* 2>/dev/null || true
    chmod 644 "$PROV_TMP/sandlot-prov.yaml"

    LOCK_GID="$(stat -c %g /run/sandswap/sandlot.role 2>/dev/null || echo "$SL_GID")"
    # The template store's refs/ is 2750 in the metadata group (sandtmpl):
    # --groups REPLACES the supplementary set, so the probe must carry the
    # group explicitly or it cannot read refs (the store scan dies EACCES).
    PROV_GROUPS="$LOCK_GID"
    if TPL_GID="$(getent group "${SS_GROUP_TPL:-sandtmpl}" | cut -d: -f3)" && [[ -n "$TPL_GID" ]]; then
        PROV_GROUPS="$PROV_GROUPS,$TPL_GID"
    fi
    # shellcheck disable=SC2086
    setpriv --reuid="$PROV_UID" --regid="$PROV_UID" \
        --groups="$PROV_GROUPS" \
        --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
        "$OUTPUT/sandlot" -config "$PROV_TMP/sandlot-prov.yaml" \
        -allow-colocated-instances \
        -allow-insecure-volumes -allow-missing-vsockguard \
        >"$PROV_TMP/prov.log" 2>&1 &
    PROV_PID=$!

    sleep 2
    PROV_LIVE=1
    if ! kill -0 "$PROV_PID" 2>/dev/null; then
        tc_fail "IdentityProv: throwaway prov instance died at spawn: $(tail -5 "$PROV_TMP/prov.log" 2>/dev/null | tr '\n' ' ')"
        PROV_LIVE=0
    fi
    if [[ "$PROV_LIVE" == "1" ]]; then
        p_uid="$(ps -o uid= -p "$PROV_PID" | tr -d ' ')"
        p_eff="$(grep '^CapEff:' "/proc/$PROV_PID/status" 2>/dev/null | awk '{print $2}')"
        if [[ "$p_uid" == "$PROV_UID" && $((16#${p_eff:-f})) -eq 0 ]]; then
            tc_pass "IdentityProv: storage-plane process runs uid=$PROV_UID CapEff=0 (zero caps, shared group only)"
        else
            tc_fail "IdentityProv: prov identity wrong: uid=$p_uid CapEff=${p_eff:-?} (want $PROV_UID / 0)"
            PROV_LIVE=0
        fi
    fi
    if [[ "$PROV_LIVE" == "1" ]]; then
        PROV_ACCEPTED=0
        PROV_NOW=""
        for _ in $(seq 1 15); do
            PROV_NOW="$(health_provisioners)"
            if [[ "${PROV_NOW:-0}" -ge $((PROV_BEFORE + 1)) ]]; then
                PROV_ACCEPTED=1
                break
            fi
            sleep 1
        done
        if [[ "$PROV_ACCEPTED" == "1" ]]; then
            tc_pass "IdentityProv: gateway prov-role gate ACCEPTED the uid=$PROV_UID zero-cap connection (provisioners $PROV_BEFORE → $PROV_NOW)"
        else
            tc_fail "IdentityProv: gateway did NOT accept the prov connection (provisioners $PROV_BEFORE → ${PROV_NOW:-?}): $(tail -5 "$PROV_TMP/prov.log" 2>/dev/null | tr '\n' ' ')"
        fi
    fi

    # 3. Teardown: the throwaway dies cleanly and frees its stream slot;
    #    the post-phase health probe below proves no collateral damage.
    kill "$PROV_PID" 2>/dev/null || true
    wait "$PROV_PID" 2>/dev/null || true
    rm -rf "$PROV_TMP"
else
    tc_log_warn "IdentityProv: skipped (requires root)"
fi

# The VM must still be healthy after the denied syscalls.
R=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "echo seccomp-alive" 15 1)
if echo "$R" | tc_json_stdout | grep -q "seccomp-alive"; then
    tc_pass "Post-deny: VM healthy after denied syscalls"
else
    tc_fail "Post-deny: VM unhealthy after denied syscalls"
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "Guest kernel hardening: user namespaces closed + new seccomp classes"
# ══════════════════════════════════════════════════════════════
# The release kernel compiles CONFIG_USER_NS out; the warden also writes
# /proc/sys/user/max_user_namespaces=0 at boot for dev/older kernels. Either
# way clone3(CLONE_NEWUSER) must not succeed. The six raw syscalls below are
# the class-completeness additions to the deny list; each must answer EPERM
# (the arguments are deliberately invalid, so EPERM proves the filter ran
# before the kernel handler).
HARDENING_PROBE=/tmp/sandswap-hardening-seccomp-probe
gcc -static -O2 -o "$HARDENING_PROBE" "$ROOT/e2e/hardening-seccomp-probe.c" \
    || { tc_fail "hardening probe: gcc -static failed"; exit 1; }
UP=""
for _try in $(seq 1 10); do
    UP=$(upload_bin "$A_KEY" "$A_SANDFS" "$HARDENING_PROBE" hardening_seccomp_probe)
    [[ "$UP" == *'"ok":true'* ]] && break
    sleep 1
done
if [[ "$UP" == *'"ok":true'* ]]; then
    tc_pass "hardening probe: static helper uploaded through the file API"
else
    tc_fail "hardening probe: upload failed: $UP"
fi
tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "chmod +x ./hardening_seccomp_probe" 15 1 >/dev/null || true
PROBE_RESP=$(tc_gw_exec_raw "$A_KEY" "$A_SANDFS" "./hardening_seccomp_probe" 30 1)
PROBE_OUT=$(echo "$PROBE_RESP" | tc_json_stdout)
if [[ -z "$PROBE_OUT" ]]; then
    tc_fail "hardening probe: no output (binary did not run)"
else
    if echo "$PROBE_OUT" | grep -qE '^USERNSSYSCTL:(0|ABSENT)$'; then
        tc_pass "hardening probe: user namespaces closed (max_user_namespaces=0 or CONFIG_USER_NS=n)"
    else
        tc_fail "hardening probe: user-namespace state unexpected: $(echo "$PROBE_OUT" | grep USERNSSYSCTL || echo '<missing>')"
    fi
    if echo "$PROBE_OUT" | grep -q '^OK:clone3_newuser:'; then
        tc_pass "hardening probe: clone3(CLONE_NEWUSER) refused"
    else
        tc_fail "hardening probe: clone3(CLONE_NEWUSER) was NOT refused: $(echo "$PROBE_OUT" | grep clone3_newuser || echo '<missing>')"
    fi
    for sc in mount_setattr statmount listmount pidfd_open pidfd_send_signal ioprio_set modify_ldt; do
        if echo "$PROBE_OUT" | grep -q "^OK:${sc}:EPERM$"; then
            tc_pass "hardening probe: ${sc} denied (EPERM)"
        else
            tc_fail "hardening probe: ${sc} NOT denied: $(echo "$PROBE_OUT" | grep "$sc" || echo '<missing>')"
        fi
    done
    if echo "$PROBE_OUT" | grep -q '^OK:vsock_socket:EPERM$'; then
        tc_pass "hardening probe: socket(AF_VSOCK) denied (EPERM)"
    else
        tc_fail "hardening probe: socket(AF_VSOCK) NOT denied: $(echo "$PROBE_OUT" | grep vsock_socket || echo '<missing>')"
    fi
    if echo "$PROBE_OUT" | grep -q '^OK:inet_socket:allowed$'; then
        tc_pass "hardening probe: socket(AF_INET) still allowed"
    else
        tc_fail "hardening probe: socket(AF_INET) NOT allowed: $(echo "$PROBE_OUT" | grep inet_socket || echo '<missing>')"
    fi
    if echo "$PROBE_OUT" | grep -q '^OK:fdhygiene:only-stdio$'; then
        tc_pass "hardening probe: no non-CLOEXEC descriptors inherited"
    else
        tc_fail "hardening probe: descriptor leak: $(echo "$PROBE_OUT" | grep fdhygiene || echo '<missing>')"
    fi
    if echo "$PROBE_OUT" | grep -q '^HARDENING_PROBE:PASS$'; then
        tc_pass "hardening probe: all checks passed"
    else
        tc_fail "hardening probe: FAIL summary: $PROBE_OUT"
    fi
fi

# ══════════════════════════════════════════════════════════════
tc_log_section "Seccomp E2E Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo "[FAIL] Seccomp E2E FAILED"
    exit 1
fi
echo "[OK] Seccomp E2E PASSED"
exit 0
