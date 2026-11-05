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
# cross-tenant-residue.sh — cross-agent residue channel test (in-guest
# occupant adversary): kernel objects AND tmpfs/proc/dev state that could
# outlive the rule-A process sweep across a real agent switch.
#
# One microVM (pool forced to 1) serves agent A, then agent B. The channels
# this suite pins:
#
#   - SysV message queue / shared memory segment (guest IPC namespace)
#   - POSIX mqueue object (addressable by name without any mount; the exec
#     profile denies the whole mq_* family, so this leg asserts DENIAL)
#   - persistent uid-0 user keyring (user-namespace scope)
#   - /dev/shm tmpfs file (shared-memory FILES: tmpfs pages are only
#     released by the unmount — drop_caches cannot evict them)
#   - masked /proc layout: kcore/kallsyms/keys read empty (the /dev/null
#     covers) and /proc is read-only (drop_caches/cgroup knobs unwritable)
#   - minimal /dev: mem/kmem/port are never created
#
# GREEN contract (post-fix warden):
#   A plants SysV msg/shm + a /dev/shm file successfully (intra-lease use is
#   legal); A's mqueue creation and keyring plant are DENIED (seccomp: the
#   whole mq_* family, add_key/request_key/keyctl). After the agent switch B
#   finds NOTHING: msg/shm gone (unmount-time SysV sweep; no mqueue sweep is
#   needed — mqueues can never be created), the /dev/shm file gone (fresh
#   tmpfs), keyctl denied, and the masked-proc / minimal-dev invariants hold.
# RED contract (pre-fix warden): A's keyring plant succeeds and B reads A's
# planted objects — the assertions below fail loudly.
#
# Requires the Ubuntu rootfs template (python3 for raw syscalls via ctypes).
# Companion suite: e2e/warden-hostile.sh covers the OTHER adversary — a
# host-side transport peer injecting hostile frames (kept separate: different
# adversary model, different fixture — probe-driven bare VM vs full-stack
# agent switch).
# Usage: sudo bash e2e/cross-tenant-residue.sh

set -euo pipefail

for p in "$HOME/.cargo/bin" "$HOME/go/bin" /usr/local/go/bin; do
    [[ -d "$p" ]] && case ":$PATH:" in *":$p:"*) ;; *) PATH="$p:$PATH" ;; esac
done
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Force a single microVM so the A→B transition is an agent switch (hot-swap),
# not a second cold VM. (Consumed by tc_start_sandlot in common.sh.)
# shellcheck disable=SC2034
SANDLOT_POOL="medium:1"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
ROOTFS_UBUNTU="${ROOTFS_UBUNTU:-$OUTPUT/rootfs-ubuntu}"

cleanup() {
    # Rescue logs before the default cleanup deletes $LOG_DIR and /run/sandswap
    # (the warden console lives in the per-VM console.log (hvc0), NOT in
    # sandlot's stdout; serial.log carries earlyprintk).
    rm -rf /tmp/sandswap-residue-logs
    cp -a "$LOG_DIR" /tmp/sandswap-residue-logs 2>/dev/null || true
    mkdir -p /tmp/sandswap-residue-logs/vm-console /tmp/sandswap-residue-logs/vm-serial
    for f in /run/sandswap/vm/*/console.log; do
        [[ -f "$f" ]] && cp -a "$f" "/tmp/sandswap-residue-logs/vm-console/$(basename "$(dirname "$f")")-console.log"
    done
    for f in /run/sandswap/vm/*/serial.log; do
        [[ -f "$f" ]] && cp -a "$f" "/tmp/sandswap-residue-logs/vm-serial/$(basename "$(dirname "$f")")-serial.log"
    done
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

# exec_code <key> <sandfs_id> <python-file> — runs the python source inside
# the agent sandbox (heredoc-embedded; the execute API has no file-attachment
# field) and prints the command's stdout.
exec_code() {
    local key="$1" sid="$2" pyfile="$3"
    local payload=/tmp/sandswap-residue-payload.json
    python3 - "$sid" "$pyfile" "$payload" <<'PYEOF'
import json, sys
sid, pyfile, out = sys.argv[1:4]
with open(pyfile) as f:
    src = f.read()
code = "cat > /workspace/plant.py <<'SANDEOF'\n" + src + "\nSANDEOF\npython3 /workspace/plant.py"
with open(out, "w") as f:
    json.dump({"sandfs_id": sid, "code": code, "language": "shell"}, f)
PYEOF
    local out
    # Single-VM pool: the previous tenant's lease/clean can make the next
    # exec a designed retryable refusal. Retry until the probe prints.
    for _try in $(seq 1 15); do
        curl -s -m 75 -X POST "$GATEWAY_URL/agent/execute" \
            -H "Authorization: Bearer $key" \
            -H "Content-Type: application/json" \
            -d @"$payload" > /tmp/sandswap-residue-resp.json
        out=$(python3 -c 'import json;print(json.load(open("/tmp/sandswap-residue-resp.json")).get("stdout",""),end="")' 2>/dev/null || true)
        [[ -n "$out" ]] && { printf '%s' "$out"; return 0; }
        sleep 1
    done
    return 0
}

# upload_bin <key> <sandfs_id> <local-file> <workspace-name> — write a binary
# into the guest through the file API (base64). The static mqueue-seccomp-probe helper is
# uploaded this way: the template's Python cannot call mq_open correctly.
upload_bin() {
    local key="$1" sid="$2" src="$3" remote="$4"
    python3 - "$sid" "$src" "$remote" > /tmp/sandswap-file-payload.json <<'PYEOF'
import base64, json, sys
sid, path, remote = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "rb") as f:
    data = base64.b64encode(f.read()).decode()
json.dump({"sandfs_id": sid, "action": "write", "path": remote, "data_base64": data}, sys.stdout)
PYEOF
    curl -s -m 30 -X POST "$GATEWAY_URL/agent/file" \
        -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        --data-binary @/tmp/sandswap-file-payload.json
}

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight"
# ══════════════════════════════════════════════════════════════════
tc_check_root
tc_preflight_standard python3
tc_check_artifacts gateway sandlot sandvmm vmlinux.bin initramfs.cpio.gz
[[ -d "$ROOTFS_UBUNTU" ]] || { log_error "missing $ROOTFS_UBUNTU (bash build/build.sh build-ubuntu-rootfs)"; exit 1; }
tc_check_kvm
tc_ensure_dev_nodes
[[ "$NETWORK_BACKEND" == "bridge" ]] && tc_setup_host_network

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Deploy (Ubuntu template — needs python3 in-guest)"
# ══════════════════════════════════════════════════════════════════
tc_clean_environment
tc_deploy_artifacts
rm -rf "$DEPLOY_DIR/flat-templates/rootfs/v1"
mkdir -p "$DEPLOY_DIR/flat-templates/rootfs/v1"
cp -a "$ROOTFS_UBUNTU/." "$DEPLOY_DIR/flat-templates/rootfs/v1/"
# Group grant + contract check: the seed identity (sandprov) is NOT root, and
# the ubuntu tree carries 0640 root:root files (etc/.pwd.lock) a root-owned copy
# cannot be read from — the sandfs create then fails EACCES at consume time.
tc_conform_template_tree "$DEPLOY_DIR/flat-templates"
[[ -x "$DEPLOY_DIR/flat-templates/rootfs/v1/bin/python3" ]] || { log_error "ubuntu template lacks python3"; exit 1; }
tc_gen_certs

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Stack up (one VM)"
# ══════════════════════════════════════════════════════════════════
tc_attach_vsockguard
tc_start_gateway
tc_start_sandlot
tc_wait_health
# SANDLOT_POOL is medium:1 (single VM by design) — pass the target explicitly;
# the bare call defaults to the 3-VM standard pool.
tc_wait_pool_ready 1
# Same-VM control: SANDLOT_POOL is medium:1, so the A→B transition is a
# hot-swap on ONE VM. Record its sandvmm pid now — if a recycle replaced the VM
# between A and B, every "GONE" assertion below would pass WITHOUT the
# switch-time sweep ever running.
VM_PID_BEFORE=$(tc_run_vm_pids | head -n1)
[[ -n "$VM_PID_BEFORE" ]] || { log_error "no live sandvmm pid in /run/sandswap-state/default/*/state.json — cannot prove the A→B switch reused one VM"; exit 1; }


RESP_A=$(tc_create_agent_and_sandfs "residue-A" "" flat || echo '{"error":"create failed"}')
RESP_B=$(tc_create_agent_and_sandfs "residue-B" "" flat || echo '{"error":"create failed"}')
KEY_A=$(json_val "$RESP_A" "api_key")
KEY_B=$(json_val "$RESP_B" "api_key")
SANDFS_A=$(json_val "$RESP_A" "sandfs_id")
SANDFS_B=$(json_val "$RESP_B" "sandfs_id")
[[ -n "$KEY_A" && -n "$KEY_B" ]] || { log_error "agent creation failed"; exit 1; }
pass "agents A/B created (single-VM pool, flat ubuntu template)"

# Build the static mqueue-seccomp-probe helper and upload it to both guests. The guest
# template's Python is statically linked and its mq_open path returns ENOENT;
# the black-box C probe is the working channel. The mqueue leg is strict, so a
# helper/toolchain failure fails the suite rather than silently skipping it.
gcc -static -O2 -o /tmp/sandswap-mqueue-seccomp-probe "$ROOT/e2e/mqueue-seccomp-probe.c" \
    || { log_error "gcc -static failed (needed for the mqueue residue probe)"; exit 1; }
for pair in "A:$KEY_A:$SANDFS_A" "B:$KEY_B:$SANDFS_B"; do
    label=${pair%%:*}; rest=${pair#*:}; key=${rest%%:*}; sid=${rest#*:}
    up=""
    # A single-VM pool: the second upload can race the first tenant's lease
    # (NO_AVAILABLE_SANDBOX / SANDBOX_CLEANING). Retry the designed refusals.
    for _try in $(seq 1 15); do
        up=$(upload_bin "$key" "$sid" /tmp/sandswap-mqueue-seccomp-probe mqueue_seccomp_probe)
        [[ "$up" == *'"ok":true'* ]] && break
        sleep 1
    done
    [[ "$up" == *'"ok":true'* ]] || { log_error "mqueue-seccomp-probe upload to $label failed: $up"; exit 1; }
    sleep 1
done
pass "mqueue-seccomp-probe helper uploaded to A and B (static glibc mqueue probe)"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Agent A plants kernel-object residue"
# ══════════════════════════════════════════════════════════════════
cat > /tmp/sandswap-residue-plant.py <<'PYEOF'
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
KEY = 0x51515151
res = []
# SysV message queue
q = libc.msgget(KEY, 0o1000 | 0o666)
if q < 0:
    res.append("msg:CREATE_ERR:%d" % ctypes.get_errno())
else:
    class MsgBuf(ctypes.Structure):
        _fields_ = [("mtype", ctypes.c_long), ("text", ctypes.c_char * 64)]
    mb = MsgBuf()
    mb.mtype = 1
    mb.text = b"RESIDUE-MSG-SECRET"
    res.append("msg:OK" if libc.msgsnd(q, ctypes.byref(mb), 20, 0) == 0
               else "msg:SEND_ERR:%d" % ctypes.get_errno())
# SysV shared memory segment
sh = libc.shmget(KEY, 4096, 0o1000 | 0o666)
if sh < 0:
    res.append("shm:CREATE_ERR:%d" % ctypes.get_errno())
else:
    libc.shmat.restype = ctypes.c_void_p
    addr = libc.shmat(sh, None, 0)
    if not addr:
        res.append("shm:ATTACH_ERR:%d" % ctypes.get_errno())
    else:
        ctypes.memmove(addr, b"RESIDUE-SHM-SECRET\x00", 19)
        libc.shmdt(ctypes.c_void_p(addr))
        res.append("shm:OK")
# POSIX mqueue: the seccomp profile denies the WHOLE family (owner ruling),
# so the helper's mq_open must fail EPERM. Success is a failure.
import os, subprocess
os.chmod("/workspace/mqueue_seccomp_probe", 0o755)
_r = subprocess.run(["/workspace/mqueue_seccomp_probe", "send", "/sandswap_residue",
                     "RESIDUE-MQ-SECRET"], capture_output=True, text=True)
_o = (_r.stdout + _r.stderr).strip()
if _r.returncode == 0:
    res.append("mq:OPENED")
elif "Operation not permitted" in _o or "EPERM" in _o:
    res.append("mq:EPERM")
else:
    res.append("mq:OTHER_ERR:%d:%s" % (_r.returncode, _o[:120]))
# /dev/shm tmpfs file: POSIX shared-memory FILES are tmpfs pages — no cache
# drop evicts them; only the unmount releases them (and the next attach
# mounts a fresh tmpfs).
with open("/dev/shm/residue-shm-file", "w") as _f:
    _f.write("RESIDUE-SHM-FILE-SECRET")
res.append("shmfile:OK")
# kernel keyring: add_key(248) into the persistent uid-0 user keyring
rc = libc.syscall(248, ctypes.c_char_p(b"user"), ctypes.c_char_p(b"leak"),
                  ctypes.c_char_p(b"RESIDUE-KEY-SECRET"), 18, ctypes.c_int(-4))
res.append("key:EPERM" if rc == -1 else "key:PLANTED")
# PID-1 retune guard: the agent and PID 1 share uid 0, so a same-owner
# prlimit64/setpriority targeting PID 1 would otherwise work with no
# capability (lowering RLIMIT_CPU kills the warden). A READ-ONLY prlimit64
# query against PID 1 must already be EPERM; the filter checks args[0] == 1.
class _Rlim(ctypes.Structure):
    _fields_ = [("cur", ctypes.c_ulong), ("max", ctypes.c_ulong)]
_rl = _Rlim()
_rc = libc.syscall(302, 1, 7, None, ctypes.byref(_rl))  # prlimit64(PID 1, RLIMIT_NOFILE, NULL, &old)
_e = ctypes.get_errno()
res.append("pid1prlimit:EPERM" if _rc == -1 and _e == 1
           else "pid1prlimit:NOT_DENIED:%d:%d" % (_rc, _e))
# TCP dead-state residue: a loopback self-connection leaves TIME_WAIT rows
# in /proc/net/tcp that outlive this process.
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
c = socket.socket(); c.connect(s.getsockname()); a, _ = s.accept()
c.close(); a.close(); s.close()
import time as _t; _t.sleep(0.2)
_tw = sum(1 for l in open("/proc/net/tcp").read().splitlines()[1:]
          if l.split()[3] == "06")
res.append("tcp:PLANTED:%d" % _tw)
print("PLANT " + " ".join(res))
PYEOF

OUT_A=$(exec_code "$KEY_A" "$SANDFS_A" /tmp/sandswap-residue-plant.py)
log_info "A plant output: $OUT_A"
[[ "$OUT_A" == *"msg:OK"* ]] || { log_error "SysV msg plant failed (intra-lease IPC must stay usable): $OUT_A"; exit 1; }
[[ "$OUT_A" == *"shm:OK"* ]] || { log_error "SysV shm plant failed: $OUT_A"; exit 1; }
# Premise for the tcp:CLEAN probe below: A must have planted at least one
# TIME_WAIT row — with 0 planted, "tcp:CLEAN" at B passes without any sweep.
TW_PLANTED=$(echo "$OUT_A" | grep -oE 'tcp:PLANTED:[0-9]+' | head -1 | cut -d: -f3 || true)
[[ "${TW_PLANTED:-0}" -gt 0 ]] || { log_error "A planted no TIME_WAIT rows (plant output: $OUT_A) — the tcp:CLEAN assertion is vacuous"; exit 1; }
pass "A planted ${TW_PLANTED} TIME_WAIT row(s) — the tcp:CLEAN probe is discriminating"
# The mqueue leg is STRICT in the OTHER direction now: the owner ruled that
# agents have no POSIX-mqueue use case (background IPC is user-space), so the
# seccomp profile denies the whole family. The plant must be DENIED; an
# OPENED queue means the denial is missing and the cross-tenant channel is
# back.
if [[ "$OUT_A" == *"mq:EPERM"* ]]; then
    pass "A's POSIX mqueue creation DENIED by seccomp (whole family blocked)"
else
    log_error "A could OPEN a POSIX mqueue ($OUT_A) — the seccomp mqueue denial is missing"
    exit 1
fi
if [[ "$OUT_A" == *"pid1prlimit:EPERM"* ]]; then
    pass "prlimit64 targeting PID 1 is denied (EPERM) — the same-owner retune channel is closed"
else
    log_error "prlimit64 targeting PID 1 was NOT denied ($OUT_A) — the seccomp PID-1 guard is missing"
    exit 1
fi
if [[ "$OUT_A" == *"key:EPERM"* ]]; then
    pass "A's keyring plant DENIED by seccomp (add_key denied)"
else
    log_error "A's keyring plant SUCCEEDED — keyctl/add_key not denied by the exec profile"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Switch to agent B (same VM) and probe"
# ══════════════════════════════════════════════════════════════════
# Let A's sticky lease expire (default 100ms) so B's exec hot-swaps the VM.
sleep 1
cat > /tmp/sandswap-residue-probe.py <<'PYEOF'
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
KEY = 0x51515151
out = []
# SysV message queue
q = libc.msgget(KEY, 0o666)
if q < 0:
    out.append("msg:GONE")
else:
    class MsgBuf(ctypes.Structure):
        _fields_ = [("mtype", ctypes.c_long), ("text", ctypes.c_char * 64)]
    mb = MsgBuf()
    n = libc.msgrcv(q, ctypes.byref(mb), 64, 0, 0)
    out.append("msg:LEAK:" + (mb.text.split(b"\x00")[0].decode() if n >= 0 else "rcv-err"))
# SysV shared memory segment
sh = libc.shmget(KEY, 0, 0o666)
if sh < 0:
    out.append("shm:GONE")
else:
    libc.shmat.restype = ctypes.c_void_p
    addr = libc.shmat(sh, None, 0)
    out.append("shm:LEAK:" + (ctypes.string_at(addr).split(b"\x00")[0].decode() if addr else "at-err"))
    if addr:
        libc.shmdt(ctypes.c_void_p(addr))
# POSIX mqueue (see the plant block): opening ANY queue must be EPERM.
import os, subprocess
os.chmod("/workspace/mqueue_seccomp_probe", 0o755)
_r2 = subprocess.run(["/workspace/mqueue_seccomp_probe", "recv", "/sandswap_residue"],
                     capture_output=True, text=True)
_o2 = (_r2.stdout + _r2.stderr).strip()
if _r2.returncode != 0 and ("Operation not permitted" in _o2 or "EPERM" in _o2):
    out.append("mq:EPERM")
elif _r2.returncode == 0:
    out.append("mq:OPENED")
else:
    out.append("mq:OTHER_ERR:%d:%s" % (_r2.returncode, _o2[:120]))
# keyctl(250) KEYCTL_READ(11) on the user keyring (-4)
rc = libc.syscall(250, ctypes.c_long(11), ctypes.c_int(-4))
out.append(("key:EPERM" if rc == -1 and ctypes.get_errno() == 1
            else "key:PRESENT" if rc > 0 else "key:EMPTY:rc=%d:errno=%d" % (rc, ctypes.get_errno())))
# /proc/kmsg masking: the /dev/null bind gives EOF even with O_NONBLOCK;
# an unmasked-but-empty kernel log raises BlockingIOError instead.
import os
try:
    fd = os.open("/proc/kmsg", os.O_RDONLY | os.O_NONBLOCK)
    out.append("kmsg:MASKED" if os.read(fd, 16) == b"" else "kmsg:READABLE")
    os.close(fd)
except BlockingIOError:
    out.append("kmsg:UNMASKED")
except OSError as e:
    out.append("kmsg:ERR:%d" % e.errno)

# /dev/shm file: must be gone — B sees a FRESH tmpfs (only the unmount
# releases tmpfs pages; a cache drop could not have).
try:
    with open("/dev/shm/residue-shm-file") as _f:
        out.append("shmfile:LEAK:" + _f.read(32))
except FileNotFoundError:
    out.append("shmfile:GONE")

# Masked /proc entries: each dangerous entry is covered by a /dev/null bind,
# so a read returns EMPTY (not an error, not content). Kernel-state files are
# masked when the kernel ships them and simply absent otherwise.
def _masked(name):
    try:
        with open("/proc/" + name, "rb") as _f:
            return "MASKED" if _f.read(16) == b"" else "READABLE"
    except FileNotFoundError:
        return "ABSENT"
    except OSError as _e:
        return "ERR:%d" % _e.errno
for _name in ("kcore", "kallsyms", "keys"):
    out.append("%s:%s" % (_name, _masked(_name)))
for _name in ("slabinfo", "kpagecount", "kpageflags", "pagetypeinfo", "buddyinfo", "zoneinfo"):
    out.append("%s:%s" % (_name, _masked(_name)))

# /proc is remounted read-only: a sysctl write (drop_caches) must fail.
try:
    with open("/proc/sys/vm/drop_caches", "w") as _f:
        _f.write("1\n")
    out.append("proc:WRITABLE")
except OSError:
    out.append("proc:RO")

# The same read-only posture must cover the other host-kernel write knobs a
# tenant could use to influence the next tenant or the host: core_pattern
# (pipe-to-program on crash), PID-1 oom_score_adj, and cgroup.kill (absent
# because the agent namespace carries no cgroupfs; if present it must be RO).
for _path, _key in (("/proc/sys/kernel/core_pattern", "core_pattern"),
                    ("/proc/1/oom_score_adj", "oom_score_adj"),
                    ("/sys/fs/cgroup/cgroup.kill", "cgroup_kill")):
    try:
        with open(_path, "w") as _f:
            _f.write("0\n")
        out.append("%s:WRITABLE" % _key)
    except FileNotFoundError:
        out.append("%s:ABSENT" % _key)
    except OSError:
        out.append("%s:RO" % _key)

# Minimal /dev: the dangerous device nodes are never created.
out.append("devmem:ABSENT" if all(not os.path.exists("/dev/" + _n)
                                  for _n in ("mem", "kmem", "port"))
           else "devmem:PRESENT")
# Warden vsock port reachability FROM INSIDE THE GUEST: the raw protocol must
# be unreachable. A connect() to the local-alias CID (1) needs a vsock
# loopback transport the kernel must not ship; a connect() to another VM's
# CID must be dropped by vhost-vsock on the host. Any connect that SUCCEEDS
# means the unauthenticated warden protocol is guest-dialable — including the
# v1 empty-identity warm-op compat path. Bounded at 0.4s/target.
import socket as _vs
try:
    _connected = []
    for _cid in (1, 3, 4, 5, 6):
        _s = None
        try:
            _s = _vs.socket(_vs.AF_VSOCK, _vs.SOCK_STREAM)
            _s.settimeout(0.4)
            _s.connect((_cid, 1024))
            _connected.append(str(_cid))
        except OSError:
            pass
        finally:
            if _s is not None:
                _s.close()
    if _connected:
        out.append("vsock:REACHABLE:" + ",".join(_connected))
    else:
        out.append("vsock:UNREACHABLE")
except (AttributeError, OSError):
    # No AF_VSOCK in this python or no transport at all — equally unreachable.
    out.append("vsock:NO_TRANSPORT")
# TCP dead-state residue: no TIME_WAIT rows may survive the switch ("06").
tw = 0
for f in ("/proc/net/tcp", "/proc/net/tcp6"):
    try:
        for line in open(f).read().splitlines()[1:]:
            if line.split()[3] == "06":
                tw += 1
    except OSError:
        pass
out.append("tcp:CLEAN" if tw == 0 else "tcp:TW:%d" % tw)
# In-guest netlink diagnostic: what does sock_diag itself see right now?
try:
    import socket as _sk, struct as _st
    _nl = _sk.socket(_sk.AF_NETLINK, _sk.SOCK_RAW, 4)
    DEAD = (1<<4)|(1<<5)|(1<<6)|(1<<8)|(1<<9)|(1<<11)
    _wild = _st.pack(">HH",0,0)+b"\x00"*32+_st.pack("<I",0)+_st.pack("<II",0xffffffff,0xffffffff)
    _req = _st.pack("<IHHII",72,20,0x301,1,0)+_st.pack("<BBBB I",2,6,0,0,DEAD)+_wild
    _nl.sendto(_req,(0,0))
    _n=0
    while True:
        _r=_nl.recv(65536); _off=0; _last=None
        while _off+16<=len(_r):
            _ln,_ty,_fl,_sq,_p=_st.unpack_from("<IHHII",_r,_off)
            if _ln==0: break
            if _ty==20 and _r[_off+17]==6: _n+=1
            _last=_ty; _off+=_ln
        if _last==3: break
    _nl.close()
    out.append("diag:TW:%d" % _n)
except OSError as _e:
    out.append("diag:ERR:%d" % _e.errno)
print("PROBE " + " ".join(out))
PYEOF

OUT_B=$(exec_code "$KEY_B" "$SANDFS_B" /tmp/sandswap-residue-probe.py)
log_info "B probe output: $OUT_B"
VM_PID_AFTER=$(tc_run_vm_pids | head -n1)
[[ -n "$VM_PID_AFTER" && "$VM_PID_AFTER" == "$VM_PID_BEFORE" ]] \
    || { log_error "VM changed across the A→B switch (sandvmm pid ${VM_PID_BEFORE} → ${VM_PID_AFTER:-<none>}) — a fresh VM also shows GONE; the sweep was never exercised"; exit 1; }
pass "same microVM served A then B (sandvmm pid $VM_PID_BEFORE) — the GONE verdicts are meaningful"
fail=0
# kcore: MASKED (kernel ships /proc/kcore, warden covers it with /dev/null) or
# ABSENT (the guest-kernel minimization compiles CONFIG_PROC_KCORE out — the
# strictly stronger guarantee). Anything READABLE is the leak.
for want in "msg:GONE" "shm:GONE" "shmfile:GONE" "mq:EPERM" "key:EPERM" "kmsg:MASKED" \
            "kallsyms:MASKED" "keys:MASKED" "proc:RO" "core_pattern:RO" \
            "oom_score_adj:RO" "devmem:ABSENT" "tcp:CLEAN"; do
    if [[ "$OUT_B" == *"$want"* ]]; then
        pass "B: $want"
    else
        log_error "B residue channel NOT closed (wanted $want): $OUT_B"
        fail=1
    fi
done
case "$OUT_B" in
    *"kcore:MASKED"*|*"kcore:ABSENT"*) pass "B: kcore masked or absent" ;;
    *) log_error "B residue channel NOT closed (wanted kcore MASKED or ABSENT): $OUT_B"; fail=1 ;;
esac
case "$OUT_B" in
    *"cgroup_kill:ABSENT"*|*"cgroup_kill:RO"*) pass "B: cgroup.kill absent or read-only" ;;
    *) log_error "B residue channel NOT closed (wanted cgroup_kill ABSENT or RO): $OUT_B"; fail=1 ;;
esac
if [[ "$fail" != 0 ]]; then
    log_error "CROSS-TENANT RESIDUE LEAK — kernel objects survived the agent switch"
    exit 1
fi
# Kernel-state /proc files: MASKED when this kernel ships them, ABSENT
# otherwise — never READABLE by the uid-0 agent.
for _m in slabinfo kpagecount kpageflags pagetypeinfo buddyinfo zoneinfo; do
    case "$OUT_B" in
        *"$_m:MASKED"*|*"$_m:ABSENT"*) pass "B: $_m masked or absent" ;;
        *) log_error "B: /proc/$_m readable by the agent (wanted MASKED or ABSENT): $OUT_B"; exit 1 ;;
    esac
done
# The warden vsock port must be unreachable from inside the guest (the
# runtime pin for the kernel-config facts docs/how-it-works/isolation-and-swap.md
# §7.3 documents — no loopback transport, vhost drops cross-VM packets).
case "$OUT_B" in
    *"vsock:UNREACHABLE"*|*"vsock:NO_TRANSPORT"*)
        pass "B: warden vsock port unreachable from inside the guest (no loopback, no cross-VM routing)" ;;
    *)
        log_error "B: the raw warden protocol is GUEST-REACHABLE (vsock probe): $OUT_B"
        exit 1 ;;
esac

# Sanity: B is functional on its own rootfs after the switch (the sweep must
# not have torn down anything B needs).
printf 'print("SANE_OK")\n' > /tmp/sandswap-residue-sane.py
OUT_SANE=$(exec_code "$KEY_B" "$SANDFS_B" /tmp/sandswap-residue-sane.py)
[[ "$OUT_SANE" == *"SANE_OK"* ]] || { log_error "B exec broken after switch: $OUT_SANE"; exit 1; }
pass "B functional after switch"

log_section "RESULT"
log_pass "cross-tenant residue channels closed (SysV swept at unmount; mqueue seccomp-denied; keyring denied)"
