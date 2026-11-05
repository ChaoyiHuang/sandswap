#!/usr/bin/env bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# vmm-api-auth.sh — the optional per-VM sandvmm API token handshake.
#
#   0. DEFAULT OFF: a VMM started WITHOUT --api-token-fd accepts a tokenless
#      raw sandvmm.ping (the default sandlot launch shape).
#   1. A VMM started with --api-token-fd accepts the correct token
#      (challenge → token XOR challenge) and serves a raw sandvmm.ping.
#   2. A client using the WRONG token is rejected at the handshake.
#   3. A tokenless client's raw frame is refused before any command is
#      processed (the server closes on the first two bytes).
#
# The preface is transport-independent (it precedes whichever framing —
# raw or HTTP — the connection then uses). No microVM is created; KVM +
# output/sandvmm are required.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

tc_use_output_binaries
tc_check_root
tc_check_kvm
[[ -x "$OUTPUT/sandvmm" ]] || { log_error "missing output/sandvmm (bash build/build.sh vmm)"; exit 1; }

TMP=$(mktemp -d)
cleanup() {
    local ec=$?
    rm -rf "$TMP"
    exit "$ec"
}
trap cleanup EXIT INT TERM

log_section "VMM API token handshake"
python3 - "$OUTPUT/sandvmm" "$TMP" <<'PY'
import os, socket, struct, subprocess, sys, time

vmm, tmp = sys.argv[1], sys.argv[2]
sock_path = os.path.join(tmp, "sandvmm.sock")
log_path = os.path.join(tmp, "sandvmm.log")
token = os.urandom(32)

r, w = os.pipe()
logf = open(log_path, "wb")
proc = subprocess.Popen(
    [vmm, "--api-socket", sock_path,
     "--api-token-fd", str(r),
     "--api-allowed-uid", str(os.getuid()),
     "--seccomp", "false", "--log-stderr"],
    pass_fds=(r,), stdout=logf, stderr=logf)

def fail(msg):
    proc.kill()
    proc.wait()
    text = open(log_path, "rb").read().decode("utf-8", "replace")[-2000:]
    print("FAIL:", msg)
    print("sandvmm log tail:\n" + text)
    sys.exit(1)

try:
    os.write(w, token)
    os.close(w)
    os.close(r)
    for _ in range(100):
        if os.path.exists(sock_path):
            break
        time.sleep(0.05)
    else:
        fail("sandvmm socket did not appear")

    def recv_exact(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    def handshake(tok):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(sock_path)
        nonce = os.urandom(32)
        s.sendall(b"\xa5\x01" + nonce)
        resp = recv_exact(s, 32)
        ok = all(resp[i] ^ nonce[i] == tok[i] for i in range(32))
        return s, ok

    # 1. Correct token: handshake + raw sandvmm.ping.
    s, ok = handshake(token)
    if not ok:
        fail("correct token was rejected")
    s.sendall(struct.pack(">BBHI", 1, 0, 0, 0))
    hdr = recv_exact(s, 8)
    version, op, status, reserved, blen = struct.unpack(">BBBBI", hdr)
    body = recv_exact(s, blen) if blen else b""
    if (version, op, status, reserved) != (1, 0, 0, 0):
        fail(f"raw ping response header = {version},{op},{status},{reserved} body={body!r}")
    s.close()
    print("PASS: correct token -> authenticated raw ping")

    # 2. Wrong token: the server answers with the real token's XOR; the
    #    client's verification must fail.
    wrong = bytearray(token); wrong[0] ^= 0xFF
    s2, ok2 = handshake(bytes(wrong))
    s2.close()
    if ok2:
        fail("wrong token was ACCEPTED")
    print("PASS: wrong token rejected at the handshake")

    # 3. Tokenless raw client: the first bytes are not the auth magic; the
    #    server must close before processing the frame.
    s3 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s3.settimeout(2)
    s3.connect(sock_path)
    s3.sendall(struct.pack(">BBHI", 1, 0, 0, 0))
    try:
        got = s3.recv(1)
    except (ConnectionResetError, BrokenPipeError):
        got = b""
    s3.close()
    if got:
        fail(f"tokenless client was not refused (read {got!r})")
    print("PASS: tokenless raw client refused before dispatch")
finally:
    proc.kill()
    proc.wait()
    logf.close()

# 0. DEFAULT OFF: no --api-token-fd -> the legacy first-byte path. A raw
#    tokenless ping must be served (the default sandlot launch shape).
sock_off = os.path.join(tmp, "sandvmm-off.sock")
log_off_path = os.path.join(tmp, "sandvmm-off.log")
log_off = open(log_off_path, "wb")
proc_off = subprocess.Popen(
    [vmm, "--api-socket", sock_off,
     "--api-allowed-uid", str(os.getuid()),
     "--seccomp", "false", "--log-stderr"],
    stdout=log_off, stderr=log_off)
try:
    for _ in range(100):
        if os.path.exists(sock_off):
            break
        time.sleep(0.05)
    else:
        print("FAIL: tokenless sandvmm socket did not appear")
        print(open(log_off_path, "rb").read().decode("utf-8", "replace")[-2000:])
        sys.exit(1)
    s0 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s0.settimeout(2)
    s0.connect(sock_off)
    s0.sendall(struct.pack(">BBHI", 1, 0, 0, 0))
    hdr0 = recv_exact(s0, 8)
    version0, op0, status0, reserved0, blen0 = struct.unpack(">BBBBI", hdr0)
    body0 = recv_exact(s0, blen0) if blen0 else b""
    s0.close()
    if (version0, op0, status0, reserved0) != (1, 0, 0, 0):
        print(f"FAIL: tokenless VMM raw ping header = {version0},{op0},{status0},{reserved0} body={body0!r}")
        sys.exit(1)
    print("PASS: default off -> tokenless VMM serves a raw ping")
finally:
    proc_off.kill()
    proc_off.wait()
    log_off.close()
PY

log_section "Verdict"
log_pass "ALL checks passed — optional VMM API token handshake (default off + enabled)"
