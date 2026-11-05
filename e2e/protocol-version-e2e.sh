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
# protocol-version-e2e.sh — REAL cross-version deployment drill (production gate
# for the protocol-version negotiation feature).
# Every other e2e exercises the system with version-matched binaries. This one
# builds genuinely MISMATCHED binaries — a warden whose wire protocol version is
# bumped, a sandlot whose stream protocol version is bumped, a gateway likewise
# — and runs them as real processes against the CURRENT build, asserting the
# exact production behavior the version gates exist for:
#   S0  control:    current×current connects and executes (the gates must not
#                   break the happy path at the process level).
#   S1  stream:     future sandlot → current gateway. Gateway rejects the
#                   handshake BEFORE registering the node; node_count stays 0.
#   S2  stream:     current sandlot → future gateway. Gateway rejects; the
#                   sandlot surfaces the gateway's supported range.
#   S3  vsock:      current stack + an initramfs whose warden speaks a version
#                   outside the current [1,1] window. VM creation fails FAST
#                   with the version mismatch (no "hung" teardown), pool
#                   scale-up aborts, and — the loop-prevention invariant — the
#                   create/destroy churn STOPS (zero additional VMM launches
#                   over an observation window instead of booting+destroying
#                   forever).
#   S4  vsock readopt: a live survivor booted from the mismatched initramfs is
#                   destroy-and-replaced at re-adopt; the replacement (current
#                   initramfs) converges to a healthy pool and serves a real
#                   exec end-to-end. This is the "node re-imaged with a new
#                   initramfs while a VM survived" production scenario.
# The ACK-side half of the stream gate (gateway acks a version the sandlot
# does not speak) cannot be produced with symmetric constants — a gateway
# outside our range rejects the handshake before acking — so it is covered by
# the fake-gateway unit test (rpc.TestConnect_HelloAckVersionMismatch).
# Variants are built from a COPY of the source trees (never mutating the
# working tree): warden via a copied crate + dedicated CARGO_TARGET_DIR,
# sandlot/gateway via copied Go modules + sed on the version constants.
# Prerequisites:
#   1. Fresh artifacts (the script self-heals a stale tree via
#      AUTO_REBUILD=1 → build.sh all; pre-build to skip the wait)
#   2. KVM available; root required; busybox-static installed (initramfs build)
# Usage: sudo bash e2e/protocol-version-e2e.sh
# Variants are cached in /tmp/pv-e2e keyed on OTHER_VER + a source-content
# OTHER_VER tracks the CURRENT wire versions: it must stay OUTSIDE every
# supported window (the warden's raw protocol is 1 with MIN 1; the stream
# protocol is 1), so bump it whenever a window moves — a variant that silently
# equals the current version makes the mismatch scenarios vacuous.
# hash: a second run reuses them until any source file changes.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

PV="${PV_DIR:-/tmp/pv-e2e}"
PV_LOGS="$PV/logs"
mkdir -p "$PV_LOGS"

# Offline VMs: every exec assertion in this drill is a guest-local shell
# command; guest egress is out of scope (smoke.sh owns that path). The value
# is consumed by the SOURCED common.sh (its sandlot starter passes
# -network-backend) — invisible to static analysis across the source boundary.
# shellcheck disable=SC2034
NETWORK_BACKEND="none"
# Self-heal a stale build tree — the version gates only exist in CURRENT
# sources, so deploying stale artifacts would make the drill vacuous.
AUTO_REBUILD="${AUTO_REBUILD:-1}"

# The "other deployment" versions the variants are built with. The variant must
# be OUTSIDE the warden's accepted window [1,1] so the mismatch is real; 2
# exercises the "newer peer" direction.
OTHER_VER=2

VM_DIR_S4="/run/sandswap/vm/pv-adopt-vm"
ADOPT_CID=90

# ── small local helpers ──────────────────────────────────────────────

collect() {
    # Snapshot the current stack's logs — tc_clean_environment wipes LOG_DIR
    # between scenarios, and post-mortem diagnosis needs them per scenario.
    local name="$1"
    mkdir -p "$PV_LOGS/$name"
    cp -f "$LOG_DIR/gateway.log" "$PV_LOGS/$name/" 2>/dev/null || true
    cp -f "$LOG_DIR/sandlot.log" "$PV_LOGS/$name/" 2>/dev/null || true
}

stop_stack() {
    # Variant binary names ("sandlot-v2") deliberately dodge
    # tc_kill_sandswap_procs' name patterns — kill by recorded PID + path.
    kill ${SANDLOT_PID:-} 2>/dev/null || true
    kill ${GATEWAY_PID:-} 2>/dev/null || true
    kill ${MANUAL_VMM_PID:-} 2>/dev/null || true
    # $PV is a unique per-run directory, so this pattern can only ever match
    # this run's variant processes (the variant sandvmm children, which have
    # no recorded PID of their own).
    pkill -f "$PV/" 2>/dev/null || true
    sleep 0.5
    SANDLOT_PID="" GATEWAY_PID="" MANUAL_VMM_PID=""
}

cleanup() {
    stop_stack
    tc_cleanup_default
}
trap cleanup EXIT INT TERM

wait_log() { # <file> <fixed-string> [timeout_sec]
    local file="$1" pattern="$2" timeout="${3:-30}"
    local deadline=$((SECONDS + timeout))
    while ((SECONDS < deadline)); do
        if [[ -f "$file" ]] && grep -qF "$pattern" "$file" 2>/dev/null; then
            pass "log [$file]: $pattern"
            return 0
        fi
        sleep 0.5
    done
    fail "pattern not found in $file within ${timeout}s: $pattern"
    tail -25 "$file" || true
    exit 1
}

stats_field() { # <python expr over d=report, g=gateways[0]>
    curl -s -m 5 "$HUMAN_URL/stats" 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
gws = d.get('gateways') or []
g = gws[0] if gws else {}
try:
    print($1)
except Exception:
    print(0)" 2>/dev/null || echo 0
}

node_count() { stats_field "int(g.get('node_count') or 0)"; }
clean_vms() { stats_field "int((d.get('totals') or {}).get('clean_vms') or 0)"; }

wait_node_count() { # <expected> [timeout]
    local want="$1" timeout="${2:-20}"
    local deadline=$((SECONDS + timeout)) got
    while ((SECONDS < deadline)); do
        got=$(node_count)
        [[ -n "$got" ]] && [[ "$got" == "$want" ]] && {
            pass "gateway node_count == $want"
            return 0
        }
        sleep 0.5
    done
    fail "node_count never became $want (last: ${got:-?})"
    exit 1
}

count_log() { # <file> <fixed-string> -> count on stdout
    # grep -c already prints 0 on no-match; swallow its nonzero exit without
    # appending a second 0 (the "0\n0" bug that broke the churn assertion).
    local n
    n=$(grep -cF "$2" "$1" 2>/dev/null || true)
    echo "${n:-0}"
}

create_agent_json() { # -> prints "key|sandfs_id"
    local out key sid
    out=$(tc_create_agent_and_sandfs "pv-agent")
    key=$(echo "$out" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || true)
    sid=$(echo "$out" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || true)
    echo "$key|$sid"
}

exec_assert() { # <key> <sandfs_id> <marker>
    local key="$1" sid="$2" marker="$3" resp
    resp=$(curl -s -m 60 -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$sid\",\"code\":\"echo $marker\",\"language\":\"shell\"}")
    echo "$resp" | grep -qF "$marker" || {
        fail "exec did not return marker '$marker': $resp"
        exit 1
    }
    pass "exec end-to-end returned '$marker'"
}

# ── variant builds ───────────────────────────────────────────────────

build_variants() {
    log_section "Building mismatched-version variants ($PV)"

    # Variant cache key: OTHER_VER plus a content hash of the source trees the
    # variants are built from. Keying only on OTHER_VER would reuse STALE
    # binaries after any later source edit — the exact false confidence this
    # drill exists to prevent. Two flavors per side:
    #   hard-mismatch — the peer speaks ONLY v$OTHER_VER (S1–S4: must fail fast)
    #   window        — the peer ALSO accepts v1 (S5: the expand phase of a
    #                   rolling upgrade — current sandlot keeps working)
    local src_hash
    src_hash=$(find "$ROOT/common" "$ROOT/sandlot" "$ROOT/gateway" "$ROOT/warden/src" "$ROOT/initramfs" \
        -type f \( -name '*.go' -o -name '*.rs' -o -name '*.proto' -o -name 'Cargo.toml' -o -name 'build.sh' \) \
        -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1)
    local key="$OTHER_VER-$src_hash"
    if [[ -x "$PV/sandlot-v2" && -x "$PV/gateway-v2" && -f "$PV/initramfs-v2.cpio.gz" \
        && -x "$PV/gateway-v2w" && -f "$PV/initramfs-v2w.cpio.gz" \
        && "$(cat "$PV/.built-key" 2>/dev/null || true)" == "$key" ]]; then
        pass "reusing existing v$OTHER_VER variants (source hash unchanged)"
        return 0
    fi

    # Go module tree: shared by all variant builds (patched per binary below).
    # Always re-copied — the cache key above already decided a rebuild is
    # needed, so the tree must reflect CURRENT sources.
    rm -rf "$PV/go"
    mkdir -p "$PV/go"
    cp -a "$ROOT/common" "$ROOT/sandlot" "$ROOT/gateway" "$PV/go/"

    # ── hard-mismatch warden: speaks ONLY v$OTHER_VER (min=$OTHER_VER) ──
    log_step "Building warden-v2 (PROTOCOL_VERSION=$OTHER_VER, MIN=$OTHER_VER)..."
    rm -rf "$PV/warden-v2" "$PV/wbuild"
    mkdir -p "$PV/warden-v2" "$PV/wbuild"
    tar -C "$ROOT/warden" --exclude=./target -cf - . | tar -C "$PV/warden-v2" -xf -
    sed -i "s/pub const PROTOCOL_VERSION: u8 = 1;/pub const PROTOCOL_VERSION: u8 = $OTHER_VER;/; s/const PROTOCOL_MIN_ACCEPTED: u8 = 1;/const PROTOCOL_MIN_ACCEPTED: u8 = $OTHER_VER;/" \
        "$PV/warden-v2/src/raw_server.rs"
    grep -q "PROTOCOL_VERSION: u8 = $OTHER_VER" "$PV/warden-v2/src/raw_server.rs" || {
        fail "warden version patch did not land"; exit 1
    }
    (cd "$PV/warden-v2" && CARGO_TARGET_DIR="$PV/wbuild" cargo build --release --target x86_64-unknown-linux-musl --quiet) || {
        fail "warden-v2 build failed"; exit 1
    }
    pass "warden-v2 built"

    log_step "Building initramfs-v2 (embeds hard-mismatch warden-v2)..."
    WARDEN_BIN="$PV/wbuild/x86_64-unknown-linux-musl/release/warden" \
        OUTPUT="$PV/initramfs-v2.cpio.gz" \
        bash "$ROOT/initramfs/build.sh" >"$PV_LOGS/initramfs-v2.log" 2>&1 || {
        fail "initramfs-v2 build failed (see $PV_LOGS/initramfs-v2.log)"; exit 1
    }
    [[ -s "$PV/initramfs-v2.cpio.gz" ]] || { fail "initramfs-v2 empty"; exit 1; }
    pass "initramfs-v2 built"

    # ── stream hard-mismatch: sandlot speaks only v$OTHER_VER / gateway too ──
    log_step "Building stream-protocol-$OTHER_VER sandlot-v2 + gateway-v2 (no window)..."
    sed -i "s/^const ProtocolVersion = 1$/const ProtocolVersion = $OTHER_VER/" "$PV/go/sandlot/rpc/client.go"
    grep -q "const ProtocolVersion = $OTHER_VER" "$PV/go/sandlot/rpc/client.go" || {
        fail "sandlot stream version patch did not land"; exit 1
    }
    sed -i -E "s/(StreamProtocolVersion[[:space:]]+=) 1/\1 $OTHER_VER/; s/(StreamProtocolMinSupported[[:space:]]+=) 1/\1 $OTHER_VER/" \
        "$PV/go/gateway/stream/server.go"
    grep -qE "StreamProtocolVersion[[:space:]]+= $OTHER_VER" "$PV/go/gateway/stream/server.go" || {
        fail "gateway stream version patch did not land"; exit 1
    }
    (cd "$PV/go/sandlot" && go build -o "$PV/sandlot-v2" ./cmd) || { fail "sandlot-v2 build failed"; exit 1; }
    (cd "$PV/go/gateway" && go build -o "$PV/gateway-v2" ./cmd) || { fail "gateway-v2 build failed"; exit 1; }
    pass "sandlot-v2 + gateway-v2 built (stream protocol $OTHER_VER, no window)"

    # ── WINDOW flavor: the new side also accepts v1 (rolling-upgrade expand) ──
    # Stream: gateway version bumped to $OTHER_VER, MinSupported stays 1.
    # Vsock: warden PROTOCOL_VERSION bumped, MIN_ACCEPTED stays 1.
    log_step "Building window variants: gateway-v2w ([1,$OTHER_VER]) + warden-v2w ([1,$OTHER_VER])..."
    # The shared go tree was already patched by the hard-mismatch pass above —
    # restore the pristine file first or the window sed is a no-op and the
    # "window" gateway silently builds as [1,1] (the exact bug this scenario
    # exists to catch, caught here on the first run).
    cp -f "$ROOT/gateway/stream/server.go" "$PV/go/gateway/stream/server.go"
    sed -i -E "s/(StreamProtocolVersion[[:space:]]+=) 1/\1 $OTHER_VER/" "$PV/go/gateway/stream/server.go"
    grep -qE "StreamProtocolVersion[[:space:]]+= $OTHER_VER" "$PV/go/gateway/stream/server.go" || {
        fail "gateway window patch did not land"; exit 1
    }
    (cd "$PV/go/gateway" && go build -o "$PV/gateway-v2w" ./cmd) || { fail "gateway-v2w build failed"; exit 1; }
    rm -rf "$PV/warden-v2w"
    mkdir -p "$PV/warden-v2w"
    tar -C "$ROOT/warden" --exclude=./target -cf - . | tar -C "$PV/warden-v2w" -xf -
    sed -i "s/pub const PROTOCOL_VERSION: u8 = 1;/pub const PROTOCOL_VERSION: u8 = $OTHER_VER;/" \
        "$PV/warden-v2w/src/raw_server.rs"
    grep -q "PROTOCOL_VERSION: u8 = $OTHER_VER" "$PV/warden-v2w/src/raw_server.rs" || {
        fail "warden window patch did not land"; exit 1
    }
    WBUILD2="$PV/wbuild2"
    (cd "$PV/warden-v2w" && CARGO_TARGET_DIR="$WBUILD2" cargo build --release --target x86_64-unknown-linux-musl --quiet) || {
        fail "warden-v2w build failed"; exit 1
    }
    WARDEN_BIN="$WBUILD2/x86_64-unknown-linux-musl/release/warden" \
        OUTPUT="$PV/initramfs-v2w.cpio.gz" \
        bash "$ROOT/initramfs/build.sh" >"$PV_LOGS/initramfs-v2w.log" 2>&1 || {
        fail "initramfs-v2w build failed (see $PV_LOGS/initramfs-v2w.log)"; exit 1
    }
    [[ -s "$PV/initramfs-v2w.cpio.gz" ]] || { fail "initramfs-v2w empty"; exit 1; }
    # Cache key written LAST, after every variant artifact exists: a partially
    # built set (crash mid-build) must not be reused.
    echo "$key" >"$PV/.built-key"
    pass "window variants built (gateway [1,$OTHER_VER], warden v$OTHER_VER min 1)"
}

# ── S0: control — current × current must fully work ──────────────────

scenario_control() {
    log_section "S0: control — current gateway × current sandlot (must pass)"
    tc_clean_environment
    tc_start_gateway
    SANDLOT_POOL="small:1" TC_NODE_ID="pv-ctl-node" tc_start_sandlot
    tc_wait_health
    tc_wait_pool_ready 1

    local kv key sid
    kv=$(create_agent_json)
    key="${kv%%|*}"; sid="${kv##*|}"
    [[ -n "$key" && -n "$sid" ]] || { fail "agent creation failed"; exit 1; }
    exec_assert "$key" "$sid" "pv-control-ok"

    collect s0-control
    stop_stack
}

# ── S1: future sandlot → current gateway ─────────────────────────────

scenario_stream_new_sandlot() {
    log_section "S1: stream — sandlot(v$OTHER_VER) → current gateway (must reject)"
    tc_clean_environment
    tc_start_gateway
    TC_SANDLOT_BIN="$PV/sandlot-v2" SANDLOT_POOL="small:1" TC_NODE_ID="pv-new-sandlot" tc_start_sandlot

    wait_log "$LOG_DIR/gateway.log" "rejected: stream protocol version $OTHER_VER outside supported range [1,1]" 20
    wait_log "$LOG_DIR/sandlot.log" "handshake failed" 20
    wait_node_count 0 15

    collect s1-stream-new-sandlot
    stop_stack
}

# ── S2: current sandlot → future gateway ─────────────────────────────

scenario_stream_new_gateway() {
    log_section "S2: stream — current sandlot → gateway(v$OTHER_VER) (must reject)"
    tc_clean_environment
    TC_GATEWAY_BIN="$PV/gateway-v2" tc_start_gateway
    SANDLOT_POOL="small:1" TC_NODE_ID="pv-cur-sandlot" tc_start_sandlot

    wait_log "$LOG_DIR/gateway.log" "rejected: stream protocol version 1 outside supported range [$OTHER_VER,$OTHER_VER]" 20
    wait_log "$LOG_DIR/sandlot.log" "stream protocol version unsupported" 20
    wait_node_count 0 15

    collect s2-stream-new-gateway
    stop_stack
}

# ── S3: vsock — mismatched-warden initramfs, loop prevention ─────────

scenario_vsock_mismatch() {
    log_section "S3: vsock — current stack + warden(v$OTHER_VER) initramfs (fail fast, NO churn)"
    tc_clean_environment
    tc_start_gateway
    TC_INITRAMFS="$PV/initramfs-v2.cpio.gz" SANDLOT_POOL="small:1" TC_NODE_ID="pv-vsock-node" \
        tc_start_sandlot

    # Fail-fast with the typed diagnosis (CreateVerifiedVM's loud line).
    wait_log "$LOG_DIR/sandlot.log" "sandlot speaks 1, warden speaks $OTHER_VER" 90
    # The scale-up loop aborts instead of grinding boot+destroy cycles.
    wait_log "$LOG_DIR/sandlot.log" "aborting scale-up" 30
    # The OLD failure mode would surface as hung-VM teardowns — must not.
    # Positive control FIRST: count_log yields 0 for BOTH "pattern absent" and
    # "log unreadable", so a zero hung-count is evidence only once a
    # known-present line is proven countable in THIS file.
    local ctrl
    ctrl=$(count_log "$LOG_DIR/sandlot.log" "sandlot speaks 1, warden speaks")
    [[ "$ctrl" -ge 1 ]] || { fail "control line 'sandlot speaks 1, warden speaks' not countable in sandlot.log (count=$ctrl) — the hung==0 check would be vacuous"; exit 1; }
    local hung
    hung=$(count_log "$LOG_DIR/sandlot.log" "declared hung")
    [[ "$hung" == "0" ]] || { fail "probe-hang teardowns fired ($hung) — mismatch must fail fast, not as a hang"; exit 1; }
    pass "zero hung-VM teardowns (mismatch classified, not misdiagnosed)"

    # THE invariant: churn stops. Two launches are the expected startup
    # attempts (preCreateVMs + ResizePool); a destroy-loop would keep adding.
    local l1 l2
    l1=$(count_log "$LOG_DIR/sandlot.log" "launching VMM")
    # Floor before the equality: l1 == 0 (anchor absent / format drift) would
    # make l1 == l2 vacuously true — 0 == 0 proves no stability.
    [[ "$l1" -ge 1 ]] || { fail "no 'launching VMM' lines in sandlot.log (l1=$l1) — the churn check is vacuous"; exit 1; }
    sleep 20
    l2=$(count_log "$LOG_DIR/sandlot.log" "launching VMM")
    [[ "$l1" == "$l2" ]] || { fail "create/destroy churn detected: $l1 launches → $l2 after 20s"; exit 1; }
    pass "no create/destroy churn (launches stable at $l2 over 20s)"

    # The NODE is fine (stream versions match); only VM creation fails.
    wait_node_count 1 15
    local cvm
    cvm=$(clean_vms)
    [[ "$cvm" == "0" ]] || { fail "expected 0 CLEAN VMs, got $cvm"; exit 1; }
    pass "node connected, zero servable VMs (as designed)"

    collect s3-vsock-mismatch
    stop_stack
}

# ── S4: vsock readopt — mismatched survivor is replaced, pool converges ──

scenario_vsock_adopt() {
    log_section "S4: vsock readopt — survivor from warden(v$OTHER_VER) initramfs is destroy-and-replaced"
    tc_clean_environment

    # Boot the survivor MANUALLY (what a pre-redeploy VM looks like after the
    # node's initramfs was replaced): sandvmm + vm.create + vsock + boot.
    # sandvmm identity (uid 987): a real VMM belongs to the dedicated VMM
    # identity post-split — /dev/vhost-vsock is OWNER=sandvmm 0600, so a VMM
    # launched as the sandlot user cannot activate its vsock device. The
    # sandbox dir carries the shared-group setgid shape (the child creates
    # its socket in it; the re-adopting sandlot reads state there).
    log_step "Manually booting a warden-v$OTHER_VER survivor (cid=$ADOPT_CID, user=sandvmm)..."
    rm -f "$VM_DIR_S4/sandvmm.sock"
    # Mirror the production shape EXACTLY: the sandlot ordinarily creates the
    # vm/ parent itself (sandlot-owned, group-writable so per-VM sandbox dirs
    # can be created inside); a root-mkdir here would leave a root-owned vm/
    # and every subsequent pool launch would fail EACCES.
    install -d -m 2770 -o "$SS_SERVICE_USER_SL" -g "$SS_SHARED_GROUP" "$(dirname "$VM_DIR_S4")"
    install -d -m 2770 -o "$SS_SERVICE_USER_SL" -g "$SS_SHARED_GROUP" "$VM_DIR_S4"
    ld_chain() { local d="$1"; while [[ "$d" != "/" && -n "$d" ]]; do ls -ld "$d" | awk '{print $1, $3":"$4, $NF}'; d="$(dirname "$d")"; done; }
    # --api-gid: the split's socket grant. The socket is owned by the sandvmm
    # identity (987); the re-adopting sandlot (985) connects through the
    # shared-group 0660 grant — without it the survivor is unreachable
    # (EACCES on connect) and re-adopt never probes the mismatched warden.
    ss_service_exec sandvmm -- "$DEPLOY_DIR/sandvmm" --api-socket "$VM_DIR_S4/sandvmm.sock" --api-gid "$(getent group "$SS_SHARED_GROUP" | cut -d: -f3)" --seccomp false --log-stderr \
        >"$PV_LOGS/s4-survivor-vmm.log" 2>&1 &
    MANUAL_VMM_PID=$!

    local up=0
    for _ in $(seq 1 40); do
        if curl -s -m 2 --unix-socket "$VM_DIR_S4/sandvmm.sock" \
            "http://localhost/api/v1/sandvmm.ping" >/dev/null 2>&1; then up=1; break; fi
        sleep 0.25
    done
    [[ "$up" == "1" ]] || {
        fail "manual sandvmm never came up"
        tail -20 "$PV_LOGS/s4-survivor-vmm.log"
        echo "--- dir chain:"; ld_chain "$VM_DIR_S4"
        echo "--- sandvmm identity:"; id "$SS_SERVICE_USER_VM" 2>/dev/null || true
        exit 1
    }
    pass "manual sandvmm up (pid $MANUAL_VMM_PID)"

    # The survivor was booted by a build that carries the raw-protocol HMAC
    # contract. The key is NOT on the kernel command line (the warden waits
    # for OP_KEY_DELIVERY); record it in state.json so the adopter and the
    # probe can deliver it and reach the VERSION gate this scenario tests.
    S4_SESSION_KEY="$(openssl rand -hex 32)"
    cat >"$PV/s4-create.json" <<EOF
{
  "cpus":   {"boot_vcpus": 2, "max_vcpus": 2},
  "memory": {"size": 268435456},
  "payload": {
    "kernel": "$DEPLOY_DIR/vmlinux.bin",
    "initramfs": "$PV/initramfs-v2.cpio.gz",
    "cmdline": "quiet clocksource=kvm-clock console=hvc0 earlyprintk=ttyS0"
  },
  "serial": {"mode": "File", "file": "$VM_DIR_S4/serial.log"},
  "console": {"mode": "File", "file": "$VM_DIR_S4/console.log"},
  "fs": [{
    "id": "vfs-rootfs",
    "tag": "sandswap",
    "backendfs_config": {"shared_dir": "$VOL_ROOT", "read_only": false, "allowed_dirs": []}
  }]
}
EOF
    curl -s -m 30 --unix-socket "$VM_DIR_S4/sandvmm.sock" -X PUT \
        "http://localhost/api/v1/vm.create" -d @"$PV/s4-create.json" >/dev/null
    curl -s -m 10 --unix-socket "$VM_DIR_S4/sandvmm.sock" -X PUT \
        "http://localhost/api/v1/vm.add-vsock" -d "{\"cid\": $ADOPT_CID}" >/dev/null
    curl -s -m 30 --unix-socket "$VM_DIR_S4/sandvmm.sock" -X PUT \
        "http://localhost/api/v1/vm.boot" >/dev/null
    pass "survivor VM created + booted"
    sleep 5 # let the guest reach userspace (warden-v2 listening)

    # state.json — what re-adopt reads: live VMM identity + v1-era bookkeeping.
    mkdir -p /run/sandswap-state/default/pv-adopt-vm
    cat >/run/sandswap-state/default/pv-adopt-vm/state.json <<EOF
{
  "vm_id": "pv-adopt-vm",
  "cid": $ADOPT_CID,
  "pid": $MANUAL_VMM_PID,
  "sandbox_dir": "$VM_DIR_S4",
  "api_socket": "$VM_DIR_S4/sandvmm.sock",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "config": {
    "vcpus": 2,
    "memory_mb": 256,
    "kernel_path": "$DEPLOY_DIR/vmlinux.bin",
    "initramfs_path": "$PV/initramfs-v2.cpio.gz",
    "kernel_cmdline": "quiet clocksource=kvm-clock console=hvc0 earlyprintk=ttyS0",
    "warden_session_key": "$S4_SESSION_KEY",
    "vmm_binary": "$DEPLOY_DIR/sandvmm",
    "volumes_dir": "$VOL_ROOT"
  },
  "spec_id": "small"
}
EOF
    # The adopter sandlot runs as the sandlot identity: the private state dir
    # enforces owner == writer, so hand the fixture (and its parent, where the
    # adopter creates replacement VM state) over before the adopter starts (a
    # root-owned dir is refused as a squat / EACCES).
    chown -R sandlot:sandlot /run/sandswap-state/default

    # The survivor must still be ALIVE and its socket present when the
    # adopter starts: a VMM that died during the harness sleep makes the
    # readopt leg vacuous ("not responding → cleaning up" is NOT the
    # mismatch path this scenario exists to prove).
    if ! kill -0 "$MANUAL_VMM_PID" 2>/dev/null || [[ ! -S "$VM_DIR_S4/sandvmm.sock" ]]; then
        fail "survivor sandvmm ($MANUAL_VMM_PID) is gone before the adopter starts (socket $([[ -S "$VM_DIR_S4/sandvmm.sock" ]] && echo present || echo missing))"
        tail -20 "$PV_LOGS/s4-survivor-vmm.log"
        exit 1
    fi
    tc_start_gateway
    # CURRENT initramfs: the survivor is v2, the replacement boots v1 — the
    # exact "node re-imaged, old VM survives, new VMs are healthy" production
    # sequence this scenario exists to prove.
    # The manual survivor VMM was launched without --api-token-fd, so the
    # adopter must not require the per-VM API token for this fixture (the
    # re-adopt mismatch being tested is the WARDEN protocol version, not API
    # authentication; VMMAPIAuth remains the production default).
    TC_SANDLOT_EXTRA_FLAGS="-vmm-api-auth=false" \
        SANDLOT_POOL="small:1" TC_NODE_ID="pv-adopt-node" tc_start_sandlot

    wait_log "$LOG_DIR/sandlot.log" "protocol version mismatch" 90
    wait_log "$LOG_DIR/sandlot.log" "destroying + reconciling" 60
    if kill -0 "$MANUAL_VMM_PID" 2>/dev/null; then
        fail "survivor sandvmm (pid $MANUAL_VMM_PID) still alive after destroy-and-replace"
        exit 1
    fi
    pass "mismatched survivor destroyed (pid $MANUAL_VMM_PID gone)"

    # The replacement (current initramfs) converges to a healthy pool and
    # serves a real exec — the node recovers without operator action.
    local deadline=$((SECONDS + 150)) cvm=""
    while ((SECONDS < deadline)); do
        cvm=$(clean_vms)
        [[ -n "$cvm" ]] && [[ "$cvm" -ge 1 ]] && break
        sleep 2
    done
    [[ -n "$cvm" && "$cvm" -ge 1 ]] || {
        fail "replacement VM never became CLEAN (last: ${cvm:-?})"
        echo "--- sandlot log tail:"; tail -20 "$LOG_DIR/sandlot.log" 2>/dev/null || true
        exit 1
    }
    pass "replacement VM healthy (clean_vms=$cvm)"

    local kv key sid
    kv=$(create_agent_json)
    key="${kv%%|*}"; sid="${kv##*|}"
    [[ -n "$key" && -n "$sid" ]] || { fail "agent creation failed"; exit 1; }
    exec_assert "$key" "$sid" "pv-adopt-ok"

    collect s4-vsock-adopt
    stop_stack
}

# ── S5: the compat WINDOW — old sandlot keeps working against new peers ──
#
# This is the rolling-upgrade expand phase and the positive half of the
# negotiation answer: a newer peer that still accepts v1 (MinSupported stays 1)
# serves the CURRENT sandlot, because both protocols NEGOTIATED-ECHO the
# agreed version instead of stamping their own.

scenario_stream_window() {
    log_section "S5a: stream WINDOW — current sandlot → gateway([1,$OTHER_VER]) (must work)"
    tc_clean_environment
    TC_GATEWAY_BIN="$PV/gateway-v2w" tc_start_gateway
    SANDLOT_POOL="small:1" TC_NODE_ID="pv-win-stream" tc_start_sandlot
    tc_wait_health
    wait_node_count 1 20

    local kv key sid
    kv=$(create_agent_json)
    key="${kv%%|*}"; sid="${kv##*|}"
    [[ -n "$key" && -n "$sid" ]] || { fail "agent creation failed"; exit 1; }
    exec_assert "$key" "$sid" "pv-window-stream-ok"

    collect s5a-stream-window
    stop_stack
}

scenario_vsock_window() {
    log_section "S5b: vsock WINDOW — current sandlot + warden(v$OTHER_VER, min 1) initramfs (must work)"
    tc_clean_environment
    tc_start_gateway
    TC_INITRAMFS="$PV/initramfs-v2w.cpio.gz" SANDLOT_POOL="small:1" TC_NODE_ID="pv-win-vsock" \
        tc_start_sandlot
    tc_wait_health
    tc_wait_pool_ready 1

    local kv key sid
    kv=$(create_agent_json)
    key="${kv%%|*}"; sid="${kv##*|}"
    [[ -n "$key" && -n "$sid" ]] || { fail "agent creation failed"; exit 1; }
    exec_assert "$key" "$sid" "pv-window-vsock-ok"

    # Cross-evidence with S3: this initramfs's warden is ALSO v$OTHER_VER — the
    # ONLY difference from S3's hard-mismatch flavor is the accepted window
    # (min 1 vs min $OTHER_VER). Failing there and working here IS the proof
    # that the negotiated echo carries the window, not luck.
    if grep -qF "protocol version mismatch" "$LOG_DIR/sandlot.log"; then
        fail "window scenario logged a version mismatch — echo contract broken"
        exit 1
    fi
    pass "zero version-mismatch lines against a v$OTHER_VER warden (negotiated echo carried the window)"

    collect s5b-vsock-window
    stop_stack
}

# ── main ─────────────────────────────────────────────────────────────

log_section "Phase 0: Pre-flight"
tc_check_root
tc_preflight_standard python3
tc_ensure_dev_nodes

log_section "Phase 1: Variant builds"
build_variants

log_section "Phase 2: Deploy (once; scenarios clean process state only)"
tc_deploy_artifacts
tc_gen_certs

scenario_control
scenario_stream_new_sandlot
scenario_stream_new_gateway
scenario_vsock_mismatch
scenario_vsock_adopt
scenario_stream_window
scenario_vsock_window

echo "Per-scenario logs: $PV_LOGS"

# ── Verdict ─────────────────────────────────────────────────────────
# e2e/run-all.sh judges this script by EXIT CODE alone: a recorded failure
# MUST become the exit status, or the suite reports green while failing
# (the false-green class this gate closes).
tc_log_section "protocol-version drill Summary"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    log_error "protocol-version drill FAILED ($FAIL_COUNT check(s))"
    exit 1
fi
log_pass "protocol-version drill PASSED ($PASS_COUNT checks)"
exit 0
