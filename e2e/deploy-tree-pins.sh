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
# deploy-tree-pins.sh — host-safe pins for the deploy-tree contracts.
# Every check runs against scratch copies under a private temp dir; nothing
# touches the host's network, systemd, /usr/local or any deployed stack, so the
# drill is safe to run anywhere. It exists because these defects had NO row:
# the deploy matrix runs the REPO-TREE copies and reads units' enabled state —
# which is exactly how a broken INSTALLED copy passed a green matrix while the
# boot-time unit crash-looped.
#
# Pins:
#   the installed copy of deploy/setup-network.sh (ExecStart of
#        sandswap-network.service) resolves common/sh/runtime.sh from the repo
#        tree or /usr/local/lib/sandswap, and dies with a NAMED message when
#        neither exists (never a bare bash ENOENT); every installer that ships
#        the binary ships the library, and uninstall removes it.
#   every log_* helper deploy/k8s/deploy-lib.sh calls is DEFINED in the
#        environment its entry scripts build (e2e/common.sh + runtime.sh): an
#        undefined helper under `set -e` exits 127 BEFORE its message prints.
#   rotate-volume-seed.sh: --stage refuses to target the file the CURRENT
#        generation points at, and a second rotation's default mint lands at a
#        NEW path — the files earlier generations point at stay byte-identical.
#   human_post (rotate-volume-seed.sh) fails on a non-2xx HTTP answer.
#   the --prov-hosts stage fan-out transfers through remote mktemp paths,
#        removes the transfer file, never parks the generation file in /tmp,
#        and names the local host the fan-out does not cover.
#   seed-fetch.sh.template reports an unreadable/unparsable config as a
#        FAILURE, while "no seed file configured" still succeeds.
#   security/verify-host-security.sh's tmpfs seed-directory check never
#        prints "ok" from an unparsable mode (a failing/absent stat used to
#        fall into the else branch and report a pass for a check that examined
#        nothing).
#   the same script parses the prov config's seed-file keys with the Go
#        loader's YAML semantics — single/double quotes and trailing comments
#        are syntax, not part of the path — and a path it cannot resolve is a
#        loud finding, never a silent skip.
#   the seed-scope predicate behind the security check classifies a
#        sandvmm-readable seed as FAIL (exit 1) and an unreadable one as
#        denied — never a pass, and never a pass by accident of string
#        matching; the live form additionally runs against this host's real
#        identity table when the drill runs as root.
#    /run/sandswap is STICKY (3770) and the setup path fails hard when the
#        mode does not land: without the sticky bit a sandvmm-identity process
#        (987, shared-group member) can unlink or replace entries it does not
#        own — the one-sandlot-per-host role lock and any seed generation
#        staged under /run. Source legs assert the stated mode + the hard
#        failure; the live leg proves the semantics with two identities in one
#        shared group (a self-test pins that the probe detects the non-sticky
#        2770) and re-runs the real shape (root-owned generation file vs the
#        host's sandvmm uid) when the identities exist. The verifier leg pins
#        the seed-dir bit check: group-writable without a root-owned sticky
#        bit is a finding, and a root-owned sticky shared dir is accepted.
#   RESERVED SANDBOX UID: the k8s sandbox uid is a HOST-IDENTITY GATE
#        (vsockguard warden admission, boxout SO_PEERCRED, api_gid on the
#        sandvmm sockets), so every manifest + deploy script must state the
#        SAME reserved value, and it must sit outside the ranges the node
#        allocates on its own (> UID_MAX 60000, != nobody 65534). The pin
#        parses the manifests and the mode scripts and refuses an
#        inconsistent or collidable value (mutation: revert one site to 1001).
#   STREAM IDENTITY: the gateway binds a stream hello's node_id to
#        the presented client certificate's CN by EXACT match and refuses a
#        shared certificate by name, so every deploy path must mint a pair
#        whose CN IS the node id it configures. The certificate check dry-runs the bare-metal
#        generator through a stub openssl and reads the CN it would sign
#        (default = hostname; SANDLOT_NODE_ID=<id>; --client-cn extras); the deploy-path sweep
#        checks every deploy path for a mint that names its node id and for
#        call sites whose CN source matches the node id written into the
#        config; the k8s-manifest check parses the manifests (node id from fieldRef
#        spec.nodeName, certs from the per-node hostPath, the prov Deployment
#        on its own Secret — never the removed shared sandlot-certs); the prov-identity check pins
#        the prov identity (its own pair and its own prov.key derivation).
#
# Run: bash e2e/deploy-tree-pins.sh
# Mutation runs can point the checks at another tree via PINS_ROOT=<dir> (a
# directory holding deploy/, e2e/ and common/).
set -uo pipefail

ROOT="${PINS_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/deploy-tree-pins.XXXXXX")"
# U8_DIR is minted inside the U8 pin: the sticky-semantics probe must run from
# a world-TRAVERSABLE scratch root (its scratch identities are neither root
# nor in $WORK's 0700 tree), so it gets its own mktemp beside $WORK.
U8_DIR=""
trap 'rm -rf "$WORK" ${U8_DIR:+"$U8_DIR"}' EXIT

PASS=0
FAIL=0
pass()    { echo "  ✓ $*"; PASS=$((PASS+1)); }
fail()    { echo "  ✗ $*"; FAIL=$((FAIL+1)); }
section() { echo; echo "── $* ──"; }

ROT="$ROOT/deploy/baremetal/rotate-volume-seed.sh"

for tool in curl openssl python3 mktemp; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

# ── shared: a local HTTP stub standing in for the human gateway ──────
# GET  /stats      → 200 {"maintenance":{"refusing":true}}  (window-open probe)
# POST /human/...  → 200 (the accepted update)
# POST /refuse/... → 400 with a JSON body (the refused update)
HTTP_URL=""
start_http_stub() {
    cat > "$WORK/http-stub.py" <<'PY'
import http.server, socketserver

class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._send(200, '{"maintenance": {"refusing": true}, "prov_seeds": []}')

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        if self.path.startswith("/refuse"):
            self._send(400, '{"error": {"code": "REFUSED", "message": "pin stub refuses"}}')
            return
        self._send(200, '{"ok": true}')

    def log_message(self, *a):
        pass

with socketserver.TCPServer(("127.0.0.1", 0), H) as srv:
    print(srv.server_address[1], flush=True)
    srv.serve_forever()
PY
    python3 -I "$WORK/http-stub.py" > "$WORK/http.port" 2> "$WORK/http.err" &
    for _ in $(seq 1 50); do
        [[ -s "$WORK/http.port" ]] && break
        sleep 0.1
    done
    if [[ ! -s "$WORK/http.port" ]]; then
        fail "cannot start the HTTP stub: $(cat "$WORK/http.err" 2>/dev/null)"
        return 1
    fi
    HTTP_URL="http://127.0.0.1:$(head -1 "$WORK/http.port")"
}

# ── setup-network runtime ──────────────────────────────────────────────────────────────
pin_setup_network_runtime() {
    section "the INSTALLED setup-network.sh resolves its shared runtime"
    local inst="$WORK/k81/usr/local/bin/sandswap-setup-network"
    mkdir -p "$WORK/k81/usr/local/bin" "$WORK/k81/empty" "$WORK/k81/lib"
    cp "$ROOT/deploy/setup-network.sh" "$inst"

    # DRIFT: an installed copy with no library anywhere → non-zero + ONE named
    # line, and NOT bash's own ENOENT (the live boot failure mode).
    local out rc
    out="$(SANDSWAP_SH_LIB_DIR="$WORK/k81/empty" UPLINK=lo "$inst" 2>&1)"; rc=$?
    [[ "$rc" -ne 0 ]] && pass "no runtime → refuses (rc=$rc)" || fail "no runtime → exit 0 (should refuse)"
    printf '%s\n' "$out" | grep -qF "shared runtime not found (looked at $WORK/k81/usr/local/common/sh/runtime.sh, $WORK/k81/empty/runtime.sh) — reinstall or set SANDSWAP_SH_LIB_DIR" \
        && pass "the refusal names both looked-at paths and the remedy" \
        || fail "refusal message drifted: $out"
    printf '%s\n' "$out" | grep -q "No such file or directory" \
        && fail "the failure is still a bare bash ENOENT: $out" \
        || pass "no bare bash ENOENT"

    # LEGIT: the library at the installed location is sourced and the delegated
    # implementation runs (the stub records the arguments it received).
    cat > "$WORK/k81/lib/runtime.sh" <<'LIB'
ss_host_network_setup() {
    echo "STUB-SETUP bridge=$1 subnet=$2 gw=$3 uplink=$4 persist=${SS_NET_PERSIST:-}"
}
LIB
    out="$(SANDSWAP_SH_LIB_DIR="$WORK/k81/lib" UPLINK=lo BRIDGE=br-x SUBNET=10.9.0.0/16 GATEWAY=10.9.0.1 "$inst" 2>&1)"; rc=$?
    [[ $rc -eq 0 && "$out" == *"STUB-SETUP bridge=br-x subnet=10.9.0.0/16 gw=10.9.0.1 uplink=lo persist=1"* ]] \
        && pass "an installed copy runs the shared implementation (SANDSWAP_SH_LIB_DIR)" \
        || fail "installed-copy delegation drifted (rc=$rc): $out"

    # The repo-tree layout still wins when both exist (resolution order 1).
    mkdir -p "$WORK/k81/repo/deploy" "$WORK/k81/repo/common/sh"
    cp "$ROOT/deploy/setup-network.sh" "$WORK/k81/repo/deploy/setup-network.sh"
    cat > "$WORK/k81/repo/common/sh/runtime.sh" <<'LIB'
ss_host_network_setup() { echo "REPO-TREE-WINS $*"; }
LIB
    out="$(SANDSWAP_SH_LIB_DIR="$WORK/k81/lib" UPLINK=lo "$WORK/k81/repo/deploy/setup-network.sh" 2>&1)"; rc=$?
    [[ $rc -eq 0 && "$out" == *"REPO-TREE-WINS"* ]] \
        && pass "the repo tree is preferred over the installed location" \
        || fail "resolution order drifted (rc=$rc): $out"
}

pin_installers_ship_library() {
    section "installers ship the library; uninstall removes it"
    local f missing="" n=0
    while IFS= read -r f; do
        n=$((n + 1))
        grep -q "usr/local/lib/sandswap/runtime.sh" "$f" || missing="$missing $f"
    done < <(grep -rlE '^[[:space:]]*install .*/usr/local/bin/sandswap-setup-network' "$ROOT/deploy" --include='*.sh' 2>/dev/null)
    if [[ "$n" -eq 0 ]]; then
        fail "no installer of /usr/local/bin/sandswap-setup-network found (installer moved? pin needs updating)"
    elif [[ -z "$missing" ]]; then
        pass "every installer of the binary ($n) also installs /usr/local/lib/sandswap/runtime.sh"
    else
        fail "installer(s) missing the runtime install:$missing"
    fi
    grep -q "rm -f /usr/local/lib/sandswap/runtime.sh" "$ROOT/deploy/baremetal/uninstall.sh" \
        && pass "uninstall.sh removes the installed runtime" \
        || fail "uninstall.sh does not remove /usr/local/lib/sandswap/runtime.sh"
}

# ── log-helper resolution ──────────────────────────────────────────────────────────────
# undefined_log_helpers FILE -> the log_* names the file references but the
# runtime environment (e2e/common.sh + common/sh/runtime.sh) does not define.
# Empty output = clean; "SOURCE-FAILED" = the environment could not be built.
undefined_log_helpers() {
    local file="$1" names
    names="$(grep -oE '(tc_)?log_[a-z_]+' "$file" | sort -u | tr '\n' ' ')"
    bash -c '
        source "$1/e2e/common.sh" >/dev/null 2>&1 || { echo SOURCE-FAILED; exit 0; }
        for f in $2; do declare -F "$f" >/dev/null || printf "%s " "$f"; done
    ' _ "$ROOT" "$names"
}

pin_log_helper_resolution() {
    section "every log_* helper deploy-lib.sh calls is defined"
    # The detector proves itself first: a synthetic file referencing a MISSING
    # helper must be reported (otherwise the pin could pass vacuously).
    local drift="$WORK/k82-drift.sh" reported
    printf '#!/bin/bash\ntc_log_error "exists"\nlog_fail "does not exist"\n' > "$drift"
    reported="$(undefined_log_helpers "$drift")"
    [[ "$reported" == "log_fail " || "$reported" == "log_fail" ]] \
        && pass "the detector reports an undefined helper (self-test)" \
        || fail "detector self-test drifted: got '$reported'"
    reported="$(undefined_log_helpers "$ROOT/deploy/k8s/deploy-lib.sh")"
    [[ -z "$reported" ]] \
        && pass "every log_* helper deploy/k8s/deploy-lib.sh references is defined in its runtime environment" \
        || fail "deploy/k8s/deploy-lib.sh references undefined helper(s): $reported"
}

# ── stage targets ──────────────────────────────────────────────────────────────
# write_state FILE STAGED STAGED_FP CURRENT_FP — the adoption record shape the
# rotation script asserts against (the daemon writes this file; here the drill
# plays the daemon).
write_state() {
    python3 - "$@" <<'PY'
import json, sys
f, staged, sfp, cfp = sys.argv[1:5]
json.dump({"pid": 0, "staged": staged == "true", "staged_fingerprint": sfp,
           "current_fingerprint": cfp, "adopted_unix": 0,
           "last_transition": "pin stub", "sources": []}, open(f, "w"))
PY
}

pin_stage_targets() {
    section "--stage never targets the CURRENT generation's file"
    mkdir -p "$WORK/bd1/volumes"
    local cfg="$WORK/bd1/sandlot-prov.yaml" gen1="$WORK/bd1/gen1"
    local tool="$WORK/bd1/template-tool" state="$WORK/bd1/state.json"
    local out rc staged1 staged2 h1 hs1
    printf '%s\n' "$(openssl rand -hex 32)" > "$gen1"
    cat > "$cfg" <<EOF
gateway_addr: "127.0.0.1:9996"
roles: [prov]
volumes_dir: $WORK/bd1/volumes
provision:
  volume_seed_file: $gen1
EOF
    # Stub tool: mints random seeds (so a rewrite of an existing generation
    # file is visible in its hash) and answers the fingerprint scans the
    # script's adoption waits assert on.
    cat > "$tool" <<'TOOL'
#!/bin/bash
case "${1:-}" in
    seed-generate)
        out=""
        while [[ $# -gt 0 ]]; do
            if [[ "$1" == "--out" ]]; then out="$2"; shift 2; continue; fi
            shift
        done
        [[ -n "$out" ]] || { echo "stub: seed-generate needs --out" >&2; exit 2; }
        umask 077
        openssl rand -hex 32 > "$out"
        ;;
    volume-name)
        if [[ " $* " == *" --fingerprint "* ]]; then echo FPFIXED; else echo "sf-pin-stub"; fi
        ;;
    seed-scan)
        exit 0
        ;;
esac
exit 0
TOOL
    chmod +x "$tool"
    # The record the running instance would carry once staged (the drill plays
    # the daemon: the script waits on the RECORD, never on a sleep).
    write_state "$state" true FPFIXED ""

    # Leg 1: a default --stage mints and the running instance adopts.
    out="$(SANDSWAP_SEED_STATE_FILE="$state" bash "$ROT" --prov-config "$cfg" \
        --template-tool "$tool" --human-url "$HTTP_URL" --stage 2>&1)"; rc=$?
    staged1="$(sed -n 's/^[[:space:]]*volume_seed_next_file:[[:space:]]*//p' "$cfg")"
    [[ $rc -eq 0 ]] && pass "a default --stage mints and adopts (rc=0)" || fail "--stage failed (rc=$rc): $out"
    [[ -n "$staged1" && "$staged1" != "$gen1" ]] \
        && pass "the mint landed at a new path ($(basename "$staged1"))" \
        || fail "the mint targeted the current generation's file: '$staged1'"

    # Leg 2: promote re-points the config at the staged file (the state the
    # defect needs: the staged path BECOMES the current path).
    write_state "$state" false "" FPFIXED
    out="$(SANDSWAP_SEED_STATE_FILE="$state" bash "$ROT" --prov-config "$cfg" \
        --template-tool "$tool" --human-url "$HTTP_URL" --promote 2>&1)"; rc=$?
    [[ $rc -eq 0 ]] && pass "promote re-pointed the config (mini rotation leg 1)" || fail "promote failed (rc=$rc): $out"
    grep -qF "volume_seed_file: $staged1" "$cfg" \
        && pass "volume_seed_file now names the staged file" \
        || fail "promote did not re-point the config: $(grep volume_seed "$cfg" | tr '\n' ' ')"
    h1="$(sha256sum "$gen1" | cut -d' ' -f1)"; hs1="$(sha256sum "$staged1" | cut -d' ' -f1)"

    # Leg 2b: an explicit --seed-file pointing at the CURRENT file is refused
    # before anything is written.
    out="$(SANDSWAP_SEED_STATE_FILE="$state" bash "$ROT" --prov-config "$cfg" \
        --template-tool "$tool" --seed-file "$staged1" --stage 2>&1)"; rc=$?
    [[ $rc -ne 0 ]] \
        && pass "--stage --seed-file <the live generation file> is refused (rc=$rc)" \
        || fail "a write to the live generation file was accepted"
    printf '%s\n' "$out" | grep -q "the CURRENT generation points at it" \
        && pass "the refusal names the reason" \
        || fail "refusal message drifted: $out"

    # Leg 3: the SECOND rotation (the defect): the default mint must land at a
    # new path again, and neither earlier generation file may change.
    write_state "$state" true FPFIXED ""
    out="$(SANDSWAP_SEED_STATE_FILE="$state" bash "$ROT" --prov-config "$cfg" \
        --template-tool "$tool" --human-url "$HTTP_URL" --stage 2>&1)"; rc=$?
    staged2="$(sed -n 's/^[[:space:]]*volume_seed_next_file:[[:space:]]*//p' "$cfg")"
    [[ $rc -eq 0 ]] && pass "a SECOND --stage on the same config succeeds (rc=0)" || fail "second --stage failed (rc=$rc): $out"
    [[ -n "$staged2" && "$staged2" != "$staged1" ]] \
        && pass "the second mint landed at a new path ($(basename "$staged2"))" \
        || fail "the second mint targeted the now-live generation file: '$staged2'"
    [[ "$(sha256sum "$staged1" | cut -d' ' -f1)" == "$hs1" ]] \
        && pass "the first generation's file is byte-identical after the second stage" \
        || fail "the second stage REWROTE the file the first generation points at"
    [[ "$(sha256sum "$gen1" | cut -d' ' -f1)" == "$h1" ]] \
        && pass "the original generation file survives too" \
        || fail "the original generation file was rewritten"
}

# ── human_post status ──────────────────────────────────────────────────────────────
pin_human_post_status() {
    section "human_post fails on a non-2xx response"
    local cfg="$WORK/bd2-cfg.yaml" out rc
    printf 'roles: [prov]\n' > "$cfg"
    # DRIFT: a 400-answering gateway must fail the switch, loudly.
    out="$(bash "$ROT" --prov-config "$cfg" --template-tool /bin/true \
        --human-url "$HTTP_URL/refuse" --maintenance on 2>&1)"; rc=$?
    [[ $rc -ne 0 ]] && pass "a refused maintenance switch exits non-zero (rc=$rc)" || fail "a refused switch exited 0"
    printf '%s\n' "$out" | grep -q "answered HTTP 400" \
        && pass "the refusal surfaces the HTTP status and body" \
        || fail "no status/body surfaced: $out"
    printf '%s\n' "$out" | grep -q "maintenance ON" \
        && fail "a refused switch was reported as ON" \
        || pass "a refused switch is not reported as ON"
    # LEGIT: a 200 must still succeed and be reported.
    out="$(bash "$ROT" --prov-config "$cfg" --template-tool /bin/true \
        --human-url "$HTTP_URL" --rotation on 2>&1)"; rc=$?
    [[ $rc -eq 0 ]] && pass "an accepted rotation switch exits 0" || fail "an accepted switch failed (rc=$rc): $out"
    printf '%s\n' "$out" | grep -q "rotation window OPEN" \
        && pass "the accepted switch is reported" \
        || fail "the accepted switch was not reported: $out"
}

# ── fan-out ──────────────────────────────────────────────────────────────
pin_fanout() {
    section "--prov-hosts fan-out stages through remote mktemp paths"
    local stub="$WORK/bd3/bin" cfg="$WORK/bd3/cfg.yaml" seed="$WORK/bd3/seed"
    local elog="$WORK/bd3/ssh.log" out rc final
    mkdir -p "$stub" "$WORK/bd3"
    printf 'gateway_addr: "127.0.0.1:9996"\nroles: [prov]\nprovision:\n  volume_seed_file: /etc/sandswap/volume-seed\n' > "$cfg"
    printf '%s\n' "$(openssl rand -hex 32)" > "$seed"
    # ssh/scp stubs: record every call; answer the mktemp probes; succeed.
    # Nothing leaves the box (no ssh is ever attempted).
    cat > "$stub/ssh" <<'SSH'
#!/bin/bash
printf '%s\n' "$*" >> "${FAKE_SSH_LOG:?}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) shift 2 ;;
        -*) shift ;;
        *) break ;;
    esac
done
shift   # host
if [[ "${1:-}" == "mktemp" ]]; then
    shift
    if [[ "${1:-}" == "-p" ]]; then
        printf '%s/volume-seed-next.fake5678\n' "$2"
    else
        printf '/tmp/sandswap-seed-stage.fake1234\n'
    fi
fi
exit 0
SSH
    cat > "$stub/scp" <<'SCP'
#!/bin/bash
printf 'SCP %s\n' "$*" >> "${FAKE_SSH_LOG:?}"
exit 0
SCP
    chmod +x "$stub/ssh" "$stub/scp"
    final="$WORK/bd3/volume-seed-next.fake5678"

    out="$(PATH="$stub:$PATH" FAKE_SSH_LOG="$elog" bash "$ROT" --prov-config "$cfg" \
        --template-tool /bin/true --seed-file "$seed" --prov-hosts prov-1,prov-2 --stage 2>&1)"; rc=$?
    [[ $rc -eq 0 ]] && pass "the fan-out completes (stubbed transport, rc=0)" || fail "fan-out failed (rc=$rc): $out"
    grep -q 'mktemp /tmp/sandswap-seed-stage' "$elog" \
        && pass "the transfer path comes from a remote mktemp (never a fixed name)" \
        || fail "no remote mktemp for the transfer path: $(grep -c . "$elog") call(s) recorded"
    grep -qF "install -m 0640 /tmp/sandswap-seed-stage.fake1234 $final" "$elog" \
        && pass "the generation file is installed under the config's directory, not /tmp" \
        || fail "generation-file install missing: $(grep install "$elog" || echo '<none>')"
    grep -qF 'rm -f /tmp/sandswap-seed-stage.fake1234' "$elog" \
        && pass "the transfer file is removed after staging" \
        || fail "the transfer file is never cleaned up"
    grep -qE '\-\-seed-file[= ]/tmp/sandswap-seed-stage' "$elog" \
        && fail "the fan-out still stages the transfer file itself as the generation" \
        || pass "the staged generation is the config-directory path, not the transfer file"
    grep -qE "\-\-seed-file[= ]$final" "$elog" \
        && pass "the remote stage points at the installed generation file" \
        || fail "the remote stage did not point at $final: $(grep seed-file "$elog" || echo '<none>')"
    printf '%s\n' "$out" | grep -q 'covers exactly the hosts in --prov-hosts' \
        && pass "the local-host skip is named explicitly" \
        || fail "the local host would be skipped silently: $out"
}

# ── seed fetch ──────────────────────────────────────────────────────────────
pin_seed_fetch() {
    section "seed-fetch.sh.template refuses an unreadable config"
    local tpl="$ROOT/deploy/baremetal/seed-fetch.sh.template"
    local out rc
    mkdir -p "$WORK/bd7"
    # DRIFT: unreadable config.
    out="$(SANDSWAP_PROV_CONFIG="$WORK/bd7/does-not-exist.yaml" bash "$tpl" 2>&1)"; rc=$?
    [[ $rc -ne 0 ]] && pass "an unreadable config exits non-zero (rc=$rc)" || fail "an unreadable config reported success"
    printf '%s\n' "$out" | grep -q "cannot read the prov config" \
        && pass "the failure is named" \
        || fail "unnamed failure: $out"
    printf '%s\n' "$out" | grep -q "nothing to fetch" \
        && fail "'nothing to fetch' printed for an unreadable config" \
        || pass "no false 'nothing to fetch'"
    # DRIFT: parses-as-a-directory (the reader raises, not the regex walk).
    out="$(SANDSWAP_PROV_CONFIG="$WORK/bd7" bash "$tpl" 2>&1)"; rc=$?
    [[ $rc -ne 0 ]] && pass "a config that cannot be parsed exits non-zero (rc=$rc)" || fail "a directory-as-config reported success"
    printf '%s\n' "$out" | grep -q "cannot parse" \
        && pass "the parse failure is named" \
        || fail "parse failure unnamed: $out"
    # LEGIT: a readable config with no seed FILE key is a legitimate no-op.
    printf 'roles: [prov]\nprovision:\n  volume_seed: deadbeef\n' > "$WORK/bd7/no-file.yaml"
    out="$(SANDSWAP_PROV_CONFIG="$WORK/bd7/no-file.yaml" bash "$tpl" 2>&1)"; rc=$?
    [[ $rc -eq 0 ]] && pass "a readable config with no seed file still succeeds (no-op)" || fail "legitimate no-op now fails (rc=$rc): $out"
    printf '%s\n' "$out" | grep -q "nothing to fetch" \
        && pass "the no-op says what it did" \
        || fail "no-op message drifted: $out"
}

# ── seed-dir checks ──────────────────────────────────────────────────────
# The seed-scope predicate and the two seed self-checks of
# security/verify-host-security.sh, driven through the REAL script:
#   * SANDSWAP_VERIFY_SEED_PROBE=<file> [SANDSWAP_VERIFY_SEED_PROBE_USER=<user>]
#     runs only the read predicate and exits 1 (readable) / 0 (denied) / 2
#     (could not classify).
#   * SANDSWAP_VERIFY_SEED_CONFIGS=<cfg[:cfg]> replaces the scanned configs,
#     so the pins never touch a live /etc/sandswap.
# Nothing here writes outside $WORK (the tmpfs leg uses a scratch dir under
# /dev/shm, removed on exit).
VERIFY="$ROOT/security/verify-host-security.sh"

# run_seed_probe <file> [user] [PATH-override] -> "verdict rc"
run_seed_probe() {
    local file="$1" user="${2:-sandvmm}" path="${3:-}"
    local out rc
    out="$(PATH="${path:-$PATH}" SANDSWAP_VERIFY_SEED_PROBE="$file" \
        SANDSWAP_VERIFY_SEED_PROBE_USER="$user" bash "$VERIFY" 2>&1)"; rc=$?
    printf '%s|%s' "$(printf '%s\n' "$out" | head -1)" "$rc"
}

pin_seed_scope_predicate() {
    section "the sandvmm seed-scope predicate never passes a readable seed"
    local bin="$WORK/bd6/bin" probe="$WORK/bd6/probe"
    mkdir -p "$bin" "$probe"
    chmod 0755 "$probe"
    printf 'seed-value\n' > "$probe/seed"
    chmod 0644 "$probe/seed"

    # Stub identities make the classification deterministic on any host (the
    # real identity table is exercised in the root leg below).
    cat > "$bin/setpriv" <<'SP'
#!/bin/bash
case "${STUB_SETPRIV_MODE:?}" in
    can-read)  exec cat "${@: -1}" ;;
    denied)    shift $(( $# - 1 )); echo "cat: $1: Permission denied" >&2; exit 1 ;;
    other)     echo "setpriv: unexpected failure" >&2; exit 1 ;;
esac
SP
    chmod +x "$bin/setpriv"
    local got

    got="$(STUB_SETPRIV_MODE=can-read run_seed_probe "$probe/seed" nobody "$bin:$PATH")"
    [[ "$got" == "readable|1" ]] \
        && pass "a seed the probe identity can read is classified FAIL (rc=1)" \
        || fail "readable seed classified '$got', want 'readable|1'"

    got="$(STUB_SETPRIV_MODE=denied run_seed_probe "$probe/seed" nobody "$bin:$PATH")"
    [[ "$got" == "denied|0" ]] \
        && pass "a seed the probe identity cannot read is classified denied (rc=0)" \
        || fail "unreadable seed classified '$got', want 'denied|0'"

    got="$(STUB_SETPRIV_MODE=other run_seed_probe "$probe/seed" nobody "$bin:$PATH")"
    [[ "$got" == inconclusive*"|2" ]] \
        && pass "a probe that cannot run is 'inconclusive' (rc=2), never a pass" \
        || fail "broken probe classified '$got', want an inconclusive rc=2"

    # Live leg: this host's REAL identity table (uid/group membership decide
    # the read, not the file mode alone). The file lives in a world-traversable
    # dir: $WORK itself is 0700, and a traverse denial would make the 0644 leg
    # "denied" for the wrong reason.
    if [[ "$(id -u)" -eq 0 ]]; then
        local who=sandvmm livedir
        id -u "$who" >/dev/null 2>&1 || who=nobody
        livedir="$(mktemp -d "${TMPDIR:-/tmp}/pins-seed-live.XXXXXX")"
        chmod 0755 "$livedir"
        printf 'seed-value\n' > "$livedir/seed"
        chmod 0644 "$livedir/seed"
        got="$(run_seed_probe "$livedir/seed" "$who")"
        [[ "$got" == "readable|1" ]] \
            && pass "live (uid $who): a 0644 seed is readable → FAIL (rc=1)" \
            || fail "live readable classification drifted: '$got'"
        chmod 0600 "$livedir/seed"
        got="$(run_seed_probe "$livedir/seed" "$who")"
        [[ "$got" == "denied|0" ]] \
            && pass "live (uid $who): an owner-only seed is denied (rc=0)" \
            || fail "live denied classification drifted: '$got'"
        rm -rf "$livedir"
    else
        echo "  – live identity-table leg skipped (needs root for setpriv)"
    fi
}

pin_tmpfs_mode_unparsable() {
    section "an unparsable tmpfs seed-dir mode is never reported as ok"
    local shm="${TMPDIR_SHM_FOR_PINS:-/dev/shm}"
    if [[ ! -w "$shm" ]]; then
        echo "  – skipped: $shm is not writable"
        return
    fi
    local dir seed bin out rc real
    dir="$(mktemp -d "$shm/deploy-tree-pins.XXXXXX")"
    chmod 0755 "$dir"
    seed="$dir/seed"
    printf 'seed-value\n' > "$seed"
    bin="$WORK/hs1/bin"
    mkdir -p "$bin"
    cat > "$bin/stat" <<'STAT'
#!/bin/bash
# Garble the mode of ONE path (the pin's tmpfs dir) and delegate everything
# else to the real stat — the unparsable-mode branch must be reachable without
# a broken host (a busybox stat, a vanished file, a TOCTOU).
if [[ "$*" == *"-c %a"* && "${@: -1}" == "${SEED_PIN_GARBLE:?}" ]]; then
    if [[ "${SEED_PIN_MODE_EMPTY:-0}" == "1" ]]; then exit 1; fi
    printf 'zzz\n'
    exit 0
fi
exec /usr/bin/stat "$@"
STAT
    chmod +x "$bin/stat"
    real="/usr/bin/stat"
    [[ -x "$real" ]] || real="$(command -v stat)"

    # Control: with the real stat the check RUNS and reports the (good) shape.
    out="$(SEED_CHECK="$seed" SANDSWAP_VERIFY_SEED_CONFIGS="" PATH="$PATH" bash "$VERIFY" 2>&1)"; rc=$?
    printf '%s\n' "$out" | grep -q "the seed's tmpfs directory is not world-writable ($dir" \
        && pass "control: a 0755 tmpfs seed dir is checked and reported" \
        || fail "control leg drifted — the tmpfs check did not run: $(printf '%s\n' "$out" | grep -i tmpfs | head -2)"

    # DRIFT: a garbage mode must produce a warning, never the ok branch.
    out="$(SEED_CHECK="$seed" SANDSWAP_VERIFY_SEED_CONFIGS="" SEED_PIN_GARBLE="$dir" \
        PATH="$bin:$PATH" bash "$VERIFY" 2>&1)"; rc=$?
    printf '%s\n' "$out" | grep -q "cannot parse the mode of $dir" \
        && pass "a garbage mode is named as unparsable" \
        || fail "no unparsable-mode warning: $(printf '%s\n' "$out" | grep -i "$dir" | head -2)"
    printf '%s\n' "$out" | grep -q "not world-writable ($dir" \
        && fail "an unparsable mode was reported as 'not world-writable' (the vacuous pass is back)" \
        || pass "an unparsable mode never reads as a pass"

    # DRIFT: stat failing outright (empty output) is the same class.
    out="$(SEED_CHECK="$seed" SANDSWAP_VERIFY_SEED_CONFIGS="" SEED_PIN_GARBLE="$dir" \
        SEED_PIN_MODE_EMPTY=1 PATH="$bin:$PATH" bash "$VERIFY" 2>&1)"; rc=$?
    printf '%s\n' "$out" | grep -q "not world-writable ($dir" \
        && fail "a failed stat was reported as 'not world-writable'" \
        || pass "a failed stat never reads as a pass"
    rm -rf "$dir"
}

pin_seed_config_parse() {
    section "seed-file keys parse like the Go loader, and a named path is never skipped"
    local d="$WORK/hs2"
    mkdir -p "$d"
    chmod 0755 "$d"
    printf 'seed-value\n' > "$d/seed-sq"
    printf 'seed-value\n' > "$d/seed-dq"
    printf 'seed-value\n' > "$d/seed-cm"
    local out rc form cfg

    # The three drift forms an operator's editor produces: without the real
    # YAML parse the path kept its quotes (or its trailing comment) and the
    # loop skipped it in silence.
    local -A forms=(
        [single-quoted]="  volume_seed_file: '$d/seed-sq'"
        [double-quoted]="  volume_seed_file: \"$d/seed-dq\""
        [trailing-comment]="  volume_seed_file: $d/seed-cm   # staged generation"
    )
    for form in single-quoted double-quoted trailing-comment; do
        cfg="$d/cfg-$form.yaml"
        printf 'roles: [prov]\nprovision:\n%s\n' "${forms[$form]}" > "$cfg"
        out="$(SEED_CHECK=/nonexistent/seed SANDSWAP_VERIFY_SEED_CONFIGS="$cfg" \
            bash "$VERIFY" 2>&1)"; rc=$?
        local named="${forms[$form]##*volume_seed_file: }"
        named="${named%% *}"
        named="${named%\'}"; named="${named#\'}"
        named="${named%\"}"; named="${named#\"}"
        printf '%s\n' "$out" | grep -qF "$named" \
            && pass "$form: the path is CHECKED (reported by name)" \
            || fail "$form: the path was silently dropped: $(printf '%s\n' "$out" | tail -3)"
        # …and it must be checked AS A FILE: a parser that leaves YAML syntax
        # in the value lands on the "not readable files" finding instead (the
        # substring assertion above would not notice — the quoted path still
        # contains the expected substring).
        printf '%s\n' "$out" | grep -qE "not readable files:.*$(basename "$named")" \
            && fail "$form: YAML syntax was kept in the path (checked as a non-file, not as the seed)" \
            || pass "$form: the parsed value is the real file path"
        printf '%s\n' "$out" | grep -q "no volume-name seed found at /nonexistent/seed$" \
            && fail "$form: the run ended on the bare 'no seed found' skip line" \
            || pass "$form: the run did not degrade to the skip line"
    done

    # A path the config names that does not exist is a finding, not a skip.
    printf 'roles: [prov]\nprovision:\n  volume_seed_file: %s/missing\n' "$d" > "$d/cfg-missing.yaml"
    out="$(SEED_CHECK=/nonexistent/seed SANDSWAP_VERIFY_SEED_CONFIGS="$d/cfg-missing.yaml" \
        bash "$VERIFY" 2>&1)"; rc=$?
    printf '%s\n' "$out" | grep -q "names seed path(s) that are not readable files: $d/missing" \
        && pass "a named-but-missing seed path FAILS loudly" \
        || fail "a named-but-missing path was skipped silently: $(printf '%s\n' "$out" | tail -3)"

    # A config that cannot be parsed at all is loudly refused, not skipped.
    printf 'provision:\n  volume_seed_file: [unclosed\n' > "$d/cfg-broken.yaml"
    out="$(SEED_CHECK=/nonexistent/seed SANDSWAP_VERIFY_SEED_CONFIGS="$d/cfg-broken.yaml" \
        bash "$VERIFY" 2>&1)"; rc=$?
    printf '%s\n' "$out" | grep -q "cannot parse the prov/sandlot config" \
        && pass "an unparsable config is named (its keys were NOT checked)" \
        || fail "an unparsable config was skipped silently: $(printf '%s\n' "$out" | tail -3)"
}


# ── runtime dir sticky ───────────────────────────────────────────────────────────────
# /run/sandswap is shared by identities that must not be able to remove each
# other's entries; the mode must be STICKY and the setup path must fail hard
# rather than leave it off. See the header.
U8_DIR=""

# u8_mode_from_source — the mode the setup path STATES for /run/sandswap.
u8_mode_from_source() {
    sed -nE 's|^d /run/sandswap ([0-9]+) .*|\1|p' "$ROOT/deploy/baremetal/setup-host.sh" | head -1
}

# u8_probe <mode> — prints "<own-removed> <foreign-removed>" after applying
# <mode> to a scratch dir owned by root with one shared group. ua (the group)
# creates `own` + `victim`; ub (a DIFFERENT uid, same group) creates a file
# first to PROVE it has directory write, then tries to remove ua's `victim`.
# "denied" must mean sticky, never "could not write". The scratch tree is
# 0755/traversable by construction: the probe identities are neither root nor
# in $WORK's 0700 tree, so a 0700 parent would deny them for the wrong reason.
u8_probe() {
    local mode="$1" d="$U8_DIR/run" ua=20011 ub=20012 rmbin
    rmbin="$(command -v rm)" || return 9
    rm -rf "$d"; mkdir -p "$d" || return 9
    chown "root:$ua" "$d" || return 9
    chmod "$mode" "$d" || return 9
    setpriv --reuid="$ua" --regid="$ua" --clear-groups -- sh -c "printf x > '$d/own' && printf v > '$d/victim'" || return 9
    setpriv --reuid="$ub" --regid="$ua" --clear-groups -- sh -c "printf y > '$d/foreign-writable'" || return 9
    [[ -f "$d/foreign-writable" ]] || return 9
    local own=no foreign=no
    setpriv --reuid="$ub" --regid="$ua" --clear-groups -- "$rmbin" -f "$d/victim" 2>/dev/null && foreign=yes
    setpriv --reuid="$ua" --regid="$ua" --clear-groups -- "$rmbin" -f "$d/own" 2>/dev/null && own=yes
    printf '%s %s\n' "$own" "$foreign"
}

pin_runtime_dir_sticky() {
    section "/run/sandswap is sticky; the setup path fails hard"
    local mode line
    mode="$(u8_mode_from_source)"
    [[ "$mode" == "3770" ]] \
        && pass "setup-host.sh's tmpfiles entry states 3770 (sticky)" \
        || fail "setup-host.sh's tmpfiles entry states '${mode:-<none>}', expected 3770 (without sticky, directory write alone lets one shared-group identity unlink another's entries)"
    line="$(grep -E 'install -d -m [0-9]+ -o root -g .* /run/sandswap$' "$ROOT/common/sh/runtime.sh" | head -1)"
    [[ "$line" == *"-m 3770"* ]] \
        && pass "ss_prepare_dirs installs /run/sandswap 3770 (sticky)" \
        || fail "ss_prepare_dirs does not install the sticky mode: '${line:-<none>}'"
    if grep -qE 'systemd-tmpfiles --create /usr/lib/tmpfiles\.d/sandswap\.conf.*\|\| true' "$ROOT/deploy/baremetal/setup-host.sh"; then
        fail "the tmpfiles application is swallowed (|| true) — a dropped sticky bit would go unnoticed"
    else
        pass "the tmpfiles application is a hard error (not swallowed)"
    fi
    grep -q 'expected 3770' "$ROOT/deploy/baremetal/setup-host.sh" \
        && pass "setup-host.sh asserts the landed mode (stat == 3770)" \
        || fail "setup-host.sh does not assert the landed mode"

    # ── live semantics ──
    if [[ "$(id -u)" -ne 0 ]] || ! command -v setpriv >/dev/null 2>&1; then
        echo "  – U8 live sticky-semantics leg skipped (needs root + setpriv)"
        return
    fi
    U8_DIR="$(mktemp -d "${TMPDIR:-/tmp}/deploy-tree-pins-u8.XXXXXX")"
    chmod 0755 "$U8_DIR"
    # The probe proves itself first: at the pre-fix 2770 the FOREIGN removal
    # MUST succeed — otherwise the probe is blind on this host and the leg
    # below could pass vacuously.
    local got
    got="$(u8_probe 2770)" || { fail "the U8 probe could not set up its scratch dirs (got '$got')"; return; }
    [[ "$got" == "yes yes" ]] \
        && pass "self-test: the probe detects the 2770 defect (a sibling identity CAN remove a foreign entry without sticky)" \
        || fail "self-test: the probe is blind — at 2770 it reported '$got' (want 'yes yes')"

    got="$(u8_probe "${mode:-3770}")" || { fail "the U8 probe could not set up its scratch dirs (got '$got')"; return; }
    [[ "$got" == "yes no" ]] \
        && pass "live: at the source-stated ${mode:-3770} an owner removes its own entry and a sibling identity CANNOT remove a foreign one" \
        || fail "live: at ${mode:-3770} the probe reported '$got' (want 'yes no': own=yes foreign=no)"

    # Real shape: root-owned generation file inside a root:<sandlot> dir; the
    # host's own sandvmm uid must not be able to take it away.
    local sandlot_gid sandvmm_uid d
    sandlot_gid="$(getent group sandlot 2>/dev/null | cut -d: -f3 || true)"
    sandvmm_uid="$(id -u sandvmm 2>/dev/null || true)"
    if [[ -n "$sandlot_gid" && -n "$sandvmm_uid" ]]; then
        d="$U8_DIR/live"; rm -rf "$d"; mkdir -p "$d"
        chown "root:$sandlot_gid" "$d"; chmod "${mode:-3770}" "$d"
        printf 'seed-value\n' > "$d/gen-1"
        chown root:root "$d/gen-1"; chmod 0640 "$d/gen-1"
        if setpriv --reuid="$sandvmm_uid" --regid="$sandlot_gid" --clear-groups -- "$(command -v rm)" -f "$d/gen-1" 2>/dev/null; then
            fail "the sandvmm identity (uid $sandvmm_uid) REMOVED a root-owned generation file from the ${mode:-3770} dir"
        else
            pass "the sandvmm identity (uid $sandvmm_uid) cannot remove a root-owned generation file from the ${mode:-3770} dir"
        fi
        [[ -f "$d/gen-1" ]] || fail "the generation file did not survive the attempted removal"
    else
        echo "  – U8 real-shape leg skipped (no sandlot group / sandvmm user on this host)"
    fi
    rm -rf "$U8_DIR"

    # ── the verifier's seed-dir bit check ──
    # Drives security/verify-host-security.sh through its SEED_CHECK override:
    # a GROUP-writable tmpfs dir is a finding (the old check read only the
    # others-write bit), a root-owned STICKY shared dir is accepted, and a
    # plain 0755 dir stays the control. Only the printed lines are asserted
    # (the scratch seed's group is not sandprov, so the overall rc is
    # irrelevant to these legs).
    local shm="${TMPDIR_SHM_FOR_PINS:-/dev/shm}"
    if [[ -w "$shm" ]]; then
        local vd out
        vd="$(mktemp -d "$shm/deploy-tree-pins-u8.XXXXXX")"
        chmod 0755 "$vd"
        mkdir "$vd/group0770" "$vd/sticky3770" "$vd/plain0755"
        chown root:root "$vd/group0770" "$vd/plain0755" 2>/dev/null || true
        chown root:root "$vd/sticky3770" 2>/dev/null || true
        chmod 0770 "$vd/group0770"
        chmod 3770 "$vd/sticky3770"
        chmod 0755 "$vd/plain0755"
        printf 'seed\n' > "$vd/group0770/seed"
        printf 'seed\n' > "$vd/sticky3770/seed"
        printf 'seed\n' > "$vd/plain0755/seed"

        out="$(SEED_CHECK="$vd/group0770/seed" SANDSWAP_VERIFY_SEED_CONFIGS="" bash "$VERIFY" 2>&1)"
        printf '%s\n' "$out" | grep -q "$vd/group0770 (the seed's directory on tmpfs) is group/world-writable" \
            && pass "verifier: a GROUP-writable seed dir is a finding (the others-write-only check was the false green)" \
            || fail "verifier: a group-writable seed dir was not flagged: $(printf '%s\n' "$out" | grep -i "seed's tmpfs directory" | head -2)"

        out="$(SEED_CHECK="$vd/sticky3770/seed" SANDSWAP_VERIFY_SEED_CONFIGS="" bash "$VERIFY" 2>&1)"
        printf '%s\n' "$out" | grep -q "STICKY and root-owned ($vd/sticky3770, 3770)" \
            && pass "verifier: a root-owned STICKY shared dir (the /run/sandswap shape) is accepted" \
            || fail "verifier: the sticky shared shape was not accepted: $(printf '%s\n' "$out" | grep -i "seed's tmpfs directory" | head -2)"

        out="$(SEED_CHECK="$vd/plain0755/seed" SANDSWAP_VERIFY_SEED_CONFIGS="" bash "$VERIFY" 2>&1)"
        printf '%s\n' "$out" | grep -q "the seed's tmpfs directory is not world-writable ($vd/plain0755" \
            && pass "verifier: control — a 0755 seed dir still reports clean" \
            || fail "verifier: the 0755 control drifted: $(printf '%s\n' "$out" | grep -i "seed's tmpfs directory" | head -2)"
        rm -rf "$vd"
    else
        echo "  – U8 verifier leg skipped: $shm is not writable"
    fi
}

# ── stream identity ─────────────────────────────────────────────────────────
# STREAM IDENTITY (the deploy-side half of the gateway's per-node binding).
# gateway/stream/server.go verifyNodeIdentity refuses a stream hello whose
# declared node_id differs from the presented client certificate's CN, and a
# deployment-wide certificate is refused by name — so EVERY deploy path must
# (a) mint a client pair whose CN IS the node id that instance will declare,
# and (b) point the instance's tls block at exactly that pair. These pins are
# the RED-provable guard: the generator check dry-runs it through a stub openssl
# and reads the CN it would actually sign; the deploy-path sweep checks every path for a
# mint that names its node id; the k8s-manifest check parses the manifests (node id from
# spec.nodeName + per-node hostPath, never the shared Secret); the prov-identity check pins the
# prov identity (its own pair, its own prov.key derivation).

# expect_grep <file> <regex> <description> — pass when the file matches.
expect_grep() {
    local f="$1" re="$2" desc="$3" rc=0
    if [[ ! -f "$f" ]]; then
        fail "$desc: $f is missing"
        return
    fi
    # `--`: patterns legitimately start with "-" (flag literals like
    # `--client-cn "$ID"`), which grep would otherwise read as an option.
    grep -qE -- "$re" "$f"; rc=$?
    if [[ $rc -eq 0 ]]; then
        pass "$desc"
    elif [[ $rc -eq 1 ]]; then
        fail "$desc — no line matches /$re/ in ${f#"$ROOT"/}"
    else
        fail "$desc — grep could not run (rc=$rc): bad pattern /$re/?"
    fi
}

# expect_fixed <file> <literal> <description> — pass when the file contains
# the literal text (long sed expressions; regex escaping would be noise).
expect_fixed() {
    local f="$1" lit="$2" desc="$3" rc=0
    if [[ ! -f "$f" ]]; then
        fail "$desc: $f is missing"
        return
    fi
    grep -qF -- "$lit" "$f"; rc=$?
    if [[ $rc -eq 0 ]]; then
        pass "$desc"
    else
        fail "$desc — literal not found in ${f#"$ROOT"/}: $lit"
    fi
}

# reject_grep <file> <regex> <description> — pass when the file does NOT match.
reject_grep() {
    local f="$1" re="$2" desc="$3" rc=0
    if [[ ! -f "$f" ]]; then
        fail "$desc: $f is missing"
        return
    fi
    grep -qE -- "$re" "$f"; rc=$?
    if [[ $rc -eq 1 ]]; then
        pass "$desc"
    elif [[ $rc -eq 0 ]]; then
        fail "$desc — matches /$re/ in ${f#"$ROOT"/}: $(grep -nE -- "$re" "$f" | head -1)"
    else
        fail "$desc — grep could not run (rc=$rc): bad pattern /$re/?"
    fi
}

pin_generator_cn() {
    section "bare-metal generator signs CN == the node id (dry mint)"
    local d="$WORK/si1" out log
    mkdir -p "$d/bin" "$d/certs-default" "$d/certs-node" "$d/certs-extra"
    # Stub openssl: record the argv and create the -out/-keyout files the
    # script later chmods and lists. Nothing is signed; the SUBJECT is what
    # this pin reads (the value that becomes the certificate's CN).
    cat > "$d/bin/openssl" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "$SANDLOT_STUB_LOG"
prev=""; out=""; keyout=""
for a in "$@"; do
    case "$prev" in
        -out) out="$a" ;;
        -keyout) keyout="$a" ;;
    esac
    prev="$a"
done
[[ -n "$keyout" ]] && : > "$keyout"
[[ -n "$out" ]] && : > "$out"
exit 0
STUB
    cat > "$d/bin/hostname" <<'STUB'
#!/bin/bash
echo "stub-node-42"
STUB
    chmod +x "$d/bin/openssl" "$d/bin/hostname"
    GEN="$ROOT/deploy/baremetal/gen-baremetal-certs.sh"

    # (1) DEFAULT: the CN must be the hostname — the sandlot's own -node-id
    # default — never a constant.
    log="$d/log-default"; : > "$log"
    out="$(PATH="$d/bin:$PATH" SANDLOT_STUB_LOG="$log" bash "$GEN" "$d/certs-default" 2>&1)"; local rc=$?
    if [[ $rc -ne 0 ]]; then
        fail "the dry mint failed (rc=$rc): $(printf '%s\n' "$out" | tail -3)"
        return
    fi
    if grep -q -- '-subj /O=Sandswap/CN=stub-node-42$' "$log"; then
        pass "default CN is the node id source (\$(hostname) → stub-node-42)"
    else
        fail "default client CN is not the hostname — what the sandlot block signed: $(grep -B1 -- '-keyout .*/sandlot\.key' "$log" | tr '\n' ' ')"
    fi
    reject_grep "$log" '-subj /O=Sandswap/CN=sandlot-client( |$)|-subj /O=Sandswap/CN=sandlot( |$)' \
        "no client pair is signed with a constant CN"

    # (2) SANDLOT_NODE_ID=<node> → CN is EXACTLY that node id (the sandlot
    # composes `<node_id>-<instance.id>` itself; the deployer must pass the
    # composed value, so this pin asserts exactness, not a prefix).
    log="$d/log-node"; : > "$log"
    PATH="$d/bin:$PATH" SANDLOT_STUB_LOG="$log" SANDLOT_NODE_ID="node-1" \
        bash "$GEN" "$d/certs-node" >/dev/null 2>&1
    if grep -q -- '-subj /O=Sandswap/CN=node-1$' "$log"; then
        pass "SANDLOT_NODE_ID=node-1 → CN=node-1 (exact)"
    else
        fail "SANDLOT_NODE_ID was ignored — log: $(grep -- '-subj' "$log" | tr '\n' ' ')"
    fi

    # (3) --client-cn mints ONE EXTRA pair per node id, same CA, CN = that id.
    log="$d/log-extra"; : > "$log"
    PATH="$d/bin:$PATH" SANDLOT_STUB_LOG="$log" SANDLOT_NODE_ID="node-1" \
        bash "$GEN" "$d/certs-extra" --client-cn sandlot-prov --client-cn other-node >/dev/null 2>&1
    local ok=1 n
    for n in sandlot-prov other-node; do
        grep -q -- "-subj /O=Sandswap/CN=${n}\$" "$log" || { ok=0; fail "extra pair for '$n': CN not signed as '$n'"; }
        [[ -f "$d/certs-extra/sandlot-${n}.crt" && -f "$d/certs-extra/sandlot-${n}.key" ]] || { ok=0; fail "extra pair for '$n': sandlot-${n}.crt/.key not written"; }
    done
    [[ $ok -eq 1 ]] && pass "--client-cn (repeatable) mints sandlot-<node>.crt/.key with CN=<node> for every id"
}

pin_deploy_paths() {
    section "every deploy path mints a pair FOR the node id it configures"
    # (a) The old shared constant must be gone from the whole deploy tree.
    local hits
    hits="$(grep -rn 'CN=sandlot-client' "$ROOT/deploy" --include='*.sh' || true)"
    [[ -z "$hits" ]] \
        && pass "no deploy script signs a client pair with a constant CN" \
        || fail "a shared constant CN is back: $hits"

    # (b) Every invoker of the generator names the node id it mints for.
    local f n=0 missing=""
    while IFS= read -r f; do
        n=$((n+1))
        grep -q 'SANDLOT_NODE_ID' "$f" || missing="$missing ${f#"$ROOT"/}"
    done < <(grep -rlE '(bash |GEN=).*gen-baremetal-certs\.sh' "$ROOT/deploy" --include='*.sh' \
                | grep -v 'gen-baremetal-certs.sh$')
    if [[ $n -eq 0 ]]; then
        fail "no invoker of gen-baremetal-certs.sh found (the mint moved? pin needs updating)"
    elif [[ -z "$missing" ]]; then
        pass "all $n generator invokers name the node id (SANDLOT_NODE_ID)"
    else
        fail "invoker(s) mint a client pair without naming the node id:$missing"
    fi

    # (c) Each deployer's CN source must EQUAL the node id it writes into the
    # config — one literal per path, compared here so a drift is caught at pin
    # time instead of at the gateway handshake.
    local s="$ROOT/deploy/baremetal"
    expect_grep "$s/deploy-single-node.sh" 'SANDLOT_NODE_ID="\$\(hostname\)"' \
        "deploy-single-node.sh mints the pair for \$(hostname) (its empty node_id resolves to the hostname)"
    expect_grep "$s/deploy-one-machine-etcd.sh" 'EXEC_CERT_CN="\$\{NODE_ID\}-\$\{INSTANCE\}"' \
        "deploy-one-machine-etcd.sh composes the exec CN as <node_id>-<instance.id>"
    expect_grep "$s/deploy-one-machine-etcd.sh" 'SANDLOT_NODE_ID="\$EXEC_CERT_CN"' \
        "deploy-one-machine-etcd.sh mints the exec pair for the COMPOSED node id"
    expect_grep "$s/deploy-one-machine-etcd.sh" '--client-cn "\${PROV_NODE_ID}:prov"' \
        "deploy-one-machine-etcd.sh mints a role/prov pair for the prov node id"
    expect_grep "$s/deploy-cluster-one-gw.sh" 'SANDLOT_NODE_ID="\$primary"' \
        "deploy-cluster-one-gw.sh mints the primary pair for the first config entry's node id"
    expect_grep "$s/deploy-cluster-one-gw.sh" 'extra_args\+=\(--client-cn "\$\{n\}:prov"\)' \
        "deploy-cluster-one-gw.sh mints a role/granting pair per remaining node id (prov node gets role/prov)"
    expect_grep "$s/deploy-cluster-one-gw.sh" 'sandlot_cert_base\(\)' \
        "deploy-cluster-one-gw.sh derives each config's tls pair from its node id"
    expect_grep "$s/deploy-cluster-multi-gw.sh" 'extra_args\+=\(--client-cn "\$\{n\}:prov"\)' \
        "deploy-cluster-multi-gw.sh mints a role-granting pair per node id (prov node gets role/prov)"
    expect_grep "$s/deploy-cluster-one-gw-simulation.sh" 'sim_cn_args.=\(--client-cn' \
        "the one-gw simulation mints a pair per instance node id"
    expect_grep "$s/deploy-cluster-multi-gw-simulation.sh" '--client-cn "\$\{PROV_NODE_ID\}:prov"' \
        "the multi-gw simulation mints a role/prov pair for the prov node id"
    expect_grep "$s/verify-binpack.sh" 'SANDLOT_NODE_ID="\$\{BP_NODE_IDS\[0\]\}"' \
        "verify-binpack.sh mints for the effective (instance-suffixed) node ids"
    expect_grep "$s/verify-failover.sh" 'SANDLOT_NODE_ID="\$FO_NODE_ID"' \
        "verify-failover.sh mints for its declared node id"
    expect_grep "$s/verify-cert-rotation.sh" 'SANDLOT_NODE_ID="\$EXEC_CERT_CN"' \
        "verify-cert-rotation.sh re-mints the SAME per-node identities"

    # (d) The config generator's tls block must be parameterized (a bare
    # sandlot.crt would silently point every instance at one node's pair).
    expect_fixed "$ROOT/deploy/baremetal/common.sh" 'cert: ${tls_dir}/${cert_base}.crt' \
        "sandswap_generate_sandlot_config writes the tls block from SANDSWAP_SANDLOT_CERT_BASE"
    reject_grep "$ROOT/deploy/baremetal/common.sh" '^  cert: \$\{tls_dir\}/sandlot\.crt$' \
        "the generator no longer hardcodes sandlot.crt"

    # (e) Each minting deploy path ASSERTS the CN at deploy time (the gateway
    # refusal is the backstop, not the first report: a deploy-time failure
    # names the node id and the fix).
    for f in deploy-single-node.sh deploy-one-machine-etcd.sh \
             deploy-cluster-one-gw.sh deploy-cluster-one-gw-simulation.sh \
             deploy-cluster-multi-gw-simulation.sh verify-binpack.sh verify-failover.sh; do
        expect_grep "$s/$f" 'sandswap_verify_client_cert_cn' \
            "$f: asserts the minted CN == its node id at deploy time"
    done
}

pin_k8s_identity() {
    section "k8s manifests bind node_id to spec.nodeName with a per-node cert"
    local y="$ROOT/deploy/k8s"
    # Structural assertions on the DaemonSets (yaml-parsed, not grepped):
    # the node id comes from fieldRef spec.nodeName and /certs is fed by the
    # per-node hostPath — never by a Secret shared across nodes.
    local out
    out="$(python3 - "$y/sandlot.yaml" "$y/sandlot-boxout.yaml" "$y/sandlot-prov.yaml" <<'PY' 2>&1
import sys, yaml
ok = []
fail = []
def spec(path):
    d = [x for x in yaml.safe_load_all(open(path)) if x][-1]
    return d, d["spec"]["template"]["spec"]
for path in sys.argv[1:4]:
    name = path.rsplit("/", 1)[1]
    d, ps = spec(path)
    cname = "sandlot" if "prov" not in name else "sandlot-prov"
    c = [x for x in ps["containers"] if x["name"] == cname][0]
    args = c.get("args", []) or []
    env = {e["name"]: e for e in (c.get("env") or [])}
    # node id must be an ARG (not left to the hostname/pod-name default)
    node_args = [a for a in args if a.startswith("--node-id=")]
    if not node_args:
        fail.append(f"{name}: container {cname} has no --node-id arg (node id would default to the pod name, which changes on every restart)")
    # the cert source must be the per-node hostPath (or, for prov, its own Secret)
    vols = {v["name"]: v for v in ps["volumes"]}
    hosts = [v for v in vols.values() if "hostPath" in v and v["hostPath"].get("path") == "/etc/sandswap/stream-certs"]
    prov_secret = [v for v in vols.values() if v.get("secret", {}).get("secretName") == "sandlot-certs-prov"]
    shared_secret = [v for v in vols.values() if v.get("secret", {}).get("secretName") == "sandlot-certs"]
    if shared_secret:
        fail.append(f"{name}: still mounts the shared Secret sandlot-certs (the gateway refuses a shared client certificate)")
    if "prov" in name:
        if not prov_secret:
            fail.append(f"{name}: does not mount its own Secret sandlot-certs-prov")
        if node_args != ["--node-id=sandlot-prov"]:
            fail.append(f"{name}: node id arg is {node_args}, want --node-id=sandlot-prov (the CN of sandlot-certs-prov)")
    else:
        if not hosts:
            fail.append(f"{name}: no volume mounts the per-node hostPath /etc/sandswap/stream-certs")
        if node_args != ["--node-id=$(SANDSWAP_NODE_NAME)"]:
            fail.append(f"{name}: node id arg is {node_args}, want --node-id=$(SANDSWAP_NODE_NAME)")
        if env.get("SANDSWAP_NODE_NAME", {}).get("valueFrom", {}).get("fieldRef", {}).get("fieldPath") != "spec.nodeName":
            fail.append(f"{name}: SANDSWAP_NODE_NAME is not sourced from fieldRef spec.nodeName")
for line in ok:
    print("OK " + line)
for line in fail:
    print("FAIL " + line)
sys.exit(1 if fail else 0)
PY
)"; local rc=$?
    if [[ $rc -eq 0 ]]; then
        pass "sandlot.yaml + sandlot-boxout.yaml: --node-id from spec.nodeName, certs from the per-node hostPath"
        pass "sandlot-prov.yaml: fixed --node-id=sandlot-prov with its own Secret (no shared cluster certificate)"
    else
        while IFS= read -r line; do
            [[ -n "$line" ]] && fail "${line#FAIL }"
        done <<< "$(printf '%s\n' "$out" | grep '^FAIL ')"
    fi

    # The generator must mint PER NODE (CN=<node>), one Secret per node.
    expect_grep "$y/gen-k8s-certs.sh" 'mint_client_pair "sandlot-\$\{n\}" "\$n"' \
        "gen-k8s-certs.sh mints one pair per node (CN=<node>)"
    expect_grep "$y/gen-k8s-certs.sh" 'NODE_SECRETS\+=\("sandlot-certs-\$\{n\} sandlot-\$\{n\}"\)' \
        "gen-k8s-certs.sh publishes one Secret per node (sandlot-certs-<node>)"
    expect_grep "$y/gen-k8s-certs.sh" 'mint_client_pair "sandlot-\$\{PROV_NODE_ID\}" "\$PROV_NODE_ID"' \
        "gen-k8s-certs.sh mints the prov singleton pair (CN=sandlot-prov)"
    reject_grep "$y/gen-k8s-certs.sh" 'CN=sandlot-client' \
        "the k8s generator no longer signs the shared CN=sandlot-client"

    # The host fetcher writes the pair with enforced modes and proves the CN.
    expect_grep "$y/k8s-host-setup.sh" 'secret="sandlot-certs-\$\{node\}"' \
        "k8s-host-setup.sh fetches THIS node's Secret"
    expect_grep "$y/k8s-host-setup.sh" 'install -m 0600 -o "\$owner_uid" -g "\$owner_gid"' \
        "k8s-host-setup.sh installs the client key 0600 owner-only (with an existing group — install -g rejects a bare numeric gid)"
    expect_grep "$y/k8s-host-setup.sh" 'carries CN=.*but this node.s id is' \
        "k8s-host-setup.sh asserts CN == node name on what landed"
    expect_grep "$y/deploy-lib.sh" '^k8s_phase_stream_certs\(\)' \
        "deploy-lib.sh has a per-node stream-cert phase"
    expect_grep "$y/deploy-lib.sh" 'k8s_phase_stream_certs$' \
        "the deploy flow runs the per-node stream-cert phase"
}

pin_prov_identity() {
    section "the prov instance loads ITS OWN pair (and its own key copy)"
    local s="$ROOT/deploy/baremetal" f
    # Every deployer that writes a dedicated prov config derives prov.key from
    # the PROV node's pair, and re-points the config's key line at it.
    for f in deploy-one-machine-etcd.sh deploy-cluster-one-gw.sh deploy-cluster-multi-gw.sh \
             deploy-cluster-one-gw-simulation.sh deploy-cluster-multi-gw-simulation.sh verify-binpack.sh; do
        if grep -q 'sandlot-prov\.yaml' "$s/$f"; then
            expect_grep "$s/$f" 'PROV_CERT_BASE' "$f: derives the prov pair name from the prov node id"
            expect_grep "$s/$f" 'prov\.key' "$f: re-points the prov config's key at prov.key"
        fi
    done
    # prepare_provision_host copies prov.key from the POINTED-AT pair, not the
    # primary one (its 3rd arg), and names the missing case instead of skipping.
    expect_fixed "$ROOT/deploy/baremetal/common.sh" 'cp -f "$cert_dir/${cert_base}.key" "$cert_dir/prov.key"' \
        "sandswap_prepare_provision_host copies the prov node's key into prov.key"
    expect_grep "$ROOT/deploy/baremetal/common.sh" 'prov\.key was NOT refreshed' \
        "sandswap_prepare_provision_host names a missing source pair instead of skipping silently"
    # The runtime assertion helper exists and is called at install time.
    expect_grep "$ROOT/deploy/baremetal/common.sh" '^sandswap_verify_client_cert_cn\(\)' \
        "sandswap_verify_client_cert_cn exists (deploy-time CN assertion)"
    expect_fixed "$ROOT/deploy/baremetal/common.sh" "sed -n 's/.*CN *= *\\([^,]*\\).*/\\1/p'" \
        "the assertion reads the CN from the certificate, not from a filename convention"
    expect_grep "$s/deploy-cluster-one-gw.sh" 'sandswap_verify_client_cert_cn' \
        "deploy-cluster-one-gw.sh asserts the installed CN at install time"
}

# ── reserved sandbox uid ──────────────────────────────────────────────────────────────
pin_reserved_sandbox_uid() {
    section "the k8s shapes pin a RESERVED sandbox uid (never a collidable one)"
    local y="$ROOT/deploy/k8s" out rc
    # The k8s sandlot uid is a HOST-IDENTITY GATE, not pod cosmetics: vsockguard
    # admits exactly this uid to the warden vsock port, boxout.sock is chowned
    # to it (+ SO_PEERCRED), and api_gid is the group on every sandvmm API
    # socket. A collidable uid (1001 = the first human user on Ubuntu) puts any
    # unrelated workload or host process inside that fence. The check extracts
    # every place the id is stated and asserts (a) they all agree and (b) the
    # value is outside the ranges the node allocates on its own: > 60000 (the
    # distro UID_MAX default, above which no useradd/adduser picks a value) and
    # not 65534 (nobody).
    out="$(python3 - "$y" <<'PY' 2>&1
import re
import sys
import yaml

y = sys.argv[1]
sites = []  # (label, site, raw value)
fails = []

def docs(path):
    return [d for d in yaml.safe_load_all(open(path)) if d]

def pod_security(doc):
    return doc["spec"]["template"]["spec"].get("securityContext") or {}

def containers(doc):
    return doc["spec"]["template"]["spec"].get("containers") or []

def inits(doc):
    return doc["spec"]["template"]["spec"].get("initContainers") or []

def cname(cs, name):
    for c in cs:
        if c.get("name") == name:
            return c
    fails.append(f"no container {name!r} (manifest renamed?)")
    return {"command": [], "args": []}

def script_of(c):
    return "\n".join(list(c.get("command") or []) + list(c.get("args") or []))

def add(label, site, value):
    sites.append((label, site, value))

# ── sandlot-boxout.yaml (the hardened shape) ──
d = docs(f"{y}/sandlot-boxout.yaml")[-1]
add("fsGroup", "sandlot-boxout.yaml pod fsGroup", pod_security(d).get("fsGroup"))
sl = cname(containers(d), "sandlot")
sc = sl.get("securityContext") or {}
add("runAsUser", "sandlot-boxout.yaml sandlot runAsUser", sc.get("runAsUser"))
add("runAsGroup", "sandlot-boxout.yaml sandlot runAsGroup", sc.get("runAsGroup"))
bx = cname(containers(d), "boxout")
m = re.search(r"--allowed-uid=(\d+)", "\n".join(bx.get("args") or []))
add("boxout --allowed-uid", "sandlot-boxout.yaml boxout --allowed-uid", m.group(1) if m else None)
vg = script_of(cname(inits(d), "attach-vsockguard"))
m = re.search(r"vsockguardctl attach\s+\S+\s+(\d+)", vg)
add("vsockguard attach", "sandlot-boxout.yaml vsockguardctl attach", m.group(1) if m else None)
m = re.search(r'"\$pinned" = "(\d+)"', vg)
add("vsockguard pinned-compare", "sandlot-boxout.yaml vsockguard pinned compare", m.group(1) if m else None)
m = re.search(r"chown\s+(\d+):(\d+)\s+/certs-out/client\.key", script_of(cname(inits(d), "prep-certs")))
add("cert key owner", "sandlot-boxout.yaml prep-certs chown", m.group(1) if m else None)
add("cert key group", "sandlot-boxout.yaml prep-certs chown", m.group(2) if m else None)
m = re.search(r"chown\s+1000:(\d+)\s+/sandswap/volumes", script_of(cname(inits(d), "prep-share-root")))
add("share-root group", "sandlot-boxout.yaml prep-share-root chown", m.group(1) if m else None)

# ── sandlot.yaml (embedded — shares the group; runs as root, documented limit) ──
d = docs(f"{y}/sandlot.yaml")[-1]
m = re.search(r"chown\s+1000:(\d+)\s+/sandswap/volumes", script_of(cname(inits(d), "prep-share-root")))
add("share-root group", "sandlot.yaml prep-share-root chown", m.group(1) if m else None)

# ── sandlot-prov.yaml (the storage-plane pod shares the group on the PVCs) ──
d = docs(f"{y}/sandlot-prov.yaml")[-1]
add("fsGroup", "sandlot-prov.yaml pod fsGroup", pod_security(d).get("fsGroup"))

# ── configmaps.yaml (api_gid + the vmm_groups grant) ──
cm = None
for d in docs(f"{y}/configmaps.yaml"):
    for k, v in (d.get("data") or {}).items():
        if isinstance(v, str) and "api_gid:" in v:
            cm = yaml.safe_load(v)
if cm is None:
    fails.append("configmaps.yaml: no ConfigMap carries microvm.api_gid (renamed?)")
else:
    mv = (cm.get("microvm") or {})
    add("api_gid", "configmaps.yaml microvm.api_gid", mv.get("api_gid"))
    groups = [g.strip() for g in str(mv.get("vmm_groups") or "").split(",") if g.strip().isdigit()]
    add("vmm_groups grant", "configmaps.yaml microvm.vmm_groups", groups[-1] if groups else None)

# ── the rules ──
values = {}
for label, site, raw in sites:
    if raw is None:
        fails.append(f"{site}: {label} not found")
        continue
    try:
        v = int(raw)
    except (TypeError, ValueError):
        fails.append(f"{site}: {label} is not a number: {raw!r}")
        continue
    values.setdefault(v, []).append(site)
if len(values) > 1:
    detail = "; ".join(f"{v}: {', '.join(sorted(s))}" for v, s in sorted(values.items()))
    fails.append(f"reserved sandbox uid INCONSISTENT across manifests — {detail}")
elif values:
    v = next(iter(values))
    if v <= 60000:
        fails.append(f"reserved sandbox uid {v} is inside the collidable range (distros allocate human/software ids up to UID_MAX 60000; the bare-metal fleet already hit uid 1001 = Ubuntu's first human user)")
    if v == 65534:
        fails.append("reserved sandbox uid 65534 is nobody — a default account, not a reservation")

for f in fails:
    print("FAIL " + f)
if not fails:
    print("OK reserved sandbox uid " + ", ".join(f"{v} ({len(s)} sites)" for v, s in sorted(values.items())))
sys.exit(1 if fails else 0)
PY
)"; rc=$?
    if [[ $rc -eq 0 ]]; then
        pass "${out#OK }"
    else
        while IFS= read -r line; do
            [[ -n "$line" ]] && fail "${line#FAIL }"
        done <<< "$(printf '%s\n' "$out" | grep '^FAIL ')"
        printf '%s\n' "$out" | grep -v '^FAIL ' | grep -v '^OK ' | while IFS= read -r line; do
            [[ -n "$line" ]] && fail "python: $line"
        done
    fi

    # The deploy scripts carry the same value as their mode constants — the
    # init container, vsockguard preflight, /run/sandswap chown and the
    # post-rollout uid assertion all read these.
    expect_grep "$y/deploy-k8s-boxout.sh" '^VSOCKGUARD_UID=65536$' \
        "deploy-k8s-boxout.sh pins VSOCKGUARD_UID to the reserved uid"
    expect_grep "$y/deploy-k8s-boxout.sh" '^CHOWN_RUN_DIR_UID=65536$' \
        "deploy-k8s-boxout.sh chowns /run/sandswap to the reserved uid"
    expect_grep "$y/deploy-k8s-boxout.sh" '^SANDBOX_UID=65536$' \
        "deploy-k8s-boxout.sh asserts the pod uid against the reserved value"
    expect_grep "$y/verify-k8s.sh" '^    SANDBOX_UID=65536$' \
        "verify-k8s.sh asserts the pod uid against the reserved value"
    expect_grep "$y/deploy-lib.sh" '^        boxout\)   sandlot_uid=65536 ;;$' \
        "deploy-lib.sh's cert-owner assertion uses the reserved uid"
    expect_grep "$y/k8s-host-setup.sh" 'useradd -r -u 65536 -s /sbin/nologin -g sandlot sandlot' \
        "k8s-host-setup.sh creates the host account at the reserved uid"
    expect_grep "$y/k8s-host-setup.sh" 'getent passwd 65536' \
        "k8s-host-setup.sh refuses a node where the reserved uid belongs to another account"
    reject_grep "$y/configmaps.yaml" 'api_gid: 1001|,1001"$' \
        "configmaps.yaml no longer grants api_gid/vmm_groups to the collidable uid 1001"
    for f in sandlot.yaml sandlot-boxout.yaml sandlot-prov.yaml; do
        reject_grep "$y/$f" 'runAsUser: 1001|runAsGroup: 1001|fsGroup: 1001|allowed-uid 1001|allowed_uid=1001' \
            "$f no longer pins any sandbox identity to 1001"
    done
    # regression pins: the Secret keys are dotted (jsonpath dot-paths
    # read them as nested fields and yield empty), and install(1) -g needs a
    # GROUP-DATABASE entry (the account's gid stays 985 while its uid is the
    # reserved 65536). Both bugs made every per-node stream cert fail to install.
    expect_grep "$y/k8s-host-setup.sh" 'go-template=\{\{index \.data' \
        "k8s-host-setup.sh reads dotted Secret keys with go-template index"
    reject_grep "$y/k8s-host-setup.sh" 'jsonpath=\{\.data\.\$k\}' \
        "k8s-host-setup.sh no longer addresses dotted Secret keys with jsonpath dots"
}

pin_k8s_sandtmpl() {
    section "every k8s pod that touches the template store carries the sandtmpl GID"
    # refs/ metadata in the template store is group-scoped to sandtmpl
    # (gid 982, pinned by host prep as SS_GID_TPL): the prov pod chgrps
    # refs/ to it, and the exec sandlot resolves overlay refs by reading
    # refs/*.json directly (sandlot/core/overlay.go) — so every exec/prov
    # pod needs the supplemental GID, and it must never reach sandvmm (the
    # FUSE daemon reads layer content through the shared group and must
    # not enumerate refs). The grant is always POD-level: container
    # securityContext has no supplementalGroups field (strict decoding
    # rejects it — a container-scoped grant once shipped and every k8s
    # apply of the manifest failed). sandvmm is excluded at spawn, not in
    # the manifest: the setpriv identity split (sandlot/vmm/launcher.go)
    # sets its groups wholesale. The boxout manifest shipped without the
    # grant and every overlay-mode execute EACCES'd; the drill phase
    # (k8s_phase_overlay_template in deploy-lib.sh) catches the live
    # behavior, this pin catches the shape.
    local y="$ROOT/deploy/k8s" out rc
    out="$(python3 - "$y" <<'PY' 2>&1
import sys
import yaml

y = sys.argv[1]
fails = []

def docs(path):
    return [d for d in yaml.safe_load_all(open(path)) if d]

def pod_security(doc):
    return doc["spec"]["template"]["spec"].get("securityContext") or {}

def containers(doc):
    return doc["spec"]["template"]["spec"].get("containers") or []

def groups_of(sc):
    return [int(g) for g in (sc.get("supplementalGroups") or [])]

def container_groups(c):
    # Container-level supplementalGroups is rejected by the API server
    # (unknown field): its presence is itself a finding.
    return [int(g) for g in ((c.get("securityContext") or {}).get("supplementalGroups") or [])]

def has_env(c, name, value):
    for e in (c.get("env") or []):
        if e.get("name") == name and str(e.get("value")) == value:
            return True
    return False

def want(cond, msg):
    if not cond:
        fails.append(msg)

# boxout: the grant is pod-level; the sandvmm exclusion lives in the
# setpriv spawn, not in the manifest (the boxout container runs as root,
# for whom a supplementary group is inert).
d = docs(f"{y}/sandlot-boxout.yaml")[-1]
sl = [c for c in containers(d) if c["name"] == "sandlot"]
bx = [c for c in containers(d) if c["name"] == "boxout"]
want(982 in groups_of(pod_security(d)),
     "sandlot-boxout.yaml: pod supplementalGroups lacks 982 (overlay refs/ unreadable by the exec pod)")
want(sl and not container_groups(sl[0]) and bx and not container_groups(bx[0]),
     "sandlot-boxout.yaml: container-level supplementalGroups present — the API server rejects that field (strict decoding)")
want(sl and has_env(sl[0], "SANDSWAP_TPL_GROUP", "982"),
     "sandlot-boxout.yaml: sandlot container misses SANDSWAP_TPL_GROUP=982")

# embedded: pod-scoped grant (the pod IS the sandlot), env on the container.
d = docs(f"{y}/sandlot.yaml")[-1]
want(982 in groups_of(pod_security(d)),
     "sandlot.yaml: pod supplementalGroups lacks 982")
sl = [c for c in containers(d) if c["name"] == "sandlot"]
want(all(not container_groups(c) for c in containers(d)),
     "sandlot.yaml: container-level supplementalGroups present — the API server rejects that field (strict decoding)")
want(sl and has_env(sl[0], "SANDSWAP_TPL_GROUP", "982"),
     "sandlot.yaml: sandlot container misses SANDSWAP_TPL_GROUP=982")

# prov: writes refs — needs the group and the env (the chgrp actor).
d = docs(f"{y}/sandlot-prov.yaml")[-1]
want(982 in groups_of(pod_security(d)),
     "sandlot-prov.yaml: pod supplementalGroups lacks 982")
pv = [c for c in containers(d) if c["name"] == "sandlot-prov"]
want(all(not container_groups(c) for c in containers(d)),
     "sandlot-prov.yaml: container-level supplementalGroups present — the API server rejects that field (strict decoding)")
want(pv and has_env(pv[0], "SANDSWAP_TPL_GROUP", "982"),
     "sandlot-prov.yaml: container misses SANDSWAP_TPL_GROUP=982")

for f in fails:
    print("FAIL " + f)
if not fails:
    print("OK sandtmpl gid 982 granted to every exec/prov pod, never the sandvmm side")
sys.exit(1 if fails else 0)
PY
)"; rc=$?
    if [[ $rc -eq 0 ]]; then
        pass "${out#OK }"
    else
        while IFS= read -r line; do
            [[ -n "$line" ]] && fail "${line#FAIL }"
        done <<< "$(printf '%s\n' "$out" | grep '^FAIL ')"
        printf '%s\n' "$out" | grep -v '^FAIL ' | grep -v '^OK ' | while IFS= read -r line; do
            [[ -n "$line" ]] && fail "python: $line"
        done
    fi
}

pin_anonymous_human_start_sites() {
    section "every human-listener start site carries the explicit anonymous opt-out"
    # made the human listener refuse to start without OIDC unless the
    # operator opts out. The shipped units and the k8s manifest carry the
    # flag; a hand-written unit in a drill is a start site too and was missed
    # once (verify-binpack's human gateway exited 1, surfacing only as
    # "human not healthy"). Pin every non-exec launch site. verify-failover's
    # unit runs mode: exec (no human listener), so it is exempt.
    local f
    for f in deploy/baremetal/systemd/sandswap-gateway.service \
             deploy/baremetal/systemd/sandswap-gateway@.service \
             deploy/k8s/human.yaml \
             deploy/baremetal/verify-binpack.sh; do
        if grep -q -- '-allow-anonymous-human' "$ROOT/$f"; then
            pass "$f carries -allow-anonymous-human"
        else
            fail "$f starts a human listener without -allow-anonymous-human (or an OIDC issuer) — the gateway refuses to start"
        fi
    done
}

pin_unit_core_dumps() {
    section "every seed/key-bearing unit suppresses core dumps (LimitCORE=0)"
    # A unit without LimitCORE=0 inherits the system default: under a plain
    # "core" core_pattern a crash drops this process's memory to disk — the
    # volume seed (prov/merged sandlot), API keys and TLS private keys
    # (gateways). The pin demands the line in every unit whose process holds
    # credential material; units with none (dns, network, retune) are exempt.
    local u
    for u in sandswap-sandlot.service sandswap-sandlot-instance@.service \
             sandswap-sandlot-prov.service sandswap-gateway.service \
             sandswap-gateway@.service sandswap-seed-fetch.service; do
        if grep -qE '^LimitCORE=0$' "$ROOT/deploy/baremetal/systemd/$u"; then
            pass "$u sets LimitCORE=0"
        else
            fail "$u does NOT set LimitCORE=0 — a crash would be able to write this process's credential material (seed / API keys / TLS keys) to disk"
        fi
    done
}

pin_no_plan_ids() {
    section "CODE: production comments carry no plan/tracker IDs"
    # The repo rule: code and comments state facts and reasons, never
    # finding-tracker identifiers. Such an identifier tells a future reader
    # nothing about the invariant; the sentence around it does, and it goes
    # stale the moment the tracker is renumbered. Greps every Sandswap-authored
    # tree (production and the deploy/security scripts) across all source
    # extensions; test files are included — a test comment is a code comment.
    local pattern='\b(R[0-9]+|C[0-9]+|DC|S)-[0-9A-Za-z]|_pin_r[0-9]|PinsR[0-9]'
    local hits
    hits="$(grep -rnE "$pattern" \
        --include='*.go' --include='*.rs' --include='*.sh' --include='*.py' \
        --include='*.yaml' --include='*.yml' \
        "$ROOT/warden/src" "$ROOT/sandlot" "$ROOT/gateway" "$ROOT/boxout" \
        "$ROOT/common" "$ROOT/dns" "$ROOT/sandctl" "$ROOT/deploy" \
        "$ROOT/security" "$ROOT/vmm/virtiofsd/src" \
        "$ROOT/vmm/virtio-devices/src" "$ROOT/vmm/vmm/src" \
        2>/dev/null | grep -v '/fuzz/' | wc -l)"
    if [[ "$hits" -eq 0 ]]; then
        pass "no plan-ID references in production sources"
    else
        fail "$hits plan-ID reference(s) remain in sources:"
        grep -rnE "$pattern" \
            --include='*.go' --include='*.rs' --include='*.sh' --include='*.py' \
            --include='*.yaml' --include='*.yml' \
            "$ROOT/warden/src" "$ROOT/sandlot" "$ROOT/gateway" "$ROOT/boxout" \
            "$ROOT/common" "$ROOT/dns" "$ROOT/sandctl" "$ROOT/deploy" \
            "$ROOT/security" "$ROOT/vmm/virtiofsd/src" \
            "$ROOT/vmm/virtio-devices/src" "$ROOT/vmm/vmm/src" \
            2>/dev/null | grep -v '/fuzz/' | head -10 | sed 's/^/      /'
    fi
}

# ── Resolved-identity consumption ────────────────────────────────────
# The deployer resolves the service identities per host (occupied-slot
# adoption/auto-pick) and publishes them in /etc/sandswap/identity.env. A
# sandlot unit without EnvironmentFile=- runs on the binary's contract
# defaults and fails its /dev/vhost-vsock owner check whenever the host's
# resolution differs (the GCP-image class). Pin every spawn site.
pin_identity_env_consumption() {
    section "sandlot units consume the resolved identity env"
    local f execs envs
    for f in "$ROOT"/deploy/baremetal/systemd/sandswap-sandlot*.service; do
        expect_grep "$f" '^EnvironmentFile=-/etc/sandswap/identity.env$' \
            "$(basename "$f") loads identity.env"
    done
    while IFS= read -r f; do
        execs="$(grep -cE -- '^ExecStart=.*sandswap-sandlot' "$f" || true)"
        envs="$(grep -cE -- '^EnvironmentFile=-/etc/sandswap/identity.env' "$f" || true)"
        if (( execs > 0 && envs >= execs )); then
            pass "${f#"$ROOT"/}: $execs sandlot spawn(s), $envs identity.env load(s)"
        else
            fail "${f#"$ROOT"/}: $execs sandlot spawn(s) but $envs identity.env load(s) — the resolved VMM/prov ids never reach the process"
        fi
    done < <(grep -rlE -- '^ExecStart=.*sandswap-sandlot' "$ROOT/deploy" --include='*.sh' 2>/dev/null)
}

# The k8s leg has no identity.env: host setup must ADOPT an existing sandvmm
# account or let useradd auto-pick (udev resolves by NAME; deploy-lib injects
# the resolved uid/gid into the manifests). A hard `-u 987` aborts host setup
# on any image that already occupies the slot, and a silent 987 fallback in
# deploy-lib injects a uid no host identity owns.
pin_k8s_no_pinned_sandvmm_uid() {
    section "k8s host setup adopts/auto-picks the sandvmm uid"
    reject_grep "$ROOT/deploy/k8s/k8s-host-setup.sh" \
        'useradd[[:space:]]+[^#]*-u[[:space:]]+987([[:space:]]|$)' \
        "k8s-host-setup does not pin sandvmm to uid 987"
    reject_grep "$ROOT/deploy/k8s/deploy-lib.sh" \
        'id -u sandvmm 2>/dev/null \|\| echo 987' \
        "deploy-lib does not silently fall back to uid 987"
    reject_grep "$ROOT/deploy/k8s/deploy-lib.sh" \
        'VMM_GID:-987' \
        "deploy-lib does not silently fall back to gid 987"
}

echo "deploy-tree-pins: $ROOT"
start_http_stub || exit 1
pin_setup_network_runtime
pin_installers_ship_library
pin_log_helper_resolution
pin_stage_targets
pin_human_post_status
pin_fanout
pin_seed_fetch
pin_seed_scope_predicate
pin_tmpfs_mode_unparsable
pin_seed_config_parse
pin_runtime_dir_sticky
pin_generator_cn
pin_deploy_paths
pin_k8s_identity
pin_prov_identity
pin_reserved_sandbox_uid
pin_k8s_sandtmpl
pin_anonymous_human_start_sites
pin_unit_core_dumps
pin_identity_env_consumption
pin_k8s_no_pinned_sandvmm_uid
pin_no_plan_ids

echo
echo "deploy-tree-pins Summary"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then
    echo "deploy-tree-pins FAILED ($FAIL check(s))"
    exit 1
fi
echo "deploy-tree-pins PASSED ($PASS checks)"
exit 0
