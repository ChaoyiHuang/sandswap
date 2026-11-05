#!/usr/bin/env bash
# lifecycle-split-gateway.sh — SPLIT-topology lifecycle e2e (the one-gw and
# fully-distributed shape): a HUMAN gateway (no pool, no exec streams) and an
# EXEC gateway (pool + exec-role sandlot) on one etcd, with a prov-role
# sandlot feeding the human gateway's storage plane.
#
# Verifies the watch-driven half of the sandfs lifecycle machinery — the half
# template-swap.sh cannot reach (single-node drains INLINE):
#   1. Warm exec via the EXEC gateway → it owns the sandfs (etcd owner key).
#   2. detach-template issued on the HUMAN gateway: no pool there, so the
#      drain happens on the EXEC gateway via its etcd identity watch → the
#      human gateway's poll sees `detached` → 200.
#   3. Execs gated (409) while detached; attach on the human gateway returns
#      the sandfs to active; the new template is live on the next exec.
#   4. No-owner escape: a created-but-never-executed sandfs detaches on the
#      human gateway directly (nothing can be mounted without an owner).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
LEASE_MS="${LEASE_MS:-1000}"
TPL_DIR="/tmp/sandswap-lcsplit-tpl"
VOL_ROOT="/tmp/sandswap-lcsplit-vol"
ETCD_DATA="/tmp/sandswap-lcsplit-etcd"
ETCD_ENDPOINT="http://127.0.0.1:2379"

EXEC_HTTP="http://127.0.0.1:13101"
EXEC_STREAM="127.0.0.1:19998"
HUMAN_HTTP="http://127.0.0.1:13100"
HUMAN_STREAM="127.0.0.1:19996"
# common.sh helpers (tc_create_agent_and_sandfs, tc_wait_pool_ready) address
# the gateways through these two — point them at THIS suite's split pair.
HUMAN_URL="$HUMAN_HTTP"
GATEWAY_URL="$EXEC_HTTP"
EXEC_GW_ID="gw-exec-lc"
HUMAN_GW_ID="gw-human-lc"

source "$ROOT/e2e/common.sh"

GW_EXEC_PID="" GW_HUMAN_PID="" SL_EXEC_PID="" SL_PROV_PID="" OPS2_GW_PID=""
cleanup() {
    local exit_code=$?
    for pid in "${OPS2_GW_PID:-}" "$SL_PROV_PID" "$SL_EXEC_PID" "$GW_HUMAN_PID" "$GW_EXEC_PID"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    tc_cleanup_etcd "$ETCD_DATA"
    rm -rf "$TPL_DIR" "$VOL_ROOT" 2>/dev/null || true
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

log_section "Phase 0: Pre-flight"
tc_check_root
tc_check_artifacts gateway sandlot sandvmm vmlinux.bin initramfs.cpio.gz
tc_ensure_dev_nodes
[[ -d "$OUTPUT/rootfs-template" ]] || { log_error "missing output/rootfs-template (bash build/build.sh rootfs-template)"; exit 1; }
tc_check_kvm
# Fresh instance-id state: two colocated instances share /run/sandswap state
# (recorded-PID discipline — never pgrep-based cleanup).
tc_clean_environment

log_section "Phase 1: etcd + two gateways + two sandlot instances"
tc_ensure_etcd
for port in 13100 13101 19996 19998; do
    if ss -tlnp 2>/dev/null | grep -q ":$port"; then
        tc_kill_port "$port"; sleep 0.5
    fi
done
tc_start_etcd lcsplit "$ETCD_DATA"

mkdir -p "$VOL_ROOT" "$TPL_DIR"
ss_prepare_shared_dir "$TPL_DIR"
ss_seed_template "$OUTPUT/rootfs-template" "$TPL_DIR/app/v1"
ss_seed_template "$OUTPUT/rootfs-template" "$TPL_DIR/app/v2"
echo -n "v2" > "$TPL_DIR/app/v2/TEMPLATE_VERSION"

# Stream mTLS material BEFORE the gateways start: the gateway refuses a
# node stream that presents no client certificate, so both sides of BOTH
# streams (exec sandlot → exec gw, prov sandlot → human gw) need certificates.
# Use the run's deploy root (the matrix isolates it under SANDSWAP_E2E_ROOT);
# a hardcoded production path shares certs across rows and contaminates both
# the battery and a co-located real deployment.
CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
tc_gen_certs

GW_BIN=/tmp/sandswap-lcsplit-gateway
cd "$ROOT/gateway" && go build -o "$GW_BIN" ./cmd/ || { echo "FAIL: gateway build"; exit 1; }
cd "$ROOT"

# This script starts its exec gateway BY HAND (not tc_start_gateway), so the
# ops token the battery helpers rely on (tc_wait_pool_ready polls this
# gateway's token-gated /stats) is minted here: same shape as
# tc_start_gateway's mint. The gateway runs as root in this suite, so the
# file only needs to be non-empty and readable.
OPS_TOKEN_FILE="/tmp/sandswap-lcsplit-ops-main.token"
printf 'lcsplit-main-%s\n' "$(openssl rand -hex 16)" > "$OPS_TOKEN_FILE"
chmod 600 "$OPS_TOKEN_FILE"
export TC_OPS_TOKEN="$(cat "$OPS_TOKEN_FILE")"

"$GW_BIN" -mode exec \
    -agent-addr 127.0.0.1:13101 -stream-addr "$EXEC_STREAM" \
    -gateway-id "$EXEC_GW_ID" -gateway-url "$EXEC_HTTP" -gateway-stream-addr "$EXEC_STREAM" \
    -etcd "$ETCD_ENDPOINT" -vol-root "$VOL_ROOT" \
    -stream-tls-cert "$CERT_DIR/gateway.crt" \
    -stream-tls-key "$CERT_DIR/gateway.key" \
    -stream-tls-ca "$CERT_DIR/ca.crt" \
    -ops-token-file "$OPS_TOKEN_FILE" \
    >/tmp/sandswap-lcsplit-exec-gw.log 2>&1 &
GW_EXEC_PID=$!
"$GW_BIN" -mode human \
    -human-addr 127.0.0.1:13100 -stream-addr "$HUMAN_STREAM" \
    -gateway-id "$HUMAN_GW_ID" -gateway-url "$HUMAN_HTTP" -gateway-stream-addr "$HUMAN_STREAM" \
    -etcd "$ETCD_ENDPOINT" -vol-root "$VOL_ROOT" \
    -stream-tls-cert "$CERT_DIR/gateway.crt" \
    -stream-tls-key "$CERT_DIR/gateway.key" \
    -stream-tls-ca "$CERT_DIR/ca.crt" \
    -allow-anonymous-human \
    >/tmp/sandswap-lcsplit-human-gw.log 2>&1 &
GW_HUMAN_PID=$!
for i in $(seq 1 60); do
    curl -sf "$EXEC_HTTP/health" >/dev/null 2>&1 && curl -sf "$HUMAN_HTTP/health" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -sf "$EXEC_HTTP/health" >/dev/null || { echo "FAIL: exec gw down"; tail -20 /tmp/sandswap-lcsplit-exec-gw.log; exit 1; }
curl -sf "$HUMAN_HTTP/health" >/dev/null || { echo "FAIL: human gw down"; tail -20 /tmp/sandswap-lcsplit-human-gw.log; exit 1; }
pass "exec gw ($EXEC_HTTP) + human gw ($HUMAN_HTTP) up on one etcd"

# Exec-role sandlot (KVM pool) → EXEC gateway stream. Colocated flag: the
# simulation runs two instances on this host (role-lock escape hatch).
SANDLOT_BIN="$DEPLOY_DIR/sandlot"
tc_attach_vsockguard
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
fi
# Mint the pairs BEFORE the background launch: command substitutions inside a
# `... &` statement run in the background subshell, so minting there races the
# prov instance's mint on the shared CA serial file (one signing loses).
EXEC_NODE_CERT="$(tc_node_cert lc-split-exec)"
# shellcheck disable=SC2046
ss_service_exec sandlot -- "$SANDLOT_BIN" \
    -gateway-addr "$EXEC_STREAM" \
    -node-id "lc-split-exec" \
    -kernel "$DEPLOY_DIR/vmlinux.bin" \
    -initramfs "$DEPLOY_DIR/initramfs.cpio.gz" \
    -vmm-binary "$DEPLOY_DIR/sandvmm" \
    -volumes-dir "$VOL_ROOT" -allow-insecure-volumes -allow-missing-vsockguard \
    -overlayfs-templates "$TPL_DIR" \
    -roles exec \
    -default-vcpus 2 -default-memory "$VM_MEMORY_MB" \
    -pool "small:1" \
    -network-backend "$NETWORK_BACKEND" \
    $([[ "$NETWORK_BACKEND" == "bridge" ]] && echo \
        -network-bridge "$NETWORK_BRIDGE" \
        -network-subnet "$NETWORK_SUBNET" \
        -network-gateway "$NETWORK_GATEWAY" \
        -network-dns "$NETWORK_DNS") \
    -tls-cert "$EXEC_NODE_CERT.crt" \
    -tls-key "$EXEC_NODE_CERT.key" \
    -tls-ca "$CERT_DIR/ca.crt" \
    -allow-colocated-instances \
    > "$LOG_DIR/sandlot-exec.log" 2>&1 &
SL_EXEC_PID=$!

# Prov-role sandlot (storage plane) → HUMAN gateway stream. NO pool: the
# config validator refuses exec machinery on prov-only roles.
# The seed must exist BEFORE the spawn (the prov role refuses to start
# without it) — a standalone statement, never a line inside the command
# continuation (a glued call silently truncates the argv and the sandlot
# runs with defaults in the FOREGROUND, hanging the suite).
tc_ensure_volume_seed
PROV_NODE_CERT="$(tc_node_cert lc-split-prov prov)"
# shellcheck disable=SC2046
ss_service_exec sandlot -- "$SANDLOT_BIN" \
    -gateway-addr "$HUMAN_STREAM" \
    -node-id "lc-split-prov" \
    -volumes-dir "$VOL_ROOT" -allow-insecure-volumes -allow-missing-vsockguard \
    -overlayfs-templates "$TPL_DIR" \
    -roles prov \
    -volume-seed-file "$DEPLOY_DIR/volume-seed" \
    -tls-cert "$PROV_NODE_CERT.crt" \
    -tls-key "$PROV_NODE_CERT.key" \
    -tls-ca "$CERT_DIR/ca.crt" \
    -allow-colocated-instances \
    > "$LOG_DIR/sandlot-prov.log" 2>&1 &
SL_PROV_PID=$!
sleep 1
kill -0 "$SL_EXEC_PID" 2>/dev/null || { echo "FAIL: exec sandlot died"; tail -10 "$LOG_DIR/sandlot-exec.log"; exit 1; }
kill -0 "$SL_PROV_PID" 2>/dev/null || { echo "FAIL: prov sandlot died"; tail -10 "$LOG_DIR/sandlot-prov.log"; exit 1; }
pass "two sandlot instances running (exec→:19998, prov→:19996)"

tc_wait_pool_ready 1 "$EXEC_HTTP"

# ── helpers ─────────────────────────────────────────────────────────
exec_via() { # base_url key sid code
    curl -s -m 60 -X POST "$1/agent/execute" \
        -H "Authorization: Bearer $2" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$3\",\"code\":\"$4\",\"language\":\"shell\"}" 2>/dev/null || echo '{}'
}
resp_stdout() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout',''))" 2>/dev/null || echo ""
}
sandfs_status() { # sid
    curl -s "$HUMAN_HTTP/human/sandfs/$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "?"
}
owner_gw() { # sid — etcdctl get prints "<key>\n<value>"; parse the VALUE line only
    "$ETCDCTL" --endpoints "$ETCD_ENDPOINT" get "/sandswap/owner/$1" --print-value-only 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('gateway_id',''))" 2>/dev/null || echo ""
}

log_section "Phase 2: create via human gw, warm exec via EXEC gw"
RESP=$(tc_create_agent_and_sandfs "split-user" "app:v1" "overlay")
SID=$(tc_json_val "$RESP" "sandfs_id")
KEY=$(tc_json_val "$RESP" "api_key")
[[ -n "$SID" ]] || { fail "create failed: $RESP"; exit 1; }
pass "overlay sandfs created via human gw ($SID)"

W=$(exec_via "$EXEC_HTTP" "$KEY" "$SID" "echo split-warm && cat /TEMPLATE_VERSION 2>/dev/null || echo noversion")
if [[ "$(resp_stdout "$W")" == *"split-warm"* ]]; then
    pass "warm exec via EXEC gateway"
else
    fail "exec via exec gw failed: $(echo "$W" | head -c 200)"
fi
# v1 baseline control: app:v1 ships NO TEMPLATE_VERSION, so the post-swap "v2"
# assertion below is only meaningful against a proven "no version" baseline.
if [[ "$(resp_stdout "$W" | tr -d '\r\n')" == *"noversion"* ]]; then
    pass "pre-swap baseline: v1 template carries no TEMPLATE_VERSION"
else
    fail "pre-swap baseline missing (probe saw: $(resp_stdout "$W" | head -c 120))"
fi
OWNER=$(owner_gw "$SID")
if [[ "$OWNER" == "$EXEC_GW_ID" ]]; then
    pass "exec gateway owns the sandfs (owner=$OWNER)"
else
    fail "unexpected owner: '$OWNER' (want $EXEC_GW_ID)"
fi

log_section "Phase 3: detach on HUMAN gw → watch-driven drain on EXEC gw"
DETACH_CODE=$(curl -s -o /tmp/lcsplit-detach.json -w '%{http_code}' -m 60 -X POST \
    "$HUMAN_HTTP/human/sandfs/$SID/detach-template" -H "Content-Type: application/json" \
    -d '{"wait_sec":30}' 2>/dev/null || echo 000)
if [[ "$DETACH_CODE" == "200" ]]; then
    pass "detach on human gw settled to detached (watch-driven drain on exec gw)"
else
    fail "detach: expected 200, got $DETACH_CODE: $(head -c 200 /tmp/lcsplit-detach.json)"
fi
[[ "$(sandfs_status "$SID")" == "detached" ]] && pass "record status=detached" || fail "status=$(sandfs_status "$SID")"
# The exec gateway's warm lease is GONE (it drained): the etcd owner key was
# released with the unmount? No — placement survives unmount; assert via the
# exec path instead: a gated exec, not a warm one.
GATED=$(curl -s -o /dev/null -w '%{http_code}' -m 30 -X POST "$EXEC_HTTP/agent/execute" \
    -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
    -d "{\"sandfs_id\":\"$SID\",\"code\":\"true\",\"language\":\"shell\"}" 2>/dev/null || echo 000)
[[ "$GATED" == "409" ]] && pass "exec on detached gated at the EXEC gateway (409)" || fail "expected 409, got $GATED"

log_section "Phase 4: attach on HUMAN gw → active → new template live"
ATTACH_CODE=$(curl -s -o /tmp/lcsplit-attach.json -w '%{http_code}' -m 60 -X POST \
    "$HUMAN_HTTP/human/sandfs/$SID/attach-template" -H "Content-Type: application/json" \
    -d '{"template_ref":"app:v2","home":"keep"}' 2>/dev/null || echo 000)
[[ "$ATTACH_CODE" == "200" ]] && pass "attach on human gw 200" || fail "attach: $ATTACH_CODE $(head -c 200 /tmp/lcsplit-attach.json)"
[[ "$(sandfs_status "$SID")" == "" ]] && pass "record back to active" || fail "status=$(sandfs_status "$SID")"
# The probe must DISCRIMINATE: `cat /TEMPLATE_VERSION` alone (the v1 fixture has
# no such file), compared exactly — the old probe appended "echo done-v2", so
# stdout contained "v2" even when the swap never took effect and cat failed.
W2=$(exec_via "$EXEC_HTTP" "$KEY" "$SID" "cat /TEMPLATE_VERSION 2>/dev/null || echo NO_VERSION")
if [[ "$(resp_stdout "$W2" | tr -d '\r\n')" == "v2" ]]; then
    pass "new template live via EXEC gateway after split swap"
else
    fail "post-attach exec output wrong: $(echo "$W2" | head -c 160)"
fi

log_section "Phase 5: no-owner escape on the human gateway"
RESP2=$(tc_create_agent_and_sandfs "split-idle" "app:v1" "overlay")
SID2=$(tc_json_val "$RESP2" "sandfs_id")
[[ -n "$SID2" ]] || { fail "idle create failed: $RESP2"; exit 1; }
# Never executed → no ownership claim anywhere → the human gateway settles
# the detach itself (nothing can be mounted without an owner).
DETACH2=$(curl -s -o /dev/null -w '%{http_code}' -m 60 -X POST \
    "$HUMAN_HTTP/human/sandfs/$SID2/detach-template" -H "Content-Type: application/json" -d '{}' 2>/dev/null || echo 000)
[[ "$DETACH2" == "200" ]] && pass "never-mounted sandfs detaches directly on human gw (no-owner escape)" || fail "no-owner detach: $DETACH2"

tc_delete_sandfs "$SID"
tc_delete_sandfs "$SID2"

# ── Phase 6: ops token gate on the exec gateway's /stats + /metrics ──
# The exec-mode agent listener must never serve the fleet-wide ops views
# unauthenticated: with no -ops-token-file the endpoints are ABSENT (404);
# with the flag they sit behind the file's bearer token (rotation by file
# write; a file that observably empties fails CLOSED). The MAIN exec gateway
# carries the flag (minted above — the pool poll already needed it); two
# throwaway gateways carry the negative controls (missing file must refuse
# to boot; no flag must 404).
log_section "Phase 6: exec-gateway ops token gate (/stats, /metrics)"
OPS_GW_ADDR="127.0.0.1:13102"
OPS_GW_HTTP="http://$OPS_GW_ADDR"
OPS2_GW_PID=""

code_of() { curl -s -o /dev/null -w '%{http_code}' -m 10 "$@" 2>/dev/null || echo 000; }

# 1. Main (tokened) gateway: the request matrix.
S_NOAUTH=$(code_of "$EXEC_HTTP/stats")
S_WRONG=$(code_of -H "Authorization: Bearer not-the-token" "$EXEC_HTTP/stats")
S_BASIC=$(code_of -H "Authorization: Basic $TC_OPS_TOKEN" "$EXEC_HTTP/stats")
S_RIGHT=$(code_of -H "Authorization: Bearer $TC_OPS_TOKEN" "$EXEC_HTTP/stats")
M_NOAUTH=$(code_of "$EXEC_HTTP/metrics")
M_RIGHT=$(code_of -H "Authorization: Bearer $TC_OPS_TOKEN" "$EXEC_HTTP/metrics")
H_OPEN=$(code_of "$EXEC_HTTP/health")
[[ "$S_NOAUTH" == "401" ]] && pass "/stats without token = 401" || fail "/stats no-auth = $S_NOAUTH"
[[ "$S_WRONG" == "401" && "$S_BASIC" == "401" ]] && pass "/stats wrong token / wrong scheme = 401" || fail "wrong-cred codes: $S_WRONG/$S_BASIC"
[[ "$S_RIGHT" == "200" && "$M_RIGHT" == "200" && "$M_NOAUTH" == "401" ]] && pass "/stats + /metrics serve with the right bearer (200); /metrics gated too" \
    || fail "right-cred codes: stats=$S_RIGHT metrics=$M_RIGHT/$M_NOAUTH"
[[ "$H_OPEN" == "200" ]] && pass "/health unaffected (probes stay tokenless)" || fail "/health=$H_OPEN (want 200)"

# 2. Startup validation: a configured-but-MISSING token file must refuse to
#    boot (fail-fast, never serve open).
"$GW_BIN" -mode exec -agent-addr "$OPS_GW_ADDR" -stream-addr 127.0.0.1:19994 \
    -gateway-id "gw-exec-opstoken-broken" -etcd "$ETCD_ENDPOINT" -vol-root "$VOL_ROOT" \
    -ops-token-file "/tmp/sandswap-lcsplit-ops.token.ABSENT" \
    >/tmp/sandswap-lcsplit-ops-broken.log 2>&1 &
OPS2_GW_PID=$!
BOOT_RC=0
for _ in $(seq 1 20); do
    if ! kill -0 "$OPS2_GW_PID" 2>/dev/null; then
        # `wait || BOOT_RC=$?`: a bare failing wait trips set -e here (the
        # refusal exits nonzero by design) and silently kills the suite.
        wait "$OPS2_GW_PID" 2>/dev/null || BOOT_RC=$?
        break
    fi
    sleep 0.5
done
if [[ "$BOOT_RC" -ne 0 ]] && grep -q "invalid -ops-token-file" /tmp/sandswap-lcsplit-ops-broken.log; then
    pass "missing token file refuses to boot (named error, exit $BOOT_RC)"
else
    fail "missing token file did not fail fast (rc=$BOOT_RC)"; kill "$OPS2_GW_PID" 2>/dev/null || true
fi
OPS2_GW_PID=""

# 3. No-flag default: the endpoints are ABSENT, not open.
"$GW_BIN" -mode exec -agent-addr "$OPS_GW_ADDR" -stream-addr 127.0.0.1:19994 \
    -gateway-id "gw-exec-opstoken-none" -etcd "$ETCD_ENDPOINT" -vol-root "$VOL_ROOT" \
    >/tmp/sandswap-lcsplit-ops-none.log 2>&1 &
OPS2_GW_PID=$!
for _ in $(seq 1 30); do code_of "$OPS_GW_HTTP/health" | grep -q 200 && break; sleep 0.5; done
S_NOFLAG=$(code_of "$OPS_GW_HTTP/stats"); M_NOFLAG=$(code_of "$OPS_GW_HTTP/metrics"); H_NOFLAG=$(code_of "$OPS_GW_HTTP/health")
[[ "$S_NOFLAG" == "404" && "$M_NOFLAG" == "404" && "$H_NOFLAG" == "200" ]] \
    && pass "no -ops-token-file: /stats+/metrics ABSENT (404), /health open" \
    || fail "no-flag defaults: stats=$S_NOFLAG metrics=$M_NOFLAG health=$H_NOFLAG (want 404/404/200)"
kill "$OPS2_GW_PID" 2>/dev/null || true
OPS2_GW_PID=""

# 4. Rotation by file write (hot reload, no restart): different LENGTH so the
#    mtime+size change is unambiguous under coarse mtime granularity.
OLD_TOKEN="$TC_OPS_TOKEN"
printf 'rotated-token-longer-%s\n' "$(openssl rand -hex 12)" > "$OPS_TOKEN_FILE"
sleep 1.2
S_OLD=$(code_of -H "Authorization: Bearer $OLD_TOKEN" "$EXEC_HTTP/stats")
S_NEW=$(code_of -H "Authorization: Bearer $(cat "$OPS_TOKEN_FILE")" "$EXEC_HTTP/stats")
[[ "$S_OLD" == "401" && "$S_NEW" == "200" ]] && pass "token rotation is a file write (old 401, new 200, no restart)" \
    || fail "rotation: old=$S_OLD new=$S_NEW"

# 5. Fail-closed: the file observably EMPTIES (credential withdrawn or a
#    broken rotation) — the previously-valid token must stop working until a
#    valid file returns.
PREV_TOKEN="$(cat "$OPS_TOKEN_FILE")"
printf '   \n' > "$OPS_TOKEN_FILE"
sleep 1.2
# FAIL-CLOSED check: the PREVIOUSLY-valid token must stop working.
S_EMPTIED=$(code_of -H "Authorization: Bearer $PREV_TOKEN" "$EXEC_HTTP/stats")
printf 'restored-token-%s\n' "$(openssl rand -hex 12)" > "$OPS_TOKEN_FILE"
sleep 1.2
S_RESTORED=$(code_of -H "Authorization: Bearer $(cat "$OPS_TOKEN_FILE")" "$EXEC_HTTP/stats")
[[ "$S_EMPTIED" == "401" && "$S_RESTORED" == "200" ]] && pass "emptied token file fails CLOSED; restored file reopens" \
    || fail "empty-file window: emptied=$S_EMPTIED restored=$S_RESTORED"
export TC_OPS_TOKEN="$(cat "$OPS_TOKEN_FILE")"

log_section "Summary"
echo "  pass=$PASS_COUNT fail=$FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    tc_log_error "$FAIL_COUNT test(s) FAILED"
    echo "  exec gw log:"; tail -12 /tmp/sandswap-lcsplit-exec-gw.log
    echo "  human gw log:"; tail -12 /tmp/sandswap-lcsplit-human-gw.log
    exit 1
fi
tc_log_pass "All split-gateway lifecycle E2E tests PASSED"
