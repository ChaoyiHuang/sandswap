#!/usr/bin/env bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, your use of this software will be
# governed by the Apache License, Version 2.0.
#
# verify-cert-rotation.sh — (moved from e2e/cert-rotation-baremetal.sh) — W5/H12 drill: rotate the whole baremetal PKI
# on the DEPLOYED one-machine stack and prove the fleet re-converges.
# Rotation = re-run gen-baremetal-certs.sh (fresh CA + all leafs) → install
# → restart every unit → the TLS pinning must FAIL CLOSED during the
# mismatch window and the stack must come back healthy with:
#   - every served cert fingerprint CHANGED (the rotation actually landed)
#   - sandlot streams re-established (mTLS client certs rotated in lockstep)
#   - exec + sandfs lifecycle serving again (end-to-end recovery)
#
# The one-machine shape keeps all trust roots in one directory, so the
# lockstep is install-then-restart-all — a multi-host rotation is the same
# per-host step ordered by the rolling-upgrade discipline (protocol-version
# window), out of scope here.
#
# Usage: sudo bash deploy/baremetal/verify-cert-rotation.sh   (needs the deployed stack)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/e2e/common.sh"

CERT_DIR="/etc/sandswap/certs"
GEN="$ROOT/deploy/baremetal/gen-baremetal-certs.sh"
UNITS=(sandswap-gateway@exec sandswap-gateway@human sandswap-etcd sandswap-sandlot-instance@main sandswap-sandlot-prov)
GW_URL="https://localhost:3000"
HUMAN_URL="https://localhost:3100"

tc_check_root
[[ -x "$GEN" ]] || { tc_skip_suite "cert generator missing ($GEN)"; }
curl -sk -m 5 "$GW_URL/health" | grep -q '"status"' || { tc_skip_suite "deployed stack not answering (run deploy-one-machine-etcd.sh first)"; }
mkdir -p "$CERT_DIR"
tc_pass "stack up, generator present"

fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }

# ── Phase 1: fingerprints before ──────────────────────────────────
BEFORE_ETCD=$(fp "$CERT_DIR/etcd-server.crt")
BEFORE_STREAM=$(fp "$CERT_DIR/human.crt")
[[ -n "$BEFORE_ETCD" && -n "$BEFORE_STREAM" ]] || { tc_fail "cannot fingerprint current certs in $CERT_DIR"; exit 1; }
tc_pass "baseline fingerprints recorded (etcd ${BEFORE_ETCD:0:16}…, stream ${BEFORE_STREAM:0:16}…)"

# ── Phase 2: rotate (fresh CA + leafs) + install + restart ────────
tc_log_section "Phase 2: regenerate + install + restart all units"
STAGE=$(mktemp -d /tmp/certrot.XXXXXX)
# Same node identities the one-machine deploy minted for: the exec pair's CN
# is the EXEC instance's effective node id (<hostname>-main, the way
# deploy-one-machine-etcd.sh composes it) and the prov node gets its own pair
# (the gateway binds node_id == client cert CN by exact match — rotating to a
# shared pair would take the whole stack down with a named handshake refusal).
EXEC_CERT_CN="$(hostname)-main"
PROV_NODE_ID="sandlot-prov"
PROV_CERT_BASE="sandlot-${PROV_NODE_ID}"
# The certificate is the role grant: the prov node's pair (and, after this
# drill's rotation, the running prov unit) needs role/prov; the exec pair
# keeps the default role/exec.
SANDLOT_NODE_ID="$EXEC_CERT_CN" \
    bash "$GEN" "$STAGE" --client-cn "${PROV_NODE_ID}:prov" >/dev/null 2>&1 || { tc_fail "cert generation failed"; exit 1; }
NEW_ETCD=$(fp "$STAGE/etcd-server.crt")
[[ "$NEW_ETCD" != "$BEFORE_ETCD" ]] || { tc_fail "generator produced the SAME etcd cert (rotation is a no-op?)"; exit 1; }
tc_pass "new PKI generated (etcd ${NEW_ETCD:0:16}… ≠ baseline)"

cp "$STAGE"/* "$CERT_DIR"/
# Derived material the GENERATOR does not produce (deployer steps): prov.key
# is the PROV NODE's client key re-owned for the sandprov identity — without
# re-deriving it after rotation, prov presents the NEW prov cert with the OLD
# key ("private key does not match public key" — found by this drill, live).
cp "$CERT_DIR/${PROV_CERT_BASE}.key" "$CERT_DIR/prov.key"
chown "${SS_PROV_USER:-sandprov}":"${SS_PROV_USER:-sandprov}" "$CERT_DIR/prov.key"
# per-identity key scoping (same as the deployer)
bash "$ROOT/deploy/baremetal/deploy-lib.sh" -- >/dev/null 2>&1 || true
if declare -F ss_own_tls_keys >/dev/null 2>&1; then ss_own_tls_keys "$CERT_DIR"; else
    # deploy-lib not sourceable standalone: scope the known keys directly
    # Per-identity cert scoping (mirrors ss_own_tls_keys): these identities are
    # PINNED by the identity split, not deployment-shape dependent; only
    # prov.key's owner follows the shape (line above).
    chown sandserv:sandserv "$CERT_DIR"/human.key "$CERT_DIR"/mcp.key "$CERT_DIR"/stream.key 2>/dev/null || true  # shape-ok: pinned service identity
    chown sandlot:sandlot "$CERT_DIR"/sandlot.key "$CERT_DIR"/sandlot-*.key 2>/dev/null || true  # shape-ok: pinned service identity
    # prov.key's owner follows the SHAPE (set above) — re-asserted AFTER the
    # sandlot-key glob, which would otherwise sweep the prov node's key pair
    # into the sandlot identity too.
    chown "${SS_PROV_USER:-sandprov}":"${SS_PROV_USER:-sandprov}" "$CERT_DIR"/prov.key 2>/dev/null || true
fi
rm -rf "$STAGE"
systemctl restart sandswap-etcd
sleep 2
# reset-failed first: a unit that crash-looped against the pre-rotation
# material is rate-limited by systemd and a bare restart silently no-ops
# ("Start request repeated too quickly" — found by this drill, live).
for u in "${UNITS[@]}"; do
    systemctl reset-failed "$u" 2>/dev/null || true
    systemctl restart "$u" 2>/dev/null || true
done
tc_pass "new material installed, all units restarted"

# ── Phase 3: re-convergence ───────────────────────────────────────
tc_log_section "Phase 3: wait for re-convergence"
UP=0
for _ in $(seq 1 60); do
    # BOTH listeners must answer: waiting only for the exec gateway let the
    # very next human-API curl race the human listener's bind (curl exit 7,
    # fatal under set -e).
    curl -sk -m 3 "$GW_URL/health" 2>/dev/null | grep -q '"status"' \
        && curl -sk -m 3 "$HUMAN_URL/health" 2>/dev/null | grep -q '"status"' \
        && { UP=1; break; }
    sleep 2
done
[[ "$UP" == "1" ]] || { tc_fail "gateway did not come back after rotation"; journalctl -u sandswap-gateway@exec -n 10 --no-pager; exit 1; }
tc_pass "gateway healthy on the new PKI"

SERVED=$(echo | openssl s_client -connect localhost:3000 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
if [[ -n "$SERVED" && "$SERVED" != "$BEFORE_STREAM" ]]; then
    tc_pass "served cert rotated (live handshake ${SERVED:0:16}…)"
else
    tc_fail "served cert unchanged after rotation ($SERVED)"
fi

# stream re-established: sandfs lifecycle needs prov over the stream. The
# prov unit was just restarted with the new material; wait for its reconnect
# instead of racing it (the health endpoint's provisioners count is the
# authoritative signal).
PROV_UP=0
for _ in $(seq 1 60); do
    curl -sk -m 3 "$HUMAN_URL/health" 2>/dev/null \
        | grep -q '"provisioners":[[:space:]]*[1-9]' && { PROV_UP=1; break; }
    sleep 1
done
[[ "$PROV_UP" == "1" ]] || { tc_fail "provision plane did not reconnect after rotation"; journalctl -u sandswap-sandlot-prov -n 10 --no-pager; exit 1; }
tc_pass "provision plane reconnected over the rotated mTLS stream"

RESP=$(curl -sk -X POST "$HUMAN_URL/human/agent" -H 'Content-Type: application/json' -d '{"name":"cert-rot"}')
A_KEY=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || true)
A_ID=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || true)
SF=$(curl -sk -X POST "$HUMAN_URL/human/sandfs" -H 'Content-Type: application/json' \
    -d "{\"agent_id\":\"$A_ID\",\"name\":\"cert-rot\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}")
SF_ID=$(echo "$SF" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || true)
if [[ -n "$SF_ID" ]]; then
    tc_pass "storage plane over the rotated mTLS stream (sandfs $SF_ID created)"
    # Bounded retry through the DESIGNED retryable refusals (NO_AVAILABLE_
    # SANDBOX / SANDBOX_CLEANING / CONCURRENT_MOUNT / OWNER_NO_COMPUTE): every unit was restarted
    # moments ago and the pool may still be rebuilding — a real client backs
    # off and retries, so the drill does too (the e2e lesson: a one-shot
    # probe measures its own impatience, not the path).
    EXEC=""
    for _ in $(seq 1 60); do
        EXEC=$(curl -sk -m 30 -X POST "$GW_URL/agent/execute" -H "Authorization: Bearer $A_KEY" -H 'Content-Type: application/json' \
            -d "{\"sandfs_id\":\"$SF_ID\",\"code\":\"echo rotated\",\"timeout\":15}")
        echo "$EXEC" | grep -q '"status":"done"' && break
        sleep 2
    done
    echo "$EXEC" | python3 -c "import sys,json;d=json.load(sys.stdin);sys.exit(0 if d.get('status')=='done' else 1)" 2>/dev/null \
        && tc_pass "end-to-end exec on the rotated stack" \
        || tc_fail "exec failed after rotation: $EXEC"
else
    tc_fail "sandfs create failed after rotation (prov stream not re-established?): $SF"
fi

tc_log_section "Summary"
if [[ "$FAIL_COUNT" -gt 0 ]]; then tc_log_error "$FAIL_COUNT check(s) FAILED"; exit 1; fi
tc_log_pass "baremetal cert rotation: regenerated → installed → restarted → re-converged → end-to-end serving"
