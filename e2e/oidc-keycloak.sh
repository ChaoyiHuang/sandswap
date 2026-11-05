#!/usr/bin/env bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed by
# the Apache License, Version 2.0.
#
# oidc-keycloak.sh — REAL-IdP OIDC integration e2e for the control plane.
# Spins up Keycloak in docker, provisions realm/client/scopes/audience-mapper/
# user over the Admin REST API (no Web UI), starts a single-node gateway with
# -authn-issuer/-authn-client-id, and drives the full enforcement matrix plus
# a live signing-key rotation. No KVM, no sandlot, no root needed.
# Covers:
#   - discovery + JWKS wiring (startup log lines)
#   - 401: missing header / garbage token / foreign-issuer token
#   - 403: authenticated but missing scope (human vs admin vs ops split —
#     a user-scoped token cannot mint agent credentials; neither human nor
#     admin scopes reach ownership reclamation, only ops does)
#   - 200/503: human on user-resource /human/*, admin on /human/agent,
#     ops passes the ownership gate (503 = single-node has no etcd layer),
#     human+ops on /stats + /metrics
#   - /health stays unauthenticated; the agent API NEVER accepts an OIDC token
#   - write path: admin-scoped token provisions an agent (POST /human/agent)
#   - namespaces: sandswap_ns multivalued claim (IdP-issued) → tenant user
#     can act in its own /human/ns/<ns>/… subtree, is 403 (NAMESPACE_FORBIDDEN)
#     outside it, 403 (FLEET_SCOPE_REQUIRED) on the unscoped fleet surface,
#     and sees a uniform 404 for cross-namespace records (no oracle); a token
#     with NO sandswap_ns claim is denied on both surfaces; the * grant keeps
#     the fleet-wide behavior
#   - key rotation: new signing key → unknown kid → gateway force-refreshes
#     JWKS without restart; old-kid tokens keep verifying (merge grace)
# Docker is REQUIRED and is the only external dependency — when docker (or the
# image pull) is unavailable the script SKIPs loudly (exit 0 + warning), the
# same treatment run-all.sh gives LLM-key-dependent scripts.
# Usage: bash e2e/oidc-keycloak.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"
# Keycloak runs as a docker container: the prelude's container-runtime stop
# must keep docker (the suite below starts the daemon itself if needed).
export SANDSWAP_KEEP_CONTAINER_RUNTIME=1

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

# Pinned to the version this test was developed against (26.7.4) — Keycloak
# majors occasionally break the Admin REST API; bump deliberately, not via
# :latest drift.
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.7.4}"
KC_NAME="sandswap-e2e-keycloak"
KC_PORT=18080
KC="http://127.0.0.1:${KC_PORT}"
REALM="sandswap"
CLIENT_ID="sandswap-api"
DEMO_USER="demo"
DEMO_PASS="demo-password-e2e"
TENANT_USER="acme-tenant"
TENANT_PASS="acme-password-e2e"
TENANT_NS="acme"

GW_BIN="/tmp/sandswap-oidckc-gateway"
GW_LOG="/tmp/sandswap-oidckc-gw.log"
GW_HUMAN="127.0.0.1:13190"
GW_AGENT="127.0.0.1:13090"
GW_STREAM="127.0.0.1:13988"
GW_URL="http://${GW_HUMAN}"
ISSUER="${KC}/realms/${REALM}"
VOL_ROOT="/tmp/sandswap-oidckc-volroot"

GW_PID=""
KC_ADMIN_TOKEN=""

cleanup() {
    [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null || true
    docker rm -f "$KC_NAME" >/dev/null 2>&1 || true
    rm -rf "$VOL_ROOT"
}
trap cleanup EXIT INT TERM

# ── JSON helpers (repo convention: python3, no jq dependency) ────
jget() { # stdin JSON, $1=key → value ('' when absent)
    python3 -c "import sys,json;d=json.load(sys.stdin);v=d.get(sys.argv[1],'') if isinstance(d,dict) else '';print(v if isinstance(v,str) else json.dumps(v))" "$1" 2>/dev/null || true
}
kid_of() { # $1=JWT → header kid
    python3 -c "import sys,json,base64;p=sys.argv[1].split('.')[0];p+='='*(-len(p)%4);print(json.loads(base64.urlsafe_b64decode(p)).get('kid',''))" "$1"
}
http_code() { # curl args... → status code (000 on connect failure)
    curl -s -o /dev/null -w '%{http_code}' "$@" || true
}

# Keycloak Admin REST: fresh admin token per phase (master tokens expire; the
# phases together can outlive one).
kc_admin_login() {
    KC_ADMIN_TOKEN=$(curl -sf "$KC/realms/master/protocol/openid-connect/token" \
        -d grant_type=password -d client_id=admin-cli \
        -d username=admin -d password=admin | jget access_token)
    [ -n "$KC_ADMIN_TOKEN" ] || { echo "FAIL: keycloak admin login"; exit 1; }
}
admin_code() { # METHOD PATH [JSON] → http code; body lands in $KC_RESP
    local m=$1 p=$2 d=${3:-}
    local -a a=(-s -o "$KC_RESP" -w '%{http_code}' -X "$m" "$KC/admin$p"
        -H "Authorization: Bearer $KC_ADMIN_TOKEN" -H 'Content-Type: application/json')
    [ -n "$d" ] && a+=(-d "$d")
    curl "${a[@]}" || true
}
KC_RESP="/tmp/sandswap-oidckc-resp.json"

kc_token() { # $1=space-separated scopes → access token ('' on failure).
    # sandswap_ns is requested on EVERY mint: it is an optional client scope,
    # so leaving it out would silently strip the claim and turn every
    # fleet-leg into a namespace denial. kc_token_nons exists for exactly
    # that (the empty-claim enforcement leg).
    curl -s "$KC/realms/$REALM/protocol/openid-connect/token" \
        -d grant_type=password -d client_id="$CLIENT_ID" \
        -d username="$DEMO_USER" -d password="$DEMO_PASS" \
        -d "scope=openid sandswap_ns $1" | jget access_token
}
kc_token_for() { # $1=user $2=pass $3=scopes → access token ('' on failure)
    curl -s "$KC/realms/$REALM/protocol/openid-connect/token" \
        -d grant_type=password -d client_id="$CLIENT_ID" \
        -d username="$1" -d password="$2" \
        -d "scope=openid sandswap_ns $3" | jget access_token
}
kc_token_nons() { # $1=space-separated scopes, WITHOUT the sandswap_ns scope
    curl -s "$KC/realms/$REALM/protocol/openid-connect/token" \
        -d grant_type=password -d client_id="$CLIENT_ID" \
        -d username="$DEMO_USER" -d password="$DEMO_PASS" \
        -d "scope=openid $1" | jget access_token
}

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 0: pre-flight (docker, image, gateway build)"
# ══════════════════════════════════════════════════════════════════
if ! command -v docker >/dev/null 2>&1; then
    tc_skip_suite "docker not installed — oidc-keycloak.sh needs a running docker daemon (Keycloak container)"
fi
# The host prelude may have just stopped docker (or a reboot left it down):
# bring it up rather than skip — this suite OWNS its daemon for the run.
if ! docker info >/dev/null 2>&1; then
    tc_log_warn "docker daemon down — starting docker.service/docker.socket"
    systemctl start docker.socket docker.service 2>/dev/null || true
    ss_wait_until 30 docker info >/dev/null 2>&1 || true
fi
if ! docker info >/dev/null 2>&1; then
    tc_skip_suite "docker daemon would not start — external-dependency skip, not a code failure"
fi
if ! docker pull -q "$KEYCLOAK_IMAGE" >/dev/null 2>&1; then
    tc_skip_suite "cannot pull $KEYCLOAK_IMAGE (offline?) — external-dependency skip, not a code failure"
fi
tc_pass "docker + image $KEYCLOAK_IMAGE ready"

cd "$ROOT/gateway"
go build -o "$GW_BIN" ./cmd/ 2>&1 || { echo "FAIL: gateway build"; exit 1; }
tc_pass "gateway built"

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 1: Keycloak up + provisioning (Admin REST)"
# ══════════════════════════════════════════════════════════════════
docker rm -f "$KC_NAME" >/dev/null 2>&1 || true
docker run -d --name "$KC_NAME" -p "127.0.0.1:${KC_PORT}:8080" \
    -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
    "$KEYCLOAK_IMAGE" start-dev >/dev/null
KC_UP=0
for _ in $(seq 1 60); do
    [ "$(http_code "$KC/realms/master/.well-known/openid-configuration")" = "200" ] && KC_UP=1 && break
    docker inspect -f '{{.State.Running}}' "$KC_NAME" 2>/dev/null | grep -q true || break
    sleep 2
done
if [ "$KC_UP" != "1" ]; then
    tc_fail "keycloak did not become ready"; docker logs --tail 30 "$KC_NAME"; exit 1
fi
tc_pass "keycloak ready on $KC"

kc_admin_login
CODE=$(admin_code POST /realms "{\"realm\":\"$REALM\",\"enabled\":true}")
[ "$CODE" = "201" ] || { tc_fail "realm create ($CODE)"; cat "$KC_RESP"; exit 1; }
# Declare sandswap_ns in the realm's declarative user profile — KC 24+
# silently DROPS user attributes that are not declared here, which would
# make every later namespace grant a silent no-op. Multivalued, admin-edit.
curl -s "$KC/admin/realms/$REALM/users/profile" -H "Authorization: Bearer $KC_ADMIN_TOKEN" | python3 -c "
import sys,json
d=json.load(sys.stdin)
d.setdefault('attributes',[]).append({
  'name':'sandswap_ns','displayName':'sandswap_ns',
  'permissions':{'view':['admin','user'],'edit':['admin']},
  'multivalued':True})
d.pop('_links',None)
print(json.dumps(d))" > "$KC_RESP"
CODE=$(admin_code PUT "/realms/$REALM/users/profile" "$(cat "$KC_RESP")")
[ "$CODE" = "200" ] || { tc_fail "user-profile declare sandswap_ns ($CODE)"; cat "$KC_RESP"; exit 1; }
CODE=$(admin_code POST "/realms/$REALM/clients" \
    "{\"clientId\":\"$CLIENT_ID\",\"publicClient\":true,\"directAccessGrantsEnabled\":true,\"standardFlowEnabled\":false}")
[ "$CODE" = "201" ] || { tc_fail "client create ($CODE)"; cat "$KC_RESP"; exit 1; }
# Custom scopes — colon characters are legal in Keycloak client-scope names,
# so the gateway's default scope names work unmodified. Three buckets by
# blast radius: human (user-resource CRUD), admin (agent credential minting
# + ownership reclamation), ops (read-only observability).
for SC in sandswap:human sandswap:admin sandswap:ops; do
    CODE=$(admin_code POST "/realms/$REALM/client-scopes" "{\"name\":\"$SC\",\"protocol\":\"openid-connect\"}")
    [ "$CODE" = "201" ] || { tc_fail "client scope $SC ($CODE)"; cat "$KC_RESP"; exit 1; }
done
# NB: the ?name= query filter does NOT filter on 26.x — list and match locally.
admin_code GET "/realms/$REALM/client-scopes" >/dev/null
SCOPE_JSON=$(cat "$KC_RESP")
SCOPE_HUMAN=$(echo "$SCOPE_JSON" | python3 -c "import sys,json;print(next(s['id'] for s in json.load(sys.stdin) if s['name']=='sandswap:human'))")
SCOPE_ADMIN=$(echo "$SCOPE_JSON" | python3 -c "import sys,json;print(next(s['id'] for s in json.load(sys.stdin) if s['name']=='sandswap:admin'))")
SCOPE_OPS=$(echo "$SCOPE_JSON" | python3 -c "import sys,json;print(next(s['id'] for s in json.load(sys.stdin) if s['name']=='sandswap:ops'))")
CLIENT_UUID=$(curl -s "$KC/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
    -H "Authorization: Bearer $KC_ADMIN_TOKEN" | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['id'])")
# Attach as OPTIONAL scopes: granted only when the token request asks for them
# (a default scope would hand every token both scopes and defeat the 403 leg).
admin_code PUT "/realms/$REALM/clients/$CLIENT_UUID/optional-client-scopes/$SCOPE_HUMAN" >/dev/null
admin_code PUT "/realms/$REALM/clients/$CLIENT_UUID/optional-client-scopes/$SCOPE_ADMIN" >/dev/null
admin_code PUT "/realms/$REALM/clients/$CLIENT_UUID/optional-client-scopes/$SCOPE_OPS" >/dev/null
# Audience mapper — without it Keycloak password-grant access tokens do NOT
# list the client in `aud` and every verification fails the audience check.
CODE=$(admin_code POST "/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
    "{\"name\":\"aud-$CLIENT_ID\",\"protocol\":\"openid-connect\",\"protocolMapper\":\"oidc-audience-mapper\",\"config\":{\"included.client.audience\":\"$CLIENT_ID\",\"access.token.claim\":\"true\",\"id.token.claim\":\"false\"}}")
[ "$CODE" = "201" ] || { tc_fail "audience mapper ($CODE)"; cat "$KC_RESP"; exit 1; }
# sandswap_ns — the namespace grant claim. Client scope (optional, requested
# on mint) + ONE multivalued user-attribute mapper: the user attribute
# sandswap_ns (Keycloak stores it as a list) lands in the access token as a
# JSON array under the same name. Which namespaces exist, and who holds them,
# is ENTIRELY IdP data — sandswap carries no namespace registry.
CODE=$(admin_code POST "/realms/$REALM/client-scopes" "{\"name\":\"sandswap_ns\",\"protocol\":\"openid-connect\"}")
[ "$CODE" = "201" ] || { tc_fail "client scope sandswap_ns ($CODE)"; cat "$KC_RESP"; exit 1; }
# SCOPE_JSON predates the create above — re-list.
SCOPE_JSON=$(curl -s "$KC/admin/realms/$REALM/client-scopes" -H "Authorization: Bearer $KC_ADMIN_TOKEN")
SCOPE_NS=$(echo "$SCOPE_JSON" | python3 -c "import sys,json;print(next(s['id'] for s in json.load(sys.stdin) if s['name']=='sandswap_ns'))")
admin_code PUT "/realms/$REALM/clients/$CLIENT_UUID/optional-client-scopes/$SCOPE_NS" >/dev/null
CODE=$(admin_code POST "/realms/$REALM/client-scopes/$SCOPE_NS/protocol-mappers/models" \
    "{\"name\":\"sandswap_ns\",\"protocol\":\"openid-connect\",\"protocolMapper\":\"oidc-usermodel-attribute-mapper\",\"config\":{\"user.attribute\":\"sandswap_ns\",\"claim.name\":\"sandswap_ns\",\"jsonType.label\":\"String\",\"multivalued\":\"true\",\"access.token.claim\":\"true\",\"id.token.claim\":\"false\"}}")
[ "$CODE" = "201" ] || { tc_fail "sandswap_ns mapper ($CODE)"; cat "$KC_RESP"; exit 1; }
tc_pass "sandswap_ns client scope + multivalued mapper provisioned"

# Users. demo = the fleet shape (sandswap_ns=* — the unscoped surface stays
# reachable); acme-tenant = one namespace, no wildcard. Attributes are set
# AFTER the user exists (users endpoint ignores attributes on create in some
# versions, so set them explicitly).
kc_make_user() { # $1=user $2=pass $3=ns-json (e.g. '["*"]' | '["acme"]')
    # lastName is REQUIRED by the default user profile (role "user") — a
    # user without it answers every mint with "Account is not fully set up".
    CODE=$(admin_code POST "/realms/$REALM/users" \
        "{\"username\":\"$1\",\"enabled\":true,\"email\":\"$1@example.com\",\"emailVerified\":true,\"firstName\":\"$1\",\"lastName\":\"ns\"}")
    [ "$CODE" = "201" ] || { tc_fail "user create $1 ($CODE)"; cat "$KC_RESP"; exit 1; }
    local uu; uu=$(curl -s "$KC/admin/realms/$REALM/users?username=$1" \
        -H "Authorization: Bearer $KC_ADMIN_TOKEN" | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['id'])")
    CODE=$(admin_code PUT "/realms/$REALM/users/$uu/reset-password" \
        "{\"type\":\"password\",\"value\":\"$2\",\"temporary\":false}")
    [ "$CODE" = "204" ] || { tc_fail "user password $1 ($CODE)"; cat "$KC_RESP"; exit 1; }
    # Attribute write: Keycloak drops create-time attributes and treats a
    # partial PUT as full-representation replace — the only reliable write
    # is GET + merge + full PUT (the profile declaration above makes it
    # persist; the merge keeps email/firstName intact).
    curl -s "$KC/admin/realms/$REALM/users/$uu" -H "Authorization: Bearer $KC_ADMIN_TOKEN" | python3 -c "
import sys,json
d=json.load(sys.stdin)
a=d.get('attributes') or {}
a['sandswap_ns']=json.loads(sys.argv[1])
d['attributes']=a
print(json.dumps(d))" "$3" > "$KC_RESP"
    CODE=$(admin_code PUT "/realms/$REALM/users/$uu" "$(cat "$KC_RESP")")
    [ "$CODE" = "204" ] || { tc_fail "user attributes $1 ($CODE)"; cat "$KC_RESP"; exit 1; }
}
kc_make_user "$DEMO_USER" "$DEMO_PASS" '["*"]'
kc_make_user "$TENANT_USER" "$TENANT_PASS" "[\"$TENANT_NS\"]"
tc_pass "users provisioned (demo=*, $TENANT_USER=$TENANT_NS)"

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 2: gateway with -authn-* (discovery + JWKS)"
# ══════════════════════════════════════════════════════════════════
mkdir -p "$VOL_ROOT"
# NB: single-node mode is the DEFAULT (empty -mode) — "single-node" is not a
# valid flag value.
"$GW_BIN" \
    -agent-addr "$GW_AGENT" -human-addr "$GW_HUMAN" -stream-addr "$GW_STREAM" \
    -vol-root "$VOL_ROOT" \
    -authn-issuer "$ISSUER" -authn-client-id "$CLIENT_ID" \
    > "$GW_LOG" 2>&1 &
GW_PID=$!
GW_UP=0
for _ in $(seq 1 60); do
    [ "$(http_code "$GW_URL/health")" = "200" ] && GW_UP=1 && break
    kill -0 "$GW_PID" 2>/dev/null || break
    sleep 0.5
done
if [ "$GW_UP" != "1" ]; then
    tc_fail "gateway did not start"; tail -20 "$GW_LOG"; exit 1
fi
tc_pass "gateway up (human $GW_HUMAN)"
grep -q "OIDC discovery successful" "$GW_LOG" && grep -q "$ISSUER" "$GW_LOG" \
    && tc_pass "startup log: OIDC discovery against real issuer" \
    || tc_fail "startup log missing discovery line"
grep -q "JWKS cached" "$GW_LOG" \
    && tc_pass "startup log: JWKS cached" \
    || tc_fail "startup log missing JWKS cached line"

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 3: enforcement matrix"
# ══════════════════════════════════════════════════════════════════
T_HUMAN=$(kc_token "sandswap:human")
T_ADMIN=$(kc_token "sandswap:admin")
T_OPS=$(kc_token "sandswap:ops")
T_BOTH=$(kc_token "sandswap:human sandswap:ops")
T_NONE=$(kc_token "")
[ -n "$T_HUMAN" ] && [ -n "$T_ADMIN" ] && [ -n "$T_OPS" ] && [ -n "$T_BOTH" ] && [ -n "$T_NONE" ] \
    && tc_pass "five tokens minted (human / admin / ops / human+ops / no scope)" \
    || { tc_fail "token minting failed"; exit 1; }

check() { # desc expected_code curl-args...
    local desc=$1 want=$2; shift 2
    local got; got=$(http_code "$@")
    [ "$got" = "$want" ] && tc_pass "$desc → $got" || tc_fail "$desc → $got (want $want)"
}

# NB: the foreign-issuer check runs in Phase 6, AFTER the rotation phase —
# its unknown kid trips the gateway's JWKS force-refresh, and the 30s
# min-interval throttle (DoS guard in gateway/authn/oidc.go) would then
# reject the rotation phase's new-kid token inside the throttle window.
check "no auth header        /human/sandfs" 401 "$GW_URL/human/sandfs"
check "garbage bearer        /human/sandfs" 401 "$GW_URL/human/sandfs" -H "Authorization: Bearer not.a.jwt"
check "human token           /human/sandfs" 200 "$GW_URL/human/sandfs" -H "Authorization: Bearer $T_HUMAN"
# Blast-radius split: agent credential minting needs ADMIN; fleet
# reclamation (ownership) needs OPS — a user-scoped token gets neither.
check "human token           /human/agent" 403 "$GW_URL/human/agent" -H "Authorization: Bearer $T_HUMAN"
check "human token           /human/ownership/reap-stuck" 403 "$GW_URL/human/ownership/reap-stuck" -X POST -H "Authorization: Bearer $T_HUMAN" -H 'Content-Type: application/json' -d '{"gateway_id":"x","dry_run":true}'
check "admin token           /human/agent" 200 "$GW_URL/human/agent" -H "Authorization: Bearer $T_ADMIN"
# ops token passes the ownership scope gate — the 503 is the HANDLER's
# "no etcd coordination layer in single-node" answer, which proves the gate
# opened for the right scope (a wrong bucket would 403 instead).
check "ops token             /human/ownership/reap-stuck" 503 "$GW_URL/human/ownership/reap-stuck" -X POST -H "Authorization: Bearer $T_OPS" -H 'Content-Type: application/json' -d '{"gateway_id":"x","dry_run":true}'
check "human token           /stats"        403 "$GW_URL/stats"        -H "Authorization: Bearer $T_HUMAN"
check "scopeless token       /human/sandfs" 403 "$GW_URL/human/sandfs" -H "Authorization: Bearer $T_NONE"
check "human+ops token       /stats"        200 "$GW_URL/stats"        -H "Authorization: Bearer $T_BOTH"
check "human+ops token       /metrics"      200 "$GW_URL/metrics"      -H "Authorization: Bearer $T_BOTH"
check "no auth (always open) /health"       200 "$GW_URL/health"
# Surface separation: an OIDC token NEVER authorizes the agent API.
check "oidc token on AGENT   /agent/sandfs" 401 "http://$GW_AGENT/agent/sandfs" -H "Authorization: Bearer $T_BOTH"

METRICS_BODY=$(curl -s "$GW_URL/metrics" -H "Authorization: Bearer $T_BOTH" || true)
[ -n "$METRICS_BODY" ] && tc_pass "/metrics body non-empty" || tc_fail "/metrics body empty"

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 3b: namespace enforcement (sandswap_ns claim)"
# ══════════════════════════════════════════════════════════════════
T_TENANT=$(kc_token_for "$TENANT_USER" "$TENANT_PASS" "sandswap:human")
[ -n "$T_TENANT" ] && tc_pass "tenant token minted (human scope + sandswap_ns=$TENANT_NS)" \
    || { tc_fail "tenant token minting failed"; exit 1; }
# The claim must actually be in the token (multivalued mapper proof).
CLAIM_PROBE=$(python3 -c "
import sys,json,base64
p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4)
c=json.loads(base64.urlsafe_b64decode(p))
print(json.dumps(c.get('sandswap_ns')))" "$T_TENANT")
[ "$CLAIM_PROBE" = '["acme"]' ] \
    && tc_pass "access token carries multivalued sandswap_ns claim: $CLAIM_PROBE" \
    || tc_fail "sandswap_ns claim wrong in token: $CLAIM_PROBE"

# Rule 1 — path grant. In-grant ns passes; out-of-grant ns is 403
# NAMESPACE_FORBIDDEN; unscoped fleet surface is 403 FLEET_SCOPE_REQUIRED.
check "tenant token   /human/ns/acme/agent"      200 "$GW_URL/human/ns/$TENANT_NS/agent" -H "Authorization: Bearer $T_TENANT"
check "tenant token   /human/ns/beta/agent"      403 "$GW_URL/human/ns/beta/agent"       -H "Authorization: Bearer $T_TENANT"
check "tenant token   /human/sandfs (unscoped)"  403 "$GW_URL/human/sandfs"              -H "Authorization: Bearer $T_TENANT"
check "tenant token   /human/agent  (unscoped)"  403 "$GW_URL/human/agent"               -H "Authorization: Bearer $T_TENANT"
# Rule 1 fires BEFORE the body is read on writes too.
check "tenant POST    /human/ns/beta/agent"      403 "$GW_URL/human/ns/beta/agent" -X POST -H "Authorization: Bearer $T_TENANT" -H 'Content-Type: application/json' -d '{"name":"nope"}'
# A 403 body must carry the named error code (a bare 403 could be the scope
# gate — the body is what distinguishes namespace denial from scope denial).
FBODY=$(curl -s "$GW_URL/human/ns/beta/agent" -H "Authorization: Bearer $T_TENANT")
echo "$FBODY" | grep -q NAMESPACE_FORBIDDEN \
    && tc_pass "ns 403 body carries NAMESPACE_FORBIDDEN" \
    || tc_fail "ns 403 body: $FBODY"
# Empty claim (authenticated, token minted WITHOUT the sandswap_ns scope):
# denied on the ns surface AND on the fleet surface — only the wildcard or a
# grant opens either; a scopeless-of-ns human token is not legacy-open.
T_NOCLAIM=$(kc_token_nons "sandswap:human")
check "no-ns-claim    /human/ns/acme/agent"      403 "$GW_URL/human/ns/$TENANT_NS/agent" -H "Authorization: Bearer $T_NOCLAIM"
check "no-ns-claim    /human/sandfs"             403 "$GW_URL/human/sandfs"              -H "Authorization: Bearer $T_NOCLAIM"

# Write path in-namespace: tenant mints its own agent (201).
TENANT_AGENT_JSON=$(curl -s "$GW_URL/human/ns/$TENANT_NS/agent" -X POST \
    -H "Authorization: Bearer $T_TENANT" -H 'Content-Type: application/json' \
    -d '{"name":"acme-agent-1"}' || true)
TENANT_AGENT_ID=$(echo "$TENANT_AGENT_JSON" | jget agent_id)
case "$TENANT_AGENT_ID" in
    agent-*) tc_pass "tenant created agent in its namespace ($TENANT_AGENT_ID)" ;;
    *) tc_fail "tenant agent create"; echo "$TENANT_AGENT_JSON" | head -c 300; echo ;;
esac
# Cross-namespace reads answer the SAME uniform 404 as a missing id (Rule 2).
check "tenant GET     /human/ns/acme/agent/<missing>" 404 "$GW_URL/human/ns/$TENANT_NS/agent/agent-doesnotexist" -H "Authorization: Bearer $T_TENANT"
# (the cross-ns leg against a REAL foreign agent lands after Phase 4 creates
# one in the default namespace)
check "fleet token    /human/ns/beta/agent"      200 "$GW_URL/human/ns/beta/agent" -H "Authorization: Bearer $T_HUMAN"
check "fleet token    /human/sandfs"             200 "$GW_URL/human/sandfs"        -H "Authorization: Bearer $T_HUMAN"

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 4: write path — admin-scoped token provisions an agent"
# ══════════════════════════════════════════════════════════════════
AGENT_JSON=$(curl -s "$GW_URL/human/agent" -X POST \
    -H "Authorization: Bearer $T_ADMIN" -H 'Content-Type: application/json' \
    -d '{"name":"oidc-e2e-agent"}' || true)
AGENT_KEY=$(echo "$AGENT_JSON" | jget api_key)
case "$AGENT_KEY" in
    sk-sandswap-agent-*) tc_pass "agent created via admin-scoped token (key ${AGENT_KEY:0:24}…)" ;;
    *) tc_fail "agent create via admin-scoped token"; echo "$AGENT_JSON" | head -c 400; echo ;;
esac
ADMIN_AGENT_ID=$(echo "$AGENT_JSON" | jget agent_id)
# The unscoped create lands in the DEFAULT namespace; the tenant asking for
# it under its own ns gets the same 404 as a missing id — never a 403 (a
# 403 would leak that the id exists somewhere).
if [ -n "$ADMIN_AGENT_ID" ] && [ "$ADMIN_AGENT_ID" != "" ]; then
    check "tenant GET     default-ns agent via ns path" 404 "$GW_URL/human/ns/$TENANT_NS/agent/$ADMIN_AGENT_ID" -H "Authorization: Bearer $T_TENANT"
fi

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 5: live signing-key rotation (no restart)"
# ══════════════════════════════════════════════════════════════════
# Baseline force-refresh count — the rotation check below asserts it GROWS,
# so an earlier (unrelated) refresh line cannot satisfy it spuriously.
FR_BEFORE=$(grep -c "JWKS key miss, force-refreshing" "$GW_LOG" || true)
T_OLD=$(kc_token "sandswap:human")
KID_OLD=$(kid_of "$T_OLD")
[ -n "$KID_OLD" ] || { tc_fail "no kid on pre-rotation token"; exit 1; }

kc_admin_login
REALM_UUID=$(curl -s "$KC/admin/realms/$REALM" -H "Authorization: Bearer $KC_ADMIN_TOKEN" | jget id)
# New higher-priority RSA key. NB: priority lives in config, not top-level
# (ComponentRepresentation rejects a top-level "priority" field).
CODE=$(admin_code POST "/realms/$REALM/components" \
    "{\"name\":\"rsa-rotated-e2e\",\"providerId\":\"rsa-generated\",\"providerType\":\"org.keycloak.keys.KeyProvider\",\"parentId\":\"$REALM_UUID\",\"config\":{\"keySize\":[\"2048\"],\"priority\":[\"200\"]}}")
[ "$CODE" = "201" ] || { tc_fail "rotation key provider ($CODE)"; cat "$KC_RESP"; exit 1; }

# Wait until Keycloak actually signs with the new kid (observed immediate,
# but poll — signing-key selection is not guaranteed instantaneous).
KID_NEW=""
for _ in $(seq 1 10); do
    KID_NEW=$(kid_of "$(kc_token "sandswap:human")")
    [ -n "$KID_NEW" ] && [ "$KID_NEW" != "$KID_OLD" ] && break
    sleep 1
done
if [ -n "$KID_NEW" ] && [ "$KID_NEW" != "$KID_OLD" ]; then
    tc_pass "signing key rotated ($KID_OLD → $KID_NEW)"
else
    tc_fail "signing key did not rotate (still $KID_OLD)"; exit 1
fi

check "OLD-kid token (grace) /human/sandfs" 200 "$GW_URL/human/sandfs" -H "Authorization: Bearer $T_OLD"
T_NEW=$(kc_token "sandswap:human")
check "NEW-kid token         /human/sandfs" 200 "$GW_URL/human/sandfs" -H "Authorization: Bearer $T_NEW"
FR_AFTER=$(grep -c "JWKS key miss, force-refreshing" "$GW_LOG" || true)
[ "$FR_AFTER" -gt "$FR_BEFORE" ] \
    && tc_pass "gateway force-refreshed JWKS on unknown kid (no restart)" \
    || tc_fail "force-refresh count did not grow ($FR_BEFORE → $FR_AFTER)"

# ══════════════════════════════════════════════════════════════════
tc_log_section "Phase 6: foreign-issuer rejection"
# ══════════════════════════════════════════════════════════════════
# A REAL Keycloak token from the master realm: correctly signed by a Keycloak
# key, but its iss (and aud) can never match the configured realm → rejected.
# Runs last: its unknown kid may trip a force-refresh (or hit the 30s throttle)
# — the 401 outcome is the same either way, and it must not spend the
# rotation phase's refresh budget.
kc_admin_login
T_FOREIGN=$(curl -sf "$KC/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin | jget access_token)
[ -n "$T_FOREIGN" ] || { tc_fail "could not mint foreign-issuer token"; exit 1; }
check "foreign-issuer token  /human/sandfs" 401 "$GW_URL/human/sandfs" -H "Authorization: Bearer $T_FOREIGN"

# ── Summary ─────────────────────────────────────────────────────
tc_log_section "Summary"
echo "  pass=$PASS_COUNT fail=$FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    tc_log_error "$FAIL_COUNT test(s) FAILED"
    echo "  gateway log (last 15 lines):"; tail -15 "$GW_LOG"
    exit 1
fi
tc_log_pass "All OIDC/Keycloak real-IdP e2e tests PASSED"
