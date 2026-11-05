---
title: Auth Integration
nav_order: 6
parent: Integration
---

# Auth Integration

Sandswap has two separate authentication surfaces, and integrating either a
third-party identity provider or your own provisioning flow means wiring
the right one:

| Surface | Endpoints (listener) | Credential | Mechanism |
|---|---|---|---|
| **Agent API** | `/agent/*`, `/mcp` (`:3000`) | per-agent API key | `Authorization: Bearer` / `X-Sandswap-Api-Key`, digest lookups in the identity store |
| **Control plane** | `/human/*`, `/stats`, `/metrics` (`:3100`) | OIDC (or mTLS) | JWT Bearer validation against your provider |

The agent API-key flow (create agent → key returned once → both headers on
every request) is covered in [Agent HTTP Integration](agent-http.md); this
page is about plugging the control plane into an external identity system.

## 1. OIDC on the human listener

Configure an issuer and every `/human/*`, `/stats`, and `/metrics` request
must carry a valid OIDC Bearer token:

```yaml
# gateway YAML (or the -authn-* CLI flags)
authn:
  issuer: "https://your-tenant.example.com/"   # empty = no auth: needs allow_anonymous
  client_id: "sandswap-api"                    # token audience check
  jwks_refresh_sec: 3600                       # JWKS cache refresh
  scope_human: "sandswap:human"                # sandfs CRUD + /human/ns/* + GET /human/templates (list)
  scope_admin: "sandswap:admin"                # agent credential minting + template creation/mutation
  scope_ops: "sandswap:ops"                    # fleet ops + agent minting + template creation/mutation + save-as-template
```

Behavior, verified against `gateway/authn/`:

- **Discovery + JWKS**: the provider fetches the issuer's discovery document
  (issuer URL must be HTTPS; plain http is accepted only for
  localhost/loopback), then validates JWTs by issuer and audience
  (`client_id`). JWKS keys refresh on a timer, and a signature whose key is
  unknown triggers a refresh-and-retry with a stale/fresh key-set merge
  grace window — key rotation needs no restart.
- **Scopes**, bucketed by blast radius (all three names configurable to
  match your provider's existing scheme):
  - `sandswap:human` — SandFS CRUD, the `/human/ns/{ns}/…` subtree, and
    `GET /human/templates` (list only: namespaces enumerate the ops-provided
    templates and create sandfs/agents from them). Template CREATION is not a
    tenant capability.
  - `sandswap:admin` — credential minting (`/human/agent*`) plus the
    template-creation surface below.
  - `sandswap:ops` — operations staff: read the fleet (`/stats`, `/metrics`),
    act on stuck ownership, the fleet switches, agent credential minting
    (`/human/agent*`), AND template creation/mutation
    (`pull`/`push`/`delete`/`save-as-template`). Ordinary namespace users do
    not create templates; ops/admin provide them.
    ownership (`/human/ownership/*` — release, reap-stuck, reap-stuck-node)
- **Empty issuer = auth disabled** (passthrough) — the dev default;
  production sets an issuer.
- All `authn.*` settings are **restart-required** (the provider is built at
  startup); a bad issuer fails startup loudly rather than serving
  unprotected.
- Verified end-to-end against a real IdP by `e2e/oidc-keycloak.sh` (Keycloak
  in docker): the full enforcement matrix across all three scopes (including
  a user-scoped token being refused on `/human/agent`, and only the ops
  scope passing the `/human/ownership/*` gate), agent provisioning through
  the admin scope, and a live signing-key rotation exercising the JWKS
  force-refresh + old-key grace merge.

### 1.1 Scopes answer "what", the `sandswap_ns` claim answers "whose"

The two axes are independent. A **scope** on the token decides which
endpoint classes the caller may touch (`human` / `admin` / `ops`); the
multivalued **`sandswap_ns` claim** decides whose resources:

- `["acme","beta"]` grants exactly those namespaces, via
  `/human/ns/{ns}/…`.
- `["*"]` is the fleet shape — and the **only** grant that reaches the
  unscoped `/human/agent*` + `/human/sandfs*` routes.
- An absent claim denies both. Scopes and namespaces are orthogonal: a
  token with `sandswap:ops` but no `sandswap_ns` can read `/stats` and
  reclaim ownership, yet cannot create anything in any namespace.

#### Where namespaces come from

There is **no namespace registry** in Sandswap — no namespace object in
etcd, nothing to create or list. Which namespaces exist, and who may act in
them, is entirely the IdP's user/group data: **creating a namespace means
granting the claim in the IdP, nothing else**. Sandswap only ever reads the
claim off a verified token.

#### Configuring the claim (Keycloak recipe)

The working setup, exactly as provisioned by `e2e/oidc-keycloak.sh`
(Keycloak in docker, verified end to end):

1. **Declare the user attribute** in the realm's declarative user profile —
   Keycloak 24+ silently *drops* undeclared user attributes, so `sandswap_ns`
   must be declared or the grant never persists.
2. **Create a client scope** named `sandswap_ns` (`openid-connect`) and
   attach it to the Sandswap client as an **optional** scope.
3. **Add a multivalued user-attribute mapper** on that scope: user attribute
   `sandswap_ns` → claim `sandswap_ns`, `multivalued: on`,
   **access-token claim: on** (the access token is what the gateway sees —
   an id-token-only claim is invisible to it), JSON type `String`.
4. **Set the attribute per user** (or group): the value is a JSON list,
   e.g. `["*"]` for the fleet shape, `["acme"]` for one tenant.
5. Also add an **audience mapper** for `client_id` on the client — without
   it, password-grant access tokens carry no audience and fail the
   gateway's audience check.

#### Getting the claim into the token

The claim lands only when the scope is requested at mint time:

```bash
# Password grant (the e2e shape) — sandswap_ns must be in the scope list:
curl -sS "$ISSUER/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=sandswap-api" \
  -d "username=$USER" -d "password=$PASS" \
  -d "scope=openid sandswap_ns" | jq -r .access_token
```

Decode the access token to verify (the gateway does exactly this):

```json
{ "iss": "https://your-tenant.example.com/",
  "aud": "sandswap-api",
  "scope": "openid sandswap:admin",
  "sandswap_ns": ["acme"] }
```

Any IdP works as long as the **access token** carries `sandswap_ns` as a
JSON array of strings (a bare string is also accepted). Malformed entries —
invalid namespace names, non-strings — are **dropped, never widened**: the
IdP is the grant authority, but a typo cannot grow a grant.

#### How the gateway consumes it

On every `/human/*` request:

1. `Authorization: Bearer <token>` → JWT signature (JWKS), issuer, and
   audience validated; scopes checked against the route class (§1 above).
2. The verified claims — including `sandswap_ns` — are resolved into the
   request's namespace grant.
3. The namespaced handler then enforces the two rules: **path grant** (the
   `{ns}` in the URL must be in the claim, else `403 NAMESPACE_FORBIDDEN`)
   and **record match** (a cross-namespace id is a uniform `404` — no
   enumeration oracle). Unscoped routes additionally require `*`
   (`403 FLEET_SCOPE_REQUIRED`).

With auth disabled (no issuer — only reachable under the explicit
`-allow-anonymous-human` opt-out; without it the human listener refuses to
start) the **unscoped** surface resolves as the full fleet, preserving the
unauthenticated behavior; the **namespaced** surface refuses anonymous
callers with `403 NAMESPACE_FORBIDDEN` (no identity ⇒ no namespace grants).
The conceptual model and the full rule table are in
[Namespaces](../how-it-works/namespaces.md) and the
[Human API Reference](../reference/human-api.md#namespaces).

## 2. mTLS-or-OIDC mode

Set `authn.mtls_trust_cert: true` (with a CA on the human listener,
`-human-tls-ca`) and the middleware accepts **either** credential:

- A verified **mTLS client certificate** → full scope
  (`sandswap:human` + `sandswap:admin` + `sandswap:ops` **and** the `*`
  namespace wildcard); subject = the certificate CN. Expired /
  not-yet-valid certs are rejected explicitly (defense in depth beyond the
  handshake).
- Otherwise fall back to the **OIDC Bearer token** path above.

This serves the common pattern where operators hold client certificates
while scripts/integrations use tokens.

## 3. What does NOT change

- The **agent API key model** is untouched by OIDC: agent keys are minted
  by `POST /human/agent` regardless of how your operators authenticate.
  An OIDC token never authorizes `/agent/*`, and an agent key never
  authorizes `/human/*`.
- `/health` and `/ready` are always unauthenticated (load balancers).
