---
title: Namespaces
nav_order: 15
parent: How It Works
---

# Namespaces

Namespaces are the human-API tenancy dimension: they partition **agents**
and **SandFS instances** on the human API so one tenant's operator (or
agent) cannot see, create, or touch another tenant's resources. The
**exec plane is untouched** — an agent's API key already scopes
everything it can do (`/agent/execute`, `/agent/file`), and a microVM mounts
exactly one SandFS.

The single most important fact about namespaces: **sandswap keeps no
namespace registry**. There is no namespace object, no create-namespace
API, no etcd key. A namespace exists exactly where an IdP says it exists.

## 1. The IdP is the authority

A namespace is granted by the **`sandswap_ns` claim** in the caller's OIDC
token (Keycloak: a client scope with one multivalued user-attribute mapper —
the provisioning recipe is in `e2e/oidc-keycloak.sh`, Phase 1). The claim
value is a list:

| Claim value | Meaning |
|-------------|---------|
| `["acme", "acme-prod"]` | the caller may act in exactly those namespaces |
| `["*"]` | fleet-wide access — the admin/operator shape; the **only** grant that reaches the unscoped `/human/agent*` + `/human/sandfs*` routes |
| absent / `[]` | no namespace access at all: every namespaced route **and** the unscoped CRUD surface answer 403 |

Creating a namespace = granting the claim in the IdP. Renaming, deleting,
listing who-has-what — all IdP work, zero sandswap involvement. Sandswap
records merely **carry** the name; nothing in the system enumerates
namespaces.

## 2. The two rules

Every request on the namespaced surface is checked by two rules, in order:

**Rule 1 — path grant (403, no store access).** The path's namespace must
appear in the caller's claim set (or the claim is `*`). A denied caller
gets `403 NAMESPACE_FORBIDDEN` and learns nothing about the namespace's
contents — the check runs before any identity-store lookup.

**Rule 2 — record match (uniform 404).** The addressed record must live in
the path's namespace. Anything else — missing id, another tenant's id, an
id from a *different* namespace — gets the **same** `404 {"error": "agent
not found"}` / `404 {"error": "sandfs not found"}`. Identical bodies for
all three cases: a 403 would leak that the id exists somewhere (an
enumeration oracle); a 404 tells a tenant nothing (the uniformity
principle, extended to tenancy).

The unscoped routes are subject to a **fleet gate** instead: with OIDC
active, `/human/agent*` and `/human/sandfs*` require the `*` grant
(`403 FLEET_SCOPE_REQUIRED` otherwise). Templates, ownership, maintenance,
`/stats`, `/metrics` are **cluster-level** — they are deliberately not
namespace-addressable; their own scope rules (`sandswap:human` /
`sandswap:admin` / `sandswap:ops`) govern them as before.

## 3. Path shapes

```
/human/ns/{ns}/agent            POST create (stamps ns) · GET list (paginated)
/human/ns/{ns}/agent/{id}       DELETE
/human/ns/{ns}/sandfs           POST create · GET list (paginated)
/human/ns/{ns}/sandfs/{id}      GET · DELETE
/human/ns/{ns}/sandfs/{id}/detach-template | attach-template | swap-template |
                                save-template | rootfs-path     POST
/human/{agent,sandfs}…          the unscoped surface = fleet (admin) shape
```

Everything on the namespaced surface behaves byte-identically to its
unscoped twin **except** for the two rules and create-time stamping:

- `POST /human/ns/{ns}/agent` stamps `namespace = {ns}` on the new agent.
- `POST /human/ns/{ns}/sandfs` requires the named agent to sit in `{ns}`
  (uniform 404 otherwise) and the SandFS **inherits** the agent's
  namespace, frozen for its lifetime. A SandFS can never sit in a different
  namespace than its agent — the pair is immutable, and the request body
  carries no namespace field to disagree with.

Namespace names follow a DNS-label grammar — lowercase first letter,
letters/digits/hyphens inside, no leading/trailing hyphen, ≤ 63 chars
(regex `^` + `[a-z]` + an optional `…` tail ending in a letter or digit;
see `ValidNamespace` in `gateway/identity`). The same grammar validates
claims and paths, so a name in an IdP grant is always a name a path can
carry. The wildcard `*` is legal only **inside** the claim set — never as a
namespace name.

## 4. Data model and the exec plane

`namespace` is a plain field on the agent and SandFS records (etcd values;
it rides the **hot** SandFS record for the same reason `status` does — the
human gateway's watch-fed cache is what per-namespace listing and Rule 2
read, and that cache is built from hot records only). Per-namespace listing
filters that cache — no new etcd key family, no transaction changes, no
index to keep consistent.

The exec plane ignores the field entirely: `/agent/*` auth is the
API-key digest lookup, scheduling/pool/lease/ownership never consult it,
and the microVM neither knows nor cares. This is the deliberate blast-radius
choice — tenancy is a control-plane concern only.

## 5. The `default` namespace

Records whose namespace field is empty are read as `default`. Operators
minting through the unscoped surface (with the `*` grant) create agents in
`default` too. A tenant granted `default` sees those records exactly like
explicit ones — there is no privileged hidden namespace.

## 6. Passthrough (no OIDC configured)

With `-authn-issuer` unset the human listener only starts under the explicit
`-allow-anonymous-human` opt-out (without it the gateway refuses to start).
In that anonymous shape there are no claims at all: the **unscoped** fleet
gate resolves as fleet and behaves exactly as before the feature existed —
which preserves the compatibility contract ("auth stays opt-in; with auth
off, operator semantics"). The **namespaced** subtree is the one exception:
with no identity there are no namespace grants, so `/human/ns/…` refuses the
anonymous caller with `403 NAMESPACE_FORBIDDEN` rather than granting every
namespace.

## 7. What a tenant workflow looks like

```
# IdP (once, by the operator): grant acme to a Keycloak user attribute
#   sandswap_ns = ["acme"]   (+ client scope sandswap_ns on the token)

# the tenant mints an agent and a SandFS inside its namespace
curl -H "Authorization: Bearer $TOKEN" -d '{"name":"ci-bot"}' \
     https://gw/human/ns/acme/agent
# → {"agent_id":"agent-1b2c…","api_key":"sk-sandswap-agent-…"}

curl -H "Authorization: Bearer $TOKEN" -d '{"agent_id":"agent-1b2c…",
     "name":"work","template":"ubuntu:24.04","mode":"flat"}' \
     https://gw/human/ns/acme/sandfs

# sandctl equivalents (the -ns flag maps onto the same paths)
sandctl api agent create -ns acme -name ci-bot
sandctl api sandfs list  -ns acme
```

The minted agent's API key works on `/agent/*` with no namespace anywhere
in the picture — execution auth remains key-scoped.

## 8. Reference

- API reference (request/response shapes, error codes):
  [Human API — Namespaces](../reference/human-api.md#namespaces)
- Gateway authn configuration: [Gateway configuration](../operations/configuration/gateway.md)
- Live IdP provisioning + enforcement matrix: `e2e/oidc-keycloak.sh`
- Enforcement unit pins: `gateway/handler/namespace_test.go`,
  `gateway/authn/namespace_test.go`, `gateway/identity/namespace_test.go`
