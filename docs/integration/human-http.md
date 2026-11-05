---
title: Human HTTP Integration
nav_order: 3
parent: Integration
---

# Human HTTP Integration

The control-plane workflow: how an operator (or a provisioning script /
control-plane service) creates the resources agents then use — an **agent**
identity and the **SandFS instances** it owns. Every example on this page is
runnable `curl` against a deployed gateway. The complete endpoint
reference — every field, status code, and error body — is the
[Human API Reference](../reference/human-api.md).

## 1. Where this fits

```
operator / control plane            agent process
      │                                  │
      │ POST /human/agent                │
      │◀── agent_id + api_key (once)     │
      │ POST /human/sandfs               │
      │◀── sandfs_id                     │
      │      (hand sandfs_id to agent)   │
      │                                  ▼
      └──────────────────────▶ POST /agent/execute (api_key + sandfs_id)
```

Everything on the left is the human listener (`:3100` in distributed mode);
everything on the right is the agent listener. The two never mix: agents
cannot call `/human/*`, and the operator's credentials are not the agent's
API key.

## 2. Quickstart

Two calls stand up a working sandbox (auth disabled — the dev default;
with OIDC configured add `-H "Authorization: Bearer $TOKEN"` to every call,
see [Auth Integration](auth.md)):

```bash
GW=https://sandswap.local:3100   # human listener; single-node: :3100 on the gateway

# 1. Create the agent identity — the API key is returned EXACTLY once.
curl -sS -X POST "$GW/human/agent" \
  -H 'Content-Type: application/json' -d '{"name": "my-agent"}'
```

```json
{"agent_id":"agent-1a2b3c4d","api_key":"sk-sandswap-agent-9f…64-hex","name":"my-agent"}
```

```bash
# 2. Create the SandFS the agent will run in.
curl -sS -X POST "$GW/human/sandfs" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-1a2b3c4d","template":"ubuntu:24.04","mode":"flat"}'
```

```json
{"sandfs_id":"sandfs-8e4f2a91","agent_id":"agent-1a2b3c4d","name":"unnamed-sandfs",
 "description":"","rootfs_path":"/var/sandswap/volumes/sf-…","template":"ubuntu:24.04",
 "pull_status":"cached"}
```

Hand `sandfs_id` + `api_key` to the agent process; from then on the agent
executes through the [agent API](agent-http.md). The first create from a
template ref that is not in the local store reports `"pull_status":"pulled"`
— the template was fetched from the OCI registry on demand
([Registry](registry.md)).

## 3. Creating an agent

`POST /human/agent` with `{"name": "..."}` (a missing name defaults to
`unnamed-agent`) returns `201` with `agent_id`, `name`, and `api_key`.

- The key (`sk-sandswap-agent-` + 64 hex chars from `crypto/rand`) is
  returned **exactly once** — store it at creation time. The identity store
  keeps only its hash, so a lost key means deleting and re-creating the
  agent (which deletes its SandFS instances too).
- Generation is fail-fast: an unavailable system PRNG aborts the request
  rather than ever issuing a predictable or shared key.
- `sandctl api agent create --name ...` wraps this call and caches the key
  locally for convenience.

## 4. Creating a SandFS

`POST /human/sandfs` — the fields that matter:

| Field | Notes |
|---|---|
| `agent_id` | required — the owner. Every subsequent agent call against this SandFS is authorized against this binding. |
| `template` | a template ref (`base:v1`, `sqlite:v1`, `ubuntu:24.04`, …). See [Templates](../how-it-works/templates.md) and [building your own](../building/templates.md). |
| `mode` | `flat` (writable copy, OS package managers work) or `overlay` (read-only shared base + writable `workspace/`, least privilege, no OS packages). Required — not auto-detected. |
| `name`, `description` | optional; the description (≤ 200 chars) is what the agent sees in `GET /agent/sandfs` / `list_sandfs` — write it for the LLM that will pick the sandbox. |
| `vcpus`, `memory_mb` | optional minimum resources; `0` inherits the template default. |

**Mode choice is also the security posture**: overlay drops all
capabilities in-guest (language packages still install to `/home/agent`
and persist); flat keeps ambient capabilities so `apt` works. The common
pattern: build in a flat SandFS, `save-template`, run production instances
in overlay.

## 5. How ids stay unique

You never choose `agent_id` or `sandfs_id` — the gateway mints both:

- Format: `agent-xxxxxxxx` / `sandfs-xxxxxxxx` — 8 hex chars (32 random
  bits) from a UUID.
- The etcd **record key is the id** (`sandfs/<id>`), so an existing-key
  check is the authoritative collision test; on collision the gateway
  regenerates and retries (bounded draws) instead of failing the create.
- The on-disk volume **directory is not the id**: names are derived
  (`sf-` + HMAC of the deployment seed — [isolation §4](../how-it-works/isolation-and-swap.md#4-the-host-side-boundary-the-virtio-fs-filter)),
  so the record's `rootfs_path` is the only supported way to learn a host
  path. Never construct `<volumes>/<sandfs-id>`.

Treat ids as opaque stable addressing: hand them out once at provisioning
time (`GET /agent/sandfs` is the agent's own discovery path) and don't
re-derive them.

## 6. Listing and lifecycle polling

The fleet-wide list endpoints are **cursor-paginated** (a million-record
fleet never materializes in one response):

```bash
curl -sS "$GW/human/sandfs?limit=100"                    # first page
curl -sS "$GW/human/sandfs?limit=100&cursor=$NEXT"       # next page
```

```json
{"items":[{"sandfs_id":"sandfs-8e4f2a91","agent_id":"agent-1a2b3c4d",
  "name":"unnamed-sandfs","description":"","rootfs_path":"/var/sandswap/volumes/sf-…",
  "template":"ubuntu:24.04","mode":"flat","min_vcpus":0,"min_memory_mb":0,
  "created_at":"2026-10-14T09:00:00Z","status":""}],
 "next_cursor":"sandfs-9a…","truncated":true}
```

- `status` is the lifecycle state: `""` = active; `detaching` / `detached`
  mid template swap; `deleting` mid deletion. `GET /human/sandfs/{id}` is
  the single-record polling endpoint for those transitions.
- The last page omits `next_cursor`. Iteration order is ascending by ID.

## 7. Multi-tenant provisioning: namespaces

The tenancy surface `/human/ns/{ns}/…` mirrors agent and SandFS CRUD one
level deeper — a token scoped by the `sandswap_ns` claim can only touch its
own namespaces:

```bash
curl -sS -X POST "$GW/human/ns/acme/agent" \
  -H 'Content-Type: application/json' -d '{"name": "acme-agent"}'
curl -sS -X POST "$GW/human/ns/acme/sandfs" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-…","template":"ubuntu:24.04","mode":"overlay"}'
```

Rule 1 (path grant): a namespace not in the caller's `sandswap_ns` claim is
`403 NAMESPACE_FORBIDDEN`. Rule 2 (record match): a cross-namespace id is a
uniform `404` — no enumeration oracle. The unscoped fleet-wide routes
require the `*` grant (`403 FLEET_SCOPE_REQUIRED` otherwise). The full
model: [Namespaces](../how-it-works/namespaces.md).

## 8. Day-2 operations from the control plane

- **Templates**: pull/push/save-template/delete — the lifecycle and the
  in-use guard are in [Registry](registry.md) and
  [building/templates](../building/templates.md).
- **Template upgrade in place**: `detach-template` → `attach-template`
  (or the one-shot `swap-template`) re-points an overlay SandFS at a new
  template while `workspace/` and `home/` carry over — the workflow and
  `home` policies are in the [Human API Reference](../reference/human-api.md#template-swap-detach--attach--swap-template).
- **Maintenance window**: `POST /human/maintenance` `{"on":true,"reason":"…"}` —
  agent traffic is refused `503 MAINTENANCE` cluster-wide (no restarts);
  flip `on:false` to resume. Used around storage moves such as the
  volume-seed rotation.
- **Ownership recovery**: `POST /human/ownership/release/{sandfs_id}`,
  `reap-stuck`, `reap-stuck-node` — the operator backstops behind the
  automatic resilience machinery; semantics and guards in
  [Resilience](../how-it-works/resilience.md) and the
  [reference](../reference/human-api.md#ownership-release).
- **Deletion is cascading**: deleting an agent deletes all SandFS it owns
  (volumes + records). Deleting a SandFS first flips it `deleting`, drains
  every mount, then removes storage + record + ownership key.
- **Observability**: `/stats` (cluster view of every gateway/node/VM) and
  `/metrics` (same data, Prometheus format — [Prometheus Integration](prometheus.md)).
