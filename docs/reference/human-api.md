---
title: Human API Reference
nav_order: 1
parent: Reference
---

# Human API Reference

The control-plane HTTP API: agent/SandFS/template CRUD, ownership
operations, and cluster statistics. Everything here is operator-facing; the
agent-facing surface is the [Agent API Reference](agent-api.md) (integration
walkthrough: [Agent HTTP Integration](../integration/agent-http.md)).

Field names, types, defaults, and status codes below are taken directly from the
handler structs and route registration in `gateway/` — the code is the source
of truth. For CLI flags and YAML config, see
[Gateway configuration](../operations/configuration/gateway.md); for the resilience behavior
behind the ownership endpoints, see
[Resilience](../how-it-works/resilience.md).

All examples below assume these shell variables (`AUTH` is empty for the
anonymous dev listener; with OIDC/mTLS configured set it to
`AUTH=(-H "Authorization: Bearer $TOKEN")`):

```bash
GW=${GW:-https://sandswap.local:3100}
AUTH=()          # empty for the anonymous dev listener
AGENT=${AGENT:-agent-1a2b3c4d}
SF=${SF:-sandfs-8e4f2a91}
```

## Listeners & run modes

The gateway runs in three modes (CLI flag `-mode`). Which listeners are active
depends on the mode:

| Mode (`-mode`) | Agent HTTP | Human HTTP | gRPC stream | Identity store | Purpose |
|----------------|:----------:|:----------:|:-----------:|-----------|---------|
| `""` (empty = single-node) | `:3000` | `:3100` | `:9998` (exec + prov) | in-process `MemoryStore` | execution + management in one process, zero external deps |
| `human` | — | `:3100` | `:9998` (prov only) | external persistence `EtcdStore` | Management service: SandFS/agent/template CRUD + the prov-only stream listener that provision-role sandlots dial for every storage op |
| `exec` | `:3000` | — | `:9998` (exec only) | external persistence `EtcdStore` | Execution gateway: `/agent/*` + stream + pool/lease |

`--etcd` is required for `human` and `exec`. Both modes share the same
`EtcdStore` implementation (etcd + local in-process cache synced via watch,
with graceful degradation when etcd is unreachable).

Listener addresses and TLS are configurable per listener:

| Listener | Default addr | Serves | TLS flag | mTLS (client cert) |
|----------|--------------|--------|----------|--------------------|
| Agent HTTP | `-agent-addr :3000` | `/agent/*`, `/mcp`, `/health`, `/ready`; exec mode additionally `/stats`, `/metrics` (`-ops-token-file`-gated, disabled without the flag) | `-agent-tls-cert` / `-agent-tls-key` | `-agent-tls-ca` (TLS 1.2+) |
| Human HTTP | `-human-addr :3100` | `/human/*`, `/health`, `/ready`, `/stats`, `/metrics` | `-human-tls-cert` / `-human-tls-key` | `-human-tls-ca` (TLS 1.2+) |
| gRPC stream (sandlot) | `-stream-addr :9998` | node streams (roles per mode, above) | `-stream-tls-cert` / `-stream-tls-key` | `-stream-tls-ca` (TLS 1.3 only) |

`/human/*` is never registered on the agent listener, and (in single-node
mode) `/stats` and `/metrics` live only on the human listener — registering
them on the agent listener would bypass authentication.

## Authentication

Human endpoints (`/human/*`, `/stats`, `/metrics`) use OIDC Bearer token auth
(`-authn-issuer` / `authn.issuer`). With **no** issuer configured the human
listener refuses to start unless the operator passes `-allow-anonymous-human`
(`authn.allow_anonymous`) — an explicit opt-out that logs the full blast
radius. In that anonymous shape every human endpoint is unauthenticated and
the **namespaced** surface (`/human/ns/{ns}/…`) refuses anonymous callers
outright with `403 NAMESPACE_FORBIDDEN` (no identity ⇒ no namespace grants);
the unscoped fleet gate keeps its passthrough.

Scopes are bucketed by blast radius (`-authn-scope-human` /
`-authn-scope-admin` / `-authn-scope-ops` rename them):

| Scope | Required for |
|-------|--------------|
| `sandswap:admin` | The unscoped credential-minting surface: `/human/agent` and `/human/agent/{agent_id}`. |
| `sandswap:admin` | `/human/agent*` (credential minting) and the same template-creation surface as ops. |
| `sandswap:ops` | `/stats`, `/metrics`, `/human/ownership/*`, `/human/maintenance`, `/human/rotation`, `/human/agent*`, `POST /human/sandfs/{id}/rootfs-path` (and its `/human/ns/{ns}/…` twin), and template CREATION/mutation: `POST /human/templates/{ref}` (pull), `.../push`, `DELETE /human/templates/{ref}`, plus `POST /human/sandfs/{id}/save-template`. |
| `sandswap:human` | SandFS CRUD, the whole `/human/ns/{ns}/…` subtree (including namespaced agent creation), and `GET /human/templates` (list only). Namespace users enumerate and USE the ops-provided templates to create sandfs/agents; they do not create templates. The volume repoint `/rootfs-path` is NOT human scope — it is ops/admin on both surfaces. |

**Scope hierarchy (production).** A human-only (`sandswap:human`) token is a
namespace user: it cannot reach any ops/admin endpoint — the route gate and
the handler-level checks both enforce this. An ops/admin token can reach the
human endpoints (`/human/` uses `RequireAnyScope(human, ops, admin)`); the
unscoped fleet routes still need the `*` namespace grant. **Encoded paths are
refused:** the human listener rejects any request with a non-empty
`RawPath` (404) before routing. Human API identifiers are ASCII tokens; an
encoded slash could otherwise make the mux match one route while the handler
dispatches on another (the `%2F` scope-bypass class).

**Templates are a curated cluster catalog.** Ops/admin create and mutate
them (pull/push/delete/save-template); human namespace users list them
(`GET /human/templates`) and use the refs when creating SandFS. The host
template store is not exposed to human callers: listing and materialization
go through the storage plane (gateway → prov sandlot), so store ownership/permissions can be
tightened without affecting the human list/use path.

A missing or invalid Bearer token is `401 {"error":"invalid token"}` (or
`{"error":"missing or malformed authorization header"}`); a valid token
without the required scope is `403 {"error":"insufficient scope: requires
<scope>"}`.

`-authn-mtls-trust-cert` additionally trusts verified mTLS client certs on the
human listener (full scope: human + admin + ops **and** the `*` namespace
wildcard). `/health` and `/ready` are always unauthenticated.

Scopes answer "what can this token do"; the **`sandswap_ns` claim** answers
"whose resources" — the multivalued namespace grant behind the namespaced
surface (`/human/ns/{ns}/…`). Claim value `["acme","beta"]` grants exactly
those namespaces; `["*"]` is the fleet shape and the only grant that reaches
the unscoped `/human/agent*` + `/human/sandfs*` routes; an absent claim
denies both. A non-`*` grant on an unscoped agent/SandFS route is
`403 FLEET_SCOPE_REQUIRED` (see [Namespaces](#namespaces)). Conceptual model:
[Namespaces](../how-it-works/namespaces.md).

**Method mismatch.** The human handler routes by exact method; an unsupported
method on a known path falls through to `404 {"error":"not found"}` (the one
exception is `/metrics`, which answers `405` for anything but `GET`/`HEAD`).

## Compatibility contract (before changing any human endpoint)

The human API has load-bearing consumers beyond external callers: the e2e
suite's shared setup helper (`tc_create_agent_and_sandfs` in
`e2e/common.sh` — used by nearly every full-stack script), `sandctl`, and
the deploy verification scripts. Any change to a `/human/*` route must
respect four rules:

1. **Add routes, never rename/remove/re-semantic existing ones.** The four
   load-bearing routes are `POST /human/agent`, `POST /human/sandfs`,
   `GET /human/templates`, and `DELETE /human/sandfs/{id}` — the e2e setup
   helper walks exactly these; breaking one fails ~15 scripts at setup.
   New surfaces go on NEW paths (e.g. a future `/human/me/*` namespace).
2. **Owner-style filtering must gate on "OIDC claims present".** With auth
   off (no `-authn-issuer` — the dev default, every e2e/sandctl/deploy
   caller) there are no claims, and the API must behave with operator
   semantics: full visibility, byte-identical to today. Never filter by
   owner with "no owner = invisible".
3. **Response shapes are append-only.** Consumers parse
   `{agent_id, api_key}` and `{sandfs_id, rootfs_path}` — field renames or
   removals break the suite's assertions; additive fields are fine.
4. **Auth stays opt-in, but its absence is now ACKNOWLEDGED.** Deploy-generated
   configs keep authn off — carried by an explicit `allow_anonymous` /
   `-allow-anonymous-human` (the shipped systemd units and k8s manifests pass
   it), since a human listener with no issuer and no opt-out refuses to
   start. Turning
   an issuer on by default would simultaneously 401 the e2e helpers,
   `sandctl` (which sends no Bearer), and the deploy verify scripts — that
   is a coordinated three-front change, never a default flip.

---

## Agent CRUD

### `POST /human/agent` — create agent

**Request** (`CreateAgentRequest`, body limit 1 MB):

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `name` | string | no | Display name; default `unnamed-agent`. |
| `description` | string | no | Free-text label, trimmed, ≤200 Unicode code points, valid UTF-8 (the same rule as a SandFS description). |

**Response** (`201`, `CreateAgentResponse`):

| Field | Type | Notes |
|-------|------|-------|
| `agent_id` | string | Opaque id (`agent-…`). |
| `api_key` | string | `sk-sandswap-agent-` + 64 hex characters. Returned **exactly once**; only its SHA-256 digest is stored. |
| `name` | string | Effective name. |
| `description` | string | The stored (trimmed) description. Persisted in the memory snapshot and the etcd agent row, so it survives restarts and is visible to every gateway. |

**Status codes:** `201`; `400` invalid JSON (an oversize body also fails the
decode and returns `400`); `500` store failure; `401`/`403` per
[Authentication](#authentication).

```bash
curl -sS -X POST "$GW/human/agent" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"name":"my-agent"}'
```

### `GET /human/agent` — list agents (paginated)

Fleet-wide listing pages by ID so a million-record fleet never materializes in
one response.

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 100 | Page size; values above 1000 are clamped to 1000, non-numeric or `< 1` is `400`. |
| `cursor` | string | — | The previous page's `next_cursor`; the next page starts at the first ID strictly greater than it. |

**Response** (`200`, `pagedList`): `{"items": [Agent...], "next_cursor": "<id>",
"truncated": bool}`. `items` are Agent records (`agent_id`, `name`,
`description`, `created_at`, `namespace` — `description`/`namespace` omitted
when empty; legacy records are treated as `default`); `api_key` is never
serialized. The last page omits
`next_cursor`. Iteration order is ascending by ID; records deleted
mid-iteration are skipped.

**Status codes:** `200`; `400` invalid `limit`; `500` store failure; `401`/`403`.

```bash
curl -sS "$GW/human/agent?limit=100" "${AUTH[@]}"
```

### `DELETE /human/agent/{agent_id}` — delete agent

Deletes the agent **and** all SandFS instances it owns (storage volumes + identity
records). Per-sandfs teardown failures are logged with the orphaned paths but do
not fail the call — the agent record is deleted regardless.

**Response** (`204`).

**Status codes:** `204`; `400` invalid id (path separators/traversal); `404`
malformed path; `500` store failure — including an unknown agent (delete is
not a silent no-op); `401`/`403`.

```bash
curl -sS -X DELETE "$GW/human/agent/$AGENT" "${AUTH[@]}"
```

## SandFS CRUD

### `POST /human/sandfs` — create SandFS

**Request** (`HumanCreateSandFSRequest`, body limit 1 MB):

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `agent_id` | string | yes | Owner agent; the SandFS inherits the agent's namespace. |
| `name` | string | no | Defaults to `unnamed-sandfs`. |
| `description` | string | no | Free-form description surfaced by `GET /agent/sandfs`. The codebase convention is ≤200 characters; the gateway does not reject longer values. |
| `template` | string | yes | Template ref (e.g. `mysql:v1`). Must be a single reference token — no `/`, `\`, NUL or `..`, ≤ 256 chars; the same charset rule the storage plane applies is enforced at the gateway, so an impossible ref is a named `400` before any storage round trip. |
| `mode` | string | yes | `flat` \| `overlay`. Required — not auto-detected. |
| `vcpus` | uint32 | no | Minimum vCPUs the sandbox's VM must provide. `0` = no requirement (inherit the template's default, else any). Overrides the template default. |
| `memory_mb` | uint64 | no | Minimum memory (MB) the sandbox's VM must provide. `0` = no requirement (inherit the template's default, else any). Overrides the template default. |

The gateway translates `vcpus`/`memory_mb` into an internal **spec** (e.g.
`small`/`medium`/`large`) at scheduling time, matching the request against each
node's learned spec table (reported by sandlot at connect) and resolving the
smallest fitting spec. The spec name is an internal gateway↔sandlot concept; the
external API never uses spec names. A template-declared minimum above the
largest advertised spec is clamped to it (with a warning) before it is stored,
so a record can never be pinned into permanent `NO_AVAILABLE_SANDBOX`.

`mode` determines the sandbox's package-installation policy, derived rather than
per-request: **flat** mode retains ambient capabilities so OS package managers
(apt/dpkg) work; **overlay** mode drops all capabilities (least privilege, no
OS package installation). A flat SandFS is the template-BUILD environment:
creating flat sandboxes and saving templates is an ops/admin workflow, and a
flat sandbox handed to a tenant carries the 10-capability install profile
inside that tenant's guest (see
[SandFS §6](../how-it-works/sandfs.md#6-security) — in-guest only, no host
effect). The flat build sandbox installs OS packages, and `save-template`
freezes the result into a template that other sandboxes consume in **overlay**
mode. **overlay** still supports installing language-specific packages
without modifying the read-only file sections; any newly installed packages
will be stored under /home/agent.

**Response** (`201`, `HumanCreateSandFSResponse`):

| Field | Type | Notes |
|-------|------|-------|
| `sandfs_id` | string | Opaque id (`sandfs-…`). |
| `agent_id` | string | Owner agent. |
| `name` | string | Effective name. |
| `description` | string | As supplied. |
| `rootfs_path` | string | Host volume directory (seed-derived; use this, never `<volumes>/<sandfs-id>`). |
| `template` | string | Template ref. |
| `pull_status` | string | `pulled` = this create fetched the ref from the OCI registry because it was missing from the local store; `cached` = served from the local store. Failures are HTTP error statuses, never a `pull_status` value. |

**Status codes:**

| Status | `error_code` | When |
|--------|--------------|------|
| `201` | — | Created. |
| `400` | — | Invalid JSON, missing `agent_id`, or an invalid `template` ref charset. |
| `409` | `VOLUME_IDENTITY_MISMATCH` | The volume at the derived name is stamped for another sandfs — an operator must reconcile it. |
| `422` | `TEMPLATE_NOT_FOUND` | The referenced template is unknown to the storage plane (local refs and auto-pull both failed). |
| `503` | — | No provision instance connected (the storage plane is unavailable); retry shortly or check the prov instances. |
| `503` | `ROTATION_IN_PROGRESS` | A volume-seed rotation window is open; `Retry-After: 60`. |
| `500` | — | Other failures: a missing `template` or invalid `mode` (rejected by the registry), an unknown `agent_id`, a materialization failure, or an unusable path returned by the storage plane. |
| `401`/`403` | — | Authentication/scope (see above). |

```bash
curl -sS -X POST "$GW/human/sandfs" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"'$AGENT'","name":"work","template":"ubuntu:24.04","mode":"flat"}'
```

### `GET /human/sandfs` — list all SandFS (paginated)

Fleet-wide listing pages by ID (same protocol as `GET /human/agent`: `limit`
default 100 / max 1000, `cursor` continues after the previous page's last ID).
`limit` non-numeric or `< 1` → `400`.

**Response** (`200`): `{"items": [Record...], "next_cursor": "<id>",
"truncated": bool}`. `Record`:

| Field | Type | Notes |
|-------|------|-------|
| `sandfs_id` | string | Opaque id. |
| `agent_id` | string | Owner agent. |
| `name` | string | Display name. |
| `description` | string | Operator-set description. |
| `rootfs_path` | string | Host volume directory. |
| `template` | string | Template ref (empty for a template-less legacy record). |
| `mode` | string | `flat` \| `overlay` (omitted when empty). |
| `min_vcpus` | uint32 | Minimum vCPUs (omitted when 0). |
| `min_memory_mb` | uint64 | Minimum memory MB (omitted when 0). |
| `created_at` | string | RFC 3339 timestamp. |
| `status` | string | Lifecycle state (omitted when active: `""`; see [Template swap](#template-swap-detach--attach--swap-template)). |
| `namespace` | string | Owning namespace (omitted for legacy records, treated as `default`). |

**Status codes:** `200`; `400` invalid `limit`; `500` store failure; `401`/`403`.

```bash
curl -sS "$GW/human/sandfs?limit=100" "${AUTH[@]}"
```

### `GET /human/sandfs/{sandfs_id}` — get one SandFS

Single-record view of the same `Record` shape — the polling endpoint for the
swap lifecycle (`status` transitions). **Response** (`200`): `Record`.

**Status codes:** `200`; `400` invalid id; `404` unknown; `401`/`403`.

```bash
curl -sS "$GW/human/sandfs/$SF" "${AUTH[@]}"
```

### `POST /human/sandfs/{sandfs_id}/rootfs-path` — re-point a moved volume directory

**Body** (limit 8 KB): `{"rootfs_path": "/var/lib/sandswap/volumes/sf-…"}`.

**Scope:** `sandswap:ops` or `sandswap:admin`, on both the unscoped route
and `/human/ns/{ns}/sandfs/{id}/rootfs-path`. A human-only token gets the
generic `403`; this is a storage-plane maintenance operation, not namespace
SandFS CRUD.

Exists for operations that MOVE a volume directory on the host — the
volume-name seed rotation renames every directory to the next generation and
must then tell the control plane where each one landed
(`deploy/baremetal/rotate-volume-seed.sh --run`). The path is validated
exactly like one arriving from the storage plane: absolute, clean, strictly
inside the volumes root, no traversal — this endpoint can never point a
mount at an arbitrary host directory. The gateway additionally verifies the
target **IS this record's volume** through the prov op `VerifyVolume` (the
node's `.sandfs-id` stamp must name this sandfs id exactly — READ-ONLY; it
never materializes anything).

**Status codes:** `204`; `400` invalid JSON or a path outside the volumes
root; `404` unknown sandfs; `409 VOLUME_IDENTITY_MISMATCH` when the directory
exists but is not proven to be this sandfs's volume (unknown or foreign stamp,
a symlink, a mid-provisioning partial run); `503` no prov instance connected;
`500` other storage/store failures; `401`/`403`.

Because directory names are **derived, not the id** (see
[isolation §4.6](../how-it-works/isolation-and-swap.md)), `rootfs_path` is
the only supported way to learn a volume's host path — never construct
`<volumes>/<sandfs-id>`.

```bash
curl -sS -X POST "$GW/human/sandfs/$SF/rootfs-path" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"rootfs_path":"/var/sandswap/volumes/sf-…"}'
```

### `DELETE /human/sandfs/{sandfs_id}` — delete SandFS

Deletion is lifecycle-gated: the record flips to `deleting` with a
compare-and-set (new execs/file ops are refused with a retryable
`409 SANDFS_NOT_ACTIVE`), every mount is **drained** — the in-flight sync
exec is waited out via the node-side mount gate and no cold mount dispatch
may still be in flight (the last dispatch's completion triggers a final
unmount sweep before the drain settles; bounded by the drain budget; on
deadline the deletion PROCEEDS, since the operator asked for the sandfs to
go) — then the host-side overlay is cleaned, storage removed, and the etcd
ownership key released. On a split deployment the key belongs to the exec
OWNER: the owner releases it when its drain settles to `detached` (a
foreign release is a no-op), and the delete returns success only after the
key is observed ABSENT (bounded poll). A key still held by another gateway
after the poll surfaces as an error naming it rather than a silent `204`.

**Response** (`204`).

**Status codes:** `204`; `400` invalid id; `409 VOLUME_IDENTITY_MISMATCH`;
`503` no prov instance connected; `500` a terminal failure, including an
unknown id (delete is not a silent no-op) and a failed ownership-key release;
`401`/`403`.

```bash
curl -sS -X DELETE "$GW/human/sandfs/$SF" "${AUTH[@]}"
```

## Template swap (detach / attach / swap-template)

An **overlay** SandFS can change its read-only template while keeping every
byte of agent work: `workspace/` and `home/` live in the volume, independent
of the template layers — a swap only re-points the `rootfs/` overlay at a new
template (see [SandFS — template swap](../how-it-works/sandfs.md#5-template-swap-detachattach)).

**Lifecycle states** (visible on every `Record`): `""` active → `detaching` →
`detached` → (attach) active; or `""` → `deleting` → terminal delete. While
non-active, execs and file ops against the sandfs get `409 SANDFS_NOT_ACTIVE`;
exec status/kill keep working (they degrade to `expired` once the drain kills
in-guest processes). On split deployments (separate human + exec gateways) the
exec gateway learns the status via its etcd identity watch and performs the
drain itself; the endpoints below poll the record until it settles.

### `POST /human/sandfs/{id}/detach-template`

**Body** (optional, limit 1 MB): `{ "wait_sec": 15 }`.

Gates execs (`detaching`), drains every mount, settles to `detached`. Idempotent;
re-issuing resumes a drain that outlived its budget. `wait_sec` is clamped to a
600 s ceiling (`0`/negative = the 15 s default) and the response echoes the
value actually applied.

**Response** (`DetachTemplateResponse`): `{sandfs_id, status, wait_sec}`.
`200` when settled (`status: "detached"`); `202` + the current status when the
drain outlived its budget (a long in-flight exec needs a proportionate
`wait_sec`).

**Status codes:** `200`/`202`; `400` invalid JSON or a flat-mode sandfs (no
separate template layer); `404` unknown; `409` a deletion is in progress (the
delete owns the lifecycle); `401`/`403`.

```bash
curl -sS -X POST "$GW/human/sandfs/$SF/detach-template" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"wait_sec":15}'
```

### `POST /human/sandfs/{id}/attach-template`

**Body** (limit 1 MB): `{ "template_ref": "app:v2", "home": "keep" }`.

Requires `status=detached` (`409` otherwise). Re-points the volume at the new
template (auto-pulls the ref when a registry is configured; a missing ref with
no auto-pull is `422 TEMPLATE_NOT_FOUND`) and completes the record in one write
(new `template`, new declared min resources, status back to active).

`home` policy:

- `keep` (default) — `/home/agent` content carries over; plain files, at worst
  stale, never destructive.
- `archive` — renamed to `home.pre-attach-<unixts>`, fresh empty home, newest
  archive kept.
- `reset` — wiped.

`workspace/` is never touched. `template_ref` obeys the ref charset rule (single
token — no `/`, `\`, NUL or `..`; ≤ 256 chars).

**Response** (`200`, `AttachTemplateResponse`): `{sandfs_id, template,
status: "active", min_vcpus?, min_memory_mb?}` (min resources omitted when 0).

**Status codes:** `200`; `400` invalid JSON, missing/invalid `template_ref`,
invalid `home`, or a flat-mode sandfs; `404` unknown; `409` not detached (or
the record left `detached` during the attach — the storage swap landed, so
re-attach once the status is stable); `409 VOLUME_IDENTITY_MISMATCH`; `422
TEMPLATE_NOT_FOUND`; `503` no prov instance; `500` other failures; `401`/`403`.

```bash
curl -sS -X POST "$GW/human/sandfs/$SF/attach-template" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"template_ref":"app:v2","home":"keep"}'
```

### `POST /human/sandfs/{id}/swap-template`

**Body** (limit 1 MB): `{ "template_ref": "app:v2", "home": "keep", "wait_sec": 15 }`.

The one-shot detach+attach composition for the common upgrade path. The body is
validated before any state changes. `200` on completion, `202` when the drain
outlived its budget (the attach never runs on a non-detached sandfs; re-issue to
resume). The `202` body is the same `{sandfs_id, status, wait_sec}` shape with
the same clamped/echoed budget. `template_ref` obeys the ref charset rule,
refused as a named `400` at the gateway before any storage round trip.

**Status codes:** `200`/`202`; `400` invalid JSON, missing/invalid
`template_ref`, invalid `home`, or a flat-mode sandfs; `404` unknown; `409` a
deletion is in progress; `409 VOLUME_IDENTITY_MISMATCH`; `422
TEMPLATE_NOT_FOUND`; `503` no prov instance; `500` other failures; `401`/`403`.

```bash
curl -sS -X POST "$GW/human/sandfs/$SF/swap-template" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"template_ref":"app:v2","home":"keep","wait_sec":15}'
```

### `POST /human/sandfs/{sandfs_id}/save-template` — save as local template

Flat-mode SandFS only (the storage plane rejects an overlay volume because its
rootfs is a read-only overlay). **Request** (`SaveAsTemplateRequest`, body limit
1 MB):

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `template_ref` | string | yes | New local ref in `name:version` form (e.g. `sqlite:v2`). |
| `description` | string | no | Template description. |
| `vcpus` | uint32 | no | Minimum vCPUs for SandFS created from this template; defaults to the source SandFS's `min_vcpus`. |
| `memory_mb` | uint64 | no | Minimum memory MB; defaults to the source SandFS's `min_memory_mb`. |

**Response** (`200`, `SaveAsTemplateResponse`): `{template_ref, path, size_kb}`.

The save copies the live volume as-is: quiesce the SandFS first (stop agent
executions / wait for background execs to finish) if you need a
point-in-time-consistent template — concurrent writes during the copy can be
torn across the snapshot.

**Status codes:** `200`; `400` invalid JSON, a missing `template_ref`, or a
`template_ref` outside the ref charset rule (the gateway validates it before any
storage round trip); `409` the sandfs is not active (mid swap/deletion); `503`
no prov instance connected; `500` storage-plane failures, including an overlay
sandfs, an unknown sandfs, a volume whose verified identity stamp names a
different sandfs, or an unwritable target; `401`/`403`.

```bash
curl -sS -X POST "$GW/human/sandfs/$SF/save-template" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"template_ref":"sqlite:v2","description":"after setup","vcpus":2,"memory_mb":512}'
```

## Namespaces

The tenancy surface `/human/ns/{ns}/…` mirrors the agent and SandFS CRUD
routes one level deeper. Full model and rules:
[Namespaces](../how-it-works/namespaces.md). Summary:

| Method | Path | Behavior |
|--------|------|----------|
| `POST` | `/human/ns/{ns}/agent` | Create agent **in `{ns}`** (the record carries `namespace: "{ns}"`). Same body/response as the unscoped create. |
| `GET` | `/human/ns/{ns}/agent` | Paginated listing of `{ns}`'s agents only (same envelope). |
| `DELETE` | `/human/ns/{ns}/agent/{agent_id}` | 404 unless the agent exists **and** sits in `{ns}` (uniform body: `{"error": "agent not found"}`). |
| `POST` | `/human/ns/{ns}/sandfs` | Create; the named agent must sit in `{ns}` (uniform `404 agent not found` otherwise); the SandFS inherits the agent's namespace. |
| `GET` | `/human/ns/{ns}/sandfs` | Paginated listing of `{ns}`'s SandFS only. |
| `GET` | `/human/ns/{ns}/sandfs/{sandfs_id}` | 404 unless the record sits in `{ns}` (uniform `{"error": "sandfs not found"}`). |
| `DELETE` | `/human/ns/{ns}/sandfs/{sandfs_id}` | Same gate; then the normal delete (drain → volume+record). |
| `POST` | `/human/ns/{ns}/sandfs/{sandfs_id}/detach-template` · `/attach-template` · `/swap-template` · `/save-template` | Same gate, then the unscoped twin's behavior verbatim. |
| `POST` | `/human/ns/{ns}/sandfs/{sandfs_id}/rootfs-path` | Namespace gate **plus `sandswap:ops`/`sandswap:admin`** — the repoint is a storage-plane maintenance operation. A human-only token gets `403`. |

Namespace names: DNS-label shape (`ValidNamespace` in `gateway/identity` —
lowercase first letter, letters/digits/hyphens, no leading/trailing hyphen,
≤ 63 chars). An invalid name in the path is a `400` before any grant
logic.

**Rule order and error codes** (Rule 1 is checked before any store access;
Rule 2 gates every record access):

| Status | `error_code` | When |
|--------|--------------|------|
| `403` | `NAMESPACE_FORBIDDEN` | Rule 1: no verified identity at all (anonymous listener), or the path's namespace is not in the caller's `sandswap_ns` claim. The body carries the namespace name, nothing else. |
| `403` | `FLEET_SCOPE_REQUIRED` | A non-`*` token reached the **unscoped** `/human/agent*` / `/human/sandfs*` surface. The body points at `/human/ns/<ns>/…`. |
| `404` | (none) | Rule 2: missing id, another tenant's id, or a cross-namespace id — deliberately **the same body** in all three cases (no enumeration oracle). |

`sandctl` reaches the surface with the `-ns` flag
(`sandctl api agent create -ns acme …`, `sandctl api sandfs list -ns acme`).

```bash
curl -sS -X POST "$GW/human/ns/acme/agent" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"name":"acme-agent"}'

curl -sS -X POST "$GW/human/ns/acme/sandfs" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-…","template":"ubuntu:24.04","mode":"flat"}'

curl -sS "$GW/human/ns/acme/sandfs" "${AUTH[@]}"

curl -sS "$GW/human/ns/acme/sandfs/$SF" "${AUTH[@]}"

curl -sS -X POST "$GW/human/ns/acme/sandfs/$SF/detach-template" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"wait_sec":15}'

curl -sS -X DELETE "$GW/human/ns/acme/sandfs/$SF" "${AUTH[@]}"
```

## Templates

### `GET /human/templates` — list locally cached templates

**Response** (`200`): array of `TemplateSummary` — `name`, `version`,
`description`, `mode` (`flat` \| `overlay`), `cached` (always `true` for a
locally stored ref). OCI-registry templates not yet pulled are not included.
When the storage plane is unavailable the response is an empty array.

**Status codes:** `200`; `401`/`403`.

```bash
curl -sS "$GW/human/templates" "${AUTH[@]}"
```

### `POST /human/templates/{ref}` — pull a template from OCI registry

**Body** (optional, limit 1 MB): `{"mode": "flat" | "overlay"}`;
absent/empty defaults to `overlay`. Overlay mode downloads and extracts every
layer into the shared content-addressed cache (`layers/sha256-<digest>/`). Flat
mode reads only the manifest and records the layer digests in the ref file —
the blobs stream straight into each SandFS volume at creation time, so a flat
pull downloads nothing and caches nothing.

**Response** (`200`, `PullTemplateResponse`): `{template_ref, name, version,
cached: true}`.

**Status codes:** `200`; `400` invalid JSON or an id containing a path
separator (the route's path-id check); `503` no prov instance connected; `500`
pull failures (unknown registry ref, a ref the storage plane rejects, no
registry configured, invalid mode, network/auth errors); `401`/`403`.

```bash
curl -sS -X POST "$GW/human/templates/ubuntu:24.04" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"mode":"overlay"}'
```

### `POST /human/templates/{ref}/push` — push a local template to OCI registry

**Body** (optional, limit 1 MB): `{"mode": "flat" | "overlay"}`; absent/empty
auto-detects from whichever mode-suffixed ref file exists (overlay first). An
auto-detect miss is a local `404`. OCI-origin flat templates (digest-only, no
local content) are rejected by the storage plane.

**Response** (`200`, `PushTemplateResponse`): `{template_ref, digest, layers,
size, push_time_ms}`.

**Status codes:** `200`; `400` invalid JSON; `404` no ref file for the
auto-detected mode (with an empty `mode`, an unreachable storage plane also
surfaces here because the mode probe cannot resolve); `503` no prov instance
connected (explicit `mode`); `500` push failures (invalid mode, OCI-origin
flat, no registry configured, transport/auth errors); `401`/`403`.

```bash
curl -sS -X POST "$GW/human/templates/sqlite:v2/push" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"mode":"overlay"}'
```

### `DELETE /human/templates/{ref}` — delete a template

**Body** (optional, limit 1 MB): `{ "mode": "overlay", "force": false }` —
`mode` absent/empty auto-detects (overlay ref first).

Two-layer in-use check, refused with `409` + `error_code: TEMPLATE_IN_USE`
while any overlay volume still names the ref in its `.template` marker:
first this gateway's identity records (fast local scan), then the node-side
marker scan over the volumes root (catches orphan volumes whose records are
already gone). Flat templates skip the marker scan — flat volumes copy
content at creation and hold no runtime dependency.

The refusal's `in_use_count` is every caller's to see; the sampled sandfs ids
(`in_use_sample`, and the `error` text naming them) ride ONLY for a caller
carrying the `sandswap:ops`/`sandswap:admin` grant — a plain tenant token
gets the count alone, so the refusal cannot be used to enumerate other
tenants' sandfs. Passthrough (no OIDC claims) keeps the full payload.

On success the ref file is removed and the `layers/` entries that NO
remaining ref names are garbage-collected (layers are content-addressed and
shared across refs — a shared base layer survives until its last referent is
deleted). `force: true` skips the check: dependent volumes fail their NEXT
cold mount with a named error (no data loss — workspace/home are
layer-independent). Because it destroys cluster-shared state other tenants
depend on, `force: true` requires the `sandswap:ops`/`sandswap:admin` scope —
a plain tenant token gets a named `403 FORCE_REQUIRES_OPS`, deliberately
identical whether or not any volume holds the ref (no in-use oracle).
`204` on success.

**Status codes:**

| Status | `error_code` | When |
|--------|--------------|------|
| `204` | — | Deleted. |
| `400` | — | Invalid JSON (an oversize body also fails the decode). |
| `403` | `FORCE_REQUIRES_OPS` | `force: true` from a caller without the ops/admin grant. |
| `409` | `TEMPLATE_IN_USE` | Overlay sandfs still reference the ref; body carries `in_use_count` (+ `in_use_sample` for ops/admin callers). |
| `422` | `TEMPLATE_NOT_FOUND` | Empty `mode` and the ref exists in neither mode. |
| `503` | — | No prov instance connected. |
| `500` | — | Other storage failures (explicit `mode` mismatch, layer-GC list failure, …). |
| `401`/`403` | — | Authentication/scope. |

**Shared storage-plane error classes** (emitted by save-template, template
pull/push, and delete; the raw storage error stays in the node log — it can
embed host paths):

| Status | `error_code` | When |
|--------|--------------|------|
| `403` | `TEMPLATE_OPS_REQUIRED` | `save-template` from a caller without the ops/admin scope (namespace users may list/use templates, not create them). |
| `409` | `TEMPLATE_EXISTS` | The ref already exists; refs are immutable. Delete it (under the in-use gate) before creating a new one. |
| `409` | `TEMPLATE_IDENTITY_MISMATCH` | The ref file names a different `name:version` than requested (filename collision or tampering); an operator must reconcile the ref store. |
| `500` | `STORAGE_ERROR` | Any other storage-plane failure; the caller gets this stable class, details are logged only. |

**Retirement loop**: swap every sandfs off a template
(`swap-template`), then delete it — the in-use check drops to zero exactly
when the last marker stops naming the ref.

```bash
curl -sS -X DELETE "$GW/human/templates/sqlite:v2" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"mode":"overlay"}'
```

## Ownership release

### Ownership records and CAS semantics

Each SandFS is owned by exactly one gateway at a time. Ownership is a **plain
etcd key** `/sandswap/owner/{sandfs_id}` with **no lease and no TTL** — it
persists until an explicit mutation. Value (`OwnershipValue`):

| Field | Meaning |
|-------|---------|
| `gateway_id` | Current owner. |
| `node_id` | The SandFS's **placement**: the node it belongs to (last mounted on). Survives unmount; `""` only for a record that was never placed. Mount state itself is transient, memory-only, and never stored in etcd. |
| `generation` | Bumped on create and takeover only. `node_id` publishes are guarded by revision CAS, not by this counter. |

Every create/update/takeover mutation is an etcd transaction with a compare
condition; releases are authoritative deletes of the key (a release is
unconditional by design — it is only issued by the owner, the operator, or the
CAS-guarded reaper):

| Transition | etcd condition | Effect |
|------------|----------------|--------|
| Create / claim | `Version(key) = 0` (key absent) | Put `{gateway_id, candidate node_id, generation 1}`. The claim's candidate placement lands in the same CAS, so `node_id == ""` provably means node selection found nothing and no mount was dispatched. |
| Placement publish | `ModRevision(key) = R` (the revision last observed) | Put the same owner with the new `node_id`. Skipped entirely when the placement is unchanged — steady-state execution performs **zero** etcd writes; only a first mount, re-placement, or takeover writes. |
| Migrated takeover | `ModRevision(key) = R` | Put the claimant, `generation+1`, preserving a non-empty placement. Fires only when the owner is dead (health key absent or `last_healthy_ts` stale past `-claim-dead-guard-sec`, default 45 s) **and** the placement node has a live stream to the claimant with the claimant's presence key — a node can only migrate through `T_tolerance + T_clean + T_isolation > T_safe` and arrives clean, so every old mount is provably gone. |
| Time-guarded claim | `ModRevision(key) = R` | Same overwrite, after the owner is dead **and** (`node_id` empty or the placement node's presence key is absent) **and** `-claim-dead-guard-sec` has elapsed since the first dead observation. The guard clock gives a recovering owner a chance; a never-placed record has nothing to interrogate, and an absent presence key proves the node has been gone ≥ `T_safe`. |
| Owner release | unconditional delete | Explicit release API, SandFS deletion teardown, the owner-release sweep, failure cleanup, or load shedding (below). |
| Reap | `ModRevision(key) = R` | Operator tool's CAS delete (below); a record whose revision moved on is left to its current owner. |

Because takeover is a single revision CAS, concurrent claimants have exactly
one winner; losers re-read and re-judge against the new bytes (the claim loop
is bounded at four attempts, then surfaces a retryable 503). A CAS loss on a
placement publish is compensated by re-reading the record and retrying, or —
if the record vanished or became foreign — by unmounting the now-uncovered
mount.

Ownership is released by exactly these paths:

- **Explicit release** — call it to rebalance a sandfs across gateways.
- **SandFS deletion** — the teardown deletes the key synchronously with a
  bounded retry (five attempts, 1 s apart); persistent failure is a `500`
  naming the orphaned key.
- **Owner-release sweep** — a gateway releases the sandfs placed on a node it
  lost only after the three-part chain: local disconnect observed, `T_safe`
  elapsed locally, and the node's presence key absent (plus the gateway itself
  healthy).
- **Failure cleanup** — after a mount/exec/file-op failure is unmounted, the
  gateway deletes the ownership record so the next request starts from a clean
  create rather than a takeover.
- **Load shed** — a sustained-saturated gateway releases ownership of a cold
  request so DNS re-routes the client to an idle peer; it refuses to re-claim
  the same sandfs during a cooldown window.

Liveness is judged by staleness, never by key disappearance: the health key
`/sandswap/health/{gateway_id}` is also a plain key, and a gateway is dead when
its `last_healthy_ts` is stale past the claim-dead guard (or the key is absent).
The node presence key `/sandswap/node/{node_id}/presence` is the exception: it
IS leased, with TTL = `T_safe`, so absence proves the node has been disconnected
for at least `T_safe` and every mount-release path has finished.

The owner's Claim fast path serves from a local cache for
`-ownership-cache-ttl-sec` (default 30 s), then re-reads etcd; the cache TTL is
the main etcd read-load lever (linearizable Gets/s ≈ active sandfs ÷ TTL).
Tolerance is the default: on health expiry or node disconnect alone ownership
is NOT moved — the agent receives `503` + retry until a confirmed condition
allows a switch. See [Resilience](../how-it-works/resilience.md) for the full
decision table.

### `POST /human/ownership/release/{sandfs_id}` — release ownership

Manually release a sandfs's ownership so another gateway can claim it
(cross-gateway rebalance). Idempotent: any well-formed id returns `200`, even
if the sandfs has no ownership record.

**Response** (`200`): `{ "status": "released", "sandfs_id": "..." }`
(single-node mode, which has no distributed ownership, returns
`{"status":"ok", "sandfs_id":"...", "mode":"single-node"}`).

**Status codes:** `200`; `400` empty or invalid id; `401`/`403` (`sandswap:ops`).

```bash
curl -sS -X POST "$GW/human/ownership/release/$SF" "${AUTH[@]}"
```

### `POST /human/ownership/reap-stuck` — reclaim both-dead stranded sandfs

Manual reclamation tool for sandfs stranded on a **permanently-dead** owner
gateway (the last-resort backstop behind presence-directed routing). Scans
every ownership key whose owner is the target gateway and reclaims it, subject
to guards that prevent a dual-mount:

- **Idle sandfs** (`node_id` empty): reaped — the owner is dead, so the key is
  safe to delete (the sandfs returns to claimable).
- **Mounted sandfs** (`node_id` set): reaped **only if** the node's presence key
  `/sandswap/node/{node_id}/presence` is gone (the node is also dead past
  `T_safe`). If the presence key still exists, the sandfs is **skipped** — the
  node may still be alive/tolerating, and deleting the ownership would risk a
  dual-mount. An etcd error reading presence also skips (fail-safe).
- **Live owner**: refused with `409` before anything is touched (the operator
  misidentified a live gateway).
- **This gateway as target**: refused with `409`.
- **Single-node / no etcd**: `503` (no distributed coordination layer).

Owner-dead judgment uses the health-key staleness signal (`last_healthy_ts`):
the owner is dead when its health key is absent or stale past
`-claim-dead-guard-sec` (default 45 s).

**Request body** (limit 1 MB):

```json
{
  "gateway_id": "gw-dead",
  "dry_run": false,
  "batch_size": 100
}
```

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `gateway_id` | string | yes | The dead owner to clean up. |
| `dry_run` | bool | no | Report what would be deleted without deleting (default `false`). |
| `batch_size` | int | no | Caps how many candidates ONE call processes (default 100). This is **not** an etcd Txn batch: every candidate is its own `ModRevision`-CAS delete Txn. Re-issue while `reaped_count == batch_size`. |

**Response** (`200`, `ReapStuckReport`):

```json
{
  "owner_gateway_id": "gw-dead",
  "dry_run": false,
  "reaped": ["sandfs-1", "sandfs-2"],
  "reaped_count": 2,
  "skipped": ["sandfs-3"],
  "skipped_count": 1
}
```

The CAS delete is what makes the tool safe against a live claimant: between the
scan and the delete, a live gateway can CAS-claim the record; a key whose
revision moved on is reported `skipped` and left to its current owner, never
blind-deleted. `reaped` serializes as `null` when nothing was reaped; `skipped`
is omitted when nothing was skipped.

**Status codes:** `200`; `400` invalid body or missing `gateway_id`; `409`
self-reap or a live owner; `500` a mid-reap batch failure (the body carries the
partial `report`); `503` single-node/no etcd; `401`/`403` (`sandswap:ops`).

**Operator workflow:** confirm the target gateway's `/stats` shows it stale/dead
**and** its nodes' presence keys are gone, then `dry_run` to preview, then run
for real. Also available via `sandctl api ownership reap-stuck <gw-id>
[--dry-run] [--batch=N]`.

```bash
curl -sS -X POST "$GW/human/ownership/reap-stuck" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"gateway_id":"gw-dead","dry_run":true,"batch_size":100}'
```

### `POST /human/ownership/reap-stuck-node` — reclaim sandfs stranded on a dead sandlot node

**The problem this solves.** When a whole sandlot node is permanently retired
(hardware failure, decommission, a host that will never come back), every
sandfs whose ownership record still points at it (`node_id` = that node) is
stranded: the node will never reconnect to any gateway, so the migrated-takeover
path (which needs the node to appear on a live gateway) never fires, and the
sandfs stays "mounted on a dead node" forever — safe, but unusable. Reclaiming
them one dead-owner at a time via `reap-stuck` is tedious when one node's
failure strands sandfs owned by several gateways; this endpoint reclaims a
dead node's stranded sandfs in one call, across owners — sandfs whose owner
gateway is still alive are skipped (see Guards).

**Why it is manual, not automatic.** A sandlot node's presence key
(`/sandswap/node/{id}/presence`) is written by its owning gateway on the node's
behalf and leased with TTL = `T_safe`. An etcd observer cannot tell "the gateway
and node are truly dead" from "the gateway is partitioned from etcd but still
connected to the node, mount still alive, warden countdown still being reset by
node heartbeats" — both leave the presence key expired after `T_safe`. Acting
on that signal automatically would, in the partition case, delete ownership
under a live mount and let another gateway remount the same disk → **dual-mount
data corruption**. The operator's out-of-band confirmation that the node is
really gone is what makes this safe; mounted-record reclamation is
intentionally manual-only for this reason. Note: if the
"stuck" condition was actually a transient etcd partition and the gateway
reconnects, it refreshes its health key and presence key and the sandfs
self-heals — so this tool is only needed when the node/gateway are confirmed
permanently dead.

**Guards** (mirror `reap-stuck`'s mounted branch, checked once for the node):

- **Node presence key MUST be absent.** Presence has TTL = `T_safe`, so absence
  means the node has been disconnected ≥ `T_safe` — every cleanup path (sandlot
  self-clean, warden countdown) has provably finished, so there is no live mount
  to dual-mount. If the presence key still exists, the call is **refused with
  `409`** (the node may still be alive/tolerating — do not touch it).
- **Each candidate's owner must be dead** (health key absent or stale past
  `-claim-dead-guard-sec`). An alive owner's sandfs are **skipped**, not reaped
  — the owner's own release chain will reclaim them; reaping here would race a
  live owner's recovery. A record with no owner id is also skipped. Skipped
  sandfs are listed in the response.
- **Single-node / no etcd**: `503`. A presence-read failure is a `500`.

**Request body** (limit 1 MB):

```json
{
  "node_id": "node-7",
  "dry_run": false,
  "batch_size": 100
}
```

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `node_id` | string | yes | The dead node to clean up. |
| `dry_run` | bool | no | Report what would be deleted without deleting (default `false`). |
| `batch_size` | int | no | Candidates processed per call (default 100), each its own CAS delete; re-issue to continue. |

**Response** (`200`, `ReapStuckNodeReport`):

```json
{
  "node_id": "node-7",
  "dry_run": false,
  "reaped": ["sandfs-1", "sandfs-2"],
  "reaped_count": 2,
  "skipped": ["sandfs-3"],
  "skipped_count": 1
}
```

`reaped` serializes as `null` when nothing was reaped; `skipped` is omitted
when nothing was skipped.

**Status codes:** `200`; `400` invalid body or missing `node_id`; `409` the
node's presence key is still alive; `500` presence-read or mid-reap failure
(the body carries the partial `report` when one exists); `503` single-node/no
etcd; `401`/`403` (`sandswap:ops`).

**Operator workflow:** confirm the node's presence key
`/sandswap/node/{node_id}/presence` is absent (gone past `T_safe`) **and** the
node is permanently retired, then `dry_run` to preview, then run for real.
Also available via `sandctl api ownership reap-stuck-node <node-id>
[--dry-run] [--batch=N]`.

```bash
curl -sS -X POST "$GW/human/ownership/reap-stuck-node" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"node_id":"node-7","dry_run":true,"batch_size":100}'
```

---

## Maintenance window (service refusal)

### `POST /human/maintenance` — refuse agent traffic without restarting

**Body** (limit 4 KB): `{"on": true|false, "reason": "…"}` — `on` is required;
`reason` defaults to `planned maintenance` when refusing and is cleared when
resuming. **Response** (`200`): `{"refusing": <bool>, "reason": "…"}` —
idempotent.

The runtime switch behind planned operations that must not overlap agent
work — the volume-name seed rotation is its first user. Semantics:

- **Refusal, not shutdown.** While on, every agent-API request
  (`/agent/*`, `/mcp`) is answered `503` with `Retry-After: 30` and
  `error_code: "MAINTENANCE"`; `/health`, `/ready`, `/stats` and `/metrics`
  keep answering (a refused gateway is not a dead one), and the node
  streams, pools and leases all survive — resuming is a flip, not a
  restart. This is deliberate: a gateway restart is the expensive way to
  stop traffic, and it would churn every node connection for nothing.
- **Cluster-wide where etcd exists.** The handler publishes the fleet key
  (`/sandswap/maintenance`) BEFORE flipping the local switch; every exec
  gateway watches the key and refuses in its own agent listener. A gateway
  restart mid-window comes back still refusing (the key, not the local
  flag, is authoritative). Publishing failures are refused outright — a
  window that only some gateways honor would be worse than none.
- **Observability**: `/stats` carries `"maintenance":
  {"refusing": <bool>, "reason": "…"}` (omitted when unwired).

**Status codes:** `200`; `400` invalid JSON or missing `on`; `401`/`403`
(`sandswap:ops`); `501` the switch is not wired in this mode; `503` the fleet
key could not be published/cleared (nothing changed).

```bash
curl -sS -X POST "$GW/human/maintenance" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"on":true,"reason":"volume-seed rotation"}'
```

## Rotation window (SandFS creation freeze)

### `POST /human/rotation` — freeze SandFS creation for a rotation window

**Body** (limit 4 KB): `{"on": true|false, "reason": "…"}`. **Response**
(`200`): `{"refusing": <bool>, "reason": "…"}` — idempotent, and the same shape
`/stats` projects as `"rotation"`.

A switch of its own, deliberately not folded into maintenance (which also
serves upgrade windows that have no reason to freeze creation). While it is
on, `POST /human/sandfs` and `POST /human/ns/{ns}/sandfs` are answered `503`
with `Retry-After: 60` and `error_code: "ROTATION_IN_PROGRESS"`. `reason`
defaults to `volume-seed rotation` when refusing and is cleared when resuming.

Why it exists: the volume-name rotation moves every volume directory from one
naming generation to the next, and a SandFS created mid-window would be named
in the generation being retired — `--run` would have to chase it, and a
straggling prov instance would later resolve a name that does not exist.
The per-instance freeze (`ErrRotationStaged`) only covers prov instances that
are themselves staged, so this flag makes the freeze a fleet property. It is
published FIRST to `/sandswap/rotation` (plain etcd key, same semantics as
maintenance: a gateway restarting mid-window comes back frozen).

Fleet convergence: `/stats` carries `prov_seeds[]` — every connected prov
instance's naming generations, straight off its heartbeat (fingerprints only;
field table under [Stats](#get-stats--cluster-statistics)).
`rotate-volume-seed.sh --rotation off` (and `--maintenance off`) refuse to
close the window while a KNOWN instance still reports the retired generation,
waiting up to 45 s first because the view lags one heartbeat (~30 s). An
instance that reports nothing at all (an older binary) closes with a warning —
"cannot tell" is not "disagrees".

**Status codes:** `200`; `400` invalid JSON or missing `on`; `401`/`403`
(`sandswap:ops`); `501` the switch is not wired in this mode; `503` the fleet
key could not be published/cleared (nothing changed).

```bash
curl -sS -X POST "$GW/human/rotation" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"on":true,"reason":"rotation"}'
```

## Health, readiness, stats

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | none | Liveness: `{"status":"ok"}`. On the human listener the body also carries `pool` (`{"CLEAN","IN_USE","node_count"}`, single-node only) and `provisioners` (connected prov-role instances; `0` means every storage op 503s). |
| `GET` | `/ready` | none | Readiness. `200 {"status":"ready"}` only after the identity snapshot load and ownership recovery (human/exec); `503 {"status":"not_ready"}` otherwise. Single-node: always `200`. |
| `GET` | `/stats` | `sandswap:ops` on the human listener; none on the exec agent listener | Cluster statistics — see below. |
| `GET` / `HEAD` | `/metrics` | same placement as `/stats` | Prometheus text projection of the same report — see below. |

```bash
curl -sS "$GW/health"
curl -sS "$GW/ready"
curl -sS "$GW/stats" "${AUTH[@]}"
curl -sS "$GW/metrics" "${AUTH[@]}" | head
```

**Status codes:** `/health` is always `200`; `/ready` is `200` or `503`;
`/stats` and `/metrics` add the authentication statuses above, and `/metrics`
answers `405` for methods other than `GET`/`HEAD`. A degraded etcd read yields
a partial `/stats` report, not an error.

### `GET /stats` — cluster statistics

Returns a unified `StatsReport` — identical shape in single-node (MemoryStore)
and distributed (etcd) modes. The human listener requires `sandswap:ops`; in
`exec` mode the endpoint rides the agent listener behind the
`-ops-token-file` bearer gate (disabled without the flag) with
per-tenant identifiers redacted. In distributed mode it aggregates every
gateway's `/sandswap/{load,health,gateway,unmount-stats}/` etcd keys, so a
query to any gateway's `/stats` returns the full multi-gateway cluster view,
not just its local sandlots. The `/sandswap/load`, `/sandswap/health`, and
`/sandswap/gateway` keys are the same ones sandns reads;
`/sandswap/unmount-stats` is read only by `/stats` (sandns never reads unmount
stats). In single-node mode it builds the report from the local pool manager —
same shape, a single self entry.

```json
{
  "gateways": [
    {
      "gateway_id": "gateway-1",
      "healthy": true,
      "gateway_url": "https://127.0.0.1:3000",
      "stream_addr": "127.0.0.1:9998",
      "node_count": 2,
      "clean_vms": 6,
      "total_vms": 6,
      "agg_duty_long": 0.12,
      "self_cpu_pct": 3.4,
      "self_mem_pct": 21.0,
      "self_inflight": 0,
      "self_pressured": false,
      "last_healthy_ts": "2026-08-30T12:00:00Z",
      "stale_sec": 0,
      "nodes": [
        {
          "node_id": "node-prod-1",
          "duty_long": 0.12, "duty_short": 0.05, "duty_daily": 0.1, "duty_var": 0.02,
          "host_cpu_pct": 8.3, "host_mem_avail_mb": 1973,
          "active_sandfs": 0, "clean_vms": 4, "total_vms": 4,
          "peak_concurrent_execs": 3, "slot_wait_ms": 0.4, "slot_wait_events": 12,
          "recycle_triggers": 0, "stranded_reservations_mb": 0, "stranded_cids": 0
        }
      ],
      "unmount_stats": [
        {
          "node_id": "node-prod-1",
          "mount_count": 3,
          "unmount_count": 4,
          "unmount_success": 3,
          "unmount_fail": 1,
          "under_5ms": 1,
          "under_10ms": 2,
          "top_slow": [
            {
              "sandfs_id": "sandfs-ddd",
              "gateway_ms": 1300.412,
              "sandlot_ms": 1250.087,
              "warden_ms": 1200.031,
              "command": "apt-get install -y build-essential",
              "reason": "lease-expiry",
              "timestamp": "2026-08-23T17:30:05Z"
            }
          ],
          "recent": {"n": 4, "p50_ms": 2.1, "p95_ms": 12.4, "p99_ms": 12.4, "max_ms": 12.4},
          "recent_warden": {"n": 4, "p50_ms": 1.8, "p95_ms": 11.0, "p99_ms": 11.0, "max_ms": 11.0},
          "lease_fire": {"total": 4, "under_1ms": 4, "under_2ms": 4, "max_ms": 0.8, "p50_ms": 0.3, "p95_ms": 0.8}
        }
      ]
    }
  ],
  "totals": {
    "clean_vms": 6, "total_vms": 6, "in_use_vms": 0,
    "node_count": 2, "gateway_count": 1
  },
  "maintenance": {"refusing": false},
  "rotation": {"refusing": false},
  "prov_seeds": [{"node_id": "node-prod-1", "generation": "3f2a…", "age_sec": 4}]
}
```

| Field | Meaning |
|-------|---------|
| `gateways[].healthy` | `true` if the gateway's `/sandswap/health/{gw}` value is fresh within the built-in claim-dead guard (45 s; the `/stats` projection uses this default, not a configured threshold). The key is a plain key with no lease (distributed); always `true` for self (single-node). |
| `gateways[].last_healthy_ts` | The health key's `last_healthy_ts` (RFC3339) — the continuous liveness signal each consumer thresholds. Omitted when no health key exists (distributed). |
| `gateways[].stale_sec` | Seconds since `last_healthy_ts` (`0` = fresh). Past `-route-stale-sec` (default 20 s) the gateway is treated as stale for DNS/307 rerouting; past `-claim-dead-guard-sec` (default 45 s) as dead for ownership takeover. (distributed) |
| `gateways[].gateway_url` / `stream_addr` | Routing addresses from `/sandswap/gateway/{gw}` (distributed); empty in single-node. |
| `gateways[].node_count` | Sandlot nodes connected to that gateway. |
| `gateways[].clean_vms` / `total_vms` | VM pool counts (clean = idle, total = clean + in-use). `total_vms` is derived from per-node `total_vms`. |
| `gateways[].self_cpu_pct` / `self_mem_pct` / `self_inflight` / `self_pressured` | The gateway process's own pressure signals: CPU as % of GOMAXPROCS, managed memory as % of the soft limit (0 when no limit), in-flight agent-listener requests (observability only), and the sustained-pressure routing gate. |
| `gateways[].nodes[]` | Per-node load signals (`duty_*`, host CPU/memory, `active_sandfs`, clean/total, `peak_concurrent_execs`, `slot_wait_*`, `recycle_triggers`, `stranded_*`) — sorted by `node_id`. Omitted for compute-less gateways. |
| `gateways[].unmount_stats[]` | Per-node unmount latency/counters — see [Unmount stats](#unmount-stats). LOCAL gateway uses a fresh in-memory snapshot; peers use their persisted `/sandswap/unmount-stats/{gw}` etcd value. Omitted when a gateway has no unmount stats. |
| `totals` | Cluster-wide rollup. |
| `maintenance` | The service-refusal switch state (`refusing`, `reason` omitted when empty); omitted when the switch is not wired. |
| `rotation` | The SandFS-creation freeze state (same shape); omitted when not wired. |
| `prov_seeds[]` | Every connected prov instance's naming generations (`node_id`, `generation`, `staged`, `staged_generation`, `age_sec` — fingerprints only, generation fields omitted when empty). Omitted when no prov instance is connected or the source is not wired. `age_sec` is the age of the heartbeat carrying the entry, so a stale entry is not evidence of anything. |

Both `nodes[]` and `unmount_stats[]` are sorted by `node_id` so a human can
read them side-by-side by index.

#### Unmount stats

`gateways[].unmount_stats[]` is a **fixed-footprint** per-node record of unmount
latency and counts, collected off the warm exec critical path (mount records run
post-response on a cold mount; unmount records run on the async
lease-expiry / failure-cleanup / delete paths). Per node it carries:

| Field | Meaning |
|-------|---------|
| `node_id` | Sandlot node this entry covers. |
| `mount_count` | Cold mounts observed on this node. |
| `unmount_count` | Total unmount attempts (success + fail). |
| `unmount_success` / `unmount_fail` | Unmount outcome counts. |
| `under_5ms` / `under_10ms` | Unmounts whose gateway E2E was <5 ms / <10 ms. |
| `top_slow[]` | The 10 slowest unmounts (by gateway E2E, descending). Each entry carries the three-layer latencies (`gateway_ms`, `sandlot_ms`, `warden_ms`; float milliseconds at 3-decimal/µs resolution), the `sandfs_id`, the `reason` (`lease-expiry` \| `cleanup-after-failure` \| `cleanup-after-file-failure` \| `delete` \| `etcd-fence`), and the sandfs's **last cold-mount command** (the command whose residual processes/cache drove the slow cgroup.kill/umount — unmount itself has no command). A `timestamp` (RFC3339) records when it was recorded. On the exec-mode agent listener, `sandfs_id` and `command` are blanked (omitted). |
| `recent` / `recent_warden` | Rolling-window latency summaries (last 1024 samples) for the gateway E2E and warden layers: `n`, `p50_ms`, `p95_ms`, `p99_ms`, `max_ms`. |
| `lease_fire` | Lease-expiry timer punctuality: lifetime `total`, strict `<1 ms`/`<2 ms` tallies, and `p50_ms`/`p95_ms`/`max_ms` of the fire lag. |

A snapshot is async-persisted to etcd under
`/sandswap/unmount-stats/{gatewayID}` as a **plain key (no lease)** every
`-unmount-stats-persist-sec` (default 600 s, hot-reloadable — the persist ticker
retunes on YAML change without restart) for `/stats` peer aggregation and ops
offline inspection. A gateway restart overwrites its own key (no read-back —
counters start fresh); orphan keys from a permanently retired gateway are
reclaimed by ops (`etcdctl del`). Single-node mode keeps it in-memory only. When
a sandlot node disconnects, its entry is dropped so stale data does not linger;
a reconnecting node (same nodeID) starts fresh.

### `GET /metrics`

Prometheus text exposition (`Content-Type: text/plain; version=0.0.4;
charset=utf-8`) of the same `StatsReport` `/stats` serves — a second projection,
not a second instrumentation. Same auth placement as `/stats`; `GET`/`HEAD`
only (anything else is `405`). Metric names, labels, and scrape wiring are
catalogued in [Prometheus Integration](../integration/prometheus.md).

---

## Request size limits (summary)

| Endpoint | Body limit | Notes |
|----------|-----------|-------|
| `POST /human/agent`, `POST /human/sandfs`, detach/attach/swap-template, save-template, template pull/push/delete | 1 MB | Small-JSON bodies (`smallJSONBodyLimit`). An oversize body fails the JSON decode and returns `400` (not `413`). |
| `POST /human/maintenance` | 4 KB | `{on, reason}`. |
| `POST /human/rotation` | 4 KB | `{on, reason}`; while on, SandFS creation is refused with `ROTATION_IN_PROGRESS`. |
| `POST /human/sandfs/{id}/rootfs-path` | 8 KB | `{"rootfs_path"}`. |
| `POST /human/ownership/reap-stuck[-node]` | 1 MB | `{gateway_id\|node_id, dry_run, batch_size}`; oversize → `400`. |
| `GET /human/*` | — | No request body is read. |

Listener timeouts: read 30 s; write 11 minutes (the lifecycle drain may block
for the caller's `wait_sec`, and auto-pull can move GBs); keep-alive idle
`-idle-timeout` (default 1 h).
