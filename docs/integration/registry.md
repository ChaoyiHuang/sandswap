---
title: OCI Registry Integration
nav_order: 9
parent: Integration
---

# OCI Registry Integration

Templates travel as **OCI artifacts** in any OCI registry — the same
push/pull/tags/digests/replication workflows that run container images run
Sandswap templates. This page is the registry integration: endpoints,
authentication, and lifecycle. The artifact format and the template concept
are in [Templates](../how-it-works/templates.md); building templates is in
[building/templates](../building/templates.md).

## 1. Enabling

The registry is configured on the **prov instance** (prov sandlot):

```bash
sandlot -roles prov \
  -oci-registry registry.example.com/sandswap-templates \
  -registry-username "$REGISTRY_USER" -registry-password "$REGISTRY_PASS"
```

or as config keys (`provision.oci_registry`, `provision.registry_*` — see
[Sandlot configuration](../operations/configuration/sandlot.md)). Without
`-oci-registry`, the prov instance still serves **local** templates (layers
cache + refs under the templates dir; local template directories are
discovered lazily — startup scan plus a rescan on every miss — so dropping
one into a scan root needs no restart) — pull/push endpoints just fail. The
registry address and its credentials are restart-required.

`-oci-registry` names the **repository** (`host[:port]/path`); a template
ref (`python-ml:v1`) is a tag inside it. OCI tags cannot contain colons, so
the ref `python-ml:v1` is stored as the tag `python-ml-v1`.

## 2. Registry authentication

Five shapes, configured on the prov instance; credential selection and TLS
are independent, so they combine:

| Method | Keys / flags | Use case |
|--------|--------------|----------|
| Username/Password | `provision.registry_username` / `registry_password` | private registry (basic auth) |
| Bearer token | `provision.registry_token` | OAuth/OIDC token auth |
| TLS client cert | `registry_cert` + `registry_key` | mTLS |
| Private CA | `registry_ca` | server verification against your own CA (combines with basic/token; cert/key/ca apply to any credential) |
| Anonymous | (default) | public registry — nothing configured |

Precedence: basic auth wins over the bearer token when both are set; the
TLS material (client pair and/or CA) applies regardless of which credential
is selected — the common private-registry shape (basic auth over TLS with a
company CA) is one config, not a choice. A cert without its key, or any
credential without `oci_registry`, is refused at startup.

**Production requires TLS** (or a trusted network path): registry basic auth
is transported by the registry's own TLS — without it the credential is
plaintext on the wire. Sandswap verifies the server normally unless
`registry_ca` points at a private CA; the e2e suite runs over plain HTTP
only because the registry is on localhost.

## 3. The template lifecycle

| Step | Endpoint (`:3100`) | sandctl |
|---|---|---|
| Publish a local template | `POST /human/templates/{ref}/push` | `sandctl api template push <ref>` |
| Pull into the storage plane's local store | `POST /human/templates/{ref}` | `sandctl api template pull <ref>` |
| List what's cached locally | `GET /human/templates` | `sandctl api template list` |
| Freeze a running flat SandFS first | `POST /human/sandfs/{id}/save-template` | `sandctl api sandfs save-template` |

- **Push** uploads the template's layers as an OCI image manifest with the
  Sandswap artifact type (`application/vnd.sandswap.template.v1+json`).
- **Pull** verifies and unpacks into the storage plane's `layers/` cache and
  writes the ref entry — after which `POST /human/sandfs` can instantiate
  from the ref immediately. This is the **overlay** pull; a **flat** pull
  (`{"mode":"flat"}` body) reads only the manifest and records the layer
  digests — the blobs stream straight into each new SandFS volume at
  creation time, so nothing is cached for flat.
- **Creation can pull on demand**: a `POST /human/sandfs` naming a ref the
  store does not have yet auto-pulls it first (when a registry is
  configured) — the create response's `pull_status` reports `pulled` for
  that create and `cached` when the ref was already local. An explicit pull
  is only needed to control *when* the download happens.
- **Refs are mode-tagged**: a ref file records whether the template
  consumes as `flat` (seeded by copy from a local dir, or stream-extracted
  from the registry's layer blobs) or `overlay` (mounted as the
  read-only lowerdir). The same registry can hold both.
- Every deployment needs the template pulled only **once into the shared
  template store** — the registry is the distribution point, the storage
  plane's `layers/` cache is what mounts actually read (overlay mode).
  Deployments **sharing the templates tree need no pull at all**: a
  template saved on one is already on all of them.

## 4. Typical flows

**Build here, run there**: save-template on deployment A (freezes a flat
SandFS into A's store) → push `ref` to the registry → create a SandFS from
`ref` on deployment B (auto-pull) → serve. Push accepts a `mode`
(`sandctl api template push <ref> --mode=flat`) — a flat push/pull
round-trips flat templates, and a flat SandFS created from a pulled flat
ref materializes by streaming the blobs directly into its volume.

**Air-gapped / mirrored**: point `oci_registry` at your internal mirror
(Harbor, Zot, Distribution); standard registry replication keeps sites in
sync — Sandswap templates are ordinary OCI artifacts to all of them.

**Public base images**: pull from a public registry anonymously, push into
your private one as your hardened base.

## 5. Source map

- `sandlot/provision/template/manager.go` — `PullTemplate` / `PushTemplate` /
  registry auth (`AuthConfig.toClient`) / `layers/`+`refs/` layout
- `sandlot/provision/volume/volume.go` — auto-pull on SandFS creation
- `sandlot/config/config.go` + `sandlot/cmd/main.go` — the `provision.*`
  keys and the `-oci-registry` / `-registry-*` flags
- `docs/how-it-works/templates.md` — artifact format, local storage layout
- `e2e/oci-registry.sh` — the full lifecycle against a real
  (htpasswd-authenticated) registry, including auto-pull-on-create
