---
title: Operations
nav_order: 9
has_children: true
permalink: /operations/
---

# Operations

Running Sandswap after it is deployed — for operators and platform
engineers. For the deployment itself, start at [Deployment](../deployment/index.md).

1. **[Configuration](configuration/index.md)** — per-component reference: gateway, sandlot, boxout, sandns, warden.
2. **[sandctl](sandctl.md)** — the client CLI: gateway HTTPS API client, DNS queries, pool/health views, and the deployer-written client contract.
3. **[etcd](etcd.md)** — the coordination-layer runbook: sizing, compaction, defragmentation, backup/restore, NOSPACE recovery.
4. **[Storage Requirements](storage.md)** — the contract a shared filesystem must satisfy, pinned service identities, the NFS recipe.
5. **[Template Contract](template-contract.md)** — the mode/ownership contract a rootfs template must satisfy, and the `template-tool` that normalizes and validates it: `validate` a template tree, `check-store` a template store.
6. **[Observability](observability.md)** — latency fields, `/stats`, per-component log surfaces, debug gating.
7. **[Troubleshooting](troubleshooting.md)** — reading `/stats`, common failures, crash recovery expectations, sandns day-2 operations.
8. **[Release](release.md)** — how releases are cut, what the release package contains, and how to consume it.
