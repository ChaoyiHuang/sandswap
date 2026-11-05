---
title: Integration
nav_order: 5
has_children: true
permalink: /integration/
---

# Integration

How to connect Sandswap to the systems and clients around it — from
provisioning an agent to swapping the VMM.

1. **[Human HTTP Integration](human-http.md)** — the control-plane workflow: create agents and SandFS, how ids stay unique.
2. **[Auth Integration](auth.md)** — the two auth surfaces; OIDC and mTLS integration for the control plane.
3. **[Agent HTTP Integration](agent-http.md)** — connecting an agent over plain HTTP/JSON: auth, connection handling, abort contract, examples.
4. **[Agent MCP Integration](agent-mcp.md)** — the MCP server: transport, the minimal client walkthrough, server instructions.
5. **[VMM Integration](vmm.md)** — the contract a third-party VMM/hypervisor must satisfy to replace sandvmm.
6. **[Storage Backends](storage-backends.md)** — no backend type
   restriction: the contract, the options (local disk, NFS, cloud managed
   services, distributed/parallel filesystems), and how to choose.
7. **[OCI Registry Integration](registry.md)** — auth methods and the template push/pull lifecycle.
8. **[Prometheus Integration](prometheus.md)** — scraping `/metrics`, the metric catalogue, starter alerts.
9. **[Egress Integration](egress-integration.md)** — building per-agent egress policy on the identity binding: enablement, reader access, consumption rules, solution patterns (the mechanism is [Egress Enabler Contract](../how-it-works/egress-enabler.md)).
10. **[Volume-Name Seed Integration](volume-seed.md)** — supplying the volume-name seed from an external secret manager (Vault, a cloud secrets manager, systemd credentials, ESO/CSI): the injection contract, the channel options, verification, and how rotation runs through each channel.
