---
title: Components
nav_order: 16
parent: How It Works
has_children: true
permalink: /how-it-works/components/
---

# Components

One page per binary: responsibilities, interfaces, workflow, and state.
[Architecture](../architecture.md) draws how they fit together.

| Component | Role | Page |
|---|---|---|
| Gateway | the entry point: agent API, identity/ownership, pool scheduling | [Gateway](gateway.md) |
| Sandlot | the per-node daemon: warm microVM pool, rootfs hot-swap, mounts, execs (prov role: storage) | [Sandlot](sandlot.md) |
| Boxout | the privileged K8s sidecar: sandvmm lifecycle, networking, mounts for an unprivileged sandlot | [Boxout](boxout.md) |
| Sandvmm | the KVM VMM, one process per microVM, driven over a Unix-socket API | [Sandvmm](sandvmm.md) |
| Warden | PID 1 in the microVM: mounts the SandFS, runs the agent's commands | [Warden](warden.md) |
| Sandns | the owner-aware DNS service for distributed deployments | [Sandns](sandns.md) |
