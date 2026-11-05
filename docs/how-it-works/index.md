---
title: How It Works
nav_order: 4
has_children: true
permalink: /how-it-works/
---

# How It Works

How Sandswap works, from the outside in. Read in order for a full picture;
each page also stands alone.

1. **[Concepts & Terms](concepts.md)** — the vocabulary everything else builds on.
2. **[Architecture](architecture.md)** — the components and their communication paths.
3. **[Design Principles](design-principles.md)** — the invariants every change must preserve.
4. **[Topologies](topologies.md)** — the deployment shapes: single-node to distributed, embedded vs boxout.
5. **[SandFS](sandfs.md)** — the core abstraction: a persistent per-agent volume and its two modes (flat writable rootfs vs read-only overlay + writable workspace).
6. **[Templates](templates.md)** — where rootfs templates live (local store + OCI registry) and how each mode consumes them.
7. **[microVM Lifecycle](vm-lifecycle.md)** — microVM states, verified creation, recycle, re-adopt, crash teardown, and the warden countdown.
8. **[Isolation and Swap](isolation-and-swap.md)** — time-sharing one microVM across SandFS: the swap machinery and the strong-isolation guarantees behind it.
9. **[Guest Kernel Hardening](guest-kernel-hardening.md)** — the guest kernel as a trust root: the minimized build and its configuration, the capability/seccomp fence on agent code, the blast radius of a compromise, and the reuse limits that bound it.
10. **[Ownership & DNS](ownership-and-dns.md)** — exclusive ownership, placement, and owner-aware routing.
11. **[Resilience](resilience.md)** — failure detection, takeover, tolerance-first recovery.
12. **[Threat Model](threat-model.md)** — the adversaries outside the microVM boundary: local user, network, compromised gateway or VMM, and the trust roots.
13. **[Vsockguard](vsockguard.md)** — the BPF LSM that pins the host-side vsock transport.
14. **[Egress Enabler Contract](egress-enabler.md)** — how egress security is constructed: the unforgeable per-attachment identity, its two carriers, the binding-region format, and the host-side isolation baseline (integration side: [Egress Integration](../integration/egress-integration.md)).
15. **[Namespaces](namespaces.md)** — the control-plane tenancy dimension: the IdP-issued `sandswap_ns` claim, the two enforcement rules, and why the exec plane is untouched.

Then the components, one page each — responsibilities, interfaces,
workflow, and state:

- **[Gateway](components/gateway.md)** · **[Sandlot](components/sandlot.md)** ·
  **[Sandvmm](components/sandvmm.md)** · **[Warden](components/warden.md)** ·
  **[Boxout](components/boxout.md)** ·
  **[Sandns](components/sandns.md)**
