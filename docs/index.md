---
title: Home
layout: home
nav_order: 1
---

# Sandswap Documentation

- **[Quick Start](getting-started/index.md)**
- **[Benchmark](benchmark/index.md)**
  - [Benchmark Report — Bare Metal](benchmark/baremetal.md)
  - [Benchmark Report — Nested Virtualization](benchmark/nested-virt.md)
  - [Benchmark Report — Bare Metal:
    microVM Reuse Capacity](benchmark/baremetal-load.md)
  - [Benchmark Report — Nested-virt:
    microVM Reuse Capacity](benchmark/nested-virt-load.md)
  - [Reproducing the Benchmarks](benchmark/reproducing.md)
- **[How It Works](how-it-works/index.md)**
  - [Concepts & Terms](how-it-works/concepts.md)
  - [Architecture](how-it-works/architecture.md)
  - [Design Principles](how-it-works/design-principles.md)
  - [Topologies](how-it-works/topologies.md)
  - [SandFS](how-it-works/sandfs.md)
  - [Templates](how-it-works/templates.md)
  - [VM Lifecycle](how-it-works/vm-lifecycle.md)
  - [Isolation and Swap](how-it-works/isolation-and-swap.md)
  - [Ownership & DNS](how-it-works/ownership-and-dns.md)
  - [Resilience](how-it-works/resilience.md)
  - [Threat Model](how-it-works/threat-model.md)
  - [Guest Kernel Hardening](how-it-works/guest-kernel-hardening.md)
  - [Vsockguard](how-it-works/vsockguard.md)
  - [Egress Enabler Contract](how-it-works/egress-enabler.md)
  - [Namespaces](how-it-works/namespaces.md)
  - *[Components](how-it-works/components/index.md)*
    - [Gateway](how-it-works/components/gateway.md)
    - [Sandlot](how-it-works/components/sandlot.md)
    - [Boxout](how-it-works/components/boxout.md)
    - [Sandvmm](how-it-works/components/sandvmm.md)
    - [Warden](how-it-works/components/warden.md)
    - [Sandns](how-it-works/components/sandns.md)
- **[Integration](integration/index.md)**
  - [Agent HTTP Integration](integration/agent-http.md)
  - [Agent MCP Integration](integration/agent-mcp.md)
  - [Human HTTP Integration](integration/human-http.md)
  - [Auth Integration](integration/auth.md)
  - [Prometheus Integration](integration/prometheus.md)
  - [OCI Registry Integration](integration/registry.md)
  - [Storage Backends](integration/storage-backends.md)
  - [VMM Integration](integration/vmm.md)
  - [Egress Integration](integration/egress-integration.md)
  - [Volume-Name Seed Integration](integration/volume-seed.md)
- **[Building](building/index.md)**
  - [Building Templates](building/templates.md)
- **[Testing](testing/index.md)**
  - [E2E Catalog](testing/e2e.md)
  - [Script framework](testing/script-framework.md)
- **[Deployment](deployment/index.md)**
  - [Host Prerequisites](deployment/prerequisites.md)
  - [Install — Bare Metal](deployment/install-baremetal.md)
  - [Install — Kubernetes](deployment/install-kubernetes.md)
- **[Operations](operations/index.md)**
  - *[Configuration](operations/configuration/index.md)*
    - [Gateway](operations/configuration/gateway.md)
    - [Sandlot](operations/configuration/sandlot.md)
    - [Boxout](operations/configuration/boxout.md)
    - [Warden](operations/configuration/warden.md)
    - [Sandns](operations/configuration/sandns.md)
  - [sandctl](operations/sandctl.md)
  - [etcd](operations/etcd.md)
  - [Storage Requirements](operations/storage.md)
  - [Template Contract](operations/template-contract.md)
  - [Observability](operations/observability.md)
  - [Troubleshooting](operations/troubleshooting.md)
  - [Release](operations/release.md)
- **[Reference](reference/index.md)**
  - [Agent API Reference](reference/agent-api.md)
  - [Human API Reference](reference/human-api.md)
  - [MCP Tools Reference](reference/mcp-tools.md)
  - [Internal Protocols](reference/protocols.md)
  - [FAQ](reference/faq.md)
