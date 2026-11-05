---
title: Concepts & Terms
nav_order: 1
parent: How It Works
---

# Concepts & Terms

The handful of terms everything else builds on. Read this once, then
[Architecture](architecture.md) makes sense.

## 1. The core idea in one paragraph

Sandswap gives every AI agent a **hardware-isolated microVM with a persistent
per-agent filesystem**: each agent's
files live on shared or local storage and are mounted into a warm pooled microVM on
demand — so switching a VM from one agent to another takes milliseconds, and
everything the agent writes persists.

## 2. Core terms

| Term | Meaning |
|------|---------|
| **SandFS** | The agent's persistent filesystem: a volume of files stored on host local or shared storage, holding everything the agent keeps — files, code, `workspace/`, `home/`. When the agent runs something, its SandFS is mounted into a microVM; the microVM is the compute, the SandFS is the disk. It is what every API request addresses by `sandfs_id`. |
| **Agent** | The client of Sandswap — typically an AI agent, but any program: it authenticates with an API key and calls the API to execute code and store files. Each agent owns one or more SandFS instances — its disks. |
| **Gateway** | The entry point of Sandswap: agents send every request here. It authenticates the agent, locates its SandFS, and dispatches the work to a node over a gRPC stream. Agents connect to HTTP `:3000` (MCP on the same listener); nodes connect to `:9998`. In split deployments the gateway runs as two instances — see §3 for the names. |
| **sandns** | The owner-aware DNS service: how agents and sandlots find the right gateway. It reads etcd and answers every lookup with the address of the Gateway that currently holds the SandFS. When ownership moves, the answers follow automatically. See [Ownership & DNS](ownership-and-dns.md). |
| **Node** | One machine that does the executing — a bare-metal host, a nested-virtualization VM, or a Kubernetes node — running one sandlot daemon and its microVMs. |
| **Sandlot** | The per-node daemon. It keeps a pool of warm microVMs ready on its machine, mounts the agent's SandFS into the right VM when work arrives, and talks to each VM's Warden over vsock. The prov role does the storage side: it creates and seeds SandFS volumes and pulls or pushes templates. Sandlot dials the Gateway — the Gateway never connects in. In split deployments sandlot runs as two instances — see §3 for the names. |
| **microVM** | A tiny hardware-isolated virtual machine (KVM): its own kernel and warden. Sandswap keeps a pool of them warm, and one microVM serves at most one SandFS at a time. |
| **sandvmm** | The virtual machine monitor: one process per microVM, running it on KVM. A fork of Cloud Hypervisor, specially trimmed and extended for Sandswap, controlled by the sandlot over an HTTP API on a Unix socket. |
| **Warden** | PID 1 inside each microVM. It mounts the SandFS into the VM and runs the agent's commands as its own children. It enforces memory limits and capability/seccomp profiles, and tears everything down when the VM goes idle. |
| **vsock** | The lightweight host↔VM socket channel the sandlot uses to reach each VM's warden — no guest network stack involved. |
| **Boxout** | An optional privileged helper (Kubernetes deployments). It does the host-privileged work — starting and stopping sandvmm, networking, mounts — so the sandlot daemon itself can run unprivileged. See [Topologies](topologies.md). |
| **Spec** | A VM size class — `small` / `medium` / `large` (vCPUs, memory, `exec_slots`). A SandFS creation states its minimum resources; the gateway resolves them to a spec. |

## 3. Instance names

Gateway and sandlot each deploy in two role flavors. The names below are
the canonical short forms — every page in this documentation uses them:

| Written | Means |
|---|---|
| **exec sandlot** | a sandlot instance running the execution role (`-roles exec`): the VM pool, mounts, execs |
| **prov sandlot** | a sandlot instance running the provision role (`-roles prov`): SandFS volume and template lifecycle on shared storage |
| **exec gateway** | a gateway instance serving the execution (agent) API — `/agent/*`, MCP, the exec stream |
| **human gateway** | a gateway instance serving the human API — SandFS/template CRUD, ownership ops |
| **sandlot** / **gateway** without a prefix | the merged single-node instance (both roles / both halves in one process) — or, where only one kind is present, the primary execution-function one |

## 4. Host user identities

Each instance type runs as a dedicated non-login host user, created once
per node by the host prep (`deploy/baremetal/setup-host.sh`). These are
service accounts — not the host's `root` user, and not agent identities.
One supplementary group (`sandtmpl`) scopes template-store metadata.

| Identity (uid) | Runs as | Scope |
|---|---|---|
| **sandlot** (985) | exec sandlot instances | the executor: KVM, mounts, the warden vsock client. The only uid vsockguard allows on the warden port. |
| **sandserv** (986) | exec gateways, human gateways, sandns | credential and coordination state only; no capabilities, no shared-storage access |
| **sandvmm** (987) | every sandvmm process (the VMM and its virtio-fs server) | **zero capabilities** — the network provider pre-creates the persistent TAP owned by this uid and pre-configures it; owns `/dev/vhost-vsock`. Guest-planted setuid files land owned by it — an identity with no warden access. |
| **sandprov** (983) | prov sandlot instances | the storage side: the only shared-storage writer (volumes and templates); no capabilities, no KVM, no vsock devices |
| **sandtmpl** (group, GID 982) | members: `sandprov` + `sandlot` — never `sandvmm` | the template-store metadata group: `refs/` is group-readable `sandtmpl`, so the FUSE daemon (sandvmm) reads layer content through the shared volume group but cannot enumerate refs |

## 5. Terms you will meet later

One line each; the linked page is where each is actually explained.

- **Warm / cold path** — warm: the request lands on a VM that already has the
  agent's SandFS mounted. Cold: the VM is idle, so the agent's SandFS
  must be mounted first. See [VM Lifecycle](vm-lifecycle.md).
- **Sticky lease** — the short window (default 100 ms, min 1 ms) after a call
  during which the same agent's next call reuses the still-mounted VM — what
  makes consecutive calls warm. See [VM Lifecycle](vm-lifecycle.md).
- **Template** — a rootfs image stored as an OCI artifact that a SandFS is
  seeded from (flat) or layered under (overlay). See [Templates](templates.md)
  and [SandFS](sandfs.md).
- **Flat / Overlay** — the two SandFS volume modes: a fully writable copy
  versus a read-only shared base with a writable `workspace/`. See
  [SandFS](sandfs.md).
- **etcd** — the distributed key-value store that Gateways and sandns share in
  multi-gateway deployments. Ownership, health, and routing records
  live here. See [Ownership & DNS](ownership-and-dns.md).
- **Ownership / placement** — which gateway owns a SandFS and which node it
  last ran on; the etcd records that make exclusive mounting and failover
  work. See [Ownership & DNS](ownership-and-dns.md).
- **MCP** — the Model Context Protocol: an alternative, tool-oriented way to
  call the same gateway API (same listener, same API key). See
  [MCP Tools Reference](../reference/mcp-tools.md).
- **Tolerance-first** — the resilience stance: mounts are held through brief
  outages so in-flight commands finish, and switching is based on confirmed
  conditions, not timers alone. See [Resilience](resilience.md).
- **vsockguard** — a BPF LSM program that pins the host-side vsock transport
  against non-root local users. See [Vsockguard](vsockguard.md).

Deeper vocabulary (T_safe, placement CAS, presence keys, mount epochs, …) is
defined on first use in the page that introduces it — there is no separate
glossary on purpose.
