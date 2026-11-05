---
title: Design Principles
nav_order: 3
parent: How It Works
---

# Design Principles

Sandswap is built on these stable architectural principles. The principles
are deliberately independent of any implementation, timer value, or file
path: those change as the code evolves; the principles do not.

Every code change must preserve them. When a change appears to require
violating one, treat the conflict as an explicit design decision — never
as an accident of local convenience. Coding agents in particular should
treat this document as the contract: if a change conflicts with a
principle below, the principle wins.

## 1. The Principles

### Principle 1. Everything persists
Sandswap durably persists all meaningful state. Sandswap serves AI agents
whose reasoning loops are long, so the cost of persistence is negligible
relative to the agent's own think time and does not affect business
response latency. Persistence is the foundation of robustness: it lets
the system recover business logic and resume from persisted state after
any failure.

### Principle 2. Minimal end-to-end latency
The Gateway → Sandlot → Warden path must carry the lowest possible
overhead, approaching the transport limit. The path must contain no
gratuitous hops, no serialization, no hot-path locks, and no per-request
work that the system could do once and reuse.

### Principle 3. Minimal swap cost
A SandFS swap must cost as little as possible. Swap-out — unmounting the
rootfs, killing the agent's processes, clearing caches — runs in the
background when a SandFS goes idle; no request waits for the swap-out.
Swap-in — mounting the requesting agent's SandFS onto an idle microVM,
the same one or a different one — sits on the critical path and must cost
as little as the mechanism allows, defensive residue re-check included.

### Principle 4. Never double-mounted — one SandFS runs on one microVM at a time
Sandswap mounts a SandFS on at most one microVM at any instant. Sandswap
never mounts one SandFS on two microVMs simultaneously — not on the same
node, not across nodes. This is the single most important safety
invariant; see [Resilience](resilience.md) for the ownership machinery
that enforces it and the in-VM counterpart (one microVM, one SandFS at a
time).

### Principle 5. One sandlot connects to one gateway at a time
A Sandlot maintains a single outbound stream to a single Gateway at any
moment. It never fans out to, or holds connections to, multiple Gateways
simultaneously.

### Principle 6. Sandlots prefer their previous gateway, with timed failover
A Sandlot (exec) sticks to the Gateway it used before. It switches to
another Gateway only after the previous one has been unreachable for a
bounded amount of time — not instantly. As with agents, failover is
time-gated, not reactive.

### Principle 7. Agents prefer their previous gateway, with timed failover
An agent sticks to the Gateway it used before. It switches to another
Gateway only after the previous one has been abnormal or unreachable for
a bounded amount of time — not on the first transient error. Failover is
a deliberate, time-gated decision, never an instant flap.

### Principle 8. Sandlots see shared directories, not a storage backend
A SandFS volume is a plain directory. Every node that may serve a SandFS
must see its directory: a single node can use local disk; multiple nodes
use any shared filesystem — NFS, CephFS, Cloud FS, or newer storage
systems. Nothing else in Sandswap depends on the storage backend. This
independence lets Sandswap serve any SandFS from any node and migrate it
between nodes seamlessly.

## 2. The Goal These Serve

Under a deliberately simple and reliable topology, these principles
together guarantee that **a SandFS is never double-mounted**, while the
system remains **resilient** enough to tolerate component failures, and
**latency stays at the transport limit**.

- Principle 1 (persistence) is the foundation of robustness — recoverable
  state that survives any failure and lets business logic resume.
- Principles 2 and 3 keep overhead at the transport limit.
- Principle 4 (no double-mount) is the safety core.
- Principles 5, 6, and 7 keep the topology simple and reduce the
  ownership churn that would stress the no-double-mount guarantee.
- Principle 8 enables resilience and seamless migration.

The principles are mutually reinforcing: weakening any one weakens the
no-double-mount guarantee, the resilience, or the latency. Therefore all
of them must hold together.
