---
title: Sandns
nav_order: 6
parent: Components
grand_parent: How It Works
---

# Sandns

## 1. Overview

sandns is Sandswap's owner-aware DNS service for distributed deployments:
agents and sandlots resolve Sandswap names through it, and every answer
respects ownership. It reads its candidates entirely from etcd — zero
static configuration. Source: `dns/` (Go; the internal module name), with
the in-house wire layer `dns/wire` (`miekg/dns` survives only as a
test-only differential oracle). Deploy it in the production topology;
single-node and small clusters dial gateways directly.

## 2. Key Responsibilities

### 2.1 The three zones

- **Agent domain** (`sandswap.local`, legacy): answer one healthy exec
  gateway for the bootstrap discovery call (`GET /agent/sandfs`).
  Single-IP round-robin via scheduling; kept for `sandctl dns agent`.
- **Stream domain** (`sandswap-stream.local`): where sandlots dial in.
  Client-IP sticky + binpack/spread placement.
- **Per-SandFS zone** (`<sandfs_id>.sandfs.sandswap.local`): answer the
  **owner** gateway, staleness-guarded. Falls back to presence-directed
  routing, then scheduling.

### 2.2 Platform duties

- **Forward everything else**, so hosts can point at it as their only
  resolver.
- **Owner-aware routing**: read the ownership key, then the owner's health
  key; return the owner only while its health is fresh.
- **Placement**: score candidates (registry = candidacy, health =
  liveness, load = scoring); persist sticky assignments in etcd across
  restarts.
- **Fail closed**: no healthy candidate → SERVFAIL, never a guess.
  Errors are never cached as negative answers.

## 3. Interfaces / Data Flow

**Inputs:**

- DNS queries on UDP/TCP `:53`.
- etcd state: gateway registry, health keys, node presence keys,
  ownership keys, sticky records.

**Outputs:**

- DNS answers (A / CNAME) or SERVFAIL.
- Sticky-record writes to etcd (the only state it writes).

```
Query: mnt-sf-3fa9c2e1.sandfs.sandswap.local
  │
  ▼
Zone dispatch ──▶ per-SandFS zone
                    │ 1. read ownership /sandswap/owner/{id}
                    │ 2. read health /sandswap/health/{gw}
                    │ 3. fresh?  ── yes ─▶ answer owner IP
                    │            └─ no ──▶ presence-directed
                    │                      fallback: scheduling
                    ▼
                  answer (A / CNAME)
```

## 4. How It Processes

1. **Receive** the query on `:53` (UDP or TCP; a TCP-originated query is
   never forwarded over UDP).
2. **Dispatch by zone**: the three Sandswap zones take the Sandswap
   logic; everything else goes to the upstream forwarder with bounded
   concurrency. The zones themselves are not open to sandbox guests: a
   source in `guest_cidrs` gets NXDOMAIN for the per-sandfs zone (so
   probing reveals neither existence nor ownership) and REFUSED for the
   stream/agent zones. Foreign-zone relay requires an explicit
   `recursive_acl` member, and a loopback entry is honored only when the
   packet arrived on a loopback-address socket — the resolver judges the
   ingress, not the claimed source address.
3. **Per-SandFS lookup**: read the ownership key. If the owner's health
   is fresh (staleness below the route threshold), answer the owner.
4. **Degrade in order**: owner stale → answer the gateway currently
   holding the node (presence-directed); no presence → schedule a
   candidate. Routing mistakes cost at most one 307/503 — never data or
   ownership.
5. **Stream-domain lookup**: honor the client-IP sticky record if live;
   otherwise place by binpack or spread (hot-reloadable policy and duty
   hard cap). Placement gates on compute (`node_count`/`clean_vms` > 0)
   for new SandFS but never for the stream domain — a compute-less
   gateway must stay selectable so it can recover.
6. **Persist and cache**: write sticky records to etcd on the sync
   interval; serve repeated lookups from O(1) LRU caches; never cache
   errors.
7. **Watch etcd**: registry, health, presence, and ownership changes
   arrive by watch — no polling loops, no static gateway list.

## 5. State & Storage

sandns is **mostly stateless**. Its only durable state is the
sticky-record store, which lives in etcd and survives restarts. In-memory
LRU caches and rate buckets are transient and rebuild on demand. It keeps
no local files. The domain names themselves come from config
(`domains.agent` / `domains.stream` / `domains.sandfs`; an empty
`domains.sandfs` disables the owner-aware zone); config parsing is strict
— unknown keys fail at startup.

Component configuration:
[sandns configuration](../../operations/configuration/sandns.md).
Day-2 ops: [Troubleshooting → sandns](../../operations/troubleshooting.md#5-sandns-day-2-operations).
