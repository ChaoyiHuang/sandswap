---
title: FAQ
nav_order: 5
parent: Reference
---

# FAQ

Short answers to the questions integrators ask most. Each answer links to the
page with the full story; the [Quick Start](../getting-started/index.md) has the commands.

## What is a SandFS? How is it different from a container or a VM?

A SandFS is a persistent, per-agent sandbox: a filesystem plus the microVM it
runs in. One SandFS maps to exactly one KVM microVM at a time — hardware-level
isolation, unlike containers, which share the host kernel. Unlike an ordinary
VM, it is pooled and warm: your files live on shared storage and reach the VM
through one virtio-fs device, and switching which filesystem the VM sees is an
`allowed_dirs` hot-swap plus bind-mount — milliseconds, no VM rebuild, no disk
image. A SandFS is never mounted on two microVMs at once
([Design Principles](../how-it-works/design-principles.md), principle 4).

## Do I need to change my agent's code?

No — that is the point. Sandswap is a transparent remote-execution layer: talk
to it over the plain HTTP/JSON API or the MCP server, with **zero changes to
agent code**. The API is documented in [Agent HTTP Integration](../integration/agent-http.md); ready-made clients
(OpenAI SDK, Eino, keep-alive, minimal MCP) live under `examples/` in the repo.

## Why does every request need `sandfs_id`?

Because requests address their sandbox explicitly — there is no
single-sandfs auto-resolution. Your API key identifies **you**; `sandfs_id`
identifies **which of your sandboxes** the call targets (one agent can own
several). The gateway verifies you own it — a sandfs that is not yours answers
exactly like one that does not exist (`404 "sandfs not found"`). Discover your
ids with `GET /agent/sandfs`, then pass `sandfs_id` on every per-sandfs
request. See [Agent HTTP Integration](../integration/agent-http.md).

## Why did my exec return 503? Should I retry?

Yes — resilience errors are **retryable by contract**. Poll at roughly the
`retry_after_ms` cadence in the error body: it is a suggested poll interval,
not a recovery deadline. Local transients (`UNMOUNT_IN_PROGRESS`,
`NO_AVAILABLE_SANDBOX`, …) clear in milliseconds to seconds; failure-class
codes (`OWNER_NODE_DOWN`, `OWNERSHIP_CONFLICT`) can legitimately persist for
minutes while the recovery clocks run (up to ~11–12 min with defaults). Do
**not** hop gateway addresses — DNS and the 307 redirect always converge back
on the owner; just keep retrying the same name. Full table:
[Agent API error model](agent-api.md#error-model).

## What happens to my files / background execs when a failure occurs?

Your **workspace always persists** — it is the recovery anchor. In-flight
commands are the uncertain part: an error or timeout means the result is
**UNKNOWN, not failed** (the command may have completed), so read the
workspace first, then resume or roll back. Make side effects idempotent or
checkpointed. Background execs are memory-only handles: after a failure they
are lost (`not_found`) and must be re-created with a new
`execute(background: true)` — the work may already have run; trust the
workspace. This is the
[abort contract](../integration/agent-http.md#7-design-for-the-abort-contract).

## How fast is it?

On bare metal: warm exec (sticky lease) **~0.9 ms client P50**, agent switch
(cold mount) **~2.7 ms client P50** — the pool absorbs VM boots, so requests
pay only the warm/switch numbers. On nested virtualization everything shifts
up (warm ~3.4 ms, switch ~9.8 ms client P50; the cold tail tops out at
14.8 ms). Numbers, methodology, and the per-segment breakdown are in the
[Latency Report](../benchmark/baremetal.md) and its
[nested-virt companion](../benchmark/nested-virt.md).

## Which volume mode should I pick?

**Flat**: full writable copy per SandFS — OS package managers work, zero
write overhead, simplest. **Overlay**: read-only template shared by all
SandFS instances of that template plus a private writable `workspace/` +
`home/` per instance — one extraction serves the fleet, creation is instant,
and it is the natural fit for multi-node shared storage. The decision table:
[SandFS](../how-it-works/sandfs.md).

## Can agents install packages?

Depends on the mode, and it is fixed per SandFS at creation (not per
request). **Flat** keeps the Install execution profile, so OS package managers
(`apt`/`dpkg`) work. **Overlay** drops all capabilities — no OS package
installation — but language packages still work and persist under
`/home/agent` (`pip install --user`, `npm install -g`, …). The common
pattern: build a template in a flat SandFS (install OS packages, save as
template), then run production SandFS instances from it in overlay mode. See
[Isolation and Swap](../how-it-works/isolation-and-swap.md) and
[Storage](../how-it-works/sandfs.md).

## Can two agents share one SandFS?

No — every SandFS has exactly one owner (`agent_id` at creation; another
agent's request for it gets the same `404 "sandfs not found"` as an unknown
id). "Cross-agent switching" is the platform's internal mechanism for
reusing a microVM between different agents' SandFS instances — with full
memory clearing between them — not a sharing feature. Give each agent its own
SandFS. Creation semantics: [Human API](../reference/human-api.md).

## Single-node or distributed — which do I need?

Single-node is one gateway process with an in-memory store — no etcd, no DNS;
right for trying Sandswap and single-box deployments. You need the
distributed shape (exec + human gateways, etcd, sandns) when you run
multiple gateways, need failover, or scale past one machine. Topologies and
the mode table are under [Operations](../operations/index.md).

## Is it safe to run untrusted agent code?

That is the design center. Executed code runs in a KVM microVM under layered
in-guest defenses (chroot, capability drops, deny-list seccomp, per-agent
cgroup with memory cap, masked `/proc`, minimal `/dev`), behind a VMM-level
`allowed_dirs` filter, with a clearing chain on every agent switch that
covers processes, mounts, caches, kernel objects, and sockets — a second
agent starts with zero residual state from the first. The profile
comparison finds Sandswap no weaker than Docker's default and strictly
stronger on seccomp and `NO_NEW_PRIVS`. Full analysis:
[Isolation and Swap](../how-it-works/isolation-and-swap.md).

## Where do I get an API key?

From the control plane: `POST /human/agent` — or `sandctl api agent
create --name ...`, which caches the key locally. The key
(`sk-sandswap-agent-...`) is returned **exactly once**; store it. Deleting
the agent deletes its SandFS instances too. Reference:
[Human API](../reference/human-api.md); walkthrough:
[Quick Start](../getting-started/index.md).
