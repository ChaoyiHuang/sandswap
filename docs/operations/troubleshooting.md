---
title: Troubleshooting
nav_order: 7
parent: Operations
---

# Troubleshooting

A symptom-first field guide: read `/stats` first, then match the symptom
below. The behavior behind most of these rows is the tolerance-first
resilience model — see [Resilience](../how-it-works/resilience.md) before
concluding something is broken.

## 1. Reading `/stats`

`GET /stats` (on the human listener `:3100` in single-node and human modes —
a classic gotcha for scripts probing `:3000`; an exec-mode gateway has no
human listener and serves `/stats` on its agent listener `:3000` instead —
gated by `-ops-token-file`, without which the endpoint is disabled)
returns the full multi-gateway view: `curl -sk https://gw:3100/stats | jq .`.
A healthy cluster looks like:

- Every gateway `healthy: true` with `stale_sec` ≈ 0 and `last_healthy_ts`
  fresh (rewritten every ~5 s).
- Every exec gateway has `node_count > 0` — a gateway with no sandlots is in
  a failure state and is not routed agents until one reconnects.
- `clean_vms` close to each node's pool target; `in_use_vms` tracks load.

`stale_sec` is judged differently per consumer — know the thresholds (all
hot-reloadable, see §10 of the
[Gateway configuration](configuration/gateway.md) reference):

| Threshold | Default | Meaning |
|---|---|---|
| `route-stale-sec` | 20 s | DNS/307 treat the gateway as stale — rerouting begins; a live gateway is never stale this long |
| `alert-stale-sec` | 30 s | the human gateway's scan logs stranded-ownership warnings |
| `claim-dead-guard-sec` | 45 s | judged dead for takeover / reap tools — expensive to get wrong, hence the longest |

**Unmount stats** (`unmount_stats[]` per node): `top_slow` lists the slowest
unmounts with **three-layer attribution** — `gateway_ms` vs `sandlot_ms` vs
`warden_ms` tells you which layer to blame. Each entry also carries the
`reason` (`lease-expiry`, `cleanup-after-failure`, `cleanup-after-file-failure`,
`delete`, `etcd-fence`) and the sandfs's **last cold-mount command** — the workload whose
residual processes/cache made the `cgroup.kill`/umount slow (unmount itself
runs no command). `under_5ms`/`under_10ms` give the floor.

**Pool-sizing signals**: `peak_concurrent_execs` (observed parallelism) vs
the spec's `exec_slots`, and `slot_wait_ms`/`slot_wait_events` (requests that
queued because the slot pool was exhausted) tell you whether to move to a
bigger spec. `recycle_triggers` counts unmounts that destroyed the VM instead
of returning it CLEAN.

**Per-node signals** (`nodes[]`): `duty_*` utilization series, `host_cpu_pct`
/ `host_mem_avail_mb`, `active_sandfs`, and clean/total VMs — the same load
contract the scheduler scores from, useful when checking why placements
avoid a node.

## 2. Common failures

| Symptom | Likely cause | Fix |
|---|---|---|
| sandlot exits at startup | `/dev/kvm` missing — no KVM on the host | enable KVM (or nested virt on a VM host); verify `ls /dev/kvm` ([prerequisites](../deployment/install-baremetal.md#3-prerequisites)) |
| sandlot exits at startup | `vhost_vsock` module not loaded | `modprobe vhost_vsock` (setup scripts do this; verify after kernel updates) |
| vsockguard attached but not enforcing | `bpf` absent from the kernel's active LSM list — the attached program is a **silent no-op** | `cat /sys/kernel/security/lsm` must contain `bpf`; run `setup-bpf-lsm.sh` + reboot. Beware the cloud-image GRUB override trap — verify `lsm=...bpf` reached `grub.cfg`. See [Host Prerequisites](../deployment/prerequisites.md#22-bpf-lsm-activation-boot-time-reboot-required) |
| pool stuck at `clean_vms: 0`, agents get `NO_AVAILABLE_SANDBOX` | (a) genuine over-subscription, or (b) a small spec whose memory sits near `recycle.mem_abs_mb` — every unmount trips the recycle threshold, so each unmount destroys + rebuilds the VM and the pool repeatedly passes through a clean=0 window | (a) raise the pool target or add nodes; (b) use a larger spec (e.g. medium) or raise/lift the recycle threshold. Watch `recycle_triggers` in `/stats` to confirm |
| `503 OWNER_NODE_DOWN` / `OWNERSHIP_CONFLICT` persists for minutes | **Expected** — recovery is clock-bounded, not stuck: the stale mount is released by the warden countdown at `T_tolerance + T_warden` (~10 min), ownership becomes movable at `T_safe` (~11 min), cross-gateway takeover completes at `T_isolation` (~12 min) | Keep polling at `retry_after_ms`; do **not** manually delete ownership keys or restart components to "force" it — that is exactly the race the design forbids. Timelines: [Resilience §10](../how-it-works/resilience.md) |
| one sandfs 503s forever after its gateway **and** node both died | both-dead safe-stuck: no living party can confirm the switch, so ownership never moves (safe, unavailable) | confirm both are permanently dead (health key stale past 45 s, node presence key gone), then reclaim via `POST /human/ownership/reap-stuck` (by dead owner) or `reap-stuck-node` (by dead node) — `dry_run` first. Guards refuse live owners/nodes (`409`). Reference: [Human API](../reference/human-api.md) |
| unmounts slow (seconds) | residual processes: unmount waits for in-flight commands, then `cgroup.kill` clears the whole agent tree; D-state survivors push it further | read `top_slow` in `/stats`: `warden_ms` dominant → guest-side clearing (the recorded last cold-mount command is the culprit workload); `sandlot_ms`/`gateway_ms` dominant → node/gateway side. An unmount ending in EBUSY destroys the VM by design (exclusivity invariant) — that is correct, not a leak |
| agent hosts can't resolve `*.sandswap.local` | systemd-resolved's stub (127.0.0.53) special-cases `.local` as mDNS and never forwards it | route the zones explicitly (`Domains=~sandswap.local ~sandswap-stream.local`, `MulticastDNS=no`) or put the sandns IP first in `/etc/resolv.conf` — [agent-side DNS](../deployment/install-baremetal.md#13-agent-side-dns-configuration) |
| stale etcd keys accumulate for retired gateways | health, routing (`/sandswap/gateway/{id}`), and unmount-stats keys are plain keys with no lease and no GC — they survive death by design | after decommissioning a gateway, delete its keys with `etcdctl del` (`/sandswap/gateway/{id}`, `/sandswap/health/{id}`, `/sandswap/unmount-stats/{id}`) — [Resilience §5](../how-it-works/resilience.md) |
| gateway fails to start, `systemctl` shows `status=226/NAMESPACE` | the sandboxed unit's `ReadWritePaths` points at a directory that does not exist (typically the shared `vol_root` not yet mounted) | mount the shared filesystem / create the path first, then start — the deploy scripts order this for you ([systemd services](../deployment/install-baremetal.md#11-systemd-services)) |
| sandlot writes to the shared volume get permission-denied | root squashing on the storage server (e.g. NFS `root_squash`) maps root → nobody; the deployment bootstraps the share root as root (`mkdir`/`chown`/setgid) and the prov sandlot writes as `sandprov` (983), so a squashing export breaks the shared-group layout | pre-create the shared layout on the storage server as local root (the one-time bootstrap), then export with Kerberos or `root_squash,all_squash` — see [Storage §4](../operations/storage.md#4-production-storage-isolation-must--the-storage-service-is-not-a-tenant-network) |
| agent requests fail TLS only after a cross-gateway 307 redirect | the redirect lands on `https://<owner-ip>:3000` and the agent cert lacks that gateway's IP SAN | regenerate `mcp.crt` with **every exec gateway IP** in its SANs and redistribute ([TLS certificates](../deployment/install-baremetal.md#9-tls-certificates)) |
| human gateway exits at startup | a non-empty `authn.issuer` enables OIDC discovery; an unreachable issuer kills the process | configure `authn:` only when an OIDC provider is actually deployed; otherwise rely on network-layer isolation ([config note](../deployment/install-baremetal.md#12-configuration-examples)) |
| human gateway refuses to start, log: `refusing to start the human listener without OIDC authentication` | a human listener with no `authn.issuer` will not start silently unauthenticated — the operator must acknowledge it | pass `-allow-anonymous-human` (yaml `authn: {allow_anonymous: true}`), or configure `authn.issuer` ([Authn config](configuration/gateway.md#8-authn-oidc-for-human-endpoints--restart-required)) |

Also worth knowing: multi-sandlot clusters need distinct `instance.id`s
(colliding VM IDs make the gateway drop a node's VMs), and re-deploys hit
"Text file busy" if old processes still hold the binaries — both covered in
the [field notes](../deployment/install-baremetal.md#16-troubleshooting).

## 3. Crash recovery expectations

- **Gateway restart/blip (most common)** — ownership keys have no lease, so
  they persist; the sandlot tolerates the drop, reconnects, and service
  continues in place within seconds. In-flight sync commands usually complete
  too: the sandlot deliberately holds the mounts for the tolerance window
  (`-tolerance-sec`, default 300 s) so commands running inside the microVM
  finish unaffected — the gateway being down does not touch them. `/ready`
  gates agent traffic until the startup full-load finishes.
- **Sandlot restart** — surviving sandvmm children stay alive
  (`KillMode=process`) and are re-adopted. Before reconnecting, the sandlot
  releases all its mounts (connect-clean invariant) — which **aborts
  still-running background execs**; the workspace survives untouched and the
  agent recovers per the
  [abort contract](../integration/agent-http.md#7-design-for-the-abort-contract).
- **Node crash/hang, gateway alive** — the warden countdown releases the
  mount by `T_tolerance + T_warden` even with nobody driving it; the gateway
  owner-releases at `T_safe`; the next request lands on another node.
- **Warden/sandvmm crash or hang inside one VM** — no resilience window at
  all: the sandlot detects it (pidfd/wait or failed probes), ensures the
  sandvmm process is dead, and replaces the VM from the pool; the agent sees
  one 503 and the retry lands on a fresh VM.
- **Gateway dead, sandlot alive** — the sandlot self-cleans, isolates, and
  migrates; the new gateway takes over at `T_isolation` (~12 min).
- **Both dead** — safe-stuck; recovery is on-demand (the next request
  triggers the time-guarded takeover) or manual (reap tools above).
- **etcd partition** — the gateway fails closed (503s, no new mounts) and
  self-fences after `-etcd-fence-sec` (default 180 s) by actively unmounting
  what it holds; when etcd returns it recovers in place. Transient blips do
  nothing.

## 4. Locating logs

- **Bare metal (systemd)**: `journalctl -u sandswap-gateway` (instances:
  `sandswap-gateway@exec` / `@human`), `-u sandswap-sandlot`, `-u
  sandswap-sandns`. The ops CLI wraps this: `sandswap-ops.sh logs gateway 100`.
- **Warden (in-VM)**: the per-VM console log (`<sandbox>/console.log`, hvc0)
  — `mount_and_exec done in Nms` / `exec done in Nms` lines for the
  guest-side view of each command. `<sandbox>/serial.log` keeps the
  `earlyprintk` boot/panic lines only. The sandlot log carries the matching
  `cold mount_and_exec` / `warm exec` lines; see the
  [Latency Report](../benchmark/baremetal.md) for the log-line inventory.
- **State at a glance**: `curl /stats | jq` (this page's first section),
  `sandctl pool`, `sandctl health-all`, or `sandswap-ops.sh status`.

## 5. sandns day-2 operations

Day-2 operations for sandns, the owner-aware DNS service (deploy steps live
in the [install guides](../deployment/install-baremetal.md); the design in
[Ownership & DNS](../how-it-works/ownership-and-dns.md); the config
reference in [sandns configuration](configuration/sandns.md)).

```bash
output/sandctl dns stream             # resolve the stream domain (short form)
output/sandctl dns sandfs <id>        # owner-aware chain for one sandfs (full output)
output/sandctl dns sticky             # list sticky records from etcd
```

- **Adding a gateway**: nothing to edit — it self-registers its routing
  address into etcd at startup and sandns picks it up via watch. Extend TLS
  SANs where 307-following matters.
- **Retiring a gateway**: delete its orphan registry key
  (`etcdctl del /sandswap/gateway/<id>`) and its health key alongside the
  usual both-dead cleanup (the reap tools in the
  [Human API](../reference/human-api.md)).
- **Rebalancing after drift**: `sandswap-ops.sh consolidate` (smart) or
  `--full` — releases ownership + clears the affected sticky records so
  clients re-resolve to idle gateways.
- **Config changes**: sandns watches its config file — scheduling and
  staleness sections hot-reload; `SIGHUP` clears all sticky records.
- **Keep it aligned with the gateways**: sandns's
  `staleness.route_stale_sec` and the gateway's `-route-stale-sec` are
  separately configured copies of one threshold — keep them equal.
- **Scaling sandns itself**: the sandfs zone is stateless, so multiple
  instances are safe behind an L4 LB with source-IP affinity (stream
  stickiness then stays instance-local); owner-cache misses multiply etcd
  reads per instance. Analysis in
  [Ownership & DNS](../how-it-works/ownership-and-dns.md).

Quick hits:

- **`.local` names unresolvable on Ubuntu hosts** — systemd-resolved's
  stub treats `.local` as mDNS; use the routing-domains config or
  resolv.conf ordering shown in the
  [install guide](../deployment/install-baremetal.md#13-agent-side-dns-configuration).
- **SERVFAIL** — no healthy gateway with capacity: check the gateways'
  `/health` and the etcd health keys (`/sandswap/health/`); sandns refuses
  to answer rather than guessing.
- **Per-sandfs name not resolving** — owner-aware names only resolve in
  distributed mode (gateways must be writing ownership to etcd); in
  single-node MemoryStore mode use the gateway address directly.
- **A just-restarted gateway's new address not served** — it rewrites its
  registry key at startup; sandns's next query (or 30 s re-list) picks it
  up — no per-sandfs staleness exists by design.
