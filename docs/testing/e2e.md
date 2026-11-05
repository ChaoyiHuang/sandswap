---
title: E2E Catalog
nav_order: 2
parent: Testing
---

# E2E Catalog

> **Developer/test-only — not a production installer and not a production test suite.**
> Everything under `e2e/` is a developer harness. The scripts deploy ephemeral
> gateways/sandlots/microVMs, create and delete test agents and SandFS records,
> reset etcd state, use anonymous control planes, change host network/device
> state (including `/dev/net/tun` modes and firewall rules), and may remove
> `/run/sandswap` or test volumes. **Do not run them against a production host
> or cluster, and do not copy their settings into production.**
> Test-only settings that must never be promoted include:
> `-allow-anonymous-human`, the loopback NFS test export,
> `chmod 666 /dev/net/tun`, any blanket FORWARD ACCEPT added around the
> `inet sandswap forward` chain the deployer installs, and
> `SANDSWAP_TEST_VMM_NET_ADMIN=1` (it grants the otherwise zero-capability
> sandvmm `CAP_NET_ADMIN` for a test host).
> For production, use [Deployment](../deployment/index.md) and
> [Operations](../operations/index.md); the storage-specific hardening is in
> [Storage Requirements §4](../operations/storage.md#4-production-storage-isolation-must--the-storage-service-is-not-a-tenant-network).

Every suite script under `e2e/` — what it validates, how to run it, and
what it needs. 67 files, each with exactly one row in
`e2e/run-matrix.sh`'s SPEC: 64 suite scripts — 52 battery rows (class A,
executed in order by the runner's phase A) and 12 self-contained rows
(class C, run outside the battery) — plus the libraries `common.sh` and
`pin.sh` (CPU/NUMA pinning) and the runner `run-matrix.sh` itself
(`run-round.sh`, at the repo root, drives the e2e and deploy runners as
one round). LLM-key gating (`eino-agent-mcp.sh`,
`latency-benchmark-aiagent.sh`, `single-node-multi-agent.sh`) and docker
gating (`oidc-keycloak.sh`) are runner rules; `--fast` skips the five
tagged rows (scale-rehearsal and the four benchmarks).
The drills that verify an operator-DEPLOYED stack instead of deploying
their own are not suite scripts — they live in
`deploy/baremetal/verify-*.sh` (the
[bare-metal script family](../deployment/install-baremetal.md#15-the-bare-metal-script-family)).

Conventions shared by all scripts (freshness gating, self-contained
setup/teardown, scoped process assertions, loud skips) are described in
[Testing](index.md). The assertions below are summaries — each script is
the source of truth for its own checks.

Prereq legend: **KVM** = root + `/dev/kvm` + built artifacts; **etcd** =
real etcd running (resolved or downloaded by the script), no KVM, no
root; **docker** = a docker daemon; **none** = binaries only.

## 1. Coordination layer (etcd)

Real etcd, real gateway/sandns binaries, no microVMs — run without root
where the etcd ports are free (§1.7 brings its own ephemeral etcd and
wants root for its dedicated ports).

### 1.1 `ownership.sh` — cross-gateway coordination

`bash e2e/ownership.sh` · etcd. Go integration tests against a real etcd:
CAS claim, health-key expiry takeover, watch conflicts, disconnect
cleanup, placement semantics, staleness gates, reap-stuck reclamation.
The `-run` list deliberately uses unanchored regex prefixes so renames
that keep the family prefix keep running; a rename away from the prefix
trips the vacuous-pass guard.

### 1.2 `dns-staleness.sh` — owner-freshness routing

`bash e2e/dns-staleness.sh` · etcd. Fresh owner → route to owner; dead
owner + mounted + presence points at a live peer → directed reroute; dead
owner + idle → scheduling fallback.

### 1.3 `self-pressure-gate.sh` — self-pressure placement gate

`bash e2e/self-pressure-gate.sh` · etcd. The self-pressure signal makes
sandns stop placing NEW traffic on a gateway under sustained resource
pressure; the gate is asserted against a real etcd-backed deployment.

### 1.4 `load-shed.sh` — voluntary rebalancing

`bash e2e/load-shed.sh` · etcd. Sustained saturation with an idle peer
releases ownership, cooldown refuses re-claiming, peer CAS-claims, watch
clears the cooldown; HTTP layer emits 503 + `Retry-After` +
`Connection: close`.

### 1.5 `staleness-gateway-e2e.sh` — reclamation endpoints

`bash e2e/staleness-gateway-e2e.sh` · etcd. The human-gateway reclamation
end to end: idle sandfs reclaimed, mounted ones only when node presence
is gone, dry-run reports only, live owner refused (409); `/stats` exposes
`stale_sec` / `last_healthy_ts`.

### 1.6 `staleness-routing-e2e.sh` — the 307 staleness gate

`bash e2e/staleness-routing-e2e.sh` · etcd. Over the full `/agent/execute`
path: fresh owner → 307 redirect (tolerate); dead owner → 503, never
redirected into a dead gateway.

### 1.7 `scale-rehearsal.sh` — million-level control-plane rehearsal

`sudo bash e2e/scale-rehearsal.sh [--smoke]` · host, no KVM — an
ephemeral etcd + gateway on dedicated ports (`--fast` drops it via the
`heavy` tag). Executes the million-level control-plane claims at target
population instead of asserting them from documentation:
`SCALE_TENANTS × SCALE_AGENTS × SCALE_SANDFS` records populated by
`gateway/cmd/scalepopulator` in the gateway's exact wire formats
(namespace-tenant-distributed), then the curves are measured — identity
full-load cold start to `/ready`, list/pagination latency at population,
ownership/health read rates — each becoming a row of the scale-claims table.

## 2. Control-plane auth (docker)

### 2.1 `oidc-keycloak.sh` — real-IdP OIDC integration

`bash e2e/oidc-keycloak.sh` · docker. Spins up Keycloak (pinned 26.7.4)
in a container, provisions realm/client/scopes/audience-mapper/user over
the Admin REST API, and drives a single-node gateway started with
`-authn-*` against it: 401 for missing/garbage/foreign-issuer tokens,
403 for missing scopes (human vs admin vs ops split — a user-scoped token
cannot mint agent credentials, and only the ops scope passes the
ownership-reclamation gate), 200 on `/human/*`+`/stats`+`/metrics` with
the right scopes, `/health` stays open, an OIDC token never authorizes
the exec plane, the write path provisions an agent through the admin
scope, and a live signing-key rotation verifies the JWKS force-refresh
(unknown kid) and the old-key grace merge — no restart. Docker (or the
image pull) absent → loud SKIP, exit 0 — the same external-dependency
treatment the runner gives LLM-key scripts. No KVM, no root.

## 3. Unit suites and static gates inside the runner

No KVM, no running stack — these rows pin a unit suite, a gate, or a
verifier parser. The unit layer itself is described in
[Testing → Unit tests](index.md#1-unit-tests).

### 3.1 `resilience.sh` — Go unit subsets, strict gate

Run `bash e2e/resilience.sh` · none (Go). Gateway unit-test subsets
(mount lock, CLEANING state, transport retry) with strict pass/fail and
the race detector; `--e2e` additionally runs the ownership integration
test.

### 3.2 `harness-fault-injection.sh` — prove the harness can FAIL

Run `bash e2e/harness-fault-injection.sh` · unit. A suite that cannot
fail is not evidence: this drill mechanizes sabotage so it can ride the
battery. Each case = SABOTAGE (break a component or assertion gate) →
run the owning gate → assert RED → RESTORE → assert the tree is clean
again.

### 3.3 `framework-unit.sh` — the shared framework's own unit suite

Run `bash e2e/framework-unit.sh` · none (seconds). The definition-time
contract of the two shared layers: every public helper exists the moment
the library is sourced, the tree's legacy names still delegate to the
shared implementation, the retryable predicate against a true/false
matrix, the JSON builder's round-trips, and every `/stats` shape the pool
parser has had — see [Script framework](script-framework.md).

### 3.4 `memory-identity-persistence.sh` — identity store persistence

Run `bash e2e/memory-identity-persistence.sh` · none (gateway only).
MemoryStore identity persistence across a real gateway restart
(`gateway/identity/identity_store.go`, `-identity-store`): the old api
key still resolves and execute passes auth after restart, the snapshot is
0600/hash-only/valid JSON at the state path, a second gateway on the same
state file is flock-locked out, a corrupt snapshot refuses to start, an
explicit empty `-identity-store=` (persistence cannot be disabled)
refuses to start.

### 3.5 `warden-unit.sh` — the Rust suite as a suite-visible step

Run `bash e2e/warden-unit.sh` · none (cargo). Runs the warden unit tests
(CI set; plus the root-gated `#[ignore]` chroot/mount/seccomp tests when
run as root) with a parsed pass-count floor — the same gate the warden
build runs, made visible in the runner so a broken Rust suite cannot hide
behind a cached binary.

### 3.6 `docs-truth.sh` — code↔docs parity, the battery's first row

Run `bash e2e/docs-truth.sh` · none (static). Runs `check-docs-truth.py`,
which derives the truth from the code and fails on drift in BOTH
directions: CLI flags, YAML config keys, HTTP routes, structured error
codes, environment variables, MCP tool names, `/metrics` metric names,
and the canonical-terminology deny-list. Read-only, stdlib-only, ~0.4 s —
a broken doc is a release defect that surfaces before any microVM boots.

### 3.7 `host-exec-paths.sh` — pinned host-utility paths

Run `bash e2e/host-exec-paths.sh` · none (static). Runs
`check-host-exec-paths.py`: a privileged component may execute a host
utility only through sandlot/hostbin's pinned absolute path — never a
bare, PATH-resolved name.

### 3.8 `build-gate-selftest.sh` — build/release supply-chain gate pins

Run `bash e2e/build-gate-selftest.sh` · none. Pins the cheap half of the
build gates without a network or a real build: the install-deps checksum
gate refuses an UNPINNED etcd version and a checksum MISMATCH before
extraction (behavioral, via `--verify-selftest`); the Ubuntu template
base tarball/mirror must be HTTPS and SHA256-pinned with no `trusted=yes`
apt sources; the release packager's `ALLOW_NO_IPV6_KERNEL` cannot skip
the kernel gate.

### 3.9 `host-id-check.sh` — the host-security verifier's identity parser

Run `bash e2e/host-id-check.sh` · none. Pins the four-value
(real/effective/saved/fs) uid/gid parser behind
`security/verify-host-security.sh` check 7: synthetic `/proc/<pid>/status`
bodies with a saved-uid 0 or a mismatched fs gid must FAIL, so reverting
the verifier to a CapEff-only check cannot pass this suite.

### 3.10 `vsockguard-verify-modes.sh` — safe vsockguard verifier refusals

Run `sudo bash e2e/vsockguard-verify-modes.sh` · root only (the verifier
checks it; nothing touches a production pin — `VSOCKGUARD_PIN_DIR` points
at a scratch directory). Pins `security/vsockguard-verify.sh`'s refusal
modes: no pin + default mode fails "not attached" (never attaches
implicitly), a present pin + `--self-test` is refused (never replaces a
production pin), `--self-test` without artifacts fails (never attaches a
half-built program).

### 3.11 `deploy-tree-pins.sh` — deploy-tree install/rotation pins

Run `bash e2e/deploy-tree-pins.sh` · none (host-safe: every check runs
against scratch copies). Pins the deploy-tree defects that once had no
row — a broken INSTALLED copy passed a green matrix while the unit
crash-looped at boot: the installed `setup-network.sh` unit resolves
`common/sh/runtime.sh` from the repo tree or `/usr/local/lib/sandswap`
and dies with a NAMED message when neither exists; every `log_*` helper
the k8s deploy library calls is defined in its entry scripts'
environment; `rotate-volume-seed.sh --stage` refuses to target the file
the CURRENT generation points at and a second rotation's mint lands at a
NEW path (earlier generations' files stay byte-identical); the
`--prov-hosts` stage fan-out transfers through remote mktemp paths,
never parks a generation file in `/tmp`, and never reports a non-2xx HTTP
answer as success; and the host-security verifier's tmpfs seed check
never prints "ok" from an unparsable mode.

## 4. Smoke and functional API

### 4.1 `smoke.sh` — minimal full-stack smoke

Run `sudo bash e2e/smoke.sh` · KVM · ~2–3 min. The recommended first run.
Validates: real KVM microVMs end to end, guest egress probe (guest → TAP
→ bridge → NAT → internet — the only test covering the full outbound
path), shell file I/O, cross-agent isolation, persistence across hot
switches, sticky lease asserted via the `X-Sandbox-Lease` header, and the
`/metrics` projection agreeing with the `/stats` numbers. Latency
measurement is deliberately NOT here — the same numbers exist at ns
precision in the execute response; use the benchmark scripts (§10).

### 4.2 `file-api.sh` — unified file API

Run `sudo bash e2e/file-api.sh` · KVM. Validates: all 7 actions
(read/write/stat/list_dir/mkdir/remove/rename), binary and offset I/O,
append, cross-agent isolation, path-traversal rejection.

### 4.3 `parallel-exec.sh` — concurrent execution on one SandFS

Run `sudo bash e2e/parallel-exec.sh` · KVM. Validates: the per-VM
connection pool (`exec_slots`) runs N commands in parallel (total ≈
single-command time), `peak_concurrent_execs` observed, no slot queuing
while N ≤ exec_slots.

### 4.4 `exec-timeout-policy.sh` — exec timeout edge policy

Run `sudo bash e2e/exec-timeout-policy.sh` · KVM. Driven by non-default
`-default-exec-timeout-sec`/`-max-exec-timeout-sec` (no other e2e passes
them). Validates: omitted/`timeout:0` → default bound fires;
far-over-max → clamped to max (and measurably later than the default
probe — two distinct knobs); `timeout:<0` → up-front 400 with the named
message; out-of-range startup flags (`max` < `default`) normalized to
`default` behaviorally. All observed as `timed_out` + kill-time windows +
preserved partial output, never internals.

### 4.5 `mcp.sh` — MCP server end to end

Run `sudo bash e2e/mcp.sh` · KVM. Validates the MCP client → gateway →
gRPC → sandlot → VMM → microVM chain with all 12 MCP tools exercised.

### 4.6 `eino-agent-mcp.sh` — LLM-driven framework agent

Run `sudo bash e2e/eino-agent-mcp.sh` · KVM + a real LLM key
(`DEEPSEEK_API_KEY`). Two agents sharing one microVM pool driven by a
real LLM: MCP tool discovery, code execution, file operations, virtio-fs
`allowed_dirs` hot-switching. Auto-builds the Ubuntu rootfs. SKIPs loudly
without a key.

### 4.7 `multi-agents.sh` — two-agent overlay scenario

Run `sudo bash e2e/multi-agents.sh` · KVM. A Task-Manager agent (SQLite)
hands over to a Data-Analyst agent (Python) with realistic thinking
delays: microVM reuse across switches, template dedup, and data
persistence.

### 4.8 `single-node-multi-agent.sh` — eino acceptance on the deploy tree's single-node stack

Run `sudo bash e2e/single-node-multi-agent.sh [--skip-build] [--no-tls]` ·
KVM + an LLM key. Deploys the background-process single-node stack by
DELEGATING to `deploy/baremetal/deploy-single-node.sh` (MemoryStore
gateway, merged exec+prov sandlot, TLS, pool wait — the stack is not
hand-rolled here), hot-swaps the Ubuntu template in (the eino agents need
a real userland; no restart), then runs the eino multi-agent acceptance:
4 agents + 4 sandfs via the `/human` API, VM reuse and cross-agent
isolation. No etcd, no Kubernetes. SKIPs loudly without a key.

## 5. SandFS and template lifecycle

### 5.1 `template-lifecycle.sh` — template discovery without restart

Run `sudo bash e2e/template-lifecycle.sh` · KVM. Add / delete / re-add a
template directory under a scan root and require every transition
reflected on the READ surfaces (listing, sandfs creation) with zero
gateway restarts — the lazy-rescan discovery contract, overlay AND flat
modes; deleting makes creation FAIL FAST (no ghost sandfs that would only
fail at mount time).

### 5.2 `template-swap.sh` — overlay template upgrade in place

Run `sudo bash e2e/template-swap.sh` · KVM. Overlay template
detach/attach while the agent's workspace and home carry over: the
lifecycle gate (`detaching` → execs/file ops 409 `SANDFS_NOT_ACTIVE`, bg
exec expires), attach rewrites the marker (home policy keep/archive/
reset), the template-deletion in-use check closes the retirement loop.

### 5.3 `template-ref-isolation.sh` — cross-tenant template-ref immutability

Run `sudo bash e2e/template-ref-isolation.sh` · KVM. The ref→filename
encoding is not injective (`RefToFilename` maps `:` to `_`), so a
colliding ref can name another tenant's ref file. On a real stack: an
attacker planting a trojan `/bin/sh` and saving a template under the
colliding AND the exact victim ref both get 409 `TEMPLATE_EXISTS` and no
attacker layer is created; the victim's ref file still names the victim's
name:version/layer; an overlay SandFS created from the ref runs the
template's `/bin/sh` (a symlink to busybox, not the trojan) and the
attacker's marker never runs. Also pins the warden seccomp fix that
restored `setsid`.

### 5.4 `sandfs-delete-lifecycle.sh` — deletion under concurrency

Run `sudo bash e2e/sandfs-delete-lifecycle.sh` · KVM. DELETE while a long
sync exec runs (the exec finishes or fails cleanly, never a hang), while
a warm lease holds the VM (clean teardown, no overlay mount residue in
the node's mountinfo), and execs against the deleted sandfs resolve 404.

### 5.5 `lifecycle-split-gateway.sh` — split-topology lifecycle

Run `sudo bash e2e/lifecycle-split-gateway.sh` · KVM + etcd. A HUMAN
gateway (no pool) and an EXEC gateway (pool + exec sandlot) on one etcd
with a prov sandlot feeding the storage plane: the watch-driven half of
the lifecycle machinery that single-node inline drains cannot reach —
detach issued on the human gateway drains the exec gateway via its etcd
identity watch, and the settled status is written back over etcd.

### 5.6 `oci-registry.sh` — template lifecycle over a real registry

Run `sudo bash e2e/oci-registry.sh` · KVM (+ local htpasswd-authenticated
registry). Flat template → SandFS → save-as-template → push → delete
local cache → pull → overlay SandFS, plus **auto-pull on create** for
both modes (the create response's `pull_status` asserted `pulled` then
`cached`) and a negative check that the registry rejects unauthenticated
access (401) — the prov instance carries registry credentials for every
pull. The executable companion of
[OCI Registry Integration](../integration/registry.md).

### 5.7 `volume-seed-rotation.sh` — the seed-rotation window

Run `sudo bash e2e/volume-seed-rotation.sh` · KVM. The maintenance-window
rotation, end to end on the real stack: maintenance ON refuses agent
traffic WITHOUT restarting the gateway (`/health` and `/stats` stay
reachable), the next seed generation is STAGED via the prov config
hot-reload, volumes are renamed and records updated, PROMOTE completes,
and traffic resumes with data and identity stamps intact.

### 5.8 `volume-seed-injection.sh` — the seed channels and their guards

Run `sudo bash e2e/volume-seed-injection.sh` · KVM. The properties an
INJECTOR (a Vault agent, an External Secrets Operator, a systemd credential,
a tmpfs fetch unit) depends on, none of which a config file can express: the
generation files live in tmpfs for the whole drill (nothing of the seed
touches persistent storage); the rotation window freezes sandfs creation
fleet-wide with a named `ROTATION_IN_PROGRESS` refusal; rewriting the CURRENT
source out of band is refused, never adopted, and the storage plane keeps serving;
swapping the STAGED generation mid-window is refused; a config-driven promote
(what `kubectl` does on k8s, no tool in the loop) is refused by the DAEMON's
own completeness gate; a full stage → run → promote rotation completes on
tmpfs with the tenant's data intact; and a restart against a tree no
configured generation derives is refused by the startup guard, with
`-allow-seed-generation-mismatch` as the deliberate re-key path.

## 6. Isolation

### 6.1 `overlayfs-isolation.sh` — overlay-mode security isolation

Run `sudo bash e2e/overlayfs-isolation.sh` · KVM. Validates: kernel-
enforced read-only rootfs (writes blocked), `/workspace` and
`/home/agent` writable, virtio-fs `allowed_dirs` confinement,
cross-agent workspace isolation, environment variables.

### 6.2 `cross-tenant-residue.sh` — residue channels across a switch

Run `sudo bash e2e/cross-tenant-residue.sh` · KVM. One microVM (pool
forced to 1) serves agent A then agent B; kernel objects and tmpfs/proc/
dev state that could outlive the rule-A process sweep are pinned: SysV
message queues / shared-memory segments (guest IPC namespace), POSIX
mqueue creation (denied by the exec seccomp profile), the persistent
uid-0 user keyring, `/dev/shm` tmpfs files, and the masked /proc +
minimal /dev layout (kcore/kallsyms/keys read empty; mem/kmem/port never
created).

### 6.3 `share-root-gate.sh` — the share-root namespace gate

Run `sudo bash e2e/share-root-gate.sh` · KVM. The virtio-fs allow-list
is a namespace control at the share root, not just a visibility filter:
every name-based op whose parent is the share root is denied
(mkdir/mknod/create/symlink/link/unlink/rmdir/rename/xattr), and the deny
path answers a real ENOENT (EIO would tell a guest a hidden name EXISTS
— a cross-tenant name-existence oracle). The executable companion of
[isolation §4](../how-it-works/isolation-and-swap.md#4-the-host-side-boundary-the-virtio-fs-filter).

### 6.4 `mount-identity-race.sh` — generation-bound mount identity

Run `sudo bash e2e/mount-identity-race.sh` · KVM. A single-VM pool (every
scenario must hit the SAME VM), driven directly through the VMM API
socket and the warden-probe — the same vsock path the sandlot uses, as
the sandlot identity — so the interleavings are deterministic: a mount
carrying a superseded generation's alias is refused
`mount_target_not_exported` and executes nothing; the stale request stays
refused after another generation mounts while the live tenant's warm exec
keeps working; an unmount naming a different identity answers MISMATCH
and tears down nothing; set-fs refuses to reuse the previous generation's
alias; and the stale-mount probe does not disturb the live mount.

## 7. Resilience and self-healing

These exercise the tolerance-first resilience model
([Resilience](../how-it-works/resilience.md)); all need root.

### 7.1 `resilience-e2e.sh` — full-stack failure scenarios

Run `sudo bash e2e/resilience-e2e.sh` · KVM. Concurrent mount mutual
exclusion, background-exec loss on sandlot crash, disconnect recovery,
multi-SandFS concurrency, body limits.

### 7.2 `disconnect-tolerance.sh` — the five disconnect paths

Run `sudo bash e2e/disconnect-tolerance.sh` · KVM · FAST mode ≈ minutes
(`FULL=1` production timings ≈ 20 min). Real-KVM coverage of: flash
disconnect (TOLERATING, fast reconnect, ownership unchanged), partition
cleanup (full TOLERATING → CLEANING → DONE → reconnect cycle), warden
countdown firing on a hung sandlot while mounted, countdown staying a
no-op on unmounted CLEAN VMs, and dialing the remembered gateway IP when
DNS has already evicted it.

### 7.3 `vmm-crash-selfheal.sh` — VMM crash → destroy-and-replace

Run `sudo bash e2e/vmm-crash-selfheal.sh` · KVM. sandvmm crash detection
→ destroy-and-replace → pool refilled; scale-down destroys surplus
sandvmm processes; re-adopt sweep kills orphan sandvmm after a sandlot
restart.

### 7.4 `readopt-restart-id-unique.sh` — restart ID-collision regressions

Run `sudo bash e2e/readopt-restart-id-unique.sh` · KVM. Two restart-path
regressions unit tests cannot reach: (PoolIDUnique) startup pre-create
must never generate a VM ID colliding with a live re-adopted survivor —
the old scheme re-landed a pre-created VM on a live seq, unlinking the
live VM's API socket and leaking the original sandvmm; the re-adopt
interplay is asserted end to end.

### 7.5 `multi-instance-orphan-safety.sh` — orphan sweep instance scoping

Run `sudo bash e2e/multi-instance-orphan-safety.sh` · KVM. The startup
orphan sweep scans all of `/proc` but may only signal sandvmm processes
whose socket lives under its own instance root — restarting instance B
must not SIGTERM/SIGKILL instance A's VM fleet; foreign sandvmm processes
are skipped with a log line.

### 7.6 `config-hotreload.sh` — runtime config changes

Run `sudo bash e2e/config-hotreload.sh` · KVM. Pool resize, sticky-lease
timeout change with header-behavior verification, restart-required fields
refusing to apply silently, pendingDestroy deferred teardown while a VM
is in use.

### 7.6a `pool-concurrency.sh` — batch create/destroy concurrency

Run `sudo bash e2e/pool-concurrency.sh` · KVM. Starts a 3-VM pool with
`concurrency.vm_create: 3` / `concurrency.vm_destroy: 4`, asserts the
configured create worker count reached the batch path, hot-reloads the
pool to empty (scale-down to zero idle VMs), and hot-reloads it back to
three. The worker-count bounds themselves (peak concurrent creates and
destroys) are pinned by `sandlot/core/pool_concurrency_test.go`.

### 7.7 `protocol-version-e2e.sh` — cross-version rolling-upgrade drill

Run `sudo bash e2e/protocol-version-e2e.sh` · KVM. Builds genuinely
mismatched binaries from source copies — two flavors per side, both bound
to the script's `OTHER_VER` (3, deliberately outside the current window):
hard mismatch (speaks ONLY v3, no window) and compat window (the newer
version with the window still open at v1, `[1,3]`) — and runs them against
the current build. Asserts: control passes end-to-end;
both stream handshake directions reject out-of-window peers with
named-version logs and zero node registration; a hard-mismatch warden
initramfs fails VM creation fast, aborts pool scale-up, and the
create/destroy churn STOPS; a live survivor booted from the
hard-mismatch initramfs is destroy-and-replaced at re-adopt and its
replacement converges to a healthy pool with a real exec; and the compat
window works in both directions (negotiated echo, zero mismatch lines).
Variants cached per version in `/tmp/pv-e2e`.

### 7.8 `switch-under-adversarial.sh` — swap machinery under hostility

Run `sudo bash e2e/switch-under-adversarial.sh [ROUNDS]` (default 5) ·
KVM. Self-contained (deploys its own single-node stack). The
directory-swap machinery (umount → set-fs → bind + the warden's residue
sweep) must hold while the guest is HOSTILE and exec traffic is
CONCURRENT: straggler background execs planted before the switch must be
gone on return, the previous agent's workspace markers must be invisible
after, and the swap must survive a concurrent sync-exec storm.

## 8. Security hardening

### 8.1 `seccomp.sh` — deterministic deny-list verification

Run `sudo bash e2e/seccomp.sh` · KVM. Seccomp deny-list verification over
the full stack (gateway → sandlot → warden → chrooted exec): mount /
umount2 / unshare return EPERM in BOTH exec profiles; the flat-mode
CapEff is the exact ambient set with `CAP_SYS_ADMIN`/`CAP_SYS_PTRACE`/
`CAP_SYS_RAWIO`/`CAP_NET_RAW` absent. Also asserts the host-side
identity split (per-owner device nodes, dedicated identities) — the
dedicated home for the identity-split and seccomp assertions the
LLM-dependent agent demo does not cover. The suite also uploads a static
`hardening-seccomp-probe`
into the guest and asserts `clone3(CLONE_NEWUSER)` is refused,
`/proc/sys/user/max_user_namespaces` is `0` or absent, and each
class-completeness denial (`mount_setattr`, `statmount`, `listmount`,
`pidfd_open`, `pidfd_send_signal`, `ioprio_set`) returns EPERM.

### 8.1b sandvmm per-thread seccomp — enforced by default

`microvm.vmm_seccomp` defaults to `true` (Trap/SIGSYS enforcement).
`e2e/vmm-seccomp.sh` validates both phases: a log-mode run with the
representative workload produces zero `RET_LOG` hits across the battery,
and the enforce-mode battery stays green. The sweep's trapped set for the
in-process virtio-fs shape (`chmod`/`chown`, `umask(0)`, `getrandom`/
`tgkill`, `readlinkat`) is covered by pin tests in
`virtio_fs_thread_rules` (`vmm/virtio-devices/src/seccomp_filters.rs`);
the credential guard's `getresuid`/`getresgid` are on both filter layers.

`log` remains the audit mode (a missed rule is logged and allowed);
`false` is the explicit escape hatch. `process` (KillProcess) is rejected
by both the sandlot config validator and the sandvmm CLI: it installs
empty per-thread filters, and a library caller that reaches the arm now
gets the full Trap filter instead. A future VMM syscall that the
allow-list misses traps that thread, so re-run `e2e/vmm-seccomp.sh` before
changing the lists.

The live capability assertion (`e2e/seccomp.sh` IdentitySplit and
`security/verify-host-security.sh` check 7) now requires every sandvmm
process to run with `CapEff=0` — the TAP is pre-created by the network
provider owned by the sandvmm uid.

### 8.1c `kernel-config-gate.sh` — guest-kernel config policy gate

Run `bash e2e/kernel-config-gate.sh` · no root/KVM/kernel build. Exercises
`kernel/build.sh config-check` against synthetic `.config` files: a
policy-compliant config passes; a re-enabled disabled symbol (`=y` or `=m`)
and a missing required symbol both fail and name the offender. The real
build runs the same gate after `make olddefconfig` and again as `nm` symbol
probes on the pre-strip image (see `docs/how-it-works/guest-kernel-hardening.md`
§2).

### 8.2 `warden-hostile.sh` — hostile/edge protocol coverage

Run `sudo bash e2e/warden-hostile.sh` · KVM (uses `output/warden-probe`).
Every scenario is a failure or boundary mode production agents can
trigger but no other e2e reaches: malformed frames, oversized bodies,
hostile `mount_point` injection, DoS budgets — dozens of assertions
against the warden's exec, file, and protocol layers.

### 8.3 `warden-log-leak-guard.sh` — no warden internals in guest volumes

Run `sudo bash e2e/warden-log-leak-guard.sh` · KVM. Validates: warden
internal bookkeeping (background-exec logs, countdown debug output) never
leaks into a mounted SandFS or the shared volumes directory.

### 8.4 `vmm-api-auth.sh` — the per-VM sandvmm API token handshake

Run `sudo bash e2e/vmm-api-auth.sh` · KVM (no microVM is created). The
optional `--api-token-fd` handshake, whose preface precedes whichever
framing the connection then uses: default OFF (a VMM started without a
token serves a tokenless raw `sandvmm.ping` — the default sandlot launch
shape); with a token, the correct one passes the challenge → token XOR
challenge exchange and serves the ping, a WRONG token is rejected at the
handshake, and a tokenless raw frame is refused before any command is
processed.

### 8.5 `stream-tls-require-ca.sh` — the stream listener needs a client CA

Run `sudo bash e2e/stream-tls-require-ca.sh` · root, no KVM. There is no
no-CA mode: without `-stream-tls-ca` the gateway exits at startup with
the named `-stream-tls-ca is required` refusal (the old builder used
`RequireAnyClientCert` and bound node identity to the hello's CN — any
host reaching the stream port could present a self-signed
`CN=<victim-node-id>` certificate and receive that node's VMCommands);
with a CA the gateway comes up and serves `/health` on the mTLS-only
stream plane.

### 8.6 `warden-chroot-escape.sh` — agent-planted-symlink chroot containment

Run `sudo bash e2e/warden-chroot-escape.sh` · KVM (self-contained; brings
up its own stack and replaces the pool VM — the warden caches its
mount-mode decision per volume for its lifetime, so each vector needs a
FRESH warden). A FLAT SandFS volume is fully agent-writable, so the agent
can plant entries the warden itself follows at mount time: a planted
`rootfs -> /` symlink must not flip the warden's following-stat
mount-mode probe into the overlay branch (which would bind the warden's
own initramfs root as the chroot); a planted
`etc/resolv.conf -> /bin/busybox` must not let the per-mount resolv write
overwrite the warden's busybox; and the hot-bound `<root>/bin/busybox`
must be READ-ONLY — a write attempt from inside the chroot fails with the
file unchanged (the bind is two-step so per-mount flags survive).

## 9. Egress identity and networking

### 9.1 `egress-identity.sh` — the enabler chain

Run `sudo bash e2e/egress-identity.sh` · KVM. Binding region opens with
sandlot, baseline applies, cold mounts stamp agent/sandfs identity into
the region, per-TAP anti-spoof chain plus VM-to-VM deny, identity
reclamation on unmount with epoch retention. `BINDING_BACKEND=bpf`
switches carrier. The mechanism is
[Egress Enabler Contract](../how-it-works/egress-enabler.md).

### 9.2 `routed-ipv6.sh` — identity-in-address backend

Run `sudo bash e2e/routed-ipv6.sh` · KVM + IPv6-enabled guest kernel.
Guest prefix address, default route, guest→TAP gateway connectivity,
identity stamping during mount (the /128 identity address + SNAT map),
stamp removal on unmount.

## 10. Benchmarks (standalone)

Measurement, not pass/fail — these print distributions; only the marked
hard-fail assertions gate. The published numbers live in the
[Benchmark reports](../benchmark/index.md) (bare-metal and nested-virt
latency, plus the two microVM-reuse capacity reports).

### 10.1 `latency-benchmark-aiagent.sh` — command-path latency

Run `sudo bash e2e/latency-benchmark-aiagent.sh` · KVM. Steady-state
warm/cold stats read from the API's ns fields (`gateway_duration_ns`,
`sandlot_duration_ns`, `exec_duration_ns`) with `X-Sandbox-Lease`
warm/cold classification; `WARM_N`/`COLD_N` sample counts,
`BENCH_VERBOSE=1` prints every sample. `SANDSWAP_BENCH_MODE=mcp` drives
the same loop through MCP tool calls. Auto-labels `[BARE-METAL]` vs
`[NESTED-VIRT]`.

### 10.2 `latency-benchmark-unmount.sh` — release-path latency

Run `sudo bash e2e/latency-benchmark-unmount.sh` · KVM. Async unmount /
VM-recycle latency read exclusively from `/stats` `unmount_stats`
(counter deltas + `top_slow` diff snapshots; baseline / cache16m /
dirty16m scenarios), iterating strictly serially on the booking counters.

### 10.3 `benchmark-overlayfs.sh` — storage-mode microbenchmarks

Run `sudo bash e2e/benchmark-overlayfs.sh` · host (no full stack).
OverlayFS mount/umount, read/write, and agent-switch latency in
isolation. Read-only-rootfs enforcement is a hard FAIL, not a warning.

### 10.4 `latency-benchmark-load.sh` — host capacity + concurrency under a 1ms sticky lease

`bash e2e/latency-benchmark-load.sh [--quick]` · KVM, self-contained
(deploys and removes its own one-machine-etcd stack, §[topologies](../how-it-works/topologies.md)).
Answers, from measurement plus clearly-stated model assumptions, how
many small microVMs / ubuntu overlay SandFS instances a host supports,
the warm and cold (every-request-cold) request rates, and whether lease
expiries still fire at the configured 1 ms precision under load.

- **Estimate** — runs `latency-benchmark-aiagent.sh http distributed`
  and `latency-benchmark-unmount.sh all` and parses their P95s, then
  combines them with `MemAvailable`, `nproc` and the measured per-VM
  `sandvmm` RSS: `N_vm = min(0.85 × avail / (vm_mem + overhead), nproc/2)`,
  `N_overlay = N_vm`, concurrency `C = min(N_vm × exec_slots, 256)`.
  `SKIP_ESTIMATE_BENCH=1` takes `WARM_P95_MS` / `COLD_P95_MS` /
  `UNMOUNT_P95_MS` overrides.
- **Load** — `output/loadgen` (Go, one keep-alive `http.Client`, one
  persistent connection per worker) drives warm runs (each worker pinned
  to one agent, zero gap) and cold runs (each worker alternates its agent
  PAIR with a 2 ms gap > the 1 ms sticky window) at `LEVELS="4 16 64 256"`
  (capped by the estimate), `DUR=10`.
- **Punctuality** — the gateway's new `/stats` `unmount_stats[].lease_fire`
  (fire lag = timer fire time − sticky deadline) must show ≥95% of fires
  under 2 ms and max ≤ 20 ms at the top level; `expected_expiries` from
  the driver must match the `unmount_count` delta within 10%.
- **Shape** — loaded warm/cold P95 ≤ 10× the idle P95, zero HTTP
  failures. Per-level `bench-result {...}` JSON lines and an estimate +
  measured table close the run; any gate failure exits non-zero.

### 10.5 `warden-timing-probe.sh` — keep-logs exec-path profiling

Run `sudo bash e2e/warden-timing-probe.sh` · KVM. Unlike the benchmarks
(which clean up on exit) this deploys a throwaway stack under
`/tmp/ssdbg`, runs warm + switch execs, and **keeps the logs** so the
warden-level exec path can be profiled afterwards.

### 10.6 `latency-benchmark-alloc-sweep.sh` — whole-core allocation search

`bash e2e/latency-benchmark-alloc-sweep.sh --plan --peaks "0.80,1.72,0.97" --cold-per-vm 35` ·
planner needs nothing (no root, no KVM); `--run` is bare-metal only (it
drives `latency-benchmark-load.sh`). The load benchmark fixes one core
allocation; this driver is the search around it: a calibration run
measures per-role peak CPU at a generous split, candidate splits assign
DISJOINT whole cores to loadgen / gateway(+human+etcd) / sandlot(+prov) /
the microVM pool, a validation run measures host and per-VM cold rates at
each split, and the best is the largest host cold/s with zero terminal
failures. The matrix runs the planner only; the published splits are in
the capacity reports.

## 11. Harness helpers (not suite scripts)

- `common.sh` — the shared helper library every script sources
  (assertions, HTTP utilities, etcd lifecycle, deployment, config
  generation, freshness gate, residue sweep).
- `pin.sh` — the CPU/NUMA pinning library the latency benchmarks use.
- `check-docs-truth.py` — the code↔docs parity checker (driven by
  `docs-truth.sh`, §3.6).
- `check-host-exec-paths.py` — the pinned host-utility-path checker
  (driven by `host-exec-paths.sh`, §3.7).
- `check-handrolled-prelude.py` — the authoring-time ratchet over the e2e
  + deploy trees ([Script framework](script-framework.md)).
- `check-docs-links.py` / `check-nil-wrap-scan.py` /
  `check-warden-path-safety.py` — static repo checks (doc-link integrity,
  nil-wrap pattern scan, warden path-safety audit) invoked by review
  flows, not part of the e2e battery.
- `go-mutate.py` — mutation-testing helper for the Go suites (injects a
  source mutation and checks a test actually fails).
- `hardening-seccomp-probe.c` / `mqueue-seccomp-probe.c` — the static
  guest-side probes uploaded by `seccomp.sh` and `cross-tenant-residue.sh`.
- `host-cgroup-migration-bench.c` — the standalone cgroup-v2 migration
  microbenchmark behind the cgroup cost numbers in the design notes.
- `README.md` — the exit-code and self-containment contract in short form.
