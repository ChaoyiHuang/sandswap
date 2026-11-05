---
title: Script framework
parent: Testing
nav_order: 3
---

# Script framework

Every script under `e2e/` and `deploy/` — 103 of them at the time of
writing (67 e2e, 36 deploy) —
is built on the same two shared libraries and is verified by the same matrix
runner. This page is the contract; the code is the reference.

## Why the layers exist

Each feature added in the last two weeks added a *dimension* to what a script
must set up before it can run: the storage-plane split made path ownership
depend on the deployment shape, the four service identities made every launch
path identity-aware, the volume-name seed became mandatory for the prov role,
the template store gained an owner, the device nodes gained per-owner modes,
and the API gained named *retryable* refusals with a pacing hint.

Each script originally hand-rolled all of it. Each one drifted differently.
The measured bill: twelve divergent exec clients, seven pasted copies of the
retryable-refusal regex, eight pool parsers over four different `/stats`
shapes, three seed implementations whose path, mode *and* owner all differed,
two host-network implementations, two device-node implementations, three
agent/sandfs creators and roughly a dozen ad-hoc wait loops — plus six broken
deploy modes and a probe with six stacked defects.

The fix is not "be more careful". It is one implementation per concern, and a
script that is written against it by default.

## Layers

| Layer | File | Owns |
|---|---|---|
| Host | `common/sh/runtime.sh` | identity creation, runtime directories, the prov-side path contract, device nodes, the volume-name seed, the host bridge + NAT, residue sweeps, logging and pass/fail counters |
| Stack | `common/sh/stack.sh` | the HTTP layer against a **running** stack: retryable-refusal classification, JSON request construction, exec calls, `/stats` parsing, health/pool waits, agent+sandfs creation, the skip-vs-fail preconditions |
| E2E | `e2e/common.sh` | the e2e tree's names (aliases for the two layers), preflight, service lifecycle helpers, cert/config generators, etcd helpers |
| Deploy | `deploy/baremetal/common.sh`, `deploy/baremetal/deploy-lib.sh` | deployment host prep, systemd units, the side-effect ledger, deploy orchestration |

Both `runtime.sh` and `stack.sh` are leaves: they set no shell options, install
no traps and source nothing. Every public name that existed before the
consolidation still exists — as a thin wrapper that delegates — so the 50-plus
existing consumers did not change.

## The prelude

A script that mutates the host calls one function:

```bash
source "$ROOT/e2e/common.sh"
ss_script_host_prep          # identities → dirs → devices → storage share → seed
```

Steps are individually skippable (`SS_PREP_SKIP=devices,network`) and the call
prints one machine-readable `PREP: …` line naming what it applied. A script
that needs the same effect piecemeal uses the individual primitives
(`ss_ensure_dev_nodes`, `ss_apply_share_plane`, `ss_ensure_volume_seed`,
`ss_prepare_dirs`) rather than writing its own `chown`/`mknod`/`openssl rand`.

## The guards

Nothing above is enforced by good intentions; three mechanical checks run in
CI and in the battery:

- **`e2e/framework-unit.sh`** — the framework's own unit suite (no root, no
  KVM, seconds). It asserts the *definition-time* contract (every public
  helper exists the moment the library is sourced — one shipped with two
  helpers defined inside another function's body), that the tree's names still
  delegate to the shared implementation, the retryable predicate against a
  true/false matrix, the JSON builder's round-trips, and all five `/stats`
  shapes.
- **`e2e/check-handrolled-prelude.py`** — the authoring-time ratchet over both
  trees. It flags a hand-rolled seed mint, a literal identity in an ownership
  operation, a pasted retryable regex, an inline `/stats` parse, a hand-made
  runtime directory and a new local exec client. Known sites are listed in the
  file with a reason; `# prelude-ok: <reason>` exempts a line in place.
- **`deploy/baremetal/check-shape-hardcodes.py`** — the same idea, scoped to
  deploy-shape ownership.

Both scanners are red-checked by `e2e/harness-fault-injection.sh` (FI-B): a
scratch tree with an injected violation must flip the scanner red, and the
injection never touches the real tree.

## The script matrix

Each tree has its own runner — `e2e/run-matrix.sh` and
`deploy/run-matrix.sh` — and each answers "which scripts of MINE have actually
been run since the last change?" mechanically. They share the engine
(`common/sh/matrix.sh`) and are **independent**: either can be run alone,
against its own checkpoint (`/var/tmp/r3-matrix/<tree>/`), without the other
tree being present or idle. A tree's runner declares only what is that tree's:
its classification table (class, timeout, cleanup, args), its phases, its
preflight and its row preconditions.

What a runner refuses to do:

- It enumerates every `*.sh` under its own tree and requires exactly one row
  per script. An unclassified script, a duplicate row, or a row count that
  disagrees with the enumeration makes the **runner itself fail** — there is
  no partial report.
- Every row records a verdict from a closed vocabulary (`PASS`, `FAIL`,
  `SKIP` with a reason, `BLOCKED-PRODUCT` with a finding id), the wall time,
  the log path, the boot id, and the **closure hash** the verdict was judged
  on: the script plus every shared file it can transitively pick up, plus its
  invocation arguments. Changing a shared library therefore invalidates
  exactly the rows that must be re-run — the re-run set is computed, never
  guessed.
- A row declares inputs beyond its own file in the spec: an `extra:` path
  folds its content into the row's closure hash (the docs-truth row scans
  the docs tree; the deploy-pins row scans deploy installers), and an
  `artifacts:` path is aggregate-preflighted before any row runs — a
  missing optional build artifact fails the pass up front, never
  mid-battery.
- The environment is swept before every row and *verified* after it; residue
  is recorded in the row rather than blamed on the next script.
- Phases that verify a fixture they deploy themselves (the deployed-stack
  drills, the k3s legs) run in fixture mode, where the sweep is suspended and
  the phase tears the fixture down and verifies cleanliness once at the end.
- The checkpoint is written atomically after every row, so a reboot resumes
  instead of restarting.

Where the two trees meet:

| | e2e runner | deploy runner |
|---|---|---|
| enumerates | `e2e/` (67) | `deploy/` (36) |
| phase A | the battery — the matrix EXECUTES the ordered rows itself (per-row verdicts, reuse and resume) | — |
| phase B | — (no class-B rows: the self-contained latency benchmark replaced the deployed-stack drill) | deploys the one-machine-etcd fixture, runs the verifiers, uninstalls |
| phase K | — | k3s legs (installs and uninstalls k3s inside the phase) |
| phase C/E/H | self-contained rows | self-contained / dry-run / heavy deploy rows |

The matrix executes the battery rows directly: each row is an independent
verdict with its own closure+artifact reuse probe, pre-row sweep and timeout,
so fixing one script re-runs that script rather than the whole battery.
LLM/docker gating is a runner rule; `--fast` skips the bench rows.
`run-round.sh` drives the e2e and deploy matrices as one round. In the
e2e tree every row runs under an isolated battery root (`SANDSWAP_E2E_ROOT`,
default `/var/lib/sandswap-e2e`) so a row's environment sweep — or a
targeted `--only` re-run — can never touch a deployment under
`/var/lib/sandswap`.

Every e2e row is self-contained: a script that needs a stack deploys and
removes its own (the benchmarks included), so no e2e verdict depends on an
externally supplied fixture.

A `SKIP` is never a silent exit-0: `tc_skip_suite` writes its reason into a
marker file that both the battery and the matrix classify on, so "it did not
run" is visible and auditable in the evidence.

## Writing a new script

1. Source the tree's `common.sh`; do not re-implement anything the two layers
   already own.
2. Call `ss_script_host_prep` (or the individual primitives) before touching
   the host.
3. Probe a stack with the `ss_*` stack helpers — the retryable predicate, the
   JSON builder and the pool parser each exist because a hand-rolled copy got
   it wrong.
4. If your script needs a precondition it does not create (a deployed stack, a
   cluster, an export), report it with `tc_skip_suite` and a reason from the
   closed vocabulary; a bare `exit 1` reads as a product failure.
5. Run `e2e/framework-unit.sh` and `e2e/check-handrolled-prelude.py`; add the
   script to YOUR tree's classification table (`e2e/run-matrix.sh` or
   `deploy/run-matrix.sh`) and re-run that runner — an unclassified script
   makes it fail its own self-check, which is the point.

## Not consolidated

Recorded so the next reader does not re-litigate it:

- Seven per-suite exec helpers that are *instrumentation* rather than
  transport (they format output, capture per-attempt latency, or resolve the
  sandfs id through a suite-local map). Consolidating them means rewriting
  each test's call sites, not its plumbing.
- The k8s deploy library keeps its own flow: its ownership model is
  Secret/ConfigMap-based and its verification needs a live cluster.
- The configuration and certificate generators stay separate: the three PKI
  shapes (bare-metal mTLS, k8s secret material, e2e throwaway) differ in what
  they must produce, and the blast radius of a wrong merge is every deploy
  path at once.
