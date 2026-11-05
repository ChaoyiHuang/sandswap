---
title: Testing
nav_order: 7
has_children: true
permalink: /testing/
---

# Testing

Sandswap is tested in three layers:

| Layer | Directory | Needs |
|---|---|---|
| 1. Unit tests | next to the sources (`*_test.go`, `#[cfg(test)]`) | nothing — no KVM, no root |
| 2. E2E integration | [`e2e/`](https://github.com/ChaoyiHuang/sandswap/tree/main/e2e) | root + KVM for full-stack scripts; the etcd-layer scripts need only etcd |
| 3. Deploy verification | [`deploy/`](https://github.com/ChaoyiHuang/sandswap/tree/main/deploy) | a deployed system |

The layers build on each other: unit suites gate every build, the e2e
battery gates every change, and the deploy drills gate real rollouts.

Every script in layers 2 and 3 is built on one shared framework and is
verified by one matrix runner — see [Script framework](script-framework.md).
Both matrices — deployment fixtures included — are driven by one
repository-root command, [`run-round.sh`](#4-the-full-verification-round).

## 1. Unit tests

Unit tests live next to the sources and run per module:

- **Go** — `*_test.go` files throughout `gateway/`, `sandlot/`, `boxout/`,
  `dns/` (the sandns sources), `sandctl/`, and `common/`. Run per module:

  ```bash
  cd gateway && go test ./...     # likewise for sandlot/, boxout/, dns/, sandctl/, common/
  ```

  The resilience-relevant gateway subsets (lease, pool, handler) are also
  run in strict mode (with the race detector, parsed pass-count floors) by
  `e2e/resilience.sh` — see the [E2E catalog](e2e.md).

- **warden (Rust)** — inline `#[cfg(test)]` modules in the warden sources;
  run with `cargo test` inside `warden/`. The CI suite is
  unprivileged-safe; the chroot/mount/seccomp tests are `#[ignore]`-gated
  and run only as root (`cargo test -- --ignored`). The warden **build**
  runs this suite first (`WARDEN_SKIP_TESTS=1` opts out for scratch
  builds), so a broken Rust suite fails the build; `e2e/warden-unit.sh`
  runs the same suites as a suite-visible step in the e2e runner.

- **sandvmm (Rust)** — unit tests across the `vmm/` crates (the
  cloud-hypervisor fork); run with `cargo test` in the `vmm/` workspace.

Unit tests deliberately stop at module boundaries — cross-process
behavior (gateway → sandlot → sandvmm → warden), real KVM, real etcd,
and failure injection are the e2e layer's job.

## 2. E2E integration tests

Every script under `e2e/` is **self-contained**: it cleans the
environment, deploys its own binaries and configs, runs, and tears
everything down — no script depends on another having run first, and any
script can be run independently. Properties enforced via the shared
`e2e/common.sh` helper (55 `tc_*` helpers):

- **Strict exit-code semantics** — exit 0 only if everything passed, 1 on
  any failure. Missing KVM, missing build artifacts, or a non-root
  invocation of a root script fail **loudly** — a broken environment shows
  up as FAILED, never as a silent skip that CI would read as green.
- **Freshness gating** — each script verifies artifact freshness
  (`tc_check_freshness`): stale `output/` artifacts are rebuilt
  automatically; with `AUTO_REBUILD=0` the script aborts instead, so you
  can never accidentally test old binaries. The matrix runner establishes
  freshness ONCE for the whole pass before any verdict is recorded; rows
  then skip their per-row gate so no row can re-stamp the shared
  artifacts mid-round.
- **Serial only** — full-stack scripts share ports (3001/3100/9998), the
  deploy directory, the vhost-vsock CID space, and the etcd ports; two
  concurrent runs are undefined. `run-matrix.sh` exists partly to make that
  rule executable.
- **Scoped process assertions** — identify processes by recorded PID
  (`tc_start_*` `$!`), by this run's own VM records (`tc_run_vm_pids`,
  re-adopt-aware), or by subtree (`tc_descendant_pids`). Never
  `pgrep`/`ps` name matches: they cannot distinguish this run's processes
  from a leaked previous-run process or an unrelated same-name service.
- **External dependencies skip loudly** — no LLM key → the LLM scripts
  SKIP with a visible line; no docker daemon → the Keycloak script SKIPs.
  A silent green no-op would be a false pass.

The serial runner:

```bash
sudo bash run-round.sh                      # whole round: e2e then deploy (daemonized)
sudo bash e2e/run-matrix.sh                 # one tree: e2e (LLM rows need an API key)
sudo bash e2e/run-matrix.sh --fast          # skip benchmarks and heavy rows
sudo bash e2e/run-matrix.sh --only e2e/smoke.sh
sudo bash e2e/run-matrix.sh --list
```

It runs each row in turn (bounded by a per-row timeout), sweeps leftover
processes / nftables rules / TAP devices / etcd between them, records a
verdict per script in a resumable checkpoint (reuse is keyed on the
script's closure and the build-artifact identity), prints a summary
table, and exits non-zero on any FAIL or NOT-RUN row. Rows are classified
in the runner's SPEC; LLM/docker gating is a runner rule and `--fast`
skips the bench rows. The drills that verify an operator-DEPLOYED stack
instead of deploying their own are not suite scripts — they live in
`deploy/baremetal/verify-*.sh` (layer 3 above). The battery rows all run
under an isolated battery root (`SANDSWAP_E2E_ROOT`, default
`/var/lib/sandswap-e2e`) — a row's environment sweep can never touch a
production deployment under `/var/lib/sandswap`.

Prerequisites for full-stack scripts: **root** (deploy directory, host
networking, vsockguard, process cleanup), `/dev/kvm` and
`/dev/vhost-vsock` (usually `modprobe vhost_vsock`), and a built
`output/` — see [Building](../building/index.md). Defaults can be
overridden by setting variables *before* the script runs, e.g.
`POOL_SIZE=2 sudo bash e2e/smoke.sh`.

The full per-script catalog — what each of the 64 suite scripts
validates, how to run it, and its prerequisites — is the
[E2E catalog](e2e.md).

## 3. Deploy verification

Deploying and verifying on real hosts is its own section — see
[Deployment](../deployment/index.md). The shape there mirrors this one:
each `deploy/` script has a matching verification step —

- **Bare metal**: `deploy/baremetal/deploy-*.sh` install the systemd
  stack per topology; the deployed-stack verifiers are `verify-binpack.sh`
  (DNS bin-pack concentration), `verify-failover.sh` (sandlot
  cross-gateway failover), `verify-eino.sh` (a real multi-agent workload),
  `verify-cert-rotation.sh` (whole-PKI rotation with fail-closed
  re-convergence), `verify-etcd-fence.sh` (the etcd-partition self-fence,
  live), and `verify-negative-path.sh` (each broken plane answers a named
  retryable refusal, never a silent success or a bare 500);
  `sandswap-ops.sh` (operations CLI) and `rotate-volume-seed.sh`
  (seed-rotation chain) also operate a deployed stack, and
  `security/verify-host-security.sh` sweeps every host invariant (also
  the pre-deploy checklist in the Deployment section).
- **Kubernetes**: `deploy/k8s/deploy-k8s-*.sh` (embedded / boxout /
  egress-enabler modes) + `verify-k8s.sh` (auto-detects the deployed
  mode and runs the full drill).
- **Operational drills against a live deployment** — certificate
  rotation, volume-seed rotation, rollback — live with their operations
  pages rather than here.

Those scripts verify deployment-specific concerns (systemd units, DNS
bin-packing, k8s DaemonSets) that the self-contained e2e layer
deliberately does not touch.

## 4. The full verification round

Both trees — the e2e battery and the deploy battery with its deployment
fixtures — are driven by one command from the repository root:

```bash
sudo bash run-round.sh            # e2e tree, then deploy tree (background)
sudo bash run-round.sh --fast     # e2e benchmark rows skipped
```

The round deploys and verifies everything the batteries cover: each e2e
row stands up its own stack, the deploy tree installs the real systemd
topologies, runs the deployed-stack verifiers against them, and leaves
the host clean whether a row passes or fails. It must run as root (KVM +
host preparation).

Properties the round guarantees:

- **Self-daemonizing** — the driver re-execs itself under `nohup`, so a
  closed terminal (or a timeout around the foreground shell) cannot kill
  the round mid-row. `ROUND_FOREGROUND=1` keeps it attached for
  interactive debugging.
- **Disk logs** — one driver log plus one log per tree under
  `/var/tmp/sandswap-round/<UTC stamp>/` (never `/tmp`: a tmpfs reboot
  must not clear it). The launcher prints the exact paths.
- **Resumable** — the per-tree checkpoints persist under
  `/var/tmp/r3-matrix/`. Rerunning the same command after an
  interruption or a reboot reuses every row whose closure and
  build-artifact identity are unchanged and re-executes FAIL and NOT-RUN
  rows; no row is ever silently re-greened.
- **One exit code** — each tree's matrix gate (any FAIL or NOT-RUN row)
  decides its status, and the round fails if either tree fails. The
  driver log ends with a triage summary: the FAIL rows with their
  reasons.
- **Environment gates, not false greens** — rows needing an LLM key or a
  docker daemon SKIP with the recorded reason when the dependency is
  absent. To exercise the real-agent rows, pass the key through sudo:
  `sudo env DEEPSEEK_API_KEY=sk-... bash run-round.sh` (plain `sudo`
  strips the environment and the rows record `needs-llm-key` SKIPs).

Variables honored: `ROUND_TREES` (default `e2e deploy`), `ROUND_FOREGROUND`,
`ROUND_LOG_DIR`, plus the tree runners' `SANDSWAP_E2E_ROOT` and
`MATRIX_STATE_DIR`. Row classification, gates, and per-script behavior:
[E2E catalog](e2e.md) and [Script framework](script-framework.md).
