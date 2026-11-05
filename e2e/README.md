# Sandswap E2E Tests

> ## ⚠ Developer/test-only — NOT for production
>
> Everything under `e2e/` is a **developer test harness**, not a production
> installer and not a production test suite. The scripts are deliberately
> destructive and assume a disposable host/cluster:
>
> - they deploy and tear down gateways, sandlots and microVMs;
> - they create/delete test agents and SandFS records, and reset etcd state;
> - they start gateways with `-allow-anonymous-human`;
> - they change host networking and device state (`/dev/net/tun` modes,
>   firewall/nft rules, TAPs) and may remove `/run/sandswap` and test volumes;
> - they use a loopback NFS test export and other test-only shortcuts.
>
> **Never run them against a production host or cluster, and never copy their
> settings into production.** For production use
> [Deployment](../docs/deployment/index.md) and
> [Operations](../docs/operations/index.md); storage isolation is covered in
> [Storage §4](../docs/operations/storage.md#4-production-storage-isolation-must--the-storage-service-is-not-a-tenant-network).
> The catalog and per-script details are in
> [docs/testing/index.md](../docs/testing/index.md).

Self-contained end-to-end test scripts: each one deploys, starts, tests, and
cleans up its own stack — any script can be run independently.

**Exit-code semantics**: every script exits 1 on failure and 0 only when all
assertions pass. Missing KVM, missing build artifacts, or non-root fail
**loudly** (no silent skips) — a broken environment must show up as FAILED,
not read green in CI.

## Prerequisites

- root (deployment to `/var/lib/sandswap`, host networking, process cleanup)
- `/dev/kvm` and `/dev/vhost-vsock`
- built artifacts in `output/` (`bash build/build.sh all`); the
  freshness pre-check auto-rebuilds stale artifacts (`AUTO_REBUILD=0` to
  forbid)

Etcd-based protocol tests (ownership, DNS staleness, load-shed, …) need no
KVM and run without root; `tc_ensure_etcd` resolves/downloads etcd for them.
`oidc-keycloak.sh` additionally needs a running docker daemon (it spins up
Keycloak in a container); without docker — or when the image cannot be
pulled — it SKIPs loudly with exit 0, like the LLM-key-dependent scripts.

The suite's setup helper (`tc_create_agent_and_sandfs`) is a consumer of the
human API: before changing any `/human/*` route, check the compatibility
contract in [human-api.md](../docs/reference/human-api.md) (four rules —
add-only routes, claims-gated owner filtering, append-only response shapes,
opt-in auth).

## Running

```bash
sudo bash e2e/smoke.sh                # any single script (self-cleaning)
sudo bash e2e/run-matrix.sh           # full e2e matrix (gate; resumable; cleans up)
sudo bash e2e/run-matrix.sh --fast    # skip benchmarks + heavy rows
sudo bash e2e/run-matrix.sh --only e2e/smoke.sh
sudo bash e2e/run-matrix.sh --list
sudo bash run-round.sh                # whole round: e2e then deploy (daemonized)
```

Scripts must run **serially**: they share ports 3001/3100/9998, the
deployment directory, the vhost-vsock CID space, and etcd ports — parallel
runs are undefined. The runner also sweeps residual processes/nft/TAP/etcd
between rows and bounds every row with a timeout.

## Shared library `common.sh`

All scripts `source "$ROOT/e2e/common.sh"` — colored logging, assertions
gated by a per-script `FAIL_COUNT`, gateway HTTP helpers, `/stats` parsing,
etcd lifecycle, preflight checks, and deploy/service/config helpers.
Override defaults via env vars set before sourcing (e.g. `POOL_SIZE=2`).

## Catalog

The per-script catalog — what each script covers, its parameters, expected
duration, and the coverage matrix — lives in
[docs/testing/index.md](../docs/testing/index.md).
