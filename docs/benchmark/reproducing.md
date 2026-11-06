---
title: Reproducing the Benchmarks
nav_order: 5
parent: Benchmark
---

# Reproducing the Benchmarks

The numbers in the four reports — [bare-metal latency](baremetal.md),
[nested-virt latency](nested-virt.md),
[bare-metal microVM reuse capacity](baremetal-load.md) and
[nested-virt microVM reuse capacity](nested-virt-load.md) — come from self-contained
scripts in [`e2e/`](https://github.com/ChaoyiHuang/sandswap/tree/main/e2e).
Each one deploys its own throwaway stack (binaries, certs, volumes, logs —
everything under `$DEPLOY_DIR`, default `/var/lib/sandswap`), runs, and
removes all of it on exit, so no prior deployment is needed.

There are two ways to get a runnable setup:

| | Path 1 — developer | Path 2 — prebuilt release |
|---|---|---|
| Audience | contributors with a full toolchain | anyone with a KVM host |
| Source of the binaries | built locally by `build.sh all` | shipped in the release tarball |
| Toolchain needed | Go, Rust, kernel build deps (~30 min first build) | **none** |
| Scripts | `e2e/` in the clone | bundled in the release tarball (same tag as the binaries) |

Both paths run the same scripts against the same on-disk layout — a
directory holding `output/` — so the commands after setup are identical.

## 1. Prerequisites (both paths)

- x86_64 bare-metal host (nested-virt works but is ~3× slower —
  see the [nested-virt report](nested-virt.md) for what to expect)
- KVM: `/dev/kvm` and `/dev/vhost-vsock` readable
  (`modprobe vhost_vsock` if the latter is missing), running as root
- `curl`, `python3`, `openssl` (mTLS cert generation)
- `iproute2` (bridge/TAP setup), `util-linux` (`setpriv`), `kmod`
  (`modprobe`); `nftables` for guest NAT and forward isolation — installed
  automatically by the scripts via the system package manager (apt/dnf/yum/
  zypper/pacman) when missing; without it the run is refused (fail-closed)
- Only for the `distributed` topology: etcd is vendored in the release and
  downloaded automatically in a dev tree — nothing to install
- Only for `mcp` mode: an LLM API key (`DEEPSEEK_API_KEY` /
  `OPENAI_API_KEY` / `GOOGLE_API_KEY`). The default `http` mode needs none.

## 2. Path 1 — developer: clone, build, benchmark

```bash
git clone <repo-url>                         # clone this repository
cd sandswap
bash build/install-deps.sh                   # one-shot dependency installer (apt + dnf/yum)
bash build/build.sh all                      # Go + Rust + kernel + initramfs (~30 min first build)
```

The build ends with a freshness check; every e2e script re-runs it
(`tc_check_freshness`) and auto-rebuilds stale artifacts, so the binaries you
benchmark always match the sources you cloned.

Then run the benchmarks — see [4](#4-latency-benchmarks) below.

## 3. Path 2 — use the release package

Releases ship a repo-shaped tree with prebuilt static binaries, the guest
kernel, initramfs, templates, vendored etcd — **and the benchmark scripts
bundled at the same tag as the binaries**, so there is nothing else to
download and no version-skew risk between scripts and binaries.

Resolve the latest
tag from the `releases/latest` redirect, then `curl` the assets:

```bash
TAG=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    https://github.com/ChaoyiHuang/sandswap/releases/latest | awk -F/ '{print $NF}')
curl -fLO "https://github.com/ChaoyiHuang/sandswap/releases/download/${TAG}/SHA256SUMS"
curl -fLO "https://github.com/ChaoyiHuang/sandswap/releases/download/${TAG}/sandswap-${TAG}-linux-amd64.tar.gz"
sha256sum -c --ignore-missing SHA256SUMS      # verify the tarball
tar xzf "sandswap-${TAG}-linux-amd64.tar.gz" && cd "sandswap-${TAG}-linux-amd64"
```

Or pin an explicit version instead of following latest:

```bash
TAG=<release-tag>
curl -fLO "https://github.com/ChaoyiHuang/sandswap/releases/download/${TAG}/sandswap-${TAG}-linux-amd64.tar.gz"
```

Extracting gives you `output/` (prebuilt artifacts) and `e2e/` (the
benchmark scripts) side by side. Scripts inside a package detect the
`.release-stamp` marker and skip the source-freshness gate — there are no
sources to compare against.

Note: match the tag — a release tarball is self-consistent (scripts and
binaries from the same tag); prefer it over mixing scripts from `main`
with release binaries, as both can drift between tags.

## 4. Latency benchmarks

Each script takes measurements from production surfaces (the gateway's own
per-stage metrics, the `X-Sandbox-Lease` header, `/stats` `unmount_stats`) —
no log scraping, no extra instrumentation.

```bash
# AI agent latency (http mode, single-node topology — the bare-metal report's
# main tables): 1 warmup + 100 warm execs + 100 cold mounts (50 rounds)
sudo bash e2e/latency-benchmark-aiagent.sh http single
# distributed topology (etcd + exec/human gateways)
sudo bash e2e/latency-benchmark-aiagent.sh http distributed
# mcp mode — additionally times the LLM and MCP tool round trips
DEEPSEEK_API_KEY=sk-... sudo bash e2e/latency-benchmark-aiagent.sh mcp single
DEEPSEEK_API_KEY=sk-... sudo bash e2e/latency-benchmark-aiagent.sh mcp distributed
# per-sample detail (the report appendix tables)
BENCH_VERBOSE=1 sudo bash e2e/latency-benchmark-aiagent.sh http single

# Unmount full-path latency (baseline + 16 MiB cache + 16 MiB dirty workloads)
sudo bash e2e/latency-benchmark-unmount.sh all
# single scenario, or a cache-size curve via the workload file size
sudo bash e2e/latency-benchmark-unmount.sh cache16m
FILE_MB=128 sudo bash e2e/latency-benchmark-unmount.sh cache16m
```

## 5. Load benchmarks (microVM reuse capacity)

Two steps: first measure the baseline (one microVM, no background load),
then run the offered-agent levels with its four P95s.

```bash
# step 1: the baseline (one microVM, no background load): gateway E2E and
# client P95, warm and cold
sudo bash e2e/latency-benchmark-aiagent.sh http distributed

# step 2: the realistic AI agent model. Offered-agent levels, one flat volume
# per simulated agent; the benchmark reserves whole cores for the host stack
# (auto-sized, or named per role with PIN_STACK_LAYOUT) and gives the rest to
# the microVM pool. Pass the baseline's four P95s so the latency tiers are
# measured.
PIN_MODE=1 PIN_RESERVE_CORES=auto PIN_SLICE_CPUS=2 POOL_SIZE=<remaining cores> \
LOADTEST_AGENT_LEVELS="<agent levels>" LOADTEST_LATENCY_TIERS="1.0 2.0" \
SKIP_ESTIMATE_BENCH=1 \
WARM_GW_P95_MS=<warm-gw-p95> COLD_GW_P95_MS=<cold-gw-p95> \
WARM_CLIENT_P95_MS=<warm-client-p95> COLD_CLIENT_P95_MS=<cold-client-p95> \
  sudo -E bash e2e/latency-benchmark-load.sh

# optional capability tests:
# ideal — ideal paced-lane test: one lane per microVM, no between-turn think
#         gap (the collision-free ceiling)
# shaped — traffic-shaped test: a full agent population queued per lane, one
#          in-flight request per VM (the realistic version of that ceiling)
POOL_SIZE=2 LOADTEST_WORKLOAD=ideal LOADTEST_LANES=2 \
  LOADTEST_TURN_PERIODS_MS="14 16 18 20 22 24" \
  SKIP_ESTIMATE_BENCH=1 \
  WARM_GW_P95_MS=<...> COLD_GW_P95_MS=<...> \
  WARM_CLIENT_P95_MS=<...> COLD_CLIENT_P95_MS=<...> \
  sudo -E bash e2e/latency-benchmark-load.sh
POOL_SIZE=2 LOADTEST_WORKLOAD=shaped LOADTEST_LANES=2 \
  LOADTEST_TURN_PERIODS_MS="14 16 18 20 24 28" LOADTEST_SHAPED_HOLD_MS=auto \
  SKIP_ESTIMATE_BENCH=1 \
  WARM_GW_P95_MS=<...> COLD_GW_P95_MS=<...> \
  WARM_CLIENT_P95_MS=<...> COLD_CLIENT_P95_MS=<...> \
  sudo -E bash e2e/latency-benchmark-load.sh
```

The two microVM reuse capacity reports ran this same script on their own
hosts; the exact command and environment behind every table are in each
report's Reproduction section and its `*-load-raw/MANIFEST.md`:

| | [bare-metal](baremetal-load.md#9-reproduction) | [nested-virt](nested-virt-load.md#9-reproduction) |
|---|---|---|
| Pinning | `PIN_MODE=1`: the host stack roles on 12 reserved whole physical cores named by `PIN_STACK_LAYOUT`, the microVM pool on the remaining 36 | `PIN_MODE=0` — the L1 vCPUs are already outer-scheduled |
| Pool / mapping | 32 VMs with `PIN_SLICE_CPUS=2` (the physical-core mapping, the recommendation) and 64 with `PIN_SLICE_CPUS=1` (the logical-core mapping, two VMs per core, comparison only) | 2 VMs |
| Latency tiers | `1.05 1.5 2.0` | `1.0 2.0` (the default) |
| Window | 20 s measured / 10 s warm-up; the first offered level is excluded | 20 s / 5 s |

**Bare-metal runs auto-pin** (`e2e/pin.sh`; `PIN_MODE=auto` resolves to 1 on
bare metal, 0 under a hypervisor, `PIN_MODE=0` forces it off): the host stack
on whole reserved physical cores and every microVM on its own whole physical
core — a 1-vCPU VM uses one thread and its vhost/virtiofs threads use the
other, so no VM spans two physical cores — with `numactl --membind` per
slice. `PIN_PLAN=1` prints the computed core partition (reserve, layout,
pool, slices) and exits without deploying, for sizing your own host.

Useful environment knobs (all optional):

| Knob | Default | Meaning |
|------|---------|---------|
| `WARM_N` / `COLD_N` | 100 / 50 | warm samples / cold rounds (each round = 2 cold samples, so 100 cold) |
| `SWITCH_GAP_MS` | 300 | gap between agent switches (must exceed the sticky window) |
| `POOL_SIZE` | 4 | sandlot VM pool size |
| `VM_MEMORY_MB` | 256 | microVM memory |
| `PIN_MODE` | `auto` | CPU/NUMA pinning: bare metal on, hypervisor off; `0`/`1` force |
| `PIN_STACK_CORES` | 8 | whole cores reserved for the host stack (aiagent/unmount) |
| `PIN_SLICE_CPUS` | 2 | CPUs per microVM slice (the load benchmark derives it from `BENCH_VCPUS`); 2 = one whole physical core (both SMT threads), 1 = one logical core (two VMs per core, comparison only) |
| `PIN_RESERVE_CORES` | 0 | load benchmark: whole cores reserved for loadgen/gateway/sandlot (`auto` = compute) |
| `PIN_STACK_LAYOUT` | — | load benchmark: explicit `role:cpus` sets for the reserved cores, e.g. `"loadgen:0-3;gateway:4-7;sandlot:8-11"`; gateway also carries the human gateway + etcd, sandlot the provision instance |
| `PIN_VERIFY_EACH_LEVEL` | 1 | load benchmark: re-verify the VM-to-slice map after every level; the report runs set 0 |
| `PIN_PLAN` | 0 | print the computed core partition (reserve, layout, pool, slices) and exit without deploying |
| `LOADTEST_AGENT_LEVELS` | `10 20 40 80` | load: offered agent counts (one flat volume per agent); capacity runs set the report's larger lists |
| `LOADTEST_STICKY_MS` | 1 | load: gateway sticky window; the follow-ups are sent immediately and must land inside it |
| `LOADTEST_THINK_MIN_MS` / `LOADTEST_THINK_MAX_MS` | 900 / 1500 | per-turn LLM think time |
| `LOADTEST_REQUESTS_PER_TURN` | `1:40,2:35,3:25` | requests per turn: `N` for a fixed count (`1` = every turn is one cold request), or `size:weight` pairs |
| `LOADTEST_BUSY_RETRIES` / `LOADTEST_BUSY_RETRY_BACKOFF_MS` | 50 / 10 | additional attempts after `503 NO_AVAILABLE_SANDBOX` and the full-jitter backoff base (`0` = surface the refusal) |
| `LOADTEST_INTRA_TURN_GAP_MS` | 0 | spacing between requests inside a turn (0 = immediate, warm under the 1 ms sticky) |
| `LOADTEST_MAX_INFLIGHT` | 1024 | client-side in-flight request cap (not a server limit) |
| `LOADTEST_LATENCY_TIERS` | `1.0 2.0` | load: latency budgets as multiples of the no-load baseline P95, for BOTH classes (warm and cold) and both surfaces (gateway E2E and client); the per-report tiers are in the contrast above |
| `LOADTEST_WORKLOAD` | `agents` | `agents` = the realistic AI agent model (closed loop); `ideal` = the ideal paced-lane test, one lane per microVM (capability test); `shaped` = the traffic-shaped test, a full agent population queued per lane, one in-flight request per VM |
| `LOADTEST_LANES` / `LOADTEST_TURN_PERIODS_MS` | `POOL_SIZE` / `20 22 24 26 28 30 35` | ideal/shaped: lane count (must equal the pool) and the turn-period sweep. The knee is the highest completed cold rate among periods that pass the test's gate — ideal: zero failed requests and busy refusals within the 0.5 % noise tolerance; shaped: zero failed requests and the cold (for mixed turns also warm) gateway and client P95 inside the last tier |
| `LOADTEST_SHAPED_AGENTS_PER_LANE` / `LOADTEST_SHAPED_HOLD_MS` | `auto` / `auto` | shaped: agents aggregated per lane (auto = rate x mean think + margin) and the VM-slot hold after the sticky window — `auto` measures this stack's unmount P95 (cold execs, then the `/stats` unmount recent P95) and uses `ceil(P95)+2ms` clamped [1,100]; bare metal calibrates several ms lower than nested |
| `LOADTEST_RECYCLE_POLICY` | `capacity` | `capacity` disables all lifetime recycle caps + memory recycle; `shipped` uses the product defaults (300 distinct agents / 10000 mounts / 100000 uses) |
| `LOADTEST_MAX_USES` / `LOADTEST_MAX_MOUNTS` / `LOADTEST_MAX_DISTINCT_AGENTS` | policy | explicit lifetime-cap overrides |
| `LOADTEST_DURATION_SEC` / `LOADTEST_WARMUP_SEC` | 30 / 10 | measurement window / excluded warm-up |
| `SKIP_ESTIMATE_BENCH` / `WARM_GW_P95_MS` / `COLD_GW_P95_MS` / `WARM_CLIENT_P95_MS` / `COLD_CLIENT_P95_MS` | 0 / — | skip the baseline run and supply its four no-load P95 values |
| `LOADTEST_AGENT_CREATE_CONCURRENCY` / `LOADTEST_PROV_MAX_OPS` | 32 / 16 | parallel agent creation / prov-instance concurrency |
| `SANDLOT_EXTRA_FLAGS` | — | extra sandlot flags, e.g. `-warden-log debug` for warden-side timing |
| `KEEP_LOGS` | 0 | keep the component and guest logs in `$LOG_DIR` after the self-cleaning exit (post-mortem) |

Further details per script: header comments in `e2e/`, plus the Reproduction
section of each report for the exact command set behind each table.

## 6. Reading your own numbers

- The latency scripts print warm/cold P50/P95 per mode/topology, and the
  unmount script prints per-scenario gateway/sandlot/warden layer breakdowns.
- The load benchmark prints, per offered-agent level, the completed cold
  reuses/s, the per-microVM rate, the warm share, the retry pressure and the
  gateway E2E / client P95 of both classes; the capacity section selects the
  highest level with zero failed requests, within each latency tier. A
  `503 NO_AVAILABLE_SANDBOX` is retried like a real agent, so it appears as
  retry pressure, not a failed turn.
- `LOADTEST_WORKLOAD=ideal` is the ideal paced-lane test, not a business
  model: one lane per microVM, each issuing a turn every period with no
  between-turn think gap. It sweeps the turn period and reports the highest
  cold rate with zero failed requests and busy refusals within the 0.5 %
  noise tolerance — the collision-free ceiling with the VMs continuously fed.
- `LOADTEST_WORKLOAD=shaped` is the realistic version of that ceiling: every
  lane aggregates a full AI agent population (own sandfs, own think time)
  whose turns queue at the lane; the lane serves one request at a time and
  holds the VM slot for sticky + `LOADTEST_SHAPED_HOLD_MS` (the unmount
  budget) between turns. Busy retries are part of the shaper's flow control;
  its knee is zero failed requests with the cold (for mixed turns also warm)
  gateway and client P95 inside the last latency tier. Compare all three —
  the `agents` no-failure maximum, `shaped`, `ideal` — to see how much of the
  ideal reuse capability each model recovers.
- The first offered level of every realistic run is a warm-up and is excluded
  from the tables: on bare metal the host kernel is still writing back the
  per-agent volume creations (multi-GB at thousands of agents), which stalls
  guest I/O (see the
  [bare-metal capacity report](baremetal-load.md#27-bare-metal-specifics-what-a-nested-virt-run-cannot-reproduce)).
- On a nested-virt host the aiagent script labels its output
  `[NESTED-VIRT]`; treat such runs as comparative only.
- Numbers are only comparable within one tag and one hardware class —
  cross-tag or cross-host comparisons should be re-measured with the
  scripts from the newer tag.
