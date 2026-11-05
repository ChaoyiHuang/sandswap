---
title: Benchmark Report — Bare Metal
nav_order: 1
parent: Benchmark
---

# Benchmark Report — Bare Metal

> Bare-metal KVM on a TencentOS Server 4 cloud bare-metal host, measured
> with the prebuilt release package; raw logs are in
> `baremetal-raw/` beside this report.
> All numbers are from real KVM microVMs (no mocks), read from the gateway's
> own ns-precision metrics in every `/agent/execute` response.
>
> Companions: [the nested-virtualization run](nested-virt.md)
> (same benchmarks inside a GCP VM, ~3-4x higher numbers with the measured
> explanation). The `exec` field is the warden-side
> mount+exec total on the cold path and spawn-to-wait on the warm path.

## 1. Executive summary

| Topology | Path | client P95 | gateway P95 | sandlot P95 | exec P95 |
|----------|------|-----------:|------------:|------------:|----------:|
| http single | Warm (sticky lease hit) | 0.997 | 0.880 | 0.758 | 0.663 |
| http single | Cold (mount_and_exec) | 2.128 | 1.993 | 1.884 | 1.696 |
| http distributed | Warm (sticky lease hit) | 1.045 | 0.891 | 0.761 | 0.668 |
| http distributed | Cold (mount_and_exec) | 2.324 | 2.194 | 2.066 | 1.782 |
| mcp single | Warm (sticky lease hit) | 1.311 | 0.947 | 0.820 | 0.733 |
| mcp single | Cold (mount_and_exec) | 2.328 | 2.093 | 1.969 | 1.743 |
| mcp distributed | Warm (sticky lease hit) | 1.341 | 0.958 | 0.821 | 0.731 |
| mcp distributed | Cold (mount_and_exec) | 2.494 | 2.086 | 1.935 | 1.740 |

All table values in ms — each cell is the P95, verbatim from the
per-topology result blocks in §3 (http) and §4 (mcp); n=100 warm / n=100
cold samples per run; no re-computation or rounding (min / P50 / max live in
the per-topology blocks and `baremetal-raw/`). `gateway` = the gateway E2E
metric. The `mcp` rows exclude the LLM-driven tool-call measurements (§4,
n=5, cold only). Every run in this report is **CPU/NUMA pinned** (§2):
the host stack (gateway, sandlot, benchmark client) runs on eight whole
physical cores (16-23 and their SMT siblings 64-71), and each microVM owns
one whole physical core (13/61, 14/62, 15/63) — vCPU and vhost/virtiofs
threads stay on that core, never spanning two physical cores.

- Warm gateway E2E P95 across topologies: 0.88 ms (http single), 0.89 ms
  (http distributed), 0.95 / 0.96 ms (mcp single/distributed) — all four
  topologies under 1 ms through the full gateway stack (gateway → sandlot →
  warden); sticky-lease reuse, no remount.
- Cold gateway E2E P95 across topologies: 1.99 ms (http single), 2.19 ms
  (http distributed), 2.09 / 2.09 ms (mcp single/distributed) — within
  ~0.2 ms of each other: etcd only records ownership / placement (zero
  writes per execution cycle in steady state); the exec path authenticates
  from the gateway's local in-memory snapshot and never touches etcd, and
  the cold-mount lifecycle gate is served from the local watch snapshot
  (§3.3), so the distributed topology pays no measurable etcd toll on the
  normal active cold mount.
- Client round-trip figures are for reference only: in a real deployment the
  client and sandswap may not be in the same data center, so client-perceived
  latency varies with the actual network path; the gateway-side numbers are
  the portion attributable to sandswap itself.
- The pinned baseline keeps the warm gateway P95 in a 0.88–0.96 ms band
  across the four topologies; CPU/NUMA placement is fixed by the benchmark
  harness (§2), so the numbers reflect the sandbox path rather than the host
  scheduler.

## 2. Test environment

| Item | Value |
|------|-------|
| Host | Inspur SA5212M5, `systemd-detect-virt=none`, no cpuinfo `hypervisor` flag |
| Chassis / BIOS | Inspur SA5212M5, BIOS 4.3.19 |
| CPU | Intel Xeon Platinum 8255C @ 2.50 GHz, 2 sockets, 96 threads (`acpi-cpufreq`, `intel_pstate=disable`, governor `performance`, `intel_idle.max_cstate=1`, `iommu=pt`) |
| RAM | 384 GiB (DIMM total; 375.8 GiB `MemTotal`), 2 NUMA nodes |
| NIC / disk | 2× Broadcom BCM58802 50GbE (bnxt_en); 2× Intel SSDPE2KX040T8 3.5 TB NVMe |
| Host kernel | 6.6.117-45.14.2.tl4.x86_64 (TencentOS Server 4) |
| Guest kernel | **7.2.8** minimized cloud-hypervisor tree (`vmlinux` ELF+PVH; `CONFIG_IPV6=y`, `CONFIG_INET_DIAG_DESTROY=y`, `INIT_ON_ALLOC_DEFAULT_ON=y`, runtime `init_on_free=0`), `clocksource=kvm-clock`, hrtimers ON |
| Binaries | prebuilt release package — [reproducing.md](reproducing.md) Path 2, scripts bundled with the binaries; cloud-vendor monitoring agents (barad/stargate) stopped for the run |
| CPU / NUMA pinning | **On (bare metal)**: host stack (gateway, sandlot, benchmark client) on eight whole physical cores — 16-23 and their SMT siblings 64-71; each microVM on **one whole physical core** (13/61, 14/62, 15/63 — both SMT threads) with `numactl --membind=0`; driven by `e2e/pin.sh` (`PIN_MODE=auto`; nested virt is not pinned, `PIN_MODE=0` disables) |
| microVM | **1 vCPU**, 256 MiB, 5 MiB initramfs, pool of 3 pre-warmed CLEAN VMs |
| Lease | sticky, 100 ms window |
| VM recycle | `max_uses=100000` — no VM replacement occurs inside a benchmark window |
| Topologies | single-node (combined gateway) and distributed (etcd + exec gateway + human gateway) |
| Benchmarks | `e2e/latency-benchmark-aiagent.sh http {single,distributed}` and `mcp {single,distributed}`, `e2e/latency-benchmark-unmount.sh all` (script defaults WARM_N=100 / COLD_N=50 → n=100 warm / n=100 cold samples, `BENCH_VERBOSE=1`; per-sample detail in `baremetal-raw/`) |
| Warden logging | default info — every per-op hot-path line lives at debug (`sandlot -warden-log debug` to enable for profiling) |

## 3. HTTP Command-execution path results

All values in ms, from the gateway's `gateway_duration_ns` /
`sandlot_duration_ns` / `exec_duration_ns` plus the client-observed round
trip; P50/P95 over n=100 (warm) and n=100 (cold). Quality gate green, zero
503s, `leaseHit` classification from `X-Sandbox-Lease`.

### 3.1 Single-node topology (`http single`)

```
Warm — sticky lease reuse (leaseHit=true, n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        0.884     0.922     0.997     1.206
  gateway E2E              0.805     0.825     0.880     1.009
  sandlot                  0.710     0.724     0.758     0.841
  exec                     0.624     0.637     0.663     0.714

Switch — cross-agent cold mount_and_exec (leaseHit=false, n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        1.920     2.009     2.128     2.210
  gateway E2E              1.821     1.900     1.993     2.100
  sandlot                  1.711     1.786     1.884     1.970
  exec                     1.513     1.602     1.696     1.770
```

### 3.2 Distributed topology (etcd + exec gateway + human gateway, `http distributed`)

```
Warm — sticky lease reuse (leaseHit=true, n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        0.896     0.946     1.045     1.174
  gateway E2E              0.814     0.848     0.891     0.999
  sandlot                  0.720     0.737     0.761     0.868
  exec                     0.633     0.647     0.668     0.718

Switch — cross-agent cold mount_and_exec (leaseHit=false, n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        2.033     2.111     2.324     3.756
  gateway E2E              1.926     1.985     2.194     3.626
  sandlot                  1.798     1.854     2.066     2.645
  exec                     1.606     1.661     1.782     2.376
```

(The cold maxima come from a couple of outlier samples — whole-request
stalls spread across all layers; the P95 rows are unaffected.)

### 3.3 Layer decomposition

Single-node (P50 / P95):

| Segment | Warm | Cold | What it is |
|---------|-----:|-------:|------------|
| client − gateway | 0.09 / 0.13 | 0.11 / 0.13 | HTTP/client stack |
| gateway − sandlot | 0.10 / 0.14 | 0.11 / 0.14 | auth, lease, pool, gRPC |
| sandlot − exec | 0.09 / 0.10 | 0.19 / 0.21 | sandlot proc + set-fs + vsock (cold only) |
| exec (warden) | 0.64 / 0.66 | 1.60 / 1.69 | virtio-fs mount + fork+execve inside the guest |

Distributed (P50 / P95):

| Segment | Warm | Cold | What it is |
|---------|-----:|-------:|------------|
| client − gateway | 0.10 / 0.13 | 0.12 / 0.14 | HTTP/client stack |
| gateway − sandlot | 0.11 / 0.14 | 0.13 / 0.16 | auth, lease, pool, gRPC (+ cold lifecycle/ownership checks) |
| sandlot − exec | 0.09 / 0.10 | 0.20 / 0.22 | sandlot proc + set-fs + vsock (cold only) |
| exec (warden) | 0.65 / 0.67 | 1.66 / 1.78 | virtio-fs mount + fork+execve inside the guest |

(Segment values are the P50/P95 of the per-sample differences between
adjacent layers; the exec row is the warden's own `exec_duration_ns`.)
The distributed topology's **warm** exec path never touches etcd — auth
resolves from the gateway's local in-memory identity snapshot, and etcd only
records ownership / placement — so warm is within noise of single-node. The
**cold** path's lifecycle gate is snapshot-first: `recheckLifecycleGate`
reads the local watch snapshot and only a non-active snapshot
(detaching/detached/deleting) performs the fresh quorum read (an attach may
have completed while the request waited); a transition that lands after the
check is handled by the record watcher's drain. A normal active cold mount
therefore performs only the local cache lookup — the cold
`gateway − sandlot` segment is 0.13 / 0.16 ms (P50/P95), within noise of
single-node (0.11 / 0.14) — and the ownership claim is a cache fast path
(in-memory after the first mount; etcd only on a cold cache miss or a
placement write). `BeginDispatch`/`EndDispatch` are in-memory; the warm path
skips the lifecycle recheck entirely, which is why its segment is unchanged.

## 4. MCP Command-execution path results

Same stack plus the MCP endpoint (`/mcp`, Streamable HTTP), driven by
`openai-sandswap` with DeepSeek (`deepseek-flash`). All values in ms, from
the same ns-precision metrics as §3 plus the client-observed round trip;
P50/P95 over n=100 (warm), n=100 (cold) and n=5 (LLM-driven). Quality gate
green, zero 503s. The LLM's own round trip (not on the tool path):
min / P50 / P95 = 778 / 968 / 1058 ms (single) and 626 / 871 / 1182 ms
(distributed) — three orders of magnitude above any sandbox segment.

### 4.1 Single-node topology (`mcp single`)

```
Warm — sticky lease reuse (n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        1.063     1.130     1.311     1.435
  gateway E2E              0.883     0.917     0.947     0.963
  sandlot                  0.787     0.802     0.820     0.829
  exec                     0.698     0.713     0.733     0.746

Switch — cross-agent cold mount_and_exec (n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        2.035     2.204     2.328     3.040
  gateway E2E              1.825     1.974     2.093     2.792
  sandlot                  1.700     1.848     1.969     2.649
  exec                     1.502     1.655     1.743     2.363

LLM-driven tool calls (cold, n=5) [ms]
  metric                     min       P50       P95       max
  client round-trip        2.189     2.358     6.989     6.989
  gateway E2E              1.945     2.085     6.539     6.539
  sandlot                  1.802     1.927     5.422     5.422
  exec                     1.605     1.717     2.462     2.462
```

### 4.2 Distributed topology (etcd + exec gateway + human gateway, `mcp distributed`)

```
Warm — sticky lease reuse (n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        1.063     1.131     1.341     1.529
  gateway E2E              0.889     0.917     0.958     1.075
  sandlot                  0.786     0.800     0.821     0.909
  exec                     0.697     0.710     0.731     0.737

Switch — cross-agent cold mount_and_exec (n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        2.089     2.184     2.494     3.066
  gateway E2E              1.866     1.945     2.086     2.814
  sandlot                  1.750     1.814     1.935     2.025
  exec                     1.563     1.621     1.740     1.770

LLM-driven tool calls (cold, n=5) [ms]
  metric                     min       P50       P95       max
  client round-trip        2.330     2.393     7.561     7.561
  gateway E2E              2.066     2.125     7.129     7.129
  sandlot                  1.914     1.959     5.491     5.491
  exec                     1.712     1.749     2.411     2.411
```

### 4.3 Layer decomposition

Single-node (P50 / P95):

| Segment | Warm | Cold | What it is |
|---------|-----:|-------:|------------|
| client − gateway | 0.21 / 0.36 | 0.23 / 0.31 | HTTP/client stack + Streamable-HTTP MCP endpoint |
| gateway − sandlot | 0.11 / 0.14 | 0.12 / 0.15 | auth, lease, pool, gRPC |
| sandlot − exec | 0.09 / 0.10 | 0.19 / 0.22 | sandlot proc + set-fs + vsock (cold only) |
| exec (warden) | 0.71 / 0.73 | 1.66 / 1.74 | virtio-fs mount + fork+execve inside the guest |

Distributed (P50 / P95):

| Segment | Warm | Cold | What it is |
|---------|-----:|-------:|------------|
| client − gateway | 0.21 / 0.40 | 0.24 / 0.41 | HTTP/client stack + Streamable-HTTP MCP endpoint |
| gateway − sandlot | 0.11 / 0.14 | 0.13 / 0.16 | auth, lease, pool, gRPC (+ cold lifecycle/ownership checks) |
| sandlot − exec | 0.09 / 0.10 | 0.19 / 0.21 | sandlot proc + set-fs + vsock (cold only) |
| exec (warden) | 0.71 / 0.73 | 1.62 / 1.74 | virtio-fs mount + fork+execve inside the guest |

(Segment values are the P50/P95 of the per-sample differences between
adjacent layers. The LLM-driven rows (n=5) are not decomposed: at n=5 the
P95 is the max, so a percentile difference has no statistical meaning.)

The `client − gateway` segment is larger than on the plain-HTTP path
(0.21–0.24 ms P50 vs 0.09–0.12): it carries the Streamable-HTTP MCP
endpoint on top of the agent API. `gateway − sandlot` and below are identical
machinery to §3.

## 5. Unmount / recycle path

`e2e/latency-benchmark-unmount.sh all` (ITER_N=20 per scenario, Ubuntu rootfs
with python3, data from `/stats unmount_stats`). Every iteration runs one
exec workload, then lets the sticky lease expire so the real lease-expiry
unmount fires — the warden's OP_UNMOUNT (cgroup.kill + rule-A process sweep +
teardown + `umount(2)` + `drop_caches` + the cross-tenant residue sweep +
the final-state gate) — and the three scenarios stack one cost layer at a
time:

- **baseline** — `echo ok` (shell): the fixed-cost floor of the unmount path
  itself (teardown, umounts, cache drop over an essentially clean state).
- **cache16m** — python3 writes 16 MB to `/workspace`, fsyncs, and reads it
  back: leaves a **clean** 16 MB page cache. Goal: measure how `drop_caches`
  scales with page-cache size, independent of writeback.
- **dirty16m** — python3 writes 16 MB with **no** fsync: pages stay dirty
  past exec return (dirty_background ≈ 25 MB at 256 MB VM RAM), so
  `umount(2)` itself pays the writeback over virtio-fs. Goal: measure
  writeback cost on top of the cache drop.

| Scenario | n | success | fail | <5 ms | <10 ms |
|----------|--:|--------:|-----:|------:|-------:|
| baseline | 20 | 20 | 0 | 100% | 100% |
| cache16m | 20 | 20 | 0 | 100% | 100% |
| dirty16m | 20 | 20 | 0 | 100% | 100% |

### 5.1 Per-layer breakdown (slowest samples from `/stats` `unmount_stats`, ms)

The gateway records every unmount at ns precision in three layers:
`gateway_ms` (RPC E2E) / `sandlot_ms` (handler total, incl. set-fs clear) /
`warden_ms` (kill + teardown + umount + drop_caches + the cross-tenant
residue sweep and final-state gate). The table below shows the per-layer
range of each scenario's slowest recorded samples (the top-slow list keeps
the 10 slowest per node; dirty16m lands one entry in it — its samples
cluster just under the cache16m maxima):

| Scenario | gateway_ms | sandlot_ms | warden_ms | slowest-sample trigger |
|----------|-----------:|-----------:|----------:|------------------------|
| baseline | 2.291–2.423 | 2.059–2.170 | 1.856–1.944 | lease-expiry |
| cache16m | 3.036–3.106 | 2.773–2.841 | 2.545–2.610 | lease-expiry |
| dirty16m | 3.070 | 2.829 | 2.624 | lease-expiry |

Run-wide rolling-window percentiles (n=63 recorded unmounts): gateway
P50 / P95 / P99 / max = 2.945 / 3.070 / 3.106 / 3.106 ms; warden
P50 / P95 / P99 / max = 2.480 / 2.590 / 2.624 / 2.624 ms.

Reading: every observed unmount is single-digit ms and 100% complete under
5 ms. The warden-side cost is the fixed teardown/sweep sequence — sync execs
are not in the agent cgroup (`kill_and_reap` returns immediately), the
rule-A sweep finds no survivors, the child mounts and workspace umount
detach cleanly, and the cross-tenant sweep plus final-state gate run on an
empty residue set. The clean 16 MiB workload raises the warden maximum by
~0.7 ms (1.944 → 2.610 ms) because `drop_caches` scales with the pinned
page cache; the dirty 16 MiB workload's slowest sample is 2.624 ms — the
writeback is absorbed before the sweep.

## 6. Reproduction

Developer path (clone → build → run) below; the no-toolchain path — release
tarball with the scripts bundled — is in
[Reproducing the Benchmarks](reproducing.md). The numbers in this report
were measured through that release path (scripts and binaries bundled
together) on a host with the cloud-vendor monitoring agents stopped.

**CPU/NUMA pinning is used on bare metal** (`e2e/pin.sh`): the host stack
(gateway, sandlot, benchmark client) is pinned to eight whole physical cores
(16-23 and their SMT siblings 64-71), and every microVM to its own whole
physical core (13/61, 14/62, 15/63), with `numactl --membind`. A 1-vCPU VM
uses one SMT thread; its vhost/virtiofs threads use the other, so the VM
never spans two physical cores. Nested-virt hosts are not pinned. Set
`PIN_MODE=0` to disable pinning, or `PIN_STACK_CORES` / `PIN_SLICE_CPUS` to
change the partition.

```bash
git clone <repo-url>                         # clone this repository
cd sandswap
bash build/install-deps.sh                   # one-shot dependency installer (apt + dnf/yum)
bash build/build.sh all                      # freshness-gated build
BENCH_VERBOSE=1 sudo bash e2e/latency-benchmark-aiagent.sh http single
BENCH_VERBOSE=1 sudo bash e2e/latency-benchmark-aiagent.sh http distributed
# mcp mode (also times the LLM round trip — needs DEEPSEEK_API_KEY /
# OPENAI_API_KEY / GOOGLE_API_KEY):
DEEPSEEK_API_KEY=sk-... sudo bash e2e/latency-benchmark-aiagent.sh mcp single
DEEPSEEK_API_KEY=sk-... sudo bash e2e/latency-benchmark-aiagent.sh mcp distributed
sudo bash e2e/latency-benchmark-unmount.sh all
# single scenario instead of all: baseline | cache16m | dirty16m
sudo bash e2e/latency-benchmark-unmount.sh cache16m
# cache-size curve: workload file size in MB (default 16)
FILE_MB=128 sudo bash e2e/latency-benchmark-unmount.sh cache16m
# per-sample detail (kept in baremetal-raw/ for this run):
BENCH_VERBOSE=1 sudo bash e2e/latency-benchmark-aiagent.sh http single
# warden-side per-op timing lines live at debug level (guest console cost —
# they tax the measured path at info):
SANDLOT_EXTRA_FLAGS="-warden-log debug" sudo bash e2e/latency-benchmark-aiagent.sh http single
```

Every script is self-cleaning and asserts its own quality gate (≥90% of
requested samples must succeed with non-zero durations, or the run fails).
The unmount benchmark additionally needs an Ubuntu rootfs with python3
(`output/rootfs-ubuntu`): it is auto-built on first run (~80 MB download)
and kept for reuse across runs — the release package ships it prebuilt.

## Appendix: raw data

The complete stdout/stderr of every run (including the per-sample
`BENCH_VERBOSE=1` detail) is kept in **`baremetal-raw/`** beside this
report. The exact commands and SHA256 are in
`baremetal-raw/MANIFEST.md`.
