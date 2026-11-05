---
title: Benchmark Report — Nested-virt
nav_order: 2
parent: Benchmark
---

# Benchmark Report — nested-virt

> This report covers the benchmark suite (http + mcp × single/distributed,
> unmount) on a small nested-virt cloud VM. The question it answers: what do
> the numbers look like when the host itself is a VM, and **why**? All
> numbers are from real KVM microVMs (no mocks), read from the gateway's own
> ns-precision metrics in every `/agent/execute` response.
>
> §1-§5 cover the executive summary, environment, HTTP path, MCP path and
> unmount path; §6 is the nested-specific analysis; raw logs are in
> `nested-virt-raw/` beside this report.

## 1. Executive summary

| Topology | Path | client P50 / P95 | gateway P50 / P95 | sandlot P50 / P95 | exec P50 / P95 |
|----------|------|-----------------:|------------------:|------------------:|---------------:|
| http single | Warm | 3.699 / 4.391 | 3.267 / 3.895 | 2.747 / 3.297 | 2.310 / 2.826 |
| http single | Cold | 7.241 / 7.866 | 6.710 / 7.251 | 6.103 / 6.646 | 5.191 / 5.668 |
| http distributed | Warm | 3.778 / 4.365 | 3.304 / 3.911 | 2.787 / 3.360 | 2.378 / 2.896 |
| http distributed | Cold | 7.447 / 8.080 | 6.903 / 7.464 | 6.224 / 6.745 | 5.233 / 5.781 |
| mcp single | Warm | 4.216 / 4.963 | 3.388 / 4.187 | 2.888 / 3.586 | 2.469 / 3.124 |
| mcp single | Cold | 7.531 / 8.280 | 6.641 / 7.318 | 5.995 / 6.617 | 5.093 / 5.652 |
| mcp distributed | Warm | 4.144 / 5.187 | 3.372 / 4.136 | 2.872 / 3.580 | 2.480 / 3.051 |
| mcp distributed | Cold | 7.786 / 8.441 | 6.849 / 7.436 | 6.134 / 6.714 | 5.204 / 5.735 |

All values in ms (P50 / P95), n=100 per class per run. `gateway` = the
gateway E2E metric. The `mcp` rows exclude the LLM-driven tool-call
measurements (§4, n=5, cold only).

- **The nested path is dominated by in-guest work** (http single): warm
  client P95 4.39 ms / cold 7.87 ms; warm exec P95 2.83 ms / cold 5.67 ms.
  The host-side segments stay sub-millisecond to low-single-digit ms.
- **Distribution stays off the exec path**: distributed is within ~0.5 ms
  of single-node on every layer's P95 (etcd is off the exec path), and the
  warm path is the sum of the same four layers.
- **MCP costs only its endpoint**: warm `client − gateway` is ~0.83 ms P50
  on the mcp path vs ~0.43 ms on plain http (the Streamable-HTTP MCP
  endpoint) — everything below `gateway` is identical machinery (§4).
- **The remaining gap sits inside the guest.** Host-side segments account
  for ~1.5 ms of a 4.39 ms warm client P95 and ~2.2 ms of a 7.87 ms cold
  client P95 (http single). The warden-side total (virtio-fs mount + exec)
  is 5.67 ms P95 cold, the dominant share of the cold path (§6).
- No VM recycle occurs inside a benchmark window (`max_uses=100000`), so no
  boot-cold sample appears in any run.

## 2. Test environment

| Item | Value |
|------|-------|
| Host | GCP VM (4 vCPUs, 5 GiB), `systemd-detect-virt=google`, VT-x exposed, `/dev/kvm` |
| CPU | Intel Xeon 2.30 GHz, 2 cores / 4 threads, 1 NUMA node, no cpufreq governor (GCP) |
| Host kernel | 7.0.0-1014-gcp |
| Guest kernel | 7.2.8 cloud-hypervisor config (PVH, minimized/hardened) |
| microVM | 1 vCPU, 256 MiB, 3 exec slots (the benchmark's `bench` spec), pool of 3 |
| CPU/NUMA pinning | **Disabled** — nested virt: the L1 vCPUs are already outer-scheduled |
| Lease | sticky, 1 ms window |
| VM recycle | `max_uses=100000` — no VM replacement inside a benchmark window |
| Topologies | single-node and distributed (etcd + exec gateway + human gateway) |
| Benchmarks | `e2e/latency-benchmark-aiagent.sh {http,mcp} {single,distributed}` (`WARM_N=100 COLD_N=50 BENCH_VERBOSE=1`), `e2e/latency-benchmark-unmount.sh all` (ITER_N=20) |
| LLM (mcp) | `openai-sandswap` with DeepSeek (`deepseek-flash`) |

The host is a spot instance; occasional glitches are possible. This run was
on a quiet machine (no competing sessions).

## 3. HTTP Command-execution path results

### 3.1 Single-node topology (`http single`)

```
Warm — sticky lease reuse (leaseHit=true, n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        3.283     3.699     4.391     4.939
  gateway E2E              2.954     3.267     3.895     4.511
  sandlot                  2.502     2.747     3.297     3.963
  exec                     2.080     2.310     2.826     3.067

Switch — cross-agent cold mount_and_exec (leaseHit=false, n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        6.254     7.241     7.866    18.886
  gateway E2E              5.801     6.710     7.251    17.559
  sandlot                  5.161     6.103     6.646    16.472
  exec                     4.274     5.191     5.668    14.405
```

### 3.2 Distributed topology (etcd + exec/human gateways, `http distributed`)

```
Warm — sticky lease reuse (leaseHit=true, n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        3.357     3.778     4.365     4.559
  gateway E2E              2.904     3.304     3.911     4.110
  sandlot                  2.438     2.787     3.360     3.601
  exec                     2.123     2.378     2.896     3.002

Switch — cross-agent cold mount_and_exec (leaseHit=false, n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        6.344     7.447     8.080    10.327
  gateway E2E              5.839     6.903     7.464     9.821
  sandlot                  5.214     6.224     6.745     7.166
  exec                     4.324     5.233     5.781     6.280
```

### 3.3 Layer decomposition

Single-node (P50 / P95):

| Segment | Warm | Cold |
|---------|-----:|-------:|
| client − gateway | 0.43 / 0.50 | 0.53 / 0.62 |
| gateway − sandlot | 0.52 / 0.60 | 0.61 / 0.61 |
| sandlot − exec | 0.44 / 0.47 | 0.91 / 0.98 |
| exec (warden) | 2.31 / 2.83 | 5.19 / 5.67 |

Distributed (P50 / P95):

| Segment | Warm | Cold |
|---------|-----:|-------:|
| client − gateway | 0.47 / 0.45 | 0.54 / 0.62 |
| gateway − sandlot | 0.52 / 0.55 | 0.68 / 0.72 |
| sandlot − exec | 0.41 / 0.46 | 0.99 / 0.96 |
| exec (warden) | 2.38 / 2.90 | 5.23 / 5.78 |

The distributed topology's warm exec path never touches etcd — auth
resolves from the gateway's local in-memory identity snapshot, and etcd only
records ownership / placement — so the decomposition is within noise of
single-node. The cold `gateway − sandlot` segment is slightly larger in
distributed because it includes the post-MountLock lifecycle recheck (§3 of
the bare-metal report). The warm path is unaffected.

## 4. MCP Command-execution path results

Same stack plus the MCP endpoint (`/mcp`, Streamable HTTP), driven by
`openai-sandswap` with DeepSeek. The LLM round-trip (~1.0-1.7 s) is three
orders of magnitude above any sandbox segment and is excluded from the
summary tables.

### 4.1 Single-node topology (`mcp single`)

```
Warm — sticky lease reuse (n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        3.708     4.216     4.963     5.307
  gateway E2E              2.895     3.388     4.187     4.413
  sandlot                  2.528     2.888     3.586     3.872
  exec                     2.178     2.469     3.124     3.338

Switch — cross-agent cold mount_and_exec (n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        6.564     7.531     8.280    26.041
  gateway E2E              5.622     6.641     7.318    24.498
  sandlot                  4.998     5.995     6.617    23.320
  exec                     4.159     5.093     5.652    21.791
```

LLM round-trip (openai-sandswap → LLM API): n=5 min=1031.9 P50=1225.2
P95=1693.0 max=1693.0 ms.

LLM-driven tool calls (cold, n=5):

| Metric | min | P50 | P95 | max |
|---|---:|---:|---:|---:|
| client round-trip | 6.752 | 7.567 | 15.367 | 15.367 |
| gateway E2E | 5.885 | 6.672 | 14.064 | 14.064 |
| sandlot | 5.309 | 6.010 | 12.741 | 12.741 |
| exec | 4.457 | 5.121 | 5.507 | 5.507 |

### 4.2 Distributed topology (etcd + exec/human gateways, `mcp distributed`)

```
Warm — sticky lease reuse (n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        3.549     4.144     5.187     5.824
  gateway E2E              2.964     3.372     4.136     4.537
  sandlot                  2.537     2.872     3.580     3.916
  exec                     2.207     2.480     3.051     3.476

Switch — cross-agent cold mount_and_exec (n=100) [ms]
  metric                     min       P50       P95       max
  client round-trip        6.550     7.786     8.441    10.674
  gateway E2E              5.672     6.849     7.436     9.705
  sandlot                  5.056     6.134     6.714     7.103
  exec                     4.237     5.204     5.735     6.097
```

LLM round-trip: n=5 min=1069.3 P50=1150.0 P95=1272.6 max=1272.6 ms.

LLM-driven tool calls (cold, n=5):

| Metric | min | P50 | P95 | max |
|---|---:|---:|---:|---:|
| client round-trip | 7.328 | 7.879 | 18.689 | 18.689 |
| gateway E2E | 6.291 | 6.987 | 17.454 | 17.454 |
| sandlot | 5.660 | 6.390 | 13.808 | 13.808 |
| exec | 4.633 | 5.397 | 6.503 | 6.503 |

### 4.3 Layer decomposition

The MCP endpoint adds its overhead **above** the gateway metric, visible as
the wider `client − gateway` segment:

| Segment | http single warm P50 | mcp single warm P50 |
|---------|-----:|-----:|
| client − gateway | 0.43 | 0.83 |
| gateway − sandlot | 0.52 | 0.50 |
| sandlot − exec | 0.44 | 0.42 |
| exec (warden) | 2.31 | 2.47 |

Everything below `gateway` is the same machinery — the MCP Streamable-HTTP
endpoint costs ~0.4 ms on the client side.

## 5. Unmount / recycle path

`latency-benchmark-unmount.sh all` (ITER_N=20 per scenario, Ubuntu rootfs
template). Each scenario mounts a volume, executes a workload, waits for
the lease to expire, and records the async unmount.

The `/stats` `unmount_stats` recent-ring results (gateway/warden layers):

| Scenario | gateway P50 / P95 | warden P50 / P95 |
|---|---:|---:|
| baseline (shell `echo`) | 7.72 / 8.76 | 6.14 / 7.13 |
| cache16m (16 MiB cached) | 8.93 / 12.54 | 7.45 / 10.69 |
| dirty16m (16 MiB dirty) | 9.11 / 12.54 | 7.59 / 10.43 |

Every observed unmount is single-digit ms to low-teens P95 and 100% complete
under 20 ms. The nested overhead inflates the warden share (the drop-caches
pass crosses two hypervisors).

## 6. Why nested-virt is slower

### 6.1 Where the time goes: the guest dominates

The http single warm path (P50 3.70 ms client) decomposes as:

- `client → gateway`: 0.43 ms (HTTP client + loopback)
- `gateway` processing: 0.52 ms (auth, lease, pool, gRPC encode)
- `sandlot` processing: 0.44 ms (dispatch, set-fs, vsock encode)
- **`exec` (in-guest)**: 2.31 ms (virtio-fs I/O + fork/execve under 2 hypervisors)

The in-guest exec share is 62% of the warm client P50 and 72% of the cold
P50 (5.19 of 7.24 ms). On bare metal the exec share is smaller because
fork/execve and virtio-fs I/O don't pay the L2 hypervisor tax.

### 6.2 Round-trip amplification under two hypervisors

Every guest↔host crossing (vsock send, virtio-fs I/O, KVM exit) is
amplified: the L0 hypervisor (GCP) schedules the L1 vCPU thread, which in
turn schedules the L2 guest. A single virtio-fs read under nested virt
incurs at least two hypervisor exits, each with the outer scheduler's
latency. This is why the cold path (which does the most guest I/O: mount,
set-fs, fork/execve, proc mounts) is ~2x the warm path.

### 6.3 Host weakness and CPU oversubscription

The GCP VM has 4 vCPUs on 2 physical cores, shared with the host stack
(gateway, sandlot, etcd, loadgen) and 3 microVMs. No pinning is possible
(the L1 vCPUs are already outer-scheduled). CPU contention between the
stack processes and the microVMs adds jitter, visible in the cold-path
maxima (18.9 ms http single, 26.0 ms mcp single vs P95 7.9/8.3 ms).

## 7. Reproduction

```bash
# HTTP latency (http mode, single-node and distributed)
WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  sudo bash e2e/latency-benchmark-aiagent.sh http single
WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  sudo bash e2e/latency-benchmark-aiagent.sh http distributed

# MCP latency (needs an LLM API key)
DEEPSEEK_API_KEY=sk-... WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  sudo bash e2e/latency-benchmark-aiagent.sh mcp single
DEEPSEEK_API_KEY=sk-... WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  sudo bash e2e/latency-benchmark-aiagent.sh mcp distributed

# Unmount full-path latency
sudo bash e2e/latency-benchmark-unmount.sh all
```

## Appendix: raw data

The complete stdout/stderr of every run (including the per-sample
`BENCH_VERBOSE=1` detail) is kept in **`nested-virt-raw/`** beside this
report. The exact commands and SHA256 are in
`nested-virt-raw/MANIFEST.md`.
