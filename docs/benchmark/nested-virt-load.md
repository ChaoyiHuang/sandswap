---
title: "Benchmark Report — Nested-virt: microVM Reuse Capacity"
nav_order: 4
parent: Benchmark
---

# Benchmark report — nested-virt: microVM reuse capacity

> Three models on the same two-microVM nested-virtualization host: the ideal
> paced-lane ceiling, the traffic-shaped test (a real agent population
> behind a per-slot admission queue), and the realistic AI agent business
> capacity. Each reported as host and per-microVM cold reuses/s.

## Summary

### Ideal capability (one lane per microVM, continuously paced)

| Workload | Per microVM | Host |
|---|---:|---:|
| Pure cold | **67.4 reuses/s** | **134.75 reuses/s** |
| Mixed (1-3 requests/turn) | **57.2 cold reuses/s** | **114.45 cold/s** (210 requests/s total) |

Zero failed requests; busy ≤ 4 attempts per 20 s window (within the 0.5%
noise tolerance; see §3.3).

### Traffic-shaped capability (many agents per lane, paced admission)

| Workload | Per microVM | Host |
|---|---:|---:|
| Pure cold | **52.6 reuses/s** | **105.20 reuses/s** |
| Mixed (1-3 requests/turn) | **44.7 cold reuses/s** | **89.35 cold/s** (166 requests/s total) |

Real agents behind a real admission queue: every lane aggregates a full agent
population (own sandfs, 0.9-1.5 s think time); the lane releases one request
at a time and holds each VM slot for sticky + the measured unmount budget
(auto-calibrated). Zero failed requests; busy absorbed by the shaper; client
cold P95 inside 2x.

### Realistic business capacity (agents think 0.9-1.5 s, 1-3 requests/turn)

| Workload | No-failure maximum (per VM / host) | 2x latency budget (per VM / host) |
|---|---:|---:|
| Pure cold | 40.9 / 81.75 reuses/s | 10.3 / 20.65 reuses/s |
| Mixed | 32.9 / 65.85 reuses/s | 4.2 / 8.35 reuses/s |

`No-failure maximum` is the highest rate at which every request completed
(busy refusals were retried); `2x latency budget` is the highest rate whose
gateway and client P95 stay within twice the no-load baseline. No offered
load holds the raw 1x budget; 1x is the no-load floor.

**These are single-host numbers from a two-microVM nested VM.** A production
bare-metal host sizes its pool to the remaining cores — dozens of microVMs,
an order of magnitude more than the two here — and in a multi-node fleet a
`NO_AVAILABLE_SANDBOX` is routed to another node. Both effects raise the real
capacity. "Realistic" describes the request pattern, not a business forecast —
the traffic model is deliberately simple (§2.4). See
[§6](#6-what-the-two-vm-nested-host-cannot-show).

## 1. Test environment

| Item | Value |
|------|-------|
| Host | GCP VM, `systemd-detect-virt=google`, nested KVM |
| CPU | 4 vCPUs = 2 physical cores x 2 SMT threads, one NUMA node |
| RAM | 5 GiB |
| Guest | 1 vCPU / 256 MiB / 3 exec slots (the benchmark's `bench` spec) |
| Stack | one-machine-etcd: exec gateway :3001 + human gateway :3100 + etcd, one merged exec,prov sandlot |
| VM pool | 2 microVMs (the other two vCPUs carry the host stack) |
| Pinning | none (`PIN_MODE=0`): the L1 vCPUs are already scheduled by the outer hypervisor |

## 2. Measurement modes and method

### 2.1 Baseline (single microVM, no background load)

Measured first, with the same flat busybox fixture (`rootfs:v1`), the same
one-machine-etcd topology and the same 1 vCPU / 256 MiB / 3 exec-slot bench
spec as the load, by `e2e/latency-benchmark-aiagent.sh http distributed`:

- **warm** — 100 back-to-back calls to one agent (sticky lease reuse);
- **cold** — 50 rounds alternating two agents with a 300 ms gap (100 cold
  samples), so every call is a full cross-agent cold mount + exec.

The **gateway E2E P95** and the **client round-trip P95** from that run are
the latency budgets: 3.778 / 7.799 ms gateway, 4.238 / 8.382 ms client. The
load tiers use 1x and 2x those numbers.

### 2.2 Ideal paced-lane test

The realistic agent model (§2.4) is demand-shaped: the offered cold rate is
roughly `agents / think`, so the pool is only as busy as the business asks,
and a busy refusal is the arrival-collision tail. The driver also supports a
separate capability test, `-workload ideal`: **one paced lane per microVM**,
paced continuously with no between-turn think gap (the agent's own LLM think
time is simply not part of the gateway load). Each lane issues a turn every
configured period. The next turn never starts inside the previous lease's
sticky window, so every turn's first request is genuinely cold; if a turn
overruns the period, the lane self-clocks on the last response plus the
sticky window. The period is swept, and the highest completed cold rate
among periods with **zero failed requests and busy within the 0.5% noise
tolerance** (§3.3) is the collision-free capability with the VMs
continuously fed.

The test is an idealized ceiling, not a business model. Section 7 explains
how a production shaper can approach it.

### 2.3 Traffic-shaped test

A more realistic variant of the capability test, `-workload shaped`: the
same one-lane-per-VM pacing, but each lane aggregates a **full agent
population** instead of a single artificial agent. Each agent runs the
realistic closed loop (own sandfs, own 0.9-1.5 s think time) and queues its
turn at the lane like cars at a toll gate; the lane serves turns one at a
time and, after a turn's last response, **holds the VM slot for the sticky
window plus the unmount budget (`hold`)** before releasing the next turn.
`hold` is not a constant: the harness measures THIS stack's async-unmount
P95 first (a dozen cold execs, then the gateway `/stats` unmount recent
P95) and uses `ceil(P95) + 2 ms`, clamped to [1, 100] ms — this stack
measured 6.291 ms and picked 9 ms (mixed) / 7.544 ms → 10 ms (cold-only).
The agents-per-lane count is sized from the period: `rate x mean think`
plus a margin. The knee is the highest cold rate with zero failed requests
and the client P95 inside the last latency tier — busy retries are part of
the shaper's flow control and are reported, not disqualifying.

### 2.4 Realistic AI agent model

`examples/loadgen` drives one closed loop per agent:

| Parameter | Value |
|---|---|
| agents | the level's offered agent count |
| think time | U(900,1500) ms after the turn's last response |
| requests per turn | `requests:weight` pairs: `1:40,2:35,3:25` means 40% of turns have 1 request, 35% have 2, 25% have 3; a bare `1` means every turn has exactly one request (cold-only) |
| warm follow-ups | sent immediately after the previous response; sticky window 1 ms |
| busy retry | `503 NO_AVAILABLE_SANDBOX` retried up to 50 more times, full-jitter exponential backoff (10 ms base, 8x cap) |
| warm-up / window | 5 s excluded + 20 s measured |
| client in-flight cap | 256 |
| recycle policy | capacity: every lifetime cap and the memory recycle disabled |

A turn is one cold mount plus 0-2 warm follow-ups: the first request of
every turn is cold, and the remaining requests are sent immediately (warm
under the 1 ms sticky window).

Every request carries the agent's own `sandfs_id`; the response's
`X-Sandbox-Lease` header classifies it warm or cold. The response's
`gateway_duration_ns` is the sandswap-attributable latency, and the client
round trip spans the first attempt through the final response, so it
includes retry backoff. A 2 s `/stats` poller records the pool's CLEAN/TOTAL
counts and the node's policy-recycle counter during each level.

**What "realistic" means here.** The loop imitates the shape of real AI agent
traffic — per-agent sandfs, think gaps between turns, multi-request turns,
client-side retry on busy — and nothing beyond that. The traffic model is
deliberately simple: uniform think times, one fixed turn mix, the same tiny
exec on one flat volume per request, no payload or burstiness diversity. It
also runs against this host's two-microVM pool, an order of magnitude
smaller than a production node (§6). The numbers are a repeatable test
model, not a representation of real business capacity.

### 2.5 Capacity definitions

For each tier `k` (1x, 2x), a realistic level qualifies when no request
failed (none exhausted its retries) and both classes stay within budget:

- gateway E2E P95 `<= k x` the no-load gateway E2E P95;
- client P95 `<= k x` the no-load client P95 (retry backoff included).

Two further quantities are reported:

- **no-failure maximum** — the highest completed cold/s at a level where no
  request failed (retries allowed), regardless of latency;
- **measured ceiling** — the highest completed cold/s observed, with its
  failed-request rate.

### 2.6 Recycle policy

`LOADTEST_RECYCLE_POLICY=capacity` (the capacity runs) disables every
lifetime cap: `max_uses=-1`, `max_mounts=-1`, `max_distinct_agents=-1`,
memory recycle 0%/0 MB. The numbers are therefore the service/hardware
ceiling, not a recycle-policy artifact. The product defaults are
`max_uses=100000`, `max_mounts=10000`, `max_distinct_agents=300`, memory
10%/100 MB; §5.6 reports a shipped-policy control.

## 3. Ideal capability

### 3.1 Pure cold

`LOADTEST_REQUESTS_PER_TURN=1`, two lanes on the two-VM pool:

| Period (ms) | cold/s | per-VM/s | cold gw p95 | client p95 | clean mean | busy | failed |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 14 | 134.75 | **67.38** | 14.200 | 14.824 | 0.85/2 | 4 | 0 |
| 16 | 120.25 | 60.13 | 11.230 | 11.812 | 1.23/2 | 4 | 0 |
| 18 | 107.55 | 53.78 | 11.355 | 11.913 | 1.08/2 | 1 | 0 |
| 19 | 102.20 | 51.10 | 12.337 | 12.897 | 1.54/2 | 0 | 0 |
| 20 | 97.05 | 48.53 | 12.274 | 12.819 | 1.54/2 | 0 | 0 |
| 22 | 88.50 | 44.25 | 7.691 | 8.214 | 1.38/2 | 1 | 0 |

### 3.2 Mixed turns

`1:40,2:35,3:25`, two lanes:

| Period (ms) | cold/s | per-VM/s | warm/s | hit% | req/s | cold gw p95 | client p95 | clean mean | busy | failed |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 14 | 114.45 | **57.23** | 95.35 | 45.5 | 209.8 | 16.465 | 16.977 | 0.77/2 | 4 | 0 |
| 16 | 110.50 | 55.25 | 91.70 | 45.4 | 202.2 | 15.996 | 16.493 | 0.92/2 | 2 | 0 |
| 18 | 104.75 | 52.38 | 87.35 | 45.5 | 192.1 | 14.598 | 15.254 | 0.92/2 | 3 | 0 |
| 20 | 96.85 | 48.43 | 81.65 | 45.7 | 178.5 | 12.694 | 13.368 | 1.08/2 | 5 | 0 |
| 22 | 88.50 | 44.25 | 74.95 | 45.9 | 163.5 | 12.324 | 12.879 | 0.92/2 | 0 | 0 |
| 24 | 81.85 | 40.93 | 69.30 | 45.9 | 151.2 | 10.803 | 11.371 | 1.15/2 | 0 | 0 |
| 26 | 75.70 | 37.85 | 63.85 | 45.8 | 139.6 | 8.684 | 9.247 | 1.08/2 | 0 | 0 |
| 28 | 70.35 | 35.18 | 59.15 | 45.7 | 129.5 | 8.242 | 8.776 | 1.08/2 | 0 | 0 |

### 3.3 Reading the numbers

- **Pure cold: 67.4 reuses/s per VM (134.75 host).** Mixed: **57.2 cold
  reuses/s per VM (114.45 host)**, plus 95.35 warm execs/s, for **210 total
  requests/s (105 per VM)**. Both knees sit at the 14 ms sweep point; the
  achieved cycle is longer than the period because the lane self-clocks on
  the cold response plus the sticky window — the rate is latency-bound at
  the bottom of the curve and falls roughly as `1/period` above it.
- **Busy tolerance.** The shorter periods carry 1-5 busy attempts (≤ 0.3%
  of requests — the guest-scheduling tail, not pacing collisions). The knee
  admits busy `<= 0.5%` of the period's completed cold requests and
  discloses the count; every failed-request count is zero.
- Punctuality at the knees is 100% under 2 ms (max 1.679 ms pure cold,
  1.126 ms mixed); conservation stays within the band (3370 vs 3372 pure
  cold).
- The ideal test is **65% (cold) / 74% (mixed) above the realistic
  no-failure maximum** (40.9 / 32.9 per VM).

## 4. Traffic-shaped capability

### 4.1 Pure cold

`LOADTEST_REQUESTS_PER_TURN=1`, two lanes, auto hold = 10 ms (this stack's
measured unmount P95 7.544 ms + 2 ms):

| Period (ms) | agents | cold/s | per-VM/s | cold gw p95 | client p95 | clean mean | busy | failed |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 14 | 214 | 104.05 | 52.02 | 10.018 | 13.781 | 1.00/2 | 190 | 0 |
| 16 | 186 | 105.05 | 52.52 | 9.341 | 13.552 | 1.15/2 | 173 | 0 |
| 18 | 166 | 105.20 | **52.60** | 7.965 | 9.423 | 1.08/2 | 62 | 0 |
| 20 | 150 | 96.50 | 48.25 | 8.277 | 9.084 | 1.38/2 | 29 | 0 |
| 24 | 124 | 81.35 | 40.67 | 9.239 | 9.735 | 1.46/2 | 0 | 0 |
| 28 | 106 | 69.95 | 34.98 | 8.239 | 8.903 | 0.77/2 | 0 | 0 |

### 4.2 Mixed turns

`1:40,2:35,3:25`, two lanes, auto hold = 9 ms (unmount P95 6.291 ms + 2 ms):

| Period (ms) | agents | cold/s | per-VM/s | warm/s | hit% | req/s | cold gw p95 | client p95 | clean mean | busy | failed |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 14 | 214 | 87.65 | 43.83 | 74.40 | 45.9 | 162.1 | 11.299 | 14.066 | 0.92/2 | 172 | 0 |
| 16 | 186 | 89.35 | **44.67** | 76.70 | 46.2 | 166.1 | 11.118 | 12.952 | 1.31/2 | 133 | 0 |
| 18 | 166 | 89.30 | 44.65 | 76.85 | 46.3 | 166.2 | 10.371 | 12.230 | 1.31/2 | 86 | 0 |
| 20 | 150 | 87.15 | 43.58 | 74.60 | 46.1 | 161.8 | 10.774 | 12.012 | 0.85/2 | 48 | 0 |
| 24 | 124 | 79.00 | 39.50 | 67.40 | 46.0 | 146.4 | 11.363 | 11.958 | 1.38/2 | 9 | 0 |
| 28 | 106 | 69.80 | 34.90 | 59.10 | 45.9 | 128.9 | 11.815 | 12.341 | 1.23/2 | 1 | 0 |

### 4.3 Reading the numbers

- **Shaped pure cold: 52.6 reuses/s per VM (105.20 host)** at the 18 ms
  sweep point (the client P95 fits inside 2x from 18 ms up; 14-16 ms carry
  a heavier retry tail). **Shaped mixed: 44.7 cold reuses/s per VM (89.35
  host, 166 requests/s total)** at 16 ms.
- The rate is flat around the knee because the hold dominates: the paced
  cycle is turn duration + sticky + hold, so periods below that do not add
  rate — the slot budget, not the timer, governs.
- **The hold is what keeps the retries down.** Without it (sticky-only
  pacing; `load-shaped-nohold.log`) the mixed sweep produced 1,477-1,708
  busy attempts and a 31-36 ms client P95 at 16-20 ms. With the hold the
  busy count falls ~10x and the client P95 ~2.5x, at the same or better
  cold/s.
- **Positioning**: shaped cold (52.6/VM) recovers +29% over the realistic
  no-failure maximum (40.9/VM); shaped mixed (44.7/VM) recovers +36% over
  32.9/VM. Both stay inside the 2x client budget. The ideal ceiling
  (67.4 / 57.2) remains above them.

## 5. Realistic business capacity

### 5.1 Baseline

`latency-benchmark-aiagent.sh http distributed` on this host, after one
excluded warmup, 100 samples per class:

| Class | Metric | min | P50 | P95 | max |
|---|---|---:|---:|---:|---:|
| warm | client round trip | 3.206 | 3.680 | 4.238 | 4.588 |
| warm | gateway E2E | 2.842 | 3.278 | **3.778** | 4.185 |
| warm | sandlot | 2.421 | 2.798 | 3.308 | 3.633 |
| warm | exec | 2.057 | 2.375 | 2.873 | 2.979 |
| cold | client round trip | 6.177 | 7.206 | 8.382 | 10.177 |
| cold | gateway E2E | 5.605 | 6.680 | **7.799** | 9.654 |
| cold | sandlot | 4.987 | 5.979 | 6.871 | 7.183 |
| cold | exec | 4.133 | 5.061 | 5.851 | 6.214 |

### 5.2 Warm-mix workload (1-3 requests/turn)

`OK` and `ERR` count completed and failed requests; `BUSY` is the number of
503 refusals absorbed by the retry policy; `RETRY%` is the share of
completed requests that needed at least one retry.

| Agents | OK | ERR | BUSY | RETRY% | cold/s | per-VM/s | warm/s | hit% | cold gw p95 | warm gw p95 | cold client p95 | warm client p95 | clean/pool |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 170 | 0 | 0 | 0.0 | 4.25 | 2.13 | 4.25 | 50.0 | 7.283 | 3.987 | 7.976 | 4.451 | 2.00/2 |
| 10 | 315 | 0 | 6 | 1.9 | 8.35 | 4.18 | 7.40 | 47.0 | 8.204 | 5.157 | 11.400 | 5.685 | 2.00/2 |
| 20 | 610 | 0 | 21 | 3.4 | 16.65 | 8.33 | 13.85 | 45.4 | 9.260 | 8.251 | 12.214 | 8.768 | 1.85/2 |
| 40 | 1195 | 0 | 148 | 12.4 | 32.45 | 16.23 | 27.30 | 45.7 | 10.353 | 9.005 | 26.145 | 9.404 | 1.77/2 |
| 80 | 2441 | 0 | 1203 | 49.3 | 65.85 | 32.93 | 56.20 | 46.1 | 10.859 | 8.982 | 86.137 | 9.425 | 1.54/2 |
| 160 | 3266 | 76 | 27420 | 55.4 | 93.15 | 46.58 | 70.15 | 43.0 | 14.539 | 6.256 | 1483.300 | 6.782 | 1.07/2 |
| 320 | 2132 | 1347 | 102088 | 76.0 | 79.00 | 39.50 | 27.60 | 25.9 | 22.655 | 9.130 | 1969.130 | 9.833 | 0.79/2 |

### 5.3 Cold-only workload (warm = 0, one request per turn)

| Agents | OK | ERR | BUSY | RETRY% | cold/s | per-VM/s | cold gw p95 | cold client p95 | clean/pool |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 166 | 0 | 6 | 3.6 | 8.30 | 4.15 | 9.331 | 11.573 | 2.00/2 |
| 25 | 413 | 0 | 21 | 5.1 | 20.65 | 10.33 | 9.577 | 10.972 | 1.62/2 |
| 50 | 827 | 0 | 192 | 23.2 | 41.35 | 20.68 | 10.242 | 26.283 | 1.54/2 |
| 100 | 1635 | 0 | 1631 | 64.1 | 81.75 | 40.88 | 10.856 | 103.728 | 1.54/2 |
| 200 | 2352 | 49 | 29827 | 96.1 | 117.60 | 58.80 | 13.191 | 1358.061 | 1.14/2 |
| 400 | 1734 | 1293 | 103511 | 98.3 | 86.70 | 43.35 | 20.280 | 1975.698 | 1.00/2 |

### 5.4 Capacity at 1x and 2x

Capacity (no failed request, both classes in budget):

| Workload | 1x (3.778 / 7.799 ms gateway; 4.238 / 8.382 ms client) | 2x (7.556 / 15.598 ms gateway; 8.476 / 16.764 ms client) |
|---|---:|---:|
| warm-mix | none | **10 agents, 8.35 cold/s (4.18/VM)** |
| cold-only | none | **25 agents, 20.65 cold/s (10.33/VM)** |

Reuse limits (no latency budget):

| Workload | Quantity | Result |
|---|---|---|
| warm-mix | no-failure maximum | 80 agents, 65.85 cold/s (32.93/VM), client cold P95 86.14 ms |
| warm-mix | measured ceiling | 160 agents, 93.15 cold/s (46.58/VM), 2.3% failed requests |
| cold-only | no-failure maximum | 100 agents, 81.75 cold/s (40.88/VM), client cold P95 103.73 ms |
| cold-only | measured ceiling | 200 agents, 117.60 cold/s (58.80/VM), 2.0% failed requests |

- **1x.** The no-load cold gateway P95 (7.799 ms) is the floor. The smallest
  levels are 7.283 ms (warm-mix, 5 agents — inside!) and 9.331 ms (cold-only,
  10 agents — 1.20x). No tested level passes ALL four 1x budgets
  simultaneously.
- **2x warm-mix.** At 10 agents: cold gateway P95 8.204 ms (1.05x), warm
  5.157 ms (1.36x), client cold 11.400 ms (1.36x), warm client 5.685 ms
  (1.34x), 6 busy refusals, zero failed. The next level (20 agents) fails on
  warm gateway P95 (8.251 > 7.556 ms).
- **2x cold-only.** At 25 agents: cold gateway P95 9.577 ms (1.23x), client
  10.972 ms (1.31x), 21 busy refusals, zero failed. At 50 agents the
  gateway still fits (10.242 ms) but the client P95 (26.283 ms) does not.
- **No-failure maximum.** 80 warm-mix agents complete 65.85 cold/s with
  49.3% retried; 100 cold-only agents complete 81.75 cold/s with 64.1%
  retried.
- **Measured ceiling.** Warm-mix peaks at 93.15 cold/s (160 agents, 2.3%
  failed); cold-only at 117.60 (200 agents, 2.0% failed).
- **Failed requests exist only well beyond the no-failure rate.** Every
  level at or below ~66 cold/s (warm-mix) / ~82 cold/s (cold-only)
  completed with zero failed requests.

### 5.5 Warm-request correctness

- The warm class is the gateway's own lease-hit classification
  (`X-Sandbox-Lease: hit`), not a client-side guess.
- Across 5-80 offered agents the warm share is 45.4-50.0%, matching the
  turn distribution (~46% follow-ups).
- At 160/320 offered agents the warm share falls to 43.0% / 25.9% — the
  response-to-follow-up path queues behind the retry storm. The 1 ms sticky
  is sufficient at and below the service rate.

### 5.6 Recycle policy

The capacity runs disable every lifetime cap (§2.6). A shipped-policy
control run:

| Agents | cold/s | cold gw p95 | client p95 | clean/pool | recycles | busy | failed |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 80 | 65.60 | 10.932 | 112.124 | 1.54/2 | 0 | 1298 | 0 |
| 160 | 95.20 | 13.938 | 1490.053 | 0.71/2 | 0 | 26212 | 60 |
| 320 | 74.20 | 22.673 | 2020.427 | 1.14/2 | 2 | 101297 | 1346 |

The only recycles happened during the 320-agent level, where the cumulative
distinct-agent count passes 300; the mount and use caps are two orders of
magnitude away at this duration. At the 2x capacity points (10-25 agents)
two VMs see far fewer than 300 distinct agents, so the shipped policy does
not change the capacity result.

### 5.7 Gates

- **Punctuality**: 100% of lease fires under 2 ms at the highest completed
  level (warm-mix 80 agents: max 1.070 ms; cold-only 100 agents: max
  1.067 ms).
- **Conservation**: expected expiries (warm-up included) versus the unmount
  delta stays within the agent-sized slack (warm-mix 1538 vs 1634;
  cold-only 1926 vs 2026).
- **Errors**: zero non-503 failures at every level.

## 6. What the two-VM nested host cannot show

The realistic numbers in §5 are a **lower bound for a production host**, for
two structural reasons:

1. **The pool is much larger on bare metal.** A production node sizes its
   microVM pool to the remaining cores after the stack — dozens of microVMs,
   an order of magnitude more than the two here. The cold-arrival collision
   tail is an Erlang-B effect: the probability that every VM is in a switch
   window at an arrival falls steeply as the pool grows. A large pool runs
   near its service rate with negligible refusals, and the host rate is `V x`
   the per-VM rate; the per-VM rate is the number that transfers.
2. **A fleet routes around a busy node.** In a multi-node deployment
   `NO_AVAILABLE_SANDBOX` is a per-node signal: placement/DNS routes the
   sandfs to another node with capacity. The fleet rate is the sum over
   nodes, not one host's ceiling.

The ideal test in §3 is the per-VM capability that survives both effects:
it removes demand shaping and the small-pool collision tail, and measures
what one microVM can do when continuously fed.

## 7. Approaching the ideal rate in production

The ideal paced-lane test is a client-side pacing model: one lane per
microVM, and the next request is released only after the previous response
plus the sticky/unmount budget. A production deployment can approach the
same reuse rate by adding a **traffic shaper / admission layer in front of
sandswap**:

- buffer the agent requests instead of firing them straight at the gateway;
- keep one in-flight cold request per microVM slot;
- release the next request for a slot when the previous response has returned
  and the switch budget (sticky window + unmount) has elapsed;
- forward the shaped stream to the gateway.

`examples/loadgen` with `-workload shaped` is the reference implementation of
exactly this shaper: a real agent population queues at one admission point
per microVM slot, and the slot is held for the sticky window plus the
measured unmount budget between turns. On this host it recovers +29% (cold)
/ +36% (mixed) cold reuse over the unshaped business workload with the
client P95 still inside the 2x budget (§4). The trade-off is explicit:
shaping converts idle VM time into queueing latency for the business. Use
it only where the workload can absorb the wait; without shaping, the
realistic model in §5 is what the host delivers.

## 8. Analysis

- **Offered load and the realistic service rate.** Each agent offers one
  cold turn per `think + turn` interval, so the offered cold rate is about
  `agents / 1.2 s`. The realistic workload completes 66-118 cold/s on two
  VMs (33-59 per VM); its ~17-25 ms per switch includes retry and
  arrival-collision pacing, not just the switch. The ideal test removes
  that pacing and reaches 135 cold/s (67.4 per VM); the gap is demand
  shaping, not a harder hardware limit.
- **Where the 503s come from.** The pool has no cold-mount queue: when both
  VMs are in a cold window, the next mount is refused immediately. Even
  below the service rate the independently phased agents collide in the
  tail, and the retry policy absorbs them. Above the service rate the retry
  rate explodes, and beyond roughly 2-3x the service rate the retry budget
  itself exhausts.
- **The 2x capacity is warm-path bound.** At 20 warm-mix agents the cold
  gateway P95 (9.260 ms) is inside 2x, but the warm gateway P95 (8.251 ms)
  exceeds 7.556 ms. The warm path — which should be the cheapest — degrades
  first because the follow-ups queue behind the pool's cold work.
- **The per-VM reuse rate is a latency trade-off.** At the 2x tier each VM
  serves 4.2 (mixed) or 10.3 (cold-only) cold switches/s. At the no-failure
  maximum it serves 32.9 or 40.9/s, in the shaped test 44.7-52.6/s, and at
  the ideal ceiling 57.2-67.4/s. The host's microVM reuse capacity is a
  curve, not a single number; the ideal test is the top, the 2x point is
  the low-latency end.
- **The pool, not the host stack, is the limit.** A bare-metal pool with
  dozens of microVMs has the same per-VM turnaround but far more slots,
  which is what the bare-metal capacity run measures.

## 9. Reproduction

Baseline (one microVM, no background load, 100 samples per class):

```bash
WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  bash e2e/latency-benchmark-aiagent.sh http distributed
```

Take its four P95s (gateway warm/cold, client warm/cold) into the
`*_P95_MS` variables below.

Realistic warm-mix load (the table in §5.2):

```bash
POOL_SIZE=2 LOADTEST_AGENT_LEVELS="5 10 20 40 80 160 320" \
  LOADTEST_DURATION_SEC=20 LOADTEST_WARMUP_SEC=5 \
  LOADTEST_STICKY_MS=1 LOADTEST_INTRA_TURN_GAP_MS=0 \
  SKIP_ESTIMATE_BENCH=1 \
  WARM_GW_P95_MS=<...> COLD_GW_P95_MS=<...> \
  WARM_CLIENT_P95_MS=<...> COLD_CLIENT_P95_MS=<...> \
  LOADTEST_MAX_INFLIGHT=256 LOADTEST_AGENT_CREATE_CONCURRENCY=16 KEEP_LOGS=1 \
  bash e2e/latency-benchmark-load.sh
```

Realistic cold-only (§5.3): same plus `LOADTEST_REQUESTS_PER_TURN=1` and
`LOADTEST_AGENT_LEVELS="10 25 50 100 200 400"`.

Ideal test, cold-only (§3.1):

```bash
POOL_SIZE=2 LOADTEST_WORKLOAD=ideal LOADTEST_LANES=2 \
  LOADTEST_TURN_PERIODS_MS="14 16 18 19 20 22" LOADTEST_REQUESTS_PER_TURN=1 \
  ... (same refs/duration knobs)
```

Ideal test, mixed (§3.2): `LOADTEST_TURN_PERIODS_MS="14 16 18 20 22 24 26 28"`.

Traffic-shaped test, cold-only (§4.1):

```bash
POOL_SIZE=2 LOADTEST_WORKLOAD=shaped LOADTEST_LANES=2 \
  LOADTEST_TURN_PERIODS_MS="14 16 18 20 24 28" LOADTEST_SHAPED_HOLD_MS=auto \
  LOADTEST_REQUESTS_PER_TURN=1 \
  ... (same refs/duration knobs)
```

Traffic-shaped test, mixed (§4.2): same without `LOADTEST_REQUESTS_PER_TURN`.

Shaped control without the hold: `LOADTEST_SHAPED_HOLD_MS=0`.

Shipped recycle-policy control (§5.6):

```bash
POOL_SIZE=2 LOADTEST_AGENT_LEVELS="80 160 320" LOADTEST_RECYCLE_POLICY=shipped \
  ... (same refs/duration knobs)
```

## Appendix: raw data

The per-level tables in §3-§5 are the measured data. The complete
stdout/stderr of every run is kept in **`nested-virt-load-raw/`** beside this
report; the directory is self-contained, including the baseline log. The
exact commands and SHA256 are in `nested-virt-load-raw/MANIFEST.md`. Each
log contains one `bench-result` JSON line per level (the numbers in §3-§5)
plus the gate output.
