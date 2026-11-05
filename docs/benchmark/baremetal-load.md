---
title: "Benchmark Report — Bare Metal: microVM Reuse Capacity"
nav_order: 3
parent: Benchmark
---

# Benchmark report — bare metal: microVM reuse capacity

> Bare-metal KVM on a TencentOS Server 4 cloud bare-metal host: the ideal
> paced-lane test (one lane per microVM, continuously fed), the traffic-shaped
> test (a full agent population queued behind one in-flight request per VM),
> and the realistic AI agent business capacity. Every role and every microVM
> is pinned to disjoint whole physical cores, and the same 36-core VM pool is
> measured under two mappings — one microVM per whole physical core, and one
> microVM per logical CPU (two VMs per physical core via SMT). Each result is
> reported as host and per-microVM cold reuses/s; the agent-population tests
> additionally report how many agents one microVM serves. The ideal and shaped
> tests
> are run in two turn shapes — **pure cold** (one request per turn) and
> **mixed** (1-3 requests per turn, the follow-ups warm) — and the two
> mappings are compared: the physical-core mapping is the deployment
> recommendation; the SMT mapping is measured only for comparison — it shows
> that doubling the VM count does not add host capacity (see §3.3 and §8.1).

## How to read this report

Capacity is quoted as a sustained rate, but it is defined by latency: a level
counts only while every request class stays inside a budget set from the same
stack with no background load.

The budgets come from the **baseline**: the four no-load P95 latencies of §2.1
— gateway E2E and client round trip, each in a warm and a cold class —
measured on an idle host. Gateway E2E is the part of the latency that sandswap
adds; the client round trip runs from the first attempt to the final response,
so it also includes retry backoff. Each **tier** is that baseline multiplied
by one factor — 1.05, 1.5 or 2.0 — applied to each of the four baseline
values separately; the table below gives every tier's four budgets in
milliseconds. A level meets a tier only when its measured P95 is at or below
the tier budget in every cell it has: a pure-cold workload has no warm class,
while a mixed workload must satisfy all four cells:

| Tier | Meaning | Gateway warm | Gateway cold | Client warm | Client cold |
|---|---|---:|---:|---:|---:|
| baseline | the no-load reference itself (§2.1) | 0.868 ms | 2.323 ms | 0.979 ms | 2.488 ms |
| 1.05x | baseline + 5 % (the bare-metal jitter is small enough to resolve it) | 0.911 ms | 2.439 ms | 1.028 ms | 2.612 ms |
| 1.5x | baseline + 50 % | 1.302 ms | 3.485 ms | 1.469 ms | 3.732 ms |
| 2.0x | baseline x 2 (the tier used for the shaped test) | 1.736 ms | 4.646 ms | 1.958 ms | 4.976 ms |

A level that misses any one cell is outside the tier even if its throughput is
higher.

**Knee period.** The ideal and shaped tests are each run at several turn
periods; a turn period is the time between the start of two consecutive turns.
The knee is the turn period that reaches the highest useful cold-reuse rate
while still passing its gate: for the ideal test, no failed requests and busy
refusals within the 0.5 % noise tolerance (the collision-free ceiling); for
the shaped test, zero failed requests and the 2.0x latency tier (for the mixed
rows, both classes must fit). Turn periods shorter than the knee collide or
queue and do not add useful capacity.

**Two mappings.** SMT (simultaneous multi-threading) is the CPU feature that
runs two threads on one physical core. The physical-core mapping gives one
microVM both threads of a whole core; it is the deployment recommendation. The
logical-core mapping gives each microVM one thread, so two VMs share a core;
it is reported only for comparison. It halves the per-VM rate, adds no host
capacity, and in the ideal test cannot hold a latency tier (all P95s are
25-51 ms). It is not a production configuration; no mixed SMT run was taken
because the pure-cold SMT run already shows the per-VM and host penalty, and
the mixed workload would only add load to the same saturated stack.

## Summary

### Ideal capability (one lane per microVM, continuously paced)

| Workload | Mapping | Per microVM | Host | Knee period |
|---|---|---:|---:|---:|
| Pure cold | Physical core (32 VMs) | **183.95 cold/s** | **5886.50 cold/s** | 5 ms |
| Mixed (1-3 requests/turn) | Physical core (32 VMs) | **155.96 cold/s + 132.25 warm/s** | **4990.83 cold/s + 4231.90 warm/s** | 6 ms |
| Pure cold | Logical CPU (64 VMs, comparison only) | 97.84 cold/s | 6261.70 cold/s | 8 ms (25.4 ms P95) |

Zero failed requests at every qualifying point. The mixed workload adds warm
follow-ups on the same VM: the cold reuse rate falls 15 % (183.95 to 155.96 per
VM) while total requests rise 57 % (5886.5 to 9222.7 per host). The SMT row is
for comparison only: its only advantage is 6 % more host cold rate, at the
cost of 5.6x the P95 and 53 % of the per-VM rate; §3.3 explains the queueing
and why it is not a deployment option.

TODO: investigate how to shape the traffic inside the gateway to approach
the ideal reuse capability for Poisson-distribution AI agent requests.

### Traffic-shaped capability (a full agent population per lane, one in-flight request per VM)

| Workload | Mapping | Per microVM | Host | Knee period | Agents | Agents per microVM |
|---|---|---:|---:|---:|---:|---:|
| Pure cold | Physical core (32 VMs) | **53.06 cold/s** | **1697.80 cold/s** | 8 ms | 2048 | **64** |
| Mixed (1-3 requests/turn) | Physical core (32 VMs) | **39.73 cold/s + 33.66 warm/s** | **1271.50 cold/s + 1077.00 warm/s** | 12 ms | 1536 | **48** |
| Pure cold | Logical CPU (64 VMs, comparison only) | 20.74 cold/s | 1327.55 cold/s | 12 ms | 1600 | 25 |

The agents are realistic — each thinks 0.9-1.5 s between turns — but the
shaper partitions the population across lanes, and each lane merges its whole
set of agents onto one microVM slot: individually an agent offers well under
one request per think gap, and only the aggregation of 25-64 agents per lane
(sized to each mapping's service ceiling) keeps a single VM's reuse
capability as full as the 2.0x tier allows.

**Agents per microVM** is the same knee seen from the agent side: with a
0.9-1.5 s think gap (mean 1.2 s), a microVM switching at 53.06 cold/s keeps
53.06 x 1.2 ≈ 64 agents continuously served — exactly the population the
shaper sizes onto each lane (`-lane-agents` ≈ lane rate x mean think). The
mixed and SMT rows convert the same way (39.73 x 1.2 ≈ 48 agents, 20.74 x
1.2 ≈ 25); one step up, 72 agents per microVM, would demand 59.63 cold/s of
the VM and pushes the gateway cold P95 past the 2.0x budget (§4.1).

The shaped knee is the highest offered population whose cold (and, for the
mixed rows, warm) gateway and client P95 stay within the 2.0x tier; one step
above it the admission queue pushes the latency outside the tier (2304 agents
on the pure-cold physical mapping, 1792 at 14 ms on the mixed mapping — where
cold still fits but warm does not). Zero failed requests at the knee; busy
refusals are part of the shaper's flow control.

### Realistic business capacity (agents think 0.9-1.5 s, 1-3 requests/turn)

| Workload | Mapping | No-failure maximum (per VM / host) | 1.5x tier (per VM / host) | 2x tier (per VM / host) |
|---|---|---:|---:|---:|
| Mixed (1-3 requests/turn) | Physical core | 51.66 / 1653.00 (2000 agents = 62.5/VM) | 1.30 / 41.60 (50 agents = 1.56/VM) | 31.18 / 997.90 (1200 agents = 37.5/VM) |
| Mixed (1-3 requests/turn) | Logical CPU (comparison only) | 23.59 / 1509.90 (2000 agents = 31.25/VM) | none | 10.39 / 664.90 (800 agents = 12.5/VM) |
| Pure cold | Physical core | 70.32 / 2250.20 (2800 agents = 87.5/VM) | none | 31.20 / 998.50 (1200 agents = 37.5/VM) |
| Pure cold | Logical CPU (comparison only) | 29.77 / 1905.60 (2400 agents = 37.5/VM) | none | 15.60 / 998.20 (1200 agents = 18.75/VM) |

`No-failure maximum` is the highest offered level at which every request
completed (busy refusals retried like a real agent). The parenthetical agent
counts also give the population one microVM serves (agents ÷ pool — here
agents are not pinned to a VM, so it is a normalization of the same
capacity): at the 2x tier one physical-core microVM serves 37.5 agents, and
the shaped admission of §4 raises that to 64 (53.06 vs 31.20 cold/s). The latency tiers are
multiples of the no-load baseline P95 (the table at the top of this report) for
BOTH classes (warm and cold) and both surfaces (gateway E2E and client):
**no offered load holds the raw 1.05x tier**, and the 1.5x capacity point is
the physical-core mixed mapping at 50 agents. Requests start failing just
above the no-failure maximum: at 2400 agents the physical mixed run logged a
single failed request (0.0015 %), at 2800/3200 the failed-request rate rises to
0.06 %/0.6 %. The SMT rows are for comparison only: they are below the
physical mapping at every latency tier, and no SMT level reaches the 1.5x
tier. "Realistic" describes the request pattern, not a business forecast:
the traffic model is deliberately simple and the pool is one host's 32/64
VMs (§2.4).

## 1. Test environment

| Item | Value |
|------|-------|
| Host | Inspur SA5212M5, `systemd-detect-virt=none`, no cpuinfo `hypervisor` flag |
| CPU | Intel Xeon Platinum 8255C @ 2.50 GHz, 2 sockets × 24 cores, 96 SMT threads, 2 NUMA nodes |
| RAM | 384 GiB (DIMM total; 375.8 GiB `MemTotal`) |
| Host kernel | 6.6.117-45.14.2.tl4.x86_64 (TencentOS Server 4) |
| Guest kernel | 7.2.8 minimized cloud-hypervisor tree (`vmlinux` ELF+PVH) |
| Binaries | prebuilt release package: static host binaries, guest kernel, initramfs, templates and vendored etcd (the benchmark scripts are bundled in the same package) |
| Host stack allocation | **12 whole physical cores**, disjoint per role: loadgen 0-3 (SMT siblings 48-51), gateway + human gateway + etcd 4-7 (52-55), sandlot + provision instance 8-11 (56-59) |
| VM pool cores | the remaining **36 whole physical cores** (12-47 and 60-95) |
| Physical-core mapping | one microVM per whole core: `POOL_SIZE=32`, 36 slices (`PIN_SLICE_CPUS=2`); 4 spare slices absorb a rare boot-failure replacement |
| Logical-core mapping | one microVM per logical CPU: `POOL_SIZE=64`, 72 slices (`PIN_SLICE_CPUS=1`), two VMs share each physical core's SMT threads; 8 spare slices |
| microVM | 1 vCPU, 256 MiB, 5 MiB initramfs, 3 exec slots, flat `rootfs:v1` busybox template |
| Lease | sticky, 1 ms window |
| VM recycle | `capacity` policy: every lifetime cap and memory recycle disabled, so no VM replacement occurs inside a measurement window |
| Background | cloud-vendor monitoring agents stopped for the run |

## 2. Measurement modes and method

### 2.1 Baseline (one microVM, no background load)

`e2e/latency-benchmark-aiagent.sh http distributed`, `WARM_N=100 COLD_N=50
BENCH_VERBOSE=1`, on the otherwise idle host: warm gateway E2E P95 **0.868 ms**,
cold **2.323 ms**; warm client P95 **0.979 ms**, cold **2.488 ms**. These four
values are the reference for every latency tier below.

### 2.2 Ideal paced-lane test

`LOADTEST_WORKLOAD=ideal`: one lane per microVM, each issuing a turn every
`period` with no between-turn think gap. The next turn never starts inside the
previous lease's sticky window; if a turn overruns the period the lane
self-clocks on the previous response plus the sticky window, so every turn's
first request is genuinely cold. Two turn shapes are swept: **pure cold**
(`LOADTEST_REQUESTS_PER_TURN=1`) and **mixed** (`1:40,2:35,3:25`), where each
turn is one cold mount followed immediately by 0-2 warm follow-ups. The period
is swept and the highest completed cold rate with zero failed requests and
busy within the 0.5 % noise tolerance is the collision-free ceiling with every
VM continuously fed. The test's gate is collisions, not a latency budget: the
P95s are reported, and the mixed point that sets the knee here also holds both
classes inside the 2.0x tier. This is a capability test, not a business model.
The period sweep brackets the service cycle (~5-6 ms cold and ~6-7 ms mixed on
the physical mapping; ~8-12 ms on SMT).

### 2.3 Traffic-shaped test

`LOADTEST_WORKLOAD=shaped`: each lane aggregates a full AI agent population
(each agent with its own sandfs and 0.9-1.5 s think time). The lane releases
one request at a time and holds the VM slot for the sticky window plus
`LOADTEST_SHAPED_HOLD_MS`, auto-calibrated on this stack from the measured
unmount P95 plus 2 ms (clamped [1,100]). This is a per-slot admission queue,
not a rate limiter: below the service cycle the lane is work-bound and
self-clocks. Pure cold and mixed are both swept. The sweep brackets
6-14 ms and the agent population is sized to the lane's service ceiling
(population ≈ per-lane cold rate x the 1.2 s mean think gap): too
few agents and the lane starves, one step above the ceiling and the queue
pushes the latency past the tier. For the mixed workload the population must
be sized separately: the 64 agents/lane that is the pure-cold physical knee
over-offers
once each turn also carries warm follow-ups, so the mixed knee is found by
varying the population at the fixed period (48 agents/lane at 12 ms). The knee
requires BOTH classes inside the 2.0x tier: at 56 agents/lane and 14 ms the
cold class still fits but the warm class does not (cold P95 4.055 ms, warm
2.268 ms vs the 1.736 ms warm budget), so that point is excluded.

### 2.4 Realistic AI agent model

One flat volume per simulated agent. Each agent thinks 0.9-1.5 s, then issues a
turn of 1-3 requests (weights 40/35/25; the first request of a turn is cold,
the follow-ups are warm under the 1 ms sticky window and sent immediately). A
`503 NO_AVAILABLE_SANDBOX` is retried with full-jitter backoff, so pool
saturation shows up as retry pressure rather than a failed request. A request
that exhausts its retry budget is counted as failed; every failure in these
runs is such a 503. Two
workloads: **mixed** (1-3 requests per turn) and **pure cold** (one cold
request per turn, warm share 0). Offered load is the agent count; each level
runs 10 s of warm-up (excluded) then a 20 s measurement window.

**What "realistic" means here.** The model imitates the shape of real AI
agent traffic — per-agent sandfs, a think gap between turns, multi-request
turns, client-side retry on busy — and nothing beyond that. The traffic model
is deliberately simple: uniform think times, one fixed turn mix, the same
tiny exec on one flat volume per request, no payload or burstiness
diversity. It also runs against a single host's 32/64-VM pool, far smaller
than a production fleet. The numbers are a repeatable test model for
comparing mappings and latency tiers; they are not a forecast of real
business capacity.

### 2.5 Capacity definitions

Per level the run reports completed cold reuses/s, the per-microVM rate, the
warm share, retry pressure, and the gateway E2E / client P95 of both classes.
The capacity points are:

- **no-failure maximum** — the highest offered level with zero failed requests
  (busy refusals retried);
- **latency tiers** — the highest level whose gateway E2E P95 AND client P95
  stay within the tier multiple of the no-load baseline, for BOTH the warm and
  cold classes. The three tiers and their absolute millisecond values are the
  table at the top of this report; a level must satisfy all four cells.

### 2.6 Recycle policy

All capacity runs use the `capacity` policy: every lifetime cap (max uses /
mounts / distinct agents) and guest-memory recycle are disabled, so every
measured microVM stays in service for the whole run. VM replacement inside a
window would otherwise fold boot-cold into the switch measurements.

### 2.7 Bare-metal specifics (what a nested-virt run cannot reproduce)

1. **Disjoint whole-core allocation.** The host stack and the VM pool own
   separate whole physical cores: loadgen / gateway (+human+etcd) / sandlot
   (+prov) get 12 reserved cores and the VM pool gets the other 36. Nested
   runs are unpinned because the L1 vCPUs are already scheduled by the outer
   hypervisor; here the placement is part of the measured configuration.
2. **Two mappings over the same core pool.** The physical-core mapping gives
   each microVM both SMT threads of a core; the vCPU and the host-side
   virtio-fs/API threads share those two threads and never span two cores. The
   logical-core mapping gives each microVM one logical CPU, so two VMs share a
   core's SMT threads. This is the main knob a nested-virt host cannot
   exercise: the two mappings differ by a factor of two in VM count on the
   same silicon, and the per-VM rates differ accordingly (§8.1). The result is
   that the SMT mapping is not a deployment option.
3. **NUMA binding per VM slice.** Each microVM's sandvmm and its allocations
   are bound to the NUMA node of its slice (`numactl --membind`), so the
   measured memory locality is fixed rather than host-scheduler dependent.
4. **The near-baseline tier.** The 1.05x tier (5 % tolerance) is only
   meaningful when the no-load path is itself sub-millisecond and stable — the
   bare-metal case; on nested virt the same tolerance is below the noise.
5. **A warm-up offered level: volume-creation writeback.** The realistic
   model creates one flat volume per simulated agent before the levels start
   (~2.1 MB each; 3.4-6.7 GB for the 1600-3200-agent populations). The host
   kernel finishes writing those dirty pages after the creation loop returns,
   and the writeback continues into the first measured level, stalling the
   guests' virtio-fs I/O: the first 10-agent level shows a gateway cold P95
   of 244-408 ms (and on one run a sustained P50 of 88 ms) while its P50 on
   the other runs stays at the normal 2.4-3.0 ms. The first offered level of
   every realistic run is therefore a warm-up and is excluded from the
   tables. The effect is the writeback, not a per-VM first-use cost: the same
   10-agent level measured after creating only 25 agents is clean (gateway
   cold P50/P95 2.4/2.7 ms). The ideal and shaped sweeps do not use a warm-up
   period: their first row is the shortest period tested, where the shaped
   lane's service cycle is longer than the period (an over-offer point,
   reported as such), not a transient.
6. **Host throughput scales with the pool; the per-VM rate does not.** The
   host totals below are for a 32-VM (physical) or 64-VM (SMT) pool on 36
   reserved cores. A production host sizes the pool to its remaining cores,
   and the per-microVM reuse rate is the number that transfers.

## 3. Ideal capability

### 3.1 Physical-core mapping — pure cold

| Period (ms) | Host cold/s | Per VM | Cold gw P95 (ms) | Cold client P95 (ms) | Busy |
|---:|---:|---:|---:|---:|---:|
| **5** | **5886.5** | **183.95** | 4.514 | 4.638 | 4 |
| 6 | 4945.4 | 154.54 | 3.618 | 3.778 | 50 |
| 7 | 4269.9 | 133.44 | 4.389 | 4.573 | 1 |

BUSY counts a `503 NO_AVAILABLE_SANDBOX` refusal: the next cold mount arrived
while the pool had no VM ready — typically the previous lease's asynchronous
unmount was still finishing on the VM the lane had just used. The loadgen
retries it with full-jitter backoff, so a BUSY attempt is retry pressure, not a
failed request. The three periods above carry 4, 50 and 1 BUSY attempts —
0.002 %, 0.034 % and 0.001 % of their completed cold requests; the count is not
monotonic in the period because it depends on the phase between the lane's
turn and the asynchronous unmount. The knee accepts
BUSY ≤ 0.5 % of a period's completed cold requests, with a floor of one attempt
(so a single collision does not disqualify a short period), as the
guest-scheduling/unmount noise band, together with zero failed requests; a
real over-offer is well above it (the shaped over-offer row at 6 ms has 471
BUSY on 22,580 completed turns, 2.1 %). The 5 ms knee's 4 attempts sit far
inside the band.

### 3.2 Physical-core mapping — mixed

`LOADTEST_REQUESTS_PER_TURN=1:40,2:35,3:25`; every turn starts with a cold
mount and immediately sends 0-2 warm follow-ups under the 1 ms sticky window.

| Period (ms) | Host cold/s | Per VM cold | Host warm/s | Per VM warm | Warm share | Req/s | Cold gw P95 (ms) | Warm gw P95 (ms) | Cold client P95 (ms) | Warm client P95 (ms) | Busy |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 3203.8 | 100.12 | 2711.3 | 84.73 | 45.8 % | 5915.1 | 16.215 | 6.163 | 16.353 | 6.282 | 0 |
| **6** | **4990.8** | **155.96** | **4231.9** | **132.25** | 45.9 % | 9222.7 | 4.395 | 1.195 | 4.512 | 1.312 | 0 |
| 7 | 3016.2 | 94.26 | 2561.3 | 80.04 | 45.9 % | 5577.5 | 16.239 | 6.334 | 16.375 | 6.464 | 0 |
| 8 | 2482.1 | 77.56 | 2110.5 | 65.95 | 46.0 % | 4592.6 | 17.174 | 6.856 | 17.314 | 6.980 | 1 |

The 6 ms row is the knee: it is the highest completed cold rate among periods
with zero failed requests and busy within tolerance, and it holds both classes
inside the 2.0x tier (cold 4.395/4.512 ms against 4.646/4.976 ms; warm
1.195/1.312 ms against 1.736/1.958 ms).

A longer period cannot improve the rate by construction: the ideal lane starts
its next turn at `turnStart + period` (or later, if the previous response plus
the sticky window is later), so the best possible rate at 7/8 ms is 1/period =
143/125 cold/s per VM — already below the 6 ms row's 156/VM. The measured 7/8 ms
rows are lower still because they fall into a self-clocked slow cycle: the
actual cycle (1 / per-VM cold rate) is 10.0, **6.4**, 10.6 and 12.9 ms for 5,
6, 7 and 8 ms, so only 6 ms runs near its nominal period. In the 7/8 ms rows a
subset of cold mounts waits for the VM slot (P95 16-17 ms) while the P50 stays
normal (2.8-3.5 ms); the lane schedules its next turn after the late response,
so the slow cycle persists. The 5 ms row is the opposite side: the period is
shorter than the mixed service cycle, so it over-offers (16 ms P95, 100.12/VM).
The reverse-order run confirms the phase dependence: 8 ms stays slow (2399.7),
7 ms is fast from that starting phase (4494.3, 7.1 ms cycle) but slow in the
ascending run, and 6 ms is fast in both orders (4913.1), so 6 ms is the stable
maximum. This is a pacing effect of the test, not a product
capacity limit; the shaped test avoids it by holding the VM slot for a
measured unmount budget before releasing the next turn (§4). Raw logs:
`14-ideal-phys-mixed.log` and `18-ideal-phys-mixed-rev.log`.

### 3.3 Logical-core (SMT) mapping — pure cold (comparison only)

| Period (ms) | Host cold/s | Per VM | Cold gw P95 (ms) | Cold client P95 (ms) | Busy |
|---:|---:|---:|---:|---:|---:|
| **8** | **6261.7** | **97.84** | 25.350 | 25.503 | 3 |
| 10 | 4473.2 | 69.89 | 37.436 | 37.602 | 2 |
| 12 | 1970.6 | 30.79 | 50.846 | 51.026 | 0 |

All three P95s are above 20 ms because the host stack, not the VM pool, is the
shared throughput limit. At the 8 ms knee, 64 lanes would demand 64 / 8 ms =
8000 cold turns/s; the stack completes 6261.7/s. The missing ~1740 turns/s are
lanes waiting on their own responses (the lane self-clocks on the last
response plus the sticky window) plus the gateway/sandlot queue, and the P95
is that queueing delay. The stack is pinned to 8 logical CPUs of gateway and 8
of sandlot (4 physical cores each); at this point sandlot uses 7.7 of its 8
logical CPUs (774 %) and gateway 6.5 (651 %) — both effectively saturated. The
36 physical cores in the VM pool are not the constraint, so adding VMs cannot
add host capacity. At longer periods the queue does not drain: the lanes
self-clock on the slow responses, so the completed rate collapses (4473/s at
10 ms, 1971/s at 12 ms) while P95 grows (37/51 ms). The 6 % host-total
advantage over the physical mapping (6261.7 vs 5886.5) is therefore not usable
capacity: it costs 5.6x the P95 and half the per-VM rate, and under the latency
tiers it disappears (§4, §5).

This is why the SMT mapping is not a deployment option. The mixed workload
would only add warm requests to a stack already at its ceiling, and the
pure-cold SMT run already misses every latency tier on this test; no mixed
SMT ideal or shaped run was taken.

### 3.4 Reading the numbers

- The physical pure-cold knee is the shortest swept period, **5 ms → 183.95
  reuses/s per VM**. The cycle at the knee (5.4 ms) is the cold service time:
  the guest mount+exec, the 1 ms sticky window, and the unmount tail. Shorter
  periods do not raise the rate — the lane self-clocks — they only add busy
  collisions.
- The mixed knee is **6 ms → 155.96 cold + 132.25 warm reuses/s per VM**
  (4990.8 cold + 4231.9 warm per host). Warm follow-ups occupy the VM slot, so
  the cold rate falls 15 % against pure cold, but total requests rise 57 %
  (5886.5 to 9222.7 per host). The warm share is 45.9 %, as the workload mix
  predicts.
- The SMT run's per-VM rate is **97.84/s (53 % of the physical-core
  rate)** at its collision-free point, with a 25 ms P95. Two VMs time-share
  each core's SMT threads, so a VM's vCPU and host-side virtio-fs threads
  compete with the co-resident VM; the host total is slightly higher only
  because the stack is driven closer to its own ceiling.
- The ideal test's gate is collisions, not latency; the realistic and shaped
  sections are the latency-bounded view. The mixed ideal point at 6 ms happens
  to fit the 2.0x tier for both classes, while the faster 5 ms row does not
  (16 ms P95) and is reported only as the over-demand point.

## 4. Traffic-shaped capability

### 4.1 Physical-core mapping — pure cold

| Period (ms) | Host cold/s | Per VM | Cold gw P95 (ms) | Cold client P95 (ms) | Busy |
|---:|---:|---:|---:|---:|---:|
| **8** | **1697.8** | **53.06** | 3.679 | 3.797 | 0 |
| 10 | 1695.2 | 52.97 | 3.774 | 3.898 | 0 |

At 6 ms the same 2048-agent population over-offers (471 BUSY); it is the
boundary check and is excluded from the table.

One step above the knee — 2304 agents (72 per lane) — the 8 ms period
completes 1908.25 cold/s (59.63 per VM) but the gateway P95 rises to 4.834 ms
(4 % over the 2x budget of 4.646 ms) and the client P95 to 4.957 ms, so the
level is outside the tier despite zero failures. At 10 ms the same population
is also outside the tier: 1902.95 cold/s, 5.070 ms gateway and 5.194 ms client
P95.

### 4.2 Physical-core mapping — mixed

`LOADTEST_REQUESTS_PER_TURN=1:40,2:35,3:25`, 32 lanes. The knee is found in two
steps: the population at the 14 ms period (where the warm boundary is visible),
then the period at the knee population (48 per lane).

**Population at 14 ms**

| Agents | Per lane | Host cold/s | Per VM cold | Host warm/s | Per VM warm | Warm share | Cold gw P95 (ms) | Warm gw P95 (ms) | Cold client P95 (ms) | Warm client P95 (ms) | Busy | Result |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1536 | 48 | 1267.7 | 39.62 | 1073.4 | 33.54 | 45.9 % | 3.368 | 1.721 | 3.485 | 1.832 | 0 | fits (12 ms is slightly faster) |
| 1792 | 56 | 1474.1 | 46.06 | 1247.9 | 39.00 | 45.8 % | 4.055 | 2.268 | 4.176 | 2.372 | 0 | cold fits, warm fails |
| 2048 | 64 | 1674.1 | 52.31 | 1421.1 | 44.41 | 45.9 % | 5.997 | 3.773 | 6.119 | 3.891 | 0 | outside tier |

At 64 per lane the 10-14 ms periods all exceed both budgets (cold gateway
5.997-6.878 ms, warm 3.773-4.186 ms); the 14 ms row is shown.

**Period at 48 agents/lane**

| Period (ms) | Host cold/s | Per VM cold | Host warm/s | Per VM warm | Warm share | Cold gw P95 (ms) | Warm gw P95 (ms) | Cold client P95 (ms) | Warm client P95 (ms) | Busy | Result |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **12** | **1271.5** | **39.73** | **1077.0** | **33.66** | 45.9 % | **3.397** | **1.711** | **3.511** | **1.813** | 0 | **knee** |
| 14 | 1267.7 | 39.62 | 1073.4 | 33.54 | 45.9 % | 3.368 | 1.721 | 3.485 | 1.832 | 0 | fits, slightly slower |

The knee is **48 per lane at 12 ms: 1271.5 cold/s (39.73 per VM) plus 1077.0
warm/s (33.66 per VM), 2348.5 requests/s**, with cold 3.397/3.511 ms and warm
1.711/1.813 ms. The 14 ms period is also inside the tier but has a slightly
lower cold rate.

**Over-offer brackets (not capacity points).** Three combinations put the lane
ahead of the VM slot's release: 48 per lane at 10 ms, 56 per lane at 12 ms and
64 per lane at 8 ms. They produce 192-274 BUSY refusals (absorbed by the
client's retries) and a queueing tail, but the cold P50 stays normal at
2.7-3.2 ms — the runs are valid, they simply over-offer. They are excluded
from the capacity tables; the exact P50/P95 values remain in the raw logs.

### 4.3 Logical-core (SMT) mapping — pure cold (comparison only)

| Period (ms) | Host cold/s | Per VM | Cold gw P95 (ms) | Cold client P95 (ms) | Busy |
|---:|---:|---:|---:|---:|---:|
| 10 | 1327.5 | 20.74 | 4.728 | 4.858 | 0 |
| **12** | **1327.6** | **20.74** | **4.510** | **4.630** | 0 |

The SMT shaped run fits the 2.0x tier only at 12 ms (the 10 ms period sits
1.8 % over the cold gateway budget), and its 20.74 reuses/s per VM is 39 % of
the physical mapping's 53.06. At 8 ms the same 1600-agent population over-offers
(185 BUSY), so its usable range is 10-12 ms. Mixed
SMT was not measured: the pure-cold SMT run already spends nearly all its
cold-latency headroom at 12 ms (4.510 of 4.646 ms), so a mixed run would have
to fit the same cold budget plus the 1.736 ms warm budget at a population
below the pure-cold knee; it cannot change the physical-mapping
recommendation.

### 4.4 Reading the numbers

- The shaped test's rate is set by the lane's service cycle (response +
  sticky + the auto hold), not by the period: once the population keeps the
  lane fed, the period only adds idle. The pure-cold physical cycle is ~8-9 ms;
  the mixed cycle is ~12 ms because each turn carries 0-2 extra warm requests.
- The 2.0x latency tier binds the knee before failures do. The physical
  pure-cold mapping completes 1908.25 cold/s (59.63 per VM) at 2304 agents and
  8 ms with zero failed requests and zero busy, but the gateway P95 is
  4.834 ms (4 % over the 4.646 ms budget); the mixed mapping completes
  52.3/s/VM with 2048 agents at 14 ms but the cold and warm P95 both exceed the
  tier. The
  transferable shaped capacities are 53.06/s/VM (pure cold) and 39.73/s/VM
  (mixed) on the physical mapping.
- Mixed vs pure cold: the cold reuse rate falls 25 % (53.06 to 39.73 per VM)
  while total requests rise 38 % (1697.8 to 2348.5 per host). The warm
  follow-ups are cheap server-side (1.7-1.8 ms P95 at the knee) but they hold
  the VM slot, so the shaper must offer a smaller population to stay inside
  the same latency budget.
- **Agents per microVM.** An agent offers one cold turn per 0.9-1.5 s think
  gap (mean 1.2 s), so the per-VM cold rate converts directly into the agent
  population one microVM serves: 53.06/s ↔ 64 agents, 39.73/s ↔ 48 and
  20.74/s ↔ 25 — the per-lane populations of the knee rows. The next
  population step, 72 agents per microVM, would demand 59.63 cold/s and
  lands 4 % over the 2.0x gateway budget (§4.1).
- Shaped vs ideal: the hold (VM-slot release cost) plus the admission queue
  costs ~71 % of the physical pure-cold ideal rate (53.06 vs 183.95) and ~75 %
  of the mixed ideal rate (39.73 vs 155.96); the shaped test is the realistic
  version of the same ceiling, not a different capability. The SMT run is
  39 % of the physical shaped rate and is not a deployment option.

## 5. Realistic business capacity

Every table's first offered level (10 agents) is the excluded warm-up level.

### 5.1 Baseline

§2.1 measured the four no-load P95s; the tier table at the top of this report
turns them into the absolute budgets. Every level is checked against all four
cells (warm/cold x gateway/client).

### 5.2 Mixed (1-3 requests/turn) — physical-core mapping

| Agents | Cold/s | Per VM | Warm share | Failed requests | Busy retries | Cold gw P95 | Cold client P95 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 25 | 20.9 | 0.65 | 46.3 % | 0 | 0 | 2.63 | 2.79 |
| 50 | 41.6 | 1.30 | 45.6 % | 0 | 0 | 3.15 | 3.26 |
| 100 | 83.2 | 2.60 | 45.5 % | 0 | 0 | 3.72 | 3.82 |
| 400 | 332.6 | 10.40 | 46.2 % | 0 | 0 | 4.04 | 4.15 |
| 1200 | 997.9 | 31.18 | 45.8 % | 0 | 4 | 3.57 | 3.69 |
| 2000 | 1653.0 | 51.66 | 45.7 % | 0 | 3837 | 10.81 | 17.49 |
| 2400 | 1796.8 | 56.15 | 46.0 % | 1 | 139054 | 15.06 | 574.84 |
| 2800 | 1979.1 | 61.85 | 44.8 % | 44 | 238945 | 14.78 | 959.36 |
| 3200 | 2114.2 | 66.07 | 44.6 % | 454 | 326009 | 14.61 | 1273.05 |

### 5.3 Pure cold — physical-core mapping

| Agents | Cold/s | Per VM | Failed requests | Busy retries | Cold gw P95 | Cold client P95 |
|---:|---:|---:|---:|---:|---:|---:|
| 50 | 41.5 | 1.30 | 0 | 0 | 3.59 | 3.69 |
| 100 | 83.3 | 2.60 | 0 | 0 | 3.79 | 3.90 |
| 400 | 332.9 | 10.40 | 0 | 0 | 4.21 | 4.31 |
| 1200 | 998.5 | 31.20 | 0 | 0 | 3.56 | 3.68 |
| 2000 | 1663.0 | 51.97 | 0 | 522 | 5.28 | 5.64 |
| 2400 | 1991.8 | 62.24 | 0 | 2376 | 10.88 | 14.12 |
| 2800 | 2250.2 | 70.32 | 0 | 72288 | 15.49 | 218.70 |
| 3200 | 2418.0 | 75.56 | 3 | 158997 | 15.71 | 569.00 |

### 5.4 Capacity at the three tiers

| Workload | Mapping | 1.05x | 1.5x | 2.0x | No-failure max |
|---|---|---|---:|---:|---:|
| Mixed (1-3 requests/turn) | Physical | none | 50 agents / 41.6 cold/s | 1200 agents / 997.9 cold/s | 2000 agents / 1653.0 cold/s |
| Mixed (1-3 requests/turn) | Logical (comparison only) | none | none | 800 agents / 664.9 cold/s | 2000 agents / 1509.9 cold/s |
| Pure cold | Physical | none | none | 1200 agents / 998.5 cold/s | 2800 agents / 2250.2 cold/s |
| Pure cold | Logical (comparison only) | none | none | 1200 agents / 998.2 cold/s | 2400 agents / 1905.6 cold/s |

The 1.05x tier is not reached by any offered level: the no-load baseline is
measured on an idle stack with three microVMs, while any multi-VM load adds
~0.2 ms to the warm path and ~1 ms to the cold path — the 5 % tolerance is
below that floor. The 1.5x capacity point is the physical mixed mapping at
50 agents; the physical pure-cold run misses it by 3 % at 50 agents
(gateway cold P95 3.587 ms vs the 3.485 ms budget) and the SMT runs miss it at
their lowest level (cold gateway 12-18 % over budget; the mixed warm
gateway 43 % over).

The SMT rows are not a deployment option. At the 2.0x tier SMT
runs at 33 % (mixed) and 50 % (pure-cold) of the physical per-VM cold rate
(10.39 vs 31.18; 15.60 vs 31.20) and, for mixed, cuts the host tier by a
third (664.9 vs 997.9). For pure cold, the host totals at 2.0x are identical
(998.2 vs 998.5) even though SMT runs twice as many VMs: the host stack, not
the VM pool, sets that ceiling. The full per-level SMT rows are in the raw logs
(`20-warmmix-smt.log`, `21-coldonly-smt.log`); they are omitted here because
they do not change the comparison.

### 5.5 Warm-request correctness

The warm share stays at 45.5-46.2 % for mixed up to 1200 agents (the
workload's expected share: 65 % of turns have at least one follow-up), and the
follow-up requests land inside the 1 ms sticky window (lease-fire punctuality
100 % < 2 ms, max ~1.05 ms in every run). Above the no-failure maximum the
warm share falls as VMs queue, which is the expected saturation signature.

### 5.6 Gates

Every realistic run passes the script's hard gates: zero non-503 failures (the
503s above are `NO_AVAILABLE_SANDBOX`, capacity information), lease
punctuality ≥ 95 % under 2 ms, and the expiry/unmount conservation check.

## 6. What the single-host benchmark cannot show

A production fleet runs the agents (loadgen) remotely and usually the gateway
on another host; this same-host run reserves loadgen+gateway cores on the VM
host and is therefore a conservative lower bound for the compute host. A
`NO_AVAILABLE_SANDBOX` in a multi-node fleet can be routed to another node,
raising effective capacity. The per-microVM rate is the number that transfers
to a production host.

## 7. Approaching the ideal rate in production

The ideal test is a ceiling obtained by keeping exactly one cold request in
flight per microVM slot and releasing the next after the previous response
plus the sticky window. A production client reaches it with a client-side
traffic shaper / admission layer with the same rule;
`examples/loadgen -workload ideal` is the reference client. The shaped test
is the same idea behind a full agent population: a per-slot queue shortens the
switch cycle to the service time instead of the business think time, and its
knee is where the admission queue starts to be visible in the client latency.
For the mixed workload the shaper releases the cold request under the same
rule; the
warm follow-ups ride the mounted VM and are sent immediately, which is why the
mixed cold rate is lower but total throughput is higher.

## 8. Analysis

### 8.1 Physical core vs logical CPU

| Metric | Physical-core mapping | SMT mapping | SMT / physical |
|---|---:|---:|---:|
| Ideal pure cold, per VM | 183.95/s | 97.84/s | 0.53 |
| Ideal mixed, per VM cold | 155.96/s | not measured | — |
| Ideal pure cold, host | 5886.5/s | 6261.7/s | 1.06 |
| Ideal pure cold P95 | 4.5 ms | 25.4 ms | 5.6x |
| Shaped pure cold (2x), per VM | 53.06/s | 20.74/s | 0.39 |
| Shaped mixed (2x), per VM cold | 39.73/s | not measured | — |
| Shaped pure cold (2x), host | 1697.8/s | 1327.6/s | 0.78 |
| Mixed 2x tier, per VM | 31.18/s | 10.39/s | 0.33 |
| Pure cold 2x tier, per VM | 31.20/s | 15.60/s | 0.50 |
| Mixed no-failure, host | 1653.0/s | 1509.9/s | 0.91 |
| Pure cold no-failure, host | 2250.2/s | 1905.6/s | 0.85 |

SMT is not a deployment option for this workload: it provides no capacity
advantage at any latency tier. The only metric where it leads is the ideal
collision-free host total: +6.4 % (6261.7 vs 5886.5), bought with a 5.6x P95
(25.4 vs 4.5 ms) and 53 % of the per-VM rate. Every latency-bounded test is at
or below the physical mapping (shaped 0.78 host, mixed 2x 0.67 host,
pure-cold 2x 1.00 host). The reason is that the host stack, not the VM pool, is
the bottleneck: at the SMT ideal knee sandlot is at 97 % and
gateway at 81 % of their 8-logical-CPU budgets, so the extra VMs only queue.
The per-VM loss from sharing a core's SMT threads (0.33-0.53) is the second
effect. The pure-cold 2x host total is identical (998.2 vs 998.5) with twice
the VM count, which makes the point: SMT doubles the number of VMs, not the
host's capacity. Use one microVM per whole physical core.

### 8.2 Where the latency goes

At the physical mapping's 2.0x tier the warm gateway P95 is ~1.0-1.8 ms and the
cold gateway P95 ~3.4-4.6 ms. The mixed knees make the split explicit: the
ideal 6 ms point is cold 4.395 / warm 1.195 ms (client 4.512 / 1.312 ms), and
the shaped 12 ms point is cold 3.397 / warm 1.711 ms (client 3.511 / 1.813 ms).
The warm follow-up itself is cheap — it reuses the mounted VM — but it occupies
the VM slot, which is why the mixed cold rate falls 15-25 % against pure cold
while total requests rise 38-57 %. The cold server-side floor (P50) is
~2.2-2.3 ms on the physical mapping and ~2.5-2.6 ms on SMT; the gap to the
no-load cold P95 (2.323 ms) is the multi-VM mix, not a single component. At
the mixed ideal knee the cold gateway P95 is 4.395 ms while its P50 is
3.627 ms, so the tail is spread across mount/exec and host dispatch rather
than concentrated in one stage.

### 8.3 The knee and the saturation regime

The shaped pure-cold knee is 64 agents/lane at 8 ms; the mixed knee is 48
agents/lane at 12 ms. The mixed 56/lane point is the near-miss: cold fits
(4.055 / 4.176 ms) but warm does not (2.268 / 2.372 ms against 1.736 / 1.958
ms), so the both-class rule excludes it; at 64/lane both classes are over. The
realistic no-failure maximum (2000-2800 agents depending on
workload/mapping) is where the busy-refusal pressure starts to be visible: at
2000 agents the mixed physical run retries 3.8 k busy refusals per 20 s
window; at 2400 it is 139 k and the first failed request appears. Beyond that
the failed-request rate rises quickly (0.06 % at 2800, 0.6 % at 3200) while
the completed cold rate keeps climbing — the pool is saturated, and the
latency tiers (not the no-failure maximum) are the business-capacity measure.

### 8.4 Comparison with the nested-virt report

The same three models on a two-vCPU nested host (see the nested report) run at
67.4/s (ideal), 52.6/s (shaped) and 40.9/s (realistic pure-cold no-failure)
per microVM with no pinning. On this bare-metal host the physical-core
mapping reaches 183.95/s, 53.06/s and 70.32/s per VM respectively. The ideal
ceiling is 2.7x higher here because each VM owns a whole physical core
instead of an outer-scheduled L1 vCPU; the shaped and realistic rates are
much closer because they are limited by the per-request service path and the
latency budget rather than by raw CPU. For the mixed workload, the nested
host gives
57.2/s ideal and 44.7/s shaped per VM, this host 155.96/s and 39.73/s. The
ideal gap is the same whole-core effect; the shaped mixed rates are close
because this host's mixed knee is set by the warm class (56 agents/lane
reaches 46.06 cold/s per VM but misses the warm tier), while the nested knee
gates on cold only. The host totals are not comparable: the nested report
measures a 2-VM pool, this report a 32/64-VM pool.

### 8.5 Measurement notes

The first offered level of every realistic run is a warm-up and is excluded
(volume-creation writeback, §2.7 item 5). The ideal mixed sweep is bistable:
6 ms is fast in both orders (4990.8 ascending, 4913.1 reverse), 7 ms is fast
or slow depending on order (4494.3 vs 3016.2), and 8 ms is slow in both
(2482.1 / 2399.7, P95 ~17 ms). The slow cycle is a phase-locked self-clocking
effect — the lane's next turn waits on the previous response plus the sticky
window — not a capacity limit; the knee is the stable maximum, 6 ms. The SMT
ideal test's P95 at its knee is high (25 ms) because the host stack is
saturated (sandlot 97 %, gateway 81 % of their 8-logical-CPU budgets); at
longer paced periods its P95 grows further (37 ms at 10 ms, 51 ms at 12 ms)
while the per-VM rate collapses. That test's gate is collisions, not latency;
the realistic and shaped sections are the latency-bounded view. The SMT mixed
runs were not taken because the pure-cold SMT run already misses every ideal
tier and the SMT shaped run spends nearly all its 2.0x headroom at 12 ms.

## 9. Reproduction

The release package ships `e2e/` beside the prebuilt `output/` tree; run from
the extracted package (the `.release-stamp` marker skips the source-freshness
gate) or from a developer tree after `bash build/build.sh all`. Every script
deploys its own throwaway stack under `$DEPLOY_DIR` (default
`/var/lib/sandswap`) and removes it on exit.

The exact commands, environment and per-run parameters behind every table are
in **`baremetal-load-raw/MANIFEST.md`**. In short:

```bash
# 1. Baseline (idle host, one microVM) — take its four P95s
WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  bash e2e/latency-benchmark-aiagent.sh http distributed

# 2. Realistic capacity (example: physical-core mapping, mixed)
PIN_MODE=1 PIN_STACK_LAYOUT="loadgen:0-3,48-51;gateway:4-7,52-55;sandlot:8-11,56-59" \
PIN_RESERVE_CORES=12 POOL_SIZE=32 PIN_SLICE_CPUS=2 PIN_VERIFY_EACH_LEVEL=0 \
LOADTEST_AGENT_LEVELS="10 25 50 100 400 1200 2000 2400 2800 3200" \
LOADTEST_DURATION_SEC=20 LOADTEST_WARMUP_SEC=10 LOADTEST_STICKY_MS=1 \
LOADTEST_REQUESTS_PER_TURN="1:40,2:35,3:25" LOADTEST_LATENCY_TIERS="1.05 1.5 2.0" \
SKIP_ESTIMATE_BENCH=1 WARM_GW_P95_MS=0.868 COLD_GW_P95_MS=2.323 \
WARM_CLIENT_P95_MS=0.979 COLD_CLIENT_P95_MS=2.488 \
  bash e2e/latency-benchmark-load.sh

# 3. Ideal test (physical-core mapping): pure cold and mixed
POOL_SIZE=32 PIN_SLICE_CPUS=2 LOADTEST_WORKLOAD=ideal LOADTEST_LANES=32 \
  LOADTEST_TURN_PERIODS_MS="5 6 7" LOADTEST_REQUESTS_PER_TURN=1 \
  LOADTEST_DURATION_SEC=30 ... (same refs/allocation)

POOL_SIZE=32 PIN_SLICE_CPUS=2 LOADTEST_WORKLOAD=ideal LOADTEST_LANES=32 \
  LOADTEST_TURN_PERIODS_MS="5 6 7 8" \
  LOADTEST_REQUESTS_PER_TURN="1:40,2:35,3:25" \
  LOADTEST_DURATION_SEC=30 ... (same refs/allocation)

# 4. Traffic-shaped test (physical-core mapping): pure cold and mixed
POOL_SIZE=32 PIN_SLICE_CPUS=2 LOADTEST_WORKLOAD=shaped LOADTEST_LANES=32 \
  LOADTEST_TURN_PERIODS_MS="6 8 10" LOADTEST_SHAPED_AGENTS_PER_LANE=64 \
  LOADTEST_REQUESTS_PER_TURN=1 LOADTEST_DURATION_SEC=20 ... (same refs/allocation)

POOL_SIZE=32 PIN_SLICE_CPUS=2 LOADTEST_WORKLOAD=shaped LOADTEST_LANES=32 \
  LOADTEST_TURN_PERIODS_MS="10 12 14" LOADTEST_SHAPED_AGENTS_PER_LANE=48 \
  LOADTEST_REQUESTS_PER_TURN="1:40,2:35,3:25" \
  LOADTEST_DURATION_SEC=20 ... (same refs/allocation)
```

For the logical-core mapping use `POOL_SIZE=64 PIN_SLICE_CPUS=1` and the same
stack layout; the ideal/shaped lanes equal the pool size (64). The SMT runs
are for comparison only: ideal `8 10 12`, shaped `8 10 12` with 25
agents/lane, and no
mixed SMT run. The first offered level of each realistic run is the warm-up and
is excluded from the tables; the shaped population is sized to the lane's
service ceiling (64 per lane pure cold, 48 mixed on the physical mapping, 25
per lane on SMT).

## Appendix: raw data

The complete stdout/stderr of every run (including the per-level and
per-period detail) is kept in **`baremetal-load-raw/`** beside this report.
The mixed runs are `14-ideal-phys-mixed.log` and
`18-ideal-phys-mixed-rev.log` (ideal, ascending and reverse order),
`15-shaped-phys-mixed.log` (64 agents/lane, over-offer),
`16-shaped-phys-mixed-48.log` (the knee) and `17-shaped-phys-mixed-56.log`
(the warm-tier near-miss). The exact commands, host facts and SHA256 are in
`baremetal-load-raw/MANIFEST.md`.
