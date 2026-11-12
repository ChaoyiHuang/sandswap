---
title: Raw logs — nested-virt microVM reuse capacity
nav_exclude: true
---

# Raw logs — nested-virt microVM reuse capacity

Raw stdout/stderr of the `e2e/latency-benchmark-aiagent.sh` and
`e2e/latency-benchmark-load.sh` runs that back
`docs/benchmark/nested-virt-load.md`. ANSI escape sequences are preserved.
The files live beside the report; the directory is self-contained, including
the baseline log.

## Host

| Item | Value |
|------|-------|
| Host | GCP VM, `systemd-detect-virt=google`, nested KVM |
| CPU / RAM | 4 vCPUs = 2 physical cores × 2 SMT threads, one NUMA node, 5 GiB |
| Guest | 1 vCPU / 256 MiB / 3 exec slots (the benchmark's `bench` spec) |
| Stack | one-machine-etcd: exec gateway :3001 + human gateway :3100 + etcd, one merged exec,prov sandlot |
| VM pool | 2 microVMs (the other two vCPUs carry the host stack) |
| Pinning | none (`PIN_MODE=0`) |

## Files

| File | Content |
|------|---------|
| `aiagent-nested-baseline.log` | `http distributed`, `WARM_N=100 COLD_N=50 BENCH_VERBOSE=1` (100 warm + 100 cold samples) |
| `load-agents-mixed.log` | realistic AI agent workload (`-workload agents`), agents 5/10/20/40/80/160/320 |
| `load-agents-cold.log` | realistic cold-only workload (`LOADTEST_REQUESTS_PER_TURN=1`), agents 10/25/50/100/200/400 |
| `load-ideal-cold.log` | ideal probe, cold-only, 2 paced lanes, periods 14-22 ms |
| `load-ideal-mixed.log` | ideal probe, mixed turns, 2 paced lanes, periods 14-28 ms |
| `load-shaped.log` | shaped probe, mixed turns (auto hold — this stack's unmount P95 6.291 ms → 9 ms), periods 14-28 ms |
| `load-shaped-cold.log` | shaped probe, cold-only (auto hold — unmount P95 7.544 ms → 10 ms), periods 14-28 ms |
| `load-shaped-nohold.log` | shaped control WITHOUT the hold budget, periods 16-32 ms |
| `load-shipped-policy.log` | shipped recycle policy control, agents 80/160/320 |

## Commands

All load runs share the baseline references measured by the first command:
`WARM_GW_P95_MS=3.778 COLD_GW_P95_MS=7.799 WARM_CLIENT_P95_MS=4.238
COLD_CLIENT_P95_MS=8.382`, `POOL_SIZE=2`, 20 s window + 5 s warm-up,
`LOADTEST_STICKY_MS=1`, `SKIP_ESTIMATE_BENCH=1`.

```bash
# baseline
WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  bash e2e/latency-benchmark-aiagent.sh http distributed

# realistic mixed / cold-only
POOL_SIZE=2 LOADTEST_AGENT_LEVELS="5 10 20 40 80 160 320" ... # cold-only: AGENT_LEVELS="10 25 50 100 200 400" REQUESTS_PER_TURN=1

# ideal cold / mixed
POOL_SIZE=2 LOADTEST_WORKLOAD=ideal LOADTEST_LANES=2 \
  LOADTEST_TURN_PERIODS_MS="14 16 18 19 20 22" LOADTEST_REQUESTS_PER_TURN=1 ... # mixed: PERIODS="14 16 18 20 22 24 26 28" (default turns)

# shaped mixed / shaped cold-only / no-hold control
POOL_SIZE=2 LOADTEST_WORKLOAD=shaped LOADTEST_LANES=2 \
  LOADTEST_TURN_PERIODS_MS="14 16 18 20 24 28" LOADTEST_SHAPED_HOLD_MS=auto ... # control: PERIODS="16 18 20 24 28 32" HOLD_MS=0

# shipped recycle policy
POOL_SIZE=2 LOADTEST_AGENT_LEVELS="80 160 320" LOADTEST_RECYCLE_POLICY=shipped ...
```

## SHA256

```
73c91e639a9978e85f7116f8bd7c48fe3018ff707fcb2a10e715e26d75c8170d  aiagent-nested-baseline.log
b006aa90b2f95b0e4a5f4a8b0b82ff5dfaf2325426b458a729bbdb1fec2c4cac  load-ideal-cold.log
b309b5bae8c681b750d0e2a863b72fc1529bb975ebd4d9370a790d8edb03ae3a  load-ideal-mixed.log
d42d1adca897486b2b21bbe63168016898a5c49cbc3880840627d5c9bf3cfaed  load-agents-cold.log
be2e9fa4ce10281b8815fa2b566f4940996d3457cae68f928a16b4d3ad202fce  load-agents-mixed.log
dea722b0f2dc92fa8b3f48d5c2b319472d056239e9ee94002a093b4e24f229b0  load-shaped-nohold.log
a83f5f458497dbb7bc4bf6f112853082f669d84f3a7019e4db70a73015b74a4f  load-shaped.log
a7e7c982bf773aae8fd9a65b7d4c303a6d1c4e3926fb97d5e42ba29f347e17f8  load-shipped-policy.log
e3b2f1fd9be706054c656310fa97624f1bb42625ac4745b3c65f1033bad95fc4  load-shaped-cold.log
```
