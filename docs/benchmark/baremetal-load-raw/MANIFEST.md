---
title: Raw logs — bare-metal microVM reuse capacity benchmark
nav_exclude: true
---

# Raw logs — bare-metal microVM reuse capacity benchmark

Raw stdout/stderr of the `e2e/latency-benchmark-aiagent.sh` and
`e2e/latency-benchmark-load.sh` runs that back
`docs/benchmark/baremetal-load.md`.

## Host

| Item | Value |
|------|-------|
| Host | TencentOS Server 4 cloud bare metal, `systemd-detect-virt=none` |
| CPU | Intel Xeon Platinum 8255C @ 2.50 GHz, 2 sockets × 24 cores, 96 SMT threads, 2 NUMA nodes |
| Host kernel | 6.6.117-45.14.2.tl4.x86_64 |
| Binaries | prebuilt release package (scripts and binaries from the same tree) |
| Pinning | host stack on 12 whole cores (loadgen 0-3/48-51, gateway+human+etcd 4-7/52-55, sandlot+prov 8-11/56-59); VM pool on the other 36 whole cores (12-47, 60-95) |
| Background | cloud-vendor monitoring agents stopped |

## Allocation and mappings

`PIN_MODE=1 PIN_STACK_LAYOUT="loadgen:0-3,48-51;gateway:4-7,52-55;sandlot:8-11,56-59" PIN_RESERVE_CORES=12 PIN_VERIFY_EACH_LEVEL=0`

- Physical-core mapping: `POOL_SIZE=32 PIN_SLICE_CPUS=2` (one microVM per whole core, 36 slices, 4 spare).
- Logical-core (SMT) mapping: `POOL_SIZE=64 PIN_SLICE_CPUS=1` (one microVM per logical CPU, 72 slices, 8 spare).

## Files

| File | Content |
|------|---------|
| `00-baseline.log` | `latency-benchmark-aiagent.sh http distributed`, `WARM_N=100 COLD_N=50 BENCH_VERBOSE=1` (idle host) |
| `10-warmmix-phys.log` | realistic warm-mix, physical-core mapping, levels `10 25 50 100 400 1200 2000 2400 2800 3200` |
| `11-coldonly-phys.log` | realistic cold-only, physical-core mapping, levels `10 50 100 400 1200 2000 2400 2800 3200` |
| `12-ideal-phys.log` | ideal paced lanes, physical-core mapping, lanes 32, periods `5 6 7` ms, pure cold |
| `13-shaped-phys-64.log` | traffic-shaped, physical-core mapping, lanes 32, periods `6 8 10` ms, 64 agents/lane, pure cold |
| `13-shaped-phys-72-overoffer.log` | traffic-shaped, physical-core mapping, lanes 32, periods `6 8 10` ms, 72 agents/lane, pure cold (over-offer point) |
| `14-ideal-phys-mixed.log` | ideal paced lanes, physical-core mapping, lanes 32, periods `5 6 7 8` ms, mixed turns `1:40,2:35,3:25` |
| `15-shaped-phys-mixed.log` | traffic-shaped, physical-core mapping, lanes 32, periods `8 10 12 14` ms, 64 agents/lane, mixed turns (over-offer point; the gate fails because both classes exceed the 2.0x tier) |
| `16-shaped-phys-mixed-48.log` | traffic-shaped, physical-core mapping, lanes 32, periods `10 12 14` ms, 48 agents/lane, mixed turns (the mixed knee at 12 ms) |
| `17-shaped-phys-mixed-56.log` | traffic-shaped, physical-core mapping, lanes 32, periods `12 14` ms, 56 agents/lane, mixed turns (cold fits, warm misses the tier at 14 ms) |
| `18-ideal-phys-mixed-rev.log` | the same mixed ideal probe in reverse period order `8 7 6` ms (stability check) |
| `20-warmmix-smt.log` | realistic warm-mix, logical-core mapping, levels `10 50 100 400 800 1200 1600 2000 2400 2800 3200` |
| `21-coldonly-smt.log` | realistic cold-only, logical-core mapping, same levels |
| `22-ideal-smt.log` | ideal paced lanes, logical-core mapping, lanes 64, periods `8 10 12` ms, pure cold (control) |
| `23-shaped-smt.log` | traffic-shaped, logical-core mapping, lanes 64, periods `8 10 12` ms, 25 agents/lane, pure cold (control) |
| `diag-firstlevel.log` | first-level diagnosis: warm-mix physical, levels `10 10 25` with only 25 agents created (the 10-agent level is clean, showing the first-level transient is volume-creation writeback, not per-VM first use) |

## Commands

Baseline (take its four P95s as the tier references):

```bash
WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  bash e2e/latency-benchmark-aiagent.sh http distributed
```

Realistic capacity — common env (all four runs):

```bash
PIN_MODE=1 PIN_STACK_LAYOUT="loadgen:0-3,48-51;gateway:4-7,52-55;sandlot:8-11,56-59" \
PIN_RESERVE_CORES=12 PIN_SLICE_CPUS=<2|1> PIN_VERIFY_EACH_LEVEL=0 \
POOL_SIZE=<32|64> LOADTEST_AGENT_LEVELS="<level list above>" \
LOADTEST_DURATION_SEC=20 LOADTEST_WARMUP_SEC=10 LOADTEST_STICKY_MS=1 \
LOADTEST_INTRA_TURN_GAP_MS=0 \
LOADTEST_REQUESTS_PER_TURN="<1:40,2:35,3:25 | 1>" \
LOADTEST_LATENCY_TIERS="1.05 1.5 2.0" SKIP_ESTIMATE_BENCH=1 \
WARM_GW_P95_MS=0.868 COLD_GW_P95_MS=2.323 \
WARM_CLIENT_P95_MS=0.979 COLD_CLIENT_P95_MS=2.488 KEEP_LOGS=1 \
  bash e2e/latency-benchmark-load.sh
```

Ideal probe — pure cold (physical; SMT control uses lanes 64, periods `8 10 12`):

```bash
... LOADTEST_WORKLOAD=ideal LOADTEST_LANES=32 \
    LOADTEST_TURN_PERIODS_MS="5 6 7" \
    LOADTEST_REQUESTS_PER_TURN=1 LOADTEST_DURATION_SEC=30 ...
```

Ideal probe — mixed turns (physical):

```bash
... LOADTEST_WORKLOAD=ideal LOADTEST_LANES=32 \
    LOADTEST_TURN_PERIODS_MS="5 6 7 8" \
    LOADTEST_REQUESTS_PER_TURN="1:40,2:35,3:25" LOADTEST_DURATION_SEC=30 ...
```

Reverse-order stability check (physical): the same command with
`LOADTEST_TURN_PERIODS_MS="8 7 6"`.

Traffic-shaped probe — pure cold (physical; SMT control uses lanes 64,
periods `8 10 12`, 25 agents/lane):

```bash
... LOADTEST_WORKLOAD=shaped LOADTEST_LANES=32 \
    LOADTEST_TURN_PERIODS_MS="6 8 10" \
    LOADTEST_SHAPED_AGENTS_PER_LANE=<64|72> LOADTEST_REQUESTS_PER_TURN=1 \
    LOADTEST_DURATION_SEC=20 ...
```

Traffic-shaped probe — mixed turns (physical): the 48-agents/lane run is the
knee; 56 and 64 are the over-offer brackets.

```bash
... LOADTEST_WORKLOAD=shaped LOADTEST_LANES=32 \
    LOADTEST_TURN_PERIODS_MS="<10 12 14 | 12 14 | 8 10 12 14>" \
    LOADTEST_SHAPED_AGENTS_PER_LANE=<48|56|64> \
    LOADTEST_REQUESTS_PER_TURN="1:40,2:35,3:25" LOADTEST_DURATION_SEC=20 ...
```

The first offered level of every realistic run (10 agents) is a warm-up and is
excluded from the report tables. The shaped period sweep's first row is the
shortest period tested (an over-offer point at 6 ms physical / 8 ms SMT for
pure cold; at 10 ms for the 48-agents/lane mixed run). No mixed SMT ideal or
shaped run was taken; the report explains why in §3.3 and §4.3.

## SHA256

```
dc9e84e978200b624a45c9d099b159d1348892e33fdbbfcabbc70346983268b5  00-baseline.log
df78b21b2e43d06101f1358a09ebf02c4f8d0b6e295467fb594928fc250e92de  10-warmmix-phys.log
ff202c87f0310461c384d6d183a50954db1a77bdd7f1bef3425b30a16c8a4a20  11-coldonly-phys.log
92496358111516687200de2ddcc074bfeae9cf267071d4b56b9056c16dd8a041  12-ideal-phys.log
382d4c93ca2efcd1660af689c3ce579baf6f3d94690362b479ca66c005058add  13-shaped-phys-64.log
9f22a82344b950bfd67e0714dffca5aeed26997f453a91c9b0938ef81de46e0b  13-shaped-phys-72-overoffer.log
14c2b72b6bf49c32fec2ba5756410c666ce612df266dc36d9ec0c7b7ed5127ea  14-ideal-phys-mixed.log
d35543d3bafd6580724363dcef4732243352d3cd9d01eff2dec60378c542c80b  15-shaped-phys-mixed.log
1b68538079b735b49a323897561cd8bee2cdfd8b3037f3a5d85ea9107e7d1c64  16-shaped-phys-mixed-48.log
eeac3e1da45ff604173d971f4d883bebde4c82b987db78efb8cd5b7936f095d3  17-shaped-phys-mixed-56.log
3be7de2bcbd29d4a88f48c6b164bd021b9f13f3b39e851726af8f28a7356f48d  18-ideal-phys-mixed-rev.log
16db7d04dbacb0b753542f7c5d4face4cfac3a22f384a5d31056ba3f1af2fb24  20-warmmix-smt.log
15920ad8c6e7e442db9e889a79c8a45acecde23397e0ce056329c617520fda33  21-coldonly-smt.log
4cc04024aa4437a74e32fe5849f164f4783f212611461b70cb97146d6a67ae82  22-ideal-smt.log
876adadddf0a9fd80b2a7255107bb85c3de335cc22f7053986123da6207bb328  23-shaped-smt.log
141b8f58708a3c623947e7782595f4f3875292c229347c32f2f1110e2c70ac65  diag-firstlevel.log
```
