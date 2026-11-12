---
title: Raw logs — bare-metal latency benchmark
nav_exclude: true
---

# Raw logs — bare-metal latency benchmark

Raw stdout/stderr of the `e2e/latency-benchmark-aiagent.sh` and
`e2e/latency-benchmark-unmount.sh` runs that back
`docs/benchmark/baremetal.md`.

## Host

| Item | Value |
|------|-------|
| Host | TencentOS Server 4 cloud bare metal, `systemd-detect-virt=none` |
| CPU | Intel Xeon Platinum 8255C @ 2.50 GHz, 2 sockets, 96 threads, 2 NUMA nodes |
| Host kernel | 6.6.117-45.14.2.tl4.x86_64 |
| Binaries | prebuilt release package |
| Pinning | on (`e2e/pin.sh`, stack CPUs 16-23,64-71; VM slices 13,61 / 14,62 / 15,63) |
| Background | Tencent cloud monitoring agents (barad/stargate) stopped for the run |

## Files

| File | Content |
|------|---------|
| `aiagent-http-single.log` | `http single`, `WARM_N=100 COLD_N=50 BENCH_VERBOSE=1` |
| `aiagent-http-distributed.log` | `http distributed`, same |
| `aiagent-mcp-single.log` | `mcp single` (DeepSeek), same |
| `aiagent-mcp-distributed.log` | `mcp distributed` (DeepSeek), same |
| `unmount-all.log` | `latency-benchmark-unmount.sh all` (ITER_N=20 per scenario) |

## Commands

```bash
WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  bash e2e/latency-benchmark-aiagent.sh http single
WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  bash e2e/latency-benchmark-aiagent.sh http distributed
DEEPSEEK_API_KEY=sk-... WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  bash e2e/latency-benchmark-aiagent.sh mcp single
DEEPSEEK_API_KEY=sk-... WARM_N=100 COLD_N=50 BENCH_VERBOSE=1 \
  bash e2e/latency-benchmark-aiagent.sh mcp distributed
bash e2e/latency-benchmark-unmount.sh all
```

## SHA256

```
ee2994225bf77bff97fc8ab6aed7e1c37fccd0880aeda765b4c60e7ea4bb1d73  aiagent-http-single.log
505ff714860db6e66de830d27709623fa2041aee376630982f2b74d6412ba2bb  aiagent-http-distributed.log
c393b08f029fe39886ead75d722ac208f690b8f4ff8a65a0f786be0cb33fc2c4  aiagent-mcp-single.log
46fdf193bc3812e7c28432fee64df7d476e47a0b17d49bbe18c5ad9687b3ae66  aiagent-mcp-distributed.log
b7be7397f8ca6fdf3e45b371f7f8259603a9a91e809beb7f1149e780fd754316  unmount-all.log
```
