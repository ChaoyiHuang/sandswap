# Raw logs — nested-virt latency benchmark

Raw stdout/stderr of the `e2e/latency-benchmark-aiagent.sh` and
`e2e/latency-benchmark-unmount.sh` runs that back
`docs/benchmark/nested-virt.md`.

## Host

| Item | Value |
|------|-------|
| Host | GCP VM, `systemd-detect-virt=google`, nested KVM |
| CPU | Intel Xeon 2.30 GHz, 2 cores / 4 threads, 1 NUMA node |
| RAM | 5 GiB |
| Host kernel | 7.0.0-1014-gcp |
| Pinning | none (nested virt) |

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
4179c901b8230fd28c1feced908636e620aca536b2f75bb0654a5760349bb3e0  aiagent-http-single.log
069dd0265f8b7b5946747bcd70ac33970a4b4a8e4e062aade1228a8922164430  aiagent-http-distributed.log
3b415c88a948a18ec3b23a6d122928093e733e2a9c501dac7e97715e507c32ce  aiagent-mcp-single.log
d31da71cafc4c6c4d5b9755938fcfcd677a3b51bd841f03f5d73bb45f8fad0ae  aiagent-mcp-distributed.log
e10ee28d175978154aea5e24c6b7af6fa3365b1584291ebb7c53afd0b55c0153  unmount-all.log
```
