# Script matrix — every .sh under e2e/

Generated 2026-11-26T07:49:12Z · repo 1e5cf6e95e6b · tree_dirty=0 · boot `6ab23126`
Heads (row counts): 1e5cf6e95e6b=69
Enumerated **69** scripts · rows **69** · FAIL=2 · PASS=67

| script | class | verdict | secs | reason / finding |
|---|---|---|---|---|
| `e2e/benchmark-overlayfs.sh` | A | PASS | 7 |  |
| `e2e/build-gate-selftest.sh` | C | PASS | 0 |  |
| `e2e/common.sh` | F | PASS | 0 | library — validated through e2e/smoke.sh |
| `e2e/config-hotreload.sh` | A | PASS | 230 |  |
| `e2e/cross-tenant-residue.sh` | A | PASS | 13 |  |
| `e2e/deploy-tree-pins.sh` | C | PASS | 29 |  |
| `e2e/disconnect-tolerance.sh` | A | PASS | 113 |  |
| `e2e/dns-staleness.sh` | A | PASS | 15 |  |
| `e2e/docs-truth.sh` | A | PASS | 2 |  |
| `e2e/egress-identity.sh` | A | PASS | 18 |  |
| `e2e/eino-agent-mcp.sh` | A | PASS | 168 |  |
| `e2e/exec-timeout-policy.sh` | A | PASS | 55 |  |
| `e2e/file-api.sh` | A | PASS | 8 |  |
| `e2e/framework-unit.sh` | C | PASS | 6 |  |
| `e2e/harness-fault-injection.sh` | A | PASS | 8 |  |
| `e2e/host-exec-paths.sh` | A | PASS | 0 |  |
| `e2e/host-id-check.sh` | C | PASS | 0 |  |
| `e2e/kernel-config-gate.sh` | A | PASS | 0 |  |
| `e2e/latency-benchmark-aiagent.sh` | A | PASS | 39 |  |
| `e2e/latency-benchmark-alloc-sweep.sh` | C | PASS | 0 |  |
| `e2e/latency-benchmark-load.sh` | A | PASS | 270 |  |
| `e2e/latency-benchmark-unmount.sh` | A | PASS | 18 |  |
| `e2e/lifecycle-split-gateway.sh` | A | PASS | 33 | residue:procs:2605876 ,taps:tap-c67bfb4c60 |
| `e2e/load-shed.sh` | A | PASS | 18 |  |
| `e2e/mcp.sh` | A | PASS | 12 |  |
| `e2e/memory-identity-persistence.sh` | A | PASS | 7 |  |
| `e2e/mount-identity-race.sh` | C | PASS | 5 |  |
| `e2e/multi-agents.sh` | A | PASS | 11 |  |
| `e2e/multi-instance-orphan-safety.sh` | A | FAIL | 11 | rc=1 |
| `e2e/oci-registry.sh` | A | PASS | 12 |  |
| `e2e/oci-template-import.sh` | A | PASS | 10 |  |
| `e2e/oidc-keycloak.sh` | A | PASS | 34 |  |
| `e2e/overlayfs-isolation.sh` | A | PASS | 52 |  |
| `e2e/ownership.sh` | A | PASS | 101 |  |
| `e2e/parallel-exec.sh` | A | PASS | 35 |  |
| `e2e/pin.sh` | F | PASS | 0 | library — validated through e2e/latency-benchmark-aiagent.sh |
| `e2e/pool-concurrency.sh` | C | PASS | 8 |  |
| `e2e/protocol-version-e2e.sh` | A | PASS | 139 |  |
| `e2e/readopt-restart-id-unique.sh` | A | PASS | 8 |  |
| `e2e/resilience-e2e.sh` | A | PASS | 30 |  |
| `e2e/resilience.sh` | A | PASS | 103 |  |
| `e2e/routed-ipv6.sh` | A | PASS | 26 |  |
| `e2e/run-matrix.sh` | F | PASS | 0 | library — validated through e2e/framework-unit.sh |
| `e2e/sandfs-delete-lifecycle.sh` | A | PASS | 15 |  |
| `e2e/scale-rehearsal.sh` | A | PASS | 91 |  |
| `e2e/seccomp.sh` | A | FAIL | 9 | rc=1 |
| `e2e/self-pressure-gate.sh` | A | PASS | 26 |  |
| `e2e/share-root-gate.sh` | A | PASS | 7 |  |
| `e2e/single-node-multi-agent.sh` | C | PASS | 153 |  |
| `e2e/smoke.sh` | A | PASS | 23 |  |
| `e2e/staleness-gateway-e2e.sh` | A | PASS | 9 |  |
| `e2e/staleness-routing-e2e.sh` | A | PASS | 11 |  |
| `e2e/sticky-default-window.sh` | A | PASS | 6 |  |
| `e2e/stream-tls-require-ca.sh` | A | PASS | 3 |  |
| `e2e/switch-under-adversarial.sh` | A | PASS | 147 | residue:procs:2670550 2670584 2670995 ,taps:tap-1a3a7a4eb3 ,ports::3001 :3100 :9998 |
| `e2e/template-lifecycle.sh` | A | PASS | 6 |  |
| `e2e/template-ref-isolation.sh` | A | PASS | 9 |  |
| `e2e/template-swap.sh` | A | PASS | 6 |  |
| `e2e/vmm-api-auth.sh` | A | PASS | 1 |  |
| `e2e/vmm-crash-selfheal.sh` | A | PASS | 164 |  |
| `e2e/vmm-seccomp.sh` | C | PASS | 46 |  |
| `e2e/volume-seed-injection.sh` | A | PASS | 43 |  |
| `e2e/volume-seed-rotation.sh` | A | PASS | 9 |  |
| `e2e/vsockguard-verify-modes.sh` | C | PASS | 0 |  |
| `e2e/warden-chroot-escape.sh` | C | PASS | 157 |  |
| `e2e/warden-hostile.sh` | A | PASS | 118 |  |
| `e2e/warden-log-leak-guard.sh` | A | PASS | 26 |  |
| `e2e/warden-timing-probe.sh` | C | PASS | 21 |  |
| `e2e/warden-unit.sh` | A | PASS | 30 |  |

## Self-check

- enumerated == rows: **True** (69 enumerated, 69 rows)
- missing: none
- duplicate: none
- library rows without a consumer verdict: none
