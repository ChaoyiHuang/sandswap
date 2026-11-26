---
title: Claude Code over MCP
nav_order: 6
parent: Benchmark
---

# Claude Code over MCP: validation summary

On **2026-11-26**, three real Claude Code coding runs passed against SandSwap
over HTTPS MCP. Each run repaired the community example's two buggy functions,
passed all five original tests without changing them, committed `fix calc`,
and passed independent arithmetic/Fibonacci checks.

This report summarizes the measured results and fixes. Session transcripts,
per-test logs, generated configuration, credentials, host addresses, and local
filesystem identifiers are intentionally excluded from this submission.

## Configuration and method

| Component | Tested configuration |
|---|---|
| Source | Community base `baa4e8f`; validator/analyzer at `1e5cf6e`; E2E harness fixes at `6126eb8` |
| Client | Existing local Claude Code **2.1.77**, macOS **26.3.1 (a)**, arm64 |
| Model | Real `glm-5.3-flash`, official Anthropic-compatible endpoint |
| Connection | Mac → loopback SSH forward → Linux HTTPS gateway `/mcp` |
| Authentication | Explicit deployment CA; certificate and hostname verification enabled; both agent authentication headers |
| Host | Dedicated Linux test environment; 2 × Xeon Gold 6248R, 48 cores / 96 threads, approximately 376 GiB RAM; kernel `6.8.0-149-generic` |
| Sandbox | Single-node systemd deployment, `medium:3` pool, flat `ubuntu:24.04` SandFS, 2 vCPUs / 512 MiB |

Claude Code remained on the Mac. The validator used isolated configuration,
`--tools ''`, `--allowedTools mcp__sandswap`, `--permission-mode dontAsk`, and
strict MCP configuration. The model had only SandSwap tools; it received the
task text directly and could not use local shell or file tools. The seed was
reset before each run. All three runs used the same service build from the
community base; the changes here affect examples, tests, and documentation.

The [example README](../../examples/claude-code/README.md#repeatable-headless-validation-including-a-mac-client)
documents reproduction. [`validate.py`](../../examples/claude-code/validate.py)
requires actual typed tool calls and matching results, then independently
checks sandbox state. Model credentials are supplied through the environment.

## Coding-loop results

| Run | Result | CLI wall time | CLI-reported model API time | Transcript task span | Tool wall time | MCP calls |
|---|---|---:|---:|---:|---:|---:|
| 1 | PASS | 43.957 s | 41.614 s | 42.59 s | 0.98 s | 6 |
| 2 | PASS | 33.849 s | 31.640 s | 32.72 s | 1.21 s | 5 |
| 3 | PASS | 47.016 s | 44.541 s | 45.87 s | 1.42 s | 6 |

Every run exercised `list_sandfs`, `execute`, `file_read`, and `file_write`.
Across **17 MCP calls**, there were no local tool calls, permission denials,
or tool errors. Each run ended with unchanged original tests passing 5/5,
the requested source-fix commit, a clean Git working tree, and passing
independent checks (additional arithmetic, Fibonacci 0–20, and negative input).

Tool wall time was **2.3%–3.7%** of the transcript span; most time was spent
waiting for or receiving model responses. The CLI timer includes process
startup/shutdown; the transcript starts at the initial user prompt; parallel
tool waits count once. The API timer is reported by Claude Code.

The six execute calls took **88.602–155.720 ms** inside the gateway, including
Python tests and Git operations. Gateway time minus guest execution time was
**0.454–0.687 ms**. Separate 30-call no-op samples on the same SandFS had median
guest execution times of **4.3, 4.2, and 3.7 ms**. These include guest process
startup and are not pure dispatch measurements.

One execute measured 192 ms at the client, 127.447 ms in the gateway, and
126.993 ms in the guest. The approximately 64.6 ms client–gateway residual
includes client scheduling/serialization and SSH transport; it is not a
direct network or TLS measurement. File/list tools do not expose separate
server timings. Three coding runs cannot establish a task P95 or capacity
limit, and CLI cost estimates are not verified provider billing data.

## Complete repository round and retests

The original **`bash run-round.sh`**, without `--fast`, ran at `1e5cf6e` with
a fresh ledger and real GLM credentials for agent cases. It covered both
default trees (`e2e deploy`) and took **80 min 46 s**. Its exit code was **1**:

| Tree | Rows | PASS | FAIL | BLOCKED-PRODUCT | SKIP / not run |
|---|---:|---:|---:|---:|---:|
| E2E | 69 | 67 | 2 | 0 | 0 |
| Deploy | 36 | 35 | 0 | 1 | 0 |

Both failed E2E rows were test-harness defects, fixed at `6126eb8`:

| Failure | Cause and fix | Targeted retest |
|---|---|---|
| `multi-instance-orphan-safety.sh` | `wait` ran in command substitution, outside the shell owning the child, producing incorrect exit status. Reap in the parent shell and return the status through `RL_WAIT_RC`; guard nonzero exits under `set -e`. | PASS, 13 s; four independent child-exit/timeout cases also passed |
| `seccomp.sh` | Old-header fallback numbers for `statmount/listmount` were 454/455 (futex operations) instead of x86_64 457/458. Correct the probe constants; retain the seccomp policy and expected `EPERM` assertions. | PASS, 9 s; intended syscalls denied with `EPERM` |

Both targeted commands exited 0. The original full-round failures remain in
the totals above. Combining those results with successful targeted reruns
does **not** constitute another complete 69-row run.

The deploy gate passed under the runner's classification rules. The one
`BLOCKED-PRODUCT` was the standalone boxout host-setup script correctly refusing
to change an existing bare-metal service identity to its reserved UID. Actual
embedded and boxout K8s deployments, and both real-agent verifiers, passed.
The verifier is one matrix row but executed separately in both deployment modes.
The default scope includes the allocation-sweep planner, multi-host deployer
dry-run, and two default K8s egress scenarios; it is not every possible
deployment or parameter combination.

The same round's native HTTP microbenchmarks used same-host transport and
BusyBox microcommands, unlike the Mac/Ubuntu coding loop:

| Measurement | Samples | Client P50 | Client P95 | Gateway P95 |
|---|---:|---:|---:|---:|
| Sticky warm lease | 100 | 0.890 ms | 0.950 ms | 0.841 ms |
| Cross-agent cold mount/execute | 100 | 1.860 ms | 1.974 ms | 1.851 ms |

At 80 simulated agents / four VMs, load reached **122.8 requests/s**, including
66.7 cold executions/s. Cold/warm client P95 was 2.657/1.150 ms and gateway P95
was 2.515/1.009 ms. The 2× baseline gate passed with zero terminal 503 responses
and three busy retries; no tested level passed the 1× gate. The pool remained
unsaturated, so this is a measured lower bound, not a capacity ceiling.

**Legacy agent-test limitation:** some Eino checks accept a background marker
in model prose without verifying a background tool call. Only the single-node
four-agent case and K8s boxout verifier showed `background=true` calls; the
dual-agent, bare-metal, and embedded verifiers did not. Their PASS verdicts do
not prove model-driven background execution in every mode. Independent HTTP
background-lifecycle assertions and the deterministic 12-tool MCP suite passed
separately. The new Claude validator requires actual tool-use evidence.

## Other fixes and preparation findings

| Finding | Resolution |
|---|---|
| Session analysis omitted initial model wait, split streamed response blocks, and double-counted parallel waits. | Include the initial prompt, group by provider message ID, and count overlapping tool waits once. Label unmeasured client/transport time as residual. |
| Analyzer assumed a local Linux endpoint and disabled TLS checks. | Honor the configured MCP URL and CA, including an SSH-forwarded endpoint, with certificate and hostname verification. |
| README test command piped output through `tail`, masking test failure status. | Run `unittest` directly before reading the Git log. |
| A Python model probe lacked a usable default CA path; IPv6 connections stalled. | Use the system CA bundle and IPv4 for that probe; retain certificate verification. |
| A preliminary model probe supplied an unsupported thinking option. | Remove that option; the real completion then returned HTTP 200. |
| Restrictive wrapper umask made generated gateway configuration unreadable by its service. | Correct generated configuration permissions and deploy with the expected umask; keep credential files private. |
| Distro libbpf 0.5 could not parse host BTF. | Link the unchanged guard utility with official libbpf 1.4.7; live allowed/denied-identity checks passed without bypassing the guard. |
| Fixture port conflicts and dependency-download restrictions affected preparation. | Apply temporary test-environment port/proxy settings and use verified cached dependencies; restore original settings afterward. |
| Initial root-only warden unit run reported `No child processes` (23 passed, 1 failed). | An unchanged build rerun and the full round's warden-unit row passed. This remains an observed intermittent failure, not a diagnosed or fixed cause. |

The validator/analyzer regression suite passed **9/9**. The two E2E fixes
above change probe behavior, not service behavior or the warden filter.
Temporary deployments, forwarding, and credentials were removed after testing;
original host configuration and previously active services were restored.
