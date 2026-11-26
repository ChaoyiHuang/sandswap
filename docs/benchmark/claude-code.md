---
title: Claude Code over MCP
nav_order: 6
parent: Benchmark
---

# Claude Code over MCP: Mac client and GLM

Three real Claude Code coding runs passed through the SandSwap HTTPS MCP
endpoint. Each run started from the community example's failing seed, repaired
the two functions, passed the five original tests without changing them, and
committed `fix calc`. Independent arithmetic/Fibonacci checks also passed.

This is an integration snapshot measured on **2026-11-26**, with three task
runs, not a latency percentile or a capacity claim. It does not replace the
same-host HTTP/MCP measurements in the [bare-metal report](baremetal.md).

## Configuration and evidence

| Component | Tested configuration |
|---|---|
| Community base | `baa4e8f`, latest main fetched for this test |
| Full-round source | `1e5cf6e95e6be8a37dc831f8e8a52e3ecfea265c` |
| Client | Existing Claude Code **2.1.77**, macOS **26.3.1 (a)**, arm64 |
| Model | Real `glm-5.3-flash`, official `https://open.bigmodel.cn/api/anthropic` |
| MCP path | Mac → loopback SSH forward → HTTPS gateway `/mcp` on the Linux host |
| TLS/authentication | Deployment CA trusted explicitly; certificate and hostname verification enabled; both agent auth headers |
| Linux host | Bare metal; 2 × Intel Xeon Gold 6248R, 48 cores / 96 threads, 385384 MiB RAM; kernel `6.8.0-149-generic` |
| SandSwap deployment | Single-node systemd; `medium:3` pool; flat `ubuntu:24.04` SandFS requested with 2 vCPUs / 512 MiB |
| Build tools | Go 1.26.3, Rust 1.99.1; source-pinned guest kernel 7.2.8 |
| Host guard | BPF LSM active; vsockguard allowed service UID and denied nobody/VMM UID in live probes |
| Permissions | `--tools ''`, `--allowedTools mcp__sandswap`, `--permission-mode dontAsk`, isolated configuration, strict MCP configuration |

Claude Code ran on the Mac throughout; no remote Claude installation was used.
The services were built from the community base; the two subsequent commits
add the example validator, analyzer corrections, and their tests/documentation,
with no service or guest-runtime changes. All three coding runs used the same
service build.
The model could not use local shell, read, edit, or write tools. The task text
was supplied directly to the CLI. The only model tool calls observed were
SandSwap MCP calls.

The [example README](../../examples/claude-code/README.md#repeatable-headless-validation-including-a-mac-client)
contains setup and SSH instructions. The executable check is
[`validate.py`](../../examples/claude-code/validate.py). Model credentials are
supplied through the environment, not stored in source. The native full round
uses GLM's OpenAI-compatible endpoint for the repository's OpenAI/Eino agents;
this is separate from Claude Code's Anthropic-compatible endpoint.

Raw, sanitized evidence is in [claude-code-raw/](claude-code-raw/manifest.json):
CLI streams, timestamped session transcripts, invocation metadata,
before/after checks, independent checks, and analyzer output. The manifest
records source and published SHA-256 hashes. Private Claude configuration
files and credential files are excluded. Client filesystem identifiers are
redacted; the measurements and tool results are retained.

## Coding-loop results

| Run | Result | CLI process wall time | Claude-reported model API time | Transcript task span | Tool wall time | LLM responses | MCP calls |
|---|---|---:|---:|---:|---:|---:|---:|
| [1](claude-code-raw/run-1/summary.json) | PASS | 43.957 s | 41.614 s | 42.59 s | 0.98 s | 6 | 6 |
| [2](claude-code-raw/run-2/summary.json) | PASS | 33.849 s | 31.640 s | 32.72 s | 1.21 s | 6 | 5 |
| [3](claude-code-raw/run-3/summary.json) | PASS | 47.016 s | 44.541 s | 45.87 s | 1.42 s | 6 | 6 |

Every run exercised `list_sandfs`, `execute`, `file_read`, and `file_write`.
Runs 1 and 3 read both source and tests; run 2 read just the source. Each made
two execute calls: survey/tests, then tests/commit. There were **17 MCP calls**
in total, zero non-MCP tool calls, zero permission denials, and zero tool errors.
All three independent verifications found the original five tests green,
unchanged test bytes, a committed source fix, and a clean Git working tree.

The CLI process timer includes startup and shutdown. The transcript span starts
at the initial user prompt and ends at the final assistant block. The API timer
is reported by Claude Code; its `num_turns` field is not used as an LLM-response
count. Responses are grouped by message ID when `requestRef` is absent, as in
these GLM transcripts. Parallel tool waits count once in the wall-time column;
per-call durations remain available separately. Claude's cost estimates in the
raw stream are not verified GLM billing data.

## What accounts for the time

Tool wall time was **2.3%–3.7%** of the transcript task span. Most elapsed time
was between/within model responses. This small task therefore benefited more
from keeping the coding loop short than it would from shaving a fraction of a
millisecond off gateway dispatch.

The six execute results reported **88.602–155.720 ms** inside the gateway,
including the actual Python tests, Git commands, and guest process startup.
The measured difference between gateway duration and guest execution duration
was **0.454–0.687 ms**. Separate 30-call `sh -c :` samples on the same Ubuntu
SandFS had median guest execution times of **4.3, 4.2, and 3.7 ms**. These are
the analyzer's no-op baseline estimates, not pure dispatch latency.

For example, run 1's final execute took **192 ms** in the client transcript,
**127.447 ms** in the gateway, and **126.993 ms** in guest execution. The
approximately **64.6 ms residual** includes client scheduling/serialization and
transport through SSH. It is not a direct network or TLS measurement. File and
list tools do not expose separate server timings, so their client durations
are not attributed entirely to SandSwap execution.

The analyzer was corrected for this validation to include the initial model
wait, group streamed blocks by provider message ID, avoid double-counting
parallel waits, and use the configured tunnel endpoint and trusted CA. Its
rejection/accounting tests and the validator tests passed **9/9**.

## Full repository round

The exact invocation is `bash run-round.sh`, without `--fast`, on the source
commit above, with a fresh matrix ledger. Both default trees (`e2e deploy`)
are included and the real-agent cases receive the authorized GLM credentials.
This is the runner's normal scope: the allocation sweep row runs its planner,
the multi-host production deployer runs its prescribed dry-run, and K8s egress
runs its two default scenarios (BPF/bridge and shared-memory/routed IPv6).

The original round ran from **07:00:37 to 08:21:23 UTC** (80 min 46 s).
Its exit code was **1** because the E2E gate had two failures:

| Tree | Rows | PASS | FAIL | BLOCKED-PRODUCT | SKIP / not run |
|---|---:|---:|---:|---:|---:|
| E2E | 69 | 67 | 2 | 0 | 0 |
| Deploy | 36 | 35 | 0 | 1 | 0 |

The deploy gate passed. Its 36 unique rows include the `verify-k8s.sh` row,
which actually ran twice: embedded (145 s) and boxout (144 s). Both outputs
are retained separately because the runner reuses that row's log pathname.

The [native result index](claude-code-raw/native/summary.json) points to the
original matrix JSON reports. The
[native evidence manifest](claude-code-raw/native/manifest.json) indexes their
Markdown reports, every per-row log, the round driver logs, separate targeted
reruns, model-call audits, and preparation diagnostics. Published files retain
source and sanitized SHA-256 hashes. The
[artifact hashes](claude-code-raw/native/build-artifacts-sha256.json) identify
the binaries used on the test host.

Two original E2E failures were traced to the test harness and corrected in
`6126eb8`, without changing the services, warden filter, or assertions:

- `multi-instance-orphan-safety.sh` called `wait` inside command substitution,
  outside the shell that owned the probe child. On Bash 5.1.16, three short
  child-exit reproductions returned `-1` even though the parent subsequently
  reaped exit codes 0/7 correctly. The helper now sets `RL_WAIT_RC` in the
  parent shell. All four independent cases, including a genuinely live child
  at the timeout, returned the expected status.
- `hardening-seccomp-probe.c` used fallback syscall numbers 454/455 for
  `statmount/listmount` when old distro headers lacked them. The pinned x86_64
  kernel and the warden filter use **457/458**; 454/455 name futex operations.
  The corrected probe addresses the intended syscalls. The original failures
  reported `EINVAL`, while the test correctly requires `EPERM` from seccomp.

The original full round remains on `1e5cf6e`. Corrected targeted results are
recorded separately after that round, rather than relabeling its failures.

Both targeted reruns passed on `6126eb89787ba84a9162ee452c76e78d862fa683`:
`multi-instance-orphan-safety.sh` in **13 s**, and `seccomp.sh` in **9 s**.
The latter now observes the intended `EPERM` denials. The resulting accumulated
E2E ledger has 69 PASS rows, but it is a mixed-commit ledger, **not a second
complete 69-row run**. Both targeted commands exited 0.

`deploy/k8s/k8s-host-setup.sh` records the runner's explicit
**BLOCKED-PRODUCT** classification: this combined development host already has
the bare-metal sandlot identity at UID 985, while standalone boxout host setup
requires reserved UID 65536. The script correctly refuses identity drift.
This is neither PASS nor an external-dependency SKIP; the actual K8s deployment
legs have separate results.

The full round also ran the repository's same-host HTTP latency and load
benchmarks. Their BusyBox microcommands and local transport differ from the
Ubuntu coding task and Mac SSH transport above:

| Native HTTP measurement | Client P50 | Client P95 | Gateway P95 |
|---|---:|---:|---:|
| Sticky warm lease, 100 samples | 0.890 ms | 0.950 ms | 0.841 ms |
| Cross-agent cold mount/execute, 100 samples | 1.860 ms | 1.974 ms | 1.851 ms |

At the load benchmark's highest tested level (80 simulated agents, four VMs),
the measured rate was 122.8 requests/s, including 66.7 cold executions/s.
Cold/warm gateway P95 was 2.515/1.009 ms; client P95 was 2.657/1.150 ms.
The 2× baseline latency gate passed with zero terminal 503 responses and
three busy retries. Mean clean pool size was 3.76 of four, so this was an
unsaturated lower bound, not a measured capacity ceiling. The 1× gate had
no passing level. These samples do not imply a Claude Code task P95.

**Evidence limitation in legacy Eino checks:** some scripts' background-marker
checks accept the model's prose without a corresponding tool call. The raw
PASS verdicts therefore do not prove model-driven background execution in
every mode. Auditing the `LLM tool call` records gives:

| Real-model case | Actual tool calls | Calls with `background=true` |
|---|---:|---:|
| E2E dual-agent MCP | 8 | 0 |
| E2E single-node, four agents | 7 | 1 |
| Bare-metal `verify-eino.sh` | 5 | 0 |
| K8s embedded verifier | 7 | 0 |
| K8s boxout verifier | 8 | 1 |

The dual-agent script's independent HTTP background lifecycle assertions
passed, and the deterministic MCP suite exercised all 12 tools. Those are
separate coverage claims. The new Claude validator requires typed tool-call
and result evidence plus independent sandbox checks; it does not accept the
model's completion statement as proof. This PR records the legacy coverage
gap rather than treating its marker checks as strict tool-use evidence.

## Preparation issues and resolutions

| Observation | Resolution and evidence boundary |
|---|---|
| A Python model probe failed certificate verification; its custom OpenSSL default CA path was missing. IPv6 connection attempts also stalled. | Explicitly used the system CA bundle and IPv4 for the probe, without disabling certificate verification or changing host network policy. Curl validated the public WoTrus issuer. Claude itself used the Mac. |
| A preliminary model probe sent `thinking: {type: disabled}`. | GLM rejected that unsupported option with HTTP 400/code 1210. Removing it produced a verified HTTP 200 real completion; the repository's agent examples do not send that option. |
| Initial warden root-only unit run failed at `filter_denies_unshare_under_root` with `No child processes` (23 passed, 1 failed). | Preserved the failure and reran unchanged; the complete build then passed. This is an observed intermittent failure, not a claim that its cause was fixed. |
| A task wrapper's `umask 077` produced a gateway configuration unreadable by `sandserv`. | Corrected that generated configuration and ran deployment with `umask 022`; credential files stayed private. No service isolation setting was relaxed. |
| Distro libbpf 0.5 could not parse host BTF, so vsockguard failed to attach and the sandlot's pre-start attestation correctly refused startup. | Linked unchanged `vsockguardctl.c` explicitly with the cached official libbpf 1.4.7 static archive. Live allowed/denied UID probes passed; the guard was not bypassed. |
| The host's ephemeral port range overlapped test fixture ports, and its idle VM pool left 500 unused TAPs. | Temporarily used `32768–60999` and removed only verified unopened, non-carrier TAPs after stopping the idle VM services. Original state was recorded for restoration. |
| Dependency downloads and temporary K3s image pulls need reliable network access. | Used a task-owned reverse SOCKS tunnel and verified cached K3s/etcd images. Local fixture traffic bypassed the proxy. |

All failures and environmental remedies are kept distinct from successful
validation results. Repeated/diagnostic results do not replace an original
full-round failure.

After testing, the temporary SandSwap/K3s services, bridge, BPF pin, proxy
configuration and SSH forwards were removed. The original Docker configuration,
DNS symlink and ephemeral port range were restored, and all 12 previously
active services were running again. The
[restoration audit](claude-code-raw/native/restoration-summary.json) omits
unrelated preexisting service/container names. Model credential files are not
included in the evidence or repository.
