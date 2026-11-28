# AgentScope MCP integration results

[English](RESULTS.md) | [简体中文](RESULTS.zh-CN.md)

Date: 2026-11-28. **PASS**: the standalone example provisioned new resources,
ran all MCP checks, completed a real GLM coding task and independently verified
the resulting sandbox. This is an AgentScope integration test, not a rerun of
the repository-wide `run-round.sh` suite.

## Configuration and reproducible flow

The complete procedure is in [README.md](README.md). All initialization,
fixtures, task generation and verification come from `examples/agentscope-sandswap/`:

`setup.py → check.py → verify.py (baseline) → run.py → verify.py (acceptance)`

| Component | Tested configuration |
|---|---|
| SandSwap runtime baseline | `a475e5f718a1080f66d951b81a3ab5ca8bb6d671` plus this PR's CA and MCP authentication fixes; runtime source directories verified against the test checkout |
| AgentScope | `b76f2726751e774541ece42256def65c247d4131` (`2.0.13.dev0`) |
| Python / MCP / HTTP / model SDK | 3.13.18 / `mcp` 2.3.0 / `httpx2` 2.16.2 / `openai` 3.60.0 |
| Model | Real `glm-5.3-flash`, official GLM OpenAI-compatible endpoint |
| Host | Bare metal, Ubuntu 22.04.4, kernel 6.8.0-149-generic, 2 × Xeon Gold 6248R, 96 logical CPUs, about 376 GiB RAM |
| Test resources | Two new agents, three flat Ubuntu 24.04 SandFS instances, each 2 vCPUs / 512 MiB |
| Transport | Same-host HTTPS `/mcp`, verified CA and hostname, dual auth headers, persistent HTTP pool |

Python uses a dedicated virtual environment. No system Python, container
runtime or K8s resources were replaced or modified for this integration.

## Functional results

**13/13 check groups passed**, covering all 12 MCP tools.

| Area | Verified behavior |
|---|---|
| Independent setup | New resources recorded in a private manifest; own fixture seeded into an empty sandbox; credential file mode 0600 |
| Discovery | 12 tools registered in AgentScope; only the owning agent's SandFS IDs listed; usage guide available |
| TLS/authentication | Untrusted CA and wrong key rejected; supplementary live check rejected hostname mismatch |
| Sync execution | stdout, stderr and nonzero command exit preserved |
| Files | mkdir, UTF-8 read/write, append, partial read, stat/list, rename, binary base64 roundtrip and recursive removal |
| Errors/isolation | Missing file and path traversal propagate as tool errors; same-path file absent in another owned SandFS; foreign-agent read/execute rejected |
| Background work | Completion and output polling; kill prevents delayed write; polling does not extend the 2-second absolute lease |
| Reconnect | Workspace contents survive closing and recreating the client connection |

`go test ./mcp -count=1` passed (2.506 s). Missing/invalid-key regressions verify
HTTP 401, Bearer challenge and rejection before malformed-body parsing.
The deployed certificate passed `openssl verify -x509_strict` and Python 3.13.

## Real model acceptance

The independent fixture started with **5 tests, 3 failures, 0 errors**. The agent
read the package, repaired addition and Fibonacci, ran tests and committed the
fix using only SandSwap tools for sandbox work.

| Final standalone run | Result |
|---|---:|
| Agent wall time, including MCP setup | 52.307 s |
| Model calls | 8 |
| SandSwap tool calls | 9: list SandFS ×1, read ×2, list directory ×1, execute ×4, write ×1 |
| Model-call event intervals, summed | 51.937 s |
| Tool-result event intervals, summed | 0.274 s |
| Model-reported input / output tokens | 54,904 / 2,130 |
| Independent acceptance | 5 passed; original test-file SHA-256 unchanged |
| Additional checks | Addition edge cases, Fibonacci 0–20, negative-input rejection passed |
| Git | Exactly one new `fix calc` commit; core file committed; clean worktree |

All nine MCP calls completed successfully. Final acceptance comes from
`verify.py`, not the model's final reply. Model latency accounts for most of the
52-second task time. These client event intervals describe one task, not a
percentile benchmark of agent performance.

## Short-command latency

Each mode ran five excluded warm-ups followed by **100 sequential `true`
executions** over one persistent HTTPS connection, without model calls. P95
uses nearest rank. The second mode held the VM with a background `sleep` lease.

| Mode | Client P50 | Client P95 | Client max | Gateway P95 | Guest execution P95 |
|---|---:|---:|---:|---:|---:|
| No background lease | 3.864 ms | 4.012 ms | 4.057 ms | 2.757 ms | 2.569 ms |
| Background lease held | 3.880 ms | 4.047 ms | 6.989 ms | 2.782 ms | 2.587 ms |

Both series use a warmed connection. “No background lease” does not mean cold
VM boot. The numbers include AgentScope MCPTool, SDK, HTTPS and command latency;
they do not establish VM startup, WAN, concurrent-load or failover performance.

## Issues found and resolutions

1. **Generated CA lacked key usage.** Python 3.13 strict TLS rejected it. The
   bare-metal generator now sets critical CA constraints and
   `keyCertSign,cRLSign`; certificates were reissued with verification enabled.
2. **Authentication errors left the SDK waiting.** HTTP 200 with JSON-RPC
   `id:null` could not match the pending request. Missing/invalid credentials
   now return HTTP 401 with a Bearer challenge, retaining pre-auth body rejection
   and the existing JSON-RPC error code. Real SDK and Go regression tests passed.
3. **Credential-file creation used the wrong Python interface.** The initial
   setup attempt passed `opener` to `Path.open`. It now uses built-in `open`
   with an exclusive create and mode 0600. Resources from the failed attempt
   were identified from its manifest and removed before a fresh setup.
4. **The workspace lacked a project README.** In the first model attempt, the
   agent followed the server guide and tried to read `README.md`, producing one
   tool error. Its code repair passed independent checks, but the strict harness
   correctly rejected that run. The fixture now includes its own README. The
   final complete run above used newly created sandboxes and had no tool errors.

MCP SDK 2.3.0 rejects cross-origin redirects. Only one gateway is validated;
no multi-gateway routing, node-failure or cluster-load claim is made. No upstream
AgentScope code was patched.

## Cleanup and evidence

The temporary deployment was removed, all **12 original host services** restored,
and Docker/containerd remained active. Docker configuration checksum, resolver
link and ephemeral-port range matched the pre-test snapshot. No active K3s or
kubelet existed on the selected host. Temporary model and agent credential
handoff files were deleted.

Private evidence retains failed attempts, final contract and model events,
before/after verification, source fingerprints, health and cleanup checks.
Only this sanitized report and reproducible example are submitted. Server
addresses, private paths, credentials, sandbox IDs and raw transcripts are omitted.
