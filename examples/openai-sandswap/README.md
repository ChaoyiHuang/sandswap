# Sandswap OpenAI + Go-SDK Agent Example

An AI agent built directly on the two **official** Go SDKs — no agent framework:

- [`github.com/openai/openai-go`](https://github.com/openai/openai-go) for the LLM (Chat Completions with tool calling)
- [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk) for the MCP client (Streamable HTTP)

It connects to a Sandswap gateway's MCP server and executes code in isolated KVM microVMs. This is a **functional twin** of [`examples/eino-sandswap`](../eino-sandswap/): same modes, same environment variables, same routing rules, same prompts, and same log-line shapes — so the end-to-end test ([`e2e/eino-agent-mcp.sh`](../../e2e/eino-agent-mcp.sh)) can target either example by pointing `EINO_DIR` at this directory.

## Architecture

### Single-Agent Mode

```
┌─────────────────────────────┐
│  Agent (this program)       │
│  ┌─────────┐  ┌──────────┐ │
│  │ openai- │  │ go-sdk   │ │
│  │ go LLM  │  │ MCP cli  │ │
│  │(Chat    │  │ (Stream- │ │
│  │Complete)│  │ ableHTTP)│ │
│  └─────────┘  └────┬─────┘ │
└──────────────────────┼──────┘
                       │ MCP (StreamableHTTP + Bearer token)
                       ▼
┌─────────────────────────────┐
│  Sandswap Gateway (:3000)   │
│  POST /mcp                  │
└──────────┬──────────────────┘
           │ gRPC stream
           ▼
┌─────────────────────────────┐
│  Sandlot → sandvmm (KVM)    │
│  ┌───────────────────────┐  │
│  │  microVM (warden)     │  │
│  │  vsock:1024           │  │
│  │  /workspace           │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

The agent loop is hand-rolled and framework-free: send the conversation to the LLM with the discovered tools → if the model returns tool calls, echo them, execute each via `mcp.ClientSession.CallTool`, feed the results back as `tool` messages, and repeat (bounded at 30 iterations) until the model returns a final text response.

### Dual-Agent Mode (VM Reuse)

Two agents run in the same process, each with its own MCP session. Prompts alternate between them sequentially over one shared pool (sequential by design). They share a single microVM — the gateway performs virtio-fs `allowed_dirs` hot-swap when switching between agents.

```
┌─────────────────────────────────────┐
│  Agent (single process)             │
│  ┌────────────────┐ ┌────────────┐  │
│  │ Agent A        │ │ Agent B    │  │
│  │ MCP session A  │ │MCP session B│ │
│  └───────┬────────┘ └─────┬──────┘  │
└──────────┼────────────────┼─────────┘
           │                │
           ▼                ▼
┌─────────────────────────────────────┐
│  Sandswap Gateway (:3000)           │
│  POST /mcp (Bearer: key_A / key_B)  │
└──────────────┬──────────────────────┘
               │ gRPC stream
               ▼
┌─────────────────────────────────────┐
│  Sandlot → sandvmm (1 KVM VM)       │
│  ┌─────────────────────────────────┐│
│  │  microVM (shared)               ││
│  │  virtio-fs allowed_dirs hot-swap││
│  │  Agent A rootfs ↔ Agent B rootfs││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
```

## Why the two official SDKs instead of an agent framework?

The Eino example (`examples/eino-sandswap`) delegates the agent loop to `adk.ChatModelAgent` + `Runner` and adapts MCP tools through `eino-ext/components/tool/mcp`. This example does the same job with ~zero framework surface:

- **LLM**: `openai-go`'s Chat Completions API with function tools. DeepSeek, OpenAI, and Gemini all speak the same OpenAI-compatible wire format, so one client serves all three backends — only the base URL and model change.
- **MCP**: `go-sdk`'s `mcp.NewClient` + `StreamableClientTransport`. Tool input schemas arrive as JSON Schema, which is exactly what OpenAI's function `parameters` field expects — a direct 1:1 conversion, no schema translation layer.

The auth contract is unchanged from the Eino example: every MCP request carries `Authorization: Bearer <key>` **and** `X-Sandswap-Api-Key: <key>` (Go's `http.Client` strips `Authorization` on cross-host 307 redirects to the owner gateway; the custom header survives so the replayed request authenticates). A custom `http.Transport` with `IdleConnTimeout: 0` keeps the affinity connection alive for the whole session.

## Features

- **Multi-LLM support**: DeepSeek (recommended), OpenAI, or Gemini — selected by environment variable
- **MCP tool integration**: All Sandswap sandbox tools available through the standard MCP protocol
- **Dual-agent mode**: Two agents in one process, sharing a microVM pool — tests VM reuse and agent switching
- **Interactive console**: Multi-turn conversation with the agent(s)
- **Full sandbox access**: Code execution, file I/O, background processes in KVM microVMs

## Prerequisites

1. A running Sandswap gateway with MCP endpoint (`POST /mcp`)
2. Agent API key(s) from the gateway
3. An LLM API key (one of DeepSeek, OpenAI, or Gemini)

## Quick Start

### Single-Agent Mode

```bash
export SANDSWAP_API_KEY=sk-sandswap-agent-xxx
export SANDSWAP_MCP_URL=http://localhost:3000/mcp

# Option 1: DeepSeek backend (recommended for tool calling)
export DEEPSEEK_API_KEY=your-deepseek-api-key
go run .   # or: go build -o agent . && ./agent

# Option 2: OpenAI backend
export OPENAI_API_KEY=your-openai-api-key
go run .

# Option 3: Gemini backend (via Google's OpenAI-compatibility endpoint)
export GOOGLE_API_KEY=your-gemini-api-key
go run .
```

### Dual-Agent Mode (VM Reuse)

```bash
export SANDSWAP_API_KEY_A=sk-sandswap-agent-aaa
export SANDSWAP_API_KEY_B=sk-sandswap-agent-bbb
export SANDSWAP_MCP_URL=http://localhost:3000/mcp
export DEEPSEEK_API_KEY=your-deepseek-api-key

go run .
```

In dual-agent interactive mode, prefix input with `A:` or `B:` to route to the respective agent:

```
You: A:Execute echo hello from agent A
[agent-A] ...

You: B:Execute echo hello from agent B
[agent-B] ...
```

## Environment Variables

### Required

| Variable | Mode | Description |
|----------|------|-------------|
| `SANDSWAP_API_KEY` | Single | Agent API key from the Sandswap gateway |
| `SANDSWAP_API_KEY_A` + `SANDSWAP_API_KEY_B` | Dual | Two agent API keys for dual-agent mode |
| One of: `DEEPSEEK_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY` | Both | LLM provider API key |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `SANDSWAP_MCP_URL` | `http://localhost:3000/mcp` | Gateway MCP endpoint URL |
| `SANDSWAP_CA_CERT` | (none) | Path to a CA cert to trust (K8s self-signed TLS) |
| `DEEPSEEK_MODEL` | `deepseek-flash` | DeepSeek model name |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | DeepSeek API base URL |
| `OPENAI_MODEL` | `gpt-4o` | OpenAI model name |
| `OPENAI_BASE_URL` | (OpenAI default) | OpenAI API base URL (for compatible providers) |
| `GEMINI_MODEL` | `gemini-2.0-flash` | Gemini model name (served via `generativelanguage.googleapis.com/v1beta/openai`) |

## LLM Backend Selection

Priority order: `DEEPSEEK_API_KEY` > `OPENAI_API_KEY` > `GOOGLE_API_KEY`

| Backend | Recommended Model | Notes |
|---------|-------------------|-------|
| DeepSeek | `deepseek-flash` | Best tool-calling accuracy for sandbox operations |
| OpenAI | `gpt-4o` | Works with any OpenAI-compatible API via `OPENAI_BASE_URL` |
| Gemini | `gemini-2.0-flash` | Good for fast iterations |

## Available Sandbox Tools

The agent has access to all Sandswap MCP tools:

| Tool | Description |
|------|-------------|
| `execute` | Execute code (shell, Python, Node.js) in the sandbox |
| `file_read` | Read file contents |
| `file_write` | Write file contents |
| `file_stat` | Get file metadata |
| `file_list_dir` | List directory contents |
| `file_mkdir` | Create directories |
| `file_remove` | Remove files/directories |
| `file_rename` | Rename files/directories |
| `exec_status` | Poll background exec status |
| `exec_kill` | Kill a background exec |
| `list_sandfs` | List available sandboxes |
| `sandswap_guide` | Get the Sandswap usage guide (how the sandbox works, warm-path guidance, failure semantics and recovery) |

## End-to-End Test

The same test that drives the Eino example can drive this one — just point `EINO_DIR` at this directory:

```bash
bash build/build.sh all
bash build/build-ubuntu-rootfs.sh

export DEEPSEEK_API_KEY=sk-xxx
EINO_DIR=/home/joehuang_sweden/sandswap/examples/openai-sandswap bash e2e/eino-agent-mcp.sh
```

The test starts the full stack (gateway + sandlot + real KVM microVMs, pool size 1), creates two agents and two sandfs, then runs the example in dual-agent piped mode with alternating `A:`/`B:` prompts. It verifies both agents' tool execution results and confirms VM reuse (only 1 VM created for 2 agents).

## Bare-metal Latency Benchmark

This directory also ships a **latency benchmark** (`SANDSWAP_BENCH_MODE=http|mcp`) that measures every segment of the path straight from the gateway's own metrics — no log scraping (it is the designated replacement for the deleted log-scraping `e2e/latency.sh` / `e2e/latency-baremetal.sh` benchmarks; `e2e/latency-benchmark-aiagent.sh` drives it). The gateway returns `gateway_duration_ns` (gateway E2E), `sandlot_duration_ns` (sandlot dispatch→response, incl. vsock round trip) and `exec_duration_ns` (warden guest spawn→wait) in every execute response; the HTTP mode also reads the `X-Sandbox-Lease: hit` header for warm/cold ground-truth classification.

The benchmark cases: 1 warmup (excluded) + `WARM_N` back-to-back `echo hi` (sticky lease hit) + `COLD_N` alternating `echo a`/`echo b` with a `SWITCH_GAP_MS` sleep (> sticky-ms 100) so each cross-agent call cold-mounts.

```bash
# Direct run (needs a live gateway + two agent keys):
export SANDSWAP_BENCH_MODE=http
export GATEWAY_URL=http://localhost:3000
export SANDSWAP_API_KEY_A=sk-... SANDSWAP_API_KEY_B=sk-...
# sandfs_id is REQUIRED — discover yours via list_sandfs / GET /agent/sandfs
export SANDSWAP_SANDFS_A=... SANDSWAP_SANDFS_B=...
export WARM_N=30 COLD_N=20 SWITCH_GAP_MS=150 BENCH_VERBOSE=0
go run .
```

Or use the orchestration script, which deploys the full stack and runs the benchmark
from the prebuilt `output/openai-sandswap` binary (`build.sh examples`):

```bash
# HTTP mode (default, no LLM needed):
bash e2e/latency-benchmark-aiagent.sh

# MCP mode (times the LLM round trip too — needs an LLM API key):
export DEEPSEEK_API_KEY=sk-xxx
bash e2e/latency-benchmark-aiagent.sh mcp

# Both modes:
bash e2e/latency-benchmark-aiagent.sh both
```

### Modes

| Mode | Transport | Segments benchmarked |
|------|-----------|----------------------|
| `http` | `POST /agent/execute` directly | `T_http` (client-observed round trip) + gateway/sandlot/exec metrics; warm/cold from the `X-Sandbox-Lease` header |
| `mcp` | MCP `execute` tool | `T_llm` (LLM request→tool-call response) + `T_mcp` (openai-sandswap→gateway round trip) + gateway/sandlot/exec metrics |

### Warm path in MCP mode

The LLM is driven once to establish the mount and collect `T_llm`; then the benchmark itself issues `WARM_N` back-to-back `execute` tool calls to the same agent, which deterministically hit the sticky lease. (If the LLM returns multiple tool calls in one response, each is executed and measured too.)

### Benchmark env vars

| Variable | Default | Description |
|----------|---------|-------------|
| `SANDSWAP_BENCH_MODE` | (none) | `http` \| `mcp`; set to enter benchmark mode instead of the agent loop |
| `GATEWAY_URL` | `http://localhost:3000` | Gateway agent API base |
| `SANDSWAP_API_KEY_A` / `_B` | — | Two agent keys (warm = A, switch = A↔B) |
| `SANDSWAP_SANDFS_A` / `_B` | — (required) | sandfs_id; discover via `list_sandfs` / `GET /agent/sandfs` |
| `WARM_N` / `COLD_N` | 30 / 20 | Warm / switch sample counts |
| `WARM_GAP_MS` | 5 | Sleep between warm calls (≪ sticky window, keeps them warm) |
| `SWITCH_GAP_MS` | 300 | Gap between switch calls (> sticky-ms 100) |
| `SWITCH_SETTLE_MS` | 1000 | Sleep after the warm phase, before the first switch call |
| `N_LLM` | 5 | MCP mode: LLM round-trip sample count |
| `BENCH_VERBOSE` | 0 | Print the per-sample detail table |
| `SANDSWAP_CA_CERT` | (none) | CA cert for https against a self-signed gateway |

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/openai/openai-go` | v1.12.0 | Official OpenAI Go SDK (Chat Completions + function tools) |
| `github.com/modelcontextprotocol/go-sdk` | v1.7.0 | Official MCP Go SDK (Streamable HTTP client, tool calls) |
