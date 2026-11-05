# Sandswap Eino Agent Example

An AI agent built with [Eino](https://github.com/cloudwego/eino) that connects to a Sandswap gateway's MCP server and executes code in isolated KVM microVMs.

## Architecture

### Single-Agent Mode

```
┌─────────────────────────────┐
│  Eino ChatModelAgent        │
│  ┌─────────┐  ┌──────────┐ │
│  │ LLM     │  │ MCP Tools│ │
│  │(DeepSeek│  │(via mcp- │ │
│  │/OpenAI/ │  │ go)      │ │
│  │Gemini)  │  │          │ │
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

### Dual-Agent Mode (VM Reuse)

Two agents run in the same process, each with its own MCP session. Prompts alternate between them sequentially over one shared pool (sequential by design). They share a single microVM — the gateway performs virtio-fs `allowed_dirs` hot-swap when switching between agents.

```
┌─────────────────────────────────────┐
│  Eino (single process)              │
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

## Features

- **Multi-LLM support**: DeepSeek (recommended), OpenAI, or Gemini — selected by environment variable
- **MCP tool integration**: All 12 Sandswap sandbox tools available through the standard MCP protocol
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
# Start the Sandswap gateway first, then:

export SANDSWAP_API_KEY=sk-sandswap-agent-xxx
export SANDSWAP_MCP_URL=http://localhost:3000/mcp

# Option 1: DeepSeek backend (recommended for tool calling)
export DEEPSEEK_API_KEY=your-deepseek-api-key
go run main.go

# Option 2: OpenAI backend
export OPENAI_API_KEY=your-openai-api-key
go run main.go

# Option 3: Gemini backend
export GOOGLE_API_KEY=your-gemini-api-key
go run main.go
```

### Dual-Agent Mode (VM Reuse)

```bash
# Set two API keys for two different agents
export SANDSWAP_API_KEY_A=sk-sandswap-agent-aaa
export SANDSWAP_API_KEY_B=sk-sandswap-agent-bbb
export SANDSWAP_MCP_URL=http://localhost:3000/mcp
export DEEPSEEK_API_KEY=your-deepseek-api-key

go run main.go
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
| `DEEPSEEK_MODEL` | `deepseek-flash` | DeepSeek model name |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | DeepSeek API base URL |
| `OPENAI_MODEL` | `gpt-4o` | OpenAI model name |
| `OPENAI_BASE_URL` | (OpenAI default) | OpenAI API base URL (for compatible providers) |
| `GEMINI_MODEL` | `gemini-2.0-flash` | Gemini model name |

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

A full end-to-end test script is available that starts the entire Sandswap stack (gateway, sandlot, VMM/warden) with Ubuntu rootfs and runs the Eino dual-agent:

```bash
# Build all Sandswap artifacts first
bash build/build.sh all
bash build/build-ubuntu-rootfs.sh

# Run the Eino e2e test (requires a KVM-capable host)
export DEEPSEEK_API_KEY=sk-xxx
bash e2e/eino-agent-mcp.sh
```

The test script:
1. Deploys all binaries and Ubuntu rootfs template
2. Starts gateway + sandlot with real KVM microVMs (pool size = 1)
3. Creates **two agents** and **two sandfs** (both with Ubuntu rootfs)
4. Builds and runs the Eino dual-agent with alternating test prompts
5. Verifies both agents' tool execution results
6. Confirms VM reuse: only 1 VM created for 2 agents
7. Cleans up all processes and resources

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/cloudwego/eino` | v0.9.12 | Agent framework (ChatModelAgent, Runner, compose) |
| `github.com/cloudwego/eino-ext/components/model/deepseek` | v0.1.6 | DeepSeek ChatModel |
| `github.com/cloudwego/eino-ext/components/model/openai` | v0.1.13 | OpenAI ChatModel |
| `github.com/cloudwego/eino-ext/components/model/gemini` | v0.1.13 | Gemini ChatModel |
| `github.com/cloudwego/eino-ext/components/tool/mcp` | v0.0.8 | MCP tool integration for Eino |
| `github.com/mark3labs/mcp-go` | v0.43.0 | MCP client (StreamableHTTP transport) |
