# AgentScope + SandSwap over MCP

[English](README.md) | [简体中文](README.zh-CN.md)

A standalone AgentScope integration with its own provisioning script, coding
fixture, task prompt, contract checks and independent acceptance checks.
All example files are contained in this directory.

## Design

`Agent → Toolkit → MCPTool → MCP Python SDK → HTTPS /mcp → tinyVM`

The agent runs outside the VM. SandSwap exposes 12 MCP tools; commands and file
operations run inside the tinyVM. Model credentials stay in the agent process.
The integration uses the public AgentScope `MCPTool` adapter and MCP SDK
transport. At the pinned revision, AgentScope's `HttpMCPConfig` does not expose
TLS contexts or connection-pool limits, so `client.py` owns the HTTP client.
It verifies the CA and hostname, sends both authentication headers and keeps
connections open between calls (`keepalive_expiry=None`). Client lifecycle
state is independent of SandSwap's stateless server protocol.

The agent receives `sandswap_guide` instructions. MCP `isError` becomes an
AgentScope tool error; a command's nonzero `exit_code` must be checked separately.
Network errors have unknown side-effect outcomes, so mutations are not replayed
automatically. Model, MCP and HTTP clients close on exit.

## Run the complete example

Run these commands from the repository root. Prerequisites: Python 3.11+, a
healthy standalone SandSwap deployment, `output/sandctl` with administrative
access, and the registered `ubuntu:24.04` template containing Python and Git.
See the [bare-metal deployment script](../../deploy/baremetal/deploy-single-node.sh).
The dependency pin uses AgentScope 2.x `Agent` / `MCPTool` APIs.

### 1. Install dependencies

```sh
python3 -m venv /tmp/agentscope-sandswap-venv
PY=/tmp/agentscope-sandswap-venv/bin/python
EXAMPLE=examples/agentscope-sandswap
"$PY" -m pip install -r "$EXAMPLE/requirements.txt"
```

### 2. Provision fresh test resources

```sh
ROUND_DIR=output/agentscope-round-1
"$PY" "$EXAMPLE/setup.py" --output-dir "$ROUND_DIR/setup"
source "$ROUND_DIR/setup/env.sh"
```

`setup.py` creates two new agents and three new flat SandFS instances (2 vCPUs /
512 MiB each): two owned by the main agent, one by the isolation-test agent.
It seeds `fixtures/` into the empty primary workspace, creates the initial Git
commit and renders [TASK.md](TASK.md) with the new sandbox ID. It refuses to seed
a nonempty workspace and never selects an existing sandbox by name.

The output directory is private (0700); `env.sh` holds the primary agent key
(0600). The other agent's key is never passed to the MCP client. `resources.json`
records created IDs as provisioning proceeds, including partial failures.
Use a new `ROUND_DIR` for each run. Optional setup flags: `--sandctl`,
`--template`, `--mcp-url`, `--ca` (see `setup.py --help`).

### 3. Check MCP behavior and the failing baseline

```sh
"$PY" "$EXAMPLE/check.py" --output-dir "$ROUND_DIR/contract" --samples 100
"$PY" "$EXAMPLE/verify.py" --output "$ROUND_DIR/before.json"
```

`check.py` exercises all 12 tools, TLS/authentication, isolation, text/binary
files, background completion/kill/lease expiry, reconnect persistence, and two
100-sample sequential command-latency series. It writes a unique
`agentscope-check-*` directory and removes it on success. If it fails, inspect
that directory or start a fresh round before coding acceptance.

`verify.py` confirms that the independent fixture starts with five tests and
three failures. The task is to fix addition and Fibonacci without changing tests.

### 4. Run the real model and independently accept the result

```sh
export MODEL_API_KEY='<model key>'
export MODEL_BASE_URL=https://open.bigmodel.cn/api/paas/v4
export MODEL_NAME=glm-5.3-flash
"$PY" "$EXAMPLE/run.py" --task "$ROUND_DIR/setup/task.md" --output-dir "$ROUND_DIR/agent"
"$PY" "$EXAMPLE/verify.py" --baseline "$ROUND_DIR/before.json" --output "$ROUND_DIR/after.json"
```

The generated task requires MCP discovery, file inspection, observing failing
tests, code repair, successful tests and a `fix calc` commit. `run.py` accepts
only a completed agent loop with successful SandSwap-only tool calls.
`verify.py` separately requires five passing tests, the same test-file SHA-256,
independent function edge cases, exactly one new `fix calc` commit and a clean
worktree. The model's final prose is not acceptance evidence.

### 5. Keep evidence private and clean up

Raw model/tool events and results stay under `ROUND_DIR` (Git-ignored under
`output/`). Publish only a sanitized summary. Delete the SandFS IDs recorded in
`resources.json` with `output/sandctl api sandfs delete <sandfs-id>`, then the
agent IDs with `output/sandctl api agent delete <agent-id>`. Remove `env.sh` and
unset `MODEL_API_KEY` and `SANDSWAP_API_KEY` after use. Restore any host services
temporarily stopped for a dedicated test deployment.

## Scope and compatibility

- Python 3.13 requires a CA with suitable key usage. Reissue an older test CA
  with the updated bare-metal generator; changing the script alone does not
  update deployed certificates. TLS verification remains enabled.
- Missing/invalid keys must return HTTP 401; this change fixes a response that
  left the MCP SDK waiting for a matching JSON-RPC request ID.
- Both latency series use a warmed connection. They do not measure VM boot time.
- MCP SDK 2.3.0 rejects cross-origin redirects even with `follow_redirects=True`.
  This example validates one gateway, not multi-gateway routing, node failover
  or cluster load. No K8s integration is involved.

See [test results and fixes](RESULTS.md) for the standalone validation run.

## References

- [AgentScope MCP documentation](https://docs.agentscope.io/latest/en/building-blocks/tool/overview)
- [Reviewed MCP client source](https://github.com/agentscope-ai/agentscope/blob/b76f2726751e774541ece42256def65c247d4131/src/agentscope/mcp/_mcp_client.py)
- [Reviewed MCPTool adapter](https://github.com/agentscope-ai/agentscope/blob/b76f2726751e774541ece42256def65c247d4131/src/agentscope/tool/_adapters.py)
- [SandSwap MCP contract](../../docs/integration/agent-mcp.md)
