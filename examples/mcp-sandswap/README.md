# mcp-sandswap — Minimal MCP Client Example

The smallest complete MCP integration loop against the Sandswap gateway's
MCP server (`POST /mcp`), using the official Go SDK
(`github.com/modelcontextprotocol/go-sdk/mcp`). It is the runnable
companion of
[`docs/integration/agent-mcp.md`](../../docs/integration/agent-mcp.md).

## What it shows

- **Connect**: one Streamable HTTP session over one persistent connection,
  with `DisableStandaloneSSE` (the gateway is POST-only) and a custom
  transport injecting **both** auth headers on every request —
  `Authorization: Bearer <key>` plus `X-Sandswap-Api-Key: <key>` (the
  custom header survives the cross-host 307 ownership redirect).
- **Discover**: `tools/list` (which embeds your SandFS instances) and the
  explicit `list_sandfs` call.
- **Execute sync**: `execute` with `sandfs_id` + `code` + `language`.
- **File I/O**: `file_write` / `file_read`, paths relative to `/workspace`.
- **Execute background**: `background: true` + `lease_duration` (an
  absolute run-time cap — polls never extend it), then `exec_status`
  polling and `exec_kill`.
- **Error surface**: tool failures arrive as `isError: true` results with
  the message (and structured resilience fields) in `content[0].text` —
  not JSON-RPC errors.

## Run it

```bash
# prerequisites: a running gateway and an agent + sandfs
export SANDSWAP_MCP_URL=https://localhost:3000/mcp   # or http://localhost:3000/mcp
export SANDSWAP_API_KEY=sk-sandswap-agent-...        # sandctl api agent create --name demo
export SANDSWAP_CA_CERT=/path/to/ca.pem              # only for a private CA

go run . -tools         # list the 12 tools and exit
go run .                # full loop: discovery, sync exec, file I/O, background exec, poll, kill
```

`SANDSWAP_SANDFS_ID` selects the sandbox for the exec demo; without it the
program prints your SandFS instances and stops there.

## License

BUSL-1.1 (same as the repository).
