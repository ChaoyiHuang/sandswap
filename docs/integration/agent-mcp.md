---
title: Agent MCP Integration
nav_order: 5
parent: Integration
---

# Agent MCP Integration

An embedded **MCP (Model Context Protocol)** server exposes the agent API
as MCP tools over Streamable HTTP — the natural integration surface for
AI-agent frameworks. It mirrors the HTTP API one-to-one; pick whichever
your stack prefers. This page is the MCP-specific integration guide; the
tool catalog is the [MCP Tools Reference](../reference/mcp-tools.md) and
the shared semantics (timeouts, lifecycle, errors) are the same as
[Agent HTTP Integration](agent-http.md).

## 1. Endpoint and transport

`POST /mcp` on the agent listener (`:3000`), same per-request API-key auth
as `/agent/*`. Body limit **50 MB**, aligned with `/agent/file` so
`file_write` can carry a full 16 MB binary payload (base64-inflated) inside
JSON-RPC params.

Stateless (MCP 2026-07-28 RC): **no** `Mcp-Session-Id` is stored — every
request is self-contained and can land on any gateway instance. An
`initialize` call is still answered (echoing the client's protocol version,
default `2025-03-26`) for compatibility with older clients. The method may
travel in the JSON-RPC body **or** via the `Mcp-Method` / `Mcp-Name`
headers (SEP-2243). Supported methods: `initialize`, `ping`, `tools/list`,
`tools/call`. `tools/list` responses carry `Cache-Control: max-age=60`.

A **stdio transport** is also available for local agent integration — JSON-RPC
on stdin/stdout, API key from `SANDSWAP_API_KEY`.

## 2. Quickstart (raw JSON-RPC)

```bash
GW=https://sandswap.local:3000
KEY=sk-sandswap-agent-…
SF=sandfs-8e4f2a91

curl -sS -X POST "$GW/mcp" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

curl -sS -X POST "$GW/mcp" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"execute","arguments":
         {"sandfs_id":"'$SF'","code":"echo hello","language":"shell"}}}'
```

```json
{"jsonrpc":"2.0","id":2,
 "result":{"content":[{"type":"text","text":"hello\n"}],"isError":false}}
```

`sandfs_id` arguments are also published as an **enum** in every tool
schema: `tools/list` embeds the agent's SandFS instances (id + description),
so an LLM sees its sandboxes without a separate discovery round-trip.

## 3. The three things every MCP client gets right

1. **Both auth headers on every request** — `Authorization: Bearer <key>`
   plus `X-Sandswap-Api-Key: <key>` (the custom header survives the
   cross-host 307 ownership redirect).
2. **One shared HTTP transport, no client-side idle timeout** — the
   connection is the affinity anchor. The gateway never pushes
   server-initiated messages, so disable the standalone SSE GET stream
   (`DisableStandaloneSSE` in the Go SDK).
3. **Background semantics** — `lease_duration` is an absolute cap, polls
   never extend it, and `not_found` after a recovery means re-create the
   work, not retry the poll.

The [abort contract](agent-http.md#7-design-for-the-abort-contract) is also
embedded verbatim in every tool description, so an LLM sees the rules
without extra prompting — one reason to prefer MCP for LLM-driven agents.

## 4. Multiple SandFS: connect per SandFS (recommended, zero redirects)

One MCP connection serves all of an agent's SandFS instances — `sandfs_id`
is a per-call argument and `list_sandfs` is how the agent picks. But the
**endpoint URL decides the routing**, and the low-latency choice is to
address each SandFS by its **per-sandfs domain**, which DNS resolves
straight to the owning gateway:

```text
https://<sandfs_id>.sandfs.sandswap.local:3000/mcp     ← per-SandFS endpoint
```

- **One active SandFS at a time** (the common case): point the endpoint at
  that SandFS's per-sandfs domain and keep the connection **long-lived**
  (keep-alive, no client idle timeout — the connection is the affinity
  anchor, item 2 above). DNS resolves to the owner once at dial; every
  call then goes straight to the gateway that owns the mount — **zero
  307 redirects, warm path at its floor**. Switching tasks = reconnecting
  to the other SandFS's name.
- **Several concurrently active**: open one MCP connection per SandFS,
  each via its own per-sandfs domain (frameworks that register multiple
  MCP server instances handle this naturally).

## 5. The agent-domain alternative (one URL, pays a 307 on foreign SandFS)

Connecting everything to the shared agent domain
(`https://sandswap.local:3000/mcp`) is the zero-configuration shape: one
endpoint, and a call for a SandFS owned by a **different** gateway is
answered with a **307 to the owner** — the server is stateless (no
session to move), so the client's HTTP stack follows it transparently,
provided both auth headers travel (item 1 above).

Know what this costs: the hop is **per-call and persists while the
connection stays pinned to a non-owner** — a keep-alive connection does
not re-resolve DNS (the TTL moving the agent domain only affects new
dials), and ownership changes are rare, so once the pattern appears it is
stable, not transient. Worst case (the pinned gateway owns none of your
SandFS) every call pays one extra LAN round trip — invisible against LLM
think time, worth caring about only in tight tool-call loops and
benchmarks.

## 6. Caveats (both shapes)

- `sandfs_id` is still required on every call — the domain in the URL is a
  routing hint; authentication and addressing remain header + body.
- After a rare ownership change (takeover/load-shed), a long-lived
  connection to the previous owner redirects to the new owner until it
  re-dials — that is the resilience path working, not a misconfiguration.
  A request already carrying `X-Sandswap-Redirected: 1` is never
  redirected again (anti-loop — it gets a JSON-RPC `-32001` error
  instead).
- TLS certificates must cover the names you connect to: the dev certs
  from `deploy/gen-certs.sh` cover `localhost` only; production certs
  need SANs for the agent and per-sandfs domains.
- The `sandswap.local` / `sandswap-stream.local` / `sandfs.sandswap.local`
  names in this page are the **shipped defaults, not fixed values** — all
  three are deployment configuration on sandns
  (`domains.agent` / `domains.stream` / `domains.sandfs`; see
  [sandns configuration](../operations/configuration/sandns.md)), so an
  enterprise suffix changes the URLs here, the sandlot's `-gateway-addr`
  (if it dials the stream domain), and the certificate SANs — nothing in
  the gateway, sandlot, or warden protocols themselves.
- HTTP (non-MCP) agents do not face this trade-off — their request URLs
  are built per call, so addressing the per-sandfs domain directly is the
  standard pattern there ([Agent HTTP Integration](agent-http.md)).

## 7. Minimal client walkthrough

[`examples/mcp-sandswap`](https://github.com/ChaoyiHuang/sandswap/tree/main/examples/mcp-sandswap)
is the smallest complete integration loop using the official Go SDK
(`github.com/modelcontextprotocol/go-sdk/mcp`): connect → `tools/list` →
sync `execute` → `file_write`/`file_read` → background `execute` →
`exec_status` poll → `exec_kill`. The connection setup is the part to copy:

```go
httpClient := &http.Client{
    Transport: &headerTransport{ // injects both auth headers on every request
        base:    &http.Transport{IdleConnTimeout: 0}, // gateway -idle-timeout governs
        headers: map[string]string{
            "Authorization":      "Bearer " + apiKey,
            "X-Sandswap-Api-Key": apiKey, // survives cross-host 307
        },
    },
}
transport := &mcp.StreamableClientTransport{
    Endpoint:             mcpURL, // https://sandswap.local:3000/mcp
    HTTPClient:           httpClient,
    DisableStandaloneSSE: true, // POST-only server: no SSE stream needed
}
cli := mcp.NewClient(&mcp.Implementation{Name: "my-agent", Version: "1.0.0"}, nil)
cs, err := cli.Connect(ctx, transport, nil) // initialize handshake happens here

res, err := cs.CallTool(ctx, &mcp.CallToolParams{
    Name: "execute",
    Arguments: map[string]any{
        "sandfs_id": sandfsID, "code": "echo hi", "language": "shell",
    },
})
```

Run the demo loop:

```bash
# Recommended: the per-sandfs domain (zero ownership redirects, single
# long-lived connection straight to the owner):
export SANDSWAP_MCP_URL=https://sandfs-xxx.sandfs.sandswap.local:3000/mcp
# The shared agent domain also works (one URL for every SandFS; a call for
# a SandFS owned elsewhere is 307-redirected — see the section above):
# export SANDSWAP_MCP_URL=https://sandswap.local:3000/mcp
export SANDSWAP_API_KEY=sk-sandswap-agent-...
export SANDSWAP_SANDFS_ID=sandfs-xxx        # discovered via list_sandfs
go run . -tools                             # list the 12 tools and exit
go run .                                    # full loop: sync, file, background, poll, kill
```

Tool-level failures return a `tools/call` result with `isError: true` and
the message in `content[0].text` — resilience errors keep their structured
fields (`error_code`, `retryable`, `retry_after_ms`) as JSON in that text.
HTTP-level behavior (raw 503 on load shed, 307 ownership redirect) matches
the HTTP API; JSON-RPC error codes are in the
[tools reference](../reference/mcp-tools.md#json-rpc-error-codes).

## 8. Server instructions

The gateway returns an **overall Sandswap guide** — how the sandbox works,
how to hold the warm path (background exec), SandFS self-description
(independent `README.md` files at the workspace root vs the sandbox root —
instance state vs base template), failure semantics and recovery — through
two channels fed by the same text:

1. **`initialize`** returns it in the standard `instructions` field (clients
   surface it to the LLM as context).
2. **`sandswap_guide`** tool returns it on demand. Stateless clients that skip
   the `initialize` handshake never see channel 1 — they can call this tool
   once before heavy use instead.

Both channels always serve the same text, and the text is
**deployment-customizable**: by default it is a built-in guide compiled into
the gateway; operators can point `-mcp-instructions-file` (or the
`mcp.instructions_file` YAML key) at a markdown file to replace or extend it —
e.g. site-specific guidance, failure-policy wording, or extra tips for their
agents. The file is **hot-reloaded** when edited in place (~200 ms event
debounce, no restart); a missing, unreadable, oversized (> 1 MB), or empty
file falls back to the built-in default with a warning instead of blocking
startup. Changing the configured *path* itself requires a restart.

The guide states the **sync-exec hard cap** explicitly ("sync execs are
HARD-CAPPED at N seconds; anything longer MUST use `background:true`") — the
`execute` tool description repeats it. The numbers are not hardcoded text: the
`{{max_exec_timeout_sec}}` placeholder is rendered at serve time from the
gateway's **live** `-max-exec-timeout-sec` value (hot-reload aware), and
`{{sticky_ms}}` from the live `-sticky-ms` idleness window, so the
agent-visible numbers always equal the enforced ones. Custom instruction files
may use the same placeholders; files without them are served verbatim.

Materializing the ops-editable file needs **no manual step** (the compiled
default is the single source of truth — no second copy in deploy templates):

- Point `-mcp-instructions-file` at a path and the gateway **materializes a
  missing file with the built-in default at startup** (atomic write,
  create-if-missing — an existing file, including operator edits, is never
  overwritten). This works wherever the gateway process can write the target
  directory (dev boxes, self-hosted).
- In production the gateway process deliberately lacks write access to its
  config directory (bare metal runs as a dedicated user against root-owned
  `/etc/sandswap`; k8s mounts the guide read-only from a ConfigMap), so the
  deploy tooling materializes it with its own privileges: bare-metal scripts
  generate `/etc/sandswap/mcp-instructions.md` as root (generate-once —
  re-deploys never clobber operator edits) and set the YAML key; Kubernetes
  seeds the `gateway-mcp-instructions` ConfigMap. Edit the file/ConfigMap
  directly — the gateway hot-reloads.
- `gateway -print-mcp-instructions` prints the built-in guide for
  inspection or piping; it is not a required step in any flow.

## 9. Framework examples

- **[examples/eino-sandswap](https://github.com/ChaoyiHuang/sandswap/tree/main/examples/eino-sandswap)**
  — CloudWeGo Eino: MCP tool discovery → OpenAI-style tool schema, two
  agents sharing one pool.
- **[examples/openai-sandswap](https://github.com/ChaoyiHuang/sandswap/tree/main/examples/openai-sandswap)**
  — official OpenAI SDKs; `SANDSWAP_BENCH_MODE=mcp` benchmarks the whole
  agent loop through MCP tool calls.
