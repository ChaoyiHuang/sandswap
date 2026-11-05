---
title: MCP Tools Reference
nav_order: 3
parent: Reference
---

# MCP Tools Reference

The 12 MCP tools exposed at `POST /mcp` (Streamable HTTP) and over stdio.
Transport, authentication, retry semantics, and the connection shapes are
covered in the [MCP server guide](../integration/agent-mcp.md);
HTTP-equivalent semantics (timeouts, background-exec lifecycle,
concurrency, size caps) in the [Agent API Reference](agent-api.md). This
page is the tool catalog: every tool's input schema, result shape, and
error behavior.

## Tools

| Tool | Backing call | Purpose |
|------|--------------|---------|
| `execute` | `/agent/execute` | Run code in a SandFS sandbox (sync or background). |
| `file_read` | `/agent/file` (read) | Read file bytes. |
| `file_write` | `/agent/file` (write) | Write text or base64 binary content. |
| `file_stat` | `/agent/file` (stat) | File/directory metadata. |
| `file_list_dir` | `/agent/file` (list_dir) | Directory listing with recursion. |
| `file_mkdir` | `/agent/file` (mkdir) | Create a directory (parents created). |
| `file_remove` | `/agent/file` (remove) | Remove a file or directory. |
| `file_rename` | `/agent/file` (rename) | Rename/move. |
| `exec_status` | `/agent/exec/status` | Poll a background exec's status + log tail. |
| `exec_kill` | `/agent/exec/kill` | Kill a background exec. |
| `list_sandfs` | `/agent/sandfs` | List the agent's SandFS instances. |
| `sandswap_guide` | *(server-side text)* | Return the server instructions on demand (call once before heavy use if `initialize` did not provide them). |

All tools resolve the caller's agent from the request's API key and go
through the same handler pipeline as the HTTP API — file and exec
operations always run inside a microVM, never on the gateway host.
`sandfs_id` is required on every per-sandfs tool; there is no
auto-resolution.

`tools/list` is built per agent: when the agent has SandFS instances, every
tool schema's `sandfs_id` property carries their ids as an `enum`, and the
`execute` description appends the instance list (name, id, description)
plus the abort contract and the live sync-exec cap. The HTTP transport
sets `Cache-Control: max-age=60` on `tools/list` responses.

## Input schemas

Argument types are JSON types; integer-valued arguments also accept a
numeric string, boolean arguments must be JSON booleans, and unknown
arguments are ignored. `sandfs_id` is a string naming one of the agent's
SandFS instances.

### `execute`

| Argument | Type | Required | Meaning |
|----------|------|----------|---------|
| `sandfs_id` | string | yes | Target SandFS. |
| `code` | string | yes | Code or command to execute. |
| `language` | string | yes | `python`, `shell`, `node`, etc. |
| `timeout` | integer | no | Sync-exec timeout in seconds; 0 = default. Values above the live sync cap are clamped and the command is killed at the cap. |
| `background` | boolean | no | Start a background exec and return an `exec_id` immediately. |
| `lease_duration` | integer | no | Background-exec hold in seconds (absolute run-time cap; polls do not extend it). 0 = the gateway's configured background-lease cap. |

### File tools

| Tool | Arguments |
|------|-----------|
| `file_read` | `sandfs_id` (required), `path` (required, relative to `/workspace`), `offset` (integer, default 0), `length` (integer; 0 = up to the single-read cap) |
| `file_write` | `sandfs_id` (required), `path` (required), `data` (string, text content), `data_base64` (string; when non-empty, decoded and takes precedence over `data`), `append` (boolean; writes at the end), `mode` (integer; 0 = default) |
| `file_stat` | `sandfs_id` (required), `path` (required) |
| `file_list_dir` | `sandfs_id` (required), `path` (required), `depth` (integer; 0 = flat) |
| `file_mkdir` | `sandfs_id` (required), `path` (required), `mode` (integer; 0 = default) |
| `file_remove` | `sandfs_id` (required), `path` (required), `recursive` (boolean) |
| `file_rename` | `sandfs_id` (required), `path` (required), `new_path` (required) |

A file-tool `path` is relative to the sandbox workspace. A leading `/`
is re-based onto `/workspace`; the sandbox root itself is reachable only
through `execute` (for example `cat /README.md`).

### Background exec and discovery

| Tool | Arguments |
|------|-----------|
| `exec_status` | `sandfs_id` (required), `exec_id` (required) |
| `exec_kill` | `sandfs_id` (required), `exec_id` (required) |
| `list_sandfs` | none |
| `sandswap_guide` | none |

## Results

Every successful `tools/call` returns `content[0].text` holding a JSON
document (or the guide text for `sandswap_guide`):

| Tool | `content[0].text` |
|------|-------------------|
| `execute` | `{"stdout","stderr","exit_code","exec_id","status","exec_duration_ns","sandlot_duration_ns","gateway_duration_ns"}`. `status` is `done`/`timed_out` for sync execs and `running` for background ones. |
| `file_read` | UTF-8 content: `{"ok":true,"data":<text>,"is_text":true,"size":<bytes>}`; binary content: `{"ok":true,"data_base64":<base64>,"is_text":false,"size":<bytes>}`. |
| `file_write` | `{"ok":true,"size":<bytes written>}` |
| `file_stat` | The warden's metadata object: `{"name","path","file_type","size","mode","modified_time"}` (`file_type` is `file`/`dir`/`symlink`). |
| `file_list_dir` | `{"entries":[{…metadata…}, …]}` |
| `file_mkdir`, `file_remove`, `file_rename` | `{"ok":true}` |
| `exec_status` | `{"status","exit_code","stdout","stderr"}`; `status` is `running`/`done`/`killed`/`not_found`/`expired`, and `stdout`/`stderr` are the captured log tails. |
| `exec_kill` | `{"status"}` — `killed`, `not_found` (idempotent: the exec is not in the registry), or `expired`. |
| `list_sandfs` | `{"sandfs_list":[{"sandfs_id","name","description","template","created_at","status"?}]}` — `status` is present only for a non-active instance (template swap or deletion in progress). |
| `sandswap_guide` | The rendered server instructions (plain text). |

A `file_stat`/`file_list_dir` payload that is not valid JSON is returned
as `{"ok":true,"data":<text>}` / `{"ok":true,"entries":<text>}`
respectively (defensive fallback; the warden always emits JSON).

## Tool-level errors

Tool failures are **not** JSON-RPC errors: the response is a `tools/call`
result with `isError: true` and the message in `content[0].text`. Three
shapes appear there:

1. **Structured resilience refusal** — JSON with `error`, `error_code`,
   `retryable`, and `retry_after_ms` (for example
   `NO_AVAILABLE_SANDBOX`, `SHED_REBALANCE`, `OWNERSHIP_CONFLICT`). On
   `retryable: true`, retry the SAME request after `retry_after_ms`; do
   not modify the request body.
2. **Named client-class refusal** — JSON with `error`, `error_code`,
   `http_status`, `retryable:false`. Currently the wire-size gates:
   `EXEC_TOO_LARGE` (wrapped command over the stream message limit) and
   `FILE_TOO_LARGE` (file data or read length over the single-op cap) and
   `FILE_PATH_TOO_LONG` (a `path`/`new_path` above PATH_MAX−1).
   These are refused before anything reaches the node stream.
3. **Plain text** — validation and application failures: an unknown tool
   (`unknown tool: <name>`), a missing required argument (`sandfs_id is
   required`, `exec_id is required`), invalid base64 in `data_base64`, or
   a file operation's application error (`<action>: <message>`, e.g. file
   not found).

A load-shed refusal is special on the HTTP transport: it is written as a
raw `503` with `Retry-After` and `Connection: close` (not an `isError`
result), so the client closes the connection and re-resolves the sandfs
DNS name to reach a peer that can claim it. The stdio transport, which
cannot emit HTTP statuses, surfaces the same condition as a JSON-RPC
`-32001` error.

## JSON-RPC error codes

| Code | Meaning |
|------|---------|
| `-32700` | Parse error (malformed JSON body). |
| `-32600` | Method not allowed (non-POST request) / request body too large (> 50 MB). |
| `-32601` | Method not found. Supported methods: `initialize`, `ping`, `tools/list`, `tools/call`. |
| `-32602` | Invalid params (`tools/call` params do not decode into a tool call). |
| `-32001` | Missing/invalid API key (also returned when the key does not resolve on `initialize`/`tools/list`/`tools/call`); on HTTP, an ownership conflict for a request that already arrived redirected (`X-Sandswap-Redirected: 1`, the anti-loop); on stdio, the encoding of an ownership redirect (`redirect to <owner-url>`) or a load-shed refusal. |

The HTTP transport expresses an ownership redirect as a real `307` to the
owner gateway's `/mcp` and marks the response with
`X-Sandswap-Redirected: 1`; a request that arrives carrying that header is
never redirected again. Authentication is per request — the server is
stateless (no `Mcp-Session-Id`), and an `initialize` call is answered
(echoing the client's protocol version, default `2025-03-26`) only for
compatibility with older clients.

## Server instructions and the instruction file

Two channels serve the same **overall Sandswap guide**, rendered at serve
time:

1. the `instructions` field of the `initialize` result;
2. the `sandswap_guide` tool (for stateless clients that skip the
   handshake).

The built-in default is compiled into the gateway. Operators replace or
extend it with `-mcp-instructions-file` (YAML `mcp.instructions_file`)
pointing at a markdown file:

- **Size/content bounds:** at most 1 MB; a missing, unreadable, oversized,
  or empty-after-trim file falls back to the built-in default with a
  warning and never blocks startup.
- **Missing file:** when the gateway can write the target directory it
  materializes the built-in default at startup (atomic create-if-missing;
  an existing file is never overwritten). In production the gateway
  deliberately cannot write its config directory, so the deploy tooling
  materializes the file with its own privileges instead (bare-metal root
  generate-once; Kubernetes `gateway-mcp-instructions` ConfigMap).
- **Hot reload:** edits apply without a restart through the gateway's
  shared config-reload watcher (fsnotify, ~200 ms debounce, parent-dir
  watch — so vim's write-temp-and-rename and kubelet's ConfigMap symlink
  swap both reload). The reload validates the same size/content bounds. A
  file that disappears mid-flight keeps the last good text; a re-save
  reloads normally. Changing the configured **path** requires a restart.
- **Placeholders:** `{{max_exec_timeout_sec}}` and `{{sticky_ms}}` are
  substituted with the live `-max-exec-timeout-sec` and `-sticky-ms`
  values (hot-reload aware), so the agent-visible numbers always equal the
  enforced ones. Custom files may omit them (served verbatim) or use them.
  `gateway -print-mcp-instructions` prints the compiled default for
  inspection; it is not a required step in any flow.

## Limits

| Limit | Value | Behavior |
|-------|-------|----------|
| HTTP request body | 50 MB | JSON-RPC `-32600` "request body too large" (aligned with `/agent/file` so a 16 MB binary write fits base64-inflated). |
| Single FileOp payload | gRPC max message size − 64 KiB (16 MiB − 64 KiB by default) | `FILE_TOO_LARGE` structured refusal before any stream write; split the write or page the read with `offset`. |
| Sync exec runtime | live `-max-exec-timeout-sec` (default 180 s) | A larger `timeout` is clamped and the command killed at the cap; use `background:true` for longer work. |
| Background exec runtime | live `-max-background-lease-sec` (default 1 h) | `lease_duration` is the absolute cap; status polls do not extend it. |
