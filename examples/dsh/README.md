# DeepSeek Harness runs its whole coding loop inside Sandswap

DeepSeek Harness (DSH) runs on **your** machine and connects to Sandswap's
MCP server (`POST /mcp`). This directory is a **DSH plugin bundle** that
does for DSH what `examples/claude-code` does for Claude Code — with the
same zero-SDK shape: install one local directory as a plugin, and the
agent's whole edit-run-test loop moves into a SandFS sandbox on a tinyVM.
Nothing it does touches your machine.

```text
 DeepSeek Harness (your machine)           Sandswap (one node or cluster)
 ┌───────────────────────────┐    MCP    ┌─────────────────────────────────┐
 │ @sandswap/dsh-sandbox     │  HTTP(S)  │ gateway ──▶ sandlot ──▶ tinyVM  │
 │  mounts /mcp connection   │ ────────▶ │              SandFS  ◀─ ubuntu  │
 │  pwsh/bash/write/edit:    │           │              /workspace (persist)│
 │  hidden + denied          │           └─────────────────────────────────┘
 └───────────────────────────┘
```

The plugin is one entry doing both halves:

1. **MCP connection** — mounts the gateway endpoint through DSH's built-in
   `@deepseek-ai/dsh-mcp-client` module, sending both auth headers on every
   request (`Authorization: Bearer` + `X-Sandswap-Api-Key`; the custom
   header survives the cross-host 307 ownership redirect). The 12 sandbox
   tools appear as `mcp__sandswap__*`.
2. **Sandbox policy** — hides the local shell and file-write tools
   (`pwsh`, `bash`, `write`, `edit`) from every new agent and denies them
   at execution, and adds a system-prompt section that routes every coding
   task into the sandbox. This is the same recipe as the Claude Code
   example's `.claude/settings.json` deny list, implemented as DSH tool
   restrictions instead.

| File | Role |
|------|------|
| `README.md` | this walkthrough — every step is a copy-paste command |
| `package.json` | bundle manifest (`dsh.bundle.patch`) |
| `cordis.patch.yml` | the plugin row: endpoint, key variable, restricted tools |
| `index.js` | plugin implementation: MCP mount + agent sandbox policy |
| `locale/`, `icon.svg`, `docs/` | Plugin Manager display resources |

## Step 1 — Deploy Sandswap

On the sandbox host, deploy as in [Deployment](../../docs/deployment/index.md)
(bare metal or Kubernetes). On a TLS deployment
whose dev certificates must cover a non-loopback name, add the SANs at mint
time: `deploy/baremetal/gen-baremetal-certs.sh --sans-ip <ip> --sans-dns
<name>`. `--no-tls` also works (plaintext, trusted networks only).

## Step 2 — Create the agent and the SandFS

Agent creation is part of the [agent API](../../docs/reference/agent-api.md);
from the Sandswap root on the sandbox host:

```bash
output/sandctl --raw api agent create --name dsh
# → {"agent_id":"agent-…","api_key":"sk-sandswap-agent-…"}   (shown once)

output/sandctl --raw api sandfs create --agent agent-… --name dsh \
    --template ubuntu:24.04 --mode flat --vcpus 2 --memory-mb 512
```

## Step 3 — Install the bundle into DSH

Copy this directory to the machine running DSH, then in DSH's
**Plugins** page choose **Add plugin** and select the directory (or, from
an agent with plugin management: install the bundle from its path).

## Step 4 — Wire the environment, start DSH

Export the agent API key from step 2. Keep the variable name
`SANDSWAP_AGENT_API_KEY` as-is — do not shorten it to `SANDSWAP_API_KEY`:
`sandctl` reads that shorter name on every `--agent` call, so a key exported
under it for DSH would silently hijack all your other `sandctl` usage.

Endpoint (default `https://localhost:3000/mcp`; pick a shape):
TLS single node `https://localhost:3000/mcp` · plaintext (`--no-tls`)
`http://<host>:3000/mcp` · shared agent domain
`https://sandswap.local:3000/mcp` (307 to owner) · per-SandFS domain
`https://<sandfs_id>.sandfs.sandswap.local:3000/mcp`.

Linux/macOS (bash):

```bash
export SANDSWAP_AGENT_API_KEY=sk-sandswap-agent-…
export SANDSWAP_URL=https://<sandbox-host>:3000/mcp
# TLS only: trust the deployment CA (copy /etc/sandswap/certs/ca.crt over)
export NODE_EXTRA_CA_CERTS=/path/to/ca.crt
```

Windows (PowerShell — DSH runs on both):

```powershell
$env:SANDSWAP_AGENT_API_KEY = "sk-sandswap-agent-…"
$env:SANDSWAP_URL = "https://<sandbox-host>:3000/mcp"
# TLS only: trust the deployment CA (copy ca.crt over, any local path)
$env:NODE_EXTRA_CA_CERTS = "C:\path\to\ca.crt"
```

Then start DSH (the variables must be set before it starts; changing them
later needs a plugin reload — toggle the **sandswap-sandbox** row in
**Plugins**).

## Step 5 — Run a task

Open a **new** session and give it a coding task. The model sees the 12
`mcp__sandswap__*` tools, no local shell and no local file-write tools, and
the sandbox guide in its system prompt. A complete loop looks like the
Claude Code example's: one `execute` to survey, `file_read`/`file_write` to
fix, one `execute` to re-run the suite and commit — all inside the tinyVM.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Tools missing, plugin row shows a connection error | `SANDSWAP_AGENT_API_KEY` not set before DSH started; or the URL scheme does not match the deployment (`http://` vs `https://`); TLS also needs `NODE_EXTRA_CA_CERTS`. Toggle the plugin row after fixing. |
| `mcp__sandswap__*` calls fail with `missing or invalid api key` | key mismatch — re-create the agent or fix the variable. |
| TLS `unable to verify the first certificate` | the certificate SAN does not cover the name in the URL (see step 1) or `NODE_EXTRA_CA_CERTS` points at the wrong CA. |
| `execute` returns 503 / `SANDBOX_CLEANING` with `retryable: true` | the sandbox is mid-recycle — a transient of a few ms; retry the same request. |
| Local `pwsh`/`bash`/`write`/`edit` still visible | the session was created before the plugin loaded (the policy applies at agent creation); open a new session, or set `restrictTools: []` to keep local tools and only add guidance. |

## Configuration

Edit `cordis.patch.yml` (then toggle the plugin row to reload):

| Key | Default | Meaning |
|-----|---------|---------|
| `serverName` | `sandswap` | MCP tool namespace (`mcp__<serverName>__*`) |
| `url` | `https://localhost:3000/mcp` (or `SANDSWAP_URL`) | gateway endpoint |
| `apiKey` | — | set the key directly instead of the environment variable |
| `apiKeyEnv` | `SANDSWAP_AGENT_API_KEY` | variable read at mount time |
| `restrictTools` | `[pwsh, bash, write, edit]` | local tools to hide and deny; `[]` keeps all |
| `toolCallTimeoutMs` / `startupTimeoutMs` / `failOnStartupError` | client defaults | forwarded to the MCP client |

## License

Apache-2.0 (see [`../../LICENSE`](../../LICENSE)) — everything under `examples/`
is Apache-2.0, so the wiring can be copied into any project.
