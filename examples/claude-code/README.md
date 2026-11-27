# Claude Code runs its whole coding loop inside Sandswap

Claude Code runs on **your** machine and connects to Sandswap's MCP server
(`POST /mcp`). It does a real coding task — run a failing test suite, fix
the code, re-run, commit — **entirely inside a SandFS sandbox** on a tinyVM.
The project's `.claude/settings.json` denies the local `Bash`, `Write` and
`Edit` tools, so every command goes through the `execute` tool and every
file change through the `file_*` tools: nothing it does touches your
machine.

The sandbox is the **stock `ubuntu:<release>` template** the deployer
registers from `build.sh ubuntu-rootfs` — Ubuntu 24.04 with a general
coding toolchain (python3 + pip/venv, git, make, curl, unzip, procps). No
OCI image, no custom template: Claude Code clones, edits, tests and commits
out of the box.

This example has two points. The first is the wiring: a Claude Code →
Sandswap integration is **one `.mcp.json` file**. The second is efficiency:
what a tool call costs and how to make an agent's loop fast — measured on
this exact setup, in [Step 9](#step-9--see-where-the-time-went).

```text
 Claude Code (your machine)                Sandswap (one node)
 ┌──────────────────────────┐   MCP     ┌─────────────────────────────────┐
 │ .mcp.json → localhost:3000/mcp ─────▶│ gateway ──▶ sandlot ──▶ tinyVM  │
 │ .claude/settings.json    │  HTTPS    │              SandFS  ◀─ ubuntu  │
 │  Bash/Write/Edit: denied │           │              /workspace (persist)│
 └──────────────────────────┘           └─────────────────────────────────┘
```

## What is here

| File | Role |
|------|------|
| `README.md` | this walkthrough — every step is a copy-paste command |
| `.mcp.json` | project MCP config: Streamable HTTP server `sandswap`, URL from `${CLAUDE_CODE_SANDBOX_MCP_URL}` (TLS localhost default) and `${CLAUDE_CODE_SANDBOX_API_KEY}` in both auth headers |
| `.claude/settings.json` | auto-approves the project MCP server + its tools; denies local `Bash`/`Write`/`Edit`/`NotebookEdit` |
| `TASK.md` | the coding task to give Claude Code, written to exercise the efficient pattern |
| `seed.sh` | puts TASK.md's failing project into the sandbox's `/workspace` (step 6) |
| `lib.sh` | `sx_exec`: run a command in the sandbox through `sandctl`, retrying the gateway's retryable busy states |
| `setup.sh` | does steps 3–5 in one command and writes `.env.sh` |
| `validate.py` | repeat the real-model task headlessly and verify tool use and sandbox state |
| `analyze_session.py` | after the run: rebuilds the turn from Claude Code's own transcript as thinking→tool rounds, and splits the time into LLM / tools / Sandswap |

## Step 0 — Before you start

**Where to run what.** You need two ordinary terminals and one Claude Code
window — three separate programs, none nested:

| Window | What it is | Used for |
|---|---|---|
| **Terminal A** | a normal system terminal | `sandctl`, `seed.sh`, and *launching* `claude` in step 7 |
| **Claude Code** | the interactive UI terminal A launches in step 7 | step 8 only: give the task, watch the tool calls |
| **Terminal B** | a second normal terminal | step 8, verifying from outside while Claude Code stays open; step 9, if you run the analyzer from here |

> **Do not run any command below inside an existing Claude Code session —
> and above all not `claude`.** That is Claude Code inside Claude Code; it
> hangs. Copy every command into your own terminal instead.

**Get Sandswap — two ways.** Every command below runs from the **Sandswap
root** and uses the artifacts under `output/`; pick one way, the steps are
the same from either:

| Way | Sandswap root | Build |
|---|---|---|
| **A. Release package** — everything prebuilt, no toolchain | the extracted `sandswap-<ver>-linux-amd64/` | none (`build/` is not shipped) |
| **B. Source checkout** — you build it | the repository root | `build.sh all` |

**A. Release package** — download, verify, extract, as in the repository
README's [quick start](../../README.md#quick-start):

```bash
# resolve the latest release tag (or pin one, e.g. VER=v0.1.0)
VER=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    https://github.com/ChaoyiHuang/sandswap/releases/latest | awk -F/ '{print $NF}')
echo "latest release: ${VER}"

# download + verify + extract
curl -fLO "https://github.com/ChaoyiHuang/sandswap/releases/download/${VER}/sandswap-${VER}-linux-amd64.tar.gz"
curl -fLO "https://github.com/ChaoyiHuang/sandswap/releases/download/${VER}/SHA256SUMS"
sha256sum -c SHA256SUMS
tar xzf "sandswap-${VER}-linux-amd64.tar.gz" && cd "sandswap-${VER}-linux-amd64"
```

**B. Source checkout** — clone, install the toolchain, build:

```bash
git clone https://github.com/ChaoyiHuang/sandswap.git
cd sandswap
sudo bash build/install-deps.sh    # one-time toolchain
sudo bash build/build.sh all       # kernel → warden → initramfs → vmm → go (+ rootfs chroot)
```

**Prerequisites.** A KVM host (`/dev/kvm`, `/dev/vhost-vsock`); the
`claude` CLI installed and logged in (`claude --version`). Build
prerequisites for B: [Building](../../docs/building/index.md). Source
checkout only — if the source changed since the last build:

```bash
bash build/build.sh check            # all [FRESH] → nothing to do
sudo bash build/build.sh all         # otherwise; the Ubuntu template layer needs root
```

(Go-only changes: `bash build/build.sh go` is enough.)

## Step 1 — Start from a clean slate, then deploy

Whatever state the host is in — fresh boot, an old deployment, a demo left
halfway — begin by uninstalling, so every later step shows a known state.

**Disk first** (the deployer's preflight needs ≥1500 MB free on `/var/lib`,
or it refuses):

```bash
df -h /var/lib | tail -1
```

Short on space, clear in this order (none of it touches `output/` or the
kernel):

```bash
go clean -cache                     # Go build cache, typically 1–2 GB
sudo journalctl --vacuum-size=50M   # system journal
sudo apt-get clean                  # apt package cache
```

**Uninstall:**

```bash
sudo bash deploy/baremetal/uninstall.sh
```

Expected last line: `✓ Environment is clean`. This stops and removes every
unit, detaches vsockguard, and deletes `/etc/sandswap`, `/var/lib/sandswap`
(**all agent and sandbox data**) and the logs.

**Deploy:**

```bash
sudo bash deploy/baremetal/deploy-single-node.sh --skip-build
```

Success is the last line `Sandswap single-node deployment complete!`. The
deployer prepares the host (service identities, udev, sysctls), **attaches
vsockguard itself**, mints the certificates, stages the two templates
(`rootfs:v1` busybox, `ubuntu:24.04` with the coding toolchain), installs and
starts `sandswap-gateway` + `sandswap-sandlot`, waits for the pool, and
writes `/etc/sandswap/sandctl.env` and `mcp-instructions.md`. Drop
`--skip-build` to build first. `--no-tls` makes the HTTP listeners plaintext
(see [Variants](#variants)).

If preflight reports `[BLOCK]`:

| Blocker | Fix |
|---|---|
| `only NNNMB free on /var/lib filesystem` | clear disk as above |
| `orphan sandswap processes survived cleanup` | uninstall again, then retry |

> Do not combine the deploy and a `systemctl … sandswap-sandlot` check in
> one command line: an older preflight mistook the launching shell (whose
> argv merely mentions the names) for its own orphan. This tree identifies
> processes by executable; on an older one, run the two as separate commands.

## Step 2 — Check the stack and the template

```bash
systemctl is-active sandswap-gateway sandswap-sandlot
for i in $(seq 1 24); do output/sandctl pool 2>&1 | grep -qE 'clean 3 / total 3' && break; sleep 5; done
output/sandctl pool | head -1
output/sandctl health-all
output/sandctl api template list
```

Expected: `active active`; the pool line `clean 3 / total 3 / in-use 0`
(first boot 10–20 s); all four probes `HTTP 200`; templates `rootfs:v1` and
`ubuntu:24.04`.

## Step 3 — Create an agent

```bash
output/sandctl --raw api agent create --name claude-code
```

```json
{"agent_id": "agent-0d4f8c21", "api_key": "sk-sandswap-agent-…", "name": "claude-code"}
```

The key is shown once (it is also cached in `run/agents.json` for
`sandctl`). Export it for Claude Code:

```bash
export CLAUDE_CODE_AGENT_ID=agent-0d4f8c21          # from the output above
export CLAUDE_CODE_SANDBOX_API_KEY=sk-sandswap-agent-…      # from the output above
```

> The variables carry a `CLAUDE_CODE_SANDBOX_` prefix on purpose. A generic
> name like `SANDSWAP_API_KEY` would collide: `sandctl` reads that one from
> the environment for **every** `--agent` call, so a key exported for this
> example would silently hijack all your other `sandctl` usage.

## Step 4 — Create the SandFS

```bash
output/sandctl --raw api sandfs create --agent "$CLAUDE_CODE_AGENT_ID" \
    --name claude-code --template ubuntu:24.04 --mode flat --vcpus 2 --memory-mb 512
```

`--mode flat` copies the template into a private, writable volume — that
is what lets the sandbox `apt install`/`pip install` and `git commit`.
Note the `sandfs_id`:

```bash
export CLAUDE_CODE_SANDFS_ID=sandfs-…               # from the output above
```

## Step 5 — Look inside the sandbox, and see what a call costs

```bash
output/sandctl api execute --agent "$CLAUDE_CODE_AGENT_ID" --sandfs "$CLAUDE_CODE_SANDFS_ID" \
    --language shell --code 'python3 --version && git --version && make --version | head -1'
```

Expected: Python 3.12, git 2.43, GNU Make 4.3, running in the tinyVM. Look
at `exec_duration_ns` in the response — then compare with the cheapest
possible call:

```bash
output/sandctl api execute --agent "$CLAUDE_CODE_AGENT_ID" --sandfs "$CLAUDE_CODE_SANDFS_ID" \
    --language shell --code 'true'
```

The second call is several times cheaper, on the identical Sandswap path.
That difference is **process startup inside the guest** (the interpreters
and tools the first call starts), not Sandswap — and it is the whole story
of making an agent fast here (Step 9).

## Step 6 — Seed the demo task

```bash
bash examples/claude-code/seed.sh
```

This resets `/workspace` to a small Python package whose suite fails on two
bugs in `calc/core.py`, committed on `main`. The tail of the output shows
the failures — that is the state Claude Code starts from. Idempotent: rerun
it any time to reset.

## Step 7 — Connect Claude Code

The three exports from steps 3–4 must still be in this shell (`export` is
per-terminal — in a new one, export them again):

```bash
echo "$CLAUDE_CODE_AGENT_ID"; echo "$CLAUDE_CODE_SANDFS_ID"; echo "${CLAUDE_CODE_SANDBOX_API_KEY:0:24}..."
```

Three values printed → go on. (Lost the key? It is shown once at creation;
`cat run/agents.json` has the copy `sandctl` cached — pick the entry by
`agent_id`, old agents accumulate there across reinstalls.) Then:

```bash
cd examples/claude-code
export NODE_EXTRA_CA_CERTS=/etc/sandswap/certs/ca.crt      # TLS deploy: trust the deployer's CA (covers localhost / 127.0.0.1)
claude "Complete the task in TASK.md using only the sandswap tools."
```

The prompt can also be typed once Claude Code is up — what matters is that
Claude Code is launched from this directory. It reads `.mcp.json` and
`.claude/settings.json` from here. The first launch shows the workspace **trust** dialog — accept
it (project settings, including the MCP auto-approval, are ignored in an
untrusted workspace). `enableAllProjectMcpServers` then approves the
`sandswap` server so there is no MCP prompt. Confirm with `/mcp`: the
`sandswap` server should show **connected** with 12 tools.

## Step 8 — Run the task

If you launched Claude Code with the prompt above it is already running;
otherwise type (or paste `TASK.md`):

```text
Complete the task in TASK.md using only the sandswap tools.
```

Claude Code will `list_sandfs`, survey the project with **one** `execute`,
read `calc/core.py` with `file_read`, fix it with `file_write`, and re-run
the suite + commit with **one** more `execute` — all through the MCP tools,
with your local shell and editor denied the whole time. `TASK.md` asks for
that shape on purpose: it is the efficient one, and the point of the
example (the analyzer in the next step shows what it saves).

Verify from the outside when it finishes (another terminal; Claude Code
stays open):

```bash
output/sandctl api execute --agent <agent id> --sandfs <sandfs id> \
    --language shell --code 'cd /workspace && python3 -m unittest discover -s tests && git log --oneline'
```

Expected: `OK`, and two commits — `fix calc` on top of `add failing calc
suite`.

### Repeatable headless validation

After steps 1–6, run the installed Claude Code CLI on the **same Linux host**
as Sandswap when collecting timings. Supply model credentials through
`ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_API_KEY`. For example, with a key authorized
for GLM's [Claude-compatible endpoint](https://docs.bigmodel.cn/cn/coding-plan/tool/claude):

```bash
source examples/claude-code/.env.sh   # written by setup.sh; or keep the exports from steps 3–4
export NODE_EXTRA_CA_CERTS=/etc/sandswap/certs/ca.crt
export ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic
export ANTHROPIC_MODEL=glm-5.3-flash
python3 examples/claude-code/validate.py --output-dir examples/claude-code/.work/validation-1
```

Before another run, reset the disposable example with `seed.sh` and choose a
new output directory. `validate.py` uses isolated Claude configuration, strict
MCP configuration, `--tools ''`, and `--allowedTools mcp__sandswap` in `dontAsk`
mode. It supplies `TASK.md` directly and requires actual discovery, execute,
read and write calls with successful results. Independent sandbox checks
require 5/5 unchanged tests, the `fix calc` commit, and additional function
checks. A nonzero exit means validation failed. Keep generated records local;
publish only a reviewed, sanitized summary, without credentials or sandbox keys.
See Claude Code's [headless documentation](https://code.claude.com/docs/en/headless).

The output directory also contains the isolated CLI session under
`claude-config/projects/`. Pass its task `.jsonl` file to the analyzer in step 9,
or export that run's `CLAUDE_CONFIG_DIR` to let it find the transcript.

## Step 9 — See where the time went

Claude Code records each LLM response and tool result with timestamps. After
running the task, use a normal terminal with the sandbox exports from steps
3–4 (or source `examples/claude-code/.env.sh`):

```bash
python3 examples/claude-code/analyze_session.py             # newest TASK.md session here
python3 examples/claude-code/analyze_session.py <session.jsonl>
```

The analyzer prints the coding loop, the model-response intervals, and tool
execution by layer. It includes the initial prompt wait, groups streamed
blocks by provider message ID, and counts parallel tool waits once. Each
client interval starts at its own recorded `tool_use` and ends at its result.
Tools can run while later model blocks arrive, so the additive task breakdown
counts only tool wait **after model emission**. The analyzer also shows the
union of complete tool intervals (which may overlap model time) and the sum
of individual durations (which can double-count parallel calls).

For `execute`, the gateway reports gateway, sandlot and guest durations. The
analyzer measures 30 `sh -c :` calls on the same sandbox to estimate the guest
process-start floor. Without usable sandbox exports or a reachable gateway,
it prints `NOT MEASURED` with the reason instead of assuming a baseline.
Certificate and hostname verification remain enabled; set `NODE_EXTRA_CA_CERTS`
to the deployment CA and `CLAUDE_CODE_SANDBOX_MCP_URL` to the actual endpoint.

**Timing boundaries.** Client time minus gateway time is a residual containing
client scheduling, serialization, connection handling and transport. It is
not an independently measured network RTT or TLS handshake. File/list tools
have no separate server timing fields, so their client intervals cannot be
attributed wholly to Sandswap. Model API time includes the external provider
path even when Claude Code and Sandswap share a host.

For repeatable comparisons, record client/server placement, virtualization,
transport (HTTP/HTTPS, direct/SSH), connection reuse, model/version, task and
sandbox template. Measure network RTT separately if attributing network cost.
A Mac→SSH→remote-host run is a useful integration check, but its client/tool
ratios are specific to that network path. Do not compare them directly with
a same-host server-latency benchmark.

### Historical nested-virtualization example

The earlier upstream interactive example used the Ubuntu template in nested
virtualization. Its two `execute` calls took **250 / 321 ms** at the client,
and its measured 30-call guest exec floor was **8.7 ms**. It used six model
responses, six MCP calls, and one local `Read` of the task prompt.

That snapshot came from an older analyzer which omitted the initial model
wait and summed overlapping tool intervals. Its reported 64.92 s task span
is therefore not directly comparable with the current accounting. The old
`http/tls` column was a client–gateway residual, not a network measurement.
Use the current analyzer on your own transcript for a consistent comparison.

### Sandbox startup is a separate measurement

The 2026-11-26 bare-metal supplement below used source `6126eb8`, 30 successful
samples per case after one excluded warmup, median P50 and nearest-rank P95.
These are sandbox measurements without a model in the loop.

| Operation | P50 | P95 |
|---|---:|---:|
| New VM → verified warden readiness, 1 vCPU / 256 MiB | 153.599 ms | 173.676 ms |
| New VM → verified warden readiness, 2 vCPUs / 512 MiB | 155.451 ms | 156.721 ms |
| Ready pool: BusyBox flat SandFS create → first command result | 7.614 ms | 8.397 ms |
| Ready pool: Ubuntu 24.04 flat SandFS create → first command result | 556.918 ms | 571.432 ms |

VM timing covers `CreateVerifiedVM` through authenticated warden readiness;
each VM was destroyed before the next sample. Guests were offline, so TAP/NAT
setup is excluded. The ready-pool measurements use three 4-vCPU/1024-MiB VMs,
same-host HTTP, and `POST /human/sandfs` followed by `execute` (`printf ready`).
They exclude agent registration, downloads and VM boot. Host cache was not
dropped and CPU/NUMA was not manually pinned. Ubuntu's flat-template
materialization dominated creation (P95 **566.656 ms**); its first command
alone was **5.863 ms**. These are not MCP or Claude Code latency percentiles.

For native warm/cold command and load measurements, see the
[benchmark reports](../../docs/benchmark/index.md). A cold SandFS mount on a
ready VM is different from starting a new guest kernel.

## Step 10 — Clean up

```bash
output/sandctl api sandfs delete "$CLAUDE_CODE_SANDFS_ID"
output/sandctl api agent delete "$CLAUDE_CODE_AGENT_ID"
```

To remove the deployment as well: `sudo bash deploy/baremetal/uninstall.sh`.

## One-command variant

`setup.sh` does steps 3–6 (reusing an existing agent/SandFS, so it is safe
to rerun) and writes `examples/claude-code/.env.sh` with the exports:

```bash
bash examples/claude-code/setup.sh
source examples/claude-code/.env.sh
export NODE_EXTRA_CA_CERTS=/etc/sandswap/certs/ca.crt   # TLS deploy
cd examples/claude-code && claude "Complete the task in TASK.md using only the sandswap tools."
```

## Variants

- **Stricter**: add `"Read"` to the deny list so even file *reading* happens
  through `file_read` in the sandbox (then paste TASK.md's text rather than
  naming the file).
- **Looser**: keep local file editing and only route commands through the
  sandbox — `"deny": ["Bash"]`.
- **`--no-tls` deployment**: no file edit needed — `setup.sh` detects the
  plaintext listener and writes
  `CLAUDE_CODE_SANDBOX_MCP_URL=http://localhost:3000/mcp` into `.env.sh`
  (source it before launching). If you exported the values by hand instead,
  `export CLAUDE_CODE_SANDBOX_MCP_URL=http://localhost:3000/mcp`; and skip
  `NODE_EXTRA_CA_CERTS`.
- **More packages**: the flat sandbox is a build environment —
  `apt-get install -y build-essential nodejs` through `execute`, then
  `output/sandctl api sandfs save-template "$CLAUDE_CODE_SANDFS_ID" --name coding --version v1`
  freezes it as a reusable template
  ([Templates](../../docs/how-it-works/templates.md)).
- **Busybox for pure-shell work**: `rootfs:v1` starts a shell several times
  faster than the Ubuntu template (its `/bin/sh` is a small static busybox,
  Ubuntu's is a dynamic dash); use it when the task needs no Python.
  Statically compiled binaries (C/Go) start in about the time of a shell
  start regardless of template — close to the shell, far from an
  interpreter — if you ship one in the template.

### Mac or another remote Claude Code client

Remote use is supported. Complete provisioning and `seed.sh` on the Linux host,
then, from this example directory on the client, copy the deployment CA and
example environment to a private local directory. Replace `HOST`, `SSH_PORT`
and `REMOTE_REPO` with your deployment:

```bash
mkdir -p .work/connection
chmod 700 .work/connection
scp -P "$SSH_PORT" "root@$HOST:/etc/sandswap/certs/ca.crt" .work/connection/
scp -P "$SSH_PORT" "root@$HOST:$REMOTE_REPO/examples/claude-code/.env.sh" .work/connection/
chmod 600 .work/connection/.env.sh
source .work/connection/.env.sh
export CLAUDE_CODE_SANDBOX_MCP_URL=https://localhost:34443/mcp
export NODE_EXTRA_CA_CERTS="$PWD/.work/connection/ca.crt"
ssh -N -o ExitOnForwardFailure=yes -p "$SSH_PORT" \
    -L 127.0.0.1:34443:127.0.0.1:3000 "root@$HOST"
```

Keep the tunnel open. In another terminal, repeat the environment exports,
supply model authentication, and run `claude` or
`python3 validate.py --output-dir .work/validation-remote-1`.
Three Mac + GLM-5.3-flash coding runs passed this route
on 2026-11-26, with 17 MCP calls and independent sandbox checks. This confirms
integration; SSH/network distance and jitter make the observed client timing
specific to that route. Use the same-host setup in step 9 for timing analysis.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `/mcp` shows `sandswap` **failed** | `CLAUDE_CODE_SANDBOX_API_KEY` not exported in the shell that launched `claude`; or, on a TLS deploy, `NODE_EXTRA_CA_CERTS` unset (Node refuses the deployer's CA); or the URL scheme does not match the deployment (see Variants). |
| Claude asks to approve the MCP server | launched from a directory other than `examples/claude-code` (settings not loaded) — `cd` there first. |
| `Ignoring permissions… this workspace has not been trusted` | accept the trust dialog on the first interactive launch; project settings (including the MCP auto-approval) are ignored in an untrusted workspace. |
| `execute` returns `404 sandfs not found` | wrong `sandfs_id` — the tool schema's `sandfs_id` enum lists the agent's SandFS instances; `list_sandfs` is the source of truth. |
| `sandctl api execute` prints `HTTP 503`, or Claude's `execute` returns `SANDBOX_CLEANING` / `NO_AVAILABLE_SANDBOX` with `retryable: true` | the sandbox is mid-recycle (its previous unmount is still finishing, or the pool is handing over a VM) — a transient of a few ms, not a failure. Run the command again; Claude Code retries on `retryable: true` per the tool contract (the scripts' `sx_exec` already does). |
| After a host reboot the pool shows 0 nodes / sandlot will not start | vsockguard is a BPF program and does not survive a reboot; the sandlot's attest step refuses to start (fail-closed). Re-run step 1 (the deployer re-attaches it), or by hand: `sudo bash security/vsockguard-attach.sh && sudo systemctl reset-failed sandswap-sandlot && sudo systemctl restart sandswap-sandlot`. |
| `HTTP 401 invalid api key` from `sandctl --agent …`, yet the key is right | a `SANDSWAP_API_KEY` left in the shell by something else — sandctl prefers that env var over `--agent` for every call. `unset SANDSWAP_API_KEY` (this example never sets it; it uses `CLAUDE_CODE_SANDBOX_API_KEY`). |
| the key is gone | it is shown once at creation; `cat run/agents.json` has the copy `sandctl` cached (pick the entry by `agent_id` — old agents accumulate there across reinstalls). Otherwise delete the agent and create a new one. |
| `ubuntu:24.04` missing from `template list` | deployed with `--skip-build` before `output/rootfs-ubuntu` existed — `sudo bash build/build.sh ubuntu-rootfs` and redeploy, or register by hand ([Building Templates](../../docs/building/templates.md)). |
| `git: ... dubious ownership` or commit refused | the sandbox runs as root and owns `/workspace`; the task passes `-c user.email/-c user.name` on commit. Add a global identity with `execute` if you prefer. |
| `analyze_session.py` prints `exec floor: NOT MEASURED (…)` | the three exports are missing from this shell (`export` is per-terminal — export them again, or `source examples/claude-code/.env.sh` when `setup.sh` wrote it for this run) or no longer valid — the parentheses say which: `HTTP 401` once the run's agent was deleted, `HTTP 404` its sandbox. The tables are still printed; only Table 3's floor/command split is lost, the whole exec layer landing under `command`. |

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)) — permissive, so the wiring can
be copied into any project. Everything under `examples/` is Apache-2.0; the
Sandswap components themselves are BUSL-1.1.
