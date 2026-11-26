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
this exact setup, at the end of [Step 8](#step-8--run-the-task).

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
| `analyze_session.py` | after the run: rebuilds the turn from Claude Code's own transcript as thinking→tool rounds, and splits the time into LLM / tools / Sandswap |

## Step 0 — Before you start

**Where to run what.** You need two ordinary terminals and one Claude Code
window — three separate programs, none nested:

| Window | What it is | Used for |
|---|---|---|
| **Terminal A** | a normal system terminal | `sandctl`, `seed.sh`, and *launching* `claude` in step 7 |
| **Claude Code** | the interactive UI terminal A launches in step 7 | step 8 only: give the task, watch the tool calls |
| **Terminal B** | a second normal terminal | step 8, verifying from outside while Claude Code stays open |

> **Do not run any command below inside an existing Claude Code session —
> and above all not `claude`.** That is Claude Code inside Claude Code; it
> hangs. Copy every command into your own terminal instead.

All commands run from the **Sandswap root** — which one depends on how you
got Sandswap:

| You have | Root | Build step |
|---|---|---|
| a source checkout | the repository root | step "build" below, when source changed |
| a release package (`sandswap-<ver>-linux-amd64.tar.gz`) unpacked at `/opt/sandswap` | `/opt/sandswap` | none — everything is prebuilt, `build/` is not shipped |

```bash
cd /opt/sandswap        # release package; or: cd <your checkout>
```

**Prerequisites.** A KVM host with the artifacts under `output/` (a
release package has them; a checkout builds them); the `claude` CLI
installed and logged in (`claude --version`). Source checkout only — if the
source changed since the last build:

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
of making an agent fast here (Step 8).

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
example (the analyzer at the end of this step shows what it saves).

Verify from the outside when it finishes (another terminal; Claude Code
stays open):

```bash
output/sandctl api execute --agent <agent id> --sandfs <sandfs id> \
    --language shell --code 'cd /workspace && python3 -m unittest discover -s tests 2>&1 | tail -1 && git log --oneline'
```

Expected: `OK`, and two commits — `fix calc` on top of `add failing calc
suite`.

### See where the time went

Claude Code records every session under `~/.claude/projects/`: each LLM
call's thinking time, every tool call and its result, all timestamped. The
model itself cannot see its own thinking time, so the analysis is done from
the transcript, after the run. Back in the shell (after `/exit`, or from
another terminal):

```bash
python3 examples/claude-code/analyze_session.py
```

It picks the newest transcript for this directory whose first prompt is the
`TASK.md` task (a session where you only ran something else is skipped;
pass a `.jsonl` path to choose one) and prints the turn as the loop it is:
every round's **thinking, what it said, how long it thought, then the tool
it called and how long that took — each `execute` split into its measured
layers**. A real interactive run:

**Table 1 — the loop, in time order.** Each LLM call, then the tools it
called, with every `execute`'s command spelled out one `&&`-step per line.
Six calls, each deciding the next tool from the previous result (the two
`file_read`s go out in parallel inside one call); the 27-second call that
finds the two bugs is the task. The first line is the sandbox's exec
floor, measured live before the analysis (see Table 3).

```text
prompt : Complete the task in TASK.md using only the sandswap tools
exec floor on this sandbox (sh -c :, median of 30): 8.7 ms

Table 1  the loop, in time order   (turn: 64.92 s, 6 LLM calls, 7 tool calls)
--------------------------------------------------------------------
call  LLM call / tool                                            time
--------------------------------------------------------------------
   1  think The user wants me to complete the task in TASK     0.33 s
            Read         TASK.md                                    35.0 ms
            list_sandfs                                             15.0 ms
   2  think The sandbox is claude-code with id sandfs-bc00     5.46 s
            execute                                                250.0 ms
                           cd /workspace
                           git log --oneline
                           echo ---
                           ls -R calc tests
                           echo ---
                           python3 -m unittest discover -s tests -v 2>&1 | tail -15
   3  think 3 failures out of 5 tests. The tail cut off th     8.23 s
            file_read    core.py                                    22.0 ms
            file_read    test_calc.py                               20.0 ms
   4  think Now let me find the bugs: Bug 1: add — return     27.35 s
            file_write   core.py                                    30.0 ms
   5  call  Now re-running the suite and committing in one     6.93 s
            execute                                                321.0 ms
                           cd /workspace
                           python3 -m unittest discover -s tests
                           git add -A
                           git -c user.email=agent@sandswap -c user.name=agent commit
                           -qm "fix calc"
                           git log --oneline
   6  think All 5 tests pass and the commit is in place. L    15.97 s
--------------------------------------------------------------------
      LLM (all calls)                                         64.28 s
      tools (all calls)                                        0.69 s
      turn total                                              64.92 s
```

**Table 2 — where the LLM's time goes.** The wait before the first token
is 79.5% of the turn and emitting blocks 19.6%; the explicit thinking
blocks alone are a third of the total. The model spends four times longer
thinking than speaking.

```text
Table 2  where the LLM's time goes
--------------------------------------------------------------------
call   before first token  emitting blocks   of which thinking  what it decided
--------------------------------------------------------------------
   1            (first)           0.33 s              5.23 s  The user wants me to complete the 
   2               4.43 s           1.03 s              0.64 s  The sandbox is claude-code with id
   3               7.03 s           1.21 s              1.91 s  3 failures out of 5 tests. The tai
   4              23.93 s           3.43 s             19.72 s  Now let me find the bugs: Bug 1: a
   5               6.23 s           0.70 s              0.00 s  Now re-running the suite and commi
   6               9.97 s           6.00 s              6.04 s  All 5 tests pass and the commit is
--------------------------------------------------------------------
                  51.59 s          12.69 s             33.53 s

  before first token  (prompt → first block: queueing + thinking)     51.59 s   79.5%
  emitting blocks     (thinking + text + tool_use reach the client)   12.69 s   19.6%
  tools               (Table 3)                                        0.69 s    1.1%
  sum                                                                      64.92 s  100.0%
```

**Table 3 — tool execution, by layer.** Every call split into the layers
the gateway measured: HTTP/TLS on Claude Code's side, the gateway's
processing, Sandswap's dispatch, the exec floor, and only then the command
itself.

```text
Table 3  tool execution, by layer
--------------------------------------------------------------------
call  tool            client  http/tls   gateway  dispatch  exec floor   command
--------------------------------------------------------------------
   1  Read            35.0ms  (local tool, not Sandswap)
   1  list_sandfs     15.0ms                               (no command)          
   2  execute        250.0ms     9.6ms     0.7ms     1.0ms       8.7ms   230.0ms
   3  file_read       22.0ms                               (no command)          
   3  file_read       20.0ms                               (no command)          
   4  file_write      30.0ms                               (no command)          
   5  execute        321.0ms     9.4ms     0.6ms     1.1ms       8.7ms   301.2ms
--------------------------------------------------------------------
  Sandswap calls (6): 0.66 s   of which Sandswap itself 0.11 s (18.0 ms per call), the commands 0.53 s
  non-Sandswap tools (1): 0.04 s
  exec floor = median exec of `sh -c :` on this sandbox (8.7 ms): guest mount bookkeeping + fork/execve + shell start,
  charged to Sandswap; 'command' = exec − floor.
```

What counts as Sandswap's own share needs care. The `exec` layer the warden
reports is **not** "the command": it also carries the sandbox's fixed
per-exec floor — guest mount bookkeeping, fork+execve, the shell start —
paid whatever the command is. That floor is exactly what the benchmark
reports' `exec (warden)` rows measure with a busybox `echo` (≈1.6 ms bare
metal, ≈5 ms nested); here the analyzer measures it live on the demo
sandbox as the median of `sh -c :` (**8.7 ms** on the Ubuntu template —
its dynamic `dash` costs more than busybox's static shell) and charges it
to Sandswap. Over the whole turn Sandswap's own share is **0.11 s across 6
calls (≈18 ms per call, ≈10 ms of an `execute`)** against 0.53 s of actual
command work — and the HTTP/TLS hop alone is 9.6 ms per call, about as
much as all of Sandswap's share of that call: the integration overhead
lives in the client's transport as much as in the sandbox. Everything else
is the interpreter the command starts, which is the whole argument for
batching: one merged `execute` is one fewer row in Table 1.

The absolute numbers depend on your host (bare metal vs. nested
virtualization differ by ~4×; see the
[benchmark reports](../../docs/benchmark/index.md)), so read the ratios,
which hold everywhere. To see the ratios yourself without a model in the
loop, time the rows directly — every `execute` response carries
`exec_duration_ns`:

```bash
sx() { output/sandctl --raw api execute --agent "$CLAUDE_CODE_AGENT_ID" --sandfs "$CLAUDE_CODE_SANDFS_ID" \
    --language shell --code "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["exec_duration_ns"]/1e6, "ms")'; }
sx 'cd /workspace && cat calc/core.py'                                      # shell: the baseline
sx 'cd /workspace && python3 -c "print(open(\"calc/core.py\").read())"'   # interpreter for the same job
sx 'cd /workspace && python3 -c "import calc.core as m; print(m.add(2,3))"'  # one probe
sx 'cd /workspace && python3 -c "import calc.core as m; print(m.add(2,3)); print(m.fib(6)); print(m.add(-1,1))"'  # three probes, ONE start
```

Measured here: `cat` ≈ 1×, `python3` for the same read ≈ 3.5×, three
separate `python3 -c` probes ≈ 10×, the same three probes in one `python3`
≈ 3.5×. The batching win is the interpreter starts you did not pay — and,
with a model in the loop, one fewer thinking→tool round-trip (see the
analyzer above).

## Step 9 — Clean up

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

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `/mcp` shows `sandswap` **failed** | `CLAUDE_CODE_SANDBOX_API_KEY` not exported in the shell that launched `claude`; or, on a TLS deploy, `NODE_EXTRA_CA_CERTS` unset (Node refuses the deployer's CA); or the URL scheme does not match the deployment (see Variants). |
| Claude asks to approve the MCP server | launched from a directory other than `examples/claude-code` (settings not loaded) — `cd` there first. |
| `Ignoring permissions… this workspace has not been trusted` | accept the trust dialog on the first interactive launch; project settings (including the MCP auto-approval) are ignored in an untrusted workspace. |
| `execute` returns `unknown sandbox` / 404 | wrong `sandfs_id` — the tool schema's `sandfs_id` enum lists the agent's SandFS instances; `list_sandfs` is the source of truth. |
| `sandctl api execute` prints `HTTP 503`, or Claude's `execute` returns `SANDBOX_CLEANING` / `NO_AVAILABLE_SANDBOX` with `retryable: true` | the sandbox is mid-recycle (its previous unmount is still finishing, or the pool is handing over a VM) — a transient of a few ms, not a failure. Run the command again; Claude Code retries on `retryable: true` per the tool contract (the scripts' `sx_exec` already does). |
| After a host reboot the pool shows 0 nodes / sandlot will not start | vsockguard is a BPF program and does not survive a reboot; the sandlot's attest step refuses to start (fail-closed). Re-run step 1 (the deployer re-attaches it), or by hand: `sudo bash security/vsockguard-attach.sh && sudo systemctl reset-failed sandswap-sandlot && sudo systemctl restart sandswap-sandlot`. |
| `HTTP 401 invalid api key` from `sandctl --agent …`, yet the key is right | a `SANDSWAP_API_KEY` left in the shell by something else — sandctl prefers that env var over `--agent` for every call. `unset SANDSWAP_API_KEY` (this example never sets it; it uses `CLAUDE_CODE_SANDBOX_API_KEY`). |
| the key is gone | it is shown once at creation; `cat run/agents.json` has the copy `sandctl` cached (pick the entry by `agent_id` — old agents accumulate there across reinstalls). Otherwise delete the agent and create a new one. |
| `ubuntu:24.04` missing from `template list` | deployed with `--skip-build` before `output/rootfs-ubuntu` existed — `sudo bash build/build.sh ubuntu-rootfs` and redeploy, or register by hand ([Building Templates](../../docs/building/templates.md)). |
| `git: ... dubious ownership` or commit refused | the sandbox runs as root and owns `/workspace`; the task passes `-c user.email/-c user.name` on commit. Add a global identity with `execute` if you prefer. |

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)) — permissive, so the wiring can
be copied into any project. Everything under `examples/` is Apache-2.0; the
Sandswap components themselves are BUSL-1.1.
