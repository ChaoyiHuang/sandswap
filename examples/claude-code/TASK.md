# Sandbox coding task — fix the failing test suite

You are wired to a **Sandswap** sandbox through the `sandswap` MCP tools.
Local `Bash`, `Write` and `Edit` are disabled for this project, so every
command and every file change happens inside the sandbox's persistent
`/workspace` — on a tinyVM that Sandswap mounts on demand.

Do this — in the **efficient** shape, which is the point of this task:

1. Call `list_sandfs` and pick the sandbox named `claude-code`.

2. Survey the project in **one** `execute` — not one call per question:

   ```
   cd /workspace && git log --oneline && echo --- && ls -R calc tests && echo --- && python3 -m unittest discover -s tests -v 2>&1 | tail -15
   ```

3. Read the failing module (`calc/core.py`) with `file_read` — file-tool
   paths are relative to `/workspace` — find the bugs, and fix them with
   `file_write`.

4. Re-run the suite and commit in **one** `execute`. Mind the pipe: `| tail`
   would mask the suite's exit code, and the sandbox's `/bin/sh` is dash (no
   `pipefail`) — so run the suite unpiped and let its own exit code gate the
   commit through the `&&` chain:

   ```
   cd /workspace && python3 -m unittest discover -s tests && git add -A && git -c user.email=agent@sandswap -c user.name=agent commit -qm "fix calc" && git log --oneline
   ```

5. Report the output.

While you work, look at `exec_duration_ns` in every `execute` result.
Sandswap's own share of a call is about 1 ms; the rest is what the command
starts inside the guest — starting the Python interpreter costs several
times a shell start, and it is paid on every `python3 -c`. That is why
this task is three `execute` calls, not ten: each call that can be merged
into the previous one saves a full process startup, and a file-sized job
done with `cat`/`sed` costs a fraction of the same job done with
`python3`.
