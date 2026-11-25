#!/usr/bin/env python3
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""analyze_session.py — where did the Claude Code run's time go?

Reads the session transcript Claude Code wrote for THIS directory (the newest
one under ~/.claude/projects/, or a path you give) and reconstructs the turn as
the loop it really is:

    user prompt → [thinking → tool call → tool result] × N → final answer

For every round it prints the LLM's thinking time, the tool it called, and how
long that tool took, then totals: LLM vs. tools vs. Sandswap. The point the
numbers make: the sandbox is a rounding error — the loop count is the cost.

Usage:
  python3 analyze_session.py                 # newest session for this directory
  python3 analyze_session.py <session.jsonl> # a specific transcript
"""
import json
import os
import re
import ssl
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))


TASK_MARKER = "TASK.md"   # the task prompt names this file; only such sessions count


def first_user_text(path: str):
    """The first user-typed text of a transcript, or '' if there is none."""
    try:
        for line in open(path):
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("type") != "user":
                continue
            c = r.get("message", {}).get("content")
            if isinstance(c, str) and c.strip():
                return c
            if isinstance(c, list):
                for b in c:
                    if isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip():
                        return b["text"]
    except (OSError, json.JSONDecodeError):
        pass
    return ""


def newest_task_session(cwd: str) -> str:
    """The newest transcript for `cwd` that is a run of THIS example's task.

    Claude Code keys transcripts by cwd ('/' and '.' → '-'). Any session in
    the directory would match by mtime alone — including one where the user
    only ran `cd ..` — so require the first user prompt to be the TASK.md
    task, newest first.
    """
    key = cwd.replace("/", "-").replace(".", "-")
    proj = os.path.expanduser("~/.claude/projects/" + key)
    if not os.path.isdir(proj):
        sys.exit(f"no Claude Code sessions recorded for {cwd} (looked in {proj})")
    sessions = [os.path.join(proj, f) for f in os.listdir(proj) if f.endswith(".jsonl")]
    sessions.sort(key=os.path.getmtime, reverse=True)
    for path in sessions:
        if TASK_MARKER in first_user_text(path):
            return path
    sys.exit(f"none of the {len(sessions)} session(s) in {proj} is a run of the "
             f"{TASK_MARKER} task (first prompt must mention it) — run the task first, "
             f"or pass a .jsonl path")


EXEC_FLOOR_MS = None   # measured once per run: median exec of `sh -c :` on the demo sandbox


def measure_exec_floor() -> float:
    """The sandbox's fixed per-exec cost on THIS deployment: the median
    exec_duration_ns of `sh -c :` over 30 warm calls. Everything a command
    pays before its own work — guest mount bookkeeping, fork+execve, shell
    start — and therefore Sandswap's, not the command's. Returns 0.0 when it
    cannot be measured (no stack / no ids exported), in which case the whole
    exec layer is reported as the command's, as before.
    """
    import http.client, statistics
    agent = os.environ.get("CLAUDE_CODE_AGENT_ID", "")
    sandfs = os.environ.get("CLAUDE_CODE_SANDFS_ID", "")
    key = os.environ.get("CLAUDE_CODE_SANDBOX_API_KEY", "")
    if not (agent and sandfs and key):
        return 0.0
    ctx = ssl.create_default_context(cafile="/etc/sandswap/certs/ca.crt")
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    hdr = {"Authorization": f"Bearer {key}", "X-Sandswap-Api-Key": key,
           "Content-Type": "application/json"}
    try:
        c = http.client.HTTPSConnection("localhost", 3000, context=ctx)
        c.connect()
    except OSError:
        return 0.0
    xs = []
    for _ in range(30):
        try:
            c.request("POST", "/agent/execute", headers=hdr,
                      body=json.dumps({"sandfs_id": sandfs, "language": "shell", "code": ":"}))
            d = json.loads(c.getresponse().read())
        except OSError:
            break
        if "exec_duration_ns" in d:
            xs.append(d["exec_duration_ns"] / 1e6)
        elif d.get("retryable"):
            import time
            time.sleep(d.get("retry_after_ms", 2000) / 1000)
    return statistics.median(xs) if xs else 0.0


def plain(text: str) -> str:
    """Markdown-free single line for a fixed-width column."""
    for ch in ("**", "`", "__"):
        text = text.replace(ch, "")
    return " ".join(text.split())


def ts(r):
    return datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))


def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = newest_task_session(HERE)
    rows = [json.loads(l) for l in open(path) if l.strip()]
    conv = [r for r in rows if r.get("type") in ("user", "assistant") and "timestamp" in r]
    if not conv:
        sys.exit("transcript has no conversational rows")
    first = first_user_text(path)
    if TASK_MARKER not in first:
        sys.exit(f"{path} is not a run of the {TASK_MARKER} task (first user prompt: {first[:60]!r}) "
                 f"— the analysis only makes sense for this example's task")

    # Group assistant blocks by requestRef: one LLM round-trip = one thinking
    # block (optional) + text blocks + tool_use blocks. The transcript carries
    # one row per block, so the group is the unit that answers "how many times
    # did the model think, and what did each round do?".
    turns = []           # each: {think_ms, t_start, t_end, text, tools:[{name, arg, id}]}
    by_ref = {}
    tool_owner = {}      # tool_use id → (turn index, tool index)
    prompt_at = None
    prompt_text = ""
    for r in conv:
        content = r["message"].get("content")
        blocks = content if isinstance(content, list) else [{"type": "text", "text": content}]
        if r["type"] == "assistant":
            ref = r.get("requestRef") or r["uuid"]
            t = by_ref.get(ref)
            if t is None:
                t = {"think_ms": 0, "t_start": ts(r), "t_end": ts(r), "text": "", "tools": [],
                     "results": {}, "raw_thinking": []}
                by_ref[ref] = t
                turns.append(t)
            t["t_end"] = max(t["t_end"], ts(r))
            for b in blocks:
                bt = b.get("type")
                if bt == "thinking":
                    t["think_ms"] += r.get("thinkingDurationMs") or 0
                    t["raw_thinking"].append((b.get("thinking") or "").replace("\n", " "))
                elif bt == "text" and b.get("text", "").strip():
                    t["text"] = (t["text"] + " " + b["text"]).strip()
                elif bt == "tool_use":
                    arg = b.get("input", {})
                        # local tools use command/file_path; the Sandswap MCP tools
                    # put the shell script in `code` and the target in `path`
                    arg = (arg.get("command") or arg.get("code") or arg.get("file_path")
                           or arg.get("path") or "")
                    t["tools"].append({"name": b["name"], "arg": str(arg), "id": b["id"],
                                       "ms": None, "out": "", "err": False})
                    tool_owner[b["id"]] = (len(turns) - 1, len(t["tools"]) - 1)
        else:
            for b in blocks:
                if b.get("type") == "tool_result":
                    out = b.get("content")
                    if isinstance(out, list):
                        out = " ".join(x.get("text", "") for x in out if isinstance(x, dict))
                    own = tool_owner.get(b.get("tool_use_id"))
                    if own:
                        ti, pi = own
                        tool = turns[ti]["tools"][pi]
                        tool["ms"] = (ts(r) - turns[ti]["t_end"]).total_seconds() * 1000
                        # keep enough of a Sandswap execute result to read its timing fields
                        keep = 400 if "exec_duration_ns" in (out or "") else 70
                        tool["out"] = (out or "")[:keep].replace("\n", " ")
                        tool["err"] = bool(b.get("is_error"))
                    # the gateway reports its own stage timings in every execute
                    # result; keep them so a tool row can show every dimension
                    gw = {}
                    for k in ("exec_duration_ns", "sandlot_duration_ns", "gateway_duration_ns"):
                        m = re.search(r'"%s":(\d+)' % k, out or "")
                        if m:
                            gw[k] = int(m.group(1)) / 1e6
                    tool["gw"] = gw
                    turns[ti]["t_last_result"] = ts(r)
                elif b.get("type") == "text" and b.get("text", "").strip() and prompt_at is None:
                    prompt_at = ts(r)
                    prompt_text = b["text"][:70].replace("\n", " ")

    # Trim to the task turn: stop before any later user prompt (what the user
    # typed next), which would start a new turn.
    later_prompt = None
    seen_first = False
    for r in conv:
        if r["type"] == "user" and isinstance(r["message"].get("content"), str) or (
                r["type"] == "user" and isinstance(r["message"].get("content"), list)
                and any(b.get("type") == "text" for b in r["message"]["content"])):
            if seen_first:
                later_prompt = ts(r)
                break
            seen_first = True
    if later_prompt:
        turns = [t for t in turns if t["t_start"] < later_prompt]

    global EXEC_FLOOR_MS
    EXEC_FLOOR_MS = measure_exec_floor()

    # ── collect everything first, then print three tables ──────────────────
    #   Table 1  the loop, in time order: each LLM call, then the tools it called
    #   Table 2  the LLM's time, split into its phases
    #   Table 3  tool execution, split into measured layers
    think_total = sum(t["think_ms"] for t in turns)
    first_t0 = turns[0]["t_start"]
    last = turns[-1]
    last_end = last.get("t_last_result", last["t_end"]) if last["tools"] else last["t_end"]
    span = (last_end - first_t0).total_seconds()
    wait_total = emit_total = 0.0
    llm_rows = []                  # (call, wait_s, emit_s, think_ms, tools)
    tool_rows = []                 # dicts: call, name, arg, ms, gw{}, err
    prev_end = None
    for i, t in enumerate(turns, 1):
        wait = (t["t_start"] - prev_end).total_seconds() if prev_end else None
        emit = (t["t_end"] - t["t_start"]).total_seconds()
        if wait is not None:
            wait_total += max(wait, 0.0)
        emit_total += emit
        llm_rows.append((i, wait, emit, t["think_ms"], len(t["tools"]),
                         plain(next((x for x in t.get("raw_thinking", []) if x.strip()), "")
                               or t["text"] or "(no reasoning text)")))
        for tool in t["tools"]:
            tool_rows.append({"call": i, "name": tool["name"].replace("mcp__sandswap__", ""),
                              "sandswap": tool["name"].startswith("mcp__sandswap__"),
                              "arg": plain(tool["arg"]), "ms": tool["ms"] or 0.0,
                              "gw": tool.get("gw") or {}, "err": tool["err"]})
        prev_end = t.get("t_last_result", t["t_end"]) if t["tools"] else t["t_end"]
    tool_total = sum(r["ms"] for r in tool_rows)
    n_tools = len(tool_rows)
    n_sw = sum(1 for r in tool_rows if r["sandswap"])
    floor = EXEC_FLOOR_MS or 0.0
    swap_own_total = command_total = 0.0
    for r in tool_rows:
        if "gateway_duration_ns" in r["gw"]:
            g = r["gw"]
            r["own"] = (g["gateway_duration_ns"] - g["sandlot_duration_ns"]) \
                + (g["sandlot_duration_ns"] - g["exec_duration_ns"]) + min(floor, g["exec_duration_ns"])
            r["command"] = g["exec_duration_ns"] - min(floor, g["exec_duration_ns"])
        else:
            r["own"], r["command"] = (r["ms"], 0.0) if r["sandswap"] else (0.0, 0.0)
        swap_own_total += r["own"]
        command_total += r["command"]
    sw_calls_total = sum(r["ms"] for r in tool_rows if r["sandswap"])
    non_sw_total = sum(r["ms"] for r in tool_rows if not r["sandswap"])

    W = 68
    def rule(): print("-" * W)
    def head(title):
        print(); print(title); rule()

    print(f"session: {os.path.basename(path)}")
    print(f"prompt : {plain(prompt_text) if prompt_at else '?'}")
    if EXEC_FLOOR_MS:
        print(f"exec floor on this sandbox (sh -c :, median of 30): {EXEC_FLOOR_MS:.1f} ms")
    else:
        print("exec floor: NOT MEASURED (no live sandbox reached via CLAUDE_CODE_SANDBOX_*; export the")
        print("            three variables to measure it) — the whole exec layer is reported as the")
        print("            command's, which UNDERSTATES Sandswap's own share by ~the floor per execute.")

    # ── Table 1: the loop ─────────────────────────────────────────────────
    head(f"Table 1  the loop, in time order   (turn: {span:.2f} s, {len(turns)} LLM calls, {n_tools} tool calls)")
    print(f"{'call':>4}  {'LLM call / tool':<52} {'time':>10}")
    rule()
    for (i, wait, emit, think_ms, ntool, desc), t in zip(llm_rows, turns):
        label = "think" if think_ms else "call "
        print(f"{i:>4}  {label} {desc[:46]:<46} {(emit + (wait or 0)):>8.2f} s")
        for r in [x for x in tool_rows if x["call"] == i]:
            # the time column is a fixed-width, right-aligned field on every row
            # so the eye can scan it; the name column is fixed too.
            name, timecol = f"{r['name']:<12}", f"{r['ms']:>8.1f} ms"
            if r["name"] == "execute":
                print(f"{'':>4}  {'':<5} {name} {'':<38} {timecol}")
                # the command, one line per `&&`-separated step: its own structure
                for step in [x.strip() for x in r["arg"].replace("\\n", " ").split("&&")]:
                    while len(step) > 60:                  # wrap a long step on spaces
                        cut = step.rfind(" ", 0, 60)
                        cut = cut if cut > 0 else 60
                        print(f"{'':>4}  {'':<5} {'':<12}   {step[:cut]}")
                        step = step[cut:].strip()
                    print(f"{'':>4}  {'':<5} {'':<12}   {step}")
            else:
                # show the file name only — the path is the example's own checkout
                arg = ("ERR " if r["err"] else "") + os.path.basename(r["arg"].rstrip("/"))
                print(f"{'':>4}  {'':<5} {name} {arg[:38]:<38} {timecol}")
    rule()
    print(f"{'':>4}  {'LLM (all calls)':<52} {wait_total + emit_total:>8.2f} s")
    print(f"{'':>4}  {'tools (all calls)':<52} {tool_total/1000:>8.2f} s")
    print(f"{'':>4}  {'turn total':<52} {span:>8.2f} s")

    # ── Table 2: the LLM's time ───────────────────────────────────────────
    head("Table 2  where the LLM's time goes")
    print(f"{'call':>4}  {'before first token':>19} {'emitting blocks':>16} {'of which thinking':>19}  what it decided")
    rule()
    for i, wait, emit, think_ms, ntool, desc in llm_rows:
        w = f"{wait:>17.2f} s" if wait is not None else f"{'(first)':>17}"
        print(f"{i:>4}  {w} {emit:>14.2f} s {think_ms/1000:>17.2f} s  {desc[:34]}")
    rule()
    print(f"{'':>4}  {wait_total:>17.2f} s {emit_total:>14.2f} s {think_total/1000:>17.2f} s")
    print()
    print(f"  before first token  (prompt → first block: queueing + thinking)   {wait_total:>7.2f} s  {wait_total/span*100:5.1f}%")
    print(f"  emitting blocks     (thinking + text + tool_use reach the client) {emit_total:>7.2f} s  {emit_total/span*100:5.1f}%")
    print(f"  tools               (Table 3)                                     {tool_total/1000:>7.2f} s  {tool_total/1000/span*100:5.1f}%")
    print(f"  {'sum':<70} {span:>7.2f} s  100.0%")

    # ── Table 3: tool execution ───────────────────────────────────────────
    head("Table 3  tool execution, by layer")
    print(f"{'call':>4}  {'tool':<12} {'client':>9} {'http/tls':>9} {'gateway':>9} {'dispatch':>9} {'exec floor':>11} {'command':>9}")
    rule()
    for r in tool_rows:
        if "gateway_duration_ns" in r["gw"]:
            g = r["gw"]; fl = min(floor, g["exec_duration_ns"])
            print(f"{r['call']:>4}  {r['name']:<12} {r['ms']:>7.1f}ms {r['ms']-g['gateway_duration_ns']:>7.1f}ms "
                  f"{g['gateway_duration_ns']-g['sandlot_duration_ns']:>7.1f}ms "
                  f"{g['sandlot_duration_ns']-g['exec_duration_ns']:>7.1f}ms {fl:>9.1f}ms {g['exec_duration_ns']-fl:>7.1f}ms")
        elif r["sandswap"]:
            # a file tool / list call: no command, the gateway reports no layers —
            # all of it is Sandswap's (transport + warden floor)
            print(f"{r['call']:>4}  {r['name']:<12} {r['ms']:>7.1f}ms {'':>9} {'':>9} {'':>9} {'(no command)':>11} {'':>9}")
        else:
            print(f"{r['call']:>4}  {r['name']:<12} {r['ms']:>7.1f}ms  (local tool, not Sandswap)")
    rule()
    print(f"  Sandswap calls ({n_sw}): {sw_calls_total/1000:.2f} s   of which Sandswap itself {swap_own_total/1000:.2f} s "
          f"({swap_own_total/n_sw:.1f} ms per call), the commands {command_total/1000:.2f} s" if n_sw else "")
    if n_tools - n_sw:
        print(f"  non-Sandswap tools ({n_tools - n_sw}): {non_sw_total/1000:.2f} s")
    if floor:
        print(f"  exec floor = median exec of `sh -c :` on this sandbox ({floor:.1f} ms): guest mount bookkeeping + fork/execve + shell start,")
        print(f"  charged to Sandswap; 'command' = exec − floor.")
    else:
        print("  exec floor not measured: the exec layer is shown entirely under 'command' (see the note above).")


if __name__ == "__main__":
    main()
