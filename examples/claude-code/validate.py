#!/usr/bin/env python3
# Copyright 2026 Chaoyi Huang. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run the seeded TASK.md with real Claude Code, then verify the sandbox.

Uses only the Python standard library and the installed `claude` executable.
Provision/reset the disposable example with setup.sh or seed.sh first. Model
authentication comes from the environment; personal Claude settings are not
loaded. All evidence stays in a new private output directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
PREFIX = "mcp__sandswap__"
REQUIRED = {PREFIX + name for name in ("list_sandfs", "execute", "file_read", "file_write")}


def assess_events(events):
    """Fail closed on missing results, local tools, tool errors, or denials."""
    calls, results, final, connected = {}, {}, None, False
    for event in events:
        if event.get("type") == "system" and event.get("subtype") == "init":
            connected = any(s.get("name") == "sandswap" and s.get("status") == "connected"
                            for s in event.get("mcp_servers", []))
        if event.get("type") == "result":
            final = event
        content = event.get("message", {}).get("content", [])
        for block in content if isinstance(content, list) else []:
            if block.get("type") == "tool_use":
                calls[block["id"]] = block["name"]
            if block.get("type") == "tool_result":
                results[block["tool_use_id"]] = block
    errors = []
    if not connected:
        errors.append("sandswap MCP did not connect")
    if not final or final.get("subtype") != "success" or final.get("is_error"):
        errors.append("Claude Code did not return a successful final result")
    if final and final.get("permission_denials"):
        errors.append("Claude Code reported permission denials")
    if any(not name.startswith(PREFIX) for name in calls.values()):
        errors.append("a tool outside sandswap was called")
    if not REQUIRED.issubset(calls.values()):
        errors.append("the discovery/execute/read/write coding loop was incomplete")
    if any(cid not in results for cid in calls):
        errors.append("a tool call has no recorded result")
    if any(r.get("is_error") for r in results.values()):
        errors.append("a tool returned an error")
    return {"passed": not errors, "errors": errors, "tool_calls": list(calls.values()),
            "claude_result": {k: (final or {}).get(k) for k in
                              ("subtype", "is_error", "duration_ms", "duration_api_ms",
                               "num_turns", "usage", "modelUsage", "permission_denials")}}


class MCP:
    def __init__(self, url, key, ca):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
            raise ValueError("MCP URL must be HTTP(S) without embedded credentials")
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("use HTTPS for non-loopback MCP endpoints")
        self.url, self.key = url, key
        self.context = ssl.create_default_context(cafile=ca)

    def call(self, name, arguments):
        body = json.dumps({"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}}).encode()
        headers = {"Authorization": "Bearer " + self.key, "X-Sandswap-Api-Key": self.key,
                   "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        for attempt in range(6):
            request = urllib.request.Request(self.url, body, headers)
            with urllib.request.urlopen(request, context=self.context, timeout=90) as response:
                envelope = json.load(response)
            if "error" in envelope:
                raise RuntimeError("MCP JSON-RPC error: " + str(envelope["error"]))
            result = envelope["result"]
            data = json.loads(result["content"][0]["text"])
            if result.get("isError"):
                if data.get("retryable") and attempt < 5:
                    time.sleep(min(max(data.get("retry_after_ms", 1000), 1), 10000) / 1000)
                    continue
                raise RuntimeError("MCP tool error: " + str(data))
            return data
        raise RuntimeError("MCP retries exhausted")

    def execute(self, sandfs, code):
        result = self.call("execute", {"sandfs_id": sandfs, "language": "shell", "code": code})
        if result.get("exit_code") != 0:
            raise RuntimeError("sandbox verification failed: " + json.dumps(result))
        return result


# Independent of the model's final prose and of any edits to the seeded tests.
# -B avoids introducing new bytecode files during verification.
VERIFY = r"""cd /workspace && python3 -B - <<'PY'
import hashlib, io, json, pathlib, subprocess, unittest
suite = unittest.defaultTestLoader.discover('tests')
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
test_bytes = pathlib.Path('tests/test_calc.py').read_bytes()
def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()
print(json.dumps({'tests_run': result.testsRun, 'failures': len(result.failures),
                  'errors': len(result.errors), 'output': stream.getvalue(),
                  'test_sha256': hashlib.sha256(test_bytes).hexdigest(),
                  'commits': git('log', '--format=%s').splitlines(),
                  'head': git('rev-parse', 'HEAD'), 'status': git('status', '--porcelain'),
                  'core_committed': git('diff', 'HEAD', '--', 'calc/core.py') == ''}))
PY"""
CHECK_FUNCTIONS = r"""cd /workspace && python3 -B - <<'PY'
from calc.core import add, fib
for a, b in [(2, 3), (-1, 1), (0, 0), (123, -8), (1.5, 2.5)]:
    assert add(a, b) == a + b, (a, b)
a, b = 0, 1
for n in range(21):
    assert fib(n) == a, n
    a, b = b, a + b
try:
    fib(-1)
except ValueError:
    pass
else:
    raise AssertionError('fib(-1) must raise ValueError')
print('independent function checks passed')
PY"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory; never overwritten")
    parser.add_argument("--timeout", type=int, default=600, help="Claude Code wall timeout in seconds")
    parser.add_argument("--ca", default=os.environ.get("NODE_EXTRA_CA_CERTS"), help="trusted MCP CA PEM")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    url = os.environ.get("CLAUDE_CODE_SANDBOX_MCP_URL", "https://localhost:3000/mcp")
    key = os.environ["CLAUDE_CODE_SANDBOX_API_KEY"]
    sandfs = os.environ["CLAUDE_CODE_SANDFS_ID"]
    if not (os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_API_KEY")):
        parser.error("export model authentication as ANTHROPIC_AUTH_TOKEN or ANTHROPIC_API_KEY")
    os.umask(0o077)
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    def save(name, data):
        (out / name).write_text(json.dumps(data, indent=2) + "\n")
    mcp = MCP(url, key, args.ca)
    before = json.loads(mcp.execute(sandfs, VERIFY)["stdout"])
    save("before.json", before)
    if (before["tests_run"], before["failures"], before["errors"], before["commits"]) != (
            5, 3, 0, ["add failing calc suite"]):
        raise RuntimeError("sandbox is not the failing TASK.md seed; run seed.sh first")
    env = os.environ.copy()
    env["CLAUDE_CODE_SANDBOX_MCP_URL"] = url
    env["CLAUDE_CONFIG_DIR"] = str(out / "claude-config")
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    if args.ca:
        env["NODE_EXTRA_CA_CERTS"] = str(Path(args.ca).resolve())
    config = Path(env["CLAUDE_CONFIG_DIR"])
    config.mkdir(mode=0o700)
    (config / ".claude.json").write_text('{"hasCompletedOnboarding":true}\n')
    session_id = str(uuid.uuid4())
    command = ["claude", "-p", "--tools", "", "--allowedTools", "mcp__sandswap",
               "--permission-mode", "dontAsk", "--setting-sources", "",
               "--disable-slash-commands", "--no-chrome", "--strict-mcp-config",
               "--mcp-config", str(HERE / ".mcp.json"), "--output-format", "stream-json",
               "--verbose", "--session-id", session_id]
    if env.get("ANTHROPIC_MODEL"):
        command += ["--model", env["ANTHROPIC_MODEL"]]
    prompt = "Complete this TASK.md using only sandswap MCP tools.\n\n" + (HERE / "TASK.md").read_text()
    save("invocation.json", {"claude_version": subprocess.check_output(["claude", "--version"], text=True).strip(),
                             "platform": platform.platform(), "command": command, "session_id": session_id,
                             "model": env.get("ANTHROPIC_MODEL"), "mcp_url": url,
                             "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                             "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    start = time.monotonic()
    timed_out = False
    with (out / "stream.jsonl").open("w") as stdout, (out / "stderr.txt").open("w") as stderr:
        try:
            completed = subprocess.run(command, input=prompt, text=True, cwd=HERE, env=env,
                                       stdout=stdout, stderr=stderr, timeout=args.timeout)
            returncode = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, None
    wall_ms = (time.monotonic() - start) * 1000
    events = [json.loads(line) for line in (out / "stream.jsonl").read_text().splitlines() if line.strip()]
    summary = assess_events(events)
    summary.update({"wall_ms": wall_ms, "process_returncode": returncode, "timed_out": timed_out})
    if returncode != 0:
        summary["errors"].append("Claude Code process failed or timed out")
    after = json.loads(mcp.execute(sandfs, VERIFY)["stdout"])
    save("after.json", after)
    if (after["tests_run"], after["failures"], after["errors"]) != (5, 0, 0):
        summary["errors"].append("the five original tests did not all pass")
    if before["test_sha256"] != after["test_sha256"]:
        summary["errors"].append("the model changed the test suite")
    if after["commits"] != ["fix calc", "add failing calc suite"] or not after["core_committed"]:
        summary["errors"].append("the fix was not committed as requested")
    try:
        save("independent-checks.json", mcp.execute(sandfs, CHECK_FUNCTIONS))
    except RuntimeError as error:
        summary["errors"].append(str(error))
    summary["passed"] = not summary["errors"]
    save("summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
