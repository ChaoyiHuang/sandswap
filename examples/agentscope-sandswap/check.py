# SPDX-License-Identifier: Apache-2.0
"""Live MCP contract checks and a small sequential operation benchmark.

Requires three disposable SandFS IDs: two owned by the supplied agent and one
owned by another agent. Never runs against a workspace selected by name alone.
"""
import argparse
import asyncio
import base64
import json
import math
import os
from pathlib import Path
import statistics
import time
import uuid

from client import connect, text_content

EXPECTED = {"execute", "file_read", "file_write", "file_stat", "file_list_dir",
            "file_mkdir", "file_remove", "file_rename", "exec_status", "exec_kill",
            "list_sandfs", "sandswap_guide"}


def errors(exc):
    yield exc
    for child in getattr(exc, "exceptions", []):
        yield from errors(child)
    if exc.__cause__:
        yield from errors(exc.__cause__)


def distribution(values):
    ordered = sorted(values)
    return {"n": len(values), "p50_ms": statistics.median(values),
            "p95_ms": ordered[math.ceil(.95*len(values))-1], "max_ms": max(values)}


async def check(output, samples):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    primary = os.environ["SANDSWAP_SANDFS_ID"]
    secondary = os.environ["SANDSWAP_SECONDARY_ID"]
    foreign = os.environ["SANDSWAP_FOREIGN_ID"]
    assert len({primary, secondary, foreign}) == 3
    prefix = "agentscope-check-" + uuid.uuid4().hex
    report = {"passed": False, "checks": [], "calls": [], "benchmarks": {}}

    def passed(name):
        report["checks"].append(name)
        print("PASS " + name, flush=True)

    async def rejected(name, predicate, **kwargs):
        try:
            async with connect(**kwargs):
                raise AssertionError("Connection unexpectedly accepted")
        except Exception as exc:
            if not any(predicate(e) for e in errors(exc)):
                raise
            passed(name)

    try:
        await rejected("untrusted TLS certificate rejected",
                       lambda e: "CERTIFICATE_VERIFY_FAILED" in str(e), ca="")
        await rejected("wrong API key rejected",
                       lambda e: getattr(getattr(e, "error", None), "code", None) == -32001,
                       key="invalid-integration-test-key")

        async with connect() as (tools, toolkit):
            assert set(tools) == EXPECTED
            assert len(await toolkit.get_tool_schemas()) == 12
            passed("12 tools discovered and registered in AgentScope")

            async def call(name, *, error=False, **kwargs):
                start = time.perf_counter()
                result = await tools[name](**kwargs)
                elapsed = (time.perf_counter()-start)*1000
                raw = text_content(result)
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = raw
                report["calls"].append({"name": name, "elapsed_ms": elapsed,
                                        "state": str(result.state), "result": data})
                assert (result.state == "error") == error, (name, data)
                return data

            async def execute(code, sid=primary, **kwargs):
                return await call("execute", sandfs_id=sid, language="shell", code=code, **kwargs)

            async def terminal(exec_id, deadline=15):
                end = time.monotonic()+deadline
                while time.monotonic() < end:
                    result = await call("exec_status", sandfs_id=primary, exec_id=exec_id)
                    if result["status"] != "running":
                        return result
                    await asyncio.sleep(.2)
                raise AssertionError("Background execution did not terminate")

            listed = await call("list_sandfs")
            ids = {s["sandfs_id"] for s in listed["sandfs_list"]}
            assert {primary, secondary} <= ids and foreign not in ids
            assert "workspace" in (await call("sandswap_guide")).lower()
            passed("tenant-scoped discovery and server guide")

            result = await execute("printf hello; printf problem >&2; exit 7")
            assert result["exit_code"] == 7 and result["stdout"] == "hello" and result["stderr"] == "problem"
            passed("sync stdout/stderr and nonzero command exit preserved")

            await call("file_mkdir", sandfs_id=primary, path=prefix)
            path = prefix + "/text.txt"
            text = "AgentScope 沙箱\n"
            await call("file_write", sandfs_id=primary, path=path, data=text)
            await call("file_write", sandfs_id=primary, path=path, data="tail", append=True)
            assert (await call("file_read", sandfs_id=primary, path=path))["data"] == text+"tail"
            assert (await call("file_read", sandfs_id=primary, path=path, offset=0, length=10))["data"] == "AgentScope"
            stat = await call("file_stat", sandfs_id=primary, path=path)
            assert stat["size"] == len((text+"tail").encode())
            renamed = prefix + "/renamed.txt"
            await call("file_rename", sandfs_id=primary, path=path, new_path=renamed)
            assert any(e["name"] == "renamed.txt" for e in
                       (await call("file_list_dir", sandfs_id=primary, path=prefix))["entries"])
            binary = b"\x00\xff\xfeSandSwap\x80"
            await call("file_write", sandfs_id=primary, path=prefix+"/binary",
                       data_base64=base64.b64encode(binary).decode())
            data = await call("file_read", sandfs_id=primary, path=prefix+"/binary")
            assert not data["is_text"] and base64.b64decode(data["data_base64"]) == binary
            passed("file CRUD, UTF-8, append, partial read and binary roundtrip")

            missing = await call("file_read", sandfs_id=primary, path=path, error=True)
            assert missing  # Generic MCP errors may be text; typed errors are JSON.
            await call("file_read", sandfs_id=primary, path="../etc/shadow", error=True)
            passed("missing file and traversal errors propagate through MCPTool")
            await call("file_read", sandfs_id=secondary, path=renamed, error=True)
            for name, args in [("file_read", {"path": renamed}),
                               ("execute", {"language": "shell", "code": "true"})]:
                denial = await call(name, sandfs_id=foreign, error=True, **args)
                assert denial
            passed("workspace and cross-agent isolation")

            bg = await execute("sleep 1; printf background-done", background=True, lease_duration=15)
            result = await terminal(bg["exec_id"])
            assert result["status"] == "done" and result["exit_code"] == 0
            assert "background-done" in result["stdout"]
            passed("background completion and polling")
            killed_marker = prefix+"/killed-must-not-exist"
            bg = await execute(f"sleep 3; touch /workspace/{killed_marker}",
                               background=True, lease_duration=30)
            assert (await call("exec_kill", sandfs_id=primary, exec_id=bg["exec_id"]))["status"] == "killed"
            # Killing releases the VM hold; status can already be expired.
            assert (await terminal(bg["exec_id"]))["status"] in {"killed", "expired", "not_found"}
            await asyncio.sleep(4)
            await call("file_read", sandfs_id=primary, path=killed_marker, error=True)
            passed("background kill")
            marker = prefix+"/must-not-exist"
            bg = await execute(f"sleep 5; touch /workspace/{marker}", background=True, lease_duration=2)
            result = await terminal(bg["exec_id"], deadline=8)
            assert result["status"] in {"expired", "not_found", "killed"}, result
            await asyncio.sleep(4)
            await call("file_read", sandfs_id=primary, path=marker, error=True)
            passed("absolute lease expires despite polls and stops work")

            for mode in ("no_background_lease", "held_background_lease"):
                hold = None
                if mode == "held_background_lease":
                    hold = await execute("sleep 120", background=True, lease_duration=120)
                try:
                    # Five excluded warm-ups, followed by sequential measured samples.
                    for _ in range(5):
                        assert (await execute("true"))["exit_code"] == 0
                    start_index = len(report["calls"])
                    for _ in range(samples):
                        assert (await execute("true"))["exit_code"] == 0
                    batch = report["calls"][start_index:]
                    report["benchmarks"][mode] = {
                        "client": distribution([x["elapsed_ms"] for x in batch]),
                        **{field: distribution([x["result"][field]/1e6 for x in batch])
                           for field in ("gateway_duration_ns", "sandlot_duration_ns", "exec_duration_ns")},
                    }
                finally:
                    if hold:
                        await call("exec_kill", sandfs_id=primary, exec_id=hold["exec_id"])
            passed("sequential operation latency sampled in both lease modes")

        async with connect() as (tools, _):
            result = await tools["file_read"](sandfs_id=primary, path=renamed)
            assert result.state != "error" and json.loads(text_content(result))["data"] == text+"tail"
            result = await tools["file_remove"](sandfs_id=primary, path=prefix, recursive=True)
            assert result.state != "error"
            result = await tools["file_read"](sandfs_id=primary, path=renamed)
            assert result.state == "error"
            passed("reconnect preserves files; recursive removal confirmed")
        report["passed"] = True
    finally:
        (output / "results.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != "calls"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=100)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be positive")
    asyncio.run(check(args.output_dir, args.samples))
