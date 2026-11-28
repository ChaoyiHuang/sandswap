# SPDX-License-Identifier: Apache-2.0
"""Run a real AgentScope coding task using SandSwap MCP tools only."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import time

from agentscope.agent import Agent, ReActConfig
from agentscope.credential import OpenAICredential
from agentscope.event import EventType
from agentscope.message import UserMsg
from agentscope.model import OpenAIChatModel
from agentscope.permission import PermissionBehavior, PermissionRule

from client import connect, text_content


async def run(task, output):
    # New private directory: never overwrite an earlier attempt's evidence.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    started = time.perf_counter()
    events = []
    summary = {"passed": False}
    try:
        async with connect() as (tools, toolkit):
            guide = await tools["sandswap_guide"]()
            if guide.state == "error":
                raise RuntimeError("Cannot read SandSwap guide")
            model = OpenAIChatModel(
                credential=OpenAICredential(
                    api_key=os.environ["MODEL_API_KEY"],
                    base_url=os.environ.get("MODEL_BASE_URL", "https://open.bigmodel.cn/api/paas/v4"),
                ),
                model=os.environ.get("MODEL_NAME", "glm-5.3-flash"),
                stream=True,
                max_retries=0,
                extra_body={"thinking": {"type": "disabled"}},
                client_kwargs={"timeout": 120, "max_retries": 0},
            )
            try:
                agent = Agent(
                    name="SandSwapCoder",
                    system_prompt=("Complete the task in the designated SandSwap sandbox. "
                                   "Use only the supplied MCP tools for all filesystem and shell work. "
                                   "Check tool JSON exit_code and error fields before claiming success.\n"
                                   + text_content(guide)),
                    model=model, toolkit=toolkit, react_config=ReActConfig(max_iters=20),
                )
                # Authorize only the explicitly configured sandbox tools.
                for tool in tools.values():
                    agent.state.permission_context.allow_rules[tool.name] = [PermissionRule(
                        tool_name=tool.name, rule_content=None,
                        behavior=PermissionBehavior.ALLOW, source="sandbox-example",
                    )]
                async with asyncio.timeout(600):
                    async for event in agent.reply_stream(UserMsg(name="user", content=task)):
                        events.append({"elapsed_ms": (time.perf_counter()-started)*1000,
                                       **event.model_dump(mode="json")})
                calls = {e["tool_call_id"]: e["tool_call_name"] for e in events
                         if e["type"] == EventType.TOOL_CALL_START}
                results = {e["tool_call_id"]: e["state"] for e in events
                           if e["type"] == EventType.TOOL_RESULT_END}
                ends = [e for e in events if e["type"] == EventType.REPLY_END]
                summary.update(
                    elapsed_ms=(time.perf_counter()-started)*1000,
                    tool_calls=list(calls.values()),
                    model_calls=sum(e["type"] == EventType.MODEL_CALL_END for e in events),
                    input_tokens=sum(e.get("input_tokens", 0) for e in events),
                    output_tokens=sum(e.get("output_tokens", 0) for e in events),
                    passed=bool(calls) and all(n.startswith("mcp__sandswap__") for n in calls.values())
                    and all(results.get(cid) == "success" for cid in calls)
                    and bool(ends) and ends[-1]["finished_reason"] == "completed",
                )
                if not summary["passed"]:
                    raise RuntimeError("Incomplete or failed AgentScope tool loop; inspect private events")
            finally:
                await model.client.close()
    finally:
        (output / "events.json").write_text(json.dumps(events, indent=2))
        (output / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(args.task.read_text(), args.output_dir))
