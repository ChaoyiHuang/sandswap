# SPDX-License-Identifier: Apache-2.0
"""Provision fresh SandFS instances and seed the standalone AgentScope task."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import shlex
import subprocess

from client import connect, text_content

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


async def setup(output, sandctl, template, url, ca):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Administrative CLI calls must not inherit an unrelated sandbox credential.
    admin_env = {k: v for k, v in os.environ.items()
                 if k not in {"SANDSWAP_API_KEY", "SANDSWAP_API_KEY_FILE"}}

    def api(*args):
        result = subprocess.run([str(sandctl), "--raw", "api", *args], cwd=ROOT,
                                env=admin_env, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    resources = {"agent_ids": [], "sandfs_ids": []}

    def record(kind, resource_id):
        resources[kind].append(resource_id)
        (output / "resources.json").write_text(json.dumps(resources, indent=2))

    templates = api("template", "list")
    if not any(f"{t['name']}:{t['version']}" == template for t in templates or []):
        raise ValueError(f"Template {template} is not registered")
    owner = api("agent", "create", "--name", "agentscope")
    record("agent_ids", owner["agent_id"])
    other = api("agent", "create", "--name", "agentscope-isolation")
    record("agent_ids", other["agent_id"])

    def sandbox(agent, name):
        sid = api("sandfs", "create", "--agent", agent, "--name", name,
                  "--template", template, "--mode", "flat", "--vcpus", "2",
                  "--memory-mb", "512")["sandfs_id"]
        record("sandfs_ids", sid)
        return sid

    env = {
        "SANDSWAP_MCP_URL": url,
        "SANDSWAP_CA": ca,
        "SANDSWAP_API_KEY": owner["api_key"],
        "SANDSWAP_SANDFS_ID": sandbox(owner["agent_id"], "agentscope-coding"),
        "SANDSWAP_SECONDARY_ID": sandbox(owner["agent_id"], "agentscope-files"),
        "SANDSWAP_FOREIGN_ID": sandbox(other["agent_id"], "agentscope-foreign"),
    }
    with open(output / "env.sh", "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as f:
        f.write("\n".join(f"export {k}={shlex.quote(v)}" for k, v in env.items()) + "\n")
    os.environ.update(env)
    files = {str(p.relative_to(HERE / "fixtures"))[:-3]: p.read_text()
             for p in sorted((HERE / "fixtures").rglob("*.in"))}
    seed = """import json, pathlib, subprocess
root = pathlib.Path('/workspace')
if any(root.iterdir()):
    raise RuntimeError('Refusing to seed a nonempty workspace')
files = json.loads(FILES_JSON)
for name, contents in files.items():
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)
def git(*args):
    subprocess.run(['git', *args], cwd=root, check=True)
git('init', '-q', '-b', 'main')
git('add', '-A')
git('-c', 'user.name=agent', '-c', 'user.email=agent@sandswap',
    'commit', '-qm', 'add failing calc suite')
print('Standalone AgentScope fixture ready')
""".replace("FILES_JSON", repr(json.dumps(files)))
    async with connect() as (tools, _):
        result = await tools["execute"](
            sandfs_id=env["SANDSWAP_SANDFS_ID"], language="shell",
            code="python3 -B - <<'PY'\n" + seed + "PY",
        )
        if result.state == "error":
            raise RuntimeError(text_content(result))
        payload = json.loads(text_content(result))
        if payload["exit_code"] != 0:
            raise RuntimeError(payload)
    task = (HERE / "TASK.md").read_text().replace("{{SANDFS_ID}}", env["SANDSWAP_SANDFS_ID"])
    (output / "task.md").write_text(task)
    print(f"Created three fresh sandboxes. Source {output / 'env.sh'}; task: {output / 'task.md'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--sandctl", type=Path, default=ROOT / "output/sandctl")
    parser.add_argument("--template", default="ubuntu:24.04")
    parser.add_argument("--mcp-url", default="https://localhost:3000/mcp")
    parser.add_argument("--ca", default="/etc/sandswap/certs/ca.crt")
    args = parser.parse_args()
    asyncio.run(setup(args.output_dir, args.sandctl.resolve(), args.template, args.mcp_url, args.ca))
