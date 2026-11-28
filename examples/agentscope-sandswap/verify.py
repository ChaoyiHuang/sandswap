# SPDX-License-Identifier: Apache-2.0
"""Independently verify the standalone AgentScope coding fixture."""
import argparse
import asyncio
import json
import os
from pathlib import Path

from client import connect, text_content

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


async def verify(baseline, output):
    async with connect() as (tools, _):
        async def execute(code):
            chunk = await tools["execute"](sandfs_id=os.environ["SANDSWAP_SANDFS_ID"],
                                           language="shell", code=code)
            assert chunk.state != "error", text_content(chunk)
            result = json.loads(text_content(chunk))
            assert result["exit_code"] == 0, result
            return result["stdout"]
        result = json.loads(await execute(VERIFY))
        with output.open("x") as f:
            json.dump(result, f, indent=2)
        if baseline:
            before = json.loads(baseline.read_text())
            assert (result["tests_run"], result["failures"], result["errors"]) == (5, 0, 0)
            assert result["test_sha256"] == before["test_sha256"]
            assert result["commits"] == ["fix calc", "add failing calc suite"]
            assert result["status"] == "" and result["core_committed"]
            assert result["head"] != before["head"]
            print((await execute(CHECK_FUNCTIONS)).strip())
            print("PASS unchanged five tests, independent edge cases, committed fix, clean worktree")
        else:
            assert (result["tests_run"], result["failures"], result["errors"]) == (5, 3, 0)
            assert result["commits"] == ["add failing calc suite"]
            print("PASS baseline: five tests, three expected failures")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(verify(args.baseline, args.output))
