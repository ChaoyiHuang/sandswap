#!/usr/bin/env bash
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

# seed.sh — put the demo coding task (TASK.md) into the sandbox's /workspace:
# a small Python package whose test suite fails on two bugs in calc/core.py,
# committed as the first commit on `main`. Claude Code's job is to make it
# green and commit the fix — through the sandswap MCP tools only.
#
# Idempotent: /workspace is reset to the seeded state on every run.
#
# Targets the sandbox named by CLAUDE_CODE_SANDFS_ID, owned by CLAUDE_CODE_AGENT_ID.
# Values already exported in the shell WIN; .env.sh (written by setup.sh) is
# only a fallback when they are not — never an override. A stale .env.sh from
# a previous deployment (ids that a reinstall deleted) must not clobber the
# ids the user just exported by hand.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT" # sandctl resolves the agent key from ./run/agents.json

if [[ -z "${CLAUDE_CODE_AGENT_ID:-}" || -z "${CLAUDE_CODE_SANDFS_ID:-}" ]] && [[ -f "$HERE/.env.sh" ]]; then
    source "$HERE/.env.sh"
fi
[[ -n "${CLAUDE_CODE_AGENT_ID:-}" && -n "${CLAUDE_CODE_SANDFS_ID:-}" ]] || {
    echo "error: set CLAUDE_CODE_AGENT_ID and CLAUDE_CODE_SANDFS_ID (or run setup.sh first)" >&2
    exit 1
}
[[ -x output/sandctl ]] || { echo "error: output/sandctl missing (bash build/build.sh go)" >&2; exit 1; }
# shellcheck source=lib.sh
source "$HERE/lib.sh"

echo "==> seeding /workspace of $CLAUDE_CODE_SANDFS_ID (expected: the suite FAILS)"
sx_exec "$CLAUDE_CODE_AGENT_ID" "$CLAUDE_CODE_SANDFS_ID" "$(cat <<'SEED'
set -e
# Reset /workspace completely — dotfiles included (an agent's .venv, history,
# tool caches), which a plain glob would leave behind.
find /workspace -mindepth 1 -delete
mkdir -p /workspace/calc /workspace/tests
cat > /workspace/calc/__init__.py <<'EOF'

EOF
cat > /workspace/calc/core.py <<'EOF'
def add(a, b):
    """Return the sum of a and b."""
    return a - b


def fib(n):
    """Return the n-th Fibonacci number (fib(0)=0, fib(1)=1)."""
    if n < 0:
        raise ValueError("n must be >= 0")
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(n - 2):
        a, b = b, a + b
    return b
EOF
cat > /workspace/tests/test_calc.py <<'EOF'
import unittest

from calc.core import add, fib


class TestAdd(unittest.TestCase):
    def test_ints(self):
        self.assertEqual(add(2, 3), 5)

    def test_negatives(self):
        self.assertEqual(add(-1, 1), 0)


class TestFib(unittest.TestCase):
    def test_base(self):
        self.assertEqual(fib(0), 0)
        self.assertEqual(fib(1), 1)

    def test_sequence(self):
        self.assertEqual([fib(i) for i in range(7)], [0, 1, 1, 2, 3, 5, 8])

    def test_rejects_negative(self):
        with self.assertRaises(ValueError):
            fib(-1)


if __name__ == "__main__":
    unittest.main()
EOF
cd /workspace
git init -q -b main
git add -A
git -c user.email=agent@sandswap -c user.name=agent commit -qm "add failing calc suite"
set +e
python3 -m unittest discover -s tests 2>&1 | tail -3
SEED
)"
