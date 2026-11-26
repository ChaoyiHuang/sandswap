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

# setup.sh — do README steps 3–6 in one go against a running single-node
# deployment: create (or reuse) the demo agent + a flat SandFS from the
# stock ubuntu:<release> template, seed TASK.md's failing suite into
# /workspace, prove the coding toolchain runs in the tinyVM, and write
# .env.sh with the wiring Claude Code needs (API key, ids, MCP URL).
#
# Re-running is idempotent: an existing agent/SandFS are reused and the
# seeded project is reset to its failing state.
#
# Environment overrides:
#   CLAUDE_CODE_SANDBOX_AGENT_NAME (claude-code)   CLAUDE_CODE_SANDBOX_NAME (claude-code)
#   CLAUDE_CODE_SANDBOX_TEMPLATE (ubuntu:24.04)    CLAUDE_CODE_SANDBOX_MCP_URL (auto-detected)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT" # sandctl resolves cached api keys from ./run/agents.json

AGENT_NAME="${CLAUDE_CODE_SANDBOX_AGENT_NAME:-claude-code}"
SANDFS_NAME="${CLAUDE_CODE_SANDBOX_NAME:-claude-code}"
TEMPLATE="${CLAUDE_CODE_SANDBOX_TEMPLATE:-ubuntu:24.04}"
WORK="$HERE/.work"

die()  { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }
# field <json-file> <key> — top-level scalar from a JSON document.
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

# ── 1. Preconditions ───────────────────────────────────────────────
[[ -x output/sandctl ]] || die "output/sandctl missing — run from the Sandswap root (a release package has it; a source checkout builds it: bash build/build.sh go)"
output/sandctl health-all >/dev/null 2>&1 || die "stack not healthy — deploy first:
  sudo bash deploy/baremetal/deploy-single-node.sh --skip-build   (README step 1)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
mkdir -p "$WORK"

output/sandctl --raw api template list > "$WORK/templates.json"
python3 - "$WORK/templates.json" "$TEMPLATE" <<'PY' || die "template $TEMPLATE is not registered — the deployer stages output/rootfs-ubuntu as ubuntu:<release>:
  sudo bash build/build.sh ubuntu-rootfs && sudo bash deploy/baremetal/deploy-single-node.sh --skip-build"
import json, sys
for t in json.load(open(sys.argv[1])) or []:
    if f'{t.get("name")}:{t.get("version")}' == sys.argv[2]:
        sys.exit(0)
sys.exit(1)
PY

# ── 2. Agent (reuse only if we hold its key) ───────────────────────
# An agent's key is shown once, at creation; sandctl caches it under
# ./run/agents.json (its --run-dir default). So an agent can be reused only
# when that cache has its key — a release package starts with no cache, and a
# reinstalled deployment invalidates old keys. Otherwise create a new agent
# (names need not be unique); the previous one is left alone.
output/sandctl --raw api agent list > "$WORK/agents.json"
API_KEY=""; AGENT_ID=""
if [[ -f run/agents.json ]]; then
    PAIR="$(python3 - "$WORK/agents.json" run/agents.json "$AGENT_NAME" <<'PY'
import json, sys
agents = {a["agent_id"]: a["name"] for a in (json.load(open(sys.argv[1])) or [])}
try:
    cached = json.load(open(sys.argv[2]))
except (OSError, json.JSONDecodeError):
    cached = []
for r in cached:
    if agents.get(r.get("agent_id")) == sys.argv[3] and r.get("api_key"):
        print(f"{r['agent_id']}\t{r['api_key']}")
PY
    )"
    AGENT_ID="${PAIR%%$'\t'*}"; API_KEY="${PAIR#*$'\t'}"
fi
if [[ -n "$AGENT_ID" && -n "$API_KEY" ]]; then
    note "reusing agent $AGENT_NAME ($AGENT_ID)"
else
    note "creating agent $AGENT_NAME"
    output/sandctl --raw api agent create --name "$AGENT_NAME" > "$WORK/agent.json"
    AGENT_ID="$(field "$WORK/agent.json" agent_id)"
    API_KEY="$(field "$WORK/agent.json" api_key)"
fi

# ── 3. SandFS (reuse by name under this agent) ─────────────────────
output/sandctl --raw api sandfs list > "$WORK/sandfs.json"
SANDFS_ID="$(python3 - "$WORK/sandfs.json" "$AGENT_ID" "$SANDFS_NAME" <<'PY'
import json, sys
for s in json.load(open(sys.argv[1])) or []:
    if s.get("agent_id") == sys.argv[2] and s.get("name") == sys.argv[3]:
        print(s.get("sandfs_id", "")); break
PY
)"
if [[ -n "$SANDFS_ID" ]]; then
    note "reusing SandFS $SANDFS_NAME ($SANDFS_ID, template $TEMPLATE)"
else
    note "creating flat SandFS $SANDFS_NAME from $TEMPLATE"
    output/sandctl --raw api sandfs create --agent "$AGENT_ID" --name "$SANDFS_NAME" \
        --template "$TEMPLATE" --mode flat --vcpus 2 --memory-mb 512 > "$WORK/sandfs.json"
    SANDFS_ID="$(field "$WORK/sandfs.json" sandfs_id)"
fi

# ── 4. Toolchain sanity check inside the tinyVM ────────────────────
# sx_exec hands the key to sandctl per command from this variable.
export CLAUDE_CODE_AGENT_ID="$AGENT_ID" CLAUDE_CODE_SANDFS_ID="$SANDFS_ID" CLAUDE_CODE_SANDBOX_API_KEY="$API_KEY"
note "sandbox toolchain check (python3 / pip3 / git / make inside the tinyVM)"
TOOLCHAIN_OUT="$(sx_exec "$AGENT_ID" "$SANDFS_ID" \
    'python3 --version && pip3 --version && git --version && make --version | head -1')" \
    || die "sandbox execute failed — see above"
printf '%s\n' "$TOOLCHAIN_OUT" | tee "$WORK/toolchain.txt"
grep -qE '"exit_code": *0[,}]' <<<"$TOOLCHAIN_OUT" \
    || die "toolchain check failed — the template lacks the coding toolchain: a source checkout rebuilds it (sudo bash build/build.sh ubuntu-rootfs) and redeploys; a release package should not hit this"

# ── 5. Seed the task ───────────────────────────────────────────────
bash "$HERE/seed.sh" | tee "$WORK/seed.txt" || die "seeding failed — see above"

# ── 6. Environment handoff ─────────────────────────────────────────
MCP_URL="${CLAUDE_CODE_SANDBOX_MCP_URL:-}"
if [[ -z "$MCP_URL" ]]; then
    if grep -q '^gateway_url=https://' /etc/sandswap/sandctl.env 2>/dev/null; then
        MCP_URL="https://localhost:3000/mcp"
    else
        MCP_URL="http://localhost:3000/mcp"
    fi
fi

cat > "$HERE/.env.sh" <<ENV
# Written by setup.sh — source it before launching Claude Code (or smoke.sh).
# Git-ignored: it carries the agent API key.
export CLAUDE_CODE_SANDBOX_MCP_URL="$MCP_URL"
export CLAUDE_CODE_SANDBOX_API_KEY="$API_KEY"
export CLAUDE_CODE_AGENT_ID="$AGENT_ID"
export CLAUDE_CODE_SANDFS_ID="$SANDFS_ID"
ENV
chmod 600 "$HERE/.env.sh"

echo
echo "==================================================================="
echo " Provisioned:"
echo "   agent:    $AGENT_NAME ($AGENT_ID)"
echo "   sandbox:  $SANDFS_ID  (template $TEMPLATE, mode flat)"
echo "   MCP url:  $MCP_URL"
case "$MCP_URL" in
    https:*) echo "   TLS:      export NODE_EXTRA_CA_CERTS=/etc/sandswap/certs/ca.crt" ;;
esac
echo
echo " Next (README step 7):"
echo "   source $HERE/.env.sh"
[[ "$MCP_URL" == https:* ]] && echo "   export NODE_EXTRA_CA_CERTS=/etc/sandswap/certs/ca.crt"
echo "   cd $HERE && claude        # then paste TASK.md, or: Complete the task in TASK.md"
echo "==================================================================="
