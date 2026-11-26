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

# lib.sh — shared by setup.sh / seed.sh / smoke.sh (source it from the repo root).

# sx_exec <agent-id> <sandfs-id> <shell-code> — run code in the sandbox through
# sandctl and print the raw JSON result. Retries the gateway's retryable busy
# states (NO_AVAILABLE_SANDBOX / SANDBOX_CLEANING: the sandbox is mid-recycle —
# its previous unmount is still finishing, or the pool is handing over a VM —
# a transient of a few ms). sandctl reports a refusal as "HTTP 503" on stderr
# and still exits 0, so success is judged by the result carrying "exit_code".
#
# Auth: sandctl resolves the key as SANDSWAP_API_KEY (env) > --api-key > the
# run/agents.json cache looked up by --agent. This example's key lives in
# CLAUDE_CODE_SANDBOX_API_KEY (its own namespace, so running the example never
# plants a SANDSWAP_API_KEY in the user's shell that would silently hijack
# every later `sandctl --agent X` call). It is handed to sandctl per command
# via `env` — scoped to that one process, never exported. If the user's shell
# already carries a SANDSWAP_API_KEY from something else, it is cleared for
# the call so it cannot override the example's agent.
sx_exec() {
    local agent="$1" sandfs="$2" code="$3" out attempt
    local key="${CLAUDE_CODE_SANDBOX_API_KEY:-}"
    if [[ -z "$key" ]]; then
        echo "error: CLAUDE_CODE_SANDBOX_API_KEY is not set (export it, or run setup.sh)" >&2
        return 1
    fi
    if [[ -n "${SANDSWAP_API_KEY:-}" ]]; then
        echo "note: this shell has a SANDSWAP_API_KEY set; sandctl would use it for EVERY --agent call — ignoring it here" >&2
    fi
    for attempt in 1 2 3 4 5 6; do
        out="$(env -u SANDSWAP_API_KEY -u SANDSWAP_API_KEY_FILE SANDSWAP_API_KEY="$key" \
                    output/sandctl --raw api execute --agent "$agent" --sandfs "$sandfs" \
                    --language shell --code "$code" 2>&1)"
        if [[ "$out" == *'"exit_code"'* ]]; then
            printf '%s\n' "$out"
            return 0
        fi
        if [[ "$out" != *"HTTP 503"* ]]; then
            printf '%s\n' "$out" >&2
            return 1
        fi
        sleep 4
    done
    printf '%s\n' "$out" >&2
    return 1
}
