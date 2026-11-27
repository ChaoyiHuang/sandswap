// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Sandswap sandbox plugin for DeepSeek Harness (single entry).
 *
 * One plugin does both halves:
 * 1. Mounts the MCP connection to a Sandswap gateway by loading the
 *    `@deepseek-ai/dsh-mcp-client` plugin module below this plugin's fiber,
 *    so the 12 sandbox tools (execute, file_read, file_write, exec_status,
 *    exec_kill, list_sandfs, …) register as `mcp__<serverName>__*`.
 *    Sandswap requires BOTH auth headers on every request; the custom
 *    `X-Sandswap-Api-Key` header survives the cross-host 307 redirect.
 * 2. Applies an agent-level sandbox policy that mirrors Sandswap's Claude
 *    Code integration recipe: local shell / file-write tools are hidden and
 *    denied, and a system-prompt section routes every coding task
 *    (edit → run → test) into the sandbox instead of the host.
 *
 * Mounting the mcp-client module through `ctx.plugin()` registers no
 * service, so a profile's MCP manager keeps ownership of ctx.mcpClientHost.
 * Cleanup lives in `ctx.effect()`: Cordis does not invoke a value returned
 * from apply(), and agent-scoped guard registrations are not removed by
 * unloading this plugin alone.
 *
 * @module @sandswap/dsh-sandbox
 */

import * as McpClient from '@deepseek-ai/dsh-mcp-client'

/** Cordis plugin name. */
export const name = 'sandswap-sandbox'

/** The tool registry and prompt registry this row contributes to. */
export const inject = ['tools', 'systemPrompt']

const DEFAULT_RESTRICTED_TOOLS = ['pwsh', 'bash', 'write', 'edit']

/**
 * Plugin config (unvalidated plain object; see cordis.patch.yml).
 * - serverName: MCP tool namespace, default "sandswap".
 * - url: gateway MCP endpoint (POST /mcp).
 * - apiKey: agent API key, or the environment variable apiKeyEnv read at
 *   mount time when unset (the key then never lands in profile files).
 * - restrictTools: local global tool names to hide/deny ([] keeps all).
 * - toolCallTimeoutMs / startupTimeoutMs / failOnStartupError: forwarded
 *   to the MCP client (defaults suit an undeployed gateway: reconnect).
 */
export function apply(ctx, config) {
  const serverName = config?.serverName || 'sandswap'
  const url = config?.url || 'https://localhost:3000/mcp'
  const apiKeyEnv = config?.apiKeyEnv || 'SANDSWAP_AGENT_API_KEY'
  const restricted = new Set(config?.restrictTools ?? DEFAULT_RESTRICTED_TOOLS)
  const toolPrefix = `mcp__${serverName}__`

  // 1. MCP connection: mount the mcp-client module below this plugin's
  // fiber. This registers no service, so the profile's MCP manager keeps
  // ownership of ctx.mcpClientHost when it is present.
  const apiKey = config?.apiKey || process.env[apiKeyEnv] || ''
  const server = ctx.plugin(McpClient, {
    serverName,
    transport: 'streamable-http',
    url,
    // Sandswap requires BOTH auth headers on every request; the custom
    // X-Sandswap-Api-Key header survives the cross-host 307 redirect.
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'X-Sandswap-Api-Key': apiKey,
    },
    failOnStartupError: config?.failOnStartupError ?? false,
    ...(config?.toolCallTimeoutMs ? { toolCallTimeoutMs: config.toolCallTimeoutMs } : {}),
    ...(config?.startupTimeoutMs ? { startupTimeoutMs: config.startupTimeoutMs } : {}),
  })

  // 2. System-prompt guidance.
  const guidance = [
    '# Sandswap sandbox',
    '',
    `Code execution and file work run inside the Sandswap tinyVM sandbox, not on this machine. Use the ${toolPrefix}* tools for every coding task:`,
    '',
    `- Run commands and tests: \`${toolPrefix}execute\` (pass the \`sandfs_id\`; sync execs are hard-capped, so anything longer must use \`background: true\` and then \`${toolPrefix}exec_status\` / \`${toolPrefix}exec_kill\`).`,
    `- Read and write project files: \`${toolPrefix}file_read\` and \`${toolPrefix}file_write\` inside the sandbox.`,
    `- Discover your sandboxes with \`${toolPrefix}list_sandfs\`; read the full sandbox guide once with \`${toolPrefix}sandswap_guide\`.`,
    '',
    'Local shell and local file-write tools are unavailable: do not attempt them, and do not assume host paths exist. The sandbox workspace is the source of truth for the task; keep the whole edit-run-fix loop there.',
    'Failure semantics: after a recovery, a `not_found` exec status means re-create the work, not retry the poll; polls never extend the lease.',
  ].join('\n')

  const leavePrompt = ctx.systemPrompt.section({
    name: 'sandswap-sandbox',
    order: 500,
    text: guidance,
    retirement: 'The Sandswap sandbox policy no longer applies.',
  })

  const perAgent = new Map()

  const disposeAgent = (agent) => {
    const disposers = perAgent.get(agent)
    if (!disposers) return
    perAgent.delete(agent)
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        // disposal races are not fatal
      }
    }
  }

  const denyReason = (tool) =>
    `Local tool "${tool}" is disabled by the Sandswap sandbox policy. Run code inside the sandbox with ${toolPrefix}execute and handle files with ${toolPrefix}file_read / ${toolPrefix}file_write.`

  const leaveCreated = ctx.on('agent/created', ({ agent }) => {
    const actx = agent.ctx
    const disposers = []

    // Enforcement: deny restricted local tools even if a later registration
    // or scoped tool bypasses the restriction below.
    disposers.push(
      actx.tools.guard((exec) => {
        if (restricted.has(exec.name)) {
          return {
            reason: denyReason(exec.name),
            info: { name: 'sandswap-sandbox', code: 'SANDBOX_ENFORCED' },
          }
        }
        return undefined
      }),
    )

    // Presentation: hide the restricted global tools from this agent's tool
    // list. Restriction fails on unknown or scope-local names, so only name
    // tools that are currently registered globally.
    try {
      const global = ctx.tools.definitions(undefined)
      const deny = global
        .map((definition) => definition.name)
        .filter((name) => restricted.has(name))
      if (deny.length > 0) {
        disposers.push(actx.tools.restrict({ deny }))
      }
    } catch {
      // Registration order may leave the registry momentarily unavailable;
      // the guard above still denies execution.
    }

    perAgent.set(agent, disposers)
  })

  const leaveDisposed = ctx.on('agent/disposed', ({ agent }) => {
    disposeAgent(agent)
  })

  // Cleanup must live in ctx.effect: Cordis does not invoke a value returned
  // from apply(), and agent-scoped guard registrations are not removed by
  // unloading this plugin alone.
  ctx.effect(() => () => {
    leavePrompt()
    leaveCreated()
    leaveDisposed()
    for (const agent of [...perAgent.keys()]) disposeAgent(agent)
    void server.dispose()
  })
}
