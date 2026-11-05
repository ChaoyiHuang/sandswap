// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

package main

// MCP benchmark mode (SANDSWAP_BENCH_MODE=mcp): measures latency through the
// MCP execute tool, so every segment of the agent loop is benchmarked:
//
//   - T_llm  (llmMs):  openai-sandswap → LLM API → tool call response.
//   - T_mcp  (clientMs): openai-sandswap → MCP server → gateway → sandlot →
//     warden → back (the "from issuing the command to receiving the gateway response" round trip), measured
//     around every CallTool invocation.
//   - gateway/sandlot/exec (ms): the gateway's own measurements, returned
//     inside the execute tool result JSON.
//
// Warm path (deterministic): the LLM is driven once to establish the mount and
// collect T_llm; then openai-sandswap itself issues WARM_N back-to-back
// `execute` tool calls to the same agent, which hit the sticky lease. (If the
// LLM happens to return multiple tool calls in one response, each is executed
// and measured too.) Cold path alternates agents with a SWITCH_GAP_MS sleep.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	openai "github.com/openai/openai-go"
)

// llmPrompt mirrors the e2e prompt style so the model reliably returns a tool
// call instead of answering from memory.
const llmPrompt = "Use the execute tool to run this shell command: echo hi. You must call the tool, do not answer from memory."

func runBenchMCP(ctx context.Context) error {
	cfg := loadBenchConfig()
	if cfg.apiKeyA == "" || cfg.apiKeyB == "" {
		return fmt.Errorf("MCP benchmark requires SANDSWAP_API_KEY_A and SANDSWAP_API_KEY_B")
	}
	client, modelName, err := createModel(ctx)
	if err != nil {
		return fmt.Errorf("MCP benchmark requires an LLM API key (DEEPSEEK_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY): %w", err)
	}
	sessA, err := newAgentSession(ctx, "bench-A", cfg.apiKeyA, cfg.mcpURL, client, modelName)
	if err != nil {
		return fmt.Errorf("connect MCP session A: %w", err)
	}
	sessB, err := newAgentSession(ctx, "bench-B", cfg.apiKeyB, cfg.mcpURL, client, modelName)
	if err != nil {
		return fmt.Errorf("connect MCP session B: %w", err)
	}

	fmt.Printf("═══ Sandswap latency benchmark — mode=mcp ═══\n")
	fmt.Printf("MCP: %s   LLM: %s   model: %s   warm_n=%d  cold_n=%d  warm_gap_ms=%d  switch_gap_ms=%d  switch_settle_ms=%d  n_llm=%d\n\n",
		cfg.mcpURL, detectBackend(), modelName, cfg.warmN, cfg.coldN, cfg.warmGapMS, cfg.switchGapMS, cfg.switchSettleMS, cfg.nLLM)

	// ── 1. LLM round-trips (T_llm) + their tool calls (LLM-driven) ──
	// Each LLM round is seconds apart (≫ sticky window), so these tool calls
	// are cold mounts. Reported as their own group (T_llm distribution plus
	// T_mcp + gateway metrics for the resulting tool calls).
	llmMs := []float64{}
	llmDriven := []execSample{}
	for i := 0; i < cfg.nLLM; i++ {
		ms, calls, err := llmRoundTrip(ctx, sessA, llmPrompt)
		if err != nil {
			fmt.Printf("  [warn] LLM round-trip failed: %v\n", formatLLMError(err))
			continue
		}
		llmMs = append(llmMs, ms)
		for _, tc := range calls {
			if tc.Function.Name != "execute" {
				fmt.Printf("  [warn] LLM returned non-execute tool call %q — skipped\n", tc.Function.Name)
				continue
			}
			args, err := parseToolCallArgs(tc.Function.Arguments)
			if err != nil {
				fmt.Printf("  [warn] LLM tool call args invalid: %v\n", err)
				continue
			}
			if cfg.sandfsA != "" {
				args["sandfs_id"] = cfg.sandfsA
			}
			if s, ok := mcpExecTimed(ctx, sessA, args); ok {
				llmDriven = append(llmDriven, s) // cold by construction
			}
		}
	}
	printLLMStats("LLM round-trip (openai-sandswap → LLM API)", llmMs)

	// ── 2. Warm: warmup (excluded), then WARM_N direct calls ──
	// Issued by openai-sandswap itself (no LLM) so they are deterministic and
	// land inside the sticky window → warm lease reuse. A small WARM_GAP_MS
	// sleep between calls keeps them warm without extreme back-to-back hammering.
	fmt.Printf("Warm: %d execute tool calls to agent A (%dms gap)...\n", cfg.warmN, cfg.warmGapMS)
	warmupRetry(ctx, func() bool {
		_, ok := mcpExecTimed(ctx, sessA, mcpExecArgs(cfg.sandfsA, "echo warmup"))
		return ok
	})
	warm := make([]execSample, 0, cfg.warmN)
	for i := 0; i < cfg.warmN; i++ {
		if s, ok := mcpExecTimed(ctx, sessA, mcpExecArgs(cfg.sandfsA, "echo hi")); ok {
			s.warm = true // back-to-back same agent within sticky window
			warm = append(warm, s)
		}
		sleepMS(cfg.warmGapMS)
	}

	// ── 3. Switch: alternate A<->B with a gap > sticky-ms ──────────
	// Settle past the sticky window (default 1s) first: the warm phase's last
	// call left a live lease, and MCP has no lease-header signal to detect (and
	// exclude) the first switch call reusing it — so sleep once so every switch
	// call is a genuine cold mount.
	sleepMS(cfg.switchSettleMS)
	fmt.Printf("Switch: %d rounds alternating A<->B (%dms gap, lease expires)...\n", cfg.coldN, cfg.switchGapMS)
	cold := make([]execSample, 0, cfg.coldN*2)
	for i := 0; i < cfg.coldN; i++ {
		if s, ok := mcpExecTimed(ctx, sessA, mcpExecArgs(cfg.sandfsA, "echo a")); ok {
			cold = append(cold, s)
		}
		sleepMS(cfg.switchGapMS)
		if s, ok := mcpExecTimed(ctx, sessB, mcpExecArgs(cfg.sandfsB, "echo b")); ok {
			cold = append(cold, s)
		}
		sleepMS(cfg.switchGapMS)
	}

	printMetricTable(fmt.Sprintf("Warm — sticky lease reuse (n=%d) [ms]", len(warm)), warm)
	printMetricTable(fmt.Sprintf("Switch — cross-agent cold mount_and_exec (n=%d) [ms]", len(cold)), cold)
	printMetricTable(fmt.Sprintf("LLM-driven tool calls (cold, n=%d) [ms]", len(llmDriven)), llmDriven)

	if cfg.verbose {
		all := append(append(append([]execSample{}, warm...), cold...), llmDriven...)
		printVerbose(all)
	}
	// Quality gates AFTER the tables: the direct-call phases are deterministic
	// (no LLM) — a broken exec path must fail the run, not print "(no samples)"
	// and exit 0. LLM round-trips are external-dependent: report, don't gate.
	if err := benchQualityGate("warm", len(warm), cfg.warmN, warm); err != nil {
		return err
	}
	if err := benchQualityGate("cold", len(cold), cfg.coldN*2, cold); err != nil {
		return err
	}
	if cfg.nLLM > 0 && len(llmMs) == 0 {
		fmt.Println("  [warn] all LLM round-trips failed (external API) — direct-call tables above are still valid")
	}
	return nil
}

// mcpExecArgs builds the execute tool arguments for a direct (non-LLM) call.
func mcpExecArgs(sandfsID, code string) map[string]any {
	args := map[string]any{"code": code, "language": "shell"}
	if sandfsID != "" {
		args["sandfs_id"] = sandfsID
	}
	return args
}

// parseToolCallArgs decodes an LLM tool call's JSON arguments into a map.
func parseToolCallArgs(raw string) (map[string]any, error) {
	args := map[string]any{}
	if raw == "" {
		return args, nil
	}
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		return nil, err
	}
	return args, nil
}

// llmRoundTrip sends one Chat Completions request and returns the LLM round
// trip (ms) plus the tool calls the model asked for.
func llmRoundTrip(ctx context.Context, sess *agentSession, prompt string) (float64, []openai.ChatCompletionMessageToolCall, error) {
	messages := []openai.ChatCompletionMessageParamUnion{
		systemMessage(sandboxInstruction),
		userMessage(prompt),
	}
	start := time.Now()
	completion, err := sess.client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model:    sess.model,
		Messages: messages,
		Tools:    sess.tools,
	})
	ms := float64(time.Since(start).Nanoseconds()) / 1e6
	if err != nil {
		return ms, nil, err
	}
	if len(completion.Choices) == 0 {
		return ms, nil, fmt.Errorf("LLM returned no choices")
	}
	return ms, completion.Choices[0].Message.ToolCalls, nil
}

// mcpExecTimed invokes the execute tool over MCP, measures T_mcp, and parses
// the gateway metrics out of the tool result JSON.
func mcpExecTimed(ctx context.Context, sess *agentSession, args map[string]any) (execSample, bool) {
	start := time.Now()
	res, err := sess.mcp.CallTool(ctx, &mcp.CallToolParams{Name: "execute", Arguments: args})
	clientMs := float64(time.Since(start).Nanoseconds()) / 1e6
	if err != nil {
		fmt.Printf("  [warn] MCP execute failed: %v\n", err)
		return execSample{}, false
	}
	text := toolResultToString(res)
	s, ok := parseExecMetrics(text)
	if !ok {
		fmt.Printf("  [warn] could not parse metrics from MCP result: %s\n", truncate(text, 200))
		return execSample{}, false
	}
	s.clientMs = clientMs
	return s, true
}

// parseExecMetrics extracts the gateway's three measurements from the execute
// tool result JSON (the MCP dispatch layer returns them alongside stdout).
// Requires gateway_duration_ns to be present so a non-execute result (e.g. a
// file-op response) is rejected instead of silently yielding all-zero samples.
func parseExecMetrics(text string) (execSample, bool) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return execSample{}, false
	}
	if _, ok := raw["gateway_duration_ns"]; !ok {
		return execSample{}, false
	}
	var m struct {
		ExitCode          int    `json:"exit_code"`
		ExecDurationNs    uint64 `json:"exec_duration_ns"`
		SandlotDurationNs uint64 `json:"sandlot_duration_ns"`
		GatewayDurationNs uint64 `json:"gateway_duration_ns"`
	}
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return execSample{}, false
	}
	return execSample{
		gatewayMs: float64(m.GatewayDurationNs) / 1e6,
		sandlotMs: float64(m.SandlotDurationNs) / 1e6,
		execMs:    float64(m.ExecDurationNs) / 1e6,
		exit:      m.ExitCode,
	}, true
}
