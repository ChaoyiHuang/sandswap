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
//
// Package main demonstrates how to create an AI agent that connects to a
// Sandswap gateway's MCP server and uses its sandbox tools, built on the two
// official Go SDKs instead of an agent framework:
//   - github.com/openai/openai-go            (LLM backend)
//   - github.com/modelcontextprotocol/go-sdk (MCP client)
// The agent can execute code in KVM microVMs, read/write files, and manage
// background processes — all through the standard MCP protocol.
// This is a functional twin of examples/eino-sandswap: identical modes, env
// vars, routing rules, prompts, and log line shapes, so the e2e test
// (e2e/eino-agent-mcp.sh) can target either example by pointing EINO_DIR at
// this directory. The only difference is the agent loop below is hand-rolled
// (LLM → tool calls → execute via MCP → feed results back) instead of being
// delegated to Eino's ChatModelAgent/Runner.
// Two modes are supported:
// Single-agent mode (default):
//	Set SANDSWAP_API_KEY — one agent connects to the MCP server.
// Dual-agent mode (VM reuse test):
//	Set SANDSWAP_API_KEY_A and SANDSWAP_API_KEY_B — two agents alternate
//	prompts over one shared pool (sequential by design), each with its own
//	MCP session. They share the same microVM pool, testing virtio-fs
//	allowed_dirs hot-swap and agent switching on the same VM.
//	Prompts are prefixed with "A:" or "B:" to route to the correct agent.
// Multi-agent mode (N agents, VM reuse test):
//	Set SANDSWAP_API_KEY_1 through SANDSWAP_API_KEY_N — N agents run,
//	each with its own MCP session. They share the same microVM pool.
//	Prompts are prefixed with "1:", "2:", etc. to route to the correct agent.
// Three LLM backends are supported (selected by environment variable), all
// served through the OpenAI-compatible Chat Completions API:
//   - DeepSeek: Set DEEPSEEK_API_KEY (recommended for tool calling)
//   - OpenAI:   Set OPENAI_API_KEY (also works for any OpenAI-compatible API via BaseURL)
//   - Gemini:   Set GOOGLE_API_KEY (via Google's OpenAI-compatibility endpoint)

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"

	openai "github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/packages/param"
	"github.com/openai/openai-go/shared"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxIterations bounds the LLM ↔ tool loop for a single prompt, matching
// the Eino ChatModelAgent's MaxIterations: 30.
const maxIterations = 30

// createModel selects and creates the LLM model based on environment variables.
//
// Priority: DEEPSEEK_API_KEY > OPENAI_API_KEY > GOOGLE_API_KEY.
// All three backends speak OpenAI's Chat Completions API, so a single
// openai-go client suffices — only the base URL and model differ.
func createModel(ctx context.Context) (*openai.Client, string, error) {
	if key := os.Getenv("DEEPSEEK_API_KEY"); key != "" {
		modelName := os.Getenv("DEEPSEEK_MODEL")
		if modelName == "" {
			modelName = "deepseek-flash"
		}
		baseURL := os.Getenv("DEEPSEEK_BASE_URL")
		if baseURL == "" {
			baseURL = "https://api.deepseek.com"
		}
		client := openai.NewClient(
			option.WithAPIKey(key),
			option.WithBaseURL(baseURL),
		)
		return &client, modelName, nil
	}

	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		modelName := os.Getenv("OPENAI_MODEL")
		if modelName == "" {
			modelName = "gpt-4o"
		}
		opts := []option.RequestOption{option.WithAPIKey(key)}
		if baseURL := os.Getenv("OPENAI_BASE_URL"); baseURL != "" {
			opts = append(opts, option.WithBaseURL(baseURL))
		}
		client := openai.NewClient(opts...)
		return &client, modelName, nil
	}

	if key := os.Getenv("GOOGLE_API_KEY"); key != "" {
		modelName := os.Getenv("GEMINI_MODEL")
		if modelName == "" {
			modelName = "gemini-2.0-flash"
		}
		baseURL := os.Getenv("GEMINI_BASE_URL")
		if baseURL == "" {
			baseURL = "https://generativelanguage.googleapis.com/v1beta/openai"
		}
		client := openai.NewClient(
			option.WithAPIKey(key),
			option.WithBaseURL(baseURL),
		)
		return &client, modelName, nil
	}

	return nil, "", fmt.Errorf("no LLM API key set: set DEEPSEEK_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY")
}

// headerRoundTripper injects static HTTP headers into every request. It wraps
// the transport so the keep-alive connection stays the affinity anchor
// (http.DefaultTransport closes idle connections after 90s, which would sever
// the agent↔gateway connection mid-session).
type headerRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	return t.base.RoundTrip(req)
}

// connectMCP connects to the Sandswap gateway's MCP server, initializes the
// session, and returns the live session plus the list of discovered tools.
func connectMCP(ctx context.Context, mcpURL, apiKey string) (*mcp.ClientSession, []*mcp.Tool, error) {
	// Always use a custom transport so the keep-alive connection is the
	// affinity anchor. IdleConnTimeout 0 = no client-side idle limit — the
	// gateway's own IdleTimeout governs.
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		IdleConnTimeout: 0,
	}
	// If a CA cert is specified, trust it. Needed for K8s self-signed TLS.
	if caPath := os.Getenv("SANDSWAP_CA_CERT"); caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read CA cert %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, nil, fmt.Errorf("failed to append CA cert from %s", caPath)
		}
		httpTransport.TLSClientConfig.RootCAs = pool
	}

	// The gateway requires Bearer token auth on every MCP request.
	// X-Sandswap-Api-Key is ALSO sent because Go's http.Client strips the
	// Authorization header on cross-host redirects (redirect 307 to the owner
	// gateway); the custom header survives the redirect so the replayed
	// request authenticates.
	httpClient := &http.Client{
		Transport: &headerRoundTripper{
			base: httpTransport,
			headers: map[string]string{
				"Authorization":      "Bearer " + apiKey,
				"X-Sandswap-Api-Key": apiKey,
			},
		},
	}

	// The Sandswap gateway MCP server is a pure request/response Streamable
	// HTTP endpoint (POST only) — it never pushes server-initiated messages,
	// so the standalone SSE GET stream is unnecessary.
	transport := &mcp.StreamableClientTransport{
		Endpoint:             mcpURL,
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
	}

	cli := mcp.NewClient(&mcp.Implementation{
		Name:    "sandswap-openai",
		Version: "1.0.0",
	}, nil)

	// Connect performs the initialize handshake; the session is ready to use.
	cs, err := cli.Connect(ctx, transport, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("connect MCP client: %w", err)
	}

	// Enumerate all tools exposed by the server.
	var tools []*mcp.Tool
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			cs.Close()
			return nil, nil, fmt.Errorf("list MCP tools: %w", err)
		}
		tools = append(tools, tool)
	}

	return cs, tools, nil
}

// toOpenAITools converts MCP tool definitions into OpenAI function-tool
// definitions. The MCP input schema is already JSON Schema, which is exactly
// what OpenAI's function `parameters` field expects.
func toOpenAITools(mcpTools []*mcp.Tool) []openai.ChatCompletionToolParam {
	out := make([]openai.ChatCompletionToolParam, 0, len(mcpTools))
	for _, t := range mcpTools {
		fn := shared.FunctionDefinitionParam{
			Name: t.Name,
		}
		if t.Description != "" {
			fn.Description = param.NewOpt(t.Description)
		}
		switch schema := t.InputSchema.(type) {
		case map[string]any:
			fn.Parameters = shared.FunctionParameters(schema)
		default:
			// Fallback: the schema may arrive as raw JSON or another shape.
			if b, err := json.Marshal(t.InputSchema); err == nil {
				var m map[string]any
				if err := json.Unmarshal(b, &m); err == nil {
					fn.Parameters = shared.FunctionParameters(m)
				}
			}
			if fn.Parameters == nil {
				fn.Parameters = shared.FunctionParameters{"type": "object", "properties": map[string]any{}}
			}
		}
		out = append(out, openai.ChatCompletionToolParam{Function: fn})
	}
	return out
}

// sandboxInstruction is the system prompt for Sandswap sandbox agents.
const sandboxInstruction = `You are a sandbox assistant with access to a Sandswap sandbox.

You can:
- Execute code in an isolated KVM microVM (execute tool)
- Read and write files in the sandbox (file_read, file_write tools)
- List directory contents (file_list_dir)
- Create directories (file_mkdir)
- Remove files (file_remove)
- Rename files (file_rename)
- Check file metadata (file_stat)
- Run background processes and check their status (execute with background=true, exec_status, exec_kill)
- List available sandboxes (list_sandfs)

When executing code, prefer the "shell" language for simple commands and "python" for Python scripts.
All file paths are relative to /workspace inside the sandbox.
Always use the sandfs_id parameter when calling tools (check list_sandfs if unsure).

IMPORTANT rules for background executions:
- After starting a background exec (background=true), you will receive an exec_id.
- Do NOT poll exec_status repeatedly. Call exec_status at most ONCE to check if it is done.
- If the background exec is still running, respond to the user that it is running and stop. Do NOT call exec_status again.
- The user will ask you to check again later if needed.
- Never call exec_status more than once for the same background exec within a single conversation turn.`

// agentSession holds the per-agent state: the openai-go LLM client, the live
// MCP session, the discovered tools, and the conversation history.
type agentSession struct {
	label     string
	client    *openai.Client
	mcp       *mcp.ClientSession
	model     string
	tools     []openai.ChatCompletionToolParam
	history   []openai.ChatCompletionMessageParamUnion
	toolCount int
}

// newAgentSession connects to the MCP server with the given API key, converts
// the discovered tools to OpenAI function definitions, and returns a ready
// agentSession (system prompt already seeded at history[0]).
func newAgentSession(ctx context.Context, label, apiKey, mcpURL string, client *openai.Client, model string) (*agentSession, error) {
	cs, mcpTools, err := connectMCP(ctx, mcpURL, apiKey)
	if err != nil {
		return nil, fmt.Errorf("[%s] connect MCP: %w", label, err)
	}

	history := []openai.ChatCompletionMessageParamUnion{
		systemMessage(sandboxInstruction),
	}

	return &agentSession{
		label:     label,
		client:    client,
		mcp:       cs,
		model:     model,
		tools:     toOpenAITools(mcpTools),
		history:   history,
		toolCount: len(mcpTools),
	}, nil
}

// systemMessage builds a Chat Completions system message.
func systemMessage(text string) openai.ChatCompletionMessageParamUnion {
	return openai.ChatCompletionMessageParamUnion{
		OfSystem: &openai.ChatCompletionSystemMessageParam{
			Content: openai.ChatCompletionSystemMessageParamContentUnion{
				OfString: param.NewOpt(text),
			},
		},
	}
}

// userMessage builds a Chat Completions user message.
func userMessage(text string) openai.ChatCompletionMessageParamUnion {
	return openai.ChatCompletionMessageParamUnion{
		OfUser: &openai.ChatCompletionUserMessageParam{
			Content: openai.ChatCompletionUserMessageParamContentUnion{
				OfString: param.NewOpt(text),
			},
		},
	}
}

// assistantTextMessage builds a plain-text assistant message (no tool calls).
func assistantTextMessage(text string) openai.ChatCompletionMessageParamUnion {
	return openai.ChatCompletionMessageParamUnion{
		OfAssistant: &openai.ChatCompletionAssistantMessageParam{
			Content: openai.ChatCompletionAssistantMessageParamContentUnion{
				OfString: param.NewOpt(text),
			},
		},
	}
}

// runPrompt executes one prompt against the agent and returns the assistant
// response text. It drives the hand-rolled LLM ↔ tool loop and prints the
// LLM's tool calls and tool results for observability — the same log lines
// the Eino example emits.
func (s *agentSession) runPrompt(ctx context.Context, prompt string) string {
	fmt.Printf("[%s] >>> user prompt: %s\n", s.label, prompt)
	s.history = append(s.history, userMessage(prompt))

	// Work on a local copy of the conversation for this turn; only the final
	// assistant text is persisted back to s.history (mirrors the Eino runner,
	// which does not surface intermediate tool-call messages to the caller).
	messages := append([]openai.ChatCompletionMessageParamUnion{}, s.history...)

	var assistantContent string
	for iter := 0; iter < maxIterations; iter++ {
		completion, err := s.client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
			Model:    s.model,
			Messages: messages,
			Tools:    s.tools,
		})
		if err != nil {
			fmt.Printf("[%s] LLM call failed: %v\n", s.label, formatLLMError(err))
			break
		}
		if len(completion.Choices) == 0 {
			fmt.Printf("[%s] LLM returned no choices\n", s.label)
			break
		}
		msg := completion.Choices[0].Message

		// ── The model wants to call tools ──────────────────────────
		if len(msg.ToolCalls) > 0 {
			assistantMsg := openai.ChatCompletionAssistantMessageParam{}
			for _, tc := range msg.ToolCalls {
				assistantMsg.ToolCalls = append(assistantMsg.ToolCalls, openai.ChatCompletionMessageToolCallParam{
					ID: tc.ID,
					Function: openai.ChatCompletionMessageToolCallFunctionParam{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				})
				fmt.Printf("[%s] <<< LLM tool call: %s(%s)\n", s.label, tc.Function.Name, truncate(tc.Function.Arguments, 200))
			}
			// Echo the assistant message with its tool calls so the model
			// sees the calls it made; then feed each tool result back.
			messages = append(messages, openai.ChatCompletionMessageParamUnion{OfAssistant: &assistantMsg})

			for _, tc := range msg.ToolCalls {
				result := s.callTool(ctx, tc)
				fmt.Printf("[%s] >>> tool result [%s]: %s\n", s.label, tc.Function.Name, truncate(result, 300))
				messages = append(messages, openai.ChatCompletionMessageParamUnion{
					OfTool: &openai.ChatCompletionToolMessageParam{
						ToolCallID: tc.ID,
						Content: openai.ChatCompletionToolMessageParamContentUnion{
							OfString: param.NewOpt(result),
						},
					},
				})
			}
			continue
		}

		// ── Final text response ────────────────────────────────────
		if msg.Content != "" {
			assistantContent = msg.Content
		}
		break
	}

	if assistantContent != "" {
		fmt.Printf("[%s] <<< LLM response: %s\n", s.label, truncate(assistantContent, 500))
		s.history = append(s.history, assistantTextMessage(assistantContent))
	}
	return assistantContent
}

// callTool executes a single tool call against the MCP server and returns the
// text of the tool result.
func (s *agentSession) callTool(ctx context.Context, tc openai.ChatCompletionMessageToolCall) string {
	// Parse the model-generated arguments. The MCP SDK marshals Arguments to
	// JSON, so a plain map (or any other JSON value) works.
	var args any
	if tc.Function.Arguments != "" {
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
			// The model did not produce valid JSON — hand it an empty object
			// so the tool call still reaches the server.
			args = map[string]any{}
		}
	} else {
		args = map[string]any{}
	}

	res, err := s.mcp.CallTool(ctx, &mcp.CallToolParams{
		Name:      tc.Function.Name,
		Arguments: args,
	})
	if err != nil {
		return fmt.Sprintf("{\"error\": %q}", err.Error())
	}
	return toolResultToString(res)
}

// toolResultToString flattens an MCP tool result into plain text for the LLM.
func toolResultToString(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		parts = append(parts, contentText(c))
	}
	text := strings.Join(parts, "\n")
	if text == "" {
		text = "{}"
	}
	return text
}

// contentText extracts the human-readable text from an MCP content item.
func contentText(c mcp.Content) string {
	switch v := c.(type) {
	case *mcp.TextContent:
		return v.Text
	default:
		// Generic fallback for image/audio/embedded content: try to surface a
		// "text" field, otherwise dump the marshaled form.
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err == nil {
			if t, ok := m["text"].(string); ok {
				return t
			}
		}
		return string(b)
	}
}

// formatLLMError renders an LLM API error in a recognizable form, keeping the
// "invalid_request_error" / "HTTP 4xx" markers the e2e test greps for.
func formatLLMError(err error) string {
	var apiErr *openai.Error
	if errors.As(err, &apiErr) {
		code := apiErr.Code
		if code == "" {
			code = apiErr.Type
		}
		if code == "" {
			code = "api_error"
		}
		status := ""
		if apiErr.StatusCode > 0 {
			status = fmt.Sprintf(" HTTP %d", apiErr.StatusCode)
		}
		return fmt.Sprintf("%s (%s)%s", code, apiErr.Message, status)
	}
	return err.Error()
}

// truncate shortens a string for display, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	// Collapse newlines for single-line display
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ── Dual-agent mode ─────────────────────────────────────────────
//
// Two agents (A and B) alternate prompts over one shared pool,
// sequentially by design: each prompt finishes before the next one
// starts. Each agent has its own MCP session and API key. They share
// the same microVM pool — when agent A finishes, agent B reuses the
// same VM (virtio-fs allowed_dirs hot-swap + bind mount switch).
//
// Input format: lines prefixed with "A:" or "B:" route to the
// respective agent. Unprefixed lines go to agent A.

func runDualAgent(ctx context.Context, mcpURL string, apiKeyA, apiKeyB string, client *openai.Client, modelName string) {
	sessA, err := newAgentSession(ctx, "agent-A", apiKeyA, mcpURL, client, modelName)
	if err != nil {
		log.Fatalf("Failed to create agent A: %v", err)
	}
	sessB, err := newAgentSession(ctx, "agent-B", apiKeyB, mcpURL, client, modelName)
	if err != nil {
		log.Fatalf("Failed to create agent B: %v", err)
	}

	backend := detectBackend()

	fmt.Printf("Sandswap OpenAI+Go-SDK dual-agent ready\n")
	fmt.Printf("  MCP endpoint: %s\n", mcpURL)
	fmt.Printf("  LLM backend:  %s\n", backend)
	fmt.Printf("  Model:        %s\n", modelName)
	fmt.Printf("  Agent A:      %s (%d tools)\n", sessA.label, sessA.toolCount)
	fmt.Printf("  Agent B:      %s (%d tools)\n", sessB.label, sessB.toolCount)
	fmt.Println()
	fmt.Println("Prefix input with 'A:' or 'B:' to route to an agent. Unprefixed → A.")
	fmt.Println("Type 'exit' or 'quit' to exit.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("You: ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			fmt.Println("Goodbye!")
			break
		}

		// Route to agent A or B based on prefix
		var sess *agentSession
		var prompt string
		switch {
		case strings.HasPrefix(line, "A:"):
			sess = sessA
			prompt = strings.TrimSpace(strings.TrimPrefix(line, "A:"))
		case strings.HasPrefix(line, "B:"):
			sess = sessB
			prompt = strings.TrimSpace(strings.TrimPrefix(line, "B:"))
		default:
			sess = sessA
			prompt = line
		}

		if prompt == "" {
			continue
		}

		resp := sess.runPrompt(ctx, prompt)
		if resp == "__exit__" {
			fmt.Printf("[%s] Agent requested exit.\n", sess.label)
			break
		}
		if resp != "" {
			fmt.Printf("[%s] %s\n\n", sess.label, resp)
		}
	}
}

// ── Piped dual-agent mode ───────────────────────────────────────
//
// Used by the e2e test: prompts arrive on stdin as "A:prompt" or "B:prompt"
// lines. Prompts are processed sequentially — each prompt completes before
// the next starts. This ensures correct conversation history ordering and
// clean VM switching between agents (no concurrent access races on the
// single-VM pool).
//
// Alternating A→B→A→B prompts exercise the core VM reuse path:
// each agent switch triggers virtio-fs allowed_dirs hot-swap on the same VM.

func runPipedDualAgent(ctx context.Context, mcpURL string, apiKeyA, apiKeyB string, client *openai.Client, modelName string) {
	sessA, err := newAgentSession(ctx, "agent-A", apiKeyA, mcpURL, client, modelName)
	if err != nil {
		log.Fatalf("Failed to create agent A: %v", err)
	}
	sessB, err := newAgentSession(ctx, "agent-B", apiKeyB, mcpURL, client, modelName)
	if err != nil {
		log.Fatalf("Failed to create agent B: %v", err)
	}

	backend := detectBackend()

	fmt.Printf("Sandswap OpenAI+Go-SDK dual-agent ready (piped mode)\n")
	fmt.Printf("  MCP endpoint: %s\n", mcpURL)
	fmt.Printf("  LLM backend:  %s\n", backend)
	fmt.Printf("  Model:        %s\n", modelName)
	fmt.Printf("  Agent A:      %s (%d tools discovered)\n", sessA.label, sessA.toolCount)
	fmt.Printf("  Agent B:      %s (%d tools discovered)\n", sessB.label, sessB.toolCount)
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}

		// Route to agent A or B based on prefix
		var sess *agentSession
		var label string
		var prompt string
		switch {
		case strings.HasPrefix(line, "A:"):
			sess = sessA
			label = "A"
			prompt = strings.TrimSpace(strings.TrimPrefix(line, "A:"))
		case strings.HasPrefix(line, "B:"):
			sess = sessB
			label = "B"
			prompt = strings.TrimSpace(strings.TrimPrefix(line, "B:"))
		default:
			sess = sessA
			label = "A"
			prompt = line
		}

		if prompt == "" {
			continue
		}

		resp := sess.runPrompt(ctx, prompt)
		if resp == "__exit__" {
			fmt.Printf("[%s] Agent requested exit.\n", label)
			break
		}
		if resp != "" {
			fmt.Printf("[%s] %s\n\n", label, resp)
		}
	}
}

// ── Multi-agent mode ─────────────────────────────────────────────
//
// N agents (1..N) run with their own MCP sessions and API keys.
// They share the same microVM pool — agent switching triggers
// virtio-fs allowed_dirs hot-swap on the same VM.
//
// Input format: lines prefixed with "1:", "2:", etc. route to the
// respective agent. Unprefixed lines go to agent 1.

func runMultiAgent(ctx context.Context, mcpURL string, apiKeys []string, client *openai.Client, modelName string) {
	sessions := make([]*agentSession, len(apiKeys))
	for i, key := range apiKeys {
		label := fmt.Sprintf("agent-%d", i+1)
		sess, err := newAgentSession(ctx, label, key, mcpURL, client, modelName)
		if err != nil {
			log.Fatalf("Failed to create %s: %v", label, err)
		}
		sessions[i] = sess
	}

	backend := detectBackend()

	fmt.Printf("Sandswap OpenAI+Go-SDK multi-agent ready\n")
	fmt.Printf("  MCP endpoint: %s\n", mcpURL)
	fmt.Printf("  LLM backend:  %s\n", backend)
	fmt.Printf("  Model:        %s\n", modelName)
	for i, sess := range sessions {
		fmt.Printf("  Agent %d:      %s (%d tools)\n", i+1, sess.label, sess.toolCount)
	}
	fmt.Println()
	fmt.Printf("Prefix input with '1:' through '%d:' to route to an agent. Unprefixed → 1.\n", len(sessions))
	fmt.Println("Type 'exit' or 'quit' to exit.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("You: ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			fmt.Println("Goodbye!")
			break
		}

		sess, prompt := routeMultiAgent(line, sessions)

		if prompt == "" {
			continue
		}

		resp := sess.runPrompt(ctx, prompt)
		if resp == "__exit__" {
			fmt.Printf("[%s] Agent requested exit.\n", sess.label)
			break
		}
		if resp != "" {
			fmt.Printf("[%s] %s\n\n", sess.label, resp)
		}
	}
}

// ── Piped multi-agent mode ───────────────────────────────────────
//
// Used by the e2e test: prompts arrive on stdin as "1:prompt",
// "2:prompt", etc. Prompts are processed sequentially.

func runPipedMultiAgent(ctx context.Context, mcpURL string, apiKeys []string, client *openai.Client, modelName string) {
	sessions := make([]*agentSession, len(apiKeys))
	for i, key := range apiKeys {
		label := fmt.Sprintf("agent-%d", i+1)
		sess, err := newAgentSession(ctx, label, key, mcpURL, client, modelName)
		if err != nil {
			log.Fatalf("Failed to create %s: %v", label, err)
		}
		sessions[i] = sess
	}

	backend := detectBackend()

	fmt.Printf("Sandswap OpenAI+Go-SDK multi-agent ready (piped mode)\n")
	fmt.Printf("  MCP endpoint: %s\n", mcpURL)
	fmt.Printf("  LLM backend:  %s\n", backend)
	fmt.Printf("  Model:        %s\n", modelName)
	for i, sess := range sessions {
		fmt.Printf("  Agent %d:      %s (%d tools discovered)\n", i+1, sess.label, sess.toolCount)
	}
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}

		sess, prompt := routeMultiAgent(line, sessions)

		if prompt == "" {
			continue
		}

		resp := sess.runPrompt(ctx, prompt)
		if resp == "__exit__" {
			fmt.Printf("[%s] Agent requested exit.\n", sess.label)
			break
		}
		if resp != "" {
			fmt.Printf("[%s] %s\n\n", sess.label, resp)
		}
	}
}

// routeMultiAgent parses the prefix from a prompt line and returns
// the target agent session and the stripped prompt text.
// Prefix format: "1:", "2:", etc. Unprefixed → agent 1.
func routeMultiAgent(line string, sessions []*agentSession) (*agentSession, string) {
	for i := len(sessions) - 1; i >= 0; i-- {
		prefix := fmt.Sprintf("%d:", i+1)
		if strings.HasPrefix(line, prefix) {
			return sessions[i], strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	// No prefix → default to agent 1
	return sessions[0], line
}

// ── Single-agent mode ───────────────────────────────────────────

func runSingleAgent(ctx context.Context, mcpURL, apiKey string, client *openai.Client, modelName string) {
	sess, err := newAgentSession(ctx, "sandswap-agent", apiKey, mcpURL, client, modelName)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	backend := detectBackend()

	fmt.Printf("Sandswap OpenAI+Go-SDK agent ready: %s\n", sess.label)
	fmt.Printf("  MCP endpoint: %s\n", mcpURL)
	fmt.Printf("  LLM backend:  %s\n", backend)
	fmt.Printf("  Model:        %s\n", modelName)
	fmt.Printf("  Tools:        Sandswap MCP (%d tools discovered)\n", sess.toolCount)
	fmt.Println()
	fmt.Println("Type a message and press Enter. Press Ctrl+C to exit.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("You: ")
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		if input == "exit" || input == "quit" {
			fmt.Println("Goodbye!")
			break
		}

		resp := sess.runPrompt(ctx, input)
		if resp == "__exit__" {
			fmt.Println("\nAgent requested exit.")
			return
		}
		if resp != "" {
			fmt.Printf("Agent: %s\n\n", resp)
		}
	}
}

// detectBackend returns the active LLM backend name for display.
func detectBackend() string {
	switch {
	case os.Getenv("DEEPSEEK_API_KEY") != "":
		return "deepseek"
	case os.Getenv("OPENAI_API_KEY") != "":
		return "openai"
	default:
		return "gemini"
	}
}

func main() {
	// ── Configuration from environment ──────────────────────────
	mcpURL := os.Getenv("SANDSWAP_MCP_URL")
	if mcpURL == "" {
		mcpURL = "http://localhost:3000/mcp"
	}

	// ── Create context that cancels on Ctrl+C ───────────────────
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// ── Benchmark mode (SANDSWAP_BENCH_MODE=http|mcp) ──────────
	// Dispatched BEFORE createModel so the HTTP mode needs no LLM key.
	// ANY non-empty value dispatches: runBenchmark names an unknown mode
	// instead of letting a typo silently fall through to the interactive
	// agent loop. See bench_http.go / bench_mcp.go.
	if mode := benchMode(); mode != "" {
		if err := runBenchmark(ctx, mode); err != nil {
			log.Fatal(err)
		}
		return
	}

	// ── Create LLM model (DeepSeek / OpenAI / Gemini) ───────────
	client, modelName, err := createModel(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// ── Detect mode: multi-agent, dual-agent, or single-agent ────
	//
	// Multi-agent mode: SANDSWAP_API_KEY_1 through SANDSWAP_API_KEY_N
	//   N agents run, each with its own MCP session,
	//   sharing the same microVM pool (tests VM reuse / agent switch).
	//
	// Dual-agent mode: SANDSWAP_API_KEY_A + SANDSWAP_API_KEY_B
	//   Two agents alternate prompts sequentially over one shared pool,
	//   each with its own MCP session (tests VM reuse / agent switch).
	//
	// Single-agent mode: SANDSWAP_API_KEY
	//   One agent with one MCP session.

	// Scan for numbered API keys (SANDSWAP_API_KEY_1 .. SANDSWAP_API_KEY_20)
	var numberedKeys []string
	for i := 1; i <= 20; i++ {
		key := os.Getenv(fmt.Sprintf("SANDSWAP_API_KEY_%d", i))
		if key == "" {
			break
		}
		numberedKeys = append(numberedKeys, key)
	}

	apiKeyA := os.Getenv("SANDSWAP_API_KEY_A")
	apiKeyB := os.Getenv("SANDSWAP_API_KEY_B")
	singleKey := os.Getenv("SANDSWAP_API_KEY")

	if len(numberedKeys) > 0 {
		// Multi-agent mode
		stdinInfo, _ := os.Stdin.Stat()
		if stdinInfo != nil && stdinInfo.Mode()&os.ModeCharDevice == 0 {
			runPipedMultiAgent(ctx, mcpURL, numberedKeys, client, modelName)
		} else {
			runMultiAgent(ctx, mcpURL, numberedKeys, client, modelName)
		}
	} else if apiKeyA != "" && apiKeyB != "" {
		// Dual-agent mode
		// Check if stdin is a pipe (piped mode for e2e tests)
		// or a terminal (interactive mode)
		stdinInfo, _ := os.Stdin.Stat()
		if stdinInfo != nil && stdinInfo.Mode()&os.ModeCharDevice == 0 {
			// Piped input — use sequential dispatch
			runPipedDualAgent(ctx, mcpURL, apiKeyA, apiKeyB, client, modelName)
		} else {
			// Interactive terminal
			runDualAgent(ctx, mcpURL, apiKeyA, apiKeyB, client, modelName)
		}
	} else if singleKey != "" {
		runSingleAgent(ctx, mcpURL, singleKey, client, modelName)
	} else {
		log.Fatal("Set SANDSWAP_API_KEY for single-agent mode, SANDSWAP_API_KEY_A + SANDSWAP_API_KEY_B for dual-agent mode, or SANDSWAP_API_KEY_1..N for multi-agent mode")
	}
}
