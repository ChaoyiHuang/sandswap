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
// Package main demonstrates how to create Eino agents that connect
// to a Sandswap gateway's MCP server and use its sandbox tools.
// The agent can execute code in KVM microVMs, read/write files, and manage
// background processes — all through the standard MCP protocol.
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
// Three LLM backends are supported (selected by environment variable):
//   - DeepSeek: Set DEEPSEEK_API_KEY (recommended for tool calling)
//   - OpenAI:   Set OPENAI_API_KEY (also works for any OpenAI-compatible API via BaseURL)
//   - Gemini:   Set GOOGLE_API_KEY

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"

	einodeepseek "github.com/cloudwego/eino-ext/components/model/deepseek"
	einogemini "github.com/cloudwego/eino-ext/components/model/gemini"
	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	mcpp "github.com/cloudwego/eino-ext/components/tool/mcp"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcp "github.com/mark3labs/mcp-go/mcp"
	"google.golang.org/genai"
)

// createModel selects and creates the LLM model based on environment variables.
//
// Priority: DEEPSEEK_API_KEY > OPENAI_API_KEY > GOOGLE_API_KEY
func createModel(ctx context.Context) (model.BaseChatModel, string, error) {
	if key := os.Getenv("DEEPSEEK_API_KEY"); key != "" {
		modelName := os.Getenv("DEEPSEEK_MODEL")
		if modelName == "" {
			modelName = "deepseek-flash"
		}
		baseURL := os.Getenv("DEEPSEEK_BASE_URL")
		if baseURL == "" {
			baseURL = "https://api.deepseek.com"
		}
		m, err := einodeepseek.NewChatModel(ctx, &einodeepseek.ChatModelConfig{
			APIKey:  key,
			Model:   modelName,
			BaseURL: baseURL,
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to create DeepSeek model: %w", err)
		}
		return m, modelName, nil
	}

	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		modelName := os.Getenv("OPENAI_MODEL")
		if modelName == "" {
			modelName = "gpt-4o"
		}
		m, err := einoopenai.NewChatModel(ctx, &einoopenai.ChatModelConfig{
			APIKey:  key,
			Model:   modelName,
			BaseURL: os.Getenv("OPENAI_BASE_URL"),
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to create OpenAI model: %w", err)
		}
		return m, modelName, nil
	}

	if key := os.Getenv("GOOGLE_API_KEY"); key != "" {
		modelName := os.Getenv("GEMINI_MODEL")
		if modelName == "" {
			modelName = "gemini-2.0-flash"
		}
		genaiClient, err := genai.NewClient(ctx, &genai.ClientConfig{
			APIKey: key,
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to create Gemini client: %w", err)
		}
		m, err := einogemini.NewChatModel(ctx, &einogemini.Config{
			Client: genaiClient,
			Model:  modelName,
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to create Gemini model: %w", err)
		}
		return m, modelName, nil
	}

	return nil, "", fmt.Errorf("no LLM API key set: set DEEPSEEK_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY")
}

// connectMCP connects to the Sandswap gateway's MCP server, initializes the
// session, and returns Eino-wrapped tools ready for use with ChatModelAgent.
func connectMCP(ctx context.Context, mcpURL, apiKey string) ([]tool.BaseTool, error) {
	// Create StreamableHTTP MCP client with Authorization header.
	// The gateway requires Bearer token auth on every MCP request.
	// X-Sandswap-Api-Key is ALSO sent because Go's http.Client strips the
	// Authorization header on cross-host redirects (redirect 307 to the owner gateway);
	// the custom header survives the redirect so the replayed request authenticates.
	opts := []transport.StreamableHTTPCOption{
		transport.WithHTTPHeaders(map[string]string{
			"Authorization":      "Bearer " + apiKey,
			"X-Sandswap-Api-Key": apiKey,
		}),
	}

	// Always use a custom transport so the keep-alive connection is the affinity
	// anchor: http.DefaultTransport closes idle connections after 90s, which
	// would sever the agent↔gateway connection mid-session. IdleConnTimeout 0 =
	// no client-side idle limit — the gateway's own IdleTimeout governs.
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		IdleConnTimeout: 0,
	}
	// If a CA cert is specified, trust it. Needed for K8s self-signed TLS.
	if caPath := os.Getenv("SANDSWAP_CA_CERT"); caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to append CA cert from %s", caPath)
		}
		httpTransport.TLSClientConfig.RootCAs = pool
	}
	httpClient := &http.Client{Transport: httpTransport}
	opts = append(opts, transport.WithHTTPBasicClient(httpClient))

	cli, err := client.NewStreamableHttpClient(mcpURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("create MCP client: %w", err)
	}

	if err = cli.Start(ctx); err != nil {
		return nil, fmt.Errorf("start MCP client: %w", err)
	}

	// Initialize the MCP session
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "sandswap-eino",
		Version: "1.0.0",
	}
	if _, err = cli.Initialize(ctx, initReq); err != nil {
		return nil, fmt.Errorf("initialize MCP client: %w", err)
	}

	// Fetch all tools from the MCP server as Eino BaseTool instances
	tools, err := mcpp.GetTools(ctx, &mcpp.Config{Cli: cli})
	if err != nil {
		return nil, fmt.Errorf("get MCP tools: %w", err)
	}

	return tools, nil
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

// agentSession holds the per-agent state: Eino agent, runner, and conversation history.
type agentSession struct {
	label     string
	agent     *adk.ChatModelAgent
	runner    *adk.Runner
	history   []*schema.Message
	toolCount int
}

// newAgentSession creates an Eino ChatModelAgent, connects to the MCP server
// with the given API key, and returns a ready-to-use agentSession.
func newAgentSession(ctx context.Context, label, apiKey, mcpURL string, chatModel model.BaseChatModel) (*agentSession, error) {
	mcpTools, err := connectMCP(ctx, mcpURL, apiKey)
	if err != nil {
		return nil, fmt.Errorf("[%s] connect MCP: %w", label, err)
	}

	agent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name:        label,
		Description: "Sandswap sandbox assistant — executes code and manages files in KVM microVMs.",
		Instruction: sandboxInstruction,
		Model:       chatModel,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{
				Tools: mcpTools,
			},
		},
		MaxIterations: 30,
	})
	if err != nil {
		return nil, fmt.Errorf("[%s] create agent: %w", label, err)
	}

	runner := adk.NewRunner(ctx, adk.RunnerConfig{
		Agent:           agent,
		EnableStreaming: false,
	})

	return &agentSession{
		label:     label,
		agent:     agent,
		runner:    runner,
		toolCount: len(mcpTools),
	}, nil
}

// runPrompt executes one prompt against the agent and returns the assistant response text.
// It prints the LLM's tool calls and tool results for observability.
func (s *agentSession) runPrompt(ctx context.Context, prompt string) string {
	fmt.Printf("[%s] >>> user prompt: %s\n", s.label, prompt)
	s.history = append(s.history, schema.UserMessage(prompt))

	iter := s.runner.Run(ctx, s.history)

	var assistantContent string
	for {
		event, ok := iter.Next()
		if !ok {
			break
		}
		if event.Err != nil {
			fmt.Printf("[%s] Error: %v\n", s.label, event.Err)
			break
		}
		if event.Output != nil && event.Output.MessageOutput != nil {
			mv := event.Output.MessageOutput
			msg, msgErr := mv.GetMessage()

			switch mv.Role {
			case schema.Assistant:
				// LLM response — may contain tool calls or text
				if msgErr == nil && msg != nil {
					if len(msg.ToolCalls) > 0 {
						// LLM decided to call tools
						for _, tc := range msg.ToolCalls {
							fmt.Printf("[%s] <<< LLM tool call: %s(%s)\n", s.label, tc.Function.Name, truncate(tc.Function.Arguments, 200))
						}
					}
					if msg.Content != "" {
						assistantContent = msg.Content
					}
				}
			case schema.Tool:
				// Tool execution result
				if msgErr == nil && msg != nil {
					fmt.Printf("[%s] >>> tool result [%s]: %s\n", s.label, mv.ToolName, truncate(msg.Content, 300))
				}
			}
		}
		if event.Action != nil && event.Action.Exit {
			return "__exit__"
		}
	}

	if assistantContent != "" {
		fmt.Printf("[%s] <<< LLM response: %s\n", s.label, truncate(assistantContent, 500))
		s.history = append(s.history, schema.AssistantMessage(assistantContent, nil))
	}
	return assistantContent
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

func runDualAgent(ctx context.Context, mcpURL string, apiKeyA, apiKeyB string, chatModel model.BaseChatModel, modelName string) {
	sessA, err := newAgentSession(ctx, "agent-A", apiKeyA, mcpURL, chatModel)
	if err != nil {
		log.Fatalf("Failed to create agent A: %v", err)
	}
	sessB, err := newAgentSession(ctx, "agent-B", apiKeyB, mcpURL, chatModel)
	if err != nil {
		log.Fatalf("Failed to create agent B: %v", err)
	}

	backend := detectBackend()

	fmt.Printf("Sandswap Eino dual-agent ready\n")
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

func runPipedDualAgent(ctx context.Context, mcpURL string, apiKeyA, apiKeyB string, chatModel model.BaseChatModel, modelName string) {
	sessA, err := newAgentSession(ctx, "agent-A", apiKeyA, mcpURL, chatModel)
	if err != nil {
		log.Fatalf("Failed to create agent A: %v", err)
	}
	sessB, err := newAgentSession(ctx, "agent-B", apiKeyB, mcpURL, chatModel)
	if err != nil {
		log.Fatalf("Failed to create agent B: %v", err)
	}

	backend := detectBackend()

	fmt.Printf("Sandswap Eino dual-agent ready (piped mode)\n")
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

func runMultiAgent(ctx context.Context, mcpURL string, apiKeys []string, chatModel model.BaseChatModel, modelName string) {
	sessions := make([]*agentSession, len(apiKeys))
	for i, key := range apiKeys {
		label := fmt.Sprintf("agent-%d", i+1)
		sess, err := newAgentSession(ctx, label, key, mcpURL, chatModel)
		if err != nil {
			log.Fatalf("Failed to create %s: %v", label, err)
		}
		sessions[i] = sess
	}

	backend := detectBackend()

	fmt.Printf("Sandswap Eino multi-agent ready\n")
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

func runPipedMultiAgent(ctx context.Context, mcpURL string, apiKeys []string, chatModel model.BaseChatModel, modelName string) {
	sessions := make([]*agentSession, len(apiKeys))
	for i, key := range apiKeys {
		label := fmt.Sprintf("agent-%d", i+1)
		sess, err := newAgentSession(ctx, label, key, mcpURL, chatModel)
		if err != nil {
			log.Fatalf("Failed to create %s: %v", label, err)
		}
		sessions[i] = sess
	}

	backend := detectBackend()

	fmt.Printf("Sandswap Eino multi-agent ready (piped mode)\n")
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

func runSingleAgent(ctx context.Context, mcpURL, apiKey string, chatModel model.BaseChatModel, modelName string) {
	sess, err := newAgentSession(ctx, "sandswap-agent", apiKey, mcpURL, chatModel)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	backend := detectBackend()

	fmt.Printf("Sandswap Eino agent ready: %s\n", sess.label)
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

	// ── Create LLM model (DeepSeek / OpenAI / Gemini) ───────────
	chatModel, modelName, err := createModel(ctx)
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
			runPipedMultiAgent(ctx, mcpURL, numberedKeys, chatModel, modelName)
		} else {
			runMultiAgent(ctx, mcpURL, numberedKeys, chatModel, modelName)
		}
	} else if apiKeyA != "" && apiKeyB != "" {
		// Dual-agent mode
		// Check if stdin is a pipe (piped mode for e2e tests)
		// or a terminal (interactive mode)
		stdinInfo, _ := os.Stdin.Stat()
		if stdinInfo != nil && stdinInfo.Mode()&os.ModeCharDevice == 0 {
			// Piped input — sequential dispatch
			runPipedDualAgent(ctx, mcpURL, apiKeyA, apiKeyB, chatModel, modelName)
		} else {
			// Interactive terminal
			runDualAgent(ctx, mcpURL, apiKeyA, apiKeyB, chatModel, modelName)
		}
	} else if singleKey != "" {
		runSingleAgent(ctx, mcpURL, singleKey, chatModel, modelName)
	} else {
		log.Fatal("Set SANDSWAP_API_KEY for single-agent mode, SANDSWAP_API_KEY_A + SANDSWAP_API_KEY_B for dual-agent mode, or SANDSWAP_API_KEY_1..N for multi-agent mode")
	}
}
