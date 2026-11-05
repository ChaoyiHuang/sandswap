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
// Package mcp implements an MCP (Model Context Protocol) server embedded in
// the gateway. It exposes Sandswap's execute and file operations as MCP tools,
// enabling AI agents to interact with sandboxes through the standard MCP protocol.
// Two transports are supported:
//   - Streamable HTTP: POST /mcp — uses the same Authorization header as the
//     HTTP API, integrates with the gateway's HTTP mux.
//   - stdio: reads JSON-RPC from stdin, writes to stdout — for local agent
//     integration (e.g., Claude Code MCP config).
// Stateless model (MCP 2026-07-28 RC): there is NO initialize handshake and
// NO Mcp-Session-Id session. Every request is self-contained — the agent API key
// (Authorization / X-Sandswap-Api-Key) is resolved per request, and sandfs_id in
// the tool arguments selects the sandbox. "Any request can land on any server
// instance" is therefore native: no per-gateway state to lose on failover.
// Affinity is owned by the transport (keep-alive) + server routing (owner-aware
// DNS + 307), NOT by an MCP session.
// Compatibility: the server still ANSWERS an "initialize" request (echoing the
// client's requested protocol version) so 2025-03-26-era clients that handshake
// keep working — it just stores no session. The method can also arrive via the
// Mcp-Method/Mcp-Name headers (SEP-2243) instead of in the JSON-RPC body.
// Auth: the agent's API key authenticates every request; sandfs_id in tool
// arguments selects the sandbox (same as HTTP API).

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"

	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/pool"
)

// MCPServer is the gateway's embedded MCP server.
type MCPServer struct {
	identityStore identity.Store
	execHandler   *handler.ExecuteHandler
	fileHandler   *handler.FileHandler
	agentHandler  *handler.AgentHandler
	leaseMgr      *lease.Lease
	pool          *pool.Manager
	sandlotClient pool.SandlotClient
	logger        *slog.Logger
	gatewayID     string // fixed gateway identity, for logging/correlation
	// instructions is the overall Sandswap guide served on initialize and the
	// sandswap_guide tool. Atomic pointer: the file watcher hot-swaps it.
	// Never nil after construction (see SetInstructions/currentInstructions).
	instructions atomic.Pointer[string]
}

// NewMCPServer creates a new MCP server. instructions is the overall guide
// text (mcp.ResolveInstructions resolves it from -mcp-instructions-file or
// the built-in default).
func NewMCPServer(store identity.Store, execH *handler.ExecuteHandler, fileH *handler.FileHandler, agentH *handler.AgentHandler, lm *lease.Lease, pm *pool.Manager, sc pool.SandlotClient, gatewayID string, instructions string, logger *slog.Logger) *MCPServer {
	s := &MCPServer{
		identityStore: store,
		execHandler:   execH,
		fileHandler:   fileH,
		agentHandler:  agentH,
		leaseMgr:      lm,
		pool:          pm,
		sandlotClient: sc,
		gatewayID:     gatewayID,
		logger:        logger,
	}
	s.SetInstructions(instructions)
	return s
}

// ── JSON-RPC types ─────────────────────────────────────────────

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	// redirectURL, when set, tells HandleHTTPRequest to write an HTTP 307 to the
	// owner gateway's /mcp instead of a JSON-RPC body (redirect). Not serialized.
	redirectURL string `json:"-"`
	// shedRebalance, when set with shedRetryAfterSec, tells HandleHTTPRequest to
	// write a raw HTTP 503 + Retry-After + Connection: close instead of a
	// JSON-RPC body. For a voluntary load shed the client must close the
	// connection and re-resolve the sandfs DNS name to land on a peer.
	// Not serialized.
	shedRebalance     bool `json:"-"`
	shedRetryAfterSec int  `json:"-"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ── MCP protocol types ─────────────────────────────────────────

type mcpInitializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      mcpClientInfo          `json:"clientInfo"`
}

type mcpClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpInitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      mcpServerInfo          `json:"serverInfo"`
	// Instructions is the optional overall server guide (MCP spec): how
	// Sandswap works, failure semantics, efficient usage. Clients surface it
	// to the LLM as context. Hot-swappable via -mcp-instructions-file.
	Instructions string `json:"instructions,omitempty"`
}

type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type mcpToolCallResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ── Connection state ───────────────────────────────────────────

// mcpConnection holds the resolved agent + tools for a SINGLE request (stateless).
// Created fresh per HTTP request / per stdio message; no session is stored.
type mcpConnection struct {
	Agent    *identity.Agent
	AgentKey string
	Tools    []mcpTool
}

// resolveAgent ensures the connection has a resolved agent. For the HTTP
// transport, this is called on every request (stateless). For stdio, it's
// called once per request too — stdio messages are self-contained.
func (s *MCPServer) resolveAgent(conn *mcpConnection) error {
	if conn.Agent != nil {
		return nil
	}
	agent, err := s.identityStore.ResolveAgent(conn.AgentKey)
	if err != nil {
		return fmt.Errorf("invalid api key")
	}
	conn.Agent = agent
	conn.Tools = s.buildToolsList(agent.ID)
	return nil
}

// ── HandleHTTPRequest handles Streamable HTTP transport (POST /mcp) ──

// HandleHTTPRequest handles MCP requests over Streamable HTTP.
// Uses the same Authorization header (or X-Sandswap-Api-Key) as the HTTP API.
//
// Stateless (MCP 2026-07-28 RC): every request resolves the agent itself
// and carries everything it needs in the body — no Mcp-Session-Id, no server-
// side session, so any request can land on any gateway instance. The method can
// arrive in the JSON-RPC body OR via the Mcp-Method/Mcp-Name headers (SEP-2243).
func (s *MCPServer) HandleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Error:   &jsonRPCError{Code: -32600, Message: "method not allowed, use POST"},
		})
		return
	}

	apiKey, err := identity.ExtractAPIKey(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Error:   &jsonRPCError{Code: -32001, Message: "missing or invalid api key"},
		})
		return
	}

	// Resolve the key BEFORE reading the body (the same pre-auth gate
	// /agent/execute and /agent/file use): an unauthenticated caller must not
	// be able to make the gateway allocate and decode a 50 MB JSON document
	// only to answer -32001. `ping` needs no session state, but it is not an
	// anonymous endpoint here — every MCP request carries an API key.
	if s.identityStore == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Error:   &jsonRPCError{Code: -32001, Message: "identity store unavailable"},
		})
		return
	}
	if _, err := s.identityStore.ResolveAgent(apiKey); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Error:   &jsonRPCError{Code: -32001, Message: "invalid api key"},
		})
		return
	}

	var req jsonRPCRequest
	// Limit request body to 50MB, matching /agent/file: MCP file_write carries
	// base64-encoded file content inside JSON-RPC params, which inflates ~33%.
	// A 50MB body lets a 16MB binary write (the warden single-op cap) still fit.
	limited := http.MaxBytesReader(w, r.Body, handler.MaxFileRequestBodyBytes)
	if err := json.NewDecoder(limited).Decode(&req); err != nil {
		// an OVERSIZE body is not a parse error — conflating them
		// told clients their JSON was malformed when the fix is "send less".
		// Distinguish via the MaxBytesError (mirrors the /agent/file handler).
		var maxBytesErr *http.MaxBytesError
		code, msg := -32700, "parse error"
		if errors.As(err, &maxBytesErr) {
			code, msg = -32600, "request body too large (50MB limit)"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Error:   &jsonRPCError{Code: code, Message: msg},
		})
		return
	}

	// SEP-2243: the method/name may travel in headers when the body is
	// self-contained without a method field. Prefer the body, fall back to
	// the headers.
	if req.Method == "" {
		req.Method = r.Header.Get("Mcp-Method")
	}
	if req.Method == "tools/call" && req.Params == nil {
		if name := r.Header.Get("Mcp-Name"); name != "" {
			req.Params, _ = json.Marshal(map[string]interface{}{"name": name})
		}
	}

	// Stateless: a fresh connection per request; the agent is resolved on demand
	// (single etcd-backed map lookup, µs) and the tools list rebuilt.
	conn := &mcpConnection{AgentKey: apiKey}

	resp := s.handleRPC(r.Context(), conn, &req)

	// redirect: this gateway is not the sandfs owner — 307 the whole /mcp request to
	// the owner gateway's /mcp (MCP client follows and re-sends the identical
	// self-contained request; the owner dispatches on its warm connection).
	if resp.redirectURL != "" {
		if r.Header.Get(handler.RedirectHeader) == "1" {
			// Anti-loop: this request is itself a redirected one — never redirect
			// again, return 503 so the client retries/errors out instead.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &jsonRPCError{Code: -32001, Message: "ownership conflict"},
			})
			return
		}
		w.Header().Set(handler.RedirectHeader, "1")
		http.Redirect(w, r, resp.redirectURL+"/mcp", http.StatusTemporaryRedirect)
		return
	}

	// shed: raw transport 503 + Retry-After + Connection: close. NOT a
	// JSON-RPC isError tool result (that would surface to the LLM, not trigger a
	// transport-layer reconnect). The client closes its connection and re-resolves
	// the sandfs DNS name to reach a peer that should claim it.
	if resp.shedRebalance {
		if resp.shedRetryAfterSec > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(resp.shedRetryAfterSec))
		}
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// Stateless: no Mcp-Session-Id — the response is fully self-contained.
	// tools/list embeds the CALLER's sandfs IDs and descriptions: never mark
	// it public. A shared/reverse cache keyed only by URL could hand one
	// agent's tool list to another. Private, short-lived caching is enough.
	if req.Method == "tools/list" {
		w.Header().Set("Cache-Control", "private, max-age=60")
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ── HandleStdio runs the stdio transport ───────────────────────

// HandleStdio runs the MCP server on stdin/stdout (stdio transport).
// The API key is read from the SANDSWAP_API_KEY environment variable.
func (s *MCPServer) HandleStdio(ctx context.Context) error {
	apiKey := os.Getenv("SANDSWAP_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("SANDSWAP_API_KEY environment variable is required")
	}

	conn := &mcpConnection{AgentKey: apiKey}

	decoder := json.NewDecoder(os.Stdin)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var req jsonRPCRequest
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			// json.Decoder does NOT advance past syntax errors: it re-reads
			// the same bad bytes on every Decode call, so `continue` here would
			// infinite-loop (100% CPU) on a single malformed stdio message.
			// Abort the session instead - the client can reconnect.
			return fmt.Errorf("invalid json-rpc message on stdio: %w", err)
		}

		resp := s.handleRPC(ctx, conn, &req)
		json.NewEncoder(os.Stdout).Encode(resp)
	}
}

// ── RPC dispatch ───────────────────────────────────────────────

func (s *MCPServer) handleRPC(ctx context.Context, conn *mcpConnection, req *jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(ctx, conn, req)
	case "tools/list":
		return s.handleToolsList(ctx, conn, req)
	case "tools/call":
		return s.handleToolsCall(ctx, conn, req)
	case "ping":
		return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{}}
	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonRPCError{Code: -32601, Message: "method not found"},
		}
	}
}

func (s *MCPServer) handleInitialize(ctx context.Context, conn *mcpConnection, req *jsonRPCRequest) jsonRPCResponse {
	// Kept as a benign, STATELESS handshake for 2025-03-26-era clients that
	// still call initialize. No session is created or stored — every request
	// resolves its own agent and the response is fully self-contained (RC model).
	if err := s.resolveAgent(conn); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonRPCError{Code: -32001, Message: "invalid api key"},
		}
	}

	// Echo the client's requested protocol version (known-version compatible) or
	// fall back to the current one when absent.
	protoVersion := "2025-03-26"
	var initParams mcpInitializeParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &initParams); err == nil && initParams.ProtocolVersion != "" {
			protoVersion = initParams.ProtocolVersion
		}
	}

	result := mcpInitializeResult{
		ProtocolVersion: protoVersion,
		Capabilities: map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		ServerInfo: mcpServerInfo{
			Name:    "sandswap-gateway",
			Version: "1.0.0",
		},
		Instructions: s.renderedInstructions(),
	}

	return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func (s *MCPServer) handleToolsList(ctx context.Context, conn *mcpConnection, req *jsonRPCRequest) jsonRPCResponse {
	// Auto-resolve agent if not already resolved (stateless HTTP transport).
	if err := s.resolveAgent(conn); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonRPCError{Code: -32001, Message: "invalid api key"},
		}
	}

	// The tools list is static per agent; the HTTP handler sets a short
	// Cache-Control so clients can skip re-listing within the window.
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]interface{}{"tools": conn.Tools},
	}
}

func (s *MCPServer) handleToolsCall(ctx context.Context, conn *mcpConnection, req *jsonRPCRequest) jsonRPCResponse {
	// Auto-resolve agent if not already resolved (stateless HTTP transport).
	if err := s.resolveAgent(conn); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonRPCError{Code: -32001, Message: "invalid api key"},
		}
	}

	var params mcpToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonRPCError{Code: -32602, Message: "invalid params"},
		}
	}

	result, err := s.dispatchToolCall(ctx, conn, params.Name, params.Arguments)
	if err != nil {
		// redirect: this gateway is not the owner — 307 the whole /mcp request to the
		// owner gateway. The MCP client (an HTTP client) follows the redirect and
		// re-sends the same self-contained tools/call; the owner dispatches it on
		// its warm connection. Only possible when the owner is healthy+routable.
		if ownerURL, ok := handler.IsOwnerRedirect(err); ok {
			// Set redirectURL for the HTTP transport (writes a 307, ignoring the
			// body). ALSO set Error so the stdio transport — which serializes
			// this response directly and cannot emit an HTTP redirect — produces
			// a valid JSON-RPC error (a response must carry either `result` or
			// `error`; without this, stdio clients get a malformed message).
			return jsonRPCResponse{
				JSONRPC:     "2.0",
				ID:          req.ID,
				redirectURL: ownerURL,
				Error:       &jsonRPCError{Code: -32001, Message: "redirect to " + ownerURL},
			}
		}
		// Preserve structured resilience error fields (error_code, retryable,
		// retry_after_ms) so MCP clients (AI agents) can programmatically
		// distinguish retryable 503s from permanent errors
		if msg, errorCode, retryable, retryAfterMs, shedRebalance, ok := handler.AsResilienceError(err); ok {
			// shed: emit a raw 503 (HandleHTTPRequest writes it) instead
			// of an isError tool result, so the client reconnects + re-resolves.
			// We ALSO set an Error field so the stdio transport (which cannot send
			// a raw HTTP 503) surfaces a meaningful message; the HTTP transport
			// ignores the Error field when shedRebalance is set and writes the 503.
			if shedRebalance {
				retrySec := 0
				if retryAfterMs > 0 {
					retrySec = retryAfterMs / 1000
				}
				return jsonRPCResponse{
					JSONRPC:           "2.0",
					ID:                req.ID,
					shedRebalance:     true,
					shedRetryAfterSec: retrySec,
					Error:             &jsonRPCError{Code: -32001, Message: msg},
				}
			}
			errJSON, _ := json.Marshal(map[string]interface{}{
				"error":          msg,
				"error_code":     errorCode,
				"retryable":      retryable,
				"retry_after_ms": retryAfterMs,
			})
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: mcpToolCallResult{
					Content: []mcpContent{{Type: "text", Text: string(errJSON)}},
					IsError: true,
				},
			}
		}
		// Named client-class refusals (4xx) — the wire-size gates — become
		// structured tool errors with a stable error_code and retryable:false,
		// so the model sees a deterministic refusal instead of a free-text blob
		// (and, crucially, the request NEVER reaches the node stream: an
		// oversize Send there would close the stream and kill co-tenant
		// commands).
		if msg, httpStatus, errorCode, ok := handler.AsNamedClientError(err); ok {
			errJSON, _ := json.Marshal(map[string]interface{}{
				"error":       msg,
				"error_code":  errorCode,
				"http_status": httpStatus,
				"retryable":   false,
			})
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: mcpToolCallResult{
					Content: []mcpContent{{Type: "text", Text: string(errJSON)}},
					IsError: true,
				},
			}
		}
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: mcpToolCallResult{
				Content: []mcpContent{{Type: "text", Text: err.Error()}},
				IsError: true,
			},
		}
	}

	return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}
