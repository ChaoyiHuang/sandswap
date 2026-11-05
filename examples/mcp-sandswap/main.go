// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

// mcp-sandswap: a minimal MCP client for the Sandswap gateway.
//
// The smallest complete integration loop against `POST /mcp`:
//
//	connect (initialize handshake) → tools/list → execute (sync)
//	  → execute (background) → exec_status poll → exec_kill → list_sandfs
//
// It demonstrates the three things every Sandswap MCP client gets right:
//
//  1. Both auth headers on every request — `Authorization: Bearer` plus
//     `X-Sandswap-Api-Key`, because the custom header survives the
//     cross-host 307 ownership redirect that strips the former.
//  2. One shared HTTP transport with no client-side idle timeout — the
//     connection is the affinity anchor; the gateway's -idle-timeout
//     (default 3600 s) governs its lifetime.
//  3. Background semantics — `lease_duration` is an absolute cap, status
//     polls never extend it, and `not_found` after a recovery means
//     re-create the work, not retry the poll (the abort contract).
//
// Usage:
//
//	export SANDSWAP_MCP_URL=https://sandswap.local:3000/mcp
//	export SANDSWAP_API_KEY=sk-sandswap-agent-...
//	go run .                      # run the whole demo loop
//	go run . -tools               # just list the tools and exit
//
// Optional: SANDSWAP_CA_CERT=/path/to/ca.pem for a private CA.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// headerTransport injects the Sandswap auth headers on every request.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return t.base.RoundTrip(r)
}

// connectMCP opens one MCP session over one persistent connection.
func connectMCP(ctx context.Context, mcpURL, apiKey string) (*mcp.ClientSession, error) {
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		// Hold the connection for the process lifetime; the gateway's
		// -idle-timeout (default 3600 s) is the real lifetime knob.
		IdleConnTimeout: 0,
	}
	if caPath := os.Getenv("SANDSWAP_CA_CERT"); caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to append CA cert from %s", caPath)
		}
		httpTransport.TLSClientConfig.RootCAs = pool
	}

	httpClient := &http.Client{
		Transport: &headerTransport{
			base: httpTransport,
			headers: map[string]string{
				"Authorization":      "Bearer " + apiKey,
				"X-Sandswap-Api-Key": apiKey, // survives cross-host 307
			},
		},
	}

	// The Sandswap MCP server is POST-only request/response Streamable HTTP;
	// it never pushes server-initiated messages, so disable the standalone
	// SSE GET stream.
	transport := &mcp.StreamableClientTransport{
		Endpoint:             mcpURL,
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
	}

	cli := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-sandswap",
		Version: "1.0.0",
	}, nil)

	// Connect performs the initialize handshake; the gateway echoes the
	// client's protocol version.
	return cli.Connect(ctx, transport, nil)
}

func listTools(ctx context.Context, cs *mcp.ClientSession) error {
	fmt.Println("tools/list:")
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return err
		}
		fmt.Printf("  %-16s %s\n", tool.Name, firstLine(tool.Description))
	}
	return nil
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}

// callTool invokes a tool and returns content[0].text, surfacing isError
// results (tool-level failures are isError results, not JSON-RPC errors).
func callTool(ctx context.Context, cs *mcp.ClientSession, name string, args map[string]any) (string, error) {
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return "", err
	}
	if res.IsError {
		text := ""
		if len(res.Content) > 0 {
			if t, ok := res.Content[0].(*mcp.TextContent); ok {
				text = t.Text
			}
		}
		return text, fmt.Errorf("tool %s failed: %s", name, text)
	}
	if len(res.Content) == 0 {
		return "", nil
	}
	if t, ok := res.Content[0].(*mcp.TextContent); ok {
		return t.Text, nil
	}
	return fmt.Sprintf("%v", res.Content[0]), nil
}

func main() {
	listOnly := flag.Bool("tools", false, "list tools and exit")
	flag.Parse()

	mcpURL := os.Getenv("SANDSWAP_MCP_URL")
	if mcpURL == "" {
		mcpURL = "http://localhost:3000/mcp"
	}
	apiKey := os.Getenv("SANDSWAP_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "SANDSWAP_API_KEY is required (create one: sandctl api agent create --name demo)")
		os.Exit(2)
	}
	sandfsID := os.Getenv("SANDSWAP_SANDFS_ID")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cs, err := connectMCP(ctx, mcpURL, apiKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer cs.Close()

	if *listOnly {
		if err := listTools(ctx, cs); err != nil {
			fmt.Fprintln(os.Stderr, "tools/list:", err)
			os.Exit(1)
		}
		return
	}

	// --- Discovery: the agent's own SandFS instances. -------------------
	// tools/list already embeds them; list_sandfs is the explicit call.
	if sandfsID == "" {
		out, err := callTool(ctx, cs, "list_sandfs", nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "list_sandfs:", err)
			os.Exit(1)
		}
		fmt.Println("list_sandfs →", out)
		fmt.Fprintln(os.Stderr, "set SANDSWAP_SANDFS_ID to one of the ids above (skipping exec demo)")
		return
	}

	// --- Sync execute: block until done (default timeout 30 s). ---------
	out, err := callTool(ctx, cs, "execute", map[string]any{
		"sandfs_id": sandfsID,
		"code":      "echo hello from $(hostname) at $(date)",
		"language":  "shell",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "execute:", err)
		os.Exit(1)
	}
	fmt.Println("execute (sync) →", out)

	// --- File write + read: paths are relative to /workspace. -----------
	if _, err := callTool(ctx, cs, "file_write", map[string]any{
		"sandfs_id": sandfsID, "path": "mcp-demo.txt", "data": "written via MCP",
	}); err != nil {
		fmt.Fprintln(os.Stderr, "file_write:", err)
		os.Exit(1)
	}
	out, err = callTool(ctx, cs, "file_read", map[string]any{
		"sandfs_id": sandfsID, "path": "mcp-demo.txt",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "file_read:", err)
		os.Exit(1)
	}
	fmt.Println("file_read →", out)

	// --- Background execute: returns exec_id immediately. ---------------
	out, err = callTool(ctx, cs, "execute", map[string]any{
		"sandfs_id":      sandfsID,
		"code":           "for i in 1 2 3; do echo tick $i; sleep 1; done",
		"language":       "shell",
		"background":     true,
		"lease_duration": 120, // absolute run-time cap (seconds); polls never extend it
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "execute(background):", err)
		os.Exit(1)
	}
	fmt.Println("execute (background) →", out)
	var started struct {
		ExecID string `json:"exec_id"`
	}
	if err := json.Unmarshal([]byte(out), &started); err != nil || started.ExecID == "" {
		fmt.Fprintln(os.Stderr, "no exec_id in background result:", out)
		os.Exit(1)
	}

	// --- Poll status at a relaxed cadence until done. --------------------
	for range 10 {
		time.Sleep(time.Second)
		out, err := callTool(ctx, cs, "exec_status", map[string]any{
			"sandfs_id": sandfsID, "exec_id": started.ExecID,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "exec_status:", err)
			os.Exit(1)
		}
		var st struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal([]byte(out), &st)
		fmt.Println("exec_status →", st.Status)
		if st.Status == "done" || st.Status == "killed" {
			break
		}
		if st.Status == "not_found" || st.Status == "expired" {
			// not_found: the handle was lost (recovery/cleanup) — re-create
			// the work; expired: nothing holds the lease — stop polling.
			return
		}
	}

	// --- Kill (idempotent semantics: returns killed or expired). ---------
	out, err = callTool(ctx, cs, "exec_kill", map[string]any{
		"sandfs_id": sandfsID, "exec_id": started.ExecID,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "exec_kill:", err)
		os.Exit(1)
	}
	fmt.Println("exec_kill →", out)
}
