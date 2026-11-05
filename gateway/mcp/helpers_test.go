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

package mcp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/pool"

	"log/slog"
)

// fakeSandlotClient is a configurable pool.SandlotClient for unit tests.
// Each RPC returns the configured result/err pair and records its last
// request so dispatch tests can assert argument forwarding.
//
// All fields are guarded by a mutex so the async cleanup goroutines spawned
// by the real handlers (cleanupAfterFailure) can't race with test assertions.
type fakeSandlotClient struct {
	mu sync.Mutex

	execResult   pool.ExecResult
	execErr      error
	statusResult pool.ExecResult
	statusErr    error
	killErr      error
	fileResult   pool.FileOpResult
	fileErr      error

	lastExecReq   pool.ExecRequest
	lastFileReq   pool.FileOpRequest
	lastFileNode  string
	lastStatusReq struct{ node, sandfsID, execID string }
	lastKillReq   struct{ node, sandfsID, execID string }

	execCalls   atomic.Int64
	fileCalls   atomic.Int64
	statusCalls atomic.Int64
	killCalls   atomic.Int64
}

// Compile-time interface check.
var _ pool.SandlotClient = (*fakeSandlotClient)(nil)

func (c *fakeSandlotClient) UnmountRootfs(_ context.Context, nodeAddr, sandfsID, volumePath, volumeEpoch string) (pool.UnmountResult, error) {
	return pool.UnmountResult{}, nil
}

func (c *fakeSandlotClient) MountRootfsAndExecute(_ context.Context, req pool.ExecRequest) (pool.ExecResult, error) {
	c.mu.Lock()
	c.lastExecReq = req
	c.mu.Unlock()
	c.execCalls.Add(1)
	return c.execResult, c.execErr
}

func (c *fakeSandlotClient) StatusExec(_ context.Context, nodeAddr, sandfsID, execID string) (pool.ExecResult, error) {
	c.mu.Lock()
	c.lastStatusReq.node = nodeAddr
	c.lastStatusReq.sandfsID = sandfsID
	c.lastStatusReq.execID = execID
	c.mu.Unlock()
	c.statusCalls.Add(1)
	return c.statusResult, c.statusErr
}

func (c *fakeSandlotClient) KillExec(_ context.Context, nodeAddr, sandfsID, execID string) error {
	c.mu.Lock()
	c.lastKillReq.node = nodeAddr
	c.lastKillReq.sandfsID = sandfsID
	c.lastKillReq.execID = execID
	c.mu.Unlock()
	c.killCalls.Add(1)
	return c.killErr
}

func (c *fakeSandlotClient) FileOp(_ context.Context, nodeAddr string, req pool.FileOpRequest) (pool.FileOpResult, error) {
	c.mu.Lock()
	c.lastFileReq = req
	c.lastFileNode = nodeAddr
	c.mu.Unlock()
	c.fileCalls.Add(1)
	return c.fileResult, c.fileErr
}

func (c *fakeSandlotClient) CleanupOverlay(_ context.Context, nodeAddr, volumePath string) error {
	return nil
}

// getters for last-request fields (mutex-protected).
func (c *fakeSandlotClient) lastFile() (pool.FileOpRequest, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastFileReq, c.lastFileNode
}

func (c *fakeSandlotClient) lastExec() pool.ExecRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastExecReq
}

// testEnv bundles an MCPServer with all its real dependencies and a fake
// sandlot client, mirroring the setup pattern in gateway/handler/execute_test.go.
// The handlers are REAL concrete instances (the dispatch layer calls concrete
// *handler.ExecuteHandler / *handler.FileHandler methods), backed by the fake
// sandlot client so we can control RPC results.
type testEnv struct {
	server   *MCPServer
	store    *identity.MemoryStore
	fake     *fakeSandlotClient
	pm       *pool.Manager
	lm       *lease.Lease
	ml       *lease.MountLock
	ss       *lease.SandfsState
	execH    *handler.ExecuteHandler
	fileH    *handler.FileHandler
	agentH   *handler.AgentHandler
	agentID  string
	agentKey string
	sandfsID string
}

// newTestEnv builds a single-node MCP server with 1 agent + 1 sandfs ready to go.
// The fake sandlot client is configured for success by default (sync exec done,
// empty file op). Tests override fake fields as needed.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	store := identity.NewMemoryStore(t.TempDir())

	agent, apiKey, err := store.CreateAgent(identity.CreateAgentRequest{Name: "test-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}

	rec, err := store.CreateSandFS(agent.ID, identity.CreateSandFSRequest{
		Name:        "test-sandfs",
		Description: "test description",
		Template:    "test:v1",
		Mode:        "flat",
	})
	if err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	// RootFSPath is needed by the cold-mount path (VolumePath). Point it at a
	// temp dir so it's non-empty; the fake client ignores it.
	if err := store.SetRootFSPath(rec.ID, t.TempDir()); err != nil {
		t.Fatalf("set rootfs path: %v", err)
	}

	fake := &fakeSandlotClient{
		execResult:   pool.ExecResult{Stdout: "ok", ExitCode: 0, Status: "done", ExecDurationNs: 1000, SandlotDurationNs: 2000},
		fileResult:   pool.FileOpResult{Success: true},
		statusResult: pool.ExecResult{Status: "running", ExitCode: 0, Stdout: "partial"},
	}

	logger := slog.New(slog.DiscardHandler)
	pm := pool.NewManager(fake, logger)
	lm := lease.New(100*time.Millisecond, 5*time.Second)
	ml := lease.NewMountLock()
	ss := lease.NewSandfsState()

	pm.AddNode("node-1")
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "medium", Clean: 3, Total: 3}})

	execH := handler.NewExecuteHandler(store, pm, lm, fake, ml, nil, ss, 30, 300, 0, logger)
	fileH := handler.NewFileHandler(store, pm, lm, fake, ml, nil, ss, logger)
	agentH := handler.NewAgentHandler(store, logger)

	srv := NewMCPServer(store, execH, fileH, agentH, lm, pm, fake, "gw-test", DefaultInstructions, logger)

	return &testEnv{
		server:   srv,
		store:    store,
		fake:     fake,
		pm:       pm,
		lm:       lm,
		ml:       ml,
		ss:       ss,
		execH:    execH,
		fileH:    fileH,
		agentH:   agentH,
		agentID:  agent.ID,
		agentKey: apiKey,
		sandfsID: rec.ID,
	}
}

// addSandfs creates an additional SandFS owned by the test agent and returns its ID.
func (e *testEnv) addSandfs(name string) string {
	rec, err := e.store.CreateSandFS(e.agentID, identity.CreateSandFSRequest{
		Name:        name,
		Description: name + " desc",
		Mode:        "flat",
	})
	if err != nil {
		panic(err)
	}
	_ = e.store.SetRootFSPath(rec.ID, "/tmp/test-vol")
	return rec.ID
}

// resolvedConn builds an mcpConnection with the agent already resolved (the
// state handleToolsCall produces after a successful resolveAgent).
func (e *testEnv) resolvedConn() *mcpConnection {
	agent, err := e.store.ResolveAgent(e.agentKey)
	if err != nil {
		panic(err)
	}
	return &mcpConnection{
		Agent:    agent,
		AgentKey: e.agentKey,
		Tools:    e.server.buildToolsList(agent.ID),
	}
}

// warmLease establishes a 60s background-exec lease for the test sandfs on
// node-1 so that ExecStatusDirect/ExecKillDirect take the warm path (lease hit)
// and actually call the sandlot RPC instead of returning "expired".
func (e *testEnv) warmLease() {
	e.lm.StartBgExec(e.sandfsID, "node-1", "bg-warm", 60*time.Second)
}
