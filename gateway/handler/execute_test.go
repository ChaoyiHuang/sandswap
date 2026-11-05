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

package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/pool"
	"gateway/registry"
	"gateway/storage"
	"gateway/storage/storagetest"
	"log/slog"
)

type testGateway struct {
	execHandler  *handler.ExecuteHandler
	fileHandler  *handler.FileHandler
	humanHandler *handler.HumanHandler
	agentHandler *handler.AgentHandler
	reg          *registry.Registry
	storage      *storagetest.Ops // the storage double (per-test knobs, e.g. SetEnsurePulled)
	pm           *pool.Manager
	lm           *lease.Lease
	agentAPIKey  string
	agentID      string
}

func setupTestGateway(t *testing.T) *testGateway {
	t.Helper()

	volRoot := t.TempDir()
	reg := registry.New(volRoot)

	// Storage plane: the test double (REAL volume dirs under the
	// temp root; no node-side provision code in the gateway module). The
	// listing is primed with the fixture template so /human/templates has
	// something to summarize.
	storageDouble := storagetest.New(reg.VolRoot())
	storageDouble.SetTemplates([]storage.TemplateInfo{{Name: "test", Version: "v1", Mode: "flat"}})
	reg.SetStorageOps(storageDouble)

	stubClient := pool.NewStubSandlotClient()
	pm := pool.NewManager(stubClient, slog.New(slog.DiscardHandler))

	lm := lease.New(100*time.Millisecond, 5*time.Second)

	pm.AddNode("localhost")
	pm.UpdateNodeCapacity("localhost", []pool.SpecCapacity{{SpecID: "medium", Total: 3}})

	execHandler := handler.NewExecuteHandler(reg.Store(), pm, lm, stubClient, lease.NewMountLock(), nil, lease.NewSandfsState(), 30, 300, 0, slog.New(slog.DiscardHandler))
	fileHandler := handler.NewFileHandler(reg.Store(), pm, lm, stubClient, lease.NewMountLock(), nil, lease.NewSandfsState(), slog.New(slog.DiscardHandler))
	humanHandler := handler.NewHumanHandler(reg, pm, slog.New(slog.DiscardHandler))
	agentHandler := handler.NewAgentHandler(reg.Store(), slog.New(slog.DiscardHandler))

	// Create a default agent for tests
	agent, apiKey, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "test-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}

	return &testGateway{
		execHandler:  execHandler,
		fileHandler:  fileHandler,
		humanHandler: humanHandler,
		agentHandler: agentHandler,
		reg:          reg,
		storage:      storageDouble,
		pm:           pm,
		lm:           lm,
		agentAPIKey:  apiKey,
		agentID:      agent.ID,
	}
}

// createTestSandFS creates a SandFS under the default test agent.
func createTestSandFS(t *testing.T, gw *testGateway, name string) string {
	t.Helper()
	rec, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
		Name:        name,
		Description: "test sandfs",
		Template:    "test:v1",
		Mode:        "flat",
	})
	if err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	return rec.ID
}

func TestCreateAgent(t *testing.T) {
	gw := setupTestGateway(t)

	body := `{"name":"new-agent"}`
	req := httptest.NewRequest("POST", "/human/agent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	gw.humanHandler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp handler.CreateAgentResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.AgentID == "" {
		t.Error("expected agent_id")
	}
	if resp.APIKey == "" {
		t.Error("expected api_key")
	}
	if !strings.HasPrefix(resp.APIKey, "sk-sandswap-agent-") {
		t.Errorf("expected api_key prefix sk-sandswap-agent-, got %s", resp.APIKey)
	}
}

func TestCreateSandFS(t *testing.T) {
	gw := setupTestGateway(t)

	body := `{"agent_id":"` + gw.agentID + `","name":"test-sandfs","template":"test:v1","mode":"flat"}`
	req := httptest.NewRequest("POST", "/human/sandfs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	gw.humanHandler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp handler.HumanCreateSandFSResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.SandfsID == "" {
		t.Error("expected sandfs_id")
	}
	if resp.AgentID != gw.agentID {
		t.Errorf("expected agent_id %s, got %s", gw.agentID, resp.AgentID)
	}
}

// TestCreateSandFSPullStatus pins the create response's pull_status against
// the storage plane's auto-pull signal: a local hit reports "cached", a
// registry auto-pull on this create reports "pulled".
func TestCreateSandFSPullStatus(t *testing.T) {
	for _, tt := range []struct {
		name   string
		pulled bool
		want   string
	}{
		{"local hit", false, "cached"},
		{"auto-pulled from the registry", true, "pulled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gw := setupTestGateway(t)
			gw.storage.SetEnsurePulled(tt.pulled)

			body := `{"agent_id":"` + gw.agentID + `","name":"pull-status","template":"test:v1","mode":"overlay"}`
			req := httptest.NewRequest("POST", "/human/sandfs", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			gw.humanHandler.ServeHTTP(w, req)

			if w.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
			}
			var resp handler.HumanCreateSandFSResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.PullStatus != tt.want {
				t.Errorf("pull_status = %q, want %q", resp.PullStatus, tt.want)
			}
		})
	}
}

func TestExecuteWithoutAuth(t *testing.T) {
	gw := setupTestGateway(t)
	sandfsID := createTestSandFS(t, gw, "test-no-auth")

	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(`{"sandfs_id":"`+sandfsID+`","code":"print(1)","language":"python"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	gw.execHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestExecuteWithInvalidKey(t *testing.T) {
	gw := setupTestGateway(t)
	sandfsID := createTestSandFS(t, gw, "test-invalid-key")

	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(`{"sandfs_id":"`+sandfsID+`","code":"print(1)","language":"python"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid-key")
	w := httptest.NewRecorder()

	gw.execHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestExecuteWithValidKey(t *testing.T) {
	gw := setupTestGateway(t)
	sandfsID := createTestSandFS(t, gw, "test-valid-key")

	// Verify the sandfs exists
	rec, err := gw.reg.Get(sandfsID)
	if err != nil {
		t.Fatalf("sandfs not found: %v", err)
	}
	if rec.RootFSPath == "" {
		t.Error("expected volume path")
	}

	// Execute code with agent API key + sandfs_id
	execBody := `{"sandfs_id":"` + sandfsID + `","code":"print(42)","language":"python"}`
	execReq := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(execBody))
	execReq.Header.Set("Content-Type", "application/json")
	execReq.Header.Set("Authorization", "Bearer "+gw.agentAPIKey)
	execW := httptest.NewRecorder()

	gw.execHandler.ServeHTTP(execW, execReq)

	if execW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", execW.Code, execW.Body.String())
	}

	var execResp handler.ExecuteResponse
	if err := json.Unmarshal(execW.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if execResp.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", execResp.ExitCode)
	}

	// Verify no microVM ID is exposed in the external response.
	if vmID := execW.Header().Get("X-Sandbox-VMID"); vmID != "" {
		t.Errorf("X-Sandbox-VMID should not be exposed to external callers, got %q", vmID)
	}
}

func TestCrossAgentAccessDenied(t *testing.T) {
	gw := setupTestGateway(t)
	sandfsID := createTestSandFS(t, gw, "test-cross-agent")

	// Create a second agent
	_, otherAPIKey, err := gw.reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "other-agent"})
	if err != nil {
		t.Fatalf("create other agent: %v", err)
	}

	// Try to execute on sandfsID with the other agent's API key → should get 403
	execBody := `{"sandfs_id":"` + sandfsID + `","code":"print(1)","language":"python"}`
	execReq := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(execBody))
	execReq.Header.Set("Content-Type", "application/json")
	execReq.Header.Set("Authorization", "Bearer "+otherAPIKey)
	execW := httptest.NewRecorder()

	gw.execHandler.ServeHTTP(execW, execReq)

	if execW.Code != http.StatusNotFound { //: uniform not-found
		t.Fatalf("expected 403, got %d", execW.Code)
	}
}

func TestStickyLeaseReuse(t *testing.T) {
	gw := setupTestGateway(t)
	sandfsID := createTestSandFS(t, gw, "test-lease")

	// First execution (cold, acquires a CLEAN VM)
	r1 := doExecute(t, gw.execHandler, gw.agentAPIKey, sandfsID, "python", "print(1)")
	if lease1 := r1.Header().Get("X-Sandbox-Lease"); lease1 == "hit" {
		t.Errorf("first call should not have lease hit, got %q", lease1)
	}

	// Second execution immediately (should reuse via sticky lease)
	r2 := doExecute(t, gw.execHandler, gw.agentAPIKey, sandfsID, "shell", "cat /w/f")
	lease2 := r2.Header().Get("X-Sandbox-Lease")
	if lease2 != "hit" {
		t.Errorf("expected lease hit on second call, got %q", lease2)
	}

	// Third execution (should still reuse)
	r3 := doExecute(t, gw.execHandler, gw.agentAPIKey, sandfsID, "shell", "ls")
	lease3 := r3.Header().Get("X-Sandbox-Lease")
	if lease3 != "hit" {
		t.Errorf("expected lease hit on third call, got %q", lease3)
	}

	// Verify the sticky lease is still held (the sandfs is warm on a node).
	if node := gw.lm.Acquire(sandfsID); node == "" {
		t.Error("expected sticky lease to be held for the sandfs")
	}
}

func doExecute(t *testing.T, h *handler.ExecuteHandler, apiKey, sandfsID, lang, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(handler.ExecuteRequest{SandfsID: sandfsID, Code: code, Language: lang})
	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("execute failed: %d %s", w.Code, w.Body.String())
	}
	return w
}

func TestHealthStats(t *testing.T) {
	gw := setupTestGateway(t)

	// Health
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	gw.humanHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("health: expected 200, got %d", w.Code)
	}

	// Stats — returns the unified StatsReport (single-node local path: one
	// self gateway with CLEAN/total rolled up).
	req = httptest.NewRequest("GET", "/stats", nil)
	w = httptest.NewRecorder()
	gw.humanHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("stats: expected 200, got %d", w.Code)
	}
	var stats handler.StatsReport
	json.Unmarshal(w.Body.Bytes(), &stats)
	if stats.Totals.CleanVMs != 3 {
		t.Errorf("expected 3 clean_vms, got %v", stats.Totals.CleanVMs)
	}
	if stats.Totals.GatewayCnt != 1 {
		t.Errorf("expected 1 gateway, got %v", stats.Totals.GatewayCnt)
	}
}

func TestListDeleteSandFS(t *testing.T) {
	gw := setupTestGateway(t)

	// Create
	body := `{"agent_id":"` + gw.agentID + `","name":"to-delete","template":"test:v1","mode":"flat"}`
	req := httptest.NewRequest("POST", "/human/sandfs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gw.humanHandler.ServeHTTP(w, req)
	var resp handler.HumanCreateSandFSResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// List
	req = httptest.NewRequest("GET", "/human/sandfs", nil)
	w = httptest.NewRecorder()
	gw.humanHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("list: expected 200, got %d", w.Code)
	}

	// Delete
	req = httptest.NewRequest("DELETE", "/human/sandfs/"+resp.SandfsID, nil)
	w = httptest.NewRecorder()
	gw.humanHandler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("delete: expected 204, got %d", w.Code)
	}
}

func TestAgentListSandFS(t *testing.T) {
	gw := setupTestGateway(t)
	sandfsID := createTestSandFS(t, gw, "list-test")

	req := httptest.NewRequest("GET", "/agent/sandfs", nil)
	req.Header.Set("Authorization", "Bearer "+gw.agentAPIKey)
	w := httptest.NewRecorder()
	gw.agentHandler.ListSandFS(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		SandfsList []handler.SandFSSummary `json:"sandfs_list"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	found := false
	for _, sf := range resp.SandfsList {
		if sf.SandfsID == sandfsID {
			found = true
			if sf.Description != "test sandfs" {
				t.Errorf("expected description 'test sandfs', got %q", sf.Description)
			}
		}
	}
	if !found {
		t.Errorf("sandfs %s not found in list", sandfsID)
	}
}

// A cold-mount path that fails after the MountLock is acquired must release
// the token. Here the ownership record has vanished, so BeginDispatch refuses
// after the lock is held; without a deferred release the sandfs's MountLock
// stays drained and every future cold mount 503s until the gateway restarts.
func TestColdMountLockReleasedWhenBeginDispatchFails(t *testing.T) {
	gw := setupTestGateway(t)
	sf := createTestSandFS(t, gw, "lock-leak")

	ml := lease.NewMountLock()
	oc := lease.NewOwnershipCacheForTest("gw-test") // no entry → BeginDispatch fails
	execH := handler.NewExecuteHandler(gw.reg.Store(), gw.pm, gw.lm, pool.NewStubSandlotClient(), ml, oc, lease.NewSandfsState(), 30, 300, 0, slog.New(slog.DiscardHandler))

	if _, err := execH.ExecuteDirect(context.Background(), gw.agentAPIKey, handler.ExecuteRequest{
		SandfsID: sf,
		Code:     "true",
		Language: "shell",
	}); err == nil {
		t.Fatal("expected the cold mount to fail when the ownership record is absent")
	}

	done := make(chan error, 1)
	go func() {
		tok, err := ml.AcquireWaitDefault(sf)
		if err == nil {
			ml.Release(tok)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("mount lock still held after a failed cold-mount path: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mount lock leaked: acquire blocked after the failed cold mount")
	}
}
