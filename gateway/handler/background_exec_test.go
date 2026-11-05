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
	"sync"
	"testing"
	"time"

	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/pool"
	"gateway/registry"
	"gateway/storage/storagetest"

	"log/slog"
)

// recordingClient is a pool.SandlotClient that records the last ExecRequest and
// serves programmable StatusExec/KillExec replies.
type recordingClient struct {
	mu          sync.Mutex
	last        pool.ExecRequest
	statusReply string
	killCalls   int
}

func (c *recordingClient) DestroyMicroVM(ctx context.Context, nodeAddr, vmID string) error {
	return nil
}
func (c *recordingClient) UnmountRootfs(ctx context.Context, nodeAddr, vmID, volumePath, volumeEpoch string) (pool.UnmountResult, error) {
	return pool.UnmountResult{}, nil
}
func (c *recordingClient) MountRootfsAndExecute(ctx context.Context, req pool.ExecRequest) (pool.ExecResult, error) {
	c.mu.Lock()
	c.last = req
	c.mu.Unlock()
	if req.Background {
		return pool.ExecResult{ExecID: "bg-1", Status: "running"}, nil
	}
	return pool.ExecResult{Stdout: "ok", ExitCode: 0, Status: "done"}, nil
}
func (c *recordingClient) StatusExec(ctx context.Context, nodeAddr, vmID, execID string) (pool.ExecResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return pool.ExecResult{Status: c.statusReply, ExitCode: 0}, nil
}
func (c *recordingClient) KillExec(ctx context.Context, nodeAddr, vmID, execID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.killCalls++
	return nil
}
func (c *recordingClient) FileOp(ctx context.Context, nodeAddr string, req pool.FileOpRequest) (pool.FileOpResult, error) {
	return pool.FileOpResult{}, nil
}

func (c *recordingClient) CleanupOverlay(ctx context.Context, nodeAddr, volumePath string) error {
	return nil
}

func setupWithClient(t *testing.T, sc pool.SandlotClient, maxBgLeaseSec int) (*handler.ExecuteHandler, *handler.HumanHandler, *registry.Registry, *pool.Manager, *lease.Lease, string, string) {
	t.Helper()
	volRoot := t.TempDir()
	reg := registry.New(volRoot)

	// Storage plane: the test double (REAL volume dirs under the
	// temp root; no node-side provision code in the gateway module).
	reg.SetStorageOps(storagetest.New(reg.VolRoot()))
	pm := pool.NewManager(sc, slog.New(slog.DiscardHandler))
	lm := lease.New(100*time.Millisecond, 5*time.Second)
	pm.AddNode("localhost")
	pm.UpdateNodeCapacity("localhost", []pool.SpecCapacity{{SpecID: "medium", Clean: 1, Total: 1}})

	// Create a test agent
	agent, apiKey, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "bg-test-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}

	return handler.NewExecuteHandler(reg.Store(), pm, lm, sc, lease.NewMountLock(), nil, lease.NewSandfsState(), 30, 300, maxBgLeaseSec, slog.New(slog.DiscardHandler)),
		handler.NewHumanHandler(reg, pm, slog.New(slog.DiscardHandler)), reg, pm, lm,
		apiKey, agent.ID
}

// createSandfsHelper creates a sandfs via the human endpoint and returns its ID.
func createSandfsHelper(t *testing.T, human *handler.HumanHandler, agentID string) string {
	body := `{"agent_id":"` + agentID + `","name":"bg-sandfs","template":"test:v1","mode":"flat"}`
	req := httptest.NewRequest("POST", "/human/sandfs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	human.ServeHTTP(w, req)
	var resp handler.HumanCreateSandFSResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	return resp.SandfsID
}

// TestBackgroundExecPassthrough verifies a background=true /agent/execute returns
// exec_id + status=running and forwards background/lease to sandlot.
func TestBackgroundExecPassthrough(t *testing.T) {
	sc := &recordingClient{statusReply: "running"}
	execH, humanH, _, _, _, apiKey, agentID := setupWithClient(t, sc, 0)
	sandfsID := createSandfsHelper(t, humanH, agentID)

	body := `{"sandfs_id":"` + sandfsID + `","code":"nohup server &","background":true,"lease_duration":120}`
	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	execH.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp handler.ExecuteResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ExecID != "bg-1" {
		t.Errorf("expected exec_id bg-1, got %q", resp.ExecID)
	}
	if resp.Status != "running" {
		t.Errorf("expected status running, got %q", resp.Status)
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()
	if !sc.last.Background {
		t.Error("sandlot did not receive background=true")
	}
	if sc.last.LeaseDurationMs != 120000 {
		t.Errorf("expected lease 120000ms, got %d", sc.last.LeaseDurationMs)
	}
}

// TestBackgroundExecLeaseDurationCap verifies the hard cap: lease_duration above
// the configured -max-background-lease-sec is rejected (400) instead of silently
// clamping to an unbounded hold; the boundary value is accepted. The handler is
// built with an explicit small cap (300) to keep the boundary tight; production
// default is 1h (DefaultMaxBackgroundLeaseSec).
func TestBackgroundExecLeaseDurationCap(t *testing.T) {
	sc := &recordingClient{statusReply: "running"}
	execH, humanH, _, _, _, apiKey, agentID := setupWithClient(t, sc, 300)
	sandfsID := createSandfsHelper(t, humanH, agentID)

	// 301 > 300 → 400, request must NOT reach sandlot.
	body := `{"sandfs_id":"` + sandfsID + `","code":"nohup x &","background":true,"lease_duration":301}`
	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	execH.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for lease_duration=301, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "lease_duration") {
		t.Errorf("400 body should mention lease_duration, got %s", w.Body.String())
	}

	// Boundary: exactly 300 is accepted.
	body2 := `{"sandfs_id":"` + sandfsID + `","code":"nohup x &","background":true,"lease_duration":300}`
	req2 := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+apiKey)
	w2 := httptest.NewRecorder()
	execH.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 for lease_duration=300, got %d: %s", w2.Code, w2.Body.String())
	}
}

// TestSyncExecTimeoutPassthrough verifies the agent's timeout is forwarded
// (sync path), and that 0 → gateway default (30s).
func TestSyncExecTimeoutPassthrough(t *testing.T) {
	sc := &recordingClient{}
	execH, humanH, _, _, _, apiKey, agentID := setupWithClient(t, sc, 0)
	sandfsID := createSandfsHelper(t, humanH, agentID)

	// Explicit timeout 45s.
	body := `{"sandfs_id":"` + sandfsID + `","code":"sleep 30","timeout":45}`
	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	execH.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	sc.mu.Lock()
	if sc.last.TimeoutMs != 45000 {
		t.Errorf("expected timeout 45000ms forwarded, got %d", sc.last.TimeoutMs)
	}
	sc.mu.Unlock()

	// Omitted timeout → gateway default 30s.
	body2 := `{"sandfs_id":"` + sandfsID + `","code":"echo hi"}`
	req2 := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+apiKey)
	w2 := httptest.NewRecorder()
	execH.ServeHTTP(w2, req2)
	sc.mu.Lock()
	if sc.last.TimeoutMs != 30000 {
		t.Errorf("expected default 30000ms, got %d", sc.last.TimeoutMs)
	}
	sc.mu.Unlock()
}

// TestSyncExecTimeoutClamp verifies an over-limit timeout is clamped to max.
func TestSyncExecTimeoutClamp(t *testing.T) {
	sc := &recordingClient{}
	execH, humanH, _, _, _, apiKey, agentID := setupWithClient(t, sc, 0)
	sandfsID := createSandfsHelper(t, humanH, agentID)

	body := `{"sandfs_id":"` + sandfsID + `","code":"sleep 99999","timeout":99999}`
	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	execH.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	sc.mu.Lock()
	if sc.last.TimeoutMs != 300000 {
		t.Errorf("expected clamp to 300000ms, got %d", sc.last.TimeoutMs)
	}
	sc.mu.Unlock()
}

// TestExecStatusAndKill verifies /agent/exec/status and /agent/exec/kill route to the
// sandlot client and return the stubbed status.
func TestExecStatusAndKill(t *testing.T) {
	sc := &recordingClient{statusReply: "running"}
	execH, humanH, _, _, _, apiKey, agentID := setupWithClient(t, sc, 0)
	sandfsID := createSandfsHelper(t, humanH, agentID)

	// Start a background exec so the agent has a leased VM.
	bgBody := `{"sandfs_id":"` + sandfsID + `","code":"nohup server &","background":true,"lease_duration":300}`
	bgReq := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(bgBody))
	bgReq.Header.Set("Authorization", "Bearer "+apiKey)
	bgW := httptest.NewRecorder()
	execH.ServeHTTP(bgW, bgReq)
	var bgResp handler.ExecuteResponse
	json.Unmarshal(bgW.Body.Bytes(), &bgResp)
	if bgResp.ExecID == "" {
		t.Fatal("expected exec_id from background start")
	}

	// /agent/exec/status
	statusBody := `{"sandfs_id":"` + sandfsID + `","exec_id":"` + bgResp.ExecID + `"}`
	sReq := httptest.NewRequest("POST", "/agent/exec/status", strings.NewReader(statusBody))
	sReq.Header.Set("Authorization", "Bearer "+apiKey)
	sW := httptest.NewRecorder()
	execH.HandleExecStatus(sW, sReq)
	var sResp handler.ExecStatusResponse
	if err := json.Unmarshal(sW.Body.Bytes(), &sResp); err != nil {
		t.Fatalf("status unmarshal: %v (body %s)", err, sW.Body.String())
	}
	if sResp.Status != "running" {
		t.Errorf("expected running, got %q", sResp.Status)
	}

	// /agent/exec/kill
	kReq := httptest.NewRequest("POST", "/agent/exec/kill", strings.NewReader(statusBody))
	kReq.Header.Set("Authorization", "Bearer "+apiKey)
	kW := httptest.NewRecorder()
	execH.HandleExecKill(kW, kReq)
	var kResp handler.ExecStatusResponse
	if err := json.Unmarshal(kW.Body.Bytes(), &kResp); err != nil {
		t.Fatalf("kill unmarshal: %v", err)
	}
	if kResp.Status != "killed" {
		t.Errorf("expected killed, got %q", kResp.Status)
	}
}

// TestExecStatusExpired verifies that with no leased VM, /agent/exec/status reports
// "expired" (the background process was already cleared at lease expiry).
func TestExecStatusExpired(t *testing.T) {
	sc := &recordingClient{statusReply: "running"}
	execH, humanH, _, _, _, apiKey, agentID := setupWithClient(t, sc, 0)
	sandfsID := createSandfsHelper(t, humanH, agentID)

	// No /agent/execute issued → no leased VM for this sandfs.
	statusBody := `{"sandfs_id":"` + sandfsID + `","exec_id":"bg-never"}`
	sReq := httptest.NewRequest("POST", "/agent/exec/status", strings.NewReader(statusBody))
	sReq.Header.Set("Authorization", "Bearer "+apiKey)
	sW := httptest.NewRecorder()
	execH.HandleExecStatus(sW, sReq)
	var sResp handler.ExecStatusResponse
	json.Unmarshal(sW.Body.Bytes(), &sResp)
	if sResp.Status != "expired" {
		t.Errorf("expected expired (no leased VM), got %q", sResp.Status)
	}
}

// TestBgExecOmittedLeaseDefaultsToCap verifies that a background exec WITHOUT
// lease_duration defaults to the configured -max-background-lease-sec cap
// (hot-reloadable), not the lease layer's 24h far-future placeholder. An
// agent spawning bg execs and never polling would otherwise hold one VM each
// for a full day (pool exhaustion vector).
func TestBgExecOmittedLeaseDefaultsToCap(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, _, lm, _, _, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	// Shrink the cap to 1s so the deadline is observable in test time.
	execH.UpdateMaxBackgroundLeaseSec(1)

	// Background exec with NO lease_duration (the omission under test).
	body, _ := json.Marshal(handler.ExecuteRequest{
		SandfsID:   sandfsID,
		Code:       "sleep 100",
		Language:   "shell",
		Background: true,
	})
	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	execH.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bg exec start failed: %d %s", w.Code, w.Body.String())
	}
	var resp handler.ExecuteResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ExecID == "" || resp.Status != "running" {
		t.Fatalf("expected running bg exec, got %+v", resp)
	}

	// While the (1s) bg lease is live the VM must stay held.
	if n := lm.Acquire(sandfsID); n == "" {
		t.Fatal("bg exec lease not held right after start")
	}

	// After the cap elapses (polls do NOT extend it), the lease must release —
	// with the old 24h default this never happens inside test time.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if n := lm.Acquire(sandfsID); n == "" {
			return // released: the cap was applied
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("bg exec lease still held long after the 1s cap elapsed (24h default leaked through?)")
}
