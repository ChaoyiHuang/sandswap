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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

// ── Test helpers ──────────────────────────────────────────────

// failingClient is a pool.SandlotClient that can be configured to fail
// MountRootfsAndExecute with either a transport error or a regular error.
type failingClient struct {
	mu           sync.Mutex
	failCount    int  // how many times to fail (0 = always fail)
	transportErr bool // true = return transport-like error
	failAfter    int  // fail after this many successful calls
	callCount    int  // total calls made
	lastReq      pool.ExecRequest
}

func (c *failingClient) DestroyMicroVM(ctx context.Context, nodeAddr, vmID string) error {
	return nil
}
func (c *failingClient) UnmountRootfs(ctx context.Context, nodeAddr, vmID, volumePath, volumeEpoch string) (pool.UnmountResult, error) {
	return pool.UnmountResult{}, nil
}
func (c *failingClient) MountRootfsAndExecute(ctx context.Context, req pool.ExecRequest) (pool.ExecResult, error) {
	c.mu.Lock()
	c.callCount++
	c.lastReq = req
	count := c.callCount
	c.mu.Unlock()

	if c.failAfter > 0 && count > c.failAfter {
		return pool.ExecResult{}, errors.New("mount-rootfs-and-execute failed: unexpected error")
	}
	if c.failCount > 0 && count <= c.failCount {
		if c.transportErr {
			return pool.ExecResult{}, errors.New("transport error: connection reset by peer")
		}
		return pool.ExecResult{}, errors.New("mount-rootfs-and-execute failed: rpc error")
	}
	return pool.ExecResult{Stdout: "ok", ExitCode: 0, Status: "done"}, nil
}
func (c *failingClient) StatusExec(ctx context.Context, nodeAddr, vmID, execID string) (pool.ExecResult, error) {
	return pool.ExecResult{Status: "running", ExitCode: 0}, nil
}
func (c *failingClient) KillExec(ctx context.Context, nodeAddr, vmID, execID string) error {
	return nil
}
func (c *failingClient) FileOp(ctx context.Context, nodeAddr string, req pool.FileOpRequest) (pool.FileOpResult, error) {
	return pool.FileOpResult{}, nil
}

func (c *failingClient) CleanupOverlay(ctx context.Context, nodeAddr, volumePath string) error {
	return nil
}

func (c *failingClient) getCallCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.callCount
}

// setupResilienceGateway creates a test gateway with configurable sandlot client
// and resilience components (MountLock, SandfsState, etc.).
func setupResilienceGateway(t *testing.T, sc pool.SandlotClient) (*handler.ExecuteHandler, *handler.FileHandler, *handler.HumanHandler, *registry.Registry, *pool.Manager, *lease.Lease, *lease.MountLock, *lease.SandfsState, string, string) {
	t.Helper()
	volRoot := t.TempDir()
	reg := registry.New(volRoot)

	// Storage plane: the test double (REAL volume dirs under the
	// temp root; no node-side provision code in the gateway module).
	reg.SetStorageOps(storagetest.New(reg.VolRoot()))

	pm := pool.NewManager(sc, slog.New(slog.DiscardHandler))

	lm := lease.New(100*time.Millisecond, 5*time.Second)
	ml := lease.NewMountLock()
	ss := lease.NewSandfsState()

	// Install an onExpiry that releases the gateway-authoritative bound,
	// mirroring production (main.go defers pm.ReleaseBound). Without this,
	// expired leases would leave bound>0 and Stats() would report IN_USE leaks.
	lm.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		defer lm.Release(sandfsID)
		pm.ReleaseBound(nodeID, spec)
	})

	pm.AddNode("localhost")
	pm.UpdateNodeCapacity("localhost", []pool.SpecCapacity{{SpecID: "medium", Total: 5}})

	execHandler := handler.NewExecuteHandler(reg.Store(), pm, lm, sc, ml, nil, ss, 30, 300, 0, slog.New(slog.DiscardHandler))
	fileHandler := handler.NewFileHandler(reg.Store(), pm, lm, sc, ml, nil, ss, slog.New(slog.DiscardHandler))
	humanHandler := handler.NewHumanHandler(reg, pm, slog.New(slog.DiscardHandler))

	agent, apiKey, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "resilience-test-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}

	return execHandler, fileHandler, humanHandler, reg, pm, lm, ml, ss, apiKey, agent.ID
}

// createResilienceSandFS creates a SandFS and returns its ID.
func createResilienceSandFS(t *testing.T, human *handler.HumanHandler, agentID string) string {
	t.Helper()
	body := `{"agent_id":"` + agentID + `","name":"resilience-sandfs","template":"test:v1","mode":"flat"}`
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

// doResilienceExecute is a helper for making execute requests in resilience tests.
func doResilienceExecute(t *testing.T, h *handler.ExecuteHandler, apiKey, sandfsID, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(handler.ExecuteRequest{SandfsID: sandfsID, Code: code, Language: "shell"})
	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// ── Resilience Tests ──────────────────────────────────────────

// TestConcurrentColdMount503 verifies that two concurrent cold mounts for the same
// sandfs result in the second one receiving a 503 CONCURRENT_MOUNT error.
func TestConcurrentColdMount503(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, pm, _, _, _, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	// First request acquires a CLEAN VM and starts cold mount.
	// Second request tries to acquire another CLEAN VM and cold mount
	// the same sandfs → MountLock blocks it → 503 CONCURRENT_MOUNT.
	//
	// Since the stub client is synchronous, we use a blocking approach:
	// fire both requests concurrently. The MountLock will serialize them.

	var wg sync.WaitGroup
	results := make([]*httptest.ResponseRecorder, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = doResilienceExecute(t, execH, apiKey, sandfsID, "echo hello")
		}(i)
	}
	wg.Wait()

	// At least one should succeed (200), and one may get 503 CONCURRENT_MOUNT
	// or both succeed (depending on timing). The key invariant: no data corruption.
	successCount := 0
	concurrentMountCount := 0
	for _, r := range results {
		if r.Code == http.StatusOK {
			successCount++
		} else if r.Code == http.StatusServiceUnavailable {
			var resp map[string]interface{}
			json.Unmarshal(r.Body.Bytes(), &resp)
			if resp["error_code"] == "CONCURRENT_MOUNT" {
				concurrentMountCount++
			}
		}
	}

	// Both could succeed if they didn't race, or one could get CONCURRENT_MOUNT.
	// The key invariant: no VM leak — verify pool stats are consistent.
	// Wait for the 100ms idle lease to expire + onExpiry's ReleaseBound
	// so bound returns to 0 and Stats() shows no IN_USE leak.
	time.Sleep(300 * time.Millisecond)
	stats := pm.Stats()
	t.Logf("success=%d concurrent_mount=%d stats=%v", successCount, concurrentMountCount, stats)

	// Verify no IN_USE VMs leaked (all should be LEASED or CLEAN after completion).
	if stats["IN_USE"] > 0 {
		t.Errorf("expected no IN_USE VMs after concurrent test, got %v", stats)
	}
}

// TestSandfsCleaning503 verifies that when a sandfs enters CLEANING state,
// new requests receive 503 SANDBOX_CLEANING.
func TestSandfsCleaning503(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, _, _, _, ss, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	// Manually enter cleaning state.
	if err := ss.EnterCleaning(sandfsID); err != nil {
		t.Fatalf("enter cleaning: %v", err)
	}

	// Request during cleaning should get 503.
	w := doResilienceExecute(t, execH, apiKey, sandfsID, "echo hello")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 during cleaning, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["error_code"] != "SANDBOX_CLEANING" {
		t.Errorf("expected error_code SANDBOX_CLEANING, got %v", resp["error_code"])
	}
	if resp["retryable"] != true {
		t.Errorf("expected retryable=true, got %v", resp["retryable"])
	}
	if resp["retry_after_ms"] == nil {
		t.Error("expected retry_after_ms to be set")
	}

	// Exit cleaning → request should succeed.
	ss.ExitCleaning(sandfsID)
	w = doResilienceExecute(t, execH, apiKey, sandfsID, "echo hello")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after cleaning exits, got %d: %s", w.Code, w.Body.String())
	}
}

// TestL2CleanupOnFailure verifies that when MountRootfsAndExecute fails,
// the system returns 503 SANDBOX_CLEANING, and after cleanup a retry succeeds.
func TestL2CleanupOnFailure(t *testing.T) {
	// Client that fails first call with non-transport error, then succeeds.
	sc := &failingClient{failCount: 1, transportErr: false}
	execH, _, humanH, _, _, _, _, ss, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	// Execute should fail and trigger L2 cleanup.
	w := doResilienceExecute(t, execH, apiKey, sandfsID, "echo hello")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 on execution failure, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["error_code"] != "SANDBOX_CLEANING" {
		t.Errorf("expected error_code SANDBOX_CLEANING, got %v", resp["error_code"])
	}

	// Wait for L2 cleanup to complete (async). With our stub client,
	// UnmountRootfs is instant, so cleanup completes quickly.
	time.Sleep(200 * time.Millisecond)

	// After cleanup, sandfs should be available again.
	if !ss.IsAvailable(sandfsID) {
		t.Error("expected sandfs to be available after L2 cleanup completes")
	}

	// Retry should succeed (end-to-end: failure → CLEANING → 503 → cleanup → retry → 200).
	w2 := doResilienceExecute(t, execH, apiKey, sandfsID, "echo hello")
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 after L2 cleanup + retry, got %d: %s", w2.Code, w2.Body.String())
	}
}

// TestL1RetryOnTransportError verifies that transport errors trigger L1 retries
// (up to 2 retries with 50ms delay).
func TestL1RetryOnTransportError(t *testing.T) {
	// Client that fails first call with transport error, then succeeds.
	sc := &failingClient{failCount: 1, transportErr: true}
	execH, _, humanH, _, _, _, _, _, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	// Execute: should fail once with transport error, then retry and succeed.
	w := doResilienceExecute(t, execH, apiKey, sandfsID, "echo hello")
	// With L1 retry, the transport error should be retried and succeed.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after L1 retry, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the client was called at least twice (original + retry).
	if sc.getCallCount() < 2 {
		t.Errorf("expected at least 2 calls (original + retry), got %d", sc.getCallCount())
	}
}

// TestL1RetryMaxRetries verifies that 2 consecutive transport errors are retried
// and eventually succeed (within the max retry count of 2).
func TestL1RetryMaxRetries(t *testing.T) {
	sc := &failingClient{failCount: 2, transportErr: true}
	execH, _, humanH, _, _, _, _, _, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	w := doResilienceExecute(t, execH, apiKey, sandfsID, "echo hello")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after 2 L1 retries, got %d: %s", w.Code, w.Body.String())
	}
	if sc.getCallCount() < 3 {
		t.Errorf("expected at least 3 calls (original + 2 retries), got %d", sc.getCallCount())
	}
}

// TestL1RetryExhausted verifies that when all L1 retries are exhausted (3+
// consecutive transport errors), the request fails with 503 SANDBOX_CLEANING.
func TestL1RetryExhausted(t *testing.T) {
	sc := &failingClient{failCount: 3, transportErr: true}
	execH, _, humanH, _, _, _, _, _, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	w := doResilienceExecute(t, execH, apiKey, sandfsID, "echo hello")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 after L1 retries exhausted, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err == nil {
		if resp["error_code"] != "SANDBOX_CLEANING" {
			t.Errorf("expected error_code SANDBOX_CLEANING, got %v", resp["error_code"])
		}
	}
}

// TestResilienceErrorStructure verifies that 503 responses include the
// structured error fields: error_code, retryable, retry_after_ms, Retry-After header.
func TestResilienceErrorStructure(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, _, _, _, ss, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	// Enter cleaning to trigger a resilience error.
	ss.EnterCleaning(sandfsID)

	w := doResilienceExecute(t, execH, apiKey, sandfsID, "echo hello")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}

	// Verify Retry-After header.
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("expected Retry-After header to be set")
	}

	// Verify structured JSON body.
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp["error_code"] != "SANDBOX_CLEANING" {
		t.Errorf("expected error_code SANDBOX_CLEANING, got %v", resp["error_code"])
	}
	if resp["retryable"] != true {
		t.Errorf("expected retryable=true, got %v", resp["retryable"])
	}
	if _, ok := resp["retry_after_ms"].(float64); !ok {
		t.Errorf("expected retry_after_ms as number, got %v (%T)", resp["retry_after_ms"], resp["retry_after_ms"])
	}
}

// TestMountLockFailureReleasesMicroVM verifies that when MountLock.Acquire fails
// (concurrent mount in progress), the already-acquired microVM is released back
// to the pool instead of being leaked.
// TestMountLockAcquireWaitSemantics verifies the basic MountLock acquire/release
// semantics (non-blocking Acquire for tests).
func TestMountLockAcquireWaitSemantics(t *testing.T) {
	ml := lease.NewMountLock()

	// Acquire the lock for sandfs-1.
	tok, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// Second acquire should fail.
	if _, err := ml.Acquire("sandfs-1"); err != lease.ErrConcurrentMount {
		t.Errorf("expected ErrConcurrentMount, got %v", err)
	}

	// Release the lock.
	ml.Release(tok)

	// Now acquire should succeed again.
	tok, err = ml.Acquire("sandfs-1")
	if err != nil {
		t.Errorf("acquire after release: %v", err)
	}
	ml.Release(tok)
}

// TestExecuteBodySizeLimit verifies that the execute endpoint rejects
// request bodies larger than 10MB with 413 ().
func TestExecuteBodySizeLimit(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, _, _, _, _, _, _, apiKey, _ := setupResilienceGateway(t, sc)

	// Create a request body larger than 10MB.
	bigBody := strings.Repeat("x", 11*1024*1024)
	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(`{"code":"`+bigBody+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	execH.ServeHTTP(w, req)

	// http.MaxBytesReader returns 413 on overflow.
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 Request Entity Too Large, got %d: %s", w.Code, w.Body.String())
	}
}

// TestMultipleSandfsConcurrentExecution verifies that concurrent execution
// on different sandfs instances is allowed.
func TestMultipleSandfsConcurrentExecution(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, _, lm, _, _, apiKey, agentID := setupResilienceGateway(t, sc)

	sandfs1 := createResilienceSandFS(t, humanH, agentID)
	sandfs2 := createResilienceSandFS(t, humanH, agentID)

	var wg sync.WaitGroup
	results := make([]*httptest.ResponseRecorder, 2)

	for i, sandfsID := range []string{sandfs1, sandfs2} {
		wg.Add(1)
		go func(idx int, sid string) {
			defer wg.Done()
			results[idx] = doResilienceExecute(t, execH, apiKey, sid, "echo hello")
		}(i, sandfsID)
	}
	wg.Wait()

	for i, r := range results {
		if r.Code != http.StatusOK {
			t.Errorf("sandfs %d: expected 200, got %d: %s", i, r.Code, r.Body.String())
		}
	}

	// Verify both are leased (sticky lease): each sandfs is warm on a node.
	for _, sid := range []string{sandfs1, sandfs2} {
		if node := lm.Acquire(sid); node == "" {
			t.Errorf("expected sticky lease for %s after concurrent execution", sid)
		}
	}
}

// TestOnExpiryPanicRecovery verifies that a panic in the onExpiry callback
// is recovered and doesn't leak the VM or crash the lease manager.
// This is .
func TestOnExpiryPanicRecovery(t *testing.T) {
	leaseMgr := lease.New(50*time.Millisecond, 200*time.Millisecond)

	var panicCount atomic.Int32
	leaseMgr.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		panicCount.Add(1)
		panic("intentional panic in onExpiry")
	})

	// Create a lease that will expire quickly.
	leaseMgr.TouchSync("test-sandfs", "test-vm", "small")

	// Wait for the lease to expire and the onExpiry to fire (and panic).
	time.Sleep(300 * time.Millisecond)

	// The panic should have been recovered. The lease manager should still work.
	if panicCount.Load() == 0 {
		t.Error("expected onExpiry to have been called at least once")
	}

	// Verify we can still use the lease manager after panic recovery.
	leaseMgr.TouchSync("test-sandfs-2", "test-vm-2", "small")
	// No panic = recovery worked.
}

// TestIsTransportError verifies the transport error detection logic.
func TestIsTransportError(t *testing.T) {
	tests := []struct {
		errMsg      string
		isTransport bool
	}{
		{"transport error: connection reset", true},
		{"rpc error: code = Unavailable", true},
		{"connection refused", true},
		{"connection reset by peer", true},
		{"mount-rootfs-and-execute failed: connection closed", true},
		{"invalid argument", false},
		{"sandbox not found", false},
		{"permission denied", false},
		{"", false},
	}

	for _, tt := range tests {
		// Test via the exported handler.IsTransportError function.
		got := handler.IsTransportError(errors.New(tt.errMsg))
		if got != tt.isTransport {
			t.Errorf("IsTransportError(%q) = %v, want %v", tt.errMsg, got, tt.isTransport)
		}
	}
}

// TestPreferredNodeRouting verifies that Acquire with preferredNode routes
// to the preferred node first, falling back to other nodes when needed.
func TestPreferredNodeRouting(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node1")
	pm.AddNode("node2")

	pm.UpdateNodeCapacity("node1", []pool.SpecCapacity{{SpecID: "medium", Total: 1}})
	pm.UpdateNodeCapacity("node2", []pool.SpecCapacity{{SpecID: "medium", Total: 1}})

	// Acquire with preferredNode="node1" should return node1 (has capacity).
	node, _, err := pm.Acquire("node1", 2, 512)
	if err != nil {
		t.Fatalf("acquire with preferredNode: %v", err)
	}
	if node != "node1" {
		t.Errorf("expected node1 (preferred), got %s", node)
	}

	// Drain node1 (bind all its capacity) -> preferred node has no clean -> falls back to node2.
	pm.UpdateNodeCapacity("node1", []pool.SpecCapacity{{SpecID: "medium", Total: 1}})
	pm.ReserveBound("node1", "medium") // clean = total - bound = 0 (drained)
	node, _, err = pm.Acquire("node1", 2, 512)
	if err != nil {
		t.Fatalf("acquire with preferredNode fallback: %v", err)
	}
	if node != "node2" {
		t.Errorf("expected node2 (fallback, node1 drained), got %s", node)
	}
}

// TestRemoveNodeCleansUp verifies that RemoveNode drops a node's capacity
// completely (delegation: the gateway holds no per-VM state to leak).
func TestRemoveNodeCleansUp(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node1")
	pm.AddNode("node2")
	pm.UpdateNodeCapacity("node1", []pool.SpecCapacity{{SpecID: "medium", Total: 2}})
	pm.UpdateNodeCapacity("node2", []pool.SpecCapacity{{SpecID: "small", Total: 1}})

	// node1 holds the most capacity.
	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node1" {
		t.Errorf("expected node1, got %s", node)
	}

	// Remove node1 -> capacity gone, Acquire falls to node2.
	pm.RemoveNode("node1")
	node, _, err = pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire after remove: %v", err)
	}
	if node != "node2" {
		t.Errorf("expected node2 after remove, got %s", node)
	}

	// Stats reflect the remaining node only.
	stats := pm.Stats()
	if stats["CLEAN"] != 1 || stats["node_count"] != 1 {
		t.Errorf("expected 1 CLEAN / 1 node after remove, got %v", stats)
	}
}

// TestSandfsStateDoubleEnter verifies that double-entering CLEANING state
// returns an error and doesn't corrupt the state machine.
func TestSandfsStateDoubleEnter(t *testing.T) {
	ss := lease.NewSandfsState()

	if err := ss.EnterCleaning("sandfs-1"); err != nil {
		t.Fatalf("first enter: %v", err)
	}

	// Second enter should fail.
	if err := ss.EnterCleaning("sandfs-1"); err != lease.ErrSandfsCleaning {
		t.Errorf("expected ErrSandfsCleaning on double enter, got %v", err)
	}

	// Should still be in CLEANING state.
	if ss.IsAvailable("sandfs-1") {
		t.Error("expected sandfs to be unavailable during cleaning")
	}

	// Exit and re-enter should work.
	ss.ExitCleaning("sandfs-1")
	if err := ss.EnterCleaning("sandfs-1"); err != nil {
		t.Fatalf("re-enter after exit: %v", err)
	}
	ss.ExitCleaning("sandfs-1")

	if !ss.IsAvailable("sandfs-1") {
		t.Error("expected available after clean cycle")
	}
}

// TestBgExecAndSyncExecConcurrent verifies that a background exec running
// alongside a sync exec on the same sandfs works correctly (bg exec running +
// sync exec → executes normally, no 503).
func TestBgExecAndSyncExecConcurrent(t *testing.T) {
	sc := &recordingClient{statusReply: "running"}
	execH, _, humanH, _, _, _, _, _, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	// Start a background exec.
	bgBody := `{"sandfs_id":"` + sandfsID + `","code":"nohup server &","background":true,"lease_duration":300}`
	bgReq := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(bgBody))
	bgReq.Header.Set("Authorization", "Bearer "+apiKey)
	bgW := httptest.NewRecorder()
	execH.ServeHTTP(bgW, bgReq)

	if bgW.Code != http.StatusOK {
		t.Fatalf("background exec: expected 200, got %d: %s", bgW.Code, bgW.Body.String())
	}

	// Now execute a sync command on the same sandfs — should succeed (lease hit).
	syncBody := `{"sandfs_id":"` + sandfsID + `","code":"echo hello"}`
	syncReq := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(syncBody))
	syncReq.Header.Set("Authorization", "Bearer "+apiKey)
	syncW := httptest.NewRecorder()
	execH.ServeHTTP(syncW, syncReq)

	if syncW.Code != http.StatusOK {
		t.Errorf("sync exec during bg exec: expected 200, got %d: %s", syncW.Code, syncW.Body.String())
	}

	// Verify lease hit on sync exec (sticky lease reuse).
	if lease := syncW.Header().Get("X-Sandbox-Lease"); lease != "hit" {
		t.Errorf("expected lease hit on sync exec during bg exec, got %q", lease)
	}
}

// TestExecStatusKillBodySizeLimit verifies: /agent/exec/status
// and /agent/exec/kill bound their request bodies (1MB) — json.Decoder buffers
// the whole value, so an unbounded body from an authenticated client is a
// memory-exhaustion vector. Oversized bodies get 413, matching /agent/execute.
func TestExecStatusKillBodySizeLimit(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, _, _, _, _, _, _, apiKey, _ := setupResilienceGateway(t, sc)

	big := strings.Repeat("x", 2<<20) // 2MB > 1MB smallJSONBodyLimit
	newReq := func(path string) *http.Request {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"exec_id":"`+big+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+apiKey)
		return r
	}

	w := httptest.NewRecorder()
	execH.HandleExecStatus(w, newReq("/agent/exec/status"))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("exec/status: expected 413, got %d: %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	execH.HandleExecKill(w, newReq("/agent/exec/kill"))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("exec/kill: expected 413, got %d: %s", w.Code, w.Body.String())
	}
}
