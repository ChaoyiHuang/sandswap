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
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
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
	"gateway/stats"
	"gateway/storage/storagetest"
)

// fileOpClient is a pool.SandlotClient that records FileOp requests and serves
// programmable results. Other RPC methods (MountRootfsAndExecute etc.) delegate
// to a stub so the pool/lease machinery works.
type fileOpClient struct {
	mu         sync.Mutex
	lastReq    pool.FileOpRequest
	calls      int
	result     pool.FileOpResult // returned on success
	err        error             // returned if non-nil
	failCount  int               // fail the first N calls with err
	unmountErr error
}

func (c *fileOpClient) DestroyMicroVM(ctx context.Context, nodeAddr, vmID string) error { return nil }
func (c *fileOpClient) UnmountRootfs(ctx context.Context, nodeAddr, vmID, volumePath, volumeEpoch string) (pool.UnmountResult, error) {
	return pool.UnmountResult{}, c.unmountErr
}
func (c *fileOpClient) MountRootfsAndExecute(ctx context.Context, req pool.ExecRequest) (pool.ExecResult, error) {
	time.Sleep(2 * time.Millisecond)
	return pool.ExecResult{Stdout: "ok", ExitCode: 0, Status: "done"}, nil
}
func (c *fileOpClient) StatusExec(ctx context.Context, nodeAddr, vmID, execID string) (pool.ExecResult, error) {
	return pool.ExecResult{Status: "done", ExitCode: 0}, nil
}
func (c *fileOpClient) KillExec(ctx context.Context, nodeAddr, vmID, execID string) error { return nil }
func (c *fileOpClient) FileOp(ctx context.Context, nodeAddr string, req pool.FileOpRequest) (pool.FileOpResult, error) {
	c.mu.Lock()
	c.lastReq = req
	c.calls++
	n := c.calls
	c.mu.Unlock()

	if c.failCount > 0 && n <= c.failCount {
		return pool.FileOpResult{}, c.err
	}
	if c.err != nil && c.failCount == 0 {
		return pool.FileOpResult{}, c.err
	}
	return c.result, nil
}
func (c *fileOpClient) CleanupOverlay(ctx context.Context, nodeAddr, volumePath string) error {
	return nil
}

func (c *fileOpClient) lastFileReq() pool.FileOpRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastReq
}
func (c *fileOpClient) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// setupFileGateway builds a minimal gateway stack for file-handler tests.
// Returns the FileHandler, the fake client, the API key, and the agent ID.
func setupFileGateway(t *testing.T) (*handler.FileHandler, *fileOpClient, *registry.Registry, string, string) {
	t.Helper()
	fh, sc, _, reg, apiKey, agentID := setupFileGatewayWithPM(t)
	return fh, sc, reg, apiKey, agentID
}

// setupFileGatewayWithPM is setupFileGateway plus the pool.Manager (for the
// bound/clean count assertions).
func setupFileGatewayWithPM(t *testing.T) (*handler.FileHandler, *fileOpClient, *pool.Manager, *registry.Registry, string, string) {
	t.Helper()
	volRoot := t.TempDir()
	reg := registry.New(volRoot)

	// Storage plane: the test double (REAL volume dirs under the
	// temp root; no node-side provision code in the gateway module).
	reg.SetStorageOps(storagetest.New(reg.VolRoot()))

	sc := &fileOpClient{}
	pm := pool.NewManager(sc, slog.New(slog.DiscardHandler))
	lm := lease.New(100*time.Millisecond, 5*time.Second)
	ml := lease.NewMountLock()
	ss := lease.NewSandfsState()

	// Install an onExpiry that releases the gateway-authoritative bound,
	// mirroring production (main.go defers pm.ReleaseBound). Without this,
	// lease-expiry unmounts would leave bound>0 and the derived clean count would
	// never recover.
	lm.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		defer lm.Release(sandfsID)
		pm.ReleaseBound(nodeID, spec)
	})

	pm.AddNode("localhost")
	pm.UpdateNodeCapacity("localhost", []pool.SpecCapacity{{SpecID: "medium", Clean: 3, Total: 3}})

	fh := handler.NewFileHandler(reg.Store(), pm, lm, sc, ml, nil, ss, slog.New(slog.DiscardHandler))

	agent, apiKey, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "file-test-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	return fh, sc, pm, reg, apiKey, agent.ID
}

// createFileTestSandFS creates a flat sandfs under the test agent.
func createFileTestSandFS(t *testing.T, reg *registry.Registry, agentID string) string {
	t.Helper()
	rec, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name:        "file-sandfs",
		Description: "file test",
		Template:    "test:v1",
		Mode:        "flat",
	})
	if err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	return rec.ID
}

// doFileRequest builds and sends a POST /agent/file request, returning the recorder.
func doFileRequest(t *testing.T, fh *handler.FileHandler, apiKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/agent/file", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	fh.ServeHTTP(w, req)
	return w
}

// ── Action dispatch and request parsing ───────────────────────

func TestFileOp_MethodNotAllowed(t *testing.T) {
	fh, _, _, apiKey, _ := setupFileGateway(t)
	req := httptest.NewRequest("GET", "/agent/file", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	fh.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestFileOp_NotFound(t *testing.T) {
	fh, _, _, apiKey, _ := setupFileGateway(t)
	req := httptest.NewRequest("POST", "/agent/file/x", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	fh.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestFileOp_MissingSandfsID(t *testing.T) {
	fh, _, _, apiKey, _ := setupFileGateway(t)
	w := doFileRequest(t, fh, apiKey, `{"action":"read","path":"f"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing sandfs_id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFileOp_MissingAction(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","path":"f"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing action, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFileOp_MissingPath(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// read without path -> 400 (rename is the only action allowed to omit path).
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing path, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFileOp_UnknownAction(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"frobnicate","path":"f"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown action, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFileOp_InvalidJSON(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	w := doFileRequest(t, fh, apiKey, `{invalid json `+sandfsID+`}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid json, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFileOp_BodySizeLimit(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// 51MB body > 50MB limit.
	big := strings.Repeat("x", 51*1024*1024)
	body := `{"sandfs_id":"` + sandfsID + `","action":"write","path":"f","data":"` + big + `"}`
	w := doFileRequest(t, fh, apiKey, body)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d: %s", w.Code, w.Body.String())
	}
}

// ── Auth checks ───────────────────────────────────────────────

func TestFileOp_MissingAuth(t *testing.T) {
	fh, _, reg, _, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	req := httptest.NewRequest("POST", "/agent/file", strings.NewReader(`{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`))
	w := httptest.NewRecorder()
	fh.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing api key, got %d", w.Code)
	}
}

func TestFileOp_InvalidAuth(t *testing.T) {
	fh, _, reg, _, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	w := doFileRequest(t, fh, "sk-sandswap-agent-wrong", `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid api key, got %d", w.Code)
	}
}

func TestFileOp_CrossAgentForbidden(t *testing.T) {
	fh, _, reg, _, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)

	// Create a second agent.
	_, otherKey, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "other"})
	if err != nil {
		t.Fatalf("create other agent: %v", err)
	}
	w := doFileRequest(t, fh, otherKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusNotFound { //: uniform not-found
		t.Errorf("expected 403 for cross-agent access, got %d: %s", w.Code, w.Body.String())
	}
}

// ── read action ───────────────────────────────────────────────

func TestFileOp_ReadText(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Data: []byte("hello world"), Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"foo.txt"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp handler.FileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data != "hello world" {
		t.Errorf("Data = %q, want 'hello world'", resp.Data)
	}
	if resp.DataBase64 != "" {
		t.Errorf("DataBase64 should be empty for text, got %q", resp.DataBase64)
	}
	if resp.IsText == nil || !*resp.IsText {
		t.Errorf("IsText = %v, want true", resp.IsText)
	}
	if resp.Size != 11 {
		t.Errorf("Size = %d, want 11", resp.Size)
	}

	// Verify the RPC request mapping.
	lr := sc.lastFileReq()
	if lr.Action != "read" {
		t.Errorf("RPC Action = %q, want 'read'", lr.Action)
	}
	if lr.Path != "foo.txt" {
		t.Errorf("RPC Path = %q, want 'foo.txt'", lr.Path)
	}
	if lr.SandfsID != sandfsID {
		t.Errorf("RPC SandfsID = %q, want %q", lr.SandfsID, sandfsID)
	}
}

func TestFileOp_ReadBinary(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// Non-UTF-8 binary data (0xFF 0xFE 0x00 invalid UTF-8 sequence).
	binData := []byte{0xFF, 0xFE, 0x00, 0x01, 0x02}
	sc.result = pool.FileOpResult{Data: binData, Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"blob.bin"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp handler.FileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data != "" {
		t.Errorf("Data should be empty for binary, got %q", resp.Data)
	}
	expectedB64 := base64.StdEncoding.EncodeToString(binData)
	if resp.DataBase64 != expectedB64 {
		t.Errorf("DataBase64 = %q, want %q", resp.DataBase64, expectedB64)
	}
	if resp.IsText == nil || *resp.IsText {
		t.Errorf("IsText = %v, want false", resp.IsText)
	}
	if resp.Size != int64(len(binData)) {
		t.Errorf("Size = %d, want %d", resp.Size, len(binData))
	}
}

func TestFileOp_ReadWithOffsetLength(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Data: []byte("page"), Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f","offset":100,"length":4}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	lr := sc.lastFileReq()
	if lr.Offset != 100 {
		t.Errorf("RPC Offset = %d, want 100", lr.Offset)
	}
	if lr.Length != 4 {
		t.Errorf("RPC Length = %d, want 4", lr.Length)
	}
}

func TestFileOp_ReadAppError(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// Status != 0 -> application-level error (e.g., file not found in warden).
	sc.result = pool.FileOpResult{Success: false, Error: "file not found"}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"missing"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for app error, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "file not found" {
		t.Errorf("error = %q, want 'file not found'", resp["error"])
	}
}

func TestFileOp_ReadAppErrorEmpty(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// Empty Error → writeFileAppError substitutes the default message.
	sc.result = pool.FileOpResult{Success: false, Error: ""}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"missing"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "file operation failed" {
		t.Errorf("error = %q, want 'file operation failed'", resp["error"])
	}
}

// ── write action ──────────────────────────────────────────────

func TestFileOp_WriteText(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"out.txt","data":"content here"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp handler.FileResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Ok {
		t.Error("expected Ok=true")
	}
	if resp.Size != 12 {
		t.Errorf("Size = %d, want 12", resp.Size)
	}
	lr := sc.lastFileReq()
	if lr.Action != "write" {
		t.Errorf("RPC Action = %q, want 'write'", lr.Action)
	}
	if string(lr.Data) != "content here" {
		t.Errorf("RPC Data = %q, want 'content here'", string(lr.Data))
	}
	if lr.Offset != 0 {
		t.Errorf("RPC Offset = %d, want 0 (default)", lr.Offset)
	}
}

func TestFileOp_WriteBase64(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}
	binData := []byte{0x00, 0x01, 0xFF}
	b64 := base64.StdEncoding.EncodeToString(binData)

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"b.bin","data_base64":"`+b64+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	lr := sc.lastFileReq()
	if string(lr.Data) != string(binData) {
		t.Errorf("RPC Data = %v, want %v", lr.Data, binData)
	}
}

func TestFileOp_WriteBothDataAndBase64(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"f","data":"x","data_base64":"eA=="}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for both data and data_base64, got %d", w.Code)
	}
}

func TestFileOp_WriteInvalidBase64(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"f","data_base64":"!!!not-base64!!!"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid base64, got %d", w.Code)
	}
}

func TestFileOp_WriteAppendMode(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"log","data":"line","append":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	lr := sc.lastFileReq()
	if lr.Offset != -1 {
		t.Errorf("RPC Offset = %d, want -1 (append mode)", lr.Offset)
	}
}

func TestFileOp_WriteWithOffset(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"f","data":"x","offset":42}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	lr := sc.lastFileReq()
	if lr.Offset != 42 {
		t.Errorf("RPC Offset = %d, want 42", lr.Offset)
	}
}

func TestFileOp_WriteWithMode(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"f","data":"x","mode":493}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	lr := sc.lastFileReq()
	// 493 = 0o755
	if lr.Mode != 493 {
		t.Errorf("RPC Mode = %d, want 493", lr.Mode)
	}
}

func TestFileOp_WriteEmpty(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}

	// No data field -> empty write (creates/truncates file).
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"empty"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	lr := sc.lastFileReq()
	if len(lr.Data) != 0 {
		t.Errorf("RPC Data len = %d, want 0", len(lr.Data))
	}
}

// ── stat action ───────────────────────────────────────────────

func TestFileOp_Stat(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// warden returns stat as JSON; handler passes it through raw.
	statJSON := []byte(`{"size":4096,"mode":420,"is_dir":true}`)
	sc.result = pool.FileOpResult{Data: statJSON, Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"stat","path":"somedir"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// The response should be the raw JSON from the warden (passthrough).
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body %s)", err, w.Body.String())
	}
	if resp["is_dir"] != true {
		t.Errorf("is_dir = %v, want true", resp["is_dir"])
	}
	if resp["size"] != float64(4096) {
		t.Errorf("size = %v, want 4096", resp["size"])
	}
}

func TestFileOp_StatAppError(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: false, Error: "no such file"}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"stat","path":"missing"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ── list_dir action ───────────────────────────────────────────

func TestFileOp_ListDir(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// warden returns a JSON array; handler wraps it in {"entries": [...]}.
	dirJSON := []byte(`[{"name":"a","is_dir":false},{"name":"b","is_dir":true}]`)
	sc.result = pool.FileOpResult{Data: dirJSON, Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"list_dir","path":"somedir","depth":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Entries []struct {
			Name  string `json:"name"`
			IsDir bool   `json:"is_dir"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body %s)", err, w.Body.String())
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(resp.Entries))
	}
	if resp.Entries[0].Name != "a" {
		t.Errorf("entry[0].Name = %q, want 'a'", resp.Entries[0].Name)
	}
	if !resp.Entries[1].IsDir {
		t.Errorf("entry[1].IsDir = false, want true")
	}
	// Verify depth was forwarded.
	lr := sc.lastFileReq()
	if lr.Depth != 2 {
		t.Errorf("RPC Depth = %d, want 2", lr.Depth)
	}
}

// ── mkdir action ──────────────────────────────────────────────

func TestFileOp_Mkdir(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"mkdir","path":"newdir","mode":493}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp handler.FileResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Ok {
		t.Error("expected Ok=true")
	}
	lr := sc.lastFileReq()
	if lr.Action != "mkdir" {
		t.Errorf("RPC Action = %q, want 'mkdir'", lr.Action)
	}
	if lr.Mode != 493 {
		t.Errorf("RPC Mode = %d, want 493", lr.Mode)
	}
}

// ── remove action ─────────────────────────────────────────────

func TestFileOp_Remove(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"remove","path":"old","recursive":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp handler.FileResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Ok {
		t.Error("expected Ok=true")
	}
	lr := sc.lastFileReq()
	if lr.Action != "remove" {
		t.Errorf("RPC Action = %q, want 'remove'", lr.Action)
	}
	if !lr.Recursive {
		t.Error("RPC Recursive = false, want true")
	}
}

// ── rename action ─────────────────────────────────────────────

func TestFileOp_Rename(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"rename","path":"old","new_path":"new"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp handler.FileResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Ok {
		t.Error("expected Ok=true")
	}
	lr := sc.lastFileReq()
	if lr.Action != "rename" {
		t.Errorf("RPC Action = %q, want 'rename'", lr.Action)
	}
	if lr.Path != "old" {
		t.Errorf("RPC Path = %q, want 'old'", lr.Path)
	}
	if lr.NewPath != "new" {
		t.Errorf("RPC NewPath = %q, want 'new'", lr.NewPath)
	}
}

func TestFileOp_RenameMissingNewPath(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"rename","path":"old"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing new_path, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFileOp_RenameMissingPath(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// rename is allowed to reach doRename with empty path (handleFileOp skips
	// the empty-path check for rename), but doRename rejects it.
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"rename","new_path":"new"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing path on rename, got %d: %s", w.Code, w.Body.String())
	}
}

// ── Lease warm path (VolumePath must STILL be set) ─────────────
//
// The volume path is the identity the node asserts to the warden. It used to
// be suppressed on a lease hit, which made the sandlot derive the identity
// from whatever volume the VM currently held — a cross-tenant window during a
// switch. Both the cold and the warm requests must carry the record's path.

func TestFileOp_LeaseHitStillCarriesVolumePath(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Data: []byte("warm"), Success: true}

	// First call: cold path (sets VolumePath for the mount).
	w1 := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w1.Code != http.StatusOK {
		t.Fatalf("first call: expected 200, got %d", w1.Code)
	}
	lr1 := sc.lastFileReq()
	if lr1.VolumePath == "" {
		t.Error("cold path: expected non-empty VolumePath")
	}

	// Second call immediately: warm path (lease hit). The identity MUST still
	// be the request's own volume, never left empty for the node to infer.
	w2 := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("second call: expected 200, got %d", w2.Code)
	}
	lr2 := sc.lastFileReq()
	if lr2.VolumePath == "" {
		t.Error("warm path: expected the request's VolumePath to be carried (cross-tenant identity guard)")
	}
	if lr2.VolumePath != lr1.VolumePath {
		t.Errorf("warm VolumePath %q must equal the cold one %q", lr2.VolumePath, lr1.VolumePath)
	}
}

// ── L1 retry on transport error ────────────────────────────────

func TestFileOp_L1RetryTransportError(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// Fail first call with transport error, then succeed.
	sc.failCount = 1
	sc.err = errors.New("transport error: connection reset by peer")
	sc.result = pool.FileOpResult{Data: []byte("ok"), Success: true}

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after L1 retry, got %d: %s", w.Code, w.Body.String())
	}
	if sc.callCount() < 2 {
		t.Errorf("expected at least 2 calls, got %d", sc.callCount())
	}
}

func TestFileOp_L2CleanupOnFailure(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// Non-transport error: L1 retry does NOT trigger, L2 cleanup fires -> 503.
	sc.err = errors.New("permission denied")
	sc.failCount = 0 // always fail

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 on non-transport failure, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error_code"] != "SANDBOX_CLEANING" {
		t.Errorf("error_code = %v, want SANDBOX_CLEANING", resp["error_code"])
	}

	// Wait for async L2 cleanup to finish.
	time.Sleep(200 * time.Millisecond)
}

// ── SandFS in CLEANING state ───────────────────────────────────

func TestFileOp_SandfsCleaning503(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	_, fileH, humanH, _, _, _, _, ss, ak, aid := setupResilienceGateway(t, sc)
	sid := createResilienceSandFS(t, humanH, aid)

	ss.EnterCleaning(sid)

	w := doResilienceFile(t, fileH, ak, sid, "read", "f")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 during cleaning, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error_code"] != "SANDBOX_CLEANING" {
		t.Errorf("error_code = %v, want SANDBOX_CLEANING", resp["error_code"])
	}
}

// doResilienceFile sends a file request via a FileHandler from setupResilienceGateway.
func doResilienceFile(t *testing.T, fh *handler.FileHandler, apiKey, sandfsID, action, path string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(handler.FileRequest{SandfsID: sandfsID, Action: action, Path: path})
	req := httptest.NewRequest("POST", "/agent/file", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	fh.ServeHTTP(w, req)
	return w
}

// ── DoFileOpDirect (MCP entry point) ───────────────────────────

func TestFileOp_DoFileOpDirect_Success(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Data: []byte("direct"), Success: true}

	result, err := fh.DoFileOpDirect(context.Background(), sandfsID, apiKey, pool.FileOpRequest{
		Action: "read",
		Path:   "f",
	})
	if err != nil {
		t.Fatalf("DoFileOpDirect: %v", err)
	}
	if string(result.Data) != "direct" {
		t.Errorf("Data = %q, want 'direct'", string(result.Data))
	}
}

func TestFileOp_DoFileOpDirect_InvalidKey(t *testing.T) {
	fh, _, reg, _, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)

	_, err := fh.DoFileOpDirect(context.Background(), sandfsID, "sk-wrong", pool.FileOpRequest{
		Action: "read", Path: "f",
	})
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
}

func TestFileOp_DoFileOpDirect_CrossAgent(t *testing.T) {
	fh, _, reg, _, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)

	_, otherKey, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "other"})
	if err != nil {
		t.Fatalf("create other agent: %v", err)
	}
	_, err = fh.DoFileOpDirect(context.Background(), sandfsID, otherKey, pool.FileOpRequest{
		Action: "read", Path: "f",
	})
	if err == nil {
		t.Fatal("expected forbidden error for cross-agent, got nil")
	}
}

// ── FileOp cold-mount bound tracking ──────────────────

// cleanCount returns the aggregate derived clean count (total - bound) for the
// single test node.
func cleanCount(t *testing.T, pm *pool.Manager) uint32 {
	t.Helper()
	counts := pm.NodeCleanCounts()
	c, ok := counts["localhost"]
	if !ok {
		t.Fatalf("node localhost not present: %v", counts)
	}
	return c[0]
}

func TestFileOp_ColdMountBoundTracking(t *testing.T) {
	fh, sc, pm, reg, apiKey, agentID := setupFileGatewayWithPM(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Data: []byte("cold"), Success: true}

	// Initial: clean = total = 3 (bound = 0).
	if c := cleanCount(t, pm); c != 3 {
		t.Fatalf("initial clean = %d, want 3", c)
	}

	// Cold op: ReserveBound(minSpec) at send → AdjustBound(actual spec) on
	// success. The stub returns Spec="" (defaults to medium), so the bound stays
	// at the provisional reservation.
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("cold op: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if c := cleanCount(t, pm); c != 2 {
		t.Errorf("after cold mount: clean = %d, want 2 (bound held)", c)
	}

	// Warm op on the same lease: reuses the bound VM — no new reservation
	// (derived clean must not double-drop).
	w = doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("warm op: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if c := cleanCount(t, pm); c != 2 {
		t.Errorf("after warm op: clean = %d, want 2 (no double-count)", c)
	}

	// Lease expiry → onExpiry → ReleaseBound → clean recovers to 3 (the node is
	// reusable after the unmount).
	deadline := time.Now().Add(2 * time.Second)
	for cleanCount(t, pm) != 3 {
		if time.Now().After(deadline) {
			t.Fatalf("clean did not recover to 3 after lease expiry, got %d", cleanCount(t, pm))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestFileOp_ColdMountFailureReleasesBound(t *testing.T) {
	fh, sc, pm, reg, apiKey, agentID := setupFileGatewayWithPM(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// Non-transport error → L2 SANDBOX_CLEANING. The send-time bound must be
	// released so the derived clean count recovers immediately.
	sc.err = errors.New("mount failed")
	sc.failCount = 0 // always fail

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	if c := cleanCount(t, pm); c != 3 {
		t.Errorf("after cold failure: clean = %d, want 3 (bound released)", c)
	}
}

func TestFileOp_NoAvailableSandbox(t *testing.T) {
	fh, sc, pm, reg, apiKey, agentID := setupFileGatewayWithPM(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	// Over-subscription / empty pool: the node has no CLEAN VM.
	// NOT a mount failure — the sandfs isn't dirty and must stay AVAILABLE.
	sc.err = pool.ErrNoAvailableSandbox
	sc.failCount = 0 // always fail

	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error_code"] != "NO_AVAILABLE_SANDBOX" {
		t.Errorf("error_code = %v, want NO_AVAILABLE_SANDBOX", resp["error_code"])
	}
	// Bound released: derived clean back to 3.
	if c := cleanCount(t, pm); c != 3 {
		t.Errorf("clean = %d, want 3 (bound released on retryable failure)", c)
	}

	// The sandfs is NOT in CLEANING (no EnterCleaning on over-subscription), so a
	// retry succeeds immediately instead of 503-blocking for ~12s.
	sc.err = nil
	sc.result = pool.FileOpResult{Data: []byte("ok"), Success: true}
	w = doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("retry after NO_AVAILABLE_SANDBOX: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestFileOp_BlocksDuringUnmount: a file op arriving while a
// lease-expiry unmount is in progress MUST block (AcquireWait) and NOT cold-mount
// on another node - which would dual-mount the sandfs during the ~8s unmount
// window. Before the fix, file.go used non-blocking Acquire (returns "" on
// unmounting) -> cold mount on another node -> dual mount. This test exposes
// the unmounting window with a blocking onExpiry and asserts no 2nd FileOp RPC
// fires until the unmount completes. Validates the DoFileOpDirect (MCP) path;
// doFileOp (HTTP) is the identical fix.
func TestFileOp_BlocksDuringUnmount(t *testing.T) {
	// Reuse the registry/template/node setup, but build a fresh FileHandler with
	// a lease manager whose onExpiry BLOCKS (exposing the unmounting window that
	// the setup helper's immediate onExpiry would hide).
	_, sc, pm, reg, apiKey, agentID := setupFileGatewayWithPM(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)

	lm := lease.New(50*time.Millisecond, 5*time.Second)
	unmountStarted := make(chan struct{})
	unmountProceed := make(chan struct{})
	lm.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		defer lm.Release(sandfsID)
		defer pm.ReleaseBound(nodeID, spec)
		close(unmountStarted)
		<-unmountProceed // block: entry stays unmounting (mirrors ~8s UnmountRootfs)
	})
	ml := lease.NewMountLock()
	ss := lease.NewSandfsState()
	fh := handler.NewFileHandler(reg.Store(), pm, lm, sc, ml, nil, ss, slog.New(slog.DiscardHandler))
	sc.result = pool.FileOpResult{Spec: "medium"}

	ctx := context.Background()

	// 1. First file op: cold mount, establishes a 50ms lease. One FileOp RPC.
	if _, err := fh.DoFileOpDirect(ctx, sandfsID, apiKey, pool.FileOpRequest{Action: "stat", Path: "."}); err != nil {
		t.Fatalf("first file op (cold mount) failed: %v", err)
	}
	if got := sc.callCount(); got != 1 {
		t.Fatalf("after first op, expected 1 FileOp RPC, got %d", got)
	}

	// 2. Wait for the lease to expire -> onExpiry starts -> entry is unmounting.
	select {
	case <-unmountStarted:
	case <-time.After(time.Second):
		t.Fatal("lease-expiry onExpiry did not start in time")
	}

	// 3. A concurrent file op must BLOCK (AcquireWait), not cold-mount. With the
	//    bug (non-blocking Acquire) it would return "" -> cold mount -> a 2nd
	//    FileOp RPC on another node = dual mount.
	type opRes struct {
		r   pool.FileOpResult
		err error
	}
	resCh := make(chan opRes, 1)
	go func() {
		r, err := fh.DoFileOpDirect(ctx, sandfsID, apiKey, pool.FileOpRequest{Action: "stat", Path: "."})
		resCh <- opRes{r, err}
	}()
	time.Sleep(100 * time.Millisecond) // give the op a chance to (wrongly) cold-mount
	if got := sc.callCount(); got != 1 {
		t.Fatalf("file op cold-mounted during unmount (possible dual-mount!): FileOp RPCs=%d", got)
	}
	select {
	case <-resCh:
		t.Fatal("file op returned during unmount; expected to block (AcquireWait)")
	default:
		// good: still blocked on the in-progress unmount
	}

	// 4. Let the unmount finish -> onExpiry returns -> defer Release deletes the
	//    entry + signals the waiter -> AcquireWait unblocks -> cold mount proceeds.
	close(unmountProceed)
	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("file op after unmount failed: %v", r.err)
		}
		if got := sc.callCount(); got != 2 {
			t.Fatalf("expected cold mount after unmount (2nd FileOp RPC), got %d", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("file op did not unblock after unmount finished")
	}
}

// ── Warm-path maxHold anchor (file-op workloads) ─────────────────

// TestFileOp_WarmOpsKeepLeasePastMaxHold verifies the warm file path refreshes
// the maxHold anchor (TouchSync on BOTH paths, mirroring ExecuteDirect): a
// file-op-heavy workload must not have its VM reaped by the maxHold reaper
// every maxHold window despite active traffic. The reaper bounds a pure-sync
// lease by time.Since(syncStartedAt) and does NOT consult the continuously
// refreshed syncStickyUntil — without the warm TouchSync, a file-only workload
// is unmounted + cold-remounted (with the unmount's drop_caches) once per
// maxHold window.
func TestFileOp_WarmOpsKeepLeasePastMaxHold(t *testing.T) {
	volRoot := t.TempDir()
	reg := registry.New(volRoot)

	reg.SetStorageOps(storagetest.New(volRoot))

	sc := &fileOpClient{}
	sc.result = pool.FileOpResult{Data: []byte("ok"), Success: true}
	pm := pool.NewManager(sc, slog.New(slog.DiscardHandler))
	// Sticky 150ms (the ~20ms op gap stays comfortably warm), maxHold 300ms:
	// without the warm-path TouchSync the reaper unmounts ~300-450ms after the
	// cold mount; with the fix the anchor refreshes on every op.
	lm := lease.New(150*time.Millisecond, 300*time.Millisecond)
	released := make(chan string, 4)
	lm.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		released <- sandfsID
		lm.Release(sandfsID)
		pm.ReleaseBound(nodeID, spec)
	})
	defer lm.Close()
	ml := lease.NewMountLock()
	ss := lease.NewSandfsState()

	pm.AddNode("localhost")
	pm.UpdateNodeCapacity("localhost", []pool.SpecCapacity{{SpecID: "medium", Clean: 3, Total: 3}})

	fh := handler.NewFileHandler(reg.Store(), pm, lm, sc, ml, nil, ss, slog.New(slog.DiscardHandler))

	agent, apiKey, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "file-warm-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	sandfsID := createFileTestSandFS(t, reg, agent.ID)

	// Cold op, then warm ops for ~1s (≈3x maxHold, ≫ the 150ms reaper tick).
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("cold file op: %d %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"f"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("warm file op: %d %s", w.Code, w.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case id := <-released:
		t.Fatalf("maxHold reaper released an actively-warm file workload (mount churn every maxHold window): %s", id)
	default:
	}
}

// TestFileOpWireSizeGate pins the pre-send size gate: a write whose
// decoded data (or a read whose requested length) would breach the stream's
// gRPC message limit must answer 413 BEFORE any RPC — a wire-limit breach is
// a stream-level failure that resets the node stream and kills every
// co-tenant in-flight command. RED with the gates removed (the
// request would reach the fake sandlot client and return 200).
func TestFileOpWireSizeGate(t *testing.T) {
	old := handler.SetMaxFileOpDataBytesForTest(1024) // shrink for the test
	defer handler.SetMaxFileOpDataBytesForTest(old)

	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Success: true}

	big := strings.Repeat("x", 2048)
	w := doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"out.txt","data":"`+big+`"}`)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize write: code = %d, want 413: %s", w.Code, w.Body.String())
	}
	if sc.lastFileReq().Action != "" {
		t.Fatal("oversize write reached the RPC (uncovered wire breach)")
	}

	w = doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"read","path":"out.txt","length":2048}`)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize read: code = %d, want 413: %s", w.Code, w.Body.String())
	}

	// Control: a within-cap write still flows.
	w = doFileRequest(t, fh, apiKey, `{"sandfs_id":"`+sandfsID+`","action":"write","path":"out.txt","data":"ok"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("control write: code = %d, want 200", w.Code)
	}
}

// TestStatsRedaction pins the agent-listener /stats redaction: the
// unmount projection carries tenant sandfs ids + raw command excerpts
// (code, paths, tokens); with redaction ON (exec mode's wiring — that
// listener has no auth in front of /stats) they must not leave the process,
// while latency fields survive. RED with the redaction removed.
func TestStatsRedaction(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	_, _, humanH, _, _, _, _, _, _, _ := setupResilienceGateway(t, sc)

	rec := stats.NewUnmountStats(10, time.Hour, nil, "gw-redact", slog.Default())
	rec.RecordMount("node-1", "sandfs-victim", "echo C-secret > /workspace/x")
	rec.RecordUnmount("node-1", "sandfs-victim", "lease-expiry", pool.UnmountResult{GatewayDurationNs: 9_000_000}, true)
	humanH.SetUnmountStats(rec)

	get := func() string {
		req := httptest.NewRequest("GET", "/stats", nil)
		w := httptest.NewRecorder()
		humanH.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("/stats: %d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	body := get()
	if !strings.Contains(body, "sandfs-victim") || !strings.Contains(body, "C-secret") {
		t.Fatalf("setup: the full view (redaction off) must carry the tenant fields: %s", body)
	}
	humanH.SetRedactTenantIDs(true)
	body = get()
	if strings.Contains(body, "sandfs-victim") || strings.Contains(body, "C-secret") {
		t.Fatalf(": tenant identifiers leaked from the redacted /stats: %s", body)
	}
	if !strings.Contains(body, "unmount") {
		t.Fatalf("utility lost: the unmount projection vanished entirely: %s", body)
	}
}
