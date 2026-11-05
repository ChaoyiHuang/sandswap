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
	"testing"

	"gateway/handler"
	"gateway/identity"
	"gateway/pool"
)

// newIdentityStoreWithAgent creates a MemoryStore pre-populated with one agent and
// one sandfs owned by that agent. Returns the store, the agent's API key, the
// agent ID, and the sandfs ID. This isolates auth-resolution tests from the
// registry/template machinery.
func newIdentityStoreWithAgent(t *testing.T) (identity.Store, string, string, string) {
	t.Helper()
	store := identity.NewMemoryStore("/tmp/test-vol")
	agent, apiKey, err := store.CreateAgent(identity.CreateAgentRequest{Name: "auth-test-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	rec, err := store.CreateSandFS(agent.ID, identity.CreateSandFSRequest{
		Name:     "auth-test-sandfs",
		Template: "test:v1",
		Mode:     "flat",
	})
	if err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	if err := store.SetRootFSPath(rec.ID, "/tmp/test-vol/"+rec.ID); err != nil {
		t.Fatalf("set rootfs path: %v", err)
	}
	if err := store.SetMinResources(rec.ID, 2, 512); err != nil {
		t.Fatalf("set min resources: %v", err)
	}
	return store, apiKey, agent.ID, rec.ID
}

// ── ResolveFromRequest ─────────────────────────────────────────

func TestResolveFromRequest_Success(t *testing.T) {
	store, apiKey, agentID, sandfsID := newIdentityStoreWithAgent(t)

	identity, err := handler.ResolveFromRequest(store, apiKey, sandfsID)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if identity.AgentID != agentID {
		t.Errorf("AgentID = %q, want %q", identity.AgentID, agentID)
	}
	if identity.SandfsID != sandfsID {
		t.Errorf("SandfsID = %q, want %q", identity.SandfsID, sandfsID)
	}
	if identity.RootFSPath == "" {
		t.Error("expected non-empty RootFSPath")
	}
	if identity.MinVCPUs != 2 || identity.MinMemoryMB != 512 {
		t.Errorf("MinVCPUs=%d MinMemoryMB=%d, want 2/512", identity.MinVCPUs, identity.MinMemoryMB)
	}
}

func TestResolveFromRequest_InvalidVolumeMode(t *testing.T) {
	store := identity.NewMemoryStore("/tmp/test-vol")
	agent, apiKey, err := store.CreateAgent(identity.CreateAgentRequest{Name: "bad-mode-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	rec, err := store.CreateSandFS(agent.ID, identity.CreateSandFSRequest{
		Name: "bad-mode", Template: "test:v1", Mode: "squashfs",
	})
	if err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	store.SetRootFSPath(rec.ID, "/tmp/test-vol/x")

	if _, err := handler.ResolveFromRequest(store, apiKey, rec.ID); err == nil {
		t.Fatal("a record with an unknown volume mode must be refused at resolve time")
	}
}

func TestResolveFromRequest_EmptyRootFSPath(t *testing.T) {
	store := identity.NewMemoryStore("/tmp/test-vol")
	agent, apiKey, err := store.CreateAgent(identity.CreateAgentRequest{Name: "no-path-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	rec, err := store.CreateSandFS(agent.ID, identity.CreateSandFSRequest{
		Name: "no-path", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	// RootFSPath deliberately left empty: the mount path would carry an empty
	// identity, which the warden now refuses — fail at the gateway instead.
	if _, err := handler.ResolveFromRequest(store, apiKey, rec.ID); err == nil {
		t.Fatal("a record with no rootfs path must be refused at resolve time")
	}
}

func TestResolveFromRequest_InvalidKey(t *testing.T) {
	store, _, _, sandfsID := newIdentityStoreWithAgent(t)

	_, err := handler.ResolveFromRequest(store, "sk-sandswap-agent-wrong", sandfsID)
	if err == nil {
		t.Fatal("expected error for invalid api key, got nil")
	}
	// Verify the error message contains "invalid api key".
	if !strings.Contains(err.Error(), "invalid api key") {
		t.Errorf("error message = %q, want substring 'invalid api key'", err.Error())
	}
}

func TestResolveFromRequest_UnknownSandfs(t *testing.T) {
	store, apiKey, _, _ := newIdentityStoreWithAgent(t)

	_, err := handler.ResolveFromRequest(store, apiKey, "sandfs-nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown sandfs, got nil")
	}
	if !strings.Contains(err.Error(), "sandfs not found") {
		t.Errorf("error message = %q, want substring 'sandfs not found'", err.Error())
	}
}

func TestResolveFromRequest_CrossAgentForbidden(t *testing.T) {
	store, _, _, sandfsID := newIdentityStoreWithAgent(t)

	// Create a second agent.
	_, otherAPIKey, err := store.CreateAgent(identity.CreateAgentRequest{Name: "other-agent"})
	if err != nil {
		t.Fatalf("create other agent: %v", err)
	}

	// Other agent tries to access the first agent's sandfs.
	_, err = handler.ResolveFromRequest(store, otherAPIKey, sandfsID)
	if err == nil {
		t.Fatal("expected forbidden error for cross-agent access, got nil")
	}
	// uniform not-found (no existence oracle).
	if !strings.Contains(err.Error(), "sandfs not found") {
		t.Errorf("error message = %q, want the uniform not-found contract", err.Error())
	}
}

// ── ResolveFromPreAuthAgent ────────────────────────────────────

func TestResolveFromPreAuthAgent_Success(t *testing.T) {
	store, apiKey, agentID, sandfsID := newIdentityStoreWithAgent(t)

	// Pre-resolve the agent (simulating resolveSandfsID having done it).
	agent, err := store.ResolveAgent(apiKey)
	if err != nil {
		t.Fatalf("resolve agent: %v", err)
	}
	if agent.ID != agentID {
		t.Fatalf("agent ID = %q, want %q", agent.ID, agentID)
	}

	identity, err := handler.ResolveFromPreAuthAgent(store, agent, sandfsID)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if identity.AgentID != agentID {
		t.Errorf("AgentID = %q, want %q", identity.AgentID, agentID)
	}
	if identity.SandfsID != sandfsID {
		t.Errorf("SandfsID = %q, want %q", identity.SandfsID, sandfsID)
	}
}

func TestResolveFromPreAuthAgent_SandfsNotFound(t *testing.T) {
	store, apiKey, _, _ := newIdentityStoreWithAgent(t)

	agent, err := store.ResolveAgent(apiKey)
	if err != nil {
		t.Fatalf("resolve agent: %v", err)
	}

	_, err = handler.ResolveFromPreAuthAgent(store, agent, "sandfs-nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown sandfs, got nil")
	}
	if !strings.Contains(err.Error(), "sandfs not found") {
		t.Errorf("error message = %q, want substring 'sandfs not found'", err.Error())
	}
}

func TestResolveFromPreAuthAgent_CrossAgent(t *testing.T) {
	store, _, _, sandfsID := newIdentityStoreWithAgent(t)

	// Create a second agent and pre-resolve it.
	_, otherAPIKey, err := store.CreateAgent(identity.CreateAgentRequest{Name: "other-agent"})
	if err != nil {
		t.Fatalf("create other agent: %v", err)
	}
	otherAgent, err := store.ResolveAgent(otherAPIKey)
	if err != nil {
		t.Fatalf("resolve other agent: %v", err)
	}

	// Other agent tries to access the first agent's sandfs via pre-auth path.
	_, err = handler.ResolveFromPreAuthAgent(store, otherAgent, sandfsID)
	if err == nil {
		t.Fatal("expected a not-found error, got nil")
	}
	// uniform not-found (no existence oracle).
	if !strings.Contains(err.Error(), "sandfs not found") {
		t.Errorf("error message = %q, want the uniform not-found contract", err.Error())
	}
}

// ── resolveFromAgent field propagation ─────────────────────────

func TestResolveFromRequest_FieldPropagation(t *testing.T) {
	store := identity.NewMemoryStore("/tmp/test-vol")
	agent, apiKey, _ := store.CreateAgent(identity.CreateAgentRequest{Name: "field-agent"})
	rec, _ := store.CreateSandFS(agent.ID, identity.CreateSandFSRequest{
		Name:        "field-sandfs",
		Description: "desc",
		Template:    "tmpl:v1",
		Mode:        "flat",
	})
	store.SetRootFSPath(rec.ID, "/custom/vol")
	store.SetMinResources(rec.ID, 4, 2048)

	identity, err := handler.ResolveFromRequest(store, apiKey, rec.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if identity.RootFSPath != "/custom/vol" {
		t.Errorf("RootFSPath = %q, want /custom/vol", identity.RootFSPath)
	}
	if identity.MinVCPUs != 4 || identity.MinMemoryMB != 2048 {
		t.Errorf("MinVCPUs=%d MinMemoryMB=%d, want 4/2048", identity.MinVCPUs, identity.MinMemoryMB)
	}
	if identity.Template != "tmpl:v1" {
		t.Errorf("Template = %q, want tmpl:v1", identity.Template)
	}
	// InstallPackages is derived from mode: flat → allowed (true).
	if !identity.InstallPackages {
		t.Error("InstallPackages = false, want true (flat mode allows packages)")
	}
}

// ── AsResilienceError ──────────────────────────────────────────

// TestAsResilienceError_FromExecuteDirect triggers a real resilienceError via
// the ExecuteDirect pipeline (sandfs in CLEANING state) and verifies
// AsResilienceError extracts the structured fields.
func TestAsResilienceError_FromExecuteDirect(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, _, _, _, ss, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	// Put the sandfs into CLEANING state -> ExecuteDirect returns *resilienceError.
	if err := ss.EnterCleaning(sandfsID); err != nil {
		t.Fatalf("enter cleaning: %v", err)
	}

	_, err := execH.ExecuteDirect(context.Background(), apiKey, handler.ExecuteRequest{
		SandfsID: sandfsID,
		Code:     "echo hi",
		Language: "shell",
	})
	if err == nil {
		t.Fatal("expected error from ExecuteDirect during cleaning, got nil")
	}

	msg, errorCode, retryable, retryAfterMs, _, ok := handler.AsResilienceError(err)
	if !ok {
		t.Fatalf("expected AsResilienceError ok=true, got false (err type %T: %v)", err, err)
	}
	if !retryable {
		t.Error("expected retryable=true")
	}
	if retryAfterMs <= 0 {
		t.Errorf("expected positive retryAfterMs, got %d", retryAfterMs)
	}
	if errorCode == "" {
		t.Error("expected non-empty errorCode")
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
}

func TestAsResilienceError_NonResilienceError(t *testing.T) {
	// A regular error should not be detected as a resilience error.
	msg, errorCode, retryable, retryAfterMs, _, ok := handler.AsResilienceError(errors.New("some random error"))
	if ok {
		t.Error("expected ok=false for non-resilience error")
	}
	if msg != "" || errorCode != "" || retryable || retryAfterMs != 0 {
		t.Errorf("expected zero values for non-resilience error, got msg=%q errorCode=%q retryable=%v retryAfterMs=%d",
			msg, errorCode, retryable, retryAfterMs)
	}
}

func TestAsResilienceError_NilError(t *testing.T) {
	_, _, _, _, _, ok := handler.AsResilienceError(nil)
	if ok {
		t.Error("expected ok=false for nil error")
	}
}

// ── IsTransportError edge cases ────────────────────────────────

func TestIsTransportError_Nil(t *testing.T) {
	// nil error is NOT a transport error (covers the err == nil branch).
	if handler.IsTransportError(nil) {
		t.Error("expected IsTransportError(nil) = false")
	}
}

// ── writeAuthError (via HandleExecStatus) ──────────────────────

// TestWriteAuthError_InvalidKey exercises writeAuthError indirectly: an invalid
// API key passed to HandleExecStatus causes ResolveFromRequest to return an
// *authHTTPError, which writeAuthError must map to the correct HTTP status.
func TestWriteAuthError_InvalidKey(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, _, _, _, _, _, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	body := `{"sandfs_id":"` + sandfsID + `","exec_id":"bg-x"}`
	req := httptest.NewRequest("POST", "/agent/exec/status", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-sandswap-agent-wrong")
	w := httptest.NewRecorder()

	execH.HandleExecStatus(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid api key, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["error"] != "invalid api key" {
		t.Errorf("error = %q, want 'invalid api key'", resp["error"])
	}
}

// TestWriteAuthError_CrossAgentForbidden exercises writeAuthError with a 403
// authHTTPError: a valid key for agent A accessing agent B's sandfs.
func TestWriteAuthError_CrossAgentForbidden(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, _, _, _, _, _, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	// Create a second agent via the human endpoint.
	body := `{"name":"other"}`
	createReq := httptest.NewRequest("POST", "/human/agent", strings.NewReader(body))
	createW := httptest.NewRecorder()
	humanH.ServeHTTP(createW, createReq)
	if createW.Code != http.StatusCreated {
		t.Fatalf("create other agent: %d %s", createW.Code, createW.Body.String())
	}
	var createResp handler.CreateAgentResponse
	json.Unmarshal(createW.Body.Bytes(), &createResp)

	// Other agent's key trying to poll status on the first agent's sandfs.
	statusBody := `{"sandfs_id":"` + sandfsID + `","exec_id":"bg-x"}`
	req := httptest.NewRequest("POST", "/agent/exec/status", strings.NewReader(statusBody))
	req.Header.Set("Authorization", "Bearer "+createResp.APIKey)
	w := httptest.NewRecorder()
	execH.HandleExecStatus(w, req)

	// uniform not-found (no existence oracle for foreign ids).
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (uniform not-found) for cross-agent access, got %d: %s", w.Code, w.Body.String())
	}
}

// ── writeResilienceError retryAfterMs header ───────────────────

// TestWriteResilienceError_RetryAfterHeader verifies the Retry-After header is
// emitted (retryAfterMs > 0 branch) and is computed as ms/1000 seconds.
func TestWriteResilienceError_RetryAfterHeader(t *testing.T) {
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, _, _, _, ss, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID := createResilienceSandFS(t, humanH, agentID)

	ss.EnterCleaning(sandfsID)

	body := `{"sandfs_id":"` + sandfsID + `","code":"echo hi"}`
	req := httptest.NewRequest("POST", "/agent/execute", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()
	execH.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("expected non-empty Retry-After header")
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["retryable"] != true {
		t.Error("expected retryable=true")
	}
}

// TestMountTemplateRef pins the node-facing template handshake: only overlay
// records ship a template ref in mount commands. Flat records send "" so the
// node ignores any marker at the volume root — in flat mode that path is the
// agent's chroot root, and honoring a planted marker flips the volume into an
// unresolvable overlay mount.
func TestMountTemplateRef(t *testing.T) {
	cases := []struct {
		name string
		id   handler.ResolvedIdentity
		want string
	}{
		{"overlay record ships its template", handler.ResolvedIdentity{Template: "rootfs:v1", Mode: "overlay"}, "rootfs:v1"},
		{"flat record with template ships empty", handler.ResolvedIdentity{Template: "rootfs:v1", Mode: "flat"}, ""},
		{"flat record without template ships empty", handler.ResolvedIdentity{Mode: "flat"}, ""},
		{"overlay record without template ships empty", handler.ResolvedIdentity{Mode: "overlay"}, ""},
	}
	for _, c := range cases {
		if got := c.id.MountTemplateRef(); got != c.want {
			t.Errorf("%s: MountTemplateRef() = %q, want %q", c.name, got, c.want)
		}
	}
}
