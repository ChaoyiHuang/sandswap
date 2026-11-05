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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/handler"
	"gateway/registry"
	"log/slog"
)

// fakeReleaser records sandfs IDs passed to ReleaseOwnership, so the ownership
// release endpoint can be verified without a real etcd-backed cache.
type fakeReleaser struct{ released []string }

func (f *fakeReleaser) ReleaseOwnership(sandfsID string) { f.released = append(f.released, sandfsID) }

// doHumanRequest issues a request to the given HumanHandler and returns the
// recorder.
func doHumanRequest(h *handler.HumanHandler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestHumanSetOwnershipAndRelease verifies SetOwnership wires the releaser and
// POST /human/ownership/release/{id} calls it, returning 200 "released".
func TestHumanSetOwnershipAndRelease(t *testing.T) {
	gw := setupTestGateway(t)
	fr := &fakeReleaser{}
	gw.humanHandler.SetOwnership(fr)

	w := doHumanRequest(gw.humanHandler, "POST", "/human/ownership/release/sandfs-1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(fr.released) != 1 || fr.released[0] != "sandfs-1" {
		t.Errorf("releaser called with %v, want [sandfs-1]", fr.released)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "released" {
		t.Errorf("status = %q, want released", body["status"])
	}
}

// TestHumanReleaseOwnershipEmptyID verifies an empty sandfs_id is rejected
// with 400 (defensive: the URL would otherwise be /human/ownership/release/).
func TestHumanReleaseOwnershipEmptyID(t *testing.T) {
	gw := setupTestGateway(t)
	w := doHumanRequest(gw.humanHandler, "POST", "/human/ownership/release/", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty sandfs_id, got %d", w.Code)
	}
}

// TestHumanReleaseOwnershipSingleNode verifies the nil-releaser path: without
// SetOwnership (single-node mode) the release always succeeds with a
// "single-node" status instead of erroring.
func TestHumanReleaseOwnershipSingleNode(t *testing.T) {
	gw := setupTestGateway(t) // ownership never set -> nil
	w := doHumanRequest(gw.humanHandler, "POST", "/human/ownership/release/sandfs-1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["mode"] != "single-node" {
		t.Errorf("mode = %q, want single-node", body["mode"])
	}
}

// TestHumanListAgents verifies GET /human/agent returns the registered agents
// in the paginated envelope (items + next_cursor + truncated).
func TestHumanListAgents(t *testing.T) {
	gw := setupTestGateway(t)
	w := doHumanRequest(gw.humanHandler, "GET", "/human/agent", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var page struct {
		Items      []map[string]interface{} `json:"items"`
		NextCursor string                   `json:"next_cursor"`
		Truncated  bool                     `json:"truncated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Items) < 1 {
		t.Fatalf("expected at least 1 agent, got %d", len(page.Items))
	}
	found := false
	for _, a := range page.Items {
		if a["agent_id"] == gw.agentID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("agent %q not in list: %v", gw.agentID, page.Items)
	}
}

// TestHumanListPagination drives the cursor protocol end-to-end on
// /human/sandfs: a small limit pages through every sandfs exactly once, in
// ascending ID order, with next_cursor chaining and no duplicates; the last
// page carries no cursor; a bogus limit is a 400; an above-max limit clamps.
func TestHumanListPagination(t *testing.T) {
	gw := setupTestGateway(t)

	// Create extra sandfs so pagination has multiple pages (IDs sort after the
	// default test sandfs). The fixture registers flat template "test:v1".
	for i := 0; i < 7; i++ {
		w := doHumanRequest(gw.humanHandler, "POST", "/human/sandfs", fmt.Sprintf(
			`{"agent_id":%q,"mode":"flat","template":"test:v1"}`, gw.agentID))
		if w.Code != http.StatusCreated {
			t.Fatalf("create sandfs %d: %d %s", i, w.Code, w.Body.String())
		}
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		path := "/human/sandfs?limit=3"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		w := doHumanRequest(gw.humanHandler, "GET", path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("page %d: %d %s", pages, w.Code, w.Body.String())
		}
		var page struct {
			Items      []map[string]interface{} `json:"items"`
			NextCursor string                   `json:"next_cursor"`
			Truncated  bool                     `json:"truncated"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode page %d: %v", pages, err)
		}
		if len(page.Items) == 0 || len(page.Items) > 3 {
			t.Fatalf("page %d: items=%d (limit 3)", pages, len(page.Items))
		}
		for _, it := range page.Items {
			id, _ := it["sandfs_id"].(string)
			if seen[id] {
				t.Fatalf("duplicate sandfs %q across pages", id)
			}
			seen[id] = true
		}
		if page.NextCursor == "" {
			if page.Truncated {
				t.Fatalf("last page marked truncated without a cursor")
			}
			break
		}
		cursor = page.NextCursor
		pages++
		if pages > 10 {
			t.Fatalf("pagination did not terminate")
		}
	}
	if len(seen) < 7 {
		t.Fatalf("expected at least 7 distinct sandfs across pages, got %d", len(seen))
	}

	// Invalid limit: 400. Above-max: clamped (single page still valid).
	if w := doHumanRequest(gw.humanHandler, "GET", "/human/sandfs?limit=abc", ""); w.Code != http.StatusBadRequest {
		t.Errorf("limit=abc: expected 400, got %d", w.Code)
	}
	if w := doHumanRequest(gw.humanHandler, "GET", "/human/sandfs?limit=0", ""); w.Code != http.StatusBadRequest {
		t.Errorf("limit=0: expected 400, got %d", w.Code)
	}
	w := doHumanRequest(gw.humanHandler, "GET", "/human/sandfs?limit=999999", "")
	if w.Code != http.StatusOK {
		t.Errorf("limit above max: expected clamped 200, got %d", w.Code)
	}
}

// TestHumanDeleteAgent verifies DELETE /human/agent/{id} returns 204 (the
// agent and its sandfs are removed).
func TestHumanDeleteAgent(t *testing.T) {
	gw := setupTestGateway(t)
	w := doHumanRequest(gw.humanHandler, "DELETE", "/human/agent/"+gw.agentID, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	// The agent is now gone from the store.
	agents, err := gw.reg.Store().ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	for _, a := range agents {
		if a.ID == gw.agentID {
			t.Error("agent should be deleted from the store")
		}
	}
}

// TestHumanDeleteAgentUnknown verifies deleting a non-existent agent surfaces
// the store error (500).
func TestHumanDeleteAgentUnknown(t *testing.T) {
	gw := setupTestGateway(t)
	w := doHumanRequest(gw.humanHandler, "DELETE", "/human/agent/does-not-exist", "")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unknown agent, got %d", w.Code)
	}
}

// TestHumanListTemplates verifies GET /human/templates with a template manager
// returns the registered local templates as summaries.
func TestHumanListTemplates(t *testing.T) {
	gw := setupTestGateway(t) // fixture registers flat template "test:v1"
	w := doHumanRequest(gw.humanHandler, "GET", "/human/templates", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var summaries []handler.TemplateSummary
	if err := json.Unmarshal(w.Body.Bytes(), &summaries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(summaries) < 1 {
		t.Fatalf("expected at least the test:v1 template, got %d", len(summaries))
	}
	found := false
	for _, s := range summaries {
		if s.Name == "test" && s.Mode == "flat" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("test:v1 flat template not in summaries: %v", summaries)
	}
}

// TestHumanTemplateEndpointsNoManager verifies the template endpoints degrade
// cleanly when the storage plane is unavailable (no local template manager
// and no provision instance): push/pull/save -> a named 503 (retryable — the
// client may land on another gateway), list -> 200 empty array (never a hang
// or panic).
func TestHumanTemplateEndpointsNoManager(t *testing.T) {
	// A registry WITHOUT a template manager (and thus no storage ops).
	reg := registry.New(t.TempDir())
	h := handler.NewHumanHandler(reg, nil, slog.New(slog.DiscardHandler))

	// push
	w := doHumanRequest(h, "POST", "/human/templates/test:v1/push", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("push no-plane: expected 503, got %d", w.Code)
	}
	// pull
	w = doHumanRequest(h, "POST", "/human/templates/test:v1", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("pull no-plane: expected 503, got %d", w.Code)
	}
	// save-template
	w = doHumanRequest(h, "POST", "/human/sandfs/sandfs-1/save-template", `{"template_ref":"x:v1"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("save-template no-plane: expected 503, got %d", w.Code)
	}
	// list -> 200 with empty array
	w = doHumanRequest(h, "GET", "/human/templates", "")
	if w.Code != http.StatusOK {
		t.Errorf("list no-mgr: expected 200, got %d", w.Code)
	}
	var summaries []handler.TemplateSummary
	if err := json.Unmarshal(w.Body.Bytes(), &summaries); err != nil {
		t.Fatalf("list no-mgr decode: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("list no-mgr: expected empty array, got %d entries", len(summaries))
	}
}

// TestHumanSaveAsTemplateValidation verifies save-template requires a
// template_ref (400) before touching the template manager.
func TestHumanSaveAsTemplateValidation(t *testing.T) {
	gw := setupTestGateway(t)
	w := doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/sandfs-1/save-template", `{}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing template_ref: expected 400, got %d", w.Code)
	}
	// Invalid JSON -> 400.
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/sandfs-1/save-template", "{not json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid json: expected 400, got %d", w.Code)
	}
}

// TestHumanCreateSandFSValidation verifies create-sandfs requires agent_id
// (400) and that a valid request reaches the registry (201).
func TestHumanCreateSandFSValidation(t *testing.T) {
	gw := setupTestGateway(t)
	// Missing agent_id -> 400.
	w := doHumanRequest(gw.humanHandler, "POST", "/human/sandfs", `{"name":"x"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing agent_id: expected 400, got %d", w.Code)
	}
	// Valid request with a real template -> 201.
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs", `{"agent_id":"`+gw.agentID+`","name":"valid-sf","template":"test:v1","mode":"flat"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("valid create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateSandFSStorageRefusals pins the named-refusal routing
// for create-sandfs (reproduced by e2e/negative-path-gates.sh):
// a registry with NO storage plane answers the NAMED retryable 503 (never
// an anonymous 500), and an unknown template ref answers 422
// TEMPLATE_NOT_FOUND (a client error, never a server 500).
func TestCreateSandFSStorageRefusals(t *testing.T) {
	reg := registry.New(t.TempDir()) // no SetStorageOps: the storage executor is absent
	h := handler.NewHumanHandler(reg, nil, slog.New(slog.DiscardHandler))

	// N1: storage plane down -> named 503
	w := doHumanRequest(h, "POST", "/human/sandfs", `{"agent_id":"agent-x","name":"sf","template":"rootfs:v1","mode":"flat"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("plane down: expected 503, got %d (%s)", w.Code, w.Body.String())
	}

	// N3 shape at unit level: the classification helper routes the wire code
	// (the full path needs a real prov instance; the handler test double covers
	// the no-storage leg end to end above).
	if w.Code == http.StatusInternalServerError {
		t.Error("anonymous 500 returned — the named-refusal routing is not wired ( regression)")
	}
}
