// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

// Tenancy/isolation pins for the human handler: cross-tenant id disclosure in
// the TEMPLATE_IN_USE refusal, the force-delete ops gate, the drain-wait
// ceiling, and the named VOLUME_IDENTITY_MISMATCH mapping.

package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway/authn"
	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/storage"
)

// doHumanRequestAs issues a request whose context carries verified token
// claims with the given scopes (the shape the OIDC middleware installs).
func doHumanRequestAs(h *handler.HumanHandler, scopes []string, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &authn.TokenClaims{
		Subject: "test-subject",
		Scopes:  scopes,
		Raw:     map[string]any{authn.NamespaceClaim: []any{authn.NamespaceWildcard}},
	}
	req = req.WithContext(authn.WithTokenClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// templateInUseBody is the 409 payload shape under test.
type templateInUseBody struct {
	Error      string   `json:"error"`
	Code       string   `json:"error_code"`
	Count      int      `json:"in_use_count"`
	Sample     []string `json:"in_use_sample"`
	HasSamples bool     `json:"-"`
}

func decodeTemplateInUse(t *testing.T, body string) templateInUseBody {
	t.Helper()
	var parsed templateInUseBody
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("decode 409 body: %v (%s)", err, body)
	}
	parsed.HasSamples = strings.Contains(body, "in_use_sample")
	return parsed
}

// TestTemplateInUseSampleScopeGated pins the isolation rule: the
// TEMPLATE_IN_USE 409 always carries the COUNT, but the sampled sandfs ids —
// the fleet census the uniform-404 rule exists to keep non-free —
// appear ONLY for a caller carrying an ops/admin scope. A tenant token must
// learn nothing beyond "N sandfs hold this ref".
func TestTemplateInUseSampleScopeGated(t *testing.T) {
	gw := setupTestGateway(t)
	rec, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
		Name: "holds-template", Template: "test:v1", Mode: "overlay",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Human-only token: template mutation is ops/admin. The refusal happens
	// before any in-use state is consulted, so there is no in-use oracle at
	// all (not even the count).
	w := doHumanRequestAs(gw.humanHandler, []string{authn.ScopeHuman}, "DELETE", "/human/templates/test:v1", `{}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant in-use delete: expected 403, got %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "TEMPLATE_IN_USE") || strings.Contains(body, "in_use_count") ||
		strings.Contains(body, "in_use_sample") || strings.Contains(body, rec.ID) {
		t.Fatalf("tenant refusal leaks in-use state: %s", body)
	}

	// Ops token: count + sample (the fleet-operations view).
	w = doHumanRequestAs(gw.humanHandler, []string{authn.ScopeHuman, authn.ScopeOps}, "DELETE", "/human/templates/test:v1", `{}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("ops in-use delete: expected 409, got %d (%s)", w.Code, w.Body.String())
	}
	ops := decodeTemplateInUse(t, w.Body.String())
	if ops.Count < 1 || len(ops.Sample) == 0 {
		t.Fatalf("ops 409 must carry count + sample: %s", w.Body.String())
	}
	if ops.Sample[0] != rec.ID {
		t.Fatalf("ops sample = %v, want %q", ops.Sample, rec.ID)
	}

	// Passthrough (no OIDC claims — single-node shape): historical full
	// payload preserved.
	w = doHumanRequest(gw.humanHandler, "DELETE", "/human/templates/test:v1", `{}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("passthrough in-use delete: expected 409, got %d (%s)", w.Code, w.Body.String())
	}
	if passthrough := decodeTemplateInUse(t, w.Body.String()); len(passthrough.Sample) == 0 {
		t.Fatalf("passthrough 409 lost its sample: %s", w.Body.String())
	}

	// Layer 2 (node-side marker scan): an orphan volume whose record is gone.
	orphan := filepath.Join(gw.reg.VolRoot(), "sf-orphan000000")
	if err := os.MkdirAll(orphan, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, ".template"), []byte("orphan:v9"), 0o644); err != nil {
		t.Fatal(err)
	}
	w = doHumanRequestAs(gw.humanHandler, []string{authn.ScopeHuman}, "DELETE", "/human/templates/orphan:v9", `{}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant orphan-volume delete: expected 403, got %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "in_use_sample") || strings.Contains(w.Body.String(), "in_use_count") {
		t.Fatalf("tenant 403 leaks in-use state: %s", w.Body.String())
	}
}

// TestDeleteTemplateForceRequiresOps pins the rule: force-skipping the
// in-use check is an operator escape hatch, gated on the ops scope. A tenant
// token sending force:true gets a named 403 — identical whether or not any
// volume holds the ref (no in-use oracle) — and the non-force path is
// unchanged.
func TestDeleteTemplateForceRequiresOps(t *testing.T) {
	gw := setupTestGateway(t)
	_, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
		Name: "holds-template", Template: "test:v1", Mode: "overlay",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Human-only token: template mutation (force or not) is ops/admin. The
	// generic refusal is identical whether or not the ref is in use, so a
	// human caller learns nothing about in-use state.
	w := doHumanRequestAs(gw.humanHandler, []string{authn.ScopeHuman}, "DELETE", "/human/templates/test:v1", `{"force":true}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant force delete: expected 403, got %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "TEMPLATE_IN_USE") || strings.Contains(w.Body.String(), "in_use_count") ||
		strings.Contains(w.Body.String(), "in_use_sample") {
		t.Fatalf("force refusal must not reveal in-use state: %s", w.Body.String())
	}

	// Tenant + force, ref NOT in use: identical refusal (no oracle).
	w = doHumanRequestAs(gw.humanHandler, []string{authn.ScopeHuman}, "DELETE", "/human/templates/unused:v9", `{"force":true}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant force delete (unused ref): expected 403, got %d (%s)", w.Code, w.Body.String())
	}

	// Tenant non-force: also the ops gate, not an in-use response.
	w = doHumanRequestAs(gw.humanHandler, []string{authn.ScopeHuman}, "DELETE", "/human/templates/test:v1", `{}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant non-force delete: expected 403, got %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "TEMPLATE_IN_USE") || strings.Contains(w.Body.String(), "in_use_count") {
		t.Fatalf("non-force refusal must not reveal in-use state: %s", w.Body.String())
	}

	// Ops + force: proceeds (the escape hatch stays reachable).
	w = doHumanRequestAs(gw.humanHandler, []string{authn.ScopeHuman, authn.ScopeOps}, "DELETE", "/human/templates/test:v1", `{"force":true}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("ops force delete: expected 204, got %d (%s)", w.Code, w.Body.String())
	}
}

// budgetRecordingDrainer observes the drain budget the handler applies and
// reports "not settled", so the endpoints answer 202 immediately instead of
// blocking for the budget.
type budgetRecordingDrainer struct {
	budgets []time.Duration
}

func (d *budgetRecordingDrainer) Drain(_, _, _ string, budget time.Duration) bool {
	d.budgets = append(d.budgets, budget)
	return false
}

// maxDrainWaitSecPinned is the documented drain ceiling: the human listeners'
// write deadline is 11 min, so a larger budget could never deliver a response
// and would only keep the sandfs pinned in "detaching".
const maxDrainWaitSecPinned = 600 * time.Second

// TestDrainWaitSecClamped pins the rule: a huge wait_sec cannot hold a
// handler goroutine (or the sandfs's "detaching" pin) past the ceiling — the
// budget handed to the drain primitive and echoed in the response is the
// CLAMPED value, on both detach and swap.
func TestDrainWaitSecClamped(t *testing.T) {
	gw := setupTestGateway(t)
	fake := &budgetRecordingDrainer{}
	gw.humanHandler.SetDrainer(fake)

	mkSandfs := func(name string) string {
		t.Helper()
		rec, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
			Name: name, Template: "test:v1", Mode: "overlay",
		})
		if err != nil {
			t.Fatal(err)
		}
		return rec.ID
	}
	decode := func(w *httptest.ResponseRecorder) (string, int) {
		t.Helper()
		var resp struct {
			Status  string `json:"status"`
			WaitSec int    `json:"wait_sec"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode lifecycle body: %v (%s)", err, w.Body.String())
		}
		return resp.Status, resp.WaitSec
	}

	// detach-template with a day-long wait_sec: 202, clamped echo + budget.
	id := mkSandfs("clamp-detach")
	w := doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+id+"/detach-template", `{"wait_sec":86400}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("detach: expected 202, got %d (%s)", w.Code, w.Body.String())
	}
	status, echoed := decode(w)
	if status != identity.SandfsStatusDetaching {
		t.Fatalf("detach status = %q, want detaching", status)
	}
	if echoed != int(maxDrainWaitSecPinned/time.Second) {
		t.Fatalf("detach response wait_sec = %d, want the clamped %d", echoed, maxDrainWaitSecPinned/time.Second)
	}
	if len(fake.budgets) != 1 || fake.budgets[0] != maxDrainWaitSecPinned {
		t.Fatalf("detach drain budgets = %v, want one %v (the clamp must reach the drain)", fake.budgets, maxDrainWaitSecPinned)
	}

	// swap-template takes the same route.
	id = mkSandfs("clamp-swap")
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+id+"/swap-template", `{"template_ref":"test:v2","wait_sec":86400}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("swap: expected 202, got %d (%s)", w.Code, w.Body.String())
	}
	if _, echoed := decode(w); echoed != int(maxDrainWaitSecPinned/time.Second) {
		t.Fatalf("swap response wait_sec = %d, want the clamped %d", echoed, maxDrainWaitSecPinned/time.Second)
	}
	if len(fake.budgets) != 2 || fake.budgets[1] != maxDrainWaitSecPinned {
		t.Fatalf("swap drain budgets = %v, want a second %v", fake.budgets, maxDrainWaitSecPinned)
	}

	// 0/unset keeps the 15s default — and the response reports it.
	id = mkSandfs("clamp-default")
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+id+"/detach-template", `{}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("default detach: expected 202, got %d (%s)", w.Code, w.Body.String())
	}
	if _, echoed := decode(w); echoed != 15 {
		t.Fatalf("default detach wait_sec = %d, want 15", echoed)
	}
	if len(fake.budgets) != 3 || fake.budgets[2] != 15*time.Second {
		t.Fatalf("default drain budgets = %v, want a third 15s", fake.budgets)
	}
}

// failOps forces the two op classes that can raise VOLUME_IDENTITY_MISMATCH;
// every other storage op forwards to the double.
type failOps struct {
	storage.Ops
	ensureErr error
	deleteErr error
}

func (f failOps) EnsureVolume(ctx context.Context, sandfsID, mode, templateRef string, volumeEpoch ...string) (*storage.EnsureResult, error) {
	if f.ensureErr != nil {
		return nil, f.ensureErr
	}
	return f.Ops.EnsureVolume(ctx, sandfsID, mode, templateRef)
}

func (f failOps) DeleteVolume(sandfsID string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.Ops.DeleteVolume(sandfsID)
}

// TestVolumeIdentityMismatchMapped pins the mapping contract: the
// node's VOLUME_IDENTITY_MISMATCH class surfaces as a named 409 with a fixed
// message — never a raw 500 carrying the node's text (which embeds the host
// volume path and, in the cross-tenant divergence case, a FOREIGN sandfs id).
func TestVolumeIdentityMismatchMapped(t *testing.T) {
	gw := setupTestGateway(t)
	// The text below is the shape volume.go builds: seed-derived volume name,
	// foreign sandfs id, absolute host path.
	raw := "VOLUME_IDENTITY_MISMATCH: volume /var/lib/sandswap/volumes/sf-aa11bb22cc33 is stamped for sandfs-deadbeef, not sandfs-cafef00d"
	leaks := []string{"/var/lib/sandswap", "sf-aa11bb22cc33", "sandfs-deadbeef", "sandfs-cafef00d"}

	assertMapped := func(w *httptest.ResponseRecorder, action string) {
		t.Helper()
		if w.Code != http.StatusConflict {
			t.Fatalf("%s: expected 409 for VOLUME_IDENTITY_MISMATCH, got %d (%s)", action, w.Code, w.Body.String())
		}
		var resp struct {
			Error string `json:"error"`
			Code  string `json:"error_code"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: decode body: %v (%s)", action, err, w.Body.String())
		}
		if resp.Code != "VOLUME_IDENTITY_MISMATCH" {
			t.Fatalf("%s: error_code = %q, want VOLUME_IDENTITY_MISMATCH (body %s)", action, resp.Code, w.Body.String())
		}
		for _, leak := range leaks {
			if strings.Contains(w.Body.String(), leak) {
				t.Fatalf("%s: 409 body leaks node-internal %q: %s", action, leak, w.Body.String())
			}
		}
	}

	// Create route (EnsureVolume).
	gw.reg.SetStorageOps(failOps{Ops: gw.storage, ensureErr: errors.New(raw)})
	body := `{"agent_id":"` + gw.agentID + `","name":"mismatch","template":"test:v1","mode":"overlay"}`
	w := doHumanRequest(gw.humanHandler, "POST", "/human/sandfs", body)
	assertMapped(w, "create")

	// SandFS-delete route (DeleteVolume raises the same class; the error
	// arrives wrapped by registry.Delete — the mapping must survive that).
	gw2 := setupTestGateway(t)
	id := createTestSandFS(t, gw2, "mismatch-delete")
	gw2.humanHandler.SetDrainer(&lease.Drainer{Pool: gw2.pm, Lease: gw2.lm, Logger: nil})
	gw2.reg.SetStorageOps(failOps{Ops: gw2.storage, deleteErr: errors.New(raw)})
	w = doHumanRequest(gw2.humanHandler, "DELETE", "/human/sandfs/"+id, "")
	assertMapped(w, "delete sandfs")
}
