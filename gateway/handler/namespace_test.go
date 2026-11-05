// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, your use of this software will be
// governed by the Apache License, Version 2.0.

package handler_test

// Namespace enforcement matrix — the two rules of the human-API tenancy
// surface (docs/how-it-works/namespaces.md):
//
//	Rule 1 (path grant):  ns in claim set or "*" — else 403 NAMESPACE_FORBIDDEN
//	Rule 2 (record match): record ns == path ns — else uniform 404
//	                     (missing == foreign == cross-ns: no oracle)
//	Fleet gate:           unscoped /human/agent* + /human/sandfs* need "*"
//	Passthrough:          no OIDC ⇒ fleet — existing deployments unchanged
//
// Each guard below is RED-verified by disabling it (see the ledger row).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/authn"
	"gateway/handler"
	"gateway/identity"
)

// nsClaims builds verified-claims with the given namespace grant values
// (nil slice ⇒ an authenticated token carrying NO sandswap_ns claim).
func nsClaims(grants ...string) *authn.TokenClaims {
	claims := &authn.TokenClaims{Subject: "test-user"}
	if grants != nil {
		var arr []any
		for _, g := range grants {
			arr = append(arr, g)
		}
		claims.Raw = map[string]any{authn.NamespaceClaim: arr}
	}
	return claims
}

// doNSRequest drives the human handler with (optionally) claims attached.
// claims == nil is the OIDC-passthrough shape (no context value at all).
func doNSRequest(h *handler.HumanHandler, method, path, body string, claims *authn.TokenClaims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if claims != nil {
		req = req.WithContext(authn.WithTokenClaims(req.Context(), claims))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// nsCreateFlatSandfs materializes a flat sandfs through the REAL registry
// path (storage double underneath) for an already-namespace-stamped agent.
func nsCreateFlatSandfs(t *testing.T, gw *testGateway, agentID, name string) *identity.Record {
	t.Helper()
	rec, _, err := gw.reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name:        name,
		Description: "ns test sandfs",
		Template:    "test:v1",
		Mode:        "flat",
	})
	if err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	return rec
}

// TestNamespaceRule1 pins the path-grant rule on the subtree: an in-grant ns
// passes, an out-of-grant ns is 403 NAMESPACE_FORBIDDEN, an authenticated
// token with NO namespace claim is denied everywhere (empty claim ⇒ refuse),
// and the ANONYMOUS passthrough is denied too(: no identity means no
// namespace grants — the namespaced surface never resolves anonymous as
// fleet).
func TestNamespaceRule1(t *testing.T) {
	gw := setupTestGateway(t)

	// tenant "acme"
	acme := nsClaims("acme")
	if w := doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/agent", "", acme); w.Code != http.StatusOK {
		t.Errorf("acme GET own ns agents: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if w := doNSRequest(gw.humanHandler, "GET", "/human/ns/beta/agent", "", acme); w.Code != http.StatusForbidden {
		t.Errorf("acme GET beta agents: expected 403, got %d (%s)", w.Code, w.Body.String())
	} else if !strings.Contains(w.Body.String(), "NAMESPACE_FORBIDDEN") {
		t.Errorf("403 body must carry NAMESPACE_FORBIDDEN, got %s", w.Body.String())
	}

	// authenticated, no sandswap_ns claim ⇒ empty grant set ⇒ refused
	if w := doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/agent", "", nsClaims()); w.Code != http.StatusForbidden {
		t.Errorf("empty claim on acme: expected 403, got %d", w.Code)
	}
	if w := doNSRequest(gw.humanHandler, "GET", "/human/ns/default/agent", "", nsClaims()); w.Code != http.StatusForbidden {
		t.Errorf("empty claim on default: expected 403, got %d", w.Code)
	}

	// wildcard ⇒ every namespace
	if w := doNSRequest(gw.humanHandler, "GET", "/human/ns/beta/agent", "", nsClaims("*")); w.Code != http.StatusOK {
		t.Errorf("wildcard GET beta: expected 200, got %d", w.Code)
	}

	// passthrough (no claims value at all — the no-OIDC shape) ⇒ DENIED on
	// the namespaced surface with the same uniform refusal(). The
	// unscoped fleet gate keeps its passthrough=fleet behavior — pinned by
	// TestNamespaceFleetGate.
	if w := doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/agent", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("anonymous GET acme: expected 403 (no identity ⇒ no namespace grants), got %d (%s)", w.Code, w.Body.String())
	} else if !strings.Contains(w.Body.String(), "NAMESPACE_FORBIDDEN") {
		t.Errorf("anonymous refusal must be the uniform NAMESPACE_FORBIDDEN, got %s", w.Body.String())
	}

	// malformed namespace in the path ⇒ 400, before any grant logic
	// ("a" alone is LEGAL — a DNS-label grammar allows single characters)
	for _, bad := range []string{"Acme", "1abc", "a_b", "ns-with-" + strings.Repeat("x", 60)} {
		if w := doNSRequest(gw.humanHandler, "GET", "/human/ns/"+bad+"/agent", "", nil); w.Code != http.StatusBadRequest {
			t.Errorf("invalid ns %q: expected 400, got %d", bad, w.Code)
		}
	}
	// Empty ns segments are 400s; the bare prefix (no trailing slash, no
	// namespace) simply matches no route — a 404.
	for _, p := range []string{"/human/ns/", "/human/ns//agent"} {
		if w := doNSRequest(gw.humanHandler, "GET", p, "", nil); w.Code != http.StatusBadRequest {
			t.Errorf("path %q: expected 400, got %d", p, w.Code)
		}
	}
	if w := doNSRequest(gw.humanHandler, "GET", "/human/ns", "", nil); w.Code != http.StatusNotFound {
		t.Errorf("bare /human/ns: expected 404, got %d", w.Code)
	}
}

// TestNamespaceRule2 pins the record-match rule: a record in another
// namespace answers the SAME uniform 404 as a missing id — no existence
// oracle across tenants (the pattern, extended to tenancy).
func TestNamespaceRule2(t *testing.T) {
	gw := setupTestGateway(t)
	store := gw.reg.Store()

	// Two tenants, one sandfs each (flat template from the fixture).
	acmeAgent, _, err := store.CreateAgent(identity.CreateAgentRequest{Name: "acme-agent", Namespace: "acme"})
	if err != nil {
		t.Fatalf("create acme agent: %v", err)
	}
	acmeRec := nsCreateFlatSandfs(t, gw, acmeAgent.ID, "acme-sf")

	missing := doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/sandfs/sandfs-missing", "", nsClaims("acme"))
	crossNS := doNSRequest(gw.humanHandler, "GET", "/human/ns/beta/sandfs/"+acmeRec.ID, "", nsClaims("beta"))
	if crossNS.Code != http.StatusNotFound || missing.Code != http.StatusNotFound {
		t.Fatalf("cross-ns=%d missing=%d: both must be 404", crossNS.Code, missing.Code)
	}
	if crossNS.Body.String() != missing.Body.String() {
		t.Errorf("cross-ns 404 body must equal missing-id 404 body:\n cross=%s\n missing=%s", crossNS.Body.String(), missing.Body.String())
	}

	// The same uniformity holds for DELETE and the template actions; the
	// DELETE cross-ns must NOT tear down the volume.
	if w := doNSRequest(gw.humanHandler, "DELETE", "/human/ns/beta/sandfs/"+acmeRec.ID, "", nsClaims("beta")); w.Code != http.StatusNotFound {
		t.Errorf("cross-ns DELETE: expected 404, got %d", w.Code)
	}
	if w := doNSRequest(gw.humanHandler, "POST", "/human/ns/beta/sandfs/"+acmeRec.ID+"/detach-template", "{}", nsClaims("beta")); w.Code != http.StatusNotFound {
		t.Errorf("cross-ns detach: expected 404, got %d", w.Code)
	}
	if rec, err := store.GetSandFS(acmeRec.ID); err != nil || rec == nil {
		t.Errorf("acme sandfs must survive the cross-ns probes: %v", err)
	}

	// Agents: cross-ns agent delete is uniform 404 too.
	if w := doNSRequest(gw.humanHandler, "DELETE", "/human/ns/beta/agent/"+acmeAgent.ID, "", nsClaims("beta")); w.Code != http.StatusNotFound {
		t.Errorf("cross-ns agent DELETE: expected 404, got %d", w.Code)
	}
	if a, err := store.(identity.PagedLister).GetAgent(acmeAgent.ID); err != nil || a == nil {
		t.Errorf("acme agent must survive the cross-ns delete: %v", err)
	}

	// In-namespace access works through the ns path.
	if w := doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/sandfs/"+acmeRec.ID, "", nsClaims("acme")); w.Code != http.StatusOK {
		t.Errorf("in-ns get: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestNamespaceFleetGate pins the unscoped-surface rule: with OIDC active,
// /human/agent* and /human/sandfs* require "*"; templates stay cluster-level
// (NOT namespace-gated); passthrough keeps the historical behavior.
func TestNamespaceFleetGate(t *testing.T) {
	gw := setupTestGateway(t)

	tenant := nsClaims("acme")
	for _, path := range []string{"/human/agent", "/human/sandfs", "/human/agent/some-id", "/human/sandfs/some-id"} {
		method := "GET"
		if strings.Contains(path, "some-id") && strings.HasPrefix(path, "/human/agent") {
			method = "DELETE" // agent subtree has no per-id GET
		}
		if w := doNSRequest(gw.humanHandler, method, path, "", tenant); w.Code != http.StatusForbidden {
			t.Errorf("tenant on %s: expected 403, got %d", path, w.Code)
		} else if !strings.Contains(w.Body.String(), "FLEET_SCOPE_REQUIRED") {
			t.Errorf("fleet refusal must carry FLEET_SCOPE_REQUIRED, got %s", w.Body.String())
		}
	}

	// Templates are cluster-scoped: a tenant with the human scope reaches
	// them (their own scope rules apply; namespace is deliberately not an
	// axis there).
	if w := doNSRequest(gw.humanHandler, "GET", "/human/templates", "", tenant); w.Code != http.StatusOK {
		t.Errorf("tenant GET templates: expected 200, got %d", w.Code)
	}

	// Unscoped agent CRUD is ops/admin: a wildcard human namespace grant is
	// not an ops grant. Passthrough (no claims) is the anonymous dev shape and
	// keeps its historical behavior.
	if w := doNSRequest(gw.humanHandler, "GET", "/human/agent", "", nsClaims("*")); w.Code != http.StatusForbidden {
		t.Errorf("wildcard human GET /human/agent: expected 403, got %d", w.Code)
	}
	ops := nsClaims("*")
	ops.Scopes = []string{authn.ScopeOps}
	if w := doNSRequest(gw.humanHandler, "GET", "/human/agent", "", ops); w.Code != http.StatusOK {
		t.Errorf("wildcard ops GET /human/agent: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if w := doNSRequest(gw.humanHandler, "GET", "/human/agent", "", nil); w.Code != http.StatusOK {
		t.Errorf("passthrough GET /human/agent: expected 200, got %d", w.Code)
	}
}

// TestNamespaceCreateAndList pins creation stamping (agent gets the path ns;
// sandfs freezes the agent's ns) and the per-namespace listing partition.
func TestNamespaceCreateAndList(t *testing.T) {
	gw := setupTestGateway(t)
	store := gw.reg.Store()

	// Agent create through the ns path stamps the namespace.
	w := doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/agent", `{"name":"acme-1"}`, nsClaims("acme"))
	if w.Code != http.StatusCreated {
		t.Fatalf("ns agent create: expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	var created struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	a, err := store.(identity.PagedLister).GetAgent(created.AgentID)
	if err != nil || a == nil {
		t.Fatalf("get created agent: %v", err)
	}
	if a.Namespace != "acme" {
		t.Errorf("agent namespace: expected acme, got %q", a.Namespace)
	}

	// SandFS create in the ns path freezes the agent's namespace and
	// materializes through the registry (storage double).
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/sandfs",
		`{"agent_id":"`+created.AgentID+`","name":"sf","template":"test:v1","mode":"flat"}`, nsClaims("acme"))
	if w.Code != http.StatusCreated {
		t.Fatalf("ns sandfs create: expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	var sf struct {
		SandfsID string `json:"sandfs_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &sf); err != nil {
		t.Fatalf("decode sandfs create: %v", err)
	}
	rec, err := store.GetSandFS(sf.SandfsID)
	if err != nil || rec == nil {
		t.Fatalf("get created sandfs: %v", err)
	}
	if rec.Namespace != "acme" {
		t.Errorf("sandfs namespace: expected acme, got %q", rec.Namespace)
	}

	// A beta tenant naming an ACME agent under the beta path: Rule 1 passes
	// (beta is granted), so Rule 2 decides — the cross-ns agent answers the
	// SAME uniform 404 "agent not found" as the ghost id below.
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/beta/sandfs",
		`{"agent_id":"`+created.AgentID+`","name":"sf","template":"test:v1","mode":"flat"}`, nsClaims("beta"))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "agent not found") {
		t.Errorf("cross-ns agent create: expected uniform 404, got %d (%s)", w.Code, w.Body.String())
	}

	// Cross-namespace agent id under an IN-GRANT path: uniform 404.
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/sandfs",
		`{"agent_id":"agent-ghost","name":"sf","template":"test:v1","mode":"flat"}`, nsClaims("acme"))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "agent not found") {
		t.Errorf("ghost agent create: expected uniform 404 agent not found, got %d (%s)", w.Code, w.Body.String())
	}

	// Listing partition: acme sees only acme; the legacy agent (fixture's
	// default-agent) is legacy-empty ⇒ reads as "default", invisible to acme.
	w = doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/agent", "", nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("acme agent list: %d", w.Code)
	}
	var agentPage struct {
		Items []*identity.Agent `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &agentPage); err != nil {
		t.Fatalf("decode agent page: %v", err)
	}
	if len(agentPage.Items) != 1 || agentPage.Items[0].Namespace != "acme" {
		t.Errorf("acme agent page: expected exactly the acme agent, got %+v", agentPage.Items)
	}

	w = doNSRequest(gw.humanHandler, "GET", "/human/ns/default/agent", "", nsClaims("*"))
	if w.Code != http.StatusOK {
		t.Fatalf("default agent list: %d", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &agentPage); err != nil {
		t.Fatalf("decode default page: %v", err)
	}
	if len(agentPage.Items) == 0 {
		t.Error("default ns must surface the legacy fixture agent (empty ns reads as default)")
	}
	for _, it := range agentPage.Items {
		if it.NamespaceOrDefault() != identity.DefaultNamespace {
			t.Errorf("default page leaked non-default agent %s (ns=%q)", it.ID, it.Namespace)
		}
	}
}

// TestNamespaceSandfsListingPartition pins the sandfs listing partition and
// pagination shape on the ns path.
func TestNamespaceSandfsListingPartition(t *testing.T) {
	gw := setupTestGateway(t)
	store := gw.reg.Store()

	betaAgent, _, err := store.CreateAgent(identity.CreateAgentRequest{Name: "beta-agent", Namespace: "beta"})
	if err != nil {
		t.Fatalf("create beta agent: %v", err)
	}
	_ = nsCreateFlatSandfs(t, gw, betaAgent.ID, "beta-sf")

	// beta list shows only beta sandfs; default list shows only default ones.
	w := doNSRequest(gw.humanHandler, "GET", "/human/ns/beta/sandfs", "", nsClaims("beta"))
	if w.Code != http.StatusOK {
		t.Fatalf("beta sandfs list: %d", w.Code)
	}
	var page struct {
		Items []*identity.Record `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("beta page: expected 1 sandfs, got %d", len(page.Items))
	}
	for _, rec := range page.Items {
		if rec.NamespaceOrDefault() != "beta" {
			t.Errorf("beta page leaked ns=%q record", rec.Namespace)
		}
	}
}
