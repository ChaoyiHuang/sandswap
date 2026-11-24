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
	"time"

	"gateway/authn"
	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
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

// TestNamespaceSandfsHidesStorageFields pins the namespace surface's view of
// a SandFS: create, list and get never carry rootfs_path (the host volume
// directory — operator storage layout) or volume_epoch (the mount-identity
// secret), on any ns path. The fleet admin surface keeps rootfs_path (it is
// the documented create contract), and the maintenance route that rewrites
// it is not namespace-addressable at all.
func TestNamespaceSandfsHidesStorageFields(t *testing.T) {
	gw := setupTestGateway(t)

	w := doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/agent", `{"name":"acme-1"}`, nsClaims("acme"))
	if w.Code != http.StatusCreated {
		t.Fatalf("ns agent create: %d (%s)", w.Code, w.Body.String())
	}
	var ag struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ag); err != nil {
		t.Fatalf("decode agent: %v", err)
	}

	// create: the response must not carry either storage field, but must
	// still carry what a tenant needs to use the sandbox.
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/sandfs",
		`{"agent_id":"`+ag.AgentID+`","name":"sf","template":"test:v1","mode":"flat","vcpus":2,"memory_mb":512}`, nsClaims("acme"))
	if w.Code != http.StatusCreated {
		t.Fatalf("ns sandfs create: %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, hidden := range []string{"rootfs_path", "volume_epoch"} {
		if strings.Contains(body, hidden) {
			t.Errorf("ns create response leaks %q: %s", hidden, body)
		}
	}
	var created struct {
		SandfsID    string `json:"sandfs_id"`
		AgentID     string `json:"agent_id"`
		Name        string `json:"name"`
		Template    string `json:"template"`
		Mode        string `json:"mode"`
		MinVCPUs    uint32 `json:"min_vcpus"`
		MinMemoryMB uint64 `json:"min_memory_mb"`
		Namespace   string `json:"namespace"`
		PullStatus  string `json:"pull_status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.SandfsID == "" || created.AgentID != ag.AgentID || created.Name != "sf" || created.Template != "test:v1" || created.Mode != "flat" {
		t.Errorf("ns create view lost tenant fields: %+v", created)
	}
	if created.MinVCPUs != 2 || created.MinMemoryMB != 512 || created.Namespace != "acme" {
		t.Errorf("ns create view resource/namespace fields: %+v", created)
	}
	if created.PullStatus == "" {
		t.Errorf("ns create view should still carry pull_status: %+v", created)
	}

	// get single
	w = doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/sandfs/"+created.SandfsID, "", nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("ns sandfs get: %d (%s)", w.Code, w.Body.String())
	}
	for _, hidden := range []string{"rootfs_path", "volume_epoch"} {
		if strings.Contains(w.Body.String(), hidden) {
			t.Errorf("ns get response leaks %q: %s", hidden, w.Body.String())
		}
	}
	var got struct {
		SandfsID  string `json:"sandfs_id"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.SandfsID != created.SandfsID || got.CreatedAt == "" {
		t.Errorf("ns get view: %+v err=%v", got, err)
	}
	if _, err := time.Parse(time.RFC3339Nano, got.CreatedAt); err != nil {
		t.Errorf("ns get created_at is not RFC 3339: %q (%v)", got.CreatedAt, err)
	}

	// list
	w = doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/sandfs", "", nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("ns sandfs list: %d (%s)", w.Code, w.Body.String())
	}
	for _, hidden := range []string{"rootfs_path", "volume_epoch"} {
		if strings.Contains(w.Body.String(), hidden) {
			t.Errorf("ns list response leaks %q: %s", hidden, w.Body.String())
		}
	}
	var page struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 1 {
		t.Fatalf("ns list: %d items err=%v", len(page.Items), err)
	}
	if page.Items[0]["sandfs_id"] != created.SandfsID {
		t.Errorf("ns list item id: %+v", page.Items[0])
	}

	// The volume repoint on the ns surface is ops scope — the handler's own
	// requireOpsScope gate: a human-only namespace token gets 403 and the
	// stored path is untouched.
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/sandfs/"+created.SandfsID+"/rootfs-path",
		`{"rootfs_path":"/var/lib/sandswap/volumes/sf-hijack"}`, nsClaims("acme"))
	if w.Code != http.StatusForbidden {
		t.Errorf("ns rootfs-path rewrite by a human-only token: expected 403, got %d (%s)", w.Code, w.Body.String())
	}
	rec, err := gw.reg.Store().GetSandFS(created.SandfsID)
	if err != nil || rec == nil {
		t.Fatalf("get record: %v", err)
	}
	if strings.Contains(rec.RootFSPath, "hijack") || rec.RootFSPath == "" {
		t.Errorf("refused ns rootfs-path rewrite changed the stored path: %q", rec.RootFSPath)
	}

	// The fleet admin surface still returns rootfs_path: documented contract.
	w = doNSRequest(gw.humanHandler, "GET", "/human/sandfs/"+created.SandfsID, "", nsClaims("*"))
	if w.Code != http.StatusOK {
		t.Fatalf("fleet get: %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"rootfs_path":"`+rec.RootFSPath+`"`) {
		t.Errorf("fleet get must still carry rootfs_path %q: %s", rec.RootFSPath, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"volume_epoch":"`+rec.VolumeEpoch+`"`) {
		t.Errorf("fleet get must still carry volume_epoch %q: %s", rec.VolumeEpoch, w.Body.String())
	}
	w = doNSRequest(gw.humanHandler, "GET", "/human/sandfs", "", nsClaims("*"))
	if w.Code != http.StatusOK {
		t.Fatalf("fleet list: %d (%s)", w.Code, w.Body.String())
	}
	for _, keep := range []string{`"rootfs_path":"` + rec.RootFSPath + `"`, `"volume_epoch":"` + rec.VolumeEpoch + `"`} {
		if !strings.Contains(w.Body.String(), keep) {
			t.Errorf("fleet list must still carry %s: %s", keep, w.Body.String())
		}
	}
}

// topLevelKeys decodes a JSON object into its top-level fields.
func topLevelKeys(t *testing.T, what string, body []byte) map[string]json.RawMessage {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("%s: decode JSON object: %v (%s)", what, err, body)
	}
	return obj
}

// assertExactlyKeys pins the complete response shape: extra keys are the
// leak this suite exists to catch, and missing keys are a broken tenant
// contract.
func assertExactlyKeys(t *testing.T, what string, obj map[string]json.RawMessage, want ...string) {
	t.Helper()
	wantSet := make(map[string]bool, len(want))
	for _, k := range want {
		wantSet[k] = true
	}
	for k := range obj {
		if !wantSet[k] {
			t.Errorf("%s: unexpected response field %q", what, k)
		}
	}
	for k := range wantSet {
		if _, ok := obj[k]; !ok {
			t.Errorf("%s: missing response field %q", what, k)
		}
	}
}

// assertNoStorageLeak checks the encoded body for the storage-side field
// names AND the actual secret values (a field renamed without being removed
// would still leak the value).
func assertNoStorageLeak(t *testing.T, what, body string, rec *identity.Record) {
	t.Helper()
	for _, needle := range []string{"rootfs_path", "volume_epoch", rec.RootFSPath, rec.VolumeEpoch} {
		if needle == "" {
			continue
		}
		if strings.Contains(body, needle) {
			t.Errorf("%s leaks storage-side value %q: %s", what, needle, body)
		}
	}
}

// TestNamespaceAgentResponseShape pins the tenant view of an Agent: the
// namespaced create honors the description (same contract as the unscoped
// create), and the list never carries credential material.
func TestNamespaceAgentResponseShape(t *testing.T) {
	gw := setupTestGateway(t)

	w := doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/agent",
		`{"name":"acme-1","description":"  tenant operator  "}`, nsClaims("acme"))
	if w.Code != http.StatusCreated {
		t.Fatalf("ns agent create: %d (%s)", w.Code, w.Body.String())
	}
	created := topLevelKeys(t, "ns agent create", w.Body.Bytes())
	assertExactlyKeys(t, "ns agent create", created, "agent_id", "api_key", "name", "description")
	if strings.TrimSpace(string(created["description"])) != `"tenant operator"` || strings.TrimSpace(string(created["name"])) != `"acme-1"` {
		t.Errorf("ns agent create body: %s", w.Body.String())
	}
	var agentID string
	if err := json.Unmarshal(created["agent_id"], &agentID); err != nil || agentID == "" {
		t.Fatalf("decode agent_id: %v", err)
	}
	a, err := gw.reg.Store().(identity.PagedLister).GetAgent(agentID)
	if err != nil || a == nil {
		t.Fatalf("get created agent: %v", err)
	}
	if a.Description != "tenant operator" {
		t.Errorf("ns create dropped/kept the wrong description: %q", a.Description)
	}

	// An over-long description is the same named 400 as the unscoped create.
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/agent",
		`{"name":"too-long","description":"`+strings.Repeat("x", identity.MaxDescriptionRunes+1)+`"}`, nsClaims("acme"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("ns agent create with over-long description: expected 400, got %d (%s)", w.Code, w.Body.String())
	}

	// List: tenant metadata only. No api_key / api_key_hash, no other fields.
	w = doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/agent", "", nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("ns agent list: %d (%s)", w.Code, w.Body.String())
	}
	var page struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 1 {
		t.Fatalf("ns agent list: %d items err=%v (%s)", len(page.Items), err, w.Body.String())
	}
	assertExactlyKeys(t, "ns agent list item", page.Items[0],
		"agent_id", "name", "description", "created_at", "namespace")
	for _, secret := range []string{"api_key", "api_key_hash", "sk-sandswap-agent-"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Errorf("ns agent list leaks credential material %q: %s", secret, w.Body.String())
		}
	}
}

// TestNamespaceSandfsRouteResponsesAreProjections drives every tenant-read
// SandFS response (create, get, list, detach, attach, swap) and pins the exact
// allow-listed field set. Storage layout (rootfs_path) and the mount-identity
// secret (volume_epoch) must never appear — not even in a lifecycle response.
func TestNamespaceSandfsRouteResponsesAreProjections(t *testing.T) {
	gw := setupTestGateway(t)
	gw.humanHandler.SetDrainer(&lease.Drainer{Pool: gw.pm, Lease: gw.lm, Logger: nil})

	w := doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/agent", `{"name":"acme-1"}`, nsClaims("acme"))
	if w.Code != http.StatusCreated {
		t.Fatalf("ns agent create: %d (%s)", w.Code, w.Body.String())
	}
	var ag struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ag); err != nil {
		t.Fatalf("decode agent: %v", err)
	}

	// Create (overlay so the lifecycle routes below are legal): tenant fields
	// present, storage fields absent.
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/sandfs",
		`{"agent_id":"`+ag.AgentID+`","name":"sf","description":"tenant sandbox","template":"test:v1","mode":"overlay","vcpus":2,"memory_mb":512}`,
		nsClaims("acme"))
	if w.Code != http.StatusCreated {
		t.Fatalf("ns sandfs create: %d (%s)", w.Code, w.Body.String())
	}
	created := topLevelKeys(t, "ns sandfs create", w.Body.Bytes())
	assertExactlyKeys(t, "ns sandfs create", created,
		"sandfs_id", "agent_id", "name", "description", "template", "mode",
		"min_vcpus", "min_memory_mb", "created_at", "namespace", "pull_status")
	var sf struct {
		SandfsID string `json:"sandfs_id"`
	}
	if err := json.Unmarshal(created["sandfs_id"], &sf.SandfsID); err != nil || sf.SandfsID == "" {
		t.Fatalf("decode sandfs_id: %v", err)
	}
	rec, err := gw.reg.Store().GetSandFS(sf.SandfsID)
	if err != nil || rec == nil {
		t.Fatalf("get stored record: %v", err)
	}
	if rec.RootFSPath == "" || rec.VolumeEpoch == "" {
		t.Fatalf("fixture must carry storage fields for the leak assertion: %+v", rec)
	}
	assertNoStorageLeak(t, "ns sandfs create", w.Body.String(), rec)

	// Get: same projection (active status is omitted, like the fleet record).
	w = doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/sandfs/"+sf.SandfsID, "", nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("ns sandfs get: %d (%s)", w.Code, w.Body.String())
	}
	assertExactlyKeys(t, "ns sandfs get", topLevelKeys(t, "ns sandfs get", w.Body.Bytes()),
		"sandfs_id", "agent_id", "name", "description", "template", "mode",
		"min_vcpus", "min_memory_mb", "created_at", "namespace")
	assertNoStorageLeak(t, "ns sandfs get", w.Body.String(), rec)

	// List: the same item projection inside the paged envelope.
	w = doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/sandfs", "", nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("ns sandfs list: %d (%s)", w.Code, w.Body.String())
	}
	var page struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 1 {
		t.Fatalf("ns sandfs list: %d items err=%v (%s)", len(page.Items), err, w.Body.String())
	}
	assertExactlyKeys(t, "ns sandfs list item", page.Items[0],
		"sandfs_id", "agent_id", "name", "description", "template", "mode",
		"min_vcpus", "min_memory_mb", "created_at", "namespace")
	assertNoStorageLeak(t, "ns sandfs list", w.Body.String(), rec)

	// Detach: lifecycle response carries state only.
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/sandfs/"+sf.SandfsID+"/detach-template",
		`{"wait_sec":2}`, nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("ns detach: %d (%s)", w.Code, w.Body.String())
	}
	assertExactlyKeys(t, "ns detach", topLevelKeys(t, "ns detach", w.Body.Bytes()),
		"sandfs_id", "status", "wait_sec")
	assertNoStorageLeak(t, "ns detach", w.Body.String(), rec)

	// While detached, GET carries status but still no storage fields.
	w = doNSRequest(gw.humanHandler, "GET", "/human/ns/acme/sandfs/"+sf.SandfsID, "", nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("ns get detached: %d (%s)", w.Code, w.Body.String())
	}
	assertExactlyKeys(t, "ns get detached", topLevelKeys(t, "ns get detached", w.Body.Bytes()),
		"sandfs_id", "agent_id", "name", "description", "template", "mode",
		"min_vcpus", "min_memory_mb", "created_at", "status", "namespace")
	assertNoStorageLeak(t, "ns get detached", w.Body.String(), rec)

	// Attach: template + resulting resources only.
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/sandfs/"+sf.SandfsID+"/attach-template",
		`{"template_ref":"test:v2"}`, nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("ns attach: %d (%s)", w.Code, w.Body.String())
	}
	assertExactlyKeys(t, "ns attach", topLevelKeys(t, "ns attach", w.Body.Bytes()),
		"sandfs_id", "template", "status", "min_vcpus", "min_memory_mb")
	assertNoStorageLeak(t, "ns attach", w.Body.String(), rec)

	// Swap (active → detached → attached in one call): same shape.
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/sandfs/"+sf.SandfsID+"/swap-template",
		`{"template_ref":"test:v3","wait_sec":2}`, nsClaims("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("ns swap: %d (%s)", w.Code, w.Body.String())
	}
	assertExactlyKeys(t, "ns swap", topLevelKeys(t, "ns swap", w.Body.Bytes()),
		"sandfs_id", "template", "status", "min_vcpus", "min_memory_mb")
	assertNoStorageLeak(t, "ns swap", w.Body.String(), rec)

	// Template capture is ops/admin: the tenant refusal must not carry the
	// save result (whose `path` names the host template store).
	w = doNSRequest(gw.humanHandler, "POST", "/human/ns/acme/sandfs/"+sf.SandfsID+"/save-template",
		`{"template_ref":"capture:v1"}`, nsClaims("acme"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("ns save-template by tenant: expected 403, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "TEMPLATE_OPS_REQUIRED") {
		t.Errorf("ns save-template refusal must carry TEMPLATE_OPS_REQUIRED: %s", w.Body.String())
	}
	for _, leaked := range []string{`"path"`, "size_kb"} {
		if strings.Contains(w.Body.String(), leaked) {
			t.Errorf("ns save-template refusal leaks %q: %s", leaked, w.Body.String())
		}
	}
}
