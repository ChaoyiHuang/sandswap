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

// Namespaced human-API routing — the tenancy surface
// /human/ns/{ns}/… (docs/how-it-works/namespaces.md). Two rules, in order:
//
//	Rule 1 (path grant):  the path's ns must be covered by the caller's
//	                      sandswap_ns claim (or "*") — else 403
//	                      NAMESPACE_FORBIDDEN. No OIDC ⇒ fleet (passthrough).
//	Rule 2 (record match): the addressed record's namespace must equal the
//	                      path's ns — else a uniform 404 "agent not found" /
//	                      "sandfs not found" (identical body whether the id is
//	                      missing, foreign, or cross-namespace: no existence
// oracle across tenants — the pattern).
//
// The unscoped /human/agent* and /human/sandfs* routes are the fleet-wide
// admin surface: with OIDC active they additionally require "*" (see
// requireFleetScope in ServeHTTP). Templates, ownership, maintenance, health
// and stats are cluster-level concerns with their own scope rules and are
// deliberately NOT namespace-addressable.

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"gateway/authn"
	"gateway/identity"
)

// nsPathPrefix is the namespaced subtree root.
const nsPathPrefix = "/human/ns/"

// writeNamespaceForbidden writes the Rule-1 refusal.
func writeNamespaceForbidden(w http.ResponseWriter, ns string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{
		"error":      "namespace not granted to this caller",
		"error_code": "NAMESPACE_FORBIDDEN",
		"namespace":  ns,
	})
}

// writeFleetScopeRequired writes the unscoped-route refusal for tenant
// callers (points them at the namespaced surface).
func writeFleetScopeRequired(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{
		"error":      "fleet-wide access requires the * namespace grant; use /human/ns/<ns>/… for tenant access",
		"error_code": "FLEET_SCOPE_REQUIRED",
	})
}

// isFleetScopedPath reports whether the (unscoped) path belongs to the
// agent/sandfs CRUD families — the only routes the fleet gate covers.
func isFleetScopedPath(path string) bool {
	return path == "/human/agent" || strings.HasPrefix(path, "/human/agent/") ||
		path == "/human/sandfs" || strings.HasPrefix(path, "/human/sandfs/")
}

// serveNamespaced routes the /human/ns/{ns}/… subtree.
func (h *HumanHandler) serveNamespaced(w http.ResponseWriter, r *http.Request, path string) {
	rest := strings.TrimPrefix(path, nsPathPrefix)
	ns, rest, _ := strings.Cut(rest, "/")
	if ns == "" || !identity.ValidNamespace(ns) {
		writeJSONError(w, "invalid namespace in path (expected ^[a-z][a-z0-9-]{0,62}$)", http.StatusBadRequest)
		return
	}
	// the namespaced surface is an IDENTITY feature — every grant
	// comes from verified token claims (the IdP is the authority; there is no
	// registry). With NO claims at all (no OIDC configured — the
	// -allow-anonymous-human deployment shape), there is no identity whose
	// namespace grants could be honored, so this subtree DENIES rather than
	// resolving anonymous as fleet and granting every namespace. The UNSCOPED
	// fleet gate deliberately keeps passthrough=fleet (that is what the
	// explicit opt-out admits); this subtree is the one place where
	// "no claims" must never mean "all namespaces". Checked before the store
	// and with Rule 1's uniform refusal so a probe learns nothing.
	if authn.TokenClaimsFromContext(r.Context()) == nil {
		writeNamespaceForbidden(w, ns)
		return
	}
	// Rule 1 — the path grant. Checked before any store access so a denied
	// caller learns nothing about the namespace's contents.
	scope := authn.NamespaceScopeFromContext(r.Context())
	if !scope.Allows(ns) {
		writeNamespaceForbidden(w, ns)
		return
	}

	switch {
	// Agent CRUD within the namespace
	case rest == "agent" && r.Method == http.MethodPost:
		h.createAgentInNS(w, r, ns)
	case rest == "agent" && r.Method == http.MethodGet:
		h.listAgentsInNS(w, r, ns)
	case rest != "" && strings.HasPrefix(rest, "agent/") && r.Method == http.MethodDelete:
		agentID, ok := extractPathID(rest, "agent/", "")
		if !ok || !validPathID(agentID) {
			writeJSONError(w, "invalid agent id", http.StatusBadRequest)
			return
		}
		if !h.agentVisibleInNS(w, agentID, ns) {
			return
		}
		h.deleteAgent(w, r, agentID)

	// SandFS CRUD within the namespace
	case rest == "sandfs" && r.Method == http.MethodPost:
		h.createSandFSInNS(w, r, ns)
	case rest == "sandfs" && r.Method == http.MethodGet:
		h.listSandFSInNS(w, r, ns)
	case rest != "" && strings.HasPrefix(rest, "sandfs/") && r.Method == http.MethodPost &&
		strings.HasSuffix(rest, "/rootfs-path"):
		sandfsID, ok := extractPathID(rest, "sandfs/", "/rootfs-path")
		if !ok || !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		if !h.sandfsVisibleInNS(w, sandfsID, ns) {
			return
		}
		h.handleSetRootFSPath(w, r, sandfsID)
	case rest != "" && strings.HasPrefix(rest, "sandfs/") && r.Method == http.MethodDelete:
		sandfsID, ok := extractPathID(rest, "sandfs/", "")
		if !ok || !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		if !h.sandfsVisibleInNS(w, sandfsID, ns) {
			return
		}
		h.deleteSandFS(w, r, sandfsID)
	case rest != "" && strings.HasPrefix(rest, "sandfs/") && r.Method == http.MethodPost:
		action, sandfsID, ok := cutSandfsAction(rest)
		if !ok || !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		if !h.sandfsVisibleInNS(w, sandfsID, ns) {
			return
		}
		switch action {
		case "detach-template":
			h.detachTemplate(w, r, sandfsID)
		case "attach-template":
			h.attachTemplate(w, r, sandfsID)
		case "swap-template":
			h.swapTemplate(w, r, sandfsID)
		case "save-template":
			h.saveAsTemplate(w, r, sandfsID)
		default:
			writeJSONError(w, "not found", http.StatusNotFound)
		}
	case rest != "" && strings.HasPrefix(rest, "sandfs/") && r.Method == http.MethodGet:
		sandfsID, ok := extractPathID(rest, "sandfs/", "")
		if !ok || !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		if !h.sandfsVisibleInNS(w, sandfsID, ns) {
			return
		}
		h.getSandFS(w, r, sandfsID)

	default:
		writeJSONError(w, "not found", http.StatusNotFound)
	}
}

// cutSandfsAction splits "sandfs/<id>/<action>" into (action, id, ok). The
// id must contain no further slash (two-suffix forms are rejected by the
// caller's action switch).
func cutSandfsAction(rest string) (action, sandfsID string, ok bool) {
	body := strings.TrimPrefix(rest, "sandfs/")
	id, act, found := strings.Cut(body, "/")
	if !found || id == "" || act == "" {
		return "", "", false
	}
	if strings.Contains(act, "/") {
		return "", "", false
	}
	return act, id, true
}

// agentGetter resolves the agent-by-ID lookup with the same preference the
// legacy list endpoints use: PagedLister's view when present, the namespace
// view next, else a scan fallback (custom stores).
func (h *HumanHandler) agentGetter() func(string) (*identity.Agent, error) {
	if pl, ok := h.identityStore.(identity.PagedLister); ok {
		return pl.GetAgent
	}
	if nl, ok := h.identityStore.(identity.NamespaceLister); ok {
		return nl.GetAgent
	}
	return func(id string) (*identity.Agent, error) {
		agents, err := h.identityStore.ListAgents()
		if err != nil {
			return nil, err
		}
		for _, a := range agents {
			if a.ID == id {
				return a, nil
			}
		}
		return nil, fmt.Errorf("agent not found: %s", id)
	}
}

// ── Rule 2 helpers ─────────────────────────────────────────────

// agentVisibleInNS enforces Rule 2 for agents: the agent must exist AND sit
// in the path's namespace, answering a uniform 404 otherwise (missing,
// foreign, and cross-namespace are indistinguishable). Writes the response
// and returns false when not visible.
func (h *HumanHandler) agentVisibleInNS(w http.ResponseWriter, agentID, ns string) bool {
	agent, err := h.agentGetter()(agentID)
	if err != nil || agent == nil || agent.NamespaceOrDefault() != ns {
		writeJSONError(w, "agent not found", http.StatusNotFound)
		return false
	}
	return true
}

// sandfsVisibleInNS is the Record twin of agentVisibleInNS.
func (h *HumanHandler) sandfsVisibleInNS(w http.ResponseWriter, sandfsID, ns string) bool {
	rec, err := h.identityStore.GetSandFS(sandfsID)
	if err != nil || rec == nil || rec.NamespaceOrDefault() != ns {
		writeJSONError(w, "sandfs not found", http.StatusNotFound)
		return false
	}
	return true
}

// ── Namespaced creates and listings ────────────────────────────

// createAgentInNS stamps the path namespace onto the new agent. The store
// validates the name (the path was already charset-checked, so this is
// defense in depth — the handler never invents namespace names itself).
func (h *HumanHandler) createAgentInNS(w http.ResponseWriter, r *http.Request, ns string) {
	var req CreateAgentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		req.Name = "unnamed-agent"
	}
	agent, apiKey, err := h.identityStore.CreateAgent(identity.CreateAgentRequest{
		Name:      req.Name,
		Namespace: ns,
	})
	if err != nil {
		h.logger.Error("create agent failed", "error", err, "namespace", ns)
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.logger.Info("agent created", "agentID", agent.ID, "name", req.Name, "namespace", ns)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CreateAgentResponse{
		AgentID:     agent.ID,
		APIKey:      apiKey,
		Name:        agent.Name,
		Description: agent.Description,
	})
}

// createSandFSInNS requires the named agent to sit in this namespace
// (uniform 404 "agent not found" otherwise — a cross-namespace agent id is
// not an oracle either), then reuses the registry create path; the store
// freezes the sandfs's namespace from the agent.
func (h *HumanHandler) createSandFSInNS(w http.ResponseWriter, r *http.Request, ns string) {
	if h.rotationRefusal(w, "creating a sandfs") {
		return
	}
	var req HumanCreateSandFSRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		writeJSONError(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	if !h.agentVisibleInNS(w, req.AgentID, ns) {
		return
	}
	if req.Name == "" {
		req.Name = "unnamed-sandfs"
	}
	// Same ref-charset rule as the unscoped create (see validateTemplateRef):
	// the ref enters a prov op, so an impossible ref is a named 400 here too.
	if req.Template != "" {
		if err := validateTemplateRef(req.Template); err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	rec, pulled, err := h.registry.CreateSandFS(r.Context(), req.AgentID, identity.CreateSandFSRequest{
		Name:        req.Name,
		Description: req.Description,
		Template:    req.Template,
		Mode:        req.Mode,
		VCPUs:       req.VCPUs,
		MemoryMB:    req.MemoryMB,
	})
	if err != nil {
		// Same named-refusal routing as the unscoped create.
		h.writeStorageErr(w, err, "create sandfs")
		return
	}
	h.logger.Info("sandfs created", "sandfsID", rec.ID, "agentID", req.AgentID,
		"name", req.Name, "template", req.Template, "pulled", pulled, "namespace", ns)
	pullStatus := "cached"
	if pulled {
		pullStatus = "pulled"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(HumanCreateSandFSResponse{
		SandfsID:    rec.ID,
		AgentID:     rec.AgentID,
		Name:        rec.Name,
		Description: rec.Description,
		RootFSPath:  rec.RootFSPath,
		Template:    rec.Template,
		PullStatus:  pullStatus,
	})
}

// listAgentsInNS lists the namespace's agents with the shared cursor
// pagination shape. NamespaceLister stores filter their watch-fed cache;
// a custom store falls back to the full list + in-memory filter.
func (h *HumanHandler) listAgentsInNS(w http.ResponseWriter, r *http.Request, ns string) {
	limit, cursor, ok := parseListPageParams(w, r)
	if !ok {
		return
	}
	var recs []*identity.Agent
	if nl, is := h.identityStore.(identity.NamespaceLister); is {
		recs = nl.ListAgentsInNamespace(ns)
	} else {
		// Custom store without the namespace view: filter the full list
		// in memory (same response shape; only viable at small scale).
		agents, err := h.identityStore.ListAgents()
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, a := range agents {
			if a.NamespaceOrDefault() == ns {
				recs = append(recs, a)
			}
		}
	}
	ids := make([]string, 0, len(recs))
	byID := make(map[string]*identity.Agent, len(recs))
	for _, a := range recs {
		ids = append(ids, a.ID)
		byID[a.ID] = a
	}
	sort.Strings(ids)
	start, end, next, truncated := pageWindow(ids, cursor, limit)
	items := make([]*identity.Agent, 0, end-start)
	for _, id := range ids[start:end] {
		items = append(items, byID[id])
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pagedList{Items: items, NextCursor: next, Truncated: truncated})
}

// listSandFSInNS is the sandfs twin of listAgentsInNS.
func (h *HumanHandler) listSandFSInNS(w http.ResponseWriter, r *http.Request, ns string) {
	limit, cursor, ok := parseListPageParams(w, r)
	if !ok {
		return
	}
	var recs []*identity.Record
	if nl, is := h.identityStore.(identity.NamespaceLister); is {
		recs = nl.ListSandFSInNamespace(ns)
	} else {
		all, err := h.identityStore.ListAllSandFS()
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, rec := range all {
			if rec.NamespaceOrDefault() == ns {
				recs = append(recs, rec)
			}
		}
	}
	ids := make([]string, 0, len(recs))
	for _, rec := range recs {
		ids = append(ids, rec.ID)
	}
	sort.Strings(ids)
	start, end, next, truncated := pageWindow(ids, cursor, limit)
	items := make([]*identity.Record, 0, end-start)
	for _, id := range ids[start:end] {
		// Per-page lazy display fetch: display meta is no longer
		// part of the snapshot; GetSandFS serves it from the bounded cache or
		// one point Get. Deleted mid-iteration records are skipped (same
		// contract as listPage).
		rec, err := h.identityStore.GetSandFS(id)
		if err != nil || rec == nil {
			continue
		}
		items = append(items, rec)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pagedList{Items: items, NextCursor: next, Truncated: truncated})
}
