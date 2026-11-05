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

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"gateway/identity"
	"gateway/lease"
	"gateway/maintenance"
	"gateway/pool"
	"gateway/registry"
	"gateway/stats"
	"gateway/storage"

	"gateway/authn"
)

// HumanHandler handles management endpoints: /human/agent, /human/sandfs,
// /human/templates, /health, /stats, /human/ownership.
// These are infrastructure management operations performed by humans,
// not by AI agents.
type HumanHandler struct {
	registry      *registry.Registry
	pool          *pool.Manager
	logger        *slog.Logger
	identityStore identity.Store
	ownership     OwnershipReleaser    // may be nil in single-node mode
	stuckReaper   StuckOwnershipReaper // may be nil in single-node mode (manual reap-stuck tool)
	// Cluster stats: etcdClient + gatewayID produce the aggregated /stats view.
	// nil etcdClient (single-node MemoryStore) → local pool.Stats() fallback.
	etcdClient *clientv3.Client
	gatewayID  string
	// maintenance is the service-refusal switch (nil = feature unwired). Its
	// state is reported on /stats so rotation tooling can poll it.
	maintenance *maintenance.Switch
	// rotation is the volume-seed rotation window switch (nil = feature
	// unwired): while ON, creating a SandFS is refused fleet-wide — a volume
	// created mid-window would be named in the generation being retired, and
	// the per-instance freeze only covers instances that are themselves
	// staged. Deliberately separate from maintenance, which also serves
	// upgrade windows that have no reason to freeze creation.
	rotation *maintenance.Switch
	// provSeedSource reports every connected prov instance's naming
	// generations (fingerprints only) for /stats — the reading a rotation uses
	// to prove the prov fleet converged before the window closes.
	provSeedSource      func() []ProvSeedState
	egressBindingSource func() []EgressBindingState
	// provisionerCount reports connected prov-role instances (nil = omit).
	provisionerCount func() int
	// localUnmountStats is this gateway's per-node unmount stats recorder. Its
	// snapshot is merged into the local /stats entry; peer gateways' snapshots
	// are read from /sandswap/unmount-stats/{gw} in etcd. nil = unmount stats
	// disabled (the /stats UnmountStats field is simply omitted).
	localUnmountStats *stats.UnmountStats
	// redactTenantIDs strips per-tenant identifiers from the /stats
	// projection (exec mode's /stats rides the unauthenticated
	// agent listener).
	redactTenantIDs bool
	// drainer is the INLINE drain primitive (pool + lease in this process —
	// single-node and one-gw topologies). Split-mode human gateways leave it
	// nil: they write the lifecycle status and the exec-side identity-watch
	// drain settles it (lifecycleDrain polls).
	drainer Drainer
}

// Drainer is the inline mount-drain primitive: reports whether every mount of
// the sandfs was released within budget. *lease.Drainer is the production
// implementation; the interface keeps the handler free of the pool/lease
// wiring (and lets tests observe the budget the handler actually applies).
type Drainer interface {
	Drain(sandfsID, volumePath, volumeEpoch string, budget time.Duration) bool
}

// SetDrainer wires the inline mount-drain primitive. Required for
// detach/delete on topologies where this process holds the pool manager
// (single-node, one-gw); optional on split deployments where the exec
// gateways drain via the identity watch.
func (h *HumanHandler) SetDrainer(d Drainer) {
	h.drainer = d
}

// OwnershipReleaser is an interface for releasing sandfs ownership.
type OwnershipReleaser interface {
	ReleaseOwnership(sandfsID string)
}

// StuckOwnershipReaper is the manual both-dead reclamation interface: reclaim
// sandfs stranded on a permanently-dead owner gateway or a permanently-dead
// sandlot node. Implemented by *lease.OwnershipCache; nil in single-node mode.
type StuckOwnershipReaper interface {
	ReapStuckOwnership(ctx context.Context, targetGwID string, dryRun bool, batchSize int) (*lease.ReapStuckReport, error)
	ReapStuckNodeOwnership(ctx context.Context, targetNodeID string, dryRun bool, batchSize int) (*lease.ReapStuckNodeReport, error)
}

// NewHumanHandler creates a new HumanHandler.
func NewHumanHandler(reg *registry.Registry, pm *pool.Manager, logger *slog.Logger) *HumanHandler {
	return &HumanHandler{
		registry:      reg,
		pool:          pm,
		logger:        logger,
		identityStore: reg.Store(),
	}
}

// storageOps returns the storage-plane executor, read at REQUEST time (the
// wiring may install it after handler construction; in rpc mode it appears
// when the first prov instance connects). nil = storage plane unavailable.
func (h *HumanHandler) storageOps() storage.Ops {
	if h.registry == nil {
		return nil
	}
	return h.registry.Storage()
}

// writeStorageErr maps storage-plane failures to HTTP: an unreachable storage
// plane (no prov instance connected) is a named 503 the client can retry
// against another gateway; node-side business failures carrying a named wire
// class get their structured status (422 unknown template, 409 volume
// identity mismatch, whose node text is deliberately NOT echoed); anything
// unmapped keeps the historical 500 + error text.
func (h *HumanHandler) writeStorageErr(w http.ResponseWriter, err error, action string) {
	if errors.Is(err, storage.ErrNoProvisioner) {
		h.logger.Error("storage plane unreachable", "action", action, "error", err)
		writeJSONError(w, "storage plane unavailable: no provision instance connected — retry shortly or check the prov instances", http.StatusServiceUnavailable)
		return
	}
	// Delete-gate outcomes are a lifecycle race, not a storage failure: the
	// sandfs moved state under the delete (or the gate could not be proven),
	// so nothing was removed and a retry is the right action.
	if errors.Is(err, errDeleteBecameActive) || errors.Is(err, registry.ErrSandfsNotDeleting) {
		h.logger.Warn(action+" refused: lifecycle state changed", "error", err)
		writeJSONError(w, err.Error(), http.StatusConflict)
		return
	}
	// The prov instance's structured wire codes arrive as text prefixes
	// (registry/store wrappers keep the code prefix readable through %w). A
	// TEMPLATE_NOT_FOUND on create is the CLIENT referencing an unknown
	// template — a named 422, never a server 500.
	// The upper-case wired code and the storage ops' lower-case "template not
	// found" text both mean the caller named an unknown template. The raw
	// error embeds an absolute host path on the delete path (stat
	// /tmp/.../refs/...); the caller gets a fixed message + code, the detail
	// stays in the log. Create keeps 422; a DELETE answers 404.
	if strings.Contains(err.Error(), "TEMPLATE_NOT_FOUND") ||
		strings.Contains(strings.ToLower(err.Error()), "template not found") {
		h.logger.Warn(action+" refused: unknown template", "error", err)
		code := http.StatusUnprocessableEntity
		if action == "delete template" {
			code = http.StatusNotFound
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{
			"error":      "template not found",
			"error_code": "TEMPLATE_NOT_FOUND",
		})
		return
	}
	// VOLUME_IDENTITY_MISMATCH: the volume carries another sandfs's identity
	// stamp (a seed-derived name/record divergence). The node's raw text
	// embeds the absolute host path AND the foreign sandfs id — exactly the
	// disclosure the named wire class was added to stop — so it never reaches
	// the caller: fixed message, stable code, full detail in the log.
	if strings.Contains(err.Error(), "VOLUME_IDENTITY_MISMATCH") {
		h.logger.Error(action+" refused: volume identity mismatch (operator attention required)", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"error":      "volume identity mismatch: the storage plane's volume does not belong to this sandfs — an operator must reconcile the volume and its record",
			"error_code": "VOLUME_IDENTITY_MISMATCH",
		})
		return
	}
	// TEMPLATE_EXISTS: ref files are immutable. An overwrite would re-point
	// every volume mounting the ref, and because the ref->filename encoding
	// is not injective it could also replace a DIFFERENT name:version (the
	// cross-tenant rootfs-substitution primitive). Fixed 409; delete first.
	if strings.Contains(err.Error(), "TEMPLATE_EXISTS") {
		h.logger.Warn(action+" refused: template ref already exists (refs are immutable)", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"error":      "template ref already exists and is immutable; delete it (under the in-use gate) before creating a new one",
			"error_code": "TEMPLATE_EXISTS",
		})
		return
	}
	// TEMPLATE_IDENTITY_MISMATCH: the ref file names a different
	// name:version than the caller asked for — the filename-collision or a
	// tampered ref. Never serve/delete it through the colliding name.
	if strings.Contains(err.Error(), "TEMPLATE_IDENTITY_MISMATCH") {
		h.logger.Error(action+" refused: ref identity mismatch (collision/tamper)", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"error":      "ref file belongs to a different template (name:version collision or tampering) — an operator must reconcile the ref store",
			"error_code": "TEMPLATE_IDENTITY_MISMATCH",
		})
		return
	}
	// Unknown storage failure: the raw error can embed absolute host paths
	// and node-internal text. Keep it in the log; the caller gets a stable
	// class. (Named classes above carry the actionable cases.)
	h.logger.Error(action+" failed", "error", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]string{
		"error":      "storage operation failed",
		"error_code": "STORAGE_ERROR",
	})
}

// NewStatsHandler creates a HumanHandler wired only for GET /stats — no
// registry, no CRUD. Used by exec mode (which has an etcd client + pool manager
// but no human CRUD surface) to serve the aggregated cluster /stats on its
// agent listener. ServeHTTP still works; only /stats is meaningful for this
// instance.
func NewStatsHandler(pm *pool.Manager, logger *slog.Logger) *HumanHandler {
	return &HumanHandler{
		pool:   pm,
		logger: logger,
	}
}

// SetOwnership sets the ownership cache for ownership release operations.
func (h *HumanHandler) SetOwnership(oc OwnershipReleaser) {
	h.ownership = oc
}

// SetStuckReaper wires the manual reap-stuck tool backend (the ownership cache).
// Nil in single-node mode (no etcd coordination layer) — the endpoint returns 503.
func (h *HumanHandler) SetStuckReaper(r StuckOwnershipReaper) {
	h.stuckReaper = r
}

// SetStatsClient wires the etcd client + gateway identity used by /stats to
// aggregate the cluster-wide view. In single-node mode (cli == nil) /stats
// falls back to the local pool manager — same StatsReport shape, one entry.
// SetMaintenance attaches the service-refusal switch (the rotation window uses
// it) plus — in split deployments — the etcd client used to publish the
// fleet-wide key the EXEC gateways watch. cli may be nil (single-node: the
// local switch is the whole story).
func (h *HumanHandler) SetMaintenance(sw *maintenance.Switch) {
	h.maintenance = sw
}

// SetRotation wires the rotation-window switch: while on, SandFS creation is
// refused (see handleRotation). nil = the feature is unavailable in this mode.
func (h *HumanHandler) SetRotation(sw *maintenance.Switch) {
	h.rotation = sw
}

// SetProvSeedSource wires the per-prov-instance naming-generation view that
// /stats projects: the reading a rotation uses to prove every prov instance
// converged before the window closes.
func (h *HumanHandler) SetProvSeedSource(fn func() []ProvSeedState) {
	h.provSeedSource = fn
}

// SetEgressBindingSource wires the per-node egress identity-binding view that
// /stats projects (the enabler audit surface).
func (h *HumanHandler) SetEgressBindingSource(fn func() []EgressBindingState) {
	h.egressBindingSource = fn
}

func (h *HumanHandler) SetStatsClient(cli *clientv3.Client, gatewayID string) {
	h.etcdClient = cli
	h.gatewayID = gatewayID
}

// SetProvisionerCounter wires a callback reporting the number of connected
// prov-role instances (the storage plane's executors). /health surfaces it as
// "provisioners"; nil omits the field.
func (h *HumanHandler) SetProvisionerCounter(fn func() int) {
	h.provisionerCount = fn
}

// SetUnmountStats wires this gateway's local unmount stats recorder so its
// snapshot is merged into the /stats report. nil (or not called) = the
// UnmountStats field is omitted from /stats.
func (h *HumanHandler) SetUnmountStats(s *stats.UnmountStats) {
	h.localUnmountStats = s
}

// unmountSnapshot returns the local recorder's current snapshot, or nil if
// unmount stats are disabled. Called per /stats request (the recorder takes its
// mutex briefly; off the exec hot path).
func (h *HumanHandler) unmountSnapshot() []stats.NodeUnmountStats {
	if h.localUnmountStats == nil {
		return nil
	}
	snap := h.localUnmountStats.Snapshot()
	if h.redactTenantIDs {
		// on the AGENT listener (exec mode has no human listener,
		// /stats rides the agent mux with no auth), per-tenant identifiers
		// must not leave the process: the top_slow entries carry the tenant's
		// sandfs_id and a 120-char command excerpt (code, paths, embedded
		// tokens). Latency utility survives (node, gateway_ms, timestamp);
		// full identity stays available on the authenticated human API.
		for i := range snap {
			for j := range snap[i].TopSlow {
				snap[i].TopSlow[j].SandfsID = ""
				snap[i].TopSlow[j].Command = ""
			}
		}
	}
	return snap
}

// SetRedactTenantIDs enables tenant-identifier redaction for this handler's
// /stats projection. Set by exec mode, whose /stats has no auth.
func (h *HumanHandler) SetRedactTenantIDs(v bool) { h.redactTenantIDs = v }

// validPathID reports whether an ID extracted from the URL path is safe to use
// in a downstream filesystem path (e.g. filepath.Join(volRoot, sandfsID)).
// Go's http.Server already cleans ".." from the decoded path, but this is
// defense in depth: it rejects any ID containing a path separator, parent
// traversal, or null byte, so a malformed value can never reach filepath.Join.
// It does NOT enforce an exact ID format — only traversal safety.
func validPathID(id string) bool {
	if id == "" {
		return false
	}
	if strings.ContainsAny(id, "/\\\x00") {
		return false
	}
	// Reject any ".." path component (e.g. "..", "foo/../bar"). A bare ".."
	// or any component equal to ".." would let filepath.Join escape upward.
	for _, part := range strings.Split(id, string(filepath.Separator)) {
		if part == ".." {
			return false
		}
	}
	return true
}

// extractPathID extracts the ID segment between prefix and suffix from a URL
// path without raw arithmetic slicing (which panics on short paths). Returns
// the ID and ok=false when the segment is absent or the path has unexpected
// extra segments. The caller validates the ID for path safety.
func extractPathID(path, prefix, suffix string) (id string, ok bool) {
	rest := strings.TrimPrefix(path, prefix)
	if suffix != "" {
		rest = strings.TrimSuffix(rest, suffix)
	}
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

// ServeHTTP routes human management requests.
func (h *HumanHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Namespaced tenancy subtree — /human/ns/{ns}/… (Rule 1 + Rule 2 live in
	// namespace.go). Evaluated before everything else: the subtree shadows
	// the unscoped route shapes below.
	if strings.HasPrefix(path, nsPathPrefix) {
		h.serveNamespaced(w, r, path)
		return
	}

	// Fleet gate: the unscoped agent/sandfs CRUD families are the fleet-wide
	// admin surface. With OIDC active, only the "*" namespace grant answers
	// them (passthrough resolves as fleet — zero-behavior-change when OIDC
	// is not configured). Templates/ownership/maintenance/health/stats are
	// cluster-level and keep their own scope rules.
	if !authn.NamespaceScopeFromContext(r.Context()).Fleet && isFleetScopedPath(path) {
		writeFleetScopeRequired(w)
		return
	}

	switch {
	// Agent CRUD
	case path == "/human/agent" && r.Method == http.MethodPost:
		h.createAgent(w, r)
	case path == "/human/agent" && r.Method == http.MethodGet:
		h.listAgents(w, r)
	case strings.HasPrefix(path, "/human/agent/") && r.Method == http.MethodDelete:
		agentID, ok := extractPathID(path, "/human/agent/", "")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(agentID) {
			writeJSONError(w, "invalid agent id", http.StatusBadRequest)
			return
		}
		// Unscoped agent CRUD is admin/ops; the namespaced surface has its own
		// grant check and calls deleteAgent directly (without this gate).
		if !requireOpsScope(w, r) {
			return
		}
		h.deleteAgent(w, r, agentID)

	// SandFS CRUD
	case path == "/human/maintenance" && r.Method == http.MethodPost:
		h.handleMaintenance(w, r)
	case path == "/human/rotation" && r.Method == http.MethodPost:
		h.handleRotation(w, r)
	case strings.HasPrefix(path, "/human/sandfs/") && strings.HasSuffix(path, "/rootfs-path") && r.Method == http.MethodPost:
		sandfsID, ok := extractPathID(path, "/human/sandfs/", "/rootfs-path")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		h.handleSetRootFSPath(w, r, sandfsID)
	case path == "/human/sandfs" && r.Method == http.MethodPost:
		h.createSandFS(w, r)
	case path == "/human/sandfs" && r.Method == http.MethodGet:
		h.listSandFS(w, r)
	case strings.HasPrefix(path, "/human/sandfs/") && r.Method == http.MethodDelete:
		sandfsID, ok := extractPathID(path, "/human/sandfs/", "")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		h.deleteSandFS(w, r, sandfsID)
	case strings.HasPrefix(path, "/human/sandfs/") && strings.HasSuffix(path, "/detach-template") && r.Method == http.MethodPost:
		sandfsID, ok := extractPathID(path, "/human/sandfs/", "/detach-template")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		h.detachTemplate(w, r, sandfsID)
	case strings.HasPrefix(path, "/human/sandfs/") && strings.HasSuffix(path, "/attach-template") && r.Method == http.MethodPost:
		sandfsID, ok := extractPathID(path, "/human/sandfs/", "/attach-template")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		h.attachTemplate(w, r, sandfsID)
	case strings.HasPrefix(path, "/human/sandfs/") && strings.HasSuffix(path, "/swap-template") && r.Method == http.MethodPost:
		sandfsID, ok := extractPathID(path, "/human/sandfs/", "/swap-template")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		h.swapTemplate(w, r, sandfsID)
	case strings.HasPrefix(path, "/human/sandfs/") && r.Method == http.MethodGet:
		// Single-sandfs get (status polling for the swap lifecycle). Must come
		// after the suffix-matched routes above.
		sandfsID, ok := extractPathID(path, "/human/sandfs/", "")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		h.getSandFS(w, r, sandfsID)
	case strings.HasPrefix(path, "/human/sandfs/") && strings.HasSuffix(path, "/save-template") && r.Method == http.MethodPost:
		sandfsID, ok := extractPathID(path, "/human/sandfs/", "/save-template")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		h.saveAsTemplate(w, r, sandfsID)

	// Templates — /push suffix must be checked BEFORE the generic POST handler
	case path == "/human/templates" && r.Method == http.MethodGet:
		h.listTemplates(w, r)
	case strings.HasPrefix(path, "/human/templates/") && strings.HasSuffix(path, "/push") && r.Method == http.MethodPost:
		templateRef, ok := extractPathID(path, "/human/templates/", "/push")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(templateRef) {
			writeJSONError(w, "invalid template ref", http.StatusBadRequest)
			return
		}
		h.pushTemplate(w, r, templateRef)
	case strings.HasPrefix(path, "/human/templates/") && r.Method == http.MethodDelete:
		templateRef, ok := extractPathID(path, "/human/templates/", "")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(templateRef) {
			writeJSONError(w, "invalid template ref", http.StatusBadRequest)
			return
		}
		h.deleteTemplate(w, r, templateRef)
	case strings.HasPrefix(path, "/human/templates/") && r.Method == http.MethodPost:
		templateRef, ok := extractPathID(path, "/human/templates/", "")
		if !ok {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		if !validPathID(templateRef) {
			writeJSONError(w, "invalid template ref", http.StatusBadRequest)
			return
		}
		h.pullTemplate(w, r, templateRef)

	// Ownership release (for rebalance)
	case strings.HasPrefix(path, "/human/ownership/release/") && r.Method == http.MethodPost:
		sandfsID, ok := extractPathID(path, "/human/ownership/release/", "")
		if !ok {
			// Empty ID (trailing slash with nothing after) is a bad request,
			// not a not-found: the route matched but the resource id is absent.
			writeJSONError(w, "sandfs_id is required", http.StatusBadRequest)
			return
		}
		if !validPathID(sandfsID) {
			writeJSONError(w, "invalid sandfs id", http.StatusBadRequest)
			return
		}
		h.releaseOwnership(w, r, sandfsID)

	case path == "/human/ownership/reap-stuck" && r.Method == http.MethodPost:
		h.reapStuckOwnership(w, r)

	case path == "/human/ownership/reap-stuck-node" && r.Method == http.MethodPost:
		h.reapStuckNodeOwnership(w, r)

	// Health/Stats
	case path == "/health":
		h.health(w, r)
	case path == "/stats":
		h.stats(w, r)

	default:
		writeJSONError(w, "not found", http.StatusNotFound)
	}
}

// ── Agent CRUD ─────────────────────────────────────────────────

// CreateAgentRequest is the body for POST /human/agent.
type CreateAgentRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// CreateAgentResponse is returned after Agent creation.
type CreateAgentResponse struct {
	AgentID     string `json:"agent_id"`
	APIKey      string `json:"api_key"` // returned exactly once
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (h *HumanHandler) createAgent(w http.ResponseWriter, r *http.Request) {
	if !requireOpsScope(w, r) {
		return
	}
	var req CreateAgentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		req.Name = "unnamed-agent"
	}

	desc := strings.TrimSpace(req.Description)
	if err := identity.ValidateDescription(desc); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	agent, apiKey, err := h.identityStore.CreateAgent(identity.CreateAgentRequest{
		Name:        req.Name,
		Description: desc,
	})
	if err != nil {
		h.logger.Error("create agent failed", "error", err)
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.logger.Info("agent created", "agentID", agent.ID, "name", req.Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CreateAgentResponse{
		AgentID:     agent.ID,
		APIKey:      apiKey,
		Name:        agent.Name,
		Description: agent.Description,
	})
}

// listPageParams bounds and defaults for the paginated human list endpoints.
const (
	listDefaultLimit = 100
	listMaxLimit     = 1000
)

// pagedList is the shared response envelope of the paginated list endpoints:
// the page's records plus the cursor continuing the iteration (empty on the
// last page) and a truncated flag. Record fields are unchanged from the
// pre-pagination bare-array responses.
type pagedList struct {
	Items      any    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Truncated  bool   `json:"truncated"`
}

// parseListPageParams parses ?limit=&cursor= for the paginated list endpoints.
// limit defaults to 100 and clamps down to 1000; a non-numeric or < 1 value is
// a 400 (silently clamping a typo hides exactly the scale problem the
// pagination exists for). On failure the error response is already written.
func parseListPageParams(w http.ResponseWriter, r *http.Request) (limit int, cursor string, ok bool) {
	limit = listDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeJSONError(w, "limit must be a positive integer", http.StatusBadRequest)
			return 0, "", false
		}
		if n > listMaxLimit {
			n = listMaxLimit
		}
		limit = n
	}
	return limit, r.URL.Query().Get("cursor"), true
}

// pageWindow slices a SORTED id list at the cursor: the first `limit` ids
// strictly greater than cursor. Returns the [start,end) window and whether
// more ids remain past it (truncated), plus the next page's cursor (the last
// id IN the window; empty when truncated is false).
func pageWindow(ids []string, cursor string, limit int) (start, end int, next string, truncated bool) {
	start = sort.SearchStrings(ids, cursor)
	if cursor != "" && start < len(ids) && ids[start] == cursor {
		start++ // strictly after the cursor
	}
	if start >= len(ids) {
		return len(ids), len(ids), "", false
	}
	end = start + limit
	if end < len(ids) {
		return start, end, ids[end-1], true
	}
	return start, len(ids), "", false
}

// listPage sorts the ID snapshot, windows it at the cursor, and resolves each
// ID through fetch (records deleted between the snapshot and the fetch are
// skipped). Shared by the paginated list endpoints.
func listPage[T any](ids []string, cursor string, limit int, fetch func(string) (T, error)) (items []T, next string, truncated bool) {
	sort.Strings(ids)
	start, end, next, truncated := pageWindow(ids, cursor, limit)
	items = make([]T, 0, end-start)
	for _, id := range ids[start:end] {
		rec, err := fetch(id)
		if err != nil {
			continue
		}
		items = append(items, rec)
	}
	return items, next, truncated
}

func (h *HumanHandler) listAgents(w http.ResponseWriter, r *http.Request) {
	if !requireOpsScope(w, r) {
		return
	}
	limit, cursor, ok := parseListPageParams(w, r)
	if !ok {
		return
	}
	var ids []string
	var fetch func(string) (*identity.Agent, error)
	if pl, paged := h.identityStore.(identity.PagedLister); paged {
		// Both real stores: page by ID — no per-call materialization of every
		// record (at fleet scale that is hundreds of MB of transient clones).
		ids = pl.ListAgentIDs()
		fetch = pl.GetAgent
	} else {
		// Custom store without the paged view: fall back to the full list and
		// page in memory (same response shape; only viable at small scale).
		agents, err := h.identityStore.ListAgents()
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		byID := make(map[string]*identity.Agent, len(agents))
		ids = make([]string, 0, len(agents))
		for _, a := range agents {
			byID[a.ID] = a
			ids = append(ids, a.ID)
		}
		fetch = func(id string) (*identity.Agent, error) {
			if a := byID[id]; a != nil {
				return a, nil
			}
			return nil, fmt.Errorf("agent not found: %s", id)
		}
	}
	items, next, truncated := listPage(ids, cursor, limit, fetch)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pagedList{Items: items, NextCursor: next, Truncated: truncated})
}

func (h *HumanHandler) deleteAgent(w http.ResponseWriter, r *http.Request, agentID string) {
	// The ops/admin check lives at the UNSCOPED route dispatch (ServeHTTP):
	// the namespaced surface deliberately calls this same implementation after
	// its own namespace grant check, and a namespace human user must keep the
	// right to delete an agent in their own namespace.
	// First, delete all sandfs owned by this agent (storage volumes + identity records).
	sandfsList, err := h.identityStore.ListSandFSByAgent(agentID)
	if err != nil {
		writeJSONError(w, "failed to list agent sandfs", http.StatusInternalServerError)
		return
	}
	// Partial failures leave orphaned volume directories on shared storage (the
	// identity record and agent are deleted regardless — the operator asked for
	// the agent to go). Collect them for ONE aggregate log carrying the exact
	// paths to inspect/remove: per-sandfs warns below carry the cause, this line
	// is the cleanup worklist.
	type orphan struct {
		id, path string
		err      error
	}
	var orphans []orphan
	for _, sf := range sandfsList {
		if delErr := h.teardownSandfs(sf.ID, agentDeleteWaitSec); delErr != nil {
			h.logger.Warn("failed to delete sandfs during agent deletion",
				"sandfsID", sf.ID, "agentID", agentID, "error", delErr)
			orphans = append(orphans, orphan{id: sf.ID, path: filepath.Join(h.registry.VolRoot(), sf.ID), err: delErr})
		}
	}

	// Then delete the agent itself.
	if err := h.identityStore.DeleteAgent(agentID); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(orphans) > 0 {
		ids := make([]string, 0, len(orphans))
		paths := make([]string, 0, len(orphans))
		for _, o := range orphans {
			ids = append(ids, o.id)
			paths = append(paths, o.path)
		}
		h.logger.Error("agent deleted but some sandfs teardown FAILED — orphaned volume directories remain on shared storage; inspect or remove manually",
			"agentID", agentID, "orphanedSandfs", ids, "orphanedPaths", paths)
	}
	h.logger.Info("agent deleted", "agentID", agentID, "sandfsDeleted", len(sandfsList)-len(orphans), "orphaned", len(orphans))
	w.WriteHeader(http.StatusNoContent)
}

// ── SandFS CRUD ────────────────────────────────────────────────

// HumanCreateSandFSRequest is the body for POST /human/sandfs.
type HumanCreateSandFSRequest struct {
	AgentID     string `json:"agent_id"` // required: owner agent
	Name        string `json:"name"`
	Description string `json:"description,omitempty"` // ≤200 chars, for agent discovery
	Template    string `json:"template,omitempty"`    // Template reference (e.g., "mysql:v1")
	Mode        string `json:"mode"`                  // "flat" | "overlay" (required)
	VCPUs       uint32 `json:"vcpus,omitempty"`       // minimum vCPUs; overrides the template default
	MemoryMB    uint64 `json:"memory_mb,omitempty"`   // minimum memory MB; overrides the template default
}

// HumanCreateSandFSResponse is returned after SandFS creation.
type HumanCreateSandFSResponse struct {
	SandfsID    string `json:"sandfs_id"`
	AgentID     string `json:"agent_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	RootFSPath  string `json:"rootfs_path"`
	Template    string `json:"template"`
	PullStatus  string `json:"pull_status,omitempty"` // "cached" | "pulled"
}

// validateTemplateRef mirrors the node-side rule (provision/volume
// ValidateTemplateRef) at the gateway: the node's charset check is the
// authority on its storage plane, but a ref that can never be valid must be
// refused HERE with a named 400 — before any storage round trip — and the two
// rules must not drift. Applied wherever a client-supplied ref enters a prov
// op (create, attach, swap).
func validateTemplateRef(ref string) error {
	if ref == "" || len(ref) > 256 || strings.ContainsAny(ref, "/\\\x00") || strings.Contains(ref, "..") {
		return fmt.Errorf("invalid template_ref %q: must be a single reference token (no '/', '\\\\', NUL or '..'), at most 256 chars", ref)
	}
	return nil
}

func (h *HumanHandler) createSandFS(w http.ResponseWriter, r *http.Request) {
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
	if req.Name == "" {
		req.Name = "unnamed-sandfs"
	}
	// Same contract as agent creation: trim first, then validate, so the
	// stored description is the one the operator meant (the 200-rune limit
	// applies to the trimmed value).
	req.Description = strings.TrimSpace(req.Description)
	if err := identity.ValidateDescription(req.Description); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The ref enters a prov op (EnsureVolume) — apply the node's charset rule
	// here so an impossible ref is a named 400 without a storage round trip
	// (the node still validates: it never trusts the gateway's strings).
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
		// Named storage-plane refusals (503 no-provisioner / 422 unknown
		// template) — never an anonymous 500.
		h.writeStorageErr(w, err, "create sandfs")
		return
	}

	h.logger.Info("sandfs created", "sandfsID", rec.ID, "agentID", req.AgentID, "name", req.Name,
		"template", req.Template, "pulled", pulled)
	// The create result is the registry's LIVE record (the store hands it back
	// so the registry can fill rootfs_path/min-resources after creation). Read
	// the response fields from a snapshot instead: a concurrent lifecycle write
	// to this freshly created sandfs would otherwise race these field reads.
	if fresh, gerr := h.identityStore.GetSandFS(rec.ID); gerr == nil {
		rec = fresh
	}
	// pull_status: "pulled" when THIS create fetched the ref from the OCI
	// registry (it was missing from the local store), "cached" otherwise —
	// errors are HTTP statuses, never a body value.
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

func (h *HumanHandler) listSandFS(w http.ResponseWriter, r *http.Request) {
	limit, cursor, ok := parseListPageParams(w, r)
	if !ok {
		return
	}
	var ids []string
	var fetch func(string) (*identity.Record, error)
	if pl, paged := h.identityStore.(identity.PagedLister); paged {
		ids = pl.ListSandFSIDs()
		fetch = h.identityStore.GetSandFS
	} else {
		recs, err := h.identityStore.ListAllSandFS()
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		byID := make(map[string]*identity.Record, len(recs))
		ids = make([]string, 0, len(recs))
		for _, rec := range recs {
			byID[rec.ID] = rec
			ids = append(ids, rec.ID)
		}
		fetch = func(id string) (*identity.Record, error) {
			if rec := byID[id]; rec != nil {
				return rec, nil
			}
			return nil, fmt.Errorf("sandfs not found: %s", id)
		}
	}
	items, next, truncated := listPage(ids, cursor, limit, fetch)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pagedList{Items: items, NextCursor: next, Truncated: truncated})
}

// errDeleteBecameActive marks a delete that lost the record to a concurrent
// attach after its drain. The attach's mount was not part of that drain, so
// the operator must retry (the next delete drains it) rather than deleting the
// volume underneath a live mount.
var errDeleteBecameActive = fmt.Errorf("sandfs became active during delete — retry")

// ensureDeletingGate moves the record to "deleting", or proves it is already
// there. A record that cannot be read (other than provably missing) aborts the
// delete: a store outage must never degrade into an ungated volume removal.
//
// refuseActive rejects an ACTIVE record — the post-drain call uses it, because
// at that point active means a concurrent attach completed after the drain.
// The pre-drain call must allow active→deleting (the operator's delete wins)
// so the following drain runs under the gate.
//
// A cache miss is re-checked through FreshReader when the store has one: the
// lazy negative cache may lag a create by one watch event, and "absent"
// licenses the terminal volume deletion — it must be a linearizable answer.
func (h *HumanHandler) ensureDeletingGate(sandfsID string, refuseActive bool) (*identity.Record, error) {
	rec, err := h.identityStore.GetSandFS(sandfsID)
	if errors.Is(err, identity.ErrSandFSNotFound) {
		if fr, ok := h.identityStore.(identity.FreshReader); ok {
			fresh, ferr := fr.GetSandFSFresh(sandfsID)
			switch {
			case errors.Is(ferr, identity.ErrSandFSNotFound):
				return nil, nil
			case ferr != nil:
				return nil, fmt.Errorf("delete gate: confirm absent sandfs %s: %w", sandfsID, ferr)
			default:
				rec, err = fresh, nil
			}
		} else {
			return nil, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("delete gate: read sandfs %s: %w", sandfsID, err)
	}
	status := rec.Status
	for attempt := 0; attempt < 3; attempt++ {
		if status == identity.SandfsStatusDeleting {
			rec.Status = identity.SandfsStatusDeleting
			return rec, nil
		}
		if refuseActive && status == "" {
			return nil, fmt.Errorf("%w (status %q)", errDeleteBecameActive, status)
		}
		applied, current, cerr := h.casStatus(sandfsID, status, identity.SandfsStatusDeleting)
		if cerr != nil {
			return nil, fmt.Errorf("delete gate: %w", cerr)
		}
		if applied || current == identity.SandfsStatusDeleting {
			rec.Status = identity.SandfsStatusDeleting
			return rec, nil
		}
		status = current
	}
	return nil, fmt.Errorf("delete gate: sandfs %s did not reach deleting (status %q) — retry", sandfsID, status)
}

// teardownSandfs is the FULL deletion teardown shared by the sandfs and agent
// delete paths: lifecycle-gate new execs ("deleting"), drain every mount
// (bounded wait — on deadline the deletion PROCEEDS: the operator asked for
// the sandfs to go; the exec gate keeps blocking new requests regardless),
// clean host-side overlays, delete the volume + identity record, then release
// the etcd ownership key with a SYNCHRONOUS bounded retry (an orphaned plain
// key is unbounded garbage at fleet churn — the caller must learn it failed).
//
//   - The unmount/overlay cleanup must precede storage removal — os.RemoveAll
//     fails with EBUSY while rootfs/ is a mount point (best-effort: an offline
//     node's overlay is cleaned by the sandlot reaper on its restart).
//   - The ownership key (/sandswap/owner/{id}, NO lease) is released only at
//     the END: with the exec gate in "deleting" state, a peer that claims and
//     mounts mid-delete is refused at its own gate (409), so the ordering is
//     safe even under the deadline-elapsed shortcut.
func (h *HumanHandler) teardownSandfs(sandfsID string, drainWaitSec int) error {
	rec, recErr := h.identityStore.GetSandFS(sandfsID)
	if recErr != nil && !errors.Is(recErr, identity.ErrSandFSNotFound) {
		// An unreadable record is not "absent": never remove the volume on a
		// store outage. ensureDeletingGate's fresh-read fallback only licenses
		// a provable miss.
		return fmt.Errorf("delete %s: read record: %w", sandfsID, recErr)
	}
	initialDetached := recErr == nil && rec.Status == identity.SandfsStatusDetached
	// The delete gate is a PRECONDITION, not a best-effort write: if the
	// record cannot be moved to deleting (or proven gone), nothing is removed.
	// The gate returns the record it verified (including one recovered through
	// a FreshReader when the lazy cache lagged), so the drain never runs
	// against a stale/absent cache view.
	gated, err := h.ensureDeletingGate(sandfsID, false)
	if err != nil {
		return err
	}
	if gated != nil && !initialDetached {
		// Result ignored ON PURPOSE (a drain deadline does not block the
		// operator's delete); the gate keeps new execs out.
		_, _ = h.lifecycleDrain(sandfsID, gated, identity.SandfsStatusDeleting, drainWaitSec)
	}

	// Final gate: a split-mode drain settles to detached, and an attach can
	// complete from detached in that window. Re-arm deleting; if the record is
	// active, an attach landed after the drain — refuse and let the operator
	// retry (the next delete drains the new mount).
	gated, err = h.ensureDeletingGate(sandfsID, true)
	if err != nil {
		return err
	}

	// Overlay cleanup uses the verified record; a record that is now gone
	// leaves the entry-time path.
	rootfsPath := ""
	if gated != nil {
		rootfsPath = gated.RootFSPath
	} else if recErr == nil {
		rootfsPath = rec.RootFSPath
	}
	if h.pool != nil {
		// The volume path is the RECORD's (names are seed-derived and cannot be
		// recomputed here — see sandlot/provision/volname). A record that is
		// already gone leaves nothing to clean: the delete proceeds.
		if rootfsPath != "" {
			h.pool.CleanupOverlayForSandFS(sandfsID, rootfsPath)
		} else if recErr == nil {
			h.logger.Warn("teardown: record carries no rootfs_path — skipping overlay cleanup", "sandfsID", sandfsID)
		}
	}
	if err := h.registry.Delete(sandfsID); err != nil {
		return err
	}
	if h.ownership != nil {
		if syncRel, ok := h.ownership.(OwnershipSyncReleaser); ok {
			if err := syncRel.ReleaseOwnershipSync(sandfsID, ownershipReleaseAttempts); err != nil {
				return fmt.Errorf("sandfs deleted but ownership key release FAILED (orphaned etcd key — reclaim via reap-stuck): %w", err)
			}
			// SPLIT deployments: this gateway is not the owner, so its release is
			// a foreign-refusal no-op — the exec OWNER releases the key when its
			// drain settles to "detached". The delete's success signal is the key
			// being ABSENT: a lingering key 307-routes a later sandfs reusing the
			// id to a gateway that no longer knows it.
			if err := h.waitOwnershipKeyAbsent(sandfsID, ownershipKeyAbsentWait); err != nil {
				return fmt.Errorf("sandfs deleted but %w", err)
			}
		} else {
			h.ownership.ReleaseOwnership(sandfsID)
		}
	}
	return nil
}

// ownershipKeyAbsentWait bounds the delete teardown's wait for the ownership key
// to disappear after the owner's settle release. The owner's release completes
// synchronously before it writes "detached", so in the normal split flow the
// key is already gone when the human gateway observes the settle; the budget
// only covers a watch/etcd lag.
const ownershipKeyAbsentWait = 5 * time.Second

// ownershipKeyAbsentPollGap is the poll cadence of waitOwnershipKeyAbsent.
const ownershipKeyAbsentPollGap = 100 * time.Millisecond

// waitOwnershipKeyAbsent polls the ownership key until it disappears or the
// budget elapses. A nil etcd client (single-node) reports absent: there is no
// ownership state to wait on.
func (h *HumanHandler) waitOwnershipKeyAbsent(sandfsID string, budget time.Duration) error {
	if h.etcdClient == nil {
		return nil
	}
	deadline := time.Now().Add(budget)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, err := h.etcdClient.Get(ctx, lease.OwnershipKey(sandfsID))
		cancel()
		if err != nil {
			return fmt.Errorf("ownership key lookup failed: %w", err)
		}
		if len(resp.Kvs) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("ownership key for %s is still held by another gateway after %v (the owner releases it when its drain settles; if that gateway is gone, reclaim via reap-stuck)",
				sandfsID, budget)
		}
		time.Sleep(ownershipKeyAbsentPollGap)
	}
}

// OwnershipSyncReleaser is the synchronous ownership-release capability used
// by the delete teardown. Implemented by *lease.OwnershipCache.
type OwnershipSyncReleaser interface {
	ReleaseOwnershipSync(sandfsID string, attempts int) error
}

// ownershipReleaseAttempts bounds the synchronous ownership-key delete retry.
const ownershipReleaseAttempts = 5

func (h *HumanHandler) deleteSandFS(w http.ResponseWriter, r *http.Request, sandfsID string) {
	if err := h.teardownSandfs(sandfsID, defaultDetachWaitSec); err != nil {
		// Through the ONE storage-error mapping table: DeleteVolume raises the
		// same VOLUME_IDENTITY_MISMATCH class as the create/swap paths (its
		// node text embeds the volume path and the foreign sandfs id), and an
		// unknown/missing storage plane is the same named 503 here as
		// everywhere else. Unmapped failures keep the raw 500 + text.
		h.writeStorageErr(w, err, "delete sandfs")
		return
	}
	h.logger.Info("sandfs deleted", "sandfsID", sandfsID)
	w.WriteHeader(http.StatusNoContent)
}

// getSandFS handles GET /human/sandfs/{id} — the single-record view used to
// poll the swap lifecycle status (the list endpoints stay paginated).
func (h *HumanHandler) getSandFS(w http.ResponseWriter, r *http.Request, sandfsID string) {
	rec, err := h.identityStore.GetSandFS(sandfsID)
	if err != nil {
		writeJSONError(w, "sandfs not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rec)
}

// ── Template swap lifecycle (detach / attach / swap) ────────────

// defaultDetachWaitSec bounds one detach/drain call. A drain normally
// completes in tens of ms (unmount RPC + overlay cleanup); the budget exists
// for in-flight sync execs — the node-side unmount deliberately waits them
// out via the mount gate, and a max-length exec (180s) needs the operator to
// pass a proportionate wait_sec.
const defaultDetachWaitSec = 15

// agentDeleteWaitSec is the per-sandfs drain budget inside an agent deletion:
// shorter than the single delete (an agent with many sandfs must not hold the
// HTTP request open for N × 15s); on deadline the deletion proceeds.
const agentDeleteWaitSec = 5

// maxDrainWaitSec is the ceiling a caller-supplied detach/swap wait_sec is
// clamped to. The drain blocks an HTTP handler goroutine and pins the sandfs
// in "detaching" until it settles or the budget expires; the human listeners'
// write deadline is 11 min (gateway/app/human.go, sized so the 10-min
// attach/auto-pull budget can deliver a response), so a larger wait could
// never deliver one anyway. 600s covers the longest legal wait (draining a
// max-length sync exec: <300s) and stays inside that listener budget. The
// response reports the applied value.
const maxDrainWaitSec = 600

// clampDrainWaitSec bounds a caller-supplied drain budget. Zero and negative
// keep their "use the default" meaning (see lifecycleDrain).
func clampDrainWaitSec(waitSec int) int {
	if waitSec > maxDrainWaitSec {
		return maxDrainWaitSec
	}
	if waitSec < 0 {
		return 0
	}
	return waitSec
}

// lifecyclePollInterval is the split-mode cadence for watching the record
// status until the exec-side drain settles it to "detached".
const lifecyclePollInterval = 250 * time.Millisecond

// DetachTemplateRequest is the body for POST /human/sandfs/{id}/detach-template.
type DetachTemplateRequest struct {
	// WaitSec bounds the drain wait. 0 = default (15s); values above
	// maxDrainWaitSec are clamped (the response reports the applied value).
	WaitSec int `json:"wait_sec"`
}

// DetachTemplateResponse reports the lifecycle state after the call.
type DetachTemplateResponse struct {
	SandfsID string `json:"sandfs_id"`
	Status   string `json:"status"` // "detached" or "detaching"/"deleting" (202)
	// WaitSec is the drain budget this call actually applied: the caller's
	// value, the 15s default, or the clamped ceiling when the request
	// exceeded maxDrainWaitSec.
	WaitSec int `json:"wait_sec"`
}

// lifecycleDrain writes the drain-trigger status and drives the drain to
// "detached":
//   - INLINE (this process holds the pool + lease — single-node, one-gw): the
//     Drainer does it directly within the budget.
//   - SPLIT (no pool here — separate human/exec gateways): the exec gateway
//     holding the sandfs sees the status via its identity watch and drains;
//     this call polls the record until it settles.
//
// A no-owner escape covers the never-mounted case: with no ownership record no
// gateway can hold a warm lease (a cold mount claims ownership first), so the
// status is settled locally. Returns true when the record reads "detached",
// plus the drain budget actually applied (the caller's wait_sec after
// clamping, or the 15s default) so the response can report it.
func (h *HumanHandler) lifecycleDrain(sandfsID string, rec *identity.Record, trigger string, waitSec int) (bool, int) {
	if rec.Status == identity.SandfsStatusDetached {
		return true, 0
	}
	// Clamp at the ONE place the budget is resolved: a caller-supplied
	// wait_sec must never hold this goroutine (and the sandfs's "detaching"
	// pin) beyond the human listener's response budget.
	waitSec = clampDrainWaitSec(waitSec)
	if waitSec <= 0 {
		waitSec = defaultDetachWaitSec
	}
	// Apply the trigger with a STATUS CAS (not a blind write): the record read
	// above may be stale, and a detach racing a delete must never move a
	// deleting record back to detaching (delete wins). The CAS also tells us
	// when there is nothing left to drain (already detached) or when another
	// transition owns the record.
	status, drainOurs, err := h.applyLifecycleTrigger(sandfsID, rec.Status, trigger)
	if err != nil {
		h.logger.Error("lifecycle: trigger status CAS failed",
			"sandfsID", sandfsID, "status", trigger, "error", err)
		return false, waitSec
	}
	if !drainOurs {
		// Detached means the mounts are already released; anything else (a
		// delete that overrode this detach) is not ours to settle.
		return status == identity.SandfsStatusDetached, waitSec
	}
	// The drain tells nodes WHICH volume to release: that is the record's
	// rootfs_path (seed-derived names are not recomputable from the ID here).
	volumePath := rec.RootFSPath
	if volumePath == "" {
		h.logger.Error("lifecycle: record has no rootfs_path — cannot address the volume", "sandfsID", sandfsID)
		return false, waitSec
	}

	if h.drainer != nil {
		if h.drainer.Drain(sandfsID, volumePath, rec.VolumeEpoch, time.Duration(waitSec)*time.Second) {
			settled, final := h.settleDetached(sandfsID, trigger)
			if !settled {
				h.logger.Warn("lifecycle: drain finished but the record left the trigger state before the settle write",
					"sandfsID", sandfsID, "status", final)
			}
			return settled, waitSec
		}
		return false, waitSec // deadline: state stays at trigger; re-issue resumes
	}

	// Split mode: poll the (watch-updated) record until the holder settles it.
	deadline := time.Now().Add(time.Duration(waitSec) * time.Second)
	for {
		if fresh, err := h.identityStore.GetSandFS(sandfsID); err == nil && fresh.Status == identity.SandfsStatusDetached {
			return true, waitSec
		}
		if !time.Now().Before(deadline) {
			// No-owner escape: nothing can be mounted without an owner.
			if h.etcdClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_, lookupErr := lease.LookupOwnerGatewayID(ctx, h.etcdClient, sandfsID)
				cancel()
				switch {
				case errors.Is(lookupErr, lease.ErrNoOwner):
					// Provably no owner: nothing can be mounting this sandfs.
					settled, final := h.settleDetached(sandfsID, trigger)
					if !settled {
						h.logger.Warn("lifecycle: no-owner settle skipped — record moved on",
							"sandfsID", sandfsID, "status", final)
					}
					return settled, waitSec
				case lookupErr != nil:
					// etcd unreachable/corrupt: the owner may still be alive and
					// mounting. Declaring `detached` here would let attach run
					// against a live mount — stay at the trigger state.
					h.logger.Warn("lifecycle: owner lookup failed; NOT settling (mount ownership unknown)",
						"sandfsID", sandfsID, "error", lookupErr)
					return false, waitSec
				}
			}
			h.logger.Warn("lifecycle drain not settled within budget (holder unreachable; re-issue to resume)",
				"sandfsID", sandfsID, "trigger", trigger, "waitSec", waitSec)
			return false, waitSec
		}
		time.Sleep(lifecyclePollInterval)
	}
}

// casStatus applies a lifecycle status transition through the store's CAS seam
// when it has one (both shipped stores do). Falls back to a best-effort
// check-then-act for stores without it (test doubles). Returns whether the
// transition applied and the status the record carries afterwards.
func (h *HumanHandler) casStatus(sandfsID, from, to string) (bool, string, error) {
	if cs, ok := h.identityStore.(identity.StatusCASStore); ok {
		return cs.CompareAndSetSandfsStatus(sandfsID, from, to)
	}
	fresh, err := h.identityStore.GetSandFS(sandfsID)
	if err != nil {
		return false, "", err
	}
	if fresh.Status != from {
		return false, fresh.Status, nil
	}
	if err := h.identityStore.SetSandfsStatus(sandfsID, to); err != nil {
		return false, "", err
	}
	return true, to, nil
}

// applyLifecycleTrigger moves the record into the drain-trigger state under a
// status CAS:
//   - "detaching" applies only from ACTIVE (""): a delete in flight owns the
//     lifecycle, and a record already detaching/detached needs no new write;
//   - "deleting" overrides ACTIVE and DETACHING (the operator's delete must not
//     be blocked by a detach that lost the race) and is idempotent on deleting.
//
// Returns the status the record carries afterwards and whether THIS call owns
// the drain (the record is in the trigger state and must be drained).
func (h *HumanHandler) applyLifecycleTrigger(sandfsID, observed, trigger string) (string, bool, error) {
	from := observed
	for attempt := 0; attempt < 3; attempt++ {
		applied, current, err := h.casStatus(sandfsID, from, trigger)
		if err != nil {
			return "", false, err
		}
		if applied {
			return trigger, true, nil
		}
		switch {
		case current == trigger:
			// Already in the trigger state (a concurrent caller or an earlier
			// partial call): the drain is idempotent, resume it.
			return current, true, nil
		case current == identity.SandfsStatusDetached:
			// Mounts already provably released.
			return current, false, nil
		case trigger == identity.SandfsStatusDeleting && current == identity.SandfsStatusDetaching:
			// Delete wins: retry the CAS from the detaching state it observed.
			from = current
			continue
		default:
			return current, false, nil
		}
	}
	return "", false, fmt.Errorf("lifecycle trigger %q could not be applied after retries", trigger)
}

// settleDetached writes the drain-settled status only FROM the trigger: a
// concurrent delete may have taken the record over (and a completed attach is
// only possible from detached), so a blind write would resurrect a detached
// status over the current transition. Returns whether the record is detached
// and the status it carries when it is not.
func (h *HumanHandler) settleDetached(sandfsID, trigger string) (bool, string) {
	applied, current, err := h.casStatus(sandfsID, trigger, identity.SandfsStatusDetached)
	if err != nil {
		h.logger.Error("lifecycle: settle status CAS failed", "sandfsID", sandfsID, "error", err)
		return false, trigger
	}
	if applied || current == identity.SandfsStatusDetached {
		return true, identity.SandfsStatusDetached
	}
	return false, current
}

// detachTemplate handles POST /human/sandfs/{id}/detach-template: gate execs,
// drain every mount, settle to "detached". Idempotent; re-issue resumes a
// drain that outlived its budget (202).
func (h *HumanHandler) detachTemplate(w http.ResponseWriter, r *http.Request, sandfsID string) {
	rec, err := h.identityStore.GetSandFS(sandfsID)
	if err != nil {
		writeJSONError(w, "sandfs not found", http.StatusNotFound)
		return
	}
	if rec.Mode != "overlay" {
		writeJSONError(w, "detach-template requires an overlay-mode sandfs (flat volumes have no separate template layer)", http.StatusBadRequest)
		return
	}
	// A deletion in flight OWNS the lifecycle: detaching here would flip the
	// status back to "detaching" and let a follow-up attach "resurrect" a
	// sandfs whose terminal delete is mid-drain. Delete wins.
	if rec.Status == identity.SandfsStatusDeleting {
		writeJSONError(w, "sandfs deletion is in progress — the delete owns the lifecycle from here", http.StatusConflict)
		return
	}
	var req DetachTemplateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}

	settled, appliedWaitSec := h.lifecycleDrain(sandfsID, rec, identity.SandfsStatusDetaching, req.WaitSec)
	if settled {
		h.logger.Info("sandfs template detached", "sandfsID", sandfsID)
		writeLifecycleJSON(w, http.StatusOK, DetachTemplateResponse{SandfsID: sandfsID, Status: identity.SandfsStatusDetached, WaitSec: appliedWaitSec})
		return
	}
	// Deadline: report the in-progress state; the drain chain continues.
	fresh, _ := h.identityStore.GetSandFS(sandfsID)
	status := identity.SandfsStatusDetaching
	if fresh != nil && fresh.Status != "" {
		status = fresh.Status
	}
	if status == identity.SandfsStatusDeleting {
		// A delete took the lifecycle over while this detach was draining: the
		// delete owns the record from here (never 202 a detach onto a delete).
		writeJSONError(w, "sandfs deletion is in progress — the delete owns the lifecycle from here", http.StatusConflict)
		return
	}
	writeLifecycleJSON(w, http.StatusAccepted, DetachTemplateResponse{SandfsID: sandfsID, Status: status, WaitSec: appliedWaitSec})
}

// AttachTemplateRequest is the body for POST /human/sandfs/{id}/attach-template.
type AttachTemplateRequest struct {
	TemplateRef string `json:"template_ref"` // required
	// Home policy: "keep" (default) | "archive" | "reset" — what happens to
	// /home/agent when the new template lands (workspace/ is never touched).
	Home string `json:"home"`
}

// AttachTemplateResponse reports the completed attach.
type AttachTemplateResponse struct {
	SandfsID    string `json:"sandfs_id"`
	Template    string `json:"template"`
	Status      string `json:"status"` // "active" (the empty status, named)
	MinVCPUs    uint32 `json:"min_vcpus,omitempty"`
	MinMemoryMB uint64 `json:"min_memory_mb,omitempty"`
}

// attachTemplate handles POST /human/sandfs/{id}/attach-template: re-point
// the detached volume at a new overlay template (storage-plane marker swap +
// home policy), then complete the record in one write. The next exec takes
// the normal cold path and mounts the new template's overlay.
func (h *HumanHandler) attachTemplate(w http.ResponseWriter, r *http.Request, sandfsID string) {
	res, ok := h.attachFlow(w, r, sandfsID)
	if !ok {
		return
	}
	writeLifecycleJSON(w, http.StatusOK, AttachTemplateResponse{
		SandfsID:    sandfsID,
		Template:    res.templateRef,
		Status:      "active",
		MinVCPUs:    res.minVCPUs,
		MinMemoryMB: res.minMemoryMB,
	})
}

// attachResult is the internal attach outcome shared by the attach and swap
// endpoints.
type attachResult struct {
	templateRef string
	minVCPUs    uint32
	minMemoryMB uint64
}

// attachFlow is the attach implementation (no HTTP writing): validation,
// SwapTemplate on the storage plane, record completion. Returns ok=false
// after writing the HTTP error when validation or the op fails.
func (h *HumanHandler) attachFlow(w http.ResponseWriter, r *http.Request, sandfsID string) (*attachResult, bool) {
	rec, err := h.identityStore.GetSandFS(sandfsID)
	if err != nil {
		writeJSONError(w, "sandfs not found", http.StatusNotFound)
		return nil, false
	}
	if rec.Mode != "overlay" {
		writeJSONError(w, "attach-template requires an overlay-mode sandfs", http.StatusBadRequest)
		return nil, false
	}
	if rec.Status != identity.SandfsStatusDetached {
		writeJSONError(w, fmt.Sprintf("sandfs must be detached before attaching a template (current status %q — detach first)", rec.Status), http.StatusConflict)
		return nil, false
	}
	var req AttachTemplateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return nil, false
	}
	if req.TemplateRef == "" {
		writeJSONError(w, "template_ref is required", http.StatusBadRequest)
		return nil, false
	}
	if err := validateTemplateRef(req.TemplateRef); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return nil, false
	}
	switch req.Home {
	case "", storage.HomeKeep, storage.HomeArchive, storage.HomeReset:
	default:
		writeJSONError(w, fmt.Sprintf("invalid home policy %q: must be keep|archive|reset", req.Home), http.StatusBadRequest)
		return nil, false
	}

	ops := h.storageOps()
	if ops == nil {
		writeJSONError(w, "storage plane unavailable: no template manager and no provision instance connected", http.StatusServiceUnavailable)
		return nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute) // auto-pull can move GBs
	defer cancel()
	swap, err := ops.SwapTemplate(ctx, sandfsID, req.TemplateRef, req.Home)
	if err != nil {
		h.writeStorageErr(w, err, "swap template")
		return nil, false
	}
	// The swap rewrites the volume IN PLACE: it must never move. A provisioner
	// answering a different rootfs path (a confused or compromised executor)
	// would leave the record pointing at a directory the exec nodes never
	// verified — refuse instead of persisting the divergence. EnsureVolume has
	// no expected path (the seed-derived name is prov-only), but for
	// an existing record the path is known exactly.
	if swap.RootfsPath != "" && rec.RootFSPath != "" && swap.RootfsPath != rec.RootFSPath {
		h.logger.Error("attach: storage answered a different rootfs path — refusing the swap",
			"sandfsID", sandfsID, "recorded", rec.RootFSPath, "answered", swap.RootfsPath)
		writeJSONError(w, "storage plane answered an unexpected rootfs path — refusing the swap", http.StatusBadGateway)
		return nil, false
	}

	// Record completion in ONE write: new ref, new declared min resources
	// (fall back to the previous values when the new template declares none),
	// status back to active. Single-write so no reader ever sees the new
	// template under a non-active status.
	vcpus, memMB := rec.MinVCPUs, rec.MinMemoryMB
	if swap.MinOK {
		vcpus, memMB = swap.MinVCPUs, swap.MinMemoryMB
	}
	if err := h.identityStore.UpdateSandfsTemplate(sandfsID, req.TemplateRef, vcpus, memMB); err != nil {
		if errors.Is(err, identity.ErrSandfsNotDetached) {
			// A concurrent delete (or a newer detach) took the record after this
			// attach's detached check while the storage swap was running. The
			// swap itself landed and is idempotent: report the state and let the
			// operator re-issue once the sandfs is stable again.
			fresh, _ := h.identityStore.GetSandFS(sandfsID)
			status := ""
			if fresh != nil {
				status = fresh.Status
			}
			h.logger.Warn("attach: record left the detached state during the swap; completion refused",
				"sandfsID", sandfsID, "status", status)
			writeJSONError(w, fmt.Sprintf("sandfs left the detached state during the attach (status %q); the storage swap landed — re-attach once it is stable", status), http.StatusConflict)
			return nil, false
		}
		// Storage is swapped but the record still says detached: the sandfs is
		// recoverable by re-issuing the attach (idempotent same-ref no-op).
		h.logger.Error("attach: record completion failed (re-issue the attach to recover)",
			"sandfsID", sandfsID, "template", req.TemplateRef, "error", err)
		writeJSONError(w, fmt.Sprintf("template swapped but record update failed: %v (re-issue attach-template to recover)", err), http.StatusInternalServerError)
		return nil, false
	}
	h.logger.Info("sandfs template attached", "sandfsID", sandfsID, "template", req.TemplateRef, "home", req.Home)
	return &attachResult{templateRef: req.TemplateRef, minVCPUs: vcpus, minMemoryMB: memMB}, true
}

// SwapTemplateRequest is the body for POST /human/sandfs/{id}/swap-template —
// the one-shot detach+attach composition for the common upgrade path.
type SwapTemplateRequest struct {
	TemplateRef string `json:"template_ref"` // required
	Home        string `json:"home"`         // keep (default) | archive | reset
	WaitSec     int    `json:"wait_sec"`     // drain budget; 0 = default, clamped above maxDrainWaitSec
}

// swapTemplate handles POST /human/sandfs/{id}/swap-template: drain to
// detached (bounded), then attach. When the drain outlives its budget the
// response is 202 (re-issue to resume — the attach never runs on a
// non-detached sandfs).
func (h *HumanHandler) swapTemplate(w http.ResponseWriter, r *http.Request, sandfsID string) {
	// Pre-validate the attach body BEFORE mutating any state: a bad ref or
	// home policy must not leave the sandfs detached for nothing.
	var req SwapTemplateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.TemplateRef == "" {
		writeJSONError(w, "template_ref is required", http.StatusBadRequest)
		return
	}
	if err := validateTemplateRef(req.TemplateRef); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch req.Home {
	case "", storage.HomeKeep, storage.HomeArchive, storage.HomeReset:
	default:
		writeJSONError(w, fmt.Sprintf("invalid home policy %q: must be keep|archive|reset", req.Home), http.StatusBadRequest)
		return
	}

	rec, err := h.identityStore.GetSandFS(sandfsID)
	if err != nil {
		writeJSONError(w, "sandfs not found", http.StatusNotFound)
		return
	}
	if rec.Mode != "overlay" {
		writeJSONError(w, "swap-template requires an overlay-mode sandfs (flat volumes have no separate template layer)", http.StatusBadRequest)
		return
	}
	// Same ownership rule as detach: a deletion in flight wins the lifecycle.
	if rec.Status == identity.SandfsStatusDeleting {
		writeJSONError(w, "sandfs deletion is in progress — the delete owns the lifecycle from here", http.StatusConflict)
		return
	}
	if settled, appliedWaitSec := h.lifecycleDrain(sandfsID, rec, identity.SandfsStatusDetaching, req.WaitSec); !settled {
		fresh, _ := h.identityStore.GetSandFS(sandfsID)
		status := identity.SandfsStatusDetaching
		if fresh != nil && fresh.Status != "" {
			status = fresh.Status
		}
		if status == identity.SandfsStatusDeleting {
			// A delete took the lifecycle over while this swap was draining.
			writeJSONError(w, "sandfs deletion is in progress — the delete owns the lifecycle from here", http.StatusConflict)
			return
		}
		writeLifecycleJSON(w, http.StatusAccepted, DetachTemplateResponse{SandfsID: sandfsID, Status: status, WaitSec: appliedWaitSec})
		return
	}
	// Detached: re-issue the parsed attach body against the drained sandfs.
	attachReq := AttachTemplateRequest{TemplateRef: req.TemplateRef, Home: req.Home}
	if err := r.Body.Close(); err != nil {
		// unreachable in practice: body already drained by the decoder
		_ = err
	}
	attachBody, _ := json.Marshal(attachReq)
	r.Body = io.NopCloser(bytes.NewReader(attachBody))
	res, ok := h.attachFlow(w, r, sandfsID)
	if !ok {
		return
	}
	writeLifecycleJSON(w, http.StatusOK, AttachTemplateResponse{
		SandfsID:    sandfsID,
		Template:    res.templateRef,
		Status:      "active",
		MinVCPUs:    res.minVCPUs,
		MinMemoryMB: res.minMemoryMB,
	})
}

// writeLifecycleJSON writes a lifecycle endpoint response.
func writeLifecycleJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ── Template deletion (in-use check + layer GC) ─────────────────

// DeleteTemplateRequest is the body for DELETE /human/templates/{ref}.
type DeleteTemplateRequest struct {
	// Mode: "flat" | "overlay"; empty = auto-detect (overlay ref first).
	Mode string `json:"mode"`
	// Force skips the in-use check (the escape hatch — deleting an in-use
	// overlay template makes dependent volumes fail their NEXT cold mount
	// with a named error; no data loss: workspace/home are layer-independent).
	// It destroys cluster-shared state other tenants' volumes depend on, so it
	// requires the sandswap:ops/admin scope: a tenant token sending force:true
	// gets a named 403 FORCE_REQUIRES_OPS, identical whether or not any volume
	// holds the ref (no in-use oracle).
	Force bool `json:"force"`
}

// deleteTemplate handles DELETE /human/templates/{ref}: refuse while overlay
// sandfs still reference the ref (two-layer check: this gateway's records,
// then the node-side .template marker scan — which also catches orphan
// volumes whose records are gone), then delete the ref file and GC the
// layers no remaining ref names.
func (h *HumanHandler) deleteTemplate(w http.ResponseWriter, r *http.Request, templateRef string) {
	if !requireOpsScope(w, r) {
		return
	}
	var req DeleteTemplateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Force skips the in-use check and deletes a ref other tenants' volumes
	// may still name (their next cold mount then fails until an operator
	// re-attaches them) plus GCs the layers — a cluster-level destruction a
	// plain sandswap:human tenant token must not reach. Ops/admin only.
	if req.Force && !callerHasOpsScope(r.Context()) {
		writeForceRequiresOps(w)
		return
	}

	// Layer 1 — this gateway's identity records (local cache, fast).
	if !req.Force {
		if count, sample := h.identityStore.CountSandFSByTemplate(templateRef); count > 0 {
			writeTemplateInUse(w, r, count, sample)
			return
		}
	}

	ops := h.storageOps()
	if ops == nil {
		writeJSONError(w, "storage plane unavailable: no template manager and no provision instance connected", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := ops.DeleteTemplate(ctx, templateRef, req.Mode, req.Force); err != nil {
		var inUse *storage.TemplateInUseError
		if errors.As(err, &inUse) {
			// The prov instance scans the volumes ROOT, so its sample carries
			// directory names — which since the seed-derived naming change are
			// OPAQUE (volname.Derive) and cannot be inverted. Translate them
			// back to sandfs IDs through the records (whose RootFSPath is
			// authoritative): an operator reading this payload needs IDs, not
			// names it cannot resolve.
			writeTemplateInUse(w, r, inUse.Count, h.sandfsIDsForVolumeNames(inUse.Sample))
			return
		}
		h.writeStorageErr(w, err, "delete template")
		return
	}
	h.logger.Info("template deleted", "templateRef", templateRef, "mode", req.Mode, "forced", req.Force)
	w.WriteHeader(http.StatusNoContent)
}

// sandfsIDsForVolumeNames maps volume directory names back to sandfs IDs for
// operator-facing messages. Names that match no record are passed through
// (a volume without a record is itself worth seeing), and the mapping is built
// from the identity store's records — the only place the (id -> name)
// direction is ever needed.
func (h *HumanHandler) sandfsIDsForVolumeNames(names []string) []string {
	if len(names) == 0 || h.identityStore == nil {
		return names
	}
	recs, err := h.identityStore.ListAllSandFS()
	if err != nil {
		return names // degrade to names rather than failing the refusal
	}
	byName := make(map[string]string, len(recs))
	for _, rec := range recs {
		if rec.RootFSPath != "" {
			byName[filepath.Base(rec.RootFSPath)] = rec.ID
		}
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if id, ok := byName[n]; ok {
			out = append(out, id)
			continue
		}
		out = append(out, n+" (no record)")
	}
	return out
}

// writeTemplateInUse writes the structured 409 refusal. The COUNT is every
// caller's to see (it names no one); the sampled sandfs ids are the fleet
// census the uniform-404 rule (handler/auth_resolve.go: a distinct 403 would
// let any tenant enumerate others' sandfs) exists to keep non-free — so they
// ride ONLY for a caller carrying the ops/admin grant, the class that can
// already read the whole fleet via /stats. Passthrough (no OIDC claims)
// keeps the historical full payload: no tenancy axis exists in that shape.
func writeTemplateInUse(w http.ResponseWriter, r *http.Request, count int, sample []string) {
	body := map[string]interface{}{
		"error_code":   "TEMPLATE_IN_USE",
		"in_use_count": count,
	}
	if callerHasOpsScope(r.Context()) {
		body["error"] = fmt.Sprintf("template in use by %d overlay sandfs (e.g. %v) — swap them to a new template first", count, sample)
		body["in_use_sample"] = sample
	} else {
		body["error"] = fmt.Sprintf("template in use by %d overlay sandfs — swap or delete them first", count)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	json.NewEncoder(w).Encode(body)
}

// callerHasOpsScope reports whether the request's verified token carries a
// fleet-operations scope (sandswap:ops or sandswap:admin — mTLS client certs
// carry all three). Passthrough (no OIDC configured ⇒ no claims) counts as
// authorized: it matches the namespace scope's fleet passthrough so the
// unauthenticated single-node deployment keeps its historical behavior.
func callerHasOpsScope(ctx context.Context) bool {
	claims := authn.TokenClaimsFromContext(ctx)
	if claims == nil {
		return true
	}
	return claims.HasScope(authn.ScopeOps) || claims.HasScope(authn.ScopeAdmin)
}

// requireOpsScope is the handler-level half of the ops/admin route gate. The
// route already requires the scope; this check keeps the authorization at the
// handler too, so a path that reaches an ops handler by any other routing path
// (the encoded-path %2F class, a future mux change) still refuses a human-only caller.
// It returns false after writing the 403 response.
func requireOpsScope(w http.ResponseWriter, r *http.Request) bool {
	if callerHasOpsScope(r.Context()) {
		return true
	}
	writeJSONError(w, "requires the sandswap:ops or sandswap:admin scope", http.StatusForbidden)
	return false
}

// writeForceRequiresOps writes the force-delete refusal for a caller without
// the ops grant. Deliberately identical whether or not any volume holds the
// ref: a refusal that varied with in-use state would be an oracle for the
// census the sample-gating above hides.
func writeForceRequiresOps(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{
		"error":      "force delete requires the sandswap:ops scope — ask an operator to remove an in-use template",
		"error_code": "FORCE_REQUIRES_OPS",
	})
}

// ── Push Template ────────────────────────────────────────────

// PushTemplateResponse is returned after pushing a template to OCI registry.
type PushTemplateResponse struct {
	TemplateRef string   `json:"template_ref"`
	Digest      string   `json:"digest"`
	Layers      []string `json:"layers"`
	Size        int64    `json:"size"`
	PushTimeMs  int64    `json:"push_time_ms"`
}

func (h *HumanHandler) pushTemplate(w http.ResponseWriter, r *http.Request, templateRef string) {
	if !requireOpsScope(w, r) {
		return
	}
	ops := h.storageOps()
	if ops == nil {
		writeJSONError(w, "storage plane unavailable: no template manager and no provision instance connected", http.StatusServiceUnavailable)
		return
	}

	// Optional body {"mode": "flat"|"overlay"}. An empty body (or an absent
	// mode) auto-detects from whichever mode-suffixed ref file exists,
	// preferring overlay — the pre-mode-parameter behavior.
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = ops.DetectTemplateMode(templateRef)
		if mode == "" {
			writeJSONError(w, fmt.Sprintf("template not found: %s", templateRef), http.StatusNotFound)
			return
		}
	}

	resp, err := ops.PushTemplate(r.Context(), templateRef, mode)
	if err != nil {
		h.writeStorageErr(w, err, "push template")
		return
	}

	h.logger.Info("template pushed", "templateRef", templateRef)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PushTemplateResponse{
		TemplateRef: resp.TemplateRef,
		Digest:      resp.Digest,
		Layers:      resp.Layers,
		Size:        resp.Size,
		PushTimeMs:  resp.PushTimeMs,
	})
}

// SaveAsTemplateRequest is the body for POST /human/sandfs/:id/save-template.
type SaveAsTemplateRequest struct {
	TemplateRef string `json:"template_ref"` // e.g., "sqlite:v2"
	Description string `json:"description"`
	VCPUs       uint32 `json:"vcpus,omitempty"`     // minimum vCPUs; defaults to the source sandfs's value
	MemoryMB    uint64 `json:"memory_mb,omitempty"` // minimum memory MB; defaults to the source sandfs's value
}

// SaveAsTemplateResponse is returned after saving a SandFS as a local template.
type SaveAsTemplateResponse struct {
	TemplateRef string `json:"template_ref"`
	Path        string `json:"path"`
	SizeKB      int64  `json:"size_kb"`
}

func (h *HumanHandler) saveAsTemplate(w http.ResponseWriter, r *http.Request, sandfsID string) {
	// TEMPLATE CREATION IS OPS/ADMIN: ordinary namespace users only list and
	// USE templates. Anonymous/passthrough (no OIDC claims, the dev shape)
	// counts as operator, matching callerHasOpsScope's fleet semantics.
	if !callerHasOpsScope(r.Context()) {
		if h.logger != nil {
			h.logger.Warn("save-template refused: template creation requires the ops or admin scope", "sandfsID", sandfsID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error":      "creating a template from a sandfs requires the ops or admin scope; namespace users list and use templates",
			"error_code": "TEMPLATE_OPS_REQUIRED",
		})
		return
	}
	// Lifecycle gate: snapshotting a sandfs mid swap/deletion would capture a
	// half-transitioned volume. Detached state is fine to snapshot (the volume
	// is quiesced) — but save-template is flat-only anyway, and flat sandfs
	// never enter the lifecycle states; the check is defense in depth.
	if rec, err := h.identityStore.GetSandFS(sandfsID); err == nil && !rec.IsActive() {
		writeJSONError(w, fmt.Sprintf("sandfs is not active (status %q)", rec.Status), http.StatusConflict)
		return
	}
	ops := h.storageOps()
	if ops == nil {
		writeJSONError(w, "storage plane unavailable: no template manager and no provision instance connected", http.StatusServiceUnavailable)
		return
	}

	var req SaveAsTemplateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.TemplateRef == "" {
		writeJSONError(w, `template_ref is required (e.g., "sqlite:v2")`, http.StatusBadRequest)
		return
	}
	// The ref enters a prov op (SaveAsTemplate) — apply the node's charset rule
	// here so an impossible ref is a named 400 without a storage round trip
	// (create/attach/swap already validate; the save path used to skip it, so a
	// ref no node could ever accept reached the provisioner and failed there).
	if err := validateTemplateRef(req.TemplateRef); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Inherit the minimum vcpus/memory from the source sandfs's record; the
	// request may override either. These become the defaults a sandfs created
	// from this template gets (unless its own create request overrides them).
	vcpus := req.VCPUs
	memMB := req.MemoryMB
	if vcpus == 0 || memMB == 0 {
		if rec, gerr := h.registry.Store().GetSandFS(sandfsID); gerr == nil {
			if vcpus == 0 {
				vcpus = rec.MinVCPUs
			}
			if memMB == 0 {
				memMB = rec.MinMemoryMB
			}
		}
	}

	resp, err := ops.SaveAsTemplate(sandfsID, storage.SaveAsRequest{
		TemplateRef: req.TemplateRef,
		Description: req.Description,
		VCPUs:       vcpus,
		MemoryMB:    memMB,
	})
	if err != nil {
		h.writeStorageErr(w, err, "save as template")
		return
	}

	h.logger.Info("sandfs saved as template", "sandfsID", sandfsID, "template", req.TemplateRef)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SaveAsTemplateResponse{
		TemplateRef: resp.TemplateRef,
		Path:        resp.Path,
		SizeKB:      resp.SizeKB,
	})
}

// ── Templates ──────────────────────────────────────────────────

// TemplateSummary is a summary of a cached template.
type TemplateSummary struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Mode        string `json:"mode"` // "flat" | "overlay"
	Cached      bool   `json:"cached"`
}

func (h *HumanHandler) listTemplates(w http.ResponseWriter, r *http.Request) {
	ops := h.storageOps()
	if ops == nil {
		// Historical shape on an unavailable storage plane: an empty array (the
		// /stats endpoint carries the availability signal, a list is not an
		// availability probe).
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]TemplateSummary{})
		return
	}

	infos := ops.ListTemplates()
	summaries := make([]TemplateSummary, 0, len(infos))
	for _, t := range infos {
		summaries = append(summaries, TemplateSummary{
			Name:        t.Name,
			Version:     t.Version,
			Description: t.Description,
			Mode:        t.Mode,
			Cached:      true,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summaries)
}

// PullTemplateResponse is returned after pulling a template.
type PullTemplateResponse struct {
	TemplateRef string `json:"template_ref"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Cached      bool   `json:"cached"`
}

func (h *HumanHandler) pullTemplate(w http.ResponseWriter, r *http.Request, templateRef string) {
	if !requireOpsScope(w, r) {
		return
	}
	ops := h.storageOps()
	if ops == nil {
		writeJSONError(w, "storage plane unavailable: no template manager and no provision instance connected", http.StatusServiceUnavailable)
		return
	}

	// Optional body {"mode": "flat"|"overlay"}. Empty (or absent body) pulls
	// in overlay mode — the historical behavior. Flat mode reads only the
	// manifest and records the layer digests; the blobs stream straight into
	// each SandFS volume at creation time.
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}

	tmpl, err := ops.PullTemplate(r.Context(), templateRef, req.Mode)
	if err != nil {
		h.writeStorageErr(w, err, "pull template")
		return
	}

	h.logger.Info("template pulled", "templateRef", templateRef)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PullTemplateResponse{
		TemplateRef: templateRef,
		Name:        tmpl.Name,
		Version:     tmpl.Version,
		Cached:      true,
	})
}

// ── Health / Stats ─────────────────────────────────────────────

func (h *HumanHandler) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body := map[string]interface{}{"status": "ok"}
	// Liveness only. Pool topology (node ids, VM counts) is ops data served by
	// /stats behind the ops scope; an UNAUTHENTICATED listener must not leak
	// the fleet layout. provisioners stays: it is a single count the deploy
	// readiness gate keys on, not topology.

	// provisioners = connected prov-role instances. 0 means every storage op
	// (sandfs create/delete, templates) will 503 — the deploy tooling's
	// readiness gate and operator dashboards both key on this.
	if h.provisionerCount != nil {
		body["provisioners"] = h.provisionerCount()
	}
	json.NewEncoder(w).Encode(body)
}

// stats handles GET /stats. Returns the unified StatsReport: in distributed
// mode (etcdClient != nil) it aggregates every gateway's
// /sandswap/{load,health,gateway}/ keys — the same keys the DNS reads, so the
// views match. In single-node mode (etcdClient == nil) it falls back to the
// local pool manager, producing the same shape with a single self entry.
func (h *HumanHandler) stats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rep, err := BuildStatsReport(ctx, h.etcdClient, h.gatewayID, h.pool, h.unmountSnapshot(), h.redactTenantIDs, h.logger)
	if h.maintenance != nil {
		refusing, reason := h.maintenance.Snapshot()
		rep.Maintenance = &MaintenanceState{Refusing: refusing, Reason: reason}
	}
	if h.rotation != nil {
		refusing, reason := h.rotation.Snapshot()
		rep.Rotation = &MaintenanceState{Refusing: refusing, Reason: reason}
	}
	if h.provSeedSource != nil {
		rep.ProvSeeds = h.provSeedSource()
	}
	if h.egressBindingSource != nil {
		rep.EgressBindings = h.egressBindingSource()
	}
	if err != nil {
		writeJSONError(w, "stats: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := renderStatsJSON(rep)
	if err != nil {
		writeJSONError(w, "stats: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

// ── Ownership Release ──────────────────────────────────────────────

// releaseOwnership handles POST /human/ownership/release/{sandfs_id}.
// It releases ownership of a sandfs so another gateway can Claim it (manual
// cross-gateway rebalance). Idempotent: returns 200 even if the sandfs has no
// ownership.
func (h *HumanHandler) releaseOwnership(w http.ResponseWriter, r *http.Request, sandfsID string) {
	if !requireOpsScope(w, r) {
		return
	}
	if sandfsID == "" {
		writeJSONError(w, "sandfs_id is required", http.StatusBadRequest)
		return
	}

	if h.ownership == nil {
		// Single-node mode: no ownership tracking, always succeeds
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":    "ok",
			"sandfs_id": sandfsID,
			"mode":      "single-node",
		})
		return
	}

	h.ownership.ReleaseOwnership(sandfsID)
	h.logger.Info("ownership released via API", "sandfs_id", sandfsID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "released",
		"sandfs_id": sandfsID,
	})
}

// reapStuckOwnershipRequest is the body for POST /human/ownership/reap-stuck.
type reapStuckOwnershipRequest struct {
	// GatewayID is the permanently-dead owner whose stranded sandfs to reclaim.
	// Required. Must not be this gateway.
	GatewayID string `json:"gateway_id"`
	// DryRun reports what WOULD be deleted without deleting. Default false.
	DryRun bool `json:"dry_run"`
	// BatchSize caps how many candidates ONE call processes (default 100).
	// Re-issue while reaped_count == batch_size. (It is NOT an etcd Txn batch:
	// every candidate is its own ModRevision-CAS Txn — see reapDeleteCAS.)
	BatchSize int `json:"batch_size"`
}

// reapStuckOwnership is the manual both-dead reclamation tool: reclaim sandfs
// stranded on a permanently-dead owner gateway. Idle sandfs are reaped (owner
// dead); mounted sandfs are reaped only if the node's presence key is gone
// (node also dead past T_safe). Dry-run reports without deleting. Operator
// workflow: confirm the owner gateway AND its nodes are permanently gone, then
// dry-run to preview, then run for real.
func (h *HumanHandler) reapStuckOwnership(w http.ResponseWriter, r *http.Request) {
	if !requireOpsScope(w, r) {
		return
	}
	if h.stuckReaper == nil {
		writeJSONError(w, "reap-stuck unavailable (single-node mode / no etcd coordination layer)", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var req reapStuckOwnershipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.GatewayID == "" {
		writeJSONError(w, "gateway_id is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	report, err := h.stuckReaper.ReapStuckOwnership(ctx, req.GatewayID, req.DryRun, req.BatchSize)
	if err != nil {
		// A refusal (self-reap / live owner) or a batch failure mid-reap: return
		// the partial report (if any) with a non-200 so the operator sees what
		// happened. Refusals are 409 (classified by sentinel, not message text).
		status := http.StatusInternalServerError
		if errors.Is(err, lease.ErrCannotReapSelf) || errors.Is(err, lease.ErrOwnerStillAlive) {
			status = http.StatusConflict
		}
		if report != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":  err.Error(),
				"report": report,
			})
			return
		}
		writeJSONError(w, err.Error(), status)
		return
	}

	h.logger.Info("reap-stuck via API", "owner", req.GatewayID, "dry_run", req.DryRun,
		"reaped", report.ReapedCount, "skipped", report.SkippedCount)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// reapStuckNodeOwnershipRequest is the body for POST /human/ownership/reap-stuck-node.
type reapStuckNodeOwnershipRequest struct {
	// NodeID is the permanently-dead sandlot node whose mounted sandfs to
	// reclaim. Required.
	NodeID string `json:"node_id"`
	// DryRun reports what WOULD be deleted without deleting. Default false.
	DryRun bool `json:"dry_run"`
	// BatchSize caps how many candidates ONE call processes (default 100) —
	// see reapStuckOwnershipRequest.BatchSize.
	BatchSize int `json:"batch_size"`
}

// reapStuckNodeOwnership is the node-granularity manual reclamation tool:
// reclaim every sandfs recorded as mounted on a permanently-dead sandlot node
// whose owner is also dead. Refused (409) if the node's presence key is still
// alive (the node may still be tolerating — do not race a live node). SandFS
// whose owner is still alive are skipped (the owner's release chain handles
// them). Single-node / no etcd → 503.
func (h *HumanHandler) reapStuckNodeOwnership(w http.ResponseWriter, r *http.Request) {
	if !requireOpsScope(w, r) {
		return
	}
	if h.stuckReaper == nil {
		writeJSONError(w, "reap-stuck-node unavailable (single-node mode / no etcd coordination layer)", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var req reapStuckNodeOwnershipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.NodeID == "" {
		writeJSONError(w, "node_id is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	report, err := h.stuckReaper.ReapStuckNodeOwnership(ctx, req.NodeID, req.DryRun, req.BatchSize)
	if err != nil {
		// A refusal (live node) or a batch failure mid-reap: return the partial
		// report (if any) with a non-200 so the operator sees what happened.
		// Refusals are 409 (classified by sentinel, not message text).
		status := http.StatusInternalServerError
		if errors.Is(err, lease.ErrNodeStillPresent) {
			status = http.StatusConflict
		}
		if report != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":  err.Error(),
				"report": report,
			})
			return
		}
		writeJSONError(w, err.Error(), status)
		return
	}

	h.logger.Info("reap-stuck-node via API", "node", req.NodeID, "dry_run", req.DryRun,
		"reaped", report.ReapedCount, "skipped", report.SkippedCount)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}
