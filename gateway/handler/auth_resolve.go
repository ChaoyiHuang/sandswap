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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gateway/identity"
	"gateway/stream"
)

// verifyAPIKeyHeader resolves the presented API key BEFORE the request body
// is read. Every body-carrying agent endpoint calls this first: without it an
// unauthenticated caller can make the gateway allocate and decode a 10–50 MB
// body only to answer 401 (an off-path OOM amplification). The later
// ResolveFromRequest still re-derives sandfs ownership; the second key
// lookup hits the in-process (or lazy-cache) hot path.
func verifyAPIKeyHeader(w http.ResponseWriter, r *http.Request, store identity.Store) bool {
	key, err := identity.ExtractAPIKey(r)
	if err != nil {
		writeJSONError(w, "missing api key", http.StatusUnauthorized)
		return false
	}
	if store == nil {
		writeJSONError(w, "identity store unavailable", http.StatusServiceUnavailable)
		return false
	}
	if _, err := store.ResolveAgent(key); err != nil {
		writeJSONError(w, "invalid api key", http.StatusUnauthorized)
		return false
	}
	return true
}

// ResolvedIdentity is the result of connection-level auth + request-level
// addressing for a single request. Shared by HTTP handlers and MCP tool handlers.
type ResolvedIdentity struct {
	AgentID     string
	SandfsID    string
	RootFSPath  string
	VolumeEpoch string
	MinVCPUs    uint32
	MinMemoryMB uint64
	Template    string
	// Mode is the record's mode ("flat"/"overlay"). Kept so handlers can
	// derive the node-facing template handshake below without re-reading the
	// record.
	Mode            string
	InstallPackages bool
	// Status is the sandfs lifecycle status snapshot from the same record read
	// ("" = active). Executing/file handlers gate on it; exec status/kill do
	// NOT (their graceful degradation when unmounted — "expired" — is the
	// correct answer mid-swap).
	Status string
}

// ResolveFromRequest performs connection-level auth + request-level addressing.
// This is the unified entry point used by both HTTP handlers and MCP tool handlers.
//
// Flow: api_key → Agent (auth) → sandfs_id → SandFS (addressing) → ownership check (authz).
func ResolveFromRequest(store identity.Store, apiKey string, sandfsID string) (*ResolvedIdentity, error) {
	// 1. Auth: api_key → agent
	agent, err := store.ResolveAgent(apiKey)
	if err != nil {
		return nil, &authHTTPError{code: http.StatusUnauthorized, msg: "invalid api key"}
	}

	return resolveFromAgent(store, agent, sandfsID)
}

// ResolveFromPreAuthAgent performs request-level addressing with a pre-resolved agent.
// Used when resolveSandfsID has already called ResolveAgent (avoids redundant lookup).
func ResolveFromPreAuthAgent(store identity.Store, agent *identity.Agent, sandfsID string) (*ResolvedIdentity, error) {
	return resolveFromAgent(store, agent, sandfsID)
}

// resolveFromAgent is the shared implementation for ResolveFromRequest and
// ResolveFromPreAuthAgent. It performs sandfs lookup + ownership check.
func resolveFromAgent(store identity.Store, agent *identity.Agent, sandfsID string) (*ResolvedIdentity, error) {
	// 2. Address: sandfs_id → sandfs
	sandfs, err := store.GetSandFS(sandfsID)
	if err != nil {
		return nil, &authHTTPError{code: http.StatusNotFound, msg: "sandfs not found"}
	}

	// 3. Authorization: agent owns this sandfs.
	// answered EXACTLY like a missing sandfs (same 404, same body) —
	// a distinct 403 let any authenticated tenant census other tenants'
	// sandfs ids (the id-disclosure finding made that free). The
	// caller cannot distinguish "not yours" from "does not exist".
	if sandfs.AgentID != agent.ID {
		return nil, &authHTTPError{code: http.StatusNotFound, msg: "sandfs not found"}
	}

	// Fail closed on a record the node would refuse anyway (or, worse, that
	// would reach it with an empty identity): the node validates the mode
	// again, but the gateway must not ship a corrupt record down the mount
	// path. These are construction bugs / storage corruption, not user input —
	// the create path validates both fields.
	if sandfs.Mode != "flat" && sandfs.Mode != "overlay" {
		return nil, &authHTTPError{code: http.StatusInternalServerError, msg: "sandfs record has an invalid volume mode"}
	}
	if sandfs.RootFSPath == "" {
		return nil, &authHTTPError{code: http.StatusInternalServerError, msg: "sandfs record has no volume path"}
	}

	return &ResolvedIdentity{
		AgentID:         agent.ID,
		SandfsID:        sandfs.ID,
		RootFSPath:      sandfs.RootFSPath,
		VolumeEpoch:     sandfs.VolumeEpoch,
		MinVCPUs:        sandfs.MinVCPUs,
		MinMemoryMB:     sandfs.MinMemoryMB,
		Template:        sandfs.Template,
		Mode:            sandfs.Mode,
		InstallPackages: sandfs.AllowsPackageInstall(), // derived from mode: flat→allow, overlay→deny
		Status:          sandfs.Status,
	}, nil
}

// MountTemplateRef is the template ref the NODE should receive in mount
// commands: the record's template for overlay sandfs, "" for flat ones. The
// node treats a marker at the volume root as storage truth (a template swap
// can land there while the node is offline) — and in FLAT mode the volume
// root IS the agent's chroot root, so the marker path is agent-writable.
// Sending "" for flat records tells the node "this sandfs has no template",
// which is what lets it ignore an agent-planted marker instead of honoring
// it (a planted marker otherwise flips the volume into an unresolvable
// overlay mount — a self-inflicted wedge plus platform churn).
func (r *ResolvedIdentity) MountTemplateRef() string {
	if r.Mode == "flat" || r.Template == "" {
		return ""
	}
	return r.Template
}

// ErrSandfsNotActive is the named gate error for execs/file ops arriving while
// the sandfs is in a non-active lifecycle state (template swap or deletion in
// progress). Retryable: the state is transient by design.
var ErrSandfsNotActive = fmt.Errorf("sandfs is not active (template swap or deletion in progress)")

// errNotActive builds the structured 409 for a gated request.
func errNotActive(status string) error {
	return &resilienceError{
		code:         http.StatusConflict,
		msg:          fmt.Sprintf("sandfs is not active (status %q): %s", status, ErrSandfsNotActive),
		errorCode:    "SANDFS_NOT_ACTIVE",
		retryAfterMs: 1000,
	}
}

// gateActive enforces the sandfs lifecycle gate for executing/file requests:
// a non-active status refuses with a retryable 409. store is only consulted
// when the gate TRIPS — one linearizable re-read to rule out a stale-cache
// false positive (the attach flow just wrote status back to active and the
// local watch cache may lag by milliseconds). The hot path (active status)
// pays a single struct-field comparison and no store access.
func gateActive(store identity.Store, id *ResolvedIdentity) error {
	if id.Status == "" {
		return nil
	}
	// Gate tripped. Re-check against the store of record: an EtcdStore's
	// FreshReader does a direct quorum read (no watch lag); a MemoryStore's
	// in-memory record IS the truth. If the re-read says active, refresh the
	// resolved snapshot and let the request through.
	var fresh *identity.Record
	var err error
	if fr, ok := store.(identity.FreshReader); ok {
		fresh, err = fr.GetSandFSFresh(id.SandfsID)
	} else {
		fresh, err = store.GetSandFS(id.SandfsID)
	}
	if err == nil && fresh != nil && fresh.Status == "" {
		id.Status = fresh.Status
		id.Template = fresh.Template
		id.MinVCPUs = fresh.MinVCPUs
		id.MinMemoryMB = fresh.MinMemoryMB
		return nil
	}
	return errNotActive(id.Status)
}

// authHTTPError is a sentinel for HTTP error responses from ResolveFromRequest.
type authHTTPError struct {
	code int
	msg  string
}

func (e *authHTTPError) Error() string { return e.msg }

// writeAuthError writes an auth/addr error as an HTTP JSON error response.
func writeAuthError(w http.ResponseWriter, err error) {
	if he, ok := err.(*authHTTPError); ok {
		writeJSONError(w, he.msg, he.code)
		return
	}
	writeJSONError(w, err.Error(), http.StatusInternalServerError)
}

// writeJSONError writes a JSON error response with the given HTTP status code.
// Uses json.Marshal to avoid injection vulnerabilities from string concatenation.
func writeJSONError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// resilienceError is a structured error for resilience-related failures
// (concurrent mount, sandbox cleaning, ownership conflict, etc.).
// It carries an error_code for programmatic handling by AI agents and a
// retry_after_ms hint for retry scheduling.
type resilienceError struct {
	code         int
	msg          string
	errorCode    string // "CONCURRENT_MOUNT", "SANDBOX_CLEANING", "OWNER_NODE_DOWN", etc.
	retryAfterMs int    // 0 = no retry hint
	// shedRebalance marks a voluntary-shed error (SHED_REBALANCE). When
	// true, the response is emitted as a raw transport-level 503 with
	// Connection: close (NOT a JSON body / NOT an MCP isError tool result): the
	// client must close the connection and re-resolve the sandfs DNS name so the
	// Sandswap DNS routes it to the peer that now should claim it. This bypasses
	// the normal resilience-error JSON encoding because a tool-result error would
	// be surfaced to the LLM, not retried at the transport layer.
	shedRebalance bool
}

func (e *resilienceError) Error() string { return e.msg }

// AsResilienceError extracts structured resilience error fields from an error.
// Returns ok=true if the error is a resilienceError. This allows the MCP layer
// and other consumers to access error_code, retryable, and retry_after_ms
// without depending on the internal resilienceError type. shedRebalance is
// returned so the MCP layer can emit a raw 503 instead of an isError tool result.
func AsResilienceError(err error) (msg string, errorCode string, retryable bool, retryAfterMs int, shedRebalance bool, ok bool) {
	if re, ok2 := err.(*resilienceError); ok2 {
		return re.msg, re.errorCode, true, re.retryAfterMs, re.shedRebalance, true
	}
	return "", "", false, 0, false, false
}

// writeResilienceError writes a resilience error as an HTTP JSON response with
// Retry-After header and structured error fields for AI agent handling.
// retryAfterSeconds renders a millisecond hint as a whole-second Retry-After,
// never 0: the sub-second hints (500 ms at the NODE_UNAVAILABLE sites) used to
// truncate to "0" — i.e. "retry immediately" — contradicting the JSON body's
// retry_after_ms pacing.
func retryAfterSeconds(ms int) string {
	sec := (ms + 999) / 1000
	if sec < 1 {
		sec = 1
	}
	return fmt.Sprintf("%d", sec)
}

func writeResilienceError(w http.ResponseWriter, err error) {
	if re, ok := err.(*resilienceError); ok {
		// shed: raw transport 503 + Connection: close. The client must
		// close its connection and re-resolve the DNS name to reach a peer.
		if re.shedRebalance {
			if re.retryAfterMs > 0 {
				w.Header().Set("Retry-After", retryAfterSeconds(re.retryAfterMs))
			}
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if re.retryAfterMs > 0 {
			w.Header().Set("Retry-After", retryAfterSeconds(re.retryAfterMs))
		}
		w.WriteHeader(re.code)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":          re.msg,
			"error_code":     re.errorCode,
			"retryable":      true,
			"retry_after_ms": re.retryAfterMs,
		})
		return
	}
	writeJSONError(w, err.Error(), http.StatusInternalServerError)
}

// IsTransportError checks if an error is a transport-level failure that can
// be retried with a fresh connection (L1 retry). Covers gRPC UNAVAILABLE,
// vsock TransportError, connection reset errors, and the gateway↔sandlot
// stream-layer sentinel errors (connection closed / send queue full / node not
// found). The stream sentinels are transient failures where the command never
// reached the sandlot — the sandfs is not dirty, so L1 retry (not L2 cleaning)
// is the right response.
func IsTransportError(err error) bool {
	if err == nil {
		return false
	}
	if stream.IsStreamTransportError(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return containsAny(msg, "transport", "unavailable", "connection reset", "connection refused", "connection closed")
}

// containsAny reports whether s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
