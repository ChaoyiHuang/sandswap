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
	"log/slog"
	"net/http"
	"time"

	"gateway/identity"
)

// AgentHandler handles agent-facing endpoints: /agent/sandfs (discovery).
// These endpoints are authenticated with the agent's API key and return
// information about the agent's SandFS instances.
//
// Design principle: no direct filesystem access. All sandfs content
// (including self-description files like SANDFS.md/CLAUDE.md/README.md)
// must be accessed through the microVM via POST /agent/file. The agent discovery
// endpoint returns only metadata stored in the identity store (description,
// name, template) — never reads from the sandbox's rootfs.
type AgentHandler struct {
	identityStore identity.Store
	logger        *slog.Logger
}

// NewAgentHandler creates a new AgentHandler.
func NewAgentHandler(store identity.Store, logger *slog.Logger) *AgentHandler {
	return &AgentHandler{
		identityStore: store,
		logger:        logger,
	}
}

// SandFSSummary is a summary of a SandFS instance for the agent discovery response.
type SandFSSummary struct {
	SandfsID    string    `json:"sandfs_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"` // from identity store (human-set at creation)
	Template    string    `json:"template,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	// Status is the lifecycle state ("" = active). A non-active sandfs
	// (template swap or deletion in progress) refuses execs/file ops with a
	// retryable 409 — the agent should back off and retry.
	Status string `json:"status,omitempty"`
}

// ListSandFS handles GET /agent/sandfs — list sandfs belonging to the authenticated agent.
// Returns only metadata from identity store. Does NOT read files from the sandbox.
func (h *AgentHandler) ListSandFS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	apiKey, err := identity.ExtractAPIKey(r)
	if err != nil {
		writeJSONError(w, "missing api key", http.StatusUnauthorized)
		return
	}

	agent, err := h.identityStore.ResolveAgent(apiKey)
	if err != nil {
		writeJSONError(w, "invalid api key", http.StatusUnauthorized)
		return
	}

	sandfsList, err := h.identityStore.ListSandFSByAgent(agent.ID)
	if err != nil {
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := make([]SandFSSummary, 0, len(sandfsList))
	for _, sf := range sandfsList {
		resp = append(resp, SandFSSummary{
			SandfsID:    sf.ID,
			Name:        sf.Name,
			Description: sf.Description,
			Template:    sf.Template,
			CreatedAt:   sf.CreatedAt,
			Status:      sf.Status,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"sandfs_list": resp})
}
