// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/authn"
)

// Template CREATION is an ops/admin capability: a namespace tenant token
// (sandswap:human) may list and use templates, but must not turn its sandfs
// into a global ref. The check runs before any store access, so a zero-value
// handler is enough to exercise it.
func TestSaveAsTemplateRefusesHumanScope(t *testing.T) {
	h := &HumanHandler{}
	req := httptest.NewRequest(http.MethodPost, "/human/sandfs/sandfs-x/save-template",
		strings.NewReader(`{"template_ref":"x:v1"}`))
	claims := &authn.TokenClaims{
		Scopes: []string{authn.ScopeHuman},
		Raw:    map[string]any{},
	}
	req = req.WithContext(authn.WithTokenClaims(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.saveAsTemplate(rec, req, "sandfs-x")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("human-scope save-template = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "TEMPLATE_OPS_REQUIRED") {
		t.Fatalf("refusal body lacks TEMPLATE_OPS_REQUIRED: %s", rec.Body.String())
	}
}
