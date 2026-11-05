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
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/maintenance"
)

// While the rotation window is open, creating a sandfs must be refused with a
// NAMED code (the per-instance freeze only covers instances that are
// themselves staged, so this is what makes the freeze a fleet property).
func TestRotationRefusalRefusesCreation(t *testing.T) {
	h := &HumanHandler{logger: slog.New(slog.NewTextHandler(nil, nil))}
	sw := &maintenance.Switch{}
	h.SetRotation(sw)

	// Off (and unwired) => no refusal.
	if h.rotationRefusal(httptest.NewRecorder(), "creating a sandfs") {
		t.Fatal("a closed window must not refuse creation")
	}
	h2 := &HumanHandler{}
	if h2.rotationRefusal(httptest.NewRecorder(), "creating a sandfs") {
		t.Fatal("an unwired switch must not refuse creation")
	}

	sw.Set(true, "volume-seed rotation")
	w := httptest.NewRecorder()
	if !h.rotationRefusal(w, "creating a sandfs") {
		t.Fatal("an open window must refuse creation")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Error("a refusal must carry Retry-After")
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("refusal body is not JSON: %v", err)
	}
	if body["error_code"] != "ROTATION_IN_PROGRESS" {
		t.Errorf("error_code = %q, want ROTATION_IN_PROGRESS", body["error_code"])
	}
	if !strings.Contains(body["error"], "rotation window") || !strings.Contains(body["error"], "retired") {
		t.Errorf("refusal must explain the reason, got %q", body["error"])
	}
}

// The window is a switch of its own: maintenance may be on for an upgrade
// without freezing creation, and its /stats projection reports "refusing".
func TestRotationSwitchIsIndependentOfMaintenance(t *testing.T) {
	h := &HumanHandler{logger: slog.New(slog.NewTextHandler(nil, nil))}
	maint := &maintenance.Switch{}
	rot := &maintenance.Switch{}
	h.SetMaintenance(maint)
	h.SetRotation(rot)

	maint.Set(true, "upgrade window")
	if h.rotationRefusal(httptest.NewRecorder(), "creating a sandfs") {
		t.Fatal("maintenance alone must not freeze sandfs creation")
	}
	rot.Set(true, "rotation")
	if !h.rotationRefusal(httptest.NewRecorder(), "creating a sandfs") {
		t.Fatal("the rotation switch must refuse creation")
	}
}

// /stats carries the per-prov-instance naming generations (fingerprints only)
// plus the age of each report, so a rotation can prove convergence and a stale
// entry cannot pass for a converged instance.
func TestStatsProjectsProvSeeds(t *testing.T) {
	h := &HumanHandler{logger: slog.New(slog.NewTextHandler(nil, nil))}
	h.SetProvSeedSource(func() []ProvSeedState {
		return []ProvSeedState{{NodeID: "prov-1", Generation: "aabbccdd", Staged: true,
			StagedGeneration: "11223344", AgeSec: 3}}
	})
	rep := StatsReport{Gateways: []GatewayStats{}}
	if h.maintenance != nil {
		t.Fatal("no maintenance switch is wired")
	}
	rep.ProvSeeds = h.provSeedSource()
	data, err := renderStatsJSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	seeds, ok := got["prov_seeds"].([]any)
	if !ok || len(seeds) != 1 {
		t.Fatalf("prov_seeds = %v, want one entry", got["prov_seeds"])
	}
	entry := seeds[0].(map[string]any)
	if entry["node_id"] != "prov-1" || entry["generation"] != "aabbccdd" ||
		entry["staged_generation"] != "11223344" || entry["staged"] != true {
		t.Errorf("projection = %v", entry)
	}
	if _, ok := entry["age_sec"]; !ok {
		t.Error("every entry must carry age_sec (staleness is the reader's business)")
	}
}
