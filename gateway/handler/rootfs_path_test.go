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
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"gateway/authn"
)

// postRootFSPath drives POST /human/sandfs/{id}/rootfs-path.
func postRootFSPath(t *testing.T, gw *testGateway, sandfsID, path string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"rootfs_path":%q}`, path)
	req := httptest.NewRequest("POST", "/human/sandfs/"+sandfsID+"/rootfs-path", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gw.humanHandler.ServeHTTP(w, req)
	return w
}

// TestSetRootFSPathRequiresVolumeIdentity pins the repoint endpoint
// validates the SHAPE of the path, but the directory must also BE the
// sandfs's volume — proven through the storage plane (the .sandfs-id stamp),
// which the gateway itself cannot compute. Repointing a record at another
// sandfs's directory must be a named 409 and must leave the record untouched.
func TestSetRootFSPathRequiresVolumeIdentity(t *testing.T) {
	gw := setupTestGateway(t)
	idA := createTestSandFS(t, gw, "repoint-a")
	idB := createTestSandFS(t, gw, "repoint-b")

	pathA := filepath.Join(gw.reg.VolRoot(), idA)
	pathB := filepath.Join(gw.reg.VolRoot(), idB)

	// The record's own directory (the rotation-target shape): accepted.
	if w := postRootFSPath(t, gw, idA, pathA); w.Code != http.StatusNoContent {
		t.Fatalf("own-volume repoint = %d %s, want 204", w.Code, w.Body.String())
	}

	// Another sandfs's directory: refused by name, record unchanged.
	w := postRootFSPath(t, gw, idA, pathB)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "VOLUME_IDENTITY_MISMATCH") {
		t.Fatalf("cross-volume repoint = %d %s, want 409 VOLUME_IDENTITY_MISMATCH", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), pathB) || strings.Contains(w.Body.String(), idB) {
		t.Errorf("refusal body leaks storage-plane detail: %s", w.Body.String())
	}
	rec, err := gw.reg.Store().GetSandFS(idA)
	if err != nil || rec == nil {
		t.Fatalf("GetSandFS: %v", err)
	}
	if rec.RootFSPath != pathA {
		t.Errorf("record rootfs_path = %q after refused repoint, want %q unchanged", rec.RootFSPath, pathA)
	}

	// A directory that does not exist: refused too (nothing to adopt).
	if w := postRootFSPath(t, gw, idA, filepath.Join(gw.reg.VolRoot(), "sf-not-there")); w.Code != http.StatusConflict {
		t.Fatalf("missing-dir repoint = %d %s, want 409", w.Code, w.Body.String())
	}
}

// The repoint endpoint is a storage-plane maintenance operation: it is
// ops/admin on BOTH the unscoped and the namespaced surface. A human-only
// token gets the same generic 403 as any other ops endpoint.
func TestSetRootFSPathRequiresOps(t *testing.T) {
	gw := setupTestGateway(t)
	id := createTestSandFS(t, gw, "repoint-ops")
	path := filepath.Join(gw.reg.VolRoot(), id)
	body := fmt.Sprintf(`{"rootfs_path":%q}`, path)

	w := doHumanRequestAs(gw.humanHandler, []string{authn.ScopeHuman}, "POST", "/human/sandfs/"+id+"/rootfs-path", body)
	if w.Code != http.StatusForbidden {
		t.Fatalf("human-only repoint = %d %s, want 403", w.Code, w.Body.String())
	}

	w = doHumanRequestAs(gw.humanHandler, []string{authn.ScopeHuman, authn.ScopeOps}, "POST", "/human/sandfs/"+id+"/rootfs-path", body)
	if w.Code != http.StatusNoContent {
		t.Fatalf("ops repoint = %d %s, want 204", w.Code, w.Body.String())
	}
}

// TestCreateSandFSRejectsMalformedTemplateRef pins the addendum: the
// node's ref charset rule is mirrored at the gateway, so a ref that can never
// be valid is a named 400 with NO storage round trip.
func TestCreateSandFSRejectsMalformedTemplateRef(t *testing.T) {
	gw := setupTestGateway(t)
	for _, bad := range []string{"../etc/passwd", "a/b", `a\b`, strings.Repeat("x", 257), "bad\u0000ref"} {
		body := fmt.Sprintf(`{"agent_id":%q,"name":"bad-ref","template":%q,"mode":"flat"}`, gw.agentID, bad)
		req := httptest.NewRequest("POST", "/human/sandfs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		gw.humanHandler.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("template %q: status = %d %s, want 400", bad, w.Code, w.Body.String())
		}
	}
	if len(gw.storage.Ensured) != 0 {
		t.Errorf("malformed refs reached the storage plane: %v", gw.storage.Ensured)
	}

	// A valid ref still creates.
	body := fmt.Sprintf(`{"agent_id":%q,"name":"good-ref","template":"test:v1","mode":"flat"}`, gw.agentID)
	req := httptest.NewRequest("POST", "/human/sandfs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gw.humanHandler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("valid ref create = %d %s, want 201", w.Code, w.Body.String())
	}
}
