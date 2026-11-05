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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteStorageErrTemplateNotFoundHidesHostPath pins a delete of
// an unknown template used to answer 500 with the storage op's raw text
// (`stat /tmp/.../refs/...`). The caller now gets a named 404 with a fixed
// message; the host path stays in the log. Create keeps its 422.
func TestWriteStorageErrTemplateNotFoundHidesHostPath(t *testing.T) {
	h := &HumanHandler{logger: slog.Default()}

	rec := httptest.NewRecorder()
	h.writeStorageErr(rec,
		errors.New(`delete template: template not found: no-such:v9: stat /tmp/sandswap-templates/refs/no-such_v9.overlay.json: no such file or directory`),
		"delete template")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown template: code=%d want 404 (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "/tmp/") || strings.Contains(body, "stat ") {
		t.Fatalf("delete 404 leaks the host path: %s", body)
	}
	if !strings.Contains(body, "TEMPLATE_NOT_FOUND") || !strings.Contains(body, "template not found") {
		t.Fatalf("delete 404 must carry the named code/message: %s", body)
	}

	rec = httptest.NewRecorder()
	h.writeStorageErr(rec,
		errors.New("create sandfs: TEMPLATE_NOT_FOUND: no such template"),
		"create sandfs")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("create unknown template: code=%d want 422 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "TEMPLATE_NOT_FOUND") {
		t.Fatalf("create 422 must carry the named code: %s", rec.Body.String())
	}
}
