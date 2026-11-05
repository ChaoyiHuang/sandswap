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
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFileHTTPError verifies the file-op HTTP error sentinel.
func TestFileHTTPError(t *testing.T) {
	e := &fileHTTPError{code: http.StatusBadRequest, msg: "bad path"}
	if e.Error() != "bad path" {
		t.Errorf("Error() = %q, want %q", e.Error(), "bad path")
	}
}

// TestWriteFileError verifies the file-op error -> HTTP mapping:
//   - owner-redirect error (redirect) -> 307 to the owner, with the anti-loop marker
//   - fileHTTPError -> its own status code + message
//   - anything else -> 500 with the raw message
func TestWriteFileError(t *testing.T) {
	// Owner redirect (redirect): healthy owner present -> 307.
	r := httptest.NewRequest("POST", "/agent/file", nil)
	w := httptest.NewRecorder()
	writeFileError(w, r, &OwnerRedirectError{OwnerURL: "https://gw-2:3000"})
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("owner redirect: expected 307, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://gw-2:3000/agent/file" {
		t.Errorf("owner redirect Location = %q", loc)
	}

	// fileHTTPError -> its code.
	r2 := httptest.NewRequest("POST", "/agent/file", nil)
	w2 := httptest.NewRecorder()
	writeFileError(w2, r2, &fileHTTPError{code: http.StatusNotFound, msg: "not found"})
	if w2.Code != http.StatusNotFound {
		t.Errorf("fileHTTPError: expected 404, got %d", w2.Code)
	}

	// Generic error -> 500 with the message.
	r3 := httptest.NewRequest("POST", "/agent/file", nil)
	w3 := httptest.NewRecorder()
	writeFileError(w3, r3, errors.New("boom"))
	if w3.Code != http.StatusInternalServerError {
		t.Errorf("generic: expected 500, got %d", w3.Code)
	}
}
