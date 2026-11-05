// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, this software will be governed by
// the Apache License, Version 2.0.

package handler

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// OpsTokenGate authenticates the exec-mode agent listener's ops endpoints
// (/stats, /metrics) with a static bearer token from a root-owned file
// (-ops-token-file).
//
// Why a static token and not the agent API key or the human API's
// OIDC/mTLS: exec deployments deliberately run without the human listener or
// an OIDC provider, and the agent API key is the WRONG credential class — it
// is a TENANT identity, and using it here would hand every tenant the
// fleet-wide ops view. A file-held token keeps the ops audience separate with
// zero new infrastructure; Prometheus's scrape_config supports bearer_token
// natively, and rotation is a file write (picked up by the mtime check
// below).
//
// Semantics:
//   - missing/malformed Authorization, or a wrong token → 401
//   - a token file that becomes empty/unreadable AFTER startup → fail
//     closed (401 for everything): an ops credential in a broken state must
//     never degrade to open
//   - the last successfully loaded token keeps serving if a re-read fails
//     (a half-written rotation must not lock ops out of the metrics endpoints).

// OpsTokenMaxBytes bounds the token file: it is a credential, not a
// document. 256 leaves room for any realistic token format.
const OpsTokenMaxBytes = 256

type OpsTokenGate struct {
	path   string
	logger *slog.Logger

	mu      sync.RWMutex
	token   []byte // trimmed file content
	modTime time.Time
	size    int64
}

// NewOpsTokenGate validates the token file up front (fail-fast at startup:
// a configured-but-broken ops credential must refuse to boot, mirroring the
// other startup validators) and returns a gate that re-reads it whenever the
// file's mtime or size changes.
func NewOpsTokenGate(path string, logger *slog.Logger) (*OpsTokenGate, error) {
	g := &OpsTokenGate{path: path, logger: logger}
	token, err := g.load()
	if err != nil {
		return nil, err
	}
	if len(token) == 0 {
		return nil, &fileHTTPError{code: http.StatusInternalServerError, msg: "ops token file is empty"}
	}
	return g, nil
}

// load reads the token file and installs it as the active token. Returns the
// installed token — possibly EMPTY, which is the revoked-credential state
// (the file was observably emptied: rotation truncation or an explicit
// withdrawal; the gate serves 401s until a valid token returns). Only a
// FAILED read keeps the previous token: that is the transient half of a
// rotation (EACCES, a rename in flight), not an observable credential
// decision. Construction treats the empty result as an error (a configured
// gate must not boot revoked). Caller serializes via g.mu.
func (g *OpsTokenGate) load() ([]byte, error) {
	st, err := os.Stat(g.path)
	if err != nil {
		return nil, &fileHTTPError{code: http.StatusInternalServerError, msg: ("ops token file: " + err.Error())}
	}
	if !st.Mode().IsRegular() {
		return nil, &fileHTTPError{code: http.StatusInternalServerError, msg: "ops token file is not a regular file"}
	}
	if st.Size() > OpsTokenMaxBytes {
		return nil, &fileHTTPError{code: http.StatusInternalServerError, msg: "ops token file exceeds the token size cap"}
	}
	raw, err := os.ReadFile(g.path)
	if err != nil {
		return nil, &fileHTTPError{code: http.StatusInternalServerError, msg: ("ops token file: " + err.Error())}
	}
	token := []byte(strings.TrimSpace(string(raw)))
	g.token = token // possibly empty: the fail-closed revoked state
	g.modTime = st.ModTime()
	g.size = st.Size()
	return token, nil
}

// current returns the active token, re-reading the file when its mtime or
// size changed (rotation). See load for the empty-vs-failed distinction.
func (g *OpsTokenGate) current() []byte {
	g.mu.RLock()
	modTime, size := g.modTime, g.size
	g.mu.RUnlock()

	st, err := os.Stat(g.path)
	if err != nil {
		// The configured credential is gone or unreadable (deleted, chmod 000,
		// a failed rotation): that is a REVOCATION, not a reason to keep
		// serving the old token. Clear it; a restored file re-loads below.
		g.mu.Lock()
		g.token = nil
		g.modTime = time.Time{}
		g.size = -1
		g.mu.Unlock()
		return nil
	}
	if st.ModTime() != modTime || st.Size() != size {
		g.mu.Lock()
		// Re-check under the write lock: a concurrent request may have
		// completed the same reload.
		if st.ModTime() != g.modTime || st.Size() != g.size {
			if _, err := g.load(); err != nil {
				// Fail closed: an unreadable/empty rotation state must not
				// keep accepting the withdrawn token.
				g.token = nil
				g.modTime = time.Time{}
				g.size = -1
				g.logger.Warn("ops token reload failed; token revoked until a valid file returns", "error", err)
			}
		}
		g.mu.Unlock()
	}

	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.token
}

// Wrap gates an ops endpoint behind the bearer token.
func (g *OpsTokenGate) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sandswap-ops"`)
			writeJSONError(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		token := g.current()
		presented := []byte(auth[len(prefix):])
		// A revoked token is nil OR empty and accepts nothing. In particular
		// "Bearer " (empty presented value, preserved on HTTP/2) must never
		// compare equal to an empty configured token: ConstantTimeCompare("",
		// "") returns 1, which would turn the revoked state into an open gate.
		// Constant-time on the value; the length leak of a mismatched-length
		// guess is not a secret.
		if len(token) == 0 || len(presented) != len(token) || subtle.ConstantTimeCompare(presented, token) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sandswap-ops", error="invalid_token"`)
			writeJSONError(w, "invalid ops token", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// OpsEndpointsDisabled is the empty-flag handler: with no -ops-token-file
// configured, the exec-mode agent listener serves NO ops endpoints at all
// (fail-closed default — these are fleet-wide ops views on a
// tenant-reachable listener; redaction alone was never authorization).
func OpsEndpointsDisabled(w http.ResponseWriter, r *http.Request) {
	writeJSONError(w, "stats and metrics are disabled on this listener (configure -ops-token-file to enable them)", http.StatusNotFound)
}
