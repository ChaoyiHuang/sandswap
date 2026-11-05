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
//
// API key extraction and validation helpers (part of package identity):

package identity

import (
	"errors"
	"net/http"
	"strings"
)

// ErrMissingKey is returned when no API key is present in the request.
var ErrMissingKey = errors.New("missing api key")

// ExtractAPIKey extracts the API key from an HTTP request.
// Supports: Authorization: Bearer <key>, or X-Sandswap-Api-Key: <key>.
//
// X-Sandswap-Api-Key exists for cross-host 307 redirects (redirect): standard HTTP
// clients strip the Authorization header when a redirect crosses hosts (Go,
// Python requests, curl, browsers all do), but preserve custom X-* headers.
// So when a request is 307-redirected from gateway A to owner gateway B, the
// API key arrives only if it travels in this header. Existing clients that
// keep sending Authorization still work — the redirect just degrades to a
// retry cycle (B strips → 401 → client retries), which self-heals.
func ExtractAPIKey(r *http.Request) (string, error) {
	// Authorization: Bearer <key> (RFC 7235: the scheme is case-insensitive).
	if auth := r.Header.Get("Authorization"); auth != "" {
		// "Bearer " is 7 chars; compare case-insensitively (RFC 7235) so
		// "bearer"/"BEARER" are accepted. len >= 7 preserves the empty-token
		// fall-through (an empty Bearer yields "" and callers reject it).
		if len(auth) >= 7 && strings.EqualFold(auth[:7], "Bearer ") {
			return strings.TrimSpace(auth[7:]), nil
		}
	}

	// Custom header — survives cross-host redirect (see doc comment).
	if key := r.Header.Get("X-Sandswap-Api-Key"); key != "" {
		return strings.TrimSpace(key), nil
	}

	return "", ErrMissingKey
}
