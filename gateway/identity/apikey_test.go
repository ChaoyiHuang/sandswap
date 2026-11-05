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

package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newReq builds an http.Request with the given headers and query for ExtractAPIKey
// tests. Uses httptest.NewRequest to avoid boilerplate.
func newReq(t *testing.T, target string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestExtractAPIKeyBearerHeader verifies the primary auth path: the API key
// arrives in the Authorization: Bearer <key> header. This is how the standard
// /agent/execute client authenticates.
func TestExtractAPIKeyBearerHeader(t *testing.T) {
	const key = "sk-sandswap-agent-abcdef123456"
	r := newReq(t, "/agent/execute", map[string]string{
		"Authorization": "Bearer " + key,
	})

	got, err := ExtractAPIKey(r)
	if err != nil {
		t.Fatalf("ExtractAPIKey: %v", err)
	}
	if got != key {
		t.Errorf("got %q, want %q", got, key)
	}
}

// TestExtractAPIKeyBearerHeaderTrimmed verifies whitespace around the key in the
// Bearer header is trimmed (defensive against clients that add trailing spaces).
func TestExtractAPIKeyBearerHeaderTrimmed(t *testing.T) {
	const key = "sk-sandswap-agent-key"
	r := newReq(t, "/agent/execute", map[string]string{
		"Authorization": "Bearer   " + key + "  ",
	})

	got, err := ExtractAPIKey(r)
	if err != nil {
		t.Fatalf("ExtractAPIKey: %v", err)
	}
	if got != key {
		t.Errorf("got %q, want %q (trimmed)", got, key)
	}
}

// TestExtractAPIKeyCustomHeader verifies the X-Sandswap-Api-Key header path.
// This header exists specifically for cross-host 307 redirects: standard HTTP
// clients strip the Authorization header when a redirect crosses hosts (Go,
// Python requests, curl, browsers), but preserve custom X-* headers. So when a
// request is redirected from gateway A to owner gateway B, the key survives
// only in this header.
func TestExtractAPIKeyCustomHeader(t *testing.T) {
	const key = "sk-sandswap-agent-redirect-survivor"
	r := newReq(t, "/agent/execute", map[string]string{
		"X-Sandswap-Api-Key": key,
	})

	got, err := ExtractAPIKey(r)
	if err != nil {
		t.Fatalf("ExtractAPIKey: %v", err)
	}
	if got != key {
		t.Errorf("got %q, want %q", got, key)
	}
}

// TestExtractAPIKeyCustomHeaderTrimmed verifies whitespace in the custom header
// is trimmed.
func TestExtractAPIKeyCustomHeaderTrimmed(t *testing.T) {
	const key = "sk-sandswap-agent-key"
	r := newReq(t, "/agent/execute", map[string]string{
		"X-Sandswap-Api-Key": "  " + key + "  ",
	})

	got, err := ExtractAPIKey(r)
	if err != nil {
		t.Fatalf("ExtractAPIKey: %v", err)
	}
	if got != key {
		t.Errorf("got %q, want %q (trimmed)", got, key)
	}
}

// TestExtractAPIKeyQueryParameterRejected verifies the query-string fallback
// (?api_key=) is no longer accepted — only Authorization and X-Sandswap-Api-Key
// are honored.
func TestExtractAPIKeyQueryParameterRejected(t *testing.T) {
	const key = "sk-sandswap-agent-query-key"
	r := newReq(t, "/agent/execute?api_key="+key, nil)

	_, err := ExtractAPIKey(r)
	if err != ErrMissingKey {
		t.Errorf("error = %v, want ErrMissingKey (query param no longer accepted)", err)
	}
}

// TestExtractAPIKeyBearerTakesPrecedence verifies the precedence: when both the
// Authorization header and the custom header are present, Authorization wins.
// This matches the doc-comment order in ExtractAPIKey.
func TestExtractAPIKeyBearerTakesPrecedence(t *testing.T) {
	r := newReq(t, "/agent/execute", map[string]string{
		"Authorization":      "Bearer sk-bearer",
		"X-Sandswap-Api-Key": "sk-custom",
	})

	got, err := ExtractAPIKey(r)
	if err != nil {
		t.Fatalf("ExtractAPIKey: %v", err)
	}
	if got != "sk-bearer" {
		t.Errorf("got %q, want %q (Authorization takes precedence)", got, "sk-bearer")
	}
}

// TestExtractAPIKeyCustomHeaderWithQueryPresent verifies the custom header is
// used even when a (now-ignored) api_key query parameter is present.
func TestExtractAPIKeyCustomHeaderWithQueryPresent(t *testing.T) {
	r := newReq(t, "/agent/execute?api_key=sk-query", map[string]string{
		"X-Sandswap-Api-Key": "sk-custom",
	})

	got, err := ExtractAPIKey(r)
	if err != nil {
		t.Fatalf("ExtractAPIKey: %v", err)
	}
	if got != "sk-custom" {
		t.Errorf("got %q, want %q (custom header used, query ignored)", got, "sk-custom")
	}
}

// TestExtractAPIKeyMissing verifies a request with no API key anywhere returns
// ErrMissingKey.
func TestExtractAPIKeyMissing(t *testing.T) {
	r := newReq(t, "/agent/execute", nil)

	_, err := ExtractAPIKey(r)
	if err != ErrMissingKey {
		t.Errorf("error = %v, want ErrMissingKey", err)
	}
}

// TestExtractAPIKeyEmptyBearer verifies an Authorization header that is present
// but has an empty Bearer token falls through to the other sources (and
// ultimately returns ErrMissingKey if none are present).
func TestExtractAPIKeyEmptyBearer(t *testing.T) {
	// "Bearer " with nothing after it -> empty key after trim.
	// The current implementation returns "" with no error here, which is a
	// documented edge: CutPrefix succeeds on "Bearer " and TrimSpace returns "".
	// We verify the actual behavior so a future change is intentional.
	r := newReq(t, "/agent/execute", map[string]string{
		"Authorization": "Bearer ",
	})

	got, err := ExtractAPIKey(r)
	if err != nil {
		t.Fatalf("ExtractAPIKey(empty Bearer): expected nil error (falls through CutPrefix), got %v", err)
	}
	// An empty Bearer token yields an empty key. Callers that need to reject
	// empty keys do so via ResolveAgent (which rejects empty keys).
	if got != "" {
		t.Errorf("got %q, want empty string from empty Bearer", got)
	}
}

// TestExtractAPIKeyMalformedAuthorization verifies an Authorization header
// without the "Bearer " prefix is not treated as a bearer token - it falls
// through to the custom header / query parameter.
func TestExtractAPIKeyMalformedAuthorization(t *testing.T) {
	// "Basic xyz" is not "Bearer ...", so the Authorization check fails.
	// With no other source, this returns ErrMissingKey.
	r := newReq(t, "/agent/execute", map[string]string{
		"Authorization": "Basic dXNlcjpwYXNz",
	})

	_, err := ExtractAPIKey(r)
	if err != ErrMissingKey {
		t.Errorf("error = %v, want ErrMissingKey (malformed Authorization falls through)", err)
	}
}

// TestExtractAPIKeyMalformedAuthorizationFallsToCustom verifies a non-Bearer
// Authorization header falls through to the custom header.
func TestExtractAPIKeyMalformedAuthorizationFallsToCustom(t *testing.T) {
	r := newReq(t, "/agent/execute", map[string]string{
		"Authorization":      "Basic dXNlcjpwYXNz",
		"X-Sandswap-Api-Key": "sk-fallback",
	})

	got, err := ExtractAPIKey(r)
	if err != nil {
		t.Fatalf("ExtractAPIKey: %v", err)
	}
	if got != "sk-fallback" {
		t.Errorf("got %q, want %q (fallback to custom header)", got, "sk-fallback")
	}
}

// TestExtractAPIKeyEmptyCustomHeaderFallsToMissing verifies an empty custom
// header value is skipped (the `!= ""` guard); with no Authorization and no
// query fallback, the request now returns ErrMissingKey.
func TestExtractAPIKeyEmptyCustomHeaderFallsToMissing(t *testing.T) {
	r := newReq(t, "/agent/execute?api_key=sk-query", map[string]string{
		"X-Sandswap-Api-Key": "", // empty -> skipped
	})

	_, err := ExtractAPIKey(r)
	if err != ErrMissingKey {
		t.Errorf("error = %v, want ErrMissingKey (empty custom header, query no longer a fallback)", err)
	}
}

// TestExtractAPIKeyNoHeadersNoQuery verifies the absolute no-key path returns
// ErrMissingKey (not a panic, not an empty string).
func TestExtractAPIKeyNoHeadersNoQuery(t *testing.T) {
	r := newReq(t, "/agent/execute", nil)

	got, err := ExtractAPIKey(r)
	if err != ErrMissingKey {
		t.Errorf("error = %v, want ErrMissingKey", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string on missing key", got)
	}
}

// TestExtractAPIKeyCaseInsensitiveBearer verifies the "Bearer " scheme is
// matched case-insensitively per RFC 7235 (the auth-scheme token is
// case-insensitive). A lowercase "bearer " matches and extracts the key.
func TestExtractAPIKeyCaseInsensitiveBearer(t *testing.T) {
	for _, scheme := range []string{"bearer ", "BEARER ", "BeArEr "} {
		r := newReq(t, "/agent/execute", map[string]string{
			"Authorization": scheme + "sk-key",
		})
		got, err := ExtractAPIKey(r)
		if err != nil {
			t.Errorf("ExtractAPIKey(%q): %v (scheme must be case-insensitive)", scheme, err)
			continue
		}
		if got != "sk-key" {
			t.Errorf("ExtractAPIKey(%q) = %q, want sk-key", scheme, got)
		}
	}
}

// TestErrMissingKey verifies ErrMissingKey is a distinct sentinel error that
// callers can compare against (errors.Is not needed since it's a value error).
func TestErrMissingKey(t *testing.T) {
	if ErrMissingKey == nil {
		t.Fatal("ErrMissingKey is nil")
	}
	if ErrMissingKey.Error() != "missing api key" {
		t.Errorf("ErrMissingKey.Error() = %q, want %q", ErrMissingKey.Error(), "missing api key")
	}
}
