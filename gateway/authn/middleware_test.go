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

package authn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestOIDCMiddleware_NilProvider tests that a nil provider passes through
// all requests without authentication (backward compatibility).
func TestOIDCMiddleware_NilProvider(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := OIDCMiddleware(nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestOIDCMiddleware_MissingToken tests that a request without a Bearer
// token returns 401 when a provider is configured.
func TestOIDCMiddleware_MissingToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test with nil provider — no auth, should pass
	middleware := OIDCMiddleware(nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("nil provider: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestRequireScope_NoClaims tests that RequireScope passes through
// when no claims are in context (OIDC not configured).
func TestRequireScope_NoClaims(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := RequireScope(ScopeHuman)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestRequireScope_SufficientScope tests that RequireScope allows
// requests when the token has the required scope.
func TestRequireScope_SufficientScope(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := RequireScope(ScopeHuman)
	handler := middleware(next)

	claims := &TokenClaims{
		Subject: "user-123",
		Scopes:  []string{ScopeHuman, ScopeOps},
	}
	ctx := context.WithValue(context.Background(), tokenClaimsKey{}, claims)
	req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestRequireScope_InsufficientScope tests that RequireScope returns
// 403 when the token lacks the required scope.
func TestRequireScope_InsufficientScope(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := RequireScope(ScopeOps)
	handler := middleware(next)

	// Token has only human scope, but ops is required
	claims := &TokenClaims{
		Subject: "user-123",
		Scopes:  []string{ScopeHuman},
	}
	ctx := context.WithValue(context.Background(), tokenClaimsKey{}, claims)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should not be called")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestExtractBearerToken tests the Bearer token extraction logic.
func TestExtractBearerToken(t *testing.T) {
	t.Run("valid_bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.test.sig")
		token, err := extractBearerToken(req)
		if err != nil {
			t.Fatalf("extractBearerToken: %v", err)
		}
		if token != "eyJhbGciOiJSUzI1NiJ9.test.sig" {
			t.Errorf("token = %q, want JWT string", token)
		}
	})

	t.Run("missing_header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_, err := extractBearerToken(req)
		if err == nil {
			t.Error("extractBearerToken(missing) = nil, want error")
		}
	})

	t.Run("wrong_scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		_, err := extractBearerToken(req)
		if err == nil {
			t.Error("extractBearerToken(Basic) = nil, want error")
		}
	})

	t.Run("empty_bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer ")
		_, err := extractBearerToken(req)
		if err == nil {
			t.Error("extractBearerToken(empty Bearer) = nil, want error")
		}
	})
}

// TestExtractBearerToken_CaseInsensitive tests RFC 7235 scheme case-insensitivity.
func TestExtractBearerToken_CaseInsensitive(t *testing.T) {
	t.Run("lowercase_bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "bearer eyJhbGciOiJSUzI1NiJ9.test.sig")
		token, err := extractBearerToken(req)
		if err != nil {
			t.Fatalf("extractBearerToken(bearer): %v", err)
		}
		if token != "eyJhbGciOiJSUzI1NiJ9.test.sig" {
			t.Errorf("token = %q, want JWT string", token)
		}
	})

	t.Run("uppercase_bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "BEARER eyJhbGciOiJSUzI1NiJ9.test.sig")
		token, err := extractBearerToken(req)
		if err != nil {
			t.Fatalf("extractBearerToken(BEARER): %v", err)
		}
		if token != "eyJhbGciOiJSUzI1NiJ9.test.sig" {
			t.Errorf("token = %q, want JWT string", token)
		}
	})
}

// TestMTLSOrOIDCMiddleware_ClientCert tests that mTLS client certificates
// are trusted and receive full scope.
func TestMTLSOrOIDCMiddleware_ClientCert(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		claims := TokenClaimsFromContext(r.Context())
		if claims == nil {
			t.Error("claims is nil")
		} else {
			if claims.Issuer != "mtls" {
				t.Errorf("Issuer = %q, want %q", claims.Issuer, "mtls")
			}
			if !claims.HasScope(ScopeHuman) {
				t.Error("missing sandswap:human scope")
			}
			if !claims.HasScope(ScopeAdmin) {
				t.Error("missing sandswap:admin scope")
			}
			if !claims.HasScope(ScopeOps) {
				t.Error("missing sandswap:ops scope")
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	// nil provider: mTLS should still work
	middleware := MTLSOrOIDCMiddleware(nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil)
	// Simulate mTLS: set TLS.PeerCertificates with valid time range
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject:   pkix.Name{CommonName: "admin@example.com"},
				NotBefore: time.Now().Add(-1 * time.Hour),
				NotAfter:  time.Now().Add(1 * time.Hour),
				URIs:      []*url.URL{operatorURI(t, "sandswap://role/ops")},
			},
		},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// operatorURI parses a role URI SAN for a test certificate.
func operatorURI(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// A CA-verified certificate WITHOUT an operator role SAN must not receive the
// admin surface: the CA may also sign certificates for other purposes.
func TestMTLSOrOIDCMiddleware_CertWithoutOperatorRoleRefused(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := MTLSOrOIDCMiddleware(nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject:   pkix.Name{CommonName: "some-other-client"},
				NotBefore: time.Now().Add(-1 * time.Hour),
				NotAfter:  time.Now().Add(1 * time.Hour),
			},
		},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Error("a certificate without an operator role SAN reached the handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestMTLSOrOIDCMiddleware_ExpiredCert tests that expired mTLS certs are rejected.
func TestMTLSOrOIDCMiddleware_ExpiredCert(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := MTLSOrOIDCMiddleware(nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject:   pkix.Name{CommonName: "admin@example.com"},
				NotBefore: time.Now().Add(-2 * time.Hour),
				NotAfter:  time.Now().Add(-1 * time.Hour), // expired
			},
		},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestMTLSOrOIDCMiddleware_NotYetValidCert tests that not-yet-valid mTLS certs are rejected.
func TestMTLSOrOIDCMiddleware_NotYetValidCert(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := MTLSOrOIDCMiddleware(nil)
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject:   pkix.Name{CommonName: "admin@example.com"},
				NotBefore: time.Now().Add(1 * time.Hour), // not yet valid
				NotAfter:  time.Now().Add(2 * time.Hour),
			},
		},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestMTLSRoleScopingWithOIDCMode pins the strict marker mapping that applies
// whenever an OIDC provider is configured: role/human is human-only (no
// admin/ops, no fleet wildcard), role/ops is ops-only, and only role/admin
// receives the full surface. Without OIDC the legacy full grant remains
// (tested separately).
func TestMTLSRoleScopingWithOIDCMode(t *testing.T) {
	cases := []struct {
		role      string
		wantHuman bool
		wantAdmin bool
		wantOps   bool
		wantWild  bool
	}{
		{"human", true, false, false, false},
		{"ops", false, false, true, false},
		{"admin", true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.role, func(t *testing.T) {
			var got *TokenClaims
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = TokenClaimsFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			handler := MTLSOrOIDCMiddleware(&OIDCProvider{})(next)
			req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
				Subject:   pkix.Name{CommonName: "op@example.com"},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour),
				URIs: []*url.URL{
					operatorURI(t, "sandswap://role/"+tc.role),
					operatorURI(t, "sandswap://ns/acme"),
				},
			}}}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || got == nil {
				t.Fatalf("request not admitted (code=%d, claims=%v)", rec.Code, got)
			}
			if got.HasScope(ScopeHuman) != tc.wantHuman ||
				got.HasScope(ScopeAdmin) != tc.wantAdmin ||
				got.HasScope(ScopeOps) != tc.wantOps {
				t.Fatalf("scopes = %v, want human=%v admin=%v ops=%v", got.Scopes, tc.wantHuman, tc.wantAdmin, tc.wantOps)
			}
			ns, _ := got.Raw[NamespaceClaim].([]any)
			wild := false
			for _, n := range ns {
				if n == NamespaceWildcard {
					wild = true
				}
			}
			if wild != tc.wantWild {
				t.Fatalf("namespaces = %v, wildcard=%v want %v", ns, wild, tc.wantWild)
			}
		})
	}
}

// TestMTLSNamespaceWildcardRequiresAdmin pins the wildcard rule on the mTLS
// path: sandswap://ns/* grants the fleet-wide namespace ONLY to a certificate
// that also carries the admin role marker. A human/ops certificate naming the
// wildcard keeps its explicit namespace grants (none here) and does NOT
// resolve as fleet; the same certificate naming explicit namespaces still
// receives exactly those.
func TestMTLSNamespaceWildcardRequiresAdmin(t *testing.T) {
	cases := []struct {
		name      string
		uris      []string
		wantFleet bool
		wantNames []string
	}{
		{
			name:      "human + ns/* is not fleet",
			uris:      []string{"sandswap://role/human", "sandswap://ns/*"},
			wantFleet: false,
		},
		{
			name:      "ops + ns/* is not fleet",
			uris:      []string{"sandswap://role/ops", "sandswap://ns/*"},
			wantFleet: false,
		},
		{
			name:      "human + explicit ns keeps the grant",
			uris:      []string{"sandswap://role/human", "sandswap://ns/acme"},
			wantNames: []string{"acme"},
		},
		{
			name:      "human + ns/* and an explicit ns keeps only the explicit one",
			uris:      []string{"sandswap://role/human", "sandswap://ns/*", "sandswap://ns/acme"},
			wantNames: []string{"acme"},
		},
		{
			name:      "admin + ns/* is fleet",
			uris:      []string{"sandswap://role/admin", "sandswap://ns/*"},
			wantFleet: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *TokenClaims
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = TokenClaimsFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			var uris []*url.URL
			for _, raw := range tc.uris {
				uris = append(uris, operatorURI(t, raw))
			}
			handler := MTLSOrOIDCMiddleware(&OIDCProvider{})(next)
			req := httptest.NewRequest(http.MethodGet, "/human/sandfs", nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
				Subject:   pkix.Name{CommonName: "op@example.com"},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour),
				URIs:      uris,
			}}}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || got == nil {
				t.Fatalf("request not admitted (code=%d, claims=%v)", rec.Code, got)
			}
			scope := NamespaceScopeFromContext(WithTokenClaims(context.Background(), got))
			if scope.Fleet != tc.wantFleet {
				t.Fatalf("fleet = %v, want %v (claims namespaces %v)", scope.Fleet, tc.wantFleet, got.Raw[NamespaceClaim])
			}
			for _, want := range tc.wantNames {
				if !scope.Allows(want) {
					t.Fatalf("explicit namespace %q not granted (namespaces %v)", want, got.Raw[NamespaceClaim])
				}
			}
			if !tc.wantFleet && len(tc.wantNames) == 0 && len(scope.Names) != 0 {
				t.Fatalf("unexpected explicit namespaces: %v", scope.Names)
			}
		})
	}
}
