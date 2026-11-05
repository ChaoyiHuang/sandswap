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
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Scope constants for Sandswap API authorization. Buckets follow blast
// radius, not audience label:
//   - sandswap:human — user-resource CRUD on /human/* (SandFS, templates)
//   - sandswap:admin — credential minting power (/human/agent*)
//   - sandswap:ops   — operations staff: read the fleet (/stats, /metrics)
//     AND act on stuck ownership
//     (/human/ownership/* — incident response)
//
// mTLS client certificates and a super-admin token may hold all three.
const (
	ScopeHuman = "sandswap:human"
	ScopeAdmin = "sandswap:admin"
	ScopeOps   = "sandswap:ops"
)

// context key for TokenClaims.
type tokenClaimsKey struct{}

// TokenClaimsFromContext returns the verified token claims from the request
// context, or nil if OIDC is not configured (backward-compatible passthrough).
func TokenClaimsFromContext(ctx context.Context) *TokenClaims {
	c, _ := ctx.Value(tokenClaimsKey{}).(*TokenClaims)
	return c
}

// OIDCMiddleware returns an HTTP middleware that validates Bearer tokens
// against the configured OIDC provider. If provider is nil, all requests
// are passed through without authentication (backward-compatible default).
func OIDCMiddleware(provider *OIDCProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No provider configured → passthrough (backward compat).
			if provider == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Extract Bearer token.
			rawToken, err := extractBearerToken(r)
			if err != nil {
				writeAuthnJSONError(w, "missing or malformed authorization header", http.StatusUnauthorized)
				return
			}

			// Verify JWT.
			claims, err := provider.Verify(r.Context(), rawToken)
			if err != nil {
				// Do not leak internal verification details to the client.
				writeAuthnJSONError(w, "invalid token", http.StatusUnauthorized)
				return
			}

			// Inject claims into context.
			ctx := WithTokenClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope returns an HTTP middleware that checks whether the verified
// token contains the specified scope. Must be used after OIDCMiddleware
// (reads claims from context).
//
// If no claims are in context (OIDC not configured), the request is
// passed through (backward-compatible default).
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := TokenClaimsFromContext(r.Context())
			if claims == nil {
				// No OIDC configured → passthrough.
				next.ServeHTTP(w, r)
				return
			}
			if !claims.HasScope(scope) {
				writeAuthnJSONError(w, "insufficient scope: requires "+scope, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyScope is the multi-scope form of RequireScope: the token must
// carry at least one of the listed scopes. Used where ops/admin are supersets
// of a lower bucket (they keep their own capabilities AND the human
// sandfs/list surface). As with RequireScope, no claims (OIDC off) passes
// through.
func RequireAnyScope(scopes ...string) func(http.Handler) http.Handler {
	joined := strings.Join(scopes, " or ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := TokenClaimsFromContext(r.Context())
			if claims == nil {
				next.ServeHTTP(w, r)
				return
			}
			for _, scope := range scopes {
				if claims.HasScope(scope) {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeAuthnJSONError(w, "insufficient scope: requires "+joined, http.StatusForbidden)
		})
	}
}

// MTLSOperatorRolePrefix is the URI-SAN namespace that marks a verified client
// certificate as an operator credential (same shape as the stream role
// SANs). A certificate signed by the human CA but carrying none of the
// operator roles is NOT an admin: the CA may also sign certificates for other
// purposes, and "any cert from this CA" used to mean silent fleet admin.
const MTLSOperatorRolePrefix = "sandswap://role/"

// certOperatorGrant maps the certificate's explicit role markers to scopes
// and namespace grants. No marker = not an operator credential. Multiple
// markers are unioned; the admin marker is the only one that grants the fleet
// namespace wildcard.
func certOperatorGrant(cert *x509.Certificate) (scopes []string, namespaces []string, ok bool) {
	if cert == nil {
		return nil, nil, false
	}
	hasHuman, hasOps, hasAdmin := false, false, false
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		switch u.String() {
		case MTLSOperatorRolePrefix + "ops":
			hasOps = true
		case MTLSOperatorRolePrefix + "admin":
			hasAdmin = true
		case MTLSOperatorRolePrefix + "human":
			hasHuman = true
		default:
			// Optional tenant scope for human/ops certs:
			// sandswap://ns/<name>.
			if u.Scheme == "sandswap" && u.Host == "ns" {
				ns := strings.Trim(u.Path, "/")
				if ns == "" {
					continue
				}
				// The fleet wildcard is the ADMIN shape only: a certificate
				// that carries no admin role marker naming sandswap://ns/* must
				// not be widened into fleet-wide namespace access. Admin certs
				// receive the wildcard from the hasAdmin branch below.
				if ns == NamespaceWildcard {
					continue
				}
				namespaces = append(namespaces, ns)
			}
		}
	}
	if hasAdmin {
		return []string{ScopeHuman, ScopeAdmin, ScopeOps}, []string{NamespaceWildcard}, true
	}
	if hasHuman {
		scopes = append(scopes, ScopeHuman)
	}
	if hasOps {
		scopes = append(scopes, ScopeOps)
	}
	if len(scopes) == 0 {
		return nil, nil, false
	}
	return scopes, namespaces, true
}

// MTLSOrOIDCMiddleware supports both mTLS client certificates and OIDC
// Bearer tokens. mTLS certificates are trusted if present (already verified
// during TLS handshake by -human-tls-ca) AND carry an explicit operator role
// URI SAN (sandswap://role/ops|admin|human). With OIDC configured the marker
// maps exactly: role/admin = human+admin+ops + fleet namespace wildcard,
// role/ops = ops, role/human = human (namespaces only from
// sandswap://ns/<name>). Without an OIDC provider mTLS is the only
// credential source and the legacy full grant is preserved. A verified
// certificate without a marker is refused. If no client cert is present,
// falls back to OIDC Bearer token validation.
func MTLSOrOIDCMiddleware(provider *OIDCProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		oidcHandler := OIDCMiddleware(provider)(next) // pre-build once, not per-request
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for mTLS client certificate.
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				cert := r.TLS.PeerCertificates[0]
				now := time.Now()
				// Reject expired client certificates (defense in depth —
				// TLS handshake should have caught this, but verify anyway).
				if now.After(cert.NotAfter) {
					writeAuthnJSONError(w, "client certificate expired", http.StatusUnauthorized)
					return
				}
				// Reject not-yet-valid client certificates.
				if now.Before(cert.NotBefore) {
					writeAuthnJSONError(w, "client certificate not yet valid", http.StatusUnauthorized)
					return
				}
				// mTLS: the certificate is CA-verified, but the CA is shared
				// with other certificate purposes. Only an explicit role SAN
				// grants the corresponding surface.
				scopes, namespaces, ok := certOperatorGrant(cert)
				if !ok {
					writeAuthnJSONError(w, "client certificate is not an operator credential (missing URI SAN "+MTLSOperatorRolePrefix+"ops)", http.StatusUnauthorized)
					return
				}
				// With OIDC configured, an mTLS marker is scoped exactly:
				// role/human gets human only (plus sandswap://ns/<name>
				// grants) and no fleet wildcard; role/ops gets ops; only
				// role/admin gets the full surface. On a deployment with NO
				// OIDC provider, mTLS is the only credential source, so the
				// legacy full grant is preserved there.
				rawNS := make([]any, 0, len(namespaces))
				for _, ns := range namespaces {
					rawNS = append(rawNS, ns)
				}
				if provider == nil {
					scopes = []string{ScopeHuman, ScopeAdmin, ScopeOps}
					rawNS = []any{NamespaceWildcard}
				}
				claims := &TokenClaims{
					Subject:  cert.Subject.CommonName,
					Name:     cert.Subject.CommonName,
					Issuer:   "mtls",
					Scopes:   scopes,
					Expiry:   cert.NotAfter,
					Audience: []string{"sandswap-api"},
					Raw:      map[string]any{NamespaceClaim: rawNS},
				}
				ctx := WithTokenClaims(r.Context(), claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// No mTLS cert → fall through to OIDC Bearer token.
			oidcHandler.ServeHTTP(w, r)
		})
	}
}

// extractBearerToken extracts the Bearer token from the Authorization header.
var errMissingBearer = errors.New("missing bearer token")

func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", errMissingBearer
	}
	// RFC 7235: the Authorization scheme is case-insensitive.
	// Normalize to "Bearer " for consistent prefix matching.
	// Only check the scheme part (before the first space), preserve token case.
	spaceIdx := strings.IndexByte(auth, ' ')
	if spaceIdx < 0 {
		return "", errMissingBearer
	}
	if !strings.EqualFold(auth[:spaceIdx], "Bearer") {
		return "", errMissingBearer
	}
	token := strings.TrimSpace(auth[spaceIdx+1:])
	if token == "" {
		return "", errMissingBearer
	}
	return token, nil
}

// writeAuthnJSONError writes a JSON error response (same format as handler/writeJSONError).
func writeAuthnJSONError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
