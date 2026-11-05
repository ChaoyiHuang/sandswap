// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, your use of this software will be
// governed by the Apache License, Version 2.0.

// Namespace claim extraction — the OIDC side of the human-API tenancy
// model (docs/how-it-works/namespaces.md). The IdP issues a multivalued
// "sandswap_ns" claim (Keycloak: a client scope with one multivalued user-
// attribute mapper per namespace grant); the human gateway treats the claim
// set as the caller's namespace grants:
//
//   - "*"                    — fleet-wide access (the admin shape; the ONLY
//                              set that can use the unscoped /human/* paths)
//   - ["acme", "acme-prod"]  — exactly those namespaces, via /human/ns/<ns>/…
//   - absent or empty        — no namespace access: every namespaced path
//                              answers 403 and the unscoped paths 403 too.
//                              (An authenticated human token with no
//                              sandswap_ns claim can still hold scopes for
//                              templates/stats/etc. — namespaces are one
//                              axis, scopes are another.)
//
// The namespace REGISTRY is implicit: no namespace object exists in
// sandswap or etcd. Which namespaces exist, and who may act in them, is
// entirely the IdP's group/attribute data — creating a namespace means
// granting the claim in the IdP, nothing else.

package authn

import (
	"context"

	"gateway/identity"
)

// NamespaceClaim is the OIDC claim carrying the caller's namespace grants.
const NamespaceClaim = "sandswap_ns"

// NamespaceWildcard is the claim value granting fleet-wide namespace access.
// It is legal ONLY inside the claim set — never as a namespace name.
//
// On the mTLS credential path the wildcard is reserved to the ADMIN operator
// role: a certificate carrying sandswap://ns/* without sandswap://role/admin is
// refused the wildcard by certOperatorGrant (middleware.go), so a CA that signs
// tenant certificates cannot widen one into fleet access through a URI SAN. The
// OIDC claim set is a different authority — the IdP is the namespace registry —
// and its "*" entries are honored as issued.
const NamespaceWildcard = "*"

// WithTokenClaims attaches verified claims to a context. Exported so the
// middleware and tests share one injection path (the context key stays
// private).
func WithTokenClaims(ctx context.Context, claims *TokenClaims) context.Context {
	return context.WithValue(ctx, tokenClaimsKey{}, claims)
}

// NamespacesFromClaims extracts the caller's namespace grants from the
// verified claims. Accepts the two shapes IdPs emit for multivalued claims —
// a JSON array of strings, or a bare string — and keeps only entries that
// are the wildcard or syntactically valid namespace names (a malformed entry
// is DROPPED, not fatal: the IdP is the authority over grant data, but the
// gateway refuses to widen a grant through a typo). Order-preserving dedup;
// nil claims yield nil.
func NamespacesFromClaims(claims *TokenClaims) []string {
	if claims == nil {
		return nil
	}
	raw, ok := claims.Raw[NamespaceClaim]
	if !ok {
		return nil
	}
	var entries []string
	switch v := raw.(type) {
	case []any:
		entries = make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				continue
			}
			entries = append(entries, s)
		}
	case string:
		entries = []string{v}
	default:
		return nil
	}
	out := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if e != NamespaceWildcard && !identity.ValidNamespace(e) {
			continue
		}
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out
}

// NamespaceScope is the resolved namespace grant for one request.
type NamespaceScope struct {
	// Fleet is true when the wildcard is granted — the unscoped /human/*
	// surface is reachable. Anonymous passthrough resolves as fleet for the
	// unscoped fleet gate only (-allow-anonymous-human shape); the namespaced
	// surface refuses anonymous requests outright before consulting this
	// scope(no identity, no namespace grants).
	Fleet bool
	// Names holds the explicit namespace grants (never contains "*").
	Names map[string]struct{}
}

// Allows reports whether the scope covers namespace ns.
func (s NamespaceScope) Allows(ns string) bool {
	if s.Fleet {
		return true
	}
	_, ok := s.Names[ns]
	return ok
}

// NamespaceScopeFromContext resolves the request's namespace grant. Claims
// absent resolves as fleet — the explicit -allow-anonymous-human deployment
// shape, where the unscoped surface is intentionally open — and callers on
// the NAMESPACED surface must refuse the anonymous case BEFORE consulting
// this (see handler.serveNamespaced: no identity means no namespace grants).
// Claims present ⇒ exactly the claim set (an authenticated token WITHOUT
// sandswap_ns gets the empty scope — deliberate: authenticated-but-ungranted
// is denied).
func NamespaceScopeFromContext(ctx context.Context) NamespaceScope {
	claims := TokenClaimsFromContext(ctx)
	if claims == nil {
		return NamespaceScope{Fleet: true}
	}
	ns := NamespacesFromClaims(claims)
	if len(ns) == 0 {
		return NamespaceScope{}
	}
	scope := NamespaceScope{Names: make(map[string]struct{}, len(ns))}
	for _, n := range ns {
		if n == NamespaceWildcard {
			scope.Fleet = true
			continue
		}
		scope.Names[n] = struct{}{}
	}
	return scope
}
