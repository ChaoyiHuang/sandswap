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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// generateTestKey generates an RSA key pair and returns the JWK public key,
// the JWK private key (for signing), and the raw RSA private key.
func generateTestKey(t *testing.T) (jwk.Key, jwk.Key, *rsa.PrivateKey) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pubJWK, err := jwk.FromRaw(privKey.Public())
	if err != nil {
		t.Fatalf("create public JWK: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}

	privJWK, err := jwk.FromRaw(privKey)
	if err != nil {
		t.Fatalf("create private JWK: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("set kid on private: %v", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg on private: %v", err)
	}

	return pubJWK, privJWK, privKey
}

// signTestToken creates and signs a JWT with the given JWK private key.
func signTestToken(t *testing.T, privJWK jwk.Key, issuer, clientID, subject string, scopes []string, expiry time.Time) string {
	t.Helper()
	tok := jwt.New()
	if err := tok.Set(jwt.IssuerKey, issuer); err != nil {
		t.Fatalf("set iss: %v", err)
	}
	if err := tok.Set(jwt.AudienceKey, clientID); err != nil {
		t.Fatalf("set aud: %v", err)
	}
	if err := tok.Set(jwt.SubjectKey, subject); err != nil {
		t.Fatalf("set sub: %v", err)
	}
	if err := tok.Set(jwt.ExpirationKey, expiry); err != nil {
		t.Fatalf("set exp: %v", err)
	}
	if len(scopes) > 0 {
		scopeStr := ""
		for i, s := range scopes {
			if i > 0 {
				scopeStr += " "
			}
			scopeStr += s
		}
		if err := tok.Set("scope", scopeStr); err != nil {
			t.Fatalf("set scope: %v", err)
		}
	}
	if err := tok.Set("email", subject+"@example.com"); err != nil {
		t.Fatalf("set email: %v", err)
	}
	if err := tok.Set("name", "Test User"); err != nil {
		t.Fatalf("set name: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privJWK))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// setupTestOIDCServer creates an httptest.Server that serves OIDC discovery
// and JWKS endpoints, and returns the server, the issuer URL, and a cleanup function.
func setupTestOIDCServer(t *testing.T, pubJWK jwk.Key) (*httptest.Server, string) {
	t.Helper()

	keySet := jwk.NewSet()
	keySet.AddKey(pubJWK)

	mux := http.NewServeMux()

	// OIDC Discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuer,
			"jwks_uri": issuer + "/jwks",
		})
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		buf, err := json.Marshal(keySet)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(buf)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server, server.URL
}

func TestOIDCProvider_Verify(t *testing.T) {
	pubJWK, privJWK, _ := generateTestKey(t)
	_, issuer := setupTestOIDCServer(t, pubJWK)

	const clientID = "test-client"
	ctx := context.Background()

	provider, err := NewOIDCProvider(ctx, OIDCConfig{
		Issuer:   issuer,
		ClientID: clientID,
	}, 1*time.Hour, slog.Default())
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	defer provider.Close()

	// Test 1: Valid token with human scope
	t.Run("valid_token_with_scope", func(t *testing.T) {
		token := signTestToken(t, privJWK, issuer, clientID, "user-123",
			[]string{ScopeHuman, ScopeOps}, time.Now().Add(1*time.Hour))

		claims, err := provider.Verify(ctx, token)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if claims.Subject != "user-123" {
			t.Errorf("Subject = %q, want %q", claims.Subject, "user-123")
		}
		if claims.Email != "user-123@example.com" {
			t.Errorf("Email = %q, want %q", claims.Email, "user-123@example.com")
		}
		if claims.Name != "Test User" {
			t.Errorf("Name = %q, want %q", claims.Name, "Test User")
		}
		if !claims.HasScope(ScopeHuman) {
			t.Error("HasScope(sandswap:human) = false, want true")
		}
		if !claims.HasScope(ScopeOps) {
			t.Error("HasScope(sandswap:ops) = false, want true")
		}
	})

	// Test 2: Expired token
	t.Run("expired_token", func(t *testing.T) {
		token := signTestToken(t, privJWK, issuer, clientID, "user-456",
			[]string{ScopeHuman}, time.Now().Add(-1*time.Hour))

		_, err := provider.Verify(ctx, token)
		if err == nil {
			t.Error("Verify(expired) = nil, want error")
		}
	})

	// Test 3: Wrong issuer
	t.Run("wrong_issuer", func(t *testing.T) {
		token := signTestToken(t, privJWK, "https://wrong-issuer.example.com",
			clientID, "user-789", []string{ScopeHuman}, time.Now().Add(1*time.Hour))

		_, err := provider.Verify(ctx, token)
		if err == nil {
			t.Error("Verify(wrong issuer) = nil, want error")
		}
	})

	// Test 4: Wrong audience
	t.Run("wrong_audience", func(t *testing.T) {
		token := signTestToken(t, privJWK, issuer, "wrong-client",
			"user-abc", []string{ScopeHuman}, time.Now().Add(1*time.Hour))

		_, err := provider.Verify(ctx, token)
		if err == nil {
			t.Error("Verify(wrong audience) = nil, want error")
		}
	})

	// Test 5: Token with only human scope
	t.Run("human_scope_only", func(t *testing.T) {
		token := signTestToken(t, privJWK, issuer, clientID, "user-def",
			[]string{ScopeHuman}, time.Now().Add(1*time.Hour))

		claims, err := provider.Verify(ctx, token)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !claims.HasScope(ScopeHuman) {
			t.Error("HasScope(sandswap:human) = false, want true")
		}
		if claims.HasScope(ScopeOps) {
			t.Error("HasScope(sandswap:ops) = true, want false")
		}
	})

	// Test 6: Token with no scopes
	t.Run("no_scopes", func(t *testing.T) {
		token := signTestToken(t, privJWK, issuer, clientID, "user-ghi",
			nil, time.Now().Add(1*time.Hour))

		claims, err := provider.Verify(ctx, token)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if claims.HasScope(ScopeHuman) {
			t.Error("HasScope(sandswap:human) = true, want false")
		}
		if len(claims.Scopes) != 0 {
			t.Errorf("Scopes = %v, want empty", claims.Scopes)
		}
	})

	// Token without "sub" claim (required claim)
	t.Run("missing_sub", func(t *testing.T) {
		tok := jwt.New()
		if err := tok.Set(jwt.IssuerKey, issuer); err != nil {
			t.Fatalf("set iss: %v", err)
		}
		if err := tok.Set(jwt.AudienceKey, clientID); err != nil {
			t.Fatalf("set aud: %v", err)
		}
		if err := tok.Set(jwt.ExpirationKey, time.Now().Add(1*time.Hour)); err != nil {
			t.Fatalf("set exp: %v", err)
		}
		// Intentionally NOT setting SubjectKey
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privJWK))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}

		_, err = provider.Verify(ctx, string(signed))
		if err == nil {
			t.Error("Verify(missing sub) = nil, want error")
		}
	})
}

// TestNewOIDCProvider_DiscoveryIssuerMismatch tests that the provider rejects
// a discovery document whose issuer doesn't match the configured issuer.
// The jwks_uri is on the SAME host as the server (so the origin check passes),
// but the "issuer" field in the doc differs from the configured issuer.
func TestNewOIDCProvider_DiscoveryIssuerMismatch(t *testing.T) {
	pubJWK, _, _ := generateTestKey(t)

	keySet := jwk.NewSet()
	keySet.AddKey(pubJWK)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// jwks_uri on the SAME host (passes the origin check), but issuer differs.
		issuer := "http://" + r.Host
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":   "https://evil-issuer.example.com", // mismatch!
			"jwks_uri": issuer + "/jwks",                  // same host — origin check passes
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		buf, _ := json.Marshal(keySet)
		w.Write(buf)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	_, err := NewOIDCProvider(context.Background(), OIDCConfig{
		Issuer:   server.URL,
		ClientID: "test-client",
	}, 1*time.Hour, slog.Default())
	if err == nil {
		t.Error("NewOIDCProvider(discovery issuer mismatch) = nil, want error")
	}
}

func TestNewOIDCProvider_InvalidConfig(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	t.Run("empty_issuer", func(t *testing.T) {
		_, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: "", ClientID: "x"}, 0, logger)
		if err == nil {
			t.Error("NewOIDCProvider(empty issuer) = nil, want error")
		}
	})

	t.Run("empty_client_id", func(t *testing.T) {
		_, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: "https://example.com", ClientID: ""}, 0, logger)
		if err == nil {
			t.Error("NewOIDCProvider(empty client_id) = nil, want error")
		}
	})

	t.Run("non_https_issuer", func(t *testing.T) {
		_, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: "http://evil.example.com", ClientID: "x"}, 0, logger)
		if err == nil {
			t.Error("NewOIDCProvider(http non-localhost) = nil, want error")
		}
	})
}

func TestTokenClaims_HasScope(t *testing.T) {
	claims := &TokenClaims{
		Scopes: []string{"sandswap:human", "sandswap:ops"},
	}

	if !claims.HasScope("sandswap:human") {
		t.Error("HasScope(sandswap:human) = false, want true")
	}
	if !claims.HasScope("sandswap:ops") {
		t.Error("HasScope(sandswap:ops) = false, want true")
	}
	if claims.HasScope("sandswap:admin") {
		t.Error("HasScope(sandswap:admin) = true, want false")
	}
}

// TestLocalhostBypass verifies that userinfo and subdomain tricks don't bypass
// the HTTPS enforcement for issuer URLs.
func TestLocalhostBypass(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	t.Run("userinfo_bypass", func(t *testing.T) {
		_, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: "http://localhost@evil.com", ClientID: "x"}, 0, logger)
		if err == nil {
			t.Error("http://localhost@evil.com should be rejected (userinfo bypass)")
		}
	})

	t.Run("subdomain_bypass", func(t *testing.T) {
		_, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: "http://localhost.evil.com", ClientID: "x"}, 0, logger)
		if err == nil {
			t.Error("http://localhost.evil.com should be rejected (subdomain bypass)")
		}
	})

	t.Run("ip_subdomain_bypass", func(t *testing.T) {
		_, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: "http://127.0.0.1.evil.com", ClientID: "x"}, 0, logger)
		if err == nil {
			t.Error("http://127.0.0.1.evil.com should be rejected (IP subdomain bypass)")
		}
	})
}

// Suppress unused import warning for jwa.
var _ = jwa.RS256
