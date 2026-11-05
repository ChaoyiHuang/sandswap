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
// Package authn provides OIDC JWT token verification for the gateway's
// human-facing endpoints (/human/*). It implements the Identity Broker
// pattern: the gateway validates JWTs from a single OIDC issuer (e.g.,
// Auth0, Keycloak, Clerk, or a direct IdP like Google/Azure AD) using
// locally cached JWKS public keys — zero network calls per request.
// Three scope levels are supported:
//   - sandswap:human — user-resource CRUD (/human/sandfs, /human/templates)
//   - sandswap:admin — agent credential minting (/human/agent*)
//   - sandswap:ops   — operations staff: observability (/stats, /metrics)
//                      + fleet reclamation (/human/ownership/*)

package authn

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/sync/singleflight"
)

// OIDCConfig configures the OIDC provider (Identity Broker or direct IdP).
type OIDCConfig struct {
	Issuer   string // OIDC issuer URL, e.g., "https://your-tenant.auth0.com/"
	ClientID string // OAuth2 client_id for audience validation
}

// OIDCProvider validates JWTs issued by a single OIDC issuer.
// It caches JWKS public keys and refreshes them periodically.
type OIDCProvider struct {
	issuer           string
	audience         string
	keySet           jwk.Set
	keySetURL        string
	httpClient       *http.Client
	logger           *slog.Logger
	mu               sync.RWMutex
	sf               singleflight.Group // dedup concurrent JWKS refreshes
	lastForceRefresh time.Time          // min-interval guard for force-refreshes (DoS mitigation)
	// missingSince records the first time each kid disappeared from a fetched
	// JWKS (guarded by mu): the bounded revocation signal for IdPs that
	// publish no per-key expiry.
	missingSince map[string]time.Time
	cancel       context.CancelFunc
}

// NewOIDCProvider initializes an OIDCProvider:
//  1. GET <issuer>/.well-known/openid-configuration → discover jwks_uri
//  2. GET <jwks_uri> → cache JWKS public keys
//  3. Start background goroutine to refresh JWKS periodically
func NewOIDCProvider(ctx context.Context, cfg OIDCConfig, refreshInterval time.Duration, logger *slog.Logger) (*OIDCProvider, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("authn: issuer is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("authn: client_id is required")
	}
	// Enforce HTTPS for the issuer URL (allow http for localhost/loopback in dev).
	// Use url.Parse + Hostname() instead of string prefix matching to prevent
	// bypasses like http://localhost@evil.com (userinfo -> host is evil.com),
	// http://localhost.evil.com, or http://127.0.0.1.evil.com.
	trimmedIssuer := strings.TrimRight(cfg.Issuer, "/")
	issuerURL, err := url.Parse(trimmedIssuer)
	if err != nil || issuerURL.Host == "" {
		return nil, fmt.Errorf("authn: invalid issuer URL %q: %v", cfg.Issuer, err)
	}
	host := issuerURL.Hostname()
	isLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if issuerURL.Scheme != "https" && !(issuerURL.Scheme == "http" && isLoopback) {
		return nil, fmt.Errorf("authn: issuer must use HTTPS (got %q); http is only allowed for localhost/loopback", cfg.Issuer)
	}
	if refreshInterval <= 0 {
		refreshInterval = 1 * time.Hour
	}
	if logger == nil {
		logger = slog.Default()
	}

	p := &OIDCProvider{
		issuer:       strings.TrimRight(cfg.Issuer, "/"),
		audience:     cfg.ClientID,
		missingSince: make(map[string]time.Time),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
		logger: logger,
	}

	// Step 1: OIDC Discovery — fetch .well-known/openid-configuration
	discoveryURL := p.issuer + "/.well-known/openid-configuration"
	keySetURL, err := p.discoverJWKSURI(ctx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("authn: OIDC discovery failed for %s: %w", p.issuer, err)
	}
	p.keySetURL = keySetURL
	logger.Info("OIDC discovery successful", "issuer", p.issuer, "jwks_uri", keySetURL)

	// Step 2: Fetch initial JWKS
	keySet, err := p.fetchJWKS(ctx, keySetURL)
	if err != nil {
		return nil, fmt.Errorf("authn: JWKS fetch failed for %s: %w", keySetURL, err)
	}
	p.keySet = keySet
	logger.Info("JWKS cached", "issuer", p.issuer, "keys", keySet.Len())

	// Step 3: Start background JWKS refresh
	refreshCtx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.jwksRefreshLoop(refreshCtx, refreshInterval)

	return p, nil
}

// Close stops the JWKS refresh goroutine.
func (p *OIDCProvider) Close() {
	if p.cancel != nil {
		p.cancel()
	}
}

// Verify validates a raw JWT string and returns the extracted claims.
//
// Steps:
//  1. Parse JWT header → kid (key ID)
//  2. Look up public key from cached JWKS (miss → force refresh)
//  3. Verify signature (RS256/RS384/RS512/ES256/ES384/ES512)
//  4. Verify iss == configured issuer
//  5. Verify aud contains configured clientID
//  6. Verify exp not expired
//  7. Extract sub, email, name, scope claims
func (p *OIDCProvider) Verify(ctx context.Context, rawToken string) (*TokenClaims, error) {
	// Parse and verify the JWT.
	// jwx's jwt.Parse verifies signature, iss, aud, exp in one call
	// when given a jwk.KeySet.
	p.mu.RLock()
	keySet := p.keySet
	p.mu.RUnlock()

	token, err := jwt.ParseString(rawToken, p.parseOptions(keySet)...)
	if err != nil {
		// Deterministic key-miss detection — parse the JWT header to get kid,
		// then check if the cached key set contains it. If not, force-refresh JWKS.
		if isKeyNotFoundError(keySet, rawToken) {
			if retryClaims, retryErr := p.verifyWithRefreshedJWKS(ctx, rawToken); retryErr == nil {
				return retryClaims, nil
			}
		}
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	return extractClaims(token), nil
}

// parseOptions is the ONE validation policy for both verification paths
// (cached-key first attempt and post-refresh retry): issuer, audience, clock
// skew, required exp/sub claims and a non-empty subject. Sharing it keeps the
// retry from silently accepting a token shape the primary path rejects.
func (p *OIDCProvider) parseOptions(keySet jwk.Set) []jwt.ParseOption {
	return []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(p.issuer),
		jwt.WithAudience(p.audience),
		jwt.WithAcceptableSkew(30 * time.Second),    // tolerate clock skew between IdP and gateway
		jwt.WithRequiredClaim(jwt.SubjectKey),       // reject tokens without "sub"
		jwt.WithRequiredClaim(jwt.ExpirationKey),    // reject tokens without "exp"
		jwt.WithValidator(nonEmptySubjectValidator), // reject sub=""
		jwt.WithValidate(true),
	}
}

// verifyWithRefreshedJWKS forces a JWKS refresh and retries verification.
// Uses singleflight to dedup concurrent refresh requests, and a minimum
// interval guard to prevent DoS amplification from sequential bogus-kid tokens.
func (p *OIDCProvider) verifyWithRefreshedJWKS(ctx context.Context, rawToken string) (*TokenClaims, error) {
	// DoS mitigation: if we force-refreshed recently, don't hammer the IdP.
	// An attacker sending sequential tokens with random kids can't trigger more
	// than one fetch per minForceRefreshInterval.
	p.mu.RLock()
	last := p.lastForceRefresh
	p.mu.RUnlock()
	if !last.IsZero() && time.Since(last) < minForceRefreshInterval {
		return nil, fmt.Errorf("token verification failed: key not in JWKS (refresh throttled)")
	}

	p.logger.Info("JWKS key miss, force-refreshing", "issuer", p.issuer)

	// Singleflight dedup — if N requests hit this concurrently, only one
	// actually fetches JWKS; the others share the result.
	v, err, _ := p.sf.Do("jwks-refresh", func() (any, error) {
		return p.fetchJWKS(ctx, p.keySetURL)
	})
	if err != nil {
		// Arm the throttle on FAILURE too: a down IdP must not be hammered by
		// every unknown-kid token (singleflight only merges concurrent calls).
		p.mu.Lock()
		p.lastForceRefresh = time.Now()
		p.mu.Unlock()
		return nil, fmt.Errorf("JWKS refresh failed: %w", err)
	}
	newKeySet := v.(jwk.Set)

	p.mu.Lock()
	// Merge: keep keys from the old set that disappeared from the new set for a
	// grace period, so in-flight tokens signed with a rotated-away key still
	// verify (key rotation gap fix).
	p.keySet = mergeKeySets(p.keySet, newKeySet, keyGracePeriod, p.missingSince)
	p.lastForceRefresh = time.Now()
	p.mu.Unlock()

	token, err := jwt.ParseString(rawToken, p.parseOptions(newKeySet)...)
	if err != nil {
		return nil, fmt.Errorf("token verification failed after JWKS refresh: %w", err)
	}

	return extractClaims(token), nil
}

// minForceRefreshInterval is the minimum time between IdP JWKS fetches triggered
// by unknown-key token verification. Bounds DoS amplification from bogus-kid tokens.
const minForceRefreshInterval = 30 * time.Second

// keyGracePeriod is how long a key that disappears from a refreshed JWKS is
// kept locally, so tokens signed with a rotated-away key keep verifying until
// they expire.
const keyGracePeriod = 24 * time.Hour

// keyIdentifier is the stable identity used for absence tracking: the JWK's
// kid, or its RFC 7638 thumbprint when the IdP publishes no kid. Without the
// fallback a kid-less key is never recorded as missing and therefore never
// revoked (it would stay valid forever once it disappears from the JWKS).
func keyIdentifier(k jwk.Key) string {
	if kid := k.KeyID(); kid != "" {
		return kid
	}
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil || len(tp) == 0 {
		return ""
	}
	return "sha256:" + hex.EncodeToString(tp)
}

// mergeKeySets returns a new key set containing all keys from fresh, plus any
// keys from stale that are absent from fresh (retained for a bounded grace
// period so tokens signed with a rotated-away key keep verifying). Keys present
// in fresh always win (latest version).
//
// Absence is tracked in missingSince: most IdPs publish no per-JWK expiry, so
// the ONLY bounded signal that a key was revoked is "it disappeared from the
// JWKS". A key first seen absent is retained until the grace elapses, then
// dropped; a key that reappears clears its marker. (The old behaviour retained
// every exp-less key forever, keeping revoked signing keys valid indefinitely.)
func mergeKeySets(stale, fresh jwk.Set, grace time.Duration, missingSince map[string]time.Time) jwk.Set {
	merged := jwk.NewSet()
	freshIDs := make(map[string]bool, fresh.Len())
	// Add all fresh keys.
	for i := 0; i < fresh.Len(); i++ {
		k, _ := fresh.Key(i)
		merged.AddKey(k)
		if id := keyIdentifier(k); id != "" {
			freshIDs[id] = true
			delete(missingSince, id)
		}
	}
	// Add stale keys missing from fresh while inside the grace window.
	now := time.Now()
	for i := 0; i < stale.Len(); i++ {
		k, _ := stale.Key(i)
		id := keyIdentifier(k)
		if id != "" {
			if freshIDs[id] {
				continue // replaced by a fresh version
			}
			first, seen := missingSince[id]
			if !seen {
				missingSince[id] = now
				first = now
			}
			if now.Sub(first) >= grace {
				continue // absent longer than the grace: revoked
			}
		}
		// A key whose own expiry is long past is dropped immediately; the
		// missing-since clock above is the bound for IdPs that publish none.
		if exp, ok := getJWKExpiry(k); ok && now.After(exp.Add(grace)) {
			continue
		}
		merged.AddKey(k)
	}
	return merged
}

// getJWKExpiry returns the key's "exp" claim if it carries one (some IdPs set
// key expiration in the JWK).
func getJWKExpiry(k jwk.Key) (time.Time, bool) {
	v, ok := k.Get("exp")
	if !ok {
		return time.Time{}, false
	}
	switch exp := v.(type) {
	case time.Time:
		return exp, true
	case *time.Time:
		if exp != nil {
			return *exp, true
		}
	}
	return time.Time{}, false
}

// isKeyNotFoundError checks whether the verification failure is due to a
// missing key in the cached JWKS. It parses the JWT header to extract the
// kid (key ID) and checks if it exists in the key set.
func isKeyNotFoundError(keySet jwk.Set, rawToken string) bool {
	// Parse just the JWT header (no verification) to extract kid.
	msg, err := jws.ParseString(rawToken)
	if err != nil {
		return false
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return false
	}
	kid := sigs[0].ProtectedHeaders().KeyID()
	if kid == "" {
		return false
	}
	// Check if the key set contains a key with this kid.
	_, found := keySet.LookupKeyID(kid)
	return !found
}

// nonEmptySubjectValidator rejects tokens with an empty "sub" claim.
// WithRequiredClaim(SubjectKey) checks presence, but "sub":"" still passes.
var nonEmptySubjectValidator = jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) jwt.ValidationError {
	if t.Subject() == "" {
		return jwt.NewValidationError(fmt.Errorf("\"sub\" claim must not be empty"))
	}
	return nil
})

// TokenClaims holds the user identity extracted from a verified JWT.
type TokenClaims struct {
	Subject  string         // "sub" — unique user ID within the issuer
	Email    string         // "email" (may be empty)
	Name     string         // "name" (may be empty)
	Issuer   string         // "iss"
	Audience []string       // "aud"
	Expiry   time.Time      // "exp"
	Scopes   []string       // "scope" — space-separated scope list, split into []string
	Raw      map[string]any // full claims for custom mapping/audit
}

// HasScope checks whether the token contains the specified scope.
func (c *TokenClaims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// extractClaims pulls standard claims from a parsed JWT.
func extractClaims(token jwt.Token) *TokenClaims {
	// Extract audience as []string.
	aud := make([]string, 0, len(token.Audience()))
	aud = append(aud, token.Audience()...)

	// Extract scope: OAuth2 scope is a single string with space-separated values.
	var scopes []string
	if scopeStr, ok := token.Get("scope"); ok {
		if s, ok := scopeStr.(string); ok && s != "" {
			scopes = strings.Split(s, " ")
		}
	}

	// Extract name: jwx may not expose "name" as a method, so try the claim directly.
	name := ""
	if n, ok := token.Get("name"); ok {
		if s, ok := n.(string); ok {
			name = s
		}
	}

	// Build raw claims map.
	raw, err := token.AsMap(context.Background())
	if err != nil {
		raw = make(map[string]any)
	}

	return &TokenClaims{
		Subject:  token.Subject(),
		Email:    claimString(token, "email"),
		Name:     name,
		Issuer:   token.Issuer(),
		Audience: aud,
		Expiry:   token.Expiration(),
		Scopes:   scopes,
		Raw:      raw,
	}
}

// claimString extracts a string claim by key.
func claimString(token jwt.Token, key string) string {
	if v, ok := token.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// discoverJWKSURI fetches the OIDC discovery document and returns the jwks_uri.
func (p *OIDCProvider) discoverJWKSURI(ctx context.Context, discoveryURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("create discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery document returned status %d", resp.StatusCode)
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("parse discovery document: %w", err)
	}

	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery document missing jwks_uri")
	}

	// Validate jwks_uri origin matches the issuer to prevent open redirect.
	// The jwks_uri must share the same scheme and host as the issuer.
	jwksURL, err := url.Parse(doc.JWKSURI)
	if err != nil {
		return "", fmt.Errorf("invalid jwks_uri %q: %w", doc.JWKSURI, err)
	}
	issuerURL, err := url.Parse(p.issuer)
	if err != nil {
		return "", fmt.Errorf("invalid issuer %q: %w", p.issuer, err)
	}
	if jwksURL.Scheme != issuerURL.Scheme || jwksURL.Host != issuerURL.Host {
		return "", fmt.Errorf("jwks_uri origin %s://%s does not match issuer origin %s://%s",
			jwksURL.Scheme, jwksURL.Host, issuerURL.Scheme, issuerURL.Host)
	}

	// Verify the issuer in the discovery document matches the configured issuer.
	// This prevents a malicious or misconfigured IdP from serving tokens
	// under a different issuer than expected (OIDC spec requirement).
	if doc.Issuer != p.issuer {
		return "", fmt.Errorf("discovery document issuer %q does not match configured issuer %q", doc.Issuer, p.issuer)
	}

	return doc.JWKSURI, nil
}

// fetchJWKS fetches and parses a JWKS from the given URL.
func (p *OIDCProvider) fetchJWKS(ctx context.Context, jwksURL string) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	keySet, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	// Reject empty key sets — a JWKS with no keys is either misconfigured
	// or a signal that the IdP is in a broken state.
	if keySet.Len() == 0 {
		return nil, fmt.Errorf("JWKS contains no keys")
	}

	return keySet, nil
}

// jwksRefreshLoop periodically refreshes the cached JWKS.
func (p *OIDCProvider) jwksRefreshLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newKeySet, err := p.fetchJWKS(ctx, p.keySetURL)
			if err != nil {
				p.logger.Warn("JWKS refresh failed, using cached keys",
					"issuer", p.issuer, "error", err)
				continue
			}
			p.mu.Lock()
			p.keySet = mergeKeySets(p.keySet, newKeySet, keyGracePeriod, p.missingSince)
			keyCount := p.keySet.Len() // read UNDER the lock (the field is shared with Verify)
			p.mu.Unlock()
			p.logger.Info("JWKS refreshed", "issuer", p.issuer, "keys", keyCount)
		}
	}
}
