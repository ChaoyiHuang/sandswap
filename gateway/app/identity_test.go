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

package app

import (
	"os"
	"strings"
	"testing"

	gwconfig "gateway/config"
)

// TestHumanAuthnRefusal pins a human listener with no issuer refuses
// to start unless the operator explicitly opts out; the refusal names both
// remedies.
func TestHumanAuthnRefusal(t *testing.T) {
	// No issuer, no opt-out → refused.
	cfg := &gwconfig.GatewayConfig{}
	err := humanAuthnRefusal(cfg)
	if err == nil {
		t.Fatal("human listener with no issuer and no opt-out must be refused")
	}
	if !strings.Contains(err.Error(), "authn.issuer") || !strings.Contains(err.Error(), "allow-anonymous-human") {
		t.Errorf("refusal must name both remedies, got %q", err.Error())
	}

	// Explicit opt-out on loopback → allowed (the loud warn happens at
	// initAuthn).
	cfg = &gwconfig.GatewayConfig{}
	cfg.Authn.AllowAnonymous = true
	cfg.Human.Addr = "127.0.0.1:3100"
	if err := humanAuthnRefusal(cfg); err != nil {
		t.Errorf("explicit loopback opt-out must be honored, got %v", err)
	}

	// Anonymous on a non-loopback bind needs the SECOND acknowledgement.
	cfg = &gwconfig.GatewayConfig{}
	cfg.Authn.AllowAnonymous = true
	cfg.Human.Addr = "0.0.0.0:3100"
	if err := humanAuthnRefusal(cfg); err == nil ||
		!strings.Contains(err.Error(), "allow-anonymous-human-public") {
		t.Errorf("anonymous non-loopback bind must be refused with the public flag named, got %v", err)
	}
	cfg.Authn.AllowAnonymousPublic = true
	if err := humanAuthnRefusal(cfg); err != nil {
		t.Errorf("public acknowledgement must be honored, got %v", err)
	}

	// Issuer configured → allowed, opt-out irrelevant.
	cfg = &gwconfig.GatewayConfig{}
	cfg.Authn.Issuer = "https://idp.example"
	if err := humanAuthnRefusal(cfg); err != nil {
		t.Errorf("issuer configured must not be refused, got %v", err)
	}
}

// TestResolveGatewayID verifies gateway identity resolution: an explicit
// GatewayID is returned verbatim (stable identity across restarts for
// ownership/registry reclaim); otherwise it derives "mode-hostname".
func TestResolveGatewayID(t *testing.T) {
	// Explicit ID wins.
	cfg := &gwconfig.GatewayConfig{GatewayID: "gw-pod-0"}
	if got := resolveGatewayID(cfg, "exec"); got != "gw-pod-0" {
		t.Errorf("explicit GatewayID = %q, want gw-pod-0", got)
	}
	// Empty -> mode-hostname.
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	cfg2 := &gwconfig.GatewayConfig{}
	if got := resolveGatewayID(cfg2, "exec"); got != "exec-"+hostname {
		t.Errorf("derived GatewayID = %q, want exec-%s", got, hostname)
	}
}

// TestResolveScopes verifies the OIDC scope defaults: an empty config falls
// back to the authn package defaults, a set value is returned verbatim.
func TestResolveScopes(t *testing.T) {
	if got := resolveScopeHuman(&gwconfig.GatewayConfig{}); got != "sandswap:human" {
		t.Errorf("default human scope = %q, want sandswap:human", got)
	}
	if got := resolveScopeAdmin(&gwconfig.GatewayConfig{}); got != "sandswap:admin" {
		t.Errorf("default admin scope = %q, want sandswap:admin", got)
	}
	if got := resolveScopeOps(&gwconfig.GatewayConfig{}); got != "sandswap:ops" {
		t.Errorf("default ops scope = %q, want sandswap:ops", got)
	}
	cfg := &gwconfig.GatewayConfig{}
	cfg.Authn.ScopeHuman = "custom:human"
	cfg.Authn.ScopeAdmin = "custom:admin"
	cfg.Authn.ScopeOps = "custom:ops"
	if got := resolveScopeHuman(cfg); got != "custom:human" {
		t.Errorf("configured human scope = %q", got)
	}
	if got := resolveScopeAdmin(cfg); got != "custom:admin" {
		t.Errorf("configured admin scope = %q", got)
	}
	if got := resolveScopeOps(cfg); got != "custom:ops" {
		t.Errorf("configured ops scope = %q", got)
	}
}
