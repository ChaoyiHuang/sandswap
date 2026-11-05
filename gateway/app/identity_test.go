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
