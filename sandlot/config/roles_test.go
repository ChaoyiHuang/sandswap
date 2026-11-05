// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

package config

import "testing"

// TestValidateRolesMatrix covers the role/config validation matrix: every
// combination that must be accepted or refused, named by the shape it
// describes.
func TestValidateRolesMatrix(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*SandlotConfig)
		wantErr bool
	}{
		{"empty roles defaults to exec", func(c *SandlotConfig) { c.Roles = nil }, false},
		{"exec only with full vm machinery", func(c *SandlotConfig) { c.Roles = []string{"exec"}; c.Pool = "small:2" }, false},
		{"prov only, plain", func(c *SandlotConfig) { c.Roles = []string{"prov"} }, false},
		{"exec+prov merged with pool", func(c *SandlotConfig) { c.Roles = []string{"exec", "prov"}; c.Pool = "small:1" }, false},
		{"prov only with pool refused", func(c *SandlotConfig) { c.Roles = []string{"prov"}; c.Pool = "small:2" }, true},
		{"prov only with boxout refused", func(c *SandlotConfig) { c.Roles = []string{"prov"}; c.VMMode = "boxout" }, true},
		{"prov only with bridge refused", func(c *SandlotConfig) { c.Roles = []string{"prov"}; c.Network.Backend = "bridge" }, true},
		{"unknown role refused", func(c *SandlotConfig) { c.Roles = []string{"storage"} }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestNormalizedRoles(t *testing.T) {
	c := Defaults()
	if got := c.NormalizedRoles(); len(got) != 1 || got[0] != "exec" {
		t.Fatalf("default roles = %v, want [exec]", got)
	}
	if !c.HasRole("exec") || c.HasRole("prov") {
		t.Fatalf("default: HasRole(exec)=%v HasRole(prov)=%v, want true/false", c.HasRole("exec"), c.HasRole("prov"))
	}
	c.Roles = []string{"prov", "exec", "prov"}
	if got := c.NormalizedRoles(); len(got) != 2 {
		t.Fatalf("dedupe failed: %v", got)
	}
	if got := parseRolesFlag(" exec , prov ,,"); len(got) != 2 || got[0] != "exec" || got[1] != "prov" {
		t.Fatalf("parseRolesFlag = %v", got)
	}
}
