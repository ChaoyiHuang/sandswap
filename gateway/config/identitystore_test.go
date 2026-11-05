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

package config

import (
	"path/filepath"
	"testing"
)

// TestEffectiveIdentityStorePath verifies resolution: an explicit override wins;
// everything else resolves to the GATEWAY STATE DIR (VolRoot's parent — the
// unit's StateDirectory), not inside the volumes tree (the storage plane owns
// that; the gateway holds no write access there). The default resolves lazily
// off VolRoot so a late -vol-root override always wins.
func TestEffectiveIdentityStorePath(t *testing.T) {
	t.Run("default sits beside vol_root (gateway state dir)", func(t *testing.T) {
		cfg := Defaults()
		want := filepath.Join(filepath.Dir(cfg.VolRoot), DefaultIdentityStoreFilename)
		if got := cfg.EffectiveIdentityStorePath(); got != want {
			t.Errorf("EffectiveIdentityStorePath() = %q, want %q", got, want)
		}
	})

	t.Run("default follows a vol-root override", func(t *testing.T) {
		cfg := Defaults()
		cfg.VolRoot = "/data/volumes"
		want := filepath.Join("/data", DefaultIdentityStoreFilename)
		if got := cfg.EffectiveIdentityStorePath(); got != want {
			t.Errorf("EffectiveIdentityStorePath() = %q, want %q", got, want)
		}
	})

	t.Run("explicit path wins", func(t *testing.T) {
		cfg := Defaults()
		cfg.VolRoot = "/data/volumes"
		cfg.IdentityStore = "/var/lib/sandswap/identity.json"
		if got := cfg.EffectiveIdentityStorePath(); got != "/var/lib/sandswap/identity.json" {
			t.Errorf("EffectiveIdentityStorePath() = %q, want the explicit path", got)
		}
	})

	t.Run("explicit empty resolves to the default path", func(t *testing.T) {
		// Persistence is mandatory: EffectiveIdentityStorePath never returns "".
		// Rejecting the explicit empty value is runSingleNodeMode's job
		// (fail-fast), not the resolver's.
		cfg := Defaults()
		cfg.IdentityStoreExplicit = true // -identity-store= (empty value)
		want := filepath.Join(filepath.Dir(cfg.VolRoot), DefaultIdentityStoreFilename)
		if got := cfg.EffectiveIdentityStorePath(); got != want {
			t.Errorf("EffectiveIdentityStorePath() = %q, want default %q", got, want)
		}
	})
}

// TestApplyFlagOverridesIdentityStore verifies the flag plumbing: an explicit
// -identity-store (even with an empty value) marks the config explicit;
// an unset flag leaves both fields untouched so the default path applies.
func TestApplyFlagOverridesIdentityStore(t *testing.T) {
	t.Run("explicit empty value is surfaced for startup rejection", func(t *testing.T) {
		cfg := Defaults()
		flags := &GatewayFlags{IdentityStore: ""}
		cfg.ApplyFlagOverrides(flags, map[string]bool{"identity-store": true})
		if !cfg.IdentityStoreExplicit {
			t.Error("IdentityStoreExplicit not set for an explicit flag")
		}
		if cfg.IdentityStore != "" {
			t.Errorf("IdentityStore = %q, want empty", cfg.IdentityStore)
		}
		// The resolver still lands on the default; cmd rejects the
		// explicit-empty combination before consulting it.
		want := filepath.Join(filepath.Dir(cfg.VolRoot), DefaultIdentityStoreFilename)
		if got := cfg.EffectiveIdentityStorePath(); got != want {
			t.Errorf("EffectiveIdentityStorePath() = %q, want %q", got, want)
		}
	})

	t.Run("explicit path overrides default", func(t *testing.T) {
		cfg := Defaults()
		flags := &GatewayFlags{IdentityStore: "/tmp/identity.json"}
		cfg.ApplyFlagOverrides(flags, map[string]bool{"identity-store": true})
		if got := cfg.EffectiveIdentityStorePath(); got != "/tmp/identity.json" {
			t.Errorf("EffectiveIdentityStorePath() = %q, want /tmp/identity.json", got)
		}
	})

	t.Run("unset flag keeps default", func(t *testing.T) {
		cfg := Defaults()
		cfg.ApplyFlagOverrides(&GatewayFlags{}, map[string]bool{})
		if cfg.IdentityStoreExplicit {
			t.Error("IdentityStoreExplicit set without an explicit flag")
		}
		want := filepath.Join(filepath.Dir(cfg.VolRoot), DefaultIdentityStoreFilename)
		if got := cfg.EffectiveIdentityStorePath(); got != want {
			t.Errorf("EffectiveIdentityStorePath() = %q, want %q", got, want)
		}
	})
}
