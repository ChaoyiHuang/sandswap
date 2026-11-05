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
// Internal (package identity) tests for etcd store settings/options and the
// cache-routing helpers. These run without an etcd connection.

package identity

import (
	"testing"
	"time"
)

func TestNewEtcdSettingsDefaults(t *testing.T) {
	s := newEtcdSettings(nil)
	if s.tls != nil {
		t.Error("default tls should be nil (plaintext)")
	}
	if s.hotOnly {
		t.Error("default hotOnly should be false")
	}
	if !s.lazyLoad {
		t.Error("default lazyLoad should be true")
	}
	if s.loadPageSize != defaultLoadPageSize {
		t.Errorf("loadPageSize = %d, want %d", s.loadPageSize, defaultLoadPageSize)
	}
	if s.loadWorkers != defaultLoadWorkers {
		t.Errorf("loadWorkers = %d, want %d", s.loadWorkers, defaultLoadWorkers)
	}
	if s.fullLoadTimeout != defaultFullLoadTimeout {
		t.Errorf("fullLoadTimeout = %v, want %v", s.fullLoadTimeout, defaultFullLoadTimeout)
	}
}

func TestEtcdOptions(t *testing.T) {
	tlsCfg := &EtcdTLSConfig{CAFile: "/ca.pem"}
	s := newEtcdSettings([]EtcdOption{
		WithTLS(tlsCfg),
		WithHotOnly(true),
		WithLazyLoad(false),
		WithLoadPageSize(500),
		WithLoadWorkers(4),
		WithFullLoadTimeout(30 * time.Second),
	})
	if s.tls != tlsCfg {
		t.Error("WithTLS did not store the config")
	}
	if !s.hotOnly {
		t.Error("WithHotOnly(true) not applied")
	}
	if s.lazyLoad {
		t.Error("WithLazyLoad(false) not applied")
	}
	if s.loadPageSize != 500 || s.loadWorkers != 4 {
		t.Errorf("loader knobs = (%d, %d), want (500, 4)", s.loadPageSize, s.loadWorkers)
	}
	if s.fullLoadTimeout != 30*time.Second {
		t.Errorf("fullLoadTimeout = %v, want 30s", s.fullLoadTimeout)
	}

	// Invalid values must keep defaults.
	s2 := newEtcdSettings([]EtcdOption{
		WithLoadPageSize(0),
		WithLoadPageSize(-10),
		WithLoadWorkers(0),
		WithFullLoadTimeout(0),
		WithFullLoadTimeout(-time.Second),
	})
	if s2.loadPageSize != defaultLoadPageSize {
		t.Errorf("invalid page size applied: %d", s2.loadPageSize)
	}
	if s2.loadWorkers != defaultLoadWorkers {
		t.Errorf("invalid workers applied: %d", s2.loadWorkers)
	}
	if s2.fullLoadTimeout != defaultFullLoadTimeout {
		t.Errorf("invalid timeout applied: %v", s2.fullLoadTimeout)
	}
}

func TestApplyPutLockedRoutesByPrefix(t *testing.T) {
	s := newTestCacheStore()
	s.mu.Lock()
	defer s.mu.Unlock()

	agentData, _ := marshalAgentForEtcd(&Agent{ID: "agent-1", APIKeyHash: hashAPIKey("k")})
	recData, err := encodeSandfsRecord(&Record{ID: "sf-1", AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("encodeSandfsRecord: %v", err)
	}
	metaData, err := encodeSandfsMeta(&sandfsMetaInfo{Name: "n"})
	if err != nil {
		t.Fatalf("encodeSandfsMeta: %v", err)
	}

	s.applyPutLocked("/p/agent/xyz", agentData)
	s.applyPutLocked("/p/sandfs/sf-1", recData)
	s.applyPutLocked("/p/meta/sandfs/sf-1", metaData)

	if _, ok := s.agents["agent-1"]; !ok {
		t.Error("agent put not routed to agents map")
	}
	if _, ok := s.sandfs["sf-1"]; !ok {
		t.Error("sandfs put not routed to sandfs map")
	}
	// Meta routing: the watch REFRESHES resident cache entries and
	// never INSERTS non-resident ones — otherwise the bounded display cache
	// would grow back into a full meta mirror through the watch stream.
	if _, ok := s.sandfsMeta["sf-1"]; ok {
		t.Error("non-resident meta put must NOT enter the bounded cache")
	}
	s.sandfsMeta["sf-1"] = &sandfsMetaInfo{Name: "stale"}
	s.applyPutLocked("/p/meta/sandfs/sf-1", metaData)
	if m, ok := s.sandfsMeta["sf-1"]; !ok || m.Name != "n" {
		t.Error("resident meta entry not refreshed by the watch put")
	}

	// Corrupt payloads are ignored silently.
	s.applyPutLocked("/p/sandfs/bad", []byte("{not json"))
	s.applyPutLocked("/p/agent/bad", []byte("{not json"))
	s.applyPutLocked("/p/meta/sandfs/bad", []byte("{not json"))
	if _, ok := s.sandfs["bad"]; ok {
		t.Error("corrupt sandfs value was stored")
	}
	if _, ok := s.agentApiKeyToID[hashAPIKey("k")]; !ok {
		t.Error("corrupt agent put clobbered the digest index")
	}

	// Unknown prefixes are ignored.
	s.applyPutLocked("/p/other/k", []byte("{}"))
}

func TestApplyPutLockedHotOnlySkipsMeta(t *testing.T) {
	s := newTestCacheStore()
	s.hotOnly = true
	s.mu.Lock()
	defer s.mu.Unlock()

	metaData, _ := encodeSandfsMeta(&sandfsMetaInfo{Name: "n"})
	s.applyPutLocked("/p/meta/sandfs/sf-1", metaData)
	if len(s.sandfsMeta) != 0 {
		t.Error("hotOnly store must skip meta puts")
	}
	s.applyDeleteLocked("/p/meta/sandfs/sf-1")
}

func TestApplyDeleteLockedUnknownPrefixNoop(t *testing.T) {
	s := newTestCacheStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyDeleteLocked("/p/other/k")
	if len(s.agents)+len(s.sandfs)+len(s.sandfsMeta) != 0 {
		t.Error("unknown-prefix delete touched the cache")
	}
}

func TestAllowsPackageInstall(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"flat", true},
		{"overlay", false},
		{"", false},
		{"Flat", false},
	}
	for _, c := range cases {
		r := &Record{Mode: c.mode}
		if got := r.AllowsPackageInstall(); got != c.want {
			t.Errorf("AllowsPackageInstall(mode=%q) = %v, want %v", c.mode, got, c.want)
		}
	}
}
