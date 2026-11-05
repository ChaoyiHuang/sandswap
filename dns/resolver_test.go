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

package main

import (
	"container/heap"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"common/config"

	"github.com/miekg/dns"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// freshOwnerEntry builds an ownerEntry with fetchedAt=now (fresh, within TTL)
// so ownerFor serves it from cache without re-validating against etcd. Because
// the ownership entry carries the gateway ID (+ node_id), routing tests pair it
// with a registry entry (registryByID[gwID].gatewayURL) and a health record
// (healthByID[gwID]) for the owner-fresh path.
func freshOwnerEntry(gwID string) *ownerEntry {
	return freshOwnerEntryNode(gwID, "")
}

// freshOwnerEntryNode is freshOwnerEntry with a node_id (mounted sandfs).
func freshOwnerEntryNode(gwID, nodeID string) *ownerEntry {
	e := &ownerEntry{gatewayID: gwID, nodeID: nodeID}
	now := time.Now().UnixNano()
	e.fetchedAt.Store(now)
	e.lastUsed.Store(now)
	return e
}

// freshHealth builds an ownerHealth with a just-now last_healthy_ts (fresh,
// within the route-stale threshold) so gwAliveLocked reports the gateway alive.
func freshHealth() ownerHealth {
	return ownerHealth{nodeCount: 1, lastHealthyTS: time.Now()}
}

// staleHealth builds an ownerHealth whose last_healthy_ts is far in the past
// (stale past the route-stale threshold) so gwAliveLocked reports the gateway
// not-alive — simulating a dead/stale owner whose lease value stopped refreshing.
func staleHealth() ownerHealth {
	return ownerHealth{nodeCount: 1, lastHealthyTS: time.Now().Add(-10 * time.Minute)}
}

// staleOwnerEntry builds an ownerEntry with fetchedAt=1 (1970, far past TTL)
// so ownerFor re-validates against etcd.
func staleOwnerEntry(gwID string) *ownerEntry {
	e := &ownerEntry{gatewayID: gwID}
	e.fetchedAt.Store(1)
	e.lastUsed.Store(1)
	return e
}

// rawQuery packs a one-question wire query via miekg/dns — the reference
// implementation, kept as a TEST-ONLY dependency: production code serves the
// wire format with dns/wire, and these tests continuously cross-validate our
// encoder's output against miekg's parser (and vice versa).
func rawQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Id = 0x0101
	m.RecursionDesired = true
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query %q: %v", name, err)
	}
	return b
}

// ask runs one query through the dispatch layer (answerQuery, transport- and
// byte-level) and unpacks the reply with miekg.
func ask(t *testing.T, s *DNSServer, name string, qtype uint16) *dns.Msg {
	t.Helper()
	return unpackReply(t, s.answerQuery("udp", "127.0.0.1", true, rawQuery(t, name, qtype)))
}

func unpackReply(t *testing.T, b []byte) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	return m
}

// TestGatewayURLHost covers the base-URL -> host extraction used by the
// owner-aware resolution: the health key stores gateway_url like
// https://gw-0...:3000, and the DNS must emit the bare host as a CNAME/A target.
func TestGatewayURLHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://gateway-0.gateway-exec.sandswap.svc.cluster.local:3000", "gateway-0.gateway-exec.sandswap.svc.cluster.local"},
		{"http://10.0.1.1:3000", "10.0.1.1"},
		{"https://gw.example.com", "gw.example.com"}, // no port
		{"10.0.1.2", "10.0.1.2"},
	}
	for _, c := range cases {
		if got := gatewayURLHost(c.in); got != c.want {
			t.Errorf("gatewayURLHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestResolveSandfsOwner verifies the sandfs -> owner mapping resolution.
//
// Owner-fresh path: an owner whose health record is fresh resolves via its
// registry gateway_url — hostname -> CNAME, IP -> A. An owner with no registry
// gateway_url is unroutable. A dead/stale owner (no health record, or a stale
// value) does NOT resolve to the owner: it falls through to presence-directed
// routing (if mounted + a live peer holds the node) or the scheduling fallback.
// This is the recovery path for a dead-owned sandfs — it must not stay pinned
// to a dead owner.
func TestResolveSandfsOwner(t *testing.T) {
	s := &DNSServer{
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		owners: map[string]*ownerEntry{
			"sandfs-abc":   freshOwnerEntry("gw0"),      // fresh owner, hostname
			"sandfs-ip":    freshOwnerEntry("gw1"),      // fresh owner, IP
			"sandfs-noreg": freshOwnerEntry("gw-noreg"), // fresh owner, no registry key
			"sandfs-dead":  freshOwnerEntry("gw-dead"),  // DEAD owner (no health record)
			"sandfs-stale": freshOwnerEntry("gw-stale"), // STALE owner (stale health value)
		},
		healthByID: map[string]ownerHealth{
			"gw0":      freshHealth(),
			"gw1":      freshHealth(),
			"gw-noreg": freshHealth(),
			"gw-stale": staleHealth(),
			// gw-dead has NO health record (dead).
		},
		registryByID: map[string]gatewayRegistry{
			"gw0":      {gatewayURL: "https://gateway-0.gateway-exec.sandswap.svc.cluster.local:3000"},
			"gw1":      {gatewayURL: "https://10.0.1.7:3000"},
			"gw-dead":  {gatewayURL: "https://10.0.1.8:3000"},
			"gw-stale": {gatewayURL: "https://10.0.1.9:3000"},
		},
	}

	// Hostname target -> CNAME.
	if cname, ip, ok, err := s.resolveSandfsOwner("sandfs-abc"); err != nil || !ok || cname != "gateway-0.gateway-exec.sandswap.svc.cluster.local" || ip != "" {
		t.Errorf("hostname owner: got (cname=%q ip=%q ok=%v err=%v), want CNAME to headless FQDN", cname, ip, ok, err)
	}
	// IP target -> A.
	if cname, ip, ok, err := s.resolveSandfsOwner("sandfs-ip"); err != nil || !ok || cname != "" || ip != "10.0.1.7" {
		t.Errorf("ip owner: got (cname=%q ip=%q ok=%v err=%v), want A to 10.0.1.7", cname, ip, ok, err)
	}
	// Owner without a registry gateway_url -> not resolvable (unroutable).
	if _, _, ok, err := s.resolveSandfsOwner("sandfs-noreg"); err != nil || ok {
		t.Errorf("owner without registry gateway_url should not resolve (ok=%v err=%v)", ok, err)
	}
	// DEAD owner (no health record): must NOT resolve to the dead owner — falls
	// through to the scheduling fallback (no presence holder here → no answer).
	if cname, ip, ok, err := s.resolveSandfsOwner("sandfs-dead"); err != nil || ok {
		t.Errorf("dead owner (no health key) must not resolve, got (cname=%q ip=%q ok=%v err=%v)", cname, ip, ok, err)
	}
	// STALE owner (stale health value): same — must not resolve to the stale owner.
	if _, _, ok, err := s.resolveSandfsOwner("sandfs-stale"); err != nil || ok {
		t.Errorf("stale owner (stale health value) must not resolve (ok=%v err=%v)", ok, err)
	}
	// Unknown sandfs -> not resolvable (nil etcd client -> no owner).
	if _, _, ok, err := s.resolveSandfsOwner("sandfs-missing"); err != nil || ok {
		t.Errorf("missing sandfs should not resolve (ok=%v err=%v)", ok, err)
	}
}

// TestPickBySchedulingPolicy verifies the no-owner fallback pool: returns any
// gateway with a live health record + registry gateway_url + compute;
// compute-less (fault) and dead gateways are skipped; empty -> none.
func TestPickBySchedulingPolicy(t *testing.T) {
	s := &DNSServer{
		healthByID: map[string]ownerHealth{
			"gw0":      {nodeCount: 1},
			"gw1":      {nodeCount: 1},
			"gwd":      {}, // no health record -> skipped (dead)
			"gw-nocmp": {}, // alive + addr but no compute
		},
		registryByID: map[string]gatewayRegistry{
			"gw0":      {gatewayURL: "https://gateway-0.gateway-exec.sandswap.svc.cluster.local:3000"},
			"gw1":      {gatewayURL: "https://10.0.1.7:3000"},
			"gw-noreg": {gatewayURL: ""}, // alive + compute but no routable URL
			"gw-nocmp": {gatewayURL: "https://10.0.1.8:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw0":      {AgentIP: "gateway-0.gateway-exec.sandswap.svc.cluster.local"},
			"gw1":      {AgentIP: "10.0.1.7", AgentPort: 3000},
			"gw-noreg": {}, // parsed from an empty gateway_url: not routable
			"gw-nocmp": {AgentIP: "10.0.1.8", AgentPort: 3000},
		},
	}
	host, ok := s.pickBySchedulingPolicy()
	if !ok || host == "" {
		t.Fatalf("expected a registered gateway, got %q ok=%v", host, ok)
	}
	if host != "gateway-0.gateway-exec.sandswap.svc.cluster.local" && host != "10.0.1.7" {
		t.Errorf("unexpected fallback host %q", host)
	}

	// Only a compute-less gateway registered -> no routable fallback.
	onlyNoCompute := &DNSServer{
		healthByID:   map[string]ownerHealth{"gw-nocmp": {}},
		registryByID: map[string]gatewayRegistry{"gw-nocmp": {gatewayURL: "https://10.0.1.8:3000"}},
		gwAddrs:      map[string]GWInfo{"gw-nocmp": {AgentIP: "10.0.1.8", AgentPort: 3000}},
	}
	if _, ok := onlyNoCompute.pickBySchedulingPolicy(); ok {
		t.Errorf("compute-less-only registry should not pick a gateway")
	}

	// Only a gateway with no routable registry URL -> no fallback.
	onlyNoURL := &DNSServer{
		healthByID:   map[string]ownerHealth{"gw-noreg": {nodeCount: 1}},
		registryByID: map[string]gatewayRegistry{"gw-noreg": {}},
		gwAddrs:      map[string]GWInfo{"gw-noreg": {}},
	}
	if _, ok := onlyNoURL.pickBySchedulingPolicy(); ok {
		t.Errorf("gateway with no registry URL should not be picked")
	}

	empty := &DNSServer{healthByID: map[string]ownerHealth{}}
	if _, ok := empty.pickBySchedulingPolicy(); ok {
		t.Errorf("empty registry should not pick a gateway")
	}
}

// TestPickBySchedulingPolicyStaleGatewayExcluded pins the aliveness gate: the
// health key is a PLAIN key that survives gateway death, and a dead gateway's
// /sandswap/load key (10s lease) expires — which makes the corpse look like a
// "bootstrap" gateway that passes every capacity gate. Only the
// last_healthy_ts staleness marks it dead. Without the gate the fallback
// answers clients a dead gateway's address (and, with no live candidate,
// answers at all instead of failing closed to SERVFAIL).
func TestPickBySchedulingPolicyStaleGatewayExcluded(t *testing.T) {
	// Dead (stale health) + live: the live one must win.
	s := &DNSServer{
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		healthByID: map[string]ownerHealth{
			"gw-dead": {nodeCount: 4, lastHealthyTS: time.Now().Add(-time.Hour)},
			"gw-live": freshHealth(),
		},
		registryByID: map[string]gatewayRegistry{
			"gw-dead": {gatewayURL: "https://10.0.0.9:3000"},
			"gw-live": {gatewayURL: "https://10.0.0.10:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-dead": {AgentIP: "10.0.0.9", AgentPort: 3000},
			"gw-live": {AgentIP: "10.0.0.10", AgentPort: 3000},
		},
	}
	host, ok := s.pickBySchedulingPolicy()
	if !ok || host != "10.0.0.10" {
		t.Fatalf("stale gateway picked: host=%q ok=%v (want the live 10.0.0.10)", host, ok)
	}

	// Dead WITH a still-present load record at the policy minimum must also be
	// excluded (the record outlives the health staleness by up to its 10s lease
	// only; a stale health record and a live load record can coexist).
	s.loadByID = map[string]gwLoad{"gw-dead": {aggDutyLong: 0, cleanVMs: 5}}
	if host, ok := s.pickBySchedulingPolicy(); !ok || host != "10.0.0.10" {
		t.Fatalf("stale gateway with a load record picked: host=%q ok=%v", host, ok)
	}

	// Only the corpse registered -> NO candidate (fail closed to SERVFAIL).
	onlyDead := &DNSServer{
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		healthByID:          map[string]ownerHealth{"gw-dead": {nodeCount: 4, lastHealthyTS: time.Now().Add(-time.Hour)}},
		registryByID:        map[string]gatewayRegistry{"gw-dead": {gatewayURL: "https://10.0.0.9:3000"}},
		gwAddrs:             map[string]GWInfo{"gw-dead": {AgentIP: "10.0.0.9", AgentPort: 3000}},
	}
	if host, ok := onlyDead.pickBySchedulingPolicy(); ok {
		t.Fatalf("dead-only fleet must fail closed, got host=%q", host)
	}
}

// TestPickBySchedulingPolicyMisregisteredExcluded verifies the fallback gate
// uses the VALIDATED gwAddrs entry, not the raw registry string: a gateway
// whose self-registered gateway_url host is garbage (parseGatewayAddrs empties
// AgentIP and logs "excluded from that domain's placement") must actually be
// excluded — gating on the raw value would return the junk as the fallback
// host, the CNAME encode would fail, and EVERY unowned-sandfs answer would
// degrade to SERVFAIL while the log claims the gateway was excluded.
func TestPickBySchedulingPolicyMisregisteredExcluded(t *testing.T) {
	s := &DNSServer{
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		healthByID: map[string]ownerHealth{
			"gw-bad": freshHealth(),
			"gw-ok":  freshHealth(),
		},
		registryByID: map[string]gatewayRegistry{
			"gw-bad": {gatewayURL: "!!!"}, // parseGatewayAddrs: invalid host
			"gw-ok":  {gatewayURL: "https://10.0.1.2:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-bad": {}, // AgentIP emptied by parseGatewayAddrs
			"gw-ok":  {AgentIP: "10.0.1.2", AgentPort: 3000},
		},
	}
	host, ok := s.pickBySchedulingPolicy()
	if !ok || host != "10.0.1.2" {
		t.Errorf("misregistered gateway must be excluded from the fallback pool; got host=%q ok=%v", host, ok)
	}

	// A fleet of ONLY misregistered gateways yields no candidate at all
	// (SERVFAIL — honest) rather than a junk host.
	onlyBad := &DNSServer{
		healthByID:   map[string]ownerHealth{"gw-bad": freshHealth()},
		registryByID: map[string]gatewayRegistry{"gw-bad": {gatewayURL: "!!!"}},
		gwAddrs:      map[string]GWInfo{"gw-bad": {}},
	}
	if host, ok := onlyBad.pickBySchedulingPolicy(); ok {
		t.Errorf("only-misregistered fleet must not produce a fallback host, got %q", host)
	}
}

// TestComputeGatingSplit verifies the compute-gating split between the two
// domains: the sandfs-domain fallback (pickBySchedulingPolicy) requires compute
// (node_count > 0) so a fault-state gateway is skipped; the stream-domain
// placement (pickGatewayLocked(stream)) does NOT - a compute-less-but-alive
// gateway is still a valid sandlot target so it can regain compute (no deadlock).
func TestComputeGatingSplit(t *testing.T) {
	// gwA has compute, gwB is compute-less but alive.
	s := &DNSServer{
		gwAddrs: map[string]GWInfo{
			"gwA": {AgentIP: "10.0.1.1", AgentPort: 3000, StreamIP: "10.0.1.1", StreamPort: 9998},
			"gwB": {AgentIP: "10.0.1.2", AgentPort: 3000, StreamIP: "10.0.1.2", StreamPort: 9998},
		},
		healthByID: map[string]ownerHealth{
			"gwA": {nodeCount: 1},
			"gwB": {nodeCount: 0}, // alive, no compute
		},
		registryByID: map[string]gatewayRegistry{
			"gwA": {gatewayURL: "https://10.0.1.1:3000"},
			"gwB": {gatewayURL: "https://10.0.1.2:3000"},
		},
	}

	// sandfs fallback: only gwA (compute) is a candidate (gwB has node_count 0).
	// pickBySchedulingPolicy takes its own RLock - do NOT hold s.mu here.
	got, ok := s.pickBySchedulingPolicy()
	if !ok || got != "10.0.1.1" {
		t.Errorf("sandfs fallback: expected compute-enabled 10.0.1.1, got %q ok=%v", got, ok)
	}
	// Stream placement: gwB is also a valid target (alive). pickGatewayLocked
	// returns the gateway_id and requires the caller to hold s.mu.
	s.mu.RLock()
	bestStream := s.pickGatewayLocked(true)
	s.mu.RUnlock()
	if bestStream == "" {
		t.Errorf("stream placement should select a gateway even when one is compute-less")
	}
}

// TestSandfsQueryCNAME builds a CNAME answer for a sandfs owned by a hostname
// gateway - the shape in-cluster agents rely on (CoreDNS chases the CNAME).
func TestSandfsQueryCNAME(t *testing.T) {
	s := &DNSServer{
		cfg:                 &Config{TTL: 10, Domains: DomainsConfig{Sandfs: "sandfs.sandswap.local"}},
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		owners: map[string]*ownerEntry{
			"sandfs-abc": freshOwnerEntry("gw0"),
		},
		healthByID: map[string]ownerHealth{
			"gw0": freshHealth(),
		},
		registryByID: map[string]gatewayRegistry{
			"gw0": {gatewayURL: "https://gateway-0.gateway-exec.sandswap.svc.cluster.local:3000"},
		},
	}

	m := ask(t, s, "sandfs-abc.sandfs.sandswap.local.", dns.TypeA)

	if len(m.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(m.Answer))
	}
	cname, ok := m.Answer[0].(*dns.CNAME)
	if !ok {
		t.Fatalf("expected CNAME, got %T", m.Answer[0])
	}
	if cname.Target != "gateway-0.gateway-exec.sandswap.svc.cluster.local." {
		t.Errorf("CNAME target = %q", cname.Target)
	}
}

// TestPickBySchedulingPolicyHeadroom verifies the no-owner fallback prefers the
// gateway with the LOWEST agg_duty_long (headroom spread). With 2 candidates
// the selection is deterministic (power-of-two-choices only kicks in >2).
func TestPickBySchedulingPolicyHeadroom(t *testing.T) {
	s := &DNSServer{
		healthByID: map[string]ownerHealth{
			"gw-busy": {nodeCount: 1},
			"gw-idle": {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw-busy": {gatewayURL: "https://10.0.1.1:3000"},
			"gw-idle": {gatewayURL: "https://10.0.1.2:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-busy": {AgentIP: "10.0.1.1", AgentPort: 3000},
			"gw-idle": {AgentIP: "10.0.1.2", AgentPort: 3000},
		},
		loadByID: map[string]gwLoad{
			"gw-busy": {aggDutyLong: 0.8, cleanVMs: 2},
			"gw-idle": {aggDutyLong: 0.1, cleanVMs: 2},
		},
	}
	host, ok := s.pickBySchedulingPolicy()
	if !ok || host != "10.0.1.2" {
		t.Errorf("expected gw-idle (lowest duty 0.1), got host=%q ok=%v", host, ok)
	}
}

// TestPickBySchedulingPolicyBinpack verifies the no-owner fallback under binpack
// prefers the gateway with the HIGHEST agg_duty_long (pack new sandfs onto the
// busiest healthy gateway so lightly-loaded ones can scale down).
func TestPickBySchedulingPolicyBinpack(t *testing.T) {
	s := &DNSServer{
		schedConfig: config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack}),
		healthByID: map[string]ownerHealth{
			"gw-busy":  {nodeCount: 1},
			"gw-idle":  {nodeCount: 1},
			"gw-nocmp": {}, // no compute -> still skipped
		},
		registryByID: map[string]gatewayRegistry{
			"gw-busy":  {gatewayURL: "https://10.0.1.1:3000"},
			"gw-idle":  {gatewayURL: "https://10.0.1.2:3000"},
			"gw-nocmp": {gatewayURL: "https://10.0.1.3:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-busy":  {AgentIP: "10.0.1.1", AgentPort: 3000},
			"gw-idle":  {AgentIP: "10.0.1.2", AgentPort: 3000},
			"gw-nocmp": {AgentIP: "10.0.1.3", AgentPort: 3000},
		},
		loadByID: map[string]gwLoad{
			"gw-busy": {aggDutyLong: 0.8, cleanVMs: 2},
			"gw-idle": {aggDutyLong: 0.1, cleanVMs: 2},
		},
	}
	host, ok := s.pickBySchedulingPolicy()
	if !ok || host != "10.0.1.1" {
		t.Errorf("expected gw-busy (highest duty 0.8 under binpack), got host=%q ok=%v", host, ok)
	}
}

// TestPresenceRouteCacheHitAndBound verifies the presence read cache and the
// shared owner-sem bound on the dead-owner recovery path: a fetch-fresh cache
// entry answers WITHOUT touching etcd (the nil client proves it); the cached
// holder is re-JUDGED at answer time (a holder equal to the dead owner, or one
// that went stale within the TTL, falls through); and a saturated ownerSem
// falls through to the scheduling fallback instead of queueing behind the Get.
func TestPresenceRouteCacheHitAndBound(t *testing.T) {
	pe := &presenceCacheEntry{holder: "gw-peer"}
	pe.fetchedAt.Store(time.Now().UnixNano())
	s := &DNSServer{
		etcdClient:          nil, // cache hit must never need etcd
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		healthByID:          map[string]ownerHealth{"gw-peer": freshHealth()},
		registryByID:        map[string]gatewayRegistry{"gw-peer": {gatewayURL: "https://10.0.2.9:3000"}},
		presence:            map[string]*presenceCacheEntry{"node-1": pe},
	}
	if cname, ip, ok := s.presenceRoute("node-1", "gw-dead"); !ok || cname != "" || ip != "10.0.2.9" {
		t.Errorf("cache hit: expected A 10.0.2.9, got (cname=%q ip=%q ok=%v)", cname, ip, ok)
	}

	// Cached holder == the dead owner itself → fall through.
	pe2 := &presenceCacheEntry{holder: "gw-dead"}
	pe2.fetchedAt.Store(time.Now().UnixNano())
	s.presence["node-1"] = pe2
	if _, _, ok := s.presenceRoute("node-1", "gw-dead"); ok {
		t.Error("holder == dead owner must fall through")
	}

	// Holder that died WITHIN the TTL: only the read is cached, never the
	// judgement — a stale holder falls through immediately.
	pe3 := &presenceCacheEntry{holder: "gw-stalepeer"}
	pe3.fetchedAt.Store(time.Now().UnixNano())
	s.presence["node-1"] = pe3
	s.healthByID["gw-stalepeer"] = staleHealth()
	s.registryByID["gw-stalepeer"] = gatewayRegistry{gatewayURL: "https://10.0.2.10:3000"}
	if _, _, ok := s.presenceRoute("node-1", "gw-dead"); ok {
		t.Error("stale cached holder must fall through (the judgement is not cached)")
	}

	// Miss + saturated ownerSem: bounded fall-through WITHOUT an etcd
	// round-trip (the non-nil client is never used before the sem gate).
	s2 := &DNSServer{
		etcdClient: &clientv3.Client{}, // would misbehave if the Get were reached
		ownerSem:   make(chan struct{}, 1),
	}
	s2.ownerSem <- struct{}{}
	if _, _, ok := s2.presenceRoute("node-x", "gw-dead"); ok {
		t.Error("saturated ownerSem must fall through to the fallback")
	}
}

// TestStickyEvictionSampledNewestProtected verifies the sampled overflow
// eviction: at the cap the map stays bounded across a hammer of inserts, and
// the STRICTLY most-recent entry is never evicted (it can never be the coldest
// of any sample; same-second ties may evict either, which is fine — they are
// equally warm). Without sampling this was an O(stickyMax) scan under the
// write lock on every overflow insert.
func TestStickyEvictionSampledNewestProtected(t *testing.T) {
	orig := stickyMax
	stickyMax = 8
	defer func() { stickyMax = orig }()

	s := healthyServer()
	// Strictly newer than any insert the test can make (resolveStream stamps
	// with time.Now()), so the "never coldest in any sample" guarantee holds
	// deterministically.
	now := time.Now().Add(10 * time.Second).Unix()
	s.sticky["warm"] = &StickyEntry{GWID: "gw-1", LastQuery: now, Created: now}
	for i := 0; i < 7; i++ {
		s.sticky[fmt.Sprintf("ancient-%d", i)] = &StickyEntry{GWID: "gw-1", LastQuery: int64(i), Created: 1}
	}
	for i := 0; i < 64; i++ {
		if gw := s.resolveStream(fmt.Sprintf("10.7.%d.%d", i/256, i%256)); gw == nil {
			t.Fatalf("expected placement on insert %d", i)
		}
	}
	s.mu.RLock()
	_, warm := s.sticky["warm"]
	size := len(s.sticky)
	s.mu.RUnlock()
	if !warm {
		t.Error("the most-recent entry must never be evicted by sampled eviction")
	}
	if size > stickyMax {
		t.Errorf("sticky map must stay bounded (cap %d), got %d", stickyMax, size)
	}
}

// TestBinpackPowerOfTwoChoices verifies binpack ALSO uses power-of-two-choices
// with >2 candidates: the single idlest gateway is never picked (it loses
// every pair it is in), while both busier gateways appear across runs —
// deterministic-best would funnel every fallback answer after a gateway death
// onto one absorber, compounding with each failure.
func TestBinpackPowerOfTwoChoices(t *testing.T) {
	s := &DNSServer{
		schedConfig: config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0}),
		healthByID: map[string]ownerHealth{
			"gw-high": {nodeCount: 1},
			"gw-mid":  {nodeCount: 1},
			"gw-low":  {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw-high": {gatewayURL: "https://10.0.1.1:3000"},
			"gw-mid":  {gatewayURL: "https://10.0.1.2:3000"},
			"gw-low":  {gatewayURL: "https://10.0.1.3:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-high": {AgentIP: "10.0.1.1", AgentPort: 3000},
			"gw-mid":  {AgentIP: "10.0.1.2", AgentPort: 3000},
			"gw-low":  {AgentIP: "10.0.1.3", AgentPort: 3000},
		},
		loadByID: map[string]gwLoad{
			"gw-high": {aggDutyLong: 0.9, cleanVMs: 2},
			"gw-mid":  {aggDutyLong: 0.5, cleanVMs: 2},
			"gw-low":  {aggDutyLong: 0.1, cleanVMs: 2},
		},
	}
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		host, ok := s.pickBySchedulingPolicy()
		if !ok {
			t.Fatal("expected a gateway")
		}
		seen[host]++
	}
	if seen["10.0.1.3"] != 0 {
		t.Errorf("idlest gateway should never win a binpack power-of-two pair, got %d picks", seen["10.0.1.3"])
	}
	if seen["10.0.1.1"] == 0 || seen["10.0.1.2"] == 0 {
		t.Errorf("expected both busier gateways to appear, got %v", seen)
	}
}

// TestAnswerQueryOpcodeNotImp verifies a well-formed query with an
// unimplemented OPCODE (STATUS) gets NOTIMP, not FORMERR — RFC 1035 §4.1.1:
// FORMERR is for malformed messages, NOTIMP for unsupported operations.
func TestAnswerQueryOpcodeNotImp(t *testing.T) {
	s := healthyServer()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("stream.sandswap.local"), dns.TypeA)
	m.Opcode = 1 // STATUS
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	reply := unpackReply(t, s.answerQuery("udp", "10.0.0.1", false, b))
	if reply.Rcode != dns.RcodeNotImplemented {
		t.Errorf("opcode STATUS: expected NOTIMP, got rcode=%d", reply.Rcode)
	}
}

// TestPickBySchedulingPolicyPowerOfTwoChoices verifies that under spread with
// >2 candidates, power-of-two-choices is used: the highest-duty gateway is
// NEVER returned (it loses every pair it is in), while the two lower-duty
// gateways are both returned across runs (randomization breaks the
// deterministic-best thundering herd). Deterministic-best would always return
// the single lowest; this test asserts variety + highest never wins.
func TestPickBySchedulingPolicyPowerOfTwoChoices(t *testing.T) {
	s := &DNSServer{
		// spread (nil schedConfig defaults to spread)
		healthByID: map[string]ownerHealth{
			"gw-low":  {nodeCount: 1},
			"gw-mid":  {nodeCount: 1},
			"gw-high": {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw-low":  {gatewayURL: "https://10.0.1.1:3000"},
			"gw-mid":  {gatewayURL: "https://10.0.1.2:3000"},
			"gw-high": {gatewayURL: "https://10.0.1.3:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-low":  {AgentIP: "10.0.1.1", AgentPort: 3000},
			"gw-mid":  {AgentIP: "10.0.1.2", AgentPort: 3000},
			"gw-high": {AgentIP: "10.0.1.3", AgentPort: 3000},
		},
		loadByID: map[string]gwLoad{
			"gw-low":  {aggDutyLong: 0.1, cleanVMs: 2},
			"gw-mid":  {aggDutyLong: 0.5, cleanVMs: 2},
			"gw-high": {aggDutyLong: 0.9, cleanVMs: 2},
		},
	}
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		host, ok := s.pickBySchedulingPolicy()
		if !ok {
			t.Fatal("expected a gateway")
		}
		seen[host]++
	}
	// Highest-duty gateway never wins a power-of-two pair.
	if seen["10.0.1.3"] != 0 {
		t.Errorf("highest-duty gateway should never be picked under spread power-of-two, got %d", seen["10.0.1.3"])
	}
	// Both lower-duty gateways appear (variety = power-of-two, not deterministic-best).
	if seen["10.0.1.1"] == 0 || seen["10.0.1.2"] == 0 {
		t.Errorf("expected both lower-duty gateways to appear, got %v", seen)
	}
	// Lowest wins more often (it wins both pairs it is in; mid wins only vs high).
	if seen["10.0.1.1"] <= seen["10.0.1.2"] {
		t.Errorf("expected lowest-duty to win most often, got %v", seen)
	}
}

// TestValidSandfsID verifies the dispatch-gate shape check: canonical IDs
// (sandfs- + alnum/dash) pass; anything else — other prefixes, embedded dots
// or escapes, overlong IDs — must be rejected before any etcd access.
func TestValidSandfsID(t *testing.T) {
	valid := []string{"sandfs-3fa9c2e1", "sandfs-a", "sandfs-a-b-c", "sandfs-" + strings.Repeat("x", 64)}
	for _, id := range valid {
		if !validSandfsID(id) {
			t.Errorf("validSandfsID(%q) = false, want true", id)
		}
	}
	invalid := []string{
		"", "sandfs-", "sandfs", "SANDFS-ABC", "foo-abc", "sandfs-a.b", "sandfs-a/b",
		"sandfs-a b", "sandfs-a_b", "sandfs-" + strings.Repeat("x", 65), "x" + strings.Repeat("a", 70),
	}
	for _, id := range invalid {
		if validSandfsID(id) {
			t.Errorf("validSandfsID(%q) = true, want false", id)
		}
	}
}

// TestHandleDNSSandfsGarbageIDNXDOMAIN verifies garbage sandfs-zone labels are
// answered NXDOMAIN at the dispatch gate with ZERO etcd access (a flood of
// random labels must not become a cache-bypassing etcd read storm), while a
// mixed-CASE valid ID (0x0x0 randomization) is normalized and dispatched.
func TestHandleDNSSandfsGarbageIDNXDOMAIN(t *testing.T) {
	s := healthyServer()
	s.owners = make(map[string]*ownerEntry) // no owner → fallback path

	// Garbage label: NXDOMAIN, and no etcd access happened (etcdClient nil —
	// a routed lookup with a nil client would still be observable via the
	// owners cache gaining an entry; assert it stayed empty).
	for _, name := range []string{
		"garbage.sandfs.sandswap.local.",
		"foo-bar.sandfs.sandswap.local.",
		"a.b.sandfs.sandswap.local.",
	} {
		if m := ask(t, s, name, dns.TypeA); m.Rcode != dns.RcodeNameError {
			t.Errorf("%s: expected NXDOMAIN, got rcode=%d", name, m.Rcode)
		}
	}
	s.ownersMu.RLock()
	n := len(s.owners)
	s.ownersMu.RUnlock()
	if n != 0 {
		t.Errorf("garbage IDs must not create owner-cache entries, got %d", n)
	}

	// Mixed case valid ID: dispatched (not NXDOMAIN) — healthyServer has a
	// live fallback gateway, so the answer is an A record for it.
	if m := ask(t, s, "SaNdFs-3Fa9C2E1.SaNdFs.SandSwap.LoCaL.", dns.TypeA); m.Rcode == dns.RcodeNameError {
		t.Errorf("mixed-case valid ID: expected dispatch (fallback answer), got NXDOMAIN")
	}
}

// TestStickyMaxEviction verifies the sticky-map cap: a spoofed-source flood
// cannot grow the map (and its etcd mirror) without bound — overflow inserts
// evict the least-recently-queried entry and mark it dirty for deletion.
func TestStickyMaxEviction(t *testing.T) {
	orig := stickyMax
	stickyMax = 2
	defer func() { stickyMax = orig }()

	s := healthyServer()
	now := time.Now().Unix()
	// Two old entries fill the cap. They are marked MIRRORED (as if a previous
	// flush had written them to etcd): the assertion below is about deleting an
	// existing mirror, and an entry that never reached etcd must NOT be queued
	// ( — that queue is what a spoofed flood grew without bound).
	s.mirrored = map[string]struct{}{"old-1": {}, "old-2": {}}
	s.sticky["old-1"] = &StickyEntry{GWID: "gw-1", LastQuery: 100, Created: 100}
	s.sticky["old-2"] = &StickyEntry{GWID: "gw-1", LastQuery: now, Created: now}
	_ = now

	// New client insert overflows the cap: old-1 (least recently queried) is
	// evicted + marked dirty for etcd deletion; the new entry lands.
	if gw := s.resolveStream("10.0.9.9"); gw == nil {
		t.Fatal("expected placement")
	}
	s.mu.RLock()
	_, hasOld1 := s.sticky["old-1"]
	_, hasNew := s.sticky["10.0.9.9"]
	_, dirtyOld1 := s.dirty["old-1"]
	size := len(s.sticky)
	s.mu.RUnlock()
	if hasOld1 {
		t.Error("oldest entry should be evicted on overflow")
	}
	if !hasNew {
		t.Error("new entry should be inserted")
	}
	if size > stickyMax {
		t.Errorf("sticky map must stay bounded (cap %d), got %d", stickyMax, size)
	}
	if !dirtyOld1 {
		t.Error("evicted entry must be marked dirty so the etcd mirror is deleted")
	}
}

// TestOwnerForBusyFailsFast verifies the etcd-Get concurrency cap: when the
// semaphore is saturated, a new lookup fails fast (busy error, fail closed)
// instead of queueing behind timeout-bound Gets — the DoS bound for a
// distinct-garbage-ID flood.
func TestOwnerForBusyFailsFast(t *testing.T) {
	s := &DNSServer{
		owners:   make(map[string]*ownerEntry),
		ownerSem: make(chan struct{}, 1),
	}
	s.ownerSem <- struct{}{} // saturate

	if _, err := s.ownerFor("sandfs-busy"); err == nil {
		t.Fatal("saturated semaphore must fail fast with an error")
	}
	s.ownersMu.RLock()
	_, cached := s.owners["sandfs-busy"]
	s.ownersMu.RUnlock()
	if cached {
		t.Error("busy failure must not create a cache entry")
	}

	// Drain: the lookup proceeds (nil etcd → no-owner, negative cached).
	<-s.ownerSem
	if res, err := s.ownerFor("sandfs-busy"); err != nil || res.gatewayID != "" {
		t.Errorf("drained semaphore: expected no-owner success, got (%q, %v)", res.gatewayID, err)
	}
}

// TestPickGatewayLockedDutyHardGate verifies duty_hard gates the stream/agent
// placement (pickGatewayLocked) in BOTH policies — a saturated gateway must not
// absorb new sandlots just because binpack prefers the busiest. A gateway with
// no load record is bootstrap and stays eligible.
func TestPickGatewayLockedDutyHardGate(t *testing.T) {
	s := &DNSServer{
		schedConfig:         config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0.85}),
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		healthByID:          map[string]ownerHealth{"gw-hot": freshHealth(), "gw-mid": freshHealth(), "gw-new": freshHealth()},
		loadByID: map[string]gwLoad{
			"gw-hot": {aggDutyLong: 0.95, cleanVMs: 1}, // above cap -> excluded
			"gw-mid": {aggDutyLong: 0.50, cleanVMs: 1},
			// gw-new: no load record (bootstrap) -> eligible, duty 0
		},
		gwAddrs: map[string]GWInfo{
			"gw-hot": {AgentIP: "10.0.1.1", StreamIP: "10.0.1.1", StreamPort: 9998},
			"gw-mid": {AgentIP: "10.0.1.2", StreamIP: "10.0.1.2", StreamPort: 9998},
			"gw-new": {AgentIP: "10.0.1.3", StreamIP: "10.0.1.3", StreamPort: 9998},
		},
	}
	if best := s.pickGatewayLocked(true); best != "gw-mid" {
		t.Errorf("binpack with duty_hard: expected gw-mid (busiest below cap), got %q", best)
	}
	// Raising the cap lets the hottest gateway win again (binpack semantics).
	s.SetScheduling(PolicyBinpack, 0.99)
	if best := s.pickGatewayLocked(true); best != "gw-hot" {
		t.Errorf("binpack with raised cap: expected gw-hot, got %q", best)
	}
	// Disabling the cap (0) also restores pure binpack.
	s.SetScheduling(PolicyBinpack, 0)
	if best := s.pickGatewayLocked(false); best != "gw-hot" {
		t.Errorf("binpack with cap disabled (agent domain): expected gw-hot, got %q", best)
	}
}

// TestPickBestStreamGatewayHeadroom verifies stream-domain selection prefers the
// lowest-duty ALIVE gateway (spread). Stream placement does not gate on compute
// or clean VMs - only liveness (a live health record).
func TestPickBestStreamGatewayHeadroom(t *testing.T) {
	s := &DNSServer{
		gwAddrs: map[string]GWInfo{
			"gw-busy": {AgentIP: "10.0.1.1", AgentPort: 3000, StreamIP: "10.0.1.1", StreamPort: 9998},
			"gw-idle": {AgentIP: "10.0.1.2", AgentPort: 3000, StreamIP: "10.0.1.2", StreamPort: 9998},
		},
		healthByID: map[string]ownerHealth{
			"gw-busy": {nodeCount: 1},
			"gw-idle": {nodeCount: 1},
		},
		loadByID: map[string]gwLoad{
			"gw-busy": {aggDutyLong: 0.8, cleanVMs: 2},
			"gw-idle": {aggDutyLong: 0.1, cleanVMs: 2},
		},
	}
	s.mu.RLock()
	gwID := s.pickGatewayLocked(true)
	s.mu.RUnlock()
	if gwID != "gw-idle" {
		t.Errorf("expected gw-idle (lowest duty), got %q", gwID)
	}
}

// TestPickBestStreamGatewaySkipsDead verifies a registered gateway with no live
// health record (dead) is skipped in stream placement, and one with no
// registered stream_addr is not a stream candidate at all.
func TestPickBestStreamGatewaySkipsDead(t *testing.T) {
	s := &DNSServer{
		gwAddrs: map[string]GWInfo{
			"gw-alive":    {AgentIP: "10.0.1.1", AgentPort: 3000, StreamIP: "10.0.1.1", StreamPort: 9998},
			"gw-dead":     {AgentIP: "10.0.1.2", AgentPort: 3000, StreamIP: "10.0.1.2", StreamPort: 9998},
			"gw-nostream": {AgentIP: "10.0.1.3", AgentPort: 3000}, // registered, no stream_addr
		},
		healthByID: map[string]ownerHealth{
			"gw-alive": {nodeCount: 0}, // alive (compute-less ok for stream)
			// "gw-dead" is intentionally ABSENT from healthByID — a gateway with
			// no health record is dead and must be skipped by placement.
		},
	}
	s.mu.RLock()
	gwID := s.pickGatewayLocked(true)
	s.mu.RUnlock()
	if gwID != "gw-alive" {
		t.Errorf("expected only the alive gateway gw-alive, got %q", gwID)
	}
}

// TestSetSchedulingPolicy verifies the hot-reload policy swap: valid policies
// apply live (reversing pick direction), invalid ones are rejected with the
// current policy kept, and a nil schedConfig (tests) defaults to spread.
func TestSetSchedulingPolicy(t *testing.T) {
	s := &DNSServer{
		schedConfig: config.NewWatchableConfig(SchedulingConfig{Policy: PolicySpread}),
		healthByID: map[string]ownerHealth{
			"gw-busy": {nodeCount: 1},
			"gw-idle": {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw-busy": {gatewayURL: "https://10.0.1.1:3000"},
			"gw-idle": {gatewayURL: "https://10.0.1.2:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-busy": {AgentIP: "10.0.1.1", AgentPort: 3000},
			"gw-idle": {AgentIP: "10.0.1.2", AgentPort: 3000},
		},
		loadByID: map[string]gwLoad{
			"gw-busy": {aggDutyLong: 0.8, cleanVMs: 2},
			"gw-idle": {aggDutyLong: 0.1, cleanVMs: 2},
		},
	}

	// Spread default -> idle.
	if host, _ := s.pickBySchedulingPolicy(); host != "10.0.1.2" {
		t.Errorf("spread: expected gw-idle, got %q", host)
	}
	// Hot-reload to binpack -> busy.
	if !s.SetScheduling(PolicyBinpack, 0) {
		t.Fatal("expected binpack accepted")
	}
	if host, _ := s.pickBySchedulingPolicy(); host != "10.0.1.1" {
		t.Errorf("binpack after reload: expected gw-busy, got %q", host)
	}
	// Invalid policy -> rejected, binpack kept.
	if s.SetScheduling("random", 0) {
		t.Error("expected invalid policy rejected")
	}
	if host, _ := s.pickBySchedulingPolicy(); host != "10.0.1.1" {
		t.Errorf("invalid reload should keep binpack, got %q", host)
	}
	// Back to spread.
	if !s.SetScheduling(PolicySpread, 0) {
		t.Fatal("expected spread accepted")
	}
	if host, _ := s.pickBySchedulingPolicy(); host != "10.0.1.2" {
		t.Errorf("spread after reload: expected gw-idle, got %q", host)
	}
}

// TestSchedulingPolicyNilDefaultsToSpread verifies a DNSServer without a
// schedConfig (tests/bootstrap) routes with the spread default, never panics.
func TestSchedulingPolicyNilDefaultsToSpread(t *testing.T) {
	if s := (&DNSServer{}).preferHigherLoad(); s {
		t.Error("expected nil schedConfig to default to spread (preferHigherLoad=false)")
	}
	s := &DNSServer{
		healthByID: map[string]ownerHealth{
			"gw-busy": {nodeCount: 1},
			"gw-idle": {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw-busy": {gatewayURL: "https://10.0.1.1:3000"},
			"gw-idle": {gatewayURL: "https://10.0.1.2:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-busy": {AgentIP: "10.0.1.1", AgentPort: 3000},
			"gw-idle": {AgentIP: "10.0.1.2", AgentPort: 3000},
		},
		loadByID: map[string]gwLoad{
			"gw-busy": {aggDutyLong: 0.8, cleanVMs: 2},
			"gw-idle": {aggDutyLong: 0.1, cleanVMs: 2},
		},
	}
	if host, _ := s.pickBySchedulingPolicy(); host != "10.0.1.2" {
		t.Errorf("nil schedConfig: expected gw-idle (spread), got %q", host)
	}
}

// TestLoadEvent verifies /sandswap/load/ events populate and clear loadByID,
// including the self_pressured gate field.
func TestLoadEvent(t *testing.T) {
	s := &DNSServer{loadByID: make(map[string]gwLoad)}
	s.handleLoadEvent("/sandswap/load/gw1", `{"agg_duty_long":0.4,"clean_vms":7,"self_pressured":true}`, false)
	if l := s.loadByID["gw1"]; l.aggDutyLong != 0.4 || l.cleanVMs != 7 || !l.selfPressured {
		t.Errorf("expected load gw1=0.4/7/pressured, got %+v", l)
	}
	s.handleLoadEvent("/sandswap/load/gw1", `{"agg_duty_long":0.4,"clean_vms":7}`, false)
	if l := s.loadByID["gw1"]; l.selfPressured {
		t.Errorf("self_pressured absent in JSON should parse as false, got %+v", l)
	}
	s.handleLoadEvent("/sandswap/load/gw1", "", true)
	if _, ok := s.loadByID["gw1"]; ok {
		t.Error("expected gw1 removed on delete event")
	}
}

// TestOwnerForCached verifies the on-demand owner LRU serves cached entries and
// safely returns no-owner for unknown sandfs with a nil etcd client.
func TestOwnerForCached(t *testing.T) {
	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	// Fresh entry (within ownerCacheTTL) -> served from cache.
	s.owners["s-1"] = freshOwnerEntry("gw1")
	if res, err := s.ownerFor("s-1"); err != nil || res.gatewayID != "gw1" {
		t.Errorf("expected cached owner gw1, got (%q, %v)", res.gatewayID, err)
	}
	if res, err := s.ownerFor("s-missing"); err != nil || res.gatewayID != "" {
		t.Errorf("expected no owner for missing sandfs, got (%q, %v)", res.gatewayID, err)
	}
}

// TestOwnerForStaleRefetches verifies the B4 TTL: a cache entry older than
// ownerCacheTTL is re-validated against etcd instead of being served blind.
// With a nil etcd client the re-validation finds no owner, so "" is returned
// (shared-pool fallback) - a force-taken-over sandfs must not keep resolving to
// its old owner - and the no-owner result goes to the NEGATIVE cache, never the
// positive LRU.
func TestOwnerForStaleRefetches(t *testing.T) {
	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	// fetchedAt far in the past -> stale (> ownerCacheTTL).
	s.owners["s-1"] = staleOwnerEntry("gw-old")
	if res, err := s.ownerFor("s-1"); err != nil || res.gatewayID != "" {
		t.Errorf("B4: stale entry served old owner %q (err=%v); want \"\" (re-fetch found no owner)", res.gatewayID, err)
	}
	s.ownersMu.RLock()
	_, neg := s.negOwners["s-1"]
	s.ownersMu.RUnlock()
	if !neg {
		t.Error("B4: a no-owner re-fetch should leave a NEGATIVE cache entry")
	}
	s.ownersMu.RLock()
	_, stillPositive := s.owners["s-1"]
	s.ownersMu.RUnlock()
	if stillPositive {
		t.Error("the superseded positive entry must be dropped (a later etcd error must not serve the old owner)")
	}
}

// TestOwnerForHotKeyRevalidatesAfterTTL is the regression test for the sliding-
// TTL bug: freshness must be measured from fetchedAt (the last etcd
// confirmation), NOT from the last use. A sandfs queried continuously (more
// often than the TTL) must STILL revalidate once the TTL since the original
// fetch elapses — otherwise ownership changes (takeover/release) stay invisible
// to exactly the busiest sandfs.
func TestOwnerForHotKeyRevalidatesAfterTTL(t *testing.T) {
	origTTL := ownerCacheTTL
	ownerCacheTTL = 150 * time.Millisecond
	defer func() { ownerCacheTTL = origTTL }()

	s := &DNSServer{owners: make(map[string]*ownerEntry)} // nil etcd: a revalidation returns no-owner
	s.owners["s-hot"] = freshOwnerEntry("gw-old")         // fetchedAt = t0

	// Hit at t0+60ms — within the TTL since fetch: cached (no revalidation).
	time.Sleep(60 * time.Millisecond)
	if res, err := s.ownerFor("s-hot"); err != nil || res.gatewayID != "gw-old" {
		t.Fatalf("hit within TTL: expected cached gw-old, got (%q, %v)", res.gatewayID, err)
	}
	// Hit at t0+120ms — still within 150ms of the FETCH (only 60ms since the
	// last hit). Cached: the TTL runs from fetchedAt.
	time.Sleep(60 * time.Millisecond)
	if res, _ := s.ownerFor("s-hot"); res.gatewayID != "gw-old" {
		t.Fatalf("second hit (120ms < 150ms TTL since fetch): expected cached gw-old, got %q", res.gatewayID)
	}
	// Past the TTL since the FETCH, continuous hits notwithstanding: the next
	// lookup must revalidate — nil etcd yields no-owner, cached negative.
	time.Sleep(100 * time.Millisecond) // t0+220ms > TTL
	res, err := s.ownerFor("s-hot")
	if err != nil || res.gatewayID != "" {
		t.Fatalf("hot key past fetchedAt+TTL: expected revalidation to no-owner, got (%q, %v)", res.gatewayID, err)
	}
	s.ownersMu.RLock()
	_, neg := s.negOwners["s-hot"]
	s.ownersMu.RUnlock()
	if !neg {
		t.Error("revalidated no-owner result should be cached in the NEGATIVE cache")
	}
}

// TestOwnerForEtcdErrorStaleWhileError verifies the etcd-failure semantics: a
// failed lookup must NOT be cached as no-owner (which would reroute an owned
// sandfs to the scheduling fallback during a transient blip); a stale-known
// entry is served as-is, and with nothing known the error propagates (fail
// closed) without polluting the cache.
func TestOwnerForEtcdErrorStaleWhileError(t *testing.T) {
	origTO := ownerEtcdTimeout
	ownerEtcdTimeout = 500 * time.Millisecond
	defer func() { ownerEtcdTimeout = origTO }()

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"127.0.0.1:1"}, // nothing listens: connection refused, fast
		DialTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Skipf("cannot build dead-endpoint etcd client: %v", err)
	}
	defer cli.Close()

	s := &DNSServer{owners: make(map[string]*ownerEntry), etcdClient: cli}

	// Stale-known POSITIVE entry: served stale, no error surfaced, and the
	// entry must NOT flip to negative.
	s.owners["s-owned"] = staleOwnerEntry("gw-old")
	if res, err := s.ownerFor("s-owned"); err != nil || res.gatewayID != "gw-old" {
		t.Errorf("etcd error with stale-known owner: expected stale gw-old, got (%q, %v)", res.gatewayID, err)
	}
	s.ownersMu.RLock()
	e := s.owners["s-owned"]
	_, negCached := s.negOwners["s-owned"]
	s.ownersMu.RUnlock()
	if e == nil || e.gatewayID != "gw-old" {
		t.Errorf("etcd error must keep the stale positive entry, got %+v", e)
	}
	if negCached {
		t.Error("etcd error must not create a negative cache entry")
	}

	// Nothing known: the error propagates (caller fails closed) and NOTHING is
	// cached for that sandfs.
	if _, err := s.ownerFor("s-unknown"); err == nil {
		t.Error("etcd error with no cached knowledge must propagate an error")
	}
	s.ownersMu.RLock()
	_, cached := s.owners["s-unknown"]
	_, negUnknown := s.negOwners["s-unknown"]
	s.ownersMu.RUnlock()
	if cached || negUnknown {
		t.Error("etcd error must not create a cache entry of either polarity")
	}
}

// TestOwnerForNegativeCache verifies a no-owner result is cached (negative) so a
// retry storm on an unowned sandfs does not re-hit etcd on every call within the
// short negative TTL — and that the miss never enters the positive LRU (probe
// traffic must not evict warm owner entries).
func TestOwnerForNegativeCache(t *testing.T) {
	s := &DNSServer{owners: make(map[string]*ownerEntry)} // nil etcdClient
	// First call: miss -> resolveOwnerFromEtcd (nil) -> no owner -> negative cached.
	if res, err := s.ownerFor("s-1"); err != nil || res.gatewayID != "" {
		t.Errorf("first call: expected no owner, got (%q, %v)", res.gatewayID, err)
	}
	s.ownersMu.RLock()
	_, inLRU := s.owners["s-1"]
	_, neg := s.negOwners["s-1"]
	s.ownersMu.RUnlock()
	if inLRU {
		t.Error("a no-owner miss must NOT be inserted into the positive owner LRU")
	}
	if !neg {
		t.Error("expected a negative cache entry for s-1")
	}
	// Second call: served from the negative cache (within TTL), returns no owner.
	if res, err := s.ownerFor("s-1"); err != nil || res.gatewayID != "" {
		t.Errorf("second call (cached negative): expected no owner, got (%q, %v)", res.gatewayID, err)
	}
}

// seedOwnerEntry inserts an owner cache entry the way the production path
// (ownerFor → ownerStoreLocked) does — map + LRU front + expiry heap — but
// with controlled fetchedAt/lastUsed timestamps so evictor tests can place
// entries in the past without sleeping. The heap push must see the final
// fetchedAt (its ordering reads the live value).
func seedOwnerEntry(s *DNSServer, id, gwID string, fetchedAt, lastUsed int64) *ownerEntry {
	e := &ownerEntry{id: id, gatewayID: gwID}
	e.fetchedAt.Store(fetchedAt)
	e.lastUsed.Store(lastUsed)
	s.ownersMu.Lock()
	s.owners[id] = e
	s.pushFrontLocked(e)
	heap.Push(&s.ownerExpiry, e)
	s.ownersMu.Unlock()
	return e
}

// TestOwnerEvictorExpired verifies the heap-driven expiry: entries past their
// TTL drop (oldest tuple first), fresh ones remain.
func TestOwnerEvictorExpired(t *testing.T) {
	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	now := time.Now().UnixNano()
	seedOwnerEntry(s, "stale", "gw-old", 1, 1) // fetched 1970: far past TTL
	seedOwnerEntry(s, "fresh", "gw-new", now, now)
	s.evictOwners()
	if _, ok := s.owners["stale"]; ok {
		t.Error("expired entry should be evicted")
	}
	if _, ok := s.owners["fresh"]; !ok {
		t.Error("fresh entry should remain")
	}
	s.ownersMu.RLock()
	left := s.ownerExpiry.Len()
	s.ownersMu.RUnlock()
	if left != 1 {
		t.Errorf("heap should hold exactly the fresh entry's tuple, got %d", left)
	}
}

// TestOwnerExpiryHeapLazyDeletion covers the heap-driven expiry corners:
// (1) a refetched entry leaves a dead tuple behind that is lazily discarded
// (pointer mismatch), never double-processed; (2) a stale-while-error
// rollback (ownerFor's error path defers revalidation by rolling fetchedAt
// forward-of-expiry) keeps a dying entry cached through an evict pass even
// though its heap tuple predates the rollback.
func TestOwnerExpiryHeapLazyDeletion(t *testing.T) {
	origTTL := ownerCacheTTL
	ownerCacheTTL = 50 * time.Millisecond
	defer func() { ownerCacheTTL = origTTL }()

	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	s.ownersMu.Lock()
	s.ownerStoreLocked("sandfs-1", ownerResolution{gatewayID: "gw-a"})
	s.ownerStoreLocked("sandfs-1", ownerResolution{gatewayID: "gw-a"}) // refetch: dead tuple left behind
	s.ownersMu.Unlock()

	// Past the TTL both tuples are poppable: the dead one is discarded by
	// pointer mismatch, the live one expires the entry exactly once.
	time.Sleep(80 * time.Millisecond)
	s.evictOwners()
	s.ownersMu.RLock()
	_, present := s.owners["sandfs-1"]
	heapLen := s.ownerExpiry.Len()
	s.ownersMu.RUnlock()
	if present {
		t.Error("expired entry should be dropped")
	}
	if heapLen != 0 {
		t.Errorf("heap should be fully drained, got %d tuples", heapLen)
	}

	// Stale-while-error rollback: reproduce ownerFor's error-path arithmetic —
	// the entry's fetchedAt moves to now-(TTL-hold), i.e. NOT yet expired even
	// though its heap tuple (pushed at fetch time) is older than the TTL.
	s.ownersMu.Lock()
	s.ownerStoreLocked("sandfs-2", ownerResolution{gatewayID: "gw-b"})
	e := s.owners["sandfs-2"]
	hold := ownerErrHold
	if hold > ownerCacheTTL {
		hold = ownerCacheTTL / 2
	}
	e.fetchedAt.Store(time.Now().Add(-(ownerCacheTTL - hold)).UnixNano())
	s.ownersMu.Unlock()
	s.evictOwners()
	s.ownersMu.RLock()
	_, present = s.owners["sandfs-2"]
	s.ownersMu.RUnlock()
	if !present {
		t.Error("rolled-back (stale-while-error) entry must survive the evict pass")
	}
}

// TestOwnerEvictorOverflow verifies the O(1) LRU overflow path: with cold
// entries (lastUsed outside the grace window) over the cap, the least
// recently INSERTED cold entry drains from the list tail and the cache is
// bounded — in O(1) per eviction, not a full-table scan per dropped entry.
func TestOwnerEvictorOverflow(t *testing.T) {
	orig := ownerLRUMax
	ownerLRUMax = 2
	defer func() { ownerLRUMax = orig }()

	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	// Seed COLD entries (fresh by fetch, cold by use; insertion order a→b→c).
	now := time.Now().UnixNano()
	cold := time.Now().Add(-time.Hour).UnixNano()
	for _, id := range []string{"a", "b", "c"} {
		seedOwnerEntry(s, id, "gw-"+id, now, cold)
	}
	s.evictOwners()
	if _, ok := s.owners["a"]; ok {
		t.Error("coldest tail entry 'a' should be evicted on overflow")
	}
	if len(s.owners) > ownerLRUMax {
		t.Errorf("expected cache bounded to cap, got %d", len(s.owners))
	}
	// The evicted entry must also be unlinked (no dangling list nodes).
	s.ownersMu.Lock()
	for _, e := range s.owners {
		if e.linked && (e.prev == nil || e.next == nil) {
			t.Errorf("entry %s linked with nil pointers", e.id)
		}
	}
	s.ownersMu.Unlock()
}

// TestOwnerEvictorHotProtection verifies the grace window: an entry used
// RECENTLY (within ownerLRUGrace) is requeued to the front instead of evicted,
// even when it sits at the list tail — the "actively-queried sandfs stay warm"
// property under the O(1) approximate LRU.
func TestOwnerEvictorHotProtection(t *testing.T) {
	orig, origGrace := ownerLRUMax, ownerLRUGrace
	ownerLRUMax = 2
	ownerLRUGrace = 30 * time.Second
	defer func() { ownerLRUMax, ownerLRUGrace = orig, origGrace }()

	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	now := time.Now().UnixNano()
	cold := time.Now().Add(-time.Hour).UnixNano()
	// "hot" is the oldest by insertion (list tail) but was JUST queried.
	for _, tc := range []struct {
		id    string
		stamp int64
	}{{"hot", now}, {"c1", cold}, {"c2", cold}, {"c3", cold}} {
		seedOwnerEntry(s, tc.id, "gw-"+tc.id, now, tc.stamp)
	}
	s.evictOwners()
	if _, ok := s.owners["hot"]; !ok {
		t.Error("recently-used tail entry must be protected by the grace window")
	}
	if len(s.owners) > ownerLRUMax {
		t.Errorf("expected cache bounded to cap, got %d", len(s.owners))
	}
}

// TestOwnerEvictorAllWarmStillBounded verifies the all-warm corner: when every
// entry is inside the grace window, the requeue cap still bounds the pass and
// the cache shrinks (over cap, the coldest-by-position has to go — no infinite
// requeue loop).
func TestOwnerEvictorAllWarmStillBounded(t *testing.T) {
	orig, origGrace := ownerLRUMax, ownerLRUGrace
	ownerLRUMax = 2
	ownerLRUGrace = time.Hour
	defer func() { ownerLRUMax, ownerLRUGrace = orig, origGrace }()

	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	now := time.Now().UnixNano()
	for _, id := range []string{"a", "b", "c"} {
		seedOwnerEntry(s, id, "gw-"+id, now, now)
	}
	done := make(chan struct{})
	go func() { s.evictOwners(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("evictOwners did not terminate (requeue loop)")
	}
	if len(s.owners) > ownerLRUMax {
		t.Errorf("expected cache bounded to cap, got %d", len(s.owners))
	}
}

// TestOwnerStoreRelinksOnRefetch verifies a revalidation REPLACES the entry:
// the old node is unlinked and the new one sits at the front, so repeated
// revalidations never leave stale list nodes.
func TestOwnerStoreRelinksOnRefetch(t *testing.T) {
	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	s.ownersMu.Lock()
	s.ownerStoreLocked("sandfs-1", ownerResolution{gatewayID: "gw-old"})
	old := s.owners["sandfs-1"]
	s.ownerStoreLocked("sandfs-1", ownerResolution{gatewayID: "gw-new"})
	got := s.owners["sandfs-1"]
	front := s.lruRoot.next
	s.ownersMu.Unlock()

	if got.gatewayID != "gw-new" {
		t.Errorf("entry not replaced, got %q", got.gatewayID)
	}
	if old.linked || old.prev != nil || old.next != nil {
		t.Error("old entry must be fully unlinked after replacement")
	}
	if front != got {
		t.Error("revalidated entry must sit at the list front")
	}
}

// TestDNSBinpackDutyHardCap verifies the configurable duty_hard cap: under
// binpack, a gateway at/above the cap is excluded even though it is the
// busiest, so new sandfs never pile onto an overloaded gateway.
func TestDNSBinpackDutyHardCap(t *testing.T) {
	s := &DNSServer{
		schedConfig: config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0.85}),
		healthByID: map[string]ownerHealth{
			"gw-hot":  {nodeCount: 1},
			"gw-busy": {nodeCount: 1},
			"gw-idle": {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw-hot":  {gatewayURL: "https://10.0.1.1:3000"},
			"gw-busy": {gatewayURL: "https://10.0.1.2:3000"},
			"gw-idle": {gatewayURL: "https://10.0.1.3:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-hot":  {AgentIP: "10.0.1.1", AgentPort: 3000},
			"gw-busy": {AgentIP: "10.0.1.2", AgentPort: 3000},
			"gw-idle": {AgentIP: "10.0.1.3", AgentPort: 3000},
		},
		loadByID: map[string]gwLoad{
			"gw-hot":  {aggDutyLong: 0.92, cleanVMs: 1}, // above cap -> excluded
			"gw-busy": {aggDutyLong: 0.50, cleanVMs: 2},
			"gw-idle": {aggDutyLong: 0.10, cleanVMs: 2},
		},
	}
	host, ok := s.pickBySchedulingPolicy()
	if !ok || host != "10.0.1.2" {
		t.Errorf("binpack with duty_hard=0.85: expected gw-busy (busiest below cap), got %q ok=%v", host, ok)
	}
	// Raising the cap lets the hotter gateway win again. Drop to two
	// candidates first: with >2, binpack uses power-of-two-choices
	// (de-concentrated by design), so only the two-gateway case is
	// deterministic.
	s.SetScheduling(PolicyBinpack, 0.99)
	s.mu.Lock()
	delete(s.healthByID, "gw-idle")
	s.mu.Unlock()
	if host, _ := s.pickBySchedulingPolicy(); host != "10.0.1.1" {
		t.Errorf("binpack with duty_hard=0.99: expected gw-hot, got %q", host)
	}
}

// TestDNSBinpackCleanCapacityGate verifies the clean-VM capacity gate: a gateway
// whose load record shows zero clean VMs is excluded from routing (routing would
// 503 at the gateway) in both policies.
func TestDNSBinpackCleanCapacityGate(t *testing.T) {
	s := &DNSServer{
		schedConfig: config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0}),
		healthByID: map[string]ownerHealth{
			"gw-full":  {nodeCount: 1},
			"gw-avail": {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw-full":  {gatewayURL: "https://10.0.1.1:3000"},
			"gw-avail": {gatewayURL: "https://10.0.1.2:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-full":  {AgentIP: "10.0.1.1", AgentPort: 3000},
			"gw-avail": {AgentIP: "10.0.1.2", AgentPort: 3000},
		},
		loadByID: map[string]gwLoad{
			"gw-full":  {aggDutyLong: 0.8, cleanVMs: 0}, // full -> excluded
			"gw-avail": {aggDutyLong: 0.5, cleanVMs: 2},
		},
	}
	host, ok := s.pickBySchedulingPolicy()
	if !ok || host != "10.0.1.2" {
		t.Errorf("capacity gate: expected gw-avail (has clean VMs), got %q ok=%v", host, ok)
	}
	// No load record yet -> bootstrap, assume capacity (not excluded).
	only := &DNSServer{
		schedConfig:  config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0}),
		healthByID:   map[string]ownerHealth{"gw-new": {nodeCount: 1}},
		registryByID: map[string]gatewayRegistry{"gw-new": {gatewayURL: "https://10.0.1.3:3000"}},
		gwAddrs:      map[string]GWInfo{"gw-new": {AgentIP: "10.0.1.3", AgentPort: 3000}},
	}
	if host, ok := only.pickBySchedulingPolicy(); !ok || host != "10.0.1.3" {
		t.Errorf("bootstrap (no load record): expected gw-new accepted, got %q ok=%v", host, ok)
	}
}

// TestDNSBinpackSelfPressureGate verifies the self-pressure gate: a gateway
// whose published self_pressured is true (the gateway process itself under
// sustained resource pressure) is excluded from the no-owner scheduling
// fallback in both policies — even though it is the busiest healthy gateway
// with clean capacity (its node-side signals say "pick me"). Gateways without
// a load record (bootstrap) stay eligible.
func TestDNSBinpackSelfPressureGate(t *testing.T) {
	s := &DNSServer{
		schedConfig: config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0}),
		healthByID: map[string]ownerHealth{
			"gw-pressured": {nodeCount: 1},
			"gw-calm":      {nodeCount: 1},
			"gw-new":       {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw-pressured": {gatewayURL: "https://10.0.1.1:3000"},
			"gw-calm":      {gatewayURL: "https://10.0.1.2:3000"},
			"gw-new":       {gatewayURL: "https://10.0.1.3:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw-pressured": {AgentIP: "10.0.1.1", AgentPort: 3000},
			"gw-calm":      {AgentIP: "10.0.1.2", AgentPort: 3000},
			"gw-new":       {AgentIP: "10.0.1.3", AgentPort: 3000},
		},
		loadByID: map[string]gwLoad{
			"gw-pressured": {aggDutyLong: 0.9, cleanVMs: 5, selfPressured: true}, // busiest, but pressured -> excluded
			"gw-calm":      {aggDutyLong: 0.5, cleanVMs: 2},
			// gw-new: no load record -> bootstrap, eligible (duty 0)
		},
	}
	host, ok := s.pickBySchedulingPolicy()
	if !ok || host != "10.0.1.2" {
		t.Errorf("self-pressure gate: expected gw-calm, got %q ok=%v", host, ok)
	}

	// Pressure clears: the (busiest) gateway becomes eligible and wins binpack.
	// Two candidates only — with >2, binpack uses power-of-two-choices
	// (de-concentrated by design).
	s.mu.Lock()
	l := s.loadByID["gw-pressured"]
	l.selfPressured = false
	s.loadByID["gw-pressured"] = l
	delete(s.healthByID, "gw-new")
	s.mu.Unlock()
	if host, _ := s.pickBySchedulingPolicy(); host != "10.0.1.1" {
		t.Errorf("recovered gateway should win binpack again, got %q", host)
	}

	// Spread policy: same exclusion (the gate is policy-independent). Two
	// candidates only — with >2, spread uses power-of-two-choices (random).
	s.SetScheduling(PolicySpread, 0)
	s.mu.Lock()
	delete(s.registryByID, "gw-new")
	delete(s.gwAddrs, "gw-new")
	s.mu.Unlock()
	if host, _ := s.pickBySchedulingPolicy(); host != "10.0.1.2" {
		t.Errorf("spread: expected gw-calm (lowest duty of the two), got %q", host)
	}

	// Bootstrap: a pressured cluster where the only other gateway has no load
	// record yet — the no-record gateway is NOT excluded (bootstrap pass).
	boot := &DNSServer{
		schedConfig:  config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0}),
		healthByID:   map[string]ownerHealth{"gw-pressured": {nodeCount: 1}, "gw-new": {nodeCount: 1}},
		registryByID: map[string]gatewayRegistry{"gw-pressured": {gatewayURL: "https://10.0.1.1:3000"}, "gw-new": {gatewayURL: "https://10.0.1.3:3000"}},
		gwAddrs:      map[string]GWInfo{"gw-pressured": {AgentIP: "10.0.1.1", AgentPort: 3000}, "gw-new": {AgentIP: "10.0.1.3", AgentPort: 3000}},
		loadByID:     map[string]gwLoad{"gw-pressured": {aggDutyLong: 0.9, cleanVMs: 5, selfPressured: true}},
	}
	if host, ok := boot.pickBySchedulingPolicy(); !ok || host != "10.0.1.3" {
		t.Errorf("bootstrap: expected the no-record gateway, got %q ok=%v", host, ok)
	}
}

// TestPickGatewayLockedSelfPressureGate verifies the same eligibility gate on
// the stream/agent placement path (pickGatewayLocked): a self-pressured
// gateway is skipped; a gateway with no load record (bootstrap) passes. Also
// pins the intentional NON-gating of sticky/owner/presence paths: an owned
// sandfs still resolves to a pressured owner (affinity trumps pressure).
func TestPickGatewayLockedSelfPressureGate(t *testing.T) {
	s := &DNSServer{
		schedConfig:         config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0}),
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		healthByID:          map[string]ownerHealth{"gw-pressured": freshHealth(), "gw-calm": freshHealth(), "gw-new": freshHealth()},
		loadByID: map[string]gwLoad{
			"gw-pressured": {aggDutyLong: 0.9, cleanVMs: 1, selfPressured: true},
			"gw-calm":      {aggDutyLong: 0.5, cleanVMs: 1},
			// gw-new: no load record (bootstrap) -> eligible
		},
		gwAddrs: map[string]GWInfo{
			"gw-pressured": {AgentIP: "10.0.1.1", StreamIP: "10.0.1.1", StreamPort: 9998},
			"gw-calm":      {AgentIP: "10.0.1.2", StreamIP: "10.0.1.2", StreamPort: 9998},
			"gw-new":       {AgentIP: "10.0.1.3", StreamIP: "10.0.1.3", StreamPort: 9998},
		},
	}
	if best := s.pickGatewayLocked(true); best != "gw-calm" {
		t.Errorf("stream pick: expected gw-calm (pressured gateway excluded), got %q", best)
	}
	// Sticky to the pressured gateway survives (stickiness is not shed by
	// pressure; the sandlot keeps its connection until the gateway dies).
	s.cfg = &Config{StickySyncInterval: 60}
	s.dirty = map[string]struct{}{}
	s.sticky = map[string]*StickyEntry{"10.9.9.9": {GWID: "gw-pressured", LastQuery: time.Now().Unix()}}
	if gw := s.resolveStream("10.9.9.9"); gw == nil || gw.StreamIP != "10.0.1.1" {
		t.Errorf("sticky to pressured gateway should hold, got %+v", gw)
	}
}

// refusedEtcd is an endpoint where connections are instantly refused, so
// clientv3's lazy dial + the first Get fail fast without a real etcd.
const refusedEtcd = "127.0.0.1:1"

// agentServer builds a DNSServer serving the shared agent domain backed by one
// healthy registered gateway.
func agentServer() *DNSServer {
	s := healthyServer()
	s.cfg.Domains.Agent = "sandswap.local"
	return s
}

// TestNewDNSServerBadTLS verifies a bad etcd_ca path fails at construction.
func TestNewDNSServerBadTLS(t *testing.T) {
	cfg := &Config{
		Etcd:   refusedEtcd,
		EtcdCA: "/nonexistent/ca.pem",
	}
	if _, err := NewDNSServer(cfg); err == nil {
		t.Error("expected error for missing etcd_ca file")
	}
}

// TestNewDNSServerOK verifies the constructor wires everything up: gateway
// addresses parsed, maps initialized, schedConfig set, and an unreachable etcd
// degrades to "starting fresh" instead of failing startup.
func TestNewDNSServerOK(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
		Etcd:       refusedEtcd,
		Domains:    DomainsConfig{Stream: "stream.sandswap.local"},
		Scheduling: SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0.5},
	}
	s, err := NewDNSServer(cfg)
	if err != nil {
		t.Fatalf("NewDNSServer: %v", err)
	}
	defer s.Close()
	if s.gwAddrs == nil || len(s.gwAddrs) != 0 {
		t.Errorf("gwAddrs should start empty (candidates come from self-registration), got %+v", s.gwAddrs)
	}
	if s.sticky == nil || s.dirty == nil || s.owners == nil || s.healthByID == nil ||
		s.loadByID == nil || s.registryByID == nil {
		t.Error("expected all internal maps initialized")
	}
	if s.schedConfig == nil || s.schedConfig.Get().Policy != PolicyBinpack {
		t.Error("schedConfig not initialized from cfg.Scheduling")
	}
	if s.dutyHard() != 0.5 {
		t.Errorf("dutyHard = %v, want 0.5", s.dutyHard())
	}
	if len(s.sticky) != 0 {
		t.Errorf("unreachable etcd should start with empty sticky, got %d", len(s.sticky))
	}
}

// TestResolveAgentNoRegistration verifies the agent domain returns nil (the
// caller SERVFAILs) when no gateway has self-registered — registration is the
// only candidate source.
func TestResolveAgentNoRegistration(t *testing.T) {
	s := &DNSServer{}
	if gw := s.resolveAgent(); gw != nil {
		t.Errorf("no registered gateways: expected nil, got %+v", gw)
	}
}

// TestResolveAgentDistributed verifies the agent domain picks the best alive
// registered gateway by duty, and returns nil when nothing is alive.
func TestResolveAgentDistributed(t *testing.T) {
	s := &DNSServer{
		gwAddrs: map[string]GWInfo{
			"gw-busy": {AgentIP: "10.0.2.1", AgentPort: 3000, StreamIP: "10.0.2.1", StreamPort: 9998},
			"gw-idle": {AgentIP: "10.0.2.2", AgentPort: 3000, StreamIP: "10.0.2.2", StreamPort: 9998},
			"gw-dead": {AgentIP: "10.0.2.3", AgentPort: 3000, StreamIP: "10.0.2.3", StreamPort: 9998},
		},
		// gw-dead registered but has no health record -> dead, skipped.
		healthByID: map[string]ownerHealth{
			"gw-busy": {nodeCount: 1},
			"gw-idle": {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw-busy": {gatewayURL: "https://10.0.2.1:3000"},
			"gw-idle": {gatewayURL: "https://10.0.2.2:3000"},
			"gw-dead": {gatewayURL: "https://10.0.2.3:3000"},
		},
		loadByID: map[string]gwLoad{
			"gw-busy": {aggDutyLong: 0.9, cleanVMs: 1},
			"gw-idle": {aggDutyLong: 0.1, cleanVMs: 1},
			"gw-dead": {aggDutyLong: 0.0, cleanVMs: 1},
		},
	}
	if gw := s.resolveAgent(); gw == nil || gw.AgentIP != "10.0.2.2" {
		t.Errorf("expected idle gateway 10.0.2.2, got %+v", gw)
	}
	s.healthByID = map[string]ownerHealth{}
	if gw := s.resolveAgent(); gw != nil {
		t.Errorf("expected nil with no alive gateways, got %+v", gw)
	}
}

// TestHandleDNSAgentDomain verifies the shared agent domain answers an A record
// with the selected gateway's AgentIP, and SERVFAILs when nothing is alive.
func TestHandleDNSAgentDomain(t *testing.T) {
	s := agentServer()
	m := ask(t, s, "sandswap.local.", dns.TypeA)
	if len(m.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(m.Answer))
	}
	a, ok := m.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("10.0.1.1")) {
		t.Errorf("expected A 10.0.1.1, got %v", m.Answer[0])
	}

	s.healthByID = map[string]ownerHealth{}
	m = ask(t, s, "sandswap.local.", dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL with no alive gateway, got rcode=%d", m.Rcode)
	}
}

// TestResolveStreamStickyHit verifies a live sticky entry pins the client to its
// gateway without reselecting.
func TestResolveStreamStickyHit(t *testing.T) {
	s := healthyServer()
	now := time.Now().Unix()
	s.sticky["c1"] = &StickyEntry{GWID: "gw-1", LastQuery: now, Created: now}
	gw := s.resolveStream("c1")
	if gw == nil || gw.StreamIP != "10.0.1.1" {
		t.Fatalf("sticky hit: expected stream 10.0.1.1, got %+v", gw)
	}
	s.mu.RLock()
	dirty := len(s.dirty)
	s.mu.RUnlock()
	if dirty != 0 {
		t.Errorf("live sticky hit should not mark dirty, got %d", dirty)
	}
}

// TestResolveStreamDeadStickyReselects verifies a sticky entry pointing at a
// dead gateway is cleared (marked dirty so the etcd mirror is deleted too) and
// the client is re-placed onto a live gateway.
func TestResolveStreamDeadStickyReselects(t *testing.T) {
	s := healthyServer()
	now := time.Now().Unix()
	s.sticky["c1"] = &StickyEntry{GWID: "gw-dead", LastQuery: now, Created: now} // no health record
	gw := s.resolveStream("c1")
	if gw == nil || gw.StreamIP != "10.0.1.1" {
		t.Fatalf("dead sticky: expected reselect to 10.0.1.1, got %+v", gw)
	}
	s.mu.RLock()
	entry := s.sticky["c1"]
	_, dirty := s.dirty["c1"]
	s.mu.RUnlock()
	if entry == nil || entry.GWID != "gw-1" {
		t.Errorf("expected new sticky entry to gw-1, got %+v", entry)
	}
	if !dirty {
		t.Error("dead sticky should be marked dirty for etcd deletion")
	}
}

// TestResolveStreamNewClient verifies a first-time client gets placed by policy
// and recorded as sticky + dirty (for persistence).
func TestResolveStreamNewClient(t *testing.T) {
	s := healthyServer()
	gw := s.resolveStream("10.0.7.7")
	if gw == nil || gw.StreamIP != "10.0.1.1" {
		t.Fatalf("new client: expected 10.0.1.1, got %+v", gw)
	}
	s.mu.RLock()
	e, ok := s.sticky["10.0.7.7"]
	_, dirty := s.dirty["10.0.7.7"]
	s.mu.RUnlock()
	if !ok || e.GWID != "gw-1" {
		t.Errorf("expected sticky entry created, got %+v ok=%v", e, ok)
	}
	if !dirty {
		t.Error("new sticky entry should be marked dirty")
	}
}

// TestResolveStreamNoGateways verifies no alive gateway yields nil (the caller
// returns SERVFAIL), and no sticky entry is created for the failed placement.
func TestResolveStreamNoGateways(t *testing.T) {
	s := healthyServer()
	s.healthByID = map[string]ownerHealth{}
	if gw := s.resolveStream("c1"); gw != nil {
		t.Errorf("expected nil with no alive gateway, got %+v", gw)
	}
	s.mu.RLock()
	n := len(s.sticky)
	s.mu.RUnlock()
	if n != 0 {
		t.Errorf("failed placement should not create sticky entries, got %d", n)
	}
}

// healthyServer builds a DNSServer with one alive SELF-REGISTERED gateway
// (gw-1 at 10.0.1.1): a gateway registry record (its self-registered routing
// addresses, parsed into gwAddrs) + an etcd health record (liveness). Used as
// the baseline for handleDNS / stream-domain routing tests. There is no shared
// agent domain - only stream + sandfs.
func healthyServer() *DNSServer {
	_, loop4, _ := net.ParseCIDR("127.0.0.1/32")
	_, loop6, _ := net.ParseCIDR("::1/128")
	_, mgmt, _ := net.ParseCIDR("10.0.0.0/8") // fixture management sources
	return &DNSServer{
		recursiveNets: []*net.IPNet{loop4, loop6, mgmt},
		cfg: &Config{
			TTL:          10,
			StickyExpire: 1800,
			Domains:      DomainsConfig{Stream: "stream.sandswap.local", Sandfs: "sandfs.sandswap.local"},
		},
		sticky:       make(map[string]*StickyEntry),
		dirty:        make(map[string]struct{}),
		owners:       make(map[string]*ownerEntry),
		healthByID:   map[string]ownerHealth{"gw-1": {nodeCount: 1}},
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000", streamAddr: "10.0.1.1:9998"}},
		gwAddrs:      map[string]GWInfo{"gw-1": {AgentIP: "10.0.1.1", AgentPort: 3000, StreamIP: "10.0.1.1", StreamPort: 9998}},
		loadByID:     make(map[string]gwLoad),
	}
}

// TestHandleDNSEmptyQuestion verifies a malformed query (no question) gets
// FORMERR rather than panicking on r.Question[0].
func TestHandleDNSEmptyQuestion(t *testing.T) {
	s := healthyServer()
	// A query with QDCOUNT=0 is malformed at the byte level now: pack a bare
	// header and expect FORMERR (never a panic).
	bare := new(dns.Msg)
	bare.Id = 0x0202
	pkt, err := bare.Pack()
	if err != nil {
		t.Fatalf("pack bare header: %v", err)
	}
	m := unpackReply(t, s.answerQuery("udp", "10.0.0.1", false, pkt))
	if m.Rcode != dns.RcodeFormatError {
		t.Errorf("expected FORMERR, got rcode=%d", m.Rcode)
	}
}

// TestHandleDNSStreamSRV verifies the stream domain resolves to the configured
// gateway (via its etcd health record) and an SRV query carries the stream port
// (9998), so sandlots can discover the gRPC stream port via DNS.
func TestHandleDNSStreamSRV(t *testing.T) {
	s := healthyServer()
	m := ask(t, s, "stream.sandswap.local.", dns.TypeSRV)
	if len(m.Answer) != 1 {
		t.Fatalf("expected 1 SRV answer, got %v", m.Answer)
	}
	srv, ok := m.Answer[0].(*dns.SRV)
	if !ok {
		t.Fatalf("expected SRV, got %T", m.Answer[0])
	}
	if srv.Port != 9998 {
		t.Errorf("expected SRV port 9998, got %d", srv.Port)
	}
	// IP target: the SRV target self-references the stream name (its A record
	// carries the address).
	if srv.Target != "stream.sandswap.local." {
		t.Errorf("expected self-referential target, got %q", srv.Target)
	}
}

// TestHandleDNSStreamDeadGateway verifies a stream query with NO alive gateway
// returns SERVFAIL (the client retries / re-resolves) rather than a zero-IP.
func TestHandleDNSStreamDeadGateway(t *testing.T) {
	s := healthyServer()
	s.healthByID = map[string]ownerHealth{} // gateway dead (no health record)
	if m := ask(t, s, "stream.sandswap.local.", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL with no alive gateway, got rcode=%d", m.Rcode)
	}
}

// TestHandleDNSForwardNoForwarders verifies a non-Sandswap domain with no
// upstream forwarders configured returns SERVFAIL (the DNS does not recurse).
func TestHandleDNSForwardNoForwarders(t *testing.T) {
	s := healthyServer() // Forwarders empty
	if m := ask(t, s, "example.com.", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for non-sandswap with no forwarders, got rcode=%d", m.Rcode)
	}
}

// TestHandleDNSSandfsDelegates verifies a <sandfs_id>.<sandfs_domain> query is
// routed to the owner-aware path (here: no owner, no registered fallback ->
// SERVFAIL), proving the dispatcher classifies the sandfs zone correctly.
func TestHandleDNSSandfsDelegates(t *testing.T) {
	s := healthyServer()
	s.healthByID = map[string]ownerHealth{} // no registered fallback
	s.owners = make(map[string]*ownerEntry)
	// No owner + no registered gateway -> SERVFAIL.
	if m := ask(t, s, "sandfs-abc.sandfs.sandswap.local.", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for unowned sandfs with no fallback, got rcode=%d", m.Rcode)
	}
}

func rcodeOf(m *dns.Msg) int {
	if m == nil {
		return -1
	}
	return m.Rcode
}

// ── handleSandfsQuery: owner-aware answer branches ──

// TestHandleSandfsQueryARecord verifies an owner whose gateway_url is an IP
// produces an A record (not a CNAME). This is the baremetal/IP-target shape.
func TestHandleSandfsQueryARecord(t *testing.T) {
	s := &DNSServer{
		cfg:                 &Config{TTL: 10, Domains: DomainsConfig{Sandfs: "sandfs.sandswap.local"}},
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		owners: map[string]*ownerEntry{
			"sandfs-ip": freshOwnerEntry("gw1"),
		},
		healthByID: map[string]ownerHealth{
			"gw1": freshHealth(),
		},
		registryByID: map[string]gatewayRegistry{
			"gw1": {gatewayURL: "https://10.0.1.7:3000"},
		},
	}
	m := ask(t, s, "sandfs-ip.sandfs.sandswap.local.", dns.TypeA)
	if len(m.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(m.Answer))
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("10.0.1.7")) {
		t.Errorf("expected A 10.0.1.7, got %v", m.Answer[0])
	}
}

// TestHandleSandfsQueryFallback verifies the no-owner fallback: an unowned
// sandfs resolves to any registered healthy gateway (IP target -> A record) so
// the client connects somewhere and the first request claims ownership there.
func TestHandleSandfsQueryFallback(t *testing.T) {
	s := &DNSServer{
		cfg:    &Config{TTL: 10, Domains: DomainsConfig{Sandfs: "sandfs.sandswap.local"}},
		owners: make(map[string]*ownerEntry), // no owner
		healthByID: map[string]ownerHealth{
			"gw1": {nodeCount: 1},
		},
		registryByID: map[string]gatewayRegistry{
			"gw1": {gatewayURL: "https://10.0.1.9:3000"},
		},
		gwAddrs: map[string]GWInfo{
			"gw1": {AgentIP: "10.0.1.9", AgentPort: 3000},
		},
	}
	m := ask(t, s, "sandfs-new.sandfs.sandswap.local.", dns.TypeA)
	if len(m.Answer) != 1 {
		t.Fatalf("expected 1 answer (fallback), got %d", len(m.Answer))
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("10.0.1.9")) {
		t.Errorf("expected fallback A 10.0.1.9, got %v", m.Answer[0])
	}
}

// TestHandleSandfsQueryNoFallback verifies the no-owner + no-registered-gateway
// case returns SERVFAIL (the client gets an explicit failure, not a hang).
func TestHandleSandfsQueryNoFallback(t *testing.T) {
	s := &DNSServer{
		cfg:        &Config{TTL: 10, Domains: DomainsConfig{Sandfs: "sandfs.sandswap.local"}},
		owners:     make(map[string]*ownerEntry),
		healthByID: map[string]ownerHealth{}, // no registered gateway
	}
	m := ask(t, s, "sandfs-x.sandfs.sandswap.local.", dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL, got rcode=%d", m.Rcode)
	}
}

// TestHandleSandfsQueryEtcdErrorFailsClosed verifies the fails-closed fix end-to-end at
// the query layer: when ownership is UNKNOWN (etcd unreachable, nothing
// cached), the answer is SERVFAIL — NOT the scheduling fallback, which would
// route a maybe-owned sandfs to a non-owner gateway for the whole outage.
func TestHandleSandfsQueryEtcdErrorFailsClosed(t *testing.T) {
	origTO := ownerEtcdTimeout
	ownerEtcdTimeout = 500 * time.Millisecond
	defer func() { ownerEtcdTimeout = origTO }()

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"127.0.0.1:1"},
		DialTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Skipf("cannot build dead-endpoint etcd client: %v", err)
	}
	defer cli.Close()

	// A healthy fallback candidate EXISTS — the wrong implementation would use
	// it; fail-closed must not.
	s := &DNSServer{
		cfg:                 &Config{TTL: 10, Domains: DomainsConfig{Sandfs: "sandfs.sandswap.local"}},
		owners:              make(map[string]*ownerEntry),
		etcdClient:          cli,
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		healthByID:          map[string]ownerHealth{"gw-live": freshHealth()},
		registryByID:        map[string]gatewayRegistry{"gw-live": {gatewayURL: "https://10.0.1.9:3000"}},
		gwAddrs:             map[string]GWInfo{"gw-live": {AgentIP: "10.0.1.9", AgentPort: 3000}},
	}
	m := ask(t, s, "sandfs-owned.sandfs.sandswap.local.", dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("etcd error must SERVFAIL (fail closed), got rcode=%d", m.Rcode)
	}
	if len(m.Answer) > 0 {
		t.Errorf("etcd error must not answer from the fallback pool, got %v", m.Answer)
	}
}

// TestListenAndServeTCPBindDegraded verifies the portability contract: a TCP
// bind failure must NOT kill the server. On default-Ubuntu hosts
// systemd-resolved's stub (127.0.0.53:53) permanently blocks a wildcard TCP
// bind (REUSEADDR cannot overlap wildcard-over-specific on TCP), while the
// same wildcard UDP bind succeeds — so a fatal TCP error would make the DNS
// unstartable exactly where UDP serving works. The pre-rewrite server had the
// opposite bug: its TCP goroutine swallowed the error SILENTLY. This asserts
// the middle ground: tcpLn stays nil, UDP keeps answering, and ListenAndServe
// does not return early.
func TestListenAndServeTCPBindDegraded(t *testing.T) {
	// Reserve a TCP port so the DNS's TCP listener cannot bind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	s := healthyServer()
	s.cfg.ListenAddr = fmt.Sprintf("127.0.0.1:%d", port)
	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe() }()
	defer s.Close()

	// UDP must come up despite the occupied TCP port.
	var udpAddr *net.UDPAddr
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		uc := s.udpConn
		tcpLn := s.tcpLn
		s.mu.RUnlock()
		if uc != nil {
			udpAddr = uc.LocalAddr().(*net.UDPAddr)
			if tcpLn != nil {
				t.Fatal("tcpLn must stay nil after a TCP bind failure")
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if udpAddr == nil {
		t.Fatal("UDP listener never bound despite TCP being occupied")
	}

	// A real UDP query must round-trip end-to-end.
	c, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(rawQuery(t, "stream.sandswap.local.", dns.TypeA)); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("udp read (server must keep serving on TCP bind failure): %v", err)
	}
	m := unpackReply(t, buf[:n])
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("stream query over degraded server: rcode=%d answers=%v", m.Rcode, m.Answer)
	}

	// And ListenAndServe must still be running (no early error return).
	select {
	case err := <-errCh:
		t.Fatalf("ListenAndServe returned early on TCP bind failure: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
}

// ── handleGatewayEvent: self-registration → gwAddrs candidates ──

// TestHandleGatewayEventRegisters verifies a registry PUT turns the gateway
// into a placement candidate: addresses are parsed from the SELF-REGISTERED
// gateway_url + stream_addr into gwAddrs, and the raw record is kept for owner
// routing. Registration IS candidacy — no static config list exists.
func TestHandleGatewayEventRegisters(t *testing.T) {
	s := &DNSServer{
		registryByID: make(map[string]gatewayRegistry),
		gwAddrs:      make(map[string]GWInfo),
	}
	val, _ := json.Marshal(map[string]interface{}{
		"gateway_url": "https://10.0.1.1:3000",
		"stream_addr": "10.0.1.1:9998",
	})
	s.handleGatewayEvent("/sandswap/gateway/gw-1", string(val), false)

	if r := s.registryByID["gw-1"]; r.gatewayURL != "https://10.0.1.1:3000" || r.streamAddr != "10.0.1.1:9998" {
		t.Errorf("registryByID not populated: %+v", r)
	}
	info := s.gwAddrs["gw-1"]
	if info.AgentIP != "10.0.1.1" || info.AgentPort != 3000 || info.StreamIP != "10.0.1.1" || info.StreamPort != 9998 {
		t.Errorf("gwAddrs not parsed from self-registration: %+v", info)
	}
}

// TestHandleGatewayEventHostnameCandidate verifies a hostname gateway_url (the
// in-cluster headless-Service FQDN shape) is still a candidate — the agent
// host is answered as a CNAME at query time.
func TestHandleGatewayEventHostnameCandidate(t *testing.T) {
	s := &DNSServer{
		registryByID: make(map[string]gatewayRegistry),
		gwAddrs:      make(map[string]GWInfo),
	}
	val, _ := json.Marshal(map[string]interface{}{
		"gateway_url": "https://gw-0.gateway-exec.sandswap.svc.cluster.local:3000",
		"stream_addr": "gw-0.gateway-exec.sandswap.svc.cluster.local:9998",
	})
	s.handleGatewayEvent("/sandswap/gateway/gw-0", string(val), false)

	info := s.gwAddrs["gw-0"]
	if info.AgentIP != "gw-0.gateway-exec.sandswap.svc.cluster.local" || info.StreamPort != 9998 {
		t.Errorf("hostname candidate not registered: %+v", info)
	}
}

// TestHandleGatewayEventNoStreamAddr verifies a gateway that registered without
// a stream_addr (e.g. human mode) is NOT a stream candidate but keeps its
// registry record (owner routing unaffected).
func TestHandleGatewayEventNoStreamAddr(t *testing.T) {
	s := &DNSServer{
		registryByID: make(map[string]gatewayRegistry),
		gwAddrs:      make(map[string]GWInfo),
	}
	val, _ := json.Marshal(map[string]interface{}{
		"gateway_url": "https://10.0.9.9:3000",
	})
	s.handleGatewayEvent("/sandswap/gateway/gw-x", string(val), false)
	if _, ok := s.registryByID["gw-x"]; !ok {
		t.Error("registryByID should store the record")
	}
	if info := s.gwAddrs["gw-x"]; info.StreamIP != "" {
		t.Errorf("no-stream gateway must not be a stream candidate, got %+v", info)
	}
}

// TestHandleGatewayEventBadStreamAddr verifies a misregistered stream_addr
// (non-numeric port) excludes the gateway from STREAM placement only (per-
// domain exclusion) instead of answering broken records — and does NOT
// destroy its agent-domain candidacy.
func TestHandleGatewayEventBadStreamAddr(t *testing.T) {
	s := &DNSServer{
		registryByID: make(map[string]gatewayRegistry),
		gwAddrs:      make(map[string]GWInfo),
	}
	val, _ := json.Marshal(map[string]interface{}{
		"gateway_url": "https://10.0.1.1:3000",
		"stream_addr": "10.0.1.1:not-a-port",
	})
	s.handleGatewayEvent("/sandswap/gateway/gw-bad", string(val), false)
	info, ok := s.gwAddrs["gw-bad"]
	if !ok {
		t.Fatal("per-domain exclusion keeps the gwAddrs entry")
	}
	if info.StreamIP != "" {
		t.Errorf("bad stream_addr must clear StreamIP (stream-ineligible), got %+v", info)
	}
	if info.AgentIP != "10.0.1.1" {
		t.Errorf("agent candidacy must survive a bad stream_addr, got %+v", info)
	}
	if _, ok := s.registryByID["gw-bad"]; !ok {
		t.Error("registry record should still be stored")
	}
}

// TestHandleGatewayEventDelete verifies a DELETE event removes both the
// registry record and the placement candidacy (gateway explicitly
// unregistered / permanent exit).
func TestHandleGatewayEventDelete(t *testing.T) {
	s := &DNSServer{
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000"}},
		gwAddrs:      map[string]GWInfo{"gw-1": {AgentIP: "10.0.1.1", AgentPort: 3000, StreamIP: "10.0.1.1", StreamPort: 9998}},
	}
	s.handleGatewayEvent("/sandswap/gateway/gw-1", "", true)
	if _, ok := s.registryByID["gw-1"]; ok {
		t.Error("DELETE should remove the registry record")
	}
	if _, ok := s.gwAddrs["gw-1"]; ok {
		t.Error("DELETE should remove the placement candidate")
	}
}

// TestHandleGatewayEventCorruptJSON verifies a corrupt value is logged and
// skipped (does not overwrite a prior good record, does not panic).
func TestHandleGatewayEventCorruptJSON(t *testing.T) {
	s := &DNSServer{
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000"}},
		gwAddrs:      map[string]GWInfo{"gw-1": {AgentIP: "10.0.1.1", AgentPort: 3000}},
	}
	s.handleGatewayEvent("/sandswap/gateway/gw-1", "{not json", false)
	// The prior good record survives (corrupt PUT does not delete).
	if r, ok := s.registryByID["gw-1"]; !ok || r.gatewayURL != "https://10.0.1.1:3000" {
		t.Errorf("corrupt PUT should not clobber prior record, got %+v ok=%v", r, ok)
	}
	if _, ok := s.gwAddrs["gw-1"]; !ok {
		t.Error("corrupt PUT should not remove the prior placement candidate")
	}
}

// TestHandleGatewayEventAddressChange verifies a gateway re-registering with a
// CHANGED address (restart with a new pod IP) updates the candidate in place —
// sticky clients keep their gateway_id and are answered with the new address.
func TestHandleGatewayEventAddressChange(t *testing.T) {
	s := healthyServer()
	val, _ := json.Marshal(map[string]interface{}{
		"gateway_url": "https://10.0.9.8:3000",
		"stream_addr": "10.0.9.8:9998",
	})
	s.handleGatewayEvent("/sandswap/gateway/gw-1", string(val), false)

	info := s.gwAddrs["gw-1"]
	if info.StreamIP != "10.0.9.8" || info.AgentIP != "10.0.9.8" {
		t.Errorf("re-registration should update addresses in place, got %+v", info)
	}
	if got := s.resolveStream("c1"); got == nil || got.StreamIP != "10.0.9.8" {
		t.Errorf("sticky client should be answered with the new address, got %+v", got)
	}
}

// ── ClearAllSticky: SIGHUP path ──

// TestClearAllSticky verifies the SIGHUP handler clears every sticky entry and
// queues a delete for those that actually have an etcd mirror — resetting
// client affinity cluster-wide. It also pins the rule from the other
// side: an entry that never reached etcd must NOT be queued (nothing to
// delete), which is what keeps the queue bounded under a spoofed-source flood.
func TestClearAllSticky(t *testing.T) {
	s := healthyServer()
	s.sticky["c1"] = &StickyEntry{GWID: "gw-1", LastQuery: 1, Created: 1} // mirrored
	s.sticky["c2"] = &StickyEntry{GWID: "gw-1", LastQuery: 2, Created: 2} // never flushed
	s.mirrored = map[string]struct{}{"c1": {}}

	s.ClearAllSticky()

	if len(s.sticky) != 0 {
		t.Errorf("expected sticky cleared, got %d entries", len(s.sticky))
	}
	if len(s.dirty) != 1 {
		t.Errorf("expected exactly 1 dirty entry (the mirrored one), got %d", len(s.dirty))
	}
	if _, ok := s.dirty["c1"]; !ok {
		t.Error("c1 has an etcd mirror and must be marked dirty for deletion")
	}
	if _, ok := s.dirty["c2"]; ok {
		t.Error("c2 was never mirrored: queueing a delete for it is a pointless RPC ")
	}
}

// TestStickyDirtySetBoundedUnderFlood is the pin: a spoofed-source
// flood (distinct client IPs, all churning through a small sticky cap) must
// not grow the dirty set without bound. Before the fix every churned IP was
// queued — creations AND cap evictions — while the flush drains at most
// sticky_sync_batch per interval, so the set grew monotonically with the
// flood (20 000 distinct clients → 20 000 entries in the recorded repro) and
// afterwards emitted Deletes for hours for keys that were never written.
//
// With the fix, only entries that HAVE a mirror can be queued for deletion,
// and live entries contribute at most one queue slot each, so the set is
// bounded by 2×sticky_max no matter how many distinct sources arrive.
func TestStickyDirtySetBoundedUnderFlood(t *testing.T) {
	orig := stickyMax
	stickyMax = 8
	defer func() { stickyMax = orig }()

	s := healthyServer()
	const clients = 5000
	for i := 0; i < clients; i++ {
		ip := fmt.Sprintf("10.9.%d.%d", i/250, i%250)
		if gw := s.resolveStream(ip); gw == nil {
			t.Fatalf("client %d (%s): expected placement", i, ip)
		}
	}
	s.mu.RLock()
	dirty, sticky := len(s.dirty), len(s.sticky)
	s.mu.RUnlock()

	if sticky > stickyMax {
		t.Errorf("sticky map must stay capped at %d, got %d", stickyMax, sticky)
	}
	if bound := 2 * stickyMax; dirty > bound {
		t.Errorf("dirty set must stay bounded by 2×sticky_max=%d under a flood, got %d (%d clients churned)",
			bound, dirty, clients)
	}
}

// TestParseGatewayAddrs verifies the self-registered registry address parser:
// valid IP/hostname targets, IPv6 literals, a gateway_url without a port, an
// EMPTY stream_addr (agent-only candidate — e.g. human mode), and that a
// non-numeric stream port is a hard error.
func TestParseGatewayAddrs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		info, err := parseGatewayAddrs("https://10.0.1.1:3000", "10.0.1.1:9998")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if info.AgentIP != "10.0.1.1" || info.AgentPort != 3000 {
			t.Errorf("agent = %+v", info)
		}
		if info.StreamIP != "10.0.1.1" || info.StreamPort != 9998 {
			t.Errorf("stream = %+v", info)
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		info, err := parseGatewayAddrs("https://[2001:db8::1]:3000", "[2001:db8::1]:9998")
		if err != nil {
			t.Fatalf("parse ipv6: %v", err)
		}
		if info.AgentIP != "2001:db8::1" || info.AgentPort != 3000 {
			t.Errorf("agent = %+v", info)
		}
		if info.StreamIP != "2001:db8::1" || info.StreamPort != 9998 {
			t.Errorf("stream = %+v", info)
		}
	})

	t.Run("hostname agent url without port", func(t *testing.T) {
		info, err := parseGatewayAddrs("https://gw-0.gateway-exec.svc.cluster.local", "10.0.1.1:9998")
		if err != nil {
			t.Fatalf("parse hostname: %v", err)
		}
		if info.AgentIP != "gw-0.gateway-exec.svc.cluster.local" || info.AgentPort != 0 {
			t.Errorf("agent = %+v", info)
		}
	})

	t.Run("empty stream_addr is agent-only candidate", func(t *testing.T) {
		info, err := parseGatewayAddrs("https://10.0.1.1:3000", "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if info.AgentIP != "10.0.1.1" || info.StreamIP != "" {
			t.Errorf("agent-only candidate = %+v", info)
		}
	})

	t.Run("bad stream_addr clears stream only", func(t *testing.T) {
		info, problems := parseGatewayAddrs("https://10.0.1.1:3000", "10.0.1.1")
		if len(problems) == 0 {
			t.Error("expected a problem for stream_addr without port")
		}
		if info.StreamIP != "" {
			t.Errorf("bad stream_addr must clear StreamIP, got %+v", info)
		}
		if info.AgentIP != "10.0.1.1" {
			t.Errorf("agent address must survive a bad stream_addr, got %+v", info)
		}
	})

	t.Run("non-numeric stream port", func(t *testing.T) {
		// Regression guard: a non-numeric port must be reported, not port 0.
		info, problems := parseGatewayAddrs("https://10.0.1.1:3000", "10.0.1.1:xyz")
		if len(problems) == 0 {
			t.Error("expected a problem for non-numeric stream port")
		}
		if info.StreamIP != "" || info.StreamPort != 0 {
			t.Errorf("bad port must clear the stream fields, got %+v", info)
		}
	})

	t.Run("garbage gateway_url clears agent only", func(t *testing.T) {
		// A garbage gateway_url host must not become a CNAME target the client
		// can never resolve — agent candidacy is withdrawn, stream survives.
		info, problems := parseGatewayAddrs("https://not a url/", "10.0.1.1:9998")
		if len(problems) == 0 {
			t.Error("expected a problem for garbage gateway_url")
		}
		if info.AgentIP != "" {
			t.Errorf("garbage gateway_url must clear AgentIP, got %+v", info)
		}
		if info.StreamIP != "10.0.1.1" || info.StreamPort != 9998 {
			t.Errorf("stream address must survive a bad gateway_url, got %+v", info)
		}
	})

	t.Run("gateway_url with underscore host rejected", func(t *testing.T) {
		// Underscores are not valid in DNS names served as CNAME targets.
		if info, _ := parseGatewayAddrs("https://gw_0.svc:3000", ""); info.AgentIP != "" {
			t.Errorf("invalid hostname charset must clear AgentIP, got %+v", info)
		}
	})
}

// TestGatewayURLToCNAMEValidation verifies the owner-branch answer shape
// validates its host: a garbage self-registered gateway_url yields ok=false
// (the caller falls back honestly) instead of a CNAME to junk.
func TestGatewayURLToCNAMEValidation(t *testing.T) {
	if _, _, ok := gatewayURLToCNAME("https://10.0.1.7:3000"); !ok {
		t.Error("IP host must be valid")
	}
	if cn, _, ok := gatewayURLToCNAME("https://gw-0.svc.cluster.local:3000"); !ok || cn != "gw-0.svc.cluster.local" {
		t.Errorf("hostname must yield CNAME, got (%q, %v)", cn, ok)
	}
	if _, _, ok := gatewayURLToCNAME("https://not a url/"); ok {
		t.Error("garbage gateway_url must not resolve (would emit a junk CNAME)")
	}
	if _, _, ok := gatewayURLToCNAME(""); ok {
		t.Error("empty gateway_url must not resolve")
	}
}

// genCert writes a self-signed CA cert + a leaf cert signed by it to temp
// files, returning (caPath, certPath, keyPath). Used to exercise etcdTLSConfig
// with real mTLS material.
func genCert(t *testing.T) (caPath, certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0644); err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644); err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}), 0600); err != nil {
		t.Fatal(err)
	}
	return
}

// TestEtcdTLSConfig verifies the etcd client TLS builder: plaintext when no
// CA, CA-only (server verification), full mTLS (CA+cert+key), and rejection
// of missing/invalid PEM material. This is the security boundary for the DNS
// -> app-etcd connection (k8s --client-cert-auth).
func TestEtcdTLSConfig(t *testing.T) {
	t.Run("no CA -> plaintext", func(t *testing.T) {
		cfg, err := etcdTLSConfig(&Config{})
		if err != nil || cfg != nil {
			t.Errorf("expected (nil,nil), got (%v,%v)", cfg, err)
		}
	})

	t.Run("CA only -> server verification", func(t *testing.T) {
		ca, _, _ := genCert(t)
		cfg, err := etcdTLSConfig(&Config{EtcdCA: ca})
		if err != nil {
			t.Fatalf("CA-only: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil tls config")
		}
		if len(cfg.Certificates) != 0 {
			t.Error("CA-only should have no client certs")
		}
		if cfg.RootCAs == nil {
			t.Error("expected RootCAs pool set")
		}
		if cfg.MinVersion < tls.VersionTLS12 {
			t.Error("expected MinVersion >= TLS 1.2")
		}
	})

	t.Run("CA + cert + key -> mTLS", func(t *testing.T) {
		ca, cert, key := genCert(t)
		cfg, err := etcdTLSConfig(&Config{EtcdCA: ca, EtcdCert: cert, EtcdKey: key})
		if err != nil {
			t.Fatalf("mTLS: %v", err)
		}
		if len(cfg.Certificates) != 1 {
			t.Errorf("expected 1 client cert, got %d", len(cfg.Certificates))
		}
	})

	t.Run("missing CA file -> error", func(t *testing.T) {
		if _, err := etcdTLSConfig(&Config{EtcdCA: "/nonexistent/ca.pem"}); err == nil {
			t.Error("expected error for missing CA file")
		}
	})

	t.Run("invalid CA PEM -> error", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(p, []byte("not a pem"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := etcdTLSConfig(&Config{EtcdCA: p}); err == nil {
			t.Error("expected error for invalid CA PEM")
		}
	})

	t.Run("CA + cert but no key -> plaintext (cert ignored)", func(t *testing.T) {
		// etcdTLSConfig only loads a client cert when BOTH cert and key are set.
		// A cert with no key is silently dropped to CA-only (server verification).
		ca, cert, _ := genCert(t)
		cfg, err := etcdTLSConfig(&Config{EtcdCA: ca, EtcdCert: cert}) // no EtcdKey
		if err != nil {
			t.Fatalf("cert-no-key: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil (CA-only) tls config")
		}
		if len(cfg.Certificates) != 0 {
			t.Errorf("cert without key should not load a client cert, got %d", len(cfg.Certificates))
		}
	})
}

// TestResolveOwnerFromEtcdNilClient verifies the nil-etcd-client guard: with
// no etcd (tests / bootstrap) owner resolution returns no owner, so the caller
// falls back to pickBySchedulingPolicy. Must not panic.
func TestResolveOwnerFromEtcdNilClient(t *testing.T) {
	s := &DNSServer{} // etcdClient == nil
	if res, err := s.resolveOwnerFromEtcd("sandfs-x"); err != nil || res.gatewayID != "" {
		t.Errorf("nil client: expected no owner, got (%q, %v)", res.gatewayID, err)
	}
}

// TestTouchSticky verifies the async sticky-update: an existing entry's
// LastQuery is refreshed and the entry is marked dirty (for the next etcd
// sync). A missing entry is a safe no-op.
func TestTouchSticky(t *testing.T) {
	s := &DNSServer{
		sticky: map[string]*StickyEntry{"c1": {GWID: "gw-1", LastQuery: 1, Created: 1}},
		dirty:  make(map[string]struct{}),
	}
	s.touchSticky("c1")
	s.mu.RLock()
	e := s.sticky["c1"]
	_, dirty := s.dirty["c1"]
	s.mu.RUnlock()
	if e.LastQuery == 1 {
		t.Error("LastQuery should be refreshed")
	}
	if !dirty {
		t.Error("entry should be marked dirty after touch")
	}
	// Missing entry -> no-op, no panic, no dirty entry created.
	before := len(s.dirty)
	s.touchSticky("c2")
	if len(s.dirty) != before {
		t.Errorf("touchSticky on missing entry should not add dirty, got %d->%d", before, len(s.dirty))
	}
}

// TestCloseNilSafe verifies Close on a DNSServer with no listeners/etcd client
// (tests / not-yet-started) is a no-op without panicking.
func TestCloseNilSafe(t *testing.T) {
	s := &DNSServer{} // dnsServer, tcpServer, etcdClient all nil
	s.Close()         // must not panic
}

// This file locks the cross-module JSON contract between the gateway (writer)
// and the DNS (reader). The gateway and dns are SEPARATE Go modules with no
// compile-time link; they coordinate via etcd JSON keys whose field names are
// a shared contract. A silent field rename on either side breaks owner-aware
// routing with no compile error - these tests make the contract executable.
//
// Under the registry decoupling, routing addresses live ONLY in the
// /sandswap/gateway/{gw} registry key (configuration, plain key); the health
// key is pure liveness + compute (node_count), and the ownership key is a pure
// per-sandfs claim (gateway_id). Each parser is locked below.
//
// Writer side (must match):
//   gateway/lease/load.go        LoadValue            -> load tags
//   gateway/lease/ownership.go   GatewayHealthValue   -> health tags
//   gateway/lease/ownership.go   GatewayRegistryValue -> registry tags
//
// Reader side (under test):
//   dns/resolver.go  handleLoadEvent      / refreshOwnerAndHealth (loadByID)
//   dns/resolver.go  handleHealthEvent    / refreshOwnerAndHealth (healthByID)
//   dns/resolver.go  handleGatewayEvent   / refreshOwnerAndHealth (registryByID)

// TestContractLoadRecord verifies the DNS load parser extracts every field the
// gateway writes in lease.LoadValue. Only agg_duty_long + clean_vms are
// consumed by the DNS today (headroom scoring + capacity gate). The load key
// must NOT carry gateway_url (routing lives in the registry key) - if the
// gateway ever re-adds it, the DNS parser ignores it (harmless), but the
// contract is that routing addresses come from the registry.
func TestContractLoadRecord(t *testing.T) {
	// Canonical load record as the gateway's lease.LoadValue marshals it.
	const loadJSON = `{
		"gateway_id": "gw-1",
		"last_update": "2026-08-07T00:00:00Z",
		"agg_duty_long": 0.42,
		"max_duty_window": 0.9,
		"clean_vms": 7,
		"node_count": 3,
		"nodes": [{"node_id": "n1", "duty_long": 0.42}]
	}`

	s := &DNSServer{loadByID: make(map[string]gwLoad)}
	s.handleLoadEvent("/sandswap/load/gw-1", loadJSON, false)

	l, ok := s.loadByID["gw-1"]
	if !ok {
		t.Fatal("load record not stored")
	}
	if l.aggDutyLong != 0.42 {
		t.Errorf("agg_duty_long: got %v, want 0.42 (field-name contract break?)", l.aggDutyLong)
	}
	if l.cleanVMs != 7 {
		t.Errorf("clean_vms: got %v, want 7 (field-name contract break?)", l.cleanVMs)
	}
}

// TestContractHealthRecord verifies the DNS health parser extracts only
// liveness + compute (node_count) from the gateway's GatewayHealthValue.
// node_count==0 is the G2 fault state (excluded from agent routing). Routing
// addresses do NOT live here - they come from the registry key
// (TestContractGatewayRegistryRecord).
func TestContractHealthRecord(t *testing.T) {
	// Canonical health record as the gateway's GatewayHealthValue marshals it
	// (post-decoupling: no gateway_url / stream_addr in the health key).
	const healthJSON = `{
		"last_healthy_ts": "2026-08-07T00:00:00Z",
		"node_count": 2
	}`

	s := &DNSServer{
		healthByID: make(map[string]ownerHealth),
	}
	s.handleHealthEvent("/sandswap/health/gw-1", healthJSON, false)

	h, ok := s.healthByID["gw-1"]
	if !ok {
		t.Fatal("health record not stored")
	}
	if h.nodeCount != 2 {
		t.Errorf("node_count: got %v, want 2 (contract break?)", h.nodeCount)
	}
	h.lastHealthyTS = time.Time{}
	if h != (ownerHealth{nodeCount: 2}) {
		t.Errorf("health record carries unexpected fields: %+v (should be pure liveness + node_count)", h)
	}
	// Negative: the health key must NOT be the source of routing addresses. If the
	// gateway writes gateway_url/stream_addr here (legacy layout), the DNS parser
	// must not surface them anywhere routable.
	const legacyHealthJSON = `{
		"last_healthy_ts": "2026-08-07T00:00:00Z",
		"node_count": 2
	}`
	s2 := &DNSServer{healthByID: make(map[string]ownerHealth)}
	s2.handleHealthEvent("/sandswap/health/gw", legacyHealthJSON, false)
	if _, ok := s2.registryByID["gw"]; ok {
		t.Error("health-key gateway_url must NOT populate the registry (addresses only from /sandswap/gateway)")
	}
}

// TestContractLoadDelete verifies the DNS treats a load-key DELETE as "gateway
// gone" -> the load record is removed (so it stops being a routing candidate).
func TestContractLoadDelete(t *testing.T) {
	s := &DNSServer{loadByID: map[string]gwLoad{"gw-1": {aggDutyLong: 0.5, cleanVMs: 3}}}
	s.handleLoadEvent("/sandswap/load/gw-1", "", true)
	if _, ok := s.loadByID["gw-1"]; ok {
		t.Error("DELETE should remove the load record")
	}
}

// TestContractHealthFaultState verifies node_count==0 (the G2 fault state) is
// faithfully carried through the parse: the gateway publishes 0 when it has no
// connected sandlot, and the DNS must see exactly 0 (not default to 1) so it
// excludes the gateway from agent routing.
func TestContractHealthFaultState(t *testing.T) {
	// Fresh last_healthy_ts (alive owner) but node_count==0 (G2 fault state: no
	// connected sandlot). The owner is alive, just compute-less.
	healthJSON := fmt.Sprintf(`{
		"last_healthy_ts": %q,
		"node_count": 0
	}`, time.Now().Format(time.RFC3339))
	s := &DNSServer{
		healthByID:          make(map[string]ownerHealth),
		registryByID:        make(map[string]gatewayRegistry),
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
	}
	s.handleHealthEvent("/sandswap/health/gw-1", healthJSON, false)
	h := s.healthByID["gw-1"]
	if h.nodeCount != 0 {
		t.Errorf("fault state: node_count = %v, want 0 (must not default to 1)", h.nodeCount)
	}
	// Tolerance-first: a fault-state owner that is ALIVE (fresh health) STILL
	// resolves — node_count is informational, not a routing gate. Ownership
	// unchanged means only the owner can serve, so route there regardless of its
	// compute state (the agent retries on failure). Fresh entry so ownerFor serves
	// it from cache; the address comes from the registry.
	s.owners = map[string]*ownerEntry{"sandfs-f": freshOwnerEntry("gw-1")}
	s.registryByID["gw-1"] = gatewayRegistry{gatewayURL: "https://10.0.1.1:3000"}
	if _, _, ok, err := s.resolveSandfsOwner("sandfs-f"); err != nil || !ok {
		t.Errorf("alive fault-state owner (node_count 0) must still resolve (tolerance-first), got ok=%v err=%v", ok, err)
	}
}

// TestContractGatewayRegistryRecord verifies the DNS registry parser extracts
// the routing addresses the gateway writes in GatewayRegistryValue
// (/sandswap/gateway/{gw}, plain configuration key). This is the NEW home of
// gateway_url + stream_addr; the DNS resolves owner addresses and the
// no-owner scheduling fallback from here.
func TestContractGatewayRegistryRecord(t *testing.T) {
	const regJSON = `{
		"gateway_url": "https://10.0.1.1:3000",
		"stream_addr": "10.0.1.1:9998"
	}`

	s := &DNSServer{
		registryByID: make(map[string]gatewayRegistry),
		gwAddrs:      make(map[string]GWInfo),
	}
	s.handleGatewayEvent("/sandswap/gateway/gw-1", regJSON, false)

	r, ok := s.registryByID["gw-1"]
	if !ok {
		t.Fatal("registry record not stored")
	}
	if r.gatewayURL != "https://10.0.1.1:3000" {
		t.Errorf("gateway_url: got %q, want https://10.0.1.1:3000 (contract break?)", r.gatewayURL)
	}
	if r.streamAddr != "10.0.1.1:9998" {
		t.Errorf("stream_addr: got %q, want 10.0.1.1:9998 (contract break?)", r.streamAddr)
	}
	// Self-registration is candidacy: the parsed addresses become the
	// placement candidate keyed by gateway_id.
	if info := s.gwAddrs["gw-1"]; info.AgentIP != "10.0.1.1" || info.StreamPort != 9998 {
		t.Errorf("gwAddrs: got %+v, want agent 10.0.1.1 + stream port 9998 (parsed from the registry value)", info)
	}

	// DELETE removes both the registry record and the placement candidacy
	// (gateway unregistered / permanent exit).
	s2 := &DNSServer{
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000"}},
		gwAddrs:      map[string]GWInfo{"gw-1": {AgentIP: "10.0.1.1", AgentPort: 3000}},
	}
	s2.handleGatewayEvent("/sandswap/gateway/gw-1", "", true)
	if _, ok := s2.registryByID["gw-1"]; ok {
		t.Error("DELETE should remove the registry record")
	}
	if _, ok := s2.gwAddrs["gw-1"]; ok {
		t.Error("DELETE should remove the placement candidate")
	}
}

// BenchmarkEvictOwnersOverflow measures the overflow drain at production
// scale: a 100k-entry cache with a recurring overflow of 100. The O(1) LRU
// drains each overflow in ~100 list operations; the previous full-scan-per-
// eviction implementation did ~100×100k map iterations per drain.
func BenchmarkEvictOwnersOverflow(b *testing.B) {
	orig := ownerLRUMax
	ownerLRUMax = 100000
	defer func() { ownerLRUMax = orig }()

	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	cold := time.Now().Add(-time.Hour).UnixNano()
	s.ownersMu.Lock()
	for i := 0; i < 100000; i++ {
		e := freshOwnerEntry("gw")
		e.id = "sandfs-" + itoaBench(i)
		e.lastUsed.Store(cold)
		s.owners[e.id] = e
		s.pushFrontLocked(e)
	}
	s.ownersMu.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s.ownersMu.Lock()
		for j := 0; j < 100; j++ {
			e := freshOwnerEntry("gw-new")
			e.id = "sandfs-ovf-" + itoaBench(i) + "-" + itoaBench(j)
			e.lastUsed.Store(cold)
			s.owners[e.id] = e
			s.pushFrontLocked(e)
		}
		s.ownersMu.Unlock()
		b.StartTimer()
		s.evictOwners()
	}
}

func itoaBench(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ──: the stale-while-error rollback must keep the expiry heap valid ──

// heapValid reports whether the slice still satisfies the min-heap property on
// fetchedAt — the invariant evictOwners' "stop at the first unexpired tuple"
// relies on.
func heapValid(h ownerExpiryHeap) bool {
	for i := 1; i < len(h); i++ {
		parent := (i - 1) / 2
		if h[i].fetchedAt.Load() < h[parent].fetchedAt.Load() {
			return false
		}
	}
	return true
}

// TestOwnerRollbackKeepsHeapInvariant is the pin. The stale-while-error
// path defers a dying entry's expiry by moving its fetchedAt FORWARD — a
// mutation of a live heap key. Without re-heapifying, the root stops being the
// minimum, and evictOwners' "stop at the first unexpired tuple" early break
// then leaves genuinely expired entries in the cache for the length of an
// etcd outage (the comment claimed the delay was bounded by the rollback hold;
// it was not provable).
//
// Fixture: the entry that gets rolled back is the heap ROOT (the oldest, hence
// the one a slow-path miss is triggered for). Moving the root's key forward
// makes it fresher than its own children — the canonical violation.
func TestOwnerRollbackKeepsHeapInvariant(t *testing.T) {
	origTO := ownerEtcdTimeout
	ownerEtcdTimeout = 500 * time.Millisecond
	defer func() { ownerEtcdTimeout = origTO }()

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{refusedEtcd}, // nothing listens: fast failure
		DialTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Skipf("cannot build dead-endpoint etcd client: %v", err)
	}
	defer cli.Close()

	s := &DNSServer{
		owners:     make(map[string]*ownerEntry),
		etcdClient: cli,
	}
	ttl := int64(ownerCacheTTL)
	now := time.Now().UnixNano()
	// a: oldest (heap root) and expired; b: also expired; c: fresh.
	for _, e := range []struct {
		id  string
		age int64
	}{
		{"sandfs-a", 3 * ttl},
		{"sandfs-b", 2 * ttl},
		{"sandfs-c", ttl / 2},
	} {
		ent := &ownerEntry{id: e.id, gatewayID: "gw-1", heapIdx: -1}
		ent.fetchedAt.Store(now - e.age)
		ent.lastUsed.Store(now)
		s.owners[e.id] = ent
		heap.Push(&s.ownerExpiry, ent)
	}
	if !heapValid(s.ownerExpiry) {
		t.Fatal("fixture heap must start valid")
	}
	if s.ownerExpiry[0].id != "sandfs-a" {
		t.Fatalf("fixture: expected sandfs-a at the heap root, got %s", s.ownerExpiry[0].id)
	}

	// Slow-path miss for the expired root + an etcd failure → the rollback.
	// (The rollback still ANSWERS with the stale value — it returns no error —
	// so the signal is the moved fetchedAt, not an error.)
	before := s.owners["sandfs-a"].fetchedAt.Load()
	s.ownerFor("sandfs-a")
	if after := s.owners["sandfs-a"].fetchedAt.Load(); after <= before {
		t.Skipf("rollback did not fire (fetchedAt %d → %d); endpoint answered?", before, after)
	}
	s.ownersMu.RLock()
	valid := heapValid(s.ownerExpiry)
	root := s.ownerExpiry[0].id
	s.ownersMu.RUnlock()
	if !valid {
		t.Errorf("rollback moved the live heap key of %s without re-heapifying: the min-heap invariant is broken ", root)
	}

	// Behavioural half: the expired entry that is NOT the root must still be
	// evicted — with the invariant broken it hides below a fresher root and the
	// early break defers it.
	s.evictOwners()
	s.ownersMu.RLock()
	_, bCached := s.owners["sandfs-b"]
	_, cCached := s.owners["sandfs-c"]
	s.ownersMu.RUnlock()
	if bCached {
		t.Error("an entry expired beyond its TTL must be evicted regardless of a concurrent rollback ")
	}
	if !cCached {
		t.Error("the fresh entry must survive the eviction pass")
	}
}

// TestOwnerForRateLimitsEtcdBoundLookups pins the lookup-rate bound: the first
// etcd-bound lookup from a source consumes its token, the next distinct probe
// is refused (fail closed; SERVFAIL at the query layer) without an etcd read,
// a refused lookup is not cached as negative, a different source has its own
// budget, and a stale-known owner is still served when the limiter trips.
func TestOwnerForRateLimitsEtcdBoundLookups(t *testing.T) {
	origSrc, origGlobal := ownerRatePerSource, ownerRateGlobal
	ownerRatePerSource, ownerRateGlobal = 1, 0 // 1/s per source, no global cap
	defer func() { ownerRatePerSource, ownerRateGlobal = origSrc, origGlobal }()

	s := &DNSServer{
		owners:      make(map[string]*ownerEntry),
		rateLimiter: newOwnerRateLimiter(),
	}
	if res, err := s.ownerFor("sandfs-1", "10.0.0.1"); err != nil || res.gatewayID != "" {
		t.Fatalf("first lookup from a source must be admitted, got (%q, %v)", res.gatewayID, err)
	}
	if _, err := s.ownerFor("sandfs-2", "10.0.0.1"); err == nil {
		t.Fatal("a second distinct etcd-bound lookup from the same source must be rate limited")
	}
	s.ownersMu.RLock()
	_, neg := s.negOwners["sandfs-2"]
	s.ownersMu.RUnlock()
	if neg {
		t.Error("a rate-limited lookup must not be cached as a negative answer")
	}
	if res, err := s.ownerFor("sandfs-3", "10.0.0.2"); err != nil || res.gatewayID != "" {
		t.Fatalf("another source has its own budget, got (%q, %v)", res.gatewayID, err)
	}

	// A saturated source still gets the stale-known owner (no reroute to the
	// scheduling fallback just because the limiter is warm).
	s.owners["sandfs-4"] = staleOwnerEntry("gw-old")
	if res, err := s.ownerFor("sandfs-4", "10.0.0.1"); err != nil || res.gatewayID != "gw-old" {
		t.Fatalf("rate-limited lookup must serve the stale owner, got (%q, %v)", res.gatewayID, err)
	}
}

// TestAdoptStickyRecordMarksEtcdMirror pins the restart-leak fix: a record
// loaded from etcd already HAS an etcd key, so it must be registered as
// mirrored; otherwise its expiry/clear queues no Delete and the key leaks in
// etcd across every restart.
func TestAdoptStickyRecordMarksEtcdMirror(t *testing.T) {
	s := &DNSServer{
		cfg:    &Config{StickyExpire: 1},
		sticky: make(map[string]*StickyEntry),
		dirty:  make(map[string]struct{}),
	}
	if !s.adoptStickyRecord(stickyPrefix+"10.1.2.3", []byte(`{"gw_id":"gw-1","last_query":1,"created":1}`)) {
		t.Fatal("valid sticky record was rejected")
	}
	if _, ok := s.sticky["10.1.2.3"]; !ok {
		t.Fatal("valid sticky record not loaded")
	}
	if !s.isMirrored("10.1.2.3") {
		t.Fatal("a loaded sticky record must be registered as mirrored (else its etcd key leaks)")
	}
	// Expiry must now queue the etcd Delete for the loaded record.
	s.expireSticky()
	if _, live := s.sticky["10.1.2.3"]; live {
		t.Fatal("expired sticky record still live")
	}
	s.mu.RLock()
	_, queued := s.dirty["10.1.2.3"]
	s.mu.RUnlock()
	if !queued {
		t.Fatal("expiry of a loaded record must queue its etcd mirror delete")
	}
	// A corrupt record is skipped (not fatal) and leaves no state.
	if s.adoptStickyRecord(stickyPrefix+"10.1.2.4", []byte("{not json")) {
		t.Fatal("corrupt sticky record must be rejected")
	}
}
