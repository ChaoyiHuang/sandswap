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

package stream

import (
	"testing"

	pb "common/proto/stream"
)

// The per-node naming-generation report is what /stats projects and what a
// rotation's convergence proof reads: only nodes that REPORTED one appear
// (exec-only instances stay out), and the newest heartbeat wins.
func TestNodeSeedReports(t *testing.T) {
	srv := NewServer("gw", nil, 8, 0)

	execConn := newTestConn("exec-1")
	provConn := newTestConn("prov-1")
	srv.mu.Lock()
	srv.nodes["exec-1"] = execConn
	srv.nodes["prov-1"] = provConn
	srv.mu.Unlock()

	// An exec node never reports one: no entry, no empty placeholder.
	if got := srv.NodeSeedReports(); len(got) != 0 {
		t.Fatalf("exec-only fleet reported %+v, want none", got)
	}

	provConn.SetSeedReport("aabbccdd", false, "")
	reports := srv.NodeSeedReports()
	if len(reports) != 1 || reports[0].NodeID != "prov-1" {
		t.Fatalf("reports = %+v, want just prov-1", reports)
	}
	if reports[0].Generation != "aabbccdd" || reports[0].Staged {
		t.Errorf("report = %+v", reports[0].SeedReport)
	}

	// The window opens: staging is visible, and the report is replaced (not
	// merged) by the next heartbeat.
	provConn.SetSeedReport("aabbccdd", true, "11223344")
	reports = srv.NodeSeedReports()
	if len(reports) != 1 || !reports[0].Staged || reports[0].StagedGeneration != "11223344" {
		t.Fatalf("staged report = %+v", reports)
	}

	// A second prov instance sorts by node id (stable output for tooling).
	prov2 := newTestConn("prov-2")
	srv.mu.Lock()
	srv.nodes["prov-2"] = prov2
	srv.mu.Unlock()
	prov2.SetSeedReport("aabbccdd", false, "")
	reports = srv.NodeSeedReports()
	if len(reports) != 2 || reports[0].NodeID != "prov-1" || reports[1].NodeID != "prov-2" {
		t.Fatalf("reports = %+v, want prov-1 then prov-2", reports)
	}
}

// A closed connection's stale report must not feed the convergence view: the
// gate blocks on what it sees, and a connection already dropped is exactly the
// instance whose generation can no longer be trusted.
func TestNodeSeedReportsSkipsClosedConnection(t *testing.T) {
	srv := NewServer("gw", nil, 8, 0)
	conn := newTestConn("prov-1")
	conn.SetSeedReport("aabbccdd", false, "")
	srv.mu.Lock()
	srv.nodes["prov-1"] = conn
	srv.mu.Unlock()

	if got := srv.NodeSeedReports(); len(got) != 1 {
		t.Fatalf("live report missing: %+v", got)
	}
	conn.Close()
	if got := srv.NodeSeedReports(); len(got) != 0 {
		t.Fatalf("closed connection still reported %+v, want none", got)
	}
}

// The seed report is a prov-role fact. The heartbeat handler filters on the
// connection's advertised role, so an exec node (or a legacy no-roles one)
// cannot inject a generation the convergence gate would then block on.
func TestHeartbeatSeedReportRequiresProvRole(t *testing.T) {
	execConn := NewNodeConnection(&pb.NodeHello{NodeId: "exec-1", Version: "v1", Roles: []string{"exec"}}, newFakeStream(), 8)
	legacyConn := newTestConn("legacy-1") // no roles: the legacy exec shape
	provConn := NewNodeConnection(&pb.NodeHello{NodeId: "prov-1", Version: "v1", Roles: []string{"prov"}}, newFakeStream(), 8)

	withGen := &pb.Heartbeat{SeedGeneration: "aabbccdd"}
	empty := &pb.Heartbeat{}

	cases := []struct {
		name string
		conn *NodeConnection
		hb   *pb.Heartbeat
		want bool
	}{
		{"prov with a generation", provConn, withGen, true},
		{"prov with a staged flag only", provConn, &pb.Heartbeat{SeedStaged: true}, true},
		{"exec node reporting a generation", execConn, withGen, false},
		{"legacy no-roles node reporting a generation", legacyConn, withGen, false},
		{"prov with an empty heartbeat", provConn, empty, false},
	}
	for _, tc := range cases {
		if got := seedReportAdmissible(tc.conn, tc.hb); got != tc.want {
			t.Errorf("%s: seedReportAdmissible = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The egress identity-binding mode rides every heartbeat and is projected per
// node in /stats: "none" is the dev/test posture (guest traffic not
// attributable to an agent), "shm"/"bpf"/"routed-ipv6" are the enablers.
func TestNodeEgressBindings(t *testing.T) {
	srv := NewServer("gw-test", silentLogger(), 8, 0)
	conn := newTestConn("node-1")
	conn.SetEgressBinding("bpf")
	srv.mu.Lock()
	srv.nodes["node-1"] = conn
	srv.mu.Unlock()

	got := srv.NodeEgressBindings()
	if len(got) != 1 || got["node-1"] != "bpf" {
		t.Fatalf("bindings = %v, want node-1=bpf", got)
	}

	// The next heartbeat replaces the mode (a live config change is a
	// restart-required flip, but a reconnect with a different config must not
	// leave the stale value).
	conn.SetEgressBinding("none")
	if got := srv.NodeEgressBindings(); got["node-1"] != "none" {
		t.Fatalf("bindings after update = %v, want node-1=none", got)
	}
}
