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

package handler

import (
	"testing"

	"gateway/identity"
)

// gateReadStore exposes only the two reads recheckLifecycleGate uses. The
// embedded nil Store satisfies the rest of the interface; any other call would
// panic and is not expected here.
type gateReadStore struct {
	identity.Store
	local      *identity.Record
	fresh      *identity.Record
	freshCalls int
}

func (s *gateReadStore) GetSandFS(string) (*identity.Record, error) { return s.local, nil }
func (s *gateReadStore) GetSandFSFresh(string) (*identity.Record, error) {
	s.freshCalls++
	return s.fresh, nil
}

// TestGateActiveActivePathDoesNotReadFresh pins the same rule on the earlier
// gate: an active snapshot is a struct-field compare, no store or etcd read.
func TestGateActiveActivePathDoesNotReadFresh(t *testing.T) {
	active := &identity.Record{ID: "sf", Status: ""}
	st := &gateReadStore{local: active, fresh: active}
	if err := gateActive(st, &ResolvedIdentity{SandfsID: "sf", Status: ""}); err != nil {
		t.Fatalf("active record: %v", err)
	}
	if st.freshCalls != 0 {
		t.Fatalf("active gate performed %d fresh (etcd) reads, want 0", st.freshCalls)
	}
}

// TestGateActiveTransitionUsesFreshRead pins the attach-completion path: a
// non-active snapshot pays exactly one fresh read, and an active fresh record
// clears the gate instead of falsely rejecting a just-attached sandfs.
func TestGateActiveTransitionUsesFreshRead(t *testing.T) {
	detaching := &identity.Record{ID: "sf", Status: identity.SandfsStatusDetaching}
	active := &identity.Record{ID: "sf", Status: ""}
	st := &gateReadStore{local: detaching, fresh: active}
	id := &ResolvedIdentity{SandfsID: "sf", Status: identity.SandfsStatusDetaching}
	if err := gateActive(st, id); err != nil {
		t.Fatalf("attach-completed record: %v", err)
	}
	if st.freshCalls != 1 {
		t.Fatalf("fresh reads = %d, want 1", st.freshCalls)
	}
	if id.Status != "" {
		t.Fatalf("id.Status = %q, want empty after the fresh read", id.Status)
	}
}

// TestRecheckLifecycleGateActivePathDoesNotReadFresh pins the latency rule:
// a normal (active) cold mount re-reads only the LOCAL watch snapshot. The
// linearizable etcd read is reserved for a snapshot that is already
// detaching/detached/deleting.
func TestRecheckLifecycleGateActivePathDoesNotReadFresh(t *testing.T) {
	active := &identity.Record{ID: "sf", Status: ""}
	st := &gateReadStore{local: active, fresh: active}
	id := &ResolvedIdentity{SandfsID: "sf"}
	if err := recheckLifecycleGate(st, id); err != nil {
		t.Fatalf("active record: %v", err)
	}
	if st.freshCalls != 0 {
		t.Fatalf("active cold path performed %d fresh (etcd) reads, want 0", st.freshCalls)
	}
}

// TestRecheckLifecycleGateTransitionUsesFreshRead pins the exceptional path:
// a non-active snapshot pays exactly one fresh read, which either confirms the
// refusal or observes a completed attach and lets the mount proceed.
func TestRecheckLifecycleGateTransitionUsesFreshRead(t *testing.T) {
	detaching := &identity.Record{ID: "sf", Status: identity.SandfsStatusDetaching}
	active := &identity.Record{ID: "sf", Status: ""}

	st := &gateReadStore{local: detaching, fresh: active}
	if err := recheckLifecycleGate(st, &ResolvedIdentity{SandfsID: "sf"}); err != nil {
		t.Fatalf("attach-completed record: %v", err)
	}
	if st.freshCalls != 1 {
		t.Fatalf("fresh reads = %d, want 1", st.freshCalls)
	}

	st = &gateReadStore{local: detaching, fresh: detaching}
	err := recheckLifecycleGate(st, &ResolvedIdentity{SandfsID: "sf"})
	if err == nil {
		t.Fatal("detaching record passed the recheck")
	}
	if st.freshCalls != 1 {
		t.Fatalf("fresh reads = %d, want 1", st.freshCalls)
	}
	_, code, _, _, _, ok := AsResilienceError(err)
	if !ok || code != "SANDFS_NOT_ACTIVE" {
		t.Fatalf("error = %v (code %q), want SANDFS_NOT_ACTIVE", err, code)
	}
}
