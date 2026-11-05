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

package network

import (
	"log"
	"testing"
)

// stubTAPOps replaces the syscall layer with recorders for one test.
type tapRecorder struct {
	created   bool
	createArg struct {
		name  string
		owner uint32
	}
	masterArg struct{ tap, bridge string }
	mtuArg    struct {
		name string
		mtu  int
	}
	upCalled bool
	deleted  string
}

func stubTAPOps(t *testing.T, exists bool) *tapRecorder {
	t.Helper()
	r := &tapRecorder{}
	origCreate, origDelete := createPersistentTAPFn, deletePersistentTAPFn
	origMaster, origMTU, origUp, origExists := setTAPMasterFn, setTAPMTUFn, setTAPUpFn, tapExistsFn
	t.Cleanup(func() {
		createPersistentTAPFn, deletePersistentTAPFn = origCreate, origDelete
		setTAPMasterFn, setTAPMTUFn, setTAPUpFn, tapExistsFn = origMaster, origMTU, origUp, origExists
	})
	createPersistentTAPFn = func(name string, owner uint32) error {
		r.created = true
		r.createArg.name, r.createArg.owner = name, owner
		return nil
	}
	deletePersistentTAPFn = func(name string) error { r.deleted = name; return nil }
	setTAPMasterFn = func(tap, bridge string) error {
		r.masterArg.tap, r.masterArg.bridge = tap, bridge
		return nil
	}
	setTAPMTUFn = func(name string, mtu int) error {
		r.mtuArg.name, r.mtuArg.mtu = name, mtu
		return nil
	}
	setTAPUpFn = func(string) error { r.upCalled = true; return nil }
	tapExistsFn = func(string) bool { return exists }
	return r
}

// The zero-capability VMM attach depends on the TAP being created with the
// sandvmm uid (TUNSETIFF owner match) and the guest MTU pre-applied (the VMM
// skips the CAP_NET_ADMIN SIOCSIFMTU when it already matches). Pin both for
// each backend.
func TestBridgeTAPIsCreatedWithOwnerMtuAndMaster(t *testing.T) {
	r := stubTAPOps(t, false)
	b := &BridgeNAT{bridge: "br-sandswap", tapOwnerUID: 987, logger: log.Default()}
	if err := b.ensureTAP("tap-x"); err != nil {
		t.Fatalf("ensureTAP: %v", err)
	}
	if !r.created || r.createArg.name != "tap-x" || r.createArg.owner != 987 {
		t.Fatalf("create = %+v, want name=tap-x owner=987", r.createArg)
	}
	if r.masterArg.tap != "tap-x" || r.masterArg.bridge != "br-sandswap" {
		t.Fatalf("master = %+v, want tap-x -> br-sandswap", r.masterArg)
	}
	if r.mtuArg.name != "tap-x" || r.mtuArg.mtu != guestMTU {
		t.Fatalf("mtu = %+v, want tap-x %d", r.mtuArg, guestMTU)
	}
	if !r.upCalled {
		t.Fatal("TAP was not brought up")
	}
}

func TestRoutedTAPIsCreatedWithOwnerAndMtu(t *testing.T) {
	r := stubTAPOps(t, false)
	r6 := &RoutedIPv6{tapOwnerUID: 987, logger: log.Default()}
	if err := r6.ensureRoutedTAP("tap-y"); err != nil {
		t.Fatalf("ensureRoutedTAP: %v", err)
	}
	if !r.created || r.createArg.name != "tap-y" || r.createArg.owner != 987 {
		t.Fatalf("create = %+v, want name=tap-y owner=987", r.createArg)
	}
	if r.mtuArg.name != "tap-y" || r.mtuArg.mtu != guestMTU {
		t.Fatalf("mtu = %+v, want tap-y %d", r.mtuArg, guestMTU)
	}
	if !r.upCalled {
		t.Fatal("TAP was not brought up")
	}
}
