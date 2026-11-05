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

//go:build linux

package network

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestTAPSyscallsRoundTrip exercises the real ioctls/netlink path when the
// test runs with CAP_NET_ADMIN (root); otherwise it skips. This is the only
// place the syscall implementation itself is executed — the provider tests
// stub the function vars.
func TestTAPSyscallsRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root/CAP_NET_ADMIN")
	}
	name := fmt.Sprintf("tap-t%d", os.Getpid()%100000)
	if err := createPersistentTAP(name, uint32(os.Geteuid())); err != nil {
		t.Skipf("TUNSETIFF unavailable in this environment: %v", err)
	}
	defer func() { _ = deletePersistentTAP(name) }()
	if !tapExists(name) {
		t.Fatalf("TAP %s not visible after create", name)
	}
	if err := setTAPMTU(name, guestMTU); err != nil {
		t.Fatalf("setTAPMTU: %v", err)
	}
	if err := setTAPUp(name); err != nil {
		t.Fatalf("setTAPUp: %v", err)
	}
	// Bridge enslavement (SIOCBRADDIF): create a throwaway bridge with the
	// test harness's own `ip` (the production path no longer spawns it), and
	// verify the kernel recorded the master relationship.
	bridge := fmt.Sprintf("br-t%d", os.Getpid()%100000)
	if err := exec.Command("ip", "link", "add", bridge, "type", "bridge").Run(); err == nil {
		defer exec.Command("ip", "link", "del", bridge).Run()
		if err := setTAPMaster(name, bridge); err != nil {
			t.Fatalf("setTAPMaster: %v", err)
		}
		if _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/master", name)); err != nil {
			t.Fatalf("TAP %s has no master after SIOCBRADDIF: %v", name, err)
		}
	} else {
		t.Logf("skipping SIOCBRADDIF check: cannot create a test bridge (%v)", err)
	}
	if err := deletePersistentTAP(name); err != nil {
		t.Fatalf("deletePersistentTAP: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for tapExists(name) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if tapExists(name) {
		t.Fatalf("TAP %s still exists after RTM_DELLINK", name)
	}
}
