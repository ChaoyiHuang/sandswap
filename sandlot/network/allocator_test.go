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
	"net"
	"testing"
)

func mustParseCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipNet
}

// --- newIPAllocator ---

func TestNewIPAllocator(t *testing.T) {
	cidr := mustParseCIDR("10.188.0.0/16")
	gw := net.ParseIP("10.188.0.1")

	a, err := newIPAllocator(cidr, gw)
	if err != nil {
		t.Fatalf("newIPAllocator: %v", err)
	}
	if a == nil {
		t.Fatal("allocator should not be nil")
	}
}

func TestNewIPAllocator_SmallSubnet(t *testing.T) {
	cidr := mustParseCIDR("10.0.0.0/30") // only 2 usable IPs
	gw := net.ParseIP("10.0.0.1")

	a, err := newIPAllocator(cidr, gw)
	if err != nil {
		t.Fatalf("newIPAllocator: %v", err)
	}
	// Should be able to allocate the one remaining IP
	ip, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate from /30: %v", err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("first allocated IP = %v, want 10.0.0.2", ip)
	}
}

// A gateway outside the subnet is a config typo that used to pass silently
// (every guest's default route then pointed nowhere).
func TestNewIPAllocator_GatewayOutsideSubnet(t *testing.T) {
	cidr := mustParseCIDR("10.188.1.0/24")
	gw := net.ParseIP("10.188.2.1") // wrong node's /24

	if _, err := newIPAllocator(cidr, gw); err == nil {
		t.Error("gateway outside subnet must be rejected")
	}
}

// A gateway at anything but the first host (.1) conflicts with the allocator,
// which reserves exactly .0 and .1 — any other gateway address would
// eventually be handed to a guest and collide with the bridge IP.
func TestNewIPAllocator_GatewayNotFirstHost(t *testing.T) {
	cidr := mustParseCIDR("10.188.1.0/24")
	gw := net.ParseIP("10.188.1.254")

	if _, err := newIPAllocator(cidr, gw); err == nil {
		t.Error("gateway at a non-.1 host address must be rejected")
	}
}

// --- Allocate ---

func TestAllocate_Sequential(t *testing.T) {
	cidr := mustParseCIDR("10.188.0.0/24")
	gw := net.ParseIP("10.188.0.1")

	a, err := newIPAllocator(cidr, gw)
	if err != nil {
		t.Fatal(err)
	}

	// First IP should be after gateway
	ip1, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if !ip1.Equal(net.ParseIP("10.188.0.2")) {
		t.Errorf("first IP = %v, want 10.188.0.2", ip1)
	}

	// Second IP should be sequential
	ip2, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if !ip2.Equal(net.ParseIP("10.188.0.3")) {
		t.Errorf("second IP = %v, want 10.188.0.3", ip2)
	}

	// Different IPs
	if ip1.Equal(ip2) {
		t.Error("allocated IPs should be different")
	}
}

func TestAllocate_Exhaustion(t *testing.T) {
	cidr := mustParseCIDR("10.0.0.0/30") // 2 usable: .2 and .3
	gw := net.ParseIP("10.0.0.1")

	a, err := newIPAllocator(cidr, gw)
	if err != nil {
		t.Fatal(err)
	}

	// Allocate the only usable IP
	_, err = a.Allocate()
	if err != nil {
		t.Fatal(err)
	}

	// Next allocation should fail
	_, err = a.Allocate()
	if err == nil {
		t.Error("expected error when IP pool is exhausted")
	}
}

// --- Reserve ---

func TestReserve_SkipsReservedIPs(t *testing.T) {
	cidr := mustParseCIDR("10.188.0.0/24")
	gw := net.ParseIP("10.188.0.1")

	a, err := newIPAllocator(cidr, gw)
	if err != nil {
		t.Fatal(err)
	}

	// Reserve 10.188.0.5
	reserved := net.ParseIP("10.188.0.5")
	a.Reserve(reserved)

	// Allocate 3 IPs — they should skip the reserved one
	ip1, _ := a.Allocate() // .2
	ip2, _ := a.Allocate() // .3
	ip3, _ := a.Allocate() // .4 (skip .5 because it's reserved)

	if ip1.Equal(reserved) || ip2.Equal(reserved) || ip3.Equal(reserved) {
		t.Errorf("reserved IP %v should not be allocated", reserved)
	}
}

// --- Release ---

func TestRelease_ReusesIP(t *testing.T) {
	cidr := mustParseCIDR("10.188.0.0/24")
	gw := net.ParseIP("10.188.0.1")

	a, err := newIPAllocator(cidr, gw)
	if err != nil {
		t.Fatal(err)
	}

	// Allocate an IP
	ip, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}

	// Release it
	a.Release(ip)

	// Allocate again — should get a released IP back
	ip2, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}

	// The released IP should come back (free-list is LIFO)
	if !ip2.Equal(ip) {
		t.Errorf("after Release(%v), Allocate returned %v, want same IP back", ip, ip2)
	}
}

func TestReserveAndRelease(t *testing.T) {
	cidr := mustParseCIDR("10.188.0.0/24")
	gw := net.ParseIP("10.188.0.1")

	a, err := newIPAllocator(cidr, gw)
	if err != nil {
		t.Fatal(err)
	}

	// Reserve .10
	ip := net.ParseIP("10.188.0.10")
	a.Reserve(ip)

	// Allocate should skip .10
	for i := 0; i < 8; i++ {
		allocated, _ := a.Allocate()
		if allocated.Equal(ip) {
			t.Errorf("reserved IP %v should not be allocated", ip)
		}
	}

	// Release .10 back
	a.Release(ip)

	// Now .10 should be available from the free-list
	ip2, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if !ip2.Equal(ip) {
		t.Errorf("after Release(%v), Allocate returned %v, want same IP", ip, ip2)
	}
}

// Reserve only accepts allocatable hosts of THIS subnet; Release only accepts
// addresses the allocator issued.
func TestAllocatorReserveAndReleaseBounds(t *testing.T) {
	cidr := mustParseCIDR("10.188.0.0/24")
	a, err := newIPAllocator(cidr, net.ParseIP("10.188.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"8.8.8.8", "10.187.0.5", "10.188.0.0", "10.188.0.1", "10.188.0.255"} {
		if a.Reserve(net.ParseIP(ip)) {
			t.Fatalf("Reserve(%s) accepted a non-allocatable address", ip)
		}
	}
	if !a.Reserve(net.ParseIP("10.188.0.9")) {
		t.Fatal("Reserve of a valid host refused")
	}

	// Never-issued address: ignored, not added to the free list.
	a.Release(net.ParseIP("8.8.8.8"))
	// Issued address: released and reusable.
	ip, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	a.Release(ip)
	again, err := a.Allocate()
	if err != nil || !again.Equal(ip) {
		t.Fatalf("released issued IP not reused: %v %v", again, err)
	}
}
