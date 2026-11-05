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
	"context"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	"sandlot/vmm"
)

// --- NewBridgeNAT parameter validation ---

func TestNewBridgeNAT_InvalidCIDR(t *testing.T) {
	_, err := NewBridgeNAT("br-sandswap", "not-a-cidr", "10.188.0.1", nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid subnet CIDR")
	}
	if !strings.Contains(err.Error(), `parse subnet "not-a-cidr"`) {
		t.Errorf("error = %q", err.Error())
	}
}

func TestNewBridgeNAT_InvalidGateway(t *testing.T) {
	tests := []string{"", "not-an-ip", "10.188.0.256"}
	for _, gw := range tests {
		_, err := NewBridgeNAT("br-sandswap", "10.188.0.0/16", gw, nil, nil, nil)
		if err == nil {
			t.Fatalf("expected error for gateway %q", gw)
		}
	}
}

func TestNewBridgeNAT_IPv6SubnetRejected(t *testing.T) {
	_, err := NewBridgeNAT("br-sandswap", "2001:db8::/32", "10.188.0.1", nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for IPv6 subnet")
	}
	if !strings.Contains(err.Error(), "non-IPv4 subnet") {
		t.Errorf("error = %q, want non-IPv4 subnet", err.Error())
	}
}

func TestNewBridgeNAT_Success(t *testing.T) {
	dns := []string{"10.188.0.1", "8.8.8.8"}
	b, err := NewBridgeNAT("br-test", "10.188.0.0/16", "10.188.0.1", dns, nil, nil)
	if err != nil {
		t.Fatalf("NewBridgeNAT: %v", err)
	}
	if b.bridge != "br-test" {
		t.Errorf("bridge = %q, want br-test", b.bridge)
	}
	if b.gw.String() != "10.188.0.1" {
		t.Errorf("gw = %v, want 10.188.0.1", b.gw)
	}
	ones, _ := b.subnet.Mask.Size()
	if ones != 16 {
		t.Errorf("subnet prefix = %d, want 16", ones)
	}
	if len(b.dns) != 2 || b.dns[1] != "8.8.8.8" {
		t.Errorf("dns = %v, want %v", b.dns, dns)
	}
	if b.leases == nil || b.taps == nil {
		t.Error("lease/tap maps must be initialized")
	}
}

// --- Provision / Release / Reclaim (host-device paths fail without root) ---

func TestBridgeNAT_Provision_FailsWithoutHostNet(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root environment to exercise the failure path")
	}
	b, err := NewBridgeNAT("br-nope", "10.199.0.0/24", "10.199.0.1", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Provision(context.Background(), "vm-1")
	if err == nil {
		t.Fatal("Provision should fail without root/netlink")
	}
	if !strings.Contains(err.Error(), "create tap") {
		t.Errorf("error = %q, want create tap failure", err.Error())
	}
	// The lease was allocated before the TAP step; it must be recorded.
	if _, ok := b.leases["vm-1"]; !ok {
		t.Error("lease should be recorded before the TAP creation attempt")
	}
}

func TestBridgeNAT_Release_UnknownVM(t *testing.T) {
	b, err := NewBridgeNAT("br-test", "10.188.0.0/16", "10.188.0.1", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Release(context.Background(), "vm-unknown"); err != nil {
		t.Errorf("Release of unknown VM = %v, want nil", err)
	}
}

func TestBridgeNAT_Reclaim(t *testing.T) {
	b, err := NewBridgeNAT("br-test", "10.188.0.0/24", "10.188.0.1", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("invalid_ip_rejected", func(t *testing.T) {
		err := b.Reclaim(context.Background(), "vm-bad", vmm.VMNetSpec{GuestIP: "999.1.2.3"})
		if err == nil || !strings.Contains(err.Error(), "reclaim vm-bad: invalid guest ip") {
			t.Errorf("err = %v, want invalid guest ip", err)
		}
	})

	t.Run("valid_spec_no_tap", func(t *testing.T) {
		spec := vmm.VMNetSpec{GuestIP: "10.188.0.5", NetConfig: map[string]any{}}
		if err := b.Reclaim(context.Background(), "vm-1", spec); err != nil {
			t.Fatalf("Reclaim: %v", err)
		}
		ip, ok := b.leases["vm-1"]
		if !ok || !ip.Equal(net.ParseIP("10.188.0.5")) {
			t.Errorf("lease not recorded: %v", b.leases)
		}
		if _, ok := b.taps["vm-1"]; ok {
			t.Error("tap must not be recorded when spec has none")
		}
		// The reclaimed IP must never be handed out again.
		for i := 0; i < 250; i++ {
			got, _ := b.alloc.Allocate()
			if got.Equal(ip) {
				t.Fatalf("reclaimed IP %v was re-allocated", ip)
			}
		}
	})
}

// --- tapNameFor ---

func TestTapNameFor(t *testing.T) {
	tests := []string{"vm-1", "pool-medium-0", "", strings.Repeat("long-id-", 20)}
	seen := make(map[string]string)
	for _, id := range tests {
		name := tapNameFor(id)
		if !strings.HasPrefix(name, "tap-") {
			t.Errorf("tapNameFor(%q) = %q, missing tap- prefix", id, name)
		}
		if len(name) > 15 {
			t.Errorf("tapNameFor(%q) = %q exceeds ifname limit of 15 chars", id, name)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("tapNameFor collision between %q and %q", prev, id)
		}
		seen[name] = id
	}
	// IDs sharing a long common prefix must still map to distinct names.
	a := tapNameFor("pool-medium-0")
	b := tapNameFor("pool-medium-1")
	if a == b {
		t.Errorf("prefix-sharing IDs collide: both %q", a)
	}
	// Deterministic.
	if again := tapNameFor("vm-1"); again != tapNameFor("vm-1") {
		t.Error("tapNameFor must be deterministic")
	}
}

// --- randomLocalMAC ---

func TestRandomLocalMAC(t *testing.T) {
	re := regexp.MustCompile(`^02:[0-9a-f]{2}(?::[0-9a-f]{2}){4}$`)
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		mac := randomLocalMAC()
		if !re.MatchString(mac) {
			t.Fatalf("randomLocalMAC() = %q, not a locally-administered unicast MAC", mac)
		}
		seen[mac] = true
	}
	if len(seen) < 50 {
		t.Errorf("expected 50 unique MACs across 50 calls, got %d", len(seen))
	}
}

// --- Noop provider ---

func TestNoop(t *testing.T) {
	n := NewNoop()
	ctx := context.Background()

	spec, err := n.Provision(ctx, "vm-1")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if spec.GuestIP != "" {
		t.Errorf("GuestIP = %q, want empty (offline VM)", spec.GuestIP)
	}
	if err := n.Release(ctx, "vm-1"); err != nil {
		t.Errorf("Release: %v", err)
	}
	if err := n.Reclaim(ctx, "vm-1", vmm.VMNetSpec{GuestIP: "10.0.0.2"}); err != nil {
		t.Errorf("Reclaim: %v", err)
	}
}

// Reclaim takes the tap name verbatim from the request (boxout
// protocol / persisted state) and Release later destroys it as ROOT (`ip link
// del`), so a tap that is not the VM's own derived name must be refused by
// name and never recorded — for both providers. The address/subnet ledger
// still reserves for a refused foreign tap (the re-adopt collision guard).
func TestReclaimForeignTapRefused(t *testing.T) {
	const vmID = "vm-owner"

	t.Run("bridge", func(t *testing.T) {
		b, err := NewBridgeNAT("br-test", "10.188.0.0/24", "10.188.0.1", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		foreign := vmm.VMNetSpec{GuestIP: "10.188.0.7", NetConfig: map[string]any{"tap": "eth0"}}
		err = b.Reclaim(context.Background(), vmID, foreign)
		if !errors.Is(err, ErrForeignTap) {
			t.Fatalf("foreign tap: err = %v, want ErrForeignTap", err)
		}
		if _, ok := b.taps[vmID]; ok {
			t.Fatal("foreign tap recorded — Release would `ip link del eth0` as root")
		}
		if _, ok := b.leases[vmID]; !ok {
			t.Error("lease must still be reserved for a refused foreign tap (re-adopt collision guard)")
		}
		own := vmm.VMNetSpec{GuestIP: "10.188.0.8", NetConfig: map[string]any{"tap": tapNameFor(vmID)}}
		if err := b.Reclaim(context.Background(), vmID, own); err != nil {
			t.Fatalf("own tap refused: %v", err)
		}
		if got := b.taps[vmID]; got != tapNameFor(vmID) {
			t.Fatalf("own tap not recorded: %q", got)
		}
	})

	t.Run("routed6", func(t *testing.T) {
		r, err := NewRoutedIPv6("fd00:5341:4e44::/48", "", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		sub, err := r.allocateSubnet()
		if err != nil {
			t.Fatal(err)
		}
		guest := addIID(r.guestSubnet(sub), 0x1111222233334444)

		foreign := vmm.VMNetSpec{
			GuestIP6: guest.String(), Prefix6: 64,
			NetConfig: map[string]any{"tap": "eth0"},
		}
		err = r.Reclaim(context.Background(), vmID, foreign)
		if !errors.Is(err, ErrForeignTap) {
			t.Fatalf("foreign tap: err = %v, want ErrForeignTap", err)
		}
		if _, ok := r.taps[vmID]; ok {
			t.Fatal("foreign tap recorded — Release would `ip link del eth0` as root")
		}
		if got, ok := r.subnets[vmID]; !ok || got != sub {
			t.Fatalf("subnet not reserved despite refusal: %v (want %d)", got, sub)
		}
		own := vmm.VMNetSpec{
			GuestIP6: guest.String(), Prefix6: 64,
			NetConfig: map[string]any{"tap": tapNameFor(vmID)},
		}
		if err := r.Reclaim(context.Background(), vmID, own); err != nil {
			t.Fatalf("own tap refused: %v", err)
		}
		if got := r.taps[vmID]; got != tapNameFor(vmID) {
			t.Fatalf("own tap not recorded: %q", got)
		}
	})
}

// Reclaim is a caller-driven ledger write: addresses outside the configured
// subnet (or the reserved network/gateway/broadcast) and addresses already
// leased to another VM must be refused, never recorded. A Release for a
// never-issued address must not poison the free list.
func TestBridgeNAT_ReclaimSubnetAndDuplicateChecks(t *testing.T) {
	b, err := NewBridgeNAT("br-test", "10.188.0.0/24", "10.188.0.1", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"8.8.8.8", "10.188.1.9", "10.188.0.0", "10.188.0.1", "10.188.0.255"} {
		vmID := "vm-" + strings.NewReplacer(".", "-").Replace(ip)
		if err := b.Reclaim(context.Background(), vmID, vmm.VMNetSpec{GuestIP: ip}); err == nil {
			t.Fatalf("reclaim of non-allocatable ip %s was accepted", ip)
		}
		if _, recorded := b.leases[vmID]; recorded {
			t.Fatalf("refused ip %s was recorded in the lease ledger", ip)
		}
	}

	if err := b.Reclaim(context.Background(), "vm-a", vmm.VMNetSpec{GuestIP: "10.188.0.5"}); err != nil {
		t.Fatalf("first reclaim: %v", err)
	}
	if err := b.Reclaim(context.Background(), "vm-b", vmm.VMNetSpec{GuestIP: "10.188.0.5"}); err == nil {
		t.Fatal("duplicate reclaim of 10.188.0.5 was accepted")
	}
	if _, recorded := b.leases["vm-b"]; recorded {
		t.Fatal("duplicate lease was recorded")
	}

	// A Release for an address this allocator never issued is ignored.
	b.alloc.Release(net.ParseIP("8.8.8.8"))
	for i := 0; i < 300; i++ {
		ip, err := b.alloc.Allocate()
		if err != nil {
			break
		}
		if ip.Equal(net.ParseIP("8.8.8.8")) {
			t.Fatal("foreign address entered the free list via Release")
		}
	}
}
