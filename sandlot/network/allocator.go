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
// Package network provides pluggable outbound-networking backends for pooled
// Sandswap microVMs. The default backend (BridgeNAT) gives each VM a virtio-net
// TAP enslaved to a host bridge, with kernel NAT and a static guest IP — no
// DHCP daemon, no per-VM process. See vmm.NetworkProvider for the contract.

package network

import (
	"fmt"
	"net"
	"sync"
)

// ipAllocator hands out IPv4 addresses from a subnet, lowest-free first, with
// a free-list of released addresses. It is in-memory and unpersisted: re-adopted
// VMs (which survive a sandlot restart) re-register their IPs via Reserve so the
// allocator won't hand them out again, but that reservation is itself in-memory
// and rebuilt from persisted state at startup (Reclaim).
type ipAllocator struct {
	mu   sync.Mutex
	base net.IP // first allocatable host (gateway+1)
	end  net.IP // broadcast address (exclusive)
	next uint32 // next counter value to try (host-order, base-relative)
	free []net.IP
	used map[uint32]bool // re-adopted/claimed IPs that must not be re-allocated
	// issued records every address this allocator handed out or reserved. A
	// Release for an address that was never issued is ignored: otherwise a
	// caller could inject an arbitrary IP (gateway, broadcast, a foreign
	// subnet) into the free list and have Allocate hand it to the next VM.
	issued map[uint32]bool
}

// newIPAllocator builds an allocator for the given CIDR. The network address,
// the gateway (first host), and the broadcast address are reserved.
func newIPAllocator(cidr *net.IPNet, gateway net.IP) (*ipAllocator, error) {
	ip4 := cidr.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("non-IPv4 subnet %s", cidr.String())
	}
	ones, bits := cidr.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("non-IPv4 mask %s", cidr.String())
	}
	// The gateway must live inside the subnet and be its FIRST host (.1 by
	// convention): the allocator below reserves exactly .0 and .1. A gateway
	// outside the subnet would silently break every guest's default route; a
	// gateway at any other address would eventually be handed to a guest and
	// conflict with the bridge IP. Both are config typos — reject at startup
	// instead of failing per-VM at runtime.
	if !cidr.Contains(gateway) {
		return nil, fmt.Errorf("gateway %s is outside subnet %s", gateway, cidr.String())
	}
	first := make(net.IP, 4)
	copy(first, ip4)
	setU32(first, u32(ip4)+1)
	if !gateway.Equal(first) {
		return nil, fmt.Errorf("gateway %s must be the first host of subnet %s (x.x.x.1): the allocator reserves only the network address and .1", gateway, cidr.String())
	}
	// First allocatable host = gateway + 1 (gateway is .1 by convention).
	base := make(net.IP, 4)
	copy(base, ip4)
	// network address + 2 (skip network .0 and gateway .1)
	setU32(base, u32(ip4)+2)
	// broadcast = network | ^mask ; allocator must not hand it out.
	bcast := make(net.IP, 4)
	maskU := uint32(1<<(32-ones)) - 1
	setU32(bcast, (u32(ip4)&^maskU)|maskU)

	return &ipAllocator{
		base:   base,
		end:    bcast,
		next:   0, // base-relative; first Allocate yields base
		used:   make(map[uint32]bool),
		issued: make(map[uint32]bool),
	}, nil
}

// Allocate returns a free IPv4. It pops the free-list first (skipping any
// Reserved IPs that may have been returned to the free-list), else advances the
// counter from base. Returns an error if the subnet is exhausted.
func (a *ipAllocator) Allocate() (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Pop from the free-list, skipping any IP currently claimed by a
	// re-adopted VM (Reserve may have marked a free-list entry as used).
	for n := len(a.free); n > 0; n = len(a.free) {
		ip := a.free[n-1]
		a.free = a.free[:n-1]
		if !a.used[u32(ip)] {
			a.issued[u32(ip)] = true
			return dup(ip), nil
		}
		// claimed by a re-adopted VM; drop it and keep scanning.
	}
	// Advance the counter until we find an unclaimed address.
	for {
		ip := make(net.IP, 4)
		copy(ip, a.base)
		setU32(ip, u32(a.base)+a.next)
		a.next++
		if u32(ip) >= u32(a.end) {
			return nil, fmt.Errorf("ip allocator exhausted (subnet full)")
		}
		if !a.used[u32(ip)] {
			a.issued[u32(ip)] = true
			return ip, nil
		}
	}
}

// Reserve marks an IP as in-use so Allocate will never hand it out. Used at
// startup to re-claim the IPs of re-adopted VMs whose sandvmm survived a
// sandlot restart. The IP is also removed from the free-list if present.
// Reserve does NOT change `next`; Allocate simply skips reserved IPs.
// Returns false when ip is not an allocatable host of THIS subnet (outside
// [base, broadcast)): a foreign address must never enter the ledger.
func (a *ipAllocator) Reserve(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	v := u32(ip4)
	if v < u32(a.base) || v >= u32(a.end) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.used[v] = true
	a.issued[v] = true
	// Drop it from the free-list if it was sitting there.
	for i, f := range a.free {
		if u32(f) == v {
			a.free = append(a.free[:i], a.free[i+1:]...)
			break
		}
	}
	return true
}

// Release returns an address to the free-list for reuse and clears any Reserve
// claim on it (a released IP is fully available again).
// Only an address this allocator ISSUED (Allocate/Reserve) may be released:
// a Release for a foreign IP is ignored instead of poisoning the free list.
func (a *ipAllocator) Release(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	v := u32(ip4)
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.issued[v] {
		return
	}
	delete(a.issued, v)
	delete(a.used, v)
	a.free = append(a.free, dup(ip))
}

func u32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func setU32(ip net.IP, v uint32) {
	ip[0] = byte(v >> 24)
	ip[1] = byte(v >> 16)
	ip[2] = byte(v >> 8)
	ip[3] = byte(v)
}

func dup(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
