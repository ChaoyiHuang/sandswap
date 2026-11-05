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

package vmm

import (
	"context"
	"fmt"
	"net"
)

// VMNetSpec carries both the host-side sandvmm net device configuration and the
// guest-side static IP parameters that flow to the warden via the kernel
// command line.
//
// A zero VMNetSpec (GuestIP == "" && GuestIP6 == "") means "no network
// device" — the VM stays offline, matching Sandswap's pre-networking behavior.
type VMNetSpec struct {
	// GuestIP is the static IPv4 address for the guest's eth0 ("" = no v4).
	GuestIP string
	// Prefix is the prefix length of GuestIP (e.g. 16 for a /16).
	Prefix int
	// Gateway is the guest's default gateway (the host bridge IP).
	Gateway string
	// GuestIP6 is the static IPv6 address for the guest's eth0 ("" = no v6).
	// The routed-IPv6 backend assigns one per TAP subnet (see
	// docs/how-it-works/egress-enabler.md).
	GuestIP6 string
	// Prefix6 is the prefix length of GuestIP6 (e.g. 64 for a per-TAP /64).
	Prefix6 int
	// Gateway6 is the guest's IPv6 default gateway (the host-side address of
	// the TAP, e.g. <subnet>::1).
	Gateway6 string
	// DNS is the list of nameservers the guest should use.
	DNS []string
	// MAC is the virtio-net MAC address; also passed to the warden so it can
	// locate the guest interface by MAC (robust vs. eth0/enp0sN naming).
	MAC string
	// NetConfig is the sandvmm vm.create "net" entry (tap, mac, mtu, ...).
	NetConfig map[string]any
}

// HasNetwork reports whether the spec carries any guest addressing (v4 or
// v6). A zero spec means the VM is offline.
func (s *VMNetSpec) HasNetwork() bool {
	if s == nil {
		return false
	}
	return s.GuestIP != "" || s.GuestIP6 != ""
}

// Validate enforces the strict grammar of the fields that reach the kernel
// command line. buildCmdline concatenates GuestIP/Gateway/GuestIP6/Gateway6/
// DNS/MAC into `warden.*=` tokens, and the warden splits the cmdline on ASCII
// whitespace (warden/src/config.rs), so a value carrying a space, tab or
// newline injects INDEPENDENT warden parameters (countdown, max exec timeout,
// log level, max_body_len) — from the unprivileged side of the boxout
// protocol. The grammar is the one the sandlot's own network code already
// uses for these fields (net.ParseIP / net.ParseCIDR in
// sandlot/network/{bridge_nat,routed6}.go), never a parallel one; a value
// that does not match is REFUSED by name, never "cleaned" in place.
//
// The empty (offline) spec and a spec with only NetConfig are legitimate.
func (s VMNetSpec) Validate() error {
	if s.GuestIP != "" {
		if ip := net.ParseIP(s.GuestIP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("guest_ip %q is not an IPv4 address", s.GuestIP)
		}
		if s.Prefix < 0 || s.Prefix > 32 {
			return fmt.Errorf("prefix %d out of range 0..32", s.Prefix)
		}
		if ip := net.ParseIP(s.Gateway); ip == nil || ip.To4() == nil {
			return fmt.Errorf("gateway %q is not an IPv4 address", s.Gateway)
		}
	}
	if s.GuestIP6 != "" {
		ip := net.ParseIP(s.GuestIP6)
		if ip == nil || ip.To4() != nil || ip.To16() == nil {
			return fmt.Errorf("guest_ip6 %q is not an IPv6 address", s.GuestIP6)
		}
		if s.Prefix6 < 0 || s.Prefix6 > 128 {
			return fmt.Errorf("prefix6 %d out of range 0..128", s.Prefix6)
		}
		gw := net.ParseIP(s.Gateway6)
		if gw == nil || gw.To4() != nil || gw.To16() == nil {
			return fmt.Errorf("gateway6 %q is not an IPv6 address", s.Gateway6)
		}
	}
	for _, d := range s.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("dns entry %q is not an IP address", d)
		}
	}
	if s.MAC != "" {
		if _, err := net.ParseMAC(s.MAC); err != nil {
			return fmt.Errorf("mac %q is not a MAC address", s.MAC)
		}
	}
	return nil
}

// NetworkProvider provisions outbound networking for pooled microVMs.
//
// Provision runs once per VM, before vm.create. Release runs at teardown.
// Reclaim runs at sandlot startup for a re-adopted VM whose network resources
// (IP/TAP) are still live on the host from before the restart — it registers
// them as in-use WITHOUT touching the host devices (the live sandvmm holds the
// TAP fd; Provision would `ip link del` and destroy it). Release still runs at
// the re-adopted VM's eventual teardown.
//
// Implementations must be safe for concurrent use (multiple VMs are created
// and destroyed concurrently on a node).
//
// The Noop provider returns a zero VMNetSpec to keep VMs offline; the bridge
// provider (bridge + kernel NAT + static guest IP, no DHCP daemon) is the
// default backend. Additional backends (e.g. passt) may be added later.
type NetworkProvider interface {
	Provision(ctx context.Context, vmID string) (VMNetSpec, error)
	Release(ctx context.Context, vmID string) error
	// Reclaim re-registers an existing (still-live) lease for a re-adopted VM
	// so a freshly Provision-ed VM never collides with its IP/TAP. It must NOT
	// create or destroy host devices. spec is the VM's persisted NetSpec.
	Reclaim(ctx context.Context, vmID string, spec VMNetSpec) error
}

// MountGater is an optional NetworkProvider extension receiving the
// mount/unmount transitions for mount-scoped network state — today the
// routed-IPv6 identity stamp, removed here at unmount (the baseline itself
// is deliberately static: no per-mount gate — see
// docs/how-it-works/egress-enabler.md). Implementations must be
// non-blocking on the mount hot path (the strict ordering guarantee comes
// from the process model, not this hook).
type MountGater interface {
	SetMountState(ctx context.Context, vmID string, mounted bool)
}

// IdentityStamper is an optional NetworkProvider extension for the
// identity-in-address pattern (docs/how-it-works/egress-enabler.md): stamp
// the mount's egress with an identity-encoded source address so middleboxes
// can attribute flows statelessly. Called with the mount binding at publish
// time (and with the stamp removed at unmount via MountGater). Like the
// mount gate, implementations must not block the hot path.
type IdentityStamper interface {
	SetMountIdentity(ctx context.Context, vmID, agentID, sandfsID string, epoch uint64)
}
