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
	"strings"
	"testing"

	"sandlot/vmm"
)

// vmmSpecForReclaim builds a minimal VMNetSpec for Reclaim tests.
func vmmSpecForReclaim(vmID, guestIP6 string) vmm.VMNetSpec {
	return vmm.VMNetSpec{
		GuestIP6: guestIP6,
		Prefix6:  64,
		NetConfig: map[string]any{
			// The reclaim tap-ownership rule accepts only the VM's
			// own derived tap name.
			"tap": tapNameFor(vmID),
		},
	}
}

func TestParseIIDTemplate(t *testing.T) {
	tpl, err := ParseIIDTemplate("agent:32,sandfs:32")
	if err != nil {
		t.Fatalf("ParseIIDTemplate: %v", err)
	}
	if got := tpl.String(); got != "agent:32,sandfs:32" {
		t.Fatalf("canonical form = %q", got)
	}
	if len(tpl.fields) != 2 {
		t.Fatalf("fields = %d, want 2", len(tpl.fields))
	}
}

func TestParseIIDTemplateErrors(t *testing.T) {
	for _, bad := range []string{
		"",                                    // empty
		"agent:32,sandfs:16",                  // not exactly 64 bits
		"agent:32,epoch:16,rand:15",           // 63 bits
		"agent:32,epoch:16,rand:17",           // 65 bits
		"agent:32,sandfs:16,epoch:16",         // identity field narrower than 32 — no uniqueness guarantee, never shipped
		"agent:16,epoch:48",                   // same, agent side
		"agent:32,sandfs:32,epoch:1",          // 65 bits
		"agent:32,sandfs:16,epoch:16,rand:",   // missing bits
		"agent:32,sandfs:16,epoch:16,ipv6:48", // unknown field
	} {
		if _, err := ParseIIDTemplate(bad); err == nil {
			t.Errorf("ParseIIDTemplate(%q) should fail", bad)
		}
	}
}

func TestIIBuildDeterministicAndSeparated(t *testing.T) {
	tpl, err := ParseIIDTemplate("agent:32,epoch:32")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	a, err := tpl.Build("agent-0a1b2c3d", "sandfs-11223344", 7)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, _ := tpl.Build("agent-0a1b2c3d", "sandfs-11223344", 7)
	if a != b {
		t.Fatalf("same inputs must build the same IID (rand:0): %d vs %d", a, b)
	}
	c, _ := tpl.Build("agent-0a1b2c3e", "sandfs-11223344", 7)
	if a == c {
		t.Fatalf("different agents must produce different IIDs")
	}
	d, _ := tpl.Build("agent-0a1b2c3d", "sandfs-11223344", 8)
	if a == d {
		t.Fatalf("different epochs must produce different IIDs")
	}
}

// TestIIDTemplateSubsetLayouts pins the supported layouts: identity fields at
// exactly 32 bits (the id suffix width), epoch/rand filling the rest —
// agent+epoch, sandfs+epoch, both ids (deterministic), and rand-padded
// variants. Determinism holds (same inputs ⇒ same IID), and the absent field
// provably does not leak into the address.
func TestIIDTemplateSubsetLayouts(t *testing.T) {
	cases := []struct {
		name string
		tpl  string
	}{
		{"agent+epoch", "agent:32,epoch:32"},
		{"sandfs+epoch", "sandfs:32,epoch:32"},
		{"both ids full width", "agent:32,sandfs:32"},
		{"agent+rand (no epoch)", "agent:32,rand:32"},
		{"agent+epoch+rand pad", "agent:32,epoch:16,rand:16"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tpl, err := ParseIIDTemplate(tc.tpl)
			if err != nil {
				t.Fatalf("ParseIIDTemplate(%q): %v", tc.tpl, err)
			}
			a, err := tpl.Build("agent-0a1b2c3d", "sandfs-11223344", 7)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			// rand-padded layouts draw fresh random bits per build — only
			// rand-free layouts are deterministic.
			if !strings.Contains(tc.tpl, "rand") {
				b, _ := tpl.Build("agent-0a1b2c3d", "sandfs-11223344", 7)
				if a != b {
					t.Fatalf("no-rand layout must be deterministic: %d vs %d", a, b)
				}
			}
			if a == 0 {
				t.Fatal("iid must be non-zero")
			}
		})
	}
	// Per-layout separation: each present field must move the IID.
	tpl, _ := ParseIIDTemplate("agent:32,epoch:32")
	base, _ := tpl.Build("agent-0a1b2c3d", "sandfs-99887766", 7)
	if otherAgent, _ := tpl.Build("agent-0a1b2c3e", "sandfs-99887766", 7); otherAgent == base {
		t.Fatal("agent+epoch layout: different agents must differ")
	}
	if otherEpoch, _ := tpl.Build("agent-0a1b2c3d", "sandfs-99887766", 8); otherEpoch == base {
		t.Fatal("agent+epoch layout: different epochs must differ")
	}
	// The ABSENT sandfs field must not influence the address.
	if withSandfs, _ := tpl.Build("agent-0a1b2c3d", "sandfs-aabbccdd", 7); withSandfs != base {
		t.Fatal("agent+epoch layout: sandfs must not leak into the IID")
	}

	// agent:32,sandfs:32 is the lossless both-identities layout: POSITION is
	// the discriminator — the agent suffix occupies the high 32 bits, the
	// sandfs suffix the low 32, and each moves independently without
	// disturbing the other half. The absent epoch must not leak.
	both, err := ParseIIDTemplate("agent:32,sandfs:32")
	if err != nil {
		t.Fatalf("ParseIIDTemplate(agent:32,sandfs:32): %v", err)
	}
	m1, _ := both.Build("agent-0a1b2c3d", "sandfs-11223344", 0)
	m2, _ := both.Build("agent-0a1b2c3e", "sandfs-11223344", 0)
	m3, _ := both.Build("agent-0a1b2c3d", "sandfs-11223345", 0)
	if m2&0xffffffff != m1&0xffffffff || m2>>32 == m1>>32 {
		t.Fatalf("agent change must move only the HIGH half: %016x vs %016x", m1, m2)
	}
	if m3>>32 != m1>>32 || m3&0xffffffff == m1&0xffffffff {
		t.Fatalf("sandfs change must move only the LOW half: %016x vs %016x", m1, m3)
	}
	if withEpoch, _ := both.Build("agent-0a1b2c3d", "sandfs-11223344", 99); withEpoch != m1 {
		t.Fatalf("epoch must not leak into agent:32,sandfs:32: %016x vs %016x", m1, withEpoch)
	}
}

// TestIIDFieldLayout pins the bit-level layout contract: with
// agent:32,epoch:16,rand:16 the agent suffix occupies bits 32..63 and the
// epoch bits 16..31, in declaration order, most-significant first.
func TestIIDFieldLayout(t *testing.T) {
	tpl, err := ParseIIDTemplate("agent:32,epoch:16,rand:16")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	const epoch = uint64(0x1234)
	iid, err := tpl.Build("agent-0a1b2c3d", "sandfs-11223344", epoch)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := iid >> 32; got != 0x0a1b2c3d {
		t.Fatalf("agent field = %#x, want %#x (raw suffix in bits 32..63)", got, 0x0a1b2c3d)
	}
	if got := (iid >> 16) & 0xFFFF; got != epoch {
		t.Fatalf("epoch field = %#x, want %#x (epoch must occupy bits 16..31)", got, epoch)
	}
	// The absent sandfs field must not leak into the address.
	other, _ := tpl.Build("agent-0a1b2c3d", "sandfs-ffffffff", epoch)
	if other>>16 != iid>>16 {
		t.Fatalf("sandfs must not leak into agent:32,epoch:16,rand:16")
	}
}

// TestIIDDeploymentField pins the deployment-number field: the operator-
// assigned value travels in the template itself ("deployment:16=42"), lands
// in the declared bits unchanged, and two deployments with identical ids but
// different numbers mint different IIDs. Also pins the parse-time guards:
// values fit the declared width, and only deployment accepts a value.
func TestIIDDeploymentField(t *testing.T) {
	tpl, err := ParseIIDTemplate("deployment:16=42,agent:32,epoch:16")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := tpl.String(); got != "deployment:16=42,agent:32,epoch:16" {
		t.Fatalf("canonical form = %q", got)
	}
	const epoch = uint64(0x0007)
	iid, err := tpl.Build("agent-0a1b2c3d", "sandfs-11223344", epoch)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := iid >> 48; got != 42 {
		t.Fatalf("deployment field = %#x, want 0x2a (bits 48..63)", got)
	}
	if got := (iid >> 16) & 0xffffffff; got != 0x0a1b2c3d {
		t.Fatalf("agent field = %#x, want %#x (bits 16..47)", got, 0x0a1b2c3d)
	}
	if got := iid & 0xFFFF; got != epoch {
		t.Fatalf("epoch field = %#x, want %#x (bits 0..15)", got, epoch)
	}
	// Same ids, different deployment number ⇒ different address.
	other, err := ParseIIDTemplate("deployment:16=43,agent:32,epoch:16")
	if err != nil {
		t.Fatalf("parse other: %v", err)
	}
	otherIID, _ := other.Build("agent-0a1b2c3d", "sandfs-11223344", epoch)
	if otherIID == iid {
		t.Fatal("different deployment numbers must produce different IIDs")
	}
	if otherIID>>48 != 43 {
		t.Fatalf("other deployment field = %#x, want 43", otherIID>>48)
	}
	// A deployment field without "=value" is legal (number 0) and canonicalizes
	// without the suffix.
	zero, err := ParseIIDTemplate("deployment:16,agent:32,epoch:16")
	if err != nil {
		t.Fatalf("parse valueless: %v", err)
	}
	if got := zero.String(); got != "deployment:16,agent:32,epoch:16" {
		t.Fatalf("valueless canonical form = %q", got)
	}
	// The absent sandfs and rand fields must not leak (deterministic layout).
	again, _ := tpl.Build("agent-0a1b2c3d", "sandfs-ffffffff", epoch)
	if again != iid {
		t.Fatal("deployment layout must be deterministic and sandfs-free")
	}

	for _, bad := range []string{
		"deployment:16=70000,agent:32,epoch:16", // value does not fit 16 bits
		"deployment:16=x,agent:32,epoch:16",     // non-numeric value
		"agent:32=7,sandfs:32",                  // identity field cannot take a value
		"epoch:16=3,agent:32,epoch:16",          // only deployment is operator-assigned
		"rand:16=3,agent:32,epoch:16",           // same
	} {
		if _, err := ParseIIDTemplate(bad); err == nil {
			t.Errorf("ParseIIDTemplate(%q) should fail", bad)
		}
	}
}

func TestRoutedSubnetMath(t *testing.T) {
	r, err := NewRoutedIPv6("fd00:5341:4e44::/48", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("NewRoutedIPv6: %v", err)
	}
	sub := r.guestSubnet(0x0102)
	want := "fd00:5341:4e44:102::"
	if got := sub.IP.String(); got != want {
		t.Fatalf("subnet(0x0102) = %s, want %s", got, want)
	}
	if sub.String() != want+"/64" {
		t.Fatalf("subnet.String() = %s, want %s/64", sub.String(), want)
	}
	if hw := hostAddr(sub).String(); hw != "fd00:5341:4e44:102::1" {
		t.Fatalf("hostAddr = %s, want fd00:5341:4e44:102::1", hw)
	}
	guest := addIID(sub, 0xdeadbeefcafebabe)
	if guest.String() != "fd00:5341:4e44:102:dead:beef:cafe:babe" {
		t.Fatalf("guest addr = %s", guest.String())
	}
	if !sameNetwork(guest, r.prefix.IP, r.prefixOnes()) {
		t.Fatalf("guest must be inside the site prefix")
	}
}

func TestRoutedPrefixValidation(t *testing.T) {
	if _, err := NewRoutedIPv6("10.0.0.0/8", "", nil, nil, nil); err == nil {
		t.Fatal("v4 prefix must be rejected")
	}
	if _, err := NewRoutedIPv6("fd00::/56", "", nil, nil, nil); err == nil {
		t.Fatal("prefix longer than /48 must be rejected (the IID would overwrite the subnet index)")
	}
	if _, err := NewRoutedIPv6("fd00::/47", "", nil, nil, nil); err == nil {
		t.Fatal("non-multiple-of-8 prefix must be rejected")
	}
	if _, err := NewRoutedIPv6("fd00::/48", "not-a-template", nil, nil, nil); err == nil {
		t.Fatal("bad iid template must be rejected")
	}
}

func TestRoutedSubnetAllocationCycle(t *testing.T) {
	r, err := NewRoutedIPv6("fd00:5341:4e44::/48", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("NewRoutedIPv6: %v", err)
	}
	s1, err := r.allocateSubnet()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	s2, _ := r.allocateSubnet()
	if s1 == s2 {
		t.Fatal("concurrent allocations must not collide")
	}
	r.releaseSubnet(s1)
	s3, _ := r.allocateSubnet()
	if s3 != s1 {
		t.Fatalf("released subnet must be reused first: got %d want %d", s3, s1)
	}
	if s1 == 0 || s2 == 0 {
		t.Fatal("subnet 0 is reserved")
	}
}

func TestReclaimSubnetRecovery(t *testing.T) {
	r, err := NewRoutedIPv6("fd00:5341:4e44::/48", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("NewRoutedIPv6: %v", err)
	}
	const vmID = "pool-medium-1"
	sub, _ := r.allocateSubnet()
	guest := addIID(r.guestSubnet(sub), 0x1111222233334444)
	spec := vmmSpecForReclaim(vmID, guest.String())

	if err := r.Reclaim(t.Context(), vmID, spec); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
	if got := r.subnets[vmID]; got != sub {
		t.Fatalf("reclaimed subnet = %d, want %d (must recover the index from the address)", got, sub)
	}
	// The reclaimed subnet must be RESERVED: a fresh allocation after the
	// restart must never hand the surviving VM's subnet to a new VM (that
	// would collide two hosts' gateway addresses on the box).
	next, err := r.allocateSubnet()
	if err != nil {
		t.Fatalf("allocate after reclaim: %v", err)
	}
	if next == sub {
		t.Fatal("allocator reused a subnet reserved by Reclaim — post-restart collision")
	}
	// A guest outside the site prefix must be rejected.
	bad := vmmSpecForReclaim("other-vm", "2001:db8::1")
	if err := r.Reclaim(t.Context(), "other-vm", bad); err == nil {
		t.Fatal("out-of-prefix reclaim must fail")
	}
}

// TestIIDNonConformingIDFails pins the safe-direction failure mode: an
// identifier without a hex suffix (the generated format is always
// "<prefix>-<8 lowercase hex>") makes Build fail loudly instead of silently
// producing a colliding or zero field — the mount then degrades to unstamped
// egress, which default-deny enforcement treats as unidentified.
func TestIIDNonConformingIDFails(t *testing.T) {
	tpl, err := ParseIIDTemplate("agent:32,epoch:32")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, bad := range []string{"ops-team", "agent-", "agent-xyznot hex", "agent-123456789"} {
		if _, err := tpl.Build(bad, "sandfs-11223344", 7); err == nil {
			t.Fatalf("Build with non-conforming id %q must fail", bad)
		}
	}
	// The canonical shape keeps working, including a bare hex suffix.
	if _, err := tpl.Build("agent-00000001", "sandfs-11223344", 7); err != nil {
		t.Fatalf("canonical id must build: %v", err)
	}
}
