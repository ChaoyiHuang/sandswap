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
	"os/exec"
	"strings"
	"testing"
)

// TestBootIIDIsFixedInvalid pins the guest boot sentinel: pooled VMs boot
// with the fixed all-zero IID (`<subnet>::`, the subnet-router anycast form),
// so an unstamped address is recognizably NOT an identity — it must never be
// a random value that could pass for one.
// TestEnsureForwardGuardInstallsVMToVMDeny pins the routed-IPv6 fix: the
// bridge-family vm2vm rule never sees L3-forwarded traffic, so the posture
// must also exist in the inet FORWARD hook.
func TestEnsureForwardGuardInstallsVMToVMDeny(t *testing.T) {
	var batches []string
	restoreRunNFT(t, func(batch string) error {
		batches = append(batches, batch)
		return nil
	})
	r := &RoutedIPv6{baseline: NewBaseline(true)}
	if err := r.ensureForwardGuard(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(batches, "\n")
	if !strings.Contains(joined, "hook forward") {
		t.Fatalf("no inet forward chain installed:\n%s", joined)
	}
	if !strings.Contains(joined, `iifname "tap*" oifname "tap*"`) ||
		!strings.Contains(joined, vm2vmComment) {
		t.Fatalf("no tap→tap drop rule installed:\n%s", joined)
	}

	// Allow posture: no VM-to-VM drop rule may be added (a previous deny
	// window's rule is removed by comment; the list call is real nft, its
	// failure is deliberately ignored). The metadata drop is posture-
	// independent and must still be present.
	batches = nil
	r.baseline = NewBaseline(false)
	if err := r.ensureForwardGuard(); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(batches, "\n")
	if strings.Contains(joined, "add rule inet "+stampTableName+" "+routed6ForwardChain) {
		t.Fatalf("vm_to_vm: allow added a VM-to-VM drop rule:\n%s", joined)
	}
	if !strings.Contains(joined, "add rule inet "+stampTableName+" "+routed6MetadataChain+" ip6 daddr "+v6MetadataAddr+" counter drop") {
		t.Fatalf("the metadata drop must be installed regardless of the VM-to-VM posture:\n%s", joined)
	}
}

// TestStampSnatMatchesTapIngress pins the SNAT direction: postrouting sees the
// guest's packets with iifname = the TAP and oifname = the uplink, so the
// per-TAP identity rewrite must match iifname. An oifname match only ever sees
// host→guest traffic — the stamp never lands on the wire and every Carrier-B
// enforcer either rejects the unstamped egress or attributes it by /64.
func TestStampSnatMatchesTapIngress(t *testing.T) {
	const tap = "tap-0123456789"
	subnet := &net.IPNet{IP: net.ParseIP("fd00:5341:4e44:102::"), Mask: net.CIDRMask(64, 128)}
	batch := stampPlumbingBatch(tap, subnet)
	want := `iifname "` + tap + `" ip6 saddr fd00:5341:4e44:102::/64 snat ip6 to ip6 saddr map @stamp_tap_0123456789`
	if !strings.Contains(batch, want) {
		t.Fatalf("stamp SNAT rule must match the TAP as the ingress interface:\n%s", batch)
	}
	if strings.Contains(batch, "oifname") {
		t.Fatalf("stamp SNAT rule must not match on oifname (it sees the uplink, not the TAP):\n%s", batch)
	}
}

func TestBootIIDIsFixedInvalid(t *testing.T) {
	if bootIID != 0 {
		t.Fatalf("bootIID = %d, want the fixed all-zero sentinel", bootIID)
	}
	sub := &net.IPNet{IP: net.ParseIP("fd00:5341:4e44:102::"), Mask: net.CIDRMask(64, 128)}
	if got := addIID(sub, bootIID).String(); got != "fd00:5341:4e44:102::" {
		t.Fatalf("boot address = %s, want fd00:5341:4e44:102::", got)
	}
}

// TestDeleteStampPlumbing guards against the per-TAP stamp chain/map leak:
// Provision creates one postrouting chain + one SNAT map per TAP, and they do
// NOT die with the interface — Release must delete both or every recycled VM
// leaks a hooked chain into the ruleset (each one still running its iifname
// compare on every postrouting packet).
func TestDeleteStampPlumbing(t *testing.T) {
	baselineNFTAvailable(t)
	tap := "sbtest0"
	cleanup := func() { _ = exec.Command("ip", "link", "del", tap).Run() }
	cleanup()
	if out, err := exec.Command("ip", "link", "add", tap, "type", "dummy").CombinedOutput(); err != nil {
		t.Skipf("dummy iface unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	t.Cleanup(cleanup)
	t.Cleanup(func() { _ = runNFT("delete table inet " + stampTableName + "\n") })

	// Recreate exactly what Provision installs for this tap.
	chain := "postrouting_" + chainNameFor(tap)
	set := "stamp_" + chainNameFor(tap)
	subnet := &net.IPNet{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(64, 128)}
	if err := runNFT(stampPlumbingBatch(tap, subnet)); err != nil {
		t.Fatalf("create stamp plumbing: %v", err)
	}

	if err := deleteTapPlumbing(tap); err != nil {
		t.Fatalf("deleteTapPlumbing: %v", err)
	}
	for _, obj := range []struct{ kind, name string }{{"chain", chain}, {"map", set}} {
		out, err := exec.Command("nft", "list", obj.kind, "inet", stampTableName, obj.name).CombinedOutput()
		if err == nil {
			t.Fatalf("%s %s still present after deleteTapPlumbing", obj.kind, obj.name)
		} else if !strings.Contains(string(out), "No such file") {
			t.Fatalf("list %s %s: %v (%s)", obj.kind, obj.name, err, strings.TrimSpace(string(out)))
		}
	}
	// Idempotent: a second delete (crash-race path) must not error.
	if err := deleteTapPlumbing(tap); err != nil {
		t.Fatalf("deleteTapPlumbing must be idempotent: %v", err)
	}
}

// TestReclaimReplaysRoutedPosture pins the re-adopt replay: a VM whose TAP
// survived a sandlot restart (or an nftables flush) must get its per-TAP
// anti-spoof chain and the shared VM-to-VM posture re-installed before it is
// steered traffic again.
func TestReclaimReplaysRoutedPosture(t *testing.T) {
	var batches []string
	restoreRunNFT(t, func(batch string) error {
		batches = append(batches, batch)
		return nil
	})
	origExists := tapExistsFn
	tapExistsFn = func(string) bool { return true }
	t.Cleanup(func() { tapExistsFn = origExists })

	r, err := NewRoutedIPv6("fd00:5341:4e44::/48", "", nil, NewBaseline(true), nil)
	if err != nil {
		t.Fatalf("NewRoutedIPv6: %v", err)
	}
	const vmID = "pool-medium-2"
	guest := "fd00:5341:4e44:7::"
	spec := vmmSpecForReclaim(vmID, guest)
	spec.NetConfig["mac"] = "02:aa:bb:cc:dd:ee"

	if err := r.Reclaim(t.Context(), vmID, spec); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
	joined := strings.Join(batches, "\n")
	if !strings.Contains(joined, "type filter hook forward priority filter") ||
		!strings.Contains(joined, `iifname "tap*" oifname "tap*" counter drop comment "`+vm2vmComment+`"`) {
		t.Fatalf("Reclaim did not replay the routed VM-to-VM forward guard:\n%s", joined)
	}
	if !strings.Contains(joined, "add rule inet "+stampTableName+" "+routed6MetadataChain+" ip6 daddr "+v6MetadataAddr+" counter drop") {
		t.Fatalf("Reclaim did not replay the v6 metadata drop:\n%s", joined)
	}
	if !strings.Contains(joined, "ether saddr != 02:aa:bb:cc:dd:ee counter drop") ||
		!strings.Contains(joined, "ip6 saddr != "+guest+" counter drop") {
		t.Fatalf("Reclaim did not replay the per-TAP source anti-spoof:\n%s", joined)
	}
	if !strings.Contains(joined, `iifname "`+tapNameFor(vmID)+`" counter drop`) {
		t.Fatalf("Reclaim did not replay the per-TAP guest→host input guard:\n%s", joined)
	}
}

// TestSetVMToVMDenyCoversRouted6 pins the runtime posture swap: with the
// routed-IPv6 backend the inversion must reach the routed6 inet-forward chain,
// not just the bridge-family rule (which never sees L3-forwarded frames).
func TestSetVMToVMDenyCoversRouted6(t *testing.T) {
	var batches []string
	restoreRunNFT(t, func(batch string) error {
		batches = append(batches, batch)
		return nil
	})
	b := NewBaseline(true)
	b.SetRouted6Posture()

	batches = nil
	if err := b.SetVMToVMDeny(false); err != nil {
		t.Fatalf("SetVMToVMDeny(false): %v", err)
	}
	for _, batch := range batches {
		if strings.Contains(batch, "add rule") {
			t.Fatalf("allow posture added a rule:\n%s", batch)
		}
	}

	batches = nil
	if err := b.SetVMToVMDeny(true); err != nil {
		t.Fatalf("SetVMToVMDeny(true): %v", err)
	}
	joined := strings.Join(batches, "\n")
	if !strings.Contains(joined, "add chain inet "+stampTableName+" "+routed6ForwardChain) {
		t.Fatalf("deny posture did not (re)create the routed6 forward chain:\n%s", joined)
	}
	if !strings.Contains(joined, "add rule inet "+stampTableName+" "+routed6ForwardChain+` iifname "tap*" oifname "tap*" counter drop comment "`+vm2vmComment+`"`) {
		t.Fatalf("deny posture did not reach the routed6 chain:\n%s", joined)
	}
}
