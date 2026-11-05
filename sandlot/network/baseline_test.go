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
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// baselineNFTAvailable reports whether this environment can exercise real
// nftables (root + nft binary + kernel netfilter support).
func baselineNFTAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skipf("nft not available: %v", err)
	}
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil {
		t.Skipf("nft not usable here: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

// newBaselineTestIFace creates a throwaway dummy interface to attach a
// baseline chain to (no TUN device needed in tests).
func newBaselineTestIFace(t *testing.T) string {
	t.Helper()
	name := "sbtest0"
	cleanup := func() { _ = exec.Command("ip", "link", "del", name).Run() }
	cleanup()
	if out, err := exec.Command("ip", "link", "add", name, "type", "dummy").CombinedOutput(); err != nil {
		t.Skipf("dummy iface unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	t.Cleanup(cleanup)
	return name
}

// baselineCleanup removes the test's tables after the test.
func baselineCleanup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		_ = exec.Command("nft", "delete", "table", "netdev", baseTableNetdev).Run()
		_ = exec.Command("nft", "delete", "table", "bridge", baseTableBridge).Run()
	})
}

func listChain(t *testing.T, family, table, chain string) string {
	t.Helper()
	out, err := exec.Command("nft", "-a", "list", "chain", family, table, chain).CombinedOutput()
	if err != nil {
		t.Fatalf("list chain %s %s %s: %v (%s)", family, table, chain, err, strings.TrimSpace(string(out)))
	}
	return string(out)
}

func TestBaselineAttachDetach(t *testing.T) {
	baselineNFTAvailable(t)
	baselineCleanup(t)
	iface := newBaselineTestIFace(t)

	b := NewBaseline(true)
	if err := b.EnsureTables(); err != nil {
		t.Fatalf("EnsureTables: %v", err)
	}
	// Idempotent: second call must succeed.
	if err := b.EnsureTables(); err != nil {
		t.Fatalf("EnsureTables (idempotent): %v", err)
	}

	if err := b.AttachTap(iface, "10.188.7.42", "", "02:11:22:33:44:55"); err != nil {
		t.Fatalf("AttachTap: %v", err)
	}
	chain := listChain(t, "netdev", baseTableNetdev, chainNameFor(iface))
	for _, want := range []string{
		"hook ingress device \"" + iface + "\"",
		"policy accept",
		"ip saddr != 10.188.7.42",
		// L2 + ARP-layer anti-spoof: the IP rules never see non-IP frames.
		"ether saddr != 02:11:22:33:44:55",
		"arp saddr ether != 02:11:22:33:44:55",
		"arp saddr ip != 10.188.7.42",
	} {
		if !strings.Contains(chain, want) {
			t.Fatalf("chain missing %q:\n%s", want, chain)
		}
	}
	// The baseline is static: no per-mount rules, no gate churn.
	// IPv6 anti-spoof rule appears when an assigned v6 is given.
	if err := b.DetachTap(iface); err != nil {
		t.Fatalf("DetachTap: %v", err)
	}
	if err := b.AttachTap(iface, "10.188.7.42", "fd00:53:41:4e44:1::42", "02:11:22:33:44:55"); err != nil {
		t.Fatalf("AttachTap v6: %v", err)
	}
	chain = listChain(t, "netdev", baseTableNetdev, chainNameFor(iface))
	if !strings.Contains(chain, "ip6 saddr != fd00:53:41:4e44:1::42") {
		t.Fatalf("v6 anti-spoof rule missing:\n%s", chain)
	}
	if err := b.DetachTap(iface); err != nil {
		t.Fatalf("DetachTap 2: %v", err)
	}
}

func TestBaselineVMToVMPosture(t *testing.T) {
	baselineNFTAvailable(t)
	baselineCleanup(t)

	b := NewBaseline(true) // deny
	if err := b.EnsureTables(); err != nil {
		t.Fatalf("EnsureTables: %v", err)
	}
	if fwd := listChain(t, "bridge", baseTableBridge, "fwdgate"); !strings.Contains(fwd, vm2vmComment) {
		t.Fatalf("deny posture must install the vm2vm rule:\n%s", fwd)
	}
	if err := b.SetVMToVMDeny(false); err != nil {
		t.Fatalf("SetVMToVMDeny(false): %v", err)
	}
	if fwd := listChain(t, "bridge", baseTableBridge, "fwdgate"); strings.Contains(fwd, vm2vmComment) {
		t.Fatalf("allow posture must remove the vm2vm rule:\n%s", fwd)
	}
	if err := b.SetVMToVMDeny(true); err != nil {
		t.Fatalf("SetVMToVMDeny(true): %v", err)
	}
	if fwd := listChain(t, "bridge", baseTableBridge, "fwdgate"); !strings.Contains(fwd, vm2vmComment) {
		t.Fatalf("re-enabled deny must reinstall the vm2vm rule:\n%s", fwd)
	}
}

// TestBaselineVMToVMRuleNotDuplicated pins the re-sync semantics: nftables
// allows duplicate identical rules, so repeated EnsureTables (every TAP
// attach) must converge to EXACTLY ONE deny rule, never stack copies.
func TestBaselineVMToVMRuleNotDuplicated(t *testing.T) {
	baselineNFTAvailable(t)
	baselineCleanup(t)

	b := NewBaseline(true)
	for i := 0; i < 4; i++ {
		if err := b.EnsureTables(); err != nil {
			t.Fatalf("EnsureTables #%d: %v", i, err)
		}
	}
	fwd := listChain(t, "bridge", baseTableBridge, "fwdgate")
	if n := strings.Count(fwd, vm2vmComment); n != 1 {
		t.Fatalf("vm2vm rule count = %d after 4 syncs, want 1:\n%s", n, fwd)
	}
}

// TestBaselineAllowFromClean pins the allow posture on a FRESH host: with
// vm_to_vm=allow and no deny rule ever installed, EnsureTables (called by
// every AttachTap) must succeed — the allow path's deleteRuleByComment found
// nothing to remove, which used to surface as a hard error and fail ALL
// network provisioning under baseline-on + allow.
func TestBaselineAllowFromClean(t *testing.T) {
	baselineNFTAvailable(t)
	baselineCleanup(t)

	b := NewBaseline(false) // allow posture from a clean slate
	if err := b.EnsureTables(); err != nil {
		t.Fatalf("EnsureTables (allow, clean): %v", err)
	}
	if err := b.EnsureTables(); err != nil {
		t.Fatalf("EnsureTables (allow, idempotent): %v", err)
	}
}

// TestAttachTapChainEEXISTRecovery pins the EEXIST-recovery path: a chain
// left over from a crashed prior run of the same vmID must be deleted and the
// batch replayed — inline, not via a recursive AttachTap call (the historical
// recursion re-locked the non-reentrant b.mu and self-deadlocked, wedging all
// network provisioning on the node).
func TestAttachTapChainEEXISTRecovery(t *testing.T) {
	orig := runNFT
	defer func() { runNFT = orig }()

	var batches []string
	runNFT = func(batch string) error {
		batches = append(batches, batch)
		if strings.Contains(batch, "chain tap_test0 {") && len(batches) == 1 {
			// First chain-install attempt: the chain survived a crashed run.
			return fmt.Errorf("nft batch: exit status 1 (Error: File exists)")
		}
		return nil
	}

	b := NewBaseline(true)
	err := b.attachTapChainLocked(chainNameFor("tap-test0"), "tap-test0", "10.0.0.5", "fd00::5", "02:aa:bb:cc:dd:ee")
	if err != nil {
		t.Fatalf("attachTapChainLocked EEXIST recovery failed: %v", err)
	}
	if len(batches) != 3 {
		t.Fatalf("runNFT called %d times, want 3 (install, delete-chain, replay): %+q", len(batches), batches)
	}
	if !strings.Contains(batches[1], "delete chain netdev sandswap_baseline tap_test0") {
		t.Errorf("recovery batch 2 = %q, want the delete-chain", batches[1])
	}
	if batches[2] != batches[0] {
		t.Errorf("recovery batch 3 must replay the original install batch verbatim")
	}
}

// attachTapChainLocked must refuse to interpolate a malformed MAC into an
// nft batch (the batch is a format template — a crafted "mac" is an nft
// injection channel), and an EMPTY mac must skip the ether/arp rules rather
// than emit a vacuous `!= ""` that drops nothing (or everything).
func TestAttachTapMACValidation(t *testing.T) {
	orig := runNFT
	defer func() { runNFT = orig }()
	var batches []string
	runNFT = func(batch string) error {
		batches = append(batches, batch)
		return nil
	}

	b := NewBaseline(true)
	for _, bad := range []string{"02-11-22-33-44-55", "02:11:22:33:44", "02:11:22:33:44:5g", "ether saddr x; table inet y"} {
		err := b.attachTapChainLocked(chainNameFor("tap-x"), "tap-x", "10.0.0.5", "", bad)
		if err == nil {
			t.Fatalf("malformed mac %q must be refused", bad)
		}
	}

	batches = nil
	if err := b.attachTapChainLocked(chainNameFor("tap-y"), "tap-y", "10.0.0.5", "", ""); err != nil {
		t.Fatalf("empty mac must be accepted (rules skipped): %v", err)
	}
	if len(batches) != 1 {
		t.Fatalf("one batch expected, got %d", len(batches))
	}
	// Empty mac skips the two MAC-keyed rules; the ip-keyed ones stay.
	if strings.Contains(batches[0], "ether saddr != ") || strings.Contains(batches[0], "arp saddr ether") {
		t.Fatalf("empty mac must skip the MAC-keyed rules:\n%s", batches[0])
	}
	if !strings.Contains(batches[0], "ip saddr != 10.0.0.5") {
		t.Fatalf("ip anti-spoof rule must survive the empty-mac form:\n%s", batches[0])
	}

	batches = nil
	if err := b.attachTapChainLocked(chainNameFor("tap-z"), "tap-z", "10.0.0.5", "", "02:11:22:33:44:55"); err != nil {
		t.Fatalf("valid mac rejected: %v", err)
	}
	for _, want := range []string{
		"ether saddr != 02:11:22:33:44:55 counter drop",
		"arp saddr ether != 02:11:22:33:44:55 counter drop",
		"arp saddr ip != 10.0.0.5 counter drop",
	} {
		if !strings.Contains(batches[0], want) {
			t.Fatalf("batch missing %q:\n%s", want, batches[0])
		}
	}
}

// Bridge/NAT guests have no pinned IPv6 identity: every IPv6 frame must be
// dropped at the tap. Without this, a guest's correct MAC carried any spoofed
// v6 source past the baseline (the ip6 rule was installed only when an
// address was assigned, and the bridge backend passes "").
func TestAttachTapChainDropsV6WhenNoAddressIsPinned(t *testing.T) {
	orig := runNFT
	defer func() { runNFT = orig }()
	var batch string
	runNFT = func(b string) error { batch = b; return nil }

	b := &Baseline{}
	if err := b.attachTapChainLocked(chainNameFor("tap-v6"), "tap-v6", "10.0.0.5", "", "02:aa:bb:cc:dd:ee"); err != nil {
		t.Fatalf("attachTapChainLocked: %v", err)
	}
	if !strings.Contains(batch, "ether type ip6 counter drop") {
		t.Fatalf("missing IPv6 drop when no v6 identity is pinned:\n%s", batch)
	}

	// Control: an assigned v6 address keeps the source-pin rule (and does not
	// get the blanket drop).
	runNFT = func(b string) error { batch = b; return nil }
	if err := b.attachTapChainLocked(chainNameFor("tap-v6b"), "tap-v6b", "10.0.0.5", "fd00::5", "02:aa:bb:cc:dd:ee"); err != nil {
		t.Fatalf("attachTapChainLocked: %v", err)
	}
	if !strings.Contains(batch, "ip6 saddr != fd00::5 counter drop") {
		t.Fatalf("missing IPv6 source pin for the assigned address:\n%s", batch)
	}
	if strings.Contains(batch, "ether type ip6 counter drop") {
		t.Fatalf("the blanket v6 drop must not be installed when an address is pinned:\n%s", batch)
	}
}

// The ingress chain starts with an explicit ethertype whitelist and, for the
// routed-IPv6 backend (no IPv4 identity), drops IPv4 and ARP outright: tagged
// (0x8100) and QinQ (0x88a8) frames never reach the L3 source pins, and a
// v6-only guest has no legitimate v4/ARP traffic.
func TestAttachTapEthertypeWhitelistAndV6OnlyDrops(t *testing.T) {
	orig := runNFT
	defer func() { runNFT = orig }()
	var batches []string
	runNFT = func(batch string) error {
		batches = append(batches, batch)
		return nil
	}

	b := NewBaseline(true)
	// Routed-IPv6 shape: ip4 empty, ip6 pinned.
	if err := b.attachTapChainLocked(chainNameFor("tap-v6"), "tap-v6", "", "fd00:5341:4e44:1::42", "02:11:22:33:44:55"); err != nil {
		t.Fatalf("attach: %v", err)
	}
	batch := batches[0]
	if !strings.Contains(batch, "ether type != { ip, arp, ip6 } counter drop") {
		t.Fatalf("explicit ethertype whitelist missing:\n%s", batch)
	}
	if !strings.Contains(batch, "ether type ip counter drop") || !strings.Contains(batch, "ether type arp counter drop") {
		t.Fatalf("v6-only tap must drop IPv4 and ARP:\n%s", batch)
	}
	if strings.Contains(batch, "ip saddr != ") {
		t.Fatalf("v6-only tap must not carry an IPv4 source pin:\n%s", batch)
	}
	if !strings.Contains(batch, "ip6 saddr != fd00:5341:4e44:1::42") {
		t.Fatalf("v6 source pin missing:\n%s", batch)
	}

	// Bridge/v4 shape keeps IPv4 + ARP and adds no blanket v4 drop.
	batches = nil
	if err := b.attachTapChainLocked(chainNameFor("tap-v4"), "tap-v4", "10.0.0.5", "", "02:11:22:33:44:55"); err != nil {
		t.Fatalf("attach v4: %v", err)
	}
	v4 := batches[0]
	if strings.Contains(v4, "ether type ip counter drop") || strings.Contains(v4, "ether type arp counter drop") {
		t.Fatalf("v4-backed tap must not blanket-drop IPv4/ARP:\n%s", v4)
	}
	if !strings.Contains(v4, "ip saddr != 10.0.0.5") || !strings.Contains(v4, "arp saddr ip != 10.0.0.5") {
		t.Fatalf("v4 source pins missing:\n%s", v4)
	}
}

// The per-TAP chain drops the cloud instance-metadata endpoints: reaching them
// through host forwarding hands the guest the NODE's credentials. The rule must
// be present in both backend shapes (v4-pinned and v6-only) — host prep owns
// the same drop in the shared forward chain, this is the sandlot-side depth.
func TestAttachTapDropsCloudMetadata(t *testing.T) {
	orig := runNFT
	t.Cleanup(func() { runNFT = orig })
	var batch string
	runNFT = func(b string) error { batch = b; return nil }

	b := &Baseline{}
	if err := b.attachTapChainLocked(chainNameFor("tap-md"), "tap-md", "10.0.0.5", "", "02:aa:bb:cc:dd:ee"); err != nil {
		t.Fatalf("attachTapChainLocked: %v", err)
	}
	for _, want := range []string{"169.254.0.0/16", "100.100.100.200", "169.254.170.2", "counter drop"} {
		if !strings.Contains(batch, want) {
			t.Fatalf("v4 tap chain missing the metadata drop component %q:\n%s", want, batch)
		}
	}

	batch = ""
	if err := b.attachTapChainLocked(chainNameFor("tap-md6"), "tap-md6", "", "fd00::5", ""); err != nil {
		t.Fatalf("attachTapChainLocked v6-only: %v", err)
	}
	if !strings.Contains(batch, "169.254.0.0/16") {
		t.Fatalf("v6-only tap chain must still carry the v4 metadata drop:\n%s", batch)
	}
}
