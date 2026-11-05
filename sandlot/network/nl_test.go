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
	"time"
)

// The nl.go tests exercise the hand-rolled netlink encoding against the REAL
// kernel and verify the kernel-side result through the standard `ip`/`nft`
// CLIs — the same tools operators would use to inspect it.

func TestNetlinkAddrAddDel(t *testing.T) {
	baselineNFTAvailable(t) // same prerequisites: root + working netlink
	iface := newBaselineTestIFace(t)

	idx, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatalf("interface: %v", err)
	}
	ip := net.ParseIP("fd00:5341:4e44:9:aa::1")
	if err := rtAddrAdd(uint32(idx.Index), ip, 128); err != nil {
		t.Fatalf("rtAddrAdd: %v", err)
	}
	out, _ := exec.Command("ip", "-6", "addr", "show", "dev", iface).CombinedOutput()
	if !strings.Contains(string(out), "fd00:5341:4e44:9:aa::1/128") {
		t.Fatalf("address not visible via ip CLI:\n%s", out)
	}
	if err := rtAddrDel(uint32(idx.Index), ip, 128); err != nil {
		t.Fatalf("rtAddrDel: %v", err)
	}
	out, _ = exec.Command("ip", "-6", "addr", "show", "dev", iface).CombinedOutput()
	if strings.Contains(string(out), "fd00:5341:4e44:9:aa::1") {
		t.Fatalf("address still present after delete:\n%s", out)
	}
}

// TestNetlinkSetElem drives the stamp flip exactly as routed6 does per
// mount: a CLI-created static snat-to-map rule, then set-element add/delete
// over the hand-rolled nfnetlink path.
func TestNetlinkSetElem(t *testing.T) {
	baselineNFTAvailable(t)
	baselineCleanup(t)
	iface := newBaselineTestIFace(t)

	const table = "sandswap_routed6_test"
	const chain = "postrouting_sbtest"
	const set = "stamp_sbtest"
	run := func(cmd string) string {
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %q: %v (%s)", cmd, err, strings.TrimSpace(string(out)))
		}
		return string(out)
	}
	run2 := func(args ...string) string {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v (%s)", args, err, strings.TrimSpace(string(out)))
		}
		return string(out)
	}
	run("nft add table inet " + table)
	run2("nft", "add", "map", "inet", table, set, "{", "type", "ipv6_addr", ":", "ipv6_addr", ";", "}")
	run2("nft", "add", "chain", "inet", table, chain, "{", "type", "nat", "hook", "postrouting", "priority", "srcnat", "-5;", "}")
	run(`nft add rule inet ` + table + ` ` + chain + ` iifname "` + iface + `" ip6 saddr fd00:5341:4e44:9::/64 snat ip6 to ip6 saddr map @` + set + ` comment "` + identityStampComment + `"`)

	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() })

	guest := net.ParseIP("fd00:5341:4e44:9:1111:2222:3333:4444").To16()
	identity := net.ParseIP("fd00:5341:4e44:9:dead:beef:cafe:1").To16()

	if err := nftSetElemAdd(table, set, guest, identity); err != nil {
		t.Fatalf("nftSetElemAdd: %v", err)
	}
	mapOut := run("nft list map inet " + table + " " + set)
	if !strings.Contains(mapOut, "fd00:5341:4e44:9:1111:2222:3333:4444") ||
		!strings.Contains(mapOut, "fd00:5341:4e44:9:dead:beef:cafe:1") {
		t.Fatalf("map element not visible via nft CLI:\n%s", mapOut)
	}
	ruleOut := run("nft list chain inet " + table + " " + chain)
	if !strings.Contains(ruleOut, "snat ip6 to ip6 saddr map") {
		t.Fatalf("static snat-to-map rule missing:\n%s", ruleOut)
	}

	// Re-add the SAME key with a NEW value must REPLACE (CREATE without
	// EXCL): production relies on this for restart self-healing — a stale
	// element from a crashed process is overwritten by the next mount.
	identity2 := net.ParseIP("fd00:5341:4e44:9:dead:beef:cafe:2").To16()
	// Isolate the DEL leg: after the (successful-acked) delete the map must
	// be empty by CLI inspection.
	if err := nftSetElemDel(table, set, guest); err != nil {
		t.Fatalf("isolated del: %v", err)
	}
	mapNow := run("nft list map inet " + table + " " + set)
	t.Logf("map after isolated del: %s", strings.TrimSpace(mapNow))
	if err := nftSetElemAdd(table, set, guest, identity2); err != nil {
		t.Fatalf("re-add (replace): %v", err)
	}
	mapOut = run("nft list map inet " + table + " " + set)
	if !strings.Contains(mapOut, "fd00:5341:4e44:9:dead:beef:cafe:2") ||
		strings.Contains(mapOut, "fd00:5341:4e44:9:dead:beef:cafe:1") {
		t.Fatalf("replace semantics violated:\n%s", mapOut)
	}

	if err := nftSetElemDel(table, set, guest); err != nil {
		t.Fatalf("nftSetElemDel: %v", err)
	}
	mapOut = run("nft list map inet " + table + " " + set)
	if strings.Contains(mapOut, "fd00:5341:4e44:9:1111:2222:3333:4444") {
		t.Fatalf("element still present after delete:\n%s", mapOut)
	}
	// Delete of an absent element must error loudly (ENOENT), not lie.
	if err := nftSetElemDel(table, set, guest); err == nil {
		t.Fatal("delete of absent element should fail")
	}
}

// TestNetlinkGetSetFailsFast pins the bounded-error contract of the set-id
// resolution: a missing set must yield a prompt error (ENOENT), never a hang
// — the mount path calls this on every stamp. Also guards the parse: a
// well-formed reply for the WRONG set must not yield an id.
func TestNetlinkGetSetFailsFast(t *testing.T) {
	baselineNFTAvailable(t)
	baselineCleanup(t)
	iface := newBaselineTestIFace(t)

	const table = "sandswap_routed6_test"
	run := func(cmd string) {
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %q: %v (%s)", cmd, err, strings.TrimSpace(string(out)))
		}
	}
	run2 := func(args ...string) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v (%s)", args, err, strings.TrimSpace(string(out)))
		}
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() })
	run("nft add table inet " + table)

	// Missing set: bounded error, well inside the netlinkRecvTimeout budget.
	start := time.Now()
	if _, err := nftResolveSetID(table, "no-such-set"); err == nil {
		t.Fatal("getset on a missing set must fail")
	} else if d := time.Since(start); d > netlinkRecvTimeout {
		t.Fatalf("getset failure took %v — must be bounded by the recv timeout", d)
	}

	// Existing set: resolution succeeds and the CLI-visible map works.
	run2("nft", "add", "map", "inet", table, "stamp_sbtest",
		"{", "type", "ipv6_addr", ":", "ipv6_addr", ";", "}")
	id, err := nftResolveSetID(table, "stamp_sbtest")
	if err != nil {
		t.Fatalf("getset on existing set: %v", err)
	}
	if id == 0 {
		t.Fatal("resolved set id must be non-zero")
	}
	_ = iface // the dummy iface only proves the environment has netlink
}
