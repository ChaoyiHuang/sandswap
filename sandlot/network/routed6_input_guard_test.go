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
	"strings"
	"testing"
)

// The routed-IPv6 per-TAP guard must drop by INTERFACE, not by the guest's
// source prefix: a forged source outside the assigned /64 (reachable once the
// guest kernel is compromised) would otherwise reach host listeners. This pins
// the batch text so a future edit cannot reintroduce the prefix match.
func TestRoutedTapInputGuardDropsByInterface(t *testing.T) {
	orig := runNFT
	t.Cleanup(func() { runNFT = orig })
	var batches []string
	runNFT = func(batch string) error {
		batches = append(batches, batch)
		return nil
	}

	subnet := &net.IPNet{IP: net.ParseIP("fd00:1234::"), Mask: net.CIDRMask(64, 128)}
	if err := ensureTapInputGuard("tap-x", subnet); err != nil {
		t.Fatalf("ensureTapInputGuard: %v", err)
	}
	all := strings.Join(batches, "\n")
	if !strings.Contains(all, `iifname "tap-x" counter drop`) {
		t.Fatalf("guard batch lacks the interface-scoped drop:\n%s", all)
	}
	if strings.Contains(all, "ip6 saddr") {
		t.Fatalf("guard still matches by source prefix (a forged source can bypass it):\n%s", all)
	}
	// The allows must precede the drop in the same chain, or DNS/NDP die.
	if strings.Index(all, "udp dport 53 accept") > strings.Index(all, `iifname "tap-x" counter drop`) {
		t.Fatalf("drop rule precedes the DNS allow:\n%s", all)
	}
}
