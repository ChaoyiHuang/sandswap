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

package runtime

import (
	"io"
	"log"
	"slices"
	"testing"
)

// TestResolveVMMGroups pins the k8s sidecar's supplementary-group resolver:
// numeric gids and group names both resolve, duplicates collapse, gid 0 is
// skipped, unresolvable names warn-and-skip, and the API gid is always
// appended.
//
// Deliberate divergence from sandlot/preflight's resolver, pinned here so it
// stays a controlled decision rather than silent drift: the boxout copy does
// NOT refuse the sandprov (volume-seed) group — the k8s sidecar never reads
// the volume-name seed itself (the prov pod owns it), so the refusal that
// guards the embedded shape does not bind here.
func TestResolveVMMGroups(t *testing.T) {
	lg := log.New(io.Discard, "", 0)

	// Mixed spec: numeric, name (root → gid 0, skipped), duplicate, empty token.
	got := ResolveVMMGroups("985, 986,986,, root", 988, lg)
	if len(got) != 3 || !slices.Contains(got, uint32(985)) || !slices.Contains(got, uint32(986)) {
		t.Fatalf("resolved groups = %v, want [985 986 988]", got)
	}
	if got[len(got)-1] != 988 {
		t.Fatalf("api gid must always be appended last, got %v", got)
	}
	if slices.Contains(got, uint32(0)) {
		t.Fatal("gid 0 must never enter the list")
	}

	// Empty spec: the API gid alone.
	if got := ResolveVMMGroups("", 4242, lg); len(got) != 1 || got[0] != 4242 {
		t.Fatalf("empty spec = %v, want [4242]", got)
	}

	// Unresolvable name: warn-and-skip, never an error.
	if got := ResolveVMMGroups("no-such-group-sandswap", 100, lg); len(got) != 1 || got[0] != 100 {
		t.Fatalf("unresolvable name = %v, want [100]", got)
	}

	// The divergence pin: the sandprov group id passes through unscreened
	// (preflight's resolver refuses this; the boxout copy must not grow the
	// refusal silently either — change this test only with the isolation
	// review that owns that decision).
	if got := ResolveVMMGroups("4242", 985, lg); len(got) != 2 {
		t.Fatalf("sandprov group handling changed: %v — this divergence is pinned", got)
	}
}
