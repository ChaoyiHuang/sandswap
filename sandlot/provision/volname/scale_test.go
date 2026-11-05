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

package volname

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

// TestDeriveScaleUniformity is the OPT-IN scale check: it derives millions of
// names and verifies zero collisions plus distribution sanity. Run it with
//
//	VOLNAME_SCALE=10000000 go test ./sandlot/provision/volname/ -run Scale -v
//
// What it can and cannot prove, stated so nobody misreads a green run:
//
//   - It CANNOT prove the collision bound. That bound is the birthday bound on
//     a 128-bit space — expected colliding pairs N(N-1)/2^129, i.e. 1.5e-27 at
//     one million volumes and 1.5e-21 at a billion. No empirical run at any
//     feasible N can demonstrate a probability that small.
//   - It CAN catch implementation defects that a small run misses: a truncated
//     or non-uniform derivation, a biased base32 encoder, or a name-space
//     smaller than advertised. Those are the realistic ways this could break.
//
// The distribution checks are concrete: every one of the 26 characters must
// use the full alphabet, except the LAST one, which carries the remaining 3
// bits of the 128 (128 = 25*5 + 3) and therefore uses exactly 8 symbols.
func TestDeriveScaleUniformity(t *testing.T) {
	n := 1 << 20
	if v := os.Getenv("VOLNAME_SCALE"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 1 {
			t.Fatalf("VOLNAME_SCALE=%q is not a positive integer", v)
		}
		n = parsed
	} else {
		t.Skip("opt-in scale check: set VOLNAME_SCALE=<count> (e.g. 10000000)")
	}

	seed := seed32(t, 0x5A)
	seen := make(map[string]struct{}, n)
	firstByte := make([]int, 256)
	charUse := make([][32]int, 26) // index by alphabet position
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"

	collisions := 0
	for i := 0; i < n; i++ {
		// IDs in the real shape: sandfs- + 8 hex, enumerated densely (worst
		// case for a weak derivation: sequential inputs).
		id := fmt.Sprintf("sandfs-%08x", i)
		name := Derive(seed, id)
		if _, dup := seen[name]; dup {
			collisions++
			continue
		}
		seen[name] = struct{}{}
		body := name[len(Prefix):]
		firstByte[body[0]]++
		for pos, c := range body {
			idx := indexByte(alphabet, byte(c))
			if idx < 0 {
				t.Fatalf("name %q has a character outside the base32 alphabet", name)
			}
			charUse[pos][idx]++
		}
	}
	if collisions != 0 {
		t.Errorf("%d collisions in %d names (space 2^128 — an implementation bug, not chance)", collisions, n)
	}

	// First-character distribution: 26 base32 characters at 10 bits each is
	// not a byte-wise uniform split, so compare against the observed maximum
	// deviation from the mean instead of an exact per-byte expectation.
	mean := float64(n) / 32.0
	maxDev := 0.0
	for pos := 0; pos < 25; pos++ { // the first 25 characters use all 32 symbols
		for _, cnt := range charUse[pos] {
			dev := abs(float64(cnt)-mean) / mean
			if dev > maxDev {
				maxDev = dev
			}
		}
		for sym, cnt := range charUse[pos] {
			_ = sym
			if cnt == 0 {
				t.Errorf("character position %d never used symbol %q — the alphabet is not fully exercised", pos, alphabet[sym])
			}
		}
	}
	lastUsed := 0
	for _, cnt := range charUse[25] {
		if cnt > 0 {
			lastUsed++
		}
	}
	if lastUsed != 8 {
		t.Errorf("last character uses %d symbols, want exactly 8 (128 = 25*5 + 3 bits)", lastUsed)
	}

	// A deviation of a few percent is sampling noise at these counts; a real
	// bias (truncation, modulo, a broken encoder) shows up as tens of percent.
	if maxDev > 0.05 {
		t.Errorf("character distribution deviates %.1f%% from uniform — the derivation is biased", maxDev*100)
	}
	t.Logf("scale check: %d names, 0 collisions, max per-symbol deviation %.2f%%, last-char symbols %d",
		n, maxDev*100, lastUsed)
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
