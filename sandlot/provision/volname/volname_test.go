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
	"strings"
	"testing"
)

func seed32(t *testing.T, fill byte) []byte {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return b
}

// The derivation is a pure function of (seed, id): the prov instance's
// idempotency and the recoverability of a lost record both rest on this.
func TestDeriveIsDeterministic(t *testing.T) {
	seed := seed32(t, 0xAB)
	a := Derive(seed, "sandfs-3fa9c2e1")
	b := Derive(seed, "sandfs-3fa9c2e1")
	if a != b {
		t.Fatalf("same (seed,id) must derive the same name: %q vs %q", a, b)
	}
	if a == "" || !strings.HasPrefix(a, Prefix) {
		t.Fatalf("derived name must carry the operator prefix: %q", a)
	}
}

// Different seeds and different IDs must not collide: a rotation that produced
// the same name for another tenant would break the isolation it exists for.
func TestDeriveSeparatesSeedsAndIDs(t *testing.T) {
	seed1, seed2 := seed32(t, 1), seed32(t, 2)
	if Derive(seed1, "sandfs-aaaaaaaa") == Derive(seed2, "sandfs-aaaaaaaa") {
		t.Error("different seeds must derive different names for the same id")
	}
	seen := map[string]string{}
	for i := 0; i < 2000; i++ {
		id := "sandfs-" + strings.Repeat("a", i%7) + string(rune('a'+i%26)) + string(rune('0'+i%10)) + string(rune('a'+(i/10)%26)) + string(rune('0'+(i/26)%10)) + string(rune('a'+(i/100)%26)) + string(rune('0'+(i/260)%10)) + string(rune('a'+(i/2600)%10))
		name := Derive(seed1, id)
		if prev, ok := seen[name]; ok && prev != id {
			t.Fatalf("name collision between %q and %q: %q", prev, id, name)
		}
		seen[name] = id
	}
}

// The name must stay filesystem-clean and short: base32 lowercase, digits 2-7,
// no separators, no case-folding hazard.
func TestDerivedNameShape(t *testing.T) {
	name := Derive(seed32(t, 7), "sandfs-deadbeef")
	body := strings.TrimPrefix(name, Prefix)
	if len(body) != 26 {
		t.Errorf("128-bit base32 body must be 26 characters, got %d (%q)", len(body), body)
	}
	for _, r := range body {
		if !((r >= 'a' && r <= 'z') || (r >= '2' && r <= '7')) {
			t.Errorf("unexpected character %q in %q", r, name)
		}
	}
	if strings.ContainsAny(name, "/. ") {
		t.Errorf("name must be a single clean path component: %q", name)
	}
	// Full path length sanity (the share root on a production host is 25 chars;
	// NAME_MAX is 255 and PATH_MAX 4096).
	if len("/var/lib/sandswap/volumes/"+name) > 64 {
		t.Errorf("derived path is longer than expected: %d chars", len("/var/lib/sandswap/volumes/"+name))
	}
}

// A guessable seed makes every name guessable, so the strength floor is part
// of the security contract, not a convenience check.
func TestValidateSeedFloor(t *testing.T) {
	if err := ValidateSeed(make([]byte, 31)); err == nil {
		t.Error("a 31-byte seed must be refused")
	}
	if err := ValidateSeed(make([]byte, 32)); err != nil {
		t.Errorf("a 32-byte seed must be accepted: %v", err)
	}
	for _, s := range []string{"", "abcd", strings.Repeat("aa", 31)} {
		if _, err := DecodeSeed(s); err == nil {
			t.Errorf("DecodeSeed(%q) must fail", s)
		}
	}
}

// Both encodings operators actually use must decode to the same bytes.
func TestDecodeSeedEncodings(t *testing.T) {
	hexSeed := GenerateSeed()
	b, err := DecodeSeed(hexSeed)
	if err != nil {
		t.Fatalf("generated hex seed must decode: %v", err)
	}
	if err := ValidateSeed(b); err != nil {
		t.Fatalf("generated seed must validate: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("generated seed must be 32 bytes, got %d", len(b))
	}
	if GenerateSeed() == hexSeed {
		t.Error("two generated seeds must differ")
	}
}
