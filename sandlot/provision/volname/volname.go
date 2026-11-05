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

// Package volname derives the ON-DISK directory name of a sandfs volume from
// the sandfs ID and a deployment-wide seed.
//
// Why the name is not the ID: the virtio-fs share root holds every tenant's
// directory, and the FUSE daemon (sandvmm) is a member of the shared storage
// group — host DAC cannot separate one tenant's directory from another's. Two
// layers keep a compromised daemon out: the root is traversal-only, so it
// cannot LIST the root (2710), and the names are unguessable, so it cannot
// enumerate by brute force either. The ID alone (`sandfs-` + 8 hex) is 32 bits
// of entropy — a local `stat` loop finds *some* tenant of a 10 000-tenant node
// in a few hundred thousand guesses, i.e. well under a second. Deriving the
// name through a keyed hash with a deployment seed makes that search 2^128.
//
// Two properties beyond unguessability are deliberate:
//
//   - DETERMINISTIC: name = f(seed, id) is a pure function, so the prov
//     instance stays idempotent (a retried EnsureVolume computes the same path
//     with no extra state) and the mapping stays RECOVERABLE: given the seed
//     and an ID (from a record, an API response, a customer ticket) the
//     directory can always be found again. A per-volume random name stored in
//     the identity record would make that record the single point of truth.
//   - ROTATABLE: changing the seed re-keys every name, which REVOKES the
//     knowledge a previously compromised daemon accumulated (it remembers the
//     paths it served; a rotation makes all of them stale). See
//     docs/how-it-works/isolation-and-swap.md §4 for the layer it belongs to.
//
// What it does NOT do: it is not access control. If a name leaks — a helper
// process with the path in argv, an info-level log, a record read by an
// attacker — host DAC still allows the access. The seed must also stay out of
// every file the sandvmm identity can read (it is in the PROV config only, and
// that config is scoped root:sandprov 0640 — never group sandlot).
package volname

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// Prefix marks a directory as a sandswap volume for operators (`ls` on the
	// share root). It carries no entropy and is not part of the derivation.
	Prefix = "sf-"

	// nameBytes is the derived entropy: 128 bits (16 bytes). Directory-name
	// length is a non-issue at this size — 26 base32 characters against
	// NAME_MAX 255 and PATH_MAX 4096 (the full path is ~51 bytes, versus 40 for
	// the ID-as-name layout).
	nameBytes = 16

	// domain separates this derivation from any future use of the same seed
	// (a seed reused for another purpose must never produce related output).
	domain = "sandswap/volume-name/v1\x00"

	// minSeedBytes is the smallest acceptable decoded seed. A short seed is a
	// brute-forceable key, which would silently reduce the name entropy to the
	// seed's — refuse it rather than let an operator deploy one.
	minSeedBytes = 32
)

// base32NoPad: 16 bytes -> 26 characters, [a-z2-7]. Lowercase because the name
// shows up in paths, logs and `ls` output; base32 avoids the case-folding and
// separator hazards of base64 on filesystems.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// Derive returns the on-disk directory name for sandfsID under seed.
//
// The result is stable for a given (seed, id) pair and opaque otherwise: it
// reveals neither the ID nor the seed, and two IDs never collide in practice
// (128-bit space).
func Derive(seed []byte, sandfsID string) string {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(domain))
	mac.Write([]byte(sandfsID))
	sum := mac.Sum(nil)[:nameBytes]
	return Prefix + strings.ToLower(base32NoPad.EncodeToString(sum))
}

// DecodeSeed parses a configured seed: hex (>= 64 characters) or standard
// base64 (>= 44 characters). Either encoding is accepted because operators
// generate these with whichever tool is at hand (`openssl rand -hex 32`,
// `head -c 32 /dev/urandom | base64`); what matters is that the decoded value
// is long enough, which ValidateSeed enforces.
func DecodeSeed(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("volume seed is empty")
	}
	if b, err := hex.DecodeString(s); err == nil {
		if err := ValidateSeed(b); err != nil {
			return nil, err
		}
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		if err := ValidateSeed(b); err != nil {
			return nil, err
		}
		return b, nil
	}
	return nil, fmt.Errorf("volume seed is neither hex nor base64")
}

// ValidateSeed enforces the strength floor. The name space is 128 bits, so a
// seed below 256 bits would become the weakest link in a brute-force search —
// and a guessable seed makes every name guessable.
func ValidateSeed(b []byte) error {
	if len(b) < minSeedBytes {
		return fmt.Errorf("volume seed is %d bytes, need at least %d (generate one with: openssl rand -hex 32)", len(b), minSeedBytes)
	}
	return nil
}

// Fingerprint returns a short non-secret identifier for a seed, safe to log,
// to stamp into a volume (see the volume identity stamp) and to show in
// /stats. It must never BE the seed: the seed's secrecy is what the names rest
// on, and a fingerprint is one-way.
func Fingerprint(seed []byte) string {
	sum := sha256.Sum256(seed)
	return hex.EncodeToString(sum[:4])
}

// GenerateSeed returns a fresh 32-byte seed as a hex string, for tooling that
// mints one (deploy scripts, rotation).
func GenerateSeed() string {
	b := make([]byte, minSeedBytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not a recoverable condition for a tool that
		// exists to produce unguessable material.
		panic(fmt.Sprintf("volname: crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}
