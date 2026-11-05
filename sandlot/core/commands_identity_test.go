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

package core

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	commonconfig "common/config"
	pb "common/proto/stream"
)

// The warden assertion for a file op must be the REQUEST's volume, and it
// must be the ALIAS recorded for that volume. There is deliberately no
// basename fallback: the real volume name is a host-side secret, and an
// unrecorded identity means the mount state is unproven (the handler refuses
// the op; the warden also refuses an empty identity).
func TestFileOpIdentityUsesOnlyTheRequestVolume(t *testing.T) {
	state := &VMState{Volumes: map[string]struct{}{"/var/lib/sandswap/volumes/sf-b": {}}}
	h := &Handler{}

	if got := h.fileOpIdentity("/var/lib/sandswap/volumes/sf-a", state); got != "" {
		t.Fatalf("an unmounted request volume must yield no identity (no basename fallback), got %q", got)
	}
	if got := h.fileOpIdentity("", state); got != "" {
		t.Fatalf("an empty request field must yield no identity (refused by the handler), got %q", got)
	}

	// A recorded alias is asserted only for the volume it was recorded for;
	// it is never borrowed for a different volume (that would let the warden
	// confirm the wrong export).
	state.mountIdentity = "00112233445566778899aabbccddeeff"
	state.mountIdentityPath = "/var/lib/sandswap/volumes/sf-a"
	if got := h.fileOpIdentity("/var/lib/sandswap/volumes/sf-a", state); got != state.mountIdentity {
		t.Fatalf("alias identity for the mounted volume = %q, want %q", got, state.mountIdentity)
	}
	if got := h.fileOpIdentity("/var/lib/sandswap/volumes/sf-b", state); got != "" {
		t.Fatalf("an alias recorded for sf-a leaked into sf-b's identity: %q", got)
	}
}

// The superseded-generation predicate used before every dirty-destroy: a
// request whose mount generation moved, or whose sandfs is no longer bound to
// this VM, must fail itself — the VM may already be serving another tenant.
// Only the current generation with the same binding may fail closed by
// destroying the VM.
func TestMountSuperseded(t *testing.T) {
	st := &VMState{}
	h := &Handler{
		vms:      map[string]*VMState{"vm-1": st},
		bindings: newBindingStore(),
	}
	h.bindSandfs("sandfs-1", "vm-1")

	gen := st.mountGen.Load()
	if h.mountSuperseded(st, "sandfs-1", gen) {
		t.Fatal("current generation + same binding must not be superseded")
	}

	st.mountGen.Add(1)
	if !h.mountSuperseded(st, "sandfs-1", gen) {
		t.Fatal("a moved mount generation must be superseded")
	}

	gen = st.mountGen.Load()
	h.bindSandfs("sandfs-1", "vm-2")
	if !h.mountSuperseded(st, "sandfs-1", gen) {
		t.Fatal("a rebinding to another VM must be superseded")
	}

	// Unbound (released) sandfs: vmForSandfs returns nil, so the request can
	// no longer prove it owns the VM's mount — fail it alone.
	if !h.mountSuperseded(st, "sandfs-unbound", gen) {
		t.Fatal("an unbound sandfs must be superseded, never destroy the VM")
	}
}

// The mount alias is 32 lowercase hex characters, fresh per generation, and
// encodes no part of the seed-derived volume name.
func TestNewMountAliasFormatAndUniqueness(t *testing.T) {
	a, err := newMountAlias()
	if err != nil {
		t.Fatalf("newMountAlias: %v", err)
	}
	b, err := newMountAlias()
	if err != nil {
		t.Fatalf("newMountAlias: %v", err)
	}
	if len(a) != 32 {
		t.Fatalf("mount alias %q must be 32 hex characters", a)
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatalf("mount alias %q is not hex: %v", a, err)
	}
	if a == b {
		t.Fatalf("two generations produced the same alias %q", a)
	}
}

// length <= 0 means "read up to the cap" at the warden; it must be normalized
// to the explicit single-op cap at the wire gate so the response plus the
// envelope stays under the gRPC message limit.
func TestNormalizeFileOpLengthClampsTheDefaultToTheWireCap(t *testing.T) {
	cap := int64(maxFileOpDataBytes)
	for _, in := range []int64{0, -1, -1 << 40} {
		n := in
		normalizeFileOpLength(&n)
		if n != cap {
			t.Fatalf("length %d must normalize to the cap %d, got %d", in, cap, n)
		}
	}
	n := int64(123)
	normalizeFileOpLength(&n)
	if n != 123 {
		t.Fatalf("an explicit in-range length must be preserved, got %d", n)
	}
}

// The reply-leg guard converts an at/over-limit payload into a named app
// error instead of forwarding it (a forwarded oversize reply resets the
// shared node stream and kills every co-tenant in-flight command).
func TestFileOpResponseWireBoundary(t *testing.T) {
	if fileOpResponseTooLarge(maxFileOpDataBytes) {
		t.Fatal("a payload at the cap fits (the cap already reserves envelope slack)")
	}
	if !fileOpResponseTooLarge(maxFileOpDataBytes + 1) {
		t.Fatal("a payload past the cap must be refused")
	}
}

// The sandlot's own wire gate refuses a >PATH_MAX path before touching a VM
// (the gateway gate already does; this is the node-side backstop). It is an
// app-level refusal — a client error must never trigger VM cleanup.
func TestHandleFileOpRejectsAnOversizedPath(t *testing.T) {
	h := newCoreTestHandler()
	long := strings.Repeat("a", commonconfig.MaxFilePathBytes+1)
	resp := h.handleFileOp(context.Background(), &pb.VMCommand{CommandId: "c1"}, &pb.FileOp{
		VolumeMode: "flat",
		SandfsId:   "sfs-1", VolumePath: "/vol/a", Action: "stat", Path: long,
	})
	if !resp.Success || resp.ErrorCode != "FILE_PATH_TOO_LONG" {
		t.Fatalf("oversized path: got %+v, want Success=true with FILE_PATH_TOO_LONG", resp)
	}
}
