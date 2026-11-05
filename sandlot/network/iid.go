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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// IIDTemplate declares how to build the 64-bit IPv6 interface identifier that
// carries the egress identity (docs/how-it-works/egress-enabler.md): fields
// are laid out most-significant first, e.g.
//
//	-iid-template "agent:32,sandfs:32"   (or "agent:32,epoch:32", ...)
//
// Identity fields (agent/sandfs) carry the id's 32-bit suffix VERBATIM and
// must be exactly 32 bits wide — the only width whose view is as unique as
// the identifier space itself; narrower fields collide at birthday bounds and
// are rejected at parse, never shipped. epoch/rand are non-unique and may
// take any width. deployment carries the operator-assigned deployment number,
// written into the template itself ("deployment:16=42,agent:32,epoch:16"):
// deployments that share one external IPv6 route (one centralized
// egress-security system) stay distinguishable even when their agent/sandfs
// ids overlap — the value's uniqueness is the operator's numbering plan, not
// Sandswap's. The widths must sum to exactly 64; a layout with no epoch or
// rand is deterministic (safe: every VM owns its own /64, and one sandfs
// always belongs to one agent, so "agent:32,sandfs:32" is a stable per-sandfs
// address).
type IIDTemplate struct {
	fields []iidField
	bits   int
}

type iidField struct {
	name  string
	bits  int
	value uint64 // deployment only: the operator-assigned number
}

const (
	// maxIIDBits is the IPv6 interface-identifier width the template must
	// fill exactly.
	maxIIDBits = 64

	// idFieldWidth is the required width of identity fields: the generated
	// ids carry exactly 32 unique random bits ("<prefix>-<8 hex>"), and a
	// field any narrower would ship an address view that cannot guarantee
	// attribution uniqueness.
	idFieldWidth = 32
)

// iidFieldNames are the template field names Build understands. Parsing
// rejects anything else so a typo fails at config load, not at first mount.
var iidFieldNames = map[string]bool{
	"agent":      true,
	"sandfs":     true,
	"epoch":      true,
	"rand":       true,
	"deployment": true,
}

// ParseIIDTemplate parses and validates a template string.
func ParseIIDTemplate(s string) (*IIDTemplate, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("iid template: empty")
	}
	t := &IIDTemplate{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("iid template %q: empty field", s)
		}
		var valueStr string
		if eq := strings.IndexByte(part, '='); eq >= 0 {
			valueStr = strings.TrimSpace(part[eq+1:])
			part = part[:eq]
		}
		nameBits := strings.SplitN(part, ":", 2)
		if len(nameBits) != 2 {
			return nil, fmt.Errorf("iid template %q: field %q must be name:bits", s, part)
		}
		name := strings.ToLower(strings.TrimSpace(nameBits[0]))
		if !iidFieldNames[name] {
			return nil, fmt.Errorf("iid template %q: unknown field %q (want agent|sandfs|epoch|rand|deployment)", s, name)
		}
		bits, err := strconv.Atoi(strings.TrimSpace(nameBits[1]))
		if err != nil || bits < 0 {
			return nil, fmt.Errorf("iid template %q: field %q bad bit count", s, part)
		}
		// Identity fields must be FULL width: they carry the id's 32-bit
		// suffix verbatim, and a narrower view (e.g. sandfs:16) overlaps at
		// birthday bounds (~300 ids at 16 bits) — an attribution guarantee
		// the address cannot keep. Parse-time rejection, never shipped.
		if (name == "agent" || name == "sandfs") && bits != idFieldWidth {
			return nil, fmt.Errorf("iid template %q: field %q must be exactly %d bits (the id suffix width — narrower fields cannot guarantee attribution uniqueness)", s, name, idFieldWidth)
		}
		f := iidField{name: name, bits: bits}
		if valueStr != "" {
			// Only deployment is deployment-configured; its value is written
			// into the template and must fit the declared width.
			if name != "deployment" {
				return nil, fmt.Errorf("iid template %q: field %q cannot take a value (only deployment is operator-assigned)", s, name)
			}
			v, err := strconv.ParseUint(valueStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("iid template %q: field %q bad value %q", s, name, valueStr)
			}
			if bits < 64 && v >= 1<<bits {
				return nil, fmt.Errorf("iid template %q: deployment value %d does not fit %d bits", s, v, bits)
			}
			f.value = v
		}
		t.fields = append(t.fields, f)
		t.bits += bits
	}
	if t.bits != maxIIDBits {
		return nil, fmt.Errorf("iid template %q: fields total %d bits, want exactly %d (pad with rand)", s, t.bits, maxIIDBits)
	}
	return t, nil
}

// String renders the template back to its canonical form.
func (t *IIDTemplate) String() string {
	parts := make([]string, len(t.fields))
	for i, f := range t.fields {
		p := fmt.Sprintf("%s:%d", f.name, f.bits)
		if f.name == "deployment" && f.value != 0 {
			p = fmt.Sprintf("%s=%d", p, f.value)
		}
		parts[i] = p
	}
	return strings.Join(parts, ",")
}

// Build assembles the 64-bit IID for a binding from the mounted identity.
// The agent/sandfs fields carry the identifier's hex suffix VERBATIM (see
// idFieldBits): ids are generated as "<prefix>-<8 lowercase hex>" — exactly
// 32 random bits — so the address view has exactly the identifier space's
// uniqueness (no hash, no added collisions) and the suffix is readable
// straight out of the address. Epoch is truncated to its field width; `rand`
// fields are freshly random every call (per-mount addresses never repeat
// across rebinds); the deployment field carries its operator-assigned value
// unchanged. A non-conforming identifier makes Build fail — the caller
// degrades to unstamped egress, where the guest keeps its fixed all-zero boot
// IID (invalid as an identity; safe direction).
func (t *IIDTemplate) Build(agentID, sandfsID string, epoch uint64) (uint64, error) {
	var iid uint64
	for _, f := range t.fields {
		var val uint64
		if f.name == "rand" {
			var b [8]byte
			if _, err := rand.Read(b[:]); err != nil {
				return 0, fmt.Errorf("iid rand: %w", err)
			}
			val = binary.BigEndian.Uint64(b[:])
		} else {
			var err error
			switch f.name {
			case "agent":
				val, err = idFieldBits(agentID, f.bits)
			case "sandfs":
				val, err = idFieldBits(sandfsID, f.bits)
			case "epoch":
				val = epoch
			case "deployment":
				val = f.value
			default:
				err = fmt.Errorf("iid template: unknown field %q (want agent|sandfs|epoch|rand|deployment)", f.name)
			}
			if err != nil {
				return 0, err
			}
		}
		mask := uint64(1)<<f.bits - 1
		iid = iid<<f.bits | val&mask
	}
	return iid, nil
}

// idFieldBits extracts an identifier's hex suffix as a w-bit field value.
// Identifiers are "<prefix>-<8 lowercase hex>" (32 random bits — the store
// guarantees live-identifier uniqueness by regenerating on collision), so
// placing the suffix directly needs no hash: the address field IS the unique
// value, a middlebox compares it against the region's id strings by eye or by
// table, and sub-32-bit fields simply mask the low bits. Any other shape (an
// id without a hex suffix) is a hard error, never a silent collision.
func idFieldBits(id string, w int) (uint64, error) {
	suffix := id
	if dash := strings.LastIndexByte(id, '-'); dash >= 0 {
		suffix = id[dash+1:]
	}
	if suffix == "" || len(suffix) > 8 {
		return 0, fmt.Errorf("iid field: id %q has no ≤8-hex-digit suffix (want <prefix>-<8 hex>)", id)
	}
	v, err := strconv.ParseUint(suffix, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("iid field: id %q suffix %q is not hex (want <prefix>-<8 hex>)", id, suffix)
	}
	return v & (uint64(1)<<w - 1), nil
}
