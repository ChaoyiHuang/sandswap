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

// The security-event counter registry.
//
// Detection blind spot: every NAMED isolation refusal the platform
// emits — the warden's volume-identity refusals, the unclean-guest unmount
// gate, the set-fs reuse tripwire — used to live only in logs. A slow
// low-and-slow probe (each attempt costs one VM destroy) was therefore
// operationally invisible. These counters make the named refusals scrapable
// by the same /metrics projection the rest of the platform uses.
//
// Lives in package pool (where the classification happens) rather than
// gateway/stats because stats imports pool for the unmount recorder — a
// registry here keeps the dependency graph acyclic.
//
// Doctrine compliance ("nothing recorded on request paths"): the classify
// call sits ONLY on command-FAILURE branches (the cold error path in
// pool/sandlot_stream.go's `command failed` sites) — never on success
// paths, never per-request. Counters are process-local atomics reset on
// restart, like the mount/unmount counters already projected.
package pool

import (
	"fmt"
	"strings"
	"sync"
)

// Security event reasons (the `reason` label's value set). Each names the
// refusal that produced it; the classifier matches the token the emitting
// side guarantees (the warden's named transport errors, the sandlot's
// named unmount refusals, the VMM's tripwire error text).
const (
	ReasonVolumeIdentityMismatch = "volume_identity_mismatch"
	ReasonVolumeIdentityMissing  = "volume_identity_missing"
	ReasonUncleanGuest           = "unclean_guest_refusal"
	ReasonSetfsTripwire          = "setfs_previous_tenant_refs"
	ReasonUnmountEBUSY           = "unmount_ebusy_destroy"
	ReasonUnknownIsolation       = "unknown_isolation_refusal"
)

// classified tokens → reason, checked by substring (the sandlot wraps the
// warden's message verbatim, and its own wraps add context around the
// token). Order matters: specific before generic.
var securityEventTokens = []struct {
	token  string
	reason string
}{
	// warden warm-op refusals (warden/src/raw_server.rs ERR_VOLUME_*)
	{"volume_identity_mismatch", ReasonVolumeIdentityMismatch},
	{"volume_identity_missing", ReasonVolumeIdentityMissing},
	// warden unmount final gate: "guest not clean at unmount: live or zombie
	// process(es)" / "refusing to reuse this VM"
	{"guest not clean at unmount", ReasonUncleanGuest},
	{"refusing to reuse this VM", ReasonUncleanGuest},
	// VMM set-fs tripwire: "PreviousTenantRefs" rides the sandlot's
	// set-fs error wrap (virtiofsd Error::PreviousTenantRefs text)
	{"PreviousTenantRefs", ReasonSetfsTripwire},
	{"previous tenant", ReasonSetfsTripwire},
	// unmount EBUSY escalation to destroy (exclusive-ownership backstop)
	{"failed to unmount workspace after retry (EBUSY)", ReasonUnmountEBUSY},
	// generic isolation-refusal shape: any remaining "exclusive-ownership"
	// refusal is at least a signal, never silently dropped
	{"exclusive-ownership", ReasonUnknownIsolation},
}

var (
	secMu     sync.Mutex
	secCounts = map[string]uint64{}
)

// ClassifySecurityEvent maps an error string to a security-event reason, or
// "" when the string carries no known isolation-refusal token (the common
// case — ordinary ENOENT/EACCES business failures never count). Pure.
func ClassifySecurityEvent(s string) string {
	for _, t := range securityEventTokens {
		if strings.Contains(s, t.token) {
			return t.reason
		}
	}
	return ""
}

// NoteSecurityEvent classifies a command-failure error string and counts it
// when it names an isolation refusal. Called only from failure paths.
func NoteSecurityEvent(errStr string) {
	reason := ClassifySecurityEvent(errStr)
	if reason == "" {
		return
	}
	secMu.Lock()
	secCounts[reason]++
	secMu.Unlock()
}

// SecurityEventSnapshot returns the current reason→count map (copy).
func SecurityEventSnapshot() map[string]uint64 {
	secMu.Lock()
	defer secMu.Unlock()
	out := make(map[string]uint64, len(secCounts))
	for k, v := range secCounts {
		out[k] = v
	}
	return out
}

// WriteSecurityMetricsText renders the counters in Prometheus text format.
// Emitted after the main report by the /metrics handler; counters with zero
// occurrences are omitted (an absent series never fired).
func WriteSecurityMetricsText() string {
	var b strings.Builder
	emitted := map[string]bool{}
	for reason, count := range SecurityEventSnapshot() {
		writeSecMetric(&b, emitted, reason, float64(count))
	}
	return b.String()
}

func writeSecMetric(b *strings.Builder, emitted map[string]bool, reason string, value float64) {
	if reason == "" || emitted[reason] {
		return
	}
	emitted[reason] = true
	fmt.Fprintf(b, "# HELP sandswap_security_events_total Named isolation refusals (warden identity checks, unclean-guest gate, set-fs tripwire).\n# TYPE sandswap_security_events_total counter\nsandswap_security_events_total{reason=%q} %v\n", reason, value)
}
