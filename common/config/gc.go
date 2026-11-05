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

package config

import (
	"fmt"
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// DefaultGOGC is applied when the operator leaves -gogc at its auto value
// (0) and no GOGC env var is set. Go's default 100 paces the next GC at
// live*2; the concurrent mark/assist cycles compete with hot-path goroutines
// for cores, and at high request rates they show up as P95/P99 tail samples.
// 200 halves the GC frequency for a proportionally larger heap — the right
// trade for these services, whose live heaps are small next to host RAM.
// Pair -gomemlimit with it in memory-constrained deployments to bound the
// worst case.
const DefaultGOGC = 200

// GCSettings describes what ApplyGCTuning changed, for the one-time boot log.
// A zero Set field means "left untouched".
type GCSettings struct {
	GOGCSet      int   // GOGC percentage applied (0 = untouched)
	GOGCPrev     int   // previous value (valid when GOGCSet != 0)
	MemLimitSet  int64 // soft memory limit applied in bytes (0 = untouched)
	MemLimitPrev int64 // previous value (valid when MemLimitSet != 0)
}

// ApplyGCTuning tunes the Go runtime's GC pacing. Process-level and
// restart-required — call once at startup, before server work begins.
//
//   - gogc > 0: force that GOGC percentage (overrides the GOGC env var).
//   - gogc == 0: auto — leave untouched when the GOGC env var is set (the
//     runtime already applied it at startup), otherwise apply DefaultGOGC.
//   - gogc < 0: rejected — a negative value would DISABLE the collector
//     entirely, which is never a valid deployment posture here.
//   - memLimit == "": leave untouched (a native GOMEMLIMIT env var still
//     applies). Otherwise parsed via ParseMemoryLimit and applied as the
//     runtime soft memory limit (debug.SetMemoryLimit).
func ApplyGCTuning(gogc int, memLimit string) (*GCSettings, error) {
	st := &GCSettings{}
	switch {
	case gogc < 0:
		return nil, fmt.Errorf("gogc must be >= 0 (got %d; negative disables the GC)", gogc)
	case gogc > 0:
		st.GOGCPrev = debug.SetGCPercent(gogc)
		st.GOGCSet = gogc
	case os.Getenv("GOGC") == "":
		st.GOGCPrev = debug.SetGCPercent(DefaultGOGC)
		st.GOGCSet = DefaultGOGC
	}
	if memLimit != "" {
		b, err := ParseMemoryLimit(memLimit)
		if err != nil {
			return nil, err
		}
		st.MemLimitPrev = debug.SetMemoryLimit(b)
		st.MemLimitSet = b
	}
	return st, nil
}

// ParseMemoryLimit parses a byte-size string into a byte count. Accepted
// forms: a plain integer (bytes) or `<n><unit>` with the binary units KiB,
// MiB, GiB, TiB (case-insensitive, no space) — e.g. "512MiB", "8GiB",
// "1048576". Values must be positive and must not overflow int64.
func ParseMemoryLimit(s string) (int64, error) {
	orig := s
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("empty memory limit")
	}
	unit := int64(1)
	switch {
	case strings.HasSuffix(s, "KIB"):
		unit, s = 1<<10, s[:len(s)-3]
	case strings.HasSuffix(s, "MIB"):
		unit, s = 1<<20, s[:len(s)-3]
	case strings.HasSuffix(s, "GIB"):
		unit, s = 1<<30, s[:len(s)-3]
	case strings.HasSuffix(s, "TIB"):
		unit, s = 1<<40, s[:len(s)-3]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory limit %q (want e.g. 512MiB, 8GiB, or raw bytes)", orig)
	}
	if n <= 0 {
		return 0, fmt.Errorf("memory limit %q must be positive", orig)
	}
	if n > math.MaxInt64/unit {
		return 0, fmt.Errorf("memory limit %q overflows int64 bytes", orig)
	}
	return n * unit, nil
}
