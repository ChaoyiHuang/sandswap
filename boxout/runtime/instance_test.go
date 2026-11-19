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
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestHostMemoryLimitMB pins the default aggregate memory cap derivation:
// roughly 80% of the host's MemTotal, and never more than it. 0 (the
// documented "count limit still applies" sentinel on an unreadable
// /proc/meminfo) is skipped, not failed — the branch only triggers on hosts
// without the file.
func TestHostMemoryLimitMB(t *testing.T) {
	got := HostMemoryLimitMB()
	if got == 0 {
		t.Skip("meminfo unreadable on this host — 0 sentinel path")
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Skip("cannot cross-check without /proc/meminfo")
	}
	totalKB := int64(0)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, _ = strconv.ParseInt(fields[1], 10, 64)
			}
			break
		}
	}
	if totalKB == 0 {
		t.Fatal("cannot parse MemTotal")
	}
	wantMax := uint64(totalKB) / 1024 * 8 / 10
	if got > wantMax {
		t.Fatalf("HostMemoryLimitMB() = %d, want <= 80%% of MemTotal (%d)", got, wantMax)
	}
	// A meaningful budget, not a rounding artifact.
	if got < wantMax/2 {
		t.Fatalf("HostMemoryLimitMB() = %d, suspiciously below 80%% of MemTotal (%d)", got, wantMax)
	}
}
