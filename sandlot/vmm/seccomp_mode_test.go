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

package vmm

import "testing"

// The default is enforce: the per-thread allow-lists passed the two-phase
// audit (e2e/vmm-seccomp.sh) before the flip. An explicit "log" remains the
// audit mode and "false" the escape hatch.
func TestSeccompModeDefaultIsEnforce(t *testing.T) {
	if got := seccompModeOr(""); got != "true" {
		t.Fatalf("seccompModeOr(\"\") = %q, want true", got)
	}
	for _, mode := range []string{"true", "false", "log"} {
		if got := seccompModeOr(mode); got != mode {
			t.Fatalf("seccompModeOr(%q) = %q, want passthrough", mode, got)
		}
	}
}
