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

package main

import (
	"net"
	"strings"
	"testing"
)

func TestFormatSRV(t *testing.T) {
	s := &net.SRV{Target: "gw1.sandswap.local.", Port: 9998, Priority: 10, Weight: 60}
	if got, want := formatSRV("_stream._tcp.sandswap.local", s, true), "10 60 9998 gw1.sandswap.local"; got != want {
		t.Fatalf("+short SRV = %q, want %q", got, want)
	}
	full := formatSRV("_stream._tcp.sandswap.local", s, false)
	for _, part := range []string{"_stream._tcp.sandswap.local.", "IN\tSRV", "10 60 9998 gw1.sandswap.local."} {
		if !strings.Contains(full, part) {
			t.Fatalf("full SRV %q missing %q", full, part)
		}
	}
}
