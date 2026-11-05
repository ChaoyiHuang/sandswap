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

import "testing"

// TestValidateStreamCaps pins the shared gateway/sandlot window/message-size
// contract: every cap >= 1, windows within int32 range, per-stream window >=
// message size, per-conn window >= stream window, and the 16MB FileOp chain
// floor.
func TestValidateStreamCaps(t *testing.T) {
	cases := []struct {
		name                  string
		initial, conn, maxMsg int
		wantErr               bool
	}{
		{"defaults valid", 64 << 20, 128 << 20, 16 << 20, false},
		{"minimum chain valid", 16 << 20, 16 << 20, 16 << 20, false},
		{"zero initial invalid", 0, 128 << 20, 16 << 20, true},
		{"zero max msg invalid", 64 << 20, 128 << 20, 0, true},
		{"window over int32 invalid", 1 << 31, 2 << 31, 16 << 20, true},
		{"conn over int32 invalid", 64 << 20, 1 << 31, 16 << 20, true},
		{"initial below msg size invalid", 8 << 20, 128 << 20, 16 << 20, true},
		{"conn below initial invalid", 64 << 20, 32 << 20, 16 << 20, true},
		{"msg below 16MB chain invalid", 64 << 20, 128 << 20, 8 << 20, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStreamCaps(tc.initial, tc.conn, tc.maxMsg)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateStreamCaps(%d,%d,%d) = %v, wantErr %v", tc.initial, tc.conn, tc.maxMsg, err, tc.wantErr)
			}
		})
	}
}
