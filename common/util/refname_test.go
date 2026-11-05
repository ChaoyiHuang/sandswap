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

package util

import "testing"

func TestRefToFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sqlite:v1", "sqlite_v1"},
		{"mysql:v2", "mysql_v2"},
		{"simple", "simple"},
		{"a:b:c", "a_b_c"},
		{"", ""},
	}
	for _, tt := range tests {
		got := RefToFilename(tt.input)
		if got != tt.expected {
			t.Errorf("RefToFilename(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
