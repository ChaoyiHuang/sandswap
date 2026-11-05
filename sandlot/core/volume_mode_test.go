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

import "testing"

// The node validates the identity record's (mode, template_ref) pair before
// any host mount or filter swap. The warden mounts by the mode it receives —
// never by probing the agent-writable volume layout — so an absent or
// inconsistent record must fail closed here instead of silently defaulting.
func TestValidateVolumeMode(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		templateRef string
		wantErr     bool
	}{
		{"flat without template", "flat", "", false},
		{"overlay with template", "overlay", "python:v3", false},
		{"flat with template (inconsistent)", "flat", "python:v3", true},
		{"overlay without template", "overlay", "", true},
		{"empty mode", "", "", true},
		{"empty mode with template", "", "python:v3", true},
		{"unknown mode", "tmpfs", "", true},
		{"case sensitive", "Flat", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateVolumeMode(tc.mode, tc.templateRef)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateVolumeMode(%q, %q) error = %v, wantErr %v",
					tc.mode, tc.templateRef, err, tc.wantErr)
			}
		})
	}
}
