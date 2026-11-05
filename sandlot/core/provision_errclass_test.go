// Copyright 2026 Chaoyang Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1

package core

import (
	"fmt"
	"testing"

	"sandlot/provision/volume"
)

// Pins: every named volume-op sentinel rides the wire with its own
// error_code (was: empty code + raw text embedding the seed-derived path).
func TestClassifyErrVolumeSentinels(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("wrap: %w", volume.ErrVolumeIdentityMismatch), "VOLUME_IDENTITY_MISMATCH"},
		{fmt.Errorf("wrap: %w", volume.ErrRotationStaged), "ROTATION_STAGED"},
		{volume.ErrInvalidArgument, "INVALID_ARGUMENT"},
		{volume.ErrTemplateNotFound, "TEMPLATE_NOT_FOUND"},
		{fmt.Errorf("plain"), ""},
	}
	for _, c := range cases {
		if got := classifyErr(c.err); got != c.want {
			t.Errorf("classifyErr(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}
