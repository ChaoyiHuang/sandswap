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

package stream

import (
	"errors"
	"testing"
)

// TestErrorSentinels verifies the package error sentinels are distinct, non-nil,
// and not wrapped copies of each other. Callers (lease/ownership.go,
// handler/execute.go) compare with errors.Is, so identity must hold.
func TestErrorSentinels(t *testing.T) {
	errs := []struct {
		name string
		err  error
		want string
	}{
		{"ErrConnectionClosed", ErrConnectionClosed, "connection closed"},
		{"ErrSendQueueFull", ErrSendQueueFull, "send queue full"},
		{"ErrNodeNotFound", ErrNodeNotFound, "node not found"},
		{"ErrExpectedHello", ErrExpectedHello, "expected NodeHello as first message"},
	}
	seen := make(map[error]string)
	for _, e := range errs {
		if e.err == nil {
			t.Errorf("%s is nil", e.name)
			continue
		}
		if e.err.Error() != e.want {
			t.Errorf("%s message: got %q, want %q", e.name, e.err.Error(), e.want)
		}
		// errors.Is identity: the sentinel must match itself.
		if !errors.Is(e.err, e.err) {
			t.Errorf("%s: errors.Is(self) = false, want true", e.name)
		}
		if prev, dup := seen[e.err]; dup {
			t.Errorf("%s is the same pointer as %s (must be distinct sentinels)", e.name, prev)
		}
		seen[e.err] = e.name
	}

	// ErrNodeNotFound is the contract ownership.go checks to detect a
	// disconnected node (Claim -> ErrOwnerNodeDown). Verify cross-package-style
	// wrapping still resolves.
	wrapped := errors.Join(ErrNodeNotFound, errors.New("ctx"))
	if !errors.Is(wrapped, ErrNodeNotFound) {
		t.Error("errors.Is(join with ErrNodeNotFound) should be true")
	}
	if errors.Is(wrapped, ErrConnectionClosed) {
		t.Error("errors.Is(join with ErrNodeNotFound, ErrConnectionClosed) should be false")
	}
}
