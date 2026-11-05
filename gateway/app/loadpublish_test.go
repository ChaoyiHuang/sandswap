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

package app

import (
	"testing"

	"gateway/pool"
)

func TestAvgDutyLong(t *testing.T) {
	cases := []struct {
		snap map[string]pool.NodeMetrics
		want float64
	}{
		{nil, 0},
		{map[string]pool.NodeMetrics{}, 0},
		{map[string]pool.NodeMetrics{"a": {DutyLong: 0.4}, "b": {DutyLong: 0.6}}, 0.5},
		{map[string]pool.NodeMetrics{"a": {DutyLong: 1.0}}, 1.0},
	}
	for _, c := range cases {
		if got := avgDutyLong(c.snap); got != c.want {
			t.Errorf("avgDutyLong(%v) = %v, want %v", c.snap, got, c.want)
		}
	}
}

func TestMaxDutyLong(t *testing.T) {
	if got := maxDutyLong(nil); got != 0 {
		t.Errorf("expected 0 for empty snapshot, got %v", got)
	}
	if got := maxDutyLong(map[string]pool.NodeMetrics{"a": {DutyLong: 0.2}, "b": {DutyLong: 0.9}}); got != 0.9 {
		t.Errorf("expected 0.9, got %v", got)
	}
}
