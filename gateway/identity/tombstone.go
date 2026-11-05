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

package identity

import (
	"fmt"
	"sync/atomic"
	"time"
)

// defaultTombstoneTTL is how long a deleted sandfs id is remembered. It must
// outlive the longest window in which a lagging gateway can still serve a
// stale record for that id — otherwise a reused 32-bit id could resurrect a
// name whose old record still exists somewhere.
const defaultTombstoneTTL = 7 * 24 * time.Hour

// tombstoneTTLNS is the live TTL. Atomic: the delete and create paths read it
// without a lock, and the operator sets it once at startup.
var tombstoneTTLNS atomic.Int64

func init() {
	tombstoneTTLNS.Store(int64(defaultTombstoneTTL))
}

// TombstoneTTL returns the configured tombstone lifetime.
func TombstoneTTL() time.Duration {
	return time.Duration(tombstoneTTLNS.Load())
}

// SetTombstoneTTL configures the tombstone lifetime (gateway -tombstone-ttl-sec).
// A value below one second is refused: a zero/negative TTL would disable the
// id-reuse guard the tombstones exist for.
func SetTombstoneTTL(d time.Duration) error {
	if d < time.Second {
		return fmt.Errorf("tombstone TTL must be >= 1s (got %s)", d)
	}
	tombstoneTTLNS.Store(int64(d))
	return nil
}
