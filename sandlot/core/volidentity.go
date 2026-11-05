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

import (
	"context"
	"errors"
	"fmt"
)

// errVolumeIdentityCheckFailed is the caller-visible error for a failed
// cold-mount identity check. Deliberately generic: the detailed cause (which
// may name the host-side volume path) is logged locally by the handler and
// never returned to the gateway/agent.
var errVolumeIdentityCheckFailed = errors.New("volume identity verification failed")

// verifyVolumeIdentity binds the gateway-supplied (sandfsID, volumePath) pair
// to the volume's on-disk `.sandfs-id` stamp before a cold mount. This is the
// node-side containment for a compromised gateway: the gateway names
// the path, but the node refuses unless the path's own stamp names the
// sandfs_id it is mounting.
//
// Cost: one stamp read on the first cold attach of a volume to this sandlot
// process; the result is cached (positive only) in a bounded LRU keyed by a
// SHA-256 of (id, path). The stamp is immutable for a given path and sandswap
// keeps sandfs placement stable, so the steady-state warm path never reaches
// this function and a re-attach is a cache hit. An evicted entry costs one
// cold-attach read — never a warm-op cost.
func (h *Handler) verifyVolumeIdentity(ctx context.Context, sandfsID, volumePath, volumeEpoch string) error {
	if sandfsID == "" {
		return fmt.Errorf("sandfs_id is required")
	}
	if h.volIDCache().Lookup(sandfsID, volumePath, volumeEpoch) {
		return nil
	}
	if h.vm == nil {
		// Initialization window only; never fail open on a missing checker.
		h.logger.Printf("volume identity check unavailable for sandfs %s: no lifecycle manager", sandfsID)
		return errVolumeIdentityCheckFailed
	}
	if err := h.vm.VerifyVolumeID(ctx, sandfsID, volumePath, volumeEpoch); err != nil {
		// Local log: the detailed cause (possibly including the path) stays
		// on this node. The caller sees the generic sentinel.
		h.logger.Printf("volume identity check failed for sandfs %s: %v", sandfsID, err)
		return errVolumeIdentityCheckFailed
	}
	h.volIDCache().Insert(sandfsID, volumePath, volumeEpoch)
	return nil
}

// volIDCache returns the lazily-initialized verified-binding cache. Lazy so
// manually constructed test handlers (and the embeddedManager construction
// order) need no extra wiring.
func (h *Handler) volIDCache() *volIDCache {
	h.volIDsOnce.Do(func() {
		if h.volIDs == nil {
			h.volIDs = newVolIDCache(volIDCacheCapacity)
		}
	})
	return h.volIDs
}
