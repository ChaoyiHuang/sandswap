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
	"time"

	"sandlot/warden"
)

// acquireWarden borrows a warden connection from the VM's pool, dialing a new
// one if none is idle (bounded by the spec's exec_slots). The returned release
// func MUST be called exactly once: release(broken=false) returns the
// connection to the pool; release(broken=true) discards it (transport error —
// the next acquire dials fresh). The caller marks inFlight so pool
// destroy/recycle can classify the VM busy without any lock probing.
func (h *Handler) acquireWarden(ctx context.Context, state *VMState) (*warden.Client, func(bool), error) {
	pool := state.wardenPoolFor()
	waitStart := time.Now()
	c, release, waited, err := pool.acquire(ctx, func() (*warden.Client, error) {
		if h.testDialFn != nil {
			// Test seam: serve pool dials from in-process fakes.
			return h.testDialFn(state.VM.GuestCID, 15*time.Second)
		}
		return h.dialWardenRetry(state.VM.GuestCID, state.Cfg.WardenSessionKey, 15*time.Second)
	})
	if waited {
		// Grayscale signal: the request queued behind execSlots in-flight ops.
		h.metrics.RecordSlotWait(time.Since(waitStart))
	}
	if err != nil {
		return nil, nil, err
	}
	state.inFlight.Add(1)
	return c, func(broken bool) {
		state.inFlight.Add(-1)
		release(broken)
	}, nil
}

// isWardenTransportErr reports whether err is a vsock transport error (the
// connection is unusable — the borrowed slot must be released broken=true so
// the pool discards it instead of handing a wedged socket to the next op).
func isWardenTransportErr(err error) bool {
	var te *warden.TransportError
	return errors.As(err, &te)
}

// wardenCountdown returns the per-request read-timeout cap for warden
// connections (the in-VM warden_countdown, T_warden). A read longer than this
// is moot anyway — the warden has already POWER_OFF'd a wedged VM — so the cap
// bounds every op's read timeout to it. Falls back to the warden-client default.
// Reads h.vmmCfg under h.mu — UpdateVMMConfig (config hot-reload) rewrites the
// whole struct, so an unguarded read races it.
func (h *Handler) wardenCountdown() time.Duration {
	h.mu.RLock()
	sec := h.vmmCfg.WardenCountdownSec
	h.mu.RUnlock()
	if sec == 0 {
		return warden.ReadTimeoutCapDefault
	}
	return time.Duration(sec) * time.Second
}

// dialWardenRetry dials the warden over AF_VSOCK with retries. sessionKey is
// the VM's hex per-VM key; a malformed/missing key fails immediately (never
// fall back to an unauthenticated connection).
func (h *Handler) dialWardenRetry(cid uint32, sessionKey string, timeout time.Duration) (*warden.Client, error) {
	key, err := warden.DecodeSessionKey(sessionKey)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		agt, err := warden.DialWithCap(cid, h.wardenCountdown(), key)
		if err == nil {
			return agt, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("warden dial cid %d: %w (after %v)", cid, err, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitWardenReady polls the warden until it answers a MemStats round trip.
// Dial success alone only proves the port is listening; the round trip proves
// the server is up AND speaks our protocol version — a version mismatch comes
// back as warden.ProtocolVersionError, returned immediately so callers fail
// creation/re-adopt fast instead of registering a VM whose every RPC would
// fail (and, worse, being torn down as "hung" by the probe loop and
// destroy-recreated forever against the same incompatible warden build).
// Boot-path cost: one extra vsock RTT (~sub-ms against a ~100ms guest boot).
func (h *Handler) waitWardenReady(ctx context.Context, cid uint32, sessionKey string, timeout time.Duration) error {
	// One re-armed timer instead of a time.After per iteration (~750 fresh
	// 20ms timers per 15s wait — pure timer-heap churn on the boot path).
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, _, err := h.probeVM(cid, sessionKey); err == nil {
			return nil
		} else {
			lastErr = err
			var pve *warden.ProtocolVersionError
			if errors.As(err, &pve) {
				return pve // fatal for this peer — no amount of polling fixes it
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	// Carry the last dial/protocol error: without it a boot-time timeout is
	// indistinguishable from a guest that never booted, a vsock registration
	// failure, or a transient host stall — the three need different responses.
	return fmt.Errorf("warden did not become ready within %v (last: %v)", timeout, lastErr)
}

// execSlotsForSpec resolves the per-VM warden connection-pool size for a spec
// (config.SpecEntry.ExecSlots). Unknown specs / 0 = 1 (serial): the memory-safe
// fallback for specs that don't declare a slot count.
func (h *Handler) execSlotsForSpec(specID string) int {
	h.mu.RLock()
	res, ok := h.specResources[specID]
	h.mu.RUnlock()
	if ok && res.ExecSlots > 0 {
		return res.ExecSlots
	}
	return 1
}
