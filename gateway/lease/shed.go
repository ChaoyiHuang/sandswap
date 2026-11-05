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

package lease

import (
	"log/slog"
	"sync/atomic"
	"time"

	"gateway/pool"
)

// ShedConfig holds the voluntary load-shed parameters. All fields are
// hot-reloadable via atomic stores (UpdateShedConfig). When Enabled is false,
// shedding is fully disabled and the gateway behaves exactly as before
// (NO_AVAILABLE_SANDBOX 503 on saturation).
type ShedConfig struct {
	Enabled       atomic.Bool
	SatSec        atomic.Int64 // sustained-saturation seconds required before shedding
	RatePerSec    atomic.Int64 // max sheds per second (token bucket, anti-thrash)
	CooldownSec   atomic.Int64 // recentlyShed cooldown window
	RetryAfterSec atomic.Int64 // Retry-After hint sent to the client (≈ sandfs DNS TTL)
}

// ShedAction is the outcome of MaybeShed: either shed (release ownership +
// return a shed-503) or pass (let the caller proceed with the normal error).
type ShedAction int

const (
	ShedActionNone     ShedAction = iota // shed disabled / conditions not met → normal error
	ShedActionShed                       // shed performed: caller returns shed-503
	ShedActionCooldown                   // sandfs is in shed cooldown (already shed recently): shed-503 without re-releasing
)

// ShedController gates voluntary load shedding. It bundles the trigger
// conditions (sustained saturation + idle peer + rate limit) and performs the
// ownership release via the OwnershipCache. Kept separate from the handlers so
// the trigger logic is defined once and shared by the execute / file / MCP paths.
type ShedController struct {
	cfg       *ShedConfig
	pool      *pool.Manager
	ownership *OwnershipCache
	peers     *PeerLoadMonitor
	logger    *slog.Logger
	// hasLocalMount reports whether THIS gateway holds a live (non-releasing)
	// lease for the sandfs. Wired from cmd/main.go with the lease manager's
	// HasActiveEntry; nil (tests) skips the guard. Shedding a sandfs with a
	// local live lease would delete the ownership record while our VM still
	// holds the volume — a peer claiming it would dual-mount until our lease
	// expires (a background exec can hold it for an hour).
	hasLocalMount func(sandfsID string) bool

	// rateBucket is a simple token bucket for RatePerSec. refilled lazily on each
	// call by elapsed time. Stored as int64 milli-tokens to avoid float atomics.
	rateBucket atomic.Int64
	rateLast   atomic.Int64 // unix milli of last refill
}

// SetLocalMountGuard wires the local-live-lease check that suppresses shedding
// a sandfs this gateway is still serving (see hasLocalMount). Called once at
// startup from cmd/main.go; nil (or not called) disables the guard.
func (s *ShedController) SetLocalMountGuard(fn func(sandfsID string) bool) {
	if s == nil {
		return
	}
	s.hasLocalMount = fn
}

// NewShedController binds the shed trigger to its dependencies. peers may be
// nil (single-node); HasIdlePeer then returns false, so shedding never fires —
// correct (no peer to shed to). ownership may be nil (single-node); likewise.
func NewShedController(cfg *ShedConfig, pm *pool.Manager, oc *OwnershipCache, peers *PeerLoadMonitor, logger *slog.Logger) *ShedController {
	if logger == nil {
		logger = slog.Default()
	}
	return &ShedController{
		cfg:       cfg,
		pool:      pm,
		ownership: oc,
		peers:     peers,
		logger:    logger,
	}
}

// MaybeShed evaluates the shed preconditions for a cold-path request that has
// just hit NO_AVAILABLE_SANDBOX (the gateway is saturated for this sandfs).
// If all hold it releases ownership and returns ShedActionShed; if the sandfs
// is already in cooldown it returns ShedActionCooldown; otherwise ShedActionNone
// (the caller proceeds with the normal saturation 503).
//
// Preconditions (all must hold):
//  1. Shedding enabled.
//  2. Sustained saturation: the gateway has been all-zero-clean for >= SatSec.
//  3. An idle peer exists (HasIdlePeer): there is somewhere to shed TO.
//  4. Rate limit: at most RatePerSec sheds per second (anti-thrash / anti-stampede).
//
// The cold-path-only constraint is enforced by the caller (this is only called
// from the ErrNoAvailableSandbox branch, which is itself cold-path only).
func (s *ShedController) MaybeShed(sandfsID string) ShedAction {
	if s == nil || s.cfg == nil || !s.cfg.Enabled.Load() {
		return ShedActionNone
	}
	// If the sandfs is already in shed cooldown, keep returning the shed-503
	// (no re-release) so the client keeps re-resolving until it lands on a peer.
	if s.ownership != nil && s.ownership.isRecentlyShed(sandfsID) {
		return ShedActionCooldown
	}
	// Local-live-lease guard: never delete the ownership of a sandfs whose VM
	// this gateway still holds (dual-mount window until our lease expires —
	// see SetLocalMountGuard). Checked BEFORE consuming a rate token.
	if s.hasLocalMount != nil && s.hasLocalMount(sandfsID) {
		return ShedActionNone
	}
	satSec := int(s.cfg.SatSec.Load())
	if satSec <= 0 || !s.pool.IsSustainedSaturated(satSec) {
		return ShedActionNone
	}
	if s.peers == nil || !s.peers.HasIdlePeer() {
		return ShedActionNone // cluster-wide saturation: shedding just moves the 503
	}
	if !s.takeToken() {
		return ShedActionNone // rate-limited this second
	}
	if s.ownership != nil {
		s.ownership.ShedOwnership(sandfsID, int(s.cfg.CooldownSec.Load()))
	}
	return ShedActionShed
}

// Update atomically applies new shed parameters (hot-reload). Used by the
// gateway config reload callback. Zero-value fields are tolerated: SatSec/Rate
// <= 0 effectively disable shedding for that dimension (MaybeShed gates on them).
func (c *ShedConfig) Update(enabled bool, satSec, ratePerSec, cooldownSec, retryAfterSec int) {
	c.Enabled.Store(enabled)
	c.SatSec.Store(int64(satSec))
	c.RatePerSec.Store(int64(ratePerSec))
	c.CooldownSec.Store(int64(cooldownSec))
	c.RetryAfterSec.Store(int64(retryAfterSec))
}

// RetryAfterSec returns the configured Retry-After hint (seconds) for shed 503s.
func (s *ShedController) RetryAfterSec() int {
	if s == nil || s.cfg == nil {
		return 5
	}
	v := int(s.cfg.RetryAfterSec.Load())
	if v <= 0 {
		return 5
	}
	return v
}

// takeToken refills the rate bucket lazily and tries to consume one token.
// Returns false if the bucket is empty (rate-limited). 1 token = 1000 milli-tokens.
func (s *ShedController) takeToken() bool {
	rps := s.cfg.RatePerSec.Load()
	if rps <= 0 {
		return false // 0 = disabled (defensive; Enabled gate should have caught it)
	}
	now := time.Now().UnixMilli()
	last := s.rateLast.Load()
	if last == 0 {
		s.rateLast.Store(now)
		s.rateBucket.Store(rps * 1000)
	} else {
		elapsed := now - last
		if elapsed > 0 {
			refill := elapsed * rps // milli-tokens earned over elapsed ms (rps tokens/ms = rps/1000 *1000)
			s.rateLast.Store(now)
			for {
				cur := s.rateBucket.Load()
				nv := cur + refill
				cap := rps * 1000
				if nv > cap {
					nv = cap
				}
				if s.rateBucket.CompareAndSwap(cur, nv) {
					break
				}
			}
		}
	}
	for {
		cur := s.rateBucket.Load()
		if cur < 1000 {
			return false
		}
		if s.rateBucket.CompareAndSwap(cur, cur-1000) {
			return true
		}
	}
}
