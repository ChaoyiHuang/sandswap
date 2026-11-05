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
	"fmt"
	"sync"
)

// memBudgetSafetyPct is the fraction of host MemTotal this node will commit to
// guest memory. The remainder covers the host OS, sandlot/sandvmm overhead, and
// page cache. Mirrors cmd/main.go's config-time memSafetyFactor so the runtime
// ledger and the config-time validation agree.
const memBudgetSafetyPct = 80

// memAdmitHeadroomMB is the MemAvailable slack required beyond the requested
// guest memory. It absorbs drift from processes outside this node's ledger.
const memAdmitHeadroomMB = 256

// memLedger is the per-node guest-memory admission ledger.
//
// It reserves memory by SPEC SIZE at admission and holds that reservation for
// the VM's whole life. This is the part MemAvailable alone cannot do: guest
// memory is faulted in lazily, so a 1GB guest that has touched 150MB looks
// nearly free to the host. Admitting against MemAvailable alone therefore lets
// N oversized guests in while each is still small, and they OOM the host later
// as they grow. Reserving the full spec up front makes admission reflect the
// commitment rather than the current footprint.
//
// MemAvailable is still consulted at admission (see admit) as a second, weaker
// gate that catches memory pressure from processes this ledger cannot see.
//
// A rejected admission creates nothing at all — no CID, no TAP, no sandvmm — so
// there is no cleanup to get wrong. Callers surface the shortage instead of
// retrying: the host does not grow more memory on a retry.
type memLedger struct {
	mu         sync.Mutex
	reservedMB uint64
	budgetMB   uint64 // 0 = unknown host MemTotal: ledger cap disabled
	// availFn reads host MemAvailable in MiB. Field (not a direct call) so tests
	// can drive admission decisions deterministically.
	availFn func() (uint64, error)
}

func newMemLedger(hostMemTotalMB uint64, availFn func() (uint64, error)) *memLedger {
	if availFn == nil {
		availFn = readMemAvailableMB
	}
	return &memLedger{
		budgetMB: hostMemTotalMB * memBudgetSafetyPct / 100,
		availFn:  availFn,
	}
}

// admit reserves memMB for a VM about to be created, or returns an error
// wrapping errInsufficientMemory when the host cannot back it. On error nothing
// is reserved. Every successful admit MUST be paired with exactly one release.
// A nil ledger (test handlers) admits unconditionally.
func (l *memLedger) admit(memMB uint64) error {
	if l == nil || memMB == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	// Gate 1: the commitment ledger. Authoritative — it counts what this node
	// has promised, not what the guests have touched so far.
	if l.budgetMB > 0 && l.reservedMB+memMB > l.budgetMB {
		return fmt.Errorf("%w: requesting %dMB with %dMB already reserved exceeds this node's %dMB guest-memory budget (%d%% of host MemTotal)",
			errInsufficientMemory, memMB, l.reservedMB, l.budgetMB, memBudgetSafetyPct)
	}

	// Gate 2: live host pressure, for memory consumed outside this ledger. A
	// read error is not treated as a shortage — gate 1 already bounds the
	// commitment, and failing closed on an unreadable /proc/meminfo would stall
	// the whole node.
	if avail, err := l.availFn(); err == nil {
		if avail < memMB+memAdmitHeadroomMB {
			return fmt.Errorf("%w: host MemAvailable %dMB is below the %dMB needed (%dMB guest + %dMB headroom)",
				errInsufficientMemory, avail, memMB+memAdmitHeadroomMB, memMB, memAdmitHeadroomMB)
		}
	}

	l.reservedMB += memMB
	return nil
}

// release returns a reservation to the ledger when a VM is destroyed, or when a
// creation that already admitted fails partway. Clamped at zero so a double
// release cannot manufacture budget out of an underflow. Nil-safe (no-op).
func (l *memLedger) release(memMB uint64) {
	if l == nil || memMB == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if memMB >= l.reservedMB {
		l.reservedMB = 0
		return
	}
	l.reservedMB -= memMB
}

// forceReserve accounts for a VM that entered this node's life without going
// through CreateVerifiedVM — i.e. a RE-ADOPTED survivor. It is already running,
// so there is nothing to admit against: the reservation records the commitment
// so future admissions see it. If the survivor pushes the ledger over budget,
// that is the host's reality (the VM exists); log it — the correct response is
// to shrink the pool target, not to kill a serving VM.
func (l *memLedger) forceReserve(memMB uint64) {
	if l == nil || memMB == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reservedMB += memMB
}

// reserved reports the currently reserved guest memory in MiB.
func (l *memLedger) reserved() uint64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reservedMB
}

// budget reports this node's guest-memory ceiling in MiB (0 = disabled).
func (l *memLedger) budget() uint64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.budgetMB
}
