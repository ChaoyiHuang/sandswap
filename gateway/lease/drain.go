// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

package lease

import (
	"log/slog"
	"time"

	"gateway/pool"
)

// Drainer brings a sandfs from "possibly mounted somewhere" to "mounts
// released on every connected node" — the shared primitive behind template
// detach and sandfs deletion. It lives in lease (not pool) because the drain
// is a coordinated dance across BOTH the lease entries and the node sweep;
// lease already imports pool, never the reverse.
//
// The caller MUST have already flipped the sandfs record's lifecycle status
// (detaching/deleting) — the exec gate blocking new requests is what makes
// the drain converge. The drain itself never needs to guess: every action is
// idempotent, and the only failure mode of an early deadline is "not yet
// drained" (the lease retry chain continues in the background; re-issuing the
// drain resumes it).
type Drainer struct {
	Pool   *pool.Manager
	Lease  *Lease
	Logger *slog.Logger
	// DispatchProbe reports whether a cold mount for the sandfs is in flight
	// or queued (nil = DispatchInFlight, the process's registered MountLock).
	// A cold mount holds no lease entry until its RPC returns, so the lease
	// alone cannot see it: settling while one is in flight writes "detached"
	// (or deletes the volume) under a mount that lands moments later.
	DispatchProbe func(sandfsID string) bool
}

// dispatchInFlight consults the explicit probe, else the process's registered
// cold-mount lock.
func (d *Drainer) dispatchInFlight(sandfsID string) bool {
	if d.DispatchProbe != nil {
		return d.DispatchProbe(sandfsID)
	}
	return DispatchInFlight(sandfsID)
}

// drainSweepInterval is the retry cadence of the node-sweep loop inside one
// Drain call. Each UnmountRootfs attempt can itself take up to its 8s RPC
// budget (the node-side handler deliberately waits out in-flight sync execs
// via the mount gate), so this interval only spaces attempts after fast
// failures.
const drainSweepInterval = 500 * time.Millisecond

// Drain blocks until the sandfs is provably unmounted on every connected
// node, or ctx/deadline elapses. Sequence per round:
//
//  1. ForceUnmount the local lease entry when one exists (first sight, and
//     again if an entry APPEARS mid-drain — a cold mount that completed after
//     the drain began): it dispatches the expiry unmount immediately and, on
//     failure, leaves the entry in the retrying `unmounting` state (its
//     backoff chain persists past this call). Without the re-dispatch a
//     mid-drain entry never settles and the drain burns its whole budget
//     even though the node sweep already released the mount.
//  2. Sweep UnmountRootfs over every connected node; a node whose RPC fails
//     (typically: a sync exec longer than the 8s RPC budget still holds the
//     mount gate) is retried next round — this is how long execs drain.
//  3. Settled when every node acknowledged, the lease entry is gone
//     (SettleUnmount deletes it only after a successful unmount), AND no cold
//     mount is in flight or queued (a dispatch has no lease entry yet).
//  4. Before reporting success, sweep once more and re-check: a mount that
//     landed between the previous sweep and the settle decision is released
//     by that final sweep, and the decision is re-validated afterwards.
//
// On success it additionally sweeps the host-side overlay cleanup
// (best-effort; offline-node stragglers are backstopped by the mount-time
// expected-ref check). Returns true = fully drained; false = deadline hit
// first — safe to re-issue.
func (d *Drainer) Drain(sandfsID, volumePath, volumeEpoch string, budget time.Duration) bool {
	if d.Pool == nil || d.Lease == nil {
		// No pool/lease (e.g. a human gateway without exec duties): with no
		// node transport there is nothing this process can drain or verify —
		// report drained and let the caller's own placement logic decide.
		return d.Pool == nil
	}
	deadline := time.Now().Add(budget)
	hadEntry := false

	for {
		if node, spec, ok := d.Lease.EntryInfo(sandfsID); ok && !hadEntry {
			d.Lease.ForceUnmount(sandfsID, node, spec)
			hadEntry = true
		} else if !ok {
			hadEntry = false
		}
		allOK := d.Pool.UnmountSandfsFromAll(sandfsID, volumePath, volumeEpoch)
		settled := !d.Lease.HasEntry(sandfsID)
		inFlight := d.dispatchInFlight(sandfsID)
		if allOK && settled && !inFlight {
			// Final sweep after the last dispatch cleared (see step 4).
			allOK = d.Pool.UnmountSandfsFromAll(sandfsID, volumePath, volumeEpoch)
			if allOK && !d.Lease.HasEntry(sandfsID) && !d.dispatchInFlight(sandfsID) {
				d.Pool.CleanupOverlayForSandFS(sandfsID, volumePath)
				return true
			}
			settled = false
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if d.Logger != nil {
				d.Logger.Warn("sandfs drain deadline elapsed before full drain (lease retry chain continues; re-issue to resume)",
					"sandfsID", sandfsID, "nodesOK", allOK, "leaseSettled", settled, "mountInFlight", inFlight)
			}
			return false
		}
		wait := drainSweepInterval
		if remaining < wait {
			wait = remaining
		}
		time.Sleep(wait)
	}
}
