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
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	rpctypes "go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"

	"gateway/lease"
	"gateway/pool"
)

// loadPublishInterval is how often the gateway rewrites its /sandswap/load key.
const loadPublishInterval = 2 * time.Second

// loadKeyTTL is the etcd TTL (seconds) for the load key. It must exceed the
// publish interval so the key survives transient publish gaps, and it expires
// shortly after a gateway dies (DNS stops seeing it).
const loadKeyTTL = 10

// startLoadPublisher publishes /sandswap/load/{gateway_id} every ~2s with the
// gateway's aggregate + per-node scheduling signals. The DNS module watches this
// key for owner-aware routing; the human gateway reads it for the global /stats
// view. A TTL lease expires the key if the gateway dies. No-op when cli is nil
// (single-node mode).
//
// Self-healing: the load lease is re-granted if it expires (KeepAliveOnce
// returns lease-not-found after a >TTL partition / GC pause). Without this, one
// expiry would make the load key vanish permanently and DNS would stop routing
// to this gateway until a full restart.
func startLoadPublisher(ctx context.Context, cli *clientv3.Client, gatewayID string, pm *pool.Manager, sp *lease.SelfPressureMonitor, logger *slog.Logger) {
	if cli == nil {
		return
	}
	key := "/sandswap/load/" + gatewayID

	// grantLoadLease grants a fresh load lease, retrying with backoff until it
	// succeeds or ctx is cancelled. The initial grant must not give up — without
	// a load key the gateway is invisible to DNS routing.
	grantLoadLease := func() clientv3.LeaseID {
		backoff := time.Second
		for {
			if ctx.Err() != nil {
				return 0
			}
			gctx, gcancel := context.WithTimeout(ctx, 5*time.Second)
			gresp, err := cli.Grant(gctx, loadKeyTTL)
			gcancel()
			if err != nil {
				logger.Warn("load: grant lease; retrying", "error", err)
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return 0
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			return gresp.ID
		}
	}

	leaseID := grantLoadLease()
	if leaseID == 0 {
		return // ctx cancelled during initial grant
	}

	write := func() {
		// Keep the persistent lease alive (Put with a lease does not reset TTL).
		kaCtx, kaCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, kaErr := cli.KeepAliveOnce(kaCtx, leaseID)
		kaCancel()
		if kaErr != nil {
			// Lease expired (partition / GC pause > TTL). Re-grant so the load
			// key self-heals instead of vanishing permanently. KeepAliveOnce on
			// a dead lease ID never succeeds again, so we must get a new one.
			if errors.Is(kaErr, rpctypes.ErrLeaseNotFound) {
				logger.Warn("load lease expired; re-granting", "leaseID", leaseID)
				newID := grantLoadLease()
				if newID == 0 {
					return
				}
				leaseID = newID
			} else {
				logger.Warn("load: keep-alive failed", "error", kaErr)
				return
			}
		}

		val := buildLoadValue(gatewayID, pm, sp)
		data, err := json.Marshal(val)
		if err != nil {
			logger.Warn("load: marshal", "error", err)
			return
		}
		pctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := cli.Put(pctx, key, string(data), clientv3.WithLease(leaseID)); err != nil {
			logger.Warn("load: put", "error", err)
		}
	}

	write()
	t := time.NewTicker(loadPublishInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			write()
		case <-ctx.Done():
			return
		}
	}
}

// avgDutyLong returns the mean of per-node duty_long (0 when no nodes).
func avgDutyLong(snap map[string]pool.NodeMetrics) float64 {
	if len(snap) == 0 {
		return 0
	}
	var sum float64
	for _, m := range snap {
		sum += m.DutyLong
	}
	return sum / float64(len(snap))
}

// buildLoadValue assembles the /sandswap/load/{gateway_id} record from the
// pool manager's latest per-node snapshot plus the gateway's self-pressure
// signals. Pure (no etcd) - extracted from the publisher's write() closure so
// the LoadValue construction is unit-testable.
// The DNS reads agg_duty_long + clean_vms from this record for headroom scoring
// + the routing-capacity gates (self_pressured being one — see
// gateway/lease/contract_test.go for the field-name contract). sp may be nil
// (single-node mode): the self_* fields then publish zeros/false.
func buildLoadValue(gatewayID string, pm *pool.Manager, sp *lease.SelfPressureMonitor) lease.LoadValue {
	snap := pm.LoadSnapshot()
	counts := pm.NodeCleanCounts()
	val := lease.LoadValue{
		GatewayID:   gatewayID,
		LastUpdate:  time.Now().Format(time.RFC3339),
		AggDutyLong: avgDutyLong(snap),
		MaxDuty:     maxDutyLong(snap),
		NodeCount:   len(snap),
	}
	if sp != nil {
		cpu, mem, inflight := sp.Snapshot()
		val.SelfCPUPct = cpu
		val.SelfMemPct = mem
		val.SelfInflight = uint32(inflight)
		val.SelfPressured = sp.Pressured()
	}
	var cleanVMs uint32
	for nodeID, m := range snap {
		c := counts[nodeID]
		cleanVMs += c[0]
		val.Nodes = append(val.Nodes, lease.NodeLoad{
			NodeID:       nodeID,
			DutyLong:     m.DutyLong,
			DutyShort:    m.DutyShort,
			DutyDaily:    m.DutyDaily,
			DutyVar:      m.DutyVar,
			HostCPU:      m.HostCPU,
			HostMemAvail: m.HostMemAvailMB,
			ActiveSandfs: m.ActiveSandfs,
			CleanVMs:     c[0],
			TotalVMs:     c[1],
			// The full scheduling signal set rides the load key: /stats builds
			// the cluster view from these keys, so a field omitted here reads
			// as zero for every gateway (including this one, whose own key is
			// aggregated like a peer's). RecycleTriggers is the ops/benchmark
			// signal for VM lifetime-cap churn.
			PeakConcurrentExecs:    m.PeakConcurrentExecs,
			SlotWaitMS:             m.SlotWaitMS,
			SlotWaitEvents:         m.SlotWaitEvents,
			RecycleTriggers:        m.RecycleTriggers,
			StrandedReservationsMB: m.StrandedReservationsMB,
			StrandedCIDs:           m.StrandedCIDs,
		})
	}
	val.CleanVMs = cleanVMs
	return val
}

// maxDutyLong returns the max of per-node duty_long (0 when no nodes).
func maxDutyLong(snap map[string]pool.NodeMetrics) float64 {
	var max float64
	for _, m := range snap {
		if m.DutyLong > max {
			max = m.DutyLong
		}
	}
	return max
}
