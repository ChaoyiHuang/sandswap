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
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// PeerLoad is the subset of a peer gateway's /sandswap/load record that the
// load-shed path needs: whether the peer has spare CLEAN capacity to absorb a
// shed sandfs. Mirrors the fields published by gateway/cmd/loadpublish.go
// (LoadValue) — the field names are the cross-module contract. A peer's routing
// address is read from its /sandswap/gateway/{gw} registry key when a shed
// actually needs to route there; HasIdlePeer only needs the capacity signal.
type PeerLoad struct {
	GatewayID   string
	CleanVMs    uint32
	AggDutyLong float64
	NodeCount   int
	LastSeen    time.Time
}

// PeerLoadMonitor watches /sandswap/load/ to track other gateways' clean-VM
// capacity, so a saturated owner can decide whether to shed a sandfs: shedding
// only makes sense if some peer currently has clean capacity to absorb it.
// Without this, shedding into a cluster-wide saturation just moves the 503.
//
// The gateway already PUBLISHES its own load; this is the read-side mirror
// (the DNS has its own equivalent watch for routing). It is best-effort: a
// missed event is recovered by the periodic full re-list, and stale peers
// (no update within peerLoadStale) are ignored by HasIdlePeer.
type PeerLoadMonitor struct {
	client *clientv3.Client
	selfID string
	logger *slog.Logger

	mu    sync.RWMutex
	peers map[string]*PeerLoad // gatewayID -> load (excludes self)
}

// peerLoadStale is how long a load record is considered fresh. The publisher
// writes every 2s with a 10s TTL; 15s tolerates a couple of missed publishes.
const peerLoadStale = 15 * time.Second

// peerLoadRelist is the safety-net full re-list interval (bounds staleness on
// a missed watch event, mirroring the DNS's 30s re-list).
const peerLoadRelist = 30 * time.Second

// NewPeerLoadMonitor creates a monitor that excludes selfID from its peer map
// (a gateway never sheds to itself). client may be nil (single-node / no etcd):
// HasIdlePeer then always returns false, disabling shedding.
func NewPeerLoadMonitor(client *clientv3.Client, selfID string, logger *slog.Logger) *PeerLoadMonitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &PeerLoadMonitor{
		client: client,
		selfID: selfID,
		logger: logger,
		peers:  make(map[string]*PeerLoad),
	}
}

// Start launches the watch + periodic re-list goroutines. Blocks until ctx is
// cancelled. No-op (returns immediately) when there is no etcd client.
func (p *PeerLoadMonitor) Start(ctx context.Context) {
	if p.client == nil {
		return
	}
	p.refresh(ctx)
	go p.watchLoop(ctx)
	go func() {
		t := time.NewTicker(peerLoadRelist)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.refresh(ctx)
			}
		}
	}()
}

// HasIdlePeer reports whether at least one peer gateway currently has clean VM
// capacity (> 0 clean VMs) and is fresh. This is the "is there somewhere to
// shed TO?" gate: shedding when no peer can absorb the sandfs would just move
// the 503 to another saturated gateway. Self is always excluded.
func (p *PeerLoadMonitor) HasIdlePeer() bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	now := time.Now()
	for _, pl := range p.peers {
		if now.Sub(pl.LastSeen) > peerLoadStale {
			continue
		}
		if pl.CleanVMs > 0 && pl.NodeCount > 0 {
			return true
		}
	}
	return false
}

// watchLoop watches /sandswap/load/ and applies events, reconnecting on error.
func (p *PeerLoadMonitor) watchLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		wch := p.client.Watch(ctx, "/sandswap/load/", clientv3.WithPrefix())
		for resp := range wch {
			if err := resp.Err(); err != nil {
				p.logger.Warn("peerload watch error, reconnecting", "error", err)
				break
			}
			for _, ev := range resp.Events {
				gwID := strings.TrimPrefix(string(ev.Kv.Key), "/sandswap/load/")
				if ev.Type == clientv3.EventTypeDelete {
					p.applyDelete(gwID)
					continue
				}
				p.applyPut(gwID, string(ev.Kv.Value))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// refresh does a full prefix Get to (re)build the peer map. Used at start and
// as the safety net for missed watch events.
func (p *PeerLoadMonitor) refresh(ctx context.Context) {
	if p.client == nil {
		return
	}
	gctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, err := p.client.Get(gctx, "/sandswap/load/", clientv3.WithPrefix())
	if err != nil {
		p.logger.Warn("peerload refresh get", "error", err)
		return
	}
	p.mu.Lock()
	// Rebuild from scratch (full list is authoritative).
	p.peers = make(map[string]*PeerLoad, len(resp.Kvs))
	p.mu.Unlock()
	for _, kv := range resp.Kvs {
		gwID := strings.TrimPrefix(string(kv.Key), "/sandswap/load/")
		p.applyPut(gwID, string(kv.Value))
	}
}

func (p *PeerLoadMonitor) applyPut(gwID, value string) {
	if gwID == "" || gwID == p.selfID {
		return
	}
	var lv struct {
		GatewayID   string  `json:"gateway_id"`
		CleanVMs    uint32  `json:"clean_vms"`
		AggDutyLong float64 `json:"agg_duty_long"`
		NodeCount   int     `json:"node_count"`
	}
	if err := json.Unmarshal([]byte(value), &lv); err != nil {
		return
	}
	p.mu.Lock()
	p.peers[gwID] = &PeerLoad{
		GatewayID:   lv.GatewayID,
		CleanVMs:    lv.CleanVMs,
		AggDutyLong: lv.AggDutyLong,
		NodeCount:   lv.NodeCount,
		LastSeen:    time.Now(),
	}
	p.mu.Unlock()
}

func (p *PeerLoadMonitor) applyDelete(gwID string) {
	if gwID == "" || gwID == p.selfID {
		return
	}
	p.mu.Lock()
	delete(p.peers, gwID)
	p.mu.Unlock()
}
