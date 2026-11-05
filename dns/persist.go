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

package main

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

const stickyPrefix = "/sandswap/dns/sticky/"

// syncLoop periodically flushes dirty sticky entries to etcd.
func (s *DNSServer) syncLoop(ctx context.Context) {
	interval := time.Duration(s.cfg.StickySyncInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush
			s.syncStickyToEtcd()
			return
		case <-ticker.C:
			s.syncStickyToEtcd()
		}
	}
}

// syncStickyToEtcd flushes dirty sticky entries to etcd, at most
// StickySyncBatch per pass (0 = unlimited). The batch bound keeps each pass
// inside its etcd timeout even with a large dirty set; entries not processed
// this pass are re-marked dirty and picked up by the next tick (map iteration
// order is randomized, so passes make fair progress across the set).
func (s *DNSServer) syncStickyToEtcd() {
	s.mu.Lock()
	if len(s.dirty) == 0 {
		s.mu.Unlock()
		return
	}
	// Snapshot the dirty set under the lock, dropping entries that can only
	// produce a pointless RPC: gone from the live sticky map AND never
	// mirrored to etcd (nothing to Put, nothing to Delete). This is what keeps
	// the flush queue bounded under a spoofed-source flood — see
	// markStickyMirrorDeleteLocked.
	dirty := make(map[string]struct{}, len(s.dirty))
	for k := range s.dirty {
		if _, live := s.sticky[k]; !live {
			if _, mirrored := s.mirrored[k]; !mirrored {
				continue // evicted before it was ever written: nothing to do
			}
		}
		dirty[k] = struct{}{}
	}
	s.dirty = make(map[string]struct{})
	s.mu.Unlock()

	// One timeout for the whole (batched) pass — the batch bound keeps the
	// pass short enough to fit inside it.
	etcdCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Entries beyond the batch stay dirty for the next pass.
	var deferred []string
	processed := 0
	for ip := range dirty {
		if s.cfg.StickySyncBatch > 0 && processed >= s.cfg.StickySyncBatch {
			deferred = append(deferred, ip)
			continue
		}
		processed++

		s.mu.RLock()
		entry, exists := s.sticky[ip]
		s.mu.RUnlock()

		if !exists {
			// Deleted → remove the etcd mirror, when one actually exists.
			if !s.isMirrored(ip) {
				continue
			}
			if _, err := s.etcdClient.Delete(etcdCtx, stickyPrefix+ip); err != nil {
				log.Printf("etcd delete sticky %s: %v", ip, err)
				s.remarkDirty(ip)
			} else {
				s.clearMirrored(ip)
			}
			continue
		}

		// Update/create → put to etcd. Marshal a COPY taken under the read
		// lock: touchSticky writes entry.LastQuery under the write lock, so
		// marshalling the live pointer races it (a real data race — `-race`
		// fails, and a torn read can persist a half-updated entry).
		s.mu.RLock()
		snapshot := *entry
		s.mu.RUnlock()
		data, err := json.Marshal(&snapshot)
		if err != nil {
			log.Printf("json marshal sticky %s: %v", ip, err)
			continue
		}
		if _, err := s.etcdClient.Put(etcdCtx, stickyPrefix+ip, string(data)); err != nil {
			log.Printf("etcd put sticky %s: %v", ip, err)
			s.remarkDirty(ip)
			continue
		}
		// The key is (or may have been) written: record the mirror. If the
		// entry was evicted between the snapshot and this Put, the mirror now
		// exists and must be deleted — queue it.
		s.mu.Lock()
		s.noteStickyMirroredLocked(ip)
		if _, live := s.sticky[ip]; !live {
			s.dirty[ip] = struct{}{}
		}
		s.mu.Unlock()
	}
	if len(deferred) > 0 {
		s.mu.Lock()
		for _, ip := range deferred {
			s.markStickyDirtyLocked(ip)
		}
		s.mu.Unlock()
	}
}

// isMirrored reports whether ip currently has a key in etcd.
func (s *DNSServer) isMirrored(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.mirrored[ip]
	return ok
}

// clearMirrored drops the mirror record after a successful Delete.
func (s *DNSServer) clearMirrored(ip string) {
	s.mu.Lock()
	delete(s.mirrored, ip)
	s.mu.Unlock()
}

// remarkDirty re-adds an IP to the dirty set after a failed flush (retry on
// the next sync pass).
func (s *DNSServer) remarkDirty(ip string) {
	s.mu.Lock()
	s.markStickyDirtyLocked(ip)
	s.mu.Unlock()
}

// expireLoop periodically removes expired sticky entries.
func (s *DNSServer) expireLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.expireSticky()
		}
	}
}

// expireSticky removes entries that haven't been queried within sticky_expire seconds.
func (s *DNSServer) expireSticky() {
	s.mu.Lock()
	defer s.mu.Unlock()

	expireSeconds := int64(s.cfg.StickyExpire)
	now := time.Now().Unix()
	expired := 0

	for ip, entry := range s.sticky {
		if now-entry.LastQuery > expireSeconds {
			delete(s.sticky, ip)
			s.markStickyMirrorDeleteLocked(ip)
			expired++
		}
	}

	// Also clean up stale entries whose gateway no longer exists (never
	// registered / permanently retired with its registry key reclaimed). The
	// sticky record carries the gateway_id; validity = that gateway still has a
	// registry record. Death alone does NOT invalidate (the registry plain key
	// survives it; resolveStream's alive check re-selects for those clients).
	// Caller holds s.mu (write) — registryByID is read directly.
	for ip, entry := range s.sticky {
		if entry.GWID == "" {
			// Legacy (pre-gw_id) or malformed record — never answerable.
			delete(s.sticky, ip)
			s.markStickyMirrorDeleteLocked(ip)
			expired++
			continue
		}
		if _, registered := s.registryByID[entry.GWID]; !registered {
			delete(s.sticky, ip)
			s.markStickyMirrorDeleteLocked(ip)
			expired++
		}
	}

	if expired > 0 {
		log.Printf("Expired %d sticky records", expired)
	}
}
