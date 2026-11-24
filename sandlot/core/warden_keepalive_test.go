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
	"net"
	"testing"
	"time"

	"sandlot/vmm"
	"sandlot/warden"
)

// These tests pin the fix for the idle-pool-slot regression: the warden closes
// an authenticated connection that is silent for 300s (its per-connection idle
// bound), the slot pool's idle connections are silent by design, and the
// heartbeat probe used to dial its OWN connection — so after a quiet stretch
// every pooled slot was peer-closed while the heartbeat stayed green, and the
// first MountAndExec after it failed with EPIPE, which the mount path must
// treat as "guest mount state unproven" and destroy the VM. The fix rides the
// heartbeat on EVERY idle pooled slot (wardenPool.keepaliveIdle via probeVM),
// so idle slots stay inside the window and a slot found dead is discarded
// before any business request sees it.

// seededPool builds a handler with one VM whose slot pool is `slots` wide and
// holds exactly `slots` idle connections into fw. The pool only dials when its
// idle queue is empty, so the seeds are acquired TOGETHER (all held, then all
// released) — acquiring one at a time would hand the same slot back every
// time. The returned dial func counts every connection dialed through it
// (the seeds are not counted).
func seededPool(t *testing.T, fw *fakeWarden, slots int) (*Handler, *VMState, func() (*warden.Client, error), *int) {
	t.Helper()
	h := newTestHandler()
	st := &VMState{VM: &vmm.RunningVM{ID: "ka-vm", GuestCID: 42}, SpecID: "small"}
	st.execSlots.Store(int64(slots))
	h.vms[st.VM.ID] = st

	seed := func() (*warden.Client, error) { return dialFake(t, fw), nil }
	p := st.wardenPoolFor()
	rels := make([]func(bool), 0, slots)
	for i := 0; i < slots; i++ {
		_, release, _, err := p.acquire(context.Background(), seed)
		if err != nil {
			t.Fatalf("seed acquire %d: %v", i, err)
		}
		rels = append(rels, release)
	}
	for _, release := range rels {
		release(false)
	}
	dials := 0
	dial := func() (*warden.Client, error) {
		dials++
		return dialFake(t, fw), nil
	}
	// Production code consults this seam for every non-pool dial (the probe's
	// fallback), so the same counter covers both business and probe dials.
	h.testDialFn = func(cid uint32, _ time.Duration) (*warden.Client, error) { return dial() }
	// The fake accepts connections on its own goroutines; wait until it has
	// seen all of them so tests can address fw.conns deterministically.
	deadline := time.Now().Add(2 * time.Second)
	for {
		fw.mu.Lock()
		n := len(fw.conns)
		fw.mu.Unlock()
		if n >= slots {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake warden accepted %d connection(s) within 2s; want %d", n, slots)
		}
		time.Sleep(time.Millisecond)
	}
	return h, st, dial, &dials
}

// connsAndOps snapshots the fake's accepted connections and op log.
func connsAndOps(fw *fakeWarden) (conns int, ops []uint8) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return len(fw.conns), append([]uint8(nil), fw.ops...)
}

// TestProbeVM_RidesEveryIdleSlot is the core regression: a heartbeat on a VM
// with N idle slots must send N MemStats — one on EACH slot's connection —
// and must not dial. Keeping one slot alive leaves the rest to die at the
// warden's per-connection bound; the first multi-slot burst after a quiet
// stretch would still hit a dead connection.
func TestProbeVM_RidesEveryIdleSlot(t *testing.T) {
	const slots = 3
	fw := &fakeWarden{memStatsReply: "1000 2000"}
	h, st, dial, dials := seededPool(t, fw, slots)

	if _, _, err := h.probeVM(st); err != nil {
		t.Fatalf("probeVM: %v", err)
	}
	conns, ops := connsAndOps(fw)
	if *dials != 0 {
		t.Fatalf("probe dialed %d new connection(s); want 0 (must reuse idle slots)", *dials)
	}
	if conns != slots {
		t.Fatalf("fake saw %d conn(s); want %d (no new connections)", conns, slots)
	}
	if len(ops) != slots {
		t.Fatalf("ops = %v; want %d MemStats (one per idle slot)", ops, slots)
	}
	for _, op := range ops {
		if op != fakeOpMemStats {
			t.Fatalf("ops = %v; want only MemStats", ops)
		}
	}
	// Every slot is back in the pool: `slots` acquires succeed with no dial.
	for i := 0; i < slots; i++ {
		_, release, _, err := st.wardenPoolFor().acquire(context.Background(), dial)
		if err != nil {
			t.Fatalf("acquire %d after heartbeat: %v", i, err)
		}
		release(false)
	}
	if *dials != 0 {
		t.Fatalf("acquires after heartbeat dialed %d; want 0 (all slots returned)", *dials)
	}
}

// TestProbeVM_FallsBackToDialWhenNoIdleSlot pins the independence guarantee:
// with every slot held by an in-flight request, the heartbeat must still go
// out — on a fresh connection — rather than block or skip. A long sync exec
// must never stall its own VM's heartbeat (the warden countdown anchor).
func TestProbeVM_FallsBackToDialWhenNoIdleSlot(t *testing.T) {
	fw := &fakeWarden{memStatsReply: "1 2"}
	h, st, dial, dials := seededPool(t, fw, 1)

	_, release, _, err := st.wardenPoolFor().acquire(context.Background(), dial)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release(false)

	avail, total, err := h.probeVM(st)
	if err != nil || avail != 1 || total != 2 {
		t.Fatalf("probeVM with busy pool = %d, %d, %v; want 1, 2, nil", avail, total, err)
	}
	if *dials != 1 {
		t.Fatalf("probe dialed %d; want exactly 1 fresh connection (pool busy)", *dials)
	}
}

// TestProbeVM_DeadSlotDiscarded_VMStillHealthy is the production failure
// absorbed: one idle slot is already peer-closed (the warden's idle bound)
// while another is alive. The sweep discards the dead one, the live one
// answers, and the probe SUCCEEDS — a dead slot is a connection fact, not a
// VM fact. Reporting it as a failed probe would count a healthy VM toward
// probeFailureThreshold and tear it down as "hung": a self-inflicted
// replacement loop.
func TestProbeVM_DeadSlotDiscarded_VMStillHealthy(t *testing.T) {
	fw := &fakeWarden{memStatsReply: "1000 2000", deadMemStatsConns: map[net.Conn]struct{}{}}
	h, st, dial, dials := seededPool(t, fw, 2)
	// The FIRST connection the fake ever accepted (slot A) is the dead one.
	fw.mu.Lock()
	fw.deadMemStatsConns[fw.conns[0]] = struct{}{}
	fw.mu.Unlock()

	avail, total, err := h.probeVM(st)
	if err != nil || avail != 1000 || total != 2000 {
		t.Fatalf("probeVM = %d, %d, %v; want 1000, 2000, nil (the live slot answers)", avail, total, err)
	}
	p := st.wardenPoolFor()
	p.mu.Lock()
	created := p.created
	p.mu.Unlock()
	if created != 1 {
		t.Fatalf("pool created = %d after discarding one dead slot; want 1", created)
	}
	if *dials != 0 {
		t.Fatalf("probe dialed %d; want 0 (a live slot answered; no fallback)", *dials)
	}
	// The surviving slot is live for business use without a dial.
	agt, release, _, err := p.acquire(context.Background(), dial)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release(false)
	if _, _, err := agt.MemStats(); err != nil {
		t.Fatalf("surviving slot is not live: %v", err)
	}
	if *dials != 0 {
		t.Fatalf("acquire dialed %d; want 0", *dials)
	}
}

// TestProbeVM_AllSlotsDead_FallsBackToFreshDial: when EVERY idle slot is
// peer-closed, the sweep discards them and — because all failures were on the
// transport — immediately verifies reachability over a fresh short-lived dial.
// A healthy VM therefore reports success in the same heartbeat and is never
// counted toward probeFailureThreshold (the dead slots were a connection fact,
// not a VM fact).
func TestProbeVM_AllSlotsDead_FallsBackToFreshDial(t *testing.T) {
	fw := &fakeWarden{memStatsReply: "1000 2000", deadMemStatsConns: map[net.Conn]struct{}{}}
	h, st, _, dials := seededPool(t, fw, 2)
	fw.mu.Lock()
	fw.deadMemStatsConns[fw.conns[0]] = struct{}{}
	fw.deadMemStatsConns[fw.conns[1]] = struct{}{}
	fw.mu.Unlock()

	avail, total, err := h.probeVM(st)
	if err != nil || avail != 1000 || total != 2000 {
		t.Fatalf("probe with every idle slot dead = %d, %d, %v; want 1000, 2000, nil (fresh dial proves the VM healthy)",
			avail, total, err)
	}
	p := st.wardenPoolFor()
	p.mu.Lock()
	created := p.created
	p.mu.Unlock()
	if created != 0 {
		t.Fatalf("pool created = %d; want 0 (both dead slots discarded)", created)
	}
	if *dials != 1 {
		t.Fatalf("probe dialed %d; want 1 (fresh-dial reachability check)", *dials)
	}

	// The pool is empty now; the next heartbeat dials again and stays healthy.
	avail, total, err = h.probeVM(st)
	if err != nil || avail != 1000 || total != 2000 {
		t.Fatalf("probe after discard = %d, %d, %v; want 1000, 2000, nil", avail, total, err)
	}
	if *dials != 2 {
		t.Fatalf("probe dialed %d; want 2 (empty-pool fallback)", *dials)
	}
}

// TestProbeVM_AllSlotsDead_FreshDialFails_ReportsFailure pins the other half:
// when the all-idle sweep failed on the transport AND the fresh reachability
// dial also fails, the probe reports the failure so the caller counts it.
func TestProbeVM_AllSlotsDead_FreshDialFails_ReportsFailure(t *testing.T) {
	fw := &fakeWarden{memStatsReply: "1000 2000", deadMemStatsConns: map[net.Conn]struct{}{}}
	h, st, _, _ := seededPool(t, fw, 1)
	fw.mu.Lock()
	fw.deadMemStatsConns[fw.conns[0]] = struct{}{}
	fw.mu.Unlock()

	wantErr := errors.New("dial refused")
	dialCalls := 0
	h.testDialFn = func(uint32, time.Duration) (*warden.Client, error) {
		dialCalls++
		return nil, wantErr
	}
	_, _, err := h.probeVM(st)
	if !errors.Is(err, wantErr) {
		t.Fatalf("probe = %v; want the fresh-dial error %v", err, wantErr)
	}
	if dialCalls != 1 {
		t.Fatalf("fresh dial called %d time(s); want 1", dialCalls)
	}
}

// TestProbeVM_MixedTransportAndBusinessError_DialsForReachability: a transport
// error on one idle slot and an APP_ERROR on another is still "no slot
// proved reachable", so the fresh-dial check runs; the APP_ERROR slot is kept
// (healthy transport, sick guest) while the dead one is discarded.
func TestProbeVM_MixedTransportAndBusinessError_DialsForReachability(t *testing.T) {
	fw := &fakeWarden{
		memStatsReply:         "1000 2000",
		deadMemStatsConns:     map[net.Conn]struct{}{},
		appErrorMemStatsConns: map[net.Conn]struct{}{},
	}
	h, st, _, dials := seededPool(t, fw, 2)
	fw.mu.Lock()
	fw.deadMemStatsConns[fw.conns[0]] = struct{}{}
	fw.appErrorMemStatsConns[fw.conns[1]] = struct{}{}
	fw.mu.Unlock()

	avail, total, err := h.probeVM(st)
	if err != nil || avail != 1000 || total != 2000 {
		t.Fatalf("probe = %d, %d, %v; want 1000, 2000, nil (fresh dial proves the VM reachable)", avail, total, err)
	}
	if *dials != 1 {
		t.Fatalf("probe dialed %d; want 1 (transport failure warrants a reachability dial)", *dials)
	}
	p := st.wardenPoolFor()
	p.mu.Lock()
	created := p.created
	p.mu.Unlock()
	if created != 1 {
		t.Fatalf("pool created = %d; want 1 (the APP_ERROR slot is kept, the dead one discarded)", created)
	}
}

// TestProbeVM_KeepsSlotOnBusinessError pins the broken-vs-sick distinction:
// an APP_ERROR MemStats reply (/proc/meminfo unreadable) is a HEALTHY
// transport reporting a sick guest. The probe must surface the error (so the
// probe-failure accounting sees it) but the slot must stay pooled.
func TestProbeVM_KeepsSlotOnBusinessError(t *testing.T) {
	fw := &fakeWarden{memStatsAppError: true}
	h, st, dial, dials := seededPool(t, fw, 1)

	_, _, err := h.probeVM(st)
	if err == nil {
		t.Fatal("probe with APP_ERROR MemStats returned nil; want the business error surfaced")
	}
	if isWardenTransportErr(err) {
		t.Fatalf("APP_ERROR classified as a transport error: %v; the slot must not be discarded for it", err)
	}
	p := st.wardenPoolFor()
	p.mu.Lock()
	created := p.created
	p.mu.Unlock()
	if created != 1 {
		t.Fatalf("pool created = %d after a business error; want 1 (slot kept)", created)
	}
	_, release, _, err := p.acquire(context.Background(), dial)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release(false)
	if *dials != 0 {
		t.Fatalf("acquire dialed %d; want 0 (slot survived the business error)", *dials)
	}
}

// TestKeepaliveIdle_Contract pins wardenPool.keepaliveIdle itself: empty → 0
// and fn never runs; every idle slot visited exactly once per sweep, returned
// on fn(true), dropped on fn(false) with capacity freed for a re-dial.
func TestKeepaliveIdle_Contract(t *testing.T) {
	fw := &fakeWarden{}
	p := newWardenPool(3)
	dials := 0
	dial := func() (*warden.Client, error) { dials++; return dialFake(t, fw), nil }

	ran := 0
	if n := p.keepaliveIdle(func(*warden.Client) bool { ran++; return true }); n != 0 || ran != 0 {
		t.Fatalf("keepaliveIdle on empty pool = %d, fn ran %d; want 0, 0", n, ran)
	}

	// Three idle slots (all held, then all released — the pool only dials
	// when its idle queue is empty): each visited exactly once per sweep.
	var held []*warden.Client
	var rels []func(bool)
	for i := 0; i < 3; i++ {
		c, rel, _, _ := p.acquire(context.Background(), dial)
		held = append(held, c)
		rels = append(rels, rel)
	}
	for _, rel := range rels {
		rel(false)
	}
	visited := map[*warden.Client]int{}
	if n := p.keepaliveIdle(func(c *warden.Client) bool { visited[c]++; return true }); n != 3 {
		t.Fatalf("keepaliveIdle = %d; want 3", n)
	}
	for _, c := range held {
		if visited[c] != 1 {
			t.Fatalf("slot visited %d times; want exactly 1", visited[c])
		}
	}
	// All three still pooled: a second sweep visits the same three objects
	// and nothing was dialed.
	visited2 := map[*warden.Client]int{}
	if n := p.keepaliveIdle(func(c *warden.Client) bool { visited2[c]++; return true }); n != 3 {
		t.Fatalf("second keepaliveIdle = %d; want 3 (all slots returned by the first)", n)
	}
	for _, c := range held {
		if visited2[c] != 1 {
			t.Fatalf("second sweep visited a kept slot %d times; want 1", visited2[c])
		}
	}
	if dials != 3 {
		t.Fatalf("dials = %d; want 3 (the seeds only)", dials)
	}

	// Now report every slot dead on the next sweep: all discarded, capacity freed.
	if n := p.keepaliveIdle(func(*warden.Client) bool { return false }); n != 3 {
		t.Fatalf("keepaliveIdle = %d; want 3", n)
	}
	p.mu.Lock()
	created := p.created
	p.mu.Unlock()
	if created != 0 {
		t.Fatalf("created = %d after all-dead sweep; want 0", created)
	}
	c, rel, _, err := p.acquire(context.Background(), dial)
	if err != nil || dials != 4 {
		t.Fatalf("acquire after discard = %v (dials=%d); want a fresh dial (dials=4)", err, dials)
	}
	_ = c
	rel(false)
}

// TestKeepaliveIdle_DoesNotTouchHeldSlots: slots held by business requests are
// not in the idle queue, so a sweep cannot take them — the two are mutually
// exclusive by construction (the slot IS the correlation). With 2 of 3 held,
// exactly the one idle slot is visited.
func TestKeepaliveIdle_DoesNotTouchHeldSlots(t *testing.T) {
	fw := &fakeWarden{}
	p := newWardenPool(3)
	dial := func() (*warden.Client, error) { return dialFake(t, fw), nil }
	heldA, relA, _, _ := p.acquire(context.Background(), dial)
	heldB, relB, _, _ := p.acquire(context.Background(), dial)
	defer relA(false)
	defer relB(false)
	_, relC, _, _ := p.acquire(context.Background(), dial)
	relC(false)

	var seen []*warden.Client
	if n := p.keepaliveIdle(func(c *warden.Client) bool { seen = append(seen, c); return true }); n != 1 {
		t.Fatalf("keepaliveIdle = %d; want 1 (only the idle slot)", n)
	}
	for _, c := range seen {
		if c == heldA || c == heldB {
			t.Fatal("keepaliveIdle took a slot a business request holds")
		}
	}
}

// TestIdleSlotsSurviveHeartbeatsThenParallelExec is the end-to-end shape of
// the bug at pool width: an idle pool is heartbeated several times (as the 3s
// probe loop does over a quiet stretch), and a following parallel burst of
// MountAndExec calls — one per slot — all run on the SAME connections and
// succeed with no re-dial: no "mount state unproven", no VM replacement.
func TestIdleSlotsSurviveHeartbeatsThenParallelExec(t *testing.T) {
	const slots = 3
	fw := &fakeWarden{memStatsReply: "1000 2000", execStatus: 0, execStdout: "ok"}
	h, st, dial, dials := seededPool(t, fw, slots)

	for i := 0; i < 5; i++ {
		if _, _, err := h.probeVM(st); err != nil {
			t.Fatalf("heartbeat %d: %v", i, err)
		}
	}
	conns, _ := connsAndOps(fw)
	if conns != slots || *dials != 0 {
		t.Fatalf("5 sweeps used %d conn(s) / %d dial(s); want %d / 0", conns, *dials, slots)
	}

	// A parallel burst takes every slot; each MountAndExec must succeed on the
	// slot it got (a dead one would fail with EPIPE here).
	type result struct {
		err  error
		exit int
	}
	results := make(chan result, slots)
	for i := 0; i < slots; i++ {
		go func() {
			agt, release, _, err := st.wardenPoolFor().acquire(context.Background(), dial)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer release(false)
			_, _, exit, _, _, _, merr := agt.MountAndExec("/dev/x", "/mnt/rootfs", "true", 5*time.Second, false, "flat")
			results <- result{err: merr, exit: exit}
		}()
	}
	for i := 0; i < slots; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("MountAndExec %d on a heartbeated slot: %v (this is the EPIPE the fix removes)", i, r.err)
		}
		if r.exit != 0 {
			t.Fatalf("MountAndExec %d exit = %d; want 0", i, r.exit)
		}
	}
	if *dials != 0 {
		t.Fatalf("burst dialed %d; want 0 (every slot was live)", *dials)
	}
}

// TestKeepaliveIdle_YieldsToParkedAcquirer pins the latency guard: while a
// business acquire is parked, keepalive must leave the idle connections to it
// (the probe caller then falls back to a fresh dial, so the VM heartbeat still
// goes out). Once the waiter leaves, the slot is probed normally.
func TestKeepaliveIdle_YieldsToParkedAcquirer(t *testing.T) {
	fw := &fakeWarden{}
	p := newWardenPool(1)
	dial := func() (*warden.Client, error) { return dialFake(t, fw), nil }
	_, release, _, err := p.acquire(context.Background(), dial)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release(false) // one idle slot

	p.waiters.Add(1)
	ran := 0
	if n := p.keepaliveIdle(func(*warden.Client) bool { ran++; return true }); n != 0 || ran != 0 {
		t.Fatalf("keepaliveIdle with a parked acquirer = %d, fn ran %d; want 0, 0", n, ran)
	}
	p.waiters.Add(-1)

	if n := p.keepaliveIdle(func(*warden.Client) bool { ran++; return true }); n != 1 || ran != 1 {
		t.Fatalf("keepaliveIdle after the waiter left = %d, fn ran %d; want 1, 1", n, ran)
	}
}

// TestKeepaliveIdle_ResetMidSweep: a reset (VM destroyed) while fn holds a
// connection must discard that connection on release, not leak it into a
// closed pool or corrupt the created count.
func TestKeepaliveIdle_ResetMidSweep(t *testing.T) {
	fw := &fakeWarden{}
	p := newWardenPool(1)
	dial := func() (*warden.Client, error) { return dialFake(t, fw), nil }
	_, release, _, err := p.acquire(context.Background(), dial)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release(false) // one idle slot

	ran := 0
	if n := p.keepaliveIdle(func(*warden.Client) bool {
		ran++
		p.reset()
		return true
	}); n != 1 || ran != 1 {
		t.Fatalf("keepaliveIdle = %d, fn ran %d; want 1, 1", n, ran)
	}
	p.mu.Lock()
	created := p.created
	p.mu.Unlock()
	if created != 0 {
		t.Fatalf("created = %d after reset-mid-sweep; want 0 (the held connection was discarded on release)", created)
	}
	if _, _, _, err := p.acquire(context.Background(), dial); !errors.Is(err, errWardenPoolClosed) {
		t.Fatalf("acquire on the reset pool = %v; want errWardenPoolClosed", err)
	}
}

// TestDrainIdle_ClosesIdleKeepsPoolOpen: the reconnect-path drain closes every
// idle connection, leaves the pool OPEN, and the next acquire dials fresh.
func TestDrainIdle_ClosesIdleKeepsPoolOpen(t *testing.T) {
	fw := &fakeWarden{memStatsReply: "1 2"}
	_, st, dial, dials := seededPool(t, fw, 2)
	p := st.wardenPoolFor()

	if n := p.drainIdle(); n != 2 {
		t.Fatalf("drainIdle = %d; want 2", n)
	}
	p.mu.Lock()
	created := p.created
	closed := p.closed
	p.mu.Unlock()
	if created != 0 || closed {
		t.Fatalf("after drain: created=%d closed=%v; want 0, false (pool stays open)", created, closed)
	}
	agt, release, _, err := p.acquire(context.Background(), dial)
	if err != nil {
		t.Fatalf("acquire after drain: %v", err)
	}
	defer release(false)
	if *dials != 1 {
		t.Fatalf("acquire dialed %d; want 1 (fresh connection after drain)", *dials)
	}
	if _, _, err := agt.MemStats(); err != nil {
		t.Fatalf("fresh slot is not usable: %v", err)
	}
}

// TestDrainIdleWardenConns: the handler-level reconnect drain reaches every
// VM's pool.
func TestDrainIdleWardenConns(t *testing.T) {
	fw := &fakeWarden{}
	h, st, _, _ := seededPool(t, fw, 2)
	if n := h.DrainIdleWardenConns(); n != 2 {
		t.Fatalf("DrainIdleWardenConns = %d; want 2", n)
	}
	p := st.wardenPoolFor()
	p.mu.Lock()
	created := p.created
	closed := p.closed
	p.mu.Unlock()
	if created != 0 || closed {
		t.Fatalf("after handler drain: created=%d closed=%v; want 0, false", created, closed)
	}
}
