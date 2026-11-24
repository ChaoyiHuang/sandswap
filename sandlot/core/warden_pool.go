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
	"sync"
	"sync/atomic"

	"sandlot/warden"
)

// wardenPool is a per-VM pool of warden vsock connections enabling parallel
// sync commands on one tinyVM.
//
// The raw vsock frame protocol carries no correlation ID — responses can only
// be matched positionally — so one connection serves exactly ONE in-flight
// request. Parallelism therefore comes from multiple connections: each pool
// slot is a dedicated connection; the slot IS the correlation. The pool size
// is the spec's exec_slots (bounded by guest memory: a full sync exec buffers
// up to ~2x max_body_len of warden-side output).
//
// Connections are dialed lazily on demand and returned to the pool on release,
// so the warm path pays no dial latency (same amortization as the old single
// cached connection). A connection that failed with a TransportError is
// discarded on release, not reused; the next acquire dials a fresh one. This
// gives per-slot failure isolation: one broken slot never poisons the others
// (the old single cached connection forced every queued op through a possibly
// wedged socket).
type wardenPool struct {
	mu      sync.Mutex
	idle    chan *warden.Client // returned connections, cap = limit
	created int                 // connections currently allocated (idle + in use)
	limit   int
	closed  bool // VM dying/destroyed: no new dials, releases discard

	// waiters counts goroutines parked in acquire. It is atomic because
	// keepaliveIdle reads it without p.mu (it must not hold the lock across a
	// warden round trip). The heartbeat checks it to avoid taking an idle
	// connection a queued business request is waiting for; the check is
	// best-effort (a waiter that appears just after it is bounded by the
	// heartbeat's read timeout), but it removes the common case.
	waiters atomic.Int32

	// notify is the broadcast channel for capacity changes: closed and
	// REPLACED under mu whenever any state a parked acquirer waits on changes
	// (a release that discards, a reset, an idle push). Waiters capture the
	// current channel under the same lock in which they observed "no capacity",
	// so a change can never be missed. Without it a parked acquirer slept on
	// <-idle until the PROCESS ctx ended: a broken release (transport error)
	// frees capacity by lowering `created` and pushing nothing, and reset()
	// closes the pool to all future releases — in both cases a waiter that
	// parked BEFORE the change could never wake, holding its command-semaphore
	// token forever (at exec_slots=1, one transport error permanently burns a
	// 1/2000 command slot; recovery required a restart).
	notify chan struct{}
}

func newWardenPool(limit int) *wardenPool {
	if limit < 1 {
		limit = 1
	}
	return &wardenPool{
		idle:   make(chan *warden.Client, limit),
		limit:  limit,
		notify: make(chan struct{}),
	}
}

// broadcastLocked wakes every parked acquirer to re-evaluate. Caller holds mu.
// The classic close-and-replace broadcast: a closed channel is ready for every
// receiver, and capture-under-lock means no wakeup is lost.
func (p *wardenPool) broadcastLocked() {
	close(p.notify)
	p.notify = make(chan struct{})
}

// acquire returns a warden connection and a release func. release(broken)
// returns the connection to the pool, or discards it when broken (transport
// error — the connection may be wedged). Blocks (FIFO on the idle channel)
// while all limit connections are in flight; ctx aborts the wait. waited
// reports that this acquire had to QUEUE (all slots busy) — the grayscale
// signal that exec_slots is undersized for the workload.
func (p *wardenPool) acquire(ctx context.Context, dial func() (*warden.Client, error)) (*warden.Client, func(bool), bool, error) {
	for {
		// Fast path: an idle connection is available.
		select {
		case c := <-p.idle:
			return c, func(broken bool) { p.release(c, broken) }, false, nil
		default:
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, nil, false, errWardenPoolClosed
		}
		if p.created < p.limit {
			// Reserve the slot before dialing so concurrent acquirers cannot
			// oversubscribe the limit.
			p.created++
			p.mu.Unlock()
			c, err := dial()
			if err != nil {
				p.mu.Lock()
				p.created--
				p.broadcastLocked()
				p.mu.Unlock()
				return nil, nil, false, err
			}
			return c, func(broken bool) { p.release(c, broken) }, false, nil
		}
		// All slots allocated and busy: capture the broadcast channel in the
		// SAME critical section that observed "no capacity" — any later
		// capacity change closes it and wakes us to re-evaluate (re-dial,
		// fail fast on a closed pool, or park again). Publish the waiter under
		// the same lock so keepaliveIdle sees it before it can take an idle
		// connection out from under this request.
		changed := p.notify
		p.waiters.Add(1)
		p.mu.Unlock()
		select {
		case c := <-p.idle:
			p.waiters.Add(-1)
			return c, func(broken bool) { p.release(c, broken) }, true, nil
		case <-changed:
			p.waiters.Add(-1)
			continue
		case <-ctx.Done():
			p.waiters.Add(-1)
			return nil, nil, false, ctx.Err()
		}
	}
}

// keepaliveIdle runs fn on every idle pooled connection it can take, one at a
// time, and returns each to the pool (discarding it when fn reports it broken).
// It never dials, never waits, and never touches a connection a business request
// holds. Returns how many idle connections fn ran on.
//
// Why: the warden closes an authenticated connection that stays silent for
// POST_DELIVERY_IDLE_TIMEOUT (300s) — any frame resets that timer. The pool's
// idle connections ARE silent between requests, so after a quiet stretch every
// pooled slot was closed by the peer without the pool knowing; the next
// acquire handed a dead connection to the first request, its write failed with
// EPIPE, and the mount path treats ANY MountAndExec error as "guest mount
// state unproven" and destroys the VM (commands.go) — a 1–3s rebuild + 503 on
// the first request after every idle period, per pool VM. Feeding the idle
// slots the probe loop's existing OP_MEM_STATS heartbeat keeps them inside the
// warden's window; a slot that is found already dead is discarded here (broken)
// and the next acquire dials fresh, so the business path never sees it.
//
// EVERY idle slot, not one: a pool holds exec_slots connections and the warden
// closes each one on its own timer, so keeping one alive leaves the others to
// die — the first multi-slot burst after a quiet stretch would still hit a
// dead connection. Each slot is taken out of the idle queue, used, and put
// back BEFORE the next is taken: at most one slot is out of the queue PER CALL,
// the queue order rotates, and every slot is covered across sweeps. A business
// acquire that lands mid-sweep sees one slot fewer (with limit=1 that is the
// whole pool, so acquire parks until this call releases it — the caller bounds
// that hold with its own read timeout).
//
// A parked acquirer is business latency, so keepalive yields to it: when any
// waiter exists this call stops immediately and leaves the slots to business.
// The probe caller then sees visited==0 and falls back to a fresh short-lived
// dial, so the VM heartbeat still goes out. The check is best-effort (waiters
// is read without p.mu); a waiter that appears just after it is bounded by the
// heartbeat read timeout.
//
// fn runs WITHOUT p.mu held and with its connection out of the idle queue, so
// it is mutually exclusive with acquire/release by construction (the slot is
// the correlation — one in-flight request per connection).
func (p *wardenPool) keepaliveIdle(fn func(c *warden.Client) bool) (visited int) {
	n := len(p.idle)
	for i := 0; i < n; i++ {
		if p.waiters.Load() > 0 {
			return visited
		}
		var c *warden.Client
		select {
		case c = <-p.idle:
		default:
			return visited
		}
		p.release(c, !fn(c))
		visited++
	}
	return visited
}

// drainIdle closes every idle connection while keeping the pool OPEN. It is the
// reconnect-path counterpart of reset(): the probe loop stops on entering
// CLEANING and the warden closes authenticated connections after
// POST_DELIVERY_IDLE_TIMEOUT (300s), so after the CLEANING + isolation window
// every surviving idle slot is already peer-closed. Handing one to the first
// business request would fail the mount RPC and dirty-destroy a healthy VM, so
// the reconnect path drains the pools before announcing the node; the first
// acquire then dials fresh.
//
// Connections held by an in-flight request are not touched (they are not in the
// idle queue); their release returns them normally because the pool stays open.
// Caller must run this while no new business traffic can arrive (before hello).
func (p *wardenPool) drainIdle() (closed int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		select {
		case c := <-p.idle:
			_ = c.Close()
			p.created--
			closed++
		default:
			if closed > 0 {
				p.broadcastLocked() // capacity freed: parked acquirers re-check
			}
			return closed
		}
	}
}

// release returns a connection to the pool, or discards it when broken.
//
// The idle-channel push happens under mu. It can never block: idle has
// capacity == limit and holds at most created-1 connections at release time
// (in-use connections are not in idle), so created <= limit bounds the queue
// below capacity. Holding mu also closes the race against reset() — a conn
// returned while the pool is closing is discarded instead of lingering in a
// closed pool's queue.
func (p *wardenPool) release(c *warden.Client, broken bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if broken || p.closed {
		_ = c.Close()
		p.created--
		p.broadcastLocked() // capacity freed: parked acquirers must re-check
		return
	}
	p.idle <- c
	// The push alone wakes one idle-receiver; broadcast so a waiter that raced
	// the receive re-evaluates instead of sleeping on a stale snapshot.
	p.broadcastLocked()
}

// reset tears the pool down (VM died / destroy / re-adopt): idle connections
// are closed, new dials are refused, and in-use connections are discarded by
// their holders' release(broken) — or by release(false) after a reset.
func (p *wardenPool) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for {
		select {
		case c := <-p.idle:
			_ = c.Close()
			p.created--
		default:
			// Parked acquirers must wake and observe `closed` — every future
			// release discards, so nothing else would ever signal them.
			p.broadcastLocked()
			return
		}
	}
}

var errWardenPoolClosed = &poolClosedError{}

type poolClosedError struct{}

func (e *poolClosedError) Error() string { return "warden connection pool closed (VM destroyed)" }

// warmup pre-dials one connection into the idle pool (best-effort pre-warming
// after VM creation). No-op if the pool is closed or already at its limit.
func (p *wardenPool) warmup(dial func() (*warden.Client, error)) {
	p.mu.Lock()
	if p.closed || p.created >= p.limit {
		p.mu.Unlock()
		return
	}
	p.created++
	p.mu.Unlock()
	c, err := dial()
	if err != nil {
		p.mu.Lock()
		p.created--
		p.broadcastLocked()
		p.mu.Unlock()
		return
	}
	p.release(c, false)
}

// seedWardenClient injects c as the pool's idle connection, replacing (and
// closing) whatever idle connection was there. Test seam: the fake warden
// clients in the handler tests are seeded through this instead of the old
// `state.Warden = agt` field write.
func (vm *VMState) seedWardenClient(c *warden.Client) {
	p := vm.wardenPoolFor()
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		select {
		case old := <-p.idle:
			_ = old.Close()
			p.created--
			continue
		default:
		}
		break
	}
	if p.closed || p.created >= p.limit {
		_ = c.Close()
		return
	}
	p.created++
	p.idle <- c
}
