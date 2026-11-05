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
	"log"
	"sync"

	"golang.org/x/sys/unix"
)

// pidfdMonitor watches the sandvmm processes of re-adopted microVMs for exit
// using a SINGLE epoll loop, scaling to tens of thousands of VMs with O(1)
// per-exit cost and ~zero CPU when idle. This replaces the naive per-VM
// Poll(pidfd, tick) approach, whose syscall rate scaled linearly with VM count
// (10k VMs × 10 polls/s = 100k syscalls/s of pure overhead).
//
// Design:
//   - One epoll fd (EPOLL_CTL_ADD each re-adopted VM's pidfd, EPOLLIN).
//   - One eventfd ("wake") in the same epoll set, so the loop can be roused
//     on demand — to add/remove a VM, or to shut down — without a poll timeout.
//     This means EpollWait blocks with timeout=-1 (indefinite) and consumes
//     zero CPU while no VM exits and no control op is pending.
//   - On a pidfd firing EPOLLIN: the tracked process has exited → invoke the
//     caller's onExit(vmID) callback (which runs handleVMDied).
//   - pidfd_open failure (kernel <5.3) is reported per-VM via the error return
//     of Add; the caller falls back to the per-VM ping-poll waitFn for that VM.
//
// A pidfdMonitor is owned by one Handler and outlives individual VMs and stream
// reconnects. It is started once and stopped only at sandlot shutdown.
type pidfdMonitor struct {
	epfd   int
	wake   int // eventfd; written to rouse the epoll loop
	logger *log.Logger

	mu      sync.Mutex
	byFd    map[int]string // pidfd -> vmID (for reverse lookup on epoll event)
	byVM    map[string]int // vmID -> pidfd (for Remove)
	stopped bool

	// dispatch routes a pidfd -> its onExit callback. A func can't be stored in
	// an EpollEvent (only Fd comes back), so this side-table maps an event back
	// to its callback. Guarded by its own mutex so the loop can read it without
	// nesting the byFd/byVM lock.
	dispatchMu sync.Mutex
	dispatch   map[int]func(string)
}

// newPidfdMonitor creates (but does not start) a pidfd monitor. Start it with
// run(), in a goroutine, passing the exit callback.
func newPidfdMonitor(logger *log.Logger) (*pidfdMonitor, error) {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("epoll_create1: %w", err)
	}
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(epfd)
		return nil, fmt.Errorf("eventfd: %w", err)
	}
	// Register the wake fd in epoll so writing to it rouses EpollWait.
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(wake)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, wake, &ev); err != nil {
		unix.Close(wake)
		unix.Close(epfd)
		return nil, fmt.Errorf("epoll_ctl wake: %w", err)
	}
	return &pidfdMonitor{
		epfd:     epfd,
		wake:     wake,
		logger:   logger,
		byFd:     make(map[int]string),
		byVM:     make(map[string]int),
		dispatch: make(map[int]func(string)),
	}, nil
}

// Add begins watching the sandvmm process `pid` for VM `vmID`. When that
// process exits, onExit(vmID) is called on the monitor goroutine. Returns an
// error if pidfd_open fails (caller should fall back to ping-poll for this VM)
// or if the VM is already watched.
func (m *pidfdMonitor) Add(vmID string, pid int, onExit func(string)) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		// Likely kernel <5.3 or PID already gone. Caller falls back to ping.
		return fmt.Errorf("pidfd_open pid %d: %w", pid, err)
	}

	m.mu.Lock()
	if _, dup := m.byVM[vmID]; dup {
		m.mu.Unlock()
		unix.Close(fd)
		return fmt.Errorf("vm %s already watched", vmID)
	}
	m.byFd[fd] = vmID
	m.byVM[vmID] = fd
	m.mu.Unlock()

	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}
	// Store the onExit callback in the dispatch side-table so the loop can
	// route an event (which only carries Fd) back to its callback.
	m.dispatchMu.Lock()
	m.dispatch[fd] = onExit
	m.dispatchMu.Unlock()

	if err := unix.EpollCtl(m.epfd, unix.EPOLL_CTL_ADD, fd, &ev); err != nil {
		m.dispatchMu.Lock()
		delete(m.dispatch, fd)
		m.dispatchMu.Unlock()
		m.mu.Lock()
		delete(m.byFd, fd)
		delete(m.byVM, vmID)
		m.mu.Unlock()
		unix.Close(fd)
		return fmt.Errorf("epoll_ctl add pidfd: %w", err)
	}
	return nil
}

// Remove stops watching a VM (e.g. on graceful destroy). It closes the pidfd,
// which also auto-removes it from epoll. Safe to call for a VM not currently
// watched (no-op).
func (m *pidfdMonitor) Remove(vmID string) {
	m.mu.Lock()
	fd, ok := m.byVM[vmID]
	if ok {
		delete(m.byVM, vmID)
		delete(m.byFd, fd)
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	// Closing the fd auto-deregisters it from epoll (EPOLL_CTL_DEL is implicit
	// on close for epoll, though a stale event may still fire once — the loop
	// guards by checking byFd presence). Remove the dispatch callback too.
	m.dispatchMu.Lock()
	delete(m.dispatch, fd)
	m.dispatchMu.Unlock()
	_ = unix.Close(fd)
}

// run is the epoll loop. It blocks until Stop() is called. Each pidfd firing
// triggers the VM's onExit callback; the wake eventfd rouses the loop for
// control ops (none strictly need rousing here since Add/Remove are async via
// epoll_ctl, but wake is how Stop breaks the indefinite EpollWait).
func (m *pidfdMonitor) run() {
	defer unix.Close(m.epfd)
	defer unix.Close(m.wake)
	events := make([]unix.EpollEvent, 128)
	for {
		n, err := unix.EpollWait(m.epfd, events, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			m.logger.Printf("pidfdMonitor: epoll_wait: %v", err)
			return
		}
		for i := 0; i < n; i++ {
			fd := int(events[i].Fd)
			if fd == m.wake {
				// Drain the eventfd counter; if stopped, exit the loop.
				var buf [8]byte
				_, _ = unix.Read(m.wake, buf[:])
				m.mu.Lock()
				stopped := m.stopped
				m.mu.Unlock()
				if stopped {
					return
				}
				continue
			}
			// A pidfd fired → process exited. Look up the VM and fire onExit.
			m.mu.Lock()
			vmID, ok := m.byFd[fd]
			if ok {
				// Remove from maps now so a concurrent Remove is a no-op and a
				// double-fire (stale epoll event after close) is ignored.
				delete(m.byFd, fd)
				delete(m.byVM, vmID)
			}
			m.mu.Unlock()
			if !ok {
				continue // stale event after Remove; ignore
			}
			m.dispatchMu.Lock()
			cb := m.dispatch[fd]
			delete(m.dispatch, fd)
			m.dispatchMu.Unlock()
			// Close the pidfd (auto-dereg from epoll) and dispatch the callback.
			_ = unix.Close(fd)
			if cb != nil {
				cb(vmID)
			}
		}
	}
}

// Stop shuts down the monitor loop. It signals the wake eventfd so the blocked
// EpollWait returns immediately. The caller should not Add/Remove after Stop.
func (m *pidfdMonitor) Stop() {
	m.mu.Lock()
	m.stopped = true
	m.mu.Unlock()
	// Wake the loop. eventfd write of 1 increments the counter; the loop reads
	// it, sees stopped, and exits.
	var buf [8]byte
	buf[0] = 1
	_, _ = unix.Write(m.wake, buf[:])
}
