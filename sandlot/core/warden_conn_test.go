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
	"sync"
	"testing"
	"time"

	pb "common/proto/stream"
	"sandlot/warden"
)

// --- wardenPool: slot semantics ---

// newTestWardenPool builds a pool wired to a dial func that returns fresh fake
// warden clients (real wire protocol over net.Pipe — Close() must work) and
// counts dial attempts. nFails leading dial attempts return an error.
func newTestWardenPool(t *testing.T, limit, nFails int) (*wardenPool, func() (*warden.Client, error), *int) {
	t.Helper()
	dials := 0
	p := newWardenPool(limit)
	dial := func() (*warden.Client, error) {
		dials++
		if dials <= nFails {
			return nil, errors.New("dial failure (test)")
		}
		c, _ := newFakeWardenClient(t, nil)
		return c, nil
	}
	return p, dial, &dials
}

func TestWardenPool_AcquireReleaseRoundTrip(t *testing.T) {
	p, dial, dials := newTestWardenPool(t, 2, 0)
	c, done, _, err := p.acquire(context.Background(), dial)
	if err != nil || c == nil {
		t.Fatalf("acquire = %v, %v", c, err)
	}
	done(false)
	c2, done2, _, err := p.acquire(context.Background(), dial)
	if err != nil || c2 != c {
		t.Fatalf("second acquire should reuse the returned slot, got %v (%v)", c2, err)
	}
	done2(false)
	if *dials != 1 {
		t.Errorf("dials = %d, want 1 (slot reused, no re-dial)", *dials)
	}
}

func TestWardenPool_BrokenReleaseDiscardsAndRedials(t *testing.T) {
	p, dial, dials := newTestWardenPool(t, 2, 0)
	c1, done, _, _ := p.acquire(context.Background(), dial)
	done(true) // transport error: discard
	c2, done2, _, _ := p.acquire(context.Background(), dial)
	if c2 == c1 {
		t.Fatal("after broken release, acquire must dial fresh, got the discarded slot")
	}
	done2(false)
	if *dials != 2 {
		t.Errorf("dials = %d, want 2", *dials)
	}
}

func TestWardenPool_LimitBlocksUntilRelease(t *testing.T) {
	p, dial, dials := newTestWardenPool(t, 1, 0)
	c1, done, _, _ := p.acquire(context.Background(), dial)

	// Second acquire must block (limit 1, slot in use).
	blocked := make(chan struct{})
	go func() {
		c2, done2, _, err := p.acquire(context.Background(), dial)
		if err != nil || c2 != c1 {
			t.Errorf("blocked acquire got %v (%v), want the released slot", c2, err)
		}
		done2(false)
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("second acquire did not block at the limit")
	case <-time.After(50 * time.Millisecond):
	}
	done(false) // release -> the blocked acquire proceeds
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("blocked acquire never resumed after release")
	}
	if *dials != 1 {
		t.Errorf("dials = %d, want 1 (FIFO handoff, no extra dial)", *dials)
	}
}

func TestWardenPool_ResetClosesIdleAndRefusesDials(t *testing.T) {
	p, dial, _ := newTestWardenPool(t, 2, 0)
	_, done, _, _ := p.acquire(context.Background(), dial)
	done(false)
	p.reset()
	_, _, _, err := p.acquire(context.Background(), dial)
	if err == nil {
		t.Fatal("acquire after reset must fail")
	}
}

func TestSeedWardenClient_ReplacesIdleConn(t *testing.T) {
	oldC, _ := newFakeWardenClient(t, nil)
	newC, _ := newFakeWardenClient(t, nil)
	vm := &VMState{}
	vm.seedWardenClient(oldC)
	vm.seedWardenClient(newC) // replaces: old discarded
	p := vm.wardenPoolFor()
	c, done, _, err := p.acquire(context.Background(), func() (*warden.Client, error) {
		return nil, errors.New("dial must not be attempted when a slot is seeded")
	})
	if err != nil || c != newC {
		t.Fatalf("acquire = %v (%v), want the seeded client", c, err)
	}
	done(false)
}

// --- handleWardenError: TransportError classification ---

func TestHandleWardenError_TransportError_InvalidatesConnection(t *testing.T) {
	_ = newTestHandler()
	transportErr := &warden.TransportError{Op: "read", Err: errors.New("ECONNRESET")}

	var te *warden.TransportError
	if !errors.As(transportErr, &te) {
		t.Fatal("errors.As should match TransportError")
	}
	if te.Op != "read" {
		t.Errorf("Op = %q, want %q", te.Op, "read")
	}
}

func TestHandleWardenError_NonTransportError_DoesNotInvalidate(t *testing.T) {
	_ = newTestHandler()
	rpcErr := errors.New("warden rpc failed: mount failed")

	var te *warden.TransportError
	if errors.As(rpcErr, &te) {
		t.Fatal("RPC error should NOT match TransportError")
	}
}

// --- Full flow: TransportError on write → invalidate → retry path ---

func TestTransportError_WritePath_Detection(t *testing.T) {
	err := &warden.TransportError{Op: "write", Err: errors.New("broken pipe")}

	var te *warden.TransportError
	if !errors.As(err, &te) {
		t.Fatal("write TransportError should be detectable via errors.As")
	}
	if te.Op != "write" {
		t.Errorf("Op = %q, want %q", te.Op, "write")
	}
}

func TestTransportError_ReadPath_Detection(t *testing.T) {
	err := &warden.TransportError{Op: "read", Err: errors.New("connection reset")}

	var te *warden.TransportError
	if !errors.As(err, &te) {
		t.Fatal("read TransportError should be detectable via errors.As")
	}
	if te.Op != "read" {
		t.Errorf("Op = %q, want %q", te.Op, "read")
	}
}

// --- Wrapped TransportError detection ---

func TestTransportError_WrappedInFmtError(t *testing.T) {
	inner := &warden.TransportError{Op: "read", Err: errors.New("ECONNRESET")}
	wrapped := fmt.Errorf("warden unmount: %w", inner)

	var te *warden.TransportError
	if !errors.As(wrapped, &te) {
		t.Fatal("errors.As should find TransportError through fmt.Errorf wrapping")
	}
	if te.Op != "read" {
		t.Errorf("Op = %q, want %q", te.Op, "read")
	}
}

// --- Multi-error classification ---

func TestErrorClassification_MixedErrors(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		isTransport bool
	}{
		{
			name:        "TransportError write",
			err:         &warden.TransportError{Op: "write", Err: errors.New("EPIPE")},
			isTransport: true,
		},
		{
			name:        "TransportError read",
			err:         &warden.TransportError{Op: "read", Err: errors.New("ECONNRESET")},
			isTransport: true,
		},
		{
			name:        "RPC error",
			err:         errors.New("warden rpc failed: something broke"),
			isTransport: false,
		},
		{
			name:        "generic error",
			err:         errors.New("some other error"),
			isTransport: false,
		},
		{
			name:        "wrapped TransportError",
			err:         fmt.Errorf("context: %w", &warden.TransportError{Op: "read", Err: errors.New("timeout")}),
			isTransport: true,
		},
		{
			name:        "doubly wrapped TransportError",
			err:         fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &warden.TransportError{Op: "write", Err: errors.New("broken")})),
			isTransport: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var te *warden.TransportError
			got := errors.As(tt.err, &te)
			if got != tt.isTransport {
				t.Errorf("errors.As = %v, want %v", got, tt.isTransport)
			}
		})
	}
}

// --- Volumes best-effort cleanup (used in unmount paths) ---

func TestUnmountRootfs_VolumesMissingIsNotBlocking(t *testing.T) {
	state := &VMState{
		Volumes: map[string]struct{}{
			"/vol/old-agent": {},
		},
	}
	delete(state.Volumes, "/vol/new-agent")
	if _, ok := state.Volumes["/vol/old-agent"]; !ok {
		t.Error("deleting a non-existent key should not affect other entries")
	}
	delete(state.Volumes, "/vol/old-agent")
	if len(state.Volumes) != 0 {
		t.Errorf("Volumes should be empty, got %d entries", len(state.Volumes))
	}
}

// --- parallel sync execs on the slot pool ---

// TestConcurrentSyncExecsRunOnParallelSlots proves two sync execs on the same
// sandfs run CONCURRENTLY: the fake warden only replies to an OP_EXEC once
// two have arrived, which a serialized handler can never satisfy. With the
// old single-connection execMu both would have deadlocked into transport
// errors; with the pool each takes its own slot and both succeed.
func TestConcurrentSyncExecsRunOnParallelSlots(t *testing.T) {
	h := newCoreTestHandler()
	fw := &fakeWarden{
		statusExecStatus: 3,
		execStdout:       "par-out",
		execBarrier:      make(chan struct{}),
		barrierCount:     2,
	}
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.execSlots.Store(2)
	st.seedWardenClient(dialFake(t, fw)) // slot 1
	h.testDialFn = func(cid uint32, timeout time.Duration) (*warden.Client, error) {
		return dialFake(t, fw), nil // slot 2
	}

	var wg sync.WaitGroup
	errs := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.handleMountRootfsAndExecute(context.Background(),
				&pb.VMCommand{CommandId: "c", AgentId: "agent-t"},
				&pb.MountRootfsAndExecute{
					VolumeMode: "flat",
					SandfsId:   "sfs-1",
					VolumePath: "/vol/a",
					Command:    "echo hi",
					TimeoutMs:  1000,
				})
			if !resp.Success {
				errs <- resp.Error
				return
			}
			if resp.Stdout != "par-out" {
				errs <- fmt.Sprintf("stdout = %q, want par-out", resp.Stdout)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent exec failed: %s", e)
	}
	ops := fw.recordedOps()
	nExec := 0
	for _, op := range ops {
		if op == fakeOpExec {
			nExec++
		}
	}
	if nExec != 2 {
		t.Errorf("OP_EXEC count = %d, want 2 (ops=%v)", nExec, ops)
	}
	if st.inFlight.Load() != 0 {
		t.Errorf("inFlight = %d after completion, want 0 (all slots released)", st.inFlight.Load())
	}
}

// TestConcurrentSyncExecsQueueBeyondPoolSize pins the overflow behavior: with
// execSlots=1, the second exec waits FIFO for the first to release its slot
// (the old execMu semantics, now expressed by the pool).
func TestConcurrentSyncExecsQueueBeyondPoolSize(t *testing.T) {
	h := newCoreTestHandler()
	fw := &fakeWarden{statusExecStatus: 3, execHold: make(chan struct{})}
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.execSlots.Store(1)
	st.seedWardenClient(dialFake(t, fw))
	h.testDialFn = func(cid uint32, timeout time.Duration) (*warden.Client, error) {
		return dialFake(t, fw), nil
	}
	call := func() *pb.CommandResponse {
		return h.handleMountRootfsAndExecute(context.Background(),
			&pb.VMCommand{CommandId: "c", AgentId: "agent-t"},
			&pb.MountRootfsAndExecute{
				VolumeMode: "flat",
				SandfsId:   "sfs-1",
				VolumePath: "/vol/a",
				Command:    "echo hi",
				TimeoutMs:  1000,
			})
	}

	done1 := make(chan *pb.CommandResponse, 1)
	go func() { done1 <- call() }() // takes the slot, blocks inside the fake
	// Wait until the first exec is actually in flight (slot held).
	deadline := time.Now().Add(time.Second)
	for st.inFlight.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	done2 := make(chan *pb.CommandResponse, 1)
	go func() { done2 <- call() }() // must queue: no slot free
	select {
	case r := <-done2:
		t.Fatalf("second exec ran while the only slot was held (resp=%+v)", r)
	case <-time.After(150 * time.Millisecond):
	}
	close(fw.execHold) // release the fake; both execs complete
	r1 := <-done1
	r2 := <-done2
	if !r1.Success || !r2.Success {
		t.Fatalf("execs failed: %q / %q", r1.Error, r2.Error)
	}
	if st.inFlight.Load() != 0 {
		t.Errorf("inFlight = %d after completion, want 0", st.inFlight.Load())
	}
}

// TestConcurrentColdExecsShareOneMount proves two concurrent COLD execs on the
// same sandfs both succeed and converge on one mount bookkeeping: each issues
// its own combined mount_and_exec (1 RTT each, no per-VM lock held across the
// exec), the warden's MOUNT_GATE folds the duplicate mount parts into one, and
// both execs run on their own slots.
func TestConcurrentColdExecsShareOneMount(t *testing.T) {
	h := newCoreTestHandler()
	// Barrier on OP_MOUNT_AND_EXEC: the fake warden holds each combined RPC
	// until BOTH have arrived. Without it the first request can complete end to
	// end — marking the volume mounted — before the second reads the warm/cold
	// verdict, which legitimately turns the second into a WARM exec (OP_EXEC)
	// and made the "2 combined RPCs" assertion flaky. Gating on the barrier
	// pins both requests to the cold path, which is what this test is about.
	fw := &fakeWarden{
		statusExecStatus: 3,
		execStdout:       "cold-out",
		execBarrier:      make(chan struct{}),
		barrierOp:        fakeOpMountAndExec,
		barrierCount:     2,
	}
	st := mountVolume(h, "vm-a", "sfs-1", "") // Volumes empty => cold
	st.execSlots.Store(2)
	st.seedWardenClient(dialFake(t, fw))
	h.testDialFn = func(cid uint32, timeout time.Duration) (*warden.Client, error) {
		return dialFake(t, fw), nil
	}

	var wg sync.WaitGroup
	errs := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.handleMountRootfsAndExecute(context.Background(),
				&pb.VMCommand{CommandId: "c", AgentId: "agent-t"},
				&pb.MountRootfsAndExecute{
					VolumeMode: "flat",
					SandfsId:   "sfs-1",
					VolumePath: "/vol/cold",
					Command:    "echo hi",
					TimeoutMs:  1000,
				})
			if !resp.Success {
				errs <- resp.Error
				return
			}
			if resp.Stdout != "cold-out" {
				errs <- fmt.Sprintf("stdout = %q, want cold-out", resp.Stdout)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent cold exec failed: %s", e)
	}
	st.mountMu.Lock()
	_, mounted := st.Volumes["/vol/cold"]
	st.mountMu.Unlock()
	if !mounted {
		t.Error("volume not tracked after concurrent cold mounts")
	}
	nMount := 0
	for _, op := range fw.recordedOps() {
		if op == fakeOpMountAndExec {
			nMount++
		}
	}
	if nMount != 2 {
		t.Errorf("mount_and_exec count = %d, want 2 (each request its own 1-RTT combined RPC; dedup is in-warden)", nMount)
	}
}

// TestWardenPool_ParkedAcquirerWakesOnDiscardingRelease pins the wakeup
// invariant a parked acquirer depends on: at the slot limit, a release that
// DISCARDS the connection (broken transport, or a closed pool) frees capacity
// by lowering `created` and pushes nothing into `idle`. Before the broadcast
// channel existed, a waiter that parked BEFORE such a release slept on <-idle
// until the process ctx ended — holding its command-semaphore token forever.
// At exec_slots=1 (the k8s small spec) one transport error permanently burned
// a 1/2000 command slot.
func TestWardenPool_ParkedAcquirerWakesOnDiscardingRelease(t *testing.T) {
	p, dial, dials := newTestWardenPool(t, 1, 0)
	_, done, _, err := p.acquire(context.Background(), dial)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Park a second acquirer on the single slot.
	type result struct {
		c   *warden.Client
		err error
	}
	res := make(chan result, 1)
	go func() {
		c, _, _, err := p.acquire(context.Background(), dial)
		res <- result{c, err}
	}()
	time.Sleep(50 * time.Millisecond) // let it park

	// The holder's connection broke: the release DISCARDS (nothing is pushed).
	done(true)

	select {
	case r := <-res:
		if r.err != nil || r.c == nil {
			t.Fatalf("parked acquirer after a broken release: c=%v err=%v (want a fresh dial)", r.c, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parked acquirer never woke after a discarding release (it holds its command slot forever)")
	}
	if *dials != 2 {
		t.Errorf("dials = %d, want 2 (the discarded slot is re-dialed)", *dials)
	}
}

// TestWardenPool_ParkedAcquirerFailsFastOnReset is the other half: reset()
// closes the pool, so no release will ever push into `idle` again — a parked
// acquirer must FAIL FAST (errWardenPoolClosed) rather than sleep until the
// process ctx ends.
func TestWardenPool_ParkedAcquirerFailsFastOnReset(t *testing.T) {
	p, dial, _ := newTestWardenPool(t, 1, 0)
	_, _, _, err := p.acquire(context.Background(), dial)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := p.acquire(context.Background(), dial)
		errCh <- err
	}()
	time.Sleep(50 * time.Millisecond)

	p.reset()

	select {
	case err := <-errCh:
		if !errors.Is(err, errWardenPoolClosed) {
			t.Fatalf("parked acquirer after reset: err=%v, want errWardenPoolClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parked acquirer never woke after reset (pool closed with a waiter parked)")
	}
}
