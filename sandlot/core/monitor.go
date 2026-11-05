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
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	pb "common/proto/stream"
	"sandlot/vmm"
	"sandlot/warden"
)

// --- crash monitor & teardown ---

// monitorVMCore is the per-VM crash monitor. It blocks on waitFn until the VMM
// exits, then either:
//   - returns silently if destroyVMByID already owns teardown (destroying=true),
//   - or runs handleVMDied (unexpected crash path: clean up + notify gateway).
//
// It takes the *VMState directly (not a vmID lookup) because destroyVMByID
// removes the map entry before the monitor's waitFn returns — a lookup would
// miss and waitDone would never close, deadlocking destroyVMByID. The shared
// pointer is safe: destroyVMByID and the monitor coordinate via the destroying
// flag + waitDone channel, not the map.
//
// waitFn is the sole reaper of the sandvmm child process for fresh VMs
// (cmd.Wait), so destroyVMByID must NOT call cmd.Wait itself (it waits on
// waitDone instead). Re-adopted VMs do NOT use this path — they are watched by
// the centralized pidfdMonitor, which fires onExit directly.
func (h *Handler) monitorVMCore(state *VMState, waitFn func() error) {
	err := waitFn()
	// Signal that the VMM has exited (destroyVMByID/killVMM wait on this).
	// Idempotent via the select in case a destroy path already closed it —
	// it doesn't, but guard against any future caller.
	select {
	case <-state.waitDone:
	default:
		close(state.waitDone)
	}
	state.mu.Lock()
	destroying := state.destroying
	state.mu.Unlock()
	if destroying {
		return // destroyVMByID owns teardown
	}
	h.handleVMDied(state, err)
}

// cmdWaitFn is the waitFn for a freshly-launched VM: it blocks on cmd.Wait(),
// which returns when the sandvmm process exits (crash or Kill). This is the
// sole reaper of the child zombie.
func (h *Handler) cmdWaitFn(state *VMState) func() error {
	return func() error { return state.VM.Wait() }
}

// handleVMDied tears down a VM that exited unexpectedly: remove it from the
// map, stand down the monitors, close the cached warden connection, ensure the
// sandvmm process is dead (mode-aware via the lifecycle manager — a no-op on
// the already-dead crash paths, a real kill on the warden-hung path), release
// network/state/CID, and notify the gateway with a CRASHED event. It must not
// crash sandlot — a single VM dying never propagates to the main loop. The
// map-presence guard prevents double-cleanup if destroyVMByID raced and
// already removed the VM.
func (h *Handler) handleVMDied(state *VMState, err error) {
	vmID := state.VM.ID
	h.mu.Lock()
	if _, ok := h.vms[vmID]; !ok {
		h.mu.Unlock()
		return // already removed (destroy raced)
	}
	delete(h.vms, vmID)
	// Stand down every monitor path (probe failure counter, pidfd onExit,
	// ping poll) so none re-enters teardown mid-cleanup.
	state.mu.Lock()
	state.destroying = true
	state.mu.Unlock()
	h.mu.Unlock()

	h.clearBindingsForVM(vmID) // release any sandfs bound to the dead VM
	h.unregisterBinding(state) // attachment is going away: erase its identity slot
	// Drop the heartbeat snapshot (same ghost-entry rationale as
	// destroyVMByID: the probe loop only deletes entries it saw failing).
	h.memStatsMu.Lock()
	delete(h.memStats, vmID)
	h.memStatsMu.Unlock()

	h.logger.Printf("VM %s died unexpectedly: %v", vmID, err)

	// Tear down the warden connection pool: idle slots are closed, new dials
	// are refused, and holders of in-flight slots discard them on release. The
	// kill below deliberately does NOT wait for in-flight RPCs (the VM's death
	// kills every guest process anyway).
	state.wardenPoolFor().reset()

	// Ensure the sandvmm process is dead (idempotent when it already exited),
	// then release network + state/sandbox dir — all mode-aware via the
	// lifecycle manager. The CID is released only AFTER the kill so a new VM
	// cannot boot onto a live vsock CID.
	target := &DestroyTarget{
		VMID:       vmID,
		VM:         state.VM,
		APISocket:  state.VM.APISocket,
		PID:        state.VM.PID(),
		Readopted:  state.VM.Readopted(),
		SandboxDir: state.Cfg.SandboxDir,
		WaitDone:   state.waitDone,
	}
	if h.vm != nil {
		if derr := h.vm.DestroyVM(context.Background(), target); derr != nil {
			// Unconfirmed death (D-state) or a failed destroy RPC: do NOT
			// release the CID — a replacement VM booting onto a live vsock CID
			// is born without an agent channel. One stranded CID until restart
			// is the safe direction. The memory reservation stays held too
			// (admission stays conservative; both self-heal at restart).
			h.metrics.RecordStranded(state.Cfg.MemoryMB)
			h.logger.Printf("destroy of crashed VM %s; CID + memory-reservation release SKIPPED: %v", vmID, derr)
			h.sendEvent(&pb.VMEvent{
				VmId:    vmID,
				Type:    pb.VMEventType_VM_EVENT_CRASHED,
				Message: fmt.Sprintf("vm teardown: %v", err),
			})
			return
		}
	} else {
		// No lifecycle manager (test env): best-effort direct cleanup.
		if state.VM != nil {
			state.VM.Kill()
		}
		removeState(state.Cfg.SandboxDir)
		removeSandboxDir(state.Cfg.SandboxDir, h.SandboxRoot)
	}

	// Return the CID to the free-list so it can be reused by a future VM.
	h.releaseCID(state.VM.GuestCID)
	// Return the VM's memory reservation to the ledger (symmetry with the
	// admit in CreateVerifiedVM / the force-reserve at re-adopt).
	h.memLedger.release(state.Cfg.MemoryMB)

	h.sendEvent(&pb.VMEvent{
		VmId:    vmID,
		Type:    pb.VMEventType_VM_EVENT_CRASHED,
		Message: fmt.Sprintf("vm teardown: %v", err),
	})
}

// startVMMonitor registers VM crash detection: it prefers the centralized
// pidfdMonitor (one epoll loop for all VMs, zero idle CPU). If pidfd_open is
// unsupported for this process (boxout mode lacks CAP_SYS_PTRACE) or the
// kernel predates pidfd, or Add fails, it falls back to the VMM-API ping-poll
// monitor (startCrashPingMonitor) so the VM is always crash-watched one way or
// another. Both re-adopt entry points (disk re-adopt via adoptReadoptedVM and
// RegisterPrecreatedVM for pre-created re-adopted VMs) call this, keeping the
// pidfd-or-ping logic in exactly one place.
func (h *Handler) startVMMonitor(vmID string, pid int, vm *vmm.RunningVM) {
	if h.pidfdM != nil {
		if err := h.pidfdM.Add(vmID, pid, func(vmID string) {
			st := h.vmState(vmID)
			if st == nil {
				return
			}
			st.mu.Lock()
			destroying := st.destroying
			st.mu.Unlock()
			if destroying {
				return
			}
			h.handleVMDied(st, fmt.Errorf("vmm process exited (pid %d)", st.VM.PID()))
		}); err == nil {
			return
		} else {
			h.logger.Printf("pidfdMonitor.Add VM %s failed (%v); using VMM ping-poll fallback", vmID, err)
		}
	} else {
		h.logger.Printf("no pidfdMonitor; VM %s (pid=%d) uses VMM ping-poll fallback", vmID, pid)
	}
	h.startCrashPingMonitor(vmID, vm)
}

// confirmDeadPollInterval is the time between pings when waiting for a re-adopted
// VM's VMM API to stop responding after a graceful shutdown request.
const confirmDeadPollInterval = 100 * time.Millisecond

// confirmDead polls a re-adopted VM's VMM API until it stops responding or the
// timeout elapses. If the process lingers past the timeout, force-kill it by
// PID. Used after a graceful Shutdown of a re-adopted VM (killVMM /
// embeddedManager.DestroyVM). Takes *vmm.RunningVM (not *VMState) so it needs
// no map lookup.
func (h *Handler) confirmDead(ctx context.Context, vm *vmm.RunningVM, timeout time.Duration) {
	if vm == nil || vm.Client == nil {
		return
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := vm.Client.Ping(ctx); err != nil {
			return // VMM API gone — process exited
		}
		time.Sleep(confirmDeadPollInterval)
	}
	// Still alive after timeout: force-kill by PID (non-child; init reaps).
	// Re-verify the pid's /proc cmdline first: the pid came from a pre-restart
	// state file and may have been reused by an unrelated process.
	if !isSandvmmProcWithSocket(vm.PID(), vm.APISocket, h.sandvmmIdentity()) {
		h.logger.Printf("re-adopted VM %s: pid %d no longer names its sandvmm; refusing to signal", vm.ID, vm.PID())
		return
	}
	h.logger.Printf("re-adopted VM %s did not exit after shutdown; force-killing pid %d",
		vm.ID, vm.PID())
	vm.Kill()
}

// --- health probe (decoupled from the gateway stream) ---

// probeInterval is how often the independent probe loop polls each VM's warden.
// Decoupled from the 30s heartbeat so warden last_heartbeat (the single
// countdown anchor) stays fresh even while the gateway stream is down — during
// TOLERATING the sandlot keeps probing, so the warden countdown only fires on a
// real cleanup overrun, NOT on gateway-loss. See docs/how-it-works/resilience.md.
const probeInterval = 3 * time.Second

// probeWorkers bounds concurrency for the per-VM probe sweep. At ~0.3-1ms/probe
// (fresh vsock dial + MemStats) this turns 5000 VMs from ~5s sequential into
// ~50-100ms, keeping the sweep well inside probeInterval (10K scalability).
const probeWorkers = 64

// probeSweepTimeout bounds a single sweep's wall time. A mass-hang (many
// wardens hitting probeVM's 2s timeout) would otherwise let one sweep block
// the probeInterval tick for ~2000/64*2s≈62s (5000 VMs ≈156s), so the ticker
// can't start the next sweep and heartbeats on HEALTHY VMs are delayed by
// tens of seconds. Capping the sweep keeps healthy VMs' memStats fresh on
// cadence; un-probed VMs simply retry the next sweep.
//
// The warden countdown (T_warden) remains the authoritative mount-release
// backstop, so a capped sweep never risks a stale mount: mount release still
// completes by T_tolerance + T_warden < T_safe regardless of probe timing.
// Must be < probeInterval so a sweep never overlaps the next tick.
const probeSweepTimeout = 2 * time.Second

// probeFailureThreshold is the number of consecutive probe failures (warden
// MemStats over a fresh short-lived connection) after which a VM is declared hung
// (warden/guest dead or stuck) and torn down via handleVMDied. At a 3s probe this
// is a ~9s window - long enough to ride out a transient vsock blip, short enough
// that a truly hung VM is reclaimed quickly.
const probeFailureThreshold = 3

// StartProbeLoop launches the independent warden-probe loop. It runs during
// CONNECTED and TOLERATING (its OP_MEM_STATS heartbeats keep each VM's warden
// countdown anchor fresh), and is stopped by StopProbeLoop when the sandlot
// enters CLEANING so the countdowns can fire as the last-resort mount release.
// Restartable and race-free: the loop is identified by a TOKEN, so a Stop()
// followed immediately by a Start() starts a FRESH loop instead of no-opping on
// the old goroutine's dying state. The previous shape cleared `probeRunning`
// from the old goroutine's defer while the old loop's first sweep could still
// be running (the sweep did not observe the cancel ctx), so a Start landing in
// that window was silently swallowed and the process was left with NO probe
// loop at all — and OP_MEM_STATS from this loop is the ONLY warden heartbeat:
// the countdown anchor would freeze and every mount would be POWER_OFF'd at
// anchor+T_warden. Two call-site patterns make that window reachable: the
// startup Start (cmd/main.go) is followed within microseconds by the
// resume-path Stop when the persisted phase is done/cleaning (runner.go), and
// the DONE-exit Start runs with wait==0 on a restart past T_isolation.
// Keep it that way — the token makes the ordering irrelevant.
func (h *Handler) StartProbeLoop(ctx context.Context) {
	h.probeMu.Lock()
	defer h.probeMu.Unlock()
	if h.probeLoop != nil {
		return // idempotent: a loop is already running
	}
	probeCtx, cancel := context.WithCancel(ctx)
	loop := &probeLoopToken{cancel: cancel}
	h.probeLoop = loop
	go func() {
		defer func() {
			h.probeMu.Lock()
			// Only clear OUR token: a Stop+Start during our shutdown already
			// installed a newer loop, whose state must survive.
			if h.probeLoop == loop {
				h.probeLoop = nil
			}
			h.probeMu.Unlock()
		}()
		h.probeAllVMsCtx(probeCtx) // immediate first sweep (cancellable)
		ticker := time.NewTicker(probeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-probeCtx.Done():
				return
			case <-ticker.C:
				h.probeAllVMs()
			}
		}
	}()
}

// StopProbeLoop cancels the running probe loop (if any). Idempotent. Called on
// entering CLEANING: with heartbeats stopped, the warden countdowns (anchored
// at the last heartbeat, ~T_tolerance) count down and fire at
// T_tolerance + T_warden as the last-resort mount release.
func (h *Handler) StopProbeLoop() {
	h.probeMu.Lock()
	defer h.probeMu.Unlock()
	if h.probeLoop != nil {
		h.probeLoop.cancel()
		// Clear the token HERE (not only in the goroutine's defer): the loop is
		// cancelled, and a Start arriving before the old goroutine has finished
		// unwinding must start a new one, not observe the dying token.
		h.probeLoop = nil
	}
}

// probeLoopToken identifies one probe-loop instance so Stop/Start cannot
// confuse a dying loop with a live one.
type probeLoopToken struct{ cancel context.CancelFunc }

// --- guest console log size cap (node-disk DoS bound) ---------------------
//
// The VMM captures the guest kernel console into two host-side files per VM
// (console.log via hvc0, serial.log via earlyprintk — see vmm/launcher.go
// sandboxLogPaths). Guest userspace can induce kernel printk at some rate from
// unprivileged syscall paths, so a hostile tenant can otherwise grow both
// files without bound — a node-disk DoS shared by every colocated tenant. The
// check runs on a slow ticker, entirely off any request path; past the cap the
// file is truncated to zero. The VMM keeps its own write offset and continues
// into the sparse hole, so real disk usage is bounded by one interval of
// writes (the same pattern the warden's bg-log watchdog uses in-guest).

const (
	// guestLogCapInterval is the cap-check cadence. Usage between truncates is
	// bounded by interval × guest printk rate.
	guestLogCapInterval = 60 * time.Second
	// guestLogCapBytes is the per-file ceiling. Generous against legitimate
	// warden/kernel output (the warden's own log limiter already bounds its
	// lines; this catches the kernel-printk channel the warden cannot rate),
	// small against node disks.
	guestLogCapBytes = 128 << 20
)

// StartGuestLogCapLoop launches the periodic console/serial log size check.
// Idempotent (a second call is a no-op) so the runner's reconnect sites can
// start it unconditionally, like StartProbeLoop. Unlike the probe loop it is
// never stopped: log growth is lifecycle-independent.
func (h *Handler) StartGuestLogCapLoop(ctx context.Context) {
	h.logCapOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(guestLogCapInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					h.capGuestLogs()
				}
			}
		}()
	})
}

// capGuestLogs truncates every live VM's console/serial log past the cap.
func (h *Handler) capGuestLogs() {
	h.mu.RLock()
	dirs := make([]string, 0, len(h.vms))
	for _, state := range h.vms {
		if state.Cfg.SandboxDir != "" {
			dirs = append(dirs, state.Cfg.SandboxDir)
		}
	}
	h.mu.RUnlock()
	for _, dir := range dirs {
		for _, name := range [...]string{"console.log", "serial.log"} {
			path := filepath.Join(dir, name)
			fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				continue
			}
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= guestLogCapBytes {
				unix.Close(fd)
				continue
			}
			if err := unix.Ftruncate(fd, 0); err != nil {
				h.logger.Printf("guest log cap: truncate %s failed: %v", path, err)
				unix.Close(fd)
				continue
			}
			unix.Close(fd)
			h.logger.Printf("guest log cap: truncated %s (%d bytes, cap %d) — guest printk flood?",
				path, st.Size, guestLogCapBytes)
		}
	}
}

// probeAllVMs probes every VM's warden in parallel (worker pool) and refreshes
// the memStats snapshot. Success updates the cache + resets the failure count;
// failure records the failure (tearing down on reaching probeFailureThreshold)
// and drops the VM from the snapshot (a stale/zero entry would falsely trip the
// gateway's OOM reclaim). The probe dials a FRESH short-lived connection per VM
// (independent of the exec slot pool), so it runs concurrently with an
// in-flight sync exec.
//
// The sweep is bounded by probeSweepTimeout: a mass-hang (many wardens hitting
// probeVM's 2s timeout) would otherwise block the probeInterval tick for tens
// of seconds, delaying heartbeats on healthy VMs. Once the budget elapses,
// dispatch stops and the sweep returns without waiting for in-flight probes;
// un-probed VMs retry the next sweep. The warden countdown (T_warden) is the
// authoritative mount-release backstop, so a capped sweep never risks a stale
// mount (T_tolerance + T_warden < T_safe holds regardless of probe timing).
func (h *Handler) probeAllVMs() { h.probeAllVMsCtx(context.Background()) }

// probeAllVMsCtx is probeAllVMs with the loop's lifetime ctx: a cancelled loop
// stops immediately instead of finishing (up to probeSweepTimeout of) work that
// belongs to a dead generation.
func (h *Handler) probeAllVMsCtx(loopCtx context.Context) {
	if loopCtx.Err() != nil {
		return
	}
	h.mu.RLock()
	states := make([]*VMState, 0, len(h.vms))
	for _, state := range h.vms {
		states = append(states, state)
	}
	h.mu.RUnlock()

	sweepCtx, sweepCancel := context.WithTimeout(loopCtx, probeSweepTimeout)
	defer sweepCancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, probeWorkers)
dispatch:
	for _, state := range states {
		// Stop dispatching once the sweep budget elapsed: in-flight probes
		// finish on their own (bounded by probeVM's 2s timeout); un-probed
		// VMs retry the next sweep.
		if sweepCtx.Err() != nil {
			break
		}
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-sweepCtx.Done():
			// Budget expired while blocked on a worker slot: cancel the Add
			// above and stop dispatching. The break MUST be labeled — a bare
			// break exits only the select, the goroutine below would still
			// launch, and its deferred wg.Done() would drive the WaitGroup
			// negative (panic) while also receiving a sem token it never
			// acquired (worker-count corruption). Remaining VMs retry next
			// sweep.
			wg.Done()
			break dispatch
		}
		go func(st *VMState) {
			defer wg.Done()
			defer func() { <-sem }()
			avail, total, err := h.probeVM(st.VM.GuestCID, st.Cfg.WardenSessionKey)
			if err != nil {
				h.recordProbeFailure(st, err)
				h.memStatsMu.Lock()
				delete(h.memStats, st.VM.ID)
				h.memStatsMu.Unlock()
				return
			}
			st.mu.Lock()
			st.consecutiveProbeFailures = 0
			st.lastProbeErrMsg = ""
			st.mu.Unlock()
			st.memAvail.Store(avail)
			st.memTotal.Store(total)
			h.memStatsMu.Lock()
			h.memStats[st.VM.ID] = &pb.VmMemInfo{
				VmId:              st.VM.ID,
				MemAvailableBytes: avail,
				MemTotalBytes:     total,
			}
			h.memStatsMu.Unlock()
		}(state)
	}
	// Wait for in-flight probes, but no longer than the sweep budget: each probe
	// is bounded by its own 2s timeout, so this returns within probeSweepTimeout.
	// Returning without draining only abandons probe results to the next sweep —
	// it never leaks goroutines (each probe's warden connection is defer-Closed).
	waitDone := make(chan struct{})
	go func() { wg.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-sweepCtx.Done():
	}
}

// VMMemStats returns the cached per-VM guest memory snapshot maintained by the
// independent probe loop (StartProbeLoop). It does NOT probe here: the probe loop
// is decoupled from the gateway stream so warden last_heartbeat stays fresh during
// gateway-loss (TOLERATING). Called by the gateway-bound heartbeat (sendHeartbeat),
// which correctly stops when the stream is down - reporting stops, probing
// continues. VMs whose last probe failed are absent from the snapshot.
func (h *Handler) VMMemStats() []*pb.VmMemInfo {
	h.memStatsMu.RLock()
	defer h.memStatsMu.RUnlock()
	out := make([]*pb.VmMemInfo, 0, len(h.memStats))
	for _, m := range h.memStats {
		out = append(out, m)
	}
	return out
}

// probeVM dials a fresh short-lived warden connection and calls MemStats. It
// is independent of the exec slot pool, so it runs concurrently with in-flight
// sync execs. 2s timeout bounds a stuck warden.
func (h *Handler) probeVM(cid uint32, sessionKey string) (avail, total uint64, err error) {
	if h.testProbeFn != nil {
		return h.testProbeFn(cid)
	}
	key, kerr := warden.DecodeSessionKey(sessionKey)
	if kerr != nil {
		return 0, 0, kerr
	}
	agt, derr := warden.DialWithTimeout(cid, 2*time.Second, key)
	if derr != nil {
		return 0, 0, derr
	}
	defer agt.Close()
	return agt.MemStats()
}

// recordProbeFailure increments the failure count and, on reaching the threshold,
// tears the VM down as a hang. Idempotent: if the VM was already removed (a
// concurrent failure or destroy), the map-presence guard in handleVMDied no-ops.
//
// Every registered VM answered at least one probe before registration
// (CreateVerifiedVM), so reaching the threshold here means a warden that WORKED
// and then went silent — a real hang, safe to tear down. A guest that never
// finished booting never reaches this function: its creator destroys it.
func (h *Handler) recordProbeFailure(state *VMState, err error) {
	state.mu.Lock()
	state.consecutiveProbeFailures++
	n := state.consecutiveProbeFailures
	alreadyDestroying := state.destroying
	// Per-episode WARN: the destroy path below only ever saw the LAST error,
	// which made a transient-blip teardown undiagnosable from the logs. Volume
	// stays bounded regardless of probe cadence — log the FIRST failure of an
	// episode and every CHANGED error; repeats of the same error carry no new
	// information (an episode ends at the threshold via destroy, which removes
	// the VM from the probe set, or at the next success, which resets n to 0).
	msg := err.Error()
	logIt := n == 1 || msg != state.lastProbeErrMsg
	state.lastProbeErrMsg = msg
	state.mu.Unlock()
	if logIt {
		h.logger.Printf("VM %s warden probe failure %d/%d: %v", state.VM.ID, n, probeFailureThreshold, err)
	}
	if n >= probeFailureThreshold && !alreadyDestroying {
		h.logger.Printf("VM %s declared hung after %d probe failures (last: %v); tearing down",
			state.VM.ID, n, err)
		h.handleVMDied(state, fmt.Errorf("warden hung: %d consecutive probe failures (last: %v)", n, err))
	}
}
