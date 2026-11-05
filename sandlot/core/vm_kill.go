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
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"sandlot/vmm"
)

// killVMMExitWait bounds how long killVMM waits for a fresh VM's monitor
// goroutine to confirm process exit before the PID-signal fallback. Var (not
// const) so unit tests can shrink it.
var killVMMExitWait = 5 * time.Second

// killVMMConfirmWait bounds how long killVMM polls for process death after the
// PID-signal fallback. Var (not const) so unit tests can shrink it.
var killVMMConfirmWait = 2 * time.Second

// DestroyTarget carries everything needed to kill a sandvmm process and clean
// up its resources WITHOUT consulting h.vms. This is deliberate: the caller
// (destroyVMByID / handleVMDied) may have already deleted the map entry before
// delegating the kill — that was the destroy regression (embeddedManager's
// DestroyVM re-looked up h.vms, always missed, and skipped the kill, leaking
// the sandvmm process + its state on every embedded-mode destroy).
type DestroyTarget struct {
	VMID       string
	VM         *vmm.RunningVM // may be nil (boxout mode / early-create failure)
	APISocket  string
	PID        int
	Readopted  bool
	SandboxDir string
	WaitDone   <-chan struct{} // fresh VMs only; nil for re-adopted
}

// procAlive reports whether pid names a live (non-zombie) process. A zombie
// counts as dead for our purposes: every fd (KVM, vhost-vsock, TAP) was closed
// at process exit, so its CID is safe to reuse.
func procAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false // gone
	}
	// The state char follows the ')' that closes comm (comm may contain spaces).
	idx := bytes.LastIndexByte(data, ')')
	if idx < 0 || idx+2 >= len(data) {
		return false
	}
	return data[idx+2] != 'Z'
}

// confirmProcDead polls until the process is no longer alive (or the wait
// elapses). Returns true when death was observed.
func confirmProcDead(pid int, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		if !procAlive(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// killVMM ensures the sandvmm process is dead, bounded at ~9s worst case.
// It NEVER waits for an in-flight warden RPC (up to max_exec_timeout) — the
// kill must never block on one.
//
// Returns true when the process's death was confirmed (or there was nothing to
// signal); false when the process may STILL be alive (D-state ignoring
// SIGTERM+SIGKILL). Callers must not release the CID on false: a replacement
// VM booting onto a live vhost-vsock CID fails at device activation and is
// born without an agent channel. A skipped release only strands one CID until
// the next sandlot restart — the safe direction.
func (h *Handler) killVMM(ctx context.Context, t *DestroyTarget) bool {
	if t == nil || t.VM == nil {
		return true // nothing to signal (boxout mode / early-create failure)
	}
	if !t.Readopted {
		// Fresh VM: SIGKILL the child. The per-VM monitor goroutine is the
		// sole reaper (cmd.Wait), so we wait on waitDone instead of calling
		// t.VM.Wait() — a second cmd.Wait would race the reap. If the process
		// is already dead (crash path), waitDone is already closed and the
		// wait returns instantly.
		t.VM.Kill()
		if t.WaitDone != nil {
			select {
			case <-t.WaitDone:
				return true
			case <-time.After(killVMMExitWait):
				// Process stuck (e.g. D-state): belt-and-braces signal by PID.
				// Guard pid>0: KillProcGraceful(0) would signal our own group.
				if t.PID > 0 {
					h.logger.Printf("killVMM: VM %s did not exit within %v of SIGKILL; forcing via pid %d",
						t.VMID, killVMMExitWait, t.PID)
					KillProcGraceful(t.PID)
				}
			}
		}
		return confirmProcDead(t.PID, killVMMConfirmWait)
	}
	// Re-adopted VM: no *exec.Cmd — graceful VMM API shutdown, then poll until
	// the API stops answering (confirmDead); force-kill by PID if it lingers.
	if h.pidfdM != nil {
		h.pidfdM.Remove(t.VMID) // stop the epoll watch; we own teardown now
	}
	sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if err := t.VM.Shutdown(sctx); err != nil {
		h.logger.Printf("killVMM: graceful shutdown of re-adopted VM %s failed (forcing): %v", t.VMID, err)
	}
	cancel()
	// Fresh deadline for the confirm: confirmDead treats a Ping ERROR as "dead",
	// so reusing the already-expired sctx would misreport the process as gone.
	cctx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	h.confirmDead(cctx, t.VM, 5*time.Second)
	return confirmProcDead(t.PID, killVMMConfirmWait)
}
