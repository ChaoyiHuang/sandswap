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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sandlot/vmm"
	"sandlot/warden"
)

// --- startup re-adopt & orphan sweep ---

// ReadoptVMs scans for surviving microVMs and re-adopts the live ones.
// Delegates the privileged scanning (/proc, vmm.Attach) to h.vm.ReadoptVMs,
// then builds VMState for each live VM (warden connection cache, CID reservation,
// pidfd monitoring).
//
// Must run before the gateway stream connects, so the live VM set reported in
// NodeHello.active_vm_ids is accurate and the gateway can reconcile.
func (h *Handler) ReadoptVMs(ctx context.Context) {
	infos, err := h.vm.ReadoptVMs(ctx)
	if err != nil {
		h.logger.Printf("re-adopt: %v", err)
		return
	}

	for _, info := range infos {
		h.adoptReadoptedVM(ctx, info)
	}

	// Clean up stale host-side overlay mounts whose SandFS has been deleted
	// while this sandlot was offline.
	h.vm.RestoreMountedOverlays()
	h.vm.CleanupStaleOverlays()
}

// adoptReadoptedVM builds a VMState from a ReadoptedVMInfo and registers it.
// This is the sandlot-side work: vmm.Attach, CID reservation, pidfd monitoring,
// warden connection cache, allowed_dirs reset.
func (h *Handler) adoptReadoptedVM(ctx context.Context, info ReadoptedVMInfo) {
	vm, err := vmm.Attach(ctx, vmm.AttachConfig{
		ID:               info.VMID,
		APISocket:        info.APISocket,
		GuestCID:         info.GuestCID,
		PID:              info.PID,
		SandboxDir:       info.SandboxDir,
		WardenSessionKey: info.Cfg.WardenSessionKey,
		VMMAPIAuth:       h.vmmCfg.VMMAPIAuth,
	}, h.logger)
	if err != nil {
		h.logger.Printf("re-adopt: attach VM %s failed: %v; cleaning up", info.VMID, err)
		h.killByPid(info.PID, info.VMID, info.APISocket)
		_ = h.vm.ReleaseNetwork(ctx, info.VMID)
		return
	}

	h.reserveCID(info.GuestCID)
	// The survivor was created by a previous process (outside this ledger), so
	// record its memory commitment here — future CreateVerifiedVM admissions
	// must see it or the ledger silently undercounts.
	h.memLedger.forceReserve(info.Cfg.MemoryMB)

	state := &VMState{
		VM:      vm,
		Cfg:     info.Cfg,
		Volumes: make(map[string]struct{}),
		SpecID:  info.SpecID,
	}
	state.mountCount.Store(info.MountCount)
	state.mountCountedGen = info.MountCountedGen
	if len(info.DistinctAgents) > 0 {
		state.distinctAgents = make(map[string]struct{}, len(info.DistinctAgents))
		for _, a := range info.DistinctAgents {
			state.distinctAgents[a] = struct{}{}
		}
	}
	// Fix the warden pool size (sync-command concurrency) from the spec. Must
	// be set before the pool is first used (lazy init).
	state.execSlots.Store(int64(h.execSlotsForSpec(info.SpecID)))
	// Resolve the egress identity slot and drop any entry the previous process
	// left behind: this process has no mounts yet (CONNECT-CLEAN guarantees
	// redialWarden releases whatever survived), so the attachment must read
	// as unbound until the next mount publishes fresh identity.
	h.initBindingSlot(state)
	h.mu.Lock()
	h.vms[info.VMID] = state
	// Advance nextPoolSeq past this re-adopted VM's seq
	if seq, ok := parsePoolSeq(info.VMID, h.poolVMIDPrefix); ok && seq >= h.nextPoolSeq {
		h.nextPoolSeq = seq + 1
	}
	h.mu.Unlock()

	// Marked pending BEFORE the cleanup starts: the runner's crash-while-
	// CONNECTED re-anchor must treat a survivor as possibly-mounting until the
	// unmount below proves otherwise (see mayHoldUnreleasedMounts), and
	// resolveVMForMount must never select it until then.
	h.markReadoptPending(info.VMID)

	// Re-cache the warden connection, release any stale agent rootfs, and only
	// THEN clear the virtio-fs allowed_dirs filter — that order is forced by
	// the reuse tripwire: the filter refuses a swap while the guest still holds
	// handles or un-FORGOTTEN inodes into the outgoing export, and a live bind
	// mount pins exactly those references until the warden's unmount +
	// drop_caches. Clearing first would trip the tripwire on every survivor and
	// destroy it instead of reusing it. The whole sequence is tracked by
	// readoptWG so the reconnect path (WaitReadoptCleanup) can hold its
	// NodeHello until every survivor is verifiably CLEAN — without the wait,
	// the startup hello can race this async cleanup by milliseconds (or
	// seconds against a slow warden), which would break the reconnect-clean
	// invariant the whole resilience model stands on.
	h.readoptWG.Add(1)
	go func() {
		defer h.readoptWG.Done()
		h.redialWarden(state)
	}()

	// Crash detection for the re-adopted VM (pidfd when available, otherwise a
	// VMM-API ping-poll fallback — see startVMMonitor).
	h.startVMMonitor(info.VMID, info.PID, vm)

	h.logger.Printf("re-adopted VM %s (cid=%d, pid=%d)", info.VMID, info.GuestCID, info.PID)
}

// WaitReadoptCleanup blocks until every re-adopt cleanup (redialWarden) has
// finished, so a connecting sandlot can truthfully promise the gateway a node
// with zero mounts (the reconnect-clean invariant). A failed cleanup now
// DESTROYS + replaces the survivor, and resolveVMForMount never
// selects a pending survivor — so "completed" means every survivor is either
// proven clean or pending destroy, not silently reused with a stale mount.
// Bounded by ctx: returns true when all cleanups completed, false on timeout —
// the caller logs and proceeds; a timed-out survivor stays unselectable until
// its redial finishes or the destroy lands. Empty (returns immediately) on
// reconnects after a process lifetime with no re-adopt.
func (h *Handler) WaitReadoptCleanup(ctx context.Context) bool {
	done := make(chan struct{})
	go func() {
		h.readoptWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// ResetSurvivorsToClean unmounts any agent rootfs still mounted on each
// surviving VM and THEN clears the virtio-fs allowed_dirs filter, resetting
// them to CLEAN. The order is forced by the reuse tripwire (see the per-VM
// goroutine below).
// Called when the sandlot enters CLEANING (tolerance-first): the stream has been
// down past T_tolerance, so every mount must be released before any new gateway
// can mount the same shared sandfs. Idempotent (unmount on an already-clean VM
// is a no-op), so a restart mid-cleanup can re-run it safely.
//
// cleanupDeadline is the hard time budget (disconnect_time + T_tolerance +
// T_clean): every VM must be unmounted by then. A VM with no cached warden
// connection (redialWarden still in flight after a restart) is cleaned over a
// fresh short dial; if the warden is unreachable, that counts as an unmount
// failure. Unmount failures (EBUSY / D-state / warden unreachable) schedule an
// async destroyAndReplaceVM — destroys the KVM process (killing all guest
// processes incl. D-state) and recreates a replacement to keep the pool
// target — and VMs still in-flight at the deadline are force-destroyed the same
// way, so no stale mount can outlive the budget. The warden countdown is the
// backstop: even if a destroy blocks (e.g. on an in-flight sync exec in the
// guest), the warden exits the VM at
// T_tolerance + T_warden, releasing the mount regardless.
func (h *Handler) ResetSurvivorsToClean(ctx context.Context, cleanupDeadline time.Time) {
	h.mu.Lock()
	states := make([]*VMState, 0, len(h.vms))
	for _, st := range h.vms {
		states = append(states, st)
	}
	h.mu.Unlock()

	// Parallelize the per-VM reset: each mounted VM's UnmountRootfs (~8s) runs
	// concurrently, so M mounted VMs finish in ~8s (not M*8s) — required for the
	// gateway-loss self-unmount to stay within the T_clean budget. Each VM has
	// its own warden slot pool + mount bookkeeping, so there is no cross-VM
	// contention.
	// Clean VMs (no mount) are a ~1ms no-op.
	//
	// "No mount" is judged by st.Volumes, the in-memory record of what this
	// process mounted. A VM with an empty set has nothing to release, so skip
	// the set-fs + cleanup dial entirely: on a VM that is still booting those
	// would time out and the failed dial would be scored as an unmount failure,
	// destroying a VM that was never dirty. After a restart the survivors'
	// Volumes are empty too (bindings are in-memory) — their stale GUEST mounts
	// are released by the async redialWarden started at re-adopt, and the
	// reconnect path waits those out (WaitReadoptCleanup) BEFORE announcing
	// itself, so skipping them here never leaks a mount into a connection.
	completed := make(chan string, len(states))
	sem := make(chan struct{}, probeWorkers)
	for _, st := range states {
		vmID := "<nil>"
		if st.VM != nil {
			vmID = st.VM.ID
		}
		h.mu.Lock()
		bound := h.vmBoundToLocked(vmID)
		h.mu.Unlock()
		st.mountMu.Lock()
		mounted := len(st.Volumes) > 0
		pending := st.pendingMount != nil
		st.mountMu.Unlock()
		// A VM is skippable only when it has NO recorded mount AND no mount
		// could still be landing: an in-flight cold mount RPC or a recorded
		// pending generation may establish a guest mount after this decision.
		// Judging on Volumes alone declared such a VM "CLEAN" and skipped the
		// forced unmount, so the late mount survived the reconnect-clean
		// announcement (untracked mount).
		busy := pending || st.inFlight.Load() > 0 || bound
		if !mounted && !busy {
			// A re-adopted clean survivor may already be at a recycle
			// threshold (mount_count is persisted). It must not re-enter
			// service: destroy+replace it instead of treating it as clean
			// capacity (selection excludes it, so it would otherwise sit
			// idle forever).
			if h.shouldRecycle(st) {
				h.scheduleDirtyVMDestroy(st, "recycle threshold reached on a re-adopted clean VM")
				continue
			}
			completed <- vmID
			continue
		}
		sem <- struct{}{}
		go func(st *VMState) {
			defer func() { <-sem }()
			defer func() { completed <- vmID }()

			// Drain first: an in-flight mount RPC that lands AFTER the forced
			// unmount would re-mount the workspace behind a cleared filter.
			// Waiting is bounded by the same cleanup budget; a mount that will
			// not finish inside it is a reason to destroy, not to reuse.
			drainDeadline := cleanupDeadline
			if drainDeadline.IsZero() {
				drainDeadline = time.Now().Add(10 * time.Second)
			}
			for {
				st.mountMu.Lock()
				pending := st.pendingMount != nil
				st.mountMu.Unlock()
				if !pending && st.inFlight.Load() == 0 {
					break
				}
				if time.Now().After(drainDeadline) {
					h.logger.Printf("re-adopt-light: in-flight mount on VM %s did not finish within the cleanup budget; destroy + replace", vmID)
					h.scheduleDirtyVMDestroy(st, "cleanup: in-flight mount outlived the budget")
					return
				}
				time.Sleep(10 * time.Millisecond)
			}

			// ORDER IS LOAD-BEARING: release the guest mount BEFORE clearing
			// the filter.
			//
			// The reuse tripwire refuses a filter swap while the guest still
			// holds open handles or un-FORGOTTEN inode references into the
			// outgoing export. A live bind mount pins the source inode's FUSE
			// lookup count for as long as it exists, so a clear-first order
			// fails the tripwire on EVERY mounted VM (fail-closed) and turns
			// the intended release into a destroy-and-replace. The warden's
			// unmount (cgroup.kill + process sweep + umount + drop_caches) is
			// what drops those references.
			if st.VM != nil {
				// Clean over a dedicated short-timeout connection: the pool's
				// slots may be mid-teardown with the dead stream, and this is a
				// one-shot cleanup dial. dialWardenRetry tolerates a VM still
				// finishing its boot (like every other dial site in core); if
				// the warden stays unreachable or the unmount fails, destroy
				// (mirrors handleUnmountRootfs's warden-unreachable path). A
				// clean VM's unmount is an idempotent no-op, so dialing is safe.
				fresh, derr := h.dialWardenRetry(st.VM.GuestCID, st.Cfg.WardenSessionKey, warden.UnmountReadTimeout)
				if derr != nil {
					h.logger.Printf("re-adopt-light: warden unreachable on VM %s (%v); destroy + replace", vmID, derr)
					h.scheduleDirtyVMDestroy(st, fmt.Sprintf("cleanup: warden unreachable: %v", derr))
					return
				}
				_, uerr := fresh.UnmountRootfsForced()
				fresh.Close()
				if uerr != nil {
					// Unmount failed (EBUSY / D-state / warden unreachable): the
					// guest mount state is uncertain — never reuse this VM. Destroy
					// it (kills the KVM process, all guest processes incl. D-state)
					// and reconcile a replacement to the pool target.
					h.logger.Printf("re-adopt-light: unmount failed on VM %s (%v); destroy + replace", vmID, uerr)
					h.scheduleDirtyVMDestroy(st, fmt.Sprintf("cleanup unmount: %v", uerr))
					return
				}
			}
			if st.VM != nil && st.VM.Client != nil {
				// The guest mount is gone, so the outgoing export holds no
				// guest references and the clear can pass the reuse tripwire.
				// Failure is still fatal to this VM: a filter whose state is
				// uncertain must never be handed to the next tenant.
				if err := setFsAllowedDirs(ctx, st.VM.Client, nil, ""); err != nil {
					h.logger.Printf("re-adopt-light: clear allowed_dirs on VM %s failed (%v); destroy + replace", vmID, err)
					h.scheduleDirtyVMDestroy(st, fmt.Sprintf("cleanup: set-fs clear: %v", err))
					return
				}
			}
			// Bookkeeping only AFTER both sides proved clean: the guest mount
			// is detached, the filter is empty, so the attachment's egress
			// identity and the per-VM mount records die with it.
			h.revokeBinding(st)
			st.mountMu.Lock()
			st.mountGen.Add(1) // invalidate any in-flight cold RPC's mark
			st.Volumes = make(map[string]struct{})
			st.mountIdentity = ""
			st.mountIdentityPath = ""
			st.pendingMount = nil
			st.mountAliasBySandfs = make(map[string]string)
			st.mountPathBySandfs = make(map[string]string)
			st.mountEpochBySandfs = make(map[string]string)
			st.mountMu.Unlock()
			st.resetBgExecTracking()
			h.logger.Printf("re-adopt-light: VM %s reset to CLEAN", vmID)
		}(st)
	}

	// Wait for all VMs with a hard deadline; on timeout force-destroy the rest
	// (scheduleDirtyVMDestroy handles each VM's bindings cleanup via destroy).
	remaining := make(map[string]struct{}, len(states))
	for _, st := range states {
		id := "<nil>"
		if st.VM != nil {
			id = st.VM.ID
		}
		remaining[id] = struct{}{}
	}
	verified := make(map[string]struct{}, len(states))
	var remainingMu sync.Mutex

	var deadlineCh <-chan time.Time
	if !cleanupDeadline.IsZero() {
		deadlineTimer := time.NewTimer(time.Until(cleanupDeadline))
		defer deadlineTimer.Stop()
		deadlineCh = deadlineTimer.C
	}
	for i := 0; i < len(states); i++ {
		select {
		case id := <-completed:
			remainingMu.Lock()
			delete(remaining, id)
			verified[id] = struct{}{}
			remainingMu.Unlock()
		case <-deadlineCh:
			remainingMu.Lock()
			ids := make([]string, 0, len(remaining))
			for id := range remaining {
				ids = append(ids, id)
			}
			remainingMu.Unlock()
			for _, id := range ids {
				if st := h.vmState(id); st != nil {
					h.logger.Printf("re-adopt-light: cleanup deadline exceeded; force-destroy VM %s", id)
					h.scheduleDirtyVMDestroy(st, "cleanup deadline exceeded")
				}
			}
			// The in-flight goroutines finish on their own (their completed
			// messages drain harmlessly into the buffered channel); return now so
			// the caller does not wait past the budget.
			return
		}
	}
	// Clear only the bindings whose cleanup was verified complete; a VM that
	// did not finish keeps its binding (and is force-destroyed, which clears
	// it through the destroy path).
	h.clearBindingsForVMs(verified)
}

// crashPingInterval is how often the VMM-API ping-poll fallback checks a
// re-adopted VM for liveness when pidfd-based monitoring is unavailable
// (sandlot may lack CAP_SYS_PTRACE in boxout mode, or the kernel predates
// pidfd). A dead sandvmm is detected within roughly this interval and torn down
// via handleVMDied so its CID and sandfs bindings are released.
const crashPingInterval = 10 * time.Second

// startCrashPingMonitor polls the re-adopted VM's VMM API on a fixed interval
// and calls handleVMDied when the API stops responding. It exits when the VM is
// no longer tracked (destroyed/re-adopted away) or is being destroyed. This is
// the fallback for re-adopted VMs that pidfd monitoring cannot watch.
func (h *Handler) startCrashPingMonitor(vmID string, vm *vmm.RunningVM) {
	go func() {
		ticker := time.NewTicker(crashPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
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
				if vm.Client == nil {
					return
				}
				if err := vm.Client.Ping(context.Background()); err != nil {
					h.handleVMDied(st, fmt.Errorf("re-adopted VM %s stopped responding to ping: %v", vmID, err))
					return
				}
			}
		}
	}()
}

// redialWarden resets a re-adopted VM to CLEAN: unmounts any stale agent
// rootfs in the guest via a pool slot (which seeds the VM's connection pool),
// destroying the VM if the unmount fails (mirrors handleUnmountRootfs).
func (h *Handler) redialWarden(state *VMState) {
	cid := state.VM.GuestCID
	if err := h.waitWardenReady(context.Background(), cid, state.Cfg.WardenSessionKey, 15*time.Second); err != nil {
		if IsProtocolVersionMismatch(err) {
			// The survivor booted from a previous deploy's initramfs and its
			// warden speaks a different protocol. Destroy + replace: the
			// replacement boots from the current initramfs and speaks our
			// version.
			h.logger.Printf("re-adopt: %v — survivor runs an incompatible warden (old initramfs); destroy + replace", err)
			h.scheduleDirtyVMDestroy(state, "warden protocol version mismatch (survivor from an incompatible build)")
			return
		}
		// a survivor whose warden cannot be reached within the boot
		// window is NOT "probably fine" — its pre-restart mount is unproven.
		// Destroy + replace; the selection gate keeps it out of service until
		// then. (The version-mismatch branch above already destroyed.)
		h.logger.Printf("re-adopt: warden not ready on VM %s (%v); destroy + replace", state.VM.ID, err)
		h.scheduleDirtyVMDestroy(state, fmt.Sprintf("re-adopt: warden not ready: %v", err))
		return
	}
	// Drop any agent rootfs still mounted from before the restart so the VM is
	// truly CLEAN (matches the allowed_dirs reset above). The borrowed slot is
	// returned to (or seeds) the VM's pool on release. Any unmount failure
	// (transport or EBUSY/D-state) leaves the guest mount state uncertain —
	// never reuse this VM, destroy + replace (mirrors handleUnmountRootfs).
	agt, done, err := h.acquireWarden(context.Background(), state)
	if err != nil {
		// same fail-closed rule as the wait above — without a dial the
		// stale mount cannot be released, so the survivor must not be reused.
		h.logger.Printf("re-adopt: dial warden for VM %s failed (%v); destroy + replace", state.VM.ID, err)
		h.scheduleDirtyVMDestroy(state, fmt.Sprintf("re-adopt: dial warden: %v", err))
		return
	}
	_, uerr := agt.UnmountRootfsForced()
	done(isWardenTransportErr(uerr))
	if uerr != nil {
		h.logger.Printf("re-adopt: unmount failed on VM %s (%v); destroy + replace", state.VM.ID, uerr)
		h.scheduleDirtyVMDestroy(state, fmt.Sprintf("re-adopt unmount: %v", uerr))
		return
	}
	// The guest mount is now proven released (processes killed, mounts
	// detached, caches dropped), so the outgoing export carries no guest
	// references and the reuse tripwire accepts the clear. Clearing BEFORE the
	// unmount is not an option: the live mount pins inode lookups, and the
	// tripwire would refuse (fail-closed) — turning every clean survivor into
	// a destroy-and-replace. Failure here is still fatal to this VM: a filter
	// whose state is uncertain must not be handed to the next tenant.
	if err := setFsAllowedDirs(context.Background(), state.VM.Client, nil, ""); err != nil {
		h.logger.Printf("re-adopt: clear allowed_dirs on VM %s failed (%v); destroy + replace", state.VM.ID, err)
		h.scheduleDirtyVMDestroy(state, fmt.Sprintf("re-adopt set-fs clear: %v", err))
		return
	}
	// The survivor's guest mount is now proven released.
	h.clearReadoptPending(state.VM.ID)
}

// PersistedNetSpec returns the network spec recorded in the VM's state.json
// under sandboxRoot (nil, true when the VM exists without a network). The
// record is the boxout-owned launch config — never a request field — so a
// reclaim driven from it cannot be steered to a caller-chosen address. The
// second return is false when no usable state exists for the id.
func PersistedNetSpec(sandboxRoot, vmID string) (*vmm.VMNetSpec, bool) {
	if !validStateComponent(vmID) {
		return nil, false
	}
	st, err := loadState(filepath.Join(sandboxRoot, vmID))
	if err != nil {
		return nil, false
	}
	if st.NetSpec == nil {
		return nil, true
	}
	cfg := configFromState(st)
	return cfg.NetSpec, true
}

// --- /proc helpers & orphan cleanup ---

// SandvmmIdentity is the process identity the orphan/re-adopt sweep may act
// on. UID is microvm.vmm_uid (987 in production; 0 = same-identity dev runs).
// BinaryPath/BinaryDev/BinaryIno identify the configured sandvmm executable:
// argv[0] and the executable's basename are forgeable by any local user, so
// the name is a cheap prefilter only — the executable image (dev,ino) is the
// proof.
type SandvmmIdentity struct {
	UID        uint32
	BinaryPath string
	BinaryDev  uint64
	BinaryIno  uint64
}

// NewSandvmmIdentity resolves binary to an absolute path and records the
// executable image's (dev,ino). A resolution failure leaves the binary proof
// unset (the UID/socket proof still applies); it must not fail startup — the
// launcher's own exec would surface a missing binary.
func NewSandvmmIdentity(uid uint32, binary string) SandvmmIdentity {
	id := SandvmmIdentity{UID: uid}
	if binary == "" {
		return id
	}
	resolved := binary
	if !filepath.IsAbs(resolved) {
		if p, err := exec.LookPath(resolved); err == nil {
			resolved = p
		}
	}
	if abs, err := filepath.Abs(resolved); err == nil {
		resolved = abs
	}
	var st unix.Stat_t
	if err := unix.Stat(resolved, &st); err == nil && st.Mode&unix.S_IFMT == unix.S_IFREG {
		id.BinaryPath = resolved
		id.BinaryDev = uint64(st.Dev)
		id.BinaryIno = uint64(st.Ino)
	}
	return id
}

// hasBinaryProof reports whether the configured executable was stat'ed and can
// be compared against /proc/<pid>/exe.
func (id SandvmmIdentity) hasBinaryProof() bool { return id.BinaryIno != 0 }

// sandvmmIdentity resolves this instance's expected process identity from the
// current microVM config. Resolved per control-plane use (one stat) so a
// hot-reloaded vmm_binary/vmm_uid is honored.
func (h *Handler) sandvmmIdentity() SandvmmIdentity {
	cfg := h.CurrentVMMConfig()
	return NewSandvmmIdentity(cfg.VMMUID, cfg.VMMBinary)
}

// ReadoptVMsFromDisk scans sandbox directories and returns info about surviving
// VMs. Exported for boxout to call during readopt_vms requests. It handles the
// /proc scan, network reclaim, and orphan cleanup — returning structured info
// that sandlot uses to build VMState.
func ReadoptVMsFromDisk(ctx context.Context, sandboxRoot string, netProv vmm.NetworkProvider, vmmAPIAuth bool, logger *log.Logger, identity SandvmmIdentity) ([]map[string]any, error) {
	entries, err := os.ReadDir(sandboxRoot)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read %s: %w", sandboxRoot, err)
		}
		return nil, nil
	}

	liveSockets := make(map[string]bool)
	var results []map[string]any

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if ctx.Err() != nil {
			logger.Printf("re-adopt: scan deadline hit; stopping scan")
			break
		}
		vmDir := filepath.Join(sandboxRoot, e.Name())
		st, err := loadState(vmDir)
		if err != nil {
			// Corrupt or missing state — kill any sandvmm holding this dir's socket
			cleanupOrphanDirByPath(ctx, vmDir, sandboxRoot, logger, identity)
			continue
		}

		tok, tokErr := vmm.ReadAPIToken(vmDir)
		if tokErr != nil && vmmAPIAuth {
			// Auth mode is on and the token is unreadable: the socket cannot
			// be authenticated. Treat the survivor as unusable NOW rather than
			// pinging it with a nil token (which could classify a squatted
			// socket as LIVE and reclaim its network).
			logger.Printf("re-adopt: %s: API token unreadable under auth mode (%v); cleaning up", vmDir, tokErr)
			cleanupOrphanDirByPath(ctx, vmDir, sandboxRoot, logger, identity)
			continue
		}
		cli := vmm.NewClient(st.APISocket, tok)
		if err := cli.Ping(ctx); err != nil {
			// Scan-budget expiry ≠ dead VMM: an expired ctx makes every
			// remaining Ping fail instantly, and judging that "dead" would
			// kill every subsequent LIVE VM (see embedded readoptOneVM).
			if ctx.Err() != nil {
				logger.Printf("re-adopt: scan deadline hit at VM %s (%v); aborting sweep", st.VMID, ctx.Err())
				return nil, ctx.Err()
			}
			// Dead VMM. Verify the PID before signaling: it came from a
			// pre-restart state.json and may have been reused by an unrelated
			// process after the sandvmm died.
			if isSandvmmProcWithSocket(st.PID, st.APISocket, identity) {
				killProcGraceful(st.PID)
			}
			if st.NetSpec.HasNetwork() {
				_ = netProv.Release(ctx, st.VMID)
			}
			removeState(vmDir)
			continue
		}

		// LIVE — reclaim network and return info
		cfg := configFromState(st)
		if cfg.NetSpec.HasNetwork() {
			_ = netProv.Reclaim(ctx, st.VMID, *cfg.NetSpec)
		}

		liveSockets[st.APISocket] = true

		cfgJSON, _ := json.Marshal(cfg)
		info := map[string]any{
			"vm_id":             st.VMID,
			"api_socket":        st.APISocket,
			"guest_cid":         st.CID,
			"pid":               st.PID,
			"spec_id":           st.SpecID,
			"mount_count":       st.MountCount,
			"mount_counted_gen": st.MountCountedGen,
			"distinct_agents":   st.DistinctAgents,
			"sandbox_dir":       vmDir,
			"config":            cfgJSON,
		}
		if cfg.NetSpec != nil {
			info["net_spec"] = cfg.NetSpec
		}
		results = append(results, info)
	}

	// Kill orphans (only those under THIS instance's sandbox root — see
	// orphanSocketInScope).
	killOrphanSandvmmStatic(liveSockets, sandboxRoot, logger, identity)

	return results, nil
}

// orphanSocketInScope reports whether a sandvmm's --api-socket belongs to THIS
// sandlot instance (i.e. lives under this instance's sandbox root). The orphan
// sweep must only ever signal processes it owns: on a multi-instance host the
// same /proc shows every instance's sandvmm, and a socket outside our root is
// a sibling instance's live VM — killing it wipes that instance's whole fleet.
// An empty/unknown socket cannot be attributed and is skipped for the same
// reason (fail-safe, not fail-dead).
func orphanSocketInScope(sock, sandboxRoot string) bool {
	if sock == "" {
		return false
	}
	return isSandswapVMDir(sock, sandboxRoot)
}

// killOrphanSandvmmStatic scans /proc for orphan sandvmm processes OWNED BY
// THIS INSTANCE — only processes whose --api-socket lives under sandboxRoot
// are candidates (see orphanSocketInScope). This is the static (non-Handler)
// version for use by boxout. Each candidate is pinned with a pidfd BEFORE its
// identity is verified, so the pid cannot be recycled between scan and signal.
func killOrphanSandvmmStatic(liveSockets map[string]bool, sandboxRoot string, logger *log.Logger, identity SandvmmIdentity) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	unverified := 0
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, ok := parsePID(p.Name())
		if !ok || pid <= 1 {
			continue
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue // gone, or no pidfd support (then no orphan sweep)
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", p.Name(), "cmdline"))
		if err != nil {
			_ = unix.Close(fd)
			continue
		}
		argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if !isSandvmmArgv(argv) {
			_ = unix.Close(fd)
			continue
		}
		sock := apiSocketFromArgv(argv)
		// The argv is a cheap prefilter; the identity proof is the configured
		// executable image or (when /proc/<pid>/exe is unreadable) the
		// dedicated UID plus an existing socket owned by that same UID. A
		// local user naming their own binary "sandvmm" cannot pass either.
		if !verifySandvmmProc(pid, sock, identity) {
			unverified++
			_ = unix.Close(fd)
			continue
		}
		if sock != "" && liveSockets[sock] {
			_ = unix.Close(fd)
			continue
		}
		if !orphanSocketInScope(sock, sandboxRoot) {
			logger.Printf("orphan sweep: skipping sandvmm pid %d (socket=%s outside this instance's sandbox root %s — another instance's VM or unattributable)", pid, sock, sandboxRoot)
			_ = unix.Close(fd)
			continue
		}
		logger.Printf("orphan sweep: killing sandvmm pid %d (socket=%s)", pid, sock)
		if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && err != unix.ESRCH {
			logger.Printf("orphan sweep: kill pid %d: %v", pid, err)
		}
		_ = unix.Close(fd)
	}
	if unverified > 0 {
		logger.Printf("orphan sweep: skipped %d sandvmm-named process(es) whose executable/uid/socket identity could not be verified", unverified)
	}
}

// SandvmmHoldingSocket reports whether a verified sandvmm currently serves
// apiSocket. The periodic sandbox-dir reaper uses it as a liveness gate: a
// live VMM holding the socket proves the directory is in use, possibly by a
// co-located instance of this binary that shares the sandbox root (every
// instance is supposed to own a distinct root, but a shared root must not
// turn one instance's reaper into a killer of the other's live VMs).
// Reaping live VMMs is the startup /proc sweep's job (killOrphanSandvmm),
// which scopes every candidate to this instance's root.
func SandvmmHoldingSocket(apiSocket string, identity SandvmmIdentity) bool {
	if apiSocket == "" {
		return false
	}
	// The socket must EXIST: a missing socket is not "held" (the old
	// missing-file-means-owned fallback let a local user pin orphan dirs with
	// a process merely named sandvmm).
	if _, ok := socketOwner(apiSocket); !ok {
		return false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		pid, ok := parsePID(e.Name())
		if !ok || pid <= 1 {
			continue
		}
		if verifySandvmmHolder(pid, apiSocket, identity) {
			return true
		}
	}
	return false
}

// cleanupOrphanDirByPath handles a sandbox dir with no usable state.json.
// Static version for boxout.
func cleanupOrphanDirByPath(ctx context.Context, vmDir, sandboxRoot string, logger *log.Logger, identity SandvmmIdentity) {
	sock := filepath.Join(vmDir, "sandvmm.sock")
	if SandvmmHoldingSocket(sock, identity) {
		logger.Printf("orphan cleanup %s: keeping dir — a live sandvmm holds %s (another instance's VM or a re-adoptable survivor)", vmDir, sock)
		return
	}
	if _, err := killSandvmmHoldingSocket(sock, identity); err != nil {
		logger.Printf("orphan cleanup %s: kill sandvmm: %v", vmDir, err)
	}
	removeSandboxDir(vmDir, sandboxRoot)
}

// killOrphanSandvmm scans /proc for sandvmm processes whose --api-socket is not
// one of the live re-adopted sockets AND lives under this instance's sandbox
// root, and kills them. Foreign-instance VMs on a shared host are never
// touched (see orphanSocketInScope).
func (h *Handler) killOrphanSandvmm(liveSockets map[string]bool) {
	killOrphanSandvmmStatic(liveSockets, h.SandboxRoot, h.logger, h.sandvmmIdentity())
}

// cleanupOrphanDir handles a sandbox dir with no usable state.json: kill any
// sandvmm still holding its socket (verified while pinned by a pidfd) and
// remove the dir.
func (h *Handler) cleanupOrphanDir(ctx context.Context, vmDir string) {
	sock := filepath.Join(vmDir, "sandvmm.sock")
	identity := h.sandvmmIdentity()
	if SandvmmHoldingSocket(sock, identity) {
		h.logger.Printf("orphan cleanup %s: keeping dir — a live sandvmm holds %s (another instance's VM or a re-adoptable survivor)", vmDir, sock)
		return
	}
	if _, err := killSandvmmHoldingSocket(sock, identity); err != nil {
		h.logger.Printf("orphan cleanup %s: kill sandvmm: %v", vmDir, err)
	}
	removeSandboxDir(vmDir, h.SandboxRoot)
}

// killByPid force-kills a sandvmm by PID (SIGTERM then SIGKILL), but only
// after verifying /proc/<pid>/cmdline is still the expected sandvmm holding
// the expected --api-socket: the PID comes from state.json written before a
// restart, and if the sandvmm died in between, the PID may have been reused
// by an UNRELATED process — signaling it would kill innocent host processes.
// Best-effort: the process may already be gone.
func (h *Handler) killByPid(pid int, vmID, apiSocket string) {
	if pid <= 0 {
		return
	}
	if !isSandvmmProcWithSocket(pid, apiSocket, h.sandvmmIdentity()) {
		h.logger.Printf("kill-by-pid %d for VM %s skipped: /proc cmdline is not sandvmm with socket %s (process gone or PID reused)",
			pid, vmID, apiSocket)
		return
	}
	if !killProcGraceful(pid) {
		h.logger.Printf("kill-by-pid %d for VM %s: process not found or already gone", pid, vmID)
	}
}

// IsSandvmmProcWithSocket reports whether pid's /proc cmdline is a sandvmm
// invocation carrying exactly the given --api-socket. Empty socket matches any
// sandvmm argv (used when the socket is unknown). Exported for boxout: the
// privileged sidecar must apply the SAME "never signal a pid we have not
// verified is ours" discipline before acting on a caller-supplied pid.
func IsSandvmmProcWithSocket(pid int, apiSocket string, identity SandvmmIdentity) bool {
	return isSandvmmProcWithSocket(pid, apiSocket, identity)
}

// FindSandvmmPIDForSocket discovers the pid of the sandvmm process whose
// --api-socket is exactly apiSocket (0 when none). The pid comes from /proc,
// never from a request: the untracked destroy path uses this to bind its
// action to the sandbox it validated instead of trusting caller-supplied
// pid/socket strings. The verification runs on a pidfd-pinned process, so the
// returned pid cannot have been recycled by the time the caller acts.
func FindSandvmmPIDForSocket(apiSocket string, identity SandvmmIdentity) int {
	pid, _ := findSandvmmForSocket(apiSocket, identity)
	return pid
}

// KillSandvmmForSocket SIGKILLs the sandvmm serving apiSocket (0, nil when
// none is running) through a pidfd opened before the identity verification.
// A signal failure is returned, never swallowed: the caller's teardown must
// see that the process it is about to remove state for may still be alive.
func KillSandvmmForSocket(apiSocket string, identity SandvmmIdentity) (int, error) {
	pid, fd := findSandvmmForSocket(apiSocket, identity)
	if fd < 0 {
		return 0, nil
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		return pid, fmt.Errorf("kill sandvmm pid %d: %w", pid, err)
	}
	return pid, nil
}

// liveSandvmmSockets returns the set of --api-socket paths served by live
// sandvmm processes, verified with the same identity rules as
// findSandvmmForSocket, in ONE /proc pass. The periodic sandbox-dir reaper
// calls this once per tick instead of scanning /proc once per directory.
func liveSandvmmSockets(identity SandvmmIdentity) map[string]struct{} {
	out := make(map[string]struct{})
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, ok := parsePID(e.Name())
		if !ok || pid <= 1 {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
		if err != nil {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if !isSandvmmArgv(argv) {
			continue
		}
		sock := apiSocketFromArgv(argv)
		if sock == "" {
			continue
		}
		// The liveness proof is the socket itself: it must exist and be
		// owned by the process's real uid (== the dedicated VMM uid when
		// configured). A local user cannot create a socket inside another
		// identity's sandbox dir; no executable-name check is needed here.
		if verifySandvmmHolder(pid, sock, identity) {
			out[sock] = struct{}{}
		}
	}
	return out
}

// findSandvmmForSocket returns the pid and its pidfd (caller closes) for the
// verified sandvmm serving apiSocket. fd is -1 when none.
func findSandvmmForSocket(apiSocket string, identity SandvmmIdentity) (int, int) {
	if apiSocket == "" {
		return 0, -1
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, -1
	}
	for _, e := range entries {
		pid, ok := parsePID(e.Name())
		if !ok || pid <= 1 {
			continue
		}
		if fd := openPidfdIfSandvmm(pid, apiSocket, identity); fd >= 0 {
			return pid, fd
		}
	}
	return 0, -1
}

// sandvmmArgvMatches is the cheap prefilter shared by both proofs: the process
// looks like a sandvmm invocation and (when apiSocket is non-empty) advertises
// exactly that socket. argv is writable by the process, so this NEVER proves
// identity on its own.
func sandvmmArgvMatches(pid int, apiSocket string) (string, bool) {
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return "", false // gone
	}
	argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if !isSandvmmArgv(argv) {
		return "", false
	}
	sock := apiSocketFromArgv(argv)
	if apiSocket != "" && sock != apiSocket {
		return "", false
	}
	return sock, true
}

// verifySandvmmHolder is the LIVENESS proof used by the sandbox-dir reaper and
// the live-socket set. A live VMM owns its API socket; a local user cannot
// create/own a socket inside another identity's sandbox dir. The socket must
// EXIST (a missing socket is not a holder — the old missing-file fallback let
// a process merely named sandvmm pin orphan dirs), its owner must equal the
// process's real uid, and when a dedicated VMM uid is configured that uid must
// match too. No executable check: co-located instances may run different
// binaries, and the socket ownership is the proof.
func verifySandvmmHolder(pid int, apiSocket string, identity SandvmmIdentity) bool {
	if apiSocket == "" {
		return false
	}
	if _, ok := sandvmmArgvMatches(pid, apiSocket); !ok {
		return false
	}
	owner, ok := socketOwner(apiSocket)
	if !ok {
		return false
	}
	uid, ok := procUID(pid)
	if !ok || uid != owner {
		return false
	}
	return identity.UID == 0 || owner == identity.UID
}

// verifySandvmmProc is the KILL proof. It accepts either:
//   - the configured executable image (dev,ino) plus the uid/socket
//     consistency rules — a readable /proc/<pid>/exe that does NOT match is a
//     refusal even if its basename is sandvmm; or
//   - when /proc/<pid>/exe is unreadable (cross-uid non-dumpable), the
//     dedicated VMM uid with an EXISTING socket owned by that uid.
//
// A missing socket is acceptable only through the binary proof (a live VMM
// whose socket path was unlinked): the image is then the identity. The old
// basename check is gone: any local user can name a binary sandvmm.
func verifySandvmmProc(pid int, apiSocket string, identity SandvmmIdentity) bool {
	if _, ok := sandvmmArgvMatches(pid, apiSocket); !ok {
		return false
	}
	uid, uidOK := procUID(pid)
	owner, sockOK := socketOwner(apiSocket)

	if identity.hasBinaryProof() {
		var exe unix.Stat_t
		if err := unix.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"), &exe); err == nil {
			if uint64(exe.Dev) != identity.BinaryDev || uint64(exe.Ino) != identity.BinaryIno {
				return false
			}
			if !uidOK {
				return false
			}
			if identity.UID > 0 && uid != identity.UID {
				return false
			}
			if sockOK && owner != uid {
				return false
			}
			return true
		}
		// exe unreadable: fall through to the uid/socket proof.
	}

	if !uidOK || !sockOK || owner != uid {
		return false
	}
	return identity.UID == 0 || owner == identity.UID
}

// isSandvmmProcWithSocket reports whether pid is the sandvmm invocation that
// serves exactly the given --api-socket, under the configured identity proof.
// Empty socket matches any sandvmm invocation (used when the socket is
// unknown).
func isSandvmmProcWithSocket(pid int, apiSocket string, identity SandvmmIdentity) bool {
	return verifySandvmmProc(pid, apiSocket, identity)
}

// procUID reads the process's real uid from /proc/<pid>/status.
func procUID(pid int) (uint32, bool) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		n, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(n), true
	}
	return 0, false
}

// socketOwner returns the owner uid of an EXISTING Unix socket at path. A
// missing entry, a non-socket, or an unreadable path is NOT an owner proof:
// the old "missing socket imposes no constraint" fallback let any process
// named sandvmm pin an orphan dir (the liveness DoS this identity check
// exists to close).
func socketOwner(path string) (uint32, bool) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return 0, false
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return 0, false
	}
	return st.Uid, true
}

// openPidfdIfSandvmm pins pid with a pidfd BEFORE verifying it is the sandvmm
// serving apiSocket. A pidfd-held process cannot be reaped, so its pid cannot
// be recycled between the scan and the signal — the TOCTOU the plain
// read-then-kill sequence had. Returns -1 when the candidate is gone or is
// not the expected process.
func openPidfdIfSandvmm(pid int, apiSocket string, identity SandvmmIdentity) int {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1
	}
	if !isSandvmmProcWithSocket(pid, apiSocket, identity) {
		_ = unix.Close(fd)
		return -1
	}
	return fd
}

// killSandvmmHoldingSocket SIGKILLs every process that is (verified while
// pinned by a pidfd) a sandvmm invocation whose --api-socket is sock. Returns
// the number signaled and the first signal error.
func killSandvmmHoldingSocket(sock string, identity SandvmmIdentity) (int, error) {
	if sock == "" {
		return 0, nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, nil
	}
	killed := 0
	var firstErr error
	for _, e := range entries {
		pid, ok := parsePID(e.Name())
		if !ok || pid <= 1 {
			continue
		}
		fd := openPidfdIfSandvmm(pid, sock, identity)
		if fd < 0 {
			continue
		}
		if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
			if firstErr == nil && err != unix.ESRCH {
				firstErr = err
			}
		} else {
			killed++
		}
		_ = unix.Close(fd)
	}
	return killed, firstErr
}

// parsePID parses a decimal PID string.
func parsePID(name string) (int, bool) {
	n := 0
	for _, c := range name {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// isSandvmmBinaryName reports whether base names a sandvmm executable: the
// build output (`sandvmm` — dev, e2e and the k8s image) and the installed
// binary name (`sandswap-sandvmm`, what the bare-metal deployers install and
// microvm.vmm_binary points at). The process image name is what /proc/<pid>/exe
// resolves to; argv[0] is forgeable.
func isSandvmmBinaryName(base string) bool {
	base = strings.TrimSuffix(base, " (deleted)")
	return base == "sandvmm" || base == "sandswap-sandvmm"
}

// isSandvmmArgv reports whether argv looks like a sandvmm invocation.
func isSandvmmArgv(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	return isSandvmmBinaryName(filepath.Base(argv[0]))
}

// apiSocketFromArgv extracts the --api-socket value from a sandvmm argv.
func apiSocketFromArgv(argv []string) string {
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "--api-socket" {
			return argv[i+1]
		}
	}
	return ""
}

// gracefulShutdownGrace is the time between SIGTERM and SIGKILL in
// killProcGraceful. Gives the process a brief window to exit cleanly.
const gracefulShutdownGrace = 300 * time.Millisecond

// killProcGraceful sends SIGTERM then SIGKILL to a PID. Returns false if the
// process did not exist at all, or if a signal failed for any reason other
// than "already gone" (an EPERM/failed SIGKILL must never read as success —
// the caller would then drop the bookkeeping for a process that still runs).
// The process is pinned with a pidfd first, so a pid recycled between the
// caller's check and this call cannot be signaled. Non-child processes are
// reaped by init.
// Exported for boxout to use when killing orphan sandvmm processes.
func KillProcGraceful(pid int) bool {
	return killProcGraceful(pid)
}

func killProcGraceful(pid int) bool {
	if pid <= 1 {
		// Never signal init (or our own process group, via pid 0/negative).
		return false
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if err == unix.ESRCH {
			return false
		}
		// Kernels without pidfd support: fall back to plain signals, keeping
		// the same "only ESRCH means gone" rule.
		if serr := syscall.Kill(pid, syscall.SIGTERM); serr != nil {
			return false
		}
		time.Sleep(gracefulShutdownGrace)
		if serr := syscall.Kill(pid, syscall.SIGKILL); serr != nil && serr != syscall.ESRCH {
			return false
		}
		return true
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
		return false
	}
	// Brief grace period, then ensure death.
	time.Sleep(gracefulShutdownGrace)
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		return err == unix.ESRCH // already gone after SIGTERM
	}
	return true
}
