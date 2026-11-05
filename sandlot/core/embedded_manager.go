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
	"os"
	"path/filepath"

	"sandlot/provision/volume"
	"sandlot/vmm"
)

// embeddedManager implements VMLifecycleManager by calling the current direct
// code paths — zero behavior change from before the VMLifecycleManager
// refactor. Used in embedded mode (default, bare-metal/systemd deployment)
// and in the existing K8s deployment (privileged sandlot pod).
type embeddedManager struct {
	handler *Handler // back-reference for net, vmm, overlay, readopt, monitor
}

// NewEmbeddedManager creates an embeddedManager wrapping the given handler.
// The handler must have its net (NetworkProvider) and pidfdM fields set.
func NewEmbeddedManager(h *Handler) *embeddedManager {
	return &embeddedManager{handler: h}
}

// CreateVM launches a sandvmm process via vmm.Launch and persists its state.
func (m *embeddedManager) CreateVM(ctx context.Context, cfg vmm.Config) (*VMLifecycleInfo, error) {
	h := m.handler

	vm, err := vmm.Launch(context.Background(), cfg, h.logger)
	if err != nil {
		return nil, fmt.Errorf("launch vmm: %w", err)
	}
	// Launch generated the key when the caller had none; carry the effective
	// value into persisted state (re-adopt must authenticate with it).
	cfg.WardenSessionKey = vm.WardenSessionKey
	// Same carry for the effective kernel cmdline: Launch applies the base
	// default and appends the warden params on its own cfg copy, so the
	// caller's cfg alone would persist an empty/partial cmdline.
	cfg.KernelCmdline = vm.KernelCmdline

	// Persist state for re-adopt
	if err := writeState(stateFromConfig(cfg.ID, cfg, vm.APISocket, vm.PID(), ""), h.SandboxRoot); err != nil {
		h.logger.Printf("write state for VM %s (non-fatal, no re-adopt on crash): %v", cfg.ID, err)
	}

	info := &VMLifecycleInfo{
		VMID:      cfg.ID,
		APISocket: vm.APISocket,
		GuestCID:  vm.GuestCID,
		PID:       vm.PID(),
		NetSpec:   cfg.NetSpec,
		RunningVM: vm, // carries *exec.Cmd for crash monitoring
	}
	return info, nil
}

// DestroyVM kills the sandvmm process, releases its network resources, and
// removes its persisted state and sandbox directory. The target carries the
// RunningVM handle — it must NOT re-look-up h.vms (the caller has already
// deleted the map entry, and a miss would skip the kill). Returns an error
// when the process death could not be confirmed (D-state): the caller must
// then skip the CID release — a replacement VM on a live vsock CID is born
// without an agent channel.
func (m *embeddedManager) DestroyVM(ctx context.Context, target *DestroyTarget) error {
	h := m.handler
	if target == nil {
		return nil
	}

	// Kill the process (bounded ~9s worst case; never takes execMu).
	confirmed := h.killVMM(ctx, target)

	// Release network resources
	if h.net != nil {
		if err := h.net.Release(ctx, target.VMID); err != nil {
			h.logger.Printf("network release for VM %s (non-fatal): %v", target.VMID, err)
		}
	}

	// Remove persisted state AND sandbox dir
	if target.SandboxDir != "" {
		removeState(target.SandboxDir)
		removeSandboxDir(target.SandboxDir, h.SandboxRoot)
	}

	if !confirmed {
		return fmt.Errorf("sandvmm for VM %s (pid %d) may still be alive (ignoring signals); CID release skipped",
			target.VMID, target.PID)
	}
	return nil
}

// ProvisionNetwork allocates network resources for a VM.
func (m *embeddedManager) ProvisionNetwork(ctx context.Context, vmID string) (vmm.VMNetSpec, error) {
	return m.handler.net.Provision(ctx, vmID)
}

// ReleaseNetwork releases network resources for a VM.
func (m *embeddedManager) ReleaseNetwork(ctx context.Context, vmID string) error {
	return m.handler.net.Release(ctx, vmID)
}

// ReclaimNetwork re-registers network resources for a re-adopted VM.
func (m *embeddedManager) ReclaimNetwork(ctx context.Context, vmID string, spec vmm.VMNetSpec) error {
	return m.handler.net.Reclaim(ctx, vmID, spec)
}

// MountOverlay mounts a read-only OverlayFS at volumePath/rootfs (verifying
// it serves expectedRef — remounting from the marker on a swap-stale
// mismatch). Returns the ref actually backing the mount.
func (m *embeddedManager) MountOverlay(ctx context.Context, volumePath, expectedRef string) (string, error) {
	return m.handler.ensureReadonlyOverlayMounted(volumePath, expectedRef)
}

// UnmountOverlay unmounts the OverlayFS at volumePath/rootfs.
func (m *embeddedManager) UnmountOverlay(ctx context.Context, volumePath string) error {
	return m.handler.cleanupHostOverlay(volumePath)
}

// VerifyVolumeID reads the volume's identity stamp directly (embedded mode:
// sandlot already has storage-group access on the node).
func (m *embeddedManager) VerifyVolumeID(ctx context.Context, sandfsID, volumePath, volumeEpoch string) error {
	return volume.CheckVolumeID(volumePath, sandfsID, volumeEpoch)
}

// ReadoptVMs scans for surviving sandvmm processes and returns their info.
// This calls the current ReadoptVMs logic but returns structured info instead
// of modifying the handler's vms map directly.
func (m *embeddedManager) ReadoptVMs(ctx context.Context) ([]ReadoptedVMInfo, error) {
	h := m.handler

	entries, err := os.ReadDir(h.SandboxRoot)
	if err != nil {
		if !os.IsNotExist(err) {
			h.logger.Printf("re-adopt: read %s: %v", h.SandboxRoot, err)
		}
		return nil, nil
	}

	var results []ReadoptedVMInfo
	liveSockets := make(map[string]bool)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Stop dispatching new judgments once the scan budget is gone: an
		// expired ctx makes every Ping fail instantly, and per-VM verdicts
		// taken past that point are about OUR deadline, not the VMM.
		if ctx.Err() != nil {
			h.logger.Printf("re-adopt: scan deadline hit; stopping after %d live VM(s)", len(results))
			break
		}
		vmDir := filepath.Join(h.SandboxRoot, e.Name())
		info := m.readoptOneVM(ctx, vmDir, liveSockets)
		if info != nil {
			results = append(results, *info)
		}
	}

	h.killOrphanSandvmm(liveSockets)

	return results, nil
}

// readoptOneVM handles a single sandbox dir for re-adoption. Returns
// ReadoptedVMInfo for live VMs, nil for dead/corrupt ones.
func (m *embeddedManager) readoptOneVM(ctx context.Context, vmDir string, liveSockets map[string]bool) *ReadoptedVMInfo {
	h := m.handler

	st, err := loadState(vmDir)
	if err != nil {
		h.logger.Printf("re-adopt: %s: %v; cleaning up", vmDir, err)
		h.cleanupOrphanDir(ctx, vmDir)
		return nil
	}

	tok, tokErr := vmm.ReadAPIToken(vmDir)
	if tokErr != nil && h.vmmCfg.VMMAPIAuth {
		// The socket cannot be authenticated; do not ping it with a nil token
		// (a squatted socket could answer and be classified LIVE).
		h.logger.Printf("re-adopt: %s: API token unreadable under auth mode (%v); cleaning up", vmDir, tokErr)
		h.cleanupOrphanDir(ctx, vmDir)
		return nil
	}
	cli := vmm.NewClient(st.APISocket, tok)
	if err := cli.Ping(ctx); err != nil {
		// A scan-budget (or shutdown) expiry makes every subsequent Ping fail
		// instantly — that is OUR deadline, not a dead VMM. Treating it as
		// "dead" would kill every remaining LIVE VM in the sweep. Leave the
		// dir untouched: the next restart (or a sweep that fits the budget)
		// re-judges it.
		if ctx.Err() != nil {
			h.logger.Printf("re-adopt: scan deadline hit at VM %s (%v); aborting sweep without judging it dead", st.VMID, ctx.Err())
			return nil
		}
		h.logger.Printf("re-adopt: VM %s not responding (%v); cleaning up", st.VMID, err)
		h.killByPid(st.PID, st.VMID, st.APISocket)
		if st.NetSpec.HasNetwork() {
			if relErr := h.net.Release(ctx, st.VMID); relErr != nil {
				h.logger.Printf("re-adopt: release net for dead VM %s (non-fatal): %v", st.VMID, relErr)
			}
		}
		h.releaseCID(st.CID)
		removeState(vmDir)
		return nil
	}

	// LIVE — return info for the caller to build VMState
	cfg := configFromState(st)
	info := &ReadoptedVMInfo{
		VMID:            st.VMID,
		APISocket:       st.APISocket,
		GuestCID:        st.CID,
		PID:             st.PID,
		SpecID:          st.SpecID,
		NetSpec:         cfg.NetSpec,
		SandboxDir:      vmDir,
		Cfg:             cfg,
		MountCount:      st.MountCount,
		MountCountedGen: st.MountCountedGen,
		DistinctAgents:  st.DistinctAgents,
	}

	// Reclaim network
	if cfg.NetSpec.HasNetwork() {
		if relErr := h.net.Reclaim(ctx, st.VMID, *cfg.NetSpec); relErr != nil {
			h.logger.Printf("re-adopt: reclaim net for VM %s (non-fatal): %v", st.VMID, relErr)
		}
	}

	liveSockets[st.APISocket] = true
	return info
}

// RestoreMountedOverlays rebuilds the overlay tracking set from mountinfo.
func (m *embeddedManager) RestoreMountedOverlays() {
	m.handler.restoreMountedOverlaysFromMountinfo()
}

// CleanupStaleOverlays scans tracked overlays and unmounts stale ones.
func (m *embeddedManager) CleanupStaleOverlays() {
	m.handler.cleanupStaleOverlays()
}

// Stop is a no-op in embedded mode — the pidfdMonitor is stopped by
// Handler.Stop() directly.
func (m *embeddedManager) Stop() {}
