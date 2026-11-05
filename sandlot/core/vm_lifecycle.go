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

	"sandlot/vmm"
)

// VMLifecycleManager abstracts VM lifecycle, network, overlay, and re-adopt
// operations that require privileges. Two implementations:
//   - embeddedManager: direct calls (current behavior, zero overhead)
//   - boxoutManager: delegates to boxout sidecar via Unix socket
//
// In embedded mode, sandlot calls vmm.Launch, h.net.Provision, syscall.Mount
// directly. In boxout mode, sandlot delegates these privileged operations to
// the boxout sidecar over a Unix socket.
//
// Hot-path operations (SetFs, warden vsock exec, lease management) do NOT go
// through this interface — they are unprivileged and sandlot calls them
// directly regardless of mode.
type VMLifecycleManager interface {
	// CreateVM launches a sandvmm process and returns its identity.
	// In embedded mode: calls vmm.Launch directly.
	// In boxout mode: sends create_vm request to boxout; boxout launches
	// sandvmm and returns the VM's identity (API socket path, PID, CID).
	// The caller (handleCreate/createPoolVM) uses the returned VMLifecycleInfo
	// to build a RunningVM handle and start the warden connection cache.
	CreateVM(ctx context.Context, cfg vmm.Config) (*VMLifecycleInfo, error)

	// DestroyVM kills a sandvmm process and cleans up its privileged resources
	// (network release, state.json removal, sandbox dir removal). target
	// carries everything needed WITHOUT a map lookup — the caller may have
	// already deleted the VM from h.vms (destroyVMByID does); the embedded
	// impl used to re-look-up the map and skip the kill on a miss.
	// In embedded mode: killVMM (Kill/Shutdown + wait) + removeState +
	// net.Release directly. In boxout mode: sends destroy_vm request; boxout
	// kills the process (even when untracked, by PID), releases network,
	// removes state.
	//
	// The caller handles sandlot-owned cleanup: deleting from the vms map,
	// closing the cached warden connection, clearing allowed_dirs (via the
	// vmm.Client that sandlot owns), and releasing the CID (which sandlot
	// allocates).
	DestroyVM(ctx context.Context, target *DestroyTarget) error

	// ProvisionNetwork allocates network resources for a VM (TAP, IP).
	// In embedded mode: calls h.net.Provision directly.
	// In boxout mode: sends provision_network request to boxout.
	ProvisionNetwork(ctx context.Context, vmID string) (vmm.VMNetSpec, error)

	// ReleaseNetwork releases network resources for a VM.
	// In embedded mode: calls h.net.Release directly.
	// In boxout mode: sends release_network request to boxout.
	ReleaseNetwork(ctx context.Context, vmID string) error

	// ReclaimNetwork re-registers network resources for a re-adopted VM.
	// In embedded mode: calls h.net.Reclaim directly.
	// In boxout mode: sends reclaim_network request to boxout.
	ReclaimNetwork(ctx context.Context, vmID string, spec vmm.VMNetSpec) error

	// MountOverlay mounts a read-only OverlayFS at volumePath/rootfs,
	// verifying it serves expectedRef (the identity record's template ref;
	// remounts from the volume's .template marker on a swap-stale mismatch —
	// the storage truth). Returns the ref actually backing the mount.
	// In embedded mode: calls h.ensureReadonlyOverlayMounted directly.
	// In boxout mode: sends mount_overlay request to boxout (which has
	// CAP_SYS_ADMIN for syscall.Mount).
	MountOverlay(ctx context.Context, volumePath, expectedRef string) (string, error)

	// UnmountOverlay unmounts the OverlayFS at volumePath/rootfs.
	// In embedded mode: calls h.cleanupHostOverlay directly.
	// In boxout mode: sends unmount_overlay request to boxout.
	UnmountOverlay(ctx context.Context, volumePath string) error

	// VerifyVolumeID binds the gateway-supplied (sandfsID, volumePath) pair
	// to the volume's on-disk identity stamp BEFORE a cold mount. The exec
	// role deliberately has no volume-name seed, so this is the seedless
	// id-equality check; the stamp's HMAC remains the prov instance's
	// VerifyVolumeIdentity. This is the node-side containment the threat
	// model claims for a compromised gateway: it can name any directory, but
	// the node refuses unless that directory's own stamp names the sandfs.
	// In embedded mode: reads the volume's .sandfs-id directly.
	// In boxout mode: sends verify_volume_id to boxout (which owns volumes-dir
	// access when sandlot runs as the unprivileged reserved UID).
	VerifyVolumeID(ctx context.Context, sandfsID, volumePath, volumeEpoch string) error

	// ReadoptVMs scans for surviving sandvmm processes and returns their info.
	// In embedded mode: scans /proc and sandbox dirs directly, calls vmm.Attach.
	// In boxout mode: sends readopt_vms request to boxout (which has hostPID
	// to scan /proc).
	ReadoptVMs(ctx context.Context) ([]ReadoptedVMInfo, error)

	// RestoreMountedOverlays rebuilds the overlay tracking set from mountinfo.
	// In embedded mode: reads /proc/self/mountinfo directly.
	// In boxout mode: sends restore_overlays request to boxout (which reads
	// its own mountinfo, since it owns the mounts).
	RestoreMountedOverlays()

	// CleanupStaleOverlays scans tracked overlays and unmounts stale ones.
	// In embedded mode: iterates mountedOverlays set + calls cleanupHostOverlay.
	// In boxout mode: sends cleanup_overlays request to boxout.
	CleanupStaleOverlays()

	// Stop shuts down the lifecycle manager (stops monitors, closes sockets).
	Stop()
}

// VMLifecycleInfo is the result of CreateVM — enough for sandlot to build
// a RunningVM handle and connect to sandvmm/warden, without having launched
// the process itself.
//
// In embedded mode, RunningVM is set (from vmm.Launch) and carries the
// *exec.Cmd needed for crash monitoring (cmd.Wait reaps the sandvmm child).
// In boxout mode, RunningVM is nil (boxout launched the process; sandlot
// only knows the PID and must use pidfd/periodic-ping for liveness).
type VMLifecycleInfo struct {
	VMID      string
	APISocket string // sandvmm HTTP Unix socket path
	GuestCID  uint32 // vsock guest CID
	PID       int    // sandvmm process ID
	NetSpec   *vmm.VMNetSpec
	RunningVM *vmm.RunningVM // non-nil in embedded mode (carries *exec.Cmd)
}

// ReadoptedVMInfo is returned by ReadoptVMs for each surviving VM.
type ReadoptedVMInfo struct {
	VMID            string
	APISocket       string // sandvmm HTTP Unix socket path
	GuestCID        uint32
	PID             int
	SpecID          string         // pool spec (e.g. "small")
	NetSpec         *vmm.VMNetSpec // network config for reclaim
	SandboxDir      string         // on-disk sandbox dir path
	Cfg             vmm.Config     // full VM config (for VMState construction)
	MountCount      uint64
	MountCountedGen int64
	DistinctAgents  []string
}
