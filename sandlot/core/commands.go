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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	commonconfig "common/config"
	pb "common/proto/stream"
	"sandlot/vmm"
	"sandlot/warden"
)

// mountedVolumeMatches asserts the warden's mounted-volume identity (the
// response `mounted` field) against the alias this cold mount generated. A
// mismatch means the warden's mount state was twisted out-of-band (a peer
// holding the VM's session key) OR a spoofed mount raced the switch: /mnt/rootfs
// does NOT provably hold this volume, so no result of the RPC that carried it
// may be trusted — not the exec output, not the exec_id.
//
// A mismatch on a SUPERSEDED generation (mountGen moved while the RPC was in
// flight) only fails this request: the VM may now be serving another tenant,
// and destroying it would turn a stale request into a cross-tenant outage.
// The current-generation case still dirty-destroys (fail-closed).
func (h *Handler) mountedVolumeMatches(state *VMState, volumePath, expected, mounted string, gen int64) error {
	if mounted == expected {
		return nil
	}
	if state.mountGen.Load() != gen {
		h.logger.Printf("VM %s: superseded cold mount answered %q (expected %q); discarding the stale result without destroying the VM",
			state.VM.ID, mounted, expected)
		return fmt.Errorf("mount generation superseded during the cold RPC — retry")
	}
	h.logger.Printf("VM %s: warden reports %q mounted at /mnt/rootfs but %q was expected for %q — twisted mount state (out-of-band mount?); dirty-destroying VM",
		state.VM.ID, mounted, expected, volumePath)
	h.scheduleDirtyVMDestroy(state, "mounted-volume identity mismatch")
	// The response string reaches the agent's API surface: carry NO volume
	// name (the on-disk name is seed-derived and must stay host-side —
	// ambient sandbox strings leak to third-party LLMs wholesale).
	return fmt.Errorf("warden mounted a different volume than requested — VM destroyed to maintain exclusive-ownership")
}

// mountSuperseded reports whether the generation this request acted on has
// moved on (or the sandfs was rebound to another VM). The VM may now be
// serving another tenant, so a failure from this request must fail itself:
// destroying the VM would turn a stale request into a cross-tenant outage.
// The switch chain has already run (or is running) whenever the generation
// moves — mounts are serialized under mountMu and the warden MOUNT_GATE
// orders an unmount behind any in-flight mount/exec — so any partially
// established mount from this request is torn down by that chain; a destroy
// adds nothing. Within the CURRENT generation an unproven mount state is
// still fail-closed (destroy).
func (h *Handler) mountSuperseded(state *VMState, sandfsID string, gen int64) bool {
	return state.mountGen.Load() != gen || h.vmForSandfs(sandfsID) != state
}

// newMountAlias mints this generation's export alias: 16 random bytes as 32
// lowercase hex characters. The alias is the capability binding one set-fs
// generation to the warden mount that follows it; it is never reused (the
// VMM refuses that) and never derived from the seed-derived volume name.
// A rand failure is fatal to the request — there is no degraded fallback
// that would reintroduce a guessable constant name.
func newMountAlias() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("mint mount alias: %w", err)
	}
	return hex.EncodeToString(nonce), nil
}

// mountIdentityFor is the identity a warm op asserts for this volume: the
// alias recorded at the cold mount when it names the request's volume.
// There is deliberately no basename fallback: the real volume name is a
// host-side secret, and an unrecorded identity means the mount state is not
// proven (the warden refuses it rather than running against whatever is
// mounted).
func (h *Handler) mountIdentityFor(state *VMState, volumePath string) string {
	state.mountMu.Lock()
	defer state.mountMu.Unlock()
	if state.mountIdentity != "" && state.mountIdentityPath == volumePath {
		return state.mountIdentity
	}
	return ""
}

// fileOpIdentity is the mounted-volume assertion a file op sends to the
// warden. ONLY the request's own volume path (the gateway's tenant record) is
// accepted: it is the one value that cannot change under the request while
// the sandlot's mount bookkeeping is switching tenants. The VM's mount record
// is not a fallback — deriving from it made the warden confirm whatever was
// mounted, which is exactly the cross-tenant bug this replaced.
func (h *Handler) fileOpIdentity(reqVolumePath string, state *VMState) string {
	return h.mountIdentityFor(state, reqVolumePath)
}

// ensureMountRecordsLocked lazily initializes the per-binding identity maps
// (VMStates are built by pool, on-demand and re-adopt paths alike).
// Caller holds mountMu.
func (h *Handler) ensureMountRecordsLocked(state *VMState) {
	if state.mountAliasBySandfs == nil {
		state.mountAliasBySandfs = make(map[string]string)
	}
	if state.mountPathBySandfs == nil {
		state.mountPathBySandfs = make(map[string]string)
	}
	if state.mountEpochBySandfs == nil {
		state.mountEpochBySandfs = make(map[string]string)
	}
}

// forgetBindingIdentityLocked drops the per-sandfs generation record.
// Caller holds mountMu.
func (h *Handler) forgetBindingIdentityLocked(state *VMState, sandfsID string) {
	if state.mountAliasBySandfs != nil {
		delete(state.mountAliasBySandfs, sandfsID)
	}
	if state.mountPathBySandfs != nil {
		delete(state.mountPathBySandfs, sandfsID)
	}
	if state.mountEpochBySandfs != nil {
		delete(state.mountEpochBySandfs, sandfsID)
	}
	if state.pendingMount != nil && state.pendingMount.sandfsID == sandfsID {
		state.pendingMount = nil
	}
}

// bindingAliasLocked returns the alias recorded for this sandfs binding, or
// "" when the VM does not hold a proven mount for it. Caller holds mountMu.
func (h *Handler) bindingAliasLocked(state *VMState, sandfsID string) string {
	if state.mountAliasBySandfs == nil {
		return ""
	}
	return state.mountAliasBySandfs[sandfsID]
}

// normalizeFileOpLength maps the wire's "0 = read up to the cap" to the
// explicit cap. The warden interprets 0 as max_file_read_bytes (16 MiB), and
// the response plus the gRPC envelope would breach the node stream's message
// limit — the reply reset kills every co-tenant in-flight command.
func normalizeFileOpLength(length *int64) {
	if *length <= 0 {
		*length = int64(maxFileOpDataBytes)
	}
}

// fileOpResponseTooLarge is the reply-leg guard (see handleFileOp).
func fileOpResponseTooLarge(n int) bool {
	return n > maxFileOpDataBytes
}

// checkVolumePathContained enforces the host-side containment every
// gateway-supplied volume path must pass before it becomes a mount source
// (MountOverlay / set-fs allowed_dirs / the host-side overlay unmount). The
// gateway validates the record's rootfs_path lexically, but this node is the
// component that turns the path into a mount(2)/unmount(2) — the same "never
// trust the peer's validation" rule the boxout sidecar applies to its
// mount_overlay/unmount_overlay requests. Refusing by name (rather than
// clamping) keeps a gateway bug or a compromised peer from mounting a host
// directory into a guest.
func (h *Handler) checkVolumePathContained(volumePath string) error {
	volumesDir := h.CurrentVMMConfig().VolumesDir
	if volumesDir == "" {
		// An empty root would make the prefix test below degenerate to "/"
		// (every absolute path passes) — the "an empty configuration value
		// must never silently disable a containment check" rule. Production
		// always sets it (the -volumes-dir flag default, preserved across
		// hot-reloads); an empty value here is a construction bug.
		return fmt.Errorf("volume_path %q refused: no volumes root configured — refusing rather than testing containment against the empty string", volumePath)
	}
	// Refuse traversal by NAME before any cleaning: the caller's intent is
	// explicit, and the error must say so rather than a generic containment
	// failure after Clean() folded the `..` away.
	if strings.Contains(volumePath, "..") {
		return fmt.Errorf("volume_path %q contains path traversal", volumePath)
	}
	// Clean both operands before the prefix test: a trailing slash in the
	// configured root (or a doubled separator) made every legitimate volume
	// path fail containment even though the config parsed and the node ran.
	root := filepath.Clean(volumesDir)
	p := filepath.Clean(volumePath)
	if !strings.HasPrefix(p, root+"/") {
		return fmt.Errorf("volume_path %q is outside the volumes root %s", volumePath, volumesDir)
	}
	// Require a DIRECT child of the volumes root. Every volume directory is
	// one seed-derived component, and the sources this path feeds (the host
	// overlay mount, set-fs allowed_dirs, the host-side overlay unmount) are
	// defined over exactly that shape. A nested path would widen the
	// VMM-exported subtree (the in-process virtio-fs filter refuses `..` but
	// serves any depth under an allowed entry), so anything deeper is refused
	// by name rather than trusted to the peer.
	if filepath.Dir(p) != root {
		return fmt.Errorf("volume_path %q is not a direct child of the volumes root %s", volumePath, volumesDir)
	}
	return nil
}

// validateVolumeMode enforces the identity record's volume mode contract at
// the node, before any host overlay mount or guest mount is attempted. The
// warden mounts according to this value and never probes the volume's layout,
// so an empty/unknown mode is refused (fail closed) rather than defaulted.
// The (mode, template_ref) PAIR is validated together: a flat record must not
// carry a template and an overlay record must carry one, so a corrupt or
// inconsistent record cannot drive the flat whole-volume bind through the
// overlay path (or mount an overlay volume without its host overlay).
func validateVolumeMode(volumeMode, templateRef string) error {
	switch volumeMode {
	case "flat":
		if templateRef != "" {
			return fmt.Errorf("volume mode flat carries template_ref %q — refusing an inconsistent mount record", templateRef)
		}
	case "overlay":
		if templateRef == "" {
			return fmt.Errorf("volume mode overlay requires a template_ref — refusing the mount")
		}
	default:
		return fmt.Errorf("volume mode %q is not flat/overlay — refusing the mount", volumeMode)
	}
	return nil
}

// mountedVolumePath returns the volume path recorded as mounted for this VM —
// state.Volumes is the one place that records the mount (a one-entry set by
// the exclusive-ownership invariant: a swap deletes the old entry before a new
// mount is recorded). Returns "" when the map does not hold exactly one entry,
// so an ambiguous record falls back to the warden's mount_active-only check
// instead of asserting a guess. Read under mountMu (Volumes is plain map state
// mutated by concurrent mount/unmount holders).
func (h *Handler) mountedVolumePath(state *VMState) string {
	state.mountMu.Lock()
	defer state.mountMu.Unlock()
	if len(state.Volumes) != 1 {
		return ""
	}
	for p := range state.Volumes {
		return p
	}
	return ""
}

// sanitizeExecOutput makes warden exec output safe for the gRPC response.
// Go strings hold arbitrary bytes, but proto3 string fields must be valid
// UTF-8 — marshaling a string containing raw binary (e.g. a filename with
// non-UTF-8 bytes echoed by ls, or any binary command output) fails the
// whole RPC, and the gateway then misreads that as a mount failure and
// puts the sandfs through a needless cleaning cycle. Mirrors warden's
// from_utf8_lossy: invalid sequences become U+FFFD. Agents needing exact
// binary output use the file API (base64).
func sanitizeExecOutput(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

// handleUnmountRootfs handles the UnmountRootfs command from the gateway.
// The gateway addresses the sandfs by sandfs_id; sandlot resolves it to the VM
// currently holding the mount (binding). Idempotent: if the sandfs is not bound
// to any VM on this node, the unmount succeeds trivially.
func (h *Handler) handleUnmountRootfs(ctx context.Context, cmd *pb.VMCommand, req *pb.UnmountRootfs) *pb.CommandResponse {
	start := time.Now()
	h.debugOp("unmounting rootfs for sandfs %s", req.SandfsId)

	state := h.vmForSandfs(req.SandfsId)
	if state == nil {
		// Not mounted on this node — nothing to unmount. Idempotent success (the
		// sandfs may have already been released, or a migration moved it off).
		return &pb.CommandResponse{
			CommandId: cmd.CommandId,
			Success:   true,
			VmId:      "",
		}
	}

	// Serialize with mount/switch on this VM — Volumes is shared state. Held
	// across the whole warden unmount RPC: the warden's MOUNT_GATE waits for
	// its in-flight execs before cgroup.kill, so this RPC takes as long as the
	// longest running sync exec; new warm execs queue on the mount gate until
	// the mount is gone.
	state.mountMu.Lock()
	defer state.mountMu.Unlock()
	h.ensureMountRecordsLocked(state)

	// The identity MUST belong to THIS sandfs. Using the VM's current mount
	// identity would let a stale binding name the live tenant and tear down
	// the wrong mount. A pending generation is also this sandfs's identity:
	// its mount RPC may still be queued, and the alias is the capability that
	// late mount will present.
	identity := h.bindingAliasLocked(state, req.SandfsId)
	if identity == "" && state.pendingMount != nil && state.pendingMount.sandfsID == req.SandfsId {
		identity = state.pendingMount.alias
	}
	// Generation binding: an unmount that names a different volume than the
	// one this sandfs is currently bound to refers to a SUPERSEDED generation.
	// It must not use the live binding's alias (that would tear down the new
	// tenant). Treat it as an idempotent no-op and leave the live records
	// untouched; the named generation is already gone. An empty path keeps the
	// legacy release behavior for callers that only have the sandfs id.
	if identity != "" && req.VolumePath != "" {
		if boundPath := state.mountPathBySandfs[req.SandfsId]; boundPath != "" && boundPath != req.VolumePath {
			return &pb.CommandResponse{
				CommandId: cmd.CommandId,
				Success:   true,
				VmId:      state.VM.ID,
				Spec:      state.SpecID,
			}
		}
	}
	if identity != "" && req.VolumeEpoch != "" {
		if boundEpoch := state.mountEpochBySandfs[req.SandfsId]; boundEpoch != "" && boundEpoch != req.VolumeEpoch {
			return &pb.CommandResponse{
				CommandId: cmd.CommandId,
				Success:   true,
				VmId:      state.VM.ID,
				Spec:      state.SpecID,
			}
		}
	}
	if identity == "" {
		if len(state.Volumes) > 0 {
			if req.VolumePath != "" && state.mountIdentityPath != "" && req.VolumePath != state.mountIdentityPath {
				// The live mount provably belongs to a different volume: this
				// binding is stale. Drop it without touching the live tenant.
				h.unbindSandfs(req.SandfsId)
				h.forgetBindingIdentityLocked(state, req.SandfsId)
				return &pb.CommandResponse{CommandId: cmd.CommandId, Success: true, VmId: state.VM.ID}
			}
			// We still hold a mount whose identity was never recorded: the
			// guest mount state is unproven. Fail closed (today's semantics).
			h.scheduleDirtyVMDestroy(state, "unmount without a recorded mount identity")
			return &pb.CommandResponse{
				CommandId: cmd.CommandId,
				Success:   false,
				Error:     "unmount refused: no recorded mount identity for this sandfs",
			}
		}
		// Nothing mounted; just drop the binding.
		h.unbindSandfs(req.SandfsId)
		h.forgetBindingIdentityLocked(state, req.SandfsId)
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: true, VmId: state.VM.ID}
	}

	// cleanupState clears local tracking so the gateway can reroute the sandfs
	// and the dirty VM is isolated immediately. We intentionally do NOT clear
	// pendingDestroy here: the failure path sets it true to exclude the VM
	// from reuse during the async destroy window.
	cleanupState := func() {
		_ = setFsAllowedDirs(ctx, state.VM.Client, nil, "")
		// A clear is the deny-all state: no alias rides the request, and the
		// per-sandfs generation records die with the mount.
		state.mountGen.Add(1) // invalidate any in-flight cold RPC's mark
		state.Volumes = make(map[string]struct{})
		state.mountIdentity = ""
		state.mountIdentityPath = ""
		state.pendingMount = nil
		state.mountAliasBySandfs = make(map[string]string)
		state.mountPathBySandfs = make(map[string]string)
		state.mountEpochBySandfs = make(map[string]string)
		h.unbindSandfs(req.SandfsId)
		// Old agent's processes are dead: detach its egress identity too.
		h.revokeBinding(state)
		// unmount's cgroup.kill clears ALL background execs in the guest;
		// reset the sandlot-side counter (and its once-set) so destroyIdleVMs
		// sees the VM as sync-handled (free to destroy immediately) after
		// unmount.
		state.resetBgExecTracking()
	}

	unmountStart := time.Now()
	outcome, _, wardenDurNs, err := h.unmountWithRetry(ctx, state, identity)
	if err != nil {
		// Warden unreachable / unmount failed (EBUSY/D-state). The guest mount
		// state is uncertain, so reusing this VM would stack the next agent's
		// bind mount over the stale one — violating exclusive-ownership. Clean
		// up local state and destroy + reconcile (sandlot-owned; no gateway).
		cleanupState()
		h.scheduleDirtyVMDestroy(state, fmt.Sprintf("warden unmount: %v", err))
		return &pb.CommandResponse{
			CommandId:         cmd.CommandId,
			Success:           false,
			Error:             fmt.Sprintf("warden unmount: %v", err),
			SandlotDurationNs: uint64(time.Since(start).Nanoseconds()),
		}
	}
	h.debugOp("warden unmount /mnt/rootfs took %v", time.Since(unmountStart))

	if outcome == warden.UnmountMismatch {
		// The warden holds a different generation than this sandfs recorded:
		// a stale binding. Tear down NOTHING — the live tenant keeps its
		// mount and filter. Drop only this sandfs's stale records. The
		// gateway's intent ("this sandfs is not here") is satisfied.
		h.unbindSandfs(req.SandfsId)
		h.forgetBindingIdentityLocked(state, req.SandfsId)
		h.logger.Printf("unmount: VM %s holds a different mount generation; dropped stale binding for sandfs %s without teardown", state.VM.ID, req.SandfsId)
		return &pb.CommandResponse{
			CommandId:         cmd.CommandId,
			Success:           true,
			VmId:              state.VM.ID,
			Spec:              state.SpecID,
			SandlotDurationNs: uint64(time.Since(start).Nanoseconds()),
		}
	}

	// REMOVED or NOT_MOUNTED: the guest mount (if any) is gone. Clear
	// allowed_dirs — the VM-level half of the switch (umount → set-fs →
	// bind). A failed clear is FATAL to this VM, not best-effort — with the
	// previous agent's directory still allowed at the VMM filter, reusing the
	// VM stacks the next attach over a share root that still exports the
	// previous tenant (a cross-tenant window if the next set-fs also fails).
	setFsStart := time.Now()
	if err := setFsAllowedDirs(ctx, state.VM.Client, nil, ""); err != nil {
		cleanupState()
		h.scheduleDirtyVMDestroy(state, fmt.Sprintf("set-fs clear allowed_dirs: %v", err))
		return &pb.CommandResponse{
			CommandId:         cmd.CommandId,
			Success:           false,
			Error:             fmt.Sprintf("set-fs clear allowed_dirs: %v", err),
			SandlotDurationNs: uint64(time.Since(start).Nanoseconds()),
		}
	}
	h.debugOp("set-fs clear allowed_dirs took %v", time.Since(setFsStart))

	// Clear ALL tracked volumes — the warden unmount cleared the whole
	// /mnt/rootfs mount.
	state.mountGen.Add(1) // invalidate any in-flight cold RPC's mark
	state.Volumes = make(map[string]struct{})
	state.mountIdentity = ""
	state.mountIdentityPath = ""
	state.pendingMount = nil
	state.mountAliasBySandfs = make(map[string]string)
	state.mountPathBySandfs = make(map[string]string)
	state.mountEpochBySandfs = make(map[string]string)
	h.unbindSandfs(req.SandfsId)
	// Old agent's processes are dead (cgroup.kill inside the warden unmount):
	// detach its egress identity from this attachment.
	h.revokeBinding(state)
	state.resetBgExecTracking()

	// Check deferred destroy: pool scale-down (pendingDestroy) or recycle policy.
	pd := state.pendingDestroy.Load()
	if pd || h.shouldRecycle(state) {
		reason := "recycle policy"
		if pd {
			reason = "pending-destroy (pool scale-down)"
		}
		state.pendingDestroy.Store(true)
		h.logger.Printf("unmount: VM %s marked for %s; destroying instead of returning to CLEAN", state.VM.ID, reason)
		h.metrics.RecordRecycleTrigger()
		go h.destroyAndReplaceVM(state.VM.ID, state.SpecID)
	}

	h.debugOp("unmount-rootfs complete for VM %s in %v", state.VM.ID, time.Since(start))
	return &pb.CommandResponse{
		CommandId:         cmd.CommandId,
		Success:           true,
		VmId:              state.VM.ID,
		Spec:              state.SpecID,
		ExecDurationNs:    wardenDurNs,
		SandlotDurationNs: uint64(time.Since(start).Nanoseconds()),
	}
}

// staleMountUnmountTimeout bounds the best-effort teardown of a mount whose
// record was discarded. The warden's own unmount read timeout is 30s and
// unmountWithRetry may spend it twice (one transport retry); the rest covers
// slot acquisition on a busy VM.
const staleMountUnmountTimeout = 90 * time.Second

// discardUnrecordedMount tears down a guest mount this request established but
// could not record (see markVolumeMounted). Without it a discarded mark left a
// live mount tracked nowhere: the next switch only unmounts what Volumes
// records, so exclusive ownership rested on the warden's cold-mount self-heal
// alone.
//
// The warden's unmount is identity-BOUND: it removes /mnt/rootfs only when the
// live mount carries THIS generation's alias, so a VM that has since switched
// tenants keeps its new mount untouched (mismatch is reported, not forced).
// A transport failure leaves the VM's mount state unproven; the request is
// already failing and the monitor's crash detection owns that VM — destroying
// it here could kill a newer tenant that won the switch.
func (h *Handler) discardUnrecordedMount(state *VMState, identity string) {
	if identity == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), staleMountUnmountTimeout)
	defer cancel()
	outcome, current, _, err := h.unmountWithRetry(ctx, state, identity)
	switch {
	case err != nil:
		h.logger.Printf("WARNING: VM %s: cannot tear down an unrecorded mount from a superseded generation (%v) — the guest mount state is unproven; crash detection owns the VM", state.VM.ID, err)
	case outcome == warden.UnmountMismatch:
		h.logger.Printf("VM %s: discarded an unrecorded mount, but the guest now holds generation %q; leaving the live tenant's mount untouched", state.VM.ID, current)
	default:
		h.debugOp("mount-rootfs: VM %s: tore down the unrecorded mount from a superseded generation (outcome %v)", state.VM.ID, outcome)
	}
}

// unmountWithRetry performs the warden OP_UNMOUNT on a borrowed slot, retrying
// once on a fresh connection after a transport error (unmount is idempotent).
func (h *Handler) unmountWithRetry(ctx context.Context, state *VMState, identity string) (warden.UnmountOutcome, string, uint64, error) {
	agt, done, err := h.acquireWarden(ctx, state)
	if err != nil {
		return warden.UnmountRemoved, "", 0, fmt.Errorf("warden get for unmount: %w", err)
	}
	outcome, current, durNs, uerr := agt.UnmountRootfs(identity)
	broken := isWardenTransportErr(uerr)
	done(broken)
	if !broken {
		return outcome, current, durNs, uerr
	}
	h.logger.Printf("unmount transport error on VM %s: %v; retrying on a fresh connection", state.VM.ID, uerr)
	agt, done, err = h.acquireWarden(ctx, state)
	if err != nil {
		return warden.UnmountRemoved, "", 0, err
	}
	outcome, current, durNs, uerr = agt.UnmountRootfs(identity)
	done(isWardenTransportErr(uerr))
	return outcome, current, durNs, uerr
}

// ensureSwitchReady performs the per-VM mount/switch BOOKKEEPING for a cold
// exec: host overlay mount, swap out any old volume (warden unmount), and the
// virtio-fs allowed_dirs swap — all serialized under mountMu. It does NOT
// establish the in-VM mount and does NOT mark Volumes: the caller issues the
// combined OP_MOUNT_AND_EXEC (mount + real command, ONE vsock RTT) on a
// borrowed slot with NO lock held, and marks Volumes after the RPC succeeds.
//
// Why the lock can be released before the RPC: the in-guest mount mutual
// exclusion and idempotency live in the warden's MOUNT_GATE — a concurrent
// cold request's combined RPC either queues behind this one's mount on the
// write gate (then sees mount_active and skips the redundant mount) or runs
// its own idempotent set-fs; either way the mount part serializes in ~ms and
// BOTH execs then run in parallel under the read gate. Holding mountMu across
// the RPC would instead queue a concurrent cold request behind the first
// request's ENTIRE exec (up to the exec timeout).
//
// Failure semantics are self-healing (same as the pre-parallel design): a
// failed combined RPC leaves Volumes unset, and every future cold attempt
// starts by idempotently unmounting whatever the guest still holds — so a
// "mount succeeded but the response was lost" outcome is cleaned up by the
// next attempt or the lease-expiry unmount, never stacked under.
func (h *Handler) ensureSwitchReady(ctx context.Context, state *VMState, agentID, sandfsID, volumePath, templateRef, volumeMode, volumeEpoch string) (string, int64, bool, error) {
	state.mountMu.Lock()
	defer state.mountMu.Unlock()

	// The sandfs→VM binding is created before this call so concurrent
	// requests converge on one VM. Any refusal below (containment, mode,
	// identity, filter swap) must release it again — otherwise the VM stays
	// bound to a sandfs that was never mounted and is excluded from the pool.
	// A JOINER that refuses must NOT clear it: the binding belongs to the
	// in-flight creator, and dropping it would unbind a mount that is still
	// landing (markVolumeMounted would have to repair the gap).
	established := false
	joined := false
	defer func() {
		if !established && !joined {
			h.unbindSandfs(sandfsID)
		}
	}()

	h.ensureMountRecordsLocked(state)

	// JOIN an in-flight generation for the same sandfs/volume. The alias is
	// per generation and not idempotent: a second set-fs would retire the
	// generation whose mount RPC is still queued, so the duplicate-mount fold
	// the warden performs (same alias → dedupe) would never happen.
	if p := state.pendingMount; p != nil {
		joined = true
		if p.sandfsID == sandfsID && p.volumePath == volumePath &&
			p.agentID == agentID && p.templateRef == templateRef && p.volumeMode == volumeMode && p.volumeEpoch == volumeEpoch {
			established = true
			return p.alias, p.gen, false, nil
		}
		return "", 0, false, fmt.Errorf("another mount generation is in flight for this VM")
	}

	// Containment before anything touches the host: volumePath becomes the
	// MountOverlay source and the virtio-fs allowed_dirs entry below.
	if err := h.checkVolumePathContained(volumePath); err != nil {
		return "", 0, false, err
	}
	// Record-driven mode: the warden mounts by THIS value, so an inconsistent
	// (mode, template_ref) pair is a control-plane bug — refuse before any
	// host mount or filter swap.
	if err := validateVolumeMode(volumeMode, templateRef); err != nil {
		return "", 0, false, err
	}

	// The egress identity contract requires an authenticated agent identity on
	// every mount: without it the attachment could not be attributed.
	if agentID == "" {
		return "", 0, false, fmt.Errorf("agent_id is required for mount")
	}
	// bind the gateway-supplied path to this sandfs against the
	// volume's own on-disk stamp before anything is mounted or exported.
	// Cold path only; cached per (id, path) so re-attaches pay nothing.
	if err := h.verifyVolumeIdentity(ctx, sandfsID, volumePath, volumeEpoch); err != nil {
		return "", 0, false, err
	}
	if _, err := h.vm.MountOverlay(ctx, volumePath, templateRef); err != nil {
		h.unbindSandfs(sandfsID)
		return "", 0, false, fmt.Errorf("overlay mount: %v", err)
	}
	// Swap out any old volume: the warden unmount is identity-bound to the
	// VM's CURRENT generation. An unrecorded identity means the mount state is
	// unproven; the VM must not be reused (fail-closed).
	for oldPath := range state.Volumes {
		h.debugOp("mount-rootfs: swapping out old volume %s", oldPath)
		identity := state.mountIdentity
		if identity == "" {
			h.scheduleDirtyVMDestroy(state, "old-volume unmount without a recorded mount identity")
			return "", 0, false, fmt.Errorf("old-volume mount identity not recorded")
		}
		outcome, _, _, err := h.unmountWithRetry(ctx, state, identity)
		if err != nil {
			h.scheduleDirtyVMDestroy(state, "old-volume unmount failed")
			return "", 0, false, fmt.Errorf("warden unmount old: %v", err)
		}
		if outcome == warden.UnmountMismatch {
			h.scheduleDirtyVMDestroy(state, "old-volume unmount identity mismatch")
			return "", 0, false, fmt.Errorf("old-volume unmount identity mismatch")
		}
		// Old agent's processes are dead (cgroup.kill): detach its identity
		// from this attachment before the new one is published.
		h.revokeBinding(state)
		delete(state.Volumes, oldPath)
		if state.mountIdentityPath == oldPath {
			state.mountIdentity = ""
			state.mountIdentityPath = ""
		}
		state.mountGen.Add(1) // invalidate any in-flight cold RPC's mark
	}

	alias, aerr := newMountAlias()
	if aerr != nil {
		return "", 0, false, aerr
	}
	gen := state.mountGen.Load()
	state.pendingMount = &pendingMount{sandfsID: sandfsID, volumePath: volumePath, alias: alias, gen: gen, agentID: agentID, templateRef: templateRef, volumeMode: volumeMode, volumeEpoch: volumeEpoch}

	setFsStart := time.Now()
	if err := setFsAllowedDirs(ctx, state.VM.Client, []string{volumePath}, alias); err != nil {
		// a failed filter swap leaves the VMM's exported set
		// uncertain — the queued event may still apply late. Never reuse this
		// VM; destroy it, exactly like the unmount clear path.
		state.pendingMount = nil
		h.scheduleDirtyVMDestroy(state, "set-fs allowed_dirs failed: filter state uncertain")
		return "", 0, false, fmt.Errorf("set-fs allowed_dirs: %v", err)
	}
	h.debugOp("mount-rootfs: set-fs allowed_dirs=[%s] alias=%s took %v", volumePath, alias, time.Since(setFsStart))
	// Publish the egress identity BEFORE the caller dispatches the combined
	// mount+exec RPC — guest processes (and therefore guest traffic) cannot
	// exist until that RPC's exec runs, so a mount's first flow always finds
	// its identity already published (constructive ordering, no time window).
	h.publishBindingLocked(state, agentID, sandfsID)
	state.mountAliasBySandfs[sandfsID] = alias
	state.mountPathBySandfs[sandfsID] = volumePath
	established = true
	return alias, gen, true, nil
}

// mountMark is markVolumeMounted's verdict.
type mountMark int

const (
	// mountMarked: the mount was recorded; the warm path may serve it.
	mountMarked mountMark = iota
	// mountMarkUnrecorded: the mount could NOT be recorded (the generation was
	// superseded, this sandfs's binding was replaced, or another VM won the
	// binding). Its guest mount may still be live, so the caller must tear it
	// down explicitly — see discardUnrecordedMount.
	mountMarkUnrecorded
	// mountMarkDirtyDestroy: the mount WAS recorded, but the VM is now
	// scheduled for destruction (the distinct-agent budget was reached). There
	// is nothing unrecorded to tear down; the destroy kills the guest.
	mountMarkDirtyDestroy
)

// markVolumeMounted records a successfully-established mount — unless the VM
// was unmounted/switched while the combined RPC was in flight (mountGen
// changed under us), in which case the result must NOT be recorded: the guest
// mount is gone or about to be replaced, and a stale entry would poison the
// warm path.
func (h *Handler) markVolumeMounted(state *VMState, sandfsID, volumePath, identity, volumeEpoch, agentID string, gen int64) mountMark {
	state.mountMu.Lock()
	defer state.mountMu.Unlock()
	h.ensureMountRecordsLocked(state)
	// The cold path pre-created this sandfs's binding (alias) before dispatch.
	// Capture it before the unbind below overrides the generation: a mark that
	// does not match its own binding is bookkeeping from a superseded attempt
	// and must not resurrect a mount.
	boundAlias := state.mountAliasBySandfs[sandfsID]
	h.forgetBindingIdentityLocked(state, sandfsID)
	if state.mountGen.Load() != gen {
		h.debugOp("mount-rootfs: VM %s unmounted/switched during cold exec; discarding stale mount result for %s", state.VM.ID, volumePath)
		return mountMarkUnrecorded
	}
	if boundAlias != identity {
		h.debugOp("mount-rootfs: VM %s has no binding for sandfs %s with generation %s; discarding unbound mount result", state.VM.ID, sandfsID, identity)
		return mountMarkUnrecorded
	}
	// Re-establish the handler-level binding if a concurrent joiner failure
	// dropped it: the guest mount is live, so an unbound VM would be handed to
	// another sandfs (double mount). If another VM now owns the binding this
	// mount lost that race; do not record it. The store's sandfs shard makes
	// the check-and-set atomic without the global mutex.
	if !h.bindings.rebindIfOwnerOrFree(sandfsID, state.VM.ID) {
		cur, _ := h.bindings.lookup(sandfsID)
		h.debugOp("mount-rootfs: VM %s lost the binding for sandfs %s to %s; discarding mount result", state.VM.ID, sandfsID, cur)
		return mountMarkUnrecorded
	}
	h.recordAffinityLocked(sandfsID, state.VM.ID)
	state.Volumes[volumePath] = struct{}{}
	state.mountIdentity = identity
	state.mountIdentityPath = volumePath
	state.mountAliasBySandfs[sandfsID] = identity
	state.mountPathBySandfs[sandfsID] = volumePath
	state.mountEpochBySandfs[sandfsID] = volumeEpoch
	state.pendingMount = nil
	// One increment per mount GENERATION; joiners report the same gen.
	if state.mountCountedGen != gen {
		state.mountCountedGen = gen
		state.mountCount.Add(1)
	}
	agentAdded := false
	// The set exists solely to enforce the distinct-agent lifetime cap. With
	// the cap disabled (limit <= 0) tracking it would grow without bound and
	// kick the state flusher on every new tenant, for a policy that never
	// reads the set — a many-tenant host with the cap off would rewrite an
	// ever-larger state.json per VM every coalesce window.
	if agentID != "" {
		if limit := h.maxDistinctAgents.Load(); limit > 0 {
			if state.distinctAgents == nil {
				state.distinctAgents = make(map[string]struct{})
			}
			if _, ok := state.distinctAgents[agentID]; !ok {
				if int64(len(state.distinctAgents)) >= limit {
					// The mount is live but must not serve a new agent beyond the
					// budget: destroy this VM and let the pool replace it. This is
					// a policy recycle (not a failure), so it counts in the same
					// metric /stats projects as the unmount-path recycles.
					if h.scheduleDirtyVMDestroy(state, "distinct-agent cap reached during mount") && h.metrics != nil {
						h.metrics.RecordRecycleTrigger()
					}
					return mountMarkDirtyDestroy
				}
				state.distinctAgents[agentID] = struct{}{}
				agentAdded = true
			}
		}
	}
	// Reuse accounting is flushed by the single state.json writer
	// (state_flush.go): an O(1) dirty mark here instead of a goroutine and an
	// event-time snapshot — the flusher reads the LATEST counters at drain
	// time, so concurrent mounts on this VM coalesce instead of racing
	// last-write-wins. A NEW agent kicks the flusher: the distinct-agent cap
	// is only enforced across restarts by what state.json remembers, so that
	// one change must not wait out the tick interval.
	h.markStateDirty(state, agentAdded)
	return mountMarked
}

// ensureMounted is the FileOp cold path: bring /mnt/rootfs to "volumePath
// mounted" WITHOUT executing anything (file ops have no command to fold into
// the mount RPC). The in-VM mount is established via OP_MOUNT_AND_EXEC with an
// EMPTY command — the warden mounts and skips the exec entirely (mount-only
// fast path; it used to run `/bin/sh -c true` as a placeholder, paying a full
// spawn+wait+group-kill cycle whose output nobody reads). The warden's
// MOUNT_GATE makes a raced duplicate skip the redundant mount. Warm path:
// no-op.
func (h *Handler) ensureMounted(ctx context.Context, state *VMState, agentID, sandfsID, volumePath, templateRef, volumeMode, volumeEpoch string) error {
	state.mountMu.Lock()
	defer state.mountMu.Unlock()

	// Release the pre-created binding on every refusal (see
	// ensureSwitchReady); the warm path marks it established immediately.
	// A joiner refusing must not clear the creator's binding.
	established := false
	joined := false
	defer func() {
		if !established && !joined {
			h.unbindSandfs(sandfsID)
		}
	}()

	h.ensureMountRecordsLocked(state)

	// Containment first (see ensureSwitchReady): same mount source and
	// allowed_dirs sink on this path.
	if err := h.checkVolumePathContained(volumePath); err != nil {
		return err
	}
	// Same record-driven mode contract as the exec cold path.
	if err := validateVolumeMode(volumeMode, templateRef); err != nil {
		return err
	}

	if _, ok := state.Volumes[volumePath]; ok {
		established = true // warm path: identity already published with the mount
		return nil
	}

	// Join an in-flight generation for the same sandfs/volume (the exec cold
	// path may have released mountMu with its mount RPC still queued). The
	// duplicate-mount fold in the warden requires the same alias, and the
	// generation identity is the full five-field tuple — joining a different
	// agent's/template's generation would attach this request to the wrong
	// volume.
	alias := ""
	gen := state.mountGen.Load()
	if p := state.pendingMount; p != nil {
		joined = true
		if p.sandfsID == sandfsID && p.volumePath == volumePath &&
			p.agentID == agentID && p.templateRef == templateRef && p.volumeMode == volumeMode && p.volumeEpoch == volumeEpoch {
			alias, gen = p.alias, p.gen
		} else {
			return fmt.Errorf("another mount generation is in flight for this VM")
		}
	} else {
		// Same contract as ensureSwitchReady: cold mounts carry an agent identity.
		if agentID == "" {
			return fmt.Errorf("agent_id is required for mount")
		}
		// same on-disk identity binding as the exec cold path.
		if err := h.verifyVolumeIdentity(ctx, sandfsID, volumePath, volumeEpoch); err != nil {
			return err
		}
		if _, err := h.vm.MountOverlay(ctx, volumePath, templateRef); err != nil {
			h.unbindSandfs(sandfsID)
			return fmt.Errorf("overlay mount: %v", err)
		}
		// Swap out any old volume (same identity-bound bookkeeping as
		// ensureSwitchReady).
		for oldPath := range state.Volumes {
			h.debugOp("file_op: swapping out old volume %s", oldPath)
			identity := state.mountIdentity
			if identity == "" {
				h.scheduleDirtyVMDestroy(state, "file_op old-volume unmount without a recorded mount identity")
				return fmt.Errorf("old-volume mount identity not recorded")
			}
			outcome, _, _, err := h.unmountWithRetry(ctx, state, identity)
			if err != nil {
				h.scheduleDirtyVMDestroy(state, "old-volume unmount failed")
				return fmt.Errorf("warden unmount old: %v", err)
			}
			if outcome == warden.UnmountMismatch {
				h.scheduleDirtyVMDestroy(state, "file_op old-volume unmount identity mismatch")
				return fmt.Errorf("old-volume unmount identity mismatch")
			}
			h.revokeBinding(state)
			delete(state.Volumes, oldPath)
			if state.mountIdentityPath == oldPath {
				state.mountIdentity = ""
				state.mountIdentityPath = ""
			}
			state.mountGen.Add(1) // invalidate any in-flight cold RPC's mark
		}
		var aerr error
		alias, aerr = newMountAlias()
		if aerr != nil {
			return aerr
		}
		gen = state.mountGen.Load()
		state.pendingMount = &pendingMount{sandfsID: sandfsID, volumePath: volumePath, alias: alias, gen: gen, agentID: agentID, templateRef: templateRef, volumeMode: volumeMode, volumeEpoch: volumeEpoch}
		setFsStart := time.Now()
		if err := setFsAllowedDirs(ctx, state.VM.Client, []string{volumePath}, alias); err != nil {
			// same fail-closed rule as ensureSwitchReady — the VMM's
			// exported set is uncertain, so the VM must not be reused.
			state.pendingMount = nil
			h.scheduleDirtyVMDestroy(state, "file_op set-fs allowed_dirs failed: filter state uncertain")
			return fmt.Errorf("set-fs allowed_dirs: %v", err)
		}
		h.debugOp("file_op: set-fs allowed_dirs=[%s] alias=%s took %v", volumePath, alias, time.Since(setFsStart))
	}

	// Publish before the warden RPC: the placeholder exec inside it creates
	// the first guest processes of this mount.
	h.publishBindingLocked(state, agentID, sandfsID)

	agt, done, err := h.acquireWarden(ctx, state)
	if err != nil {
		return fmt.Errorf("warden get for mount: %v", err)
	}
	mounted, merr := agt.MountOnly(alias, "/mnt/rootfs", volumeMode)
	transport := isWardenTransportErr(merr)
	done(transport)
	if merr != nil {
		state.pendingMount = nil
		if errors.Is(merr, warden.ErrMountTargetNotExported) {
			// The set-fs succeeded but the filter does not export the alias:
			// a generation/filter anomaly while we still hold the lock. The
			// mount state is unproven — fail closed.
			h.scheduleDirtyVMDestroy(state, "mount-only alias not exported after this generation's set-fs")
			return fmt.Errorf("warden mount: %v", merr)
		}
		// the mount RPC failed after the mount was dispatched. The
		// guest mount state is unproven (a lost reply, or a partial mount
		// stack on the warden's failure path), Volumes was never set, and the
		// binding was dropped — the cleanup chain cannot reach this VM.
		// Destroy + replace rather than leave an untracked guest mount.
		h.scheduleDirtyVMDestroy(state, "mount-only failed: guest mount state unproven")
		return fmt.Errorf("warden mount: %v", merr)
	}
	if verr := h.mountedVolumeMatches(state, volumePath, alias, mounted, gen); verr != nil {
		return verr
	}
	state.Volumes[volumePath] = struct{}{}
	state.mountIdentity = alias
	state.mountIdentityPath = volumePath
	state.mountAliasBySandfs[sandfsID] = alias
	state.mountPathBySandfs[sandfsID] = volumePath
	state.pendingMount = nil
	established = true
	return nil
}

// clearPendingMount drops the in-flight generation record for this request.
// Called when the mount RPC failed: leaving it would make the next request
// join a dead generation and skip its own set-fs.
func (h *Handler) clearPendingMount(state *VMState, sandfsID, alias string) {
	state.mountMu.Lock()
	defer state.mountMu.Unlock()
	if p := state.pendingMount; p != nil && p.sandfsID == sandfsID && p.alias == alias {
		state.pendingMount = nil
	}
}

// scheduleDirtyVMDestroy marks a VM whose guest mount state is uncertain
// (warden unmount failed with EBUSY / D-state, or the warden is unreachable)
// as pending-destroy and asynchronously destroys it + reconciles spec capacity.
// The exclusive-ownership invariant forbids reusing such a VM: a stale
// /mnt/rootfs mount could stack under the next agent's bind mount, letting two
// SandFS's processes coexist in the same VM. pendingDestroy=true excludes the
// VM from resolveVMForMount and the heartbeat clean-count during the async
// destroy window; destroyAndReplaceVM then kills the KVM process (all guest
// processes incl. D-state die) and recreates a replacement if spec current <
// target. Async because destroyVMByID acquires state.execMu, which all callers
// hold. sandlot-owned - the gateway is not involved (delegated VM lifecycle).
// It returns true only for the caller that actually scheduled the destroy, so
// a policy trigger (the distinct-agent cap) can record exactly one recycle in
// the node metrics even when concurrent mounts race the same cap.
func (h *Handler) scheduleDirtyVMDestroy(state *VMState, reason string) bool {
	// Once-guard: two teardown paths can independently declare the same VM
	// dirty (restart-resumed redialWarden racing ResetSurvivorsToClean). Only
	// the first schedules the destroy-and-replace; the second is a no-op.
	if !state.dirtyDestroyScheduled.CompareAndSwap(false, true) {
		h.logger.Printf("dirty VM %s (%s); destroy already scheduled, skipping duplicate", state.VM.ID, reason)
		return false
	}
	state.pendingDestroy.Store(true)
	vmID := state.VM.ID
	specID := state.SpecID
	h.logger.Printf("dirty VM %s (%s); destroying + reconciling spec %q", vmID, reason, specID)
	go h.destroyAndReplaceVM(vmID, specID)
	return true
}

// handleMountRootfsAndExecute is the attach+execute path. It is idempotent:
// if the requested agent directory is already mounted at /mnt/rootfs (warm/
// lease case), it skips straight to OP_EXEC. On the cold path it keeps the
// original ONE-RTT combined mount_and_exec (mount + real command in a single
// vsock call) — but on a borrowed pool slot with NO per-VM lock held during
// the exec wait: the mount/switch bookkeeping is serialized under mountMu by
// ensureSwitchReady, and the in-guest mount mutual exclusion + duplicate-mount
// dedup live in the warden's MOUNT_GATE. Concurrent cold requests therefore
// each issue their own combined RPC, the warden folds their mount parts into
// one, and all the execs run in parallel (bounded by the spec's exec_slots).
//
// Cross-agent reuse of the same VM: if /mnt/rootfs currently holds a different
// agent's volume, unmount it first (the lease-expiry async detach usually
// already did this, but we guard the narrow window where it hasn't).
func (h *Handler) handleMountRootfsAndExecute(ctx context.Context, cmd *pb.VMCommand, req *pb.MountRootfsAndExecute) *pb.CommandResponse {
	start := time.Now()
	// Metrics: count every exec (sync + bg) for duty/exec-rate; the duration is
	// the handler time (a proxy for the command's VM hold time).
	h.metrics.ExecStart(start)
	defer func() { h.metrics.ExecComplete(time.Since(start)) }()

	// A mount/exec without a volume path has no identity to assert to the
	// warden: the warm lookup would key on "", and the warden's identity
	// check would see an empty field. Refuse before selecting or binding a
	// VM — cold commands already fail containment, but the warm path's map
	// lookup must never be reachable with an empty key.
	if req.VolumePath == "" {
		return &pb.CommandResponse{
			CommandId: cmd.CommandId,
			Success:   false,
			Error:     "volume_path is required for mount/exec (empty mounted-volume identity refused)",
		}
	}

	// Resolve the sandfs to a VM: reuse the bound VM if warm, else pick a CLEAN
	// spec-satisfying VM and bind it (invariant B: one sandfs -> one VM).
	state := h.resolveVMForMount(req.SandfsId, req.MinSpec, cmd.GetAgentId())
	if state == nil {
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "no available VM on node", ErrorCode: "NO_AVAILABLE_VM"}
	}

	timeout := time.Duration(req.GetTimeoutMs()) * time.Millisecond

	// Warm/cold decision, read under mountMu (Volumes is a plain map mutated
	// by concurrent mount/unmount holders — a lock-free read would be a data
	// race). The verdict can still go stale right after the unlock, and both
	// directions are safe: a stale "cold" re-runs the idempotent switch
	// bookkeeping and the warden dedups the mount; a stale "warm" is caught by
	// the warden's mount_active check (CODE_TRANSPORT_ERROR ⇒ the gateway
	// retries) rather than executing against a torn-down chroot.
	state.mountMu.Lock()
	_, warm := state.Volumes[req.VolumePath]
	// The generation this request acts on. Together with the sandfs binding
	// it decides whether a later failure may dirty-destroy the VM: a request
	// whose generation has been superseded fails itself instead (see
	// mountSuperseded).
	decisionGen := state.mountGen.Load()
	state.mountMu.Unlock()

	// Background exec: return immediately with exec_id + status=running. The
	// agent polls via StatusExec.
	if req.GetBackground() {
		if warm {
			agt, done, err := h.acquireWarden(ctx, state)
			if err != nil {
				return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden get: %v", err)}
			}
			// The warm verdict came from state.Volumes[req.VolumePath]; the
			// identity asserted to the warden is derived from that same
			// volume path (the caller's belief — never an arbitrary map key:
			// if the record ever held two entries, the caller's own path must
			// still be what the warden checks the mount against).
			mountedID := h.mountIdentityFor(state, req.VolumePath)
			if mountedID == "" {
				// Release the borrowed slot first: this branch used to return
				// without calling done, leaking one exec slot per occurrence.
				done(false)
				if h.mountSuperseded(state, req.SandfsId, decisionGen) {
					return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount generation superseded — retry"}
				}
				h.scheduleDirtyVMDestroy(state, "warm async op without a recorded mount identity")
				return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount identity not recorded — retry"}
			}
			execID, aerr := agt.AsyncExec(req.Command, req.InstallPackages, mountedID)
			done(isWardenTransportErr(aerr))
			if aerr != nil {
				return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden async_exec: %v", aerr)}
			}
			state.activeBgExecs.Add(1) // track for sync/async destroy preference
			state.useCount.Add(1)      // one command served (recycle accounting)
			h.debugOp("mount-rootfs: warm async_exec exec_id=%s", execID)
			return &pb.CommandResponse{
				CommandId: cmd.CommandId,
				Success:   true,
				VmId:      state.VM.ID,
				Spec:      state.SpecID,
				ExecId:    execID,
				Status:    "running",
			}
		}
		// Cold: ONE-RTT mount + async_exec combined RPC on a borrowed slot.
		alias, mountGen, created, err := h.ensureSwitchReady(ctx, state, cmd.GetAgentId(), req.SandfsId, req.VolumePath, req.TemplateRef, req.VolumeMode, req.GetVolumeEpoch())
		if err != nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: err.Error()}
		}
		agt, done, err := h.acquireWarden(ctx, state)
		if err != nil {
			// Only the request that CREATED this generation may clear it and
			// release the binding; a joiner must not unbind the creator's live
			// mount.
			if created {
				h.clearPendingMount(state, req.SandfsId, alias)
				h.unbindSandfs(req.SandfsId)
			}
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden get: %v", err)}
		}
		execID, mountedB, aerr := agt.MountAndAsyncExec(alias, "/mnt/rootfs", req.Command, req.InstallPackages, req.VolumeMode)
		transport := isWardenTransportErr(aerr)
		done(transport)
		if errors.Is(aerr, warden.ErrMountTargetNotExported) {
			h.clearPendingMount(state, req.SandfsId, alias)
			// Keep the superseded verdict from BEFORE the unbind: unbind
			// deletes this sandfs's binding, after which vmForSandfs always
			// answers nil and the fail-closed destroy below could never run
			// (a stale request would leave the VM reusable, fail-open).
			superseded := h.mountSuperseded(state, req.SandfsId, mountGen)
			h.unbindSandfs(req.SandfsId)
			if superseded {
				// This request was superseded while its mount was queued. The
				// VM may now serve another tenant: fail this request only.
				return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount generation superseded — retry"}
			}
			h.scheduleDirtyVMDestroy(state, "mount_and_async_exec alias not exported after this generation's set-fs")
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount target not exported in the current generation"}
		}
		if aerr != nil {
			h.clearPendingMount(state, req.SandfsId, alias)
			if h.mountSuperseded(state, req.SandfsId, mountGen) {
				// Superseded while the RPC was in flight: the switch chain
				// owns the teardown, and the VM may already serve another
				// tenant. Fail this request only — never destroy or unbind.
				return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount generation superseded — retry"}
			}
			// the combined mount RPC failed after being dispatched. The
			// guest mount state is unproven (lost reply or a partial mount),
			// the binding is dropped and Volumes was never set, so cleanup
			// cannot reach this VM — destroy it instead of leaking an
			// untracked mount that could be double-placed.
			h.scheduleDirtyVMDestroy(state, "mount_and_async_exec failed: guest mount state unproven")
			h.unbindSandfs(req.SandfsId)
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden mount_and_async_exec: %v", aerr)}
		}
		if verr := h.mountedVolumeMatches(state, req.VolumePath, alias, mountedB, mountGen); verr != nil {
			// The exec started against a volume that is NOT this sandfs's —
			// its exec_id is moot. The VM is already marked dirty-destroy.
			h.unbindSandfs(req.SandfsId)
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: verr.Error()}
		}
		switch h.markVolumeMounted(state, req.SandfsId, req.VolumePath, alias, req.GetVolumeEpoch(), cmd.GetAgentId(), mountGen) {
		case mountMarkUnrecorded:
			// The result was discarded: the guest mount may still be live, so
			// tear down THIS generation explicitly (identity-bound; a VM that
			// already switched tenants keeps its new mount).
			h.discardUnrecordedMount(state, alias)
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "sandfs released during cold exec"}
		case mountMarkDirtyDestroy:
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "sandfs released during cold exec"}
		}
		state.activeBgExecs.Add(1) // track for sync/async destroy preference
		state.useCount.Add(1)      // one command served (recycle accounting)
		h.debugOp("mount-rootfs: cold mount_and_async_exec exec_id=%s", execID)
		return &pb.CommandResponse{
			CommandId: cmd.CommandId,
			Success:   true,
			VmId:      state.VM.ID,
			Spec:      state.SpecID,
			ExecId:    execID,
			Status:    "running",
		}
	}

	// Sync exec on a borrowed slot. Parallel execs each take their own slot
	// (up to execSlots in flight); requests beyond the pool size queue FIFO
	// on the pool — the same observable semantics as the old per-VM execMu,
	// but with execSlots-way concurrency. Cold bookkeeping runs BEFORE the
	// slot borrow: ensureSwitchReady itself borrows slots (old-volume
	// unmount), so holding one across it would self-deadlock a 1-slot pool.
	var alias string
	var mountGen int64
	var created bool
	if !warm {
		var serr error
		alias, mountGen, created, serr = h.ensureSwitchReady(ctx, state, cmd.GetAgentId(), req.SandfsId, req.VolumePath, req.TemplateRef, req.VolumeMode, req.GetVolumeEpoch())
		if serr != nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: serr.Error()}
		}
	}
	agt, done, err := h.acquireWarden(ctx, state)
	if err != nil {
		if !warm && created {
			h.clearPendingMount(state, req.SandfsId, alias)
			h.unbindSandfs(req.SandfsId)
		}
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden get: %v", err)}
	}

	if warm {
		// Same identity rule as the warm async path: the volume path the warm
		// verdict matched is what the warden must confirm is mounted.
		mountedID := h.mountIdentityFor(state, req.VolumePath)
		if mountedID == "" {
			done(false)
			if h.mountSuperseded(state, req.SandfsId, decisionGen) {
				return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount generation superseded — retry"}
			}
			h.scheduleDirtyVMDestroy(state, "warm exec without a recorded mount identity")
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount identity not recorded — retry"}
		}
		stdout, stderr, exitCode, status, execDurationNs, xerr := agt.ExecWorkspace(req.Command, timeout, req.InstallPackages, mountedID)
		done(isWardenTransportErr(xerr))
		if xerr != nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden exec: %v", xerr)}
		}
		sandlotDurationNs := uint64(time.Since(start).Nanoseconds())
		h.debugOp("mount-rootfs: warm exec took %v (exit=%d status=%s)", time.Since(start), exitCode, status)
		state.useCount.Add(1) // one command served (recycle accounting; see VMState.useCount)
		return &pb.CommandResponse{
			CommandId:         cmd.CommandId,
			Success:           true,
			VmId:              state.VM.ID,
			Spec:              state.SpecID,
			Stdout:            sanitizeExecOutput(stdout),
			Stderr:            sanitizeExecOutput(stderr),
			ExitCode:          int32(exitCode),
			Status:            status,
			ExecDurationNs:    execDurationNs,
			SandlotDurationNs: sandlotDurationNs,
		}
	}

	// Cold: ONE-RTT mount + exec combined RPC — no lock held across the exec
	// wait (see ensureSwitchReady for the locking rationale).
	stdout, stderr, exitCode, status, execDurationNs, mountedB, xerr := agt.MountAndExec(alias, "/mnt/rootfs", req.Command, timeout, req.InstallPackages, req.VolumeMode)
	transport := isWardenTransportErr(xerr)
	done(transport)
	if errors.Is(xerr, warden.ErrMountTargetNotExported) {
		h.clearPendingMount(state, req.SandfsId, alias)
		// Superseded verdict BEFORE the unbind — see the async twin above:
		// unbinding first made the fail-closed destroy unreachable.
		superseded := h.mountSuperseded(state, req.SandfsId, mountGen)
		h.unbindSandfs(req.SandfsId)
		if superseded {
			// Superseded while the mount RPC was queued: the VM may now serve
			// another tenant. Fail this request only — never destroy it.
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount generation superseded — retry"}
		}
		h.scheduleDirtyVMDestroy(state, "mount_and_exec alias not exported after this generation's set-fs")
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount target not exported in the current generation"}
	}
	if xerr != nil {
		h.clearPendingMount(state, req.SandfsId, alias)
		if h.mountSuperseded(state, req.SandfsId, mountGen) {
			// Superseded while the RPC was in flight: the switch chain owns
			// the teardown, and the VM may already serve another tenant.
			// Fail this request only — never destroy or unbind.
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "mount generation superseded — retry"}
		}
		// the combined mount RPC failed after being dispatched. The
		// guest mount state is unproven (lost reply or a partial mount stack),
		// Volumes was never set and the binding is dropped, so the gateway's
		// cleanup cannot reach the VM — destroy it rather than leave an
		// untracked mount.
		h.scheduleDirtyVMDestroy(state, "mount_and_exec failed: guest mount state unproven")
		h.unbindSandfs(req.SandfsId)
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden mount_and_exec: %v", xerr)}
	}
	if verr := h.mountedVolumeMatches(state, req.VolumePath, alias, mountedB, mountGen); verr != nil {
		// The exec ran against a volume that is NOT this sandfs's — its
		// output is moot. The VM is already marked dirty-destroy.
		h.unbindSandfs(req.SandfsId)
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: verr.Error()}
	}
	switch h.markVolumeMounted(state, req.SandfsId, req.VolumePath, alias, req.GetVolumeEpoch(), cmd.GetAgentId(), mountGen) {
	case mountMarkUnrecorded:
		// The VM was unmounted/switched while this RPC ran — the exec result
		// is moot. The guest mount may still be live: tear THIS generation
		// down explicitly (identity-bound) before surfacing the failure.
		h.discardUnrecordedMount(state, alias)
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "sandfs released during cold exec"}
	case mountMarkDirtyDestroy:
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "sandfs released during cold exec"}
	}
	sandlotDurationNs := uint64(time.Since(start).Nanoseconds())
	h.debugOp("mount-rootfs: cold mount_and_exec took %v (exit=%d status=%s)", time.Since(start), exitCode, status)
	state.useCount.Add(1) // one command served (recycle accounting; see VMState.useCount)
	return &pb.CommandResponse{
		CommandId:         cmd.CommandId,
		Success:           true,
		VmId:              state.VM.ID,
		Spec:              state.SpecID,
		Stdout:            sanitizeExecOutput(stdout),
		Stderr:            sanitizeExecOutput(stderr),
		ExitCode:          int32(exitCode),
		Status:            status,
		ExecDurationNs:    execDurationNs,
		SandlotDurationNs: sandlotDurationNs,
	}
}

// handleStatusExec polls a background exec's liveness + log tail. The warden
// call runs on a borrowed pool slot: one in-flight request per slot, so no
// frame interleaving with concurrent execs is possible.
func (h *Handler) handleStatusExec(ctx context.Context, cmd *pb.VMCommand, req *pb.StatusExec) *pb.CommandResponse {
	state := h.vmForSandfs(req.SandfsId)
	if state == nil {
		// SandFS not mounted on this node — its bg execs are gone (unmounted).
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: true, Status: "not_found"}
	}
	agt, done, err := h.acquireWarden(ctx, state)
	if err != nil {
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden get: %v", err)}
	}
	logTail, status, exitCode, serr := agt.StatusExec(req.ExecId)
	broken := isWardenTransportErr(serr)
	done(broken)
	if broken {
		// StatusExec is idempotent — retry on transport error with a fresh slot.
		h.logger.Printf("status_exec transport error on VM %s: %v; retrying", state.VM.ID, serr)
		agt, done, err = h.acquireWarden(ctx, state)
		if err != nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden get: %v", err)}
		}
		logTail, status, exitCode, serr = agt.StatusExec(req.ExecId)
		done(isWardenTransportErr(serr))
	}
	if serr != nil {
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden status_exec: %v", serr)}
	}
	// If the background exec is no longer running, decrement the active count —
	// ONCE per exec (the warden answers every later poll of a finished exec
	// with done/killed again; countBgDoneOnce is what keeps repeats from eating
	// a sibling exec's count). CAS-guarded against underflow regardless.
	if (status == "done" || status == "killed") && state.countBgDoneOnce(req.ExecId) {
		for {
			v := state.activeBgExecs.Load()
			if v <= 0 {
				break
			}
			if state.activeBgExecs.CompareAndSwap(v, v-1) {
				break
			}
		}
	}
	return &pb.CommandResponse{
		CommandId: cmd.CommandId,
		Success:   true,
		VmId:      state.VM.ID,
		Spec:      state.SpecID,
		ExecId:    req.ExecId,
		Status:    status,
		Stdout:    sanitizeExecOutput(logTail),
		ExitCode:  int32(exitCode),
	}
}

// handleKillExec kills a background exec by exec_id. The warden call runs on
// a borrowed pool slot (see handleStatusExec).
func (h *Handler) handleKillExec(ctx context.Context, cmd *pb.VMCommand, req *pb.KillExec) *pb.CommandResponse {
	state := h.vmForSandfs(req.SandfsId)
	if state == nil {
		// Sandfs not mounted on this node — nothing to kill. Idempotent, but
		// reported truthfully as not_found: "killed" claimed a kill
		// that never happened.
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: true, Status: "not_found"}
	}
	agt, done, err := h.acquireWarden(ctx, state)
	if err != nil {
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden get: %v", err)}
	}
	kerr := agt.KillExec(req.ExecId)
	broken := isWardenTransportErr(kerr)
	done(broken)
	if broken {
		// KillExec is idempotent — retry on transport error with a fresh slot.
		h.logger.Printf("kill_exec transport error on VM %s: %v; retrying", state.VM.ID, kerr)
		agt, done, err = h.acquireWarden(ctx, state)
		if err != nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden get: %v", err)}
		}
		kerr = agt.KillExec(req.ExecId)
		done(isWardenTransportErr(kerr))
	}
	if errors.Is(kerr, warden.ErrBgExecNotFound) {
		// no such exec in the warden's registry — idempotent success,
		// distinctly reported (was: the response CODE was discarded by the
		// client, so this path reported "killed").
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: true, Status: "not_found"}
	}
	if kerr != nil {
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden kill_exec: %v", kerr)}
	}
	// The kill succeeded: adjust the active-background-exec count (CAS-guarded
	// against underflow). Only counted gone after a confirmed kill — a failed
	// KillExec leaves the exec running and the count intact, so the
	// pool-recycle path never destroys a VM with live background work. The
	// once-set dedups against the StatusExec poll that later reports the same
	// exec as "killed" (the warden keeps the entry until unmount).
	if state.countBgDoneOnce(req.ExecId) {
		for {
			v := state.activeBgExecs.Load()
			if v <= 0 {
				break
			}
			if state.activeBgExecs.CompareAndSwap(v, v-1) {
				break
			}
		}
	}
	return &pb.CommandResponse{
		CommandId: cmd.CommandId,
		Success:   true,
		VmId:      state.VM.ID,
		Spec:      state.SpecID,
		ExecId:    req.ExecId,
		Status:    "killed",
	}
}

// maxFileOpDataBytes is the single-op FileOp payload bound; the
// chain-floor constant, shrunk only by tests.
var maxFileOpDataBytes = commonconfig.MaxFileOpPayload(commonconfig.MinFileOpChainBytes)

// fileOpRetryIdempotent reports whether a file op may be replayed after a
// transport error without duplicating an effect (see handleFileOp). The warden
// expresses append as offset -1 (O_APPEND), which is the one write shape a
// replay must never repeat; the mutating directory ops are excluded so a
// replay's EEXIST/ENOENT cannot masquerade as the operation's outcome.
func fileOpRetryIdempotent(subOp byte, offset int64) bool {
	switch subOp {
	case warden.SubOpRead, warden.SubOpStat, warden.SubOpListDir:
		return true
	case warden.SubOpWrite:
		return offset != -1
	default:
		return false
	}
}

// handleFileOp handles the FileOp command from the gateway.
// This is the unified entry point for all file I/O operations: a single handler
// with one mount check covers all 7 sub-operations (read, write, stat, list_dir,
// mkdir, remove, rename). The warden's OP_FILE dispatch resolves the sub-opcode.
//
// If volume_path is set and the rootfs is not yet mounted, this handler mounts
// the rootfs first (same logic as handleMountRootfsAndExecute) and then performs
// the file op — combining mount + file op in one gRPC round-trip. If the rootfs
// is already mounted with the same volume_path, the mount is skipped (warm path).
func (h *Handler) handleFileOp(ctx context.Context, cmd *pb.VMCommand, req *pb.FileOp) *pb.CommandResponse {
	// Defense-in-depth wire gate (mirrors the gateway handler): an
	// oversized Data/Length would breach the gRPC message limit on the
	// RESPONSE leg (payload + envelope) after already being received — the
	// gateway gate prevents the send, this one prevents the effect for any
	// other caller. Named refusal, no VM touched.
	if n := len(req.Data); n > maxFileOpDataBytes {
		return &pb.CommandResponse{
			CommandId: cmd.CommandId, Success: false, ErrorCode: "FILE_TOO_LARGE",
			Error: fmt.Sprintf("data %d bytes exceeds the single-op cap (split the write)", n),
		}
	}
	// Paths are attacker strings: a >PATH_MAX one cannot resolve, and the
	// warden's ancestor walk is O(bytes). Refuse at the wire gate (the warden
	// enforces the same bound as defense in depth).
	if len(req.Path) > commonconfig.MaxFilePathBytes || len(req.NewPath) > commonconfig.MaxFilePathBytes {
		// App-level (Success=true + Error): a client-side refusal must not look
		// like a sandlot/mount failure, which would trigger VM cleanup.
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: true, ErrorCode: "FILE_PATH_TOO_LONG",
			Error: fmt.Sprintf("path exceeds %d bytes", commonconfig.MaxFilePathBytes)}
	}
	// length <= 0 means "read up to the cap" at the warden; normalize it here
	// so the RESPONSE (payload + envelope) stays under the gRPC max message
	// size. The old gate let 0 through, the warden returned max_file_read_bytes
	// (16 MiB) and the reply breached the node stream's limit — a stream reset
	// that killed every co-tenant in-flight command on this sandlot.
	normalizeFileOpLength(&req.Length)
	if req.Length > int64(maxFileOpDataBytes) {
		return &pb.CommandResponse{
			CommandId: cmd.CommandId, Success: false, ErrorCode: "FILE_TOO_LARGE",
			Error: fmt.Sprintf("length %d exceeds the single-read cap (page with offset)", req.Length),
		}
	}

	// Resolve the sandfs to a VM. When volume_path is set (cold-mount allowed),
	// reuse the bound VM or pick a CLEAN spec-satisfying VM and bind. When
	// volume_path is empty, the sandfs must already be mounted here.
	var state *VMState
	if req.VolumePath != "" {
		state = h.resolveVMForMount(req.SandfsId, req.MinSpec, cmd.GetAgentId())
		if state == nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "no available VM on node", ErrorCode: "NO_AVAILABLE_VM"}
		}
	} else {
		state = h.vmForSandfs(req.SandfsId)
		if state == nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: "sandfs not mounted on node"}
		}
	}

	// Ensure the rootfs is mounted (cold path: overlay + allowed_dirs swap +
	// warden placeholder mount, serialized per VM inside ensureMounted). File
	// ops SHARE the exec slot pool — they are short ops that would otherwise
	// head-of-line block behind a long sync exec (and agents do issue parallel
	// multi-file reads, which the pool serves concurrently).
	if req.VolumePath != "" {
		if err := h.ensureMounted(ctx, state, cmd.GetAgentId(), req.SandfsId, req.VolumePath, req.TemplateRef, req.VolumeMode, req.GetVolumeEpoch()); err != nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: err.Error()}
		}
	}

	// Verify the rootfs is mounted (either already was, or we just mounted it),
	// and take the mounted-volume identity for the warm-op assertion from the
	// same record: file ops resolve paths INSIDE the mounted volume, so a
	// bookkeeping skew must be caught by the warden before any path is touched.
	state.mountMu.Lock()
	mountedCount := len(state.Volumes)
	state.mountMu.Unlock()
	if mountedCount == 0 {
		return &pb.CommandResponse{
			CommandId: cmd.CommandId,
			Success:   false,
			Error:     "no rootfs mounted — file ops require a mounted workspace",
		}
	}
	// The identity the warden asserts is the REQUEST's volume (the gateway's
	// tenant record), never the VM's current mount record: deriving it from
	// state.Volumes made the warden confirm whatever was mounted, so a switch
	// between the binding lookup above and this point executed A's file op
	// inside B's volume. A missing field is refused below (the gateway always
	// carries it; there is no compatibility path).
	mountedVolume := h.fileOpIdentity(req.VolumePath, state)
	if mountedVolume == "" {
		return &pb.CommandResponse{
			CommandId: cmd.CommandId,
			Success:   false,
			Error:     "file op carries no volume_path — refusing (the request must name its own volume)",
			ErrorCode: "INVALID_ARGUMENT",
		}
	}

	agt, done, err := h.acquireWarden(ctx, state)
	if err != nil {
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden get: %v", err)}
	}

	// Map proto action string to sub-opcode.
	subOp, err := fileSubOpFromAction(req.Action)
	if err != nil {
		done(false)
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: err.Error()}
	}

	wardenReq := warden.FileOpRequest{
		SubOp:         subOp,
		Path:          req.Path,
		NewPath:       req.NewPath,
		Offset:        req.Offset,
		Length:        req.Length,
		Mode:          uint32(req.Mode),
		Recursive:     req.Recursive,
		Depth:         uint32(req.Depth),
		Data:          req.Data,
		MountedVolume: mountedVolume,
	}

	resp, ferr := agt.FileOp(wardenReq)
	broken := isWardenTransportErr(ferr)
	done(broken)
	if broken {
		// Replay ONLY an op whose second attempt cannot duplicate an effect:
		// reads/stat/list are side-effect free, and a write at an explicit
		// offset stores identical bytes at an identical position. An APPEND
		// write (offset -1, O_APPEND at the warden) would append the same
		// payload twice when the first attempt landed but its reply was lost,
		// and the directory ops (mkdir/remove/rename) would report a
		// misleading EEXIST/ENOENT for an operation that already applied —
		// those return the transport error instead (the caller may retry the
		// whole operation at the API level, where the outcome is visible).
		if !fileOpRetryIdempotent(subOp, req.Offset) {
			h.logger.Printf("file_op transport error on VM %s: %v; not replaying a non-idempotent op", state.VM.ID, ferr)
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden file_op: %v", ferr)}
		}
		h.logger.Printf("file_op transport error on VM %s: %v; retrying", state.VM.ID, ferr)
		agt, done, err = h.acquireWarden(ctx, state)
		if err != nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden get: %v", err)}
		}
		resp, ferr = agt.FileOp(wardenReq)
		done(isWardenTransportErr(ferr))
	}
	if ferr != nil {
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: fmt.Sprintf("warden file_op: %v", ferr)}
	}

	// Build response. File op results carry binary data (e.g., file reads)
	// that may contain invalid UTF-8. Protobuf string fields require valid
	// UTF-8, so we use StdoutRaw (bytes) instead of Stdout (string) to
	// avoid "string field contains invalid UTF-8" marshal errors that would
	// crash the entire gRPC stream. The gateway checks StdoutRaw first.
	//
	// Success is always true here: the RPC reached the warden and got a reply,
	// so the transport succeeded. An app-level failure (ENOENT, EACCES, ...) is
	// carried in the Error field (non-empty) with empty Data — the gateway
	// checks Error to return a 400 without invalidating the VM (only a false
	// Success, i.e. a sandlot-side mount/transport failure, triggers cleanup).
	//
	// L1 wire guard (defense in depth): a response payload that would
	// breach the gRPC message limit on the reply leg is converted to a NAMED
	// app-level error here — forwarding it would reset the shared node stream
	// and kill every co-tenant in-flight command. The gateway normalizes the
	// request and the warden's list budget reserves headroom; this catches any
	// other caller/version skew.
	if fileOpResponseTooLarge(len(resp.Data)) {
		state.useCount.Add(1)
		return &pb.CommandResponse{
			CommandId: cmd.CommandId,
			Success:   true,
			VmId:      state.VM.ID,
			Spec:      state.SpecID,
			Error:     fmt.Sprintf("file op response %d bytes exceeds the %d-byte single-op cap", len(resp.Data), maxFileOpDataBytes),
		}
	}

	// Recycle accounting: the command was served by the VM (app-level failures
	// included — the warden ran it; only transport/mount failures above skip
	// this). Counted per command, warm and cold alike, exactly like execs.
	state.useCount.Add(1)
	return &pb.CommandResponse{
		CommandId: cmd.CommandId,
		Success:   true,
		VmId:      state.VM.ID,
		Spec:      state.SpecID,
		StdoutRaw: resp.Data,
		Error:     resp.Error,
	}
}

// fileSubOpFromAction maps the proto action string to a warden sub-opcode byte.
func fileSubOpFromAction(action string) (byte, error) {
	switch action {
	case "read":
		return warden.SubOpRead, nil
	case "write":
		return warden.SubOpWrite, nil
	case "stat":
		return warden.SubOpStat, nil
	case "list_dir":
		return warden.SubOpListDir, nil
	case "mkdir":
		return warden.SubOpMakeDir, nil
	case "remove":
		return warden.SubOpRemove, nil
	case "rename":
		return warden.SubOpRename, nil
	default:
		return 0, fmt.Errorf("unknown file action: %s", action)
	}
}

// handleCleanupOverlay handles the CleanupOverlay command from the gateway.
// It unmounts the host-side read-only overlay at <volumePath>/rootfs/ so the
// SandFS directory can be deleted. Idempotent: returns success if the overlay
// is not mounted.
func (h *Handler) handleCleanupOverlay(ctx context.Context, cmd *pb.VMCommand, req *pb.CleanupOverlay) *pb.CommandResponse {
	// An empty path stays the documented idempotent no-op (nothing to
	// unmount); a non-empty one is a host unmount source and must be
	// contained — in embedded mode this handler calls UnmountOverlay
	// directly, with no boxout-side check behind it.
	if req.VolumePath != "" {
		if err := h.checkVolumePathContained(req.VolumePath); err != nil {
			return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: err.Error()}
		}
	}
	if err := h.vm.UnmountOverlay(ctx, req.VolumePath); err != nil {
		return &pb.CommandResponse{CommandId: cmd.CommandId, Success: false, Error: err.Error()}
	}
	return &pb.CommandResponse{CommandId: cmd.CommandId, Success: true}
}

// wardenBootTimeout is how long CreateVerifiedVM waits for a freshly launched
// guest's warden to answer its first vsock probe. It bounds the SYNCHRONOUS
// part of VM creation: past this, the VM is never registered — it is destroyed
// completely. There is no retry ladder; the next pool reconcile creates a new
// VM from scratch if the host can afford one.
const wardenBootTimeout = 15 * time.Second

// resourceAlarmInterval throttles the resource-shortage alarm. Admission
// rejections can recur on every reconcile tick while the host stays short of
// memory; the situation does not change second to second, so one alarm per
// interval is all an operator (or the gateway) can act on. Everything within
// the window is still logged at admission time — only the VMEvent fan-out is
// throttled.
const resourceAlarmInterval = 60 * time.Second

// IsProtocolVersionMismatch reports whether err (or anything it wraps) is a
// warden protocol-version mismatch — the node-level "redeploy sandlot +
// initramfs together" condition. Pool scale-up loops (ResizePool,
// ReconcilePool, preCreateVMs) abort on it like ErrInsufficientMemory:
// continuing would create, boot, and destroy VM after VM against a warden
// that can never answer.
func IsProtocolVersionMismatch(err error) bool {
	var pve *warden.ProtocolVersionError
	return errors.As(err, &pve)
}

// alarmResourceShortage raises the node-level "not enough memory" alarm: a
// throttled WARN log plus a VM_EVENT_RESOURCE_SHORTAGE to the gateway. The
// shortage is a state, not an event — the node stops growing its pool until
// memory actually frees up, and this alarm says why.
func (h *Handler) alarmResourceShortage(cfg vmm.Config, cause error) {
	now := time.Now()
	h.alarmMu.Lock()
	shouldSend := now.Sub(h.lastResourceAlarm) >= resourceAlarmInterval
	if shouldSend {
		h.lastResourceAlarm = now
	}
	h.alarmMu.Unlock()

	h.logger.Printf("RESOURCE SHORTAGE: VM %s (%dMB) not started: %v (reserved=%dMB budget=%dMB; no retry — the pool refills via reconcile only after memory frees)",
		cfg.ID, cfg.MemoryMB, cause, h.memLedger.reserved(), h.memLedger.budget())
	if shouldSend {
		h.sendEvent(&pb.VMEvent{
			VmId:    cfg.ID,
			Type:    pb.VMEventType_VM_EVENT_RESOURCE_SHORTAGE,
			Message: cause.Error(),
		})
	}
}

// CreateVerifiedVM is the SINGLE entry point for creating a microVM. Every
// creation path (startup pre-creation, pool scale-up, crash replacement) goes
// through it, and it upholds the two invariants the rest of the code relies on:
//
//  1. Memory is admitted BEFORE anything is allocated (memLedger.admit on the
//     spec's full size — guests fault lazily, so MemAvailable alone would let
//     several oversized guests in while each still looks small). A rejected
//     admission creates nothing at all.
//  2. h.vms only ever contains VMs whose warden has answered at least once.
//     The warden wait is SYNCHRONOUS: a VM that does not come up within
//     wardenBootTimeout is destroyed completely — sandvmm killed and its death
//     confirmed, network + CID + sandbox dir + state.json released, memory
//     reservation returned — and never enters the registry. There is no
//     half-created VM for the probe loop, the mount path, or the gateway to
//     trip over, and no retry loop: a failed creation is a teardown plus an
//     error, nothing more.
//
// cfg must carry ID, SandboxDir, VCPUs and MemoryMB; GuestCID is allocated
// here (so it can be returned atomically on failure). NetSpec is provisioned
// here too — the guest IP feeds the kernel cmdline.
func (h *Handler) CreateVerifiedVM(ctx context.Context, cfg vmm.Config, specID string) (*vmm.RunningVM, error) {
	// 0. Quarantine gate: an unresolved destroy means an orphan VM may still
	// export an old volume on this node. Refuse new creation until the retry
	// loop confirms it is dead; the pool reports the shortage rather than
	// risking a double mount.
	if err := h.errNodeQuarantined(); err != nil {
		return nil, err
	}

	// 0. Duplicate-ID guard: registering a VM whose ID is already live would
	// silently overwrite the existing registry entry (no teardown of the old
	// VMState) and — because the sandbox dir and API socket path derive from
	// the ID — unlink the live VM's API socket mid-flight. Every legit creator
	// allocates IDs through NextPoolVMID (never colliding), so hitting this
	// guard means a caller bug; refuse loudly instead of corrupting the node.
	if h.vmState(cfg.ID) != nil {
		return nil, fmt.Errorf("VM %s: ID already registered — refusing to create a second VM under a live ID", cfg.ID)
	}

	// 1. Memory admission — before CID, before TAP, before sandvmm. Nothing to
	// clean up if this fails.
	if err := h.memLedger.admit(cfg.MemoryMB); err != nil {
		h.alarmResourceShortage(cfg, err)
		return nil, err
	}

	// 2. CID. Held from here on; every failure path below returns it.
	cid := h.AllocateCID()
	if cid == 0 {
		h.memLedger.release(cfg.MemoryMB)
		return nil, fmt.Errorf("CID range exhausted (cid_range_end reached); cannot create more VMs")
	}
	cfg.GuestCID = cid

	// 2b. Per-VM raw-protocol key. Generated here (not inside Launch) so the
	// caller keeps it for the warden round trips, VMState and state.json.
	// crypto/rand failure fails the create: a VM whose warden cannot
	// authenticate is unusable.
	if cfg.WardenSessionKey == "" {
		key, err := vmm.NewWardenSessionKey()
		if err != nil {
			h.releaseCID(cid)
			h.memLedger.release(cfg.MemoryMB)
			return nil, fmt.Errorf("VM %s: generate warden session key: %w", cfg.ID, err)
		}
		cfg.WardenSessionKey = key
	}

	// 3. Network. The guest IP is baked into the kernel cmdline, so this must
	// happen before launch. A provision failure leaves the VM offline (existing
	// semantics) — but any PARTIAL allocation is released first, so a failed
	// provision never leaks a TAP/IP. The provisioned spec is re-validated
	// against the strict cmdline grammar before it is carried into
	// cfg.NetSpec: a spec that does not match is dropped (VM boots offline)
	// with a named log, never forwarded to the cmdline builder
	// (vmm.VMNetSpec.Validate).
	if spec, err := h.vm.ProvisionNetwork(ctx, cfg.ID); err != nil {
		h.logger.Printf("VM %s: network provision failed (%v); continuing offline", cfg.ID, err)
		if relErr := h.vm.ReleaseNetwork(ctx, cfg.ID); relErr != nil {
			h.logger.Printf("VM %s: net release after failed provision (non-fatal): %v", cfg.ID, relErr)
		}
	} else if spec.HasNetwork() {
		if verr := spec.Validate(); verr != nil {
			h.logger.Printf("VM %s: provisioned net spec rejected (%v); continuing offline", cfg.ID, verr)
			if relErr := h.vm.ReleaseNetwork(ctx, cfg.ID); relErr != nil {
				h.logger.Printf("VM %s: net release after rejected spec (non-fatal): %v", cfg.ID, relErr)
			}
		} else {
			cfg.NetSpec = &spec
			h.debugOp("VM %s: provisioned net ip %s tap %v mac %s", cfg.ID, spec.GuestIP, spec.NetConfig["tap"], spec.MAC)
		}
	}

	// 4. Launch sandvmm. On failure release everything allocated so far.
	vm, err := h.vmCreateAndAttach(ctx, cfg)
	if err != nil {
		h.logger.Printf("VM %s: launch failed: %v", cfg.ID, err)
		h.discardUnregisteredVM(cfg, vm)
		return nil, err
	}

	// 5. Verify the guest actually came up. This is the gate for registration:
	// a VM whose warden never answers is DESTROYED, not registered-and-waited.
	if err := h.waitWardenReady(ctx, cid, cfg.WardenSessionKey, wardenBootTimeout); err != nil {
		var pve *warden.ProtocolVersionError
		if errors.As(err, &pve) {
			// LOUD and terminal for the pool loop: every VM booted from this
			// node's initramfs carries the same incompatible warden, so
			// destroying this one and creating the next cannot fix anything —
			// callers abort the scale-up (like ErrInsufficientMemory) and the
			// operator redeploys sandlot + initramfs together.
			h.logger.Printf("VM %s: %v — node's kernel/initramfs warden is incompatible with this sandlot build; destroy+recreate cannot fix it, redeploy the pair together", cfg.ID, err)
			h.discardUnregisteredVM(cfg, vm)
			return nil, pve
		}
		h.logger.Printf("VM %s: warden not ready within %v (%v); destroying completely", cfg.ID, wardenBootTimeout, err)
		h.discardUnregisteredVM(cfg, vm)
		return nil, fmt.Errorf("warden not ready on VM %s within %v: %w", cfg.ID, wardenBootTimeout, err)
	}

	// 6. Registered = verified. From here the VM is a first-class citizen:
	// mountable, probed, heartbeat-visible.
	h.registerReadyVM(vm, cfg, specID)
	h.debugOp("VM %s ready (cid=%d, spec=%s)", cfg.ID, cid, specID)
	return vm, nil
}

// discardUnregisteredVM tears down a VM that CreateVerifiedVM created but can
// no longer proceed with (launch failure, warden never came up). It is the
// failure-side mirror of registration: sandvmm killed with confirmed death,
// network + state + sandbox dir removed, CID returned. Memory stays reserved —
// the ledger reservation is released by the caller only after the process is
// truly gone, via the release here in every path.
//
// The VM was never in h.vms, so none of the registry-based teardown helpers
// (destroyVMByID, handleVMDied) apply; this is the direct cleanup. The destroy
// delegates to the lifecycle manager so embedded and boxout modes both kill
// correctly, and a death that CANNOT be confirmed skips the CID release — a
// CID whose previous holder may still be alive must not be handed out again.
func (h *Handler) discardUnregisteredVM(cfg vmm.Config, vm *vmm.RunningVM) {
	if vm != nil {
		target := &DestroyTarget{
			VMID:       cfg.ID,
			VM:         vm,
			APISocket:  vm.APISocket,
			PID:        vm.PID(),
			Readopted:  false,
			SandboxDir: cfg.SandboxDir,
			WaitDone:   nil, // fresh VM: killVMM falls back to confirmProcDead
		}
		if h.vm != nil {
			if err := h.vm.DestroyVM(context.Background(), target); err != nil {
				h.metrics.RecordStranded(cfg.MemoryMB)
				h.logger.Printf("VM %s: destroy after failed creation did not confirm death; CID release SKIPPED: %v", cfg.ID, err)
				return // memory reservation stays held too — process may live
			}
		} else {
			// No lifecycle manager (test env): best-effort direct cleanup.
			vm.Kill()
			removeState(cfg.SandboxDir)
			removeSandboxDir(cfg.SandboxDir, h.SandboxRoot)
		}
	}
	if h.vm != nil {
		if err := h.vm.ReleaseNetwork(context.Background(), cfg.ID); err != nil {
			h.logger.Printf("VM %s: net release on discard (non-fatal): %v", cfg.ID, err)
		}
	}
	h.releaseCID(cfg.GuestCID)
	h.memLedger.release(cfg.MemoryMB)
}

// registerReadyVM enters a VERIFIED VM into the registry: warden has answered,
// so the VM is immediately mountable, probeable, and heartbeat-visible. This
// is everything RegisterPrecreatedVM used to do, minus the async warden wait
// (CreateVerifiedVM already did it synchronously).
func (h *Handler) registerReadyVM(vm *vmm.RunningVM, cfg vmm.Config, specID string) {
	vmID := cfg.ID
	state := &VMState{
		VM:      vm,
		Cfg:     cfg,
		Volumes: make(map[string]struct{}),
		SpecID:  specID,
		vmMonitorState: vmMonitorState{
			waitDone: make(chan struct{}),
		},
	}
	// Fix the warden pool size (sync-command concurrency) at creation from the
	// spec's exec_slots. Must be set before the pool is first used (lazy init).
	state.execSlots.Store(int64(h.execSlotsForSpec(specID)))
	// Resolve the egress identity slot (TAP ifindex) once and reset any stale
	// region entry for it.
	h.initBindingSlot(state)
	h.mu.Lock()
	h.vms[vmID] = state
	h.mu.Unlock()

	// Update state.json with the specID. CreateVM writes state.json before
	// the specID is known (it's set here). Without this rewrite, re-adopted
	// VMs have spec_id="" and preCreateVMs counts zero re-adopted VMs per
	// spec, creating a full extra pool on every restart.
	if specID != "" {
		// Carry the EFFECTIVE kernel cmdline into the record (Launch applies
		// the base default + warden params on its own cfg copy — see the
		// WardenSessionKey carry in embedded_manager for the same pattern).
		cfg.KernelCmdline = vm.KernelCmdline
		if err := writeState(stateFromConfig(vmID, cfg, vm.APISocket, vm.PID(), specID), h.SandboxRoot); err != nil {
			h.logger.Printf("rewrite state with specID for VM %s (non-fatal): %v", vmID, err)
		}
	}

	// Crash monitor — use the captured state pointer (not a second vmState
	// lookup) to avoid a TOCTOU race where handleVMDied removes the map
	// entry between the two calls.
	//
	// For readopted VMs (boxout mode: vmm.Attach, no *exec.Cmd), cmdWaitFn's
	// Wait() returns nil immediately — use pidfdMonitor instead.
	if vm.Readopted() {
		h.startVMMonitor(vmID, vm.PID(), vm)
	} else {
		go h.monitorVMCore(state, h.cmdWaitFn(state))
	}

	// Pre-warm one pool slot (best-effort; the pool dials more on demand).
	// Synchronous and cheap: warden is confirmed up, so this is one vsock dial.
	// Send MemStats as the connection's FIRST frame: the warden closes a fresh
	// connection that stays silent for FIRST_FRAME_TIMEOUT (30s), and a
	// pre-warmed slot can sit idle past that before its first business request
	// (e.g. a pool VM created long before its first exec). After this one
	// round trip the connection is established and may idle indefinitely
	// between ops, like every other pooled slot.
	state.wardenPoolFor().warmup(func() (*warden.Client, error) {
		c, err := h.dialWardenRetry(vm.GuestCID, cfg.WardenSessionKey, 5*time.Second)
		if err != nil {
			return nil, err
		}
		if _, _, err := c.MemStats(); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	})
}
