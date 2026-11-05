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
	"time"

	"sandlot/bindreg"
	"sandlot/vmm"
)

// Egress identity binding (the Sandswap enabler for third-party network
// policy, see docs/how-it-works/egress-enabler.md).
//
// The Handler holds an optional bindreg.Region. When enabled, every mount
// publishes (tap-ifindex -> agent/sandfs) into the region BEFORE the warden
// RPC that creates guest processes is dispatched, and every unmount/destroy
// revokes it. The ordering is constructive: guest code does not exist before
// exec, and exec is dispatched after the publish, so a vendor enforcer can
// never see an unattributable or misattributable flow.
//
// All hot-path writes are single memory-write sets (~0.2µs, no syscalls).
// Publishers are serialized per VM by mountMu (mount/unmount/switch), which
// is what the seqlock's single-writer-per-slot assumption expects; a revoke
// racing a publish from a destroy path degrades to a retry-able seqlock
// collision, never a torn read on the vendor side.

// SetBindRegion attaches the egress identity binding region. Call once at
// startup, before any command processing. nil (the default) disables the
// enabler entirely — zero behavior change, zero hot-path cost.
func (h *Handler) SetBindRegion(r *bindreg.Region) {
	h.mu.Lock()
	h.bind = r
	h.mu.Unlock()
}

// tapNameFromConfig extracts the VM's TAP device name from its network spec
// ("" when the VM is offline).
func tapNameFromConfig(cfg vmm.Config) string {
	if cfg.NetSpec == nil || cfg.NetSpec.NetConfig == nil {
		return ""
	}
	tap, _ := cfg.NetSpec.NetConfig["tap"].(string)
	return tap
}

// initBindingSlot resolves the VM's TAP ifindex once, at registration time
// (both fresh-create and re-adopt). The ifindex is the binding-region slot
// key and stays stable for the TAP's lifetime. A VM whose TAP is missing is
// offline and simply never publishes.
func (h *Handler) initBindingSlot(state *VMState) {
	if h.bind == nil || state == nil {
		return
	}
	// Seed the epoch counter from wall-clock so generations never repeat on
	// one attachment: without this, a sandlot restart (or a destroyed VM whose
	// ifindex is immediately recycled) would restart at epoch 1 and a vendor
	// cache keyed on (ifindex, epoch) could match a PREVIOUS tenant's entry —
	// exactly the misattribution the epoch field exists to prevent.
	state.bindEpoch.Store(epochSeed())
	tap := tapNameFromConfig(state.Cfg)
	if tap == "" {
		// Diagnostic: a VM with a net spec but no resolvable tap never gets a
		// binding slot (silent offline-VM semantics are a config bug trap).
		if state.Cfg.NetSpec != nil && state.Cfg.NetSpec.HasNetwork() {
			h.logger.Printf("VM %s: bindreg slot skipped — net spec has no tap name", state.VM.ID)
		}
		return
	}
	idx, err := bindreg.ResolveIfindex(tap)
	if err != nil {
		h.logger.Printf("VM %s: bindreg slot unavailable (tap %s: %v); identity publishes disabled for this VM", state.VM.ID, tap, err)
		return
	}
	state.tapIfindex.Store(idx)
	// Churn budget: ifindexes grow monotonically per boot and recycle policies
	// destroy+recreate a TAP per cycle (~2 ifindexes per cycle — the default
	// 65536 slots are weeks of heavy churn). Past the bound every publish
	// fails safe (deny); loud and early beats silent.
	maxIdx := h.bind.MaxIfindex()
	// Guard the subtraction: idx > max (a region reconfigured smaller than the
	// TAPs already on the host) would underflow uint64 and silently skip the
	// warning — publishes past the bound still fail safe (deny), but the
	// operator must hear about it.
	if idx >= maxIdx || maxIdx-idx < maxIdx/10 {
		h.logger.Printf("VM %s: ifindex %d is at/within 10%% of region max %d — raise the binding region's max_ifindex (or reboot) before exhaustion; publishes past the bound fail safe as unidentified",
			state.VM.ID, idx, maxIdx)
	}
	// Fresh slot: drop any stale entry that a recycled ifindex may still carry
	// (e.g. after a crash + re-adopt chain). An absent entry reads as
	// "unidentified" to enforcers, which is exactly right for a CLEAN VM.
	if err := h.bind.Unregister(idx); err != nil {
		h.logger.Printf("VM %s: bindreg slot reset failed (ifindex %d): %v", state.VM.ID, idx, err)
	}
}

// setNetMountGate hands the network provider (when it implements MountGater)
// this VM's mount/unmount transition, so mount-scoped network state — the
// routed-IPv6 identity stamp — is torn down at unmount. Async by contract:
// the mount hot path never waits on it.
func (h *Handler) setNetMountGate(state *VMState, mounted bool) {
	if h.net == nil || state == nil {
		return
	}
	if g, ok := h.net.(vmm.MountGater); ok {
		g.SetMountState(context.Background(), state.VM.ID, mounted)
	}
}

// epochSeed returns a non-repeating base for a VMState's bindEpoch: wall-clock
// at ~µs resolution (UnixNano >> 10). Two VMStates may share a seed only if
// created within the same microsecond — and epoch uniqueness only has to hold
// per attachment (ifindex), which is never recycled that fast.
func epochSeed() uint64 { return uint64(time.Now().UnixNano()) >> 10 }

// publishBindingLocked records that `state` now serves agentID's sandfsID.
// Caller must serialize with mount switches (hold state.mountMu). The epoch
// increments per publish so a recycled attachment never shares a generation
// with its previous tenant (seeded from wall clock at registration — see
// epochSeed — so generations never repeat across restarts either).
//
// Parallel execs: a sandfs accepts concurrent execs, and two cold execs can
// both pass the warm check before either marks Volumes (the first's combined
// RPC is still in flight), so publishBindingLocked re-enters with an
// UNCHANGED identity. That is a continuation of the same mount, not a switch:
// the already-published generation (epoch + stamp) stays — one generation per
// mount, per the contract's lifecycle table. A re-publish would churn the
// epoch and the identity stamp on every parallel first-exec, forcing vendors
// that pin per-epoch policy to reload rules for an identity that never
// changed. Revoke and failure clear the record, so a real switch (or a retry
// after a failed publish) always gets a fresh generation.
func (h *Handler) publishBindingLocked(state *VMState, agentID, sandfsID string) {
	h.setNetMountGate(state, true)
	if state.bindAgentID == agentID && state.bindSandfsID == sandfsID {
		return // same generation already live on this attachment
	}
	if h.bind == nil {
		return
	}
	idx := state.tapIfindex.Load()
	if idx == 0 {
		return // offline VM: cannot emit traffic, nothing to attribute
	}
	epoch := state.bindEpoch.Add(1)
	err := h.bind.Publish(idx, bindreg.Entry{
		State:      bindreg.StateMounted,
		MountEpoch: epoch,
		AgentID:    agentID,
		SandfsID:   sandfsID,
		VMID:       state.VM.ID,
	})
	if err != nil {
		state.bindAgentID, state.bindSandfsID = "", "" // retry next exec
		// Fail-safe: never leave a PREVIOUS agent's identity attached to this
		// attachment — revoke so enforcers see "unbound" (deny) instead of a
		// stale identity (misattribution).
		h.logger.Printf("VM %s: bindreg publish failed (ifindex %d): %v; revoking", state.VM.ID, idx, err)
		if rerr := h.bind.Revoke(idx); rerr != nil {
			h.logger.Printf("VM %s: bindreg fallback revoke also failed: %v", state.VM.ID, rerr)
		}
	} else {
		state.bindAgentID, state.bindSandfsID = agentID, sandfsID
	}
	// Identity-in-address pattern: stamp the mount's egress with the
	// identity-encoded source address. Synchronous by design (the
	// stamp follows the region publish carrying the same epoch) but
	// µs-class and bounded — the network provider's netlink paths never
	// block unboundedly and never spawn processes.
	if h.net != nil {
		if s, ok := h.net.(vmm.IdentityStamper); ok {
			s.SetMountIdentity(context.Background(), state.VM.ID, agentID, sandfsID, epoch)
		}
	}
}

// revokeBinding flips the attachment back to StateUnbound (mount released)
// and clears the published-identity record so the next mount — even with an
// unchanged identity — starts a fresh generation. All callers hold
// state.mountMu. No-op when the enabler is off or the VM never published.
func (h *Handler) revokeBinding(state *VMState) {
	h.setNetMountGate(state, false)
	if state == nil {
		return
	}
	state.bindAgentID, state.bindSandfsID = "", ""
	if h.bind == nil {
		return
	}
	idx := state.tapIfindex.Load()
	if idx == 0 {
		return
	}
	if err := h.bind.Revoke(idx); err != nil {
		h.logger.Printf("VM %s: bindreg revoke failed (ifindex %d): %v", state.VM.ID, idx, err)
	}
}

// unregisterBinding erases the attachment's slot entirely (TAP/VM gone).
func (h *Handler) unregisterBinding(state *VMState) {
	if h.bind == nil || state == nil {
		return
	}
	idx := state.tapIfindex.Load()
	if idx == 0 {
		return
	}
	if err := h.bind.Unregister(idx); err != nil {
		h.logger.Printf("VM %s: bindreg unregister failed (ifindex %d): %v", state.VM.ID, idx, err)
	}
}
