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

package network

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"sandlot/vmm"
)

// BridgeNAT is a NetworkProvider that gives each microVM a virtio-net TAP
// enslaved to a shared host bridge, with kernel NAT (installed once by
// deploy/setup-network.sh) and a static guest IP — no DHCP daemon, no
// per-VM process. The TAP is created at Provision time and torn down at
// Release time, matching the microVM lifecycle.
type BridgeNAT struct {
	bridge string // host bridge name (e.g. br-sandswap)
	subnet *net.IPNet
	gw     net.IP
	dns    []string
	alloc  *ipAllocator
	// baseline is the optional egress network baseline (anti-spoof, VM
	// isolation). nil = disabled (plain pre-baseline behavior).
	baseline *Baseline
	// logger receives the provider's failure-path diagnostics so they carry
	// the process log prefix and stream (fmt/os.Stderr would not).
	logger *log.Logger
	// tapOwnerUID is the sandvmm identity that owns every TAP this provider
	// creates. TUNSETIFF admits an owner match without CAP_NET_ADMIN, so the
	// VMM attaches to the pre-created persistent TAP with zero capabilities.
	// 0 = the provider's own euid (no identity transition).
	tapOwnerUID uint32

	mu     sync.Mutex
	leases map[string]net.IP // vmID -> allocated guest IP
	taps   map[string]string // vmID -> tap name
}

// NewBridgeNAT builds a BridgeNAT provider. bridge is the host bridge (must
// already exist — create it with deploy/setup-network.sh); subnetCIDR is the
// guest subnet (e.g. 10.188.0.0/16); gateway is the bridge IP / guest default
// gateway; dns is the guest nameserver list. baseline may be nil (baseline
// disabled). logger may be nil (falls back to the standard logger).
// SetTapOwnerUID pins the identity that will own created TAPs (the sandvmm
// uid). Called by the shared provider factory before any Provision.
func (b *BridgeNAT) SetTapOwnerUID(uid uint32) { b.tapOwnerUID = uid }

func NewBridgeNAT(bridge, subnetCIDR, gateway string, dns []string, baseline *Baseline, logger *log.Logger) (*BridgeNAT, error) {
	_, ipnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse subnet %q: %w", subnetCIDR, err)
	}
	gw := net.ParseIP(gateway).To4()
	if gw == nil {
		return nil, fmt.Errorf("invalid gateway %q", gateway)
	}
	alloc, err := newIPAllocator(ipnet, gw)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.Default()
	}
	return &BridgeNAT{
		bridge:   bridge,
		subnet:   ipnet,
		gw:       gw,
		dns:      dns,
		alloc:    alloc,
		baseline: baseline,
		logger:   logger,
		leases:   make(map[string]net.IP),
		taps:     make(map[string]string),
	}, nil
}

// Provision allocates a static guest IP, creates a TAP enslaved to the bridge,
// and returns the net spec (host-side NetConfig + guest-side IP params for the
// warden cmdline). It is idempotent per vmID: re-provisioning the same vmID
// reuses its lease and re-creates the tap if missing.
func (b *BridgeNAT) Provision(_ context.Context, vmID string) (vmm.VMNetSpec, error) {
	b.mu.Lock()
	ip, ok := b.leases[vmID]
	if !ok {
		var err error
		ip, err = b.alloc.Allocate()
		if err != nil {
			b.mu.Unlock()
			return vmm.VMNetSpec{}, fmt.Errorf("allocate ip for %s: %w", vmID, err)
		}
		b.leases[vmID] = ip
	}
	b.mu.Unlock()

	ones, _ := b.subnet.Mask.Size()
	mac := randomLocalMAC()
	tapName := tapNameFor(vmID)
	if err := b.ensureTAP(tapName); err != nil {
		return vmm.VMNetSpec{}, fmt.Errorf("create tap %s: %w", tapName, err)
	}

	b.mu.Lock()
	b.taps[vmID] = tapName
	b.mu.Unlock()

	// Egress network baseline (L2+L3 source anti-spoof): part of the
	// identity-anchor guarantee, installed at provision (cold path).
	if b.baseline != nil {
		if err := b.baseline.AttachTap(tapName, ip.String(), "", mac); err != nil {
			return vmm.VMNetSpec{}, fmt.Errorf("baseline attach %s: %w", tapName, err)
		}
	}

	return vmm.VMNetSpec{
		GuestIP: ip.String(),
		Prefix:  ones,
		Gateway: b.gw.String(),
		DNS:     b.dns,
		MAC:     mac,
		NetConfig: map[string]any{
			"tap": tapName,
			"mac": mac,
			"mtu": guestMTU,
		},
	}, nil
}

// Release tears down the TAP and returns the IP to the free-list. It is
// best-effort: errors are returned but callers should log, not fail the VM
// destroy.
func (b *BridgeNAT) Release(_ context.Context, vmID string) error {
	b.mu.Lock()
	ip := b.leases[vmID]
	tap := b.taps[vmID]
	delete(b.leases, vmID)
	delete(b.taps, vmID)
	b.mu.Unlock()

	var firstErr error
	if tap != "" {
		if b.baseline != nil {
			if err := b.baseline.DetachTap(tap); err != nil {
				firstErr = err
			}
		}
		if err := destroyTAP(tap); err != nil {
			firstErr = err
		}
	}
	if ip != nil {
		b.alloc.Release(ip)
	}
	return firstErr
}

// Reclaim re-registers an existing (still-live) lease for a re-adopted VM whose
// sandvmm survived a sandlot restart. It reserves the IP (so a freshly
// Provision-ed VM can't collide) and records the lease/TAP, but does NOT create
// or destroy any host device — the live sandvmm still holds the TAP fd, and
// calling Provision's ensureTAP would `ip link del` it, taking the VM offline.
// The TAP's continued existence is verified (best-effort); a missing TAP leaves
// the VM offline but does not fail re-adopt.
func (b *BridgeNAT) Reclaim(_ context.Context, vmID string, spec vmm.VMNetSpec) error {
	ip := net.ParseIP(spec.GuestIP).To4()
	if ip == nil {
		return fmt.Errorf("reclaim %s: invalid guest ip %q", vmID, spec.GuestIP)
	}
	tap, _ := spec.NetConfig["tap"].(string)

	// The tap is destroyed as root by Release, so only this VM's own
	// derived name may be re-registered. The address reservation below still
	// happens for a refused foreign tap — it is the collision ledger the
	// re-adopt path depends on (refusing before it would let a fresh
	// Provision double-assign the survivor's IP); the REFUSAL is what keeps
	// the tap out of b.taps, and the named error is returned for the caller.
	tapErr := checkReclaimTap(vmID, tap)

	b.mu.Lock()
	// The address must be an allocatable host of THIS subnet: a reclaim for
	// 8.8.8.8 (or the gateway/broadcast) must never enter the ledger, or the
	// next Allocate could hand a forged/duplicate IP to a legitimate VM.
	if !b.alloc.Reserve(ip) {
		b.mu.Unlock()
		return fmt.Errorf("reclaim %s: guest ip %s is not an allocatable host of subnet %s", vmID, spec.GuestIP, b.subnet)
	}
	// An address already leased to another VM is a duplicate registration:
	// refuse instead of silently overlapping two tenants.
	for other, oip := range b.leases {
		if other != vmID && oip.Equal(ip) {
			b.mu.Unlock()
			return fmt.Errorf("reclaim %s: guest ip %s is already leased to %s", vmID, spec.GuestIP, other)
		}
	}
	b.leases[vmID] = ip
	if tap != "" && tapErr == nil {
		b.taps[vmID] = tap
	}
	b.mu.Unlock()

	if tapErr != nil {
		return tapErr
	}

	// Verify the TAP still exists on the host (the live sandvmm holds its fd).
	// A missing TAP means the VM will be offline; log but don't fail re-adopt.
	if tap != "" && !tapExistsFn(tap) {
		b.logger.Printf("bridge reclaim %s: tap %s missing on host (VM will be offline)",
			vmID, tap)
	}
	// Replay the per-TAP source anti-spoof. A re-adopted VM inherited whatever
	// ruleset survived the restart: the netdev chain dies with the table on a
	// flush and the TAP keeps running, so steering traffic back to it without
	// re-installing the pins would let the guest source any address it likes.
	// A failure refuses the reclaim (fail-closed) — the VM must not serve with
	// its identity anchor missing.
	if tap != "" && tapExistsFn(tap) && b.baseline != nil {
		mac, _ := spec.NetConfig["mac"].(string)
		if err := b.baseline.AttachTap(tap, ip.String(), "", mac); err != nil {
			return fmt.Errorf("reclaim %s: replay anti-spoof: %w", vmID, err)
		}
	}
	return nil
}

// ensureTAP creates the TAP, enslaves it to the bridge, and brings it up.
// All operations are ioctls on /dev/net/tun and the interface (see
// tap_linux.go); no `ip` process is spawned.
//
// If a TAP with the same name already exists:
//   - Active (another sandvmm holds a TUNSETIFF binding /sys/class/net/<tap>/tun_flags
//     exists): fail — the TAP is in use and cannot be provisioned.
//   - Stale (persistent TAP with no binding, e.g. from a previous VM whose Release
//     wasn't called or didn't complete): delete it and create a fresh one.
//
// Requires root/CAP_NET_ADMIN (the provider is the privileged side).
func (b *BridgeNAT) ensureTAP(name string) error {
	if tapExistsFn(name) {
		// TAP exists. The attachment test is the kernel's EBUSY on a second
		// non-multi-queue TUNSETIFF, not the sysfs tun_flags file (that file
		// exists for the device's whole life once any queue was ever attached,
		// so it falsely reports stale TAPs as active forever).
		attached, probeErr := tapHasAttachedQueueFn(name)
		if probeErr != nil {
			return fmt.Errorf("tap %s: attachment probe failed: %w", name, probeErr)
		}
		if attached {
			// Active TAP — another sandvmm holds it. Cannot provision.
			return fmt.Errorf("tap %s already in use by another process", name)
		}
		// Stale TAP (persistent, no binding) — clean it up before creating fresh.
		if err := destroyTAP(name); err != nil {
			return fmt.Errorf("remove stale tap %s: %w", name, err)
		}
	}

	// TAP does not exist — create it fresh, owned by the VMM identity and
	// pre-configured (MTU, bridge, up) so the VMM's attach needs no
	// CAP_NET_ADMIN: TUNSETIFF admits the owner, the MTU/enable ioctls then
	// find the desired state already in place and skip themselves.
	owner := b.tapOwnerUID
	if owner == 0 {
		owner = uint32(os.Geteuid())
	}
	if err := createPersistentTAPFn(name, owner); err != nil {
		return err
	}
	cleanup := func() {
		if derr := deletePersistentTAPFn(name); derr != nil {
			b.logger.Printf("tap %s: cleanup after failed provision: %v", name, derr)
		}
	}
	if err := setTAPMasterFn(name, b.bridge); err != nil {
		cleanup()
		return err
	}
	if err := setTAPMTUFn(name, guestMTU); err != nil {
		cleanup()
		return err
	}
	if err := setTAPUpFn(name); err != nil {
		cleanup()
		return err
	}
	return nil
}

func destroyTAP(name string) error {
	if err := deletePersistentTAPFn(name); err != nil {
		return fmt.Errorf("del tap %s: %w", name, err)
	}
	// Wait for the TAP to truly disappear from the kernel. Clearing
	// TUNSETPERSIST and closing the fd schedules the interface teardown, but
	// the kernel TUN subsystem's internal cleanup may lag — especially in
	// nested virtualization where guest scheduling adds jitter. Without this
	// poll, a subsequent Provision for the same TAP name could find a "dying"
	// interface, and sandvmm's TUNSETIFF would fail with EBUSY. Polling
	// guarantees the name is fully available for reuse when Release returns.
	const maxWait = 5 * time.Second
	const pollInterval = 50 * time.Millisecond
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if !tapExistsFn(name) {
			return nil // TAP is truly gone
		}
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("tap %s still exists after %v (kernel cleanup delay)", name, maxWait)
}

// tapNameFor derives a unique, ifname-length-safe tap name from a vmID.
// Linux interface names are limited to 15 characters. We use "tap-" (4 chars)
// plus 10 hex digits from a SHA-256 digest of the vmID, giving
// "tap-XXXXXXXXXX" (14 chars total). The hash ensures distinct vmIDs always
// get distinct tap names — the previous truncation scheme (id[:8]) caused
// collisions for IDs sharing a common prefix (e.g. pool-medium-{0,1,2} all
// mapped to "tap-pool-med").
// TapNameFor exposes the deterministic TAP name to the privileged boundary
// (boxout) that validates a caller-supplied net_config against the TAP this
// host actually created for the VM.
func TapNameFor(vmID string) string { return tapNameFor(vmID) }

func tapNameFor(vmID string) string {
	h := sha256.Sum256([]byte(vmID))
	return fmt.Sprintf("tap-%x", h[:5])
}

// ErrForeignTap is the refusal class for a Reclaim whose caller-supplied tap
// name does not belong to the VM it is registered for. The tap
// travels verbatim in the reclaim request (boxout protocol / persisted state)
// and Release later destroys it as ROOT (`ip link del`), so an unchecked name
// is a root-level interface-destroy primitive for the request's author. Only
// the VM's own derived tap name is accepted.
var ErrForeignTap = fmt.Errorf("tap does not belong to this vm")

// checkReclaimTap reports the tap-ownership violation a Reclaim must refuse.
// An EMPTY tap is legal (a spec without a tap records nothing); anything else
// must be exactly tapNameFor(vmID).
func checkReclaimTap(vmID, tap string) error {
	if tap == "" || tap == tapNameFor(vmID) {
		return nil
	}
	return fmt.Errorf("%w: %s carries tap %q, want %q", ErrForeignTap, vmID, tap, tapNameFor(vmID))
}

// randomLocalMAC returns a locally-administered (02:xx) unicast MAC.
//
// A rand failure is UNRECOVERABLE and must not fall back: the old fallback
// returned one FIXED MAC, so every concurrently provisioned VM shared it —
// on a shared L2 bridge that is a silent, total forwarding breakdown (every
// guest's frames claimed by one MAC table entry). crypto/rand failing means
// the kernel entropy source is gone; provisioning cannot proceed.
func randomLocalMAC() string {
	b := make([]byte, 6)
	// Use crypto/rand for genuine uniqueness across concurrent VMs.
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("randomLocalMAC: crypto/rand failed — cannot provision a unique guest MAC: %v", err))
	}
	b[0] = 0x02 // locally administered, unicast
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// tapExistsFn is the syscall-backed existence probe (tap_linux.go). It used
// to be an `ip link show` process spawn at three call sites.
