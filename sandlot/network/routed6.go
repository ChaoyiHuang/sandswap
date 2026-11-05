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
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"sandlot/vmm"
)

// RoutedIPv6 is the NetworkProvider for the identity-in-address pattern
// (docs/how-it-works/egress-enabler.md): each microVM TAP gets its own
// routed /64 carved from a site prefix — NO shared L2, so neighbor-discovery
// spoofing cannot exist by construction. The microVM gets a static IPv6
// address; egress steers to a central policy point by source-prefix policy
// routing.
//
// Addressing plan (default prefix fd00:5341:4e44::/48 — "SAND" in ASCII hex):
//
//	fd00:5341:4e44:<subnet>:<IID>   microVM address (one /64 per TAP)
//	fd00:5341:4e44:<subnet>::1      host-side TAP address = the microVM's gateway
//
// Subnet indices are the 16 bits right after the prefix; prefixes must be a
// multiple of 8 bits and ≤ /48 — the address is <prefix | 16-bit subnet |
// 64-bit IID>, and a longer prefix would let the IID overwrite the subnet
// index (see NewRoutedIPv6).
//
// Identity vs. pool reuse: the identity is known at MOUNT, not at provision
// (pooled VMs are pre-created CLEAN). The guest therefore boots with the
// fixed all-zero IID (`<subnet>::` — the subnet-router anycast form, invalid
// as an identity), and each mount STAMPS the identity: a secondary identity-
// encoded address (per the IID template) is added on the TAP host-side plus
// an SNAT map element rewriting the tap's v6 egress to it, so middleboxes see
// per-mount identity-encoded source addresses and parse them statelessly per
// the declared template. Unmount removes the stamp. Stamping is synchronous
// and runs after the binding-region publish; both the mount-side add and the
// unmount-side delete are sub-ms (persistent netlink sockets + a cached map
// set id; measured ~0.4 ms mount / ~0.8 ms unmount on the nested review host).
// Failures degrade to unstamped egress, never to a wrong identity.
type RoutedIPv6 struct {
	prefix *net.IPNet // site prefix, multiple of 8 bits, ≤ /48
	dns    []string
	iid    *IIDTemplate // nil = stamping disabled (no template declared)
	stamp  bool         // identity SNAT stamping enabled
	// baseline installs the per-tap source anti-spoof —
	// without it a guest could source a non-assigned address that misses the
	// SNAT map and egress unattributed. nil = disabled (baseline off).
	baseline *Baseline
	// logger receives the provider's failure-path diagnostics so they carry
	// the process log prefix and stream (fmt.Printf would not).
	logger *log.Logger
	// tapOwnerUID is the sandvmm identity that owns every TAP this provider
	// creates (owner match admits TUNSETIFF without CAP_NET_ADMIN).
	// 0 = the provider's own euid (no identity transition).
	tapOwnerUID uint32

	mu      sync.Mutex
	subnets map[string]uint32      // vmID -> subnet index
	taps    map[string]string      // vmID -> tap name
	stamps  map[string]*stampState // vmID -> currently stamped identity
	specs   map[string]string      // vmID -> guest boot address (SNAT map key)
	setIDs  map[string]uint32      // vmID -> cached nft map set id (stable per TAP)

	// subnets are handed out lowest-free-first from a used-set. The set (not
	// a bump counter) is what makes re-adoption safe: Reclaim reserves the
	// survived VMs' subnets, so fresh Provision can never double-assign them.
	// subnetOwner names the VM that owns a reserved index, so a Reclaim for a
	// DIFFERENT VM can be refused instead of silently overlapping two tenants
	// on one /64 (which would make the source pins and SNAT map ambiguous).
	allocMu     sync.Mutex
	usedSub     map[uint32]bool
	subnetOwner map[uint32]string
}

// identityStampComment marks the per-tap SNAT rule for handle-based removal.
const identityStampComment = "sandswap-identity-stamp"

// stampTableName holds the per-tap stamp maps/chains (nftables inet family —
// requires kernel ≥ 5.2 for inet-family NAT).
const stampTableName = "sandswap_routed6"

// routed6ForwardChain is the inet-family FORWARD chain carrying the routed-IPv6
// VM-to-VM posture. The Baseline's bridge-family rule only sees L2-bridged
// frames; routed TAPs are standalone L3 interfaces, so their guest→guest
// traffic must be dropped from this chain instead.
const routed6ForwardChain = "fwd_vm2vm"

// routed6MetadataChain carries the routed-IPv6 metadata-endpoint drop. It is
// posture-independent (it protects the HOST's cloud identity, not tenant
// isolation) and runs ahead of the standard filter priority so no
// operator/vendor chain can forward a guest packet to it first.
const routed6MetadataChain = "fwd_metadata"

// v6MetadataAddr is the IPv6 cloud instance-metadata endpoint (the v6
// counterpart of 169.254.169.254). A guest reaching it through host
// forwarding would obtain the NODE's credentials.
const v6MetadataAddr = "fd00:ec2::254/128"

// v6MetadataComment marks the metadata drop for handle-based re-sync.
const v6MetadataComment = "sandswap-v6-metadata-deny"

// guestPrefixLen is every TAP's /64 (the subnet granularity).
const guestPrefixLen = 64

// stampPriority runs the identity SNAT ahead of the standard srcnat priority
// so operator/vendor NAT at srcnat observes identity-encoded sources.
const stampPriority = "srcnat - 5"

// metadataPriority runs the routed-IPv6 metadata drop ahead of the standard
// filter priority, so an operator/vendor forward chain at `filter` cannot
// forward a guest packet to the metadata endpoint before this drop runs.
const metadataPriority = "filter - 5"

// maxSubnetIndex bounds the 16-bit subnet index carried right after the site
// prefix (prefixes are ≤ /48).
const maxSubnetIndex = uint32(0xFFFF)

// guestMTU is the virtio-net MTU handed to every guest. Fixed (not
// configurable): it must match the host-side TAP and no scenario in this
// system needs jumbo frames.
const guestMTU = 1500

// stampState tracks the currently stamped identity per VM so unstamp knows
// exactly what to remove: the identity /128 on the TAP and the map element
// keyed by the guest's fixed all-zero boot IID (the SNAT map key).
type stampState struct {
	addr     net.IP   // identity address (SNAT target + /128 on the tap)
	guestKey [16]byte // guest boot address = SNAT map element key
	tap      string
	setID    uint32 // cached nft map set id
}

// NewRoutedIPv6 builds the provider. prefixCIDR is the routed site prefix;
// iidTemplate may be "" (stamping disabled — guests keep the fixed boot IID)
// or a parsed template ("agent:32,epoch:32" — stamping enabled; identity
// fields are pinned to exactly 32 bits, see iid.go); baseline may be nil
// (anti-spoof off — dev use only).
// SetTapOwnerUID pins the identity that will own created TAPs (the sandvmm
// uid). Called by the shared provider factory before any Provision.
func (r *RoutedIPv6) SetTapOwnerUID(uid uint32) { r.tapOwnerUID = uid }

func NewRoutedIPv6(prefixCIDR, iidTemplate string, dns []string, baseline *Baseline, logger *log.Logger) (*RoutedIPv6, error) {
	_, ipnet, err := net.ParseCIDR(prefixCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse v6 prefix %q: %w", prefixCIDR, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("prefix %q is not IPv6", prefixCIDR)
	}
	if ones%8 != 0 {
		return nil, fmt.Errorf("prefix %q: length must be a multiple of 8 bits", prefixCIDR)
	}
	// The address layout is <prefix | 16-bit subnet index | 64-bit IID>: the
	// subnet index occupies bytes [ones/8, ones/8+2) and the IID occupies
	// bytes [8, 16) (addIID writes exactly there). The two must not overlap,
	// which pins the prefix at ≤ /48 — a /56 would silently lose the subnet
	// index's low byte, a /64 or longer the whole index.
	if ones > 48 {
		return nil, fmt.Errorf("prefix %q too long: addresses are <prefix|16-bit subnet|64-bit IID>, so the prefix must be ≤ /48", prefixCIDR)
	}
	var tpl *IIDTemplate
	stamp := false
	if iidTemplate != "" {
		tpl, err = ParseIIDTemplate(iidTemplate)
		if err != nil {
			return nil, err
		}
		stamp = true
	}
	if logger == nil {
		logger = log.Default()
	}
	return &RoutedIPv6{
		prefix:      ipnet,
		dns:         dns,
		iid:         tpl,
		stamp:       stamp,
		baseline:    baseline,
		logger:      logger,
		subnets:     make(map[string]uint32),
		taps:        make(map[string]string),
		stamps:      make(map[string]*stampState),
		specs:       make(map[string]string),
		setIDs:      make(map[string]uint32),
		usedSub:     make(map[uint32]bool),
		subnetOwner: make(map[uint32]string),
	}, nil
}

// subnetIndexBytes reports where the 16-bit subnet index lives in the address.
func (r *RoutedIPv6) subnetIndexBytes() int {
	return r.prefixOnes() / 8
}

func (r *RoutedIPv6) prefixOnes() int {
	ones, _ := r.prefix.Mask.Size()
	return ones
}

// guestSubnet renders subnet index s as the /64 network for one TAP.
func (r *RoutedIPv6) guestSubnet(s uint32) *net.IPNet {
	ip := make(net.IP, net.IPv6len)
	copy(ip, r.prefix.IP.To16())
	b := r.subnetIndexBytes()
	ip[b] = byte(s >> 8)
	ip[b+1] = byte(s)
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}
}

// hostAddr is the gateway (::1) of a subnet.
func hostAddr(subnet *net.IPNet) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, subnet.IP.To16())
	ip[net.IPv6len-1] = 1
	return ip
}

// addIID returns subnet | IID.
func addIID(subnet *net.IPNet, iid uint64) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, subnet.IP.To16())
	binary.BigEndian.PutUint64(ip[8:], iid)
	return ip
}

// firstSubnet is the lowest allocatable /64 index. Index 0 is kept reserved
// so no guest subnet is the all-zero subnet of the prefix.
const firstSubnet = 1

// bootIID is the interface identifier a guest boots with, before any mount
// stamps an identity: the fixed all-zero IID. `<subnet>::` is the
// subnet-router anycast form — invalid as a unicast identity — so egress that
// never got stamped (template not configured, or a failed stamp) is
// recognizable at the policy point from the address alone; a random boot IID
// could pass for one.
const bootIID uint64 = 0

// allocateSubnet hands out the lowest free subnet index.
func (r *RoutedIPv6) allocateSubnet() (uint32, error) {
	r.allocMu.Lock()
	defer r.allocMu.Unlock()
	for s := uint32(firstSubnet); s <= maxSubnetIndex; s++ {
		if !r.usedSub[s] {
			r.usedSub[s] = true
			return s, nil
		}
	}
	return 0, fmt.Errorf("routed-ipv6: subnet space exhausted (%d /64s)", maxSubnetIndex)
}

// reserveSubnet marks s as in-use for vmID without allocating (re-adopted VMs
// re-register their surviving subnet so it is never handed out again). It
// returns false — and changes nothing — when a DIFFERENT VM already owns the
// index: two VMs sharing one /64 would make the source pins and the SNAT map
// ambiguous, and the allocator ledger would double-release it.
func (r *RoutedIPv6) reserveSubnet(vmID string, s uint32) bool {
	if s < firstSubnet {
		return false
	}
	r.allocMu.Lock()
	defer r.allocMu.Unlock()
	if owner, ok := r.subnetOwner[s]; ok && owner != vmID {
		return false
	}
	r.usedSub[s] = true
	r.subnetOwner[s] = vmID
	return true
}

// bindSubnetOwner records that the freshly allocated index s belongs to vmID
// (Provision allocates before the VM's state is registered).
func (r *RoutedIPv6) bindSubnetOwner(vmID string, s uint32) {
	r.allocMu.Lock()
	defer r.allocMu.Unlock()
	r.subnetOwner[s] = vmID
}

func (r *RoutedIPv6) releaseSubnet(s uint32) {
	r.allocMu.Lock()
	defer r.allocMu.Unlock()
	delete(r.usedSub, s)
	delete(r.subnetOwner, s)
}

// ensureRoutedTAP creates the TAP and brings it up — no bridge enslavement
// (routed model: the host routes between the /64s, it does not bridge). The
// create/MTU/up steps are ioctls on /dev/net/tun and the interface (see
// tap_linux.go); no `ip` process is spawned.
func (r *RoutedIPv6) ensureRoutedTAP(name string) error {
	if tapExistsFn(name) {
		attached, probeErr := tapHasAttachedQueueFn(name)
		if probeErr != nil {
			return fmt.Errorf("tap %s: attachment probe failed: %w", name, probeErr)
		}
		if !attached {
			// Stale TAP with no active binding — recreate it.
			if err := destroyTAP(name); err != nil {
				return fmt.Errorf("remove stale tap %s: %w", name, err)
			}
		} else {
			return nil // active TAP already exists (re-provision of live VM)
		}
	}
	owner := r.tapOwnerUID
	if owner == 0 {
		owner = uint32(os.Geteuid())
	}
	if err := createPersistentTAPFn(name, owner); err != nil {
		return err
	}
	cleanup := func() {
		if derr := deletePersistentTAPFn(name); derr != nil {
			r.logger.Printf("tap %s: cleanup after failed provision: %v", name, derr)
		}
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

// stampPlumbingBatch renders the per-TAP identity-stamp plumbing created once
// at Provision: a map guest-IID → identity address plus ONE static snat rule
// reading it. The rule matches on `iifname`, not `oifname`: the packets being
// rewritten are arriving FROM the guest TAP (`iifname` = the TAP) and leaving
// for the uplink (`oifname` = the uplink), so an `oifname "<tap>"` match would
// only ever see host→guest traffic and the identity would never reach the wire.
func stampPlumbingBatch(tapName string, subnet *net.IPNet) string {
	chain := "postrouting_" + chainNameFor(tapName)
	set := "stamp_" + chainNameFor(tapName)
	return fmt.Sprintf(
		"add table inet %s\n"+
			"add map inet %s %s { type ipv6_addr : ipv6_addr; }\n"+
			"add chain inet %s %s { type nat hook postrouting priority %s; }\n"+
			"add rule inet %s %s iifname \"%s\" ip6 saddr %s/64 snat ip6 to ip6 saddr map @%s comment \"%s\"\n",
		stampTableName, stampTableName, set, stampTableName, chain, stampPriority,
		stampTableName, chain, tapName, subnet.IP.String(), set, identityStampComment)
}

// Provision allocates a subnet, creates + addresses the TAP, and returns the
// net spec with the microVM's static IPv6 (the fixed all-zero boot IID at
// this stage — the identity is not known until mount).
func (r *RoutedIPv6) Provision(_ context.Context, vmID string) (vmm.VMNetSpec, error) {
	sub, err := r.allocateSubnet()
	if err != nil {
		return vmm.VMNetSpec{}, err
	}
	subnet := r.guestSubnet(sub)

	tapName := tapNameFor(vmID)
	if err := r.ensureRoutedTAP(tapName); err != nil {
		r.releaseSubnet(sub)
		return vmm.VMNetSpec{}, fmt.Errorf("create tap %s: %w", tapName, err)
	}
	// Static addressing: silence duplicate-address detection on this link.
	// accept_dad is read by the kernel AT ADDRESS-CREATION TIME, so this
	// sysctl must be written BEFORE the address is added — writing it after
	// cannot cancel an already-started DAD, leaving the gateway address
	// tentative (bind() → EADDRNOTAVAIL) for the ~1-2s DAD window.
	_ = writeSysctl(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", tapName), "0")
	// Host-side address on the TAP = the guest's default gateway. rtAddrAdd
	// sets IFA_F_NODAD (the same effect as `nodad`), belt to the accept_dad
	// suspend above: fresh TAPs race the sysctl write on first creation.
	idx, ierr := tapIndex(tapName)
	if ierr != nil {
		_ = destroyTAP(tapName)
		r.releaseSubnet(sub)
		return vmm.VMNetSpec{}, fmt.Errorf("ifindex %s: %w", tapName, ierr)
	}
	if err := rtAddrAdd(uint32(idx), hostAddr(subnet), 64); err != nil {
		_ = destroyTAP(tapName)
		r.releaseSubnet(sub)
		return vmm.VMNetSpec{}, fmt.Errorf("addradd %s: %w", tapName, err)
	}

	mac := randomLocalMAC()
	guestIP := addIID(subnet, bootIID)

	// Identity-stamp plumbing (static parts, provision-time / cold path):
	// a named map guest-IID -> identity address plus ONE static snat rule
	// reading it. Per-mount flips are then a single set-element add/delete
	// over netlink (nl.go) — no process spawns on the hot path.
	var stampSetID uint32
	if r.stamp {
		set := "stamp_" + chainNameFor(tapName)
		if err := runNFT(stampPlumbingBatch(tapName, subnet)); err != nil {
			_ = destroyTAP(tapName)
			r.releaseSubnet(sub)
			return vmm.VMNetSpec{}, fmt.Errorf("stamp plumbing %s: %w", tapName, err)
		}
		// Cache the kernel's set id now: it is stable until the map is deleted
		// at Release, and resolving it per mount/unmount is both a GETSET round
		// trip and a point that can contend with a previous transaction.
		id, rerr := nftResolveSetID(stampTableName, set)
		if rerr != nil {
			_ = destroyTAP(tapName)
			_ = deleteTapPlumbing(tapName)
			r.releaseSubnet(sub)
			return vmm.VMNetSpec{}, fmt.Errorf("stamp set id %s: %w", tapName, rerr)
		}
		stampSetID = id
	} // Guest→host default-deny on the v6 path: every host listener must be
	// unreachable from the guest over its TAP gateway address except the
	// resolver (and NDP/ICMPv6 errors, without which the v6 adjacency itself
	// stops working — NDP must be admitted BEFORE the drop, a missing allow
	// here is how a filter once took a whole bridge down).
	if err := ensureTapInputGuard(tapName, subnet); err != nil {
		_ = destroyTAP(tapName)
		if r.stamp {
			_ = deleteTapPlumbing(tapName)
		}
		r.releaseSubnet(sub)
		return vmm.VMNetSpec{}, fmt.Errorf("input guard %s: %w", tapName, err)
	}
	// VM-to-VM posture on the L3 path. The Baseline's bridge-family fwdgate
	// rule only matches BRIDGED frames; routed-IPv6 traffic between two TAPs
	// goes through the inet FORWARD hook and would bypass `vm_to_vm: deny`
	// entirely. Install the equivalent inet forward drop (or remove a stale
	// one when the posture is allow).
	if err := r.ensureForwardGuard(); err != nil {
		_ = destroyTAP(tapName)
		_ = deleteTapPlumbing(tapName)
		r.releaseSubnet(sub)
		return vmm.VMNetSpec{}, fmt.Errorf("forward guard %s: %w", tapName, err)
	}
	// Source anti-spoof: the soundness of "address =
	// identity". Without it a guest could source an arbitrary in-subnet
	// address that misses the SNAT map and egress unattributed.
	if r.baseline != nil {
		if err := r.baseline.AttachTap(tapName, "", guestIP.String(), mac); err != nil {
			_ = destroyTAP(tapName)
			// The plumbing created above (stamp chain/map, input guard) hooks
			// on the tap — with the tap gone it leaks (and the VM was never
			// recorded in r.taps, so Release can never clean it). Same cleanup
			// Release performs; absent chains are tolerated.
			_ = deleteTapPlumbing(tapName)
			r.releaseSubnet(sub)
			return vmm.VMNetSpec{}, fmt.Errorf("baseline attach %s: %w", tapName, err)
		}
	}

	r.mu.Lock()
	r.subnets[vmID] = sub
	r.taps[vmID] = tapName
	r.specs[vmID] = guestIP.String()
	if r.stamp {
		r.setIDs[vmID] = stampSetID
	}
	r.mu.Unlock()
	r.bindSubnetOwner(vmID, sub)

	return vmm.VMNetSpec{
		GuestIP6: guestIP.String(),
		Prefix6:  guestPrefixLen,
		Gateway6: hostAddr(subnet).String(),
		DNS:      r.dns,
		MAC:      mac,
		NetConfig: map[string]any{
			"tap": tapName,
			"mac": mac,
			"mtu": guestMTU,
		},
	}, nil
}

// Release tears down the TAP (its host address and baseline chain go with
// it) and frees the subnet.
func (r *RoutedIPv6) Release(_ context.Context, vmID string) error {
	r.unstamp(vmID)

	r.mu.Lock()
	sub, okSub := r.subnets[vmID]
	tap := r.taps[vmID]
	delete(r.subnets, vmID)
	delete(r.taps, vmID)
	delete(r.specs, vmID)
	delete(r.setIDs, vmID)
	r.mu.Unlock()

	var firstErr error
	if tap != "" {
		if err := destroyTAP(tap); err != nil {
			firstErr = err
		}
		// The TAP's plumbing (postrouting stamp chain + SNAT map + the v6
		// host-input guard chain) does NOT die with the interface: every
		// Provision creates one of each, so skipping this delete leaks a
		// hooked chain per recycled VM into the ruleset — and each leaked
		// chain still runs its (non-matching) iifname/oifname compare on
		// EVERY packet. Stamp chain first, then map (the chain's rule
		// references the map; the reverse order fails with EBUSY).
		if err := deleteTapPlumbing(tap); err != nil && firstErr == nil {
			firstErr = err
		}
		if r.baseline != nil {
			if err := r.baseline.DetachTap(tap); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	if okSub {
		r.releaseSubnet(sub)
	}
	return firstErr
}

// deleteTapPlumbing removes the per-TAP plumbing created by Provision: the
// v6 host-input guard chain, the stamp postrouting chain, and the SNAT map —
// none of it dies with the interface. Best-effort idempotent: a missing
// object (crashed prior run, stamping disabled) is not an error.
func deleteTapPlumbing(tap string) error {
	guard := "input_" + chainNameFor(tap)
	chain := "postrouting_" + chainNameFor(tap)
	set := "stamp_" + chainNameFor(tap)
	// The guard delete rides its OWN batch: a missing chain there must not
	// abort the stamp teardown in the next one.
	_ = runNFT(fmt.Sprintf("delete chain inet %s %s\n", stampTableName, guard))
	err := runNFT(fmt.Sprintf(
		"delete chain inet %s %s\ndelete map inet %s %s\n",
		stampTableName, chain, stampTableName, set))
	if err != nil && strings.Contains(err.Error(), "No such file or directory") {
		return nil // already gone (crash cleanup raced) — fine
	}
	return err
}

// ensureForwardGuard installs (or removes) the routed-IPv6 forward-hook
// posture, replaying it at every point where the ruleset may have been flushed
// or a resource re-adopted (Provision, provider construction, Reclaim):
//
//   - the metadata-endpoint drop, ALWAYS — the routed backend turns host IPv6
//     forwarding on, and without this the host's IMDSv6 would be reachable
//     from every guest through the host's egress identity. It must be in place
//     BEFORE forwarding is enabled (the provider orders it that way);
//   - the VM-to-VM deny, when the baseline is on. The Baseline's rule lives in
//     the bridge family and only sees frames a bridge forwards; each routed
//     TAP is a standalone L3 interface, so guest→guest traffic is forwarded by
//     the host's IP stack and would bypass it.
func (r *RoutedIPv6) ensureForwardGuard() error {
	if err := ensureRouted6MetadataGuard(); err != nil {
		return err
	}
	if r.baseline == nil {
		// Explicit egress_baseline: off — the operator accepted per-VM-only
		// isolation; do not invent a second posture.
		return nil
	}
	return syncRouted6ForwardGuard(r.baseline.VMToVMDeny())
}

// ensureRouted6MetadataGuard converges the routed-IPv6 metadata drop. Like the
// VM-to-VM posture it is re-synced (not merely added): nftables does not dedupe
// identical rules, and the drop must exist even on a host whose prep only
// installed the v4 guards (host prep cannot see the sandlot's backend at boot).
// The delete+add runs in ONE transaction so the endpoint is never reachable
// through the window between two nft invocations.
func ensureRouted6MetadataGuard() error {
	if err := runNFT(fmt.Sprintf("add table inet %s\n", stampTableName)); err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("create routed6 table: %w", err)
	}
	if err := runNFT(fmt.Sprintf(
		"add chain inet %s %s { type filter hook forward priority %s; policy accept; }\n",
		stampTableName, routed6MetadataChain, metadataPriority)); err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("create routed6 metadata chain: %w", err)
	}
	if err := convergeRuleByComment("inet", stampTableName, routed6MetadataChain, v6MetadataComment, fmt.Sprintf(
		"add rule inet %s %s ip6 daddr %s counter drop comment \"%s\"\n",
		stampTableName, routed6MetadataChain, v6MetadataAddr, v6MetadataComment)); err != nil {
		return fmt.Errorf("converge routed6 metadata drop rule: %w", err)
	}
	return nil
}

// syncRouted6ForwardGuard converges the routed-IPv6 VM-to-VM posture in the
// routed6 table's inet FORWARD chain. Called from the RoutedIPv6 provider and
// from Baseline.SetVMToVMDeny, so a runtime posture flip covers BOTH the
// bridge-family rule and this chain.
func syncRouted6ForwardGuard(deny bool) error {
	// Table and chain are separate batches: in ONE batch a failing `add table`
	// aborts the chain creation too, and an existing table (any TAP's stamp
	// plumbing creates it) is the common case. EEXIST is expected in both.
	if err := runNFT(fmt.Sprintf("add table inet %s\n", stampTableName)); err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("create routed6 table: %w", err)
	}
	if err := runNFT(fmt.Sprintf(
		"add chain inet %s %s { type filter hook forward priority filter; policy accept; }\n",
		stampTableName, routed6ForwardChain)); err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("create routed6 forward guard chain: %w", err)
	}
	addRule := ""
	if deny {
		addRule = fmt.Sprintf(
			"add rule inet %s %s iifname \"tap*\" oifname \"tap*\" counter drop comment \"%s\"\n",
			stampTableName, routed6ForwardChain, vm2vmComment)
	}
	// One transaction: the allow posture removes a previous deny rule, the deny
	// posture replaces the old rule with exactly one — never delete-then-add in
	// two transactions (the window between them is fail-open).
	if err := convergeRuleByComment("inet", stampTableName, routed6ForwardChain, vm2vmComment, addRule); err != nil {
		return fmt.Errorf("converge routed6 forward vm2vm rule: %w", err)
	}
	return nil
}

// ensureTapInputGuard installs the per-TAP guest→host default-deny: NDP/router
// discovery, ICMPv6 echo and path errors stay reachable (without NDP the TAP
// adjacency itself breaks — the allows must precede the drop; echo keeps the
// adjacency debuggable), established/related replies flow, the resolver port is
// open — and everything else arriving on THIS TAP is dropped.
//
// The final rule matches by INTERFACE, not by the guest's source prefix: an
// `ip6 saddr <subnet>/64` match lets a forged source outside the /64 through
// (the guest kernel has CAP_NET_RAW once compromised; the agent does not).
// `iifname` covers both families and every source address. Forwarded traffic
// (guest egress, the identity stamp path) never traverses input, so it is
// unaffected.
//
// Convergence is ONE transaction: a `flush chain` plus the rules in the same
// nft batch. The previous delete-chain-then-add sequence left a window in
// which a re-adopted, live guest could reach every host listener — and when
// the add failed, the guard stayed gone. flush chain removes the rules but
// keeps the chain (and its hook), so the table/chain creation below is a
// separate idempotent step.
func ensureTapInputGuard(tapName string, _ *net.IPNet) error {
	guard := "input_" + chainNameFor(tapName)
	if err := runNFT(fmt.Sprintf("add table inet %s\n", stampTableName)); err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("add table inet %s: %w", stampTableName, err)
	}
	if err := runNFT(fmt.Sprintf(
		"add chain inet %s %s { type filter hook input priority filter; }\n",
		stampTableName, guard)); err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("add chain inet %s %s: %w", stampTableName, guard, err)
	}
	batch := fmt.Sprintf(
		"flush chain inet %s %s\n"+
			"add rule inet %s %s iifname \"%s\" icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, echo-request, echo-reply, packet-too-big, destination-unreachable, time-exceeded } counter accept\n"+
			"add rule inet %s %s iifname \"%s\" ct state established,related accept\n"+
			"add rule inet %s %s iifname \"%s\" udp dport 53 accept\n"+
			"add rule inet %s %s iifname \"%s\" tcp dport 53 accept\n"+
			"add rule inet %s %s iifname \"%s\" counter drop\n",
		stampTableName, guard,
		stampTableName, guard, tapName,
		stampTableName, guard, tapName,
		stampTableName, guard, tapName,
		stampTableName, guard, tapName,
		stampTableName, guard, tapName)
	if err := runNFT(batch); err != nil {
		return fmt.Errorf("converge input guard %s: %w", tapName, err)
	}
	return nil
}

// Reclaim re-registers a re-adopted VM's still-live subnet/TAP without
// touching host devices (same contract as BridgeNAT.Reclaim). The subnet is
// RESERVED in the allocator: fresh Provision must never double-assign the
// subnet of a VM that survived a sandlot restart.
func (r *RoutedIPv6) Reclaim(_ context.Context, vmID string, spec vmm.VMNetSpec) error {
	guest := net.ParseIP(spec.GuestIP6).To16()
	if guest == nil {
		return fmt.Errorf("reclaim %s: invalid guest v6 %q", vmID, spec.GuestIP6)
	}
	if !sameNetwork(guest, r.prefix.IP.To16(), r.prefixOnes()) {
		return fmt.Errorf("reclaim %s: guest %s outside site prefix %s", vmID, guest, r.prefix.String())
	}
	b := r.subnetIndexBytes()
	sub := uint32(guest[b])<<8 | uint32(guest[b+1])
	tap, _ := spec.NetConfig["tap"].(string)

	// The tap is destroyed as root by Release (`ip link del`), so only
	// this VM's own derived name may be re-registered. The subnet reservation
	// below still happens for a refused foreign tap — it is the collision
	// ledger the re-adopt path depends on (refusing before it would let a
	// fresh Provision double-assign the survivor's subnet); the REFUSAL is
	// what keeps the tap out of r.taps, and the named error is returned.
	tapErr := checkReclaimTap(vmID, tap)

	if !r.reserveSubnet(vmID, sub) {
		return fmt.Errorf("reclaim %s: subnet %s is already reserved by another VM", vmID, r.guestSubnet(sub).String())
	}

	r.mu.Lock()
	r.subnets[vmID] = sub
	if tap != "" && tapErr == nil {
		r.taps[vmID] = tap
		if r.specs[vmID] == "" {
			r.specs[vmID] = guest.String()
		}
		if r.stamp {
			if id, rerr := nftResolveSetID(stampTableName, "stamp_"+chainNameFor(tap)); rerr == nil {
				r.setIDs[vmID] = id
			} else {
				r.logger.Printf("routed6 reclaim %s: stamp set id: %v", vmID, rerr)
			}
		}
	}
	r.mu.Unlock()

	if tapErr != nil {
		return tapErr
	}

	// Replay the routed posture. A re-adopted VM inherited whatever ruleset
	// survived the restart: the nftables table (and with it the VM-to-VM deny
	// and the per-TAP anti-spoof/input chains) may have been flushed while the
	// VM kept running, so steering back to it without re-installing the
	// posture would let tenants reach each other and spoof sources. The
	// forward guard is global and always re-synced; the per-TAP chains exist
	// only when the TAP still does (a missing TAP means the VM is offline and
	// its chains have nothing to filter).
	if err := r.ensureForwardGuard(); err != nil {
		return fmt.Errorf("reclaim %s: replay forward guard: %w", vmID, err)
	}
	if tap != "" && tapExistsFn(tap) {
		subnet := r.guestSubnet(sub)
		mac, _ := spec.NetConfig["mac"].(string)
		if r.baseline != nil {
			if err := r.baseline.AttachTap(tap, "", guest.String(), mac); err != nil {
				return fmt.Errorf("reclaim %s: replay anti-spoof: %w", vmID, err)
			}
		}
		if err := ensureTapInputGuard(tap, subnet); err != nil {
			return fmt.Errorf("reclaim %s: replay input guard: %w", vmID, err)
		}
	} else if tap != "" {
		r.logger.Printf("routed6 reclaim %s: tap %s missing on host (VM offline)", vmID, tap)
	}
	return nil
}

// SetMountState implements vmm.MountGater. Mount-open is handled by
// SetMountIdentity (needs the binding); unmount removes any stamp.
func (r *RoutedIPv6) SetMountState(_ context.Context, vmID string, mounted bool) {
	if mounted {
		return
	}
	r.unstamp(vmID)
}

// SetMountIdentity implements vmm.IdentityStamper: add the identity-encoded
// address + SNAT element for this mount. It runs SYNCHRONOUSLY inside the
// mount call (after the binding-region publish): InterfaceByName + RTM_NEWADDR
// + one set-element add, measured sub-ms on a nested host; every receive is
// deadline-bounded, no process spawn, no unbounded wait. Any failure degrades to unstamped egress
// (the region stays authoritative; enforcement points default-deny unknown
// addresses) and never disturbs the mount.
func (r *RoutedIPv6) SetMountIdentity(_ context.Context, vmID, agentID, sandfsID string, epoch uint64) {
	if !r.stamp {
		return
	}
	r.mu.Lock()
	sub, okSub := r.subnets[vmID]
	tap := r.taps[vmID]
	prev := r.stamps[vmID]
	guestIPStr := r.specs[vmID] // read under mu: Release deletes concurrently
	setID := r.setIDs[vmID]
	r.mu.Unlock()
	if !okSub || tap == "" {
		return
	}
	setName := "stamp_" + chainNameFor(tap)
	if setID == 0 {
		// Re-adopted/legacy VM: resolve once and cache. The set id is stable
		// for the map's lifetime; the per-mount path then never resolves.
		id, rerr := nftResolveSetID(stampTableName, setName)
		if rerr != nil {
			r.logger.Printf("routed6 stamp %s: set id: %v", vmID, rerr)
			return
		}
		setID = id
		r.mu.Lock()
		if r.setIDs[vmID] == 0 {
			r.setIDs[vmID] = setID
		}
		r.mu.Unlock()
	}
	if prev != nil {
		r.unstampElem(tap, prev)
	}
	iid, err := r.iid.Build(agentID, sandfsID, epoch)
	if err != nil {
		r.logger.Printf("routed6 stamp %s: build iid: %v", vmID, err)
		return
	}
	addr := addIID(r.guestSubnet(sub), iid)
	// Guest fixed all-zero boot-IID address (the SNAT map key) — fixed at provision.
	guestIP := net.ParseIP(guestIPStr).To16()
	if guestIP == nil {
		r.logger.Printf("routed6 stamp %s: guest iid missing", vmID)
		return
	}
	var guestKey [16]byte
	copy(guestKey[:], guestIP)

	// 1. Assign the identity address on the TAP (host side; /128 secondary)
	//    via rtnetlink — ~tens of µs, no process spawn.
	iface, ierr := net.InterfaceByName(tap)
	if ierr != nil {
		r.logger.Printf("routed6 stamp %s: tap: %v", vmID, ierr)
		return
	}
	if err := rtAddrAdd(uint32(iface.Index), addr, 128); err != nil {
		r.logger.Printf("routed6 stamp %s: addr add: %v", vmID, err)
		return
	}
	// 2. Flip the SNAT map element guest-IID -> identity (nfnetlink
	//    NFT_MSG_NEWSETELEM). The rule itself is static (provisioned).
	if err := nftSetElemAddID(stampTableName, setName, setID, guestKey[:], addr.To16()); err != nil {
		r.logger.Printf("routed6 stamp %s: snat element: %v", vmID, err)
		if iface.Index > 0 {
			_ = rtAddrDel(uint32(iface.Index), addr, 128)
		}
		return
	}
	r.mu.Lock()
	r.stamps[vmID] = &stampState{addr: addr, guestKey: guestKey, tap: tap, setID: setID}
	r.mu.Unlock()
}

// unstampElem removes a previous stamp's tap address + map element (used on
// rebind before publishing the new identity).
func (r *RoutedIPv6) unstampElem(tap string, prev *stampState) {
	iface, err := net.InterfaceByName(tap)
	if err != nil {
		return // TAP already gone: its address and map died with it
	}
	_ = rtAddrDel(uint32(iface.Index), prev.addr, 128)
	if err := nftSetElemDelID(stampTableName, "stamp_"+chainNameFor(tap), prev.setID, prev.guestKey[:]); err != nil {
		r.logger.Printf("routed6 restamp %s: clear old element: %v", tap, err)
	}
}

// unstamp removes any identity stamp for a VM (unmount/destroy path).
func (r *RoutedIPv6) unstamp(vmID string) {
	r.mu.Lock()
	prev := r.stamps[vmID]
	delete(r.stamps, vmID)
	r.mu.Unlock()
	if prev == nil {
		return
	}
	iface, err := net.InterfaceByName(prev.tap)
	if err != nil {
		return // TAP already gone: its address and map died with it
	}
	_ = rtAddrDel(uint32(iface.Index), prev.addr, 128)
	if err := nftSetElemDelID(stampTableName, "stamp_"+chainNameFor(prev.tap), prev.setID, prev.guestKey[:]); err != nil {
		r.logger.Printf("routed6 unstamp %s: %v", vmID, err)
	}
}

func sameNetwork(a, b net.IP, ones int) bool {
	mask := net.CIDRMask(ones, 128)
	return a.Mask(mask).Equal(b.Mask(mask))
}

func writeSysctl(path, val string) error {
	return os.WriteFile(path, []byte(val+"\n"), 0o644)
}
