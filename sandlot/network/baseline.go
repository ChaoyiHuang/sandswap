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
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"sandlot/hostbin"
)

// Baseline implements the egress network baseline from
// docs/how-it-works/egress-enabler.md: the host-side isolation primitives that
// make a VM's TAP a valid identity anchor. It carries NO policy semantics and
// NO per-mount work — everything here is installed per TAP at Provision and
// removed at Release (both cold paths):
//
//  1. source-address anti-spoof: only the assigned guest address may leave
//     the TAP — the precondition for "address = identity";
//  2. VM-to-VM isolation at the bridge (deny by default, configurable).
//
// "Unmounted VMs have no egress" — a contract guarantee — is enforced by the process
// model, not by nftables: guest processes exist only between mount and
// unmount (cgroup.kill clears them at unmount), a stale-mount VM is
// destroyed (killing the TAP with it), and pool VMs have nothing to emit
// with. Keeping the baseline static is deliberate: a per-mount nftables
// flip measured +1.2ms on the switch hot path and left a first-packet race —
// hot-path purity (contract red line 1) wins.
type Baseline struct {
	vmToVMDeny bool

	// Bridge-backend L3 guard. The bridge-family forward rule matches only
	// L2-bridged frames; a guest frame addressed to the HOST's MAC with a
	// destination in another guest's IP is routed by the host and comes back
	// out the bridge, bypassing that rule. l3Subnet/l3Bridge describe the
	// inet forward drop that closes the routed path (empty = not configured).
	l3Subnet string
	l3Bridge string
	l3Family string // "ip" or "ip6"

	// routed6 marks this baseline as backing the routed-IPv6 backend, whose
	// VM-to-VM posture lives in a separate inet-forward chain (the bridge
	// family rule never sees L3-routed traffic). Set once at provider
	// construction; guarded by mu like the rest of the posture state.
	routed6 bool

	// hostInputBridge is the sandbox bridge whose guest→host input guard host
	// prep installs (empty = no bridge backend was configured). Every
	// AttachTap re-verifies the guard's hook shape and terminal drop, so a
	// runtime flush of the host input chain fails provisioning instead of
	// silently exposing host listeners for the VM's whole life.
	hostInputBridge string

	// mu serializes nftables mutations (AttachTap's refresh path and
	// SetVMToVMDeny's posture swap must not interleave).
	mu sync.Mutex
}

// NewBaseline creates a Baseline manager. vmToVMDeny selects the VM-to-VM
// posture (contract default: deny).
func NewBaseline(vmToVMDeny bool) *Baseline {
	return &Baseline{vmToVMDeny: vmToVMDeny}
}

const (
	baseTableNetdev = "sandswap_baseline"
	baseTableBridge = "sandswap_baseline"
	baseTableInet   = "sandswap_baseline"
	vm2vmComment    = "sandswap-vm2vm-deny"
	vm2vmL3Comment  = "sandswap-vm2vm-l3-deny"

	// baselinePriority runs the anti-spoof chains ahead of the standard
	// filter priority: source spoofing is dropped before any operator- or
	// vendor-installed filter chain at `filter` ever sees the frame.
	baselinePriority = "filter - 5"

	// v4MetadataDropRule drops the cloud instance-metadata endpoints at every
	// guest TAP ingress. The range is IPv4 link-local (AWS/Azure/GCP IMDS and
	// the ECS task endpoint); 100.100.100.200 is Alibaba Cloud's IMDS and
	// 169.254.170.2 the ECS credentials endpoint. A guest that reaches any of
	// them through host forwarding obtains the NODE's credentials. Host prep
	// carries the same drop in the shared forward chain; this per-TAP rule is
	// the sandlot-side depth that does not depend on host prep having run.
	v4MetadataDropRule = `ip daddr { 169.254.0.0/16, 100.100.100.200, 169.254.170.2 } counter drop`
)

// chainNameFor maps a TAP device name to a valid nftables chain identifier.
// nft identifiers accept only [a-zA-Z0-9_]; TAP names contain hyphens, and
// quoted identifiers are not accepted in the table-block syntax.
func chainNameFor(tapName string) string {
	return strings.ReplaceAll(tapName, "-", "_")
}

// runNFT executes an nft batch from stdin. A package-level var (not a func)
// so tests can drive the EEXIST-recovery path deterministically without nft.
var runNFT = func(batch string) error {
	nft := hostbin.Path("nft")
	if nft == "" {
		return fmt.Errorf("nft not found at any absolute candidate path")
	}
	cmd := exec.Command(nft, "-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft batch: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnsureTables creates (idempotently) the baseline tables and the VM-to-VM
// forward rule. Called before any TAP is attached (and safe to re-call when
// the posture changes).
func (b *Baseline) EnsureTables() error {
	if err := runNFT(fmt.Sprintf("table netdev %s {}\n", baseTableNetdev)); err != nil {
		return fmt.Errorf("baseline: netdev table: %w", err)
	}
	if err := runNFT(fmt.Sprintf(`
table bridge %s {
	chain fwdgate {
		type filter hook forward priority filter; policy accept;
	}
}
`, baseTableBridge)); err != nil {
		return fmt.Errorf("baseline: bridge table: %w", err)
	}
	if err := b.ensureL3Table(); err != nil {
		return err
	}
	return b.syncVMToVMRuleLocked()
}

// SetL3Guard configures the inet-forward half of the VM-to-VM posture for the
// bridge backend: traffic from the guest subnet to the same subnet that the
// host ROUTES (instead of bridging) is dropped when the posture is deny. The
// subnet and bridge are validated here because both are interpolated into an
// nft batch.
func (b *Baseline) SetL3Guard(subnet, bridge string) error {
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("baseline: l3 guard subnet %q: %w", subnet, err)
	}
	if bridge == "" || len(bridge) > 64 || strings.ContainsAny(bridge, " \t\r\n\"';{}") {
		return fmt.Errorf("baseline: l3 guard bridge name %q is not a plain interface name", bridge)
	}
	family := "ip"
	if ip.To4() == nil {
		family = "ip6"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.l3Subnet = ipnet.String()
	b.l3Bridge = bridge
	b.l3Family = family
	b.hostInputBridge = bridge
	if err := b.ensureL3Table(); err != nil {
		return err
	}
	return b.syncVMToVMRuleLocked()
}

// ensureL3Table creates the inet table/chain used by the routed-path guard.
// A no-op when no L3 guard is configured. Caller holds b.mu (or is the
// single-threaded startup path).
func (b *Baseline) ensureL3Table() error {
	if b.l3Subnet == "" {
		return nil
	}
	if err := runNFT(fmt.Sprintf(`
table inet %s {
	chain fwdgate {
		type filter hook forward priority filter; policy accept;
	}
}
`, baseTableInet)); err != nil {
		return fmt.Errorf("baseline: inet table: %w", err)
	}
	return nil
}

// syncVMToVMRule matches both forward chains to the configured posture. The
// caller must hold b.mu (AttachTap's path) or be the single-threaded startup
// path. The bridge rule covers L2-bridged frames; the inet rule (when an L3
// guard is configured) covers frames the host ROUTES between two guests.
//
// nftables does NOT dedupe identical rules, so a plain "add" would stack one
// copy per EnsureTables call (every TAP attach). Convergence therefore deletes
// the rules carrying the comment and re-adds the posture in ONE transaction:
// the old rule is never gone while the new one is absent.
func (b *Baseline) syncVMToVMRuleLocked() error {
	bridgeRule := ""
	if b.vmToVMDeny {
		bridgeRule = fmt.Sprintf("add rule bridge %s fwdgate iifname \"tap*\" oifname \"tap*\" counter drop comment \"%s\"\n", baseTableBridge, vm2vmComment)
	}
	if err := convergeRuleByComment("bridge", baseTableBridge, "fwdgate", vm2vmComment, bridgeRule); err != nil {
		return fmt.Errorf("baseline: vm2vm deny rule: %w", err)
	}

	// Routed-path half (bridge backend only; empty when not configured).
	if b.l3Subnet == "" {
		return nil
	}
	l3Rule := ""
	if b.vmToVMDeny {
		l3Rule = fmt.Sprintf(
			"add rule inet %s fwdgate iifname \"%s\" oifname \"%s\" %s saddr %s %s daddr %s counter drop comment \"%s\"\n",
			baseTableInet, b.l3Bridge, b.l3Bridge, b.l3Family, b.l3Subnet, b.l3Family, b.l3Subnet, vm2vmL3Comment,
		)
	}
	if err := convergeRuleByComment("inet", baseTableInet, "fwdgate", vm2vmL3Comment, l3Rule); err != nil {
		return fmt.Errorf("baseline: vm2vm L3 deny rule: %w", err)
	}
	return nil
}

// AttachTap installs a TAP's baseline: a per-TAP netdev ingress chain
// (policy accept) whose rules drop any frame whose L2 or L3 source is not
// the assigned one. ip4/ip6 may be empty (address not assigned); mac must
// be the guest NIC's MAC (both backends generate it at Provision, right
// where this is called).
func (b *Baseline) AttachTap(tapName, ip4, ip6, mac string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.EnsureTables(); err != nil {
		return err
	}
	// Runtime re-check of the host-side guest→host input guard (startup alone
	// cannot see a later flush of the host chain). A missing hook shape or
	// terminal drop fails provisioning: serving a TAP while every host
	// listener is tenant-reachable is worse than refusing the cold path.
	if b.hostInputBridge != "" {
		if err := VerifyHostInputGuard(b.hostInputBridge); err != nil {
			return err
		}
	}
	return b.attachTapChainLocked(chainNameFor(tapName), tapName, ip4, ip6, mac)
}

// validMAC accepts exactly six lowercase-or-uppercase hex pairs joined by
// colons. The MAC is interpolated into an nft batch, so anything looser is
// a template-injection channel.
func validMAC(mac string) bool {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		for _, c := range []byte(p) {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// attachTapChainLocked builds and installs the per-TAP netdev chain. Caller
// holds b.mu. Extracted from AttachTap so the EEXIST-recovery path is unit-
// testable without nftables on the host.
//
// Anti-spoof layers, in order:
//   - ether saddr: the L2 identity. The IP rules below never see non-IP
//     frames (ARP carries no IP header), so without this rule a guest could
//     emit frames with a co-tenant's (or the bridge's) source MAC — poisoning
//     the bridge FDB redirects host-to-guest unicast for the victim onto this
//     TAP. The VM-to-VM deny covers tap→tap forwarding only, never the
//     host→tap direction such a poisoning attacks.
//   - arp saddr ether/ip: the ARP payload mirrors both identities. A forged
//     ARP reply claiming the co-tenant's IP would otherwise redirect the
//     HOST's neighbor resolution for that IP onto this guest's MAC (the
//     kernel resists unsolicited updates on REACHABLE entries, but an
//     INCOMPLETE-resolution race is first-reply-wins).
//   - ip/ip6 saddr: the routed-identity pins (the original baseline).
func (b *Baseline) attachTapChainLocked(chain, tapName, ip4, ip6, mac string) error {
	if mac != "" && !validMAC(mac) {
		return fmt.Errorf("baseline: tap %s mac %q is not a valid colon-hex MAC — refusing to interpolate it into an nft batch", tapName, mac)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "table netdev %s {\n\tchain %s {\n\t\ttype filter hook ingress device \"%s\" priority %s; policy accept;\n", baseTableNetdev, chain, tapName, baselinePriority)
	// EXPLICIT ethertype whitelist, first: the L3 source rules below only see
	// plain IP/ARP frames. VLAN-tagged (0x8100) and QinQ (0x88a8/0x8100)
	// frames carry the tenant's L3 header behind a tag the address rules never
	// match, so a guest with CAP_NET_ADMIN (guest-kernel class) could bypass
	// the source pins entirely. Only untagged IPv4/IPv6/ARP pass.
	fmt.Fprintf(&sb, "\t\tether type != { ip, arp, ip6 } counter drop\n")
	// Cloud instance metadata is never a legitimate guest destination, and
	// reaching it through host forwarding hands the guest the NODE's
	// credentials. Host prep drops it in the shared forward chain; this
	// per-TAP drop is the sandlot-side depth for a host whose prep did not run
	// (or whose shared chain was flushed).
	fmt.Fprintf(&sb, "\t\t%s\n", v4MetadataDropRule)
	if mac != "" {
		fmt.Fprintf(&sb, "\t\tether saddr != %s counter drop\n", mac)
		// No `meta nfproto arp` guard here: netdev-family chains reject it
		// (inet-only), and the arp payload expressions only ever match ARP
		// frames on their own.
		fmt.Fprintf(&sb, "\t\tarp saddr ether != %s counter drop\n", mac)
	}
	if ip4 != "" {
		fmt.Fprintf(&sb, "\t\tip saddr != %s counter drop\n", ip4)
		fmt.Fprintf(&sb, "\t\tarp saddr ip != %s counter drop\n", ip4)
	} else {
		// Routed-IPv6 backend: no IPv4 identity is pinned for this guest, so
		// any IPv4/ARP frame would be an unattributable source. Drop both —
		// the whitelist above admits them only for the v4-backed bridge.
		fmt.Fprintf(&sb, "\t\tether type ip counter drop\n")
		fmt.Fprintf(&sb, "\t\tether type arp counter drop\n")
	}
	if ip6 != "" {
		fmt.Fprintf(&sb, "\t\tip6 saddr != %s counter drop\n", ip6)
	} else {
		// No IPv6 identity is pinned in this backend (the bridge/NAT backend
		// is IPv4-only). Drop every IPv6 frame at the tap: without a pinned
		// source the guest could spoof any v6 address, and Carrier B
		// (routed-ipv6) is the supported way to give a guest v6. `ether type`
		// is the netdev-family-safe matcher (meta nfproto is inet-only here).
		fmt.Fprintf(&sb, "\t\tether type ip6 counter drop\n")
	}
	sb.WriteString("\t}\n}\n")
	if err := runNFT(sb.String()); err != nil {
		// A chain left over from a crashed previous run of the same vmID
		// already exists — delete it and replay the same batch. The retry is
		// inline, NOT a recursive AttachTap call: b.mu is a non-reentrant
		// sync.Mutex already held here, and the old recursion self-deadlocked
		// on this very path (every subsequent AttachTap — i.e. all network
		// provisioning — then wedged forever). Note the delete-then-replay
		// (not flush-then-replay): the batch's `chain … { … }` declaration is
		// an ADD, which would hit EEXIST again on a merely flushed chain.
		if strings.Contains(err.Error(), "exists") {
			if err := runNFT(fmt.Sprintf("delete chain netdev %s %s\n", baseTableNetdev, chain)); err != nil {
				return err
			}
			return runNFT(sb.String())
		}
		return err
	}
	return nil
}

// DetachTap removes the TAP's baseline chain (TAP destroyed).
func (b *Baseline) DetachTap(tapName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	err := runNFT(fmt.Sprintf("delete chain netdev %s %s\n", baseTableNetdev, chainNameFor(tapName)))
	if err != nil && strings.Contains(err.Error(), "No such file or directory") {
		return nil // chain already gone (crash cleanup raced) — fine
	}
	return err
}

// SetRouted6Posture declares that this baseline backs the routed-IPv6 backend,
// so every posture sync also converges the routed6 table's inet forward chain.
// Called by the shared provider factory after construction, before any TAP is
// attached.
func (b *Baseline) SetRouted6Posture() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.routed6 = true
}

// VMToVMDeny reports the current guest-to-guest posture. The routed-IPv6
// backend needs it to install the SAME posture in the inet forward hook: the
// bridge-family rule this type installs never sees L3-routed traffic.
func (b *Baseline) VMToVMDeny() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.vmToVMDeny
}

// SetVMToVMDeny updates the VM-to-VM posture at runtime. With the routed-IPv6
// backend the flip must also reach the routed6 inet-forward chain: its TAPs are
// standalone L3 interfaces, so the bridge-family rule never sees their traffic.
// The per-provision EnsureTables/AttachTap path deliberately does NOT sync the
// routed6 chain — the RoutedIPv6 provider owns that convergence — so a posture
// change is the only place both chains must move together.
func (b *Baseline) SetVMToVMDeny(deny bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.vmToVMDeny = deny
	if err := b.syncVMToVMRuleLocked(); err != nil {
		return err
	}
	if b.routed6 {
		return syncRouted6ForwardGuard(deny)
	}
	return nil
}

// ruleHandlesByComment returns the handle numbers of every rule in a chain
// carrying the given comment. A chain that does not exist (yet) is an empty
// set, never an error: EnsureTables runs before every sync, but a first-ever
// convergence on a fresh host must not fail on the missing-chain read.
func ruleHandlesByComment(family, table, chain, comment string) ([]string, error) {
	out, err := nftListChain(family, table, chain)
	if err != nil {
		if strings.Contains(err.Error(), "No such file or directory") {
			return nil, nil
		}
		return nil, err
	}
	var handles []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `comment "`+comment+`"`) {
			continue
		}
		if h := ruleHandle(line); h != "" {
			handles = append(handles, h)
		}
	}
	return handles, nil
}

// convergeRuleByComment converges a chain to one posture: every existing rule
// carrying the comment is deleted and addRule (when non-empty) is appended, in
// ONE nft batch. The previous delete-then-add sequence ran two transactions,
// leaving a fail-open window between them (and, when the add failed, leaving
// the rule gone for the VM's whole life). An empty addRule is the allow
// posture: delete only.
func convergeRuleByComment(family, table, chain, comment, addRule string) error {
	// The nft baseline tables are HOST-wide: colocated sandlot instances
	// converge the same chains. Serialize the LIST + batch on the shared
	// runtime directory so two instances cannot delete each other's handles
	// between them. Directory flock needs no write access; if the directory is
	// unavailable the convergence proceeds unserialized.
	if lockDir, err := os.Open("/run/sandswap"); err == nil {
		_ = unix.Flock(int(lockDir.Fd()), unix.LOCK_EX)
		defer func() {
			_ = unix.Flock(int(lockDir.Fd()), unix.LOCK_UN)
			_ = lockDir.Close()
		}()
	}
	handles, err := ruleHandlesByComment(family, table, chain, comment)
	if err != nil {
		return fmt.Errorf("list chain %s %s %s: %w", family, table, chain, err)
	}
	var sb strings.Builder
	for _, h := range handles {
		fmt.Fprintf(&sb, "delete rule %s %s %s handle %s\n", family, table, chain, h)
	}
	sb.WriteString(addRule)
	if sb.Len() == 0 {
		return nil
	}
	return runNFT(sb.String())
}

// ruleHandle extracts the `handle N` token from an `nft -a list chain` line.
func ruleHandle(line string) string {
	const marker = "handle "
	i := strings.LastIndex(line, marker)
	if i < 0 {
		return ""
	}
	rest := line[i+len(marker):]
	if j := strings.IndexAny(rest, " \t"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// VMToVMPolicy renders the effective guest-to-guest posture for logs: the
// config value is deny-by-absence, and "deny" reads better than "".
func VMToVMPolicy(v string) string {
	if v == "allow" {
		return "allow"
	}
	return "deny"
}
