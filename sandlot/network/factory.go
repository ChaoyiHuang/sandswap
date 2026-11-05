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
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	sandlotconfig "sandlot/config"
	"sandlot/hostbin"
	"sandlot/vmm"
)

// BuildProvider constructs the outbound-networking provider from the network
// config: the egress baseline (when enabled and nftables is available) plus
// the bridge-nat or routed-ipv6 backend. Shared by sandlot's embedded mode and
// the boxout sidecar (the two privileged sides).
//
// The caller owns any preflight beyond construction: sandlot's embedded mode
// additionally verifies bridge readiness (CheckBridgeReady) before serving;
// boxout provisions the bridge itself and does not preflight.
// tapOwnerUID is the sandvmm identity: every TAP is created owned by it so the
// VMM can attach to the pre-created persistent TAP with zero capabilities
// (TUNSETIFF admits an owner match without CAP_NET_ADMIN). 0 = no identity
// transition (the VMM runs as the caller's identity and keeps its caps).
func BuildProvider(cfg sandlotconfig.NetworkConfig, tapOwnerUID uint32, logger *log.Logger) (vmm.NetworkProvider, error) {
	switch cfg.Backend {
	case "", "none":
		logger.Printf("network backend: none (offline)")
		return NewNoop(), nil

	case "bridge", "routed-ipv6":
		// Egress network baseline (source anti-spoof + VM-to-VM posture):
		// on by default (isolation primitives, not policy), and FAIL-CLOSED —
		// every tenant TAP shares one L2 bridge, so a node that ran without
		// the baseline would leave tenants able to ARP-poison and directly
		// attack each other's guest network stacks. A missing `nft` or a
		// failing EnsureTables therefore refuses to start the node; the only
		// sanctioned way to run without the baseline is an explicit
		// `egress_baseline: off` (or `network.backend: none`, which has no
		// guest network at all). Shared by both networking backends — the
		// routed backend needs the per-tap anti-spoof just as much as the
		// bridge one.
		var baseline *Baseline
		if cfg.EgressBaseline != "" && cfg.EgressBaseline != "on" && cfg.EgressBaseline != "off" {
			// A typo (`On`) used to fall through to "no baseline" SILENTLY,
			// dropping source anti-spoof + VM-to-VM isolation on a bridge or
			// routed host. Refuse instead: this is an isolation primitive, not
			// policy (see the comment above).
			return nil, fmt.Errorf("network.egress_baseline %q: must be \"on\" or \"off\"", cfg.EgressBaseline)
		}
		if cfg.EgressBaseline == "" || cfg.EgressBaseline == "on" {
			if hostbin.Path("nft") == "" {
				return nil, fmt.Errorf(
					"network.egress_baseline on: nftables not found — the per-TAP source anti-spoof and VM-to-VM isolation cannot be enforced on the shared bridge; install nftables (apt install nftables), or set network.egress_baseline: off explicitly to accept an isolated-per-VM-only deployment",
				)
			}
			baseline = NewBaseline(cfg.VMToVM != "allow")
			if err := baseline.EnsureTables(); err != nil {
				return nil, fmt.Errorf(
					"network.egress_baseline on: nftables baseline tables could not be installed (%v) — refusing to run without per-TAP source anti-spoof and VM-to-VM isolation; fix nftables on this host or set network.egress_baseline: off explicitly",
					err,
				)
			}
			logger.Printf("egress baseline: on (vm-to-vm=%s)", VMToVMPolicy(cfg.VMToVM))
		} else {
			logger.Printf("WARNING: network.egress_baseline is OFF — per-VM isolation only; per-TAP source anti-spoof, VM-to-VM deny and the guest→host input guard are NOT enforced")
		}
		if cfg.Backend == "bridge" {
			// The bridge-family forward rule only sees L2-bridged frames; a
			// guest frame addressed to the host's MAC with another guest's IP
			// is routed by the host and bypasses it. Install the equivalent
			// inet-forward drop for the routed path (same posture).
			if baseline != nil {
				if err := baseline.SetL3Guard(cfg.Subnet, cfg.Bridge); err != nil {
					return nil, fmt.Errorf("network backend bridge: %w", err)
				}
			}
			bn, err := NewBridgeNAT(
				cfg.Bridge, cfg.Subnet, cfg.Gateway,
				strings.Split(cfg.DNS, ","),
				baseline, logger,
			)
			if err != nil {
				return nil, fmt.Errorf("network backend bridge: %w", err)
			}
			bn.SetTapOwnerUID(tapOwnerUID)
			// Guest→host control-plane isolation is a host-prep artifact (the
			// inet sandswap input chain). Validate it at startup: a node that
			// skipped prep, used a different bridge name, or had its rules
			// flushed must not serve guests with the host's listeners
			// reachable. Only when the baseline is on — egress_baseline: off
			// is the explicit "per-VM only" opt-out and must not touch nft.
			if baseline != nil {
				if err := VerifyHostInputGuard(cfg.Bridge); err != nil {
					return nil, fmt.Errorf("network backend bridge: %w", err)
				}
			}
			logger.Printf("network backend: bridge %s subnet %s gw %s",
				cfg.Bridge, cfg.Subnet, cfg.Gateway)
			return bn, nil
		}
		// Route every later posture sync (SetVMToVMDeny included) through the
		// routed6 inet-forward chain as well as the bridge-family one.
		if baseline != nil {
			baseline.SetRouted6Posture()
		}
		// The guest kernel needs IPv6 for identity-in-address. The default
		// kernel/build.sh build includes it (ch_defconfig + CONFIG_IPV6=y);
		// only the dev-only `build.sh download` variant (the official v6.2
		// prebuilt) boots guests with IPv6 absent.
		logger.Printf("routed-ipv6: guest kernel needs CONFIG_IPV6 (the default kernel build has it; the dev-only `kernel/build.sh download` variant does not)")
		r6, err := NewRoutedIPv6(
			cfg.V6Prefix, cfg.IIDTemplate,
			strings.Split(cfg.DNS, ","),
			baseline, logger,
		)
		if err != nil {
			return nil, fmt.Errorf("network backend routed-ipv6: %w", err)
		}
		r6.SetTapOwnerUID(tapOwnerUID)
		// Replay the shared forward-hook posture (metadata drop + VM-to-VM
		// deny) BEFORE forwarding is enabled: the routed TAPs are pre-created
		// per VM, so this is the one place the TAP-independent posture can be
		// reinstated after a shutdown or an operator flush — and the metadata
		// drop must be in place before the host forwards the first packet.
		if err := r6.ensureForwardGuard(); err != nil {
			return nil, fmt.Errorf("network backend routed-ipv6: replay forward posture: %w", err)
		}
		// The backend forwards between per-TAP /64s and the uplink in the host
		// IP stack: with IPv6 forwarding off, every guest's egress is a silent
		// blackhole. Refuse to start when the forwarding prerequisite cannot
		// be established and verified.
		if err := ensureIPv6Forwarding(); err != nil {
			return nil, fmt.Errorf("network backend routed-ipv6: %w", err)
		}
		stamp := "off"
		if cfg.IIDTemplate != "" {
			stamp = cfg.IIDTemplate
		}
		logger.Printf("network backend: routed-ipv6 prefix %s iid-template %s",
			cfg.V6Prefix, stamp)
		return r6, nil

	default:
		return nil, fmt.Errorf("unknown network backend %q (want none|bridge|routed-ipv6)", cfg.Backend)
	}
}

// CheckBridgeReady verifies the host bridge exists and IPv4 forwarding is on.
func CheckBridgeReady(bridge string) error {
	if _, err := net.InterfaceByName(bridge); err != nil {
		return fmt.Errorf("bridge %s missing: %w (create it with deploy/setup-network.sh)", bridge, err)
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("read ip_forward: %w", err)
	}
	if strings.TrimSpace(string(b)) != "1" {
		return fmt.Errorf("net.ipv4.ip_forward is not 1")
	}
	return nil
}

// ipv6SysctlRoot is the IPv6 sysctl tree; a var so tests can point it at a
// temp directory instead of the live host's /proc/sys.
var ipv6SysctlRoot = "/proc/sys/net/ipv6"

// ipv6ForwardingSysctls are the two knobs that together make the host an IPv6
// router: `all` turns forwarding on for the interfaces that exist now, and
// `default` is what a newly created interface (each VM's TAP, created after
// startup) inherits. Enabling only one is the classic half-configured router
// either existing TAPs or later ones silently drop.
var ipv6ForwardingSysctls = []string{"conf/all/forwarding", "conf/default/forwarding"}

// ensureIPv6Forwarding verifies IPv6 forwarding is enabled and turns it on
// when it is not, then re-reads every knob to verify the write took. The
// routed-IPv6 backend cannot deliver egress without it, and a half-enabled
// state is worse than a refusal: guests silently blackhole while the node
// looks healthy. Failure is fatal to provider construction (the caller turns
// it into a startup refusal).
func ensureIPv6Forwarding() error {
	// The whole tree is absent when the host kernel has no IPv6 support
	// (CONFIG_IPV6=n) or the ipv6 module has not been loaded. Name both
	// causes: a raw ENOENT from the knob read is otherwise easy to mistake
	// for a missing /proc mount or a hardened-sysctl directory. This check
	// only runs for the routed-ipv6 backend (BuildProvider calls it after
	// choosing that backend), so kernels without IPv6 are unaffected unless
	// the operator enabled IPv6.
	if _, err := os.Stat(ipv6SysctlRoot); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("IPv6 is not available on this host: %s does not exist — the kernel was built without IPv6 (CONFIG_IPV6=n) or the ipv6 module is not loaded (run: modprobe ipv6); routed-ipv6 needs IPv6 forwarding", ipv6SysctlRoot)
		}
		return fmt.Errorf("stat %s: %w — routed-ipv6 needs IPv6 forwarding", ipv6SysctlRoot, err)
	}
	for _, name := range ipv6ForwardingSysctls {
		path := filepath.Join(ipv6SysctlRoot, name)
		v, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w — routed-ipv6 needs IPv6 forwarding", path, err)
		}
		if strings.TrimSpace(string(v)) == "1" {
			continue
		}
		if err := writeSysctl(path, "1"); err != nil {
			return fmt.Errorf("enable IPv6 forwarding (%s): %w — routed-ipv6 needs the host IP stack to forward between per-TAP /64s and the uplink; grant CAP_NET_ADMIN or set net.ipv6.conf.%s=1 in host prep", path, err, strings.ReplaceAll(name, "/", "."))
		}
		v, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("verify IPv6 forwarding (%s): %w", path, err)
		}
		if strings.TrimSpace(string(v)) != "1" {
			return fmt.Errorf("IPv6 forwarding did not take: %s reads %q after the write", path, strings.TrimSpace(string(v)))
		}
	}
	return nil
}
