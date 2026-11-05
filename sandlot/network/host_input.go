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
	"os/exec"
	"regexp"
	"strings"

	"sandlot/hostbin"
)

// nftListChain reads a chain with rule handles. A package var (like runNFT)
// so the startup guard is unit-testable without nftables on the test host.
var nftListChain = func(family, table, chain string) (string, error) {
	nft := hostbin.Path("nft")
	if nft == "" {
		return "", fmt.Errorf("nft not found at any absolute candidate path")
	}
	out, err := exec.Command(nft, "-a", "list", "chain", family, table, chain).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("nft list chain %s %s %s: %w (%s)",
			family, table, chain, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ifaceNameRE matches a Linux interface name: 1-15 chars of the characters
// the kernel accepts. The bridge name is interpolated into an nft rule, so a
// looser value would be a template-injection channel.
var ifaceNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// hookInputRE matches a base-chain declaration for the INPUT hook: `type
// filter hook input priority <spec>;`. A regular (non-base) chain or a chain
// hooked somewhere else can carry the same rule text without filtering
// anything the bridge sends to this host.
var hookInputRE = regexp.MustCompile(`^type\s+filter\s+hook\s+input\s+priority\s+\S+\s*;`)

// VerifyHostInputGuard is the startup fail-closed check for the guest→host
// control-plane isolation that host prep installs:
//
//	table inet sandswap {
//	  chain input { type filter hook input priority 0; policy accept;
//	    iifname "<bridge>" ct state invalid drop
//	    iifname "<bridge>" ct state established,related accept
//	    iifname "<bridge>" udp dport 53 accept
//	    iifname "<bridge>" tcp dport 53 accept
//	    iifname "<bridge>" counter drop
//	  }
//	}
//
// The chain is the only thing stopping a guest from reaching host listeners
// (gateway :3000/:3100/:9998, etcd, ...) over the sandbox bridge. It used to
// live exclusively in common/sh/runtime.sh (host prep), so a node that skipped
// prep, used a differently-named bridge, or had its rules flushed would run
// silently exposed. This check runs at provider construction (sandlot embedded
// and boxout both call BuildProvider) AND on every TAP attach (a runtime
// re-check: startup alone cannot see a later flush). It refuses when the
// chain's HOOK declaration is not the input filter hook, or when the drop rule
// for THIS bridge is absent. It deliberately does not install the chain: host
// prep owns the allowlist (SS_HOST_ALLOW_PORTS) and rewriting it here would
// silently drop operator extensions.
func VerifyHostInputGuard(bridge string) error {
	if !ifaceNameRE.MatchString(bridge) {
		return fmt.Errorf("bridge name %q is not a valid Linux interface name (1-15 chars of [A-Za-z0-9_.-])", bridge)
	}
	out, err := nftListChain("inet", "sandswap", "input")
	if err != nil {
		return fmt.Errorf("guest→host input guard (inet sandswap input) is absent or unreadable: %w — run the host prep (common/sh/runtime.sh, or the bare-metal/k8s setup script) before starting sandlot; without it a guest can reach host listeners over the sandbox bridge", err)
	}
	if !chainHooksInput(out) {
		return fmt.Errorf("inet sandswap input is not an INPUT-hook filter chain (no `type filter hook input priority …;` declaration in:\n%s) — a regular or differently-hooked chain can carry the same rule text and filter nothing; re-run host prep to recreate the base chain", strings.TrimSpace(out))
	}
	for _, line := range strings.Split(out, "\n") {
		if isFinalBridgeDrop(line, bridge) {
			return nil
		}
	}
	return fmt.Errorf("guest→host input guard is missing the terminal drop rule for bridge %q in inet sandswap input (a conditional drop such as `ct state invalid drop` is not the guard) — re-run host prep; refusing to start with a guest that can reach host listeners", bridge)
}

// chainHooksInput reports whether an `nft -a list chain` listing carries the
// INPUT filter hook declaration (`type filter hook input priority …;`). Rule
// lines never begin with `type filter hook`, so scanning the listing cannot be
// spoofed by rule text (which is only concatenated after the matcher).
func chainHooksInput(listing string) bool {
	for _, line := range strings.Split(listing, "\n") {
		if hookInputRE.MatchString(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

// finalDropRE is built per call (startup-only). The terminal rule must match
// the bridge and NOTHING else before `drop`: a conditional drop
// (`ct state invalid drop`) is a different, much narrower rule and must not
// satisfy the guard.
func isFinalBridgeDrop(line, bridge string) bool {
	line = strings.TrimSpace(line)
	if i := strings.Index(line, "# handle "); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	re := regexp.MustCompile(`^iifname "` + regexp.QuoteMeta(bridge) + `"( counter packets [0-9]+ bytes [0-9]+)? drop$`)
	return re.MatchString(line)
}
