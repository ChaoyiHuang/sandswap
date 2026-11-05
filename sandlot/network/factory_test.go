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
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sandlotconfig "sandlot/config"
)

// errFakeNft stands in for a failing `nft` executor (see restoreRunNFT).
var errFakeNft = errors.New("fake nft failure")

// The egress baseline is an ISOLATION PRIMITIVE, not policy: every tenant TAP
// shares one L2 bridge, so running without the per-TAP anti-spoof and the
// VM-to-VM deny leaves tenants able to ARP-poison and directly attack each
// other's guest network stacks. These tests pin the fail-closed contract:
// a node configured for networking (bridge or routed-ipv6) must REFUSE to
// start when the baseline cannot be enforced. The only sanctioned ways to
// run without it are an explicit `egress_baseline: off` or `backend: none`
// (no guest network at all).

// restoreRunNFT stubs the nft executor for one test and restores it after.
func restoreRunNFT(t *testing.T, stub func(batch string) error) {
	t.Helper()
	orig := runNFT
	t.Cleanup(func() { runNFT = orig })
	runNFT = stub
}

// restoreNFTList stubs the nft chain reader (the startup host-input-guard
// check) for one test and restores it after.
func restoreNFTList(t *testing.T, stub func(family, table, chain string) (string, error)) {
	t.Helper()
	orig := nftListChain
	t.Cleanup(func() { nftListChain = orig })
	nftListChain = stub
}

func TestBuildProviderRefusesWhenNftMissing(t *testing.T) {
	// PATH without an `nft` binary: LookPath must fail and BuildProvider
	// must refuse — NOT warn-and-proceed on an unfiltered shared bridge.
	t.Setenv("PATH", t.TempDir())
	_, err := BuildProvider(sandlotconfig.NetworkConfig{
		Backend: "bridge", Bridge: "br-test", Subnet: "10.188.0.0/16", Gateway: "10.188.0.1",
	}, 0, log.Default())
	if err == nil {
		t.Fatal("BuildProvider must refuse when nft is missing and the baseline is on (default)")
	}
	if !strings.Contains(err.Error(), "nftables not found") {
		t.Fatalf("the refusal must name the missing prerequisite, got: %v", err)
	}
	if !strings.Contains(err.Error(), "egress_baseline") {
		t.Fatalf("the refusal must name the config knob that opts out, got: %v", err)
	}
}

func TestBuildProviderRefusesWhenEnsureTablesFails(t *testing.T) {
	// nft present on PATH (stubbed executor) but the baseline tables cannot
	// be installed: also a refusal — a half-installed baseline is as good as
	// none.
	t.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	restoreRunNFT(t, func(batch string) error {
		return errFakeNft
	})
	_, err := BuildProvider(sandlotconfig.NetworkConfig{
		Backend: "bridge", Bridge: "br-test", Subnet: "10.188.0.0/16", Gateway: "10.188.0.1",
	}, 0, log.Default())
	if err == nil {
		t.Fatal("BuildProvider must refuse when the baseline tables cannot be installed")
	}
	if !strings.Contains(err.Error(), "could not be installed") {
		t.Fatalf("the refusal must name the table installation failure, got: %v", err)
	}
}

func TestBuildProviderExplicitOffSkipsBaseline(t *testing.T) {
	// The explicit opt-out keeps working without nftables: an operator who
	// accepts an isolated-per-VM-only deployment says so in the config.
	t.Setenv("PATH", t.TempDir())
	called := false
	restoreRunNFT(t, func(batch string) error { called = true; return nil })
	var logs bytes.Buffer
	_, err := BuildProvider(sandlotconfig.NetworkConfig{
		Backend: "bridge", Bridge: "br-test", Subnet: "10.188.0.0/16", Gateway: "10.188.0.1",
		EgressBaseline: "off",
	}, 0, log.New(&logs, "", 0))
	if err != nil {
		t.Fatalf("explicit egress_baseline=off must not require nft: %v", err)
	}
	if called {
		t.Fatal("egress_baseline=off must not touch nftables")
	}
	// The opt-out is a security posture change: it must be visible in the
	// startup log, not silent.
	if !strings.Contains(logs.String(), "egress_baseline is OFF") {
		t.Fatalf("explicit off must log a startup WARNING, got %q", logs.String())
	}
}

func TestBuildProviderBaselineOnInstallsTables(t *testing.T) {
	// Baseline on + nft available: the tables are installed exactly once at
	// construction (EnsureTables), and the provider carries the baseline.
	t.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	var batches []string
	restoreRunNFT(t, func(batch string) error {
		batches = append(batches, batch)
		return nil
	})
	restoreNFTList(t, func(string, string, string) (string, error) {
		return "chain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tiifname \"br-test\" counter packets 0 bytes 0 drop\n\t}", nil
	})
	p, err := BuildProvider(sandlotconfig.NetworkConfig{
		Backend: "bridge", Bridge: "br-test", Subnet: "10.188.0.0/16", Gateway: "10.188.0.1",
	}, 0, log.Default())
	if err != nil {
		t.Fatalf("baseline on with nft available must succeed: %v", err)
	}
	if p == nil {
		t.Fatal("provider must be constructed")
	}
	if len(batches) == 0 {
		t.Fatal("EnsureTables must have run (nft batches executed)")
	}
}

func TestBuildProviderRefusesWhenHostInputGuardMissing(t *testing.T) {
	// Baseline on, baseline tables install, but the host-prep input chain has
	// no drop rule for THIS bridge: refuse to start. A guest that can reach
	// host listeners over the sandbox bridge is the exposure this check closes.
	t.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	restoreRunNFT(t, func(string) error { return nil })
	restoreNFTList(t, func(string, string, string) (string, error) {
		return "chain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tiifname \"other-br\" counter drop\n\t}", nil
	})
	_, err := BuildProvider(sandlotconfig.NetworkConfig{
		Backend: "bridge", Bridge: "br-test", Subnet: "10.188.0.0/16", Gateway: "10.188.0.1",
	}, 0, log.Default())
	if err == nil {
		t.Fatal("BuildProvider must refuse when the guest→host input guard has no drop rule for the bridge")
	}
	if !strings.Contains(err.Error(), "guest→host input guard") {
		t.Fatalf("refusal must name the guest→host input guard, got: %v", err)
	}
}

func TestHostInputGuardAcceptsBridgeDropRule(t *testing.T) {
	t.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	restoreRunNFT(t, func(string) error { return nil })
	restoreNFTList(t, func(string, string, string) (string, error) {
		return "chain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tiifname \"br-test\" counter packets 0 bytes 0 drop\n\t}", nil
	})
	if _, err := BuildProvider(sandlotconfig.NetworkConfig{
		Backend: "bridge", Bridge: "br-test", Subnet: "10.188.0.0/16", Gateway: "10.188.0.1",
	}, 0, log.Default()); err != nil {
		t.Fatalf("a bridge-scoped drop rule must satisfy the guard: %v", err)
	}
}

func TestBuildProviderBackendNoneNeedsNoNft(t *testing.T) {
	// backend=none is the offline deployment: no guest network, so no
	// baseline requirement and no nft dependency.
	t.Setenv("PATH", t.TempDir())
	_, err := BuildProvider(sandlotconfig.NetworkConfig{Backend: "none"}, 0, log.Default())
	if err != nil {
		t.Fatalf("backend=none must not require nftables: %v", err)
	}
}

// ipv6SysctlTree fabricates an IPv6 sysctl tree for ensureIPv6Forwarding
// tests (the live host's /proc/sys is never written by a test).
func ipv6SysctlTree(t *testing.T, all, def string) string {
	t.Helper()
	root := t.TempDir()
	for name, val := range map[string]string{
		"conf/all/forwarding":     all,
		"conf/default/forwarding": def,
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func setIPv6SysctlRoot(t *testing.T, root string) {
	t.Helper()
	orig := ipv6SysctlRoot
	t.Cleanup(func() { ipv6SysctlRoot = orig })
	ipv6SysctlRoot = root
}

// TestEnsureIPv6Forwarding pins the fail-fatal forwarding prerequisite of the
// routed-IPv6 backend: already-on passes untouched, off is enabled AND read
// back (a write that did not take must refuse), and unreadable/unwritable
// knobs refuse instead of letting the node serve guests with a black-holed
// egress path.
func TestEnsureIPv6Forwarding(t *testing.T) {
	t.Run("already enabled", func(t *testing.T) {
		root := ipv6SysctlTree(t, "1", "1")
		setIPv6SysctlRoot(t, root)
		if err := ensureIPv6Forwarding(); err != nil {
			t.Fatalf("ensureIPv6Forwarding: %v", err)
		}
	})

	t.Run("enables both knobs and verifies", func(t *testing.T) {
		root := ipv6SysctlTree(t, "0", "0")
		setIPv6SysctlRoot(t, root)
		if err := ensureIPv6Forwarding(); err != nil {
			t.Fatalf("ensureIPv6Forwarding: %v", err)
		}
		for _, name := range ipv6ForwardingSysctls {
			v, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(v)) != "1" {
				t.Fatalf("%s = %q after enable, want 1", name, strings.TrimSpace(string(v)))
			}
		}
	})

	t.Run("missing knob refuses", func(t *testing.T) {
		setIPv6SysctlRoot(t, t.TempDir())
		err := ensureIPv6Forwarding()
		if err == nil {
			t.Fatal("a missing forwarding knob must refuse")
		}
		if !strings.Contains(err.Error(), "IPv6 forwarding") {
			t.Fatalf("error must name the forwarding prerequisite: %v", err)
		}
	})

	t.Run("absent IPv6 tree names CONFIG_IPV6 and modprobe", func(t *testing.T) {
		setIPv6SysctlRoot(t, filepath.Join(t.TempDir(), "absent"))
		err := ensureIPv6Forwarding()
		if err == nil {
			t.Fatal("an absent /proc/sys/net/ipv6 tree must refuse")
		}
		for _, want := range []string{"CONFIG_IPV6", "modprobe ipv6", "IPv6 forwarding"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error must contain %q, got: %v", want, err)
			}
		}
	})

	t.Run("write that does not take refuses", func(t *testing.T) {
		root := ipv6SysctlTree(t, "0", "1")
		if err := os.Remove(filepath.Join(root, "conf/all/forwarding")); err != nil {
			t.Fatal(err)
		}
		// Writable but never reads back 1: the verify step must catch it.
		if err := os.Symlink("/dev/null", filepath.Join(root, "conf/all/forwarding")); err != nil {
			t.Fatal(err)
		}
		setIPv6SysctlRoot(t, root)
		err := ensureIPv6Forwarding()
		if err == nil || !strings.Contains(err.Error(), "did not take") {
			t.Fatalf("a write that does not take must refuse, got %v", err)
		}
	})
}

// TestBuildProviderRoutedIPv6ReplaysPosture pins the routed-IPv6 construction
// contract: forwarding is enabled+verified and the TAP-independent VM-to-VM
// posture is installed before the provider is returned.
func TestBuildProviderRoutedIPv6ReplaysPosture(t *testing.T) {
	t.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	root := ipv6SysctlTree(t, "0", "0")
	setIPv6SysctlRoot(t, root)
	var batches []string
	restoreRunNFT(t, func(batch string) error {
		batches = append(batches, batch)
		return nil
	})

	p, err := BuildProvider(sandlotconfig.NetworkConfig{
		Backend: "routed-ipv6", V6Prefix: "fd00:5341:4e44::/48",
	}, 0, log.Default())
	if err != nil {
		t.Fatalf("BuildProvider routed-ipv6: %v", err)
	}
	if p == nil {
		t.Fatal("provider must be constructed")
	}
	joined := strings.Join(batches, "\n")
	if !strings.Contains(joined, "type filter hook forward priority filter") ||
		!strings.Contains(joined, `iifname "tap*" oifname "tap*" counter drop comment "`+vm2vmComment+`"`) {
		t.Fatalf("construction did not replay the routed VM-to-VM posture:\n%s", joined)
	}
	if !strings.Contains(joined, "ip6 daddr "+v6MetadataAddr+" counter drop comment \""+v6MetadataComment+"\"") {
		t.Fatalf("construction did not install the v6 metadata drop:\n%s", joined)
	}
	for _, name := range ipv6ForwardingSysctls {
		v, rerr := os.ReadFile(filepath.Join(root, name))
		if rerr != nil || strings.TrimSpace(string(v)) != "1" {
			t.Fatalf("%s not enabled at construction (err=%v)", name, rerr)
		}
	}
}

// TestBuildProviderRoutedIPv6RefusesWithoutForwarding pins the fail-fatal
// half: a host where IPv6 forwarding cannot be enabled must not serve the
// routed backend.
func TestBuildProviderRoutedIPv6RefusesWithoutForwarding(t *testing.T) {
	t.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	setIPv6SysctlRoot(t, t.TempDir()) // no knobs present
	restoreRunNFT(t, func(string) error { return nil })

	_, err := BuildProvider(sandlotconfig.NetworkConfig{
		Backend: "routed-ipv6", V6Prefix: "fd00:5341:4e44::/48",
	}, 0, log.Default())
	if err == nil {
		t.Fatal("BuildProvider must refuse routed-ipv6 when IPv6 forwarding cannot be enabled")
	}
	if !strings.Contains(err.Error(), "routed-ipv6") || !strings.Contains(err.Error(), "IPv6 forwarding") {
		t.Fatalf("refusal must name the forwarding prerequisite, got: %v", err)
	}
}
