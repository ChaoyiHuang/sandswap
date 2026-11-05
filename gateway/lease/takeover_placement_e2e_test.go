//go:build ownership_e2e

// Copyright 2026 Chaoyang Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// pin (e2e): a successful CAS takeover must return the preserved (or
// candidate) placement as the claim hint. RED before the fix: forceTakeover
// returned claimStep{} and pool.Acquire re-scored blind, losing the affinity
// the takeover deliberately preserved plus one extra placement write.
// Runs against a real etcd like the sibling e2e suites.

package lease

import (
	"context"
	"encoding/json"
	clientv3 "go.etcd.io/etcd/client/v3"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTakeoverReturnsPreservedPlacementE2E(t *testing.T) {
	cli := stalenessEtcdClient(t)
	oc := newStalenessCache(t, "gw-takeover-hint", nil)

	// Seed a foreign dead-owner record with a placement, read its real
	// ModRevision (the CAS baseline), then CAS-takeover it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	val, _ := json.Marshal(OwnershipValue{GatewayID: "gw-dead", NodeID: "node-m", Generation: 1})
	if _, err := cli.Put(ctx, ownershipPrefix+"sf-hint", string(val)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := cli.Get(ctx, ownershipPrefix+"sf-hint")
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("read seeded record: %v", err)
	}
	modRev := resp.Kvs[0].ModRevision

	step, err := oc.forceTakeoverForTest("sf-hint", 1, modRev, "node-m")
	if err != nil {
		t.Fatalf("forceTakeover: %v", err)
	}
	if step.preferredNode != "node-m" {
		t.Fatalf("takeover hint must be the preserved placement, got %q ", step.preferredNode)
	}
}

// TestCompactionInvalidatesCacheE2E pins: after a watch ErrCompacted
// fallback, every cached entry must re-validate against etcd before the fast
// path can serve again — a takeover PUT lost to compaction must never be
// served from the stale cache; this pin requires exactly that.
// startPrivateEtcd runs a dedicated etcd for destructive tests (Compact
// poisons every watch bookmark on a shared instance — sibling tests subscribe
// from older revisions and would fall into their own ErrCompacted paths).
func startPrivateEtcd(t *testing.T) (*clientv3.Client, func()) {
	t.Helper()
	bin := os.Getenv("SANDSWAP_ETCD_BIN")
	if bin == "" {
		bin = "../../output/etcd/etcd"
	}
	dataDir := filepath.Join(t.TempDir(), "etcd-data")
	cliURL := "http://127.0.0.1:12391"
	cmd := exec.Command(bin,
		"--data-dir", dataDir,
		"--listen-client-urls", cliURL,
		"--advertise-client-urls", cliURL,
		"--listen-peer-urls", "http://127.0.0.1:12392",
		"--initial-advertise-peer-urls", "http://127.0.0.1:12392",
		"--initial-cluster", "default=http://127.0.0.1:12392",
	)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start private etcd: %v", err)
	}
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{cliURL}, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err = cli.Get(ctx, "ready-probe")
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("private etcd never became ready: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return cli, func() { cli.Close(); _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }
}

func TestCompactionInvalidatesCacheE2E(t *testing.T) {
	cli, stop := startPrivateEtcd(t)
	defer stop()
	// Build the cache around the private client (newStalenessCache uses the
	// shared endpoint).
	oc, err0 := NewOwnershipCache(cli, "gw-a", nil, slog.Default())
	if err0 != nil {
		t.Fatalf("cache: %v", err0)
	}
	t.Cleanup(func() { oc.Close() })
	oc.SetNodeCountFunc(func() int { return 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	val, _ := json.Marshal(OwnershipValue{GatewayID: "gw-a", NodeID: "node-a", Generation: 1})
	if _, err := cli.Put(ctx, ownershipPrefix+"sf-c", string(val)); err != nil {
		t.Fatal(err)
	}
	oc.SetPresenceStateForTest(func(string) (presenceState, error) { return presenceSelf, nil })
	t.Cleanup(func() { testPresenceStateFn.Store(nil) }) // package-level hook: never leak into sibling e2e tests
	if _, err := oc.claimFromEtcdCtx(ctx, "sf-c", "node-a"); err != nil {
		t.Fatalf("initial claim: %v", err)
	}

	// The takeover PUT lands while NO watch is subscribed, then compaction
	// erases it — the deterministic form of "an event lost to compaction"
	// (a live watch would deliver it). The first subscription below starts
	// from the stale bookmark and
	// must get ErrCompacted.
	takerVal, _ := json.Marshal(OwnershipValue{GatewayID: "gw-taker", NodeID: "node-a", Generation: 2})
	resp, err := cli.Put(ctx, ownershipPrefix+"sf-c", string(takerVal))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Compact(ctx, resp.Header.Revision); err != nil {
		t.Fatal(err)
	}

	oc.StartWatch() // ErrCompacted fires immediately → fallback
	time.Sleep(600 * time.Millisecond)

	// FAST-PATH Claim — the surface that must not serve stale.
	placement, err := oc.Claim("sf-c", "node-a")
	if err == nil && placement == "node-a" {
		t.Fatalf(": stale cache served after compaction (missed takeover); placement=%q", placement)
	}
}
