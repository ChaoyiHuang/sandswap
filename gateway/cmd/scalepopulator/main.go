// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, your use of this software will be
// governed by the Apache License, Version 2.0.
//
// scalepopulator — the W5 scale-rehearsal population generator (diagnostics
// tool; the same product-tree precedent as sandlot's warden-probe). Writes a
// tenant-distributed control-plane population into etcd in the EXACT wire
// formats the gateway writes (etcdAgentJSON / etcdSandfsJSON / meta /
// OwnershipValue), so the gateways' watch-fed caches parse it natively:
//
//	per tenant t, per agent a (A per tenant), per sandfs s (S per agent):
//	  <prefix>agent/<sha256(key)>          agent record (namespace: tenant-<t>)
//	  <prefix>agentid/<agentID>            → sha256(key)
//	  <prefix>sandfs/<sandfsID>            hot record   (namespace: tenant-<t>)
//	  <prefix>meta/sandfs/<sandfsID>       display meta
//	  /sandswap/owner/<sandfsID>           ownership (gateway_id, node placement)
//	plus: /sandswap/health/{gw}, /sandswap/gateway/{gw}, presence per node.
//
// All IDs and API keys are DETERMINISTIC (sha256 of tenant/agent/sandfs
// indices) so the measurement phase can mint valid Authorization headers and
// address any record without persisting secrets.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func deterministicID(kind string, parts ...int) string {
	var feed string
	for _, p := range parts {
		feed += fmt.Sprintf("%d/", p)
	}
	d := shaHex(kind + "/" + feed)
	return fmt.Sprintf("%s-%s", kind, d[:8])
}

// etcdAgentJSON mirrors identity.etcdAgentJSON — the wire is the contract;
// a divergent copy here would silently populate unparseable rows.
type agentWire struct {
	AgentID    string `json:"agent_id"`
	Name       string `json:"name"`
	APIKeyHash string `json:"api_key_hash"`
	CreatedAt  string `json:"created_at"`
	Namespace  string `json:"namespace,omitempty"`
}

// sandfsWire mirrors identity.etcdSandfsJSON (the HOT record).
type sandfsWire struct {
	SandfsID    string `json:"sandfs_id"`
	AgentID     string `json:"agent_id"`
	RootFSPath  string `json:"rootfs_path,omitempty"`
	Template    string `json:"template,omitempty"`
	Mode        string `json:"mode,omitempty"`
	MinVCPUs    uint32 `json:"min_vcpus,omitempty"`
	MinMemoryMB uint64 `json:"min_memory_mb,omitempty"`
	Status      string `json:"status,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
}

// metaWire mirrors identity.sandfsMetaInfo.
type metaWire struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// ownerWire mirrors lease.OwnershipValue.
type ownerWire struct {
	GatewayID  string `json:"gateway_id"`
	NodeID     string `json:"node_id"`
	Generation uint64 `json:"generation"`
}

type healthWire struct {
	LastHealthyTS string `json:"last_healthy_ts"`
	NodeCount     int    `json:"node_count"`
}

type registryWire struct {
	GatewayURL string `json:"gateway_url,omitempty"`
	StreamAddr string `json:"stream_addr,omitempty"`
}

func main() {
	endpoints := flag.String("endpoints", "127.0.0.1:12379", "comma-separated etcd endpoints")
	prefix := flag.String("prefix", "/sandswap/identity/", "identity store prefix (must match the gateways under test)")
	tenants := flag.Int("tenants", 1000, "tenant count (namespace tenant-<t>)")
	agentsPerTenant := flag.Int("agents-per-tenant", 100, "agents per tenant")
	sandfsPerAgent := flag.Int("sandfs-per-agent", 10, "sandfs per agent")
	nodes := flag.Int("nodes", 4, "sandlot node count for placement + presence keys")
	gatewayID := flag.String("gateway-id", "gw-exec-1", "gateway id owning the population")
	gatewayURL := flag.String("gateway-url", "http://127.0.0.1:13000", "gateway agent-plane URL for the registry key")
	streamAddr := flag.String("stream-addr", "127.0.0.1:13998", "gateway stream addr for the registry key")
	sampleOut := flag.String("sample-out", "", "optional file: one plaintext API key per line (first agent of every tenant) for hot-path probes")
	workers := flag.Int("workers", 32, "parallel etcd writers")
	flag.Parse()

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{*endpoints},
		DialTimeout: 10 * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "etcd connect: %v\n", err)
		os.Exit(1)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	total := *tenants * *agentsPerTenant * *sandfsPerAgent
	fmt.Fprintf(os.Stderr, "populating: tenants=%d agents/t=%d sandfs/agent=%d → %d sandfs, %d agents, ~%d keys\n",
		*tenants, *agentsPerTenant, *sandfsPerAgent, total, *tenants**agentsPerTenant, total*4+total)

	var written atomic.Int64
	start := time.Now()

	// One txn-batch per (agent): its agent key + agentid key + S sandfs hots +
	// S metas + S owners — batches keep etcd happy without single-put overhead.
	batch := func(agentKeys [][2]string) error { // [key, value] pairs
		ops := make([]clientv3.Op, 0, len(agentKeys))
		for _, kv := range agentKeys {
			ops = append(ops, clientv3.OpPut(kv[0], kv[1]))
		}
		_, err := cli.Txn(ctx).Then(ops...).Commit()
		return err
	}

	type job struct{ t, a int }
	jobs := make(chan job, 1024)
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				tenant := fmt.Sprintf("tenant-%d", j.t)
				agentID := deterministicID("agent", j.t, j.a)
				apiKey := "sk-sandswap-agent-" + shaHex(fmt.Sprintf("scale/%d/%d", j.t, j.a))
				digest := shaHex(apiKey)
				created := now

				kvs := make([][2]string, 0, 2+3**sandfsPerAgent)
				agentJSON, _ := json.Marshal(agentWire{
					AgentID: agentID, Name: fmt.Sprintf("scale-t%d-a%d", j.t, j.a),
					APIKeyHash: digest, CreatedAt: created, Namespace: tenant,
				})
				kvs = append(kvs, [2]string{*prefix + "agent/" + digest, string(agentJSON)})
				kvs = append(kvs, [2]string{*prefix + "agentid/" + agentID, digest})

				for s := 0; s < *sandfsPerAgent; s++ {
					sfID := deterministicID("sandfs", j.t, j.a, s)
					hot, _ := json.Marshal(sandfsWire{
						SandfsID: sfID, AgentID: agentID,
						RootFSPath: "/var/lib/sandswap/volumes/sf-" + shaHex(sfID)[:40],
						Template:   "rootfs:v1", Mode: "flat", Namespace: tenant,
					})
					kvs = append(kvs, [2]string{*prefix + "sandfs/" + sfID, string(hot)})
					meta, _ := json.Marshal(metaWire{
						Name: fmt.Sprintf("scale-sf-t%d-a%d-%d", j.t, j.a, s), CreatedAt: created,
					})
					kvs = append(kvs, [2]string{*prefix + "meta/sandfs/" + sfID, string(meta)})
					owner, _ := json.Marshal(ownerWire{
						GatewayID: *gatewayID,
						NodeID:    fmt.Sprintf("node-%d", (j.t+spread(s))%*nodes),
						// +1 per ownership write on the real path; the base is
						// what matters for the control plane curves.
						Generation: 1,
					})
					kvs = append(kvs, [2]string{"/sandswap/owner/" + sfID, string(owner)})
				}
				if err := batch(kvs); err != nil {
					fmt.Fprintf(os.Stderr, "batch t%d/a%d: %v\n", j.t, j.a, err)
					os.Exit(1)
				}
				n := written.Add(int64(len(kvs)))
				if n%500_000 < int64(2+3**sandfsPerAgent) {
					fmt.Fprintf(os.Stderr, "  ... %d keys (%.0f keys/s)\n", n,
						float64(n)/time.Since(start).Seconds())
				}
			}
		}()
	}
	for t := 1; t <= *tenants; t++ {
		for a := 1; a <= *agentsPerTenant; a++ {
			jobs <- job{t, a}
		}
	}
	close(jobs)
	wg.Wait()

	// Registry + health + presence (single small writes).
	hv, _ := json.Marshal(healthWire{LastHealthyTS: now, NodeCount: *nodes})
	cli.Txn(ctx).Then(
		clientv3.OpPut("/sandswap/gateway/"+*gatewayID, mustJSON(registryWire{GatewayURL: *gatewayURL, StreamAddr: *streamAddr})),
		clientv3.OpPut("/sandswap/health/"+*gatewayID, string(hv)),
	).Commit()
	for n := 0; n < *nodes; n++ {
		cli.Put(ctx, fmt.Sprintf("/sandswap/node/node-%d/presence", n), now)
	}

	elapsed := time.Since(start)
	fmt.Printf("POPULATED keys=%d elapsed=%s rate=%.0f/s\n", written.Load(), elapsed.Round(time.Second),
		float64(written.Load())/elapsed.Seconds())

	// Sample keys: the FIRST agent of every tenant — the probe phase uses
	// these as Bearer tokens (deterministic, so no secret persistence).
	if *sampleOut != "" {
		f, err := os.Create(*sampleOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sample-out: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		for t := 1; t <= *tenants; t++ {
			fmt.Fprintf(f, "tenant-%d sk-sandswap-agent-%s\n", t, shaHex(fmt.Sprintf("scale/%d/%d", t, 1)))
		}
		fmt.Fprintf(os.Stderr, "sample keys → %s (%d lines)\n", *sampleOut, *tenants)
	}
}

// spread is a tiny deterministic scatter so one agent's sandfs land on
// different nodes (placement realism without randomness).
func spread(x int) int { return ((x + 1) * 2654435761 >> 8) % 997 }

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
