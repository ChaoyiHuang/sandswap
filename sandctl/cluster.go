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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// clusterLoadValue mirrors gateway/lease.LoadValue (the /sandswap/load/{gw}
// contract shape). sandctl is a standalone module and can't import gateway, so
// the JSON tags are duplicated here — they're contract-stable (see
// gateway/lease/contract_test.go).
type clusterLoadValue struct {
	GatewayID   string            `json:"gateway_id"`
	AggDutyLong float64           `json:"agg_duty_long"`
	CleanVMs    uint32            `json:"clean_vms"`
	NodeCount   int               `json:"node_count"`
	Nodes       []clusterNodeLoad `json:"nodes,omitempty"`
}
type clusterNodeLoad struct {
	NodeID       string  `json:"node_id"`
	DutyLong     float64 `json:"duty_long"`
	HostCPU      float64 `json:"host_cpu_pct"`
	ActiveSandfs uint32  `json:"active_sandfs"`
	CleanVMs     uint32  `json:"clean_vms"`
	TotalVMs     uint32  `json:"total_vms"`
}

// clusterGatewayStats is one gateway's row in the sandctl cluster view — same
// fields as gateway/handler.GatewayStats (kept in sync manually).
type clusterGatewayStats struct {
	GatewayID   string            `json:"gateway_id"`
	Healthy     bool              `json:"healthy"`
	GatewayURL  string            `json:"gateway_url"`
	StreamAddr  string            `json:"stream_addr"`
	NodeCount   int               `json:"node_count"`
	CleanVMs    uint32            `json:"clean_vms"`
	TotalVMs    uint32            `json:"total_vms"`
	AggDutyLong float64           `json:"agg_duty_long"`
	Nodes       []clusterNodeLoad `json:"nodes,omitempty"`
}

// clusterReport is the unified shape sandctl prints — identical to
// gateway/handler.StatsReport so `sandctl pool` (etcd path) and `curl /stats`
// (gateway aggregate path) line up.
type clusterReport struct {
	Gateways []clusterGatewayStats `json:"gateways"`
	Totals   struct {
		CleanVMs   uint32 `json:"clean_vms"`
		TotalVMs   uint32 `json:"total_vms"`
		InUseVMs   uint32 `json:"in_use_vms"`
		NodeCount  int    `json:"node_count"`
		GatewayCnt int    `json:"gateway_count"`
	} `json:"totals"`
}

// etcdGetPrefix fetches all keys under prefix via etcdctl, returning a
// key→value map. TLS material comes ONLY from explicit flags (--ca /
// --client-cert / --client-key): the deployment's etcd client key belongs to
// the sandserv identity and is not a client credential. A caller without etcd
// credentials (the normal case) gets an error here and cmdPool falls back to
// the human listener's anonymous /stats.
func etcdGetPrefix(g Global, prefix string) (map[string]string, error) {
	etcdctl, err := resolveEtcdctl(g)
	if err != nil {
		return nil, err
	}
	cmdArgs := []string{"--endpoints=" + g.etcdClientURL(), "get", "--prefix", prefix}
	if g.TLS || strings.HasPrefix(g.etcdClientURL(), "https://") {
		tlsArgs, err := g.etcdTLSArgs()
		if err != nil {
			return nil, err
		}
		cmdArgs = append(tlsArgs, cmdArgs...)
	}
	out, err := exec.Command(etcdctl, cmdArgs...).Output()
	if err != nil {
		return nil, err
	}
	// etcdctl default output: alternating key / value lines.
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	m := make(map[string]string, len(lines)/2+1)
	for i := 0; i+1 < len(lines); i += 2 {
		k := strings.TrimSpace(lines[i])
		v := strings.TrimSpace(lines[i+1])
		if k != "" {
			m[k] = v
		}
	}
	return m, nil
}

// resolveEtcdctl prefers the etcdctl vendored beside the release binaries
// (output/etcd/etcdctl), then PATH, then the e2e download cache.
func resolveEtcdctl(g Global) (string, error) {
	bundled := filepath.Join(g.BinDir, "etcd", "etcdctl")
	if st, err := os.Stat(bundled); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
		return bundled, nil
	}
	if p, err := exec.LookPath("etcdctl"); err == nil {
		return p, nil
	}
	if alt := findCachedEtcdctl(); alt != "" {
		return alt, nil
	}
	return "", fmt.Errorf("etcdctl not found (looked for %s, on PATH, and in /tmp/etcd-*/)", bundled)
}

// etcdTLSArgs builds etcdctl's TLS flags from explicit client material only.
// A caller-supplied key must pass the same file-isolation check as the HTTPS
// client: the service identities' keys (sandserv/sandlot-owned, 0640/0600)
// must never be usable as client credentials.
func (g Global) etcdTLSArgs() ([]string, error) {
	var args []string
	if g.CA != "" {
		args = append(args, "--cacert="+g.CertPath(g.CA))
	}
	if (g.ClientCert == "") != (g.ClientKey == "") {
		return nil, fmt.Errorf("--client-cert and --client-key must be set together")
	}
	if g.ClientCert != "" {
		keyPath := g.CertPath(g.ClientKey)
		if err := checkClientKeyFile(keyPath); err != nil {
			return nil, err
		}
		args = append(args, "--cert="+g.CertPath(g.ClientCert), "--key="+keyPath)
	}
	return args, nil
}

// buildClusterReport aggregates /sandswap/{load,health,gateway}/ from etcd into
// the unified clusterReport. Mirrors gateway/handler.etcdStatsReport — same
// keys, same merge — so sandctl and the gateway /stats see the same view.
func buildClusterReport(g Global) (clusterReport, bool, error) {
	loads, err := etcdGetPrefix(g, "/sandswap/load/")
	if err != nil {
		return clusterReport{}, false, err
	}
	// Single-node MemoryStore writes NO load keys → fall back to /stats.
	if len(loads) == 0 {
		return clusterReport{}, false, nil
	}
	healths, _ := etcdGetPrefix(g, "/sandswap/health/")
	registries, _ := etcdGetPrefix(g, "/sandswap/gateway/")

	gwSet := map[string]struct{}{}
	for k := range loads {
		gwSet[strings.TrimPrefix(k, "/sandswap/load/")] = struct{}{}
	}
	for k := range healths {
		gwSet[strings.TrimPrefix(k, "/sandswap/health/")] = struct{}{}
	}
	for k := range registries {
		gwSet[strings.TrimPrefix(k, "/sandswap/gateway/")] = struct{}{}
	}
	ids := make([]string, 0, len(gwSet))
	for id := range gwSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rep := clusterReport{}
	var totClean, totTotal uint32
	totNodes := 0
	for _, id := range ids {
		gw := clusterGatewayStats{GatewayID: id}
		if _, ok := healths["/sandswap/health/"+id]; ok {
			gw.Healthy = true
		}
		if rv, ok := registries["/sandswap/gateway/"+id]; ok {
			var reg struct {
				GatewayURL string `json:"gateway_url"`
				StreamAddr string `json:"stream_addr"`
			}
			if json.Unmarshal([]byte(rv), &reg) == nil {
				gw.GatewayURL = reg.GatewayURL
				gw.StreamAddr = reg.StreamAddr
			}
		}
		if lv, ok := loads["/sandswap/load/"+id]; ok {
			var v clusterLoadValue
			if json.Unmarshal([]byte(lv), &v) == nil {
				gw.NodeCount = v.NodeCount
				gw.CleanVMs = v.CleanVMs
				gw.AggDutyLong = v.AggDutyLong
				gw.Nodes = v.Nodes
				var t uint32
				for _, n := range v.Nodes {
					t += n.TotalVMs
				}
				gw.TotalVMs = t
			}
		}
		totClean += gw.CleanVMs
		totTotal += gw.TotalVMs
		totNodes += gw.NodeCount
		rep.Gateways = append(rep.Gateways, gw)
	}
	rep.Totals.CleanVMs = totClean
	rep.Totals.TotalVMs = totTotal
	rep.Totals.InUseVMs = totTotal - totClean
	rep.Totals.NodeCount = totNodes
	rep.Totals.GatewayCnt = len(rep.Gateways)
	return rep, true, nil
}

// cmdPool prints the cluster pool view: etcd-first (distributed), /stats
// fallback (single-node MemoryStore). Both paths yield the same shape.
func cmdPool(g Global, args []string) {
	fs := newFlagSet("pool")
	var raw bool
	fs.BoolVar(&raw, "raw", false, "print raw JSON (no table)")
	fs.Parse(args)

	// 1. etcd-first: if load keys exist, aggregate directly from etcd.
	if rep, ok, err := buildClusterReport(g); err == nil && ok {
		printClusterReport(g, rep, raw)
		return
	}

	// 2. Fallback: GET /stats from the gateway (single-node MemoryStore, which
	//    now returns the same StatsReport shape).
	base := g.HumanURL
	// In exec mode /stats is on the agent listener; try human first, then agent.
	data, status, err := g.request(base, "GET", "/stats", nil, "", nil)
	if err != nil || status >= 400 {
		data, status, err = g.request(g.GatewayURL, "GET", "/stats", nil, "", nil)
	}
	if err != nil {
		fatal("stats: " + err.Error())
	}
	if status >= 400 {
		// Both listeners answered with an error status: a failed probe, not a
		// report to pretty-print. The body explains why; the exit code is the
		// gate (a pipeline must not read a dead stack as success).
		if raw {
			fmt.Fprintf(os.Stderr, "HTTP %d\n", status)
			fmt.Println(string(data))
		} else {
			g.printResp(data, status)
		}
		os.Exit(1)
	}
	if raw {
		fmt.Println(string(data))
		return
	}
	// The gateway returns StatsReport; pretty-print it.
	var rep clusterReport
	if json.Unmarshal(data, &rep) == nil && len(rep.Gateways) > 0 {
		printClusterReport(g, rep, false)
		return
	}
	g.printResp(data, status)
}

// printClusterReport renders the unified cluster view as a table (or raw JSON).
func printClusterReport(g Global, rep clusterReport, raw bool) {
	if raw || g.Raw {
		data, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(data))
		return
	}
	fmt.Printf("CLUSTER  %d gateway(s) · %d node(s) · clean %d / total %d / in-use %d\n",
		rep.Totals.GatewayCnt, rep.Totals.NodeCount,
		rep.Totals.CleanVMs, rep.Totals.TotalVMs, rep.Totals.InUseVMs)
	fmt.Printf("%-12s %-7s %-6s %-6s %-6s %-8s %s\n",
		"GATEWAY", "HEALTH", "NODES", "CLEAN", "TOTAL", "DUTY", "URL")
	fmt.Println(strings.Repeat("─", 70))
	for _, gw := range rep.Gateways {
		h := "down"
		if gw.Healthy {
			h = "up"
		}
		fmt.Printf("%-12s %-7s %-6d %-6d %-6d %-8.2f %s\n",
			gw.GatewayID, h, gw.NodeCount, gw.CleanVMs, gw.TotalVMs,
			gw.AggDutyLong, gw.GatewayURL)
		for _, n := range gw.Nodes {
			fmt.Printf("  └ %-10s clean %d / total %d  sandfs %d  duty %.2f  cpu %.0f%%\n",
				n.NodeID, n.CleanVMs, n.TotalVMs, n.ActiveSandfs, n.DutyLong, n.HostCPU)
		}
	}
}
