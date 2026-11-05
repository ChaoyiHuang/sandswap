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
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func cmdDNS(g Global, args []string) {
	if len(args) == 0 {
		fail("dns <stream|agent|sandfs <id>|resolve <name>|sticky>")
	}
	sub := args[0]
	switch sub {
	case "stream":
		queryDNS(g, "sandswap-stream.local", false)
	case "agent":
		queryDNS(g, "sandswap.local", false)
	case "sandfs":
		if len(args) < 2 {
			fail("dns sandfs <sandfs-id>")
		}
		queryDNS(g, args[1]+".sandfs.sandswap.local", true)
	case "resolve":
		if len(args) < 2 {
			fail("dns resolve <name>")
		}
		queryDNS(g, args[1], true)
	case "sticky":
		dnsSticky(g)
	default:
		fail("unknown dns subcommand %q", sub)
	}
}

// queryDNS asks the Sandswap resolver directly (no external `dig`). It uses
// Go's resolver pinned to --dns-addr so a release host needs no bind9-utils.
// short mirrors dig +short; full prints a compact CNAME/A/AAAA answer.
func queryDNS(g Global, name string, short bool) {
	host, port := splitHostPort(g.DNSAddr, "53")
	addr := net.JoinHostPort(host, port)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cname, cerr := resolver.LookupCNAME(ctx, name)
	addrs, aerr := resolver.LookupHost(ctx, name)
	canon := strings.TrimSuffix(cname, ".")
	trimmed := strings.TrimSuffix(name, ".")
	// Service records: `_service._proto.name` (or an explicit underscore
	// name) is an SRV question; Go's LookupSRV with empty service/proto
	// queries the name as given.
	var srvs []*net.SRV
	var srvErr error
	if strings.HasPrefix(trimmed, "_") {
		_, srvs, srvErr = resolver.LookupSRV(ctx, "", "", trimmed)
	}
	if aerr != nil && cerr != nil && srvErr != nil {
		fmt.Fprintf(os.Stderr, "query %s via %s: %v\n", name, addr, aerr)
		return
	}
	if short {
		if canon != "" && canon != trimmed {
			fmt.Println(canon)
		}
		for _, s := range srvs {
			fmt.Println(formatSRV(trimmed, s, true))
		}
		for _, a := range addrs {
			fmt.Println(a)
		}
		return
	}
	fmt.Printf("; <<>> sandns query %s via %s <<>>\n", name, addr)
	if canon != "" && canon != trimmed {
		fmt.Printf("%s.\t0\tIN\tCNAME\t%s.\n", trimmed, canon)
	}
	for _, s := range srvs {
		fmt.Println(formatSRV(trimmed, s, false))
	}
	for _, a := range addrs {
		rr := "A"
		if strings.Contains(a, ":") {
			rr = "AAAA"
		}
		fmt.Printf("%s.\t0\tIN\t%s\t%s\n", trimmed, rr, a)
	}
}

// formatSRV renders one SRV answer in dig +short form (priority weight port
// target) or one full RR. Pure so the record shape is unit-tested without a
// live resolver.
func formatSRV(name string, s *net.SRV, short bool) string {
	target := strings.TrimSuffix(s.Target, ".")
	if short {
		return fmt.Sprintf("%d %d %d %s", s.Priority, s.Weight, s.Port, target)
	}
	return fmt.Sprintf("%s.\t0\tIN\tSRV\t%d %d %d %s.", name, s.Priority, s.Weight, s.Port, target)
}

// dnsSticky lists the DNS sticky records via etcdctl (shared resolveEtcdctl +
// TLS handling with cluster.go).
func dnsSticky(g Global) {
	recs, err := etcdGetPrefix(g, "/sandswap/dns/sticky/")
	if err != nil {
		fatal("etcdctl: " + err.Error() + " (sticky records live in etcd under /sandswap/dns/sticky/)")
	}
	if len(recs) == 0 {
		fmt.Println("(no sticky records)")
		return
	}
	// Print key<tab>value, sorted by key for stable output.
	keys := make([]string, 0, len(recs))
	for k := range recs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s\t%s\n", k, recs[k])
	}
}

// findCachedEtcdctl looks for etcdctl in the e2e download cache
// (/tmp/etcd-*/etcdctl) when the bundled/PATH lookups fail.
func findCachedEtcdctl() string {
	matches, _ := filepath.Glob("/tmp/etcd-*/etcdctl")
	for _, p := range matches {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
