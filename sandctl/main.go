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
	"fmt"
	"os"
	"strings"
)

const usage = `sandctl — Sandswap client CLI (HTTPS API + DNS + pool/health views)

Usage:
  sandctl [global-flags] <command> [subcommand] [flags] [args]

Deployment and component lifecycle belong to deploy/baremetal (systemd). This
binary only talks to an already-deployed stack.

Configuration is resolved from CLI flags → client contract → defaults:
  $SANDSWAP_SANDCTL_ENV (explicit file), else /etc/sandswap/sandctl.env
  (written by deploy/baremetal once the deployment is healthy; public URLs +
  CA trust anchor only). CLI flags always win.

Global flags:
  --run-dir DIR        agent-key cache root (default ./run)
  --bin-dir DIR        component binary dir, for the vendored etcdctl (default ./output)
  --gateway-url URL    agent listener (default http://127.0.0.1:3000)
  --human-url URL      human listener (default http://127.0.0.1:3100)
  --dns-addr ADDR      DNS server (default 127.0.0.1:8053)
  --etcd URL           etcd endpoint (default http://127.0.0.1:2379)
  --tls                enable TLS for the HTTPS listeners / etcd
  --ca FILE            CA bundle (absolute, or relative to <run-dir>/certs)
  --client-cert FILE   mTLS client certificate (caller-owned)
  --client-key FILE    mTLS client key (caller-owned, mode 0600)
  --insecure           skip TLS verification (development only)
  --raw                don't pretty-print JSON
  --dry-run            print the HTTP request, don't send

Commands:
  pool                 show VM pool per-node counts (etcd, else /stats)
  health-all           probe gateway/human /health + /ready (exit 1 on any failure)

  api <sub>            call the gateway HTTPS API:
    health | ready | stats
    agent create|list|delete
    sandfs create|list|delete|save-template
    template list|pull|push
    ownership release <id> | reap-stuck <gateway-id> [--dry-run] [--batch N] | reap-stuck-node <node-id> [--dry-run] [--batch N]
    execute | exec-status <id> | exec-kill <id>
    file

  dns <sub>            query the Sandswap DNS:
    stream | agent | sandfs <id> | resolve <name> | sticky

Run "sandctl <command> -h" for command-specific flags.
See docs/operations/sandctl.md for the client guide.
`

// globalFlagSpec describes each global flag: name + whether it takes a value.
var globalFlagSpec = map[string]bool{
	// value flags
	"run-dir": true, "bin-dir": true, "gateway-url": true, "human-url": true,
	"dns-addr": true, "etcd": true, "ca": true,
	"client-cert": true, "client-key": true,
	// boolean flags
	"tls": false, "insecure": false, "raw": false, "dry-run": false,
}

// Version information — set via ldflags at build time (build/build.sh
// stamps every shipped binary uniformly; dev builds show the defaults).
var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-version") {
		printVersion()
		return
	}
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(0)
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usage)
		os.Exit(0)
	}

	g := Defaults()
	explicit := make(map[string]bool)

	// Scan leading global flags until the first non-flag token (the command).
	// Global flags may also be interleaved after the command by accident; we
	// only consume the leading run so per-command flag parsing stays intact.
	var rest []string
	i := 0
	for i < len(args) {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			rest = args[i:]
			break
		}
		name, val, hasVal := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		takesVal, ok := globalFlagSpec[name]
		if !ok {
			// Unknown leading flag — stop; let the command see it (it may be a
			// command-specific flag that happens to start with --).
			rest = args[i:]
			break
		}
		if takesVal {
			if !hasVal {
				if i+1 >= len(args) {
					fatal(fmt.Sprintf("flag --%s requires a value", name))
				}
				val = args[i+1]
				i++
			}
			applyGlobalFlag(&g, explicit, name, val)
		} else {
			applyGlobalFlag(&g, explicit, name, "true")
		}
		i++
	}
	if rest == nil {
		rest = args[i:]
	}
	if len(rest) == 0 {
		fmt.Print(usage)
		os.Exit(0)
	}

	// Load the deployment's client contract for anything not set on the CLI.
	// An error is never downgraded to a warning: a missing explicit override
	// must not silently fall back to the built-in defaults (the documented
	// contract), and a default contract that exists but cannot be trusted
	// (foreign owner, group/world writable) fails closed. Only the ABSENCE of
	// a default contract means "built-in defaults apply" — LoadEnv returns
	// nil for exactly that case and an error for everything else.
	if err := g.LoadEnv(explicit); err != nil {
		fatal(err.Error())
	}

	cmd := rest[0]
	cmdArgs := rest[1:]

	switch cmd {
	case "pool":
		cmdPool(g, cmdArgs)
	case "health-all":
		cmdHealthAll(g, cmdArgs)
	case "api":
		cmdAPI(g, cmdArgs)
	case "dns":
		cmdDNS(g, cmdArgs)
	case "version":
		printVersion()
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		fmt.Print(usage)
		os.Exit(2)
	}
}

func printVersion() {
	fmt.Printf("sandctl %s (commit %s, built %s)\n", Version, Commit, BuildTime)
}

// applyGlobalFlag sets one Global field from a CLI flag value, recording that
// it was explicitly set (so the client contract doesn't override it).
func applyGlobalFlag(g *Global, explicit map[string]bool, name, val string) {
	explicit[name] = true
	switch name {
	case "run-dir":
		g.RunDir = val
	case "bin-dir":
		g.BinDir = val
	case "gateway-url":
		g.GatewayURL = val
	case "human-url":
		g.HumanURL = val
	case "dns-addr":
		g.DNSAddr = val
	case "etcd":
		g.Etcd = val
	case "ca":
		g.CA = val
	case "client-cert":
		g.ClientCert = val
	case "client-key":
		g.ClientKey = val
	case "tls":
		g.TLS = true
	case "insecure":
		g.Insecure = true
	case "raw":
		g.Raw = true
	case "dry-run":
		g.DryRun = true
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}

// fail prints an error and exits 1 (for command functions).
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
