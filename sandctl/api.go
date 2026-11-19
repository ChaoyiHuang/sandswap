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

// cmdAPI dispatches the `api` subcommands.
func cmdAPI(g Global, args []string) {
	if len(args) == 0 {
		fail("api <health|ready|stats|agent|sandfs|template|ownership|execute|exec-status|exec-kill|file>")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "health":
		// /health is on the agent listener in single-node/exec, on the human
		// listener in human mode. Try agent first, fall back to human.
		g.getJSONAny("/health", g.GatewayURL, g.HumanURL)
	case "ready":
		g.getJSONAny("/ready", g.GatewayURL, g.HumanURL)
	case "stats":
		// Stats lives on the human listener in all modes (gateway/cmd/main.go:
		// humanMux owns /stats; agentMux does not). Query humanUrl so single-node
		// and distributed both work; this matches `sandctl pool` which also uses human.
		g.getJSON(g.HumanURL, "/stats", "", nil)
	case "agent":
		apiAgent(g, rest)
	case "sandfs":
		apiSandFS(g, rest)
	case "template":
		apiTemplate(g, rest)
	case "ownership":
		apiOwnership(g, rest)
	case "execute":
		apiExecute(g, rest)
	case "exec-status":
		apiExecStatus(g, rest)
	case "exec-kill":
		apiExecKill(g, rest)
	case "file":
		apiFile(g, rest)
	default:
		fail("unknown api subcommand %q", sub)
	}
}

// ── API key intake ─────────────────────────────────────

// apiKeyFromSources resolves the agent API key without requiring it on the
// command line: the DEPRECATED -api-key flag still works (and wins when set)
// but warns — /proc/<pid>/cmdline is world-readable, so an argv key leaks to
// every local user. The preferred forms are the SANDSWAP_API_KEY environment
// variable and SANDSWAP_API_KEY_FILE (a file whose contents are the key,
// e.g. an 0600 credential file). Returns "" when none is set.
func apiKeyFromSources(flagKey string) (string, error) {
	if flagKey != "" {
		fmt.Fprintln(os.Stderr, "warning: --api-key on the command line is visible to every local user via /proc/<pid>/cmdline; use the SANDSWAP_API_KEY environment variable or SANDSWAP_API_KEY_FILE instead (the flag is deprecated)")
		return flagKey, nil
	}
	if v := os.Getenv("SANDSWAP_API_KEY"); v != "" {
		return v, nil
	}
	if f := os.Getenv("SANDSWAP_API_KEY_FILE"); f != "" {
		data, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read SANDSWAP_API_KEY_FILE %s: %w", f, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", nil
}

// apiKeyOrExit is apiKeyFromSources plus the CLI's fail-fast error handling.
func apiKeyOrExit(flagKey string) string {
	k, err := apiKeyFromSources(flagKey)
	if err != nil {
		fail("%v", err)
	}
	return k
}

// apiHeader returns the mTLS/ops headers if configured (none needed for the
// dev single-node gateway, which has no OIDC).
func apiHeader(_ Global) map[string]string { return nil }

// bearerFor prints the resolved key and returns it; on failure exits.
func bearerFor(g Global, agentID, key string) string {
	k, err := resolveAgentKey(g, agentID, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	return k
}
