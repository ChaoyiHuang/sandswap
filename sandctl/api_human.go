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
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ── namespace routing (api agent + api sandfs) ─────────────────

// extractNSFlag pulls --namespace VALUE (or -ns VALUE / --namespace=VALUE)
// out of args and returns the cleaned args. Shared by `api agent` and
// `api sandfs`: a non-empty value routes EVERY request in that invocation to
// the namespaced tenant surface /human/ns/<ns>/… ; empty keeps the
// fleet-wide admin surface (which requires the * namespace grant when OIDC
// is configured). The ns value itself is validated server-side.
func extractNSFlag(args []string) (ns string, rest []string) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-ns" || a == "--namespace":
			if i+1 >= len(args) {
				fail("--namespace requires a value")
			}
			ns = args[i+1]
			i++
		case strings.HasPrefix(a, "-ns="):
			ns = strings.TrimPrefix(a, "-ns=")
		case strings.HasPrefix(a, "--namespace="):
			ns = strings.TrimPrefix(a, "--namespace=")
		default:
			rest = append(rest, a)
		}
	}
	return ns, rest
}

// nsJoin maps a fleet-surface path onto the namespace surface: nsJoin("acme",
// "/human/agent") == "/human/ns/acme/agent". ns == "" returns base unchanged.
func nsJoin(ns, base string) string {
	if ns == "" {
		return base
	}
	return "/human/ns/" + ns + strings.TrimPrefix(base, "/human")
}

// ── api agent ───────────────────────────────────────────────────

func apiAgent(g Global, args []string) {
	if len(args) == 0 {
		fail("api agent <create|list|delete>")
	}
	ns, args := extractNSFlag(args)
	switch args[0] {
	case "create":
		fs := newFlagSet("api agent create")
		var name string
		fs.StringVar(&name, "name", "", "agent name (required)")
		fs.Parse(args[1:])
		if name == "" {
			fail("--name is required")
		}
		body := map[string]string{"name": name}
		raw := g.postJSON(g.HumanURL, nsJoin(ns, "/human/agent"), body, "", apiHeader(g))
		// Cache the returned api_key so --agent <id> resolves later.
		var resp struct {
			AgentID string `json:"agent_id"`
			APIKey  string `json:"api_key"`
			Name    string `json:"name"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.AgentID != "" {
			if err := addAgent(g, AgentRecord{resp.AgentID, resp.APIKey, resp.Name}); err != nil {
				fmt.Fprintf(os.Stderr, "warn: cache agent: %v\n", err)
			}
		}
	case "list":
		fs := newFlagSet("api agent list")
		limit := fs.Int("limit", 0, "page size (0 = server default 100, max 1000)")
		all := fs.Bool("all", false, "follow cursors and print every page (bounded at 10000 pages)")
		fs.Parse(args[1:])
		g.getPagedJSON(g.HumanURL, nsJoin(ns, "/human/agent"), *limit, *all, apiHeader(g))
	case "delete":
		if len(args) < 2 {
			fail("api agent delete <agent-id>")
		}
		g.deleteJSON(g.HumanURL, nsJoin(ns, "/human/agent")+"/"+args[1], "", apiHeader(g))
	default:
		fail("unknown api agent subcommand %q", args[0])
	}
}

// ── api sandfs ──────────────────────────────────────────────────

func apiSandFS(g Global, args []string) {
	if len(args) == 0 {
		fail("api sandfs <create|list|get|delete|save-template|detach-template|attach-template|swap-template>")
	}
	ns, args := extractNSFlag(args)
	base := nsJoin(ns, "/human/sandfs")
	switch args[0] {
	case "create":
		fs := newFlagSet("api sandfs create")
		var agentID, name, desc, template, mode string
		var vcpus uint64
		var memMB uint64
		fs.StringVar(&agentID, "agent", "", "owner agent id (required)")
		fs.StringVar(&name, "name", "", "sandfs name (required)")
		fs.StringVar(&desc, "description", "", "sandfs description")
		fs.StringVar(&template, "template", "", "template ref (e.g. ubuntu:24.04)")
		fs.StringVar(&mode, "mode", "flat", "flat | overlay")
		fs.Uint64Var(&vcpus, "vcpus", 0, "minimum vCPUs (0 = inherit template/no requirement)")
		fs.Uint64Var(&memMB, "memory-mb", 0, "minimum memory MB (0 = inherit/no requirement)")
		fs.Parse(args[1:])
		if agentID == "" || name == "" {
			fail("--agent and --name are required")
		}
		if template == "" {
			fail("--template is required (e.g. ubuntu:24.04)")
		}
		body := map[string]any{
			"agent_id": agentID, "name": name, "template": template, "mode": mode,
		}
		if desc != "" {
			body["description"] = desc
		}
		if vcpus != 0 {
			body["vcpus"] = vcpus
		}
		if memMB != 0 {
			body["memory_mb"] = memMB
		}
		g.postJSON(g.HumanURL, base, body, "", apiHeader(g))
	case "list":
		fs := newFlagSet("api sandfs list")
		limit := fs.Int("limit", 0, "page size (0 = server default 100, max 1000)")
		all := fs.Bool("all", false, "follow cursors and print every page (bounded at 10000 pages)")
		fs.Parse(args[1:])
		g.getPagedJSON(g.HumanURL, base, *limit, *all, apiHeader(g))
	case "get":
		if len(args) < 2 {
			fail("api sandfs get <sandfs-id>")
		}
		g.getJSON(g.HumanURL, base+"/"+args[1], "", apiHeader(g))
	case "delete":
		if len(args) < 2 {
			fail("api sandfs delete <sandfs-id>")
		}
		g.deleteJSON(g.HumanURL, base+"/"+args[1], "", apiHeader(g))
	case "detach-template":
		if len(args) < 2 {
			fail("api sandfs detach-template <sandfs-id> [--wait-sec N]")
		}
		fs := newFlagSet("api sandfs detach-template")
		waitSec := fs.Int("wait-sec", 0, "drain wait budget in seconds (0 = server default 15)")
		fs.Parse(args[2:])
		body := map[string]any{}
		if *waitSec > 0 {
			body["wait_sec"] = *waitSec
		}
		g.postJSON(g.HumanURL, base+"/"+args[1]+"/detach-template", body, "", apiHeader(g))
	case "attach-template":
		if len(args) < 3 {
			fail("api sandfs attach-template <sandfs-id> <template-ref> [--home keep|archive|reset]")
		}
		home := homePolicyFlag(newFlagSet("api sandfs attach-template"), args[3:])
		body := map[string]any{"template_ref": args[2]}
		if home != "" {
			body["home"] = home
		}
		g.postJSON(g.HumanURL, base+"/"+args[1]+"/attach-template", body, "", apiHeader(g))
	case "swap-template":
		if len(args) < 3 {
			fail("api sandfs swap-template <sandfs-id> <template-ref> [--home keep|archive|reset] [--wait-sec N]")
		}
		fs := newFlagSet("api sandfs swap-template")
		home := fs.String("home", "", "what happens to /home/agent on attach: keep (default) | archive | reset")
		waitSec := fs.Int("wait-sec", 0, "drain wait budget in seconds (0 = server default 15)")
		fs.Parse(args[3:])
		switch *home {
		case "", "keep", "archive", "reset":
		default:
			fail("--home must be keep, archive, or reset (got %q)", *home)
		}
		body := map[string]any{"template_ref": args[2]}
		if *home != "" {
			body["home"] = *home
		}
		if *waitSec > 0 {
			body["wait_sec"] = *waitSec
		}
		g.postJSON(g.HumanURL, base+"/"+args[1]+"/swap-template", body, "", apiHeader(g))
	case "save-template":
		if len(args) < 2 {
			fail("api sandfs save-template <sandfs-id>")
		}
		sandfsID := args[1]
		fs := newFlagSet("api sandfs save-template")
		var name, ver string
		var vcpus, memMB uint64
		fs.StringVar(&name, "name", "", "template name")
		fs.StringVar(&ver, "version", "", "template version")
		fs.Uint64Var(&vcpus, "vcpus", 0, "override minimum vCPUs (0 = inherit source sandfs)")
		fs.Uint64Var(&memMB, "memory-mb", 0, "override minimum memory MB (0 = inherit)")
		fs.Parse(args[2:])
		body := map[string]any{}
		// Handler expects `template_ref` like "name:version" (handler/human.go:
		// SaveAsTemplateRequest.TemplateRef). Combine --name + --version.
		if name != "" || ver != "" {
			ref := name
			if ver != "" {
				if ref == "" {
					ref = ver
				} else {
					ref = ref + ":" + ver
				}
			}
			body["template_ref"] = ref
		}
		if vcpus != 0 {
			body["vcpus"] = vcpus
		}
		if memMB != 0 {
			body["memory_mb"] = memMB
		}
		g.postJSON(g.HumanURL, base+"/"+sandfsID+"/save-template", body, "", apiHeader(g))
	default:
		fail("unknown api sandfs subcommand %q", args[0])
	}
}

// homePolicyFlag registers the shared --home keep|archive|reset flag on fs and
// parses args, returning the validated policy ("" = server default keep).
func homePolicyFlag(fs *flag.FlagSet, args []string) string {
	home := fs.String("home", "", "what happens to /home/agent on attach: keep (default) | archive | reset")
	_ = fs.Parse(args)
	switch *home {
	case "", "keep", "archive", "reset":
		return *home
	default:
		fail("--home must be keep, archive, or reset (got %q)", *home)
		return ""
	}
}

// ── api template ────────────────────────────────────────────────

// templateModeFlags parses the optional --mode=flat|overlay flag shared by
// the template pull/push subcommands. Returns the request body to send.
func templateModeFlags(args []string) map[string]any {
	body := map[string]any{}
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--mode="):
			mode := strings.TrimPrefix(a, "--mode=")
			if mode != "flat" && mode != "overlay" {
				fail("--mode must be flat or overlay (got %q)", mode)
			}
			body["mode"] = mode
		default:
			fail("unknown flag %q (use --mode=flat|overlay)", a)
		}
	}
	return body
}

func apiTemplate(g Global, args []string) {
	if len(args) == 0 {
		fail("api template <list|pull|push|delete>")
	}
	switch args[0] {
	case "list":
		g.getJSON(g.HumanURL, "/human/templates", "", apiHeader(g))
	case "pull":
		if len(args) < 2 {
			fail("api template pull <ref> [--mode=flat|overlay]")
		}
		g.postJSON(g.HumanURL, "/human/templates/"+args[1], templateModeFlags(args[2:]), "", apiHeader(g))
	case "push":
		if len(args) < 2 {
			fail("api template push <ref> [--mode=flat|overlay]")
		}
		g.postJSON(g.HumanURL, "/human/templates/"+args[1]+"/push", templateModeFlags(args[2:]), "", apiHeader(g))
	case "delete":
		if len(args) < 2 {
			fail("api template delete <ref> [--mode=flat|overlay] [--force]")
		}
		ref := args[1]
		body := map[string]any{}
		force := false
		for _, a := range args[2:] {
			switch {
			case strings.HasPrefix(a, "--mode="):
				mode := strings.TrimPrefix(a, "--mode=")
				if mode != "flat" && mode != "overlay" {
					fail("--mode must be flat or overlay (got %q)", mode)
				}
				body["mode"] = mode
			case a == "--force":
				force = true
			default:
				fail("unknown flag %q (use --mode=flat|overlay or --force)", a)
			}
		}
		if force {
			body["force"] = true
		}
		// DELETE with a JSON body: the deleteJSON helper sends no body, so use
		// the raw request path with the body encoded.
		g.deleteJSONBody(g.HumanURL, "/human/templates/"+ref, body, apiHeader(g))
	default:
		fail("unknown api template subcommand %q", args[0])
	}
}

// ── api ownership ───────────────────────────────────────────────

func apiOwnership(g Global, args []string) {
	if len(args) == 0 {
		fail("api ownership release <sandfs-id> | reap-stuck <gateway-id> [--dry-run] [--batch N] | reap-stuck-node <node-id> [--dry-run] [--batch N]")
	}
	switch args[0] {
	case "release":
		if len(args) < 2 {
			fail("api ownership release <sandfs-id>")
		}
		g.postJSON(g.HumanURL, "/human/ownership/release/"+args[1], map[string]any{}, "", apiHeader(g))
	case "reap-stuck":
		apiOwnershipReapStuck(g, args[1:])
	case "reap-stuck-node":
		apiOwnershipReapStuckNode(g, args[1:])
	default:
		fail("unknown api ownership subcommand %q", args[0])
	}
}

// apiOwnershipReapStuck drives the manual both-dead reclamation tool
// (POST /human/ownership/reap-stuck). It reclaims sandfs stranded on a
// permanently-dead owner gateway. Operator workflow: confirm the owner AND its
// nodes are permanently gone, run with --dry-run to preview, then without to
// delete.
func apiOwnershipReapStuck(g Global, args []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "--") {
		fail("api ownership reap-stuck <gateway-id> [--dry-run] [--batch N]")
	}
	gwID := args[0]
	dryRun := g.DryRun // honor the global --dry-run too (prints request, no send)
	batch := 0
	for _, a := range args[1:] {
		switch {
		case a == "--dry-run":
			dryRun = true
		case strings.HasPrefix(a, "--batch="):
			n, err := strconv.Atoi(strings.TrimPrefix(a, "--batch="))
			if err != nil || n <= 0 {
				fail("--batch must be a positive integer")
			}
			batch = n
		case a == "--batch":
			fail("--batch requires =N (e.g. --batch=100)")
		default:
			fail("unknown flag %q (use --dry-run or --batch=N)", a)
		}
	}
	body := map[string]any{"gateway_id": gwID, "dry_run": dryRun, "batch_size": batch}
	g.postJSON(g.HumanURL, "/human/ownership/reap-stuck", body, "", apiHeader(g))
}

// apiOwnershipReapStuckNode drives the node-granularity manual reclamation
// tool (POST /human/ownership/reap-stuck-node). It reclaims every sandfs
// recorded as mounted on a permanently-dead sandlot node whose owner is also
// dead — useful when a whole node is retired and you want to reclaim all its
// stranded sandfs in one call. Refused if the node's presence key is still
// alive. Operator workflow: confirm the node is permanently gone (presence key
// absent), run with --dry-run to preview, then without to delete.
func apiOwnershipReapStuckNode(g Global, args []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "--") {
		fail("api ownership reap-stuck-node <node-id> [--dry-run] [--batch N]")
	}
	nodeID := args[0]
	dryRun := g.DryRun
	batch := 0
	for _, a := range args[1:] {
		switch {
		case a == "--dry-run":
			dryRun = true
		case strings.HasPrefix(a, "--batch="):
			n, err := strconv.Atoi(strings.TrimPrefix(a, "--batch="))
			if err != nil || n <= 0 {
				fail("--batch must be a positive integer")
			}
			batch = n
		case a == "--batch":
			fail("--batch requires =N (e.g. --batch=100)")
		default:
			fail("unknown flag %q (use --dry-run or --batch=N)", a)
		}
	}
	body := map[string]any{"node_id": nodeID, "dry_run": dryRun, "batch_size": batch}
	g.postJSON(g.HumanURL, "/human/ownership/reap-stuck-node", body, "", apiHeader(g))
}
