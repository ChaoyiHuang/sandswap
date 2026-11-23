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

// template-tool — the single implementation of the Sandswap TEMPLATE
// CONTRACT (docs/operations/template-contract.md): every entry of a template
// tree must be reachable by the consuming service identities through the
// shared group (directories g+rx; files mirror their owner r/x bits into the
// group), because the FUSE passthrough daemon (sandvmm) performs every guest
// read and the exec sandlot mounts the layers — neither is the tree's owner.
//
// Subcommands:
//
//	template-tool normalize <dir>   apply the contract in place (idempotent);
//	                                prints how many entries changed
//	template-tool check <dir>       validate the contract only; exits 1 and
//	                                lists every violation (path mode reason)
//	template-tool validate <dir>    full offline conformance of a template
//	                                tree: the contract plus rootfs
//	                                well-formedness (/bin/sh, skeleton dirs,
//	                                volume control files, unsupported entry
//	                                types); a scan root (name/version/
//	                                nesting) validates every leaf tree
//	template-tool check-store <dir> [--flat-root <dir>]...
//	                                integrity of a template store (refs/ +
//	                                layers/): ref identity and modes, the
//	                                layer trust boundary, layer presence,
//	                                orphans and writer debris
//	template-tool volume-name / seed-generate / seed-scan /
//	                       volume-stamp-read / volume-stamp-write
//	                                volume identity helpers (see usage)
//
// Producers (build/build-rootfs-template.sh, build/build-ubuntu-rootfs.sh,
// deploy copies, operators building a rootfs by hand) run `normalize`; CI and
// the build scripts additionally run `validate` as the gate. The prov instance
// applies the same policy at layer materialization as a backstop.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"sandlot/hostbin"
	"sandlot/provision/template"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  template-tool normalize <dir>   apply the Sandswap template contract in place
  template-tool check <dir>       validate the contract (exit 1 on violations)
  template-tool validate <dir> [--expect-group NUM|NAME]
                                  full offline conformance of a template tree:
                                  the contract + /bin/sh, skeleton dirs,
                                  volume control files, unsupported entry
                                  types; a scan root validates every leaf;
                                  --expect-group adds the static group audit
                                  (entries that rely on the group grant must
                                  carry the expected gid — numeric form is
                                  the cross-host contract, a name resolves
                                  on this host)
  template-tool import <src> --name N --version V [--out DIR] [--push REGISTRY/REPO]
                                  offline conversion of a local OCI image
                                  archive (docker save ≥25, skopeo
                                  oci-archive, buildx type=oci, podman
                                  oci-archive) or a plain rootfs tar
                                  (docker export, minirootfs) into a
                                  validated template — published as a local
                                  tree at <out>/<name>/<version>/ and/or
                                  pushed straight to an OCI registry as a
                                  Sandswap template artifact (tag
                                  <name>-<version>; no gateway needed;
                                  the artifact is mode-agnostic — the
                                  consuming side pulls it as flat or
                                  overlay). Flags: --platform (linux/amd64
                                  only), --description, --group NUM|NAME
                                  (settle the published tree's group — the
                                  grant the contract rides on; default: the
                                  gid of the --out root; a numeric gid is
                                  used as-is for cross-host preparation, a
                                  name resolves on this host),
                                  --registry-username/-password/-token/
                                  -ca/-cert/-key; the credential flags fall
                                  back to the SANDSWAP_REGISTRY_USERNAME,
                                  SANDSWAP_REGISTRY_PASSWORD and
                                  SANDSWAP_REGISTRY_TOKEN env vars (keep
                                  secrets out of the process list).
                                  Whiteouts and opaque dirs applied;
                                  linux/amd64 only
  template-tool check-store <dir> [--flat-root <dir>]... [--expect-group NUM|NAME]
                                  integrity of a template store (refs/ +
                                  layers/): ref identity, layer trust
                                  boundary, layer presence, orphans, and
                                  the group audit (layers/, the store root
                                  and in-store template trees). The group
                                  audit compares against the store root's
                                  own group by default; --expect-group
                                  overrides it with the TARGET deployment's
                                  shared gid (cross-host: a store moved
                                  with cp -a from a differently-numbered
                                  host is internally consistent yet
                                  unreachable — only an external expected
                                  number can catch it);
                                  --flat-root is the PROV instance's
                                  -flat-templates path as the refs record it
  template-tool volume-name --prov-config <path> --id <sandfs-id> [--generation current|next] [--fingerprint]
                                  derive the on-disk volume directory name (reads the seed from the config)
  template-tool seed-generate [--out <file>]
                                  mint a fresh volume-name seed (hex)
  template-tool seed-scan --prov-config <path> [--json]
                                  read every volume's generation stamp and print the
                                  promote completeness verdict (exit 1 = refuse)
  template-tool volume-stamp-read --volume <dir> [--field sandfs_id|generation|mode|created_unix]
                                  read a volume's identity stamp SAFELY (no symlink/
                                  FIFO following; exit 1 when the entry is unsafe)
  template-tool volume-stamp-write --prov-config <path> --volume <dir> --id <sandfs-id>
                                   --generation current|next [--mode flat|overlay] [--created-unix N]
                                   [--previous-name <old-dir-name>]
                                  re-sign a volume's identity stamp in place (atomic,
                                  symlink-proof; preserves mode/created/volume_epoch when the
                                  existing stamp verifies, including under a rotation rename)`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]

	// Pin cp for SaveAsTemplate/materialization paths.
	hostbin.Init()

	// Subcommands that take flags (not a positional directory) dispatch
	// BEFORE the <dir> validation below.
	if cmd == "import" {
		os.Exit(importCmd(os.Args[2:]))
	}
	if cmd == "validate" {
		os.Exit(validateCmd(os.Args[2:]))
	}
	if cmd == "volume-name" || cmd == "seed-generate" || cmd == "seed-scan" ||
		cmd == "volume-stamp-read" || cmd == "volume-stamp-write" {
		os.Exit(volumeNameCmd(cmd, os.Args[2:]))
	}
	if cmd == "check-store" {
		os.Exit(checkStoreCmd(os.Args[2:]))
	}
	if len(os.Args) != 3 {
		usage()
		os.Exit(2)
	}
	dir := os.Args[2]
	fi, err := os.Stat(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool: %v\n", err)
		os.Exit(2)
	}
	if !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "template-tool: %s is not a directory\n", dir)
		os.Exit(2)
	}

	switch cmd {
	case "normalize":
		changed, err := template.NormalizeTemplateTree(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "template-tool: normalize %s: %v\n", dir, err)
			os.Exit(1)
		}
		fmt.Printf("template-tool: %s normalized (%d entries changed)\n", dir, changed)
	case "check":
		violations, err := template.ValidateTemplateTree(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "template-tool: check %s: %v\n", dir, err)
			os.Exit(1)
		}
		if len(violations) == 0 {
			fmt.Printf("template-tool: %s conforms to the template contract\n", dir)
			return
		}
		fmt.Fprintf(os.Stderr, "template-tool: %s violates the template contract (%d entries):\n", dir, len(violations))
		for i, v := range violations {
			if i == 20 {
				fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(violations)-20)
				break
			}
			fmt.Fprintf(os.Stderr, "  %s  mode=%04o  %s\n", v.Path, v.Mode, v.Reason)
		}
		fmt.Fprintln(os.Stderr, "fix: template-tool normalize "+dir)
		os.Exit(1)
	default:
		usage()
		os.Exit(2)
	}
}

// validateCmd implements `validate <dir> [--expect-group NUM|NAME]`: the full
// offline conformance pass, plus — with --expect-group — the static group
// audit from template/groupaudit.go, so a wrong group is caught offline
// instead of as an EACCES at sandfs create. The walk has to list every
// directory (the contract rules share the pass), so a tree carrying a
// 0700 directory owned by another identity can only be audited by its
// owner or root. The numeric form is the contract (cross-host); a name
// resolves on this host. Parsed by hand like checkStoreCmd so the
// directory and flags work in either order.
func validateCmd(args []string) int {
	var expectGroup string
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--expect-group" || a == "-expect-group":
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				fmt.Fprintln(os.Stderr, "template-tool validate: --expect-group requires an argument (numeric gid, or a group name resolved on this host)")
				return 2
			}
			expectGroup = args[i]
		case strings.HasPrefix(a, "--expect-group=") || strings.HasPrefix(a, "-expect-group="):
			expectGroup = a[strings.IndexByte(a, '=')+1:]
			if expectGroup == "" {
				fmt.Fprintln(os.Stderr, "template-tool validate: --expect-group requires an argument (numeric gid, or a group name resolved on this host)")
				return 2
			}
		case a == "-h" || a == "--help":
			usage()
			return 2
		case strings.HasPrefix(a, "-") && a != "-":
			fmt.Fprintf(os.Stderr, "template-tool validate: unknown flag %s\n", a)
			return 2
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "template-tool validate: exactly one directory is required")
		return 2
	}
	dir := rest[0]
	fi, err := os.Stat(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool: %v\n", err)
		return 2
	}
	if !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "template-tool: %s is not a directory\n", dir)
		return 2
	}
	// A store directory is a category error for this subcommand: the trees
	// under layers/ are layer fragments, never complete rootfs trees —
	// validating them would only produce false findings.
	if template.IsStoreShape(dir) {
		fmt.Fprintf(os.Stderr, "template-tool: %s carries refs/ + layers/ — it is a template store; use: template-tool check-store %s (add --expect-group NUM|NAME for the cross-host form)\n", dir, dir)
		return 2
	}
	var findings []template.Finding
	if template.IsScanRootDir(dir) {
		findings, err = template.ValidateScanRoot(dir)
	} else {
		findings, err = template.ValidateRootfsTree(dir)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool: validate %s: %v\n", dir, err)
		return 1
	}

	if expectGroup != "" {
		gid, gerr := template.ResolveGroupSpec(expectGroup)
		if gerr != nil {
			fmt.Fprintf(os.Stderr, "template-tool validate: --expect-group: %v\n", gerr)
			return 2
		}
		var audit *template.GroupGrantAudit
		var aerr error
		if template.IsScanRootDir(dir) {
			// Mirror the registration scan's classification: top-level dot
			// entries, layers/ and refs/ are not consumed, so their groups
			// must not be judged (the discovery skips exactly these).
			audit, aerr = template.AuditGroupGrantsSkipping(dir, gid, func(path string, d fs.DirEntry) bool {
				if filepath.Dir(path) != dir || !d.IsDir() {
					return false
				}
				name := d.Name()
				return strings.HasPrefix(name, ".") || name == "layers" || name == "refs"
			})
		} else {
			audit, aerr = template.AuditGroupGrants(dir, gid)
		}
		if aerr != nil {
			fmt.Fprintf(os.Stderr, "template-tool: validate %s: group audit: %v\n", dir, aerr)
			return 1
		}
		// A subtree the contract pass already reported as unreadable is not
		// repeated here; the group audit's own unreachable entries carry the
		// audit's reach, not a wrong gid.
		reportedUnreadable := map[string]bool{}
		for _, f := range findings {
			if f.Rule == "unreadable" {
				reportedUnreadable[f.Path] = true
			}
		}
		for _, u := range audit.Unreachable {
			if reportedUnreadable[u.Path] {
				continue
			}
			findings = append(findings, template.Finding{
				Path: u.Path, Severity: template.SeverityError, Rule: "unreadable",
				Detail: fmt.Sprintf("the group audit cannot list this subtree as the current identity (%v): run the audit as the tree's owner or root — the grant below it is unjudged", u.Err),
			})
		}
		for _, p := range audit.WrongGroup {
			findings = append(findings, template.Finding{
				Path: p, Severity: template.SeverityError, Rule: "group-grant",
				Detail: fmt.Sprintf("entry relies on the group grant (a file without other-read, or a directory without other-list/traverse) but its gid is not the expected %d — EACCES for every consuming service identity; fix: chgrp -R %d %s", gid, gid, dir),
			})
		}
		if audit.Reliant > 0 && len(audit.WrongGroup) == 0 && len(audit.Unreachable) == 0 {
			findings = append(findings, template.Finding{
				Path: dir, Severity: template.SeverityInfo, Rule: "group-grant",
				Detail: fmt.Sprintf("%d entries rely on the group grant and all carry the expected gid %d", audit.Reliant, gid),
			})
		} else if audit.Reliant == 0 && len(audit.Unreachable) == 0 {
			findings = append(findings, template.Finding{
				Path: dir, Severity: template.SeverityInfo, Rule: "group-grant",
				Detail: "every entry is other-readable/traversable — the group grant is not load-bearing for this tree",
			})
		}
	}
	return reportFindings("validate", dir, findings)
}

// reportFindings prints a finding list and returns the exit code: 0 when no
// error-severity finding exists, 1 otherwise. Warnings and info lines print
// either way — the tool's value is the full picture, the exit code is the
// gate.
func reportFindings(cmd, subject string, findings []template.Finding) int {
	counts := map[template.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	if len(findings) == 0 {
		fmt.Printf("template-tool: %s conforms (%s: no findings)\n", subject, cmd)
		return 0
	}
	fmt.Fprintf(os.Stderr, "template-tool: %s — %s: %d error(s), %d warning(s), %d info\n",
		subject, cmd, counts[template.SeverityError], counts[template.SeverityWarning], counts[template.SeverityInfo])
	for i, f := range findings {
		if i == 20 {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(findings)-20)
			break
		}
		fmt.Fprintf(os.Stderr, "  [%s] %s\n        %s\n", f.Severity, f.Path, f.Detail)
	}
	if counts[template.SeverityError] == 0 {
		// The count summary above already names the warning/info totals; this
		// line only states the verdict (an info-only run is not "warnings").
		fmt.Fprintf(os.Stderr, "template-tool: %s passes (exit 0; errors only fail the gate)\n", subject)
		return 0
	}
	return 1
}

// checkStoreCmd implements `check-store <dir> [--flat-root <dir>]...`: the
// offline integrity pass over a template store. --flat-root repeats the
// operator's -flat-templates scan roots so absolute flat layer paths can be
// judged against the union of legal roots (exactly what the runtime's
// flatLayerRoots enforces at consume time). Parsed by hand (not the flag
// package) so the directory and the flags work in either order.
func checkStoreCmd(args []string) int {
	var flatRoots []string
	var expectGroup string
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--expect-group" || a == "-expect-group":
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				fmt.Fprintln(os.Stderr, "template-tool check-store: --expect-group requires an argument (numeric gid, or a group name resolved on this host)")
				return 2
			}
			expectGroup = args[i]
		case strings.HasPrefix(a, "--expect-group=") || strings.HasPrefix(a, "-expect-group="):
			expectGroup = a[strings.IndexByte(a, '=')+1:]
			if expectGroup == "" {
				fmt.Fprintln(os.Stderr, "template-tool check-store: --expect-group requires an argument (numeric gid, or a group name resolved on this host)")
				return 2
			}
		case a == "--flat-root" || a == "-flat-root":
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				fmt.Fprintln(os.Stderr, "template-tool check-store: --flat-root requires a directory argument")
				return 2
			}
			flatRoots = append(flatRoots, args[i])
		case strings.HasPrefix(a, "--flat-root=") || strings.HasPrefix(a, "-flat-root="):
			v := a[strings.IndexByte(a, '=')+1:]
			if v == "" {
				fmt.Fprintln(os.Stderr, "template-tool check-store: --flat-root requires a directory argument")
				return 2
			}
			flatRoots = append(flatRoots, v)
		case a == "-h" || a == "--help":
			usage()
			return 2
		case strings.HasPrefix(a, "-") && a != "-":
			fmt.Fprintf(os.Stderr, "template-tool check-store: unknown flag %s\n", a)
			return 2
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "template-tool check-store: exactly one store directory is required")
		return 2
	}
	dir := rest[0]
	expectGid := -1
	if expectGroup != "" {
		gid, gerr := template.ResolveGroupSpec(expectGroup)
		if gerr != nil {
			fmt.Fprintf(os.Stderr, "template-tool check-store: --expect-group: %v\n", gerr)
			return 2
		}
		expectGid = gid
	}
	findings, err := template.ValidateStoreWithExpectedGroup(dir, flatRoots, expectGid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool: check-store %s: %v\n", dir, err)
		return 2
	}
	return reportFindings("check-store", dir, findings)
}
