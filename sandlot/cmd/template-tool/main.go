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
	"os"
	"strings"

	"sandlot/hostbin"
	"sandlot/provision/template"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  template-tool normalize <dir>   apply the Sandswap template contract in place
  template-tool check <dir>       validate the contract (exit 1 on violations)
  template-tool validate <dir>    full offline conformance of a template tree:
                                  the contract + /bin/sh, skeleton dirs,
                                  volume control files, unsupported entry
                                  types; a scan root validates every leaf
  template-tool check-store <dir> [--flat-root <dir>]...
                                  integrity of a template store (refs/ +
                                  layers/): ref identity, layer trust
                                  boundary, layer presence, orphans;
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
	case "validate":
		// A store directory is a category error for this subcommand: the
		// trees under layers/ are layer fragments, never complete rootfs
		// trees — validating them would only produce false findings.
		if template.IsStoreShape(dir) {
			fmt.Fprintf(os.Stderr, "template-tool: %s carries refs/ + layers/ — it is a template store; use: template-tool check-store %s\n", dir, dir)
			os.Exit(2)
		}
		var findings []template.Finding
		var err error
		if template.IsScanRootDir(dir) {
			findings, err = template.ValidateScanRoot(dir)
		} else {
			findings, err = template.ValidateRootfsTree(dir)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "template-tool: validate %s: %v\n", dir, err)
			os.Exit(1)
		}
		os.Exit(reportFindings("validate", dir, findings))
	default:
		usage()
		os.Exit(2)
	}
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
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
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
	findings, err := template.ValidateStore(dir, flatRoots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool: check-store %s: %v\n", dir, err)
		return 2
	}
	return reportFindings("check-store", dir, findings)
}
