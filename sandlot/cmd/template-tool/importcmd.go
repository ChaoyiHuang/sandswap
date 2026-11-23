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

	"sandlot/provision/template"
	"sandlot/provision/template/imageimport"
)

// importCmd implements `template-tool import <src> --name N --version V
// [--out DIR] [--push REGISTRY/REPO]`: offline conversion of a local OCI
// image archive (docker save ≥25 / skopeo oci-archive / buildx type=oci /
// podman oci-archive) or a plain rootfs tar (docker export, minirootfs) into
// a validated Sandswap template — published as a local tree under
// <out>/<name>/<version>/ and/or pushed straight to an OCI registry as a
// Sandswap template artifact (no gateway, no running stack; the same
// packing/push code the prov instance serves).
//
// Parsed by hand (not the flag package) so the source path and the flags
// work in either order — `import <src> --name n` is the natural spelling.
func importCmd(args []string) int {
	var name, version, out, platform, push, description, group string
	var username, password, token, caFile, certFile, keyFile string
	platform = "linux/amd64"
	var rest []string

	valueFlags := map[string]*string{
		"--name": &name, "-name": &name,
		"--version": &version, "-version": &version,
		"--out": &out, "-out": &out,
		"--platform": &platform, "-platform": &platform,
		"--push": &push, "-push": &push,
		"--description": &description, "-description": &description,
		"--group": &group, "-group": &group,
		"--registry-username": &username, "-registry-username": &username,
		"--registry-password": &password, "-registry-password": &password,
		"--registry-token": &token, "-registry-token": &token,
		"--registry-ca": &caFile, "-registry-ca": &caFile,
		"--registry-cert": &certFile, "-registry-cert": &certFile,
		"--registry-key": &keyFile, "-registry-key": &keyFile,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			rest = append(rest, a)
			continue
		}
		if a == "-h" || a == "--help" {
			usage()
			return 2
		}
		key, val := a, ""
		hasVal := false
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			key, val, hasVal = a[:eq], a[eq+1:], true
		}
		p, ok := valueFlags[key]
		if !ok {
			fmt.Fprintf(os.Stderr, "template-tool import: unknown flag %s\n", a)
			return 2
		}
		if !hasVal {
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "template-tool import: %s requires a value\n", key)
				return 2
			}
			val = args[i]
		}
		*p = val
	}

	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "template-tool import: exactly one source path is required")
		return 2
	}
	if name == "" || version == "" {
		fmt.Fprintln(os.Stderr, "template-tool import: --name and --version are required")
		return 2
	}
	if out == "" && push == "" {
		fmt.Fprintln(os.Stderr, "template-tool import: --out is required (or set --push to publish straight to a registry)")
		return 2
	}

	// Registry credentials: flags win, environment fills the gaps so a CI
	// secret store never has to put a password on the command line (where
	// it is visible in the process list and shell history).
	username = firstNonEmpty(username, os.Getenv("SANDSWAP_REGISTRY_USERNAME"))
	password = firstNonEmpty(password, os.Getenv("SANDSWAP_REGISTRY_PASSWORD"))
	token = firstNonEmpty(token, os.Getenv("SANDSWAP_REGISTRY_TOKEN"))

	res, err := imageimport.Import(imageimport.Options{
		Src:         rest[0],
		Name:        name,
		Version:     version,
		Out:         out,
		Push:        push,
		Description: description,
		Group:       group,
		Auth: template.AuthConfig{
			Username: username,
			Password: password,
			Token:    token,
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		},
		Platform: platform,
		Log: func(format string, args ...any) {
			fmt.Printf("template-tool import: "+format+"\n", args...)
		},
	})
	if err != nil {
		// A combined run publishes locally before pushing; on a push
		// failure the validated local template is kept, and the operator
		// must be told where it is.
		if res != nil && res.Path != "" {
			fmt.Fprintf(os.Stderr, "template-tool import: local template kept at %s\n", res.Path)
		}
		fmt.Fprintf(os.Stderr, "template-tool import: %v\n", err)
		return 1
	}
	fmt.Printf("template-tool import: %s → %s\n", res.Source, orDash(res.Path))
	fmt.Printf("  ref:      %s\n", res.TemplateRef)
	fmt.Printf("  platform: %s\n", res.Platform)
	if res.PushDigest != "" {
		fmt.Printf("  pushed:   %s/%s (digest %s)\n", push,
			strings.ReplaceAll(res.TemplateRef, ":", "-"), res.PushDigest)
	}
	if len(res.Warnings) > 0 {
		fmt.Printf("  warnings: %d (see above)\n", len(res.Warnings))
	}
	if res.Path != "" {
		fmt.Printf("next:\n")
		fmt.Printf("  output/template-tool validate %s\n", res.Path)
		fmt.Printf("  flat:    place the tree under the prov instance's -flat-templates scan root\n")
		fmt.Printf("  overlay: place the tree under the template store (-templates-dir)\n")
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "(registry only, no local output)"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
