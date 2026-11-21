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

// Package imageimport converts a local OCI image archive (or a plain rootfs
// tar) into a Sandswap rootfs template tree, offline: no registry, no
// network, no root. The output is a scan-layout directory
// <out>/<name>/<version>/ that registers itself when placed under a
// -flat-templates scan root (flat) or the template store (overlay), and it
// is gated on the full template contract (normalize + validate) before
// anything is published.
//
// The one substantive algorithm is the layer merge: container image layers
// carry OCI whiteout/opaque semantics that Sandswap's own single-layer
// template format never produces, so the layers are applied bottom→top into
// ONE merged tree (deletions applied, type transitions resolved) instead of
// being kept as a lowerdir stack.
package imageimport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"sandlot/provision/template"
)

// shortDigestString truncates a digest string for logs (the string form of
// layout.go's shortDigest).
func shortDigestString(s string) string {
	if len(s) > 19 {
		return s[:19] + "…"
	}
	return s
}

// Options configures one import run.
type Options struct {
	// Src is the source: an OCI image-layout directory, a tar/tar.gz
	// archive of one (docker save ≥25, skopeo oci-archive, buildx
	// type=oci, podman --format oci-archive), or a plain rootfs tar /
	// directory (docker export, distro minirootfs).
	Src string
	// Name / Version form the template ref ("name:version") and the output
	// path <out>/<name>/<version>/.
	Name    string
	Version string
	// Out is the output root (created when absent). It should be (or sit
	// beside) the directory a sandlot scan root watches. Optional when Push
	// is set (push-only run: nothing lands on local disk).
	Out string
	// Push, when non-empty, is an OCI registry REPOSITORY reference
	// ("registry.example.com/sandswap-templates") the converted template is
	// pushed to as a Sandswap template artifact — standalone, reusing the
	// same packing/push code the prov instance serves, no gateway involved.
	// The artifact tag is always <name>-<version> (the form template pull
	// expects). The artifact is mode-agnostic: the consuming side pulls it
	// as flat or overlay.
	Push string
	// Description lands in the pushed artifact's annotations.
	Description string
	// Auth carries the push registry credentials (basic / token / mTLS /
	// private CA — the same options the prov instance takes).
	Auth template.AuthConfig
	// Platform selects the image manifest from a multi-platform archive
	// ("linux/amd64", optionally with a /variant). Empty defaults to
	// linux/amd64. The only accepted value today is linux/amd64 — the
	// shipped guest kernel and VMM are x86_64-only, and static validation
	// cannot catch a wrong-architecture userspace at exec time.
	Platform string
	// Log receives progress lines (nil = silent).
	Log func(format string, args ...any)
}

// Result reports a successful import.
type Result struct {
	// TemplateRef is "name:version".
	TemplateRef string
	// Path is the published template tree ("" on a push-only run).
	Path string
	// Source identifies the origin: "oci:<top digest>" for image archives
	// and layouts, "rootfs" for plain rootfs tars/directories.
	Source string
	// Platform is the selected/verified platform ("linux/amd64").
	Platform string
	// PushDigest is the pushed artifact's manifest digest ("" when no push).
	PushDigest string
	// Warnings are the non-fatal findings collected along the way.
	Warnings []string
}

// reservedTemplateNames collide with the template store's internal layout;
// reservedTemplateVersions collide with the versioned-dir heuristic in the
// registration scans (a version named bin/usr/… misclassifies the tree).
var reservedTemplateNames = map[string]bool{"layers": true, "refs": true}
var reservedTemplateVersions = map[string]bool{
	"bin": true, "etc": true, "usr": true, "lib": true, "sbin": true, "var": true,
}

// Import converts opts.Src into a validated template tree and publishes it
// atomically under opts.Out. It never writes ref files — discovery owns
// registration — and leaves no partial output behind on failure.
func Import(opts Options) (*Result, error) {
	log := opts.Log
	logf := func(format string, args ...any) {
		if log != nil {
			log(format, args...)
		}
	}

	if opts.Src == "" || opts.Name == "" || opts.Version == "" {
		return nil, errors.New("src, name and version are all required")
	}
	if opts.Out == "" && opts.Push == "" {
		return nil, errors.New("out is required (or set push to publish straight to a registry)")
	}
	ref := opts.Name + ":" + opts.Version
	if err := template.ValidateTemplateRef(ref); err != nil {
		return nil, err
	}
	if reservedTemplateNames[opts.Name] {
		return nil, fmt.Errorf("template name %q collides with the template store's internal layout", opts.Name)
	}
	if reservedTemplateVersions[opts.Version] {
		return nil, fmt.Errorf("template version %q collides with the versioned-directory scan heuristic; pick a different version", opts.Version)
	}
	want, err := parsePlatformPolicy(opts.Platform)
	if err != nil {
		return nil, err
	}

	// Same-filesystem staging under the output root when publishing locally
	// (the publish step is a rename); the dot prefix keeps it invisible to
	// template discovery. A push-only run has no local output — stage in
	// the system temp instead.
	var stagingRoot string
	if opts.Out == "" {
		if stagingRoot, err = os.MkdirTemp("", "template-import-"); err != nil {
			return nil, fmt.Errorf("create staging: %w", err)
		}
	} else {
		if err := os.MkdirAll(opts.Out, 0o755); err != nil {
			return nil, fmt.Errorf("create output root: %w", err)
		}
		if stagingRoot, err = os.MkdirTemp(opts.Out, ".template-import-"); err != nil {
			return nil, fmt.Errorf("create staging: %w", err)
		}
	}
	defer os.RemoveAll(stagingRoot)

	prepared, err := prepareSource(opts.Src, stagingRoot)
	if err != nil {
		return nil, err
	}
	for _, w := range prepared.warnings {
		logf("%s", w)
	}

	res := &Result{TemplateRef: ref, Platform: platformString(want)}
	res.Warnings = append(res.Warnings, prepared.warnings...)

	var tree string
	if prepared.layout != nil {
		res.Source = "oci"
		img, err := resolveImage(prepared.layout, want)
		if err != nil {
			return nil, err
		}
		res.Source = "oci:" + img.digest.String()
		logf("image manifest %s (%d layers, %s)", shortDigest(img.digest), len(img.manifest.Layers), res.Platform)

		tree = filepath.Join(stagingRoot, "tree")
		if err := os.MkdirAll(tree, 0o755); err != nil {
			return nil, err
		}
		if err := mergeLayers(prepared.layout, img.manifest.Layers, tree, logf); err != nil {
			return nil, err
		}
	} else {
		res.Source = "rootfs"
		tree = prepared.rootfs
		msg := "plain rootfs sources carry no platform metadata — the userspace must be linux/amd64 (the shipped guest kernel and VMM are x86_64-only)"
		res.Warnings = append(res.Warnings, msg)
		logf("%s", msg)
	}

	// On a push-only run there is no final local path to report against;
	// keep the staging path rather than inventing a relative one.
	var displayTree string
	if opts.Out != "" {
		displayTree = filepath.Join(opts.Out, opts.Name, opts.Version)
	}
	warnings, err := finalizeTree(tree, displayTree, opts.Log)
	if err != nil {
		return nil, err
	}
	res.Warnings = append(res.Warnings, warnings...)

	// Local publication first (when asked for): on a push failure the
	// already-validated local template stays, and the error says which leg
	// failed.
	if opts.Out != "" {
		dst, err := publishTree(tree, stagingRoot, opts.Out, opts.Name, opts.Version)
		if err != nil {
			return nil, err
		}
		res.Path = dst
		tree = dst
	}

	if opts.Push != "" {
		// A CLI tool has no cancellation semantics to plumb; the network
		// leg is bounded by the HTTP client's own timeouts.
		ctx := context.Background()
		pushRes, err := template.PushTemplateDirs(ctx, template.PushTemplateDirRequest{
			Registry:    opts.Push,
			Auth:        opts.Auth,
			TemplateRef: ref,
			Description: opts.Description,
			LayerDirs:   []string{tree},
			Annotations: map[string]string{
				// Producer metadata: what this template was converted from.
				"sandswap.template.source.image":    res.Source,
				"sandswap.template.source.platform": res.Platform,
			},
		})
		if err != nil {
			return res, fmt.Errorf("push to %s (local template, if any, is kept): %w", opts.Push, err)
		}
		res.PushDigest = pushRes.Digest
		logf("pushed %s → %s/%s (digest %s, %d bytes, %d ms)", ref, opts.Push,
			strings.ReplaceAll(ref, ":", "-"), shortDigestString(pushRes.Digest), pushRes.Size, pushRes.PushTimeMs)
	}
	return res, nil
}

// publishTree installs tree at <out>/<name>/<version> without ever exposing
// a half-made layout to a live discovery scan:
//
//   - an existing <name>/ must be a real directory (the scans skip symlinks
//     by design); the version is renamed in atomically inside it.
//   - a MISSING <name>/ is published as a whole (name + version together) in
//     one rename. Creating the name directory first would leave it
//     observable-but-empty, and discovery classifies an empty name dir as a
//     rootfs template named <name> — leaving a durable bogus ref behind.
//
// The version directory is immutable: an existing one is refused.
func publishTree(tree, stagingRoot, out, name, version string) (string, error) {
	nameDir := filepath.Join(out, name)
	fi, err := os.Lstat(nameDir)
	switch {
	case err == nil:
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%s exists but is not a real directory — template discovery skips it; remove it or choose another --name", nameDir)
		}
		return installVersion(tree, nameDir, version)
	case !os.IsNotExist(err):
		return "", err
	}

	stagedName := filepath.Join(stagingRoot, "publish", name)
	if err := os.MkdirAll(stagedName, 0o755); err != nil {
		return "", fmt.Errorf("create publish staging: %w", err)
	}
	stagedVersion := filepath.Join(stagedName, version)
	if err := os.Rename(tree, stagedVersion); err != nil {
		return "", fmt.Errorf("stage for publish: %w", err)
	}
	if err := template.InstallTemplateDir(stagedName, nameDir); err == nil {
		return filepath.Join(nameDir, version), nil
	} else if !errors.Is(err, template.ErrRefExists) {
		return "", fmt.Errorf("publish: %w", err)
	}
	// Lost a race with another publisher of the same name: publish the
	// already-staged version inside the now-existing name directory.
	if fi, err := os.Lstat(nameDir); err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s appeared during publish but is not a real directory", nameDir)
	}
	return installVersion(stagedVersion, nameDir, version)
}

// installVersion atomically installs a completed tree as <nameDir>/<version>.
func installVersion(tree, nameDir, version string) (string, error) {
	dst := filepath.Join(nameDir, version)
	if err := template.InstallTemplateDir(tree, dst); err != nil {
		if errors.Is(err, template.ErrRefExists) {
			return "", fmt.Errorf("%s already exists — template refs are immutable: pick a new --version or remove it deliberately", dst)
		}
		return "", fmt.Errorf("publish: %w", err)
	}
	return dst, nil
}

// mergeLayers applies the image's layers bottom→top onto tree: extract each
// blob (digest-verified) into a per-layer staging dir, apply its whiteouts
// to the merged tree, merge the remaining entries, drop the staging dir.
func mergeLayers(l *layout, layers []ocispec.Descriptor, tree string, logf func(string, ...any)) error {
	for i, desc := range layers {
		stage := filepath.Join(filepath.Dir(tree), fmt.Sprintf("layer-%d", i))
		report, err := extractVerifiedLayer(l, desc, stage)
		if err != nil {
			return err
		}
		if len(report.SkippedSymlinkAncestor) > 0 {
			shown := report.SkippedSymlinkAncestor
			if len(shown) > 5 {
				shown = shown[:5]
			}
			return fmt.Errorf("layer %d (%s) carries entries under a symlinked ancestor — content would be lost (e.g. %s); refusing",
				i, shortDigest(desc.Digest), strings.Join(shown, ", "))
		}
		whs, warns, err := collectWhiteouts(stage, report.Specials)
		if err != nil {
			return fmt.Errorf("layer %d: %w", i, err)
		}
		for _, w := range warns {
			logf("layer %d: %s", i, w)
		}
		if err := applyWhiteouts(tree, whs); err != nil {
			return fmt.Errorf("layer %d whiteouts: %w", i, err)
		}
		if err := mergeTree(tree, stage); err != nil {
			return fmt.Errorf("layer %d merge: %w", i, err)
		}
		if err := os.RemoveAll(stage); err != nil {
			return fmt.Errorf("clean layer %d staging: %w", i, err)
		}
		logf("layer %d/%d applied (%d whiteout(s))", i+1, len(layers), len(whs))
	}
	return nil
}

// parsePlatformPolicy parses and enforces the platform selection. The guest
// kernel/VMM this repo ships is x86_64-only, so linux/amd64 is the only
// accepted target; the matcher itself stays generic for the day that
// changes.
func parsePlatformPolicy(s string) (ocispec.Platform, error) {
	if s == "" {
		s = "linux/amd64"
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(s)), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return ocispec.Platform{}, fmt.Errorf("platform %q must be os/arch[/variant], e.g. linux/amd64", s)
	}
	for _, p := range parts {
		if p == "" {
			return ocispec.Platform{}, fmt.Errorf("platform %q has an empty component", s)
		}
	}
	p := ocispec.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	if p.OS != "linux" || p.Architecture != "amd64" {
		return ocispec.Platform{}, fmt.Errorf("platform %s is not supported: the shipped guest kernel and VMM are x86_64-only (linux/amd64)", platformString(p))
	}
	// amd64 has no meaningful variants ("v1" is a spelling of the default) —
	// normalize so index matching never hides an amd64 image behind one.
	p.Variant = ""
	return p, nil
}

func platformString(p ocispec.Platform) string {
	return p.OS + "/" + p.Architecture + variantSuffix(p.Variant)
}
