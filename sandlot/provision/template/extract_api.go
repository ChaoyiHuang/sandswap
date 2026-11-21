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

package template

import "io"

// Skip reasons reported through ExtractOptions.OnSkip (and the internal
// extractOptions callback). Stable strings: importers switch on them.
const (
	// SkipSymlinkAncestor names an entry whose path runs under a symlinked
	// directory inside the tree — landing it would follow the link outside
	// the extraction root (containment), so the entry is NOT extracted.
	// An importer treats this as CONTENT LOSS and fails the import.
	SkipSymlinkAncestor = "symlink-ancestor"
	// SkipSpecialEntry names a device/FIFO/socket entry the extractor did
	// not land — unsupported by the template contract (inert under nodev,
	// never read through the passthrough daemon). An importer surfaces them
	// as warnings, except legacy 0/0 device whiteouts, which it interprets.
	SkipSpecialEntry = "special-entry"
)

// ExtractedSpecial names one tar entry the extractor did not land, with the
// header fields an importer needs to decide what to do with it.
type ExtractedSpecial struct {
	Name     string
	Typeflag byte
	Mode     int64
	DevMajor int64
	DevMinor int64
}

// ExtractOptions parameterizes ExtractTarTree. The zero value reproduces the
// runtime extraction policy exactly: gzip-only, root "." entries rejected,
// package-level size/entry caps, specials dropped, symlink-ancestor skips
// logged.
type ExtractOptions struct {
	// PlainTar accepts an uncompressed tar stream (no gzip magic). The
	// runtime paths are gzip-only by contract; offline importers of plain
	// tar archives (docker save on the classic store, hand-rolled tar -c)
	// opt in.
	PlainTar bool
	// AllowRootDirEntry skips directory entries whose cleaned name is "."
	// (common `tar -C dir -c .` packing). Non-directory root entries are
	// rejected regardless.
	AllowRootDirEntry bool
	// MaxBytes / MaxEntries override the package caps when > 0. An importer
	// bounds the OUTER archive differently than a store layer.
	MaxBytes int64
	// MaxEntries caps the number of tar entries (0 = package default).
	MaxEntries int
	// OnSkip receives every skipped entry. nil keeps current behavior.
	OnSkip func(ExtractedSpecial, string)
}

// ExtractReport summarizes what the extractor skipped.
type ExtractReport struct {
	// SkippedSymlinkAncestor lists entries not extracted because an ancestor
	// directory in the tree is a symlink (containment) — content loss.
	SkippedSymlinkAncestor []string
	// Specials lists device/FIFO/socket entries that were dropped.
	Specials []ExtractedSpecial
}

// ExtractTarTree extracts a tar (optionally gzip-compressed) stream into dir
// under the audited extraction policy (path/symlink containment, O_NOFOLLOW,
// hardlink validation, deterministic modes) and reports skipped entries.
// See extractTarGzToDir for the security properties; this wrapper only adds
// the reporting seam for offline importers.
func ExtractTarTree(reader io.Reader, dir string, opts ExtractOptions) (*ExtractReport, error) {
	report := &ExtractReport{}
	internal := extractOptions{
		plainTar:          opts.PlainTar,
		allowRootDirEntry: opts.AllowRootDirEntry,
		maxBytes:          opts.MaxBytes,
		maxEntries:        opts.MaxEntries,
	}
	internal.onSkip = func(s ExtractedSpecial, reason string) {
		switch reason {
		case SkipSymlinkAncestor:
			report.SkippedSymlinkAncestor = append(report.SkippedSymlinkAncestor, s.Name)
		case SkipSpecialEntry:
			report.Specials = append(report.Specials, s)
		}
		if opts.OnSkip != nil {
			opts.OnSkip(s, reason)
		}
	}
	if err := extractTarGzToDir(reader, dir, internal); err != nil {
		return nil, err
	}
	return report, nil
}

// EnsureTemplateSkeleton creates any missing skeleton directories (bin etc
// dev proc workspace home) under dir and returns the names created. Wrapper
// for offline producers; the runtime import paths call the same function.
func EnsureTemplateSkeleton(dir string) ([]string, error) {
	return ensureTemplateSkeleton(dir)
}

// ValidateTemplateRef checks a template reference ("name:version") against
// the component grammar every registration path enforces.
func ValidateTemplateRef(ref string) error {
	return validateRef(ref)
}

// InstallTemplateDir atomically publishes a completed staging directory at
// dst, refusing when dst already exists (ErrRefExists). Same-filesystem
// rename only: staging must live beside dst.
func InstallTemplateDir(staging, dst string) error {
	return renameDirNoReplace(staging, dst)
}

// VolumeControlFiles names the volume-state files that must never become
// template content (stripped at save-template; also stripped by importers).
func VolumeControlFiles() []string {
	return []string{volumeIdentityFile, provisioningMarkerFile, saveStagingMarker}
}
