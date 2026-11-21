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

package imageimport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"sandlot/provision/copyfs"
	"sandlot/provision/template"
)

// maxOuterArchiveBytes bounds the DECOMPRESSED size of the outer archive
// (the image-layout tree: index.json + blobs). It is deliberately far above
// the layer cap: the blobs it carries are the already-compressed layers of
// a full distro image.
const maxOuterArchiveBytes = int64(64) << 30

// preparedSource is the classified input: exactly one of layout / rootfs is
// set.
type preparedSource struct {
	// layout is an opened OCI image layout (OCI image mode).
	layout *layout
	// rootfs is a directory that IS the rootfs tree (rootfs-tar mode:
	// docker export / minirootfs archives and plain rootfs directories).
	rootfs string
	// warnings are non-fatal findings from source preparation.
	warnings []string
}

// Compressed-but-unsupported formats are refused by MAGIC with a named
// cause instead of a confusing tar parse error. Gzip (the one supported
// compression) is detected inside the extractor, not here.
var unsupportedMagics = []struct {
	magic []byte
	name  string
}{
	{[]byte{0x28, 0xb5, 0x2f, 0xfd}, "zstd"}, // 0xFD2FB528 little-endian
	{[]byte{0xfd, 0x37, 0x7a, 0x58}, "xz"},   // \xfd7zX
	{[]byte{0x42, 0x5a, 0x68}, "bzip2"},      // "BZh"
}

func hasMagic(magic, peek []byte) bool {
	return len(peek) >= len(magic) && string(peek[:len(magic)]) == string(magic)
}

func unsupportedFormatError(name string) error {
	return fmt.Errorf("%s archives are not supported: re-pack with gzip (gzip < in > out.tar.gz) or plain tar (gunzip)", name)
}

// prepareSource stats, extracts, and classifies the input:
//
//   - a directory carrying the layout markers → OCI image mode, blobs read
//     in place (no copy);
//   - a directory that looks like a rootfs → copied into staging (the
//     policy pass MUTATES the tree; the source must stay untouched);
//   - an archive (tar / tar.gz, gzip detected by magic) → extracted into
//     staging under the audited extractor, then classified: OCI image
//     layout (descending a single wrapping directory), legacy docker-save
//     (manifest.json without index.json → refuse with instructions), or a
//     plain rootfs tar.
func prepareSource(src, stagingRoot string) (*preparedSource, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	if fi.IsDir() {
		if isLayoutDir(src) {
			l, err := openLayout(src)
			if err != nil {
				return nil, err
			}
			return &preparedSource{layout: l}, nil
		}
		// A plain rootfs directory: copy it — the policy pass mutates the
		// tree (skeleton, normalize) and must not touch the input.
		tree := filepath.Join(stagingRoot, "tree")
		if err := copyfs.CopyDirArchive(src, tree); err != nil {
			return nil, fmt.Errorf("copy rootfs directory: %w", err)
		}
		return &preparedSource{rootfs: tree,
			warnings: []string{fmt.Sprintf("source %s treated as a rootfs directory (no OCI layout markers)", src)}}, nil
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("source %s is not a regular file or directory", src)
	}

	f, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	// Sniff the compression before extracting: gzip passes through to the
	// extractor's own magic check; zstd/xz/bzip2 get a named refusal
	// instead of a confusing tar parse error.
	br := bufio.NewReader(f)
	if magic, _ := br.Peek(6); magic != nil {
		for _, m := range unsupportedMagics {
			if hasMagic(m.magic, magic) {
				return nil, unsupportedFormatError(m.name)
			}
		}
	}

	in := filepath.Join(stagingRoot, "in")
	report, err := template.ExtractTarTree(br, in, template.ExtractOptions{
		PlainTar:          true,
		AllowRootDirEntry: true,
		MaxBytes:          maxOuterArchiveBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("extract archive: %w", err)
	}
	if len(report.SkippedSymlinkAncestor) > 0 {
		return nil, fmt.Errorf("archive carries entries under a symlinked ancestor (content loss, refusing): %s (and %d more)",
			report.SkippedSymlinkAncestor[0], len(report.SkippedSymlinkAncestor)-1)
	}
	return classifyExtracted(in, report)
}

// classifyExtracted decides what the extracted archive is.
func classifyExtracted(in string, report *template.ExtractReport) (*preparedSource, error) {
	var warnings []string
	for _, sp := range report.Specials {
		warnings = append(warnings, fmt.Sprintf("dropped unsupported entry %s from the outer archive", sp.Name))
	}

	if isLayoutDir(in) {
		l, err := openLayout(in)
		if err != nil {
			return nil, err
		}
		return &preparedSource{layout: l, warnings: warnings}, nil
	}
	// A single wrapping directory around a layout (tar -cf x.tar mylayout/).
	if name, ok := singleTopDir(in); ok && isLayoutDir(filepath.Join(in, name)) {
		l, err := openLayout(filepath.Join(in, name))
		if err != nil {
			return nil, err
		}
		return &preparedSource{layout: l, warnings: warnings}, nil
	}
	// Legacy docker save (Docker <25): manifest.json, no OCI layout.
	if fi, err := os.Lstat(filepath.Join(in, "manifest.json")); err == nil && fi.Mode().IsRegular() {
		return nil, errors.New("legacy docker-save archive (manifest.json without an OCI layout): re-export with Docker 25+ `docker save`, or `skopeo copy docker://… oci-archive:out.tar`, or `docker export` for a plain rootfs tar")
	}
	// A blobs/ tree without the markers is a broken layout, not a rootfs.
	if fi, err := os.Lstat(filepath.Join(in, "blobs")); err == nil && fi.IsDir() {
		return nil, errors.New("archive carries blobs/ without oci-layout+index.json — incomplete OCI image layout")
	}
	// oci-layout is an OCI-only name: a tree carrying it without index.json
	// is a truncated layout, never a rootfs.
	if _, err := os.Lstat(filepath.Join(in, "oci-layout")); err == nil {
		return nil, errors.New("archive carries oci-layout without index.json — incomplete OCI image layout")
	}
	// Everything else is treated as a rootfs tar. A single top-level
	// directory without rootfs markers is far more likely a repack mistake
	// than a rootfs — refuse with the fix instead of importing garbage.
	if name, ok := singleTopDir(in); ok && !looksLikeRootfs(filepath.Join(in, name)) {
		return nil, fmt.Errorf("archive root contains only the directory %q and it has no rootfs markers — pack the CONTENTS with `tar -C <rootfs> -c .` (or pass the extracted directory)", name)
	}
	return &preparedSource{rootfs: in, warnings: warnings}, nil
}

// rootfsMarkers are directory names a real rootfs tree virtually always
// carries several of.
var rootfsMarkers = []string{
	"bin", "sbin", "etc", "usr", "lib", "lib64", "var", "home", "opt",
	"root", "tmp", "proc", "sys", "dev", "workspace", "boot", "srv",
	"media", "mnt", "run",
}

// looksLikeRootfs reports whether dir carries ≥2 rootfs marker directories.
func looksLikeRootfs(dir string) bool {
	found := 0
	for _, name := range rootfsMarkers {
		if fi, err := os.Lstat(filepath.Join(dir, name)); err == nil && fi.IsDir() {
			found++
			if found >= 2 {
				return true
			}
		}
	}
	return false
}

// singleTopDir reports the only entry of dir when it is exactly one real
// directory.
func singleTopDir(dir string) (string, bool) {
	des, err := os.ReadDir(dir)
	if err != nil || len(des) != 1 {
		return "", false
	}
	if !des[0].IsDir() {
		return "", false
	}
	return des[0].Name(), true
}

// extractVerifiedLayer streams one layer blob through the audited extractor
// into layerDir, hashing the RAW bytes as they pass; after the tar stream
// ends the remainder is drained so the whole blob is covered by the digest
// check. The blob must match its descriptor exactly or nothing is merged.
func extractVerifiedLayer(l *layout, desc ocispec.Descriptor, layerDir string) (*template.ExtractReport, error) {
	if err := checkLayerMediaType(desc); err != nil {
		return nil, err
	}
	h, digestOf, err := newHasher(desc)
	if err != nil {
		return nil, err
	}
	f, err := l.openBlob(desc)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tee := io.TeeReader(f, h)
	br := bufio.NewReader(tee)
	report, err := template.ExtractTarTree(br, layerDir, template.ExtractOptions{
		PlainTar:          true,
		AllowRootDirEntry: true,
	})
	if err != nil {
		return nil, fmt.Errorf("extract layer %s: %w", shortDigest(desc.Digest), err)
	}
	// Drain what the tar reader did not consume (gzip trailer, end-of-
	// archive padding, any trailing bytes) so the digest covers the WHOLE
	// blob — a truncated-read dodge must fail, not silently pass.
	if _, err := io.Copy(io.Discard, br); err != nil {
		return nil, fmt.Errorf("drain layer %s: %w", shortDigest(desc.Digest), err)
	}
	if got := digestOf(); got != desc.Digest {
		return nil, fmt.Errorf("layer digest mismatch: descriptor says %s, content hashes %s",
			shortDigest(desc.Digest), shortDigest(got))
	}
	return report, nil
}
