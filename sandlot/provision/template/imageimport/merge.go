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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"archive/tar"

	"sandlot/provision/template"
)

// Whiteout markers per the OCI image-spec (and the legacy aufs encoding the
// extractor reports as dropped specials).
const (
	whiteoutPrefix = ".wh."
	opaqueMarker   = ".wh..wh..opq"
)

// whiteout is one deletion an upper layer applies to the lower stack.
type whiteout struct {
	// dir is the tree-relative directory holding the marker; "" and "." both
	// mean the tree root.
	dir string
	// victim is the entry name removed by dir/.wh.<victim>; empty for an
	// opaque marker.
	victim string
	opaque bool
}

// collectWhiteouts walks an extracted layer staging directory for whiteout
// markers and validates every name. specials carries the device/FIFO/socket
// entries the extractor dropped; legacy 0/0 device whiteouts are converted,
// remaining specials are returned as warnings for the caller to report.
func collectWhiteouts(stage string, specials []template.ExtractedSpecial) ([]whiteout, []string, error) {
	var whs []whiteout
	var warnings []string

	for _, sp := range specials {
		base := filepath.Base(sp.Name)
		inNamespace := base == opaqueMarker || strings.HasPrefix(base, whiteoutPrefix)
		if !inNamespace {
			warnings = append(warnings, fmt.Sprintf("dropped unsupported entry %s (not a whiteout)", sp.Name))
			continue
		}
		if !isDeviceTypeflag(sp.Typeflag) {
			return nil, warnings, fmt.Errorf("whiteout %s is a %q, not a legacy 0/0 device", sp.Name, typeflagName(sp.Typeflag))
		}
		// Legacy aufs whiteouts are character devices with 0/0 numbers;
		// any other device number at a reserved name is malformed.
		if sp.DevMajor != 0 || sp.DevMinor != 0 {
			return nil, warnings, fmt.Errorf("device whiteout %s carries device numbers (%d,%d); legacy whiteouts are 0/0", sp.Name, sp.DevMajor, sp.DevMinor)
		}
		dirRel, err := relDirOf(sp.Name)
		if err != nil {
			return nil, warnings, fmt.Errorf("device whiteout %s: %w", sp.Name, err)
		}
		switch {
		case base == opaqueMarker:
			whs = append(whs, whiteout{dir: dirRel, opaque: true})
		default:
			victim, err := validateVictim(base)
			if err != nil {
				return nil, warnings, fmt.Errorf("device whiteout %s: %w", sp.Name, err)
			}
			whs = append(whs, whiteout{dir: dirRel, victim: victim})
		}
	}

	walkErr := filepath.WalkDir(stage, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == stage {
			return nil
		}
		base := filepath.Base(path)
		if base != opaqueMarker && !strings.HasPrefix(base, whiteoutPrefix) {
			return nil
		}
		dirRel, rerr := stageRel(stage, filepath.Dir(path))
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			return fmt.Errorf("whiteout marker %s is a directory", path)
		}
		switch {
		case base == opaqueMarker:
			whs = append(whs, whiteout{dir: dirRel, opaque: true})
		default:
			victim, verr := validateVictim(base)
			if verr != nil {
				return fmt.Errorf("whiteout %s: %w", path, verr)
			}
			whs = append(whs, whiteout{dir: dirRel, victim: victim})
		}
		// Markers are whiteout METADATA, never layer content: drop them
		// from the stage now, so no merge path (including the whole-subtree
		// rename fast path) can ever carry one into the template.
		return removeWhiteoutMarker(path)
	})
	if walkErr != nil {
		return nil, warnings, walkErr
	}
	return whs, warnings, nil
}

// removeWhiteoutMarker unlinks a marker from the stage tree. The stage is
// created by this process, so a marker that exists was created inside a
// writable directory; the retry with owner rwx exists only for a directory
// a later tar entry re-chmodded read-only. The original mode is restored so
// the merge's top-layer directory-metadata rule sees the authored mode.
func removeWhiteoutMarker(path string) error {
	err := os.Remove(path)
	if err == nil {
		return nil
	}
	dir := filepath.Dir(path)
	fi, serr := os.Stat(dir)
	if serr != nil {
		return err
	}
	orig := fi.Mode()
	if cerr := os.Chmod(dir, orig.Perm()|0o700); cerr != nil {
		return err
	}
	rerr := os.Remove(path)
	if cerr := os.Chmod(dir, orig); cerr != nil && rerr == nil {
		return cerr
	}
	return rerr
}

func typeflagName(tf byte) string {
	switch tf {
	case tar.TypeChar:
		return "character device"
	case tar.TypeBlock:
		return "block device"
	case tar.TypeFifo:
		return "FIFO"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeDir:
		return "directory"
	case tar.TypeReg:
		return "regular file"
	}
	return fmt.Sprintf("typeflag %q", string(tf))
}

func isDeviceTypeflag(tf byte) bool {
	return tf == tar.TypeChar || tf == tar.TypeBlock
}

// validateVictim checks the name a .wh. marker deletes: exactly one path
// component, no reserved whiteout namespace, no traversal. ".wh..." would
// otherwise yield ".." — a traversal primitive.
func validateVictim(base string) (string, error) {
	victim := strings.TrimPrefix(base, whiteoutPrefix)
	if victim == "" {
		return "", fmt.Errorf("empty victim name")
	}
	if victim == "." || victim == ".." {
		return "", fmt.Errorf("victim %q would target a parent or the marker's own directory", victim)
	}
	if strings.ContainsAny(victim, "/\x00") || !utf8.ValidString(victim) {
		return "", fmt.Errorf("victim %q is not a single path component", base)
	}
	if strings.HasPrefix(victim, whiteoutPrefix) {
		return "", fmt.Errorf("victim %q is inside the reserved .wh. namespace", base)
	}
	return victim, nil
}

// stageRel converts an absolute path inside stage into its slash-separated
// relative form ("" for the stage root).
func stageRel(stage, path string) (string, error) {
	rel, err := filepath.Rel(stage, path)
	if err != nil {
		return "", fmt.Errorf("whiteout outside the layer: %s", path)
	}
	if rel == "." {
		return "", nil
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("whiteout outside the layer: %s", path)
	}
	return filepath.ToSlash(rel), nil
}

// relDirOf returns the slash-separated directory part of a RELATIVE entry
// name ("" for the root). Absolute names and any traversal are refused —
// the extractor already validated containment, this is the belt-and-braces
// leg for names coming back through the specials report.
func relDirOf(name string) (string, error) {
	name = filepath.ToSlash(name)
	if strings.HasPrefix(name, "/") || name == "" {
		return "", fmt.Errorf("entry %q is not a relative path", name)
	}
	dir := path.Dir(name)
	if dir == "." {
		return "", nil
	}
	for _, comp := range strings.Split(dir, "/") {
		if comp == ".." {
			return "", fmt.Errorf("entry %q climbs above the layer root", name)
		}
	}
	return dir, nil
}

// applyWhiteouts applies the layer's deletions to the merged tree: opaque
// markers first (clear a directory's lower children), then individual
// victims. Path resolution NEVER follows symlinks — a component that is not
// a real directory means the lower tree is MASKED at that point by this
// layer's own staging tree, and overlay semantics make the whiteout a no-op.
func applyWhiteouts(tree string, whs []whiteout) error {
	for pass := 0; pass < 2; pass++ {
		for _, wh := range whs {
			if (pass == 0) != wh.opaque {
				continue
			}
			dir, ok, err := resolveDirNoFollow(tree, wh.dir)
			if err != nil {
				return err
			}
			if !ok {
				continue // masked by an upper layer — nothing to delete
			}
			if wh.opaque {
				if err := clearDir(dir); err != nil {
					return fmt.Errorf("opaque whiteout in %s: %w", wh.dir, err)
				}
				continue
			}
			victim := filepath.Join(dir, wh.victim)
			if _, err := os.Lstat(victim); err == nil {
				if err := removeTree(victim); err != nil {
					return fmt.Errorf("whiteout %s/%s: %w", wh.dir, wh.victim, err)
				}
			}
		}
	}
	return nil
}

// resolveDirNoFollow walks rel from the tree root WITHOUT following
// symlinks. ok=false when a component is absent or not a real directory
// (masked). rel uses slashes; "" is the root.
func resolveDirNoFollow(tree, rel string) (string, bool, error) {
	rel = filepath.ToSlash(rel)
	if rel == "" || rel == "." {
		return tree, true, nil
	}
	cur := tree
	for _, comp := range strings.Split(rel, "/") {
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." {
			return "", false, fmt.Errorf("whiteout path %q climbs above the tree root", rel)
		}
		cur = filepath.Join(cur, comp)
		fi, err := os.Lstat(cur)
		if err != nil || !fi.IsDir() {
			return "", false, nil
		}
	}
	return cur, true, nil
}

// clearDir removes every child of dir (the dir itself survives an opaque
// marker: the upper layer re-populates it in the merge pass).
func clearDir(dir string) error {
	if err := ensureWritable(dir); err != nil {
		return err
	}
	names, err := readDirNames(dir)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := removeTree(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// mergeTree merges one extracted layer staging directory onto the merged
// tree. Renames move whole subtrees, preserving exact modes (setuid/setgid/
// sticky included) and intra-layer hardlink identity. Destination checks use
// Lstat — a symlink victim is replaced as a link, never followed.
//
// Directory metadata: the TOP layer wins, applied after the children are
// merged (a 0555 mode applied first would block the children's renames).
func mergeTree(tree, stage string) error {
	if err := ensureWritable(tree); err != nil {
		return err
	}
	names, err := readDirNames(stage)
	if err != nil {
		return fmt.Errorf("read layer dir %s: %w", stage, err)
	}
	for _, name := range names {
		// Belt-and-braces: collectWhiteouts removes regular-file markers
		// from the stage, but a marker that somehow survived must never
		// become template content.
		if strings.HasPrefix(name, whiteoutPrefix) {
			continue
		}
		stagePath := filepath.Join(stage, name)
		treePath := filepath.Join(tree, name)
		sfi, err := os.Lstat(stagePath)
		if err != nil {
			return err
		}
		tfi, terr := os.Lstat(treePath)
		if terr == nil && tfi.IsDir() && sfi.IsDir() {
			if err := mergeTree(treePath, stagePath); err != nil {
				return err
			}
			// Top-layer directory mode wins (full mode: keeps setgid).
			if err := os.Chmod(treePath, sfi.Mode()); err != nil {
				return fmt.Errorf("chmod %s: %w", treePath, err)
			}
			continue
		}
		if terr == nil && tfi.IsDir() != sfi.IsDir() {
			// Type transition (file↔dir): the staged entry replaces the
			// whole lower subtree.
			if err := removeTree(treePath); err != nil {
				return fmt.Errorf("replace %s: %w", treePath, err)
			}
		}
		if err := os.Rename(stagePath, treePath); err != nil {
			return fmt.Errorf("merge %s into %s: %w", stagePath, treePath, err)
		}
	}
	return nil
}

// readDirNames lists a directory, retrying once after granting the owner
// rwx: a layer may carry a 0111-style directory whose contents must still
// be enumerated (the final mode is applied from the stage twin afterwards).
func readDirNames(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil && errors.Is(err, fs.ErrPermission) {
		if cerr := ensureWritable(dir); cerr == nil {
			des, err = os.ReadDir(dir)
		}
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(des))
	for _, de := range des {
		names = append(names, de.Name())
	}
	return names, nil
}

// ensureWritable adds owner rwx to a directory lacking owner write. All
// content under the import staging root was created by this process, so the
// chmod is always permitted.
func ensureWritable(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o200 != 0 {
		return nil
	}
	return os.Chmod(dir, fi.Mode().Perm()|0o700)
}

// removeTree deletes a subtree whose directories may carry read-only modes
// from lower layers: grant owner rwx down the tree first, then RemoveAll.
func removeTree(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		chmodTreeOwnerRWX(path)
	}
	return os.RemoveAll(path)
}

// chmodTreeOwnerRWX walks a directory subtree granting owner rwx on every
// directory so unlink/rename can proceed. Best-effort on the way down —
// RemoveAll reports the failure that matters.
func chmodTreeOwnerRWX(dir string) {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return
	}
	if fi.Mode().Perm()&0o700 != 0o700 {
		if err := os.Chmod(dir, fi.Mode().Perm()|0o700); err != nil {
			return
		}
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, de := range des {
		if de.IsDir() {
			chmodTreeOwnerRWX(filepath.Join(dir, de.Name()))
		}
	}
}
