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

// Offline template conformance: the checks the runtime applies at consume
// time (mount, materialization, registration), movable to the producer's
// desk. Every rule below MIRRORS a runtime check and names it — the goal is
// that a template passing `template-tool validate` / `check-store` cannot
// fail a runtime check for a static reason. The permission contract
// (ValidateTemplateTree) is one input; this file adds the rootfs
// well-formedness rules and the store (layers/ + refs/) integrity rules.

package template

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/opencontainers/go-digest"

	"common/util"
)

// Severity of an offline validation finding. error = a runtime consumer
// refuses or breaks; warning = legal but degraded / never healed on some
// path; info = hygiene, safe to ignore after reading.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Finding is one offline conformance finding. Path is the offending path
// (tree walk) or a store-relative description (store checks); Rule is a
// stable short id; Detail is the human sentence, including what the runtime
// would do.
type Finding struct {
	Path     string
	Severity Severity
	Rule     string
	Detail   string
}

// guestExpectDirs are the directories the guest environment expects to find
// (the warden mounts the real proc/dev inside the guest): documented
// template guidance, softer than the skeleton list (templateSkeletonDirs).
var guestExpectDirs = []string{"sys", "tmp"}

// ValidateRootfsTree checks one rootfs template directory offline: the
// permission contract (ValidateTemplateTree) plus the well-formedness rules
// the runtime either requires (/bin/sh — the warden execs it for every
// command) or repairs only on SOME import paths (skeleton dirs — created by
// OCI pull and save-as-template, never healed for a directory registered
// directly as a local template). Read-only: never mutates.
func ValidateRootfsTree(root string) ([]Finding, error) {
	fi, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, fmt.Errorf("template root %s is not a real directory", root)
	}

	var out []Finding

	// Permission contract (the `check` rules): an off-contract template
	// reads as EACCES inside every guest.
	violations, err := ValidateTemplateTree(root)
	if err != nil {
		return nil, err
	}
	for _, v := range violations {
		out = append(out, Finding{
			Path: v.Path, Severity: SeverityError, Rule: "contract",
			Detail: v.Reason + " (fix: template-tool normalize)",
		})
	}

	// Volume control files are VOLUME state, never template content: the
	// identity stamp (.sandfs-id) leaking into a layer would publish the
	// source tenant's metadata at the merged root of every guest booted from
	// the template. SaveAsTemplate strips them; a hand-built tree must not
	// carry them either.
	for _, name := range []string{volumeIdentityFile, provisioningMarkerFile, saveStagingMarker} {
		p := filepath.Join(root, name)
		if _, err := os.Lstat(p); err == nil {
			out = append(out, Finding{
				Path: p, Severity: SeverityError, Rule: "control-file",
				Detail: fmt.Sprintf("%s is volume state, never template content (save-as-template strips it; a template carrying it leaks the source volume's metadata into every guest)", name),
			})
		}
	}

	// Device/FIFO/socket entries are not supported (contract rule 6): they
	// are never read through the passthrough daemon and packTarGz SKIPS them
	// on push. A saved layer may legitimately carry tenant-planted ones;
	// a hand-built tree should not.
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		t := d.Type()
		if !d.IsDir() && t&fs.ModeSymlink == 0 && !t.IsRegular() {
			out = append(out, Finding{
				Path: path, Severity: SeverityWarning, Rule: "special-file",
				Detail: "device/FIFO/socket entries are not supported (inert under nodev; skipped when the template is pushed) — remove if hand-built",
			})
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	// /bin/sh: the warden execs `/bin/sh -c <command>` chrooted into the
	// rootfs for every agent command — a root without it cannot exec at all
	// (the busybox hot-bind only ADDS bin/busybox; it does not create /bin/sh).
	if err := checkChrootShell(root); err != nil {
		out = append(out, Finding{
			Path: filepath.Join(root, "bin", "sh"), Severity: SeverityError, Rule: "bin-sh",
			Detail: err.Error(),
		})
	}

	// Attach-critical skeleton dirs: the warden secures each of these with
	// open_dir(O_PATH|O_DIRECTORY|O_NOFOLLOW), which mkdirat's a missing one
	// and refuses a symlink — and the failure is FATAL (the mount is
	// refused, not degraded). On an overlay template's read-only merged
	// root the mkdirat cannot repair anything, so a missing or symlinked
	// entry fails every attach; dev/proc run the same fatal step in flat
	// mode too. The OCI-pull and save-as-template import paths create a
	// missing one (ensureTemplateSkeleton), but a directory registered
	// DIRECTLY as a local template is never healed — and ensureTemplateSkeleton
	// cannot heal a SYMLINK either (MkdirAll over an existing entry is
	// EEXIST). A real directory is therefore required, not merely something
	// that resolves to one.
	for _, name := range attachCriticalDirs {
		p := filepath.Join(root, name)
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			out = append(out, Finding{
				Path: p, Severity: SeverityError, Rule: "skeleton-dir",
				Detail: "missing attach-critical directory — the warden secures dev/proc/workspace/home with a FATAL mount step and refuses the attach when it cannot (an overlay root is read-only; a directly registered local template is never healed): mkdir it at the source",
			})
		case err != nil:
			return nil, err
		case fi.Mode()&os.ModeSymlink != 0:
			out = append(out, Finding{
				Path: p, Severity: SeverityError, Rule: "skeleton-dir",
				Detail: "is a symlink — the warden's mount-target step refuses symlinks (O_NOFOLLOW) and cannot replace one on a read-only overlay root, so the attach is refused; and the import paths cannot heal it (MkdirAll over an existing entry fails): make it a real directory",
			})
		case !fi.IsDir():
			out = append(out, Finding{
				Path: p, Severity: SeverityError, Rule: "skeleton-dir",
				Detail: "exists but is not a directory — the warden's mount-target step and every import path that touches the skeleton refuse it",
			})
		}
	}

	// bin/ and etc/ degrade instead of refusing: the busybox hot-bind is
	// skipped when bin/ cannot be secured, and resolv.conf injection is
	// best-effort. They are resolved with the same CHROOT semantics as
	// /bin/sh (a usr-merge `bin -> usr/bin` is legitimate; an absolute
	// symlink is judged as the guest sees it, never against the host root).
	// A missing entry is a warning (the OCI pull / save-as-template import
	// paths create it); an entry that EXISTS but does not resolve to a
	// directory is an error — the import paths cannot repair it either.
	for _, name := range softSkeletonDirs() {
		p := filepath.Join(root, name)
		if _, lerr := os.Lstat(p); errors.Is(lerr, fs.ErrNotExist) {
			out = append(out, Finding{
				Path: p, Severity: SeverityWarning, Rule: "skeleton-dir",
				Detail: "missing skeleton directory — created automatically on the OCI pull / save-as-template import paths, but a template registered directly as a local directory is never healed; the runtime degrades (busybox hot-bind skipped, no resolv.conf): add it at the source",
			})
			continue
		}
		_, fi, err := resolveChrootPath(root, name, maxSymlinkHops)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			out = append(out, Finding{
				Path: p, Severity: SeverityError, Rule: "skeleton-dir",
				Detail: "is a dangling symlink (does not resolve inside the tree as the guest would) — the import paths cannot heal it: ensureTemplateSkeleton's MkdirAll fails on an existing entry",
			})
		case err != nil:
			out = append(out, Finding{
				Path: p, Severity: SeverityError, Rule: "skeleton-dir",
				Detail: fmt.Sprintf("does not resolve inside the tree as the guest would resolve it: %v", err),
			})
		case !fi.IsDir():
			out = append(out, Finding{
				Path: p, Severity: SeverityError, Rule: "skeleton-dir",
				Detail: "resolves to an entry that is not a directory — the guest cannot use it as one",
			})
		}
	}

	// The warden mounts the real proc/dev inside the guest and expects
	// sys/tmp to exist (documented template guidance — a warning, not an
	// error). Same chroot-semantic resolution as above.
	for _, name := range guestExpectDirs {
		p := filepath.Join(root, name)
		if _, fi, err := resolveChrootPath(root, name, maxSymlinkHops); err != nil || !fi.IsDir() {
			out = append(out, Finding{
				Path: p, Severity: SeverityWarning, Rule: "guest-dir",
				Detail: "the warden mounts the real proc/dev inside the guest and expects this directory to exist (an empty directory is fine)",
			})
		}
	}

	return out, nil
}

// attachCriticalDirs are the skeleton entries the warden secures with a
// FATAL mount step (open_dir: mkdirat on ENOENT, refuse a symlink). MIRRORS
// warden/src/mount/workspace.rs (the `?`-propagated mount targets) and
// hardening.rs setup_masked_proc / setup_minimal_dev.
var attachCriticalDirs = []string{"dev", "proc", "workspace", "home"}

// softSkeletonDirs returns the skeleton entries NOT in attachCriticalDirs:
// their failures degrade (busybox hot-bind skip, best-effort resolv.conf).
func softSkeletonDirs() []string {
	strict := make(map[string]struct{}, len(attachCriticalDirs))
	for _, d := range attachCriticalDirs {
		strict[d] = struct{}{}
	}
	var out []string
	for _, d := range templateSkeletonDirs {
		if _, ok := strict[d]; !ok {
			out = append(out, d)
		}
	}
	return out
}

// maxSymlinkHops bounds symlink resolution (an ELOOP-class guard): a chain
// longer than this — or a loop — is reported, never followed forever.
const maxSymlinkHops = 40

// checkChrootShell verifies that /bin/sh resolves, with CHROOT semantics, to
// an executable regular file inside the tree (see resolveChrootPath).
func checkChrootShell(root string) error {
	_, fi, err := resolveChrootPath(root, filepath.Join("bin", "sh"), maxSymlinkHops)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("/bin/sh does not exist in the template (every agent command execs /bin/sh)")
		}
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("/bin/sh resolves to a directory")
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("/bin/sh resolves to a non-regular entry")
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("/bin/sh resolves to a file with no execute bit")
	}
	return nil
}

// resolveChrootPath resolves rel (a tree-relative slash path) inside root
// with GUEST (chroot) semantics, component by component — no step ever
// touches the host root, and no lexical shortcut may cancel a component:
//
//   - Components are processed strictly left to right and each must exist as
//     it is reached. A target like "sub/../../bin/x" with no `sub` fails
//     exactly as the guest syscall would (filepath.Join would have silently
//     cancelled `sub/..` — a false negative).
//   - A relative symlink target is applied to the directory the link was
//     FOUND IN, after that directory was itself resolved (the kernel's
//     behavior). Applying it to the link's lexical parent mis-resolves any
//     symlinked ancestor — e.g. a working usr-merge tree with
//     `bin -> usr/bin` and `usr/bin/sh -> ../../bin/busybox` would look like
//     it climbed above the root (a false positive).
//   - An absolute target restarts at the tree root, never the host root.
//   - `..` above the root is refused rather than clamped: the kernel would
//     clamp it at /, i.e. a link that only works through clamping is broken
//     as authored.
//
// Returns the resolved host path and the Lstat of the fully resolved final
// entry. A missing component wraps fs.ErrNotExist so callers can soften it;
// every other error (escaping or looping link, non-directory component,
// I/O) means the guest cannot resolve the path either.
func resolveChrootPath(root, rel string, hops int) (string, os.FileInfo, error) {
	queue := splitPathComponents(rel)
	resolved := make([]string, 0, 8) // real (symlink-free) components below root
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		switch c {
		case ".":
			continue
		case "..":
			if len(resolved) == 0 {
				return "", nil, fmt.Errorf("path %q climbs above the template root — the guest kernel would clamp it at /, i.e. not the path that was authored", rel)
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		p := filepath.Join(root, filepath.Join(resolved...), c)
		fi, err := os.Lstat(p)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", p, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			hops--
			if hops <= 0 {
				return "", nil, fmt.Errorf("symlink chain under %s exceeds the hop bound (a loop?)", filepath.Join(root, rel))
			}
			target, err := os.Readlink(p)
			if err != nil {
				return "", nil, err
			}
			if filepath.IsAbs(target) {
				resolved = resolved[:0] // chroot: an absolute target restarts at the tree root
			}
			queue = append(splitPathComponents(target), queue...)
			continue
		}
		if len(queue) > 0 && !fi.IsDir() {
			return "", nil, fmt.Errorf("%s is not a directory (path %q)", p, rel)
		}
		resolved = append(resolved, c)
	}
	finalPath := filepath.Join(append([]string{root}, resolved...)...)
	fi, err := os.Lstat(finalPath)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", finalPath, err)
	}
	return finalPath, fi, nil
}

// splitPathComponents splits a slash path into non-empty components,
// preserving "." and ".." (they have resolution meaning).
func splitPathComponents(p string) []string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	out := parts[:0]
	for _, c := range parts {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// ValidateScanRoot validates a template scan root (-flat-templates or the
// template store's local-template area): each <name>/ entry is either a
// versioned container (name/version/ leaves) or itself a rootfs leaf — the
// same classification the registration scans apply (ScanFlatTemplates /
// ScanLocalTemplates via isVersionedTemplateDir). Every leaf runs
// ValidateRootfsTree. Internal store dirs (refs/, layers/) are skipped (the
// scans skip them too); dot-entries are skipped as well — the scans cannot
// register them (a dot name fails the ref component rule).
func ValidateScanRoot(scanRoot string) ([]Finding, error) {
	entries, err := os.ReadDir(scanRoot)
	if err != nil {
		return nil, err
	}
	var out []Finding
	leaves := 0
	validateLeaf := func(dir string) {
		leaves++
		fs, err := ValidateRootfsTree(dir)
		if err != nil {
			out = append(out, Finding{
				Path: dir, Severity: SeverityError, Rule: "tree",
				Detail: err.Error(),
			})
			return
		}
		out = append(out, fs...)
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || e.Name() == "layers" || e.Name() == "refs" {
			continue
		}
		namePath := filepath.Join(scanRoot, e.Name())
		if isVersionedTemplateDir(namePath) {
			vers, err := os.ReadDir(namePath)
			if err != nil {
				continue // the registration scans skip unreadable name dirs too
			}
			for _, ve := range vers {
				if !ve.IsDir() || strings.HasPrefix(ve.Name(), ".") {
					continue
				}
				validateLeaf(filepath.Join(namePath, ve.Name()))
			}
		} else {
			validateLeaf(namePath)
		}
	}
	if leaves == 0 {
		out = append(out, Finding{
			Path: scanRoot, Severity: SeverityWarning, Rule: "scan-root",
			Detail: "no template directories found — the registration scan would register nothing from this root",
		})
	}
	return out, nil
}

// IsStoreShape reports whether dir carries the template store's internal
// layout (a refs/ or layers/ subdirectory). Used by the CLI to refuse
// pointing `validate` at a store (the leaves under layers/ are layer
// fragments, not complete rootfs trees — validating them would only produce
// false findings).
func IsStoreShape(dir string) bool {
	for _, name := range []string{"refs", "layers"} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

// IsScanRootDir reports whether dir looks like a scan root (a directory of
// template name directories) rather than a single rootfs tree: it carries no
// rootfs marker directly inside, and at least one subdirectory is itself a
// rootfs or a name/version container. The same classification the
// registration scans apply per entry (isRootfsDir / isVersionedTemplateDir);
// a directory of unrelated subdirectories is NOT a scan root — the scan
// would register it as one (broken) template, so the validator treats it as
// one tree too.
func IsScanRootDir(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return false
	}
	anyCandidate := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		versioned := isVersionedTemplateDir(p)
		switch e.Name() {
		case "bin", "etc", "usr", "lib", "sbin", "var":
			// A marker name normally means dir IS a rootfs — but a template
			// may legitimately be NAMED "bin" (`flat-templates/bin/v1/` is
			// registered as bin:v1 by the scans). Only the non-versioned
			// shape is evidence of a rootfs.
			if !versioned {
				return false // a rootfs itself
			}
		}
		if versioned || isRootfsDir(p) {
			anyCandidate = true
		}
	}
	return anyCandidate
}

// ValidateStore checks the integrity of a whole template store (the
// <templates>/ tree: refs/ + layers/): every ref file parses and names the
// ref its filename encodes, every layer id respects the trust boundary the
// mount-time and seeding validators enforce, every named layer is present,
// and the layers/ directory carries no unreachable debris. flatRoots lists
// the operator-configured -flat-templates scan roots (absolute flat layer
// paths are legal only inside the store or one of them — mirror of
// flatLayerRoots; empty means "cannot judge", which downgrades the check to
// a warning naming the missing context).
//
// The layer trust boundary mirrors sandlot/core's validateLayerID (mount
// time) and this package's ResolveFlatLayerPath / resolveOverlayLayerPath
// (seeding / packing): those run against ref files on SHARED storage, where
// a peer node or a tampered store can rewrite them. This offline pass finds
// the same defects before a template ever reaches a consumer.
func ValidateStore(storeDir string, flatRoots []string) ([]Finding, error) {
	// Every layer-boundary comparison pairs layer IDs (which are ABSOLUTE for
	// the local-template format) with the store root; a relative invocation
	// ("check-store store2" from its parent) would make filepath.Rel report
	// every in-store absolute layer as outside the store. Normalize both
	// sides once, here.
	absStore, err := filepath.Abs(storeDir)
	if err != nil {
		return nil, err
	}
	storeDir = absStore
	absRoots := make([]string, 0, len(flatRoots))
	for _, r := range flatRoots {
		ar, aerr := filepath.Abs(r)
		if aerr != nil {
			return nil, aerr
		}
		absRoots = append(absRoots, ar)
	}
	flatRoots = absRoots

	fi, err := os.Stat(storeDir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", storeDir)
	}
	refsDir := filepath.Join(storeDir, "refs")
	layersDir := filepath.Join(storeDir, "layers")
	refsStat, refsErr := os.Stat(refsDir)
	layersStat, layersErr := os.Stat(layersDir)
	if refsErr != nil && layersErr != nil {
		return nil, fmt.Errorf("%s has neither refs/ nor layers/ — not a template store (for a template directory use: template-tool validate <dir>)", storeDir)
	}

	var out []Finding
	// reachable mirrors DeleteTemplate's GC union: the RAW relative layer ids
	// every ref names. Only relative ids count — absolute-path Layers are
	// local-template source dirs the GC never touches.
	reachable := map[string]bool{}

	if refsErr == nil {
		if !refsStat.IsDir() {
			out = append(out, Finding{Path: refsDir, Severity: SeverityError, Rule: "store-shape", Detail: "refs exists but is not a directory"})
		} else {
			entries, err := os.ReadDir(refsDir)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				name := e.Name()
				path := filepath.Join(refsDir, name)
				if strings.HasPrefix(name, ".") {
					// Save locks (.<ref>.save.lock) and ref temp files
					// (.ref-*.tmp) are transient; a leftover past its run is
					// debris the flock semantics already neutralize.
					if strings.HasSuffix(name, ".save.lock") || strings.HasSuffix(name, ".tmp") {
						out = append(out, Finding{Path: path, Severity: SeverityInfo, Rule: "store-debris", Detail: "transient writer state (lock or temp publish); stale copies are inert — delete at leisure"})
					}
					continue
				}
				if e.IsDir() || !strings.HasSuffix(name, ".json") {
					out = append(out, Finding{Path: path, Severity: SeverityWarning, Rule: "ref-file", Detail: "unexpected entry in refs/ (ref files are <name>_<version>.<mode>.json)"})
					continue
				}
				out = append(out, validateRefFile(storeDir, path, name, flatRoots, reachable)...)
			}
		}
	}

	if layersErr == nil {
		if !layersStat.IsDir() {
			out = append(out, Finding{Path: layersDir, Severity: SeverityError, Rule: "store-shape", Detail: "layers exists but is not a directory"})
		} else {
			out = append(out, validateLayersDir(layersDir, reachable)...)
		}
	}

	return out, nil
}

// maxRefFileBytes bounds how large a ref file may be to be read at all. A
// legitimate entry is a few hundred bytes; the bound keeps a tampered store
// (shared, peer-writable) from turning the tool into an unbounded reader.
const maxRefFileBytes = 1 << 20

// validateRefFile checks one refs/<file>.json against everything the two
// runtime ref loaders enforce: the manager's loadRefFile and the exec
// sandlot's core.getCachedRefEntry (which keeps its own mirror of the format
// precisely because it loads ref files without importing this package).
func validateRefFile(storeDir, path, filename string, flatRoots []string, reachable map[string]bool) []Finding {
	var out []Finding
	fail := func(rule, format string, args ...any) {
		out = append(out, Finding{Path: path, Severity: SeverityError, Rule: rule, Detail: fmt.Sprintf(format, args...)})
	}
	warn := func(rule, format string, args ...any) {
		out = append(out, Finding{Path: path, Severity: SeverityWarning, Rule: rule, Detail: fmt.Sprintf(format, args...)})
	}

	// Filename → (base, mode). Same suffix discipline as ListLocalTemplates:
	// only known mode suffixes are stripped so versions containing '.'
	// (e.g. "24.04") survive; a missing suffix is the legacy format — and
	// the loaders open ONLY <base>.<mode>.json, so a legacy file is
	// listing-only, never consumable.
	base := strings.TrimSuffix(filename, ".json")
	mode := "overlay"
	switch {
	case strings.HasSuffix(base, ".flat"):
		base, mode = strings.TrimSuffix(base, ".flat"), "flat"
	case strings.HasSuffix(base, ".overlay"):
		base, mode = strings.TrimSuffix(base, ".overlay"), "overlay"
	default:
		warn("ref-legacy", "no mode suffix — every ref loader opens <name>_<version>.<mode>.json, so this legacy file is listing-only and can never be consumed")
	}

	// The store is shared, tamperable input: a FIFO or device at a ref name
	// would BLOCK or read unboundedly (os.ReadFile on a FIFO waits for a
	// writer forever). The entry is opened WITHOUT following a final symlink,
	// and the type/size verdict is taken from the DESCRIPTOR (fstat), not
	// from a separate Lstat — a peer rewriting the entry between an Lstat and
	// a ReadFile would race the check (TOCTOU on shared storage). Every
	// writer produces a small regular file (CreateTemp + rename), so anything
	// else is debris or an attack, and reporting it IS the finding.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			fail("ref-file", "is a symlink — refusing to read through it; no writer produces this (every ref is published by rename from a temp regular file)")
			return out
		}
		fail("ref-parse", "unreadable: %v", err)
		return out
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		fail("ref-parse", "unreadable: %v", err)
		return out
	}
	if !fi.Mode().IsRegular() {
		fail("ref-file", "not a regular file (mode %s) — refusing to read it; no writer produces this and the readers would block or read it unboundedly", fi.Mode().Type())
		return out
	}
	if fi.Size() > maxRefFileBytes {
		fail("ref-file", "ref file is %d bytes (over the %d-byte bound) — a legitimate ref entry is a few hundred bytes", fi.Size(), int64(maxRefFileBytes))
		return out
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRefFileBytes))
	if err != nil {
		fail("ref-parse", "unreadable: %v", err)
		return out
	}
	var entry RefEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		fail("ref-parse", "does not parse as a ref entry: %v", err)
		return out
	}

	// Identity (mirror loadRefFile + core.getCachedRefEntry + the volume
	// in-use gate): the ref→filename encoding is not injective (':' and '_'
	// both encode to '_'), so identity is judged at the FILENAME level —
	// RefToFilename(entry identity) must equal this file's base. Without
	// this check a ref written for one name:version is served (or mounted)
	// for a colliding one: the cross-tenant rootfs-substitution class.
	// Deriving the identity FROM the filename (filenameToRef) instead would
	// be wrong in the other direction: a legal ref whose version contains
	// '_' ("a:b_c") is indistinguishable there and would be falsely
	// rejected.
	switch {
	case entry.Name == "" && entry.Version == "":
		warn("ref-identity", "legacy entry records no name/version — readers cannot bind it to the ref it was written for")
	case entry.Name == "" || entry.Version == "":
		// The readers' identity check requires BOTH fields (a partial entry
		// is accepted as legacy by loadRefFile / getCachedRefEntry), and no
		// writer produces one — informational, not a refusal.
		warn("ref-identity", "entry records only half of the identity (name=%q version=%q) — readers treat a partial identity as legacy and skip the binding check", entry.Name, entry.Version)
	default:
		entryRef := entry.Name + ":" + entry.Version
		if err := validateRef(entryRef); err != nil {
			fail("ref-identity", "entry names an invalid ref: %v", err)
		} else if !refEncodesToFilename(entryRef, entry.Version, base) {
			fail("ref-identity", "entry names %q:%q, which encodes to %q, but this file is %q — a colliding or tampered ref; every reader refuses it",
				entry.Name, entry.Version, util.RefToFilename(entryRef), base)
		}
	}

	// The mode FIELD is only consumed at write time (GetMode picks the
	// filename suffix); every reader selects the file by its filename
	// suffix and never looks at the field. A parked invalid value is
	// therefore a recording defect, not a broken ref — warning.
	switch entry.Mode {
	case "", "flat", "overlay":
	default:
		warn("ref-mode", "recorded mode %q is invalid (flat | overlay | empty); readers select by filename suffix and never consult the field", entry.Mode)
	}
	if entry.GetMode() != mode {
		warn("ref-mode", "entry mode %q disagrees with the filename suffix %q (a recorded empty mode reads as overlay)", entry.GetMode(), mode)
	}

	// Layer provenance is EITHER local directories (Layers) OR recorded OCI
	// digests (OCILayers); no writer produces both, and each consumer path
	// reads only one of them — a mixed ref is ambiguous (tampered or hand-
	// written).
	if len(entry.Layers) > 0 && len(entry.OCILayers) > 0 {
		warn("ref-layers", "records both local layers and oci_layers — no writer produces this; the provenance is ambiguous")
	}

	// An OCI-origin flat ref records only digests — nothing local to check,
	// but the digests themselves are consumed at every creation
	// (digest.Parse + VerifyReader), so their format is. Such a ref can only
	// be consumed as FLAT (nothing local to mount; only the flat create
	// streams the blobs), so an .overlay.json carrying ONLY oci_layers is
	// refused by every consumer: the overlay mount loader's mirror struct
	// does not even carry the digests and fails "template has no layers".
	if len(entry.Layers) == 0 {
		if len(entry.OCILayers) > 0 {
			if mode != "flat" {
				fail("ref-mode", "records only OCI layer digests but is stored as %q — only the flat creation path consumes oci_layers (the overlay mount refuses a ref with no local layers); a registry-origin ref belongs in <ref>.flat.json", filename)
			}
			for i, l := range entry.OCILayers {
				if _, err := digest.Parse(l.Digest); err != nil {
					fail("oci-layer", "oci_layers[%d] digest %q does not parse: %v — every flat creation from this ref fails", i, l.Digest, err)
				}
				if l.Size < 0 {
					fail("oci-layer", "oci_layers[%d] records a negative size %d", i, l.Size)
				}
			}
			return out
		}
		fail("ref-layers", "records no layers — creation fails fast and the listing hides the ref")
		return out
	}

	for i, layerID := range entry.Layers {
		ld := fmt.Sprintf("layer %d (%q)", i, layerID)
		if !filepath.IsAbs(layerID) {
			reachable[layerID] = true
		}
		out = append(out, validateStoreLayerID(storeDir, path, ld, mode, layerID, flatRoots)...)
	}
	return out
}

// refEncodesToFilename reports whether a ref entry's identity is consistent
// with the base name of the ref file it was found in. A BARE ref ("sqlite")
// is written under its bare name while the entry records version "local";
// an explicit "sqlite:local" ref encodes WITH the suffix. Both are legal
// encodings of the same entry identity, so version "local" accepts either.
func refEncodesToFilename(ref, version, base string) bool {
	if util.RefToFilename(ref) == base {
		return true
	}
	if version == "local" {
		name, _ := parseTemplateRef(ref)
		return util.RefToFilename(name) == base
	}
	return false
}

// validateStoreLayerID judges ONE layer id of a ref entry against the trust
// boundary the consumers enforce: core.validateLayerID (overlay mount),
// ResolveFlatLayerPath (flat seeding), resolveOverlayLayerPath (packing).
// refPath/label exist only for finding attribution.
func validateStoreLayerID(storeDir, refPath, label, mode, layerID string, flatRoots []string) []Finding {
	var out []Finding
	fail := func(rule, format string, args ...any) {
		out = append(out, Finding{Path: refPath, Severity: SeverityError, Rule: rule, Detail: label + ": " + fmt.Sprintf(format, args...)})
	}
	warn := func(rule, format string, args ...any) {
		out = append(out, Finding{Path: refPath, Severity: SeverityWarning, Rule: rule, Detail: label + ": " + fmt.Sprintf(format, args...)})
	}

	if layerID == "" || layerID == "." {
		fail("layer-id", "empty layer id")
		return out
	}
	// The id is interpolated into the overlay `lowerdir=` mount option, where
	// ':' separates lowerdirs and ',' separates options — the separators are
	// refused before any path check (mirror validateLayerID).
	if strings.ContainsAny(layerID, ":,") {
		fail("layer-id", "contains a mount-option separator (':' or ',') — every overlay mount of this ref refuses it")
		return out
	}

	layersDir := filepath.Join(storeDir, "layers")
	var path string
	if filepath.IsAbs(layerID) {
		path = layerID
		if mode == "overlay" {
			// The local-template format: an absolute overlay layer must sit
			// inside the store (mirror validateLayerID's absolute leg +
			// resolveOverlayLayerPath's symlink leg).
			if !withinRoot(filepath.Clean(path), filepath.Clean(storeDir)) {
				fail("layer-boundary", "absolute path outside the template store — the mount-time validator refuses it (host-path injection)")
				return out
			}
			if !symlinkContained(path, storeDir) {
				fail("layer-boundary", "resolves via symlinks outside the template store")
				return out
			}
		} else {
			// Flat: the layer may sit in the store or any configured
			// -flat-templates root (mirror flatLayerRoots: lexically inside
			// SOME root AND, after symlink resolution, still inside some
			// root). Without roots given, an outside-store path cannot be
			// judged — warn with the missing context instead of guessing.
			roots := append([]string{storeDir}, flatRoots...)
			inside := false
			for _, root := range roots {
				if withinRoot(filepath.Clean(path), filepath.Clean(root)) {
					inside = true
					break
				}
			}
			if inside {
				inside = symlinkContainedMulti(path, roots)
			}
			if !inside {
				if len(flatRoots) == 0 {
					warn("layer-boundary", "absolute path not provably inside the template store (outside it, or escaping it through symlinks) — pass --flat-root <dir> if it lives in an operator-configured flat scan root (flat seeding refuses anything outside the configured roots)")
				} else {
					fail("layer-boundary", "absolute path outside the store and every configured flat root (lexically or through symlinks) — flat seeding refuses it; on a multi-host deployment pass the PROV instance's -flat-templates roots (the paths the refs record, which differ per host)")
				}
				return out
			}
		}
	} else {
		// Relative ids are split by CONSUMER, which is what makes the right
		// containment root differ:
		//   - lexical: always under layers/ (core.validateLayerID requires it
		//     for the overwrite mount option interpolation leg);
		//   - overlay mount: the resolved path must stay inside the STORE
		//     (sandlot/core/overlay.go resolves each layer and checks
		//     pathWithin templatesDir — not layers/);
		//   - flat seeding: the resolved path must stay inside the store or
		//     a configured flat root (ResolveFlatLayerPath's union).
		// A link that leaves layers/ but stays inside the store therefore
		// MOUNTS and SEEDS fine; only packing (template push) refuses it —
		// that is a warning, not a broken store.
		path = filepath.Join(layersDir, layerID)
		if !withinRoot(filepath.Clean(path), filepath.Clean(layersDir)) {
			fail("layer-boundary", "relative id escapes layers/ — every consumer refuses it")
			return out
		}
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			roots := []string{storeDir}
			if mode == "flat" {
				roots = append([]string{storeDir}, flatRoots...)
			}
			contained := false
			for _, root := range roots {
				if rr, rerr := filepath.EvalSymlinks(root); rerr == nil && withinRoot(resolved, rr) {
					contained = true
					break
				}
			}
			if !contained {
				fail("layer-boundary", "resolves via symlinks outside the template store — the mount-time and seeding validators refuse it")
				return out
			}
			if rr, rerr := filepath.EvalSymlinks(layersDir); rerr == nil && !withinRoot(resolved, rr) {
				warn("layer-boundary", "resolves via symlinks outside layers/ but inside the store — mounting and seeding accept it; packing (template push) refuses it")
			}
		}
	}

	// Existence (mirror RefEntryExists). Severity follows OWNERSHIP:
	// a relative id names the store's own layers/ cache — the store owns
	// it and its GC only reaps unreachable entries, so a reachable layer
	// that is gone was hand-deleted or corrupted (the documented way to
	// break other templates). An absolute id names a local-template SOURCE
	// directory outside the store (a scan root): refs are durable records
	// by design, and a temporarily unmounted scan root or a moved build
	// output is a degradation (the listing hides the ref, creation fails
	// fast; re-creating the directory restores it), not store corruption.
	if fi, err := os.Stat(path); err != nil {
		if filepath.IsAbs(layerID) {
			warn("layer-missing", "layer source directory missing — the listing hides the ref and creation fails fast; the ref is kept by design and re-creating the directory at the same path restores the template")
		} else {
			fail("layer-missing", "layer directory missing under layers/ — the store owns its cache and only reaps unreachable entries, so this is a hand-deleted or corrupted layer (re-pull the ref to restore)")
		}
	} else if !fi.IsDir() {
		fail("layer-missing", "layer path is not a directory")
	}
	return out
}

// symlinkContained reports whether path, after EvalSymlinks, stays strictly
// inside root (both sides resolved; a path that does not resolve — a missing
// layer — is not this check's verdict).
func symlinkContained(path, root string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return true
	}
	rr, rerr := filepath.EvalSymlinks(root)
	if rerr != nil {
		return true
	}
	return withinRoot(resolved, rr)
}

// symlinkContainedMulti is symlinkContained against a set of roots: true
// when the resolved path stays inside ANY of them (the flat trust boundary
// is a union of roots — mirror ResolveFlatLayerPath).
func symlinkContainedMulti(path string, roots []string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return true
	}
	for _, root := range roots {
		rr, rerr := filepath.EvalSymlinks(root)
		if rerr != nil {
			continue
		}
		if withinRoot(resolved, rr) {
			return true
		}
	}
	return false
}

// ociLayerDirRe matches the content-addressed layer directory name an OCI
// pull creates (sha256-<64 lowercase hex>); localLayerDirRe matches the
// save-as-template output name (local-<name>-<version>, both components ref
// components). Anything else under layers/ is not a name this codebase
// writes — legal to read, worth a warning.
var (
	ociLayerDirRe   = regexp.MustCompile(`^sha256-[0-9a-f]{64}$`)
	localLayerDirRe = regexp.MustCompile(`^local-[a-zA-Z0-9][a-zA-Z0-9._-]*-[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
)

// validateLayersDir checks the layers/ directory itself: naming convention,
// slot shape, reachability (the inverse of DeleteTemplate's GC) and writer
// debris.
func validateLayersDir(layersDir string, reachable map[string]bool) []Finding {
	entries, err := os.ReadDir(layersDir)
	if err != nil {
		return []Finding{{Path: layersDir, Severity: SeverityError, Rule: "store-shape", Detail: fmt.Sprintf("unreadable: %v", err)}}
	}
	var out []Finding
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(layersDir, name)
		if strings.HasPrefix(name, ".") {
			// Extract staging dirs (.<layer>.staging-*) and save publish
			// markers (.<layer>.publishing) are writer-internal; the staging
			// reaper removes stale ones after their bounded age.
			if strings.Contains(name, ".staging-") || strings.HasSuffix(name, ".publishing") {
				out = append(out, Finding{Path: path, Severity: SeverityInfo, Rule: "store-debris", Detail: "writer-internal staging/publish state; stale copies are reaped automatically"})
			}
			continue
		}
		if !e.IsDir() {
			// A file or symlink at a layer slot is a poisoned or partial
			// publish — the GC reaps it, and no ref can use it.
			out = append(out, Finding{Path: path, Severity: SeverityWarning, Rule: "layer-slot", Detail: "layer slot is not a directory (a poisoned/partial publish or a stray entry); if no ref names it the delete GC reaps it — re-pulling the ref restores a real layer"})
			continue
		}
		if !ociLayerDirRe.MatchString(name) && !localLayerDirRe.MatchString(name) {
			out = append(out, Finding{Path: path, Severity: SeverityWarning, Rule: "layer-name", Detail: "unrecognized layer directory name (writers produce sha256-<digest> and local-<name>-<version>)"})
		}
		if !reachable[name] {
			out = append(out, Finding{Path: path, Severity: SeverityInfo, Rule: "layer-orphan", Detail: "no ref names this layer — unreachable; the delete GC reaps it (a pull in flight on another instance may still claim it)"})
		}
	}
	return out
}
