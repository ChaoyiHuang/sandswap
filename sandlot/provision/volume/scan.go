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

package volume

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Generation stamps are the disk-side authority on which naming generation a
// volume directory belongs to (see stamp.go). Three callers need that reading,
// and they must agree on it exactly, so the scan lives here once:
//
//   - the prov instance's STARTUP guard: a volumes root whose stamps do not
//     intersect the generations the process loaded means the seed source moved
//     under the deployment (an injection source replaced, a rollback, a
//     botched restore). Serving from there would silently split tenants, so the
//     instance refuses to start.
//   - the DAEMON's promote gate: promoting while a volume still carries the
//     pre-promote generation makes that volume unresolvable forever (the seed
//     is dropped at promote), so the transition is refused.
//   - the ROTATION TOOL's pre-flight (`template-tool seed-scan`), which is the
//     same check with better messages, run while the operator is watching.
//
// Everything here is read-only and best-effort: a directory whose stamp cannot
// be read is counted, never fatal.

const (
	scanDefaultWorkers     = 16
	scanDefaultDeadline    = 30 * time.Second
	scanDefaultMaxExamples = 3
)

// ScanOptions tunes ScanGenerationStamps. The zero value is usable.
type ScanOptions struct {
	// Known is the set of generation fingerprints the caller accepts as
	// "belonging to a configured generation". Stamped volumes outside it are
	// counted in ScanResult.Foreign. Empty disables the classification (the
	// count stays 0), so callers that only want a histogram can omit it.
	Known []string
	// Seeds are the generation seed bytes a SIGNED stamp may verify against
	// (current and, during a rotation window, staged). A stamp whose
	// signature does not verify (including an unsigned stamp) is counted as
	// Unverified — it was forged by a tenant, copied from another volume, or
	// written by a pre-signature build. A production caller always supplies
	// the seeds, so nil means "nothing can verify".
	Seeds [][]byte
	// Workers bounds concurrent stamp reads (default 16).
	Workers int
	// Deadline bounds how long new directories are scheduled (default 30s).
	// In-flight reads are not interrupted: a root slow enough to hit this
	// reports Complete=false and the counts are a lower bound.
	Deadline time.Duration
	// MaxExamples caps ScanResult.Examples (default 3).
	MaxExamples int
	// readStamp is the per-volume stamp read. Test seam for the concurrency
	// pin (TestScanGenerationStampsReadsConcurrently): it must run OUTSIDE the
	// merge lock, or Workers does nothing and the deadline refuses clean
	// fleet-scale trees. nil = readVolumeStamp.
	readStamp func(volPath string) (volumeStamp, bool, error)
}

// ScanResult is the reading of every volume stamp under a root.
type ScanResult struct {
	// ByGeneration counts stamped volumes per generation fingerprint.
	ByGeneration map[string]int
	// Unstamped counts directories with no stamp file at all (a tree that
	// predates stamping, or a non-volume directory).
	Unstamped int
	// PreGeneration counts stamps that exist but carry no generation (the
	// pre-generation format): also a legacy/migration signal.
	PreGeneration int
	// Foreign counts stamped volumes whose fingerprint is not in Known.
	Foreign int
	// Partial counts genuine mid-provision directories: a .provisioning marker
	// AND no authenticated stamp (the stamp is written last). A marker on a
	// volume with a valid signed stamp is tenant-plantable and is classified
	// by that stamp instead — see the worker.
	Partial int
	// Sampled counts the volume directories actually examined.
	Sampled int
	// ReadErrors counts stamps that could not be read (I/O, permissions).
	ReadErrors int
	// Unverified counts stamps that were READ but could not be authenticated:
	// unsigned, or signed with a seed no live generation matches. The tenant
	// can replace the file in flat mode, and a seed mix-up looks exactly like
	// this, so the strict gates refuse on a non-zero count.
	Unverified int
	// Complete is false when the deadline cut the scan short.
	Complete bool
	// RootMissing reports that the volumes root did not exist: the scan
	// examined nothing, so every count is zero for lack of a tree, not because
	// the tree is clean. Best-effort callers (the startup guard) stay lenient;
	// the strictly gated ones (the promote gate, `seed-scan`) must refuse — a
	// promote against a root that was never read drops the old generation while
	// the real tree's volumes become unresolvable.
	RootMissing bool
	// Examples holds up to MaxExamples anomalies as "<dir>: <reason>".
	Examples []string
}

// GenerationCount returns how many sampled volumes carry fp.
func (r ScanResult) GenerationCount(fp string) int { return r.ByGeneration[fp] }

// LegacyCount is the number of volumes with no usable generation: no stamp, or
// a pre-generation stamp. Both need `--migrate` before a promote can be safe.
func (r ScanResult) LegacyCount() int { return r.Unstamped + r.PreGeneration }

// ScanGenerationStamps reads the generation stamp of every volume directory
// under root. Skip rules, shared with the rotation tooling: dot-prefixed names
// (orphan-rename debris, tmpfiles) and directories carrying the .provisioning
// marker (partial runs). A root that does not exist is not an ERROR here —
// EnsureVolume owns the actionable "volumes root missing" error — but it is
// reported in RootMissing: "nothing was scanned" and "the tree is clean" are
// different readings, and the strictly gated callers must refuse the former.
func ScanGenerationStamps(root string, opts ScanOptions) (ScanResult, error) {
	workers := opts.Workers
	if workers <= 0 {
		workers = scanDefaultWorkers
	}
	deadline := opts.Deadline
	if deadline <= 0 {
		deadline = scanDefaultDeadline
	}
	maxExamples := opts.MaxExamples
	if maxExamples <= 0 {
		maxExamples = scanDefaultMaxExamples
	}
	known := make(map[string]bool, len(opts.Known))
	for _, fp := range opts.Known {
		if fp != "" {
			known[fp] = true
		}
	}
	read := opts.readStamp
	if read == nil {
		read = readVolumeStamp
	}

	res := ScanResult{ByGeneration: map[string]int{}, Complete: true}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			res.RootMissing = true
			return res, nil
		}
		return res, fmt.Errorf("scan volume stamps under %s: %w", root, err)
	}

	var candidates []string
	for _, e := range entries {
		name := e.Name()
		// Symlinks are not followed: a volume is a real directory, and a
		// symlink in the root is not one (following it would read outside the
		// tree this scan is defined over).
		if strings.HasPrefix(name, ".") || !e.IsDir() {
			continue
		}
		candidates = append(candidates, name)
	}

	// Time-based, not context-based: the scheduling budget must be
	// deterministically testable (a timer goroutine's firing order is not).
	deadlineAt := time.Now().Add(deadline)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	addExample := func(s string) {
		if len(res.Examples) < maxExamples {
			res.Examples = append(res.Examples, s)
		}
	}

schedule:
	for _, name := range candidates {
		if time.Now().After(deadlineAt) {
			mu.Lock()
			res.Complete = false
			mu.Unlock()
			break schedule
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			vol := filepath.Join(root, name)

			// The filesystem work runs OUTSIDE the merge lock: Workers is the
			// knob that lets a fleet-scale shared-storage tree finish inside
			// Deadline, and holding mu across the marker stat and the stamp
			// read serialized every worker into one — a clean tree then
			// reported Complete=false and the promote gate refused it. The
			// critical section below only merges the result.
			partial := hasProvisioningMarker(vol)
			var (
				st   volumeStamp
				ok   bool
				serr error
			)
			verified := true
			// Read the stamp even under a .provisioning marker: a marker is
			// only a GENUINE partial run when the stamp is missing/unverifiable
			// (the stamp is written last). A flat-mode tenant can plant the
			// marker in its own complete volume; treating that as "skip" hid
			// the volume from the promote gate (stranding it in the retired
			// generation). Classify a marked volume by its authenticated stamp
			// and reserve Partial for the no-stamp case.
			st, ok, serr = read(vol)
			// A stamp the live seeds cannot authenticate (unsigned, or
			// signed by a seed no generation matches) is tampering or a
			// seed mix-up: its own counter, distinct from an I/O read
			// error. The strict gates refuse on it.
			if serr == nil && ok {
				verified = verifyVolumeStamp(vol, st, opts.Seeds)
			}

			mu.Lock()
			defer mu.Unlock()
			if partial && !(serr == nil && ok && verified && st.Generation != "") {
				res.Partial++
				return
			}
			res.Sampled++
			switch {
			case serr != nil:
				res.ReadErrors++
				addExample(fmt.Sprintf("%s: stamp unreadable", name))
			case ok && !verified:
				res.Unverified++
				addExample(fmt.Sprintf("%s: stamp signature does not verify (generation %s)", name, st.Generation))
			case !ok:
				res.Unstamped++
				addExample(fmt.Sprintf("%s: no stamp", name))
			case st.Generation == "":
				res.PreGeneration++
				addExample(fmt.Sprintf("%s: pre-generation stamp", name))
			default:
				res.ByGeneration[st.Generation]++
				if len(known) > 0 && !known[st.Generation] {
					res.Foreign++
					addExample(fmt.Sprintf("%s: generation %s is not configured", name, st.Generation))
				}
			}
		}(name)
	}
	wg.Wait()
	// Complete is only cleared by the scheduling loop above: a deadline that
	// expires after the last directory was scheduled still means everything
	// was examined.
	return res, nil
}
