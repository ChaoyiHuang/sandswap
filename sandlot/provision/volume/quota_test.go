// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, this software will be governed by
// the Apache License, Version 2.0.

package volume

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The hook's three outcomes through the REAL exec path (a shell script as
// the hook): exit 0 passes, nonzero fails with the sentinel + output tail,
// and a timeout fails with the sentinel (deadline shrunk for the test).
// Plus the empty-command no-op.
func TestRunQuotaStampCmdOutcomes(t *testing.T) {
	dir := t.TempDir()
	okHook := filepath.Join(dir, "ok.sh")
	badHook := filepath.Join(dir, "bad.sh")
	slowHook := filepath.Join(dir, "slow.sh")
	for path, body := range map[string]string{
		okHook: "#!/bin/sh\n" +
			// Contract check: argv[1] is the sandfs id, the volume path is
			// one line on stdin (never argv — /proc/cmdline is world-readable).
			"read -r p\n" +
			"[ \"$1\" = \"sf-1\" ] || exit 8\n" +
			"[ \"$p\" = \"/v/x\" ] || exit 9\n" +
			"exit 0\n",
		badHook:  "#!/bin/sh\necho ceph-fs-full >&2\nexit 3\n",
		slowHook: "#!/bin/sh\nsleep 5\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	if err := runQuotaStampCmd(ctx, "", "/v/x", "sf-1"); err != nil {
		t.Fatalf("empty command must be a no-op, got %v", err)
	}
	if err := runQuotaStampCmd(ctx, okHook, "/v/x", "sf-1"); err != nil {
		t.Fatalf("exit-0 hook failed: %v", err)
	}
	err := runQuotaStampCmd(ctx, badHook, "/v/x", "sf-1")
	if !errors.Is(err, ErrQuotaStamp) {
		t.Fatalf("nonzero hook must fail with the sentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), "ceph-fs-full") {
		t.Fatalf("error should carry exit status + output tail: %v", err)
	}

	prev := quotaStampDeadline
	quotaStampDeadline = 200 * time.Millisecond
	defer func() { quotaStampDeadline = prev }()
	err = runQuotaStampCmd(ctx, slowHook, "/v/x", "sf-1")
	if !errors.Is(err, ErrQuotaStamp) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("slow hook must fail with sentinel + timeout, got %v", err)
	}
}

// ValidateQuotaStampCmd: empty ok, absolute ok, relative refused.
func TestValidateQuotaStampCmd(t *testing.T) {
	if err := ValidateQuotaStampCmd(""); err != nil {
		t.Fatalf("empty must pass: %v", err)
	}
	if err := ValidateQuotaStampCmd("/usr/libexec/sandswap/quota-stamp"); err != nil {
		t.Fatalf("absolute must pass: %v", err)
	}
	if err := ValidateQuotaStampCmd("quota-stamp"); err == nil {
		t.Fatal("relative must be refused")
	}
}

// The EnsureVolume CONTRACT for a failed quota stamp: the create fails with
// the sentinel AND the provisioning marker STAYS — the next attempt must
// self-heal (wipe + redo, hook included), never finalize an unquota'd
// volume. A succeeding stamp leaves no marker, and the empty-command default
// changes nothing (the plain happy path is covered by the seed tests).
func TestEnsureVolumeQuotaStampFailureKeepsMarkerForSelfHeal(t *testing.T) {
	p, _, _ := newFixture(t)
	orig := stampQuota
	defer func() { stampQuota = orig }()

	stampQuota = func(ctx context.Context, cmd, vp, id string) error {
		if cmd == "" {
			t.Fatal("hook invoked with an empty command (must be a no-op)")
		}
		if id != "sandfs-1" || vp != volPath(p, "sandfs-1") {
			t.Fatalf("hook args = %q %q", vp, id)
		}
		return fmt.Errorf("%w: simulated ceph error", ErrQuotaStamp)
	}
	p.QuotaStampCmd = "/storage/quota-stamp"

	_, err := p.EnsureVolume(context.Background(), "sandfs-1", "flat", "seed:v1")
	if !errors.Is(err, ErrQuotaStamp) {
		t.Fatalf("EnsureVolume must fail with the quota sentinel, got %v", err)
	}
	vol := volPath(p, "sandfs-1")
	if _, serr := os.Stat(filepath.Join(vol, provisioningMarker)); serr != nil {
		t.Fatalf("marker must SURVIVE a failed stamp (self-heal contract): %v", serr)
	}

	// Self-heal: a retry with a WORKING hook wipes the partial tree and
	// finalizes (marker gone, content present, hook saw the fresh path).
	var hookPath string
	stampQuota = func(ctx context.Context, cmd, vp, id string) error {
		hookPath = vp
		return nil
	}
	if _, err := p.EnsureVolume(context.Background(), "sandfs-1", "flat", "seed:v1"); err != nil {
		t.Fatalf("self-heal retry: %v", err)
	}
	if hookPath != vol {
		t.Fatalf("retry hook saw %q, want the re-seeded volume %q", hookPath, vol)
	}
	if _, serr := os.Stat(filepath.Join(vol, provisioningMarker)); !os.IsNotExist(serr) {
		t.Fatalf("marker present after healed retry: %v", serr)
	}
}

// The no-op default: an unset QuotaStampCmd must not invoke anything — the
// seed happy-path test already pins the finalization; this pins the seam.
func TestEnsureVolumeQuotaStampDefaultIsNoop(t *testing.T) {
	p, _, _ := newFixture(t)
	orig := stampQuota
	defer func() { stampQuota = orig }()
	stampQuota = func(ctx context.Context, cmd, vp, id string) error {
		if cmd != "" {
			t.Fatalf("hook must not be CONFIGURED: stampQuota called with cmd %q", cmd)
		}
		// Reaching the seam with an empty cmd is the contract's shape; the
		// real runner (and the seam test above) pin that empty means no-op.
		return nil
	}
	if _, err := p.EnsureVolume(context.Background(), "sandfs-2", "flat", "seed:v1"); err != nil {
		t.Fatalf("EnsureVolume (no quota cmd): %v", err)
	}
}
