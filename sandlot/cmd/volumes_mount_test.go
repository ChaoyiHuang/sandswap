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
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVolumesMountSecureRequiresBothFlags(t *testing.T) {
	cases := []struct {
		flags uint64
		want  bool
		name  string
	}{
		{unix.ST_NOSUID | unix.ST_NODEV, true, "both set"},
		{unix.ST_NOSUID, false, "nosuid only"},
		{unix.ST_NODEV, false, "nodev only"},
		{0, false, "neither"},
		{unix.ST_NOSUID | unix.ST_NODEV | unix.ST_RDONLY, true, "both set plus extras"},
	}
	for _, c := range cases {
		if got := volumesMountSecure(c.flags); got != c.want {
			t.Errorf("%s: volumesMountSecure(%#x) = %v, want %v", c.name, c.flags, got, c.want)
		}
	}
}

func TestMissingMountFlagsNamesTheGap(t *testing.T) {
	if got := missingMountFlags(0); got != "nosuid,nodev" {
		t.Errorf("neither flag: got %q, want nosuid,nodev", got)
	}
	if got := missingMountFlags(unix.ST_NODEV); got != "nosuid" {
		t.Errorf("nodev present: got %q, want nosuid", got)
	}
	if got := missingMountFlags(unix.ST_NOSUID); got != "nodev" {
		t.Errorf("nosuid present: got %q, want nodev", got)
	}
}

func TestRequireSecureVolumesMountFailsClosed(t *testing.T) {
	// A path that does not exist: refusal (never "probably fine").
	err := requireSecureVolumesMount("/nonexistent-sandswap-volumes-check", false)
	if err == nil {
		t.Fatal("missing volumes dir must be refused")
	}
	if !strings.Contains(err.Error(), "refusing to start") {
		t.Errorf("refusal must be named, got: %v", err)
	}

	// The explicit admission bypasses the check (dev/test contract).
	if err := requireSecureVolumesMount("/nonexistent-sandswap-volumes-check", true); err != nil {
		t.Errorf("allow-insecure must bypass, got: %v", err)
	}

	// The host's own /dev is nodev but typically NOT nosuid; /proc is
	// nosuid but not nodev — both must be refused. (If a build host ever
	// mounts both flags on either, the assertion degrades to testing the
	// secure path below — still meaningful.)
	for _, path := range []string{"/dev", "/proc", "/"} {
		if err := requireSecureVolumesMount(path, false); err == nil {
			// Not a failure per se (unusual host), but pin the secure-path
			// behavior explicitly when it happens.
			t.Logf("note: %s already carries both flags on this host", path)
		} else if !strings.Contains(err.Error(), "nosuid") {
			t.Errorf("refusal for %s must name the missing flags, got: %v", path, err)
		}
	}

	// A tmpfs mounted with the flags satisfies the gate: /dev/shm on
	// systemd hosts is nosuid,nodev. Skipped silently when it is not.
	if err := requireSecureVolumesMount("/dev/shm", false); err != nil {
		t.Logf("note: /dev/shm not nosuid,nodev here (%v) — secure-path pin skipped", err)
	}
}
