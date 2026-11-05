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

package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The overlay mount-point preparation is COLD-path only (a volume's first
// attach): the fd-anchored walk adds two openat/mkdirat calls relative to the
// old path-based MkdirAll+Chmod. These benchmarks pin that delta. The mount(2)
// itself (the dominant cost, tens to hundreds of microseconds) is not
// included — it needs a real overlay lowerdir and CAP_SYS_ADMIN.

func BenchmarkPrepareOverlayMountDir(b *testing.B) {
	root := b.TempDir()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		vol := filepath.Join(root, fmt.Sprintf("vol-%d", i))
		if err := os.Mkdir(vol, 0o755); err != nil {
			b.Fatal(err)
		}
		fd, _, err := prepareOverlayMountDir(vol)
		if err != nil {
			b.Fatal(err)
		}
		unix.Close(fd)
	}
}

func BenchmarkLegacyPathMountDirPrep(b *testing.B) {
	root := b.TempDir()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		vol := filepath.Join(root, fmt.Sprintf("vol-%d", i))
		if err := os.Mkdir(vol, 0o755); err != nil {
			b.Fatal(err)
		}
		mountDir := filepath.Join(vol, "rootfs")
		if err := os.MkdirAll(mountDir, 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.Chmod(mountDir, 0o755); err != nil {
			b.Fatal(err)
		}
	}
}
