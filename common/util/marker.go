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

package util

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// MaxMarkerBytes bounds a marker read. Markers hold a short identifier
// (e.g. a template ref like "rootfs:v1"); anything larger is not a marker
// sandswap wrote.
const MaxMarkerBytes = 4096

// ReadMarkerFile reads a small marker file (a SandFS volume's .template)
// WITHOUT following symlinks and WITHOUT blocking on special files.
//
// Why the hardening: in flat mode the volume root IS the agent's chroot
// root, so the agent can plant any entry at the marker path. A planted
// SYMLINK would turn a host-side marker read into an arbitrary host-file
// read (the kernel resolves the target against the host root); a planted
// FIFO would make open(2) block forever and hang the mounting or scanning
// node; a giant regular file would balloon memory. None of those can be a
// marker sandswap wrote — markers are small regular files.
//
// Returns:
//   - (data, true, nil)  — a regular file within the size cap, read fully.
//   - (nil, false, nil)  — the path exists but is not a usable marker file
//     (symlink, FIFO, device, oversized); callers treat this as "no marker".
//   - (nil, false, err)  — any other error, fs.ErrNotExist included.
func ReadMarkerFile(path string) ([]byte, bool, error) {
	// O_NONBLOCK: a FIFO opened for read blocks until a writer appears —
	// with O_NONBLOCK the open returns immediately and the fstat below
	// rejects the entry. Inert on regular files.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, false, nil // a symlink: never a marker sandswap wrote
		}
		return nil, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxMarkerBytes {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxMarkerBytes))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}
