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

package seed

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteStateScopesFile pins the adoption record's access contract: owner
// read/write plus the provision group, NEVER world-readable. The record carries
// fingerprints (not seed material), but it is provision-plane metadata and its
// error text can describe the tree — a world-readable copy is exactly the leak
// this mode closes.
func TestWriteStateScopesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFilename)
	if err := WriteState(path, State{PID: os.Getpid(), CurrentFingerprint: "deadbeef"}); err != nil {
		t.Fatalf("WriteState: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Fatalf("state file mode = %o, want 640", got)
	}
	if fi.Mode().Perm()&0o007 != 0 {
		t.Fatalf("state file has world bits (%o)", fi.Mode().Perm())
	}
	st, ok, err := ReadState(path)
	if err != nil || !ok || st.CurrentFingerprint != "deadbeef" {
		t.Fatalf("ReadState = %+v, %v, %v", st, ok, err)
	}
}
