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
	"path/filepath"
	"testing"

	"sandlot/provision/template"
)

// testSeed is the fixed 32-byte seed the volume tests derive names from.
func testSeed() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func newTestProvisioner(t *testing.T, volRoot string, mgr *template.Manager) *Provisioner {
	t.Helper()
	p, err := New(volRoot, mgr, testSeed())
	if err != nil {
		t.Fatalf("volume.New: %v", err)
	}
	return p
}

// volPath is the on-disk directory of id under the provisioner's current seed
// — the single place the tests spell out the volume layout, so a name change
// (or a rotation) moves every fixture with it.
func volPath(p *Provisioner, id string) string {
	return filepath.Join(p.VolRoot, p.volumeName(id))
}
