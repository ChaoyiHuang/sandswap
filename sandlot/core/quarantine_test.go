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
	"context"
	"strings"
	"testing"

	"sandlot/vmm"
)

// An unresolved destroy means an orphan VM may still export an old volume on
// this node. New VM creation must fail closed until the retry loop confirms
// the process is dead — re-placing a sandfs could double-mount the volume.
func TestCreateVerifiedVMRefusesWhileQuarantined(t *testing.T) {
	h := newCoreTestHandler()
	h.quarantineMu.Lock()
	h.quarantine = map[string]*quarantinedVM{
		"vm-orphan": {cid: 42, memMB: 256},
	}
	h.quarantineMu.Unlock()

	_, err := h.CreateVerifiedVM(context.Background(), vmm.Config{ID: "vm-new", MemoryMB: 64, VCPUs: 1}, "small")
	if err == nil {
		t.Fatal("CreateVerifiedVM must refuse while a VM is quarantined")
	}
	if !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("refusal must name the quarantine, got: %v", err)
	}
}
