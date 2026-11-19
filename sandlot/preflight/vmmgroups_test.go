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

package preflight

import (
	"io"
	"log"
	"testing"
)

// TestResolveVMMGroupsRejectsSandprovGroup pins the startup refusal: the
// sandvmm/FUSE child must never carry the volume-seed group, whether it is
// named directly or arrives through api_gid.
func TestResolveVMMGroupsRejectsSandprovGroup(t *testing.T) {
	t.Setenv("SANDSWAP_PROV_GID", "4242")
	t.Setenv("SS_GID_SANDPROV", "")
	t.Setenv("SANDPROV_GROUP", "")
	lg := log.New(io.Discard, "", 0)

	if _, err := ResolveVMMGroups("4242", 985, lg); err == nil {
		t.Fatal("sandprov group accepted in tinyvm.vmm_groups")
	}
	if _, err := ResolveVMMGroups("", 4242, lg); err == nil {
		t.Fatal("sandprov group accepted as api_gid")
	}
	got, err := ResolveVMMGroups("985", 986, lg)
	if err != nil {
		t.Fatalf("valid group list rejected: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("resolved groups = %v, want 2 entries", got)
	}
}
