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

package runtime

import (
	"log"
	"os/user"
	"strconv"
	"strings"
)

// ResolveVMMGroups turns the tinyvm.vmm_groups spec (comma-separated
// numeric gids or group NAMES) into the sandvmm child's supplementary group
// list — same contract as the embedded side's resolver, kept local because
// the boxout module cannot import sandlot's package main.
// The API gid is always included so the socket chgrp (group-membership
// only, no CAP_CHOWN needed) succeeds. In k8s the spec is numeric by
// construction (deploy-lib host-injects the kvm gid); name lookup stays
// for dev runs, warn-and-skip on unresolvable entries (a missing "kvm"
// group only costs /dev/kvm, surfacing loudly at the first create).
func ResolveVMMGroups(spec string, apiGid uint32, logger *log.Logger) []uint32 {
	var out []uint32
	seen := map[uint32]bool{}
	add := func(g uint32) {
		if g != 0 && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if n, err := strconv.ParseUint(tok, 10, 32); err == nil {
			add(uint32(n))
			continue
		}
		g, err := user.LookupGroup(tok)
		if err != nil {
			logger.Printf("warning: tinyvm.vmm_groups entry %q unresolvable (skipped): %v", tok, err)
			continue
		}
		if n, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
			add(uint32(n))
		}
	}
	add(apiGid)
	return out
}
