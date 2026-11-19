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

// Package preflight holds the refuse-to-start checks every sandlot instance
// passes before serving: host role exclusivity, volumes-mount hardening,
// guest-TCB integrity, vsockguard attestation, spawn capabilities, and the
// sandvmm supplementary-group resolution. Each check fails closed — a node
// that cannot prove its own preconditions never serves a tenant.

package preflight

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// ResolveVMMGroups turns the tinyvm.vmm_groups spec (comma-separated numeric
// gids or group NAMES — names carry per-host variance like "kvm", numbers
// carry the contract pins like 985) into the supplementary group list for
// the sandvmm child. The API gid is always included so the socket chgrp
// (group-membership-only, no CAP_CHOWN) succeeds. Unresolvable names are a
// warn-and-skip (a missing "kvm" group only costs /dev/kvm access, which
// surfaces immediately at the first VM create with a clear error).
func ResolveVMMGroups(spec string, apiGid uint32, logger *log.Logger) ([]uint32, error) {
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
	// The volume-seed group must never reach the sandvmm/FUSE child: it reads
	// the seed and every tenant's derived volume name. A group list that
	// resolves to it (by number or name, including api_gid) is refused at
	// startup rather than silently handing the seed to the daemon.
	if forbidden := SandprovGroupID(); forbidden != 0 {
		for _, g := range out {
			if g == forbidden {
				return nil, fmt.Errorf("tinyvm.vmm_groups/api_gid resolves to the sandprov group %d — the VMM/FUSE child must never carry the volume-seed group; remove it from the group list", g)
			}
		}
	}
	return out, nil
}

// SandprovGroupID resolves the provision identity's group id from the
// deployer's environment (SANDSWAP_PROV_GID, then the identity.env key), with
// a name lookup fallback for hosts that predate the export. 0 = unknown (the
// check is skipped rather than failing every host without the account).
func SandprovGroupID() uint32 {
	for _, env := range []string{"SANDSWAP_PROV_GID", "SS_GID_SANDPROV"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				return uint32(n)
			}
		}
	}
	name := os.Getenv("SANDPROV_GROUP")
	if name == "" {
		name = "sandprov"
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}
