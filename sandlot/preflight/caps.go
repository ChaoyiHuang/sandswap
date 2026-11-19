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
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CheckCapsForVMMSpawn verifies this process can actually perform the
// identity-split spawn and teardown: the uid transition needs
// CAP_SETUID/CAP_SETGID, and killing a different-uid child needs CAP_KILL.
// Failing here (startup) beats failing per-VM-create with a bare EPERM.
func CheckCapsForVMMSpawn(vmmUid uint32) error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("cannot read /proc/self/status for capability pre-flight: %w", err)
	}
	var effHex string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			effHex = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	if effHex == "" {
		return fmt.Errorf("no CapEff line in /proc/self/status")
	}
	eff, err := strconv.ParseUint(effHex, 16, 64)
	if err != nil {
		return fmt.Errorf("parse CapEff %q: %w", effHex, err)
	}
	const (
		capSetGID = 1 << 6 // CAP_SETGID (capability 6; 1 is DAC_OVERRIDE)
		capSetUID = 1 << 7 // CAP_SETUID
		capKill   = 1 << 5 // CAP_KILL
	)
	missing := []string{}
	if eff&capSetUID == 0 {
		missing = append(missing, "CAP_SETUID")
	}
	if eff&capSetGID == 0 {
		missing = append(missing, "CAP_SETGID")
	}
	if eff&capKill == 0 {
		missing = append(missing, "CAP_KILL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("sandlot lacks %s — required by the sandvmm identity split (uid %d):\n"+
			"  fix: update the service unit / launch path to AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_KILL\n"+
			"  (deploy/baremetal/systemd/sandswap-sandlot.service, or common/sh/runtime.sh ss_service_exec)",
			strings.Join(missing, ", "), vmmUid)
	}
	return nil
}
