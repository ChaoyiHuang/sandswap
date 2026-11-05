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
	"flag"
	"strconv"
	"testing"

	sandlotconfig "sandlot/config"
)

// TestFlagDefaultsMatchConfigDefaults pins every flag whose default is shared
// with Defaults() through a named constant. A flag default is the value a config
// file does not override (and the one -help advertises), so silent drift between
// the two is a real operational difference, not a cosmetic one.
func TestFlagDefaultsMatchConfigDefaults(t *testing.T) {
	d := sandlotconfig.Defaults()
	cases := []struct{ name, want string }{
		{"gateway-addr", d.GatewayAddr},
		{"kernel", d.MicroVM.Kernel},
		{"initramfs", d.MicroVM.Initramfs},
		{"default-vcpus", strconv.FormatUint(uint64(d.MicroVM.DefaultVCPUs), 10)},
		{"default-memory", strconv.FormatUint(d.MicroVM.DefaultMemoryMB, 10)},
		{"vmm-binary", d.VMMBinary},
		{"volumes-dir", d.MicroVM.VolumesDir},
		{"network-backend", d.Network.Backend},
		{"network-bridge", d.Network.Bridge},
		{"network-subnet", d.Network.Subnet},
		{"network-gateway", d.Network.Gateway},
		{"network-dns", d.Network.DNS},
		{"network-v6-prefix", d.Network.V6Prefix},
		{"egress-baseline", d.Network.EgressBaseline},
		{"vm-to-vm-policy", d.Network.VMToVM},
		{"max-uses", strconv.Itoa(d.Recycle.MaxUses)},
		{"recycle-mem-percent", strconv.Itoa(d.Recycle.MemPercent)},
		{"recycle-mem-abs-mb", strconv.Itoa(d.Recycle.MemAbsMB)},
		{"min-idle-floor-frac", strconv.FormatFloat(d.Recycle.MinIdleFloorFrac, 'g', -1, 64)},
		{"vm-create-concurrency", strconv.Itoa(d.Concurrency.VMCreate)},
		{"vm-destroy-concurrency", strconv.Itoa(d.Concurrency.VMDestroy)},
		{"vm-mode", d.VMMode},
		{"boxout-socket", d.BoxoutSocket},
		{"setfs-transport", d.SetFsTransport},
		{"vmm-api-auth", strconv.FormatBool(d.MicroVM.VMMAPIAuth)},
		{"tolerance-sec", strconv.Itoa(d.Resilience.ToleranceSec)},
		{"cleanup-sec", strconv.Itoa(d.Resilience.CleanupSec)},
		{"warden-countdown-sec", strconv.Itoa(d.Resilience.WardenCountdownSec)},
		{"isolation-sec", strconv.Itoa(d.Resilience.IsolationSec)},
		{"max-provision-ops", strconv.Itoa(d.Provision.MaxConcurrentOps)},
		{"provision-deadline-sec", strconv.Itoa(d.Provision.DefaultDeadlineSec)},
		{"provision-reconnect-sec", strconv.Itoa(d.Provision.ReconnectSec)},
	}
	for _, tc := range cases {
		f := flag.Lookup(tc.name)
		if f == nil {
			t.Fatalf("flag -%s is not registered", tc.name)
		}
		if f.DefValue != tc.want {
			t.Errorf("-%s default = %q, Defaults() = %q — register the flag from the shared constant", tc.name, f.DefValue, tc.want)
		}
	}
}
