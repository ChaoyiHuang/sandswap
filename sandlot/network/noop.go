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

package network

import (
	"context"

	"sandlot/vmm"
)

// Noop is a NetworkProvider that keeps microVMs offline. It is the default
// backend (--network-backend=none) and matches Sandswap's pre-networking
// behavior: no net device, no warden.net_* cmdline params.
type Noop struct{}

// NewNoop returns a Noop network provider.
func NewNoop() *Noop { return &Noop{} }

// Provision returns a zero VMNetSpec (GuestIP == "" => offline).
func (Noop) Provision(context.Context, string) (vmm.VMNetSpec, error) {
	return vmm.VMNetSpec{}, nil
}

// Release is a no-op.
func (Noop) Release(context.Context, string) error { return nil }

// Reclaim is a no-op: offline VMs hold no network resources to re-register.
func (Noop) Reclaim(context.Context, string, vmm.VMNetSpec) error { return nil }
