// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, this software will be governed by
// the Apache License, Version 2.0.

package core

import (
	"os"
	"testing"

	"sandlot/vmm"
)

// TestMain pins the legacy HTTP transport for the whole core suite: the stub
// sandvmm servers used here speak only HTTP/JSON. The raw control-frame
// transport (the production default) is covered by the sandlot/vmm package
// suites and the e2e stack, which runs real sandvmm binaries.
func TestMain(m *testing.M) {
	if err := vmm.ConfigureSetFsTransport("http"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
