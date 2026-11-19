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
	"fmt"
	"os"
)

// newFlagSet returns a FlagSet that exits on parse error with a usage hint.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sandctl %s [flags] [args]\n", name)
		fs.PrintDefaults()
	}
	fs.SetOutput(os.Stderr)
	return fs
}
