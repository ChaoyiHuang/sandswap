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
//
// Package util provides shared utility functions used across Sandswap components
// (gateway, sandlot). Functions here must have no dependency on component-specific
// packages — only standard library.

package util

import "strings"

// RefToFilename converts a template reference (e.g., "python:v1") to a safe
// filename (e.g., "python_v1"). Used by gateway and sandlot to build ref file
// paths under the refs/ directory. Colons are illegal in filenames on many
// filesystems; underscores are universally safe.
//
// NOTE: this only replaces ':' with '_' — it does NOT validate that the ref is
// free of path separators (/, ..). Callers MUST validate the ref (e.g. gateway
// template.validateRef) before using it in any filesystem path, otherwise a
// crafted ref like "../../etc/evil" would escape the refs/ directory. This
// function is a pure character mapping shared across components; validation
// belongs at the entry point that accepts external input.
func RefToFilename(ref string) string {
	return strings.ReplaceAll(ref, ":", "_")
}
