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

package imageimport

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sandlot/provision/template"
)

// finalizeTree applies the template-contract policy pass IN ORDER and gates
// the tree on full offline conformance. The order is load-bearing: control
// files first (volume state must never survive), skeleton before normalize
// (created dirs get their contract modes in the normalize pass), normalize
// before validate (validation must see final modes).
//
// Every severity-error finding fails the import (warnings pass) — this is
// the same gate `template-tool validate` applies, run before anything is
// published. Findings are reported against displayTree (the final
// <out>/<name>/<version> path) rather than the private staging path.
func finalizeTree(tree, displayTree string, log func(string, ...any)) ([]string, error) {
	var warnings []string
	warnf := func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
		if log != nil {
			log(format, args...)
		}
	}
	display := func(p string) string {
		if displayTree == "" || p == tree {
			return p
		}
		if strings.HasPrefix(p, tree+string(os.PathSeparator)) {
			return filepath.Join(displayTree, strings.TrimPrefix(p, tree))
		}
		return p
	}

	// 1. Volume control files are volume state, never template content.
	for _, name := range template.VolumeControlFiles() {
		p := filepath.Join(tree, name)
		if _, err := os.Lstat(p); err == nil {
			if err := os.RemoveAll(p); err != nil {
				return warnings, fmt.Errorf("strip volume control file %s: %w", name, err)
			}
			warnf("stripped volume control file %s (volume state is never template content)", name)
		}
	}

	// 2. Attach-critical + soft skeleton directories.
	created, err := template.EnsureTemplateSkeleton(tree)
	if err != nil {
		return warnings, fmt.Errorf("ensure skeleton: %w", err)
	}
	if len(created) > 0 {
		warnf("created missing skeleton directories: %s", strings.Join(created, " "))
	}

	// 3. sys/ and tmp/: the warden mounts the real proc/dev inside the
	// guest and expects them. Creating them keeps validate warning-free.
	for _, name := range []string{"sys", "tmp"} {
		p := filepath.Join(tree, name)
		if _, err := os.Lstat(p); err == nil {
			continue
		}
		if err := os.Mkdir(p, 0o755); err != nil {
			return warnings, fmt.Errorf("create %s: %w", name, err)
		}
		warnf("created missing directory %s/", name)
	}

	// 4. The contract modes pass (group grant, owner-write-only).
	changed, err := template.NormalizeTemplateTree(tree)
	if err != nil {
		return warnings, fmt.Errorf("normalize: %w", err)
	}
	if changed > 0 && log != nil {
		log("normalized %d entries to the template contract", changed)
	}

	// 5. The full offline conformance gate.
	findings, err := template.ValidateRootfsTree(tree)
	if err != nil {
		return warnings, fmt.Errorf("validate: %w", err)
	}
	var errs []string
	for _, f := range findings {
		if f.Severity == template.SeverityError {
			errs = append(errs, fmt.Sprintf("%s: %s", display(f.Path), f.Detail))
			continue
		}
		warnf("validate [%s] %s: %s", f.Severity, display(f.Path), f.Detail)
	}
	if len(errs) > 0 {
		shown := errs
		if len(shown) > 10 {
			shown = shown[:10]
		}
		return warnings, fmt.Errorf("template tree fails offline validation (%d error(s)):\n  %s",
			len(errs), strings.Join(shown, "\n  "))
	}
	return warnings, nil
}
