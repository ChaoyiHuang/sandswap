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

package config

import (
	"flag"
	"fmt"
	"reflect"
)

// ExplicitFlags returns a set of flag names that were explicitly set on the
// command line. This wraps flag.Visit for convenience.
func ExplicitFlags() map[string]bool {
	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		set[f.Name] = true
	})
	return set
}

// DiffConfigs compares two config structs field-by-field using reflection.
// It calls the provided classify function for each changed field to determine
// whether it is hot-reloadable or restart-required.
//
// The structs must be comparable (no unexported fields, no slices/maps with
// uncomparable elements). For practical Sandswap configs, all fields are
// strings, ints, or nested structs of the same.
//
// The prefix is prepended to field names (e.g. "lease" → "lease.timeout_ms").
func DiffConfigs(old, new any, prefix string, classify func(fieldName string) ChangeClass) ChangeSet {
	var cs ChangeSet
	diffStructs(reflect.ValueOf(old), reflect.ValueOf(new), prefix, classify, &cs)
	return cs
}

// diffStructs recursively walks two struct values and records differences.
func diffStructs(oldVal, newVal reflect.Value, prefix string, classify func(string) ChangeClass, cs *ChangeSet) {
	// Dereference pointers.
	if oldVal.Kind() == reflect.Ptr {
		oldVal = oldVal.Elem()
	}
	if newVal.Kind() == reflect.Ptr {
		newVal = newVal.Elem()
	}

	if oldVal.Kind() != reflect.Struct || newVal.Kind() != reflect.Struct {
		return
	}

	t := oldVal.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		// Skip unexported fields.
		if !field.IsExported() {
			continue
		}

		yamlTag := field.Tag.Get("yaml")
		// A field tagged `yaml:"-"` is by definition not part of the FILE's
		// surface (it is set from a flag or at runtime, e.g. ConfigFilePath
		// from -config). Diffing it compares a live-only field against the
		// zero value a freshly decoded struct carries, so EVERY reload
		// reports it as a restart-required change — pure noise that buries
		// the real diff lines an operator greps for.
		if yamlTag == "-" {
			continue
		}
		fieldName := yamlName(yamlTag, field.Name)

		var fullKey string
		if prefix != "" {
			fullKey = prefix + "." + fieldName
		} else {
			fullKey = fieldName
		}

		of := oldVal.Field(i)
		nf := newVal.Field(i)

		// Recurse into nested structs.
		if of.Kind() == reflect.Struct && nf.Kind() == reflect.Struct {
			diffStructs(of, nf, fullKey, classify, cs)
			continue
		}

		// Compare field values.
		if !reflect.DeepEqual(of.Interface(), nf.Interface()) {
			fc := FieldChange{
				Name:  fullKey,
				Old:   fmt.Sprintf("%v", of.Interface()),
				New:   fmt.Sprintf("%v", nf.Interface()),
				Class: classify(fullKey),
			}
			if fc.Class == ChangeRestartRequired {
				cs.RestartReq = append(cs.RestartReq, fc)
			} else {
				cs.HotReload = append(cs.HotReload, fc)
			}
		}
	}
}

// yamlName extracts the YAML field name from a tag. For a tag like
// `yaml:"timeout_ms,omitempty"`, it returns "timeout_ms". If no yaml tag
// or the tag is "-", it returns the Go field name.
func yamlName(tag, fallback string) string {
	if tag == "" || tag == "-" {
		return fallback
	}
	// Handle "name,omitempty" → extract "name".
	for i := 0; i < len(tag); i++ {
		if tag[i] == ',' {
			name := tag[:i]
			if name == "" {
				return fallback
			}
			return name
		}
	}
	return tag
}
