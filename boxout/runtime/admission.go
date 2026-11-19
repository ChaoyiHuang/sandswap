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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadOrCreateClientToken reads the per-pod token shared with sandlot, or
// creates it on first start. The file must live in a pod-private directory
// (an emptyDir shared by the two containers), mode 0400 owned by the sandlot
// UID. A pre-existing valid token is reused so a boxout restart does not
// invalidate the sandlot's copy.
func LoadOrCreateClientToken(path string, allowedUID int) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		tok := strings.TrimSpace(string(data))
		if raw, derr := hex.DecodeString(tok); derr == nil && len(raw) == sha256.Size {
			return tok, nil
		}
		return "", fmt.Errorf("existing token file is malformed (want 64 hex characters)")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	var raw [sha256.Size]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(tok+"\n"), 0o400); err != nil {
		return "", err
	}
	if err := os.Chown(tmp, allowedUID, allowedUID); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tok, nil
}
