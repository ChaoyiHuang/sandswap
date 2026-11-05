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

package core

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestHelperSandvmmProc is the child half of the identity test: it runs as a
// process named "sandvmm", binds --api-socket, and blocks until stdin closes.
// The parent drives verifySandvmmHolder/verifySandvmmProc against it.
func TestHelperSandvmmProc(t *testing.T) {
	if os.Getenv("SANDSWAP_TEST_SANDVMM_PROC") != "1" {
		return
	}
	sock := os.Getenv("SANDSWAP_TEST_SANDVMM_SOCK")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(2)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = ln.Close()
	os.Exit(0)
}

func TestSandvmmIdentityProofs(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("sandvmm-id-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(sock) })

	// The non-flag "x" stops flag parsing before --api-socket (the testing
	// framework rejects unknown flags); the helper only needs the argv text.
	cmd := exec.Command(self, "-test.run=TestHelperSandvmmProc", "x", "--api-socket", sock)
	cmd.Args[0] = "sandvmm"
	cmd.Env = append(os.Environ(),
		"SANDSWAP_TEST_SANDVMM_PROC=1",
		"SANDSWAP_TEST_SANDVMM_SOCK="+sock,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Readiness = the socket exists with its owner; no stdout parsing (the
	// testing framework may interleave its own lines).
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, ok := socketOwner(sock); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not bind its socket in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	uid := uint32(os.Geteuid())
	pid := cmd.Process.Pid

	// The configured binary (the test executable) is the kill proof.
	good := NewSandvmmIdentity(uid, self)
	if !good.hasBinaryProof() {
		t.Fatal("identity has no binary proof for an existing executable")
	}
	if !verifySandvmmProc(pid, sock, good) {
		t.Fatal("configured binary + uid/socket should verify")
	}
	if !verifySandvmmHolder(pid, sock, good) {
		t.Fatal("socket ownership should prove liveness")
	}

	// A process whose executable does not match the configured VMM binary is
	// refused even though its argv[0] is "sandvmm" and it owns the socket.
	other := filepath.Join(t.TempDir(), "sandvmm")
	if err := os.WriteFile(other, []byte("not the vmm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if verifySandvmmProc(pid, sock, NewSandvmmIdentity(uid, other)) {
		t.Fatal("a forged executable image must be refused")
	}

	// When no binary proof is available, the fallback requires the configured
	// UID and an existing socket owned by the process's real uid.
	noBinary := NewSandvmmIdentity(uid, "/nonexistent/sandvmm")
	if noBinary.hasBinaryProof() {
		t.Fatal("a missing binary must not yield a binary proof")
	}
	if !verifySandvmmProc(pid, sock, noBinary) {
		t.Fatal("uid/socket fallback should verify when the image is unavailable")
	}
	if verifySandvmmProc(pid, sock, NewSandvmmIdentity(uid+1, "/nonexistent/sandvmm")) {
		t.Fatal("a mismatched configured UID must be refused")
	}
	if verifySandvmmHolder(pid, sock, NewSandvmmIdentity(uid+1, self)) {
		t.Fatal("a mismatched configured UID must not prove liveness")
	}

	// A missing socket is not a holder: the old fallback treated it as owned,
	// which let a local user pin orphan dirs.
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	if SandvmmHoldingSocket(sock, good) {
		t.Fatal("a missing socket must not be treated as held")
	}
	if _, ok := socketOwner(sock); ok {
		t.Fatal("socketOwner must fail for a missing path")
	}
}
