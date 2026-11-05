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

package bindreg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// testHammerDuration bounds the seqlock concurrency hammer.
const testHammerDuration = 300 * time.Millisecond

// openTestShm opens a throwaway shm region in t.TempDir.
func openTestShm(t *testing.T, cfg Config) *Region {
	t.Helper()
	cfg.Backend = BackendShm
	cfg.Path = filepath.Join(t.TempDir(), "bindings")
	r, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open shm: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// TestLayoutStable pins the binary layout contract. A change here is a
// FormatVersion change — if this test fails, bump FormatVersion and update
// every third-party reader, do not silently move fields.
func TestLayoutStable(t *testing.T) {
	if EntrySize != 256 {
		t.Fatalf("EntrySize = %d, want 256", EntrySize)
	}
	if HeaderSize != 4096 {
		t.Fatalf("HeaderSize = %d, want 4096", HeaderSize)
	}
	for _, c := range []struct {
		name string
		off  int
		want int
	}{
		{"magic", offMagic, 0},
		{"version", offVersion, 4},
		{"state", offState, 8},
		{"epoch", offEpoch, 16},
		{"agent_id", offAgentID, 24},
		{"sandfs_id", offSandfsID, 88},
		{"vm_id", offVMID, 152},
		{"seq", offSeq, 248},
		{"entry_end", offEntryEnd, 256},
		{"global_seq", offGlobalSeq, 24},
	} {
		if c.off != c.want {
			t.Errorf("%s offset = %d, want %d", c.name, c.off, c.want)
		}
	}
	// The seqlock sequence must sit OUTSIDE the 8-byte payload word range so
	// payload stores can never clobber it (the bug class the concurrency test
	// exists to catch).
	if offSeq < int(EntrySize)-8 || offSeq%8 != 0 {
		t.Errorf("offSeq=%d must be the last 8-aligned word of the entry", offSeq)
	}
	// ID fields must not overlap: agent[24..87], sandfs[88..151], vm[152..215].
	if offSandfsID != offAgentID+IDLen || offVMID != offSandfsID+IDLen {
		t.Errorf("ID fields overlap or misaligned")
	}
}

// TestGoldenEntryBytes locks the first entry's exact bytes so a reader written
// against the documented layout stays compatible.
func TestGoldenEntryBytes(t *testing.T) {
	r := openTestShm(t, Config{})
	slot := r.data[entryOffset(7):entryOffset(8)]
	var p [EntrySize]byte
	encodeEntry(p[:], StateMounted, 42, "agent-a", "sandfs-b", "vm-c")
	publishSeq(slot, &p)

	want := make([]byte, EntrySize)
	binary.LittleEndian.PutUint32(want[0:], RegionMagic)
	binary.LittleEndian.PutUint32(want[4:], 1)
	binary.LittleEndian.PutUint32(want[8:], 1) // state = mounted
	binary.LittleEndian.PutUint64(want[16:], 42)
	copy(want[24:], "agent-a")
	copy(want[88:], "sandfs-b")
	copy(want[152:], "vm-c")
	binary.LittleEndian.PutUint32(want[offSeq:], 2) // even sequence
	// (everything else must be zero — reserved ranges included)
	for i := range want {
		if slot[i] != want[i] {
			t.Fatalf("byte %d differs: got %02x want %02x (layout drift — bump FormatVersion)", i, slot[i], want[i])
		}
	}
}

func TestPublishLookupRoundtrip(t *testing.T) {
	r := openTestShm(t, Config{})
	const idx = 12
	if _, ok, err := r.Lookup(idx); err != nil || ok {
		t.Fatalf("empty region Lookup: ok=%v err=%v", ok, err)
	}
	e := Entry{State: StateMounted, MountEpoch: 3, AgentID: "agent-xyz", SandfsID: "sfs-1", VMID: "vm-9"}
	if err := r.Publish(idx, e); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, ok, err := r.Lookup(idx)
	if err != nil || !ok {
		t.Fatalf("Lookup: ok=%v err=%v", ok, err)
	}
	if got != e {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", got, e)
	}
	if r.GlobalSeq() != 1 {
		t.Fatalf("GlobalSeq after publish = %d, want 1", r.GlobalSeq())
	}

	// Revoke keeps identity fields but clears state.
	if err := r.Revoke(idx); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, ok, err = r.Lookup(idx)
	if err != nil || !ok {
		t.Fatalf("Lookup after revoke: ok=%v err=%v", ok, err)
	}
	if got.State != StateUnbound || got.AgentID != "" || got.SandfsID != "" {
		t.Fatalf("revoked entry = %+v, want state=unbound with identity cleared", got)
	}
	if got.MountEpoch != 3 {
		t.Fatalf("revoked entry lost epoch: %+v", got)
	}

	// Unregister erases the slot entirely.
	if err := r.Unregister(idx); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if _, ok, err := r.Lookup(idx); err != nil || ok {
		t.Fatalf("Lookup after unregister: ok=%v err=%v", ok, err)
	}
}

func TestLongIDsTruncated(t *testing.T) {
	r := openTestShm(t, Config{})
	long := strings.Repeat("x", 200)
	if err := r.Publish(1, Entry{State: StateMounted, AgentID: long, SandfsID: long, VMID: long}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, ok, err := r.Lookup(1)
	if err != nil || !ok {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got.AgentID) != IDLen || len(got.SandfsID) != IDLen || len(got.VMID) != IDLen {
		t.Fatalf("IDs not truncated to %d: %d/%d/%d", IDLen, len(got.AgentID), len(got.SandfsID), len(got.VMID))
	}
}

func TestOutOfRange(t *testing.T) {
	r := openTestShm(t, Config{MaxIfindex: 100})
	err := r.Publish(100, Entry{State: StateMounted})
	var oor *ErrOutOfRange
	if err == nil || !errors.As(err, &oor) {
		t.Fatalf("Publish beyond max: err=%v, want ErrOutOfRange", err)
	}
	if _, _, err := r.Lookup(100); err == nil || !errors.As(err, &oor) {
		t.Fatalf("Lookup beyond max: err=%v, want ErrOutOfRange", err)
	}
}

// TestConcurrentWriterReaders hammers the seqlock with one writer and many
// readers, asserting no reader ever observes a torn entry. Every mounted
// generation encodes its epoch inside its agent id, so any accepted read whose
// fields disagree across generations proves a torn read.
func TestConcurrentWriterReaders(t *testing.T) {
	r := openTestShm(t, Config{})
	const idx = 3
	const seedEpoch = uint64(1_000_000)
	// Seed with a SELF-CONSISTENT generation: every accepted mounted read must
	// satisfy agentID == "agent-<epoch>".
	if err := r.Publish(idx, Entry{State: StateMounted, MountEpoch: seedEpoch, AgentID: "agent-1000000"}); err != nil {
		t.Fatalf("Publish seed: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // writer: flip identities forever
		defer wg.Done()
		for i := seedEpoch + 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = r.Publish(idx, Entry{State: StateMounted, MountEpoch: i,
				AgentID: fmt.Sprintf("agent-%d", i), SandfsID: "sfs", VMID: "vm"})
			_ = r.Revoke(idx)
		}
	}()

	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				e, _, err := r.Lookup(idx)
				if err == ErrStaleRead {
					continue
				}
				if err != nil {
					t.Errorf("Lookup: %v", err)
					return
				}
				switch e.State {
				case StateMounted:
					if e.MountEpoch < seedEpoch || e.AgentID == "" {
						t.Errorf("torn mounted entry: %+v", e)
						return
					}
					// epoch and agent must agree (both written together)
					if want := fmt.Sprintf("agent-%d", e.MountEpoch); e.AgentID != want {
						t.Errorf("torn entry: agent=%q epoch=%d (want %q)", e.AgentID, e.MountEpoch, want)
						return
					}
				case StateUnbound:
					if e.AgentID != "" {
						t.Errorf("unbound entry carries identity: %+v", e)
						return
					}
				}
			}
		}()
	}

	// Run the hammer for a bounded time.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	deadline := time.After(testHammerDuration)
	select {
	case <-done:
	case <-deadline:
	}
	close(stop)
	<-done
}

// TestReopenPreservesRegion: a second Open on the same path re-attaches to the
// existing region and sees prior content (sandlot restart snapshot semantics).
func TestReopenPreservesRegion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings")
	cfg := Config{Backend: BackendShm, Path: path}
	r1, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	if err := r1.Publish(5, Entry{State: StateMounted, MountEpoch: 9, AgentID: "a", SandfsID: "s", VMID: "v"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := r1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// File persists after Close.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("region file removed by Close: %v", err)
	}
	r2, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	defer r2.Close()
	got, ok, err := r2.Lookup(5)
	if err != nil || !ok || got != (Entry{State: StateMounted, MountEpoch: 9, AgentID: "a", SandfsID: "s", VMID: "v"}) {
		t.Fatalf("reopen lookup: ok=%v err=%v entry=%+v", ok, err, got)
	}
}

// TestSizeMismatchRejected: an existing region with a different MaxIfindex
// must be rejected, not silently reinterpreted.
func TestSizeMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings")
	r1, err := Open(Config{Backend: BackendShm, Path: path, MaxIfindex: 128})
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	_ = r1.Close()
	if _, err := Open(Config{Backend: BackendShm, Path: path, MaxIfindex: 256}); err == nil {
		t.Fatalf("opening mismatched region should fail")
	}
}

// TestReopenDefaultConfigVsCustomRegion: a region created with an explicit
// small MaxIfindex must be rejected even by a config that resolves to the
// DEFAULT MaxIfindex (zero value) — the pre-check that used to exempt the
// default would have mapped a 16 MiB window over a smaller region and let
// slot() slice past the mmap.
func TestReopenDefaultConfigVsCustomRegion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings")
	r1, err := Open(Config{Backend: BackendShm, Path: path, MaxIfindex: 128})
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	_ = r1.Close()
	// Config{} resolves MaxIfindex 0 → DefaultMaxIfindex; must still fail.
	if _, err := Open(Config{Backend: BackendShm, Path: path}); err == nil {
		t.Fatalf("default-config open of a custom-sized region should fail")
	}
}

// TestMaxIfindexCap: absurd slot counts are refused outright (config typo
// guard), before any allocation is attempted.
func TestMaxIfindexCap(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(Config{Backend: BackendShm, Path: filepath.Join(dir, "b"), MaxIfindex: maxIfindexCap + 1}); err == nil {
		t.Fatalf("MaxIfindex above the cap must be rejected")
	}
}

func TestResolveIfindexUnknown(t *testing.T) {
	if _, err := ResolveIfindex("no-such-tap-xyz"); err == nil {
		t.Fatalf("ResolveIfindex on missing interface should fail")
	}
}

// TestBPFCarrier exercises the bpf backend end-to-end against the real
// kernel: create BPF_F_MMAPABLE array, pin to bpffs, mmap, publish, read
// back, and re-open the pinned region (restart semantics). Skips when the
// environment lacks support (no CAP_BPF, kernel < 5.5, bpffs unmounted).
func TestBPFCarrier(t *testing.T) {
	const pinPath = "/sys/fs/bpf/sandswap-bindreg-test"
	_ = os.Remove(pinPath) // clear a stale pin from a previous run/iteration
	t.Cleanup(func() { _ = os.Remove(pinPath) })

	r1, err := Open(Config{Backend: BackendBPF, Path: pinPath, MaxIfindex: 4096})
	if err != nil {
		t.Skipf("bpf backend unavailable here: %v", err)
	}
	e := Entry{State: StateMounted, MountEpoch: 1, AgentID: "agent-bpf", SandfsID: "sfs-bpf", VMID: "vm-bpf"}
	if err := r1.Publish(2, e); err != nil {
		t.Fatalf("bpf Publish: %v", err)
	}
	got, ok, err := r1.Lookup(2)
	if err != nil || !ok || got != e {
		t.Fatalf("bpf roundtrip: ok=%v err=%v entry=%+v", ok, err, got)
	}
	if err := r1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open: the pinned map persists (sandlot restart re-attaches).
	r2, err := Open(Config{Backend: BackendBPF, Path: pinPath, MaxIfindex: 4096})
	if err != nil {
		t.Fatalf("re-open pinned region: %v", err)
	}
	defer r2.Close()
	got, ok, err = r2.Lookup(2)
	if err != nil || !ok || got != e {
		t.Fatalf("re-open roundtrip: ok=%v err=%v entry=%+v", ok, err, got)
	}

	// MaxIfindex mismatch on re-open must be rejected (format drift guard).
	if _, err := Open(Config{Backend: BackendBPF, Path: pinPath, MaxIfindex: 8192}); err == nil {
		t.Fatalf("mismatched MaxIfindex re-open should fail")
	}
}

// TestBackendsIdenticalLayout proves the two carriers are byte-identical for
// readers: same publish on both must decode identically.
func TestBackendsIdenticalLayout(t *testing.T) {
	const pinPath = "/sys/fs/bpf/sandswap-bindreg-test-parity"
	_ = os.Remove(pinPath) // clear a stale pin from a previous run/iteration
	shm := openTestShm(t, Config{})
	bpf, err := Open(Config{Backend: BackendBPF, Path: pinPath, MaxIfindex: 4096})
	if err != nil {
		t.Skipf("bpf backend unavailable here: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove("/sys/fs/bpf/sandswap-bindreg-test-parity"); _ = bpf.Close() })

	e := Entry{State: StateMounted, MountEpoch: 7, AgentID: "a", SandfsID: "s", VMID: "v"}
	if err := shm.Publish(9, e); err != nil {
		t.Fatalf("shm Publish: %v", err)
	}
	if err := bpf.Publish(9, e); err != nil {
		t.Fatalf("bpf Publish: %v", err)
	}
	shmRaw := shm.data[entryOffset(9):entryOffset(10)]
	bpfRaw := bpf.data[entryOffset(9):entryOffset(10)]
	for i := 0; i < int(EntrySize); i++ {
		if shmRaw[i] != bpfRaw[i] {
			t.Fatalf("carriers diverge at byte %d: shm=%02x bpf=%02x", i, shmRaw[i], bpfRaw[i])
		}
	}
}

// ── Write-integrity: the writer must own the region file, exclusively ──────
//
// The shm default path lives in a world-writable sticky directory (/dev/shm);
// these tests pin the open-time defenses against the pre-creation squatting
// pattern (a local user planting the region file before sandlot's first start
// would otherwise own every published identity).

// TestShmRejectsGroupOrWorldWritable: a region file writable by anyone but
// its owner is refused — the write set must be exactly the owner.
func TestShmRejectsGroupOrWorldWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings")
	r, err := Open(Config{Backend: BackendShm, Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = r.Close()
	for _, mode := range []os.FileMode{0o666, 0o664, 0o646} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod %04o: %v", mode, err)
		}
		if _, err := Open(Config{Backend: BackendShm, Path: path}); err == nil {
			t.Fatalf("open of %04o region must fail", mode)
		}
	}
}

// TestShmRejectsSymlink: a symlink planted at the region path must fail
// loudly (O_NOFOLLOW), for writers and readers alike.
func TestShmRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings")
	target := filepath.Join(dir, "elsewhere")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := Open(Config{Backend: BackendShm, Path: path}); err == nil {
		t.Fatalf("writer open of symlinked region path must fail")
	}
	if _, err := Open(Config{Backend: BackendShm, Path: path, ReadOnly: true}); err == nil {
		t.Fatalf("reader open of symlinked region path must fail")
	}
}

// TestShmFchmodNormalizesUmask: creation must land on 0640 regardless of the
// process umask — a restrictive umask silently stripping the group's read bit
// would lock vendor enforcers out.
func TestShmFchmodNormalizesUmask(t *testing.T) {
	old := unix.Umask(0o077)
	defer unix.Umask(old)
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings")
	r, err := Open(Config{Backend: BackendShm, Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := st.Mode().Perm(); got != shmFileMode {
		t.Fatalf("region mode = %04o, want %04o (umask must not strip the group read bit)", got, shmFileMode)
	}
}

// TestShmRejectsForeignOwner: a region file owned by ANOTHER uid is refused
// even by root — the baremetal deployment runs sandlot as root, so the
// squatting file must be rejected on ownership, not permissions. Root-gated
// (needs CAP_CHOWN to plant the foreign-owned file).
func TestShmRejectsForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown the planted file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings")
	if err := os.WriteFile(path, make([]byte, regionBytes(1024)), 0o640); err != nil {
		t.Fatalf("plant file: %v", err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Skipf("cannot chown to nobody: %v", err)
	}
	if _, err := Open(Config{Backend: BackendShm, Path: path, MaxIfindex: 1024}); err == nil {
		t.Fatalf("open of foreign-owned region must fail")
	}
	// The remediation (remove the squatted file) restores a working open.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	r, err := Open(Config{Backend: BackendShm, Path: path, MaxIfindex: 1024})
	if err != nil {
		t.Fatalf("open after remediation: %v", err)
	}
	_ = r.Close()
}

// TestShmReadOnly: readers attach without creating and without the writer
// checks; Publish on a read-only mapping must error, never fault.
func TestShmReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings")
	cfg := Config{Backend: BackendShm, Path: path}
	w, err := Open(cfg)
	if err != nil {
		t.Fatalf("writer Open: %v", err)
	}
	e := Entry{State: StateMounted, MountEpoch: 5, AgentID: "a", SandfsID: "s", VMID: "v"}
	if err := w.Publish(3, e); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	_ = w.Close()

	ro, err := Open(Config{Backend: BackendShm, Path: path, ReadOnly: true})
	if err != nil {
		t.Fatalf("read-only Open: %v", err)
	}
	defer func() { _ = ro.Close() }()
	got, ok, err := ro.Lookup(3)
	if err != nil || !ok || got != e {
		t.Fatalf("read-only Lookup: ok=%v err=%v entry=%+v", ok, err, got)
	}
	if err := ro.Publish(4, e); err == nil {
		t.Fatalf("Publish on read-only region must error")
	}
	if err := ro.Revoke(3); err == nil {
		t.Fatalf("Revoke on read-only region must error")
	}
	if err := ro.Unregister(3); err == nil {
		t.Fatalf("Unregister on read-only region must error")
	}
}

// TestShmReadOnlyAbsentRegion: a reader never creates — a missing region is
// an error, not a fresh empty one.
func TestShmReadOnlyAbsentRegion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings")
	if _, err := Open(Config{Backend: BackendShm, Path: path, ReadOnly: true}); err == nil {
		t.Fatalf("read-only open of absent region must fail")
	}
}

// TestBPFReadOnlyForeignOwner: the reader of a pinned region is never the
// writer identity (an ops tool runs as root, a vendor enforcer as its own
// uid, while the pin belongs to the sandlot), so a read-only open must not
// apply the writer's owner-equality gate — reads are bpffs DAC's job, and
// the header verification rejects structurally foreign maps. The WRITER open
// of the same foreign-owned pin must still refuse (write-integrity gate).
// Root-gated: needs bpffs + CAP to create/chown.
func TestBPFReadOnlyForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create + chown the pinned region")
	}
	const pinPath = "/sys/fs/bpf/sandswap-bindreg-foreign-owner-test"
	_ = os.Remove(pinPath)
	t.Cleanup(func() { _ = os.Remove(pinPath) })

	w, err := Open(Config{Backend: BackendBPF, Path: pinPath, MaxIfindex: 4096})
	if err != nil {
		t.Skipf("bpf backend unavailable here: %v", err)
	}
	e := Entry{State: StateMounted, MountEpoch: 7, AgentID: "agent-ro", SandfsID: "sfs-ro", VMID: "vm-ro"}
	if err := w.Publish(3, e); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Hand the pin to a foreign identity, readable by others (the deployed
	// shape: the sandlot identity owns it, ops/enforcers only read).
	if err := os.Chown(pinPath, 65534, 65534); err != nil {
		t.Skipf("cannot chown bpffs pin: %v", err)
	}
	if err := os.Chmod(pinPath, 0o644); err != nil {
		t.Fatalf("chmod pin: %v", err)
	}

	// Reader (root ≠ 65534): attaches and sees the writer's entry.
	ro, err := Open(Config{Backend: BackendBPF, Path: pinPath, MaxIfindex: 4096, ReadOnly: true})
	if err != nil {
		t.Fatalf("read-only open of foreign-owned pin must succeed (reads are DAC's job): %v", err)
	}
	defer ro.Close()
	got, ok, err := ro.Lookup(3)
	if err != nil || !ok || got != e {
		t.Fatalf("reader lookup: ok=%v err=%v entry=%+v", ok, err, got)
	}

	// Writer (root ≠ 65534): the ownership gate still refuses.
	if _, err := Open(Config{Backend: BackendBPF, Path: pinPath, MaxIfindex: 4096}); err == nil {
		t.Fatalf("writer open of foreign-owned pin must fail (write-integrity gate)")
	}
}
