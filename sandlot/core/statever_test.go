package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStateFormatVersionRoundtrip pins the v1 format: a state written by this
// binary carries version=1 and loads back; a FUTURE version (>1) is refused as
// corrupt (no-state → re-adopt cleans + replaces — the safe direction).
func TestStateFormatVersionRoundtrip(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vm-v1")
	os.MkdirAll(dir, 0755)
	st := persistedState{
		Version:    stateFormatVersion,
		VMID:       "vm-v1",
		CID:        5,
		PID:        42,
		SandboxDir: dir,
		APISocket:  filepath.Join(dir, "sandvmm.sock"),
	}
	if err := writeState(st, root); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	data, _ := os.ReadFile(testStatePath(dir))
	if !strings.Contains(string(data), `"version":1`) {
		t.Errorf("state.json missing version:1: %s", data[:120])
	}
	got, err := loadState(dir)
	if err != nil || got == nil || got.Version != 1 || got.VMID != "vm-v1" {
		t.Fatalf("roundtrip: %+v err=%v", got, err)
	}
	// Future format refused (treated as corrupt → callers clean+replace).
	future := `{"version":2,"vm_id":"vm-future","cid":9,"pid":9,"sandbox_dir":"` + dir + `","api_socket":"x"}`
	os.WriteFile(testStatePath(dir), []byte(future), 0600)
	if _, err := loadState(dir); err == nil {
		t.Fatal("future format version must be refused, got nil error")
	}
}
