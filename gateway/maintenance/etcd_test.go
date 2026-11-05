package maintenance

import (
	"context"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestParseKey(t *testing.T) {
	if on, reason := ParseKey(false, "ignored"); on || reason != "" {
		t.Errorf("absent key must mean serving, got on=%v reason=%q", on, reason)
	}
	on, reason := ParseKey(true, "volume seed rotation")
	if !on || reason != "volume seed rotation" {
		t.Errorf("present key must refuse with its reason, got on=%v reason=%q", on, reason)
	}
	if on, _ := ParseKey(true, ""); !on {
		t.Error("an empty reason must still refuse")
	}
}

// TestWatchKeyForFailsClosedUntilReadable pins the initial-read contract: a
// gateway that cannot read the switch state must refuse (503) rather than
// assume "off" and serve through an already-open maintenance/rotation window.
func TestWatchKeyForFailsClosedUntilReadable(t *testing.T) {
	old := switchReadTimeout
	switchReadTimeout = 50 * time.Millisecond
	t.Cleanup(func() { switchReadTimeout = old })

	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{"http://127.0.0.1:1"}})
	if err != nil {
		t.Fatalf("create etcd client: %v", err)
	}
	defer cli.Close()

	var sw Switch
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchKeyFor(ctx, cli, nil, &sw, Key, "test")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sw.On() {
			if _, reason := sw.Snapshot(); !strings.Contains(reason, "state unknown") {
				t.Fatalf("fail-closed reason = %q, want it to name the unknown state", reason)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("switch did not fail closed while the initial state read was failing")
}
