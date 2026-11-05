package config

import (
	"bytes"
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzStrictDecodeValidate replays arbitrary bytes through the sandlot
// config's strict YAML decode (KnownFields(true)) AND the full Validate()
// (the startup + hot-reload gate for CID ranges, stream caps, uint wrap
// guards, recycle sentinels). Config files are operator-owned input; a
// hostile or half-written file must error — never panic, hang, or slip a
// wrap-prone value past Validate.
//
// Run: go test ./config -run '^$' -fuzz FuzzStrictDecodeValidate -fuzztime 60s
func FuzzStrictDecodeValidate(f *testing.F) {
	f.Add([]byte("kernel: /boot/vmlinuz\nvolumes_dir: /srv/volumes")) // valid
	f.Add([]byte("default_vcpus: 2\ndefault_memory_mb: 256"))
	f.Add([]byte("default_vcpus: -1"))                     // negative → uint wrap guard
	f.Add([]byte("default_memory_mb: -64"))                // negative MB → MinBootMemoryMB guard
	f.Add([]byte("default_vcpus: 9999999999999999999999")) // int64 overflow
	f.Add([]byte("unknown_dead_key: 1"))                   // strict rejection
	f.Add([]byte("kernel: [x]"))                           // type abuse
	f.Add([]byte("kernel: a\nkernel: b"))                  // duplicate key
	f.Add([]byte("a: &a [*a]"))                            // alias cycle
	f.Add([]byte("stream:\n  initial_window: 0"))          // hostile nested value

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := Defaults()
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return // rejected at decode — fine
		}
		// Decoded: Validate must run to completion and return errors
		// rather than panic on any field combination.
		_ = cfg.Validate()
	})
}
