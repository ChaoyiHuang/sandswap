package config

import (
	"bytes"
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzStrictDecode replays arbitrary bytes through the gateway config's
// strict YAML decode (KnownFields(true)) plus every domain validator. The
// config file is operator-owned input on a long-lived host; a corrupt,
// hostile, or half-written file must produce an error — never a panic, a
// hang, or a validator misfire. A dead key must stay a hard error (strict
// decode is the dns/config.go lesson made permanent).
//
// Run: go test ./config -run '^$' -fuzz FuzzStrictDecode -fuzztime 60s
func FuzzStrictDecode(f *testing.F) {
	f.Add([]byte("addr: 127.0.0.1:3000")) // valid
	f.Add([]byte("tls_cert: /etc/certs/gw.crt\nsend_buffer_size: 2000"))
	f.Add([]byte("addr: [a, b]"))                             // sequence into string
	f.Add([]byte("addr: 3000"))                               // scalar type abuse
	f.Add([]byte("unknown_key_dead: 1"))                      // strict rejection
	f.Add([]byte("addr: x\naddr: y"))                         // duplicate key
	f.Add([]byte("a: &a [*a]"))                               // alias cycle
	f.Add([]byte("&a {addr: *a}"))                            // anchor abuse
	f.Add([]byte("addr: !!binary |\n  AAAA"))                 // unexpected tag
	f.Add([]byte("addr: \"\\x8b\""))                          // escaped bytes in scalar
	f.Add([]byte("send_buffer_size: -1"))                     // hostile value → validator
	f.Add([]byte("send_buffer_size: 9999999999999999999999")) // overflows int

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := Defaults()
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return // rejected at decode — fine
		}
		// Decoded: every validator must run to completion on hostile
		// values and return errors rather than panic.
		_ = cfg.ValidateLease()
		_ = cfg.ValidateExec()
		_ = cfg.ValidateStreamConcurrency()
		_ = cfg.ValidateStaleness()
		_ = cfg.ValidateOwnership()
		_ = cfg.ValidateShed()
	})
}
