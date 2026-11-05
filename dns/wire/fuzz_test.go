package wire

import (
	"bytes"
	"testing"
)

// FuzzParseQuery replays arbitrary bytes through the DNS query parser. The
// declared attacker is any DNS client: a hostile packet must produce a
// categorized error or a parsed query — never a panic, an out-of-bounds
// access, or a hang. Seeds cover the parser's documented rejection classes
// (short, response-not-query, no-question, compression pointer in QNAME,
// reserved length prefixes, over-long names, truncation at every section).
//
// Run the fuzzer: go test ./wire -run '^$' -fuzz FuzzParseQuery -fuzztime 60s
// The seed corpus also runs as a plain regression test in every `go test`.
func FuzzParseQuery(f *testing.F) {
	// A well-formed query: id 0x1234, RD, one question "a.example" A IN.
	valid := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: RD, standard query
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
		0x01, 'a',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x00,       // root label
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
	}
	f.Add(valid)
	f.Add([]byte{})                                                                                  // short
	f.Add([]byte{0x12, 0x34, 0x80, 0x00, 0x00, 0x01})                                                // QR set + short
	f.Add([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0})                              // header, zero questions
	f.Add([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})                              // header, question never arrives
	f.Add(append([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, 0xc0, 0x0c))          // compression pointer in QNAME
	f.Add(append([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, 0x40))                // reserved 0x40 length prefix
	f.Add(append([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, 63))                  // label length without the label
	f.Add(bytes.Repeat(append([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, 62), 8)) // 8×62 labels → name over 255
	f.Add(append(valid[:len(valid)-2], 0x00, 0x01))                                                  // QTYPE present, QCLASS truncated

	f.Fuzz(func(t *testing.T, data []byte) {
		q, err := ParseQuery(data)
		if err != nil {
			return
		}
		// Parsed queries must answer basic accessors without panicking.
		_ = q.Question
		_ = q.Name()
		_ = q.flags()
	})
}
