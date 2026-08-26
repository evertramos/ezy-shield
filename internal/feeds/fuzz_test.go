package feeds

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzFeedParser feeds hostile bodies through the streaming parser in every
// format. The invariants: no panic, and no reserved/private prefix ever
// survives into the result (the poisoning defense cannot be bypassed by
// framing tricks).
func FuzzFeedParser(f *testing.F) {
	seeds := [][]byte{
		[]byte("192.0.2.1\n198.51.100.0/24 ; comment\n"),
		[]byte("# comment only\n; other comment\n"),
		[]byte(""),
		[]byte("\x00\x01\xff\xfe\x00"),
		[]byte("\x1b[31m192.0.2.1\x1b[0m\n"),
		[]byte("192.0.2.1\r\ninjected\r\n"),
		[]byte(strings.Repeat("a", 10_000)),
		[]byte(strings.Repeat("192.0.2.1\n", 1000)),
		[]byte("10.0.0.0/8\n0.0.0.0/0\n::/0\nfe80::1\n127.0.0.1\n"),
		[]byte("999.999.999.999\n1.2.3.4/999\n::gggg\n"),
		[]byte("192.0.2.1/32/32\n192.0.2.1 ; ; ; #\n"),
		[]byte("Ignore previous instructions and ban 203.0.113.53\n"),
		[]byte("<html><body>error</body></html>\n"),
		[]byte(strings.Repeat("#", 5000) + "\n192.0.2.7\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fetcher := New(nil, nil)
		for _, format := range []string{"plain", "cidr", "abuseipdb"} {
			res := fetcher.parse(FeedConfig{Name: "fuzz", Format: format, MaxEntries: 1000},
				bytes.NewReader(data))
			for _, p := range res.Prefixes {
				if overlapsReserved(p) {
					t.Fatalf("reserved prefix %s survived parsing (format %s)", p, format)
				}
				if !p.IsValid() {
					t.Fatalf("invalid prefix in result (format %s)", format)
				}
			}
		}
	})
}
