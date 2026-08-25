package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// Regression tests for issue #302: the ban table and the --by-country /
// --by-asn groupings printed Reason, Country, and ASN unsanitized, while
// the --audit path in the same file, report.go, and watch already stripped
// terminal escapes from the identical fields (§1: log lines are untrusted
// data; GeoIP values are external data).

// hostileBanEntries carries ANSI escapes, CR/LF, and C1 bytes in every
// untrusted field. The IP is an RFC 5737 documentation address.
func hostileBanEntries() []daemon.BanEntry {
	return []daemon.BanEntry{{
		IP:      "203.0.113.7",
		Strike:  2,
		TTL:     "1h",
		Country: "B\x1b[31mR",
		ASN:     "AS\x1b]0;pwned\x07123",
		Reason:  "rule/ssh: user \x1b[2Jroot\r\nfake-log-line \x9b31m",
	}}
}

// assertClean fails if rendered output still carries any of the injection
// vectors sanitizeField exists to strip.
func assertClean(t *testing.T, out string) {
	t.Helper()
	for _, bad := range []string{"\x1b", "\r", "\x9b", "\x07", "fake-log-line\n"} {
		if strings.Contains(out, bad) {
			t.Errorf("output still contains %q:\n%q", bad, out)
		}
	}
}

func newBufCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	return cmd, &buf
}

func TestPrintBanTable_SanitizesUntrustedColumns(t *testing.T) {
	t.Parallel()
	cmd, buf := newBufCmd()
	if err := printBanTable(cmd, hostileBanEntries()); err != nil {
		t.Fatalf("printBanTable: %v", err)
	}
	out := buf.String()
	assertClean(t, out)
	for _, want := range []string{"203.0.113.7", "BR", "AS123", "user root"} {
		if !strings.Contains(out, want) {
			t.Errorf("sanitized output lost legitimate content %q:\n%q", want, out)
		}
	}
}

func TestPrintByCountry_SanitizesGroupKeyAndReason(t *testing.T) {
	t.Parallel()
	cmd, buf := newBufCmd()
	if err := printByCountry(cmd, hostileBanEntries()); err != nil {
		t.Fatalf("printByCountry: %v", err)
	}
	out := buf.String()
	assertClean(t, out)
	if !strings.Contains(out, "Country: BR") {
		t.Errorf("group header not sanitized/kept: %q", out)
	}
}

func TestPrintByASN_SanitizesGroupKeyAndReason(t *testing.T) {
	t.Parallel()
	cmd, buf := newBufCmd()
	if err := printByASN(cmd, hostileBanEntries()); err != nil {
		t.Fatalf("printByASN: %v", err)
	}
	out := buf.String()
	assertClean(t, out)
	if !strings.Contains(out, "ASN: AS123") {
		t.Errorf("group header not sanitized/kept: %q", out)
	}
}
