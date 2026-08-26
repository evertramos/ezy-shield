package parser_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// BenchmarkPostfixParser_AuthFail measures throughput on the hottest
// signature (SASL failure). Target: same order as the other line parsers
// (≥ 50k lines/sec).
func BenchmarkPostfixParser_AuthFail(b *testing.B) {
	p := parser.NewPostfixParser(slog.New(slog.NewTextHandler(io.Discard, nil)))
	line := sdk.RawLine{
		Source: "journald:postfix",
		Line:   []byte("Aug 25 12:00:02 mail postfix/smtpd[3121]: warning: unknown[203.0.113.50]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"),
		At:     time.Now(),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Parse(line); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPostfixParser_NoMatch measures the skip path — most mail.log
// lines (connect/disconnect/qmgr) are not abuse signatures, so the
// non-matching cost dominates real workloads.
func BenchmarkPostfixParser_NoMatch(b *testing.B) {
	p := parser.NewPostfixParser(slog.New(slog.NewTextHandler(io.Discard, nil)))
	line := sdk.RawLine{
		Source: "journald:postfix",
		Line:   []byte("Aug 25 12:00:15 mail postfix/smtpd[3121]: disconnect from unknown[203.0.113.50] ehlo=1 auth=0/3 quit=1 commands=2/5"),
		At:     time.Now(),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Parse(line); err != nil {
			b.Fatal(err)
		}
	}
}
