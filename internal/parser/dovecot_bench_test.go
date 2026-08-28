// SPDX-License-Identifier: AGPL-3.0-only

package parser_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// BenchmarkDovecotParser_AuthFail measures throughput on the hottest
// signature. Target: same order as the other line parsers (≥ 50k lines/sec).
func BenchmarkDovecotParser_AuthFail(b *testing.B) {
	p := parser.NewDovecotParser(slog.New(slog.NewTextHandler(io.Discard, nil)))
	line := sdk.RawLine{
		Source: "journald:dovecot",
		Line:   []byte("Aug 25 13:00:02 mail dovecot: imap-login: Aborted login (auth failed, 3 attempts in 6 secs): user=<admin>, method=PLAIN, rip=203.0.113.70, lip=198.51.100.1, TLS, session=<x1>"),
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

// BenchmarkDovecotParser_NoMatch measures the skip path — successful logins
// and service chatter dominate real mail logs.
func BenchmarkDovecotParser_NoMatch(b *testing.B) {
	p := parser.NewDovecotParser(slog.New(slog.NewTextHandler(io.Discard, nil)))
	line := sdk.RawLine{
		Source: "journald:dovecot",
		Line:   []byte("Aug 25 13:00:01 mail dovecot: imap-login: Login: user=<evert>, method=PLAIN, rip=198.51.100.9, lip=198.51.100.1, mpid=1234, TLS, session=<ok1>"),
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
