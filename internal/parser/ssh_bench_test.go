package parser_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// BenchmarkSSHParser measures parser throughput.
// Target: ≥ 50 000 iterations/second (≥ 50k lines/sec).
func BenchmarkSSHParser(b *testing.B) {
	p := parser.NewSSHParser(slog.Default())
	line := sdk.RawLine{
		Source: "file:/var/log/auth.log",
		Line:   []byte("Jan 15 10:00:01 webserver sshd[12345]: Failed password for root from 192.0.2.1 port 40122 ssh2"),
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
