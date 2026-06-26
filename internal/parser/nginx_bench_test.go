package parser_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// BenchmarkNginxParser_Combined measures combined-format parser throughput.
// Target: ≥ 50 000 iterations/second (≥ 50k lines/sec).
func BenchmarkNginxParser_Combined(b *testing.B) {
	p := parser.NewNginxParser(slog.Default(), parser.NginxConfig{})
	line := sdk.RawLine{
		Source: "file:/var/log/nginx/access.log",
		Line:   []byte(`192.0.2.1 - alice [15/Jan/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"`),
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

// BenchmarkNginxParser_JSON measures JSON-format parser throughput.
func BenchmarkNginxParser_JSON(b *testing.B) {
	p := parser.NewNginxParser(slog.Default(), parser.NginxConfig{})
	line := sdk.RawLine{
		Source: "journald:nginx",
		Line:   []byte(`{"remote_addr":"192.0.2.1","request":"GET /index.html HTTP/1.1","status":"200","body_bytes_sent":"1234","http_user_agent":"Mozilla/5.0","http_x_forwarded_for":"-"}`),
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
