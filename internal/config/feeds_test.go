package config

// Validation tests for the reputation-feeds section (issue #194).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadFeedsYAML(t *testing.T, feedsBody string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "data_dir: /var/lib/ezyshield\nfeeds:\n" + feedsBody
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return LoadConfig(path)
}

func TestFeedsConfig_Valid(t *testing.T) {
	cfg, err := loadFeedsYAML(t, `
  - name: spamhaus-drop
    url: https://www.spamhaus.org/drop/drop.txt
    format: cidr
    refresh_interval: 12h
  - name: abuse-list
    url: https://feeds.example/plain.txt
    format: abuseipdb
    refresh_interval: 24h
    max_entries: 200000
    timeout: 60s
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Feeds) != 2 {
		t.Fatalf("feeds = %d, want 2", len(cfg.Feeds))
	}
	f := cfg.Feeds[0]
	if f.Name != "spamhaus-drop" || f.Format != "cidr" ||
		f.RefreshInterval.AsDuration() != 12*time.Hour {
		t.Errorf("first feed = %+v", f)
	}
}

func TestFeedsConfig_Invalid(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "http rejected",
			body: `
  - name: bad
    url: http://feeds.example/list.txt
    format: plain
    refresh_interval: 12h
`,
			wantErr: "https://",
		},
		{
			name: "zero interval",
			body: `
  - name: bad
    url: https://feeds.example/list.txt
    format: plain
`,
			wantErr: "refresh_interval",
		},
		{
			name: "interval below floor",
			body: `
  - name: bad
    url: https://feeds.example/list.txt
    format: plain
    refresh_interval: 5m
`,
			wantErr: "politeness floor",
		},
		{
			name: "absurd max_entries",
			body: `
  - name: bad
    url: https://feeds.example/list.txt
    format: plain
    refresh_interval: 12h
    max_entries: 10000000
`,
			wantErr: "hard cap",
		},
		{
			name: "unknown format",
			body: `
  - name: bad
    url: https://feeds.example/list.txt
    format: xml
    refresh_interval: 12h
`,
			wantErr: "format",
		},
		{
			name: "missing name",
			body: `
  - url: https://feeds.example/list.txt
    format: plain
    refresh_interval: 12h
`,
			wantErr: "'name' is required",
		},
		{
			name: "duplicate name",
			body: `
  - name: same
    url: https://feeds.example/a.txt
    format: plain
    refresh_interval: 12h
  - name: same
    url: https://feeds.example/b.txt
    format: plain
    refresh_interval: 12h
`,
			wantErr: "duplicate",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadFeedsYAML(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
