package config

// Validation tests for the siem forwarding section (issue #203).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadSIEMYAML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "data_dir: /var/lib/ezyshield\nsiem:\n" + body
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return LoadConfig(path)
}

func TestSIEMConfig_Valid(t *testing.T) {
	cfg, err := loadSIEMYAML(t, `
  - name: wazuh
    address: tls://siem.example:6514
    format: rfc5424
    ca_file: /etc/ezyshield/wazuh-ca.pem
    events: [ban, unban, dry_ban]
  - name: local-file
    address: file:///var/log/ezyshield-forward.log
  - name: legacy-udp
    address: udp://10.0.0.5:514
    allow_insecure_transport: true
    queue_size: 2048
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.SIEM) != 3 {
		t.Fatalf("siem sinks = %d, want 3", len(cfg.SIEM))
	}
	if cfg.SIEM[0].Format != "rfc5424" || len(cfg.SIEM[0].Events) != 3 {
		t.Errorf("first sink = %+v", cfg.SIEM[0])
	}
}

func TestSIEMConfig_Invalid(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "plaintext tcp without opt-in",
			body: `
  - name: bad
    address: tcp://siem.example:601
`,
			wantErr: "allow_insecure_transport",
		},
		{
			name: "plaintext udp without opt-in",
			body: `
  - name: bad
    address: udp://siem.example:514
`,
			wantErr: "unencrypted",
		},
		{
			name: "unknown scheme",
			body: `
  - name: bad
    address: http://siem.example
`,
			wantErr: "unsupported scheme",
		},
		{
			name: "bad format",
			body: `
  - name: bad
    address: tls://siem.example:6514
    format: xml
`,
			wantErr: "format",
		},
		{
			name: "ca_file on non-tls",
			body: `
  - name: bad
    address: file:///var/log/fwd.log
    ca_file: /etc/ca.pem
`,
			wantErr: "ca_file",
		},
		{
			name: "missing name",
			body: `
  - address: tls://siem.example:6514
`,
			wantErr: "'name' is required",
		},
		{
			name: "duplicate name",
			body: `
  - name: same
    address: tls://a.example:6514
  - name: same
    address: tls://b.example:6514
`,
			wantErr: "duplicate",
		},
		{
			name: "queue size out of range",
			body: `
  - name: bad
    address: tls://siem.example:6514
    queue_size: 1000000
`,
			wantErr: "queue_size",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadSIEMYAML(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
