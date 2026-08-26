package config

// Validation tests for the enforce.bunny section (issue #198).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadBunnyYAML(t *testing.T, enforceBody string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "data_dir: /var/lib/ezyshield\nenforce:\n" + enforceBody
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return LoadConfig(path)
}

func TestBunnyConfig_Valid(t *testing.T) {
	cfg, err := loadBunnyYAML(t, `
  bunny:
    api_key: env:BUNNY_API_KEY
    pull_zones:
      - 101
      - 202
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	b := cfg.Enforce.Bunny
	if b == nil {
		t.Fatal("enforce.bunny not parsed")
	}
	if len(b.PullZones) != 2 || b.PullZones[0] != 101 || b.PullZones[1] != 202 {
		t.Errorf("pull_zones = %v", b.PullZones)
	}
	if b.APIKey != SecretRef("env:BUNNY_API_KEY") {
		t.Errorf("api_key = %q", b.APIKey)
	}
}

func TestBunnyConfig_InlineSecretRejected(t *testing.T) {
	_, err := loadBunnyYAML(t, `
  bunny:
    api_key: literal-key-pasted-by-mistake
    pull_zones: [101]
`)
	if err == nil {
		t.Fatal("inline api_key must be rejected at load time")
	}
	if !strings.Contains(err.Error(), "env:VARNAME") {
		t.Errorf("error should point at the env: requirement, got %v", err)
	}
	// The redaction rule: the pasted value must not be echoed back.
	if strings.Contains(err.Error(), "literal-key-pasted-by-mistake") {
		t.Errorf("inline secret echoed into the error: %v", err)
	}
}

func TestBunnyConfig_Invalid(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "missing api_key",
			body: `
  bunny:
    pull_zones: [101]
`,
			wantErr: "'api_key' is required",
		},
		{
			name: "missing zones",
			body: `
  bunny:
    api_key: env:BUNNY_API_KEY
`,
			wantErr: "pull_zones",
		},
		{
			name: "non-positive zone",
			body: `
  bunny:
    api_key: env:BUNNY_API_KEY
    pull_zones: [0]
`,
			wantErr: "positive",
		},
		{
			name: "duplicate zone",
			body: `
  bunny:
    api_key: env:BUNNY_API_KEY
    pull_zones: [101, 101]
`,
			wantErr: "duplicate",
		},
		{
			name: "bad name",
			body: `
  bunny:
    name: "no spaces!"
    api_key: env:BUNNY_API_KEY
    pull_zones: [101]
`,
			wantErr: "'name'",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadBunnyYAML(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
