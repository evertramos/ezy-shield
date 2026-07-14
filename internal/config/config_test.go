package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/evertramos/ezy-shield/configs"
)

// ---- helpers ----------------------------------------------------------------

func mustLoadConfig(t *testing.T, yaml string) *Config {
	t.Helper()
	cfg, err := LoadConfigReader(strings.NewReader(yaml), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return cfg
}

func mustLoadPolicy(t *testing.T, yaml string) *Policy {
	t.Helper()
	p, err := LoadPolicyReader(strings.NewReader(yaml), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return p
}

func wantErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not contain %q", err.Error(), contains)
	}
}

// ---- LoadConfig -------------------------------------------------------------

func TestLoadConfig_ValidMinimal(t *testing.T) {
	t.Parallel()
	cfg := mustLoadConfig(t, `
data_dir: /var/lib/ezyshield
socket_path: /run/ezyshield/ezyshield.sock
`)
	if cfg.DataDir != "/var/lib/ezyshield" {
		t.Errorf("DataDir = %q, want /var/lib/ezyshield", cfg.DataDir)
	}
}

func TestLoadConfig_RulesPath(t *testing.T) {
	t.Parallel()
	cfg := mustLoadConfig(t, `
data_dir: /var/lib/ezyshield
rules_path: /etc/ezyshield/rules.yaml
`)
	if cfg.RulesPath != "/etc/ezyshield/rules.yaml" {
		t.Errorf("RulesPath = %q, want /etc/ezyshield/rules.yaml", cfg.RulesPath)
	}
}

func TestLoadConfig_RulesPathEmpty(t *testing.T) {
	t.Parallel()
	cfg := mustLoadConfig(t, "data_dir: /tmp\n")
	if cfg.RulesPath != "" {
		t.Errorf("RulesPath = %q, want empty (uses embedded defaults)", cfg.RulesPath)
	}
}

func TestLoadConfig_ValidLogLevel(t *testing.T) {
	t.Parallel()
	for _, level := range []string{"debug", "info", "warn", "error"} {
		level := level
		t.Run(level, func(t *testing.T) {
			t.Parallel()
			cfg := mustLoadConfig(t, "log:\n  level: "+level+"\n")
			if cfg.Log.Level != level {
				t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, level)
			}
		})
	}
}

func TestLoadConfig_EmptyLogLevel(t *testing.T) {
	t.Parallel()
	cfg := mustLoadConfig(t, "data_dir: /tmp\n")
	if cfg.Log.Level != "" {
		t.Errorf("expected empty log level, got %q", cfg.Log.Level)
	}
}

func TestLoadConfig_InvalidLogLevel(t *testing.T) {
	t.Parallel()
	_, err := LoadConfigReader(strings.NewReader("log:\n  level: verbose\n"), "test")
	wantErr(t, err, "log.level")
}

func TestLoadConfig_UnknownKey(t *testing.T) {
	t.Parallel()
	_, err := LoadConfigReader(strings.NewReader("unknown_field: true\n"), "test")
	if err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}
	// yaml.v3 includes "line N" in the error message
	if !strings.Contains(err.Error(), "line") && !strings.Contains(err.Error(), "field unknown_field") {
		t.Errorf("error %q should mention the unknown field", err.Error())
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	t.Parallel()
	_, err := LoadConfigReader(strings.NewReader("key: [\nbad\n"), "test")
	wantErr(t, err, "parsing test")
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	t.Parallel()
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	wantErr(t, err, "opening config")
}

func TestLoadConfig_CollectorFile(t *testing.T) {
	t.Parallel()
	yaml := `
collectors:
  - kind: file
    path: /var/log/auth.log
`
	cfg := mustLoadConfig(t, yaml)
	if len(cfg.Collectors) != 1 || cfg.Collectors[0].Path != "/var/log/auth.log" {
		t.Errorf("unexpected collectors: %+v", cfg.Collectors)
	}
}

func TestLoadConfig_CollectorJournald(t *testing.T) {
	t.Parallel()
	yaml := `
collectors:
  - kind: journald
    unit: sshd
`
	cfg := mustLoadConfig(t, yaml)
	if len(cfg.Collectors) != 1 || cfg.Collectors[0].Unit != "sshd" {
		t.Errorf("unexpected collectors: %+v", cfg.Collectors)
	}
}

func TestLoadConfig_CollectorFileMissingPath(t *testing.T) {
	t.Parallel()
	_, err := LoadConfigReader(strings.NewReader("collectors:\n  - kind: file\n"), "test")
	wantErr(t, err, "kind 'file' requires 'path'")
}

func TestLoadConfig_CollectorJournaldMissingUnit(t *testing.T) {
	t.Parallel()
	_, err := LoadConfigReader(strings.NewReader("collectors:\n  - kind: journald\n"), "test")
	wantErr(t, err, "kind 'journald' requires 'unit'")
}

func TestLoadConfig_CollectorMissingKind(t *testing.T) {
	t.Parallel()
	_, err := LoadConfigReader(strings.NewReader("collectors:\n  - path: /tmp/x\n"), "test")
	wantErr(t, err, "'kind' is required")
}

func TestLoadConfig_CollectorInvalidKind(t *testing.T) {
	t.Parallel()
	_, err := LoadConfigReader(
		strings.NewReader("collectors:\n  - kind: syslog\n    path: /tmp\n"), "test")
	wantErr(t, err, "invalid kind")
}

func TestLoadConfig_EnforceNFTables(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  nftables:
    table: inet ezyshield
    set: blocked
`
	cfg := mustLoadConfig(t, yaml)
	if cfg.Enforce == nil || cfg.Enforce.NFTables == nil {
		t.Fatal("expected Enforce.NFTables to be set")
	}
	if cfg.Enforce.NFTables.Table != "inet ezyshield" {
		t.Errorf("Table = %q", cfg.Enforce.NFTables.Table)
	}
}

func TestLoadConfig_NFTablesMissingTable(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  nftables:
    set: blocked
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "'table' is required")
}

func TestLoadConfig_NFTablesMissingSet(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  nftables:
    table: inet ezyshield
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "'set' is required")
}

// ---- Cloudflare enforcer config --------------------------------------------

func TestLoadConfig_CloudflareListsDefault(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare:
    api_token: env:CF_TOKEN
    account_id: abc123
`
	cfg := mustLoadConfig(t, yaml)
	if cfg.Enforce == nil || len(cfg.Enforce.Cloudflare) != 1 {
		t.Fatalf("expected exactly 1 Cloudflare entry, got %d", len(cfg.Enforce.Cloudflare))
	}
	cf := cfg.Enforce.Cloudflare[0]
	if cf.Mode != "" {
		t.Errorf("Mode = %q, want empty (so factory picks default 'lists')", cf.Mode)
	}
	if cf.AccountID != "abc123" {
		t.Errorf("AccountID = %q, want abc123", cf.AccountID)
	}
}

func TestLoadConfig_CloudflareListsRequiresAccountID(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare:
    api_token: env:CF_TOKEN
    mode: lists
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "'account_id' is required")
}

func TestLoadConfig_CloudflareListsRejectsInvalidListName(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare:
    api_token: env:CF_TOKEN
    mode: lists
    account_id: abc123
    list_name: bad-name!
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "list_name")
}

func TestLoadConfig_CloudflareRulesetsRequiresZoneIDs(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare:
    api_token: env:CF_TOKEN
    mode: rulesets
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "zone_ids")
}

func TestLoadConfig_CloudflareRulesetsOK(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare:
    api_token: env:CF_TOKEN
    mode: rulesets
    zone_ids:
      - zone1
    action: challenge
`
	cfg := mustLoadConfig(t, yaml)
	if len(cfg.Enforce.Cloudflare) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(cfg.Enforce.Cloudflare))
	}
	cf := cfg.Enforce.Cloudflare[0]
	if cf.Mode != "rulesets" {
		t.Errorf("Mode = %q, want rulesets", cf.Mode)
	}
	if len(cf.ZoneIDs) != 1 {
		t.Errorf("ZoneIDs length = %d, want 1", len(cf.ZoneIDs))
	}
}

// ---- Multi-account Cloudflare (issue #90) ----------------------------------

func TestLoadConfig_CloudflareArrayForm(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare:
    - name: client_a
      api_token: env:CF_TOKEN_A
      account_id: aaa111
    - name: client_b
      api_token: env:CF_TOKEN_B
      account_id: bbb222
      list_name: alt_list
`
	cfg := mustLoadConfig(t, yaml)
	if got := len(cfg.Enforce.Cloudflare); got != 2 {
		t.Fatalf("expected 2 entries, got %d", got)
	}
	if cfg.Enforce.Cloudflare[0].Name != "client_a" {
		t.Errorf("entry[0].Name = %q, want client_a", cfg.Enforce.Cloudflare[0].Name)
	}
	if cfg.Enforce.Cloudflare[1].AccountID != "bbb222" {
		t.Errorf("entry[1].AccountID = %q, want bbb222", cfg.Enforce.Cloudflare[1].AccountID)
	}
	if cfg.Enforce.Cloudflare[1].ListName != "alt_list" {
		t.Errorf("entry[1].ListName = %q, want alt_list", cfg.Enforce.Cloudflare[1].ListName)
	}
}

func TestLoadConfig_CloudflareSingleObjectStillWorks(t *testing.T) {
	t.Parallel()
	// Single-mapping form (no name required) — backward compat for existing users.
	yaml := `
enforce:
  cloudflare:
    api_token: env:CF_TOKEN
    account_id: abc123
`
	cfg := mustLoadConfig(t, yaml)
	if len(cfg.Enforce.Cloudflare) != 1 {
		t.Fatalf("single-object form should normalize to 1-element slice, got %d", len(cfg.Enforce.Cloudflare))
	}
	if cfg.Enforce.Cloudflare[0].Name != "" {
		t.Errorf("Name should default to empty for the single-object form, got %q", cfg.Enforce.Cloudflare[0].Name)
	}
}

func TestLoadConfig_CloudflareEmptyArrayRejected(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare: []
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "at least one entry is required")
}

func TestLoadConfig_CloudflareMultiRequiresName(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare:
    - api_token: env:CF_TOKEN_A
      account_id: aaa111
    - api_token: env:CF_TOKEN_B
      account_id: bbb222
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "'name' is required when more than one cloudflare account")
}

func TestLoadConfig_CloudflareDuplicateName(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare:
    - name: same
      api_token: env:CF_TOKEN_A
      account_id: aaa111
    - name: same
      api_token: env:CF_TOKEN_B
      account_id: bbb222
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "duplicate 'name'")
}

func TestLoadConfig_CloudflareInvalidName(t *testing.T) {
	t.Parallel()
	// Multi-account so Name is required; "bad name" has whitespace.
	yaml := `
enforce:
  cloudflare:
    - name: "bad name"
      api_token: env:CF_TOKEN_A
      account_id: aaa111
    - name: ok
      api_token: env:CF_TOKEN_B
      account_id: bbb222
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "must match [A-Za-z0-9_-]+")
}

func TestLoadConfig_CloudflareMultiPerEntryValidationStillRuns(t *testing.T) {
	t.Parallel()
	// Second entry omits account_id (required for default mode "lists").
	yaml := `
enforce:
  cloudflare:
    - name: ok
      api_token: env:CF_TOKEN_A
      account_id: aaa111
    - name: broken
      api_token: env:CF_TOKEN_B
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "'account_id' is required")
}

func TestLoadConfig_CloudflareScalarRejected(t *testing.T) {
	t.Parallel()
	// A bare scalar is neither a mapping nor a sequence — must be rejected.
	yaml := `
enforce:
  cloudflare: bogus
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "must be a mapping or a sequence")
}

func TestLoadConfig_CloudflareInvalidMode(t *testing.T) {
	t.Parallel()
	yaml := `
enforce:
  cloudflare:
    api_token: env:CF_TOKEN
    mode: bogus
    account_id: abc123
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "'mode' must be lists|rulesets")
}

func TestLoadConfig_AIWithSecretRef(t *testing.T) {
	t.Parallel()
	yaml := `
ai:
  provider: anthropic
  api_key: "env:ANTHROPIC_API_KEY"
  ambiguous_band: [30, 75]
  token_budget_daily: 500000
`
	cfg := mustLoadConfig(t, yaml)
	if cfg.AI == nil {
		t.Fatal("expected AI config to be set")
	}
	if cfg.AI.APIKey != "env:ANTHROPIC_API_KEY" {
		t.Errorf("APIKey = %q, want env:ANTHROPIC_API_KEY", cfg.AI.APIKey)
	}
}

func TestLoadConfig_AIInlineSecretRejected(t *testing.T) {
	t.Parallel()
	yaml := `
ai:
  provider: anthropic
  api_key: "sk-actualSecretKey"
`
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "env:VARNAME")
}

func TestLoadConfig_FromFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/config.yaml"
	//nolint:gosec // test file
	if err := os.WriteFile(path, []byte("data_dir: /tmp\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DataDir != "/tmp" {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
}

// ---- LoadPolicy -------------------------------------------------------------

func TestLoadPolicy_ValidFull(t *testing.T) {
	t.Parallel()
	yaml := `
armed: true
ban_threshold: 80
observe_threshold: 50
max_bans_per_minute: 10
strikes:
  - ttl: 5m
  - ttl: 1h
  - ttl: 0
allowlist:
  - 192.168.1.0/24
  - 10.0.0.1
admin_cidrs:
  - 10.0.0.0/8
`
	p := mustLoadPolicy(t, yaml)
	if !p.Armed {
		t.Error("expected Armed=true")
	}
	if p.BanThreshold != 80 {
		t.Errorf("BanThreshold = %d", p.BanThreshold)
	}
	if len(p.Strikes) != 3 {
		t.Errorf("Strikes len = %d, want 3", len(p.Strikes))
	}
	if len(p.Allowlist) != 2 {
		t.Errorf("Allowlist len = %d, want 2", len(p.Allowlist))
	}
}

func TestLoadPolicy_DefaultsApplied(t *testing.T) {
	t.Parallel()
	p := mustLoadPolicy(t, "armed: false\n")
	if p.BanThreshold != DefaultBanThreshold {
		t.Errorf("BanThreshold = %d, want %d", p.BanThreshold, DefaultBanThreshold)
	}
	// ObserveThreshold is not defaulted (0 is a valid setting).
	if p.ObserveThreshold != 0 {
		t.Errorf("ObserveThreshold = %d, want 0 (not defaulted)", p.ObserveThreshold)
	}
	if p.MaxBansPerMinute != DefaultMaxBansPerMinute {
		t.Errorf("MaxBansPerMinute = %d, want %d", p.MaxBansPerMinute, DefaultMaxBansPerMinute)
	}
	if len(p.Strikes) != len(DefaultStrikes) {
		t.Fatalf("Strikes len = %d, want %d", len(p.Strikes), len(DefaultStrikes))
	}
	for i, s := range p.Strikes {
		if s.TTL != DefaultStrikes[i].TTL {
			t.Errorf("Strikes[%d].TTL = %v, want %v", i, s.TTL, DefaultStrikes[i].TTL)
		}
	}
	if p.EscalationExemptWindow.AsDuration() != DefaultEscalationExemptWindow {
		t.Errorf("EscalationExemptWindow = %v, want %v",
			p.EscalationExemptWindow.AsDuration(), DefaultEscalationExemptWindow)
	}
}

func TestLoadPolicy_EscalationExemptWindowBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		yaml string
		want time.Duration
	}{
		{"omitted → default", "armed: false\n", DefaultEscalationExemptWindow},
		{"tightening allowed", "armed: false\nescalation_exempt_window: 1h\n", time.Hour},
		{"at ceiling kept", "armed: false\nescalation_exempt_window: 168h\n", MaxEscalationExemptWindow},
		{"above ceiling clamped", "armed: false\nescalation_exempt_window: 720h\n", MaxEscalationExemptWindow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := mustLoadPolicy(t, tc.yaml)
			if got := p.EscalationExemptWindow.AsDuration(); got != tc.want {
				t.Errorf("EscalationExemptWindow = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLoadPolicy_DefaultStrikesNotMutated(t *testing.T) {
	t.Parallel()
	p1 := mustLoadPolicy(t, "armed: false\n")
	p2 := mustLoadPolicy(t, "armed: false\n")
	p1.Strikes[0].TTL = Duration(99 * time.Hour)
	if p2.Strikes[0].TTL == Duration(99*time.Hour) {
		t.Error("mutating one Policy's Strikes affected another (shared slice)")
	}
	if DefaultStrikes[0].TTL == Duration(99*time.Hour) {
		t.Error("mutating one Policy's Strikes mutated DefaultStrikes")
	}
}

func TestLoadPolicy_UnknownKey(t *testing.T) {
	t.Parallel()
	_, err := LoadPolicyReader(strings.NewReader("armed: false\nunknown: true\n"), "test")
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	t.Parallel()
	_, err := LoadPolicyReader(strings.NewReader(": bad\n"), "test")
	wantErr(t, err, "parsing test")
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	t.Parallel()
	_, err := LoadPolicy("/nonexistent/policy.yaml")
	wantErr(t, err, "opening policy")
}

func TestLoadPolicy_BanThresholdOutOfRange(t *testing.T) {
	t.Parallel()
	cases := []struct {
		threshold int
		wantErr   bool
	}{
		{0, false}, // triggers default=70; with observe_threshold=0 (default=40) that's valid
		{101, true},
		{-1, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("threshold_%d", tc.threshold), func(t *testing.T) {
			t.Parallel()
			// Use observe_threshold: 0 — after defaults: ban=70, observe=40 (valid).
			// For the out-of-range cases, the ban_threshold error fires first.
			yaml := fmt.Sprintf("ban_threshold: %d\nobserve_threshold: 0\n", tc.threshold)
			_, err := LoadPolicyReader(strings.NewReader(yaml), "test")
			if tc.wantErr && err == nil {
				t.Errorf("expected error for ban_threshold=%d, got nil", tc.threshold)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for ban_threshold=%d: %v", tc.threshold, err)
			}
		})
	}
}

func TestLoadPolicy_ExplicitBanThresholdValid(t *testing.T) {
	t.Parallel()
	// Explicitly set both thresholds so defaults don't interfere.
	cases := []int{1, 50, 100}
	for _, bt := range cases {
		bt := bt
		t.Run(fmt.Sprintf("ban_threshold_%d", bt), func(t *testing.T) {
			t.Parallel()
			yaml := fmt.Sprintf("ban_threshold: %d\nobserve_threshold: 0\n", bt)
			_, err := LoadPolicyReader(strings.NewReader(yaml), "test")
			if err != nil {
				t.Errorf("unexpected error for ban_threshold=%d: %v", bt, err)
			}
		})
	}
}

func TestLoadPolicy_ObserveThresholdMustBeLessThanBan(t *testing.T) {
	t.Parallel()
	// observe_threshold must be < ban_threshold
	yaml := "ban_threshold: 50\nobserve_threshold: 50\n"
	_, err := LoadPolicyReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "observe_threshold")
}

func TestLoadPolicy_MaxBansPerMinuteZero(t *testing.T) {
	t.Parallel()
	// Explicitly set ban_threshold and observe_threshold to avoid defaults interfering.
	// max_bans_per_minute: 0 should be caught even after default=30 is NOT applied
	// because 0 triggers the default, so this path won't be reached that way.
	// Set it to a negative value to exercise the validator directly.
	yaml := "ban_threshold: 70\nobserve_threshold: 40\nmax_bans_per_minute: -1\n"
	_, err := LoadPolicyReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "max_bans_per_minute")
}

func TestLoadPolicy_InvalidAllowlistEntry(t *testing.T) {
	t.Parallel()
	yaml := "allowlist:\n  - not-an-ip\n"
	_, err := LoadPolicyReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "allowlist[0]")
}

func TestLoadPolicy_InvalidAdminCIDR(t *testing.T) {
	t.Parallel()
	yaml := "admin_cidrs:\n  - 1.2.3.4\n" // bare IP not valid as CIDR for admin_cidrs
	_, err := LoadPolicyReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "admin_cidrs[0]")
}

func TestLoadPolicy_BlockCountries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		yaml    string
		wantErr string
		wantLen int
	}{
		{
			name:    "valid two-letter codes",
			yaml:    "block_countries:\n  - CN\n  - RU\n  - KP\n",
			wantLen: 3,
		},
		{
			name:    "invalid: single letter",
			yaml:    "block_countries:\n  - X\n",
			wantErr: "block_countries[0]",
		},
		{
			name:    "invalid: three letters",
			yaml:    "block_countries:\n  - USA\n",
			wantErr: "block_countries[0]",
		},
		{
			name:    "empty list is valid",
			yaml:    "block_countries: []\n",
			wantLen: 0,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := LoadPolicyReader(strings.NewReader(tc.yaml), "test")
			if tc.wantErr != "" {
				wantErr(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(p.BlockCountries) != tc.wantLen {
				t.Errorf("BlockCountries len = %d, want %d", len(p.BlockCountries), tc.wantLen)
			}
		})
	}
}

func TestLoadPolicy_BlockASNs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		yaml    string
		wantErr string
		wantLen int
	}{
		{
			name:    "valid AS numbers",
			yaml:    "block_asns:\n  - AS16276\n  - AS14061\n",
			wantLen: 2,
		},
		{
			name:    "invalid: no AS prefix",
			yaml:    "block_asns:\n  - 16276\n",
			wantErr: "block_asns[0]",
		},
		{
			name:    "invalid: AS only no number",
			yaml:    "block_asns:\n  - AS\n",
			wantErr: "block_asns[0]",
		},
		{
			name:    "invalid: AS with non-digit",
			yaml:    "block_asns:\n  - AS123X\n",
			wantErr: "block_asns[0]",
		},
		{
			name:    "empty list is valid",
			yaml:    "block_asns: []\n",
			wantLen: 0,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := LoadPolicyReader(strings.NewReader(tc.yaml), "test")
			if tc.wantErr != "" {
				wantErr(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(p.BlockASNs) != tc.wantLen {
				t.Errorf("BlockASNs len = %d, want %d", len(p.BlockASNs), tc.wantLen)
			}
		})
	}
}

func TestParseASN(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input   string
		want    uint32
		wantErr bool
	}{
		{"AS0", 0, false},
		{"AS16276", 16276, false},
		{"AS4294967295", 4294967295, false},
		{"as16276", 16276, false}, // lowercase
		{"16276", 0, true},        // missing AS prefix
		{"AS", 0, true},           // no number
		{"AS12X", 0, true},        // non-digit
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := parseASN(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseASN(%q): expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseASN(%q): unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("parseASN(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestLoadPolicy_ValidAllowlistIPv4(t *testing.T) {
	t.Parallel()
	yaml := "allowlist:\n  - 1.2.3.4\n  - 10.0.0.0/8\n"
	p := mustLoadPolicy(t, yaml)
	if len(p.Allowlist) != 2 {
		t.Errorf("Allowlist len = %d", len(p.Allowlist))
	}
}

func TestLoadPolicy_ValidAllowlistIPv6(t *testing.T) {
	t.Parallel()
	yaml := "allowlist:\n  - \"::1\"\n  - 2001:db8::/32\n"
	p := mustLoadPolicy(t, yaml)
	if len(p.Allowlist) != 2 {
		t.Errorf("Allowlist len = %d", len(p.Allowlist))
	}
}

func TestLoadPolicy_FromFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	//nolint:gosec // test file
	if err := os.WriteFile(path, []byte("armed: false\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Armed {
		t.Error("expected Armed=false")
	}
}

// ---- Duration ---------------------------------------------------------------

func TestDuration_ParseString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"1h", time.Hour},
		{"24h", 24 * time.Hour},
		{"168h", 168 * time.Hour},
		{"0s", 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			yaml := fmt.Sprintf("strikes:\n  - ttl: %s\n", tc.input)
			p := mustLoadPolicy(t, yaml)
			if got := p.Strikes[0].TTL.AsDuration(); got != tc.want {
				t.Errorf("TTL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDuration_ParseIntZero(t *testing.T) {
	t.Parallel()
	yaml := "strikes:\n  - ttl: 0\n"
	p := mustLoadPolicy(t, yaml)
	if p.Strikes[0].TTL.AsDuration() != 0 {
		t.Errorf("expected zero duration, got %v", p.Strikes[0].TTL.AsDuration())
	}
}

func TestDuration_InvalidString(t *testing.T) {
	t.Parallel()
	yaml := "strikes:\n  - ttl: not-a-duration\n"
	_, err := LoadPolicyReader(strings.NewReader(yaml), "test")
	wantErr(t, err, "invalid duration")
}

func TestDuration_AsDuration(t *testing.T) {
	t.Parallel()
	d := Duration(5 * time.Minute)
	if d.AsDuration() != 5*time.Minute {
		t.Errorf("AsDuration() = %v, want 5m", d.AsDuration())
	}
}

// ---- SecretRef --------------------------------------------------------------

func TestSecretRef_ValidEnvRef(t *testing.T) {
	t.Parallel()
	yaml := `
ai:
  provider: anthropic
  api_key: "env:MY_SECRET"
`
	cfg := mustLoadConfig(t, yaml)
	if cfg.AI.APIKey != "env:MY_SECRET" {
		t.Errorf("APIKey = %q, want env:MY_SECRET", cfg.AI.APIKey)
	}
}

func TestSecretRef_RejectsInlineValue(t *testing.T) {
	t.Parallel()
	cases := []string{
		"sk-plaintext-token",
		"Bearer token123",
		"password",
		"0x",
	}
	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			yaml := fmt.Sprintf("ai:\n  provider: test\n  api_key: \"%s\"\n", raw)
			_, err := LoadConfigReader(strings.NewReader(yaml), "test")
			wantErr(t, err, "env:VARNAME")
		})
	}
}

func TestSecretRef_EmptyAccepted(t *testing.T) {
	t.Parallel()
	// An empty api_key is valid (field unset/optional).
	yaml := "ai:\n  provider: anthropic\n  api_key: \"\"\n"
	cfg := mustLoadConfig(t, yaml)
	if cfg.AI.APIKey.IsSet() {
		t.Error("expected IsSet()=false for empty api_key")
	}
}

func TestSecretRef_IsSet(t *testing.T) {
	t.Parallel()
	var s SecretRef
	if s.IsSet() {
		t.Error("zero value should not be set")
	}
	s = SecretRef("env:FOO")
	if !s.IsSet() {
		t.Error("env: ref should be set")
	}
}

func TestSecretRef_Resolve(t *testing.T) {
	t.Setenv("EZYSHIELD_TEST_SECRET", "supersecret")
	s := SecretRef("env:EZYSHIELD_TEST_SECRET")
	v, err := s.Resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "supersecret" {
		t.Errorf("Resolve() = %q, want supersecret", v)
	}
}

func TestSecretRef_ResolveMissingEnv(t *testing.T) {
	t.Parallel()
	// After issue #13, a missing env var yields a fixed, redacted error
	// (config.ErrAPIKeyMissing) that does NOT echo the referenced variable
	// name. This is intentional: even the var name isn't sensitive, but
	// keeping the message identical for both "unset" and "placeholder still
	// in .env" simplifies log filtering and matches SECURITY-REVIEW §4.
	s := SecretRef("env:EZYSHIELD_NONEXISTENT_VAR_XYZ")
	_, err := s.Resolve()
	if err == nil {
		t.Fatal("expected error for unset env var, got nil")
	}
	if !errors.Is(err, ErrAPIKeyMissing) {
		t.Errorf("Resolve() err = %v, want ErrAPIKeyMissing", err)
	}
}

func TestSecretRef_ResolveWhenEmpty(t *testing.T) {
	t.Parallel()
	var s SecretRef
	_, err := s.Resolve()
	wantErr(t, err, "not configured")
}

// ---- Example configs (CI gate) ----------------------------------------------

// TestExampleConfigs validates that the embedded example configs in configs/
// parse cleanly through the strict loaders. These run in CI on every push.

func TestExampleConfigs_Config(t *testing.T) {
	t.Parallel()
	data, err := configs.FS.ReadFile("config.yaml")
	if err != nil {
		t.Fatalf("reading embedded config.yaml: %v", err)
	}
	cfg, err := LoadConfigReader(bytes.NewReader(data), "configs/config.yaml")
	if err != nil {
		t.Fatalf("LoadConfigReader: %v", err)
	}
	if cfg.DataDir == "" {
		t.Error("expected DataDir to be set in example config")
	}
}

func TestExampleConfigs_Policy(t *testing.T) {
	t.Parallel()
	data, err := configs.FS.ReadFile("policy.yaml")
	if err != nil {
		t.Fatalf("reading embedded policy.yaml: %v", err)
	}
	p, err := LoadPolicyReader(bytes.NewReader(data), "configs/policy.yaml")
	if err != nil {
		t.Fatalf("LoadPolicyReader: %v", err)
	}
	// Example policy ships with explicit strikes; verify they loaded.
	if len(p.Strikes) == 0 {
		t.Error("expected Strikes to be non-empty after loading example policy")
	}
	// armed: false is the safe default
	if p.Armed {
		t.Error("example policy.yaml must ship with armed: false")
	}
}

// TestDuration_MarshalYAML_RoundTrip guards the `config show` policy dump:
// rendered strike TTLs must be re-loadable by LoadPolicyReader, including the
// integer-zero permanent marker.
func TestDuration_MarshalYAML_RoundTrip(t *testing.T) {
	t.Parallel()
	in := &Policy{
		Armed:            false,
		BanThreshold:     70,
		ObserveThreshold: 40,
		MaxBansPerMinute: 30,
		Strikes: []StrikeEntry{
			{TTL: Duration(5 * time.Minute)},
			{TTL: Duration(168 * time.Hour)},
			{TTL: Duration(0)}, // permanent
		},
	}
	data, err := yaml.Marshal(in)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if !strings.Contains(string(data), "ttl: 5m0s") {
		t.Errorf("expected duration string form in dump, got:\n%s", data)
	}
	if !strings.Contains(string(data), "ttl: 0") {
		t.Errorf("expected integer 0 for permanent TTL in dump, got:\n%s", data)
	}
	out, err := LoadPolicyReader(bytes.NewReader(data), "round-trip")
	if err != nil {
		t.Fatalf("LoadPolicyReader on marshaled policy: %v", err)
	}
	for i := range in.Strikes {
		if out.Strikes[i].TTL != in.Strikes[i].TTL {
			t.Errorf("strikes[%d].TTL = %v, want %v", i, out.Strikes[i].TTL, in.Strikes[i].TTL)
		}
	}
}
