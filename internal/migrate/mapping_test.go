package migrate

// Tests for the fail2ban → EzyShield mapping (issue #182). Pure-function
// tests over hand-built models; the file-level golden behavior is covered
// by the CLI test in cmd/ezyshield.

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestMapToEzyShield_V1Table(t *testing.T) {
	t.Parallel()
	pfx := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	cfg := &Config{Jails: []Jail{
		{Name: "sshd", Enabled: true, MaxRetry: 3, BanTime: time.Hour,
			IgnoreIP: []netip.Prefix{pfx("127.0.0.0/8"), pfx("203.0.113.4/32")}},
		{Name: "nginx-http-auth", Enabled: true,
			LogPaths: []string{"/var/log/nginx/error.log"},
			IgnoreIP: []netip.Prefix{pfx("127.0.0.0/8")}},
		{Name: "nginx-botsearch", Enabled: true,
			Unresolved: map[string]string{"logpath": "%(nginx_access_log)s"}},
		{Name: "apache-auth", Enabled: true, LogPaths: []string{"/var/log/apache2/error.log"}},
		{Name: "postfix-sasl", Enabled: true, Filter: "postfix[mode=auth]", BanTime: 2 * 24 * time.Hour},
		{Name: "recidive", Enabled: true, BanTime: 7 * 24 * time.Hour},
		{Name: "my-custom-app", Enabled: true, Filter: "my-custom-filter"},
		{Name: "dovecot", Enabled: false},
	}}

	m := MapToEzyShield(cfg)

	// Collectors: journald ssh + two file collectors (nginx error, apache).
	var kinds []string
	for _, c := range m.Collectors {
		kinds = append(kinds, c.Kind+":"+c.Unit+c.Path+":"+c.Parser)
	}
	want := []string{
		"journald:ssh:",
		"file:/var/log/nginx/error.log:nginx",
		"file:/var/log/apache2/error.log:apache",
	}
	if strings.Join(kinds, "|") != strings.Join(want, "|") {
		t.Fatalf("collectors = %v, want %v", kinds, want)
	}

	// Mapped: sshd, nginx-http-auth, apache-auth, recidive (natively).
	mappedNames := map[string]string{}
	for _, mj := range m.Mapped {
		mappedNames[mj.Jail.Name] = mj.How
	}
	if len(mappedNames) != 4 {
		t.Fatalf("mapped = %v, want 4 entries", mappedNames)
	}
	if !strings.Contains(mappedNames["recidive"], "natively") {
		t.Errorf("recidive must be reported as covered natively: %q", mappedNames["recidive"])
	}
	if !strings.Contains(mappedNames["sshd"], "unit name") {
		t.Errorf("sshd mapping must carry the distro unit-name note: %q", mappedNames["sshd"])
	}

	// Unmapped: interpolated-logpath nginx, postfix (planned), custom.
	unmapped := map[string]string{}
	for _, uj := range m.Unmapped {
		unmapped[uj.Jail.Name] = uj.Reason
	}
	if len(unmapped) != 3 {
		t.Fatalf("unmapped = %v, want 3 entries", unmapped)
	}
	if !strings.Contains(unmapped["nginx-botsearch"], "interpolation") {
		t.Errorf("interpolated logpath reason = %q", unmapped["nginx-botsearch"])
	}
	if !strings.Contains(unmapped["postfix-sasl"], "#188") ||
		!strings.Contains(unmapped["postfix-sasl"], "postfix[mode=auth]") {
		t.Errorf("postfix reason must name the planned issue and the filter: %q", unmapped["postfix-sasl"])
	}
	if !strings.Contains(unmapped["my-custom-app"], "my-custom-filter") {
		t.Errorf("custom jail reason must include the filter path/name: %q", unmapped["my-custom-app"])
	}

	// Disabled jails are skipped, not unmapped.
	if len(m.Skipped) != 1 || m.Skipped[0] != "dovecot" {
		t.Fatalf("skipped = %v, want [dovecot]", m.Skipped)
	}

	// Allowlist union, deduped and sorted.
	if len(m.Allowlist) != 2 {
		t.Fatalf("allowlist = %v, want 2 deduped prefixes", m.Allowlist)
	}

	// Largest bantime becomes the strike-1 suggestion.
	if m.BanTimeSuggestion != 7*24*time.Hour {
		t.Fatalf("bantime suggestion = %s, want the recidive 1w", m.BanTimeSuggestion)
	}

	// The standing differences are spelled out.
	joined := strings.Join(m.Notes, " ")
	for _, wantNote := range []string{"escalates", "maxretry", "not translated"} {
		if !strings.Contains(joined, wantNote) {
			t.Errorf("notes lack %q: %v", wantNote, m.Notes)
		}
	}
}
