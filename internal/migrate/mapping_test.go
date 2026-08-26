// SPDX-License-Identifier: AGPL-3.0-only

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
		{Name: "postfix-sasl", Enabled: true, Filter: "postfix[mode=auth]", BanTime: 2 * 24 * time.Hour,
			LogPaths: []string{"/var/log/mail.log"}},
		{Name: "dovecot", Enabled: true, LogPaths: []string{"/var/log/dovecot.log"}},
		{Name: "postfix-flood", Enabled: true}, // no logpath: manual-fix hint
		{Name: "recidive", Enabled: true, BanTime: 7 * 24 * time.Hour},
		{Name: "my-custom-app", Enabled: true, Filter: "my-custom-filter"},
		{Name: "roundcube-auth", Enabled: false},
	}}

	m := MapToEzyShield(cfg)

	// Collectors: journald ssh + four file collectors (nginx error, apache,
	// postfix mail.log, dovecot).
	var kinds []string
	for _, c := range m.Collectors {
		kinds = append(kinds, c.Kind+":"+c.Unit+c.Path+":"+c.Parser)
	}
	want := []string{
		"journald:ssh:",
		"file:/var/log/nginx/error.log:nginx",
		"file:/var/log/apache2/error.log:apache",
		"file:/var/log/mail.log:postfix",
		"file:/var/log/dovecot.log:dovecot",
	}
	if strings.Join(kinds, "|") != strings.Join(want, "|") {
		t.Fatalf("collectors = %v, want %v", kinds, want)
	}

	// Mapped: sshd, nginx-http-auth, apache-auth, postfix-sasl, dovecot,
	// recidive (natively).
	mappedNames := map[string]string{}
	for _, mj := range m.Mapped {
		mappedNames[mj.Jail.Name] = mj.How
	}
	if len(mappedNames) != 6 {
		t.Fatalf("mapped = %v, want 6 entries", mappedNames)
	}
	if !strings.Contains(mappedNames["recidive"], "natively") {
		t.Errorf("recidive must be reported as covered natively: %q", mappedNames["recidive"])
	}
	if !strings.Contains(mappedNames["sshd"], "unit name") {
		t.Errorf("sshd mapping must carry the distro unit-name note: %q", mappedNames["sshd"])
	}
	if !strings.Contains(mappedNames["postfix-sasl"], "mail rule family") {
		t.Errorf("postfix mapping must cite the mail rule family: %q", mappedNames["postfix-sasl"])
	}
	if !strings.Contains(mappedNames["dovecot"], "imap") {
		t.Errorf("dovecot mapping must cite the imap rules: %q", mappedNames["dovecot"])
	}

	// Unmapped: interpolated-logpath nginx, postfix without logpath
	// (manual-fix hint), custom filter.
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
	if !strings.Contains(unmapped["postfix-flood"], "manually") ||
		!strings.Contains(unmapped["postfix-flood"], "journald") {
		t.Errorf("logpath-less mail jail must carry the manual-collector hint: %q", unmapped["postfix-flood"])
	}
	if !strings.Contains(unmapped["my-custom-app"], "my-custom-filter") {
		t.Errorf("custom jail reason must include the filter path/name: %q", unmapped["my-custom-app"])
	}

	// Disabled jails are skipped, not unmapped.
	if len(m.Skipped) != 1 || m.Skipped[0] != "roundcube-auth" {
		t.Fatalf("skipped = %v, want [roundcube-auth]", m.Skipped)
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
