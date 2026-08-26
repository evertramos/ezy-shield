package migrate

// Table-driven tests for the fail2ban configuration reader (issue #181),
// driven by fixtures under fixtures/fail2ban/. The reader is read-only and
// must survive malformed and oversized input without failing the run.

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "fixtures", "fail2ban", name)
}

func jailByName(t *testing.T, cfg *Config, name string) *Jail {
	t.Helper()
	for i := range cfg.Jails {
		if cfg.Jails[i].Name == name {
			return &cfg.Jails[i]
		}
	}
	t.Fatalf("jail %q not found in %v", name, cfg.Jails)
	return nil
}

func TestReadFail2ban_DebianDefault(t *testing.T) {
	t.Parallel()
	cfg, err := ReadFail2ban(fixture(t, "debian-default"))
	if err != nil {
		t.Fatalf("ReadFail2ban: %v", err)
	}

	sshd := jailByName(t, cfg, "sshd")
	if sshd.Enabled {
		t.Error("Debian default ships sshd DISABLED at the jail.conf layer (enabled via defaults-debian.conf normally)")
	}
	if sshd.Ports != "ssh" {
		t.Errorf("sshd port = %q", sshd.Ports)
	}
	// %(sshd_log)s stays unresolved but recorded.
	if got := sshd.Unresolved["logpath"]; !strings.Contains(got, "%(sshd_log)s") {
		t.Errorf("interpolated logpath not recorded: %q (unresolved=%v)", got, sshd.Unresolved)
	}
	if len(sshd.LogPaths) != 0 {
		t.Errorf("interpolated logpath must not be resolved into LogPaths: %v", sshd.LogPaths)
	}
	// [DEFAULT] inheritance: maxretry 5, bantime 10m.
	if sshd.MaxRetry != 5 || sshd.BanTime != 10*time.Minute {
		t.Errorf("sshd inherited = maxretry %d bantime %s, want 5 / 10m", sshd.MaxRetry, sshd.BanTime)
	}
	if len(sshd.IgnoreIP) != 2 {
		t.Errorf("default ignoreip = %v, want 127.0.0.1/8 + ::1", sshd.IgnoreIP)
	}

	rec := jailByName(t, cfg, "recidive")
	if rec.BanTime != 7*24*time.Hour || rec.FindTime != 24*time.Hour {
		t.Errorf("recidive = bantime %s findtime %s, want 1w / 1d", rec.BanTime, rec.FindTime)
	}

	// [INCLUDES] must not surface as a jail.
	for _, j := range cfg.Jails {
		if j.Name == "INCLUDES" || j.Name == "DEFAULT" {
			t.Errorf("pseudo-section %q surfaced as a jail", j.Name)
		}
	}
}

func TestReadFail2ban_LayeredOverrides(t *testing.T) {
	t.Parallel()
	cfg, err := ReadFail2ban(fixture(t, "overrides"))
	if err != nil {
		t.Fatalf("ReadFail2ban: %v", err)
	}

	// jail.local flips sshd on and overrides thresholds; multiline logpath.
	sshd := jailByName(t, cfg, "sshd")
	if !sshd.Enabled {
		t.Error("jail.local enabled=true must override jail.conf's false")
	}
	if sshd.MaxRetry != 3 || sshd.FindTime != 20*time.Minute {
		t.Errorf("sshd overrides = maxretry %d findtime %s, want 3 / 20m", sshd.MaxRetry, sshd.FindTime)
	}
	if len(sshd.LogPaths) != 2 || sshd.LogPaths[1] != "/var/log/auth.log.1" {
		t.Errorf("multiline logpath = %v", sshd.LogPaths)
	}
	// DEFAULT layered: jail.local's bantime 1h wins over jail.conf's 10m.
	if sshd.BanTime != time.Hour {
		t.Errorf("sshd bantime = %s, want 1h from jail.local [DEFAULT]", sshd.BanTime)
	}
	// ignoreip: two valid prefixes, hostname skipped with a warning.
	if len(sshd.IgnoreIP) != 2 {
		t.Errorf("ignoreip = %v, want 2 validated prefixes", sshd.IgnoreIP)
	}
	wantPfx := netip.MustParsePrefix("203.0.113.4/32")
	if sshd.IgnoreIP[1] != wantPfx {
		t.Errorf("ignoreip[1] = %v, want %v", sshd.IgnoreIP[1], wantPfx)
	}
	var hostnameWarned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "office.example.com") {
			hostnameWarned = true
		}
	}
	if !hostnameWarned {
		t.Errorf("hostname in ignoreip must be reported, warnings: %v", cfg.Warnings)
	}

	// jail.d/*.local layer (last) enables nginx and bumps maxretry.
	nginx := jailByName(t, cfg, "nginx-http-auth")
	if !nginx.Enabled || nginx.MaxRetry != 6 {
		t.Errorf("nginx = enabled %v maxretry %d, want true / 6 (jail.d .local layer)", nginx.Enabled, nginx.MaxRetry)
	}
	// jail.d/*.conf layer adds postfix with a day-suffixed bantime.
	postfix := jailByName(t, cfg, "postfix")
	if !postfix.Enabled || postfix.BanTime != 48*time.Hour {
		t.Errorf("postfix = enabled %v bantime %s, want true / 48h", postfix.Enabled, postfix.BanTime)
	}
}

func TestReadFail2ban_MalformedNeverFatal(t *testing.T) {
	t.Parallel()
	cfg, err := ReadFail2ban(fixture(t, "malformed"))
	if err != nil {
		t.Fatalf("malformed input must not be fatal: %v", err)
	}
	sshd := jailByName(t, cfg, "sshd")
	if !sshd.Enabled || len(sshd.LogPaths) != 1 {
		t.Errorf("valid keys around the damage must survive: %+v", sshd)
	}
	if sshd.MaxRetry != 0 || sshd.BanTime != 0 {
		t.Errorf("invalid numeric values must fall back to zero: %+v", sshd)
	}
	var badRetry, badTime bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "maxretry") {
			badRetry = true
		}
		if strings.Contains(w, "bantime") {
			badTime = true
		}
	}
	if !badRetry || !badTime {
		t.Errorf("invalid values must be reported, warnings: %v", cfg.Warnings)
	}
}

func TestReadFail2ban_HugeFileTruncatedSafely(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	var b strings.Builder
	b.WriteString("[DEFAULT]\nbantime = 10m\n\n[sshd]\nenabled = true\nlogpath = /var/log/auth.log\n")
	for b.Len() < maxINIFileSize+4096 {
		b.WriteString("# padding comment line to push the file past the size cap\n")
	}
	if err := os.WriteFile(filepath.Join(root, "jail.conf"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := ReadFail2ban(root)
	if err != nil {
		t.Fatalf("huge file must not be fatal: %v", err)
	}
	sshd := jailByName(t, cfg, "sshd")
	if !sshd.Enabled || sshd.BanTime != 10*time.Minute {
		t.Errorf("content before the cap must parse: %+v", sshd)
	}
	var truncated bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "truncated") {
			truncated = true
		}
	}
	if !truncated {
		t.Errorf("truncation must be reported, warnings: %v", cfg.Warnings)
	}
}

func TestReadFail2ban_JailCap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	var b strings.Builder
	for i := 0; i < maxJails+10; i++ {
		fmt.Fprintf(&b, "[jail%d]\nenabled = true\n", i)
	}
	if err := os.WriteFile(filepath.Join(root, "jail.conf"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := ReadFail2ban(root)
	if err != nil {
		t.Fatalf("ReadFail2ban: %v", err)
	}
	if len(cfg.Jails) != maxJails {
		t.Fatalf("jails = %d, want capped at %d", len(cfg.Jails), maxJails)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "skipped") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("jail cap must be reported, warnings: %v", cfg.Warnings)
	}
}

func TestReadFail2ban_MissingRootErrors(t *testing.T) {
	t.Parallel()
	if _, err := ReadFail2ban(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("a missing root must error (the ONLY fatal case)")
	}
}
