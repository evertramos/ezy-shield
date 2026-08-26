package config

// Retention policy (issue #184): how long each unbounded table keeps rows.
// The SQLite database grows without bound on attacked hosts (strikes,
// audit_log, ai_usage), and IPs are personal data under GDPR/LGPD — auditors
// ask for a retention policy. Pruning must respect domain semantics, so the
// windows are per-table with long defaults and hard minimum floors that
// protect users from foot-guns.
//
// The section is OPT-IN: when `retention:` is absent from config.yaml the
// daemon never prunes anything (pre-#184 behavior). When present, omitted
// fields take the documented defaults below.

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Retention window defaults. strikes is longest because strike history powers
// repeat-offender escalation context; audit is the security journal; ai_usage
// is operational accounting.
const (
	DefaultRetentionStrikes = 730 * 24 * time.Hour // 2 years
	DefaultRetentionAudit   = 365 * 24 * time.Hour // 1 year
	DefaultRetentionAIUsage = 90 * 24 * time.Hour  // 90 days
)

// Minimum floors. Values below these are rejected unless
// retention.i_understand_the_risks is true — and even then an absolute
// minimum of 24h applies (a shorter window would let a typo erase the
// database on the next maintenance tick).
const (
	MinRetentionStrikes  = 180 * 24 * time.Hour
	MinRetentionAudit    = 90 * 24 * time.Hour
	MinRetentionAIUsage  = 7 * 24 * time.Hour
	AbsoluteMinRetention = 24 * time.Hour
)

// RetentionCfg is the `retention:` section of config.yaml.
// Durations accept Go syntax plus a day unit ("30d", "365d", "24h").
// The literal "never" (or "0") disables pruning for that table.
type RetentionCfg struct {
	// Strikes is the window for strikes rows (default 730d, floor 180d).
	// Offender rows are dropped only when their entire strike history has
	// aged out AND they have no active ban; the escalation counter of any
	// offender that still has strikes or a ban is never touched.
	Strikes string `yaml:"strikes"`
	// Audit is the window for audit_log rows (default 365d, floor 90d).
	// Audit pruning additionally requires audit_export_not_required: true —
	// see that field. This is the ONLY delete path audit_log has.
	Audit string `yaml:"audit"`
	// AIUsage is the window for ai_usage accounting rows
	// (default 90d, floor 7d).
	AIUsage string `yaml:"ai_usage"`
	// IUnderstandTheRisks allows windows below the per-table floors
	// (never below 24h). Named to make the config file self-documenting.
	IUnderstandTheRisks bool `yaml:"i_understand_the_risks"`
	// AuditExportNotRequired acknowledges that audit_log rows will be
	// DELETED without any export having archived them. Until an automatic
	// export checkpoint exists (SIEM forwarding, issue #203), audit pruning
	// refuses to run unless this is explicitly true; the other tables are
	// pruned either way.
	AuditExportNotRequired bool `yaml:"audit_export_not_required"`
}

// RetentionWindows is the parsed, validated form of RetentionCfg.
// A zero duration means "never prune this table".
type RetentionWindows struct {
	Strikes time.Duration
	Audit   time.Duration
	AIUsage time.Duration
}

// parseRetentionDuration parses a retention window: Go duration syntax
// extended with a whole-day unit ("30d"), or "never"/"0" for disabled.
func parseRetentionDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "never", "0":
		return 0, nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid duration %q (want e.g. \"30d\", \"365d\", \"24h\", or \"never\")", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q (want e.g. \"30d\", \"365d\", \"24h\", or \"never\")", s)
	}
	return d, nil
}

// Windows parses the section into concrete durations, applying defaults for
// empty fields. It does NOT check floors — Validate does, so the daemon can
// call Windows on an already-validated config without re-handling floor
// errors.
func (r *RetentionCfg) Windows() (RetentionWindows, error) {
	w := RetentionWindows{
		Strikes: DefaultRetentionStrikes,
		Audit:   DefaultRetentionAudit,
		AIUsage: DefaultRetentionAIUsage,
	}
	var err error
	if r.Strikes != "" {
		if w.Strikes, err = parseRetentionDuration(r.Strikes); err != nil {
			return RetentionWindows{}, fmt.Errorf("strikes: %w", err)
		}
	}
	if r.Audit != "" {
		if w.Audit, err = parseRetentionDuration(r.Audit); err != nil {
			return RetentionWindows{}, fmt.Errorf("audit: %w", err)
		}
	}
	if r.AIUsage != "" {
		if w.AIUsage, err = parseRetentionDuration(r.AIUsage); err != nil {
			return RetentionWindows{}, fmt.Errorf("ai_usage: %w", err)
		}
	}
	return w, nil
}

// validateRetention enforces the per-table floors (or, with
// i_understand_the_risks, the 24h absolute minimum). Zero (= never prune)
// is always allowed.
func validateRetention(r *RetentionCfg) error {
	w, err := r.Windows()
	if err != nil {
		return err
	}
	check := func(field string, got, floor time.Duration) error {
		if got == 0 {
			return nil // never prune
		}
		if !r.IUnderstandTheRisks && got < floor {
			return fmt.Errorf("%s: %s is below the %s safety floor; raise it or set i_understand_the_risks: true", field, got, floor)
		}
		if got < AbsoluteMinRetention {
			return fmt.Errorf("%s: %s is below the absolute 24h minimum (not overridable)", field, got)
		}
		return nil
	}
	if err := check("strikes", w.Strikes, MinRetentionStrikes); err != nil {
		return err
	}
	if err := check("audit", w.Audit, MinRetentionAudit); err != nil {
		return err
	}
	if err := check("ai_usage", w.AIUsage, MinRetentionAIUsage); err != nil {
		return err
	}
	return nil
}
