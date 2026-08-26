package config

// Tests for the retention section (issue #184): day-suffix parsing, defaults,
// safety floors, and the i_understand_the_risks override with its 24h
// absolute minimum.

import (
	"strings"
	"testing"
	"time"
)

func TestRetentionWindows_DefaultsAndParsing(t *testing.T) {
	t.Parallel()
	w, err := (&RetentionCfg{}).Windows()
	if err != nil {
		t.Fatalf("Windows: %v", err)
	}
	if w.Strikes != DefaultRetentionStrikes || w.Audit != DefaultRetentionAudit || w.AIUsage != DefaultRetentionAIUsage {
		t.Fatalf("defaults = %+v", w)
	}

	w, err = (&RetentionCfg{Strikes: "365d", Audit: "never", AIUsage: "2160h"}).Windows()
	if err != nil {
		t.Fatalf("Windows: %v", err)
	}
	if w.Strikes != 365*24*time.Hour {
		t.Fatalf("strikes 365d = %s", w.Strikes)
	}
	if w.Audit != 0 {
		t.Fatalf("audit \"never\" = %s, want 0 (disabled)", w.Audit)
	}
	if w.AIUsage != 2160*time.Hour {
		t.Fatalf("ai_usage 2160h = %s", w.AIUsage)
	}

	for _, bad := range []string{"30", "-5d", "1w", "soon"} {
		if _, err := (&RetentionCfg{Strikes: bad}).Windows(); err == nil {
			t.Fatalf("Strikes=%q must be rejected", bad)
		}
	}
}

func TestValidateRetention_FloorsAndOverride(t *testing.T) {
	t.Parallel()
	// Below floor without the override: rejected, naming the fix.
	err := validateRetention(&RetentionCfg{Strikes: "30d"})
	if err == nil || !strings.Contains(err.Error(), "i_understand_the_risks") {
		t.Fatalf("below-floor strikes err = %v, want floor rejection naming the override", err)
	}
	if err := validateRetention(&RetentionCfg{Audit: "10d"}); err == nil {
		t.Fatal("audit below 90d floor must be rejected")
	}
	if err := validateRetention(&RetentionCfg{AIUsage: "1d"}); err == nil {
		t.Fatal("ai_usage below 7d floor must be rejected")
	}

	// With the override: floor waived...
	if err := validateRetention(&RetentionCfg{Strikes: "30d", IUnderstandTheRisks: true}); err != nil {
		t.Fatalf("override should allow 30d strikes: %v", err)
	}
	// ...but never below the absolute 24h minimum.
	err = validateRetention(&RetentionCfg{Strikes: "1h", IUnderstandTheRisks: true})
	if err == nil || !strings.Contains(err.Error(), "24h minimum") {
		t.Fatalf("sub-24h err = %v, want absolute-minimum rejection", err)
	}

	// "never" is always fine, floors don't apply to disabled tables.
	if err := validateRetention(&RetentionCfg{Strikes: "never", Audit: "never", AIUsage: "never"}); err != nil {
		t.Fatalf("all-never: %v", err)
	}
	// Defaults validate.
	if err := validateRetention(&RetentionCfg{}); err != nil {
		t.Fatalf("empty section (defaults): %v", err)
	}
}

func TestConfigValidate_WiresRetention(t *testing.T) {
	t.Parallel()
	c := &Config{Retention: &RetentionCfg{Audit: "10d"}}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "retention:") {
		t.Fatalf("Validate err = %v, want retention floor error", err)
	}
	if err := (&Config{Retention: &RetentionCfg{}}).Validate(); err != nil {
		t.Fatalf("valid retention section rejected: %v", err)
	}
}
