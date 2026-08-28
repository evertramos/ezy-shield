// SPDX-License-Identifier: AGPL-3.0-only

package rules_test

// Tests for the built-in mail rules (issue #190) against synthetic
// aggregates shaped exactly like the postfix (#188) and dovecot (#189)
// parsers produce.

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func mailAgg(ip string, window time.Duration, kinds map[string]int) sdk.Aggregate {
	total := 0
	for _, n := range kinds {
		total += n
	}
	return sdk.Aggregate{
		IP:     netip.MustParseAddr(ip),
		Window: window,
		Count:  total,
		Kinds:  kinds,
	}
}

func firedRules(t *testing.T, agg sdk.Aggregate) map[string]int {
	t.Helper()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	out := map[string]int{}
	for _, v := range e.Evaluate(context.Background(), agg) {
		if name, ok := strings.CutPrefix(v.Reason, "rule/"); ok {
			if i := strings.IndexByte(name, ':'); i > 0 {
				out[name[:i]] = v.Score
			}
		}
	}
	return out
}

func TestMailBruteforce_MixedSMTPAndIMAP(t *testing.T) {
	t.Parallel()
	// 3 SMTP + 2 IMAP failures inside 5 minutes = threshold 5 across kinds.
	fired := firedRules(t, mailAgg("203.0.113.90", 300*time.Second,
		map[string]int{"smtp_auth_fail": 3, "imap_auth_fail": 2}))
	score, ok := fired["mail_bruteforce"]
	if !ok {
		t.Fatalf("mail_bruteforce did not fire: %v", fired)
	}
	if score < 70 {
		t.Fatalf("score %d below the ban threshold", score)
	}
	// Below threshold: silent.
	fired = firedRules(t, mailAgg("203.0.113.91", 300*time.Second,
		map[string]int{"smtp_auth_fail": 2, "imap_auth_fail": 2}))
	if _, ok := fired["mail_bruteforce"]; ok {
		t.Fatal("mail_bruteforce fired below threshold")
	}
}

func TestMailRelayProbe(t *testing.T) {
	t.Parallel()
	fired := firedRules(t, mailAgg("203.0.113.92", 300*time.Second,
		map[string]int{"smtp_relay_denied": 3}))
	if _, ok := fired["mail_relay_probe"]; !ok {
		t.Fatalf("mail_relay_probe did not fire: %v", fired)
	}
	fired = firedRules(t, mailAgg("203.0.113.93", 300*time.Second,
		map[string]int{"smtp_relay_denied": 2}))
	if _, ok := fired["mail_relay_probe"]; ok {
		t.Fatal("mail_relay_probe fired below threshold")
	}
}

func TestMailBruteforceSustained(t *testing.T) {
	t.Parallel()
	// Low & slow across the hour, mixing failures and connection abuse.
	fired := firedRules(t, mailAgg("203.0.113.94", 3600*time.Second,
		map[string]int{"smtp_auth_fail": 4, "imap_auth_fail": 3, "smtp_abuse": 3}))
	if _, ok := fired["mail_bruteforce_sustained"]; !ok {
		t.Fatalf("mail_bruteforce_sustained did not fire: %v", fired)
	}
}

func TestMailProbes_NotCountedByDefault(t *testing.T) {
	t.Parallel()
	// Credential-less probes alone must not trip any shipped rule — the
	// aggressive tier is opt-in (commented in rules.yaml, like ssh_probe).
	for _, w := range []time.Duration{300 * time.Second, 3600 * time.Second} {
		fired := firedRules(t, mailAgg("203.0.113.95", w, map[string]int{"imap_probe": 50}))
		if len(fired) != 0 {
			t.Fatalf("imap_probe alone fired %v in window %s", fired, w)
		}
	}
}
