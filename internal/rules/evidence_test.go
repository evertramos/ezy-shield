// SPDX-License-Identifier: AGPL-3.0-only

package rules_test

// Tests for capture-at-detection evidence (ADR-0011, issue #127): a firing
// rule attaches the raw lines of the events that matched it, bounded, and
// only from events that actually carry Raw.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func sshAggWithRaw(ip netip.Addr, n int) sdk.Aggregate {
	agg := sdk.Aggregate{
		IP:     ip,
		Window: 60 * time.Second,
		Count:  n,
		Kinds:  map[string]int{"ssh_fail": n},
	}
	for i := range n {
		agg.Sample = append(agg.Sample, sdk.Event{
			SourceIP: ip,
			Kind:     "ssh_fail",
			Fields:   map[string]string{"user": "root"},
			Raw:      fmt.Appendf(nil, "Failed password for root from %s port %d ssh2", ip, 40000+i),
		})
	}
	return agg
}

func TestEvidence_AttachedToFiringRuleVerdict(t *testing.T) {
	t.Parallel()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	ip := netip.MustParseAddr("192.0.2.80")
	verdicts := e.Evaluate(context.Background(), sshAggWithRaw(ip, 7))
	if len(verdicts) == 0 {
		t.Fatal("ssh_bruteforce must fire at 7 failures")
	}
	v := verdicts[0]
	if len(v.Evidence) != sdk.EvidenceMaxLines {
		t.Fatalf("evidence lines = %d, want capped at %d", len(v.Evidence), sdk.EvidenceMaxLines)
	}
	for _, line := range v.Evidence {
		if !strings.Contains(line, ip.String()) {
			t.Fatalf("evidence line %q does not look like a captured raw line", line)
		}
	}
}

func TestEvidence_FieldLevelRuleOnlyMatchingLines(t *testing.T) {
	t.Parallel()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	ip := netip.MustParseAddr("192.0.2.81")
	agg := sdk.Aggregate{IP: ip, Window: 60 * time.Second, Count: 4,
		Kinds: map[string]int{"http_request": 4}}
	// 3 wp-login hits (threshold 3) interleaved with a benign request.
	for i := range 3 {
		agg.Sample = append(agg.Sample, sdk.Event{
			SourceIP: ip, Kind: "http_request",
			Fields: map[string]string{"path": "/wp-login.php", "status": "200"},
			Raw:    fmt.Appendf(nil, "GET /wp-login.php attempt %d", i),
		})
	}
	agg.Sample = append(agg.Sample, sdk.Event{
		SourceIP: ip, Kind: "http_request",
		Fields: map[string]string{"path": "/index.html", "status": "200"},
		Raw:    []byte("GET /index.html benign"),
	})

	var found *sdk.Verdict
	for _, v := range e.Evaluate(context.Background(), agg) {
		if strings.Contains(v.Reason, "http_wp_probe") {
			vv := v
			found = &vv
		}
	}
	if found == nil {
		t.Fatal("http_wp_probe must fire")
	}
	if len(found.Evidence) != 3 {
		t.Fatalf("evidence = %d lines, want exactly the 3 matching ones", len(found.Evidence))
	}
	for _, line := range found.Evidence {
		if !strings.Contains(line, "wp-login") {
			t.Fatalf("non-matching line captured as evidence: %q", line)
		}
	}
}

func TestEvidence_AbsentWhenEventsCarryNoRaw(t *testing.T) {
	t.Parallel()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	ip := netip.MustParseAddr("192.0.2.82")
	agg := sshAggWithRaw(ip, 6)
	for i := range agg.Sample {
		agg.Sample[i].Raw = nil // pre-#127 events / counter-built aggregates
	}
	verdicts := e.Evaluate(context.Background(), agg)
	if len(verdicts) == 0 {
		t.Fatal("rule must still fire without Raw")
	}
	if len(verdicts[0].Evidence) != 0 {
		t.Fatalf("evidence must be absent without Raw, got %v", verdicts[0].Evidence)
	}
}
