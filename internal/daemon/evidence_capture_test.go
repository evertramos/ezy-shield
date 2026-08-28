// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// End-to-end test for capture-at-detection evidence (ADR-0011, issue #127):
// raw lines fed to the pipeline surface, bounded, in the persisted strike's
// verdicts — and therefore in `report`.

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestPipeline_StrikePersistsCapturedEvidence(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            false,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		SocketPath: "",
		MaxIPs:     100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	attacker := netip.MustParseAddr("192.0.2.90")
	// One oversized line among normal ones proves the attach-time cap.
	long := "Failed password for root from " + attacker.String() + " port 40122 ssh2" + strings.Repeat(" pad", 300)
	for i := 0; i < 6; i++ {
		line := "Failed password for root from " + attacker.String() + " port 40122 ssh2"
		if i == 0 {
			line = long
		}
		d.processRaw(ctx, sdk.RawLine{
			Source: "journald:sshd",
			Line:   []byte(line),
			At:     time.Now(),
		})
	}

	strikes, err := db.StrikesForIP(ctx, attacker, 10)
	if err != nil {
		t.Fatalf("StrikesForIP: %v", err)
	}
	if len(strikes) == 0 {
		t.Fatal("no strike recorded")
	}
	var evidence []string
	for _, v := range strikes[0].Verdicts {
		evidence = append(evidence, v.Evidence...)
	}
	if len(evidence) == 0 {
		t.Fatal("persisted strike carries no captured evidence")
	}
	if len(evidence) > sdk.EvidenceMaxLines*len(strikes[0].Verdicts) {
		t.Fatalf("evidence exceeds the per-verdict cap: %d lines", len(evidence))
	}
	var sawTriggering, sawTruncated bool
	for _, line := range evidence {
		if len(line) > sdk.EvidenceRawCap {
			t.Fatalf("evidence line exceeds EvidenceRawCap (%d): %d bytes", sdk.EvidenceRawCap, len(line))
		}
		if strings.Contains(line, "Failed password for root from "+attacker.String()) {
			sawTriggering = true
		}
		if strings.Contains(line, " pad") {
			sawTruncated = true
		}
	}
	if !sawTriggering {
		t.Fatalf("evidence does not contain the triggering lines: %q", evidence)
	}
	if !sawTruncated {
		t.Fatal("the oversized line should appear truncated in evidence (attach-time cap)")
	}
}
