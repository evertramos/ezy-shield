package store

// Regression tests for issue #422: ai_usage rows carry the analyzed IP so
// per-IP cost attribution is a single SELECT instead of a journal×DB join.

import (
	"context"
	"testing"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestRecordUsage_AttributesIP(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.RecordUsage(ctx, "anthropic",
		sdk.Usage{InputTokens: 10, OutputTokens: 5, CostUSD: 0.0001}, "192.0.2.70"); err != nil {
		t.Fatalf("RecordUsage with ip: %v", err)
	}
	if err := db.RecordUsage(ctx, "anthropic",
		sdk.Usage{InputTokens: 10, OutputTokens: 5, CostUSD: 0.0001}, ""); err != nil {
		t.Fatalf("RecordUsage without ip: %v", err)
	}

	var attributed int
	if err := db.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ai_usage WHERE ip = '192.0.2.70'`).Scan(&attributed); err != nil {
		t.Fatalf("query attributed: %v", err)
	}
	if attributed != 1 {
		t.Errorf("attributed rows = %d, want 1", attributed)
	}

	// No subject IP stores NULL (never empty string) so attributed and
	// unattributed spend stay cleanly separable.
	var nullRows int
	if err := db.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ai_usage WHERE ip IS NULL`).Scan(&nullRows); err != nil {
		t.Fatalf("query null: %v", err)
	}
	if nullRows != 1 {
		t.Errorf("NULL-ip rows = %d, want 1", nullRows)
	}

	// The documented top-spenders query works as written in the migration.
	var topIP string
	var usd float64
	if err := db.db.QueryRowContext(ctx, `
		SELECT ip, SUM(cost_usd) usd FROM ai_usage
		WHERE ip IS NOT NULL GROUP BY ip ORDER BY usd DESC LIMIT 1`).Scan(&topIP, &usd); err != nil {
		t.Fatalf("top-spenders query: %v", err)
	}
	if topIP != "192.0.2.70" {
		t.Errorf("top spender = %q, want 192.0.2.70", topIP)
	}
}
