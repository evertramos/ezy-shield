// SPDX-License-Identifier: AGPL-3.0-only

package ai

// Issue #422: Consume attributes usage to the analyzed IP in canonical form.

import (
	"context"
	"net/netip"
	"testing"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// ipRecordingStore captures the ip passed to RecordUsage.
type ipRecordingStore struct {
	ips []string
}

func (r *ipRecordingStore) RecordUsage(_ context.Context, _ string, _ sdk.Usage, ip string) error {
	r.ips = append(r.ips, ip)
	return nil
}

func (r *ipRecordingStore) TodayUsage(context.Context, string) (sdk.Usage, error) {
	return sdk.Usage{}, nil
}

func TestConsume_AttributesCanonicalIP(t *testing.T) {
	store := &ipRecordingStore{}
	b := NewBudget("anthropic", 0, store)
	ctx := context.Background()

	// 4-in-6 mapped form must canonicalize (cf. #314) so one IP is one key.
	if _, err := b.Consume(ctx, sdk.Usage{InputTokens: 1}, netip.MustParseAddr("::ffff:192.0.2.71")); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	// No subject IP records empty (→ NULL at the store layer).
	if _, err := b.Consume(ctx, sdk.Usage{InputTokens: 1}, netip.Addr{}); err != nil {
		t.Fatalf("Consume no-ip: %v", err)
	}

	if len(store.ips) != 2 || store.ips[0] != "192.0.2.71" || store.ips[1] != "" {
		t.Fatalf("recorded ips = %v, want [192.0.2.71 \"\"]", store.ips)
	}
}
