// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Issue #622 / E3-2, through the real pipeline: a busy client (5000 benign
// requests in 5 minutes) that then paces 12 wp-login attempts inside the
// hour must still trip http_wp_probe_sustained (10/1h). With an oldest-first
// sample cap the attacker's requests never reached the field-level rule.

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestBusyIP_FieldLevelHourlyRuleSeesCurrentTraffic(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clk := &virtualClock{t: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)}
	d, err := New(Config{
		Policy:     &config.Policy{Armed: false, BanThreshold: config.DefaultBanThreshold, ObserveThreshold: config.DefaultObserveThreshold, MaxBansPerMinute: config.DefaultMaxBansPerMinute, Strikes: config.DefaultStrikes},
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewNginxParser(slog.Default(), parser.NginxConfig{})},
		SocketPath: "",
		MaxIPs:     100,
		Now:        clk.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	actions := make(chan sdk.Action, 64)
	d.SetActionsSink(actions)
	ip := netip.MustParseAddr("203.0.113.120")
	line := func(path string) sdk.RawLine {
		return sdk.RawLine{Source: "file:/var/log/nginx/access.log", At: clk.now(),
			Line: []byte(ip.String() + ` - - [15/Sep/2026:12:00:00 +0000] "GET ` + path + ` HTTP/1.1" 200 512 "-" "Mozilla/5.0"`)}
	}
	for i := 0; i < 5000; i++ { // 5000 benign requests in 5 minutes
		d.processRaw(ctx, line("/"))
		clk.advance(60 * time.Millisecond)
	}
	for i := 0; i < 12; i++ { // then 12 paced wp-login attempts within the hour
		clk.advance(2 * time.Minute)
		d.processRaw(ctx, line("/wp-login.php"))
	}
	fired := false
	for len(actions) > 0 {
		if a := <-actions; a.IP == ip && a.Op == "dry_ban" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("12 wp-login attempts after a benign flood produced no decision — the field-level hourly rule could not see current traffic")
	}
}
