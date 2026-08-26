package daemon

// Tests for the daemon-side metrics (issue #183).

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestSocketMetricsVerb(t *testing.T) {
	d := newTestDaemonForSocket(t, false)

	// Instrument a few things so the exposition has samples.
	d.recordActionMetrics(sdk.Action{Op: "dry_ban", Strike: 2,
		IP: netip.MustParseAddr("192.0.2.4"), TTL: time.Hour}, false)
	d.recordActionMetrics(sdk.Action{Op: "notify_only",
		IP: netip.MustParseAddr("192.0.2.5")}, false)

	resp := callSocket(t, d, SocketRequest{Verb: "metrics"})
	if !resp.OK {
		t.Fatalf("metrics verb: %s", resp.Error)
	}
	var data MetricsData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, want := range []string{
		"# TYPE ezyshield_build_info gauge",
		"ezyshield_build_info{",
		`ezyshield_actions_total{op="dry_ban"} 1`,
		`ezyshield_actions_total{op="notify_only"} 1`,
		`ezyshield_strikes_total{level="2"} 1`,
		"# TYPE ezyshield_active_bans gauge",
		"ezyshield_active_bans 0",
	} {
		if !strings.Contains(data.Text, want) {
			t.Errorf("exposition missing %q:\n%s", want, data.Text)
		}
	}
	// No IP may ever surface as a label value.
	if strings.Contains(data.Text, "192.0.2.") {
		t.Errorf("an IP leaked into the exposition:\n%s", data.Text)
	}
}

func TestMetricNameDerivation(t *testing.T) {
	// Type-derived labels must be short tokens, never paths.
	if got := metricCollectorType(&scriptedCollector{}); strings.ContainsAny(got, "/\\ ") {
		t.Errorf("collector label %q contains path-like characters", got)
	}
}
