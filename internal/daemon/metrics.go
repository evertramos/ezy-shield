// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Prometheus metrics (issue #183). The daemon owns a per-instance registry
// (no process-global state — tests run many daemons in one process) and
// serves the rendered text exposition over the existing unix socket
// ("metrics" verb); the dashboard proxies it at GET /metrics on the
// loopback listener, keeping the no-new-listeners rule intact.
//
// Label cardinality is bounded by construction in internal/metrics: only
// enumerable labels (collector, parser, op, level, enforcer, provider) —
// never IPs, usernames, or paths.

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/metrics"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// daemonMetrics bundles the instrumented families.
type daemonMetrics struct {
	reg            *metrics.Registry
	collectorLines *metrics.LabeledCounter
	parserEvents   *metrics.LabeledCounter
	actions        *metrics.LabeledCounter
	strikes        *metrics.LabeledCounter
	bansApplied    *metrics.LabeledCounter
	aiRequests     *metrics.LabeledCounter
	aiTokens       *metrics.LabeledCounter
}

// newDaemonMetrics registers the metric families on a fresh registry.
func newDaemonMetrics(version string) *daemonMetrics {
	reg := metrics.NewRegistry()
	reg.BuildInfo(version)
	return &daemonMetrics{
		reg: reg,
		collectorLines: reg.LabeledCounter("ezyshield_collector_lines_total",
			"Raw log lines received per collector.", "collector"),
		parserEvents: reg.LabeledCounter("ezyshield_parser_events_total",
			"Structured events produced per parser.", "parser"),
		actions: reg.LabeledCounter("ezyshield_actions_total",
			"Decision-engine actions by operation (ban, dry_ban, notify_only, ...).", "op"),
		strikes: reg.LabeledCounter("ezyshield_strikes_total",
			"Strikes recorded by escalation level (1-5).", "level"),
		bansApplied: reg.LabeledCounter("ezyshield_bans_applied_total",
			"Bans successfully applied per enforcer backend.", "enforcer"),
		aiRequests: reg.LabeledCounter("ezyshield_ai_requests_total",
			"AI analyze calls per provider.", "provider"),
		aiTokens: reg.LabeledCounter("ezyshield_ai_tokens_total",
			"AI tokens consumed (input+output) per provider.", "provider"),
	}
}

// registerActiveBansGauge wires the store-sourced gauge; called from New
// once the store exists.
func (d *Daemon) registerActiveBansGauge() {
	d.metrics.reg.GaugeFunc("ezyshield_active_bans",
		"Active bans currently in the store (incl. permanent; excl. expired).",
		func() int64 {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			bans, err := d.store.ActiveBans(ctx)
			if err != nil {
				return -1 // scrape-visible signal that the query failed
			}
			return int64(len(bans))
		})
}

// metricParserName derives a bounded, human-readable parser label from the
// parser's type ("*parser.SSHParser" → "ssh").
func metricParserName(p sdk.Parser) string {
	name := fmt.Sprintf("%T", p)
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, "Parser")
	return strings.ToLower(name)
}

// recordAction instruments one dispatched action: the op counter, the
// strike-level counter, and (for enforced bans) the per-enforcer counter.
func (d *Daemon) recordActionMetrics(action sdk.Action, banApplied bool) {
	if d.metrics == nil { // bare Daemon literals in tests
		return
	}
	d.metrics.actions.With(action.Op).Inc()
	if action.Strike > 0 && (action.Op == "ban" || action.Op == "dry_ban") {
		d.metrics.strikes.With(strconv.Itoa(action.Strike)).Inc()
	}
	if banApplied && d.enforcer != nil {
		d.metrics.bansApplied.With(d.enforcer.Name()).Inc()
	}
}

// handleMetrics serves the "metrics" socket verb: the rendered Prometheus
// text exposition, wrapped for the JSON envelope.
func (d *Daemon) handleMetrics(_ context.Context) SocketResponse {
	if d.metrics == nil {
		return SocketResponse{Error: "metrics registry not initialized"}
	}
	data, err := json.Marshal(MetricsData{Text: d.metrics.reg.Snapshot()})
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("encode metrics: %v", err)}
	}
	return SocketResponse{OK: true, Data: data}
}

// MetricsData is the Data payload of the "metrics" verb.
type MetricsData struct {
	// Text is the Prometheus text exposition (format 0.0.4).
	Text string `json:"text"`
}
