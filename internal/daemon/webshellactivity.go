package daemon

// Webshell-drop tripwire delivery (issue #221): the watcher (wired by
// run.go through Config.WebshellActivity, so the daemon never imports the
// watcher package) reports filesystem changes in web roots; the daemon
// makes them visible — audit trail, live stream (watch), and a
// notification whose severity reflects the content heuristic — and
// deliberately does NOTHING else. No ban decision derives from a file
// change: there is no remote IP on a filesystem event, and correlation
// with HTTP traffic is future work (the issue's "may", not "must").

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// WebshellReport is one observed web-root change, as delivered to the
// daemon. Fields are pre-capped by the watcher but remain hostile content
// (attacker-chosen filenames) — render-time sanitization applies wherever
// they surface.
type WebshellReport struct {
	Path       string
	Op         string // created | modified | mass_change
	Owner      string
	Size       int64
	Suspicious bool
	Markers    []string
	Count      int // mass_change only
}

// ReportWebshellActivity records one tripwire observation: an audit_log row
// (op "webshell_watch"), a stream event for `watch`, and a notification —
// critical when the content heuristic flagged the file, warn otherwise.
func (d *Daemon) ReportWebshellActivity(ctx context.Context, r WebshellReport) {
	var summary string
	if r.Op == "mass_change" {
		summary = fmt.Sprintf("mass change in watched web roots: %d files in one sweep (deploy? tune webshell_watch.ignore)", r.Count)
	} else {
		summary = fmt.Sprintf("web-root file %s: %q (uid %s, %d bytes)", r.Op, r.Path, r.Owner, r.Size)
		if r.Suspicious {
			summary += " — SUSPICIOUS content markers: " + strings.Join(r.Markers, ",")
		}
	}

	slog.WarnContext(ctx, "daemon: webshell tripwire observation",
		"op", r.Op, "suspicious", r.Suspicious)

	if err := d.store.AuditSystem(ctx, "webshell_watch", summary); err != nil {
		slog.ErrorContext(ctx, "daemon: audit webshell_watch", "err", err)
	}

	if d.events != nil && d.events.hasSubscribers() {
		d.events.publish(StreamEvent{
			Time:   eventTime(),
			Kind:   "webshell",
			Reason: summary,
			Source: "webshell-watch",
		})
	}

	if d.notifier != nil {
		severity := "warn"
		title := "web-root change observed"
		if r.Suspicious {
			severity = "critical"
			title = "possible webshell dropped"
		}
		_ = d.notifier.Send(ctx, sdk.Notification{
			Severity: severity,
			Title:    title,
			Body:     summary,
		})
	}
}

// runWebshellActivity starts the injected watcher, if any
// (Config.WebshellActivity; nil = feature disabled).
func (d *Daemon) runWebshellActivity(ctx context.Context) {
	if d.webshellActivity == nil {
		return
	}
	d.webshellActivity(ctx, func(r WebshellReport) {
		d.ReportWebshellActivity(ctx, r)
	})
}
