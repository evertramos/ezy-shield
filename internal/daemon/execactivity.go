// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Docker exec activity delivery (issue #220): the watcher (wired by run.go
// through Config.ExecActivity, so the daemon never imports the linux-only
// collector package) reports each observed `docker exec`; the daemon makes
// it visible — audit trail, live stream (watch), and a warn-severity
// notification — and deliberately does NOTHING else. No ban decision ever
// derives from exec activity: there is usually no remote IP to ban, and a
// fabricated one would corrupt the offender store.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// ExecActivityReport is one observed exec, as delivered to the daemon.
// All fields are pre-capped by the watcher but remain hostile content —
// render-time sanitization applies everywhere they surface.
type ExecActivityReport struct {
	Container string
	Image     string
	Command   string
	User      string
}

// ReportExecActivity records one exec observation: an audit_log row
// (op "docker_exec"), a stream event for `watch` subscribers, and a
// warn-severity notification through the normal dedup/rate-limit pipeline.
func (d *Daemon) ReportExecActivity(ctx context.Context, r ExecActivityReport) {
	summary := fmt.Sprintf("exec into container %q (image %q)", r.Container, r.Image)
	if r.User != "" {
		summary += fmt.Sprintf(" as %q", r.User)
	}
	if r.Command != "" {
		summary += ": " + r.Command
	}

	slog.WarnContext(ctx, "daemon: docker exec activity observed",
		"container", r.Container, "image", r.Image, "user", r.User)

	if err := d.store.AuditSystem(ctx, "docker_exec", summary); err != nil {
		slog.ErrorContext(ctx, "daemon: audit docker_exec", "err", err)
	}

	if d.events != nil && d.events.hasSubscribers() {
		d.events.publish(StreamEvent{
			Time:   eventTime(),
			Kind:   "docker_exec",
			Reason: summary,
			Source: "docker-exec-watch",
		})
	}

	if d.notifier != nil {
		_ = d.notifier.Send(ctx, sdk.Notification{
			Severity: "warn",
			Title:    "docker exec activity in " + r.Container,
			Body:     summary,
		})
	}
}

// runExecActivity starts the injected watcher, if any (Config.ExecActivity;
// nil = feature disabled or non-docker host).
func (d *Daemon) runExecActivity(ctx context.Context) {
	if d.execActivity == nil {
		return
	}
	d.execActivity(ctx, func(r ExecActivityReport) {
		d.ReportExecActivity(ctx, r)
	})
}
