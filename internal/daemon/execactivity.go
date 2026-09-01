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
	"errors"
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
//
// The watcher runs under the same supervision as a collector (issue #580):
// it is an observation source, and one that stops — because the Docker socket
// became unreadable, say — used to leave a single log line behind while the
// daemon kept claiming it was watching `docker exec`. Going through
// runCollector gives it the restart backoff, the DEGRADED observation state,
// the audit row and the one-shot critical notification.
func (d *Daemon) runExecActivity(ctx context.Context) {
	if d.execActivity == nil {
		return
	}
	d.runCollector(ctx, &execActivityWatcher{d: d}, nil)
}

// execActivityWatcher adapts the injected exec watcher to sdk.Collector so it
// can be supervised. It never emits RawLines — exec events go to the daemon
// through ReportExecActivity, not through the parsing pipeline — so the out
// channel is unused and may be nil.
type execActivityWatcher struct{ d *Daemon }

// Name is the identity used in supervision logs, alerts and collectors_detail.
func (e *execActivityWatcher) Name() string { return "docker-exec-watch" }

// Run blocks in the injected watcher. A return before shutdown means the
// watcher gave up; the injected closure logs the underlying cause, and the
// error returned here is what makes the gap visible in `status` and doctor.
func (e *execActivityWatcher) Run(ctx context.Context, _ chan<- sdk.RawLine) error {
	e.d.execActivity(ctx, func(r ExecActivityReport) {
		e.d.ReportExecActivity(ctx, r)
	})
	if ctx.Err() != nil {
		return nil
	}
	return errors.New("docker exec watcher stopped before shutdown — `docker exec` activity is no longer observed " +
		"(the underlying error is in the daemon log)")
}
