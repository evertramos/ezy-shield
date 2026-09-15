// SPDX-License-Identifier: AGPL-3.0-only

package main

// Notification routing check (issue #613): the "enforcement DEGRADED"
// alert is critical severity. A channel set whose severity filters all
// exclude "critical" silently discards it — the operator hears nothing
// exactly when enforcement breaks.

import (
	"path/filepath"
	"strings"

	"github.com/evertramos/ezy-shield/internal/config"
)

// checkNotifyCriticalRoute reports whether at least one configured channel
// forwards critical notifications.
func checkNotifyCriticalRoute(configDir string) CheckResult {
	const name = "notify: critical alerts have a route"
	cfg, err := config.LoadConfig(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		return CheckResult{Name: name, Status: statusNA,
			Hint: "config.yaml not loadable -- the config checks report that separately"}
	}
	if cfg.Notify == nil {
		return CheckResult{Name: name, Status: statusNA, Hint: "no notify section configured"}
	}
	type channel struct {
		name     string
		severity []string
	}
	var channels []channel
	if t := cfg.Notify.Telegram; t != nil {
		channels = append(channels, channel{"telegram", t.Severity})
	}
	if e := cfg.Notify.Email; e != nil {
		channels = append(channels, channel{"email", e.Severity})
	}
	if s := cfg.Notify.Slack; s != nil {
		channels = append(channels, channel{"slack", s.Severity})
	}
	if d := cfg.Notify.Discord; d != nil {
		channels = append(channels, channel{"discord", d.Severity})
	}
	if w := cfg.Notify.Webhook; w != nil {
		channels = append(channels, channel{"webhook", w.Severity})
	}
	if len(channels) == 0 {
		return CheckResult{Name: name, Status: statusNA, Hint: "no notification channels configured"}
	}
	var names []string
	for _, ch := range channels {
		names = append(names, ch.name)
		if len(ch.severity) == 0 {
			return CheckResult{Name: name, Status: statusPass,
				Hint: ch.name + " forwards every severity (no filter)"}
		}
		for _, sev := range ch.severity {
			if sev == "critical" {
				return CheckResult{Name: name, Status: statusPass,
					Hint: ch.name + " forwards critical"}
			}
		}
	}
	return CheckResult{Name: name, Status: statusWarn,
		Hint: "no channel (" + strings.Join(names, ", ") + ") accepts severity 'critical' -- the 'enforcement DEGRADED' alert " +
			"and enforcer failures are discarded; add 'critical' to at least one channel's severity list in config.yaml"}
}
