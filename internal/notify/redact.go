package notify

import (
	"github.com/evertramos/ezy-shield/internal/httpx"
)

// redactTransportErr strips the request URL from an HTTP transport error
// before it is wrapped, logged, or shown to the user (Hard Rule 3, issue
// #319). Thin alias over the shared helper: the implementation lives in
// internal/httpx (issue #439 — it used to be duplicated here and in
// internal/enrich, and a hardening applied to one copy could silently miss
// the other). This package's secret-leak gate keeps guarding the call sites
// (webhook.go, slack.go, discord.go, telegram.go).
//
// keepHost=true keeps scheme+host (well-known public API hosts: Telegram,
// Slack, Discord); keepHost=false collapses everything — for a generic
// webhook the operator's host can itself be secret (issue #360, CWE-209).
func redactTransportErr(err error, keepHost bool) error {
	return httpx.RedactTransportErr(err, keepHost)
}
