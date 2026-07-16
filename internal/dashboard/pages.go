package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// Flash codes rendered by pages when a POST redirected here after an action.
// Only keys in this map are considered — anything else is silently ignored so
// crafted URLs cannot inject arbitrary strings into the UI.
var flashMessages = map[string]string{
	"invalid-ip":     "Invalid IP or CIDR — nothing was sent to the daemon.",
	"missing-ip":     "IP or CIDR is required.",
	"bad-form":       "Malformed form submission.",
	"bad-reason":     "Reason contains disallowed characters or exceeds 500 characters.",
	"daemon-error":   "The daemon rejected the request. See the daemon log for details.",
	"daemon-offline": "The daemon is not reachable right now.",
	"ban-queued":     "Ban queued.",
	"unban-queued":   "Unban queued.",
	"allow-added":    "Allowlist entry added.",
}

func flashFor(r *http.Request, key string) (string, bool) {
	if code := r.URL.Query().Get(key); code != "" {
		if msg, ok := flashMessages[code]; ok {
			return msg, true
		}
	}
	return "", false
}

// csrfOf returns the CSRF token attached to r by requireAuth. If the
// middleware chain was misconfigured the empty string is returned — the
// template still renders but any subsequent POST will fail the CSRF check.
func csrfOf(r *http.Request) string {
	if info, ok := sessionFromContext(r.Context()); ok {
		return info.CSRF
	}
	return ""
}

// statusPageData is the concrete payload rendered by the status template.
type statusPageData struct {
	Daemon       string
	Mode         string
	Uptime       string
	Version      string
	ActiveBans   int
	BansByStrike []strikeCount
	Offline      bool
	Error        string
	Info         string
}

type strikeCount struct {
	Bucket string
	Count  int
}

func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	data := statusPageData{Daemon: "stopped", Mode: "unknown"}

	sd, err := s.fetchStatus(r.Context())
	switch {
	case err == nil:
		data.Daemon = "running"
		data.Uptime = sd.Uptime
		data.Version = sd.Version
		data.ActiveBans = sd.ActiveBans
		if sd.Armed {
			data.Mode = "enforce"
		} else {
			data.Mode = "dry-run"
		}
	case isOffline(err):
		data.Offline = true
	default:
		s.logger.Error("dashboard status rpc", "err", err)
		data.Error = "Daemon returned an error. See the daemon log."
	}

	// Best-effort per-strike breakdown. A list failure here is not fatal —
	// the overview page still renders the status card.
	if bans, err := s.fetchBans(r.Context()); err == nil {
		data.BansByStrike = sortedStrikeCounts(bansByStrike(bans))
	}

	if flash, ok := flashFor(r, "info"); ok {
		data.Info = flash
	}

	if err := renderStatusPage(w, csrfOf(r), data); err != nil {
		s.logger.Error("render status", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

type bansPageData struct {
	Entries []daemon.BanEntry
	Offline bool
	Error   string
	Info    string
}

func (s *Server) handleBansPage(w http.ResponseWriter, r *http.Request) {
	data := bansPageData{}
	entries, err := s.fetchBans(r.Context())
	switch {
	case err == nil:
		data.Entries = entries
	case isOffline(err):
		data.Offline = true
	default:
		s.logger.Error("dashboard list rpc", "err", err)
		data.Error = "Daemon returned an error. See the daemon log."
	}
	if flash, ok := flashFor(r, "err"); ok {
		data.Error = flash
	}
	if flash, ok := flashFor(r, "ok"); ok {
		data.Info = flash
	}
	if err := renderBansPage(w, csrfOf(r), data); err != nil {
		s.logger.Error("render bans", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

type allowlistPageData struct {
	Entries []daemon.AllowEntry
	Offline bool
	Error   string
	Info    string
}

type eventsPageData struct {
	Entries []daemon.EventEntry
	Offline bool
	Error   string
	Info    string
}

// timelineEntry is one row in the /dashboard/timeline view — one card
// per currently-banned IP, showing where the address sits on the
// 5-strike ladder plus the reconstructed timestamps of each step.
type timelineEntry struct {
	IP          string
	Country     string
	ASN         string
	CurrentTTL  string
	CurrentTier int
	Steps       []timelineStep
}

// timelineStep is one point on the ladder. Reached is true when the IP
// has hit that strike number, false when the step is still ahead.
type timelineStep struct {
	Strike     int
	Reached    bool
	RecordedAt string
	Reason     string
}

type timelinePageData struct {
	Entries []timelineEntry
	Offline bool
	Error   string
	Info    string
}

// handleTimelinePage renders the strike-ladder view. It combines the
// list of currently-active bans with the recent audit_log rows so each
// IP shows where it sits on the 1→5 ladder plus the timestamps of the
// prior steps. Read-only: no daemon writes, no store mutations.
func (s *Server) handleTimelinePage(w http.ResponseWriter, r *http.Request) {
	data := timelinePageData{}
	bans, err := s.fetchBans(r.Context())
	switch {
	case err == nil:
	case isOffline(err):
		data.Offline = true
	default:
		s.logger.Error("dashboard list rpc (timeline)", "err", err)
		data.Error = "Daemon returned an error. See the daemon log."
	}
	if !data.Offline && data.Error == "" && len(bans) > 0 {
		events, evErr := s.fetchEventsN(r.Context(), 500)
		if evErr != nil && !isOffline(evErr) {
			s.logger.Debug("dashboard events for timeline", "err", evErr)
		}
		data.Entries = buildTimeline(bans, events)
	}
	if err := renderTimelinePage(w, csrfOf(r), data); err != nil {
		s.logger.Error("render timeline", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// buildTimeline turns the raw list + events pair into one card per IP
// with 5 ladder steps. Only ban / dry_ban ops count as escalations; a
// row without a matching audit entry still renders the current tier.
func buildTimeline(bans []daemon.BanEntry, events []daemon.EventEntry) []timelineEntry {
	perIP := map[string]map[int]daemon.EventEntry{}
	for _, e := range events {
		switch e.Op {
		case "ban", "dry_ban":
		default:
			continue
		}
		if _, ok := perIP[e.IP]; !ok {
			perIP[e.IP] = map[int]daemon.EventEntry{}
		}
		prev, seen := perIP[e.IP][e.Strike]
		if !seen || e.ID > prev.ID {
			perIP[e.IP][e.Strike] = e
		}
	}
	out := make([]timelineEntry, 0, len(bans))
	for _, b := range bans {
		steps := make([]timelineStep, 0, 5)
		for tier := 1; tier <= 5; tier++ {
			step := timelineStep{Strike: tier}
			if hit, ok := perIP[b.IP][tier]; ok {
				step.Reached = true
				step.RecordedAt = hit.RecordedAt
				step.Reason = hit.Reason
			} else if tier <= b.Strike {
				step.Reached = true
			}
			steps = append(steps, step)
		}
		out = append(out, timelineEntry{
			IP:          b.IP,
			Country:     b.Country,
			ASN:         b.ASN,
			CurrentTTL:  b.TTL,
			CurrentTier: b.Strike,
			Steps:       steps,
		})
	}
	return out
}

func (s *Server) handleEventsPage(w http.ResponseWriter, r *http.Request) {
	data := eventsPageData{}
	entries, err := s.fetchEvents(r.Context())
	switch {
	case err == nil:
		data.Entries = entries
	case isOffline(err):
		data.Offline = true
	default:
		s.logger.Error("dashboard events rpc", "err", err)
		data.Error = "Daemon returned an error. See the daemon log."
	}
	if err := renderEventsPage(w, csrfOf(r), data); err != nil {
		s.logger.Error("render events", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *Server) handleAllowlistPage(w http.ResponseWriter, r *http.Request) {
	data := allowlistPageData{}
	entries, err := s.fetchAllows(r.Context())
	switch {
	case err == nil:
		data.Entries = entries
	case isOffline(err):
		data.Offline = true
	default:
		s.logger.Error("dashboard list_allow rpc", "err", err)
		data.Error = "Daemon returned an error. See the daemon log."
	}
	if flash, ok := flashFor(r, "err"); ok {
		data.Error = flash
	}
	if flash, ok := flashFor(r, "ok"); ok {
		data.Info = flash
	}
	if err := renderAllowlistPage(w, csrfOf(r), data); err != nil {
		s.logger.Error("render allowlist", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleBanPost validates the IP form field, dispatches "ban" via the
// daemon RPC, and redirects back to /dashboard/bans with a flash code.
// The operator-supplied reason is prefixed with "dashboard:admin" so the
// daemon's audit_log distinguishes dashboard-originated writes from CLI
// verbs (Phase 4 spec). html/template auto-escapes hostile content when
// the reason is rendered back.
func (s *Server) handleBanPost(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	target, reason, code := parseTargetForm(r)
	if code != "" {
		redirectFlash(w, r, "/dashboard/bans", "err", code)
		return
	}
	tagged := dashboardActionReason(reason)
	code = s.doWrite(r.Context(), func(ctx context.Context) error {
		return s.callBan(ctx, target, tagged)
	})
	if code != "" {
		redirectFlash(w, r, "/dashboard/bans", "err", code)
		return
	}
	redirectFlash(w, r, "/dashboard/bans", "ok", "ban-queued")
}

func (s *Server) handleUnbanPost(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	target, _, code := parseTargetForm(r)
	if code != "" {
		redirectFlash(w, r, "/dashboard/bans", "err", code)
		return
	}
	code = s.doWrite(r.Context(), func(ctx context.Context) error {
		return s.callUnban(ctx, target)
	})
	if code != "" {
		redirectFlash(w, r, "/dashboard/bans", "err", code)
		return
	}
	redirectFlash(w, r, "/dashboard/bans", "ok", "unban-queued")
}

func (s *Server) handleAllowPost(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	target, reason, code := parseTargetForm(r)
	if code != "" {
		redirectFlash(w, r, "/dashboard/allowlist", "err", code)
		return
	}
	tagged := dashboardActionReason(reason)
	code = s.doWrite(r.Context(), func(ctx context.Context) error {
		return s.callAllow(ctx, target, tagged)
	})
	if code != "" {
		redirectFlash(w, r, "/dashboard/allowlist", "err", code)
		return
	}
	redirectFlash(w, r, "/dashboard/allowlist", "ok", "allow-added")
}

// requireCSRF fetches the expected token from the session context and
// delegates to checkCSRF, which writes 403 and returns an error on
// mismatch. Callers exit early when this returns false.
func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	info, ok := sessionFromContext(r.Context())
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return checkCSRF(w, r, info.CSRF) == nil
}

// dashboardActionReason tags an operator-supplied reason so audit_log
// consumers can tell dashboard writes apart from CLI verbs. When the
// operator left the field blank the tag stands alone; otherwise operator
// text is preserved after the tag for the paper trail.
func dashboardActionReason(userReason string) string {
	if userReason == "" {
		return "dashboard:admin"
	}
	return "dashboard:admin: " + userReason
}

// parseTargetForm parses a POST form and returns the canonicalised target
// prefix, an operator-supplied reason, and a flash code. The IP field
// accepts either a bare address or a CIDR; bare addresses are widened to
// /32 or /128 so the daemon receives a consistent shape. A non-empty
// flash code means the request must not reach the daemon.
func parseTargetForm(r *http.Request) (target, reason, flashCode string) {
	if err := r.ParseForm(); err != nil {
		return "", "", "bad-form"
	}
	raw := strings.TrimSpace(r.FormValue("ip"))
	if raw == "" {
		return "", "", "missing-ip"
	}
	target, ok := canonicalPrefix(raw)
	if !ok {
		return "", "", "invalid-ip"
	}
	reason = strings.TrimSpace(r.FormValue("reason"))
	if !validReason(reason) {
		return "", "", "bad-reason"
	}
	return target, reason, ""
}

// validReason bounds the operator-supplied reason before it reaches the
// daemon RPC: at most 500 characters post-trim, valid UTF-8, and no control
// bytes other than tab. audit_log stores the reason verbatim, so exports
// (CSV, JSON, SIEM) must never receive framing or terminal-control payloads
// through this field (SECURITY-REVIEW §1); the cap also closes the
// unbounded-size surface. Empty is valid — the bare dashboard:admin tag is
// applied as today.
func validReason(reason string) bool {
	if !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 500 {
		return false
	}
	for _, b := range []byte(reason) {
		if (b < 0x20 && b != 0x09) || b == 0x7f {
			return false
		}
	}
	return true
}

// canonicalPrefix accepts a bare IP or CIDR and returns the canonical
// prefix string. It uses netip so hostnames, oversized inputs and mixed
// representations are rejected before any bytes reach the daemon
// (SECURITY-REVIEW §1).
func canonicalPrefix(raw string) (string, bool) {
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String(), true
	}
	return "", false
}

// doWrite runs fn against the daemon and translates the outcome into a
// flash code. It centralises the "was this daemon offline vs. daemon
// error vs. success" mapping so every write handler stays a two-liner.
func (s *Server) doWrite(ctx context.Context, fn func(context.Context) error) string {
	err := fn(ctx)
	switch {
	case err == nil:
		return ""
	case isOffline(err):
		return "daemon-offline"
	default:
		s.logger.Error("dashboard write rpc", "err", err)
		return "daemon-error"
	}
}

// redirectFlash issues a 303 to base?key=code, sanitising both parts so a
// crafted base or code cannot break out of the redirect target.
func redirectFlash(w http.ResponseWriter, r *http.Request, base, key, code string) {
	q := url.Values{}
	if _, ok := flashMessages[code]; ok {
		q.Set(key, code)
	}
	target := base
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// sortedStrikeCounts returns the strike-bucket map as a slice with the
// deterministic order used by the CLI: "strike 1", "strike 2", …, then
// "permanent". Deterministic ordering keeps the template output stable
// across renders (important for tests and screenshots).
func sortedStrikeCounts(m map[string]int) []strikeCount {
	if len(m) == 0 {
		return nil
	}
	// Buckets are either "strike N" or "permanent"; iterate the CLI order.
	out := make([]strikeCount, 0, len(m))
	for n := 1; n <= 8; n++ {
		key := fmt.Sprintf("strike %d", n)
		if v, ok := m[key]; ok {
			out = append(out, strikeCount{Bucket: key, Count: v})
		}
	}
	if v, ok := m["permanent"]; ok {
		out = append(out, strikeCount{Bucket: "permanent", Count: v})
	}
	return out
}

// Compile-time check: the daemon.ErrDaemonUnreachable sentinel is the one
// isOffline consults, so a future rename in internal/daemon fails loud here
// rather than silently making every page render as "healthy".
var _ = errors.Is(daemon.ErrDaemonUnreachable, daemon.ErrDaemonUnreachable)
