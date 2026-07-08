package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// Flash codes rendered by pages when a POST redirected here after an action.
// Only keys in this map are considered — anything else is silently ignored so
// crafted URLs cannot inject arbitrary strings into the UI.
var flashMessages = map[string]string{
	"invalid-ip":     "Invalid IP or CIDR — nothing was sent to the daemon.",
	"missing-ip":     "IP or CIDR is required.",
	"bad-form":       "Malformed form submission.",
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

	if err := renderStatusPage(w, data); err != nil {
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
	if err := renderBansPage(w, data); err != nil {
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
	if err := renderAllowlistPage(w, data); err != nil {
		s.logger.Error("render allowlist", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleBanPost validates the IP form field, dispatches "ban" via the
// daemon RPC, and redirects back to /dashboard/bans with a flash code.
// Reason is passed through untouched (rendered via html/template only, so
// auto-escaping handles any hostile content).
func (s *Server) handleBanPost(w http.ResponseWriter, r *http.Request) {
	target, reason, code := parseTargetForm(r)
	if code != "" {
		redirectFlash(w, r, "/dashboard/bans", "err", code)
		return
	}
	code = s.doWrite(r.Context(), func(ctx context.Context) error {
		return s.callBan(ctx, target, reason)
	})
	if code != "" {
		redirectFlash(w, r, "/dashboard/bans", "err", code)
		return
	}
	redirectFlash(w, r, "/dashboard/bans", "ok", "ban-queued")
}

func (s *Server) handleUnbanPost(w http.ResponseWriter, r *http.Request) {
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
	target, reason, code := parseTargetForm(r)
	if code != "" {
		redirectFlash(w, r, "/dashboard/allowlist", "err", code)
		return
	}
	code = s.doWrite(r.Context(), func(ctx context.Context) error {
		return s.callAllow(ctx, target, reason)
	})
	if code != "" {
		redirectFlash(w, r, "/dashboard/allowlist", "err", code)
		return
	}
	redirectFlash(w, r, "/dashboard/allowlist", "ok", "allow-added")
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
	return target, reason, ""
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
