package main

// The `watch` command — a live, read-only stream of daemon events over the
// unix control socket (issue #105). `watch` complements `list`: `list` is a
// point-in-time snapshot of active bans, `watch` follows detections, strikes,
// bans, unbans and allowlist changes as they happen.
//
// Security posture (docs/SECURITY-REVIEW.md):
//   - §6: the underlying "subscribe" verb is strictly read-only — no request
//     field can mutate daemon state.
//   - §1: every event field may embed content copied from hostile log lines,
//     so all fields pass through sanitizeField before touching the terminal.
//     In --json mode, encoding/json escapes every C0 control byte (ESC, CR,
//     LF included) as \uXXXX, so hostile bytes cannot break NDJSON line
//     framing or start a terminal escape sequence.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// maxReconnectBackoff caps the exponential retry delay when the daemon
// restarts underneath an active watch.
const maxReconnectBackoff = 30 * time.Second

// validEventKinds is the closed vocabulary accepted by --kind. It mirrors the
// daemon's StreamEvent kinds: "detection" plus the decision-engine ops.
var validEventKinds = map[string]bool{
	"detection":      true,
	"record":         true,
	"notify_only":    true,
	"dry_ban":        true,
	"ban":            true,
	"already_banned": true,
	"unban":          true,
	"allow":          true,
}

func newWatchCmd() *cobra.Command {
	var (
		socketPath string
		kinds      []string
		ipFilter   string
	)

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Stream live daemon events (detections, strikes, bans)",
		Long: `Stream live security events from the running daemon.

Follows the daemon's event feed in real time: detections, strike escalations,
bans, dry-run bans, unbans and allowlist changes. This is a live view — for a
point-in-time snapshot of active bans use the 'list' command instead.

Filters:
  --kind   only show the given event kinds (repeatable / comma-separated)
  --ip     only show events for one address or CIDR block

With --json, each event is printed as one JSON object per line (NDJSON),
suitable for piping into jq or a log shipper.

The daemon must be running — start it with the 'run' command or via systemd
(sudo systemctl start ezyshield). If the connection drops (e.g. daemon
restart), watch reconnects automatically with backoff. Press Ctrl-C to exit.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWatch(cmd, socketPath, kinds, ipFilter)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().StringSliceVar(&kinds, "kind", nil,
		"only show these event kinds ("+strings.Join(sortedEventKinds(), ", ")+")")
	cmd.Flags().StringVar(&ipFilter, "ip", "",
		"only show events for this IP address or CIDR block")

	return cmd
}

func runWatch(cmd *cobra.Command, socketPath string, kinds []string, ipFilter string) error {
	filter, err := newEventFilter(kinds, ipFilter)
	if err != nil {
		return err
	}

	// SIGINT/SIGTERM cancel the context; daemon.Subscribe closes its
	// connection via context.AfterFunc, so Ctrl-C exits promptly and cleanly.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()
	color := !jsonOutput && colorEnabled(out)

	// NDJSON: one compact JSON object per event, one per line. The encoder
	// escapes all C0 control bytes (ESC, CR, LF) as \uXXXX, so hostile bytes
	// in event fields cannot break line framing or inject escape sequences.
	enc := json.NewEncoder(out)

	onEvent := func(ev daemon.StreamEvent) {
		if !filter.match(ev) {
			return
		}
		if jsonOutput {
			_ = enc.Encode(ev)
			return
		}
		_, _ = fmt.Fprintln(out, formatEventLine(ev, color))
	}

	backoff := time.Second
	connectedOnce := false
	for {
		connectedThisAttempt := false
		err := daemon.Subscribe(ctx, socketPath, func() {
			connectedThisAttempt = true
			connectedOnce = true
			backoff = time.Second // healthy connection: reset backoff
			if !jsonOutput {
				_, _ = fmt.Fprintf(errOut, "watch: connected — streaming events (Ctrl-C to exit)\n")
			}
		}, onEvent)
		if err == nil || ctx.Err() != nil {
			return nil // clean shutdown (Ctrl-C)
		}
		if !connectedOnce {
			// Never got through: the daemon is almost certainly not running.
			// Fail fast with a friendly hint instead of retrying forever.
			_, _ = fmt.Fprintf(errOut,
				"EzyShield daemon is not running — start it with the 'run' command (systemd: sudo systemctl start ezyshield)\n")
			return err
		}
		// Stream dropped after a successful subscription (daemon restart?):
		// reconnect with capped exponential backoff. The error text can echo
		// bytes read from the socket, so sanitize before printing (§1).
		_, _ = fmt.Fprintf(errOut, "watch: connection lost (%s) — retrying in %s\n",
			sanitizeField(err.Error(), 200), backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if !connectedThisAttempt {
			backoff *= 2
			if backoff > maxReconnectBackoff {
				backoff = maxReconnectBackoff
			}
		}
	}
}

// eventFilter holds the client-side --kind/--ip filters. Filtering happens in
// the CLI, not the daemon, keeping the socket surface minimal (§6).
type eventFilter struct {
	kinds  map[string]bool // empty = all kinds
	prefix netip.Prefix
	hasIP  bool
}

func newEventFilter(kinds []string, ipFilter string) (*eventFilter, error) {
	f := &eventFilter{kinds: make(map[string]bool)}
	for _, k := range kinds {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if !validEventKinds[k] {
			return nil, fmt.Errorf("unknown event kind %q (available: %s)",
				k, strings.Join(sortedEventKinds(), ", "))
		}
		f.kinds[k] = true
	}
	if ipFilter != "" {
		if p, err := netip.ParsePrefix(ipFilter); err == nil {
			f.prefix = p.Masked()
			f.hasIP = true
		} else if a, err := netip.ParseAddr(ipFilter); err == nil {
			f.prefix = netip.PrefixFrom(a, a.BitLen())
			f.hasIP = true
		} else {
			return nil, fmt.Errorf("invalid --ip %q: not an IP address or CIDR", ipFilter)
		}
	}
	return f, nil
}

// match reports whether ev passes the kind and IP filters. Events whose IP
// field does not parse (or is empty) are dropped when an IP filter is active.
func (f *eventFilter) match(ev daemon.StreamEvent) bool {
	if len(f.kinds) > 0 && !f.kinds[ev.Kind] {
		return false
	}
	if !f.hasIP {
		return true
	}
	if p, err := netip.ParsePrefix(ev.IP); err == nil {
		return f.prefix.Overlaps(p)
	}
	if a, err := netip.ParseAddr(ev.IP); err == nil {
		return f.prefix.Contains(a)
	}
	return false
}

// sortedEventKinds returns the --kind vocabulary in stable order for help
// text and error messages.
func sortedEventKinds() []string {
	kinds := make([]string, 0, len(validEventKinds))
	for k := range validEventKinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

// formatEventLine renders one event as a single human-readable line. Every
// field is passed through sanitizeField — event fields can embed content
// copied from hostile log lines (§1 SECURITY-REVIEW), so nothing reaches the
// terminal unsanitized. The only escape sequences in the output are the ones
// this function itself emits (kindColor), and only when color is enabled.
func formatEventLine(ev daemon.StreamEvent, color bool) string {
	kind := sanitizeField(ev.Kind, 20)
	ip := sanitizeField(ev.IP, 43) // widest valid form: IPv6 + zone + /prefix

	var det []string
	if ev.Score != 0 {
		det = append(det, fmt.Sprintf("score=%d", ev.Score))
	}
	if ev.Category != "" {
		det = append(det, "category="+sanitizeField(ev.Category, 32))
	}
	if ev.Rule != "" {
		det = append(det, "rule="+sanitizeField(ev.Rule, 48))
	}
	if ev.Strike != 0 {
		det = append(det, fmt.Sprintf("strike=%d", ev.Strike))
	}
	if ev.TTL != "" {
		det = append(det, "ttl="+sanitizeField(ev.TTL, 16))
	}
	if ev.Enforcer != "" {
		det = append(det, "enforcer="+sanitizeField(ev.Enforcer, 32))
	}
	if ev.Source != "" {
		det = append(det, "source="+sanitizeField(ev.Source, 16))
	}
	if ev.Reason != "" {
		// Quote the reason: it is free-form text copied from log lines.
		det = append(det, "reason="+strconv.Quote(sanitizeField(ev.Reason, 120)))
	}

	padded := fmt.Sprintf("%-11s", kind)
	if color {
		padded = kindColor(ev.Kind) + padded + "\x1b[0m"
	}
	return fmt.Sprintf("%s  %s  %-15s  %s",
		eventClock(ev.Time), padded, ip, strings.Join(det, " "))
}

// eventClock renders the event timestamp as a local wall-clock time. The
// daemon always sends RFC 3339; anything else is untrusted and sanitized.
func eventClock(t string) string {
	if ts, err := time.Parse(time.RFC3339, t); err == nil {
		return ts.Local().Format("15:04:05")
	}
	return sanitizeField(t, 25)
}

// kindColor maps an event kind to an ANSI color by severity: red for real
// bans, yellow for would-ban/repeat, green for removals/allow, cyan for
// informational.
func kindColor(kind string) string {
	switch kind {
	case "ban":
		return "\x1b[31m" // red
	case "dry_ban", "notify_only", "already_banned":
		return "\x1b[33m" // yellow
	case "unban", "allow":
		return "\x1b[32m" // green
	default: // detection, record
		return "\x1b[36m" // cyan
	}
}
