// SPDX-License-Identifier: AGPL-3.0-only

package decision

// Authenticated-peer narrowing of the SSH anti-lockout (ADR-0013, issue
// #560): with policy `anti_lockout.require_authenticated: true`, an
// ESTABLISHED SSH peer is immune to bans only when systemd-logind also
// reports a session whose RemoteHost is that IP — i.e. someone actually
// LOGGED IN on it. A connection parked in sshd's "Timeout before
// authentication" (the #559 kylian attack) has no logind session and
// loses the free immunity it enjoys today.
//
// Every failure mode fails OPEN, toward the operator (Hard Rule 1):
//   - loginctl missing, erroring, or timing out  → no narrowing at all
//     (today's ESTABLISHED-only behavior);
//   - a RemoteHost value that does not parse as an IP (UseDNS yes hosts)
//     → the whole probe reports unavailable, same fallback;
//   - a peer whose connection appeared less than GraceWindow ago is kept
//     immune even without a session yet — covering the race where a login
//     completes milliseconds before the probe reads logind. The #420
//     deferred re-check naturally re-evaluates after the grace expires,
//     which is when a held-but-never-authenticated socket becomes
//     bannable.
//
// Read-only throughout: two loginctl invocations, cached, unprivileged.

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// AuthPeerGraceWindow keeps a brand-new ESTABLISHED connection immune
	// while its login may still be completing. Well above any realistic
	// auth handshake, far below the attack's useful hold time.
	AuthPeerGraceWindow = 10 * time.Second
	// logindCacheTTL bounds how often loginctl is invoked on the hot path.
	logindCacheTTL = 5 * time.Second
	// logindCallTimeout bounds one loginctl invocation.
	logindCallTimeout = time.Second
)

// execLoginctl runs loginctl with args; a variable so tests inject fixture
// output without systemd.
var execLoginctl = func(ctx context.Context, args ...string) ([]byte, error) {
	if _, err := exec.LookPath("loginctl"); err != nil {
		return nil, err
	}
	// G204: fixed binary, fixed subcommands, session IDs come from
	// loginctl's own output — nothing user- or log-controlled.
	return exec.CommandContext(ctx, "loginctl", args...).Output() //nolint:gosec
}

// logindRemoteHosts returns the set of remote IPs with a logind session
// (any state — presence proves authentication happened), and ok=false when
// the answer cannot be trusted: loginctl unavailable/failing, or a
// RemoteHost that is not an IP (the caller then skips narrowing entirely).
func logindRemoteHosts(ctx context.Context) (map[netip.Addr]bool, bool) {
	listCtx, cancel := context.WithTimeout(ctx, logindCallTimeout)
	defer cancel()
	out, err := execLoginctl(listCtx, "list-sessions", "--no-legend")
	if err != nil {
		return nil, false
	}
	var ids []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			ids = append(ids, fields[0])
		}
	}
	hosts := map[netip.Addr]bool{}
	if len(ids) == 0 {
		return hosts, true
	}

	showCtx, cancel2 := context.WithTimeout(ctx, logindCallTimeout)
	defer cancel2()
	args := append([]string{"show-session", "--property=RemoteHost", "--value"}, ids...)
	out, err = execLoginctl(showCtx, args...)
	if err != nil {
		return nil, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		v := strings.TrimSpace(line)
		if v == "" {
			continue // local session (no RemoteHost)
		}
		addr, perr := netip.ParseAddr(v)
		if perr != nil {
			// A hostname (UseDNS yes) means we cannot match sessions to
			// peers reliably — narrowing anything here could strip a real
			// operator's immunity. Fail open: report unavailable.
			return nil, false
		}
		hosts[addr.Unmap()] = true
	}
	return hosts, true
}

// NewLogindSessionProbe returns a TTL-cached logind reader for the filter.
func NewLogindSessionProbe() func() (map[netip.Addr]bool, bool) {
	var mu sync.Mutex
	var cached map[netip.Addr]bool
	var cachedOK bool
	var fetched time.Time
	return func() (map[netip.Addr]bool, bool) {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(fetched) < logindCacheTTL {
			return cached, cachedOK
		}
		cached, cachedOK = logindRemoteHosts(context.Background())
		fetched = time.Now()
		return cached, cachedOK
	}
}

// AuthenticatedPeerFilter narrows a base ESTABLISHED-peer probe to
// authenticated peers per ADR-0013. It plugs into
// Engine.SetSSHPeerProbe, so BOTH immunity layers (decision engine and
// enforcement gate) see the narrowed set from one source.
type AuthenticatedPeerFilter struct {
	base     func() []netip.Addr
	sessions func() (map[netip.Addr]bool, bool)
	grace    time.Duration
	now      func() time.Time

	mu        sync.Mutex
	firstSeen map[netip.Addr]time.Time
}

// NewAuthenticatedPeerFilter builds the filter. base is the kernel probe
// (ProcSSHPeers in production); sessions the (cached) logind reader; grace
// the new-connection window (AuthPeerGraceWindow in production).
func NewAuthenticatedPeerFilter(base func() []netip.Addr, sessions func() (map[netip.Addr]bool, bool), grace time.Duration) *AuthenticatedPeerFilter {
	return &AuthenticatedPeerFilter{
		base:      base,
		sessions:  sessions,
		grace:     grace,
		now:       time.Now,
		firstSeen: map[netip.Addr]time.Time{},
	}
}

// Peers implements the probe contract: the ESTABLISHED peers that keep
// anti-lockout immunity under ADR-0013.
func (f *AuthenticatedPeerFilter) Peers() []netip.Addr {
	established := f.base()

	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()

	// Track connection first-sight; prune addresses no longer established
	// so a reconnect starts a fresh grace window.
	current := make(map[netip.Addr]bool, len(established))
	for _, p := range established {
		key := p.Unmap()
		current[key] = true
		if _, ok := f.firstSeen[key]; !ok {
			f.firstSeen[key] = now
		}
	}
	for addr := range f.firstSeen {
		if !current[addr] {
			delete(f.firstSeen, addr)
		}
	}

	sessions, ok := f.sessions()
	if !ok {
		// Fail open (ADR-0013 §2): without a trustworthy logind answer,
		// narrowing is disabled entirely — today's behavior.
		return established
	}

	kept := established[:0]
	for _, p := range established {
		key := p.Unmap()
		if sessions[key] || now.Sub(f.firstSeen[key]) <= f.grace {
			kept = append(kept, p)
		}
	}
	return kept
}
