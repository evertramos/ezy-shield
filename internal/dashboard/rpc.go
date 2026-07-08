package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// rpcTimeout caps every dashboard-initiated daemon RPC. It is short so a
// page render fails fast when the daemon is down instead of blocking the
// browser for the daemon package's default 5 s dial budget.
const rpcTimeout = 2 * time.Second

// callDaemon is the single choke point through which dashboard handlers
// reach the daemon. It applies rpcTimeout, forwards to daemon.Call, and
// returns daemon.ErrDaemonUnreachable unchanged so handlers can render an
// offline panel with errors.Is.
func (s *Server) callDaemon(ctx context.Context, req daemon.SocketRequest) (*daemon.SocketResponse, error) {
	if s.cfg.DaemonSocketPath == "" {
		return nil, fmt.Errorf("%w: daemon socket not configured", daemon.ErrDaemonUnreachable)
	}
	callCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	return daemon.Call(callCtx, s.cfg.DaemonSocketPath, req)
}

func (s *Server) fetchStatus(ctx context.Context) (daemon.StatusData, error) {
	var sd daemon.StatusData
	resp, err := s.callDaemon(ctx, daemon.SocketRequest{Verb: "status"})
	if err != nil {
		return sd, err
	}
	if err := json.Unmarshal(resp.Data, &sd); err != nil {
		return sd, fmt.Errorf("parse status response: %w", err)
	}
	return sd, nil
}

func (s *Server) fetchBans(ctx context.Context) ([]daemon.BanEntry, error) {
	resp, err := s.callDaemon(ctx, daemon.SocketRequest{Verb: "list"})
	if err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 {
		return nil, nil
	}
	var entries []daemon.BanEntry
	if err := json.Unmarshal(resp.Data, &entries); err != nil {
		return nil, fmt.Errorf("parse list response: %w", err)
	}
	return entries, nil
}

func (s *Server) fetchAllows(ctx context.Context) ([]daemon.AllowEntry, error) {
	resp, err := s.callDaemon(ctx, daemon.SocketRequest{Verb: "list_allow"})
	if err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 {
		return nil, nil
	}
	var entries []daemon.AllowEntry
	if err := json.Unmarshal(resp.Data, &entries); err != nil {
		return nil, fmt.Errorf("parse list_allow response: %w", err)
	}
	return entries, nil
}

// bansByStrike aggregates a slice of bans into strike-bucket → count. Empty
// input returns an empty map so the caller can range over it without a nil
// check. The bucket key format matches the CLI ("strike N" / "permanent")
// so the maintainer's existing dashboards read the same labels.
func bansByStrike(entries []daemon.BanEntry) map[string]int {
	out := make(map[string]int)
	for _, e := range entries {
		out[strikeBucket(e.Strike, e.TTL)]++
	}
	return out
}

func strikeBucket(strike int, ttl string) string {
	if strike == 0 || ttl == "permanent" {
		return "permanent"
	}
	return fmt.Sprintf("strike %d", strike)
}

// callBan / callUnban / callAllow are the write-side wrappers. They exist
// so handler code stays free of the daemon.SocketRequest boilerplate and
// so tests can assert on the exact verb + payload delivered to the socket.
func (s *Server) callBan(ctx context.Context, target, reason string) error {
	_, err := s.callDaemon(ctx, daemon.SocketRequest{Verb: "ban", IP: target, Reason: reason})
	return err
}

func (s *Server) callUnban(ctx context.Context, target string) error {
	_, err := s.callDaemon(ctx, daemon.SocketRequest{Verb: "unban", IP: target})
	return err
}

func (s *Server) callAllow(ctx context.Context, target, reason string) error {
	_, err := s.callDaemon(ctx, daemon.SocketRequest{Verb: "allow", IP: target, Reason: reason})
	return err
}

// isOffline reports whether err is a daemon-unreachable error (dial refused,
// no socket configured, timeout). Handlers use this to swap in the offline
// panel instead of surfacing a raw syscall message.
func isOffline(err error) bool {
	return errors.Is(err, daemon.ErrDaemonUnreachable)
}
