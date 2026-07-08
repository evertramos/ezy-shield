package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// daemonRPC is a thin wrapper around daemon.Call that keeps the CLI's
// friendly "is 'ezyshield watch' running?" hint when the socket refuses
// the connection. New callers should use daemon.Call directly.
func daemonRPC(ctx context.Context, socketPath string, req daemon.SocketRequest) (*daemon.SocketResponse, error) {
	resp, err := daemon.Call(ctx, socketPath, req)
	if err != nil {
		if errors.Is(err, daemon.ErrDaemonUnreachable) {
			return nil, fmt.Errorf("cannot connect to daemon at %s: %w\n(Is 'ezyshield watch' running?)", socketPath, err)
		}
		return resp, err
	}
	return resp, nil
}
