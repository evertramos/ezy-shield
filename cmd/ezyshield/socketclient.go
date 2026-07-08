package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

const dialTimeout = 5 * time.Second

// daemonRPC opens a connection to the daemon unix socket, sends req, and
// returns the parsed SocketResponse.  It returns a non-nil error if the
// connection fails or the daemon reports an error.
func daemonRPC(ctx context.Context, socketPath string, req daemon.SocketRequest) (*daemon.SocketResponse, error) {
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to daemon at %s: %w\n(Is 'ezyshield run' running?)", socketPath, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	var resp daemon.SocketResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if !resp.OK {
		return &resp, fmt.Errorf("daemon error: %s", resp.Error)
	}

	return &resp, nil
}
