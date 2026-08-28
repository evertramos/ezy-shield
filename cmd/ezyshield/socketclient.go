// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// daemonRPC is a thin wrapper around daemon.Call that keeps the CLI's
// friendly "is '<prog> run' running?" hint when the socket refuses
// the connection, and transparently falls back to the read-only socket
// (issue #212) when the operator socket denies permission — so a member of
// the ezyshield-view group can run the read commands with no extra flags.
// New callers should use daemon.Call directly.
func daemonRPC(ctx context.Context, socketPath string, req daemon.SocketRequest) (*daemon.SocketResponse, error) {
	resp, err := daemon.Call(ctx, socketPath, req)
	if err != nil {
		if roResp, ok, roErr := roFallback(ctx, socketPath, req, err); ok {
			return roResp, roErr
		}
		if errors.Is(err, daemon.ErrDaemonUnreachable) {
			return nil, fmt.Errorf("cannot connect to daemon at %s: %w\n(Is '%s run' running?)", socketPath, err, progName)
		}
		return resp, err
	}
	return resp, nil
}

// roFallback retries req against the read-only companion socket when the
// primary socket denied permission (viewer-tier caller). ok reports whether
// the fallback path applied at all: it does only for a permission-denied
// dial, and the result then replaces the original outcome — including a
// daemon-side refusal ("read-only socket: verb ... requires the operator
// socket"), which is the honest error for a viewer issuing a write verb.
func roFallback(ctx context.Context, socketPath string, req daemon.SocketRequest, err error) (*daemon.SocketResponse, bool, error) {
	if !errors.Is(err, daemon.ErrDaemonUnreachable) || !errors.Is(err, fs.ErrPermission) {
		return nil, false, nil
	}
	roPath := daemon.ROSocketPath(socketPath)
	if roPath == socketPath {
		return nil, false, nil
	}
	resp, roErr := daemon.Call(ctx, roPath, req)
	if roErr != nil && errors.Is(roErr, daemon.ErrDaemonUnreachable) {
		// The RO socket is not usable either — surface the original error.
		return nil, false, nil
	}
	return resp, true, roErr
}

// resolveReadSocket returns the socket path a read-only stream (watch)
// should dial: the primary socket normally, or the read-only companion when
// the primary denies permission to this user (issue #212) and the RO socket
// answers. Probed once with a cheap "status" call.
func resolveReadSocket(ctx context.Context, socketPath string) string {
	_, err := daemon.Call(ctx, socketPath, daemon.SocketRequest{Verb: "status"})
	if err == nil || !errors.Is(err, daemon.ErrDaemonUnreachable) || !errors.Is(err, fs.ErrPermission) {
		return socketPath
	}
	roPath := daemon.ROSocketPath(socketPath)
	if roPath == socketPath {
		return socketPath
	}
	if _, roErr := daemon.Call(ctx, roPath, daemon.SocketRequest{Verb: "status"}); roErr != nil && errors.Is(roErr, daemon.ErrDaemonUnreachable) {
		return socketPath
	}
	return roPath
}
