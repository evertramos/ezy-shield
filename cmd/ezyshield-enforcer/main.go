// SPDX-License-Identifier: AGPL-3.0-only

// Command ezyshield-enforcer is the privileged nftables helper. All logic
// lives in internal/enforcerd so the integration harness can run the real
// helper in-process against a scripted kernel (issue #605); this file only
// parses flags and wires signals.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/evertramos/ezy-shield/internal/enforcerd"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	socketPath := flag.String("socket", "/run/ezyshield-enforcer/enforcer.sock", "path to the enforcer unix socket")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ezyshield-enforcer %s (commit: %s, built: %s)\n", version, commit, buildDate)
		return
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv := enforcerd.NewServer(*socketPath, enforcerd.RealNftRunner)
	if err := srv.Listen(ctx); err != nil {
		slog.Error("enforcer: listen", "err", err)
		os.Exit(1)
	}
	if err := srv.Init(ctx); err != nil {
		slog.Error("enforcer: init", "err", err)
		os.Exit(1)
	}
	if ssPath, err := exec.LookPath("ss"); err == nil {
		slog.Info("enforcer: ss detected; pre-ban TCP session teardown enabled", "path", ssPath)
	} else {
		slog.Warn("enforcer: ss binary not found on PATH; pre-ban TCP sessions will NOT be torn down (install iproute2)",
			"err", err.Error())
	}
	slog.Info("enforcer: ready", "socket", *socketPath)
	if err := srv.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("enforcer: serve", "err", err)
		os.Exit(1)
	}
	slog.Info("enforcer: shutdown complete")
}
