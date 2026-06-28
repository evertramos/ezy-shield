// ezyshield-enforcer is the privileged helper that applies nftables rules on
// behalf of the main ezyshield daemon.
//
// It holds CAP_NET_ADMIN (via systemd AmbientCapabilities) while the main
// daemon runs as an unprivileged user.  Communication is over a root-owned
// unix socket (mode 0660, group ezyshield) using newline-delimited JSON.
//
// Accepted verbs: add, del, flush, list, ping — anything else is rejected.
// IP arguments are validated as netip.Addr / netip.Prefix; raw nft syntax
// is never accepted (AGENTS.md §3 / SECURITY-REVIEW.md §3).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// Injected via -ldflags at build time; see Makefile.
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

	srv := newServer(*socketPath, realNftRunner)

	if err := srv.listen(ctx); err != nil {
		slog.Error("enforcer: listen", "err", err)
		os.Exit(1)
	}

	if err := srv.init(ctx); err != nil {
		slog.Error("enforcer: init", "err", err)
		os.Exit(1)
	}

	slog.Info("enforcer: ready", "socket", *socketPath)

	if err := srv.serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("enforcer: serve", "err", err)
		os.Exit(1)
	}

	slog.Info("enforcer: shutdown complete")
}
