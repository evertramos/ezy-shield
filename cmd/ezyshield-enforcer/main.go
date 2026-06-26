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
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	socketPath := flag.String("socket", "/run/ezyshield-enforcer/enforcer.sock", "path to the enforcer unix socket")
	flag.Parse()

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
