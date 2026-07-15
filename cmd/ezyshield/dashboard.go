package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/daemon"
	"github.com/evertramos/ezy-shield/internal/dashboard"
)

const defaultConfigPath = "/etc/ezyshield/config.yaml"

func newDashboardCmd() *cobra.Command {
	var configPath, addr, authDB, daemonSock string

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Serve the localhost-only web dashboard",
		Long: `Start the EzyShield dashboard.

The dashboard binds exclusively to a loopback address (127.0.0.1 or ::1).
Any non-loopback bind — including 0.0.0.0 — is refused at startup.

The dashboard reads live data (status, active bans, allowlist) from the
daemon over its unix socket. If the daemon is not running, pages still
render but show an "offline" banner.

For remote access, use an operator-managed tunnel such as an SSH port
forward or a Cloudflare Tunnel. See docs/dashboard.md.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDashboard(cmd.Context(), cmd.OutOrStderr(), configPath, addr, authDB, daemonSock)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath, "path to config.yaml")
	cmd.Flags().StringVar(&addr, "addr", "", "override bind address (defaults to config, else 127.0.0.1:9090)")
	cmd.Flags().StringVar(&authDB, "auth-db", "", "override auth DB path (defaults to <data_dir>/dashboard.db)")
	cmd.Flags().StringVar(&daemonSock, "socket", "", "override daemon control socket path (defaults to config, else "+daemon.DefaultSocketPath+")")
	return cmd
}

func runDashboard(ctx context.Context, stderr io.Writer, configPath, addrOverride, authDBOverride, daemonSockOverride string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Config is optional at dashboard startup: operators can dogfood the UI
	// against defaults before the daemon is even initialised. Any error
	// other than "not present" surfaces so a broken config is not silently
	// ignored.
	var cfg *config.Config
	if c, err := config.LoadConfig(configPath); err == nil {
		cfg = c
	} else if !os.IsNotExist(err) {
		return err
	} else {
		cfg = &config.Config{}
	}
	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "/var/lib/ezyshield"
	}

	addr := dashboard.DefaultAddr
	if cfg.Dashboard != nil && cfg.Dashboard.Addr != "" {
		addr = cfg.Dashboard.Addr
	}
	if addrOverride != "" {
		addr = addrOverride
	}
	authDB := filepath.Join(dataDir, "dashboard.db")
	if cfg.Dashboard != nil && cfg.Dashboard.AuthDBPath != "" {
		authDB = cfg.Dashboard.AuthDBPath
	}
	if authDBOverride != "" {
		authDB = authDBOverride
	}
	daemonSock := daemon.DefaultSocketPath
	if cfg.SocketPath != "" {
		daemonSock = cfg.SocketPath
	}
	if daemonSockOverride != "" {
		daemonSock = daemonSockOverride
	}

	srv, err := dashboard.New(dashboard.Config{
		Addr:             addr,
		AuthDBPath:       authDB,
		DaemonSocketPath: daemonSock,
		Logger:           slog.Default(),
	})
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	pw, created, err := srv.EnsureAdmin(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	if created {
		isTTY := term.IsTerminal(int(os.Stderr.Fd()))
		if err := emitBootstrapCredentials(stderr, isTTY, pw, authDB); err != nil {
			return err
		}
	}

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return srv.Run(sigCtx)
}

// emitBootstrapCredentials delivers the first-run admin password. On an
// interactive stderr it prints the banner inline, exactly as before. When
// stderr is not a TTY (systemd, docker, cron, redirection) the plaintext
// would be captured on disk by journald / docker logs, so the password is
// written to a 0600 file next to the auth DB and only the path is printed
// (issue #89) — the captured log line contains no secret.
func emitBootstrapCredentials(w io.Writer, isTTY bool, password, authDBPath string) error {
	if isTTY {
		printBootstrapCredentials(w, password, authDBPath)
		return nil
	}
	path := filepath.Join(filepath.Dir(authDBPath), "dashboard.first-run-password")
	if err := writePasswordFile(path, password); err != nil {
		return fmt.Errorf("dashboard: write initial password file %s: %w", path, err)
	}
	fmt.Fprintln(w, "EzyShield dashboard: admin account created (username: admin).")   //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "stderr is not a terminal — the initial password was written to:") //nolint:errcheck // stderr banner
	fmt.Fprintln(w, " ", path, "(mode 0600)")                                          //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "Read it once and remove it:")                                     //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "  sudo cat", path, "&& sudo rm", path)                            //nolint:errcheck // stderr banner
	return nil
}

// writePasswordFile creates path with O_EXCL so a still-unread password from
// a previous run is never clobbered, and chmods 0600 explicitly as
// belt-and-suspenders against permissive umask setups. Any failure after
// creation removes the file: a partial write must never leave a truncated
// password an operator could mistake for the real one, and a leftover file
// would block the O_EXCL retry path. The remove is safe — O_EXCL succeeding
// proves this call created the file.
func writePasswordFile(path, password string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600) //nolint:gosec // path is derived from the admin-controlled auth DB location
	if err != nil {
		return err
	}
	if _, err := f.WriteString(password + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		// A failed close can mean buffered bytes never hit the disk — the
		// file content is untrustworthy, so it goes too.
		_ = os.Remove(path)
		return err
	}
	return nil
}

func printBootstrapCredentials(w io.Writer, password, authDBPath string) {
	fmt.Fprintln(w, "======================================================================") //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "EzyShield dashboard: admin account created.")                            //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "  Username: admin")                                                      //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "  Password:", password)                                                  //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "STORE THIS PASSWORD NOW — it will not be shown again.")                  //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "To rotate the password, delete the auth DB and restart:")                //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "  rm", authDBPath)                                                       //nolint:errcheck // stderr banner
	fmt.Fprintln(w, "======================================================================") //nolint:errcheck // stderr banner
}
