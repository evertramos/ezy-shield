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

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/dashboard"
)

const defaultConfigPath = "/etc/ezyshield/config.yaml"

func newDashboardCmd() *cobra.Command {
	var configPath, addr, authDB string

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Serve the localhost-only web dashboard",
		Long: `Start the EzyShield dashboard.

The dashboard binds exclusively to a loopback address (127.0.0.1 or ::1).
Any non-loopback bind — including 0.0.0.0 — is refused at startup.

For remote access, use an operator-managed tunnel such as an SSH port
forward or a Cloudflare Tunnel. See docs/dashboard.md.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDashboard(cmd.Context(), cmd.OutOrStderr(), configPath, addr, authDB)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath, "path to config.yaml")
	cmd.Flags().StringVar(&addr, "addr", "", "override bind address (defaults to config, else 127.0.0.1:9090)")
	cmd.Flags().StringVar(&authDB, "auth-db", "", "override auth DB path (defaults to <data_dir>/dashboard.db)")
	return cmd
}

func runDashboard(ctx context.Context, stderr io.Writer, configPath, addrOverride, authDBOverride string) error {
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

	srv, err := dashboard.New(dashboard.Config{
		Addr:       addr,
		AuthDBPath: authDB,
		Logger:     slog.Default(),
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
		printBootstrapCredentials(stderr, pw, authDB)
	}

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return srv.Run(sigCtx)
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
