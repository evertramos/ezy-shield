package main

// `ezyshield disable` — the panic button family (issue #176):
//
//	disable              → disarm only (same as `disarm`)
//	disable --all        → disarm + remove every active block everywhere
//	disable --local-only → flush the LOCAL nftables sets via the enforcer
//	                       helper directly (daemon not involved), edge as-is
//	enable               → re-arm (alias for `arm`, full pre-flight)
//
// Everything mutating sits behind a unix socket (daemon 0660 or the
// enforcer helper 0660) — there is deliberately no config flag that can
// trigger any of this, and every action is audited.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
	"github.com/evertramos/ezy-shield/internal/enforce"
)

func newDisableCmd() *cobra.Command {
	var (
		socketPath   string
		all          bool
		localOnly    bool
		yes          bool
		enfSocketArg string
	)

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disarm — or, with --all, remove every active block everywhere",
		Long: `One-command recovery when something goes wrong (false positives, a
locked-out colleague, a broken rule).

Without flags: disarm only (identical to '` + progName + ` disarm').

--all: disarm the daemon AND remove every active block from every
configured enforcer — the local nftables sets are emptied via the enforcer
helper and edge enforcers (Cloudflare) empty through their reconcile path.
Ban history and strikes are preserved; '` + progName + ` enable' (or 'arm')
re-arms later without re-applying anything.

--local-only: emergency flush of the LOCAL nftables sets, talking straight
to the enforcer helper socket — works even when the daemon is down. Edge
blocks stay as-is, and if the daemon IS running its next reconcile will
re-apply active bans within about a minute; follow up with 'allow',
'unban', or 'disable --all'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if all && localOnly {
				return fmt.Errorf("--all and --local-only are mutually exclusive")
			}
			switch {
			case all:
				return runDisableAll(cmd, socketPath, yes)
			case localOnly:
				return runDisableLocal(cmd, enfSocketArg, yes)
			default:
				return runDisarmVerb(cmd, socketPath)
			}
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().StringVar(&enfSocketArg, "enforcer-socket", enforcerSockPath,
		"path to the enforcer helper socket (--local-only)")
	cmd.Flags().BoolVar(&all, "all", false,
		"disarm AND remove every active block from every enforcer")
	cmd.Flags().BoolVar(&localOnly, "local-only", false,
		"flush local nftables enforcement only, via the helper directly; edge unchanged")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")

	return cmd
}

// newEnableCmd re-arms: a discoverable alias for `arm` (full pre-flight
// applies — enable is never a shortcut past the safety checks).
func newEnableCmd() *cobra.Command {
	armCmd := newArmCmd()
	armCmd.Use = "enable"
	armCmd.Short = "Re-arm enforcement (alias for 'arm', full pre-flight)"
	armCmd.Long = `Re-arm enforcement after 'disable'. Identical to '` + progName + ` arm':
the mandatory pre-flight runs, the transition is persisted and audited, and
nothing previously cleared by 'disable --all' is re-applied (those bans are
gone from the store; only new detections create new bans).`
	return armCmd
}

// confirmOrAbort prompts unless yes; returns false when the operator declined.
func confirmOrAbort(cmd *cobra.Command, yes bool, what string) bool {
	if yes {
		return true
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s\nProceed? [y/N]: ", what) //nolint:errcheck
	var answer string
	_, _ = fmt.Fscanln(cmd.InOrStdin(), &answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y")
}

func runDisableAll(cmd *cobra.Command, socketPath string, yes bool) error {
	if !confirmOrAbort(cmd, yes,
		"This disarms the daemon and removes EVERY active block (local nftables + edge).\n"+
			"Ban history is preserved; nothing is re-applied on re-arm.") {
		fmt.Fprintln(cmd.OutOrStdout(), "aborted — nothing changed") //nolint:errcheck
		return nil
	}
	resp, err := daemonRPC(cmd.Context(), socketPath, daemon.SocketRequest{Verb: "disable_all"})
	if err != nil {
		printDisableFallback(cmd)
		return err
	}
	if resp.Error != "" {
		// Partial success carries Data alongside the error — show both.
		if len(resp.Data) > 0 && jsonOutput {
			_ = writeJSON(cmd.OutOrStdout(), resp)
		}
		return fmt.Errorf("%s", resp.Error)
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}
	var data daemon.DisableAllData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "disarmed — daemon is in dry-run mode\n")                                    //nolint:errcheck
	fmt.Fprintf(out, "removed %d active ban(s); enforcers synced to empty\n", data.BansRemoved)   //nolint:errcheck
	fmt.Fprintf(out, "history and strikes preserved — re-arm later with '%s enable'\n", progName) //nolint:errcheck
	return nil
}

// runDisableLocal flushes the blocked sets via the enforcer helper directly.
// This is the break-glass path that works with the daemon down.
func runDisableLocal(cmd *cobra.Command, enfSocket string, yes bool) error {
	if !confirmOrAbort(cmd, yes,
		"This flushes the LOCAL nftables blocked sets via the enforcer helper.\n"+
			"Edge blocks stay; a running daemon will re-apply active bans on its next reconcile (~1 min).") {
		fmt.Fprintln(cmd.OutOrStdout(), "aborted — nothing changed") //nolint:errcheck
		return nil
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", enfSocket)
	if err != nil {
		printDisableFallback(cmd)
		return fmt.Errorf("enforcer helper unreachable at %s: %w", enfSocket, err)
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(enforce.Request{Verb: "flush"}); err != nil {
		return fmt.Errorf("send flush: %w", err)
	}
	var resp enforce.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("read flush response: %w", err)
	}
	if !resp.OK {
		printDisableFallback(cmd)
		return fmt.Errorf("helper flush failed: %s", resp.Error)
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), map[string]any{"flushed": true, "scope": "local"})
	}
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "local nftables blocked sets flushed (edge unchanged)")                               //nolint:errcheck
	fmt.Fprintln(out, "note: a running daemon re-applies active bans on its next reconcile (~1 min);")      //nolint:errcheck
	fmt.Fprintf(out, "      follow up with '%s allow <your-ip>', '%s unban <ip>', or '%s disable --all'\n", //nolint:errcheck
		progName, progName, progName)
	return nil
}

// runDisarmVerb is the flagless path — identical to `disarm`.
func runDisarmVerb(cmd *cobra.Command, socketPath string) error {
	resp, err := daemonRPC(cmd.Context(), socketPath, daemon.SocketRequest{Verb: "disarm"})
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), map[string]any{"armed": false, "status": "disarmed"})
	}
	fmt.Fprintln(cmd.OutOrStdout(), "disarmed — daemon is back in dry-run mode") //nolint:errcheck
	return nil
}

// printDisableFallback documents manual recovery for the worst case: both
// sockets down. Everything here is also in the docs ("when to reach for
// this"), but the emergency is exactly when nobody is reading docs.
func printDisableFallback(cmd *cobra.Command) {
	err := cmd.ErrOrStderr()
	fmt.Fprintln(err, "")                                                                   //nolint:errcheck
	fmt.Fprintln(err, "manual recovery (daemon/helper unreachable):")                       //nolint:errcheck
	fmt.Fprintln(err, "  # stop new bans:")                                                 //nolint:errcheck
	fmt.Fprintln(err, "  sudo systemctl stop ezyshield")                                    //nolint:errcheck
	fmt.Fprintln(err, "  # remove all local blocks (default table/set names):")             //nolint:errcheck
	fmt.Fprintln(err, "  sudo nft flush set inet ezyshield blocked")                        //nolint:errcheck
	fmt.Fprintln(err, "  sudo nft flush set inet ezyshield blocked6")                       //nolint:errcheck
	fmt.Fprintln(err, "  # edge blocks (Cloudflare): empty the ezyshield_blocked IP list")  //nolint:errcheck
	fmt.Fprintln(err, "  # in the dashboard, or restart the daemon disarmed to reconcile.") //nolint:errcheck
	fmt.Fprintln(err, "  # keep dry-run on restart: set 'armed: false' in policy.yaml")     //nolint:errcheck
}
