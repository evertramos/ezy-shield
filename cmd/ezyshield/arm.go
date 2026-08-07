package main

// arm.go — explicit arm/disarm commands (issue #228). Arming is the single
// most dangerous moment of the product's lifecycle; `arm` fronts it with a
// daemon-side pre-flight, and `--for` adds an auto-revert window that
// survives losing the SSH session (the revert runs in the daemon).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newArmCmd() *cobra.Command {
	var socketPath, forWindow string
	var keep, force bool

	cmd := &cobra.Command{
		Use:   "arm",
		Short: "Arm enforcement after a mandatory pre-flight",
		Long: `Flip the daemon from dry-run to live enforcement.

A pre-flight runs first: enforcer health, allowlist/admin_cidrs coverage,
a "would I ban myself?" simulation for your own client IP, and a summary
of recent dry-run activity. Failing checks refuse the transition; --force
overrides everything except the self-ban check.

--for arms temporarily: unless you confirm with 'ezyshield arm --keep'
before the window expires, the daemon reverts to dry-run by itself and
notifies. The revert is daemon-side — it fires even if you lose this
session.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if keep && (forWindow != "" || force) {
				return fmt.Errorf("--keep confirms an existing window and cannot be combined with --for/--force")
			}
			if keep {
				return runArmKeep(cmd, socketPath)
			}
			return runArm(cmd, socketPath, forWindow, force)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().StringVar(&forWindow, "for", "",
		"arm temporarily (e.g. 1h, 24h): auto-reverts to dry-run unless confirmed with --keep")
	cmd.Flags().BoolVar(&keep, "keep", false,
		"confirm the active arm window — armed becomes unconditional")
	cmd.Flags().BoolVar(&force, "force", false,
		"arm despite failing pre-flight checks (the self-ban check is never bypassable)")

	return cmd
}

func newDisarmCmd() *cobra.Command {
	var socketPath string

	cmd := &cobra.Command{
		Use:   "disarm",
		Short: "Return to dry-run mode",
		Long: `Flip the daemon back to dry-run (armed: false). No pre-flight —
moving toward dry-run is always the safe direction. The transition is
persisted to policy.yaml and audited.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := daemonRPC(context.Background(), socketPath, daemon.SocketRequest{Verb: "disarm"})
			if err != nil {
				return err
			}
			if resp.Error != "" {
				return fmt.Errorf("%s", resp.Error)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "disarmed — daemon is back in dry-run mode") //nolint:errcheck
			return nil
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	return cmd
}

func runArm(cmd *cobra.Command, socketPath, forWindow string, force bool) error {
	req := daemon.SocketRequest{
		Verb:  "arm",
		For:   forWindow,
		Force: force,
		Peer:  sshClientPeer(),
	}
	// A refusal is a non-OK response WITH a payload (the pre-flight report).
	// daemonRPC surfaces it as resp+err together — keep going so the
	// operator sees WHICH checks failed, then exit non-zero.
	resp, err := daemonRPC(context.Background(), socketPath, req)
	if resp == nil {
		return err // unreachable daemon or transport failure
	}

	var data daemon.ArmData
	if len(resp.Data) > 0 {
		if uerr := json.Unmarshal(resp.Data, &data); uerr != nil {
			return fmt.Errorf("parse arm response: %w", uerr)
		}
	}

	if jsonOutput {
		if resp.Error != "" {
			// Refusals carry the pre-flight report alongside the error.
			out := struct {
				daemon.ArmData
				Error string `json:"error"`
			}{data, resp.Error}
			if werr := writeJSON(cmd.OutOrStdout(), out); werr != nil {
				return werr
			}
			return fmt.Errorf("arming refused")
		}
		return writeJSON(cmd.OutOrStdout(), data)
	}

	printPreflight(cmd, data.Checks)
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}

	w := cmd.OutOrStdout()
	fmt.Fprintln(w) //nolint:errcheck
	if data.RevertAt != "" {
		fmt.Fprintf(w, "ARMED until %s — confirm with 'ezyshield arm --keep' to keep enforcement on,\n", data.RevertAt) //nolint:errcheck
		fmt.Fprintln(w, "or do nothing and the daemon reverts to dry-run automatically.")                               //nolint:errcheck
	} else {
		fmt.Fprintln(w, "ARMED — enforcement is live. 'ezyshield disarm' returns to dry-run.") //nolint:errcheck
	}
	return nil
}

func runArmKeep(cmd *cobra.Command, socketPath string) error {
	resp, err := daemonRPC(context.Background(), socketPath, daemon.SocketRequest{Verb: "arm_keep"})
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "confirmed — armed is now unconditional (auto-revert window cleared)") //nolint:errcheck
	return nil
}

// printPreflight renders the pre-flight report, one line per check.
func printPreflight(cmd *cobra.Command, checks []daemon.PreflightCheck) {
	if len(checks) == 0 {
		return
	}
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "pre-flight:") //nolint:errcheck
	for _, c := range checks {
		marker := "?"
		switch c.Status {
		case "pass":
			marker = "✓"
		case "warn":
			marker = "!"
		case "fail":
			marker = "✗"
		}
		fmt.Fprintf(w, "  %s %-18s %s\n", marker, c.Name, c.Detail) //nolint:errcheck
	}
}

// sshClientPeer returns this process's SSH client IP from SSH_CLIENT
// ("IP srcport dstport"), or "" when unavailable. Sent to the daemon so the
// self-ban pre-flight can verify the operator's own session would survive
// enforcement.
func sshClientPeer() string {
	fields := strings.Fields(os.Getenv("SSH_CLIENT"))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
