package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	var socketPath string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		Long:  `Connect to the EzyShield daemon socket and print its current status.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd, socketPath)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", "/run/ezyshield/ezyshield.sock",
		"path to daemon control socket")

	return cmd
}

func runStatus(cmd *cobra.Command, socketPath string) error {
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return printStatus(cmd, "stopped", "daemon not running")
	}

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		return printStatus(cmd, "stopped", fmt.Sprintf("socket exists but cannot connect: %v", err))
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf("closing probe connection: %w", err)
	}

	return printStatus(cmd, "running", "")
}

func printStatus(cmd *cobra.Command, status, message string) error {
	if jsonOutput {
		payload := map[string]string{"status": status}
		if message != "" {
			payload["message"] = message
		}
		return writeJSON(cmd.OutOrStdout(), payload)
	}

	var err error
	if message != "" {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), message)
	} else {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "status: %s\n", status)
	}
	return err
}
