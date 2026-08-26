// SPDX-License-Identifier: AGPL-3.0-only

package main

// `ezyshield plugins` (issue #207): list discovered tier-1 plugins and
// dry-validate a plugin directory for authors. Listing never executes
// anything; validate performs exactly one handshake and kills the process.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/plugin"
)

func newPluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Inspect tier-1 plugins (executables in plugins.d)",
	}
	cmd.AddCommand(newPluginsListCmd(), newPluginsValidateCmd())
	return cmd
}

// pluginRow is the stable --json shape for one discovered plugin.
type pluginRow struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

func newPluginsListCmd() *cobra.Command {
	var configPath = defaultConfigDir + "/config.yaml"
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List discovered plugins and their status (never executes them)",
		Long: `List every plugins.d entry with its name, version, type and status:
ready (valid + allowlisted), not-allowed (valid but absent from
plugins.allow), or invalid (manifest failed validation, with the reason).

Plugins run only when plugins.enabled is true in config.yaml AND the name
is listed in plugins.allow — dropping files into plugins.d is never
enough to execute code. The network declaration in module.yaml is
advisory in v1 (documented, not yet enforced).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPluginsList(cmd, configPath, cmd.Flags().Changed("config"))
		},
	}
	cmd.Flags().StringVar(&configPath, "config", configPath, "path to config.yaml")
	return cmd
}

func runPluginsList(cmd *cobra.Command, configPath string, configSet bool) error {
	out := cmd.OutOrStdout()

	enabled := false
	dir := plugin.DefaultPluginsDir
	var allow []string
	if _, err := os.Stat(configPath); err == nil {
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("plugins list: %w", err)
		}
		if cfg.Plugins != nil {
			enabled = cfg.Plugins.Enabled
			allow = cfg.Plugins.Allow
			if cfg.Plugins.Dir != "" {
				dir = cfg.Plugins.Dir
			}
		}
	} else if configSet {
		return fmt.Errorf("plugins list: config %s: %w", configPath, err)
	}

	found, err := plugin.Discover(dir, allow)
	if err != nil {
		return fmt.Errorf("plugins list: %w", err)
	}

	rows := make([]pluginRow, 0, len(found))
	for _, d := range found {
		row := pluginRow{Name: sanitizeField(d.Name, reportFieldMax), Status: d.Status}
		if d.Manifest != nil {
			row.Version = sanitizeField(d.Manifest.Version, reportFieldMax)
			row.Type = d.Manifest.Type
		}
		if !enabled && row.Status == plugin.StatusReady {
			row.Status = "disabled"
			row.Detail = "plugins.enabled is false"
		}
		if d.Err != nil {
			row.Detail = sanitizeField(d.Err.Error(), reportReasonMax)
		}
		rows = append(rows, row)
	}

	if jsonOutput {
		return writeJSON(out, map[string]any{"enabled": enabled, "dir": dir, "plugins": rows})
	}

	st := newStyler(out)
	fmt.Fprintln(out, st.header("Plugins")) //nolint:errcheck
	if !enabled {
		fmt.Fprintln(out, st.warn("plugin system is disabled (plugins.enabled: false or absent) — nothing will be executed")) //nolint:errcheck
	}
	if len(rows) == 0 {
		fmt.Fprintf(out, "  no plugins found in %s\n", dir) //nolint:errcheck
		return nil
	}
	for _, r := range rows {
		detail := ""
		if r.Detail != "" {
			detail = " — " + r.Detail
		}
		fmt.Fprintf(out, "  %-24s %-12s %-10s %s%s\n", r.Name, r.Version, r.Type, r.Status, detail) //nolint:errcheck
	}
	return nil
}

func newPluginsValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <dir>",
		Short: "Validate a plugin directory: manifest checks + one handshake dry-run",
		Long: `Author helper: load and strictly validate <dir>/module.yaml (schema,
file permissions, ownership, exec resolution), then start the executable
once, perform the protocol handshake, and kill it. Nothing else runs.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPluginsValidate(cmd, args[0])
		},
	}
	return cmd
}

func runPluginsValidate(cmd *cobra.Command, dir string) error {
	out := cmd.OutOrStdout()
	st := newStyler(out)

	m, err := plugin.LoadManifest(dir)
	if err != nil {
		return fmt.Errorf("plugins validate: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()
	hs, err := plugin.DryRunHandshake(ctx, m)
	if err != nil {
		return fmt.Errorf("plugins validate: handshake dry-run: %w", err)
	}

	if jsonOutput {
		return writeJSON(out, map[string]any{
			"manifest":  map[string]any{"name": m.Name, "version": m.Version, "type": m.Type},
			"handshake": hs,
		})
	}
	fmt.Fprintln(out, st.ok(fmt.Sprintf("manifest valid: %s v%s (%s)", //nolint:errcheck
		sanitizeField(m.Name, reportFieldMax), sanitizeField(m.Version, reportFieldMax), m.Type)))
	if len(m.Network.Hosts) > 0 {
		fmt.Fprintln(out, st.warn(fmt.Sprintf("declares network access to: %s (ADVISORY in v1 — not yet enforced)", //nolint:errcheck
			sanitizeField(strings.Join(m.Network.Hosts, ", "), reportReasonMax))))
	}
	fmt.Fprintln(out, st.ok(fmt.Sprintf("handshake OK: %s v%s (protocol %d, capabilities: %s)", //nolint:errcheck
		sanitizeField(hs.Name, reportFieldMax), sanitizeField(hs.Version, reportFieldMax),
		hs.ProtocolVersion, sanitizeField(strings.Join(hs.Capabilities, ", "), reportReasonMax))))
	return nil
}
