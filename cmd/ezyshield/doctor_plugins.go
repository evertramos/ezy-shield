// SPDX-License-Identifier: AGPL-3.0-only

package main

// Plugin-system doctor checks (issue #207): when plugins are enabled,
// the dir must exist, every allowlisted name must resolve to a valid
// manifest, and invalid manifests are surfaced. Nothing is executed.

import (
	"path/filepath"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/plugin"
)

// checkPlugins audits the plugins.d state. A single N/A result when the
// plugin system is absent or disabled.
func checkPlugins(configDir string) []CheckResult {
	cfg, err := config.LoadConfig(filepath.Join(configDir, "config.yaml"))
	if err != nil || cfg.Plugins == nil || !cfg.Plugins.Enabled {
		return []CheckResult{{
			Name:   "plugins: system",
			Status: statusNA,
			Hint:   "plugin system disabled (plugins.enabled: false or absent)",
		}}
	}
	dir := cfg.Plugins.Dir
	if dir == "" {
		dir = plugin.DefaultPluginsDir
	}

	found, err := plugin.Discover(dir, cfg.Plugins.Allow)
	if err != nil {
		return []CheckResult{{
			Name:   "plugins: discovery",
			Status: statusFail,
			Hint:   sanitizeErrorMessage(err.Error()),
		}}
	}

	var out []CheckResult
	byName := map[string]plugin.Discovered{}
	for _, d := range found {
		byName[d.Name] = d
		if d.Status == plugin.StatusInvalid {
			out = append(out, CheckResult{
				Name:   "plugins: " + d.Name,
				Status: statusWarn,
				Hint:   "manifest invalid: " + sanitizeErrorMessage(d.Err.Error()),
			})
		}
	}
	// Every allowlisted name must exist and be valid — a typo'd allow entry
	// silently runs nothing.
	for _, name := range cfg.Plugins.Allow {
		d, ok := byName[name]
		switch {
		case !ok:
			out = append(out, CheckResult{
				Name:   "plugins: " + name,
				Status: statusWarn,
				Hint:   "allowlisted but no such plugin directory in " + dir,
			})
		case d.Status == plugin.StatusReady:
			out = append(out, CheckResult{Name: "plugins: " + name, Status: statusPass})
		}
	}
	if len(out) == 0 {
		out = append(out, CheckResult{
			Name:   "plugins: system",
			Status: statusWarn,
			Hint:   "enabled but nothing is allowlisted and " + dir + " has no plugins",
		})
	}
	return out
}
