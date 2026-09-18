// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// loadConfigDirEnv loads <configDir>/.env into the process environment so
// CLI commands that resolve `env:VARNAME` secret references (test notifier,
// test enforcer, validate) can see the values the wizard stored there —
// the daemon gets them via the systemd EnvironmentFile, but a CLI run from
// a shell does not (issue #665). A variable already present in the real
// environment is NOT overridden: an explicit shell/systemd value always
// wins over the file. A missing .env is not an error.
func loadConfigDirEnv(configDir string) {
	if configDir == "" {
		return
	}
	lines, err := loadEnvFileLines(filepath.Join(configDir, envFileName))
	if err != nil {
		return // best-effort: never block a command because .env is unreadable
	}
	for _, ln := range lines {
		if ln.key == "" {
			continue
		}
		if _, set := os.LookupEnv(ln.key); set {
			continue // shell/systemd value wins
		}
		_ = os.Setenv(ln.key, unquoteEnvValue(ln.value))
	}
}

// unquoteEnvValue trims surrounding whitespace and a single matched pair of
// double or single quotes from a .env value, mirroring the common dotenv
// convention. It does not interpret escapes — the wizard writes plain values.
func unquoteEnvValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "\r")
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
