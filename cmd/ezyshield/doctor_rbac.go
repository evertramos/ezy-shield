// SPDX-License-Identifier: AGPL-3.0-only

package main

// Dashboard RBAC doctor checks (issue #204): every provisioned user's
// resolved token must carry enough entropy (>= 32 bytes), and no two users
// may share a token. Token VALUES never appear in any output — only user
// names and lengths.

import (
	"crypto/sha256"
	"path/filepath"
	"strings"

	"github.com/evertramos/ezy-shield/internal/config"
)

// dashboardTokenMinBytes is the doctor floor for resolved token length.
const dashboardTokenMinBytes = 32

// checkDashboardUsers audits the RBAC user list. A single N/A result when
// no users are provisioned.
func checkDashboardUsers(configDir string) []CheckResult {
	cfg, err := config.LoadConfig(filepath.Join(configDir, "config.yaml"))
	if err != nil || cfg.Dashboard == nil || len(cfg.Dashboard.Users) == 0 {
		return []CheckResult{{
			Name:   "dashboard: rbac users",
			Status: statusNA,
			Hint:   "no dashboard users provisioned (single-credential mode)",
		}}
	}

	var out []CheckResult
	seen := map[[sha256.Size]byte]string{} // token digest -> first user name
	for _, u := range cfg.Dashboard.Users {
		name := "dashboard: user " + u.Name
		token, err := u.Token.Resolve()
		if err != nil {
			envVar := strings.TrimPrefix(string(u.Token), "env:")
			if v, ok := readEnvValue(filepath.Join(configDir, envFileName), envVar); ok && v != "" {
				token = v
			} else {
				out = append(out, CheckResult{
					Name:   name,
					Status: statusFail,
					Hint:   "token env var " + envVar + " is not set (checked environment and " + filepath.Join(configDir, envFileName) + ")",
				})
				continue
			}
		}
		if len(token) < dashboardTokenMinBytes {
			out = append(out, CheckResult{
				Name:   name,
				Status: statusWarn,
				Hint:   "resolved token is shorter than 32 bytes — generate a strong one: openssl rand -hex 32",
			})
			continue
		}
		digest := sha256.Sum256([]byte(token))
		if first, dup := seen[digest]; dup {
			out = append(out, CheckResult{
				Name:   name,
				Status: statusWarn,
				Hint:   "token is identical to user " + first + "'s — per-user tokens must be unique for audit attribution",
			})
			continue
		}
		seen[digest] = u.Name
		out = append(out, CheckResult{Name: name, Status: statusPass})
	}
	return out
}
