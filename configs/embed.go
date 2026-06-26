// Package configs provides embedded example configuration files for ezyshield init.
package configs

import "embed"

// FS contains the embedded config.yaml, policy.yaml, rules.yaml templates and systemd units.
//
//go:embed config.yaml policy.yaml rules.yaml systemd
var FS embed.FS
