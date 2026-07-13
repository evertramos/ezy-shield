// Package collector provides log collectors that implement sdk.Collector.
//
// This file holds the input allowlists shared by the collectors and by the
// daemon's on-demand evidence extraction (issue #126). It has no build tag so
// the validators compile on every platform even though some collectors are
// linux-only.
package collector

import "regexp"

// reUnitName is an allowlist for journald unit names.
// Only alphanumeric characters plus [._@:-] are accepted to prevent injection.
var reUnitName = regexp.MustCompile(`^[A-Za-z0-9._@:\-]+$`)

// reDockerContainerName is an allowlist for Docker container names and IDs.
// Names: [a-zA-Z0-9][a-zA-Z0-9_.-]* Short IDs: 12 hex chars. Full IDs: 64 hex.
// The pattern covers all valid forms.
var reDockerContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$`)

// ValidUnitName reports whether s is a safe systemd unit name to pass as a
// subprocess argument (see reUnitName).
func ValidUnitName(s string) bool { return reUnitName.MatchString(s) }

// ValidContainerName reports whether s is a safe Docker container name or ID
// to embed in an Engine API path or subprocess argument (see
// reDockerContainerName).
func ValidContainerName(s string) bool { return reDockerContainerName.MatchString(s) }
