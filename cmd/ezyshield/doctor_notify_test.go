// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeDoctorConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCheckNotifyCriticalRoute(t *testing.T) {
	base := "collectors:\n  - kind: journald\n    unit: sshd\n"
	for _, tc := range []struct {
		name   string
		notify string
		want   string
	}{
		{"no notify section", "", statusNA},
		{"warn-only channel", "notify:\n  slack:\n    webhook_url: env:SLACK_URL\n    severity: [warn]\n", statusWarn},
		{"critical listed", "notify:\n  slack:\n    webhook_url: env:SLACK_URL\n    severity: [warn, critical]\n", statusPass},
		{"unfiltered channel", "notify:\n  discord:\n    webhook_url: env:DISCORD_URL\n", statusPass},
		{"one warn-only, one unfiltered", "notify:\n  slack:\n    webhook_url: env:SLACK_URL\n    severity: [warn]\n  discord:\n    webhook_url: env:DISCORD_URL\n", statusPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeDoctorConfig(t, base+tc.notify)
			got := checkNotifyCriticalRoute(dir)
			if got.Status != tc.want {
				t.Fatalf("status = %s (%s), want %s", got.Status, got.Hint, tc.want)
			}
		})
	}
}
