// SPDX-License-Identifier: AGPL-3.0-only

package configs_test

import (
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/configs"
)

// TestSystemdUnit_SupplementaryGroups pins the two memberships the daemon
// cannot work without: systemd-journal (journald collector, issue #454) and
// ezyshield-view (the daemon must be a member to group-own the read-only
// socket — without it the viewer tier silently never comes up, issue #594).
func TestSystemdUnit_SupplementaryGroups(t *testing.T) {
	t.Parallel()

	data, err := configs.FS.ReadFile("systemd/ezyshield.service")
	if err != nil {
		t.Fatalf("read embedded unit: %v", err)
	}
	var line string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, "SupplementaryGroups=") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("unit has no SupplementaryGroups= directive")
	}
	groups := strings.Fields(strings.TrimPrefix(line, "SupplementaryGroups="))
	for _, want := range []string{"systemd-journal", "ezyshield-view"} {
		found := false
		for _, g := range groups {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("SupplementaryGroups=%v is missing %q", groups, want)
		}
	}
}
