// SPDX-License-Identifier: AGPL-3.0-only

package config

// Validation tests for the self_check section (issue #563): tri-state
// enabled and the 10m interval floor.

import (
	"strings"
	"testing"
)

func TestSelfCheckConfig_Validation(t *testing.T) {
	t.Parallel()
	if _, err := LoadConfigReader(strings.NewReader("data_dir: /tmp\nself_check:\n  interval: 5m\n"), "t"); err == nil ||
		!strings.Contains(err.Error(), "10m floor") {
		t.Errorf("interval below the floor must be rejected, got %v", err)
	}
	for _, ok := range []string{
		"data_dir: /tmp\nself_check:\n  enabled: false\n",
		"data_dir: /tmp\nself_check:\n  interval: 12h\n",
		"data_dir: /tmp\n",
	} {
		if _, err := LoadConfigReader(strings.NewReader(ok), "t"); err != nil {
			t.Errorf("valid self_check config rejected: %v (%q)", err, ok)
		}
	}
}
