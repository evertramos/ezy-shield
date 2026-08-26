// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// Tests for issue #386: a daemon with zero configured collectors looks
// healthy while ingesting nothing — doctor must WARN and the runtime must
// log loudly at startup.

func writeTestConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func TestCheckCollectorsConfigured(t *testing.T) {
	t.Parallel()

	t.Run("zero collectors is WARN with an actionable hint", func(t *testing.T) {
		t.Parallel()
		path := writeTestConfig(t, "data_dir: /tmp/x\ncollectors: []\n")
		res := checkCollectorsConfigured(path)
		if res.Status != statusWarn {
			t.Fatalf("status = %s, want WARN (hint: %s)", res.Status, res.Hint)
		}
		for _, want := range []string{"no collectors configured", "nothing will ever be detected", "collectors:"} {
			if !strings.Contains(res.Hint, want) {
				t.Errorf("hint %q missing %q", res.Hint, want)
			}
		}
	})

	t.Run("configured collectors PASS with a count", func(t *testing.T) {
		t.Parallel()
		path := writeTestConfig(t, "data_dir: /tmp/x\ncollectors:\n  - kind: journald\n    unit: sshd\n")
		res := checkCollectorsConfigured(path)
		if res.Status != statusPass {
			t.Fatalf("status = %s, want PASS (hint: %s)", res.Status, res.Hint)
		}
		if !strings.Contains(res.Hint, "1 collector(s)") {
			t.Errorf("hint %q missing the count", res.Hint)
		}
	})

	t.Run("missing or unloadable config is N/A (covered by other checks)", func(t *testing.T) {
		t.Parallel()
		res := checkCollectorsConfigured(filepath.Join(t.TempDir(), "absent.yaml"))
		if res.Status != statusNA {
			t.Fatalf("status = %s, want N/A", res.Status)
		}
	})
}

func TestBuildCollectors_WarnsLoudlyOnZero(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	cols := buildCollectors(&config.Config{}, logger)
	if len(cols) != 0 {
		t.Fatalf("collectors = %d, want 0", len(cols))
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "no collectors configured") {
		t.Errorf("startup warn missing for zero collectors; log output: %q", out)
	}

	// And the inverse: a configured collector must NOT trigger the warn.
	buf.Reset()
	cols = buildCollectors(&config.Config{
		Collectors: []config.CollectorCfg{{Kind: "journald", Unit: "sshd"}},
	}, logger)
	if len(cols) != 1 {
		t.Fatalf("collectors = %d, want 1", len(cols))
	}
	if strings.Contains(buf.String(), "no collectors configured") {
		t.Errorf("warn fired despite a configured collector")
	}
}
