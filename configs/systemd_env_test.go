package configs_test

import (
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/configs"
)

// TestSystemdUnit_EnvironmentFileIsDotEnv locks in issue #13 §4: the ezyshield
// systemd unit's EnvironmentFile= directive must point at the dot-prefixed
// /etc/ezyshield/.env, matching what `ezyshield init` writes.
//
// If somebody flips it back to the old /etc/ezyshield/env path (or drops the
// directive entirely) systemd silently fails to load the API key at boot,
// the daemon calls Resolve(), gets ErrAPIKeyMissing, and the operator is left
// wondering why AI is off. This test is the tripwire.
func TestSystemdUnit_EnvironmentFileIsDotEnv(t *testing.T) {
	t.Parallel()

	data, err := configs.FS.ReadFile("systemd/ezyshield.service")
	if err != nil {
		t.Fatalf("read embedded unit: %v", err)
	}
	body := string(data)

	// Must reference the dot-prefixed path exactly once.
	const wantLine = "EnvironmentFile=-/etc/ezyshield/.env"
	if !strings.Contains(body, wantLine) {
		t.Errorf("unit missing %q; body=%q", wantLine, body)
	}

	// And must NOT reference the legacy (dotless) path — that would load the
	// wrong file after an upgrade if both existed.
	for _, bad := range []string{
		"EnvironmentFile=/etc/ezyshield/env\n",
		"EnvironmentFile=-/etc/ezyshield/env\n",
	} {
		if strings.Contains(body, bad) {
			t.Errorf("unit still references legacy path %q", bad)
		}
	}
}
