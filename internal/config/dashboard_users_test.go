// SPDX-License-Identifier: AGPL-3.0-only

package config

// Validation tests for dashboard.users (issue #204).

import (
	"strings"
	"testing"
)

func loadDashboardUsers(t *testing.T, section string) error {
	t.Helper()
	yaml := "data_dir: /tmp\ndashboard:\n  users:\n" + section
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	return err
}

func TestDashboardUsers_Valid(t *testing.T) {
	t.Parallel()
	err := loadDashboardUsers(t, `    - name: vera
      role: viewer
      token: env:DASH_VERA_TOKEN
    - name: omar
      role: operator
      token: env:DASH_OMAR_TOKEN
    - name: ada
      role: admin
      token: env:DASH_ADA_TOKEN
`)
	if err != nil {
		t.Fatalf("valid users rejected: %v", err)
	}
}

func TestDashboardUsers_Invalid(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		section string
		wantErr string
	}{
		"missing name": {
			"    - role: viewer\n      token: env:T\n", "'name' is required",
		},
		"bad role": {
			"    - name: x\n      role: root\n      token: env:T\n", "must be viewer, operator, or admin",
		},
		"duplicate names": {
			"    - name: x\n      role: viewer\n      token: env:T1\n    - name: x\n      role: admin\n      token: env:T2\n",
			"duplicate name",
		},
		"missing token": {
			"    - name: x\n      role: viewer\n", "'token' is required",
		},
		// The SecretRef loader rejects inline literals before validation
		// ever runs — same rule as every other secret.
		"inline token": {
			"    - name: x\n      role: viewer\n      token: super-secret-inline-value\n",
			"env:",
		},
	} {
		err := loadDashboardUsers(t, tc.section)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error %q does not contain %q", name, err, tc.wantErr)
		}
	}
}

// TestDashboardUsers_InlineTokenNeverEchoed: the inline-literal rejection
// must not leak the pasted value in the error (redaction discipline).
func TestDashboardUsers_InlineTokenNeverEchoed(t *testing.T) {
	t.Parallel()
	err := loadDashboardUsers(t, "    - name: x\n      role: viewer\n      token: super-secret-inline-value\n")
	if err == nil {
		t.Fatalf("inline token must be rejected")
	}
	if strings.Contains(err.Error(), "super-secret-inline-value") {
		t.Errorf("error echoes the inline secret: %v", err)
	}
}
