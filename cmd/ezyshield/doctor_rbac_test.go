// SPDX-License-Identifier: AGPL-3.0-only

package main

// Doctor tests for the dashboard RBAC token checks (issue #204).

import (
	"strings"
	"testing"
)

const rbacDoctorConfig = `data_dir: /tmp
dashboard:
  users:
    - {name: vera, role: viewer, token: env:EZY_TEST_DASH_VERA}
    - {name: omar, role: operator, token: env:EZY_TEST_DASH_OMAR}
`

func TestCheckDashboardUsers_NoUsersIsNA(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", "data_dir: /tmp\n")
	results := checkDashboardUsers(dir)
	if len(results) != 1 || results[0].Status != statusNA {
		t.Fatalf("expected N/A, got %+v", results)
	}
}

func TestCheckDashboardUsers_EntropyAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", rbacDoctorConfig)

	// Strong unique tokens: both pass.
	t.Setenv("EZY_TEST_DASH_VERA", strings.Repeat("a", 64))
	t.Setenv("EZY_TEST_DASH_OMAR", strings.Repeat("b", 64))
	for _, r := range checkDashboardUsers(dir) {
		if r.Status != statusPass {
			t.Errorf("strong tokens: %s = %s (%s)", r.Name, r.Status, r.Hint)
		}
	}

	// Short token: warned, with the generation suggestion.
	t.Setenv("EZY_TEST_DASH_VERA", "tinytok9")
	results := checkDashboardUsers(dir)
	warned := false
	for _, r := range results {
		if strings.Contains(r.Name, "vera") && r.Status == statusWarn &&
			strings.Contains(r.Hint, "openssl rand") {
			warned = true
		}
		if strings.Contains(r.Hint, "tinytok9") {
			t.Errorf("hint echoes the token value: %s", r.Hint)
		}
	}
	if !warned {
		t.Errorf("weak token not warned: %+v", results)
	}

	// Duplicate tokens: second user warned.
	t.Setenv("EZY_TEST_DASH_VERA", strings.Repeat("c", 64))
	t.Setenv("EZY_TEST_DASH_OMAR", strings.Repeat("c", 64))
	results = checkDashboardUsers(dir)
	dup := false
	for _, r := range results {
		if strings.Contains(r.Name, "omar") && r.Status == statusWarn &&
			strings.Contains(r.Hint, "identical") {
			dup = true
		}
	}
	if !dup {
		t.Errorf("duplicate tokens not warned: %+v", results)
	}

	// Unset env var: failure naming the variable, not any value.
	t.Setenv("EZY_TEST_DASH_OMAR", "")
	results = checkDashboardUsers(dir)
	failed := false
	for _, r := range results {
		if strings.Contains(r.Name, "omar") && r.Status == statusFail &&
			strings.Contains(r.Hint, "EZY_TEST_DASH_OMAR") {
			failed = true
		}
	}
	if !failed {
		t.Errorf("unset token env not failed: %+v", results)
	}
}
