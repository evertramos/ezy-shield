package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckAllowlistBreadth covers issue #210 AC #4: doctor warns when the
// active policy allowlist contains a very broad private (RFC1918/ULA) range
// -- prefix length <= 16 (/16, /12, /8) -- and does not warn on narrower
// private ranges or public ranges.
func TestCheckAllowlistBreadth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		policyYAML string
		wantStatus string // status of the single/first result we check for
		wantWarns  int    // number of WARN results expected
	}{
		{
			name:       "empty allowlist -- PASS",
			policyYAML: "armed: false\nallowlist: []\n",
			wantStatus: statusPass,
			wantWarns:  0,
		},
		{
			name:       "narrow private /24 -- no warning",
			policyYAML: "armed: false\nallowlist:\n  - 192.168.1.0/24\n",
			wantStatus: statusPass,
			wantWarns:  0,
		},
		{
			// 100.64.0.0/10 is CGNAT shared address space (RFC 6598) — not
			// RFC1918 private, so netip.Addr.IsPrivate() reports false for
			// it even though it isn't globally routable either. Used here
			// (rather than a real public block) to keep this test file free
			// of non-example IP literals (AGENTS.md Hard Rule 8 / CI
			// ip-hygiene-gate).
			name:       "non-private range -- no warning regardless of width",
			policyYAML: "armed: false\nallowlist:\n  - 100.64.0.0/10\n",
			wantStatus: statusPass,
			wantWarns:  0,
		},
		{
			name:       "single host IP -- no warning",
			policyYAML: "armed: false\nallowlist:\n  - 10.0.0.5/32\n",
			wantStatus: statusPass,
			wantWarns:  0,
		},
		{
			name:       "private /16 -- WARN",
			policyYAML: "armed: false\nallowlist:\n  - 172.17.0.0/16\n",
			wantStatus: statusWarn,
			wantWarns:  1,
		},
		{
			name:       "private /12 -- WARN",
			policyYAML: "armed: false\nallowlist:\n  - 172.16.0.0/12\n",
			wantStatus: statusWarn,
			wantWarns:  1,
		},
		{
			name:       "private /8 -- WARN",
			policyYAML: "armed: false\nallowlist:\n  - 10.0.0.0/8\n",
			wantStatus: statusWarn,
			wantWarns:  1,
		},
		{
			name: "mixed -- one broad entry warns, narrow entry does not",
			policyYAML: "armed: false\nallowlist:\n" +
				"  - 192.168.1.0/24\n" +
				"  - 10.0.0.0/8\n",
			wantStatus: statusWarn,
			wantWarns:  1,
		},
		{
			name:       "IPv6 ULA broad range -- WARN",
			policyYAML: "armed: false\nallowlist:\n  - \"fc00::/8\"\n",
			wantStatus: statusWarn,
			wantWarns:  1,
		},
		{
			name:       "IPv6 public range -- no warning",
			policyYAML: "armed: false\nallowlist:\n  - \"2001:db8::/32\"\n",
			wantStatus: statusPass,
			wantWarns:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.yaml")
			//nolint:gosec // test file, intentional permission
			if err := os.WriteFile(path, []byte(tt.policyYAML), 0o640); err != nil {
				t.Fatal(err)
			}

			results := checkAllowlistBreadth(dir)

			warns := 0
			for _, r := range results {
				if r.Status == statusWarn {
					warns++
					if r.Hint == "" {
						t.Error("WARN result must include a hint")
					}
				}
			}
			if warns != tt.wantWarns {
				t.Errorf("got %d WARN result(s) %+v, want %d", warns, results, tt.wantWarns)
			}
			if tt.wantWarns == 0 {
				if len(results) != 1 || results[0].Status != tt.wantStatus {
					t.Errorf("got %+v, want single %s result", results, tt.wantStatus)
				}
			}
		})
	}

	t.Run("policy.yaml absent -- N/A", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		results := checkAllowlistBreadth(dir)
		if len(results) != 1 || results[0].Status != statusNA {
			t.Errorf("got %+v, want single N/A result", results)
		}
	})

	t.Run("policy.yaml invalid -- N/A, not a crash", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.yaml")
		//nolint:gosec // test file, intentional permission
		if err := os.WriteFile(path, []byte("armed: [not-a-bool\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		results := checkAllowlistBreadth(dir)
		if len(results) != 1 || results[0].Status != statusNA {
			t.Errorf("got %+v, want single N/A result", results)
		}
	})
}

// TestRunDoctor_AllowlistWarningSurfacesInSummary verifies the WARN check is
// wired into runDoctor's full check list and counted in the JSON summary.
func TestRunDoctor_AllowlistWarningSurfacesInSummary(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("data_dir: /tmp\n"), 0o640); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	policy := "armed: false\nallowlist:\n  - 172.16.0.0/12\n"
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(policy), 0o640); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	if err := runDoctor(silentCmd(), dir, false); err != nil {
		t.Fatalf("runDoctor returned unexpected error: %v", err)
	}
}
