package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPreflightExistingConfigFiles covers the four states the pre-flight can
// find the config directory in: neither file present, only config.yaml, only
// policy.yaml, and both. Issue #5 requires that when both are present the
// operator sees a single error listing every offending path, not one at a
// time — so the "both" case asserts the substring for each path.
//
// The test uses t.TempDir() as --config-dir so it never touches /etc.
func TestPreflightExistingConfigFiles(t *testing.T) {
	t.Parallel()

	// touch creates the given file inside dir; helper avoids repeating the
	// boilerplate in every case below.
	touch := func(t *testing.T, dir, name string) {
		t.Helper()
		//nolint:gosec // 0o600: test artefact under t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stub\n"), 0o600); err != nil {
			t.Fatalf("touch %s: %v", name, err)
		}
	}

	cases := []struct {
		name        string
		preExisting []string // filenames to create inside the temp dir
		wantErr     bool
		wantIn      []string // substrings that MUST appear in the error message
	}{
		{
			name:        "neither present — wizard proceeds",
			preExisting: nil,
			wantErr:     false,
		},
		{
			name:        "only config.yaml present — fail fast",
			preExisting: []string{"config.yaml"},
			wantErr:     true,
			wantIn:      []string{"config.yaml", "already exists"},
		},
		{
			name:        "only policy.yaml present — fail fast",
			preExisting: []string{"policy.yaml"},
			wantErr:     true,
			wantIn:      []string{"policy.yaml", "already exists"},
		},
		{
			name:        "both present — single error lists both paths",
			preExisting: []string{"config.yaml", "policy.yaml"},
			wantErr:     true,
			wantIn:      []string{"config.yaml", "policy.yaml", "already exist"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for _, f := range tc.preExisting {
				touch(t, dir, f)
			}
			err := preflightExistingConfigFiles(dir)
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("expected error, got nil")
			case !tc.wantErr && err != nil:
				t.Fatalf("expected no error, got: %v", err)
			case tc.wantErr:
				msg := err.Error()
				for _, want := range tc.wantIn {
					if !strings.Contains(msg, want) {
						t.Errorf("error %q missing substring %q", msg, want)
					}
				}
			}
		})
	}
}

// TestPreflightExistingConfigFiles_UnreadableDir asserts that a stat error
// other than "not exist" (e.g. a permission-denied on the parent directory)
// surfaces as an error rather than a false "safe to proceed" result. Skip on
// root, where 0o000 doesn't stop us.
func TestPreflightExistingConfigFiles_UnreadableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — 0o000 does not deny stat")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	//nolint:gosec // 0o700 restores traversal so t.TempDir() cleanup can remove the test dir
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if err := preflightExistingConfigFiles(locked); err == nil {
		t.Fatalf("expected stat error on unreadable dir, got nil")
	}
}
