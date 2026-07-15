package main

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRequireRootForWrites(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — the non-root fail-fast branch is untestable")
	}

	cmd := &cobra.Command{Use: "config"}
	root := &cobra.Command{Use: progName}
	root.AddCommand(cmd)

	cases := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"system config dir requires sudo", defaultConfigDir, true},
		{"file under system config dir requires sudo", defaultConfigDir + "/config.yaml", true},
		{"custom dir passes (fs perms apply at write time)", "/tmp/ezyshield-test", false},
		{"custom file passes", "/home/op/staging/config.yaml", false},
		{"lookalike prefix passes", defaultConfigDir + "-staging/config.yaml", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireRootForWrites(cmd, tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("target %q: want sudo error, got nil", tc.target)
				}
				if !strings.Contains(err.Error(), "sudo") {
					t.Errorf("error should tell the operator to use sudo: %v", err)
				}
				if !strings.Contains(err.Error(), progName+" config") {
					t.Errorf("error should carry the derived command path: %v", err)
				}
			} else if err != nil {
				t.Fatalf("target %q: unexpected error: %v", tc.target, err)
			}
		})
	}
}
