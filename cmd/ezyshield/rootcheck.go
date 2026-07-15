package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// requireRootForWrites fails fast when a wizard targets the system config
// directory without the privileges to write it, so the operator hears "run
// with sudo" before answering the first question instead of after the last
// one (issue #149). Custom target paths (tests, dogfooding, staging dirs)
// skip the check: when the operator points the wizard elsewhere, regular
// filesystem permissions apply at write time. The message derives the
// invocation name from cobra so `ezyshield ...` and a future `ezy shield ...`
// both print correctly (ezy family convention).
func requireRootForWrites(cmd *cobra.Command, target string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	systemTarget := target == defaultConfigDir || strings.HasPrefix(target, defaultConfigDir+"/")
	if !systemTarget {
		return nil
	}
	return fmt.Errorf("%s writes to %s — run it with sudo", cmd.CommandPath(), defaultConfigDir)
}
