// Command ezyshield is the EzyShield CLI and daemon.
// It is part of the `ezy` tool family: `ezyshield <verb>` == `ezy shield <verb>`.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Injected via -ldflags at build time; see Makefile.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}

// runMain wires the root command to out/errW, executes it, and returns the
// process exit code. Split from main so tests can drive the full CLI path
// (argument parsing → run → exit-code mapping) without spawning a process.
func runMain(args []string, out, errW io.Writer) int {
	root := newRootCmd()
	root.SetOut(out)
	root.SetErr(errW)
	root.SetArgs(args)

	// Track whether execution reached the command itself: cobra runs
	// PersistentPreRun only after command lookup, flag parsing, and argument
	// validation have all succeeded, so if it never ran the failure is a
	// usage error (exit 2). Subcommands must not define their own
	// PersistentPreRun — it would shadow this hook.
	started := false
	root.PersistentPreRun = func(*cobra.Command, []string) { started = true }

	err := root.Execute()
	code, print := exitCodeFor(err, started)
	if print {
		fmt.Fprintln(errW, "error:", err) //nolint:errcheck
	}
	return code
}
