// Command ezyshield is the EzyShield CLI and daemon.
// It is part of the `ezy` tool family: `ezyshield <verb>` == `ezy shield <verb>`.
package main

import (
	"fmt"
	"os"
)

// Injected via -ldflags at build time; see Makefile.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
