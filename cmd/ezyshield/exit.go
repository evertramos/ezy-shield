package main

import (
	"errors"
	"fmt"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// Process exit codes, frozen for v0.1 and documented in the CLI reference
// (docs/content/*/reference/cli.md "Global conventions"). Scripts rely on
// these — changing a value or meaning is a breaking change.
const (
	exitOK          = 0 // success
	exitRuntime     = 1 // runtime error: the command started but failed
	exitUsage       = 2 // usage error: bad flag/argument or missing input file
	exitUnreachable = 3 // daemon unreachable: control socket refused connection
)

// exitCodeError lets a RunE choose the process exit code explicitly after it
// has already written its own diagnostics. runMain exits with Code and prints
// nothing further.
type exitCodeError struct{ Code int }

func (e exitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

// exitCodeFor maps the error returned by cobra's Execute to a process exit
// code. started reports whether execution reached the command's run hooks:
// when it did not (unknown command, bad flag, wrong argument count), the
// failure is by definition a usage error. The second return value reports
// whether the error message should still be printed to stderr.
func exitCodeFor(err error, started bool) (code int, print bool) {
	var ec exitCodeError
	switch {
	case err == nil:
		return exitOK, false
	case errors.As(err, &ec):
		return ec.Code, false
	case errors.Is(err, daemon.ErrDaemonUnreachable):
		return exitUnreachable, true
	case !started:
		return exitUsage, true
	default:
		return exitRuntime, true
	}
}
