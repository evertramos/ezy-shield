package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// tokenReader lets tests substitute the /dev/tty path with an in-process pipe
// or an error. The production implementation is readMaskedTokenFromTTY, which
// opens /dev/tty directly and calls term.ReadPassword — never bufio.Scanner
// on os.Stdin, which would echo the token to the screen and, worse, could
// leave it in shell history if the operator hit Ctrl-U (issue #13 §2, §6).
//
// The var is package-scoped so tests can swap it via t.Cleanup; no argv or
// flag exposes it, keeping the production path a single, obvious call.
var tokenReader func(prompt string) (string, error) = readMaskedTokenFromTTY

// ErrNoTTY is returned when /dev/tty cannot be opened — the operator is
// running under a piped install, CI, systemd, or otherwise has no
// controlling terminal. Callers fall through to the placeholder path
// (issue #13 §2 fall-through rule).
var ErrNoTTY = errors.New("no controlling tty (piped install / non-interactive)")

// readMaskedTokenFromTTY opens /dev/tty, writes prompt to it, reads a line
// without echoing, and returns the trimmed value. On any error opening the
// tty (non-interactive stdin, no controlling terminal) it returns ErrNoTTY
// and the caller falls through to §5 placeholder handling.
//
// Two hard invariants for issue #13 §6:
//  1. The token never appears on stdout or stderr — we write the prompt to
//     the tty and read the reply from the tty, so a redirected stdout /
//     stderr cannot capture either.
//  2. The token never reaches os.Stdin — bufio.Scanner on stdin would echo
//     characters at the terminal driver before we could react.
//
// A trailing "\n" is written to the tty after ReadPassword returns so the
// operator's next prompt starts on a fresh line (ReadPassword eats the
// user's Enter but not the visual newline).
func readMaskedTokenFromTTY(prompt string) (string, error) {
	// O_NOCTTY: never make the tty the process's controlling terminal on us.
	// O_RDWR because term.ReadPassword needs to disable echo via TIOCGETA/
	// TIOCSETA (or the Linux equivalent) on the SAME fd.
	f, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return "", ErrNoTTY
	}
	defer f.Close() //nolint:errcheck // read-only close on tty; error irrelevant to the token path

	if !term.IsTerminal(int(f.Fd())) {
		return "", ErrNoTTY
	}

	// Prompt goes to the tty (NOT stdout) so nothing leaks even if stdout is
	// captured to a log file. Any write error demotes to "no tty" — we
	// don't want to leak partial prompt info to callers.
	if _, err := fmt.Fprint(f, prompt); err != nil {
		return "", ErrNoTTY
	}

	// term.ReadPassword sets the tty into raw / no-echo mode, reads to \n,
	// then restores the original mode. On SIGINT the tty mode is restored
	// on process exit by the terminal driver's tcgetattr save/restore — no
	// stuck no-echo shell if the operator hits Ctrl-C.
	raw, err := term.ReadPassword(int(f.Fd()))
	// Regardless of err, print a newline so the next output isn't glued to
	// the prompt line (ReadPassword eats the Enter but doesn't echo it).
	//nolint:errcheck
	fmt.Fprintln(f)
	if err != nil {
		// Do NOT wrap err with %v/%w that carries any part of the read
		// buffer — return a fixed marker so callers can't accidentally
		// leak a partial-read token.
		return "", ErrNoTTY
	}
	// Trim ASCII whitespace only. Trimming Unicode whitespace would risk
	// eating a legitimate character out of an unusual key format.
	return strings.Trim(string(raw), " \t\r\n"), nil
}
