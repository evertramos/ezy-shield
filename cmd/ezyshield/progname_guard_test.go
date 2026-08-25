package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoHardcodedProgramInvocations guards the CLI-naming rule (AGENTS.md,
// root.go: "every printed hint derives from progName" — issues #295/#304):
// no non-test source file in this package may contain an invocation-style
// literal like 'ezyshield arm'. The pattern is the hint convention (a
// single quote directly before the name, followed by a subcommand), so
// legitimate literals — the systemd UNIT name in "systemctl start
// ezyshield", the system USER in "usermod -aG … ezyshield", file paths,
// and code comments — never match.
func TestNoHardcodedProgramInvocations(t *testing.T) {
	invocation := regexp.MustCompile(`'ezyshield [a-z-]`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue // comments are not user-facing output
			}
			if invocation.MatchString(line) {
				t.Errorf("%s:%d: hardcoded program invocation %q — derive from progName instead (AGENTS.md CLI naming)",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
