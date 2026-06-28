//go:build !linux

package main

// checkConfigOwnership is a no-op on non-Linux platforms — EzyShield is a
// Linux-only daemon, but cmd/ezyshield still needs to compile elsewhere so
// `go vet` and IDE tooling work for contributors on macOS.
func checkConfigOwnership(_, label string) CheckResult {
	return CheckResult{Name: label + ": ownership", Status: statusNA,
		Hint: "ownership check is Linux-only"}
}
