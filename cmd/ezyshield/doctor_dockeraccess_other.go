// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

// statSocketOwnership is unavailable off Linux — EzyShield is a Linux-only
// daemon, but cmd/ezyshield still compiles elsewhere so `go vet` and IDE
// tooling work for contributors on macOS. The check degrades to N/A.
func statSocketOwnership(string) (socketOwnership, error) {
	return socketOwnership{}, errStatUnsupported
}
