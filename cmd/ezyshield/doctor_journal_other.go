// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import "os/exec"

// applyProbeCredential is a no-op on non-Linux platforms — EzyShield is a
// Linux-only daemon, but cmd/ezyshield still needs to compile elsewhere so
// `go vet` and IDE tooling work for contributors on macOS (same split as
// doctor_ownership_other.go).
func applyProbeCredential(_ *exec.Cmd, _ journalProbeID) {}
