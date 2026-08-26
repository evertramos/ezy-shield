// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package plugin

import "os"

// checkFileOwner is a no-op off Linux: the uid-based ownership rule needs
// syscall.Stat_t. Mode checks (regular, world-writable, exec bit) still
// apply on every platform.
func checkFileOwner(string, os.FileInfo) error { return nil }
