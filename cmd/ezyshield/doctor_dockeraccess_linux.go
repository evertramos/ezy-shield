// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"os"
	"syscall"
)

// statSocketOwnership reads the owner, group and mode of path. Reading
// uid/gid from FileInfo.Sys() needs the Linux-only syscall.Stat_t, hence this
// file's build tag (same split as checkConfigOwnership).
func statSocketOwnership(path string) (socketOwnership, error) {
	info, err := os.Stat(path)
	if err != nil {
		return socketOwnership{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return socketOwnership{}, errStatUnsupported
	}
	return socketOwnership{
		uid:      st.Uid,
		gid:      st.Gid,
		mode:     info.Mode(),
		isSocket: info.Mode()&os.ModeSocket != 0,
	}, nil
}
