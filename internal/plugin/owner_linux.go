// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkFileOwner enforces the ownership rule (issue #207): the file must
// be owned by root or by the owner of its containing directory (the
// operator who installed the plugin tree). Same trust boundary as the
// config-ownership doctor checks.
func checkFileOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid == 0 {
		return nil
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("stat parent dir: %w", err)
	}
	dirSt, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != dirSt.Uid {
		return fmt.Errorf("owned by uid %d, but the plugin dir is owned by uid %d — the executable must belong to root or the dir owner", st.Uid, dirSt.Uid)
	}
	return nil
}
