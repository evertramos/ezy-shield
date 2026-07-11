package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SaveConfig atomically replaces the config file at path with the YAML
// rendering of cfg, prefixed by header (a "# ..." comment block or "").
//
// Safety order — nothing touches the original file until the new content
// has fully proven itself:
//
//  1. cfg.Validate() — an invalid struct never reaches disk.
//  2. The rendered YAML is round-tripped through LoadConfigReader, catching
//     any drift between the marshaller and the strict loader.
//  3. The current file, when present, is copied to path+".bak" (same mode).
//  4. The YAML is written to a temp file in the same directory and renamed
//     over path, so readers never observe a partial file.
//
// The new file inherits the original file's permission bits (0640 when the
// file didn't exist). Comments in the original file are NOT preserved —
// that's what the .bak is for. Returns the backup path, or "" when path
// didn't exist before.
//
// SaveConfig never writes secret values: Config carries credentials only as
// SecretRef env: references, which is exactly what gets marshalled.
func SaveConfig(path string, cfg *Config, header string) (bakPath string, err error) {
	if cfg == nil {
		return "", fmt.Errorf("refusing to save nil config")
	}
	if err := cfg.Validate(); err != nil {
		return "", fmt.Errorf("refusing to save invalid config: %w", err)
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("rendering config: %w", err)
	}
	data := append([]byte(header), body...)
	if _, err := LoadConfigReader(bytes.NewReader(data), "rendered config"); err != nil {
		return "", fmt.Errorf("rendered config failed re-validation: %w", err)
	}

	mode := os.FileMode(0o640)
	if orig, rerr := os.ReadFile(path); rerr == nil { //nolint:gosec // admin-controlled config location
		if st, serr := os.Stat(path); serr == nil {
			mode = st.Mode().Perm()
		}
		bakPath = path + ".bak"
		if werr := os.WriteFile(bakPath, orig, mode); werr != nil { //nolint:gosec // same perms as the file it backs up
			return "", fmt.Errorf("writing backup %s: %w", bakPath, werr)
		}
	} else if !os.IsNotExist(rerr) {
		return "", fmt.Errorf("reading %s for backup: %w", path, rerr)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup on any failure after creation; once the rename
		// has succeeded the file no longer exists under tmpName.
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("writing %s: %w", tmpName, err)
	}
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return "", fmt.Errorf("closing %s: %w", tmpName, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("replacing %s: %w", path, err)
	}
	return bakPath, nil
}
