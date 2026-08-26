// SPDX-License-Identifier: AGPL-3.0-only

// Package migrate reads other ban tools' configurations so EzyShield can
// propose an equivalent setup. This file is the fail2ban half (issue #181):
// read and model fail2ban's EFFECTIVE jail configuration — layered INI with
// overrides — without writing anything, ever. The mapping to EzyShield
// config and the CLI command are issue #182.
package migrate

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Defensive limits: fail2ban trees are operator-owned, but a migration tool
// must survive a corrupted or hostile file without taking the process down.
const (
	// maxINIFileSize caps each file read; larger files are truncated at the
	// last full line and reported in Warnings.
	maxINIFileSize = 1 << 20 // 1 MiB
	// maxJails caps the modeled jails; extras are dropped with a warning.
	maxJails = 256
	// maxValueLen caps any single (possibly multiline) value.
	maxValueLen = 4096
)

// Jail models one fail2ban jail's effective settings.
type Jail struct {
	Name    string
	Enabled bool
	// Filter is the filter name ("sshd"); empty means fail2ban's default
	// (the jail name).
	Filter string
	// Ports is the raw port spec ("ssh", "http,https", "0:65535").
	Ports string
	// LogPaths are the logpath entries (one per line in the INI value).
	LogPaths []string
	// MaxRetry / FindTime / BanTime are fail2ban's threshold trio; zero
	// values mean "not set at any layer".
	MaxRetry int
	FindTime time.Duration
	BanTime  time.Duration
	// Backend is the raw backend value ("auto", "systemd", ...).
	Backend string
	// IgnoreIP holds the validated ignoreip prefixes; hostnames and
	// malformed entries are skipped and reported in Config.Warnings.
	IgnoreIP []netip.Prefix
	// Unresolved records raw values that contain %(interpolation)s — kept
	// verbatim (never resolved) so the report can show them, keyed by the
	// INI key that carried them.
	Unresolved map[string]string
}

// Config is the modeled fail2ban installation.
type Config struct {
	// Jails is every jail section seen (enabled or not), [DEFAULT]
	// inheritance applied, in file-then-name order.
	Jails []Jail
	// Warnings lists everything the reader had to skip, truncate, or could
	// not read — an unreadable file is never fatal for the whole run.
	Warnings []string
}

// ReadFail2ban reads root (typically /etc/fail2ban) with fail2ban's
// precedence: jail.conf, then jail.d/*.conf (lexical), then jail.local,
// then jail.d/*.local (lexical) — later layers override earlier ones
// per-key. Only a completely unreadable root errors.
func ReadFail2ban(root string) (*Config, error) {
	if info, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("migrate: fail2ban root %s: %w", root, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("migrate: fail2ban root %s is not a directory", root)
	}

	cfg := &Config{}
	sections := map[string]map[string]string{} // section -> key -> raw value
	var order []string                         // section discovery order

	for _, path := range layerFiles(root, cfg) {
		parseINIFile(path, sections, &order, cfg)
	}

	defaults := sections["DEFAULT"]
	for _, name := range order {
		if name == "DEFAULT" || name == "INCLUDES" {
			continue
		}
		if len(cfg.Jails) >= maxJails {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("more than %d jails; the rest were skipped", maxJails))
			break
		}
		cfg.Jails = append(cfg.Jails, buildJail(name, sections[name], defaults, cfg))
	}
	return cfg, nil
}

// layerFiles returns the files to read, in fail2ban precedence order.
// Missing files/dirs are normal (a minimal install has only jail.conf).
func layerFiles(root string, cfg *Config) []string {
	var files []string
	addIf := func(path string) {
		if _, err := os.Stat(path); err == nil {
			files = append(files, path)
		}
	}
	addDir := func(dir, ext string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("cannot read %s: %v", dir, err))
			}
			return
		}
		var names []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ext) {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			files = append(files, filepath.Join(dir, n))
		}
	}
	addIf(filepath.Join(root, "jail.conf"))
	addDir(filepath.Join(root, "jail.d"), ".conf")
	addIf(filepath.Join(root, "jail.local"))
	addDir(filepath.Join(root, "jail.d"), ".local")
	return files
}

// parseINIFile merges one file's sections into the accumulated maps.
// Tolerant by design: comments (# / ; at line start), fail2ban-style
// multiline continuations (indented lines append to the previous value),
// and unparseable lines are skipped with a warning rather than failing.
func parseINIFile(path string, sections map[string]map[string]string, order *[]string, cfg *Config) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-owned fail2ban tree, migration is read-only
	if err != nil {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("cannot read %s: %v", path, err))
		return
	}
	if len(data) > maxINIFileSize {
		cut := maxINIFileSize
		if nl := strings.LastIndexByte(string(data[:cut]), '\n'); nl > 0 {
			cut = nl
		}
		data = data[:cut]
		cfg.Warnings = append(cfg.Warnings,
			fmt.Sprintf("%s exceeds %d bytes — truncated at the last full line", path, maxINIFileSize))
	}

	section := ""
	lastKey := ""
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			lastKey = ""
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if _, seen := sections[section]; !seen {
				sections[section] = map[string]string{}
				*order = append(*order, section)
			}
			lastKey = ""
		case (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && lastKey != "" && section != "":
			// fail2ban multiline continuation (e.g. logpath lists).
			cur := sections[section][lastKey]
			if len(cur)+len(trimmed)+1 <= maxValueLen {
				sections[section][lastKey] = cur + "\n" + trimmed
			}
		default:
			if section == "" {
				continue // prelude junk before any section
			}
			key, val, found := cutKV(trimmed)
			if !found {
				cfg.Warnings = append(cfg.Warnings,
					fmt.Sprintf("%s: unparseable line %q ignored", path, capString(trimmed, 80)))
				lastKey = ""
				continue
			}
			sections[section][key] = capString(val, maxValueLen)
			lastKey = key
		}
	}
}

// cutKV splits "key = value" or "key: value" (fail2ban accepts both).
func cutKV(line string) (key, val string, found bool) {
	eq := strings.IndexByte(line, '=')
	col := strings.IndexByte(line, ':')
	sep := eq
	if sep == -1 || (col != -1 && col < sep) {
		sep = col
	}
	if sep <= 0 {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(line[:sep])), strings.TrimSpace(line[sep+1:]), true
}

func capString(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// buildJail resolves one jail with [DEFAULT] inheritance and records
// interpolations instead of resolving them.
func buildJail(name string, own, defaults map[string]string, cfg *Config) Jail {
	j := Jail{Name: name, Unresolved: map[string]string{}}
	get := func(key string) (string, bool) {
		if v, ok := own[key]; ok {
			return v, true
		}
		v, ok := defaults[key]
		return v, ok
	}
	str := func(key string) string {
		v, ok := get(key)
		if !ok {
			return ""
		}
		if strings.Contains(v, "%(") {
			j.Unresolved[key] = v
			return ""
		}
		return v
	}

	if v, ok := get("enabled"); ok {
		j.Enabled = parseF2BBool(v)
	}
	j.Filter = str("filter")
	j.Ports = str("port")
	j.Backend = str("backend")
	if lp := str("logpath"); lp != "" {
		for _, p := range strings.Split(lp, "\n") {
			if p = strings.TrimSpace(p); p != "" {
				j.LogPaths = append(j.LogPaths, p)
			}
		}
	}
	if v := str("maxretry"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			j.MaxRetry = n
		} else {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("jail %s: invalid maxretry %q", name, v))
		}
	}
	j.FindTime = parseDurationField(name, "findtime", str("findtime"), cfg)
	j.BanTime = parseDurationField(name, "bantime", str("bantime"), cfg)
	if v := str("ignoreip"); v != "" {
		j.IgnoreIP = parseIgnoreIP(name, v, cfg)
	}
	return j
}

// parseF2BBool accepts fail2ban's truthy spellings.
func parseF2BBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

// parseDurationField parses fail2ban time values: bare seconds ("600") or
// suffixed ("10m", "1h", "1d", "2w"). Empty means unset (0). Bad values
// warn and return 0.
func parseDurationField(jail, key, v string, cfg *Config) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if d, err := parseF2BDuration(v); err == nil {
		return d
	}
	cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("jail %s: invalid %s %q", jail, key, v))
	return 0
}

// parseF2BDuration handles the suffixed forms (also day/week units, which
// Go's ParseDuration lacks).
func parseF2BDuration(v string) (time.Duration, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	unit := time.Duration(0)
	switch {
	case strings.HasSuffix(v, "w"):
		unit = 7 * 24 * time.Hour
	case strings.HasSuffix(v, "d"):
		unit = 24 * time.Hour
	}
	if unit > 0 {
		n, err := strconv.Atoi(strings.TrimSpace(v[:len(v)-1]))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", v)
		}
		return time.Duration(n) * unit, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", v)
	}
	return d, nil
}

// parseIgnoreIP validates the whitespace/comma-separated ignoreip list into
// prefixes; hostnames and junk are skipped with a warning (never resolved —
// DNS at migration time would be both slow and spoofable).
func parseIgnoreIP(jail, v string, cfg *Config) []netip.Prefix {
	var out []netip.Prefix
	for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\t' }) {
		if tok == "" {
			continue
		}
		if p, err := netip.ParsePrefix(tok); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(tok); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		cfg.Warnings = append(cfg.Warnings,
			fmt.Sprintf("jail %s: ignoreip entry %q is not an IP/CIDR (hostnames are not imported)", jail, capString(tok, 80)))
	}
	return out
}
