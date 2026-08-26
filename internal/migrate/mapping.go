// SPDX-License-Identifier: AGPL-3.0-only

package migrate

// Second half of the fail2ban migration (issue #182): map the modeled
// fail2ban configuration onto EzyShield concepts. Pure — no I/O; the CLI
// command renders files from the returned Migration and never touches /etc
// without an explicit --write.
//
// v1 mapping table (from the issue):
//
//	sshd                  → journald/ssh collector + built-in ssh rules
//	nginx-*               → nginx parser file collectors + built-in http rules
//	apache-*              → apache parser file collectors
//	postfix*, dovecot     → reported: parser planned (issues #188/#189)
//	recidive              → covered natively by strike escalation
//	ignoreip              → allowlist entries (validated prefixes)
//	maxretry/findtime     → report note (rules.d tuning, thresholds differ)
//	bantime               → strike-1 TTL suggestion in the report only
//	unknown/custom filter → listed in the report with the filter name
//
// Custom regex filters are never translated (report-only, per the issue).

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// MappedCollector is one collector the migration proposes.
type MappedCollector struct {
	Kind     string // "journald" | "file"
	Unit     string // journald
	Path     string // file
	Parser   string // file
	FromJail string
}

// MappedJail records a jail the migration handled, with how.
type MappedJail struct {
	Jail Jail
	How  string
}

// UnmappedJail records a jail v1 cannot map, with why (and the filter name
// so the operator can find its regexes).
type UnmappedJail struct {
	Jail   Jail
	Reason string
}

// Migration is the full mapping result the CLI renders into files.
type Migration struct {
	Collectors []MappedCollector
	// Allowlist is the union of every enabled jail's ignoreip (deduped,
	// sorted) — fail2ban's ignoreip maps onto EzyShield's policy allowlist.
	Allowlist []netip.Prefix
	Mapped    []MappedJail
	Unmapped  []UnmappedJail
	// Skipped are disabled jails (listed so the report is complete).
	Skipped []string
	// BanTimeSuggestion is the largest enabled bantime seen — reported as a
	// strike-1 TTL suggestion only (EzyShield escalates; fail2ban is fixed).
	BanTimeSuggestion time.Duration
	// Notes carries the standing differences the report must explain.
	Notes []string
}

// MapToEzyShield converts the modeled fail2ban config. It never fails on
// content — everything it cannot map lands in Unmapped/Skipped.
func MapToEzyShield(cfg *Config) *Migration {
	m := &Migration{}
	seenCollector := map[string]bool{}
	allow := map[netip.Prefix]bool{}

	for _, j := range cfg.Jails {
		if !j.Enabled {
			m.Skipped = append(m.Skipped, j.Name)
			continue
		}
		for _, p := range j.IgnoreIP {
			allow[p] = true
		}
		if j.BanTime > m.BanTimeSuggestion {
			m.BanTimeSuggestion = j.BanTime
		}
		mapJail(m, seenCollector, j)
	}

	for p := range allow {
		m.Allowlist = append(m.Allowlist, p)
	}
	sort.Slice(m.Allowlist, func(i, k int) bool {
		return m.Allowlist[i].String() < m.Allowlist[k].String()
	})

	m.Notes = append(m.Notes,
		"fail2ban bans for a FIXED time per jail; EzyShield escalates per offender (5m → 1h → 24h → 7d → permanent). The largest bantime seen is reported as a strike-1 TTL suggestion only.",
		"maxretry/findtime have no 1:1 equivalent: EzyShield's built-in rules carry tuned thresholds per window, adjustable via /etc/ezyshield/rules.d drop-ins (merged by rule name).",
		"custom fail2ban filters (regexes) are not translated — review the built-in rules and rules.d before disabling fail2ban.",
	)
	return m
}

// mapJail applies the v1 table to one enabled jail.
func mapJail(m *Migration, seen map[string]bool, j Jail) {
	name := strings.ToLower(j.Name)
	switch {
	case name == "sshd" || name == "ssh":
		// journald is the right source regardless of the file logpath
		// fail2ban was tailing; the unit name differs per distro.
		addCollector(m, seen, MappedCollector{Kind: "journald", Unit: "ssh", FromJail: j.Name})
		m.Mapped = append(m.Mapped, MappedJail{Jail: j,
			How: "journald SSH collector + built-in ssh_bruteforce rule family (adjust the unit name: 'ssh' on Debian/Ubuntu, 'sshd' on RHEL)"})

	case name == "recidive":
		m.Mapped = append(m.Mapped, MappedJail{Jail: j,
			How: "covered natively — repeat offenders escalate through the strike ladder; no collector needed"})

	case strings.HasPrefix(name, "nginx"):
		mapWebJail(m, seen, j, "nginx")

	case strings.HasPrefix(name, "apache"):
		mapWebJail(m, seen, j, "apache")

	case strings.HasPrefix(name, "postfix"):
		m.Unmapped = append(m.Unmapped, UnmappedJail{Jail: j,
			Reason: "postfix parser is planned (issue #188) — keep this jail on fail2ban until it ships (filter: " + filterName(j) + ")"})

	case strings.HasPrefix(name, "dovecot"):
		m.Unmapped = append(m.Unmapped, UnmappedJail{Jail: j,
			Reason: "dovecot parser is planned (issue #189) — keep this jail on fail2ban until it ships (filter: " + filterName(j) + ")"})

	default:
		m.Unmapped = append(m.Unmapped, UnmappedJail{Jail: j,
			Reason: "no EzyShield equivalent for this jail/filter (filter: " + filterName(j) + ") — custom filters are not translated"})
	}
}

// mapWebJail emits file collectors for a web-server jail's log paths.
func mapWebJail(m *Migration, seen map[string]bool, j Jail, parser string) {
	if len(j.LogPaths) == 0 {
		reason := "logpath is empty"
		if raw, ok := j.Unresolved["logpath"]; ok {
			reason = fmt.Sprintf("logpath uses fail2ban interpolation (%s) — set the real path and re-run, or add the collector manually", raw)
		}
		m.Unmapped = append(m.Unmapped, UnmappedJail{Jail: j, Reason: reason})
		return
	}
	for _, p := range j.LogPaths {
		addCollector(m, seen, MappedCollector{Kind: "file", Path: p, Parser: parser, FromJail: j.Name})
	}
	how := fmt.Sprintf("%s parser file collector(s) + built-in http rule family", parser)
	if strings.Contains(strings.Join(j.LogPaths, " "), "error") {
		how += " (note: EzyShield's http rules read ACCESS logs; an error-log jail's signal is covered by the access-log rules instead)"
	}
	m.Mapped = append(m.Mapped, MappedJail{Jail: j, How: how})
}

func filterName(j Jail) string {
	if j.Filter != "" {
		return j.Filter
	}
	return j.Name + " (default)"
}

// addCollector dedupes by (kind, unit/path, parser). The zero value is a
// no-op so callers can use it unconditionally.
func addCollector(m *Migration, seen map[string]bool, c MappedCollector) {
	if c.Kind == "" {
		return
	}
	key := c.Kind + "|" + c.Unit + "|" + c.Path + "|" + c.Parser
	if seen[key] {
		return
	}
	seen[key] = true
	m.Collectors = append(m.Collectors, c)
}
