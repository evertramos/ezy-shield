// Package nftnames is the single source of truth for the nftables table and
// set names EzyShield enforces into (issue #268).
//
// It is a leaf package (no internal imports) on purpose: both sides of the
// privilege boundary depend on it — internal/config validates operator input
// at load time, internal/enforce puts the names on the wire, and
// cmd/ezyshield-enforcer re-validates them before they get anywhere near an
// nft script. The privileged helper NEVER trusts the daemon: everything that
// reaches script generation must have passed Resolve in the helper's own
// process (SECURITY-REVIEW.md §3).
//
// Validation is deliberately stricter than what nftables itself would accept:
// names are limited to [A-Za-z_][A-Za-z0-9_]* so a name can never smuggle nft
// syntax (spaces, semicolons, braces) into a generated script, and the table
// family is fixed to inet — the enforcer's dual-stack rule layout (v4+v6 sets
// in one table) only works there.
package nftnames

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// DefaultTable is the nftables table used when config leaves
	// enforce.nftables.table empty. The family is part of the name.
	DefaultTable = "inet ezyshield"
	// DefaultSet is the IPv4 blocked set used when config leaves
	// enforce.nftables.set empty. The IPv6 twin is derived: DefaultSet + "6".
	DefaultSet = "blocked"

	// maxNameLen caps identifier length. nftables allows longer, but nothing
	// legitimate needs more and shorter keeps generated scripts readable.
	maxNameLen = 32
)

// nameRe is the identifier charset. Conservative on purpose — see the
// package comment. First char must not be a digit (nft parser requirement).
var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Names holds the fully-resolved nftables object names the enforcer operates
// on. Allow-set names are fixed (they are an EzyShield-internal invariant —
// the anti-lockout rules reference them) but live in the same table.
type Names struct {
	// Table is the full table spec including family, e.g. "inet ezyshield".
	Table string
	// Set4 / Set6 hold banned IPv4 / IPv6 addresses. Set6 is always
	// Set4 + "6" — one config knob, both families covered.
	Set4 string
	Set6 string
	// Allow4 / Allow6 are the allowlist sets (fixed names).
	Allow4 string
	Allow6 string
}

// IsDefault reports whether n is exactly the default name set.
func (n Names) IsDefault() bool {
	d, _ := Resolve("", "")
	return n == d
}

// Resolve validates and normalizes the operator-supplied table and set names
// (empty means default) into the full Names the enforcer uses.
//
// Accepted table forms: "" (default), "<name>" (family defaults to inet), or
// "inet <name>". Any other family is rejected — the enforcer's rule layout is
// inet-only. Set must be "" or a bare identifier; the IPv6 set is derived by
// appending "6".
func Resolve(table, set string) (Names, error) {
	table = strings.TrimSpace(table)
	set = strings.TrimSpace(set)

	tableName := "ezyshield"
	if table != "" {
		fields := strings.Fields(table)
		switch len(fields) {
		case 1:
			tableName = fields[0]
		case 2:
			if fields[0] != "inet" {
				return Names{}, fmt.Errorf("nftables table family must be 'inet' (got %q): the enforcer's dual-stack v4+v6 layout requires it", fields[0])
			}
			tableName = fields[1]
		default:
			return Names{}, fmt.Errorf("nftables table must be '<name>' or 'inet <name>', got %q", table)
		}
		if err := validName("table", tableName); err != nil {
			return Names{}, err
		}
	}

	setName := DefaultSet
	if set != "" {
		if err := validName("set", set); err != nil {
			return Names{}, err
		}
		// One char of headroom: the IPv6 twin appends "6".
		if len(set) >= maxNameLen {
			return Names{}, fmt.Errorf("nftables set name %q is longer than %d characters (the derived IPv6 set appends '6')", set, maxNameLen-1)
		}
		// The allowlist sets are a fixed anti-lockout invariant living in the
		// same table — a blocked set may not shadow them.
		if set == "allowed" || set == "allowed6" {
			return Names{}, fmt.Errorf("nftables set name %q collides with the reserved allowlist sets (allowed/allowed6)", set)
		}
		setName = set
	}

	return Names{
		Table:  "inet " + tableName,
		Set4:   setName,
		Set6:   setName + "6",
		Allow4: "allowed",
		Allow6: "allowed6",
	}, nil
}

// validName enforces the conservative identifier rules.
func validName(kind, name string) error {
	if len(name) > maxNameLen {
		return fmt.Errorf("nftables %s name %q is longer than %d characters", kind, name, maxNameLen)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("nftables %s name %q must match [A-Za-z_][A-Za-z0-9_]* — letters, digits and underscore only", kind, name)
	}
	return nil
}
