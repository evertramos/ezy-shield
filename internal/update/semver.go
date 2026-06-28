// Package update implements EzyShield's self-update logic: fetching releases
// from GitHub, verifying SHA256 checksums against checksums.txt, and atomically
// replacing the on-disk binaries.
//
// The package is split so the high-risk pieces (HTTP fetch, semver compare,
// checksum parsing, atomic replace) can be unit-tested without exercising the
// real filesystem or network.
package update

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// semverRE matches "v1.2.3", "1.2.3", "v1.2.3-rc.1", "v1.2.3+build.1", etc.
// Captures: 1=major, 2=minor, 3=patch, 4=prerelease (without leading '-').
var semverRE = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

// CompareSemver returns -1, 0, or 1 if a<b, a==b, or a>b respectively, using
// semver precedence (prerelease ranks below the same base version).
//
// Returns an error if either side is not parseable as semver (e.g. "dev",
// "unknown"). Callers should treat that as "cannot determine — proceed".
func CompareSemver(a, b string) (int, error) {
	ap, err := parseSemver(a)
	if err != nil {
		return 0, fmt.Errorf("compare %q: %w", a, err)
	}
	bp, err := parseSemver(b)
	if err != nil {
		return 0, fmt.Errorf("compare %q: %w", b, err)
	}
	for i := 0; i < 3; i++ {
		if ap.nums[i] < bp.nums[i] {
			return -1, nil
		}
		if ap.nums[i] > bp.nums[i] {
			return 1, nil
		}
	}
	// Same major.minor.patch — prerelease loses to no-prerelease.
	switch {
	case ap.pre == "" && bp.pre != "":
		return 1, nil
	case ap.pre != "" && bp.pre == "":
		return -1, nil
	case ap.pre == bp.pre:
		return 0, nil
	case ap.pre < bp.pre:
		return -1, nil
	default:
		return 1, nil
	}
}

type semverParts struct {
	nums [3]int
	pre  string
}

func parseSemver(v string) (semverParts, error) {
	v = strings.TrimSpace(v)
	m := semverRE.FindStringSubmatch(v)
	if m == nil {
		return semverParts{}, fmt.Errorf("not a semver version")
	}
	var p semverParts
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return semverParts{}, fmt.Errorf("parse component: %w", err)
		}
		p.nums[i] = n
	}
	p.pre = m[4]
	return p, nil
}
