// SPDX-License-Identifier: AGPL-3.0-only

package main

// automerge.go — issue #588: the blocked sets no longer carry nft's
// `auto-merge` flag, because a merged interval has ONE timeout (the last
// add's) and silently rewrote its neighbour's ban lifetime — a permanent
// ban adjacent to a fresh 5-minute ban expired in 5 minutes while the cache
// still called it permanent. Two consequences are handled here:
//
//   - `add set` on an existing set is a no-op even with different flags, so
//     removing the flag from initTable alone would leave every existing
//     install merged forever. migrateAutoMerge detects the flag on the live
//     set and rebuilds it once, in one nft -f transaction.
//   - Without the flag the kernel refuses an add that overlaps an existing
//     interval instead of merging. addOverlapping keeps the two legitimate
//     shapes working: an address already covered by a broader element is
//     already enforced (succeed with CodeCoveredByInterval, do NOT cache —
//     issue #590), and a prefix that covers existing single elements
//     absorbs them (delete, retry once).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/nftnames"
)

// migrateAutoMerge rebuilds each blocked set still created with `auto-merge`
// (pre-#588 install) without the flag, preserving every element it can
// parse with its remaining lifetime. Merged intervals (`a-b`) cannot be
// re-added under a per-IP key; they are left to the daemon's reconcile,
// which re-adds their members from the store within seconds. Called with
// the table layout already applied (initTable) and before the cache is
// loaded, so the cache reflects the rebuilt set.
func (s *Server) migrateAutoMerge(ctx context.Context, n nftnames.Names) error {
	for _, set := range []string{n.Set4, n.Set6} {
		has, err := s.autoMergeFn(ctx, n, set)
		if err != nil {
			return fmt.Errorf("enforcer: inspect set %s: %w", set, err)
		}
		if !has {
			continue
		}
		all, err := s.listFn(ctx, n)
		if err != nil {
			return fmt.Errorf("enforcer: read set %s before rebuild: %w", set, err)
		}
		// listFn reads both blocked sets; keep the family this set holds.
		els := elemsOfFamily(all, set == n.Set4)
		if err := s.run(ctx, []byte(migrateAutoMergeScript(n, set, els))); err != nil {
			return fmt.Errorf("enforcer: rebuild set %s without auto-merge: %w", set, err)
		}
		slog.WarnContext(ctx, "enforcer: rebuilt blocked set without auto-merge — merged neighbours shared one timeout (issue #588); unparseable merged intervals are left to the daemon reconcile",
			"set", set, "preserved", len(els))
	}
	return nil
}

// elemsOfFamily filters a combined v4+v6 listing down to one family.
func elemsOfFamily(els []setElem, v4 bool) []setElem {
	var out []setElem
	for _, el := range els {
		var addr netip.Addr
		if a, err := netip.ParseAddr(el.ip); err == nil {
			addr = a
		} else if p, err := netip.ParsePrefix(el.ip); err == nil {
			addr = p.Addr()
		} else {
			continue
		}
		if addr.Is4() == v4 {
			out = append(out, el)
		}
	}
	return out
}

// errCoveredByInterval reports a single-address add that an existing
// broader element already enforces (issue #590): success for the caller,
// but nothing to cache.
var errCoveredByInterval = errors.New("address covered by an existing blocked interval")

// addOverlapping resolves an `add` the kernel refused for overlapping an
// existing interval. Caller holds mutateMu. req.IP passed validateIP, so it
// is a bare address or a prefix.
func (s *Server) addOverlapping(ctx context.Context, names nftnames.Names, req enforce.Request) error {
	if _, err := netip.ParseAddr(req.IP); err == nil {
		// Covered by a broader element (a prefix ban): the address is
		// already dropped. It must NOT enter the cache (issue #590): the
		// daemon's reconcile may delete the covering element as stale in
		// the same pass (the #589 migration leaves aligned merged pairs
		// behind as /31 prefixes the store never held), and a cached
		// address with its cover gone is a ghost — `list` claims it,
		// nothing enforces it, nothing ever re-adds it. The typed code
		// lets the daemon retry after its remove pass.
		slog.InfoContext(ctx, "enforcer: address already covered by a broader blocked interval — not recorded, caller may retry",
			"ip", req.IP)
		return errCoveredByInterval
	}
	pfx, _ := netip.ParsePrefix(req.IP)
	var contained []string
	s.mu.RLock()
	for key := range s.blocked {
		if a, err := netip.ParseAddr(key); err == nil && pfx.Contains(a) {
			contained = append(contained, key)
			continue
		}
		if p, err := netip.ParsePrefix(key); err == nil && pfx.Overlaps(p) && pfx.Bits() <= p.Bits() {
			contained = append(contained, key)
		}
	}
	s.mu.RUnlock()
	for _, key := range contained {
		if err := nftDel(ctx, s.run, names, key); err != nil && !errors.Is(err, errElementAbsent) {
			return fmt.Errorf("absorb %s into %s: %w", key, req.IP, err)
		}
		s.mu.Lock()
		delete(s.blocked, key)
		s.mu.Unlock()
	}
	if len(contained) > 0 {
		slog.WarnContext(ctx, "enforcer: prefix ban absorbed existing narrower elements",
			"prefix", req.IP, "absorbed", contained)
	}
	return nftAdd(ctx, s.run, names, req.IP, req.TTLSeconds)
}
