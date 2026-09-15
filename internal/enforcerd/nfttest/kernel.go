// SPDX-License-Identifier: AGPL-3.0-only

// Package nfttest is a scripted stand-in for the nftables kernel state the
// enforcer helper mutates: it applies the helper's `nft -f` scripts, keeps
// per-element timeouts on a virtual clock (garbage-collecting on advance,
// like the kernel's timer), refuses overlapping interval elements exactly as
// a set without auto-merge does, and renders `nft list set` output so the
// helper's real parsers (init, auto-merge probe) run unchanged. It exists so
// the integration harness (issue #605) can chain the real store, the real
// decision engine, the real daemon, the real enforcer client and the real
// helper without a root-only kernel — and so no test has to re-model the
// helper's cache in a fake.
//
// Semantics were verified against nftables 1.1.1/1.1.3 (issues #588/#590):
// re-adding a live element refreshes its timeout; adding an address covered
// by an existing interval, or an interval overlapping existing elements,
// fails with "interval overlaps with an existing one"; deleting an absent
// element fails with "element does not exist".
package nfttest

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type set struct {
	family    string // ipv4_addr | ipv6_addr
	autoMerge bool
	elems     map[string]time.Time // element → expiry (zero = permanent)
}

// Kernel is one scripted nftables instance.
type Kernel struct {
	mu   sync.Mutex
	now  func() time.Time
	sets map[string]*set
	// Scripts records every script applied, for assertions on churn.
	Scripts []string
}

// New returns an empty kernel on the given clock.
func New(now func() time.Time) *Kernel {
	return &Kernel{now: now, sets: map[string]*set{}}
}

// Runner returns the nft runner the helper executes scripts through
// (assignable to enforcerd's unexported nftRunner type).
func (k *Kernel) Runner() func(ctx context.Context, script []byte) error {
	return func(_ context.Context, script []byte) error {
		return k.Apply(string(script))
	}
}

// GC removes elements whose timeout has elapsed at the current clock — the
// kernel's timer. Called implicitly by every read; exposed for clarity.
func (k *Kernel) GC() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gcLocked()
}

func (k *Kernel) gcLocked() {
	now := k.now()
	for _, s := range k.sets {
		for el, exp := range s.elems {
			if !exp.IsZero() && !exp.After(now) {
				delete(s.elems, el)
			}
		}
	}
}

// Elements returns the live elements of a set, sorted.
func (k *Kernel) Elements(setName string) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gcLocked()
	s := k.sets[setName]
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.elems))
	for el := range s.elems {
		out = append(out, el)
	}
	sort.Strings(out)
	return out
}

// Expiry returns an element's expiry (zero = permanent) and presence.
func (k *Kernel) Expiry(setName, el string) (time.Time, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gcLocked()
	s := k.sets[setName]
	if s == nil {
		return time.Time{}, false
	}
	exp, ok := s.elems[el]
	return exp, ok
}

// Seed places an element directly (as a previous helper generation or an
// operator's manual `nft` might have), bypassing overlap checks. ttl 0 =
// permanent. The set is created as IPv4 unless the element is IPv6.
func (k *Kernel) Seed(setName, el string, ttl time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := k.sets[setName]
	if s == nil {
		fam := "ipv4_addr"
		if strings.Contains(el, ":") {
			fam = "ipv6_addr"
		}
		s = &set{family: fam, elems: map[string]time.Time{}}
		k.sets[setName] = s
	}
	exp := time.Time{}
	if ttl > 0 {
		exp = k.now().Add(ttl)
	}
	s.elems[el] = exp
}

// MarkAutoMerge flags a set as created with auto-merge (pre-#588 layout) so
// the helper's migration path runs against it.
func (k *Kernel) MarkAutoMerge(setName string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if s := k.sets[setName]; s != nil {
		s.autoMerge = true
	}
}

// Apply executes one nft script atomically: the first failing statement
// aborts the whole script with no partial effect (nft -f semantics).
func (k *Kernel) Apply(script string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.Scripts = append(k.Scripts, script)
	k.gcLocked()
	// Work on a copy so a failing statement leaves the kernel untouched.
	snap := k.snapshotLocked()
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := k.applyLineLocked(line); err != nil {
			k.sets = snap
			return err
		}
	}
	return nil
}

func (k *Kernel) snapshotLocked() map[string]*set {
	out := make(map[string]*set, len(k.sets))
	for n, s := range k.sets {
		c := &set{family: s.family, autoMerge: s.autoMerge, elems: make(map[string]time.Time, len(s.elems))}
		for el, exp := range s.elems {
			c.elems[el] = exp
		}
		out[n] = c
	}
	return out
}

func (k *Kernel) applyLineLocked(line string) error {
	switch {
	case strings.HasPrefix(line, "add set "):
		// add set inet ezyshield blocked { type ipv4_addr ; flags interval,timeout ; [auto-merge ;] }
		f := strings.Fields(line)
		name := f[4]
		if k.sets[name] != nil {
			return nil // idempotent, flags are NOT changed (real nft)
		}
		fam := "ipv4_addr"
		if strings.Contains(line, "ipv6_addr") {
			fam = "ipv6_addr"
		}
		k.sets[name] = &set{family: fam, autoMerge: strings.Contains(line, "auto-merge"), elems: map[string]time.Time{}}
	case strings.HasPrefix(line, "delete set "):
		f := strings.Fields(line)
		delete(k.sets, f[len(f)-1])
	case strings.HasPrefix(line, "flush set "):
		f := strings.Fields(line)
		if s := k.sets[f[len(f)-1]]; s != nil {
			s.elems = map[string]time.Time{}
		}
	case strings.HasPrefix(line, "add element "):
		name, els, err := parseElements(strings.TrimPrefix(line, "add element "))
		if err != nil {
			return err
		}
		s := k.sets[name]
		if s == nil {
			return fmt.Errorf("nft -f: exit status 1\nError: No such file or directory")
		}
		for _, e := range els {
			if !s.autoMerge {
				if err := overlaps(s, e.key); err != nil {
					return err
				}
			}
			exp := time.Time{}
			if e.ttl > 0 {
				exp = k.now().Add(e.ttl)
			}
			s.elems[e.key] = exp
		}
	case strings.HasPrefix(line, "delete element "):
		name, els, err := parseElements(strings.TrimPrefix(line, "delete element "))
		if err != nil {
			return err
		}
		s := k.sets[name]
		for _, e := range els {
			if s == nil {
				return fmt.Errorf("nft -f: exit status 1\nError: element does not exist")
			}
			if _, ok := s.elems[e.key]; !ok {
				return fmt.Errorf("nft -f: exit status 1\nError: element does not exist")
			}
			delete(s.elems, e.key)
		}
	default:
		// add table / add chain / flush chain / add rule / delete table:
		// accepted, not modelled.
	}
	return nil
}

type elem struct {
	key string
	ttl time.Duration
}

// parseElements parses `inet ezyshield <set> { a timeout 5s, b, c/24 }`.
func parseElements(rest string) (string, []elem, error) {
	head, body, ok := strings.Cut(rest, "{")
	if !ok {
		return "", nil, fmt.Errorf("nfttest: malformed element line %q", rest)
	}
	hf := strings.Fields(head)
	if len(hf) != 3 {
		return "", nil, fmt.Errorf("nfttest: malformed element head %q", head)
	}
	body = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(body), "}"))
	var out []elem
	for _, part := range strings.Split(body, ",") {
		bf := strings.Fields(part)
		if len(bf) == 0 {
			continue
		}
		e := elem{key: bf[0]}
		if len(bf) == 3 && bf[1] == "timeout" {
			d, err := time.ParseDuration(bf[2])
			if err != nil {
				return "", nil, fmt.Errorf("nfttest: bad timeout in %q: %w", part, err)
			}
			e.ttl = d
		}
		out = append(out, e)
	}
	return hf[2], out, nil
}

// overlaps enforces the no-auto-merge interval rule: an existing element
// (address or prefix) that shares any address with key → error, except an
// exact re-add of the same element (timeout refresh).
func overlaps(s *set, key string) error {
	np := toPrefix(key)
	for el := range s.elems {
		if el == key {
			return nil
		}
		if np.Overlaps(toPrefix(el)) {
			return fmt.Errorf("nft -f: exit status 1\nError: interval overlaps with an existing one")
		}
	}
	return nil
}

func toPrefix(key string) netip.Prefix {
	if p, err := netip.ParsePrefix(key); err == nil {
		return p.Masked()
	}
	if a, err := netip.ParseAddr(key); err == nil {
		return netip.PrefixFrom(a, a.BitLen())
	}
	return netip.Prefix{}
}

// ListSetOutput renders `nft list set <family> <table> <set>` for the
// helper's parsers. Unknown sets fail like nft does when the set is absent.
func (k *Kernel) ListSetOutput(_ context.Context, family, table, setName string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gcLocked()
	s := k.sets[setName]
	if s == nil {
		// The helper always runs initTable (which creates every set) before
		// it lists, so this is a harness bug, not a kernel state.
		return nil, fmt.Errorf("nfttest: set %q does not exist (initTable not applied?)", setName)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table %s %s {\n\tset %s {\n\t\ttype %s\n\t\tflags interval,timeout\n", family, table, setName, s.family)
	if s.autoMerge {
		b.WriteString("\t\tauto-merge\n")
	}
	if len(s.elems) > 0 {
		keys := make([]string, 0, len(s.elems))
		for el := range s.elems {
			keys = append(keys, el)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		now := k.now()
		for _, el := range keys {
			exp := s.elems[el]
			if exp.IsZero() {
				parts = append(parts, el)
				continue
			}
			rem := exp.Sub(now).Round(time.Second)
			parts = append(parts, fmt.Sprintf("%s timeout %s expires %s", el, rem, rem))
		}
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(parts, ",\n\t\t\t     "))
	}
	b.WriteString("\t}\n}\n")
	return []byte(b.String()), nil
}
