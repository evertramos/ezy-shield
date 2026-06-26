// Package enrich provides O(1) GeoIP/ASN lookups via MaxMind MMDB files.
// When no databases are loaded, Lookup returns empty Enrichment — the daemon
// never crashes due to missing or corrupt DB files.
package enrich

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/oschwald/maxminddb-golang"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// dbReader is the minimal interface consumed from *maxminddb.Reader.
// The abstraction enables mock injection in tests.
type dbReader interface {
	Lookup(ip net.IP, v any) error
	Close() error
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type asnRecord struct {
	ASN    uint32 `maxminddb:"autonomous_system_number"`
	ASNOrg string `maxminddb:"autonomous_system_organization"`
}

// Enricher performs GeoIP/ASN lookups against MaxMind MMDB files.
// It is safe for concurrent use and supports hot-reload via Reload.
type Enricher struct {
	mu        sync.RWMutex
	countryDB dbReader
	asnDB     dbReader

	countryPath string
	asnPath     string
}

// New opens MMDB files at countryPath and asnPath.
// Either path may be empty or point to a missing file — the enricher starts in
// degraded mode (empty enrichment) rather than returning an error.
func New(countryPath, asnPath string) *Enricher {
	e := &Enricher{countryPath: countryPath, asnPath: asnPath}
	if countryPath != "" {
		r, err := maxminddb.Open(countryPath)
		if err != nil {
			slog.Warn("enrich: country DB unavailable; enrichment degraded", "path", countryPath, "err", err)
		} else {
			e.countryDB = r
		}
	}
	if asnPath != "" {
		r, err := maxminddb.Open(asnPath)
		if err != nil {
			slog.Warn("enrich: ASN DB unavailable; enrichment degraded", "path", asnPath, "err", err)
		} else {
			e.asnDB = r
		}
	}
	return e
}

// newWithReaders constructs an Enricher from pre-built readers.
// Used by tests to inject mocks without touching the filesystem.
func newWithReaders(country, asn dbReader) *Enricher {
	return &Enricher{countryDB: country, asnDB: asn}
}

// Lookup returns geo/ASN metadata for addr.
// Returns an empty Enrichment when databases are not loaded or lookup fails.
func (e *Enricher) Lookup(addr netip.Addr) sdk.Enrichment {
	ip := toNetIP(addr.Unmap())
	if ip == nil {
		return sdk.Enrichment{}
	}

	e.mu.RLock()
	cDB, aDB := e.countryDB, e.asnDB
	e.mu.RUnlock()

	var out sdk.Enrichment

	if cDB != nil {
		var rec countryRecord
		if err := cDB.Lookup(ip, &rec); err == nil {
			out.Country = rec.Country.ISOCode
		}
	}

	if aDB != nil {
		var rec asnRecord
		if err := aDB.Lookup(ip, &rec); err == nil {
			out.ASN = rec.ASN
			out.ASNOrg = rec.ASNOrg
		}
	}

	return out
}

// Reload atomically swaps in freshly-opened MMDB readers for countryPath and
// asnPath (the paths passed to New). Old readers are closed after the swap.
// Called by Updater after a successful download. A failed open is logged and
// the existing reader is kept.
func (e *Enricher) Reload() {
	var toClose []dbReader

	e.mu.Lock()
	if e.countryPath != "" {
		r, err := maxminddb.Open(e.countryPath)
		if err != nil {
			slog.Warn("enrich: reload country DB failed; keeping existing", "err", err)
		} else {
			if e.countryDB != nil {
				toClose = append(toClose, e.countryDB)
			}
			e.countryDB = r
		}
	}
	if e.asnPath != "" {
		r, err := maxminddb.Open(e.asnPath)
		if err != nil {
			slog.Warn("enrich: reload ASN DB failed; keeping existing", "err", err)
		} else {
			if e.asnDB != nil {
				toClose = append(toClose, e.asnDB)
			}
			e.asnDB = r
		}
	}
	e.mu.Unlock()

	for _, r := range toClose {
		_ = r.Close()
	}
}

// Close releases MMDB file handles.
func (e *Enricher) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.countryDB != nil {
		_ = e.countryDB.Close()
		e.countryDB = nil
	}
	if e.asnDB != nil {
		_ = e.asnDB.Close()
		e.asnDB = nil
	}
}

// toNetIP converts a netip.Addr to net.IP.
// addr must already be Unmap()'d (no IPv4-in-IPv6 wrappers).
func toNetIP(addr netip.Addr) net.IP {
	if !addr.IsValid() {
		return nil
	}
	if addr.Is4() {
		b := addr.As4()
		return net.IP(b[:])
	}
	b := addr.As16()
	return net.IP(b[:])
}
