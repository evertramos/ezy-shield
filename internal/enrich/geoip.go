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

// openFunc opens an MMDB file at path and returns a reader. It is a field on
// Enricher so tests can inject instrumented readers through the real Reload
// path; production uses openMMDB.
type openFunc func(path string) (dbReader, error)

// openMMDB is the production opener. It avoids returning a non-nil interface
// wrapping a nil *maxminddb.Reader (the typed-nil trap) on error.
func openMMDB(path string) (dbReader, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return r, nil
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

	open openFunc
}

// New opens MMDB files at countryPath and asnPath.
// Either path may be empty or point to a missing file — the enricher starts in
// degraded mode (empty enrichment) rather than returning an error.
func New(countryPath, asnPath string) *Enricher {
	e := &Enricher{countryPath: countryPath, asnPath: asnPath, open: openMMDB}
	if countryPath != "" {
		r, err := e.open(countryPath)
		if err != nil {
			slog.Warn("enrich: country DB unavailable; enrichment degraded", "path", countryPath, "err", err)
		} else {
			e.countryDB = r
		}
	}
	if asnPath != "" {
		r, err := e.open(asnPath)
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
	return &Enricher{countryDB: country, asnDB: asn, open: openMMDB}
}

// Lookup returns geo/ASN metadata for addr.
// Returns an empty Enrichment when databases are not loaded or lookup fails.
func (e *Enricher) Lookup(addr netip.Addr) sdk.Enrichment {
	ip := toNetIP(addr.Unmap())
	if ip == nil {
		return sdk.Enrichment{}
	}

	// Hold the read lock for the entire duration of the mmap-backed reads.
	// The previous code copied the reader pointers under RLock and released it
	// before calling Lookup, so a concurrent Reload could Close() (munmap) a
	// reader mid-read — dereferencing unmapped memory (SIGSEGV) or the nil'd
	// buffer, killing the root daemon. Keeping RLock held for the whole read
	// forces Reload's WLock — and therefore the Close that follows it — to
	// wait until every in-flight lookup has returned. RLock still admits
	// concurrent lookups; only the rare (weekly) Reload blocks. (issue #310)
	e.mu.RLock()
	defer e.mu.RUnlock()

	var out sdk.Enrichment

	if e.countryDB != nil {
		var rec countryRecord
		if err := e.countryDB.Lookup(ip, &rec); err == nil {
			out.Country = rec.Country.ISOCode
		}
	}

	if e.asnDB != nil {
		var rec asnRecord
		if err := e.asnDB.Lookup(ip, &rec); err == nil {
			out.ASN = rec.ASN
			out.ASNOrg = rec.ASNOrg
		}
	}

	return out
}

// Reload atomically swaps in freshly-opened MMDB readers for countryPath and
// asnPath (the paths passed to New). Old readers are closed only after the swap
// and after in-flight lookups have drained: the swap happens under the write
// lock (which cannot be acquired while any Lookup holds the read lock), and by
// the time Close runs the fields already point at the new readers, so no lookup
// can still reach the ones being closed. Called by Updater after a successful
// download. A failed open is logged and the existing reader is kept.
func (e *Enricher) Reload() {
	var toClose []dbReader

	e.mu.Lock()
	if e.countryPath != "" {
		r, err := e.open(e.countryPath)
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
		r, err := e.open(e.asnPath)
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

	// Safe to Close outside the lock: the swap above already replaced the field
	// references, and the write lock guaranteed no Lookup was mid-read on these
	// readers. Any Lookup that starts now reads the new readers under RLock.
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
