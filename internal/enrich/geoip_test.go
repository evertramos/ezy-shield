// SPDX-License-Identifier: AGPL-3.0-only

package enrich

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// mockReader is a test double for dbReader.
type mockReader struct {
	country string
	asn     uint32
	asnOrg  string
	err     error
}

func (m *mockReader) Lookup(ip net.IP, v any) error {
	if m.err != nil {
		return m.err
	}
	switch dst := v.(type) {
	case *countryRecord:
		dst.Country.ISOCode = m.country
	case *asnRecord:
		dst.ASN = m.asn
		dst.ASNOrg = m.asnOrg
	}
	return nil
}

func (m *mockReader) Close() error { return nil }

func addr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func TestEnricher_NoDB(t *testing.T) {
	e := New("", "")
	got := e.Lookup(addr("1.2.3.4"))
	if got != (sdk.Enrichment{}) {
		t.Errorf("want empty enrichment, got %+v", got)
	}
}

func TestEnricher_MissingFiles(t *testing.T) {
	e := New("/nonexistent/country.mmdb", "/nonexistent/asn.mmdb")
	got := e.Lookup(addr("1.2.3.4"))
	if got != (sdk.Enrichment{}) {
		t.Errorf("want empty enrichment for missing files, got %+v", got)
	}
}

func TestEnricher_MockCountryAndASN(t *testing.T) {
	cDB := &mockReader{country: "BR"}
	aDB := &mockReader{asn: 12345, asnOrg: "Example ISP"}
	e := newWithReaders(cDB, aDB)

	got := e.Lookup(addr("203.0.113.1"))
	if got.Country != "BR" {
		t.Errorf("Country: want BR, got %q", got.Country)
	}
	if got.ASN != 12345 {
		t.Errorf("ASN: want 12345, got %d", got.ASN)
	}
	if got.ASNOrg != "Example ISP" {
		t.Errorf("ASNOrg: want %q, got %q", "Example ISP", got.ASNOrg)
	}
}

func TestEnricher_IPv4MappedIPv6(t *testing.T) {
	cDB := &mockReader{country: "US"}
	e := newWithReaders(cDB, nil)

	// ::ffff:1.2.3.4 is an IPv4-in-IPv6; Unmap() converts it to pure IPv4.
	got := e.Lookup(addr("::ffff:1.2.3.4"))
	if got.Country != "US" {
		t.Errorf("Country: want US, got %q", got.Country)
	}
}

func TestEnricher_LookupError(t *testing.T) {
	cDB := &mockReader{err: errors.New("db error")}
	aDB := &mockReader{err: errors.New("db error")}
	e := newWithReaders(cDB, aDB)

	got := e.Lookup(addr("1.2.3.4"))
	if got != (sdk.Enrichment{}) {
		t.Errorf("want empty enrichment on lookup error, got %+v", got)
	}
}

func TestEnricher_CountryOnly(t *testing.T) {
	e := newWithReaders(&mockReader{country: "DE"}, nil)
	got := e.Lookup(addr("8.8.8.8"))
	if got.Country != "DE" {
		t.Errorf("Country: want DE, got %q", got.Country)
	}
	if got.ASN != 0 || got.ASNOrg != "" {
		t.Errorf("want zero ASN fields, got asn=%d org=%q", got.ASN, got.ASNOrg)
	}
}

func TestEnricher_ASNOnly(t *testing.T) {
	e := newWithReaders(nil, &mockReader{asn: 7922, asnOrg: "Comcast"})
	got := e.Lookup(addr("::1"))
	if got.Country != "" {
		t.Errorf("want empty Country, got %q", got.Country)
	}
	if got.ASN != 7922 {
		t.Errorf("ASN: want 7922, got %d", got.ASN)
	}
}

func TestEnricher_Close(t *testing.T) {
	e := newWithReaders(&mockReader{}, &mockReader{})
	e.Close()
	// After Close the readers are nil; Lookup must still return empty (no panic).
	got := e.Lookup(addr("1.2.3.4"))
	if got != (sdk.Enrichment{}) {
		t.Errorf("want empty enrichment after close, got %+v", got)
	}
}

// raceReader models a maxminddb reader whose Close() munmaps its backing
// buffer (buffer = nil), exactly as maxminddb-golang v1.13.1 does in
// reader_mmap.go. A Lookup that reads buf concurrently with a Close that nils
// it is a data race — the in-process, race-detector-observable analogue of the
// use-after-munmap SIGSEGV that issue #310 fixes. In production the same
// unsynchronized access dereferences unmapped memory and kills the daemon.
type raceReader struct {
	buf     []byte
	country string
}

func newRaceReader(country string) *raceReader {
	return &raceReader{buf: make([]byte, 4096), country: country}
}

func (r *raceReader) Lookup(_ net.IP, v any) error {
	// Read the mmap-backed buffer, as a real lookup would. Racing with Close's
	// r.buf = nil, this is the flagged read.
	if len(r.buf) == 0 {
		return errors.New("closed reader")
	}
	_ = r.buf[len(r.buf)-1]
	switch dst := v.(type) {
	case *countryRecord:
		dst.Country.ISOCode = r.country
	case *asnRecord:
		dst.ASN = 64500
	}
	return nil
}

func (r *raceReader) Close() error {
	r.buf = nil // simulates munmap of the mmap'd region
	return nil
}

// TestEnricher_LookupReloadRace hammers Lookup on many goroutines while Reload
// repeatedly swaps and closes (munmaps) the underlying readers. It must be
// clean under `go test -race`; on the pre-fix code (Lookup copies the reader
// pointer and releases the lock before reading) the detector flags a read of
// the closed reader's buffer against Reload's Close. (issue #310)
func TestEnricher_LookupReloadRace(t *testing.T) {
	e := newWithReaders(newRaceReader("BR"), newRaceReader("BR"))
	// Drive Reload through its real path, but open instrumented readers instead
	// of touching the filesystem.
	e.countryPath = "country"
	e.asnPath = "asn"
	e.open = func(_ string) (dbReader, error) { return newRaceReader("BR"), nil }

	const readers = 8
	const reloads = 100

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = e.Lookup(addr("203.0.113.7"))
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < reloads; i++ {
			e.Reload()
		}
		close(stop)
	}()

	wg.Wait()
	e.Close()
}

func TestToNetIP(t *testing.T) {
	cases := []struct {
		in   string
		want net.IP
	}{
		{"1.2.3.4", net.IP{1, 2, 3, 4}},
		{"2001:db8::1", net.ParseIP("2001:db8::1").To16()},
	}
	for _, tc := range cases {
		a := addr(tc.in)
		got := toNetIP(a.Unmap())
		if !got.Equal(tc.want) {
			t.Errorf("toNetIP(%s): want %v, got %v", tc.in, tc.want, got)
		}
	}
}
