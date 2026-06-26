package enrich

import (
	"errors"
	"net"
	"net/netip"
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
