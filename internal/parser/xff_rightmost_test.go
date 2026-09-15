// SPDX-License-Identifier: AGPL-3.0-only

package parser_test

// Regression tests for issue #612: with the connecting address inside
// trusted_proxies, the client is the RIGHTMOST hop of X-Forwarded-For that
// is not itself a trusted proxy. Proxies and CDNs append the connecting
// address, so a client-supplied header arrives as "<forged>, <real client>";
// taking the leftmost hop let the client choose which IP earned the ban.

import (
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

var trusted = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

// want "" means "fall back to remote_addr" (the trusted proxy's own address).
var xffCases = []struct {
	name string
	xff  string
	want string
}{
	{"forged then real", "203.0.113.9, 198.51.100.7", "198.51.100.7"},
	{"forged, real, trusted proxy", "203.0.113.9, 198.51.100.7, 10.0.0.99", "198.51.100.7"},
	{"single hop", "203.0.113.9", "203.0.113.9"},
	{"all trusted after the client", "203.0.113.7, 10.0.0.99, 10.0.0.5", "203.0.113.7"},
	{"real hop carries a port (IIS ARR, Azure AppGW)", "203.0.113.9, 198.51.100.7:54321", "198.51.100.7"},
	{"real hop is bracketed v6 with port", "203.0.113.9, [2001:db8::7]:443", "2001:db8::7"},
	{"real hop is mapped v4", "203.0.113.9, ::ffff:198.51.100.7", "198.51.100.7"},
	{"mapped spelling of a trusted proxy is still trusted", "203.0.113.9, ::ffff:10.0.0.99", "203.0.113.9"},
	{"proxy appended unknown (squid forwarded_for off)", "203.0.113.9, unknown", ""},
	{"proxy appended an obfuscated identifier (RFC 7239)", "203.0.113.9, _hidden", ""},
	{"garbage as the rightmost token", "198.51.100.7, garbage", ""},
	{"only trusted hops", "10.0.0.99, 10.0.0.5", ""},
	{"empty", "", ""},
}

func TestXFF_RightmostUntrustedHop(t *testing.T) {
	for _, tc := range xffCases {
		t.Run("nginx/"+tc.name, func(t *testing.T) {
			p := parser.NewNginxParser(discardLogger(), parser.NginxConfig{TrustedProxies: trusted})
			evs, err := p.Parse(sdk.RawLine{Source: "nginx:json", At: time.Now(),
				Line: []byte(`{"remote_addr":"10.0.0.1","request":"GET / HTTP/1.1","status":"200","body_bytes_sent":"0","http_user_agent":"t","http_x_forwarded_for":"` + tc.xff + `"}`)})
			if err != nil || len(evs) != 1 {
				t.Fatalf("parse: %d events, err=%v", len(evs), err)
			}
			want := tc.want
			if want == "" {
				want = "10.0.0.1"
			}
			if got := evs[0].SourceIP.String(); got != want {
				t.Errorf("SourceIP = %s, want %s", got, want)
			}
		})
		t.Run("caddy/"+tc.name, func(t *testing.T) {
			p := parser.NewCaddyParser(discardLogger(), parser.CaddyConfig{TrustedProxies: trusted})
			evs, err := p.Parse(sdk.RawLine{Source: "caddy:caddy", At: time.Now(),
				Line: []byte(`{"request":{"remote_ip":"10.0.0.5","method":"GET","uri":"/","host":"x","headers":{"X-Forwarded-For":["` + tc.xff + `"]}},"status":200,"size":0,"duration":0.001}`)})
			if err != nil || len(evs) != 1 {
				t.Fatalf("parse: %d events, err=%v", len(evs), err)
			}
			want := tc.want
			if want == "" {
				want = "10.0.0.5"
			}
			if got := evs[0].SourceIP.String(); got != want {
				t.Errorf("SourceIP = %s, want %s", got, want)
			}
		})
		t.Run("traefik/"+tc.name, func(t *testing.T) {
			p := parser.NewTraefikParser(discardLogger(), parser.TraefikConfig{TrustedProxies: trusted})
			evs, err := p.Parse(sdk.RawLine{Source: "traefik:traefik", At: time.Now(),
				Line: []byte(`{"ClientAddr":"10.0.0.5:1234","ClientHost":"10.0.0.5","RequestMethod":"GET","RequestPath":"/","RequestProtocol":"HTTP/1.1","DownstreamStatus":200,"DownstreamContentSize":0,"request_X-Forwarded-For":"` + tc.xff + `","request_User-Agent":"t"}`)})
			if err != nil || len(evs) != 1 {
				t.Fatalf("parse: %d events, err=%v", len(evs), err)
			}
			want := tc.want
			if want == "" {
				want = "10.0.0.5"
			}
			if got := evs[0].SourceIP.String(); got != want {
				t.Errorf("SourceIP = %s, want %s", got, want)
			}
		})
	}
}

// TestXFF_CaddyRepeatedHeaderValuesAreOneList: a trusted proxy that adds
// its own X-Forwarded-For line (HAProxy's default) makes Caddy log two
// values, the client's first. They are one list in order — the proxy's
// value is still the rightmost, trusted suffix.
func TestXFF_CaddyRepeatedHeaderValuesAreOneList(t *testing.T) {
	p := parser.NewCaddyParser(discardLogger(), parser.CaddyConfig{TrustedProxies: trusted})
	evs, err := p.Parse(sdk.RawLine{Source: "caddy:caddy", At: time.Now(),
		Line: []byte(`{"request":{"remote_ip":"10.0.0.5","method":"GET","uri":"/","host":"x","headers":{"X-Forwarded-For":["203.0.113.9","198.51.100.7"]}},"status":200,"size":0,"duration":0.001}`)})
	if err != nil || len(evs) != 1 {
		t.Fatalf("parse: %d events, err=%v", len(evs), err)
	}
	if got := evs[0].SourceIP.String(); got != "198.51.100.7" {
		t.Errorf("SourceIP = %s, want 198.51.100.7 (the proxy-added value, not the client's line)", got)
	}
}
