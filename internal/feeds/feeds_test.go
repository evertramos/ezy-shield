package feeds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "feeds", name)) //nolint:gosec // test fixture path from a compile-time constant set
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

// serveFeed builds an https test server returning body (with optional knobs)
// and a Fetcher whose client trusts it.
type feedServer struct {
	body        []byte
	status      int
	etag        string
	hits        atomic.Int32
	notModOn304 bool
}

func newFeedFetcher(t *testing.T, fs *feedServer) (*Fetcher, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.hits.Add(1)
		if fs.notModOn304 && fs.etag != "" && r.Header.Get("If-None-Match") == fs.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if fs.etag != "" {
			w.Header().Set("ETag", fs.etag)
		}
		status := fs.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(fs.body)
	}))
	t.Cleanup(ts.Close)
	return New(ts.Client(), nil), ts.URL
}

func feedCfg(url, format string) FeedConfig {
	return FeedConfig{Name: "test", URL: url, Format: format, Timeout: 5 * time.Second}
}

func prefixSet(t *testing.T, res *Result) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, p := range res.Prefixes {
		out[p.String()] = true
	}
	return out
}

// ── Format parsing (table-driven over fixtures) ──────────────────────────────

func TestFetch_Formats(t *testing.T) {
	cases := []struct {
		fixture     string
		format      string
		want        []string
		wantAbsent  []string
		wantInvalid int
	}{
		{
			fixture: "spamhaus-drop.txt",
			format:  "cidr",
			want:    []string{"192.0.2.0/24", "198.51.100.0/25", "203.0.113.64/26", "2001:db8:100::/48"},
		},
		{
			fixture: "firehol.txt",
			format:  "cidr",
			want:    []string{"192.0.2.16/28", "198.51.100.200/32", "203.0.113.0/24", "2001:db8:2::/64"},
		},
		{
			fixture: "abuseipdb.txt",
			format:  "abuseipdb",
			want:    []string{"192.0.2.10/32", "192.0.2.11/32", "198.51.100.42/32", "2001:db8::bad/128"},
		},
		{
			fixture: "garbage.txt",
			format:  "plain",
			// A lone CR is NOT a line separator: "injected\r192.0.2.52" is
			// one invalid line — CRLF injection cannot smuggle an entry.
			want:        []string{"192.0.2.50/32", "192.0.2.51/32"},
			wantInvalid: 7, // binary, ANSI, injected+CR, not-an-ip, 999..., /33 in plain, 300...
		},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			f, url := newFeedFetcher(t, &feedServer{body: fixture(t, tc.fixture)})
			res, err := f.Fetch(context.Background(), feedCfg(url, tc.format))
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			got := prefixSet(t, res)
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing %s in %v", w, res.Prefixes)
				}
			}
			if len(res.Prefixes) != len(tc.want) {
				t.Errorf("prefixes = %v, want exactly %d", res.Prefixes, len(tc.want))
			}
			if tc.wantInvalid > 0 && res.Invalid < tc.wantInvalid {
				t.Errorf("Invalid = %d, want >= %d", res.Invalid, tc.wantInvalid)
			}
		})
	}
}

// TestFetch_PrivateSmuggling pins the core poisoning defense: reserved
// ranges NEVER pass, regardless of how they are written.
func TestFetch_PrivateSmuggling(t *testing.T) {
	f, url := newFeedFetcher(t, &feedServer{body: fixture(t, "private-smuggle.txt")})
	res, err := f.Fetch(context.Background(), feedCfg(url, "cidr"))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got := prefixSet(t, res)
	if len(res.Prefixes) != 2 || !got["192.0.2.99/32"] || !got["198.51.100.7/32"] {
		t.Fatalf("prefixes = %v, want only the two public examples", res.Prefixes)
	}
	if res.DroppedReserved != 11 {
		t.Errorf("DroppedReserved = %d, want 11", res.DroppedReserved)
	}
}

// TestFetch_HTMLErrorPage pins that a 200 serving an HTML error page never
// replaces the set with garbage or emptiness.
func TestFetch_HTMLErrorPage(t *testing.T) {
	f, url := newFeedFetcher(t, &feedServer{body: fixture(t, "error-page.html")})
	_, err := f.Fetch(context.Background(), feedCfg(url, "plain"))
	if err == nil || !strings.Contains(err.Error(), "no valid entries") {
		t.Fatalf("want no-valid-entries error, got %v", err)
	}
}

// ── Caps ─────────────────────────────────────────────────────────────────────

func TestFetch_OversizedTruncatedSafely(t *testing.T) {
	// >10MiB of valid lines: parse keeps what fits, flags Truncated, and
	// never errors.
	var b strings.Builder
	for i := 0; b.Len() < maxResponseBytes+1024; i++ {
		fmt.Fprintf(&b, "192.0.2.%d\n198.51.100.%d\n203.0.113.%d\n", i%256, i%256, i%256)
	}
	f, url := newFeedFetcher(t, &feedServer{body: []byte(b.String())})
	res, err := f.Fetch(context.Background(), feedCfg(url, "plain"))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.Truncated {
		t.Error("Truncated not set on an oversized body")
	}
	if len(res.Prefixes) == 0 {
		t.Error("truncation lost all parsed entries")
	}
}

func TestFetch_EntryCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "192.0.2.%d\n198.51.100.%d\n", i%256, i%256)
	}
	f, url := newFeedFetcher(t, &feedServer{body: []byte(b.String())})
	cfg := feedCfg(url, "plain")
	cfg.MaxEntries = 100
	res, err := f.Fetch(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(res.Prefixes) != 100 {
		t.Errorf("prefixes = %d, want capped at 100", len(res.Prefixes))
	}
	if res.DroppedOverCap == 0 {
		t.Error("DroppedOverCap not counted")
	}
}

func TestFetch_HugeLineSkipped(t *testing.T) {
	body := "192.0.2.1\n" + strings.Repeat("a", 100_000) + "\n192.0.2.2\n"
	f, url := newFeedFetcher(t, &feedServer{body: []byte(body)})
	res, err := f.Fetch(context.Background(), feedCfg(url, "plain"))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(res.Prefixes) != 2 {
		t.Errorf("prefixes = %v, want the 2 valid IPs around the huge line", res.Prefixes)
	}
	if res.Invalid != 1 {
		t.Errorf("Invalid = %d, want 1 (the huge line)", res.Invalid)
	}
}

// ── HTTP semantics ───────────────────────────────────────────────────────────

func TestFetch_HTTPRejected(t *testing.T) {
	f := New(nil, nil)
	_, err := f.Fetch(context.Background(), feedCfg("http://feeds.example/list.txt", "plain"))
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("want https-only rejection, got %v", err)
	}
}

func TestFetch_NotModifiedKeepsLastGood(t *testing.T) {
	fs := &feedServer{body: []byte("192.0.2.1\n192.0.2.2\n"), etag: `"v1"`, notModOn304: true}
	f, url := newFeedFetcher(t, fs)
	ctx := context.Background()
	cfg := feedCfg(url, "plain")

	first, err := f.Fetch(ctx, cfg)
	if err != nil || len(first.Prefixes) != 2 {
		t.Fatalf("first fetch: %v / %v", err, first)
	}
	second, err := f.Fetch(ctx, cfg)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if !second.NotModified || len(second.Prefixes) != 2 {
		t.Fatalf("304 must return last-known-good, got %+v", second)
	}
}

func TestFetch_ServerErrorKeepsLastGood(t *testing.T) {
	fs := &feedServer{body: []byte("192.0.2.1\n")}
	f, url := newFeedFetcher(t, fs)
	ctx := context.Background()
	cfg := feedCfg(url, "plain")

	if _, err := f.Fetch(ctx, cfg); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	fs.status = http.StatusServiceUnavailable
	if _, err := f.Fetch(ctx, cfg); err == nil {
		t.Fatal("want error on 503")
	}
	if lg := f.LastGood("test"); len(lg) != 1 {
		t.Fatalf("last-known-good lost on failure: %v", lg)
	}
}

func TestFetch_RedirectToHTTPRefused(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://insecure.example/list.txt", http.StatusFound)
	}))
	t.Cleanup(ts.Close)
	f := New(ts.Client(), nil)
	_, err := f.Fetch(context.Background(), feedCfg(ts.URL, "plain"))
	if err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("want non-https redirect refusal, got %v", err)
	}
}

// ── Refresh loop ─────────────────────────────────────────────────────────────

func TestRun_HonorsContext(t *testing.T) {
	fs := &feedServer{body: []byte("192.0.2.1\n")}
	f, url := newFeedFetcher(t, fs)
	cfg := feedCfg(url, "plain")
	cfg.RefreshInterval = MinRefreshInterval

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		f.Run(ctx, []FeedConfig{cfg}, func(*Result) {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on context cancellation")
	}
}

// ── Reserved-overlap unit coverage ───────────────────────────────────────────

func TestOverlapsReserved(t *testing.T) {
	cases := map[string]bool{
		"192.0.2.0/24":   false,
		"10.1.2.3/32":    true,
		"10.0.0.0/8":     true,
		"0.0.0.0/1":      true, // contains 10/8
		"0.0.0.0/0":      true,
		"2001:db8::/32":  false,
		"::/0":           true,
		"fe80::1/128":    true,
		"192.88.99.0/24": false, // 6to4 anycast is public-routable; not reserved here
	}
	for s, want := range cases {
		p := netip.MustParsePrefix(s)
		if got := overlapsReserved(p); got != want {
			t.Errorf("overlapsReserved(%s) = %v, want %v", s, got, want)
		}
	}
}
