// Package feeds downloads and parses IP reputation feeds (issue #194):
// Spamhaus DROP, FireHOL, AbuseIPDB plain exports, and anything else that
// is one IP or CIDR per line over HTTPS.
//
// A feed is REMOTE, ATTACKER-ADJACENT INPUT that will eventually influence
// blocking, so this package is written for poisoning first:
//
//   - parsing is netip.ParseAddr/ParsePrefix ONLY — no DNS, no heuristics;
//     invalid lines are counted and skipped, never fatal;
//   - private/loopback/link-local/reserved ranges are ALWAYS dropped, so a
//     compromised feed can never smuggle 10.0.0.0/8 or ::1 into a blocklist;
//   - hard caps everywhere: 10MiB response (enforced while streaming),
//     4KiB lines, 500k entries;
//   - HTTPS only, including redirect targets; timeouts and context honored;
//   - a fetch failure keeps the last-known-good set.
//
// This issue covers download + parsing only. Applying feed entries to
// enforcement/decisions is the follow-up (#195), which is also where
// allowlist supremacy is enforced at the choke point (Hard Rule §1) — this
// package deliberately produces data, not actions.
package feeds

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// maxResponseBytes caps how much of a feed body is ever read (streamed;
	// a bigger body is truncated safely, keeping what parsed).
	maxResponseBytes = 10 << 20
	// maxLineBytes caps a single feed line; longer lines are discarded and
	// counted invalid.
	maxLineBytes = 4096
	// DefaultMaxEntries is the per-feed entry cap when the config leaves
	// max_entries unset.
	DefaultMaxEntries = 100_000
	// HardMaxEntries is the absolute per-feed cap; config validation
	// rejects anything above it.
	HardMaxEntries = 500_000
	// MinRefreshInterval is the politeness floor for refresh_interval.
	MinRefreshInterval = time.Hour
	// DefaultTimeout bounds one fetch when the config leaves timeout unset.
	DefaultTimeout = 30 * time.Second
	// maxRedirects bounds a redirect chain; every hop must stay https.
	maxRedirects = 5
)

// ValidFormats enumerates the supported feed formats. "plain" and
// "abuseipdb" are one IP per line (AbuseIPDB kept as its own name so
// configs document intent); "cidr" accepts IPs or prefixes plus ';'/'#'
// comments (the Spamhaus DROP / FireHOL shape).
var ValidFormats = map[string]bool{"plain": true, "cidr": true, "abuseipdb": true}

// reservedPrefixes are ranges a reputation feed must NEVER contribute:
// private, loopback, link-local, unspecified/broadcast-ish, multicast, and
// their IPv6 equivalents. Any entry overlapping one of these is dropped.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"), // multicast
	netip.MustParsePrefix("240.0.0.0/4"), // reserved incl. broadcast
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),  // ULA
	netip.MustParsePrefix("fe80::/10"), // link-local
	netip.MustParsePrefix("ff00::/8"),  // multicast
}

// FeedConfig describes one feed. Mirrors the config.yaml section (#194);
// validation lives in internal/config, and New re-checks the load-bearing
// parts so programmatic use cannot bypass them.
type FeedConfig struct {
	// Name identifies the feed in logs and provenance.
	Name string
	// URL is the https:// source.
	URL string
	// Format is one of ValidFormats.
	Format string
	// RefreshInterval is how often the feed is re-fetched (floor
	// MinRefreshInterval).
	RefreshInterval time.Duration
	// MaxEntries caps parsed entries (0 = DefaultMaxEntries; hard-capped
	// at HardMaxEntries).
	MaxEntries int
	// Timeout bounds one fetch (0 = DefaultTimeout).
	Timeout time.Duration
}

// Result is one successful parse of one feed.
type Result struct {
	// Name is the feed's configured name (provenance travels with the data).
	Name string
	// Prefixes is the deduplicated, sanitized entry set. Single IPs are
	// normalized to /32 (or /128).
	Prefixes []netip.Prefix
	// FetchedAt is when the fetch completed.
	FetchedAt time.Time
	// NotModified is true when the server answered 304 — Prefixes then
	// carries the last-known-good set.
	NotModified bool
	// Invalid counts skipped lines (unparseable or over the line cap).
	Invalid int
	// DroppedReserved counts entries discarded for overlapping a reserved
	// range — a non-zero value on a reputable feed is a poisoning signal
	// worth surfacing.
	DroppedReserved int
	// DroppedOverCap counts entries discarded past MaxEntries.
	DroppedOverCap int
	// Truncated is true when the response hit maxResponseBytes.
	Truncated bool
}

// feedState is the per-feed cache the Fetcher keeps between refreshes.
type feedState struct {
	etag         string
	lastModified string
	lastGood     []netip.Prefix
}

// Fetcher downloads and parses feeds. Safe for concurrent use: Run spawns
// one goroutine per feed and on-demand refreshes may race with them, so the
// per-feed cache map is mutex-guarded. Construct one per daemon.
type Fetcher struct {
	client *http.Client
	logger *slog.Logger

	mu    sync.Mutex
	state map[string]*feedState
}

// New builds a Fetcher. client may be nil (a default HTTPS client with
// redirect policing is built); pass one in tests.
func New(client *http.Client, logger *slog.Logger) *Fetcher {
	if logger == nil {
		logger = slog.Default()
	}
	if client == nil {
		client = &http.Client{}
	}
	// Redirect policing applies to injected clients too: every hop must
	// stay https and the chain is bounded.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("feeds: too many redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("feeds: refusing redirect to non-https URL")
		}
		return nil
	}
	return &Fetcher{client: client, logger: logger, state: map[string]*feedState{}}
}

// Fetch downloads and parses one feed. On a 304 it returns the
// last-known-good set with NotModified=true. Any error leaves the cached
// last-known-good untouched for the caller to keep using.
func (f *Fetcher) Fetch(ctx context.Context, cfg FeedConfig) (*Result, error) {
	if err := checkFeedURL(cfg.URL); err != nil {
		return nil, err
	}
	if !ValidFormats[cfg.Format] {
		return nil, fmt.Errorf("feeds %s: unknown format %q", cfg.Name, cfg.Format)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	f.mu.Lock()
	st, ok := f.state[cfg.Name]
	if !ok {
		st = &feedState{}
		f.state[cfg.Name] = st
	}
	etag, lastMod := st.etag, st.lastModified
	f.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("feeds %s: build request: %w", cfg.Name, err)
	}
	req.Header.Set("User-Agent", "ezyshield-feeds/1")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feeds %s: fetch failed: %w", cfg.Name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	switch {
	case resp.StatusCode == http.StatusNotModified:
		f.mu.Lock()
		lastGood := st.lastGood
		f.mu.Unlock()
		return &Result{
			Name:        cfg.Name,
			Prefixes:    lastGood,
			FetchedAt:   time.Now(),
			NotModified: true,
		}, nil
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("feeds %s: HTTP %d", cfg.Name, resp.StatusCode)
	}

	res := f.parse(cfg, resp.Body)
	res.FetchedAt = time.Now()

	// An all-invalid body (an HTML error page served with 200) must not
	// replace a known-good set with emptiness.
	if len(res.Prefixes) == 0 && res.Invalid > 0 {
		return nil, fmt.Errorf("feeds %s: no valid entries in response (%d invalid lines — not a feed?)",
			cfg.Name, res.Invalid)
	}

	f.mu.Lock()
	st.etag = resp.Header.Get("ETag")
	st.lastModified = resp.Header.Get("Last-Modified")
	st.lastGood = res.Prefixes
	f.mu.Unlock()
	return res, nil
}

// LastGood returns the cached last-known-good set for a feed (nil when the
// feed never fetched successfully).
func (f *Fetcher) LastGood(name string) []netip.Prefix {
	f.mu.Lock()
	defer f.mu.Unlock()
	if st, ok := f.state[name]; ok {
		return st.lastGood
	}
	return nil
}

// parse streams body line by line with every cap enforced. Never returns an
// error: hostile input degrades to counters, not failures.
func (f *Fetcher) parse(cfg FeedConfig, body io.Reader) *Result {
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	if maxEntries > HardMaxEntries {
		maxEntries = HardMaxEntries
	}

	res := &Result{Name: cfg.Name}
	lr := &io.LimitedReader{R: body, N: maxResponseBytes}
	br := bufio.NewReaderSize(lr, 64*1024)
	seen := make(map[netip.Prefix]struct{})

	for {
		line, err := readCappedLine(br, &res.Invalid)
		if line != nil {
			f.parseLine(cfg.Format, string(line), maxEntries, seen, res)
		}
		if err != nil {
			break
		}
	}
	if lr.N <= 0 {
		res.Truncated = true
	}
	return res
}

// readCappedLine reads one line of at most maxLineBytes. An over-long line
// is consumed to its end, discarded, and counted invalid. Returns a nil
// line with io.EOF (or another read error) when the stream ends.
func readCappedLine(br *bufio.Reader, invalid *int) ([]byte, error) {
	var (
		line     []byte
		overlong bool
	)
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			if len(line)+len(chunk) > maxLineBytes {
				overlong = true
				line = nil
			} else if !overlong {
				line = append(line, chunk...)
			}
		}
		switch err {
		case bufio.ErrBufferFull:
			continue // keep consuming the same (long) line
		case nil:
			if overlong {
				*invalid++
				return nil, nil
			}
			return line, nil
		default:
			if overlong {
				*invalid++
				return nil, err
			}
			if len(line) == 0 {
				return nil, err
			}
			return line, err
		}
	}
}

// parseLine parses one line per the feed format and accumulates into res.
func (f *Fetcher) parseLine(format, line string, maxEntries int, seen map[netip.Prefix]struct{}, res *Result) {
	// Comments: full-line for every format; the cidr format (Spamhaus
	// DROP: "1.2.3.0/24 ; SBL123") also carries trailing comments.
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return
	}
	if format == "cidr" {
		if i := strings.IndexAny(line, ";#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				return
			}
		}
	}

	var p netip.Prefix
	if addr, err := netip.ParseAddr(line); err == nil {
		p = netip.PrefixFrom(addr, addr.BitLen())
	} else if format == "cidr" {
		pp, err := netip.ParsePrefix(line)
		if err != nil {
			res.Invalid++
			return
		}
		p = pp.Masked()
	} else {
		res.Invalid++
		return
	}

	if overlapsReserved(p) {
		res.DroppedReserved++
		return
	}
	if _, dup := seen[p]; dup {
		return
	}
	if len(res.Prefixes) >= maxEntries {
		res.DroppedOverCap++
		return
	}
	seen[p] = struct{}{}
	res.Prefixes = append(res.Prefixes, p)
}

// overlapsReserved reports whether p intersects any reserved range — either
// direction: a feed entry inside 10/8, or a broad prefix that CONTAINS a
// reserved range (0.0.0.0/0 must not survive just because its base address
// looks public).
func overlapsReserved(p netip.Prefix) bool {
	for _, r := range reservedPrefixes {
		if r.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if r.Overlaps(p) {
			return true
		}
	}
	return false
}

// checkFeedURL enforces https and a well-formed host. Shared with config
// validation.
func checkFeedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("feeds: invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("feeds: url must be https:// (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("feeds: url has no host")
	}
	return nil
}

// CheckFeedURL is the exported form for config validation.
func CheckFeedURL(raw string) error { return checkFeedURL(raw) }

// Run refreshes every feed on its jittered interval until ctx is done,
// calling onUpdate with each successful (or 304-refreshed) result. A failed
// refresh logs a warning and keeps the last-known-good set — onUpdate is
// NOT called with an empty set on failure. Each feed gets one goroutine;
// Run blocks until ctx is done.
func (f *Fetcher) Run(ctx context.Context, cfgs []FeedConfig, onUpdate func(*Result)) {
	done := make(chan struct{})
	for i := range cfgs {
		cfg := cfgs[i]
		go func() {
			defer func() { done <- struct{}{} }()
			f.runOne(ctx, cfg, onUpdate)
		}()
	}
	for range cfgs {
		<-done
	}
}

func (f *Fetcher) runOne(ctx context.Context, cfg FeedConfig, onUpdate func(*Result)) {
	interval := cfg.RefreshInterval
	if interval < MinRefreshInterval {
		interval = MinRefreshInterval
	}
	// Initial fetch happens immediately (with a small jitter so many feeds
	// don't all fire at daemon start), then on the jittered interval.
	if !sleepCtx(ctx, jitter(time.Duration(rand.Int64N(int64(10*time.Second))))) { //nolint:gosec // schedule spreading, not security
		return
	}
	for {
		res, err := f.Fetch(ctx, cfg)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			f.logger.Warn("feeds: refresh failed; keeping last-known-good set",
				"feed", cfg.Name, "known_entries", len(f.LastGood(cfg.Name)), "err", err)
		default:
			if res.DroppedReserved > 0 {
				f.logger.Warn("feeds: feed contained reserved/private ranges — dropped (possible poisoning)",
					"feed", cfg.Name, "dropped", res.DroppedReserved)
			}
			onUpdate(res)
		}
		if !sleepCtx(ctx, jitter(interval)) {
			return
		}
	}
}

// jitter spreads d by ±10% so refreshes don't synchronize across restarts.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(float64(d) * (0.9 + 0.2*rand.Float64())) //nolint:gosec // schedule spreading, not security
}

// sleepCtx sleeps for d, returning false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
