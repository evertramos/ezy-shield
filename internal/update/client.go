package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultRepo is the public release source. The private repo will be
	// deprecated; update must never reference it.
	DefaultRepo = "evertramos/ezy-shield"
	// DefaultAPIBaseURL is the base for GitHub Releases JSON.
	DefaultAPIBaseURL = "https://api.github.com"
	// DefaultDLBaseURL is the base for browser-style asset downloads, used as a
	// fallback URL when a release JSON omits asset URLs.
	DefaultDLBaseURL = "https://github.com"

	userAgent = "ezyshield-update"

	connectTimeout  = 30 * time.Second
	downloadTimeout = 120 * time.Second

	maxJSONSize     = 1 << 20  // 1 MiB
	maxChecksumSize = 64 << 10 // 64 KiB
	// MaxBinarySize caps how many bytes Download will accept. Plenty of headroom
	// for a stripped Go binary; rejects a runaway response from a hostile mirror.
	MaxBinarySize = 100 << 20 // 100 MiB
)

// ErrNoStableRelease is returned by LatestRelease when GitHub's
// releases/latest endpoint has nothing to return. That endpoint only ever
// considers non-prerelease releases — during the release-candidate phase
// before the first stable tag ships, every published release is a
// prerelease, so it 404s. This is an expected, named condition (issue
// #235), distinct from a genuine "release not found" on ReleaseByTag.
var ErrNoStableRelease = errors.New("no stable (non-prerelease) release has been published yet")

// errReleaseAPINotFound is the internal 404 signal from fetchRelease.
// LatestRelease translates it into the more specific ErrNoStableRelease;
// ReleaseByTag's 404 (a bad/nonexistent tag) keeps its own message — the
// sentinel is plumbing between fetchRelease and LatestRelease only and
// never escapes to a caller directly.
var errReleaseAPINotFound = errors.New("release API 404")

// Asset mirrors the GitHub Releases "assets[]" entries we care about.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Release is the strict subset of GitHub's release JSON we decode. We
// intentionally omit other fields to keep the trust boundary small: an
// attacker controlling the release JSON shouldn't be able to influence
// behavior through fields we ignore.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// FindAsset returns the asset whose Name exactly matches name, or false.
func (r *Release) FindAsset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// Client fetches release metadata and binary assets. APIBaseURL and Repo are
// overridable so tests can point the client at an httptest server.
type Client struct {
	HTTP       *http.Client
	APIBaseURL string
	Repo       string
}

// NewClient returns a Client with conservative timeouts and the default
// public-repo URLs. Override APIBaseURL / Repo to redirect (env-var case) or
// for tests.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout: downloadTimeout,
			Transport: &http.Transport{
				ResponseHeaderTimeout: connectTimeout,
				ForceAttemptHTTP2:     true,
			},
		},
		APIBaseURL: DefaultAPIBaseURL,
		Repo:       DefaultRepo,
	}
}

// LatestRelease fetches /repos/{repo}/releases/latest. GitHub excludes
// prereleases from this endpoint by design — a 404 during the RC phase
// (before any stable tag exists) is translated to ErrNoStableRelease so
// callers can give an actionable message instead of a bare "not found".
func (c *Client) LatestRelease(ctx context.Context) (*Release, error) {
	u := fmt.Sprintf("%s/repos/%s/releases/latest", c.APIBaseURL, c.Repo)
	rel, err := c.fetchRelease(ctx, u)
	if err != nil && errors.Is(err, errReleaseAPINotFound) {
		return nil, ErrNoStableRelease
	}
	return rel, err
}

// NewestRelease fetches the single most recent release regardless of
// prerelease status (GET /releases?per_page=1 — GitHub returns releases
// newest-first). Used only to surface an actionable "pin this exact tag"
// suggestion when LatestRelease finds no stable release; the result is
// NEVER auto-installed.
func (c *Client) NewestRelease(ctx context.Context) (*Release, error) {
	u := fmt.Sprintf("%s/repos/%s/releases?per_page=1", c.APIBaseURL, c.Repo)
	if err := requireHTTPS(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch releases list: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("releases list API returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONSize))
	if err != nil {
		return nil, fmt.Errorf("read releases list body: %w", err)
	}
	var releases []Release
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("parse releases list JSON: %w", err)
	}
	if len(releases) == 0 {
		return nil, errors.New("no releases published yet")
	}
	if releases[0].TagName == "" {
		return nil, errors.New("newest release has no tag_name")
	}
	return &releases[0], nil
}

// ReleaseByTag fetches /repos/{repo}/releases/tags/{tag}. tag must be a
// semver-shaped string (no path traversal, no slashes).
func (c *Client) ReleaseByTag(ctx context.Context, tag string) (*Release, error) {
	if !validTag(tag) {
		return nil, fmt.Errorf("invalid tag: %q (expected vX.Y.Z)", tag)
	}
	u := fmt.Sprintf("%s/repos/%s/releases/tags/%s", c.APIBaseURL, c.Repo, url.PathEscape(tag))
	return c.fetchRelease(ctx, u)
}

func (c *Client) fetchRelease(ctx context.Context, u string) (*Release, error) {
	if err := requireHTTPS(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch release: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("release not found at %s: %w", redactURL(u), errReleaseAPINotFound)
	default:
		return nil, fmt.Errorf("release API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONSize))
	if err != nil {
		return nil, fmt.Errorf("read release body: %w", err)
	}
	var r Release
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("parse release JSON: %w", err)
	}
	if r.TagName == "" {
		return nil, errors.New("release has no tag_name")
	}
	return &r, nil
}

// Download streams the asset at u into dst. It enforces HTTPS, a hard size cap,
// and returns an error if the response status isn't 200. Returns bytes written.
func (c *Client) Download(ctx context.Context, u string, dst io.Writer) (int64, error) {
	if err := requireHTTPS(u); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download %s: status %d", redactURL(u), resp.StatusCode)
	}

	// Read MaxBinarySize+1 to detect overflow vs. exact-cap.
	n, err := io.Copy(dst, io.LimitReader(resp.Body, MaxBinarySize+1))
	if err != nil {
		return n, fmt.Errorf("copy body: %w", err)
	}
	if n > MaxBinarySize {
		return n, fmt.Errorf("download exceeded %d bytes", MaxBinarySize)
	}
	return n, nil
}

// DownloadChecksums fetches checksums.txt into memory (small file) and parses
// it. Capped at maxChecksumSize.
func (c *Client) DownloadChecksums(ctx context.Context, u string) (map[string]string, error) {
	if err := requireHTTPS(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download checksums: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksums %s: status %d", redactURL(u), resp.StatusCode)
	}
	return ParseChecksums(io.LimitReader(resp.Body, maxChecksumSize))
}

// requireHTTPS rejects any URL whose scheme isn't "https". This is a defense in
// depth on top of the configured base URLs.
func requireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-HTTPS URL (scheme=%q)", u.Scheme)
	}
	return nil
}

// validTag accepts vX.Y.Z[-prerelease][+build] only; rejects anything with
// slashes, dotdot, or other path-y characters so a tag from --version can't be
// used to traverse beyond /releases/tags/.
func validTag(tag string) bool {
	if tag == "" || strings.ContainsAny(tag, "/\\ \t\n\r") {
		return false
	}
	if strings.Contains(tag, "..") {
		return false
	}
	return semverRE.MatchString(tag)
}

// redactURL strips query strings so we never echo a token-bearing URL back to
// the user in error messages.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<url>"
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
