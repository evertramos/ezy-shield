package vhostdetect

// sources.go — detection sources beyond the nginx-proxy VIRTUAL_HOST
// convention (issue #488): Traefik router rules from docker labels, Traefik
// local config files, and local nginx server_name directives. All sources
// share the wizard's best-effort discipline (missing tools/files are
// silently skipped) and defensive parsing: size caps, linear scans (no
// backtracking-prone patterns), and hostname validation before anything is
// handed to DNS resolution. Values never reach a shell or an API call —
// downstream lookups go through the typed resolvers/clients.

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Source identifies where a VHost's domains were detected.
type Source string

const (
	// SourceDockerEnv is the nginx-proxy VIRTUAL_HOST env convention.
	SourceDockerEnv Source = "docker-env"
	// SourceTraefikDocker is Traefik router rules read from docker labels.
	SourceTraefikDocker Source = "traefik-docker"
	// SourceTraefikFile is Traefik router rules read from local config files.
	SourceTraefikFile Source = "traefik-file"
	// SourceNginxFile is server_name directives from local nginx config.
	SourceNginxFile Source = "nginx-file"
)

// Defensive caps (issue #488 §1): label values and local config files are
// semi-trusted operator data, but a hostile value must cost bounded work.
const (
	maxRuleValueBytes = 4096      // one router rule string
	maxLocalFileBytes = 256 << 10 // one traefik/nginx config file
	maxLocalFiles     = 200       // files walked per directory tree
	maxDomainsPerFile = 200
)

// validHostname is the conservative pre-DNS gate: dotted labels of
// letters/digits/hyphens, no leading/trailing hyphen or dot, ≤253 bytes.
// Rejecting here keeps garbage (and nginx variables like $host) from ever
// reaching the resolver.
func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
			if !ok {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// normalizeDomain trims a detected name and maps wildcard/catch-all forms to
// their registrable base ("*.example.com" and ".example.com" → "example.com")
// so CDN classification can still run. Returns "" when nothing valid remains.
func normalizeDomain(s string) string {
	d := strings.TrimSpace(s)
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")
	if d == "" || d == "_" || strings.ContainsAny(d, "$*") {
		return ""
	}
	if !validHostname(d) {
		return ""
	}
	return d
}

// parseTraefikRule extracts hostnames from a Traefik router rule such as
// "Host(`a.example.com`, `b.example.com`) || HostSNI(`c.example.com`)".
// Linear scan: find Host(/HostSNI( groups, then quoted tokens inside — no
// regular expressions, so a hostile rule string cannot trigger pathological
// matching. Input is size-capped by the caller.
func parseTraefikRule(rule string) []string {
	var out []string
	rest := rule
	for {
		idx := strings.Index(rest, "Host")
		if idx < 0 {
			break
		}
		rest = rest[idx+len("Host"):]
		rest = strings.TrimPrefix(rest, "SNI")
		if !strings.HasPrefix(rest, "(") {
			continue
		}
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			break
		}
		group := rest[1:end]
		rest = rest[end+1:]
		out = append(out, quotedTokens(group)...)
	}
	return out
}

// quotedTokens returns every backtick-, single- or double-quoted token in s,
// normalized; unquoted content is ignored.
func quotedTokens(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '`' && c != '\'' && c != '"' {
			continue
		}
		close := strings.IndexByte(s[i+1:], c)
		if close < 0 {
			break
		}
		if d := normalizeDomain(s[i+1 : i+1+close]); d != "" {
			out = append(out, d)
		}
		i += close + 1
	}
	return out
}

// extractTraefikLabelDomains scans KEY=VALUE lines (docker inspect output)
// for Traefik router rule labels — traefik.http.routers.<name>.rule and the
// tcp/HostSNI variant — and extracts their hostnames.
func extractTraefikLabelDomains(kv string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(kv))
	sc.Buffer(make([]byte, 0, 64*1024), maxRuleValueBytes+1024)
	for sc.Scan() {
		key, val, ok := strings.Cut(strings.TrimRight(sc.Text(), "\r"), "=")
		if !ok || len(val) > maxRuleValueBytes {
			continue
		}
		key = strings.TrimSpace(key)
		if !strings.HasPrefix(key, "traefik.") ||
			!strings.HasSuffix(key, ".rule") || !strings.Contains(key, ".routers.") {
			continue
		}
		out = append(out, parseTraefikRule(val)...)
	}
	return out
}

// LocalPaths names the directories the file-based sources scan. Injectable
// so tests point at fixtures and never at the host's real /etc.
type LocalPaths struct {
	TraefikDirs []string
	NginxDirs   []string
}

// DefaultLocalPaths returns the conventional locations.
func DefaultLocalPaths() LocalPaths {
	return LocalPaths{
		TraefikDirs: []string{"/etc/traefik"},
		NginxDirs:   []string{"/etc/nginx/sites-enabled", "/etc/nginx/conf.d"},
	}
}

// DetectLocal scans the given directories for Traefik router rules and nginx
// server_name directives. Best-effort like Detect: missing directories,
// unreadable files, or oversized files are skipped silently.
func DetectLocal(paths LocalPaths) []VHost {
	var out []VHost
	for _, dir := range paths.TraefikDirs {
		if domains := scanDirForDomains(dir, []string{".yml", ".yaml", ".toml"}, extractTraefikFileDomains); len(domains) > 0 {
			out = append(out, VHost{Container: dir, Domains: domains, Source: SourceTraefikFile})
		}
	}
	for _, dir := range paths.NginxDirs {
		// sites-enabled entries often have no extension; scan everything.
		if domains := scanDirForDomains(dir, nil, extractNginxServerNames); len(domains) > 0 {
			out = append(out, VHost{Container: dir, Domains: domains, Source: SourceNginxFile})
		}
	}
	return out
}

// DetectLocalDefault is DetectLocal over DefaultLocalPaths — the production
// wiring the wizard injects (tests leave the hook nil and scan nothing).
func DetectLocalDefault() []VHost { return DetectLocal(DefaultLocalPaths()) }

// scanDirForDomains walks dir (bounded), reads each matching file
// (size-capped), and accumulates the extractor's deduplicated results.
func scanDirForDomains(dir string, exts []string, extract func(string) []string) []string {
	seen := make(map[string]bool)
	var out []string
	files := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // best-effort: skip unreadable entries
		}
		if d.IsDir() {
			return nil
		}
		if files++; files > maxLocalFiles {
			return fs.SkipAll
		}
		if len(exts) > 0 {
			ok := false
			for _, e := range exts {
				if strings.HasSuffix(path, e) {
					ok = true
					break
				}
			}
			if !ok {
				return nil
			}
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > maxLocalFileBytes {
			// A symlink (sites-enabled convention) reports the LINK's info;
			// stat the target before giving up on it.
			if st, serr := os.Stat(path); serr != nil || st.Size() > maxLocalFileBytes {
				return nil
			}
		}
		data, rerr := os.ReadFile(path) //nolint:gosec // operator config dirs, size-capped above
		if rerr != nil || len(data) > maxLocalFileBytes {
			return nil
		}
		for _, dom := range extract(string(data)) {
			if seen[dom] || len(out) >= maxDomainsPerFile {
				continue
			}
			seen[dom] = true
			out = append(out, dom)
		}
		return nil
	})
	return out
}

// extractTraefikFileDomains scans a Traefik config file (YAML or TOML) for
// router rule lines. A textual line scan handles both formats without
// parsing arbitrary operator YAML/TOML: `rule: "Host(...)"` / `rule = "..."`.
func extractTraefikFileDomains(content string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), maxRuleValueBytes+1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if len(line) > maxRuleValueBytes {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			key, val, ok = strings.Cut(line, "=")
		}
		if !ok || strings.TrimSpace(strings.Trim(key, `"'`)) != "rule" {
			continue
		}
		out = append(out, parseTraefikRule(val)...)
	}
	return out
}

// extractNginxServerNames scans nginx config content for server_name
// directives. Single-line form only (the overwhelmingly common case);
// catch-all "_" and variable names are dropped, wildcards map to their
// registrable base.
func extractNginxServerNames(content string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), maxRuleValueBytes+1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		rest, ok := strings.CutPrefix(line, "server_name")
		if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		rest = strings.TrimSuffix(strings.TrimSpace(rest), ";")
		for _, tok := range strings.Fields(rest) {
			if d := normalizeDomain(tok); d != "" {
				out = append(out, d)
			}
		}
	}
	return out
}
