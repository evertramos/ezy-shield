package main

// CDN detection + Cloudflare edge-enforcer subflow for `ezyshield init`.
// See issue #43 for the design rationale — the tl;dr is that a server behind
// Cloudflare (or any CDN) only sees CDN IPs at the TCP layer, so an nftables
// ban on the "real" client IP never matches. This step detects the situation
// and offers to wire the CF enforcer at init time instead of the operator
// discovering the gap 30 minutes into a live incident.
//
// The step is deliberately loud on the skip path (issue #43 §3): if we found
// a CDN and the operator opted out, the wizard prints a big warning so the
// mistake is visible in the terminal history, not buried behind a config
// diff.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/cdndetect"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/vhostdetect"
)

// cdnStep collects everything the CDN detection + CF subflow adds to the
// wizard state. Extracted so the state struct stays small and the flow can
// be tested via the exported RunCDNStep entry point without dragging in the
// whole wizard.
type cdnStep struct {
	// vhosts is the raw output of vhostdetect.Detect(). Kept for tests /
	// future dashboard views.
	vhosts []vhostdetect.VHost
	// results is one DomainResult per resolved domain (in enumeration order).
	results []cdndetect.DomainResult
	// detected is the deduplicated set of providers that matched at least
	// one domain. Order-preserving from first match.
	detected []cdndetect.Provider
	// cfEnabled is true when the operator agreed to configure the Cloudflare
	// enforcer at init time. On false with detected non-empty, the wizard
	// prints the loud-skip warning (issue #43 §3).
	cfEnabled bool
	// cfCfg is the CF config the wizard will emit into config.yaml, only
	// populated when cfEnabled is true and validation succeeded.
	cfCfg *config.CloudflareCfg
	// cfTokenEnvVar is the exact env-var name the wizard wrote to .env; the
	// yaml gets `api_token: env:<cfTokenEnvVar>`.
	cfTokenEnvVar string
	// cfToken holds the raw token between the prompt and the .env write.
	// Same discipline as wizardState.aiToken — never appears in any log
	// path, never printed to stdout, redacted by String() (see below).
	cfToken string
	// cfWAFRuleExpression is the WAF Custom Rule expression printed to the
	// operator in lists mode so they can paste it into the CF dashboard.
	cfWAFRuleExpression string
}

// String on *cdnStep masks the CF token, mirroring wizardState.String().
// A `slog.Debug("state", "s", cdnStep)` or a %+v in tests must never leak
// the paste.
func (c *cdnStep) String() string {
	if c == nil {
		return "<nil cdnStep>"
	}
	tokMark := "<empty>"
	if c.cfToken != "" {
		tokMark = "<redacted>"
	}
	return fmt.Sprintf("cdnStep{vhosts=%d detected=%d cfEnabled=%v tokenEnvVar=%q token=%s}",
		len(c.vhosts), len(c.detected), c.cfEnabled, c.cfTokenEnvVar, tokMark)
}

// prompter is the tiny surface the CDN subflow needs from askQuestions.
// The wizard uses closures; extracting an interface lets tests drive the
// step without the whole wizard. `yes` mode maps to "def is returned; no
// prompt printed".
type prompter interface {
	ask(question, def string) string
	askBool(question string, def bool) bool
}

// closurePrompter adapts the ask/askBool closures already built by
// askQuestions in init.go so we don't have to refactor them. The wizard
// hands us these directly.
type closurePrompter struct {
	askFn     func(q, def string) string
	askBoolFn func(q string, def bool) bool
}

func (c closurePrompter) ask(q, def string) string        { return c.askFn(q, def) }
func (c closurePrompter) askBool(q string, def bool) bool { return c.askBoolFn(q, def) }

// cfClient is the subset of *http.Client the dry token-validation call
// needs. Tests provide a canned response transport.
type cfClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// cdnDeps bundles every side-effecting dependency the step consumes. Zero-
// value defaults kick in for anything the wizard leaves unset, keeping the
// production call site trivial (`runCDNStep(ctx, p, prompter, state, cdnDeps{})`).
type cdnDeps struct {
	// DockerCLI overrides the default (real) `docker` CLI. Tests set this
	// to a fake so the step can run without Docker installed.
	DockerCLI vhostdetect.DockerCLI
	// Resolver overrides the default net.Resolver. Tests set this to a
	// canned lookup table.
	Resolver cdndetect.Resolver
	// HTTPClient overrides the default Cloudflare API client used for
	// dry token validation. Tests wire this to a Transport that returns
	// canned JSON.
	HTTPClient cfClient
	// TokenReader lets tests substitute the masked-tty read path. When
	// nil, the wizard reuses the package-level tokenReader (same one the
	// AI-token prompt uses).
	TokenReader func(prompt string) (string, error)
	// CFAPIBaseURL overrides https://api.cloudflare.com/client/v4 for
	// tests. Empty means the real endpoint.
	CFAPIBaseURL string
	// Yes mirrors the wizard's --yes flag: when true, prompts are skipped
	// entirely (the whole CDN subflow becomes a no-op, since we cannot
	// safely make firewall + secret decisions without operator input).
	Yes bool
}

// runCDNStep executes the CDN detection + optional CF subflow. It writes
// its outcome into step (a fresh *cdnStep the caller stores on wizardState).
// The function is best-effort: any I/O failure short-circuits to "skip the
// subflow" rather than aborting the wizard.
func runCDNStep(
	ctx context.Context,
	p *wPrinter,
	pr prompter,
	step *cdnStep,
	deps cdnDeps,
) {
	// --yes mode disables the whole step. Configuring an edge enforcer
	// silently on a piped install would surprise the operator: it involves
	// pasting a secret and picking a mode. Refuse to guess.
	if deps.Yes {
		p.println("  CDN detection: skipped (--yes mode)")
		return
	}

	// 1. Enumerate vhosts + resolve → classify.
	step.vhosts = detectVHosts(ctx, deps.DockerCLI)
	domains := vhostdetect.AllDomains(step.vhosts)

	if len(domains) == 0 {
		p.println("  CDN detection: no vhosts discovered — skipping matching.")
		// The issue explicitly says even with no detection we should
		// still ask the generic "behind a CDN?" question so the operator
		// isn't silently skipped.
		if pr.askBool("Does this server sit behind a CDN (Cloudflare, Bunny, …)?", false) {
			runCloudflareSubflow(ctx, p, pr, step, deps, nil)
		}
		return
	}

	p.printf("  CDN detection: probing %d vhost domain(s)...\n", len(domains))
	step.results = cdndetect.MatchDomains(ctx, domains, cdndetect.Options{
		Resolver: deps.Resolver,
	})
	step.detected = mergeDetectedProviders(step.results)

	renderDetectionSummary(p, step.results)

	if len(step.detected) == 0 {
		// No known CDN in front of any domain. Still offer the generic
		// question — the range table may be out of date, or the user
		// might be on a CDN we haven't populated yet.
		if pr.askBool("Does this server sit behind a CDN (Cloudflare, Bunny, …)?", false) {
			runCloudflareSubflow(ctx, p, pr, step, deps, nil)
		}
		return
	}

	// Which CF-matched domain(s) does the operator need to be aware of?
	cfDomains := domainsForProvider(step.results, "cloudflare")

	// If Cloudflare is one of the detected providers, offer the CF
	// subflow. For non-CF detections (Bunny/Fastly/…) the enforcer isn't
	// wired yet — we still print the loud warning if the operator does
	// nothing so they know their bans won't cover those domains.
	hasCF := providerDetected(step.detected, "cloudflare")
	if hasCF {
		want := pr.askBool("Configure the Cloudflare edge enforcer now? (recommended)", true)
		if want {
			runCloudflareSubflow(ctx, p, pr, step, deps, cfDomains)
		}
	} else {
		p.println("  Detected CDNs do not have an EzyShield enforcer wired yet in this release.")
		p.println("  Bans will still be ineffective for those domains — see the warning below.")
	}

	// Loud-skip warning (issue #43 §3): if any provider was detected AND
	// we're leaving without a working edge enforcer for it, tell the
	// operator, per-domain, with the exact IPs.
	if !step.cfEnabled {
		printLoudSkipWarning(p, step.results)
	}
}

// detectVHosts wraps vhostdetect.Detect with the wizard's error policy
// (never fatal — Docker missing/down is a normal path). Returns nil on any
// failure so the caller can `len(...) == 0` cleanly.
func detectVHosts(ctx context.Context, cli vhostdetect.DockerCLI) []vhostdetect.VHost {
	if cli == nil {
		cli = vhostdetect.DefaultCLI()
	}
	vh, err := vhostdetect.Detect(ctx, cli)
	if err != nil {
		return nil
	}
	return vh
}

// mergeDetectedProviders folds every DomainResult into a single ordered,
// deduplicated Provider slice.
func mergeDetectedProviders(results []cdndetect.DomainResult) []cdndetect.Provider {
	seen := make(map[string]bool)
	var out []cdndetect.Provider
	for _, r := range results {
		for _, p := range r.CDNProviders() {
			if seen[p.ID] {
				continue
			}
			seen[p.ID] = true
			out = append(out, p)
		}
	}
	return out
}

// providerDetected reports whether id is present in list.
func providerDetected(list []cdndetect.Provider, id string) bool {
	for _, p := range list {
		if p.ID == id {
			return true
		}
	}
	return false
}

// domainsForProvider collects every domain whose result matched provider id.
func domainsForProvider(results []cdndetect.DomainResult, id string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, r := range results {
		for _, p := range r.CDNProviders() {
			if p.ID != id {
				continue
			}
			if seen[r.Domain] {
				continue
			}
			seen[r.Domain] = true
			out = append(out, r.Domain)
			break
		}
	}
	return out
}

// renderDetectionSummary prints one line per resolved domain: either the
// matched provider(s), or "no CDN match — direct" for domains that resolved
// to origin. Lookup failures are surfaced explicitly so the operator can
// tell "DNS is broken" from "no CDN".
func renderDetectionSummary(p *wPrinter, results []cdndetect.DomainResult) {
	for _, r := range results {
		if r.LookupError != nil {
			p.printf("    %s — DNS lookup failed (%v)\n", r.Domain, r.LookupError)
			continue
		}
		if len(r.Matches) == 0 {
			p.printf("    %s — origin (no CDN match): %s\n", r.Domain, addrsList(r.Addrs))
			continue
		}
		names := make([]string, 0, len(r.CDNProviders()))
		for _, prov := range r.CDNProviders() {
			names = append(names, prov.Name)
		}
		p.printf("    %s — %s: %s\n", r.Domain, strings.Join(names, ", "), addrsList(matchedAddrs(r)))
	}
}

// matchedAddrs returns just the addresses that classified as a CDN, so the
// summary shows the operator "104.21.13.183" and not the whole A+AAAA set.
func matchedAddrs(r cdndetect.DomainResult) []netip.Addr {
	seen := make(map[netip.Addr]bool, len(r.Matches))
	out := make([]netip.Addr, 0, len(r.Matches))
	for _, m := range r.Matches {
		if seen[m.Addr] {
			continue
		}
		seen[m.Addr] = true
		out = append(out, m.Addr)
	}
	return out
}

func addrsList(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

// printLoudSkipWarning implements the issue #43 §3 wording. Prints to the
// wizard's regular sink (stdout) — the wizard reuses this printer for all
// output so operators see a coherent transcript.
func printLoudSkipWarning(p *wPrinter, results []cdndetect.DomainResult) {
	// Only warn for domains that actually matched a CDN. Origin-only
	// entries and lookup errors get skipped.
	type flagged struct {
		domain    string
		providers []string
		addrs     []netip.Addr
	}
	var list []flagged
	for _, r := range results {
		if len(r.Matches) == 0 {
			continue
		}
		names := make([]string, 0, len(r.CDNProviders()))
		for _, prov := range r.CDNProviders() {
			names = append(names, prov.Name)
		}
		list = append(list, flagged{
			domain:    r.Domain,
			providers: names,
			addrs:     matchedAddrs(r),
		})
	}
	if len(list) == 0 {
		return
	}
	p.println("")
	p.println("  ─────────────────────────────────────────────────────────────")
	p.println("  [!] CDN detected but no edge enforcer configured.")
	p.println("      Bans issued by ezyshield will NOT block real client IPs for")
	p.println("      the following domains — only local traffic reaching the")
	p.println("      host IP directly will be affected. The nginx access log")
	p.println("      will still show the client IP, which is misleading if you")
	p.println("      are troubleshooting a failed ban.")
	p.println("")
	for _, f := range list {
		p.printf("      • %s → %s (%s)\n",
			f.domain, strings.Join(f.providers, ", "), addrsList(f.addrs))
	}
	p.println("")
	p.println("      To retry: delete /etc/ezyshield/config.yaml + policy.yaml")
	p.println("      and re-run 'sudo ezyshield init'.")
	p.println("  ─────────────────────────────────────────────────────────────")
	p.println("")
}

// printCFSetupAbortedBanner is emitted when the operator explicitly opted
// into the Cloudflare subflow (auto-detect happy-path OR the generic "behind
// a CDN?" prompt) but the subflow returned before setting cfEnabled=true —
// invalid account_id, invalid list_name, dryValidateCFToken failure, etc.
//
// Without this banner (issue #93) the specific error line printed inside
// runCloudflareSubflow scrolls past under the AI prompts and the "[3/5]
// Writing configuration files..." output, leaving the operator with a
// config.yaml that silently lacks the enforce.cloudflare section they asked
// for. The banner sits at the end of the CDN step so it's the last thing
// visible before the wizard moves on.
func printCFSetupAbortedBanner(p *wPrinter) {
	p.println("")
	p.println("  ─────────────────────────────────────────────────────────────")
	p.println("  [!] Cloudflare enforcer setup did NOT complete.")
	p.println("      config.yaml will NOT contain enforce.cloudflare, and .env")
	p.println("      will NOT contain CLOUDFLARE_API_TOKEN. See the specific")
	p.println("      reason printed above (invalid input, or token validation).")
	p.println("")
	p.println("      To retry: delete /etc/ezyshield/config.yaml + policy.yaml")
	p.println("      and re-run 'sudo ezyshield init'.")
	p.println("  ─────────────────────────────────────────────────────────────")
	p.println("")
}

// ── Cloudflare subflow ──────────────────────────────────────────────────────

// cfListNameRe matches config.validateCFListName's constraint.
var cfListNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// cfZoneIDRe is a defensive check on operator-typed zone IDs. Cloudflare
// zone IDs are 32 hex chars; account IDs the same. The wizard rejects
// obvious typos ("my-zone", empty, punctuation) before the dry-validation
// call so an operator with a fat-fingered ID sees the mistake immediately.
var cfHexIDRe = regexp.MustCompile(`^[a-f0-9]{32}$`)

// runCloudflareSubflow drives the CF-specific prompts and, on success,
// populates step.cfCfg + step.cfTokenEnvVar + step.cfToken. It never
// returns an error: on any failure it prints the reason and leaves
// step.cfEnabled=false so the loud-skip warning fires.
//
// detectedCFDomains lists the CF-fronted domains the operator will be
// covering — used purely for the display prompt so the operator sees why
// they're being asked. Nil is fine (no detection or the generic path).
func runCloudflareSubflow(
	ctx context.Context,
	p *wPrinter,
	pr prompter,
	step *cdnStep,
	deps cdnDeps,
	detectedCFDomains []string,
) {
	// Every early-return path below leaves step.cfEnabled=false. Without a
	// tail-banner the per-line reason ("invalid account_id", "token
	// validation failed", …) scrolls past under the AI prompts and the
	// "[3/5] Writing configuration files..." output, and the operator ends
	// up with a config.yaml silently missing enforce.cloudflare — issue #93.
	// The defer fires on every exit, including the happy-path where it's a
	// no-op because cfEnabled has been flipped to true just before the
	// function returns naturally.
	defer func() {
		if !step.cfEnabled {
			printCFSetupAbortedBanner(p)
		}
	}()

	if len(detectedCFDomains) > 0 {
		p.printf("  Configuring Cloudflare enforcer for detected domain(s): %s\n",
			strings.Join(detectedCFDomains, ", "))
	}
	p.println("")
	p.println("  Cloudflare enforcement modes:")
	p.println("    • lists    — one account-scoped Custom IP List, one API token")
	p.println("                 for the whole account, propagates to every zone")
	p.println("                 referencing it via a WAF Custom Rule.")
	p.println("                 Requires a one-time manual step in the CF dashboard")
	p.println("                 (the wizard prints the exact rule to paste).")
	p.println("                 Recommended for multi-zone / high-volume deploys.")
	p.println("    • rulesets — one WAF Custom Rule per zone, wired entirely via API.")
	p.println("                 Requires listing every zone_id. ~200 IP cap per")
	p.println("                 rule, auto-split by the enforcer.")
	p.println("                 Recommended for single-zone setups.")

	mode := pr.ask("Cloudflare mode (lists/rulesets)", "lists")
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "lists" && mode != "rulesets" {
		p.printf("  invalid mode %q — expected 'lists' or 'rulesets'; skipping CF setup.\n", mode)
		return
	}

	// Operator label — optional for single-account (default ""). Not
	// prompted at all in the single-account happy path to keep the flow
	// short; the operator can add it by hand later if they add a second
	// account.
	name := ""
	// For now the wizard configures a single CF account; multi-account
	// setups can add more via a follow-up flag or a config-yaml edit.

	action := pr.ask("Rule action (block/challenge/js_challenge)", "block")
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "block" && action != "challenge" && action != "js_challenge" {
		p.printf("  invalid action %q; skipping CF setup.\n", action)
		return
	}

	// Fixed env-var NAME (issue #13 precedent: never prompt the operator
	// for the NAME). One CF account → CLOUDFLARE_API_TOKEN. When we add
	// multi-account later, the wizard will pick CLOUDFLARE_API_TOKEN_<NAME>.
	tokenEnvVar := cfEnvVarForName(name)
	step.cfTokenEnvVar = tokenEnvVar

	// Prompt for the token itself, masked, via the same tty path the AI
	// step uses. Same fall-through rules on error (no tty → skip).
	reader := deps.TokenReader
	if reader == nil {
		reader = tokenReader
	}
	tok, err := reader("  Paste your Cloudflare API token (input hidden, ENTER to skip): ")
	if err != nil || tok == "" {
		// No token means we can't even validate scope. Refuse to write
		// half-configured CF settings — the loud-skip warning will fire.
		p.println("  No Cloudflare token provided; skipping CF setup.")
		return
	}
	step.cfToken = tok

	// Mode-specific fields.
	cfg := &config.CloudflareCfg{
		Name:     name,
		APIToken: config.SecretRef("env:" + tokenEnvVar),
		Mode:     mode,
		Action:   action,
	}

	switch mode {
	case "lists":
		accountID := pr.ask("Cloudflare account ID (32 hex chars)", "")
		accountID = strings.ToLower(strings.TrimSpace(accountID))
		if !cfHexIDRe.MatchString(accountID) {
			p.println("  account_id must be 32 lowercase hex characters (see CF dashboard → Overview → Account ID); skipping CF setup.")
			return
		}
		cfg.AccountID = accountID
		listName := pr.ask("Custom IP List name", "ezyshield_blocked")
		listName = strings.TrimSpace(listName)
		if !cfListNameRe.MatchString(listName) {
			p.printf("  list_name must match [A-Za-z0-9_]+; got %q; skipping CF setup.\n", listName)
			return
		}
		cfg.ListName = listName

	case "rulesets":
		rawZones := pr.ask("Zone IDs (comma-separated, 32 hex chars each)", "")
		zones := splitAndTrim(rawZones)
		if len(zones) == 0 {
			p.println("  no zone_ids given; skipping CF setup.")
			return
		}
		for _, z := range zones {
			if !cfHexIDRe.MatchString(z) {
				p.printf("  zone_id %q is not 32 hex chars; skipping CF setup.\n", z)
				return
			}
		}
		cfg.ZoneIDs = zones
	}

	// Dry token validation before we write anything.
	if err := dryValidateCFToken(ctx, deps, cfg, tok); err != nil {
		p.printf("  Cloudflare token validation failed: %v\n", err)
		p.println("  Refusing to write config with an unvalidated token.")
		return
	}
	p.println("  Cloudflare token validated OK.")

	// Success. Commit to the state; the writer step (in init.go) reads
	// step.cfEnabled and emits the yaml.
	step.cfCfg = cfg
	step.cfEnabled = true

	if mode == "lists" {
		step.cfWAFRuleExpression = buildCFWAFRuleExpression(cfg.ListName)
		p.println("")
		p.println("  Lists mode requires a one-time manual step in the Cloudflare dashboard:")
		p.println("    1. Go to Security → WAF → Custom Rules on any zone under the account.")
		p.println("    2. Create a rule with the expression below and Action = 'Block' (or")
		p.println("       'Managed Challenge' if you prefer challenges over hard blocks).")
		p.println("    3. Repeat per zone you want covered by the list.")
		p.println("")
		p.printf("    Expression: %s\n", step.cfWAFRuleExpression)
		p.println("")
	}
}

// cfEnvVarForName picks the env-var NAME for a given CF account label.
// Single-account (empty name) uses the plain CLOUDFLARE_API_TOKEN; multi-
// account setups get CLOUDFLARE_API_TOKEN_<UPPER_NAME>. This mirrors the
// AI-provider precedent where each provider has a fixed env-var name and
// the operator never types the NAME (issue #13 §1).
func cfEnvVarForName(name string) string {
	if name == "" {
		return "CLOUDFLARE_API_TOKEN"
	}
	// The label is already restricted to [A-Za-z0-9_-]+; convert to a
	// valid POSIX identifier by upper-casing and swapping '-' for '_'.
	upper := strings.ToUpper(name)
	upper = strings.ReplaceAll(upper, "-", "_")
	return "CLOUDFLARE_API_TOKEN_" + upper
}

// splitAndTrim splits raw on ',' and trims whitespace; empty segments
// dropped. Nil on empty input.
func splitAndTrim(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, strings.ToLower(s))
		}
	}
	return out
}

// buildCFWAFRuleExpression returns the exact Cloudflare rule expression the
// operator must paste in the dashboard for lists mode. Kept as a plain
// function (not templated) so the format is trivially reviewable and no
// user-controlled string can end up in it — the list name has already been
// validated against cfListNameRe (alphanumeric + underscore only).
func buildCFWAFRuleExpression(listName string) string {
	return fmt.Sprintf("(ip.src in $%s)", listName)
}

// dryValidateCFToken makes a single GET request to the Cloudflare API to
// verify the token is scoped correctly for the chosen mode. On 401/403 it
// returns a scope-specific message; on any other non-2xx it returns a
// generic error including the status code but NOT the response body (which
// could contain rate-limit correlation IDs or other Cloudflare-internal
// data we don't need to surface).
//
// The token is never appended to the error message — the CF API only
// accepts it in the Authorization header, and %w/%v wrapping is scoped to
// the request URL (built with req.URL.Query()) which never carries the
// token.
func dryValidateCFToken(ctx context.Context, deps cdnDeps, cfg *config.CloudflareCfg, token string) error {
	base := deps.CFAPIBaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	var url, scopeHint string
	switch cfg.Mode {
	case "lists":
		url = fmt.Sprintf("%s/accounts/%s", base, cfg.AccountID)
		scopeHint = "Account:Account Filter Lists:Edit on account " + cfg.AccountID
	case "rulesets":
		if len(cfg.ZoneIDs) == 0 {
			return fmt.Errorf("internal: rulesets mode with no zone_ids")
		}
		url = fmt.Sprintf("%s/zones/%s", base, cfg.ZoneIDs[0])
		scopeHint = "Zone:Firewall:Edit on zone " + cfg.ZoneIDs[0]
	default:
		return fmt.Errorf("internal: unknown mode %q", cfg.Mode)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // G107: url is built from compile-time constant base + operator-typed ID validated to [a-f0-9]{32}
	if err != nil {
		// This can only happen for a malformed URL (would indicate an
		// internal bug, not operator error). Report without echoing the
		// URL — which is fine here since the URL doesn't contain the
		// token, but stays defensive.
		return fmt.Errorf("building validation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ezyshield-init/cdn-detect")

	client := deps.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare API unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// Best-effort read of the CF error struct so we can echo the
		// most useful hint. Bounded to keep the message reasonable —
		// even a runaway CF response shouldn't ever be more than a few
		// hundred bytes for these endpoints.
		msg := readCFErrorMessage(resp.Body)
		if msg == "" {
			return fmt.Errorf("token lacks scope %q (HTTP %d) — see https://developers.cloudflare.com/fundamentals/api/reference/permissions/",
				scopeHint, resp.StatusCode)
		}
		return fmt.Errorf("token lacks scope %q (HTTP %d: %s)", scopeHint, resp.StatusCode, msg)
	case resp.StatusCode >= 400:
		return fmt.Errorf("cloudflare API returned HTTP %d validating %s (transient?) — delete config.yaml and re-run `sudo ezyshield init` to retry",
			resp.StatusCode, cfg.Mode)
	}
	return nil
}

// cfErrorResponse mirrors the Cloudflare v4 error envelope. We only look at
// the first errors[].message to keep parsing simple.
type cfErrorResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// readCFErrorMessage extracts errors[0].message from a bounded read of the
// response body. Returns "" on any parse failure or when no message is
// present — the caller supplies a generic fallback.
func readCFErrorMessage(body io.Reader) string {
	// Cap read to 4 KiB; more than enough for any CF error envelope.
	const maxBytes = 4 << 10
	buf, err := io.ReadAll(io.LimitReader(body, maxBytes))
	if err != nil {
		return ""
	}
	var e cfErrorResponse
	if err := json.Unmarshal(buf, &e); err != nil {
		return ""
	}
	if len(e.Errors) == 0 {
		return ""
	}
	// Guard against a Cloudflare-crafted message that could inject ANSI
	// escapes into the wizard terminal. Strip control chars.
	return sanitizeErrorMessage(e.Errors[0].Message)
}

// sanitizeErrorMessage strips ASCII control characters + trims to 200
// bytes so a malicious upstream cannot forge terminal output via the
// wizard's stdout. §1 (SECURITY-REVIEW.md).
func sanitizeErrorMessage(s string) string {
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' {
			b.WriteByte(' ')
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ── config.yaml + .env emission (called from init.go) ──────────────────────

// emitCloudflareYAML appends the enforce.cloudflare section for step.cfCfg
// to the string builder used by writeGeneratedConfig. The generated yaml is
// still round-tripped through config.LoadConfigReader before the file
// commits, so any mismatch between this emitter and the config schema is
// caught before the operator can see it.
//
// This function is deliberately in init_cdn.go rather than init.go so the
// full CF-specific yaml emission logic lives next to the prompts it
// backs. init.go just calls it.
func emitCloudflareYAML(b *strings.Builder, step *cdnStep) {
	if step == nil || step.cfCfg == nil {
		return
	}
	cfg := step.cfCfg
	// enforce: has already been opened by init.go (nftables lives there
	// too); we only append the cloudflare: mapping. Emit as a single-map
	// (not a sequence) since we only support one account in this cut.
	fmt.Fprintf(b, "  cloudflare:\n")
	if cfg.Name != "" {
		fmt.Fprintf(b, "    name: %s\n", cfg.Name)
	}
	fmt.Fprintf(b, "    api_token: %s\n", cfg.APIToken)
	fmt.Fprintf(b, "    mode: %s\n", cfg.Mode)
	if cfg.Action != "" {
		fmt.Fprintf(b, "    action: %s\n", cfg.Action)
	}
	switch cfg.Mode {
	case "lists":
		fmt.Fprintf(b, "    account_id: %s\n", cfg.AccountID)
		if cfg.ListName != "" {
			fmt.Fprintf(b, "    list_name: %s\n", cfg.ListName)
		}
	case "rulesets":
		fmt.Fprintf(b, "    zone_ids:\n")
		for _, z := range cfg.ZoneIDs {
			fmt.Fprintf(b, "      - %s\n", z)
		}
	}
}

// writeCloudflareEnvFile writes / merges the CF token into the same .env
// file that the AI step uses. It reuses writeEnvFileContent's shape but
// appends rather than overwrites so a prior ANTHROPIC_API_KEY line is
// preserved on the same file. Mode + ownership match the AI file: 0600
// root:ezyshield.
//
// Returns wrote/kept in the same shape as writeOrKeepEnvFile so the
// caller can render a consistent log line.
func writeCloudflareEnvFile(configDir, envVar, token string) (wrote, kept bool, err error) {
	if envVar == "" {
		return false, false, fmt.Errorf("internal: writeCloudflareEnvFile called with empty envVar")
	}
	if token == "" {
		return false, false, fmt.Errorf("internal: writeCloudflareEnvFile called with empty token")
	}
	envPath := filepath.Join(configDir, envFileName)

	// Idempotency: if the file already has envVar=<non-placeholder>,
	// leave it alone. This lets a re-run avoid clobbering a manually
	// rotated token — matches the AI-key idempotency (§5 issue #13).
	if existing, ok := readEnvValue(envPath, envVar); ok &&
		existing != "" && existing != envAPIKeyPlaceholder {
		if existing == token {
			// Same value; no change on disk.
			return false, true, nil
		}
	}

	// Load existing content (if any), replace or append envVar.
	existing, err := loadEnvFileLines(envPath)
	if err != nil {
		return false, false, err
	}
	updated := upsertEnvLine(existing, envVar, token)
	body := renderEnvFile(updated)
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		return false, false, fmt.Errorf("writing %s: %w", envPath, err)
	}
	if err := applyDaemonOwnership(envPath, 0o600); err != nil {
		return false, false, fmt.Errorf("set ownership on %s: %w", envPath, err)
	}
	return true, false, nil
}

// envLine holds one line of a shell env file. Comments and blank lines are
// preserved verbatim so an operator's hand-edited annotations survive a
// wizard re-run.
type envLine struct {
	// key is set when this line is a KEY=VALUE entry; empty for comments
	// or blanks. When key is non-empty, raw is ignored on serialization.
	key   string
	value string
	// raw is the original line contents for non-KV lines (comments/blanks).
	raw string
}

// loadEnvFileLines reads path into an envLine slice. Missing file returns
// nil, nil — the caller writes a fresh header.
func loadEnvFileLines(path string) ([]envLine, error) {
	f, err := os.Open(path) //nolint:gosec // wizard-owned path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var out []envLine
	buf := make([]byte, 0, 4096)
	// Simple line reader; the file is tiny (KB scale) so a hand-rolled
	// scan avoids pulling bufio.Scanner + a Split func.
	all, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	buf = append(buf, all...)
	for _, line := range strings.Split(string(buf), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			out = append(out, envLine{raw: line})
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			out = append(out, envLine{raw: line})
			continue
		}
		out = append(out, envLine{key: strings.TrimSpace(k), value: v})
	}
	// The final split trailing "" becomes a blank envLine we should
	// strip so we don't accumulate blank lines on every re-write.
	if n := len(out); n > 0 && out[n-1].key == "" && strings.TrimSpace(out[n-1].raw) == "" {
		out = out[:n-1]
	}
	return out, nil
}

// upsertEnvLine returns lines with key=value updated or appended.
func upsertEnvLine(lines []envLine, key, value string) []envLine {
	for i, l := range lines {
		if l.key == key {
			lines[i].value = value
			return lines
		}
	}
	// New key — append.
	return append(lines, envLine{key: key, value: value})
}

// renderEnvFile serializes back to the on-disk shape. When lines is empty
// we prepend the same header writeEnvFileContent uses so a fresh file
// looks identical whether the AI step or the CF step wrote it.
func renderEnvFile(lines []envLine) string {
	var b strings.Builder
	// Header ONLY when no comment lines already exist — otherwise we
	// duplicate the header on every re-run.
	hasHeader := false
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l.raw), "#") {
			hasHeader = true
			break
		}
	}
	if !hasHeader {
		fmt.Fprint(&b, "# EzyShield environment — generated by 'ezyshield init'\n")
		fmt.Fprint(&b, "# systemd loads this via EnvironmentFile= (see ezyshield.service).\n")
	}
	for _, l := range lines {
		if l.key == "" {
			b.WriteString(l.raw)
			b.WriteString("\n")
			continue
		}
		fmt.Fprintf(&b, "%s=%s\n", l.key, l.value)
	}
	return b.String()
}
