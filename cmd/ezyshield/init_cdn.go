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
	// cfAttempted is true once the operator entered the Cloudflare subflow.
	// cfAttempted && !cfEnabled means the subflow aborted (the loud banner
	// from issue #93 fired); used only by the init summary (issue #102).
	cfAttempted bool
	// cfAccounts holds one entry per Cloudflare account the operator
	// configured (issue #217: agencies commonly manage several client
	// accounts, each with its own token). Only populated when cfEnabled is
	// true and every entry passed validation.
	cfAccounts []cfAccountSetup
}

// cfAccountSetup is one configured Cloudflare account: the config.yaml entry
// plus the secret material that goes to .env instead.
type cfAccountSetup struct {
	// cfg is the entry the wizard will emit into enforce.cloudflare.
	cfg config.CloudflareCfg
	// tokenEnvVar is the exact env-var name the wizard writes to .env; the
	// yaml gets `api_token: env:<tokenEnvVar>`.
	tokenEnvVar string
	// token holds the raw token between the prompt and the .env write.
	// Same discipline as wizardState.aiToken — never appears in any log
	// path, never printed to stdout, redacted by cdnStep.String().
	token string
	// wafRuleExpression is the WAF Custom Rule expression printed to the
	// operator in lists mode so they can paste it into the CF dashboard.
	wafRuleExpression string
}

// String on *cdnStep masks every CF token, mirroring wizardState.String().
// A `slog.Debug("state", "s", cdnStep)` or a %+v in tests must never leak
// a paste.
func (c *cdnStep) String() string {
	if c == nil {
		return "<nil cdnStep>"
	}
	accts := make([]string, 0, len(c.cfAccounts))
	for _, a := range c.cfAccounts {
		accts = append(accts, a.String())
	}
	return fmt.Sprintf("cdnStep{vhosts=%d detected=%d cfEnabled=%v accounts=[%s]}",
		len(c.vhosts), len(c.detected), c.cfEnabled, strings.Join(accts, " "))
}

// String on cfAccountSetup masks the token for the same reason.
func (a cfAccountSetup) String() string {
	tokMark := "<empty>"
	if a.token != "" {
		tokMark = "<redacted>"
	}
	return fmt.Sprintf("cfAccount{name=%q mode=%s tokenEnvVar=%q token=%s}",
		a.cfg.Name, a.cfg.Mode, a.tokenEnvVar, tokMark)
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
			runCloudflareSubflow(ctx, p, pr, step, deps, nil, cfSubflowOpts{})
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
			runCloudflareSubflow(ctx, p, pr, step, deps, nil, cfSubflowOpts{})
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
			runCloudflareSubflow(ctx, p, pr, step, deps, cfDomains, cfSubflowOpts{})
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
	p.printf("      and re-run 'sudo %s init'.\n", progName)
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
	p.printf("      and re-run 'sudo %s init'.\n", progName)
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

// cfSubflowOpts parameterizes runCloudflareSubflow for its two entry points.
// The init wizard passes the zero value (no pre-existing accounts); the
// `config enforcer cloudflare` wizard passes the accounts already present in
// config.yaml plus, when the operator chose to reconfigure one of them, the
// exact name to replace.
type cfSubflowOpts struct {
	// existing lists the accounts already configured in config.yaml. Their
	// names/env vars are reserved; typing an existing name means "replace".
	existing []config.CloudflareCfg
	// reconfigureName, when set (hasReconfigure), pins the FIRST prompted
	// account to this exact name — the operator picked an existing account
	// to redo, so the name prompt is skipped. May pin the empty name (the
	// legacy unnamed single-account shape).
	reconfigureName string
	hasReconfigure  bool
}

// cfNameRe matches config.validateCFInstanceName's constraint (1..32 of
// [A-Za-z0-9_-]) so the wizard rejects a bad label before write-time
// validation would.
var cfNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// runCloudflareSubflow drives the CF-specific prompts and, on success,
// populates step.cfAccounts (one entry per configured account, issue #217).
// It never returns an error: on any failure it prints the reason; if NO
// account was completed, step.cfEnabled stays false so the loud banner and
// the skip warning fire.
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
	opts cfSubflowOpts,
) {
	// Mark the attempt so the init summary can distinguish "operator entered
	// the subflow and it aborted" from "operator declined at the yes/no
	// prompt" (issue #102). Presentation-only: no prompt or write changes.
	step.cfAttempted = true

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
	printCFModeHelp(p)

	// Name/env-var bookkeeping across the loop. Existing accounts reserve
	// their names (typing one = replace intent, allowed with a note) and
	// their env vars; session accounts reserve both outright.
	sessionNames := make(map[string]bool)
	existingNames := make(map[string]bool)
	takenEnvVars := make(map[string]bool)
	for _, ex := range opts.existing {
		if ex.Name != "" {
			existingNames[ex.Name] = true
		}
		if v, ok := strings.CutPrefix(string(ex.APIToken), "env:"); ok {
			// The account being reconfigured keeps its own env var free.
			if !opts.hasReconfigure || ex.Name != opts.reconfigureName {
				takenEnvVars[v] = true
			}
		}
	}

	for {
		first := len(step.cfAccounts) == 0
		nameCtx := cfNamePromptCtx{
			// The very first overall account may stay unnamed; anything
			// beyond it (existing accounts count) needs a unique name.
			required:      !first || len(opts.existing) > 0,
			sessionNames:  sessionNames,
			existingNames: existingNames,
			takenEnvVars:  takenEnvVars,
		}
		if first && opts.hasReconfigure {
			nameCtx.forcedName = opts.reconfigureName
			nameCtx.hasForced = true
		}

		acct, ok := promptOneCFAccount(ctx, p, pr, deps, nameCtx)
		if !ok {
			if first {
				// Nothing configured at all — the deferred banner fires.
				return
			}
			p.println("  This account was NOT added; keeping the account(s) configured above.")
			break
		}
		step.cfAccounts = append(step.cfAccounts, *acct)
		if acct.cfg.Name != "" {
			sessionNames[acct.cfg.Name] = true
		}
		takenEnvVars[acct.tokenEnvVar] = true

		if !pr.askBool("Add another Cloudflare account (separate token, e.g. another client)?", false) {
			break
		}
		// Going multi-account: config validation requires every entry to
		// carry a unique name, so a still-unnamed first account must be
		// named before we continue.
		if len(opts.existing) == 0 && step.cfAccounts[0].cfg.Name == "" {
			name := strings.TrimSpace(pr.ask("Name for the first account (e.g. main)", "main"))
			if !cfNameRe.MatchString(name) || sessionNames[name] {
				p.printf("  invalid or duplicate name %q — keeping a single account.\n", name)
				break
			}
			// The env var stays CLOUDFLARE_API_TOKEN: api_token references
			// are independent of the account label.
			step.cfAccounts[0].cfg.Name = name
			sessionNames[name] = true
		}
	}
	step.cfEnabled = len(step.cfAccounts) > 0
}

// printCFModeHelp explains the two enforcement modes. Both are first-class:
// lists suits many zones behind one account; rulesets suits precise per-zone
// control (and needs no account-level list quota).
func printCFModeHelp(p *wPrinter) {
	p.println("")
	p.println("  Cloudflare enforcement modes (both fully supported — pick per account):")
	p.println("    • lists    — one account-scoped Custom IP List, one API token")
	p.println("                 for the whole account, propagates to every zone")
	p.println("                 referencing it via a WAF Custom Rule.")
	p.println("                 Good fit for multi-zone / high-volume deploys.")
	p.println("    • rulesets — one WAF Custom Rule per zone, wired entirely via API.")
	p.println("                 Requires listing every zone_id. ~200 IP cap per")
	p.println("                 rule, auto-split by the enforcer.")
	p.println("                 Good fit when you want per-zone control or the")
	p.println("                 account's custom-list quota is taken.")
}

// cfNamePromptCtx carries the naming rules for one account prompt; see
// runCloudflareSubflow for how the maps are maintained across the loop.
type cfNamePromptCtx struct {
	forcedName    string
	hasForced     bool
	required      bool
	sessionNames  map[string]bool
	existingNames map[string]bool
	takenEnvVars  map[string]bool
}

// promptOneCFAccount collects, validates, and preflights a single Cloudflare
// account. Returns (nil, false) on any failure — the caller decides whether
// that aborts the subflow (first account) or just ends the loop.
func promptOneCFAccount(
	ctx context.Context,
	p *wPrinter,
	pr prompter,
	deps cdnDeps,
	nameCtx cfNamePromptCtx,
) (*cfAccountSetup, bool) {
	name, ok := promptCFAccountName(p, pr, nameCtx)
	if !ok {
		return nil, false
	}

	mode := pr.ask("Cloudflare mode (lists/rulesets)", "lists")
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "lists" && mode != "rulesets" {
		p.printf("  invalid mode %q — expected 'lists' or 'rulesets'; skipping this account.\n", mode)
		return nil, false
	}

	action := pr.ask("Rule action (block/challenge/js_challenge)", "block")
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "block" && action != "challenge" && action != "js_challenge" {
		p.printf("  invalid action %q; skipping this account.\n", action)
		return nil, false
	}

	// Fixed env-var NAME derived from the account label (issue #13
	// precedent: never prompt the operator for the NAME). Unnamed account →
	// CLOUDFLARE_API_TOKEN; named → CLOUDFLARE_API_TOKEN_<UPPER_NAME>.
	tokenEnvVar := cfEnvVarForName(name)
	if nameCtx.takenEnvVars[tokenEnvVar] {
		p.printf("  account name %q maps to env var %s, which is already used by another account; choose a different name.\n",
			name, tokenEnvVar)
		return nil, false
	}

	// Prompt for the token itself, masked, via the same tty path the AI
	// step uses. Same fall-through rules on error (no tty → skip).
	reader := deps.TokenReader
	if reader == nil {
		reader = tokenReader
	}
	tok, err := reader("  Paste the Cloudflare API token for this account (input hidden, ENTER to skip): ")
	if err != nil || tok == "" {
		// No token means we can't even validate scope. Refuse to write
		// half-configured CF settings.
		p.println("  No Cloudflare token provided; skipping this account.")
		return nil, false
	}

	// Mode-specific fields.
	cfg := &config.CloudflareCfg{
		Name:     name,
		APIToken: config.SecretRef("env:" + tokenEnvVar),
		Mode:     mode,
		Action:   action,
	}
	var coverage cfZoneCoverage

	switch mode {
	case "lists":
		accountID := pr.ask("Cloudflare account ID (32 hex chars)", "")
		accountID = strings.ToLower(strings.TrimSpace(accountID))
		if !cfHexIDRe.MatchString(accountID) {
			p.println("  account_id must be 32 lowercase hex characters (see CF dashboard → Overview → Account ID); skipping this account.")
			return nil, false
		}
		cfg.AccountID = accountID
		listName := pr.ask("Custom IP List name", "ezyshield_blocked")
		listName = strings.TrimSpace(listName)
		if !cfListNameRe.MatchString(listName) {
			p.printf("  list_name must match [A-Za-z0-9_]+; got %q; skipping this account.\n", listName)
			return nil, false
		}
		cfg.ListName = listName
		// Which zones should the WAF block rule cover (issue #121)? ENTER
		// keeps the manual-instructions path; the rollout itself runs after
		// the preflight below has proven the list exists.
		var covOK bool
		coverage, covOK = promptCFZoneCoverage(p, pr)
		if !covOK {
			return nil, false
		}

	case "rulesets":
		rawZones := pr.ask("Zone IDs (comma-separated, 32 hex chars each)", "")
		zones := splitAndTrim(rawZones)
		if len(zones) == 0 {
			p.println("  no zone_ids given; skipping this account.")
			return nil, false
		}
		for _, z := range zones {
			if !cfHexIDRe.MatchString(z) {
				p.printf("  zone_id %q is not 32 hex chars; skipping this account.\n", z)
				return nil, false
			}
		}
		cfg.ZoneIDs = zones
	}

	// Dry token validation before we write anything.
	if err := dryValidateCFToken(ctx, deps, cfg, tok); err != nil {
		p.printf("  Cloudflare token validation failed: %v\n", err)
		p.println("  Refusing to write config with an unvalidated token.")
		return nil, false
	}
	p.println("  Cloudflare token validated OK.")

	// Capability preflight (issue #234): a valid, correctly-scoped token
	// does not mean the chosen configuration can work — plan quotas can
	// still make it a guaranteed runtime failure. Prove feasibility now,
	// while the operator is at the prompt, or refuse to write the config.
	if !runCFCapabilityPreflight(ctx, p, deps, cfg, tok) {
		return nil, false
	}

	if mode == "lists" {
		// Zone rollout (issue #121): resolve the coverage answer, persist
		// zone_ids, create-or-verify the WAF rule per zone with a report.
		cfConfigureZoneCoverage(ctx, p, deps, cfg, tok, coverage)
	}

	acct := &cfAccountSetup{cfg: *cfg, tokenEnvVar: tokenEnvVar, token: tok}
	if mode == "lists" {
		acct.wafRuleExpression = buildCFWAFRuleExpression(cfg.ListName)
		if len(cfg.ZoneIDs) == 0 {
			// Manual path (no coverage chosen, or enumeration degraded):
			// same instructions as before.
			printCFListsManualStep(p, acct.wafRuleExpression)
		}
	}
	return acct, true
}

// promptCFAccountName resolves the account label for the entry being
// configured: forced (reconfigure path), required-unique (multi-account), or
// — the single-account happy path — no prompt at all, keeping today's short
// flow (the label is only asked once a second account enters the picture).
func promptCFAccountName(p *wPrinter, pr prompter, nameCtx cfNamePromptCtx) (string, bool) {
	if nameCtx.hasForced {
		return nameCtx.forcedName, true
	}
	if !nameCtx.required {
		return "", true
	}
	name := strings.TrimSpace(pr.ask("Account name (unique label, e.g. client_a)", "main"))
	if !cfNameRe.MatchString(name) {
		p.printf("  account name must match [A-Za-z0-9_-]+ (max 32 chars); got %q; skipping this account.\n", name)
		return "", false
	}
	if nameCtx.sessionNames[name] {
		p.printf("  account name %q was already used in this run; skipping this account.\n", name)
		return "", false
	}
	if nameCtx.existingNames[name] {
		p.printf("  (name %q matches an existing account — it will be replaced)\n", name)
	}
	return name, true
}

// printCFListsManualStep prints the one-time WAF Custom Rule instructions for
// a lists-mode account.
func printCFListsManualStep(p *wPrinter, expression string) {
	p.println("")
	p.println("  Lists mode requires a one-time manual step in the Cloudflare dashboard:")
	p.println("    1. Go to Security → WAF → Custom Rules on any zone under the account.")
	p.println("    2. Create a rule with the expression below and Action = 'Block' (or")
	p.println("       'Managed Challenge' if you prefer challenges over hard blocks).")
	p.println("    3. Repeat per zone you want covered by the list.")
	p.println("")
	p.printf("    Expression: %s\n", expression)
	p.println("")
}

// runCFCapabilityPreflight proves the chosen mode can actually operate on
// this account before any config is written (issue #234). Returns false
// when setup must abort — the caller's deferred banner then fires and no
// enforce.cloudflare section is emitted.
//
// Lists mode: create-or-adopt the configured Custom List right now. The
// canonical failure this catches is a plan-quota refusal (free accounts get
// a single custom list); it is rendered with the ways out instead of the
// raw API error alone.
//
// Rulesets mode: report each zone's current WAF custom-rule count so the
// operator can see slot headroom (free-plan zones allow 5 custom rules and
// EzyShield needs one free slot). Informational — plan caps are not
// queryable with the enforcer's own token scope, so counts cannot hard-fail
// the wizard; a read error on any zone does abort (it means the zone ID or
// scope is wrong in a way the earlier probe missed).
func runCFCapabilityPreflight(ctx context.Context, p *wPrinter, deps cdnDeps, cfg *config.CloudflareCfg, token string) bool {
	base := deps.CFAPIBaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	switch cfg.Mode {
	case "lists":
		res, err := cfEnsureList(ctx, deps.HTTPClient, base, cfg.AccountID, cfg.ListName, token)
		if err != nil {
			p.printf("  %v\n", err)
			if res.QuotaExceeded {
				p.println("")
				p.println("  This usually means your Cloudflare plan's custom-list quota is")
				p.println("  exhausted — free accounts get a single custom list. Ways out:")
				p.println("    • delete an unused list in the CF dashboard (Manage Account →")
				p.println("      Configurations → Lists) and re-run this setup, or")
				p.println("    • upgrade the Cloudflare plan, or")
				p.println("    • re-run and choose 'rulesets' mode (needs no custom list).")
			}
			p.println("  Refusing to write a Cloudflare config that cannot enforce.")
			return false
		}
		if res.Adopted {
			p.printf("  Adopting existing Custom IP List %q (%d item(s)).\n", cfg.ListName, res.Items)
		} else {
			p.printf("  Created Custom IP List %q on account %s.\n", cfg.ListName, cfg.AccountID)
		}
		return true

	case "rulesets":
		for _, zone := range cfg.ZoneIDs {
			n, err := cfCountZoneRules(ctx, deps.HTTPClient, base, zone, token)
			if err != nil {
				p.printf("  %v\n", err)
				p.println("  Refusing to write a Cloudflare config that cannot enforce.")
				return false
			}
			p.printf("  Zone %s: %d WAF custom rule(s) currently in use.\n", zone, n)
		}
		p.println("  Note: EzyShield needs one free custom-rule slot per zone")
		p.println("  (free-plan zones allow 5 WAF custom rules in total).")
		return true
	}
	return true
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

// dryValidateCFToken checks that the token the operator pasted is (a) a
// real, active Cloudflare API token and (b) actually usable for the mode
// the operator chose. It never hits an endpoint that requires a scope the
// enforcer itself would not need — that was the original bug: probing
// GET /accounts/{id} demanded Account Settings:Read, so a correctly
// Account-Filter-Lists:Edit-scoped token failed here with 403 even though
// nothing else was wrong with it.
//
// The check runs in two phases:
//
//  1. Identity probe — is this token alive at all? Cloudflare exposes
//     two verify endpoints depending on who OWNS the token:
//     - Account-owned tokens: GET /accounts/{account_id}/tokens/verify
//     - User-owned  tokens:   GET /user/tokens/verify
//     We try the account path first (recommended for service accounts)
//     and fall back to the user path. If neither returns 200 the token
//     is genuinely invalid or expired.
//     This phase REQUIRES an account ID: account-owned (cfat_) tokens
//     are rejected by /user/tokens/verify, and without an ID the account
//     URL degenerates to /accounts//tokens/verify. Rulesets mode never
//     collects an account ID (it only needs zone IDs), so running the
//     identity probe there would misreport a perfectly valid cfat_
//     token as "invalid or expired". When cfg.AccountID is empty we
//     skip Phase 1 entirely and let Phase 2 prove the token is alive —
//     a 200 on the zone rulesets read implies both identity and scope.
//
//  2. Scope probe — does the token actually have the permission needed
//     for the operational mode? We hit the read-side of the endpoint the
//     enforcer will write to. Read implies Edit succeeds too (Edit is a
//     superset), so we accept 200 as evidence of "at least Read on the
//     right object" and rely on the scope-hint text to tell the operator
//     which Edit scope to enable if this fails with 403.
//     - lists    → GET /accounts/{account_id}/rules/lists?per_page=1
//     - rulesets → GET /zones/{zone_id}/rulesets?per_page=1
//
// The token is only ever sent as an Authorization header — never in a URL
// path or query — so %w wrapping of transport errors and status-code
// echoes cannot leak it. All error bodies are read through
// readCFErrorMessage, which caps the read and strips ANSI (§1
// SECURITY-REVIEW.md).
func dryValidateCFToken(ctx context.Context, deps cdnDeps, cfg *config.CloudflareCfg, token string) error {
	base := deps.CFAPIBaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	identityVerified := false
	if cfg.AccountID != "" {
		if err := verifyCFTokenIdentity(ctx, deps, base, cfg.AccountID, token); err != nil {
			return err
		}
		identityVerified = true
	}
	return probeCFTokenScope(ctx, deps, base, cfg, token, identityVerified)
}

// verifyCFTokenIdentity implements Phase 1. Returns nil as soon as either
// verify endpoint reports 200; otherwise returns an "invalid or expired"
// error that echoes both status codes so the operator can distinguish
// "wrong account_id" (accounts verify 404 / 401 with `invalid account`)
// from "token expired" (both verify 401).
func verifyCFTokenIdentity(ctx context.Context, deps cdnDeps, base, accountID, token string) error {
	// Account-owned path first — this is what CI/service tokens use, and
	// what the wizard steers operators toward.
	acctURL := fmt.Sprintf("%s/accounts/%s/tokens/verify", base, accountID)
	acctStatus, acctMsg, err := doCFGet(ctx, deps, acctURL, token)
	if err != nil {
		return err
	}
	if acctStatus == http.StatusOK {
		return nil
	}
	// User-owned fallback for personal API tokens.
	userURL := base + "/user/tokens/verify"
	userStatus, _, err := doCFGet(ctx, deps, userURL, token)
	if err != nil {
		return err
	}
	if userStatus == http.StatusOK {
		return nil
	}
	// Both verify endpoints rejected the token. Prefer the account
	// endpoint's error message when available — it's the more specific
	// diagnostic ("wrong account" vs "expired token"). We deliberately
	// do NOT surface the user-endpoint body: it can only add noise here.
	if acctMsg != "" {
		return fmt.Errorf("cloudflare token is invalid, expired, or not authorised for account %s (accounts verify HTTP %d: %s; user verify HTTP %d) — see https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
			accountID, acctStatus, acctMsg, userStatus)
	}
	return fmt.Errorf("cloudflare token is invalid, expired, or not authorised for account %s (accounts verify HTTP %d; user verify HTTP %d) — see https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
		accountID, acctStatus, userStatus)
}

// probeCFTokenScope implements Phase 2: "can this token actually operate
// on the target resource?". identityVerified says whether Phase 1 ran and
// passed; when it did NOT (rulesets mode has no account ID to verify
// against), a 401/403 here is ambiguous — the token may be dead, not just
// under-scoped — and the error message must say so.
func probeCFTokenScope(ctx context.Context, deps cdnDeps, base string, cfg *config.CloudflareCfg, token string, identityVerified bool) error {
	var url, scopeHint string
	switch cfg.Mode {
	case "lists":
		// per_page=1 keeps the response tiny even on accounts with
		// thousands of Custom Lists.
		url = fmt.Sprintf("%s/accounts/%s/rules/lists?per_page=1", base, cfg.AccountID)
		scopeHint = "Account:Account Filter Lists:Edit on account " + cfg.AccountID
	case "rulesets":
		if len(cfg.ZoneIDs) == 0 {
			return fmt.Errorf("internal: rulesets mode with no zone_ids")
		}
		url = fmt.Sprintf("%s/zones/%s/rulesets?per_page=1", base, cfg.ZoneIDs[0])
		scopeHint = "Zone:Firewall Services:Edit on zone " + cfg.ZoneIDs[0]
	default:
		return fmt.Errorf("internal: unknown mode %q", cfg.Mode)
	}
	status, msg, err := doCFGet(ctx, deps, url, token)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		reason := fmt.Sprintf("token lacks scope %q", scopeHint)
		if !identityVerified {
			// No Phase-1 identity check ran, so we cannot distinguish a
			// dead token from an under-scoped one — name both.
			reason = fmt.Sprintf("token is invalid, expired, or lacks scope %q", scopeHint)
		}
		if msg == "" {
			return fmt.Errorf("%s (HTTP %d) — see https://developers.cloudflare.com/fundamentals/api/reference/permissions/",
				reason, status)
		}
		return fmt.Errorf("%s (HTTP %d: %s)", reason, status, msg)
	default:
		return fmt.Errorf("cloudflare API returned HTTP %d validating %s (transient?) — delete config.yaml and re-run `sudo %s init` to retry",
			status, cfg.Mode, progName)
	}
}

// doCFGet issues one GET against the Cloudflare API and returns the HTTP
// status, a best-effort parsed error message on non-2xx, and any
// transport-layer error. The token is passed exclusively as an
// Authorization header; the response body is bounded via readCFErrorMessage.
//
// On 2xx the response body is closed but NOT parsed — we don't need any
// verify-endpoint payload, and skipping the parse avoids exposing us to a
// giant success response.
func doCFGet(ctx context.Context, deps cdnDeps, url, token string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // G107: url is built from compile-time constant base + operator-typed IDs validated to [a-f0-9]{32}
	if err != nil {
		return 0, "", fmt.Errorf("building validation request: %w", err)
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
		return 0, "", fmt.Errorf("cloudflare API unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var msg string
	if resp.StatusCode != http.StatusOK {
		msg = readCFErrorMessage(resp.Body)
	}
	return resp.StatusCode, msg, nil
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

// emitCloudflareYAML appends the enforce.cloudflare section for
// step.cfAccounts to the string builder used by writeGeneratedConfig. The
// generated yaml is still round-tripped through config.LoadConfigReader
// before the file commits, so any mismatch between this emitter and the
// config schema is caught before the operator can see it.
//
// A single account keeps the compact single-mapping shape (the legacy form
// CloudflareCfgs.UnmarshalYAML accepts); multiple accounts emit a sequence,
// one entry per account (issue #217).
//
// This function is deliberately in init_cdn.go rather than init.go so the
// full CF-specific yaml emission logic lives next to the prompts it
// backs. init.go just calls it.
func emitCloudflareYAML(b *strings.Builder, step *cdnStep) {
	if step == nil || len(step.cfAccounts) == 0 {
		return
	}
	// enforce: has already been opened by init.go (nftables lives there
	// too); we only append the cloudflare: section.
	fmt.Fprintf(b, "  cloudflare:\n")
	if len(step.cfAccounts) == 1 {
		emitCFAccountYAML(b, &step.cfAccounts[0].cfg, "    ", "")
		return
	}
	for i := range step.cfAccounts {
		emitCFAccountYAML(b, &step.cfAccounts[i].cfg, "      ", "    - ")
	}
}

// emitCFAccountYAML writes one account's fields. firstPrefix, when non-empty,
// replaces indent on the first line only (the "- " sequence-item marker).
func emitCFAccountYAML(b *strings.Builder, cfg *config.CloudflareCfg, indent, firstPrefix string) {
	prefix := firstPrefix
	if prefix == "" {
		prefix = indent
	}
	line := func(format string, args ...any) {
		fmt.Fprintf(b, prefix+format, args...)
		prefix = indent
	}
	if cfg.Name != "" {
		line("name: %s\n", cfg.Name)
	}
	line("api_token: %s\n", cfg.APIToken)
	line("mode: %s\n", cfg.Mode)
	if cfg.Action != "" {
		line("action: %s\n", cfg.Action)
	}
	switch cfg.Mode {
	case "lists":
		line("account_id: %s\n", cfg.AccountID)
		if cfg.ListName != "" {
			line("list_name: %s\n", cfg.ListName)
		}
		// Optional in lists mode: zones whose WAF rule the enforcer manages
		// (collected by the coverage prompt, issue #121).
		if len(cfg.ZoneIDs) > 0 {
			line("zone_ids:\n")
			for _, z := range cfg.ZoneIDs {
				fmt.Fprintf(b, indent+"  - %s\n", z)
			}
		}
	case "rulesets":
		line("zone_ids:\n")
		for _, z := range cfg.ZoneIDs {
			fmt.Fprintf(b, indent+"  - %s\n", z)
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
