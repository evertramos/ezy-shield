package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/configs"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/ownership"
)

const (
	defaultConfigDir  = "/etc/ezyshield"
	defaultSystemdDir = "/etc/systemd/system"
	enforcerSockPath  = "/run/ezyshield-enforcer/enforcer.sock"
	daemonSockPath    = "/run/ezyshield/ezyshield.sock"

	// envFileName is the dot-prefixed shell env file that holds the AI API
	// token loaded via systemd's EnvironmentFile= directive (issue #13 §3).
	// The leading dot brings us in line with the Docker/Kubernetes convention
	// and, more importantly, matches the systemd unit's EnvironmentFile path.
	// Do NOT change this without updating configs/systemd/ezyshield.service.
	envFileName = ".env"

	// envAPIKeyPlaceholder is written to .env when the operator skips the
	// token prompt (piped install, --yes, non-TTY, or blank paste). The
	// loader (internal/config.SecretRef.Resolve) treats this exact string as
	// equivalent to "unset" so a stale placeholder never gets forwarded to a
	// real AI provider (issue #13 §5, §6).
	envAPIKeyPlaceholder = "YOUR_API_KEY_HERE" //nolint:gosec // G101: literal placeholder, deliberately public — the loader (SecretRef.Resolve) treats this exact string as "unset" so a stale placeholder never reaches a real AI provider.

	// systemdDropInDir is the per-unit drop-in override directory. The init
	// wizard writes env.conf here so EnvironmentFile= is active even on hosts
	// with an older embedded service file that predates issue #22.
	systemdDropInDir = defaultSystemdDir + "/ezyshield.service.d"
)

func newInitCmd() *cobra.Command {
	var (
		configDir  string
		yes        bool
		skipSystem bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Interactive setup wizard",
		Long: `Detect the environment, ask a few questions, write config files,
install systemd units, and start EzyShield in dry-run mode.

Pass --yes to accept all smart defaults without prompting.
Pass --config-dir to write files elsewhere (skips systemd/service steps — useful for testing).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRootForWrites(cmd, configDir); err != nil {
				return err
			}
			if configDir != defaultConfigDir {
				skipSystem = true
			}
			return runInitWizard(cmd, configDir, yes, skipSystem)
		},
	}

	cmd.Flags().StringVar(&configDir, "config-dir", defaultConfigDir,
		"directory to write configuration files")
	cmd.Flags().BoolVar(&yes, "yes", false,
		"accept all defaults without interactive prompts")

	return cmd
}

// wPrinter wraps io.Writer and captures the first write error, preventing
// subsequent calls once an error has occurred.
type wPrinter struct {
	w   io.Writer
	err error
}

func (p *wPrinter) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

func (p *wPrinter) println(s string) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintln(p.w, s)
}

// wizardState collects detected values and user answers.
type wizardState struct {
	osArch        string
	nftPath       string
	hasDocker     bool
	allContainers []dockerContainer
	// dockerAllowlist holds the docker bridge subnets to write into the
	// generated policy allowlist (issue #210). Populated by
	// detectDockerBridgeSubnets() during environment detection — empty when
	// docker isn't detected, so buildAllowlist never needs its own docker
	// gate. Never the whole 172.16.0.0/12 supernet: either the subnets that
	// actually exist on the host, or (enumeration failure only) the single
	// default bridge subnet.
	dockerAllowlist []string
	sshUnit         string
	publicIP        string
	sshSourceIP     string

	hasWordPress bool
	wpRulesPath  string

	webServers    []detectedWebServer  // detection result (for display + prompts)
	webCollectors []webServerCollector // operator-approved collectors
	monitorSSH    bool
	adminIPs      []string
	enableAI      bool
	aiProvider    string
	aiModel       string
	aiKeyEnvVar   string
	// aiToken holds the operator-typed API key between the prompt and the
	// .env write. It's ONLY the empty string or the raw token — never used
	// in any log/print/error path (issue #13 §6). Note the deliberate lack
	// of a getter and the redacted String() form on wizardState (below).
	aiToken string
	armed   bool

	// cdn holds CDN-detection + CF-subflow state. Populated by runCDNStep
	// during askQuestions (see init_cdn.go). Non-nil after askQuestions
	// returns so downstream writers can rely on len(cdn.cfAccounts) checks
	// alone. Its String() masks every CF token.
	cdn *cdnStep
}

// String on *wizardState prints every field EXCEPT aiToken, which is masked.
// This exists so an accidental `slog.Debug("state", "s", state)` or a test
// helper that spins the struct through %+v cannot leak the token.
func (s *wizardState) String() string {
	if s == nil {
		return "<nil wizardState>"
	}
	tokenMark := "<empty>"
	if s.aiToken != "" {
		tokenMark = "<redacted>"
	}
	return fmt.Sprintf("wizardState{enableAI=%v provider=%q model=%q keyEnvVar=%q token=%s armed=%v cdn=%s}",
		s.enableAI, s.aiProvider, s.aiModel, s.aiKeyEnvVar, tokenMark, s.armed, s.cdn.String())
}

type dockerContainer struct {
	name  string
	image string
	ports string
}

func runInitWizard(cmd *cobra.Command, configDir string, yes, skipSystem bool) error {
	p := &wPrinter{w: cmd.OutOrStdout()}
	st := newStyler(cmd.OutOrStdout())

	// Pre-flight: refuse before printing the banner or running detection if the
	// wizard would clobber an existing config.yaml or policy.yaml. The writers
	// themselves still guard against overwrite as defense-in-depth (see
	// writeGeneratedConfig / writeGeneratedPolicy), but doing the check up
	// front means the operator doesn't burn several minutes of Q&A only to be
	// told at the Files step that the run cannot succeed. Issue #5.
	if err := preflightExistingConfigFiles(configDir); err != nil {
		return err
	}

	p.println("")
	p.println(st.header("EzyShield setup"))
	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	if !skipSystem && os.Getuid() != 0 {
		return fmt.Errorf("init requires root — re-run with sudo or as root")
	}

	var sc *bufio.Scanner
	if !yes {
		sc = bufio.NewScanner(os.Stdin)
	}

	// ── Environment detection ─────────────────────────────────────────────
	p.println("")
	p.println(st.header("Environment"))

	state := &wizardState{}
	sum := &initSummary{}

	state.osArch = runtime.GOOS + "/" + runtime.GOARCH
	p.printf("  OS/arch: %s\n", state.osArch)

	state.nftPath = detectNFT()
	if state.nftPath != "" {
		p.println(st.ok("nftables: " + state.nftPath))
	} else {
		p.println(st.fail("nftables: not found"))
		if !skipSystem {
			if p.err != nil {
				return fmt.Errorf("writing output: %w", p.err)
			}
			state.nftPath = offerInstallNFT(sc, yes, p.w)
			if state.nftPath != "" {
				p.println(st.ok("nftables: " + state.nftPath + " (installed)"))
			} else {
				p.println(st.warn("nftables: skipped — only dry-run and edge enforcement will work"))
			}
		}
	}

	state.allContainers = detectDockerContainers()
	state.hasDocker = len(state.allContainers) > 0
	if state.hasDocker {
		p.println(st.ok(fmt.Sprintf("docker: %d container(s) running", len(state.allContainers))))

		// Allowlist only the docker bridge subnets that actually exist on
		// this host (issue #210) — never the whole 172.16.0.0/12 supernet,
		// which would exempt >1M RFC1918 addresses from enforcement forever
		// (allowlist always wins).
		subnets, usedFallback := detectDockerBridgeSubnets()
		state.dockerAllowlist = subnets
		switch {
		case usedFallback:
			p.println(st.warn(fmt.Sprintf(
				"docker networks: could not enumerate — allowlisting the default bridge subnet only (%s)",
				defaultDockerBridgeSubnet)))
		case len(subnets) == 0:
			p.println(st.ok("docker networks: no bridge subnets found — no docker allowlist entry added"))
		default:
			p.println(st.ok(fmt.Sprintf("docker networks: allowlisting %d bridge subnet(s): %s",
				len(subnets), strings.Join(subnets, ", "))))
		}
	} else {
		p.println(st.fail("docker: not running / no containers"))
	}

	state.hasWordPress = hasWordPressContainers(state.allContainers)
	if state.hasWordPress {
		state.wpRulesPath = filepath.Join(configDir, "rules.d", "10-wordpress.yaml")
		p.println(st.ok("WordPress detected — rules are built in; tuning drop-in: " + state.wpRulesPath))
	}

	p.println("\n  Detecting web servers...")
	state.webServers = detectWebServers(state.allContainers)
	renderWebServerSummary(p, state.webServers)

	state.sshUnit = detectSSHUnit()
	p.println(st.ok("SSH unit: " + state.sshUnit))

	state.publicIP = fetchPublicIP()
	if state.publicIP != "" {
		p.println(st.ok("public IP: " + state.publicIP))
	} else {
		p.println(st.warn("public IP: unknown (ifconfig.me unreachable)"))
	}

	state.sshSourceIP = sshSourceIP()
	if state.sshSourceIP != "" {
		p.println(st.ok("SSH source: " + state.sshSourceIP))
	}

	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	// ── Questions (sectioned sub-flows) ───────────────────────────────────
	askQuestions(p.w, sc, state, yes, st)

	// Distill the operator's answers for the final Summary section. Runs
	// before the writers so a skipped/aborted component is reported even
	// when a later step fails and the wizard exits early.
	summarizeChoices(state, sum, yes)

	// ── Write config files ────────────────────────────────────────────────
	p.println("")
	p.println(st.header("Files"))
	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	// Create the ezyshield user/group BEFORE writing configs so that
	// applyDaemonOwnership can chown root:ezyshield (issue #91). In test mode
	// (--config-dir), skipSystem is true and we don't touch system accounts.
	if !skipSystem {
		if err := createEzyshieldUser(p.w); err != nil {
			p.printf("  warning: could not create ezyshield user: %v\n", err)
		}
		// Add the invoking admin to the ezyshield group so they can use the
		// control socket (root:ezyshield 0660) without sudo — issue #6.
		if err := addAdminToEzyshieldGroup(p.w); err != nil {
			p.printf("  warning: could not add admin to ezyshield group: %v\n", err)
		}
	}

	if err := os.MkdirAll(configDir, 0o750); err != nil {
		return fmt.Errorf("creating config dir %s: %w", configDir, err)
	}
	// Chown the directory itself so the daemon (User=ezyshield) can traverse
	// it. Without this, /etc/ezyshield ends up root:root 0750 and the daemon
	// crashes on startup unable to open its config — see issue #91.
	if err := applyDaemonOwnership(configDir, 0o750); err != nil {
		return fmt.Errorf("set ownership on %s: %w", configDir, err)
	}

	configPath := filepath.Join(configDir, "config.yaml")
	policyPath := filepath.Join(configDir, "policy.yaml")
	envPath := filepath.Join(configDir, envFileName)

	if err := writeGeneratedConfig(configPath, state); err != nil {
		return err
	}
	p.println(st.ok("wrote " + configPath))
	sum.files = append(sum.files, configPath)

	if err := writeGeneratedPolicy(policyPath, state); err != nil {
		return err
	}
	p.println(st.ok("wrote " + policyPath))
	sum.files = append(sum.files, fmt.Sprintf("%s (armed: %v)", policyPath, state.armed))

	// AI env file: written whenever the provider expects a key (anthropic /
	// openai) — even if the operator skipped the paste prompt, in which case
	// we write the placeholder and print an instruction (issue #13 §5). We
	// do NOT emit the token or a fingerprint of it here.
	envTouched := false
	if state.enableAI && state.aiKeyEnvVar != "" {
		wrote, kept, err := writeOrKeepEnvFile(envPath, state.aiKeyEnvVar, state.aiToken)
		if err != nil {
			return err
		}
		switch {
		case kept:
			p.println(st.ok("kept " + envPath + " (existing token preserved)"))
		case wrote && state.aiToken == "":
			p.println(st.warn("wrote " + envPath + " (chmod 600, placeholder — edit and restart the daemon)"))
			p.printf("    AI API key not set. Edit %s to add it, then restart the daemon.\n", envPath)
		case wrote:
			p.println(st.ok("wrote " + envPath + " (chmod 600)"))
		}
		envTouched = envTouched || wrote || kept
	}

	// Cloudflare tokens: written to the same .env file, one line per account
	// token. Merge semantics preserve any AI KEY= line written above (issue
	// #43). The tokens themselves are NEVER logged — only "wrote" / "kept".
	if state.cdn != nil && state.cdn.cfEnabled {
		for i := range state.cdn.cfAccounts {
			acct := &state.cdn.cfAccounts[i]
			if acct.token == "" || acct.tokenEnvVar == "" {
				continue
			}
			wrote, kept, err := writeCloudflareEnvFile(configDir, acct.tokenEnvVar, acct.token)
			if err != nil {
				return err
			}
			switch {
			case kept:
				p.println(st.ok("kept " + envPath + " (existing " + acct.tokenEnvVar + " preserved)"))
			case wrote:
				p.println(st.ok("wrote " + envPath + " (chmod 600, " + acct.tokenEnvVar + " merged)"))
			}
			envTouched = envTouched || wrote || kept
		}
	}
	if envTouched {
		sum.files = append(sum.files, envPath+" (mode 0600 — secret tokens live here, never in config.yaml)")
	}

	rulesDir := filepath.Join(configDir, "rules.d")
	if err := ensureRulesDir(rulesDir); err != nil {
		return err
	}
	sum.files = append(sum.files, rulesDir+" (drop-in rule customizations — merged over the built-in rules)")
	if state.hasWordPress {
		wrote, err := writeWordPressDropin(state.wpRulesPath)
		if err != nil {
			return err
		}
		if wrote {
			p.println(st.ok("wrote " + state.wpRulesPath + " (commented tuning template)"))
			sum.files = append(sum.files, state.wpRulesPath)
		} else {
			p.println(st.ok("kept " + state.wpRulesPath + " (existing drop-in preserved)"))
		}
	}

	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	if skipSystem {
		sum.skipped = append(sum.skipped,
			"systemd units and services — skipped (non-default --config-dir)")
		renderInitSummary(p, st, state, sum, -1, configDir)
		return p.err
	}

	// ── Install systemd units + start services ────────────────────────────
	p.println("")
	p.println(st.header("System services"))
	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	if err := installSystemdUnits(p.w); err != nil {
		return err
	}

	if wrote, err := writeSystemdEnvDropIn(); err != nil {
		p.printf("  warning: could not write systemd drop-in: %v\n", err)
	} else if wrote {
		p.printf("  wrote %s/env.conf (EnvironmentFile drop-in)\n", systemdDropInDir)
	}

	if err := runSysCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	p.println(st.ok("systemctl daemon-reload OK"))

	if err := runSysCmd("systemctl", "enable", "--now", "ezyshield-enforcer"); err != nil {
		return fmt.Errorf("starting ezyshield-enforcer: %w", err)
	}
	p.println(st.ok("ezyshield-enforcer: enabled and started"))

	if err := waitForSocket(enforcerSockPath, 10*time.Second); err != nil {
		p.println(st.warn(fmt.Sprintf("enforcer socket not ready after 10s: %v", err)))
	} else {
		p.println(st.ok("enforcer socket ready: " + enforcerSockPath))
	}

	if err := runSysCmd("systemctl", "enable", "--now", "ezyshield"); err != nil {
		return fmt.Errorf("starting ezyshield: %w", err)
	}
	p.println(st.ok("ezyshield: enabled and started"))
	p.println("  waiting 15s for first detections...")
	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	time.Sleep(15 * time.Second)

	renderInitSummary(p, st, state, sum, checkRecentDetections(), configDir)

	return p.err
}

// initSummary accumulates what the wizard configured, skipped, and wrote,
// for the final Summary section (issue #102). Purely presentational —
// nothing in here feeds back into wizard decisions.
type initSummary struct {
	configured []string // components that were set up
	skipped    []string // components that were not, with the reason why
	files      []string // paths written, with short annotations
}

// summarizeChoices distills the operator's answers into the configured /
// skipped lines shown by renderInitSummary. It only reads state; every
// value it prints is either wizard-generated or operator-typed (and was
// already echoed at its prompt) — no log-derived data flows through here.
func summarizeChoices(state *wizardState, sum *initSummary, yes bool) {
	// Collectors.
	if state.monitorSSH && state.sshUnit != "" {
		sum.configured = append(sum.configured,
			fmt.Sprintf("collector: journald (SSH unit %s)", state.sshUnit))
	} else if state.sshUnit != "" {
		sum.skipped = append(sum.skipped, "SSH monitoring — declined at prompt")
	}
	for _, wc := range state.webCollectors {
		switch wc.Kind {
		case "file":
			sum.configured = append(sum.configured,
				fmt.Sprintf("collector: %s (%s)", wc.Parser, wc.Path))
		case "docker":
			sum.configured = append(sum.configured,
				fmt.Sprintf("collector: %s (container %s)", wc.Parser, wc.Container))
		}
	}

	// Enforcers.
	if state.nftPath != "" {
		sum.configured = append(sum.configured, "enforcer: nftables ("+state.nftPath+")")
	} else {
		sum.skipped = append(sum.skipped,
			"nftables — not installed (dry-run and edge enforcement only)")
	}
	switch {
	case state.cdn == nil:
		// askQuestions always sets cdn; nil only in unit tests.
	case state.cdn.cfEnabled && len(state.cdn.cfAccounts) > 0:
		for _, acct := range state.cdn.cfAccounts {
			label := "cloudflare"
			if acct.cfg.Name != "" {
				label = "cloudflare/" + acct.cfg.Name
			}
			sum.configured = append(sum.configured,
				fmt.Sprintf("enforcer: %s (mode %s, action %s)",
					label, acct.cfg.Mode, acct.cfg.Action))
		}
	case state.cdn.cfAttempted:
		// The loud abort banner (issue #93) already printed the specific
		// reason; this line makes sure the failure also survives into the
		// summary instead of scrolling away with the banner.
		sum.skipped = append(sum.skipped,
			"cloudflare enforcer — setup did NOT complete (see the banner above)")
	case yes:
		sum.skipped = append(sum.skipped, "CDN detection — skipped (--yes mode)")
	case providerDetected(state.cdn.detected, "cloudflare"):
		sum.skipped = append(sum.skipped,
			"cloudflare enforcer — declined (CDN detected: bans will not reach real client IPs)")
	}

	// AI.
	if state.enableAI && state.aiProvider != "" {
		sum.configured = append(sum.configured,
			fmt.Sprintf("AI analysis: %s (model %s)", state.aiProvider, state.aiModel))
	} else {
		sum.skipped = append(sum.skipped, "AI analysis — disabled (rule engine only)")
	}

	// Allowlist.
	if len(state.adminIPs) > 0 {
		sum.configured = append(sum.configured,
			fmt.Sprintf("allowlist: %d admin IP(s)/CIDR(s)", len(state.adminIPs)))
	}
}

// renderInitSummary prints the final Summary section: what was configured,
// what was skipped and why, which files were written, the dry-run reminder,
// and numbered next steps. detections < 0 means the services step did not
// run (--config-dir mode). Presentation only (issue #102): the summary
// complements — never replaces — warnings printed earlier in the run, such
// as the Cloudflare abort banner (issue #93).
func renderInitSummary(p *wPrinter, st styler, state *wizardState, sum *initSummary,
	detections int, configDir string) {
	p.println("")
	p.println(st.header("Summary"))

	if len(sum.configured) > 0 {
		p.println("  Configured:")
		for _, line := range sum.configured {
			p.println("  " + st.ok(line))
		}
	}
	if len(sum.skipped) > 0 {
		p.println("  Skipped:")
		for _, line := range sum.skipped {
			p.println("  " + st.warn(line))
		}
	}
	if len(sum.files) > 0 {
		p.println("  Files written:")
		for _, f := range sum.files {
			p.printf("    %s\n", f)
		}
	}

	p.println("")
	p.printf("  Mode: %s\n", modeLabel(state.armed))
	switch {
	case detections > 0:
		p.printf("  Events: %d dry-ban(s) detected in the first 15s\n", detections)
	case detections == 0:
		p.println("  Events: none yet — check back in a few minutes")
	}

	policyPath := filepath.Join(configDir, "policy.yaml")
	p.println("")
	p.println("  Next steps:")
	if detections < 0 {
		// Config-only run: no services were installed or started.
		p.printf("    1. %s doctor        — verify the configuration\n", progName)
		p.printf("    2. %s run           — start in the foreground and observe\n", progName)
		p.printf("    3. %s watch         — see detections live\n", progName)
	} else {
		p.printf("    1. sudo %s doctor   — verify the configuration\n", progName)
		p.printf("    2. sudo %s status   — daemon and enforcer health\n", progName)
		p.printf("    3. sudo %s watch    — see detections live\n", progName)
	}
	if !state.armed {
		p.printf("    4. set armed: true in %s when confident (after 24h+ of clean dry-run)\n", policyPath)
	}
}

// askQuestions fills state from interactive prompts or uses defaults.
// sc is nil when yes=true; every prompt returns its default in that case.
// The ask/askBool closures are shared with the `config <kind> <name>`
// wizards (see newAskFuncs in configwizard.go). Prompts and section
// headers are written to out (the wizard's stdout).
func askQuestions(out io.Writer, sc *bufio.Scanner, state *wizardState, yes bool, st styler) {
	p := &wPrinter{w: out}
	ask, askBool := newAskFuncs(sc, out, yes)

	// Per-server collector confirmation (replaces the old single proxy prompt).
	p.println("")
	p.println(st.header("Collectors"))
	state.webCollectors = confirmWebServerCollectors(ask, askBool, state.webServers)

	// SSH monitoring
	if state.sshUnit != "" {
		state.monitorSSH = askBool(
			fmt.Sprintf("Monitor SSH via journald (unit: %s)?", state.sshUnit), true)
	}

	// Admin IPs for allowlist
	p.println("")
	p.println(st.header("Allowlist"))
	defaultAdmin := state.sshSourceIP
	if defaultAdmin == "" {
		// No SSH_CLIENT (sudo su -, console, automation): fall back to the
		// kernel-derived SSH peers — the same source the daemon's
		// anti-lockout uses under systemd (issue #175).
		if peers := decision.ProcSSHPeers(); len(peers) > 0 {
			defaultAdmin = peers[0].String()
			p.println(st.ok("detected your SSH client via /proc: " + defaultAdmin))
		}
	}
	if defaultAdmin == "" {
		defaultAdmin = state.publicIP
	}
	if rawAdmin := ask("Admin IP(s) to allowlist (space or comma separated)", defaultAdmin); rawAdmin != "" {
		state.adminIPs = validAdminEntries(p, st, splitIPs(rawAdmin))
	}
	if len(state.adminIPs) == 0 {
		// Strong recommendation (issue #175): admin_cidrs is the durable
		// anti-lockout protection; live-session detection alone only covers
		// connections that exist at decision time.
		p.println(st.warn("admin_cidrs will be EMPTY — strongly recommended to add your management"))
		p.println(st.warn("IPs later in policy.yaml; 'ezyshield arm' will flag this before arming."))
	}

	// CDN detection + Cloudflare subflow — runs BEFORE AI so the loud-skip
	// warning fires before the operator commits to any downstream config.
	// See init_cdn.go for the flow and issue #43 for the design.
	p.println("")
	p.println(st.header("Edge enforcers"))
	state.cdn = &cdnStep{}
	runCDNStep(
		context.Background(),
		p,
		closurePrompter{askFn: ask, askBoolFn: askBool},
		state.cdn,
		cdnDeps{Yes: yes},
	)

	// AI — model + key prompts shared with `config ai <provider>` via the
	// sub-flow in init_ai.go (issue #96): the logic lives only there.
	p.println("")
	p.println(st.header("AI analysis"))
	state.enableAI = askBool("Enable AI analysis?", false)
	if state.enableAI {
		state.aiProvider = ask("AI provider (anthropic/openai/ollama)", "anthropic")
		// The env var NAME is fixed per provider (issue #13 §1) — we NEVER
		// prompt the operator for it. Anything not in the table (typo) falls
		// through to no key at all; the wizard warns instead of guessing.
		if _, known := aiProviderKeyName[state.aiProvider]; !known {
			p.printf("    unknown provider %q — supported: anthropic, openai, ollama; leaving AI key unset\n",
				state.aiProvider)
		}
		// Key prompts (issue #22 two-option menu) are skipped when yes=true
		// (placeholder path, issue #13 §5).
		step := &aiStep{provider: state.aiProvider}
		runAIProviderSubflow(p,
			closurePrompter{askFn: ask, askBoolFn: askBool}, step, nil, yes)
		state.aiModel = step.model
		state.aiKeyEnvVar = step.keyEnvVar
		state.aiToken = step.token
	}

	// Dry-run vs armed
	p.println("")
	p.println(st.header("Policy"))
	state.armed = askBool("Start in armed mode? (no = dry-run, recommended for first run)", false)
}

// writeSystemdEnvDropIn emits /etc/systemd/system/ezyshield.service.d/env.conf
// so EnvironmentFile=-/etc/ezyshield/.env is active even on hosts running an
// older service file that predates this directive (issue #22). Idempotent: if
// the file already contains the exact content no write occurs.
func writeSystemdEnvDropIn() (wrote bool, err error) {
	if err := os.MkdirAll(systemdDropInDir, 0o750); err != nil {
		return false, fmt.Errorf("creating drop-in dir %s: %w", systemdDropInDir, err)
	}
	content := "[Service]\nEnvironmentFile=-" + defaultConfigDir + "/" + envFileName + "\n"
	dst := filepath.Join(systemdDropInDir, "env.conf")
	if existing, rerr := os.ReadFile(dst); rerr == nil && string(existing) == content { //nolint:gosec // path is a fixed admin-only constant
		return false, nil
	}
	if err := os.WriteFile(dst, []byte(content), 0o644); err != nil { //nolint:gosec // 0644 is standard for systemd units
		return false, fmt.Errorf("writing %s: %w", dst, err)
	}
	return true, nil
}

// ── Config file generation ───────────────────────────────────────────────────

// preflightExistingConfigFiles refuses the wizard when config.yaml or
// policy.yaml already exist in configDir, before any prompt or detection has
// run. When both files exist, the single returned error lists both paths so
// the operator can fix them in one shot rather than iteratively. Any stat
// error other than "not exist" (e.g. permission denied on /etc/ezyshield)
// short-circuits the same way — the wizard can't safely proceed if it can't
// even see whether it would clobber. Issue #5.
//
// The late-stage checks inside writeGeneratedConfig / writeGeneratedPolicy
// remain in place as defense-in-depth against a concurrent operator writing
// the same file mid-wizard; this preflight is purely a UX improvement.
func preflightExistingConfigFiles(configDir string) error {
	targets := []string{
		filepath.Join(configDir, "config.yaml"),
		filepath.Join(configDir, "policy.yaml"),
	}
	var existing []string
	for _, path := range targets {
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
			continue
		} else if !os.IsNotExist(err) {
			// A stat error we don't recognise (permission, I/O, etc.) means we
			// can't reason about whether the target is safe to write — fail
			// closed with the underlying error so the operator sees the real
			// cause. No secret can be reached through this path (configDir is
			// operator-supplied and echoed).
			return fmt.Errorf("checking %s: %w", path, err)
		}
	}
	switch len(existing) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%s already exists — delete it to regenerate", existing[0])
	default:
		return fmt.Errorf("%s already exist — delete them to regenerate", strings.Join(existing, ", "))
	}
}

// writeGeneratedConfig writes config.yaml using only valid Config struct fields.
// Validates via LoadConfigReader before writing to disk.
func writeGeneratedConfig(path string, state *wizardState) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists — delete it to regenerate", path)
	}

	var b strings.Builder
	b.WriteString("# EzyShield config — generated by 'ezyshield init'\n")
	b.WriteString("# Secrets must use 'env:VARNAME' references, never inline values.\n\n")
	fmt.Fprintf(&b, "data_dir: /var/lib/ezyshield\n")
	fmt.Fprintf(&b, "socket_path: %s\n", daemonSockPath)
	b.WriteString("log:\n  level: info\n")

	hasSSH := state.monitorSSH && state.sshUnit != ""
	if !hasSSH && len(state.webCollectors) == 0 {
		b.WriteString("collectors: []\n")
	} else {
		b.WriteString("collectors:\n")
		if hasSSH {
			fmt.Fprintf(&b, "  - kind: journald\n    unit: %s\n", state.sshUnit)
		}
		for _, wc := range state.webCollectors {
			switch wc.Kind {
			case "file":
				fmt.Fprintf(&b, "  - kind: file\n    path: %s\n    parser: %s\n", wc.Path, wc.Parser)
			case "docker":
				fmt.Fprintf(&b, "  - kind: docker\n    container: %s\n    parser: %s\n", wc.Container, wc.Parser)
			}
		}
	}

	hasCF := state.cdn != nil && state.cdn.cfEnabled && len(state.cdn.cfAccounts) > 0
	if state.nftPath != "" || hasCF {
		b.WriteString("enforce:\n")
		if state.nftPath != "" {
			// The empty mapping is the whole configuration (issue #268): its
			// presence switches local enforcement on, and table/set/socket
			// all have real, honored defaults. Emitting any of them here
			// would just pin today's defaults into every generated config —
			// reference/config.md documents how to customize when needed.
			b.WriteString("  nftables: {}\n")
		}
		if hasCF {
			emitCloudflareYAML(&b, state.cdn)
		}
	}

	if state.enableAI && state.aiProvider != "" {
		b.WriteString("ai:\n")
		fmt.Fprintf(&b, "  provider: %s\n", state.aiProvider)
		if state.aiModel != "" {
			fmt.Fprintf(&b, "  model: %s\n", state.aiModel)
		}
		if state.aiKeyEnvVar != "" {
			fmt.Fprintf(&b, "  api_key: env:%s\n", state.aiKeyEnvVar)
		}
		b.WriteString("  ambiguous_band: [30, 75]\n")
		b.WriteString("  token_budget_daily: 100000\n")
	}

	data := []byte(b.String())

	// validate before writing — catches any field mismatch immediately
	if _, err := config.LoadConfigReader(bytes.NewReader(data), "generated config"); err != nil {
		return fmt.Errorf("generated config.yaml failed validation: %w", err)
	}

	//nolint:gosec // 0640: group-readable; no secrets here (SecretRef env: references only)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := applyDaemonOwnership(path, 0o640); err != nil {
		return fmt.Errorf("set ownership on %s: %w", path, err)
	}
	return nil
}

// writeGeneratedPolicy writes policy.yaml using only valid Policy fields.
// Validates via LoadPolicyReader before writing to disk.
func writeGeneratedPolicy(path string, state *wizardState) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists — delete it to regenerate", path)
	}

	var b strings.Builder
	b.WriteString("# EzyShield policy — generated by 'ezyshield init'\n\n")
	fmt.Fprintf(&b, "armed: %v\n", state.armed)
	b.WriteString("ban_threshold: 70\n")
	b.WriteString("observe_threshold: 40\n")
	b.WriteString("strikes:\n")
	b.WriteString("  - ttl: 5m\n")
	b.WriteString("  - ttl: 1h\n")
	b.WriteString("  - ttl: 24h\n")
	b.WriteString("  - ttl: 168h\n")
	b.WriteString("  - ttl: 0\n")
	b.WriteString("max_bans_per_minute: 30\n")

	b.WriteString("allowlist:\n")
	for _, ip := range buildAllowlist(state) {
		fmt.Fprintf(&b, "  - %s\n", ip)
	}
	// Issue #210: only real, detected subnets are written above. Broader
	// internal ranges are opt-in — the commented example below (written
	// into policy.yaml itself, not just this source file) shows how, and
	// spells out the trade-off so a future editor doesn't uncomment it
	// without understanding the consequence.
	b.WriteString("# To allow a broader internal range (VPN, office LAN, a multi-host docker\n")
	b.WriteString("# overlay) deliberately, uncomment and edit the line below.\n")
	b.WriteString("# Trade-off: an allowlisted range can NEVER be banned (allowlist always wins\n")
	b.WriteString("# over rules, AI, and geo blocking) — the broader the range, the more of your\n")
	b.WriteString("# network permanently loses enforcement coverage.\n")
	b.WriteString("# 'ezyshield doctor' warns if any private allowlist entry is /16 or broader.\n")
	b.WriteString("#   - 10.0.0.0/8\n")

	if len(state.adminIPs) > 0 {
		b.WriteString("admin_cidrs:\n")
		for _, ip := range state.adminIPs {
			fmt.Fprintf(&b, "  - %s\n", normalizeToPrefix(ip))
		}
	} else {
		b.WriteString("admin_cidrs: []\n")
	}

	data := []byte(b.String())

	// validate before writing
	if _, err := config.LoadPolicyReader(bytes.NewReader(data), "generated policy"); err != nil {
		return fmt.Errorf("generated policy.yaml failed validation: %w", err)
	}

	//nolint:gosec // 0640: group-readable; no secrets in policy
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := applyDaemonOwnership(path, 0o640); err != nil {
		return fmt.Errorf("set ownership on %s: %w", path, err)
	}
	return nil
}

// writeOrKeepEnvFile writes /etc/ezyshield/.env with the operator-supplied
// token (issue #13 §3). Behavior matrix:
//
//	token != ""                       → overwrite with the real token
//	token == "", .env already good    → preserve (idempotent re-run, §5)
//	token == "", .env absent / stub   → write the placeholder
//
// "already good" means the file contains a line `<KEY>=<value>` where value is
// neither empty nor the literal placeholder. This lets an operator re-run
// `ezyshield init` without clobbering a working key.
//
// Returned wrote/kept booleans tell the caller which log line to print — the
// token itself never appears in that log path (issue #13 §6).
func writeOrKeepEnvFile(path, keyEnvVar, token string) (wrote, kept bool, err error) {
	if keyEnvVar == "" {
		// Nothing to write; caller shouldn't have called us. Defense.
		return false, false, nil
	}
	// Idempotency check (§5): if we have no new token AND the file already
	// contains a non-placeholder value for keyEnvVar, keep the existing file.
	if token == "" {
		if existing, ok := readEnvValue(path, keyEnvVar); ok &&
			existing != "" && existing != envAPIKeyPlaceholder {
			return false, true, nil
		}
	}
	value := token
	if value == "" {
		value = envAPIKeyPlaceholder
	}
	if err := writeEnvFileContent(path, keyEnvVar, value); err != nil {
		return false, false, err
	}
	return true, false, nil
}

// writeEnvFileContent writes exactly `<name>=<value>\n` (plus a short header
// that does NOT include the token or a fingerprint of it) to path with mode
// 0600 and root:ezyshield ownership. Extracted so tests can drive it directly.
func writeEnvFileContent(path, name, value string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# EzyShield environment — generated by 'ezyshield init'\n")
	fmt.Fprintf(&b, "# systemd loads this via EnvironmentFile= (see ezyshield.service).\n")
	// One shell-style KEY=VALUE line, no quoting, no export, trailing \n so
	// systemd parses it cleanly (issue #13 §3).
	fmt.Fprintf(&b, "%s=%s\n", name, value)

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := applyDaemonOwnership(path, 0o600); err != nil {
		return fmt.Errorf("set ownership on %s: %w", path, err)
	}
	return nil
}

// readEnvValue parses a shell env file (very simple: KEY=VALUE per line,
// ignoring '#' comments and blank lines) and returns the value for name.
// The 2nd return is false when the file is missing OR the key is absent.
// The value returned is NEVER logged by callers — it may be the real token
// (idempotency check).
func readEnvValue(path, name string) (string, bool) {
	f, err := os.Open(path) //nolint:gosec // path is admin-controlled; called only on the wizard's own writes
	if err != nil {
		return "", false
	}
	defer f.Close() //nolint:errcheck
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) == name {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// ── System installation helpers ──────────────────────────────────────────────

// addAdminToEzyshieldGroup adds the invoking sudo user (SUDO_USER) to the
// ezyshield group so they can use the control socket without sudo. When the
// wizard is run directly as root (no SUDO_USER) there is no admin account to
// add and the function is a no-op. Idempotent — usermod -aG is safe to repeat.
func addAdminToEzyshieldGroup(out io.Writer) error {
	admin := os.Getenv("SUDO_USER")
	if admin == "" || admin == "root" {
		return nil
	}
	if alreadyInGroup(admin, ownership.Group) {
		if _, err := fmt.Fprintf(out, "  user %s: already in %s group\n", admin, ownership.Group); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	if err := runSysCmd("usermod", "-aG", ownership.Group, admin); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "  user %s: added to %s group (log out + back in to take effect)\n", admin, ownership.Group); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// alreadyInGroup checks /etc/group via `id -nG <user>` for the group name.
// Falls back to false on any error so the caller will attempt usermod, which
// is idempotent and surfaces a real error if something is actually wrong.
func alreadyInGroup(username, group string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	//nolint:gosec // fixed binary, username sourced from SUDO_USER (set by sudo)
	out, err := exec.CommandContext(ctx, "id", "-nG", username).Output()
	if err != nil {
		return false
	}
	for _, g := range strings.Fields(string(out)) {
		if g == group {
			return true
		}
	}
	return false
}

func createEzyshieldUser(out io.Writer) error {
	if runCmdSilent("id", "ezyshield") == nil {
		if _, err := fmt.Fprintln(out, "  user ezyshield: already exists"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	if err := runSysCmd("useradd", "-r", "-s", "/usr/sbin/nologin", "-d", "/var/lib/ezyshield", "-m", "ezyshield"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "  user ezyshield: created"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	// best-effort: add to docker and systemd-journal groups for log access
	_ = runCmdSilent("usermod", "-aG", "docker", "ezyshield")
	_ = runCmdSilent("usermod", "-aG", "systemd-journal", "ezyshield")
	return nil
}

func installSystemdUnits(out io.Writer) error {
	for _, unit := range []string{"ezyshield.service", "ezyshield-enforcer.service"} {
		data, err := configs.FS.ReadFile("systemd/" + unit)
		if err != nil {
			return fmt.Errorf("reading embedded %s: %w", unit, err)
		}
		dst := filepath.Join(defaultSystemdDir, unit)
		if err := os.WriteFile(dst, data, 0o644); err != nil { //nolint:gosec // 0644 is standard for systemd units
			return fmt.Errorf("installing %s: %w", dst, err)
		}
		if _, err := fmt.Fprintf(out, "  installed %s\n", dst); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}

// waitForSocket polls for a unix socket to appear within timeout.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("socket %s not ready after %s", path, timeout)
}

// checkRecentDetections counts dry_ban events in the last 30s of journal output.
func checkRecentDetections() int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:gosec // fixed args, no user input
	out, err := exec.CommandContext(ctx, "journalctl", "-u", "ezyshield",
		"--since", "30 seconds ago", "--no-pager", "-q").Output()
	if err != nil {
		return 0
	}
	return strings.Count(string(out), "dry_ban")
}

// ── nftables install offer ───────────────────────────────────────────────────

// detectPkgManager returns the first available package manager binary path,
// checking apt-get, dnf, pacman, and zypper in that order.
func detectPkgManager() string {
	for _, pm := range []string{"apt-get", "dnf", "pacman", "zypper"} {
		if p, err := exec.LookPath(pm); err == nil {
			return p
		}
	}
	return ""
}

// installNFTPackage runs the appropriate non-interactive install command for
// the given package manager binary (full path or base name).
func installNFTPackage(pm string) error {
	base := filepath.Base(pm)
	var args []string
	switch base {
	case "apt-get":
		args = []string{"-y", "install", "nftables"}
	case "dnf":
		args = []string{"-y", "install", "nftables"}
	case "pacman":
		args = []string{"-S", "--noconfirm", "nftables"}
	case "zypper":
		args = []string{"--non-interactive", "install", "nftables"}
	default:
		return fmt.Errorf("unsupported package manager: %s", base)
	}
	return runSysCmd(pm, args...)
}

// offerInstallNFT prompts the user (or auto-accepts when yes=true) to install
// nftables. Returns the detected nft binary path after a successful install,
// or "" if the user declined or the install failed.
func offerInstallNFT(sc *bufio.Scanner, yes bool, out io.Writer) string {
	pm := detectPkgManager()
	if pm == "" {
		//nolint:errcheck // best-effort console output; write errors handled by caller's wPrinter
		fmt.Fprintln(out, "\n  ⚠  nftables not found and no supported package manager detected (apt-get/dnf/pacman/zypper).")
		//nolint:errcheck
		fmt.Fprintln(out, "     Install nftables manually, then re-run init.")
		return ""
	}

	doInstall := yes
	if !yes {
		//nolint:errcheck
		fmt.Fprint(out, "\n  ⚠  nftables not found.\n")
		//nolint:errcheck
		fmt.Fprint(out, "  EzyShield requires nftables for local IP blocking.\n")
		//nolint:errcheck
		fmt.Fprintf(out, "  Install now via %s? [Y/n]: ", filepath.Base(pm))
		if sc != nil && sc.Scan() {
			lower := strings.ToLower(strings.TrimSpace(sc.Text()))
			doInstall = lower == "" || lower == "y" || lower == "yes"
		} else {
			doInstall = true // EOF → default Y
		}
	}

	if !doInstall {
		return ""
	}

	//nolint:errcheck
	fmt.Fprintf(out, "  Installing nftables via %s...\n", filepath.Base(pm))
	if err := installNFTPackage(pm); err != nil {
		//nolint:errcheck
		fmt.Fprintf(out, "  ⚠  Install failed: %v\n", err)
		return ""
	}

	if err := runSysCmd("systemctl", "enable", "--now", "nftables"); err != nil {
		//nolint:errcheck
		fmt.Fprintf(out, "  ⚠  Could not enable nftables.service: %v\n", err)
	} else {
		//nolint:errcheck
		fmt.Fprintln(out, "  nftables.service: enabled and started")
	}

	return detectNFT()
}

// ── Environment detection ────────────────────────────────────────────────────

func detectNFT() string {
	if p, err := exec.LookPath("nft"); err == nil {
		return p
	}
	if _, err := os.Stat("/usr/sbin/nft"); err == nil {
		return "/usr/sbin/nft"
	}
	return ""
}

func detectDockerContainers() []dockerContainer {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:gosec // fixed args
	out, err := exec.CommandContext(ctx, "docker", "ps",
		"--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}").Output()
	if err != nil {
		return nil
	}
	var containers []dockerContainer
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		c := dockerContainer{name: parts[0]}
		if len(parts) > 1 {
			c.image = parts[1]
		}
		if len(parts) > 2 {
			c.ports = parts[2]
		}
		containers = append(containers, c)
	}
	return containers
}

// defaultDockerBridgeSubnet is Docker Engine's out-of-the-box default bridge
// subnet (the "docker0" bridge). Used ONLY as a fallback when network
// enumeration fails (issue #210) — never as a substitute for the actual
// host subnets, and never widened to the 172.16.0.0/12 supernet.
const defaultDockerBridgeSubnet = "172.17.0.0/16"

// dockerNetworkLister enumerates the docker bridge network subnets present
// on the host. It is a package-level var so tests can override it without a
// real docker daemon (see init_allowlist_test.go); production code always
// uses listDockerBridgeSubnets.
var dockerNetworkLister = listDockerBridgeSubnets

// dockerNetworkInspect mirrors the subset of `docker network inspect` JSON
// output this package needs. Docker's own output is treated as untrusted
// external input, same as any other subprocess result: it is decoded with
// encoding/json (never interpolated into a shell command or trusted as a
// pre-validated CIDR), and every subnet string is re-validated with
// netip.ParsePrefix before being accepted (§1 SECURITY-REVIEW: input
// handling).
type dockerNetworkInspect struct {
	Driver string `json:"Driver"`
	IPAM   struct {
		Config []struct {
			Subnet string `json:"Subnet"`
		} `json:"Config"`
	} `json:"IPAM"`
}

// listDockerBridgeSubnets asks the docker CLI for every network's inspect
// payload and returns the deduplicated subnets of bridge-driver networks
// only — the networks that place container IPs on a host-routed subnet and
// therefore need an enforcement exemption. host/none/overlay/macvlan
// networks are skipped: they either have no subnet of their own or aren't
// what the original 172.16.0.0/12 entry was meant to cover.
//
// Returns an error on any failure (docker not reachable, malformed output,
// timeout). Callers MUST fall back to defaultDockerBridgeSubnet in that
// case — never skip the allowlist entry silently, and never widen it.
func listDockerBridgeSubnets(ctx context.Context) ([]string, error) {
	//nolint:gosec // fixed args, no user input
	idsOut, err := exec.CommandContext(ctx, "docker", "network", "ls", "-q").Output()
	if err != nil {
		return nil, fmt.Errorf("docker network ls: %w", err)
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(idsOut)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			ids = append(ids, line)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}

	// ids come from docker's own output, not from a shell string — they are
	// passed as separate argv entries below (exec.Command never invokes a
	// shell), so there is no command-injection surface regardless of their
	// content. We still never trust them as anything other than opaque
	// tokens: they are neither parsed nor interpolated, only forwarded.
	args := append([]string{"network", "inspect"}, ids...)
	//nolint:gosec // args are argv entries (no shell), see comment above
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("docker network inspect: %w", err)
	}

	return parseDockerBridgeSubnets(out)
}

// parseDockerBridgeSubnets decodes the JSON payload from `docker network
// inspect` and returns the deduplicated subnets of bridge-driver networks
// only, in first-seen order. Split out from listDockerBridgeSubnets so the
// untrusted-input handling (§1 SECURITY-REVIEW) can be unit tested without a
// real docker daemon: malformed JSON, non-bridge drivers, and unparsable
// subnet strings are all exercised directly in init_allowlist_test.go.
func parseDockerBridgeSubnets(data []byte) ([]string, error) {
	var networks []dockerNetworkInspect
	if err := json.Unmarshal(data, &networks); err != nil {
		return nil, fmt.Errorf("parsing docker network inspect output: %w", err)
	}

	seen := make(map[string]bool)
	var subnets []string
	for _, n := range networks {
		if n.Driver != "bridge" {
			continue
		}
		for _, c := range n.IPAM.Config {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(c.Subnet))
			if err != nil {
				// Never trust docker's output blindly — skip anything that
				// doesn't parse as a CIDR rather than writing it verbatim
				// into policy.yaml.
				continue
			}
			cidr := prefix.String()
			if !seen[cidr] {
				seen[cidr] = true
				subnets = append(subnets, cidr)
			}
		}
	}
	return subnets, nil
}

// detectDockerBridgeSubnets enumerates the docker bridge subnets that
// actually exist on the host, falling back to the single default bridge
// subnet (never the /12 supernet) on any enumeration failure. The bool
// return reports whether the fallback was used, so the caller can surface a
// warning to the operator instead of silently narrowing coverage.
func detectDockerBridgeSubnets() (subnets []string, usedFallback bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := dockerNetworkLister(ctx)
	if err != nil {
		return []string{defaultDockerBridgeSubnet}, true
	}
	return got, false
}

// confirmWebServerCollectors prompts the operator for each detected web
// server and returns the collector list to write into config.yaml.
//
// Local entries surface a "Log path [default]:" follow-up so the operator can
// override the auto-discovered path. Docker entries are confirmed by a single
// yes/no — the collector targets the container, not a host file.
func confirmWebServerCollectors(
	ask func(question, def string) string,
	askBool func(question string, def bool) bool,
	servers []detectedWebServer,
) []webServerCollector {
	var out []webServerCollector
	for _, ws := range servers {
		var label string
		switch ws.Location {
		case "local":
			label = fmt.Sprintf("Configure collector for %s (local)?", ws.Kind)
		case "docker":
			label = fmt.Sprintf("Configure collector for %s (container: %s)?", ws.Kind, ws.Container)
		default:
			continue
		}
		if !askBool(label, true) {
			continue
		}
		switch ws.Location {
		case "local":
			path := ask("Log path", ws.LogPath)
			if path == "" {
				continue
			}
			out = append(out, webServerCollector{
				Kind:   "file",
				Path:   path,
				Parser: ws.Parser,
			})
		case "docker":
			out = append(out, webServerCollector{
				Kind:      "docker",
				Container: ws.Container,
				Parser:    ws.Parser,
			})
		}
	}
	return out
}

func detectSSHUnit() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, unit := range []string{"ssh", "sshd"} {
		//nolint:gosec // fixed args
		out, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			return unit
		}
	}
	return "ssh" // Debian/Ubuntu default
}

func fetchPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://ifconfig.me") //nolint:noctx // client-level timeout is sufficient
	if err != nil {
		return ""
	}
	defer resp.Body.Close() //nolint:errcheck
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	ip := strings.TrimSpace(string(buf[:n]))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func sshSourceIP() string {
	val := os.Getenv("SSH_CLIENT")
	if val == "" {
		return ""
	}
	parts := strings.Fields(val)
	if len(parts) == 0 || net.ParseIP(parts[0]) == nil {
		return ""
	}
	return parts[0]
}

// ── Policy helpers ───────────────────────────────────────────────────────────

// buildAllowlist returns loopback + real docker bridge subnets (if any) +
// server public IP.
//
// Issue #210: this intentionally does NOT add a blanket RFC1918 entry.
// Non-docker hosts get no docker-related entry at all; docker hosts get
// only the subnets detected in state.dockerAllowlist (populated during
// environment detection — see the "docker networks" block in
// runInitWizard and detectDockerBridgeSubnets below). Allowlisted ranges
// can never be banned (allowlist always wins, hard rule #1), so this stays
// as narrow as possible by default — see the commented example
// writeGeneratedPolicy appends for how an operator opts into something
// broader.
func buildAllowlist(state *wizardState) []string {
	list := []string{
		"127.0.0.1/32",
		"::1/128",
	}
	list = append(list, state.dockerAllowlist...)
	if state.publicIP != "" {
		list = append(list, state.publicIP+"/32")
	}
	return list
}

// normalizeToPrefix converts a bare IP into /32 (IPv4) or /128 (IPv6).
// Inputs already containing "/" are returned unchanged.
func normalizeToPrefix(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if parsed.To4() != nil {
		return ip + "/32"
	}
	return ip + "/128"
}

// splitIPs splits a space- or comma-separated string of IPs/CIDRs.
// validAdminEntries keeps only entries that parse as an IP or CIDR
// (netip validation, issue #175); invalid ones are reported and dropped so
// a typo never lands in policy.yaml as a dead allowlist entry.
func validAdminEntries(p *wPrinter, st styler, entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if _, err := netip.ParseAddr(e); err == nil {
			out = append(out, e)
			continue
		}
		if _, err := netip.ParsePrefix(e); err == nil {
			out = append(out, e)
			continue
		}
		p.println(st.warn("ignoring invalid admin IP/CIDR: " + e))
	}
	return out
}

func splitIPs(s string) []string {
	s = strings.ReplaceAll(s, ",", " ")
	fields := strings.Fields(s)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ── Exec helpers ─────────────────────────────────────────────────────────────

func runSysCmd(name string, args ...string) error {
	//nolint:gosec // caller controls name+args; no user data reaches here
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runCmdSilent(name string, args ...string) error {
	//nolint:gosec // caller controls name+args; no user data reaches here
	return exec.CommandContext(context.Background(), name, args...).Run()
}

func modeLabel(armed bool) string {
	if armed {
		return "ARMED (live enforcement)"
	}
	return "DRY-RUN (logging only, nothing blocked)"
}

// hasWordPressContainers reports whether any running container looks like WordPress.
func hasWordPressContainers(containers []dockerContainer) bool {
	for _, c := range containers {
		lName := strings.ToLower(c.name)
		lImage := strings.ToLower(c.image)
		if strings.Contains(lName, "wordpress") || strings.Contains(lName, "wp-") ||
			strings.Contains(lImage, "wordpress") {
			return true
		}
	}
	return false
}

// ensureRulesDir creates the rules.d drop-in directory (issue #136) so every
// install — WordPress or not — has a discoverable customization surface.
// Drop-ins placed there merge over the embedded base rules by name and
// survive binary updates. Idempotent.
func ensureRulesDir(dir string) error {
	//nolint:gosec // 0750: matches the config dir; rules contain no secrets
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := applyDaemonOwnership(dir, 0o750); err != nil {
		return fmt.Errorf("set ownership on %s: %w", dir, err)
	}
	return nil
}

// writeWordPressDropin writes a fully-commented tuning template to path
// (issue #136). The WordPress detection rules are part of the embedded base
// and are already active — this file materializes NOTHING (the pre-#136 flow
// copied the whole embedded ruleset to disk and pointed rules_path at it,
// silently freezing the install out of upstream rule tuning). Uncommenting
// an entry here overrides just that rule, and everything else keeps riding
// binary updates.
//
// Returns wrote=false when the file already exists — a re-run must never
// clobber operator edits.
func writeWordPressDropin(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("checking %s: %w", path, err)
	}
	const template = `# EzyShield rules.d drop-in — generated by 'ezyshield init' (WordPress detected)
#
# The WordPress detection rules (wp-login, xmlrpc, .env probing) are BUILT IN
# and already active — you do not need this file for detection to work.
#
# To tune a rule, uncomment it below and adjust; the entry overrides the
# built-in rule with the same name. Everything you do NOT override keeps
# receiving upstream tuning with every EzyShield update.
#
# After editing: sudo systemctl restart ezyshield
# (an invalid file stops the daemon from starting — it fails closed)
#
# Current built-in values shown as of the version that generated this file.
#
# rules:
#   - name: http_wp_probe
#     description: "WordPress login probe"
#     kinds: [http_request]
#     field: path
#     contains: wp-login
#     window: 60s
#     threshold: 3
#     score: 80
#     category: scanner
#
#   - name: http_xmlrpc_abuse
#     description: "XML-RPC brute force (pingback/auth abuse)"
#     kinds: [http_request]
#     field: path
#     contains: xmlrpc.php
#     window: 60s
#     threshold: 5
#     score: 80
#     category: bruteforce
`
	//nolint:gosec // 0640: group-readable; rules contain no secrets
	if err := os.WriteFile(path, []byte(template), 0o640); err != nil {
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := applyDaemonOwnership(path, 0o640); err != nil {
		return false, fmt.Errorf("set ownership on %s: %w", path, err)
	}
	return true, nil
}
