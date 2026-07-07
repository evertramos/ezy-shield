package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/configs"
	"github.com/evertramos/ezy-shield/internal/config"
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
)

// aiProviderKeyName maps the supported AI provider names to the fixed env var
// that will hold their API key. Ollama runs locally and has no key. This
// table is the single source of truth — the wizard never asks the operator
// for the env var NAME any more (issue #13 §1).
var aiProviderKeyName = map[string]string{
	"anthropic": "ANTHROPIC_API_KEY",
	"openai":    "OPENAI_API_KEY",
	"ollama":    "",
}

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
	sshUnit       string
	publicIP      string
	sshSourceIP   string

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
	// returns so downstream writers can rely on nil checks on cdn.cfCfg
	// alone. Its String() masks the CF token.
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

	p.println("")
	p.println("EzyShield setup wizard")
	p.println("======================")
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

	// ── 1. Detect environment ─────────────────────────────────────────────
	p.println("\n[1/5] Detecting environment...")

	state := &wizardState{}

	state.osArch = runtime.GOOS + "/" + runtime.GOARCH
	p.printf("  OS/arch:      %s\n", state.osArch)

	state.nftPath = detectNFT()
	if state.nftPath != "" {
		p.printf("  nftables:     %s\n", state.nftPath)
	} else {
		p.println("  nftables:     not found")
		if !skipSystem {
			if p.err != nil {
				return fmt.Errorf("writing output: %w", p.err)
			}
			state.nftPath = offerInstallNFT(sc, yes, p.w)
			if state.nftPath != "" {
				p.printf("  nftables:     %s (installed)\n", state.nftPath)
			} else {
				p.println("  nftables:     skipped — only dry-run and edge enforcement will work")
			}
		}
	}

	state.allContainers = detectDockerContainers()
	state.hasDocker = len(state.allContainers) > 0
	if state.hasDocker {
		p.printf("  docker:       %d container(s) running\n", len(state.allContainers))
	} else {
		p.println("  docker:       not running / no containers")
	}

	state.hasWordPress = hasWordPressContainers(state.allContainers)
	if state.hasWordPress {
		state.wpRulesPath = filepath.Join(configDir, "rules.yaml")
		p.printf("  WordPress detected — will write custom rules: %s\n", state.wpRulesPath)
	}

	p.println("\n  Detecting web servers...")
	state.webServers = detectWebServers(state.allContainers)
	renderWebServerSummary(p, state.webServers)

	state.sshUnit = detectSSHUnit()
	p.printf("  SSH unit:     %s\n", state.sshUnit)

	state.publicIP = fetchPublicIP()
	if state.publicIP != "" {
		p.printf("  public IP:    %s\n", state.publicIP)
	} else {
		p.println("  public IP:    unknown (ifconfig.me unreachable)")
	}

	state.sshSourceIP = sshSourceIP()
	if state.sshSourceIP != "" {
		p.printf("  SSH source:   %s\n", state.sshSourceIP)
	}

	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	// ── 2. Ask questions ──────────────────────────────────────────────────
	p.println("\n[2/5] Configuration")
	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	askQuestions(sc, state, yes)

	// ── 3. Write config files ─────────────────────────────────────────────
	p.println("\n[3/5] Writing configuration files...")
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
	p.printf("  wrote %s\n", configPath)

	if err := writeGeneratedPolicy(policyPath, state); err != nil {
		return err
	}
	p.printf("  wrote %s\n", policyPath)

	// AI env file: written whenever the provider expects a key (anthropic /
	// openai) — even if the operator skipped the paste prompt, in which case
	// we write the placeholder and print an instruction (issue #13 §5). We
	// do NOT emit the token or a fingerprint of it here.
	if state.enableAI && state.aiKeyEnvVar != "" {
		wrote, kept, err := writeOrKeepEnvFile(envPath, state.aiKeyEnvVar, state.aiToken)
		if err != nil {
			return err
		}
		switch {
		case kept:
			p.printf("  kept %s (existing token preserved)\n", envPath)
		case wrote && state.aiToken == "":
			p.printf("  wrote %s (chmod 600, placeholder — edit and restart the daemon)\n", envPath)
			p.printf("  AI API key not set. Edit %s to add it, then restart the daemon.\n", envPath)
		case wrote:
			p.printf("  wrote %s (chmod 600)\n", envPath)
		}
	}

	// Cloudflare token: written to the same .env file, one line per token.
	// Merge semantics preserve any AI KEY= line written above (issue #43).
	// The token itself is NEVER logged — only "wrote" / "kept".
	if state.cdn != nil && state.cdn.cfEnabled && state.cdn.cfToken != "" && state.cdn.cfTokenEnvVar != "" {
		wrote, kept, err := writeCloudflareEnvFile(configDir, state.cdn.cfTokenEnvVar, state.cdn.cfToken)
		if err != nil {
			return err
		}
		switch {
		case kept:
			p.printf("  kept %s (existing Cloudflare token preserved)\n", envPath)
		case wrote:
			p.printf("  wrote %s (chmod 600, Cloudflare token merged)\n", envPath)
		}
	}

	if state.hasWordPress {
		if err := writeWordPressRules(state.wpRulesPath); err != nil {
			return err
		}
		p.printf("  wrote %s\n", state.wpRulesPath)
	}

	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	if skipSystem {
		p.println("\nConfig files written. Skipping systemd/service steps (non-default --config-dir).")
		return p.err
	}

	// ── 4. Install systemd units ──────────────────────────────────────────
	p.println("\n[4/5] Installing systemd units...")
	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	if err := installSystemdUnits(p.w); err != nil {
		return err
	}

	if err := runSysCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	p.println("  systemctl daemon-reload OK")

	// ── 5. Start services and verify ──────────────────────────────────────
	p.println("\n[5/5] Starting services...")
	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	if err := runSysCmd("systemctl", "enable", "--now", "ezyshield-enforcer"); err != nil {
		return fmt.Errorf("starting ezyshield-enforcer: %w", err)
	}
	p.println("  ezyshield-enforcer: enabled and started")

	if err := waitForSocket(enforcerSockPath, 10*time.Second); err != nil {
		p.printf("  warning: enforcer socket not ready after 10s: %v\n", err)
	} else {
		p.printf("  enforcer socket ready: %s\n", enforcerSockPath)
	}

	if err := runSysCmd("systemctl", "enable", "--now", "ezyshield"); err != nil {
		return fmt.Errorf("starting ezyshield: %w", err)
	}
	p.println("  ezyshield: enabled and started")
	p.println("  waiting 15s for first detections...")
	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	time.Sleep(15 * time.Second)

	detections := checkRecentDetections()

	p.println("")
	p.println("────────────────────────────────────────")
	p.println("Setup complete!")
	p.println("────────────────────────────────────────")
	p.printf("  Config:   %s\n", configPath)
	p.printf("  Policy:   %s  (armed=%v)\n", policyPath, state.armed)
	p.printf("  Mode:     %s\n", modeLabel(state.armed))
	if detections > 0 {
		p.printf("  Events:   %d dry-ban(s) detected in first 15s\n", detections)
	} else {
		p.println("  Events:   none yet — check back in a few minutes")
	}
	p.println("")
	p.println("Next steps:")
	p.println("  sudo ezyshield status        — live view of detections")
	p.println("  sudo ezyshield doctor        — verify configuration")
	if !state.armed {
		p.println("  sudo ezyshield arm           — switch from dry-run to armed (after 24h+ validation)")
	}

	return p.err
}

// askQuestions fills state from interactive prompts or uses defaults.
// sc is nil when yes=true; every prompt returns its default in that case.
func askQuestions(sc *bufio.Scanner, state *wizardState, yes bool) {
	ask := func(question, def string) string {
		if yes {
			return def
		}
		if def != "" {
			fmt.Printf("  %s [%s]: ", question, def)
		} else {
			fmt.Printf("  %s: ", question)
		}
		if sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				return line
			}
		}
		return def
	}

	askBool := func(question string, def bool) bool {
		if yes {
			return def
		}
		choices := "y/N"
		if def {
			choices = "Y/n"
		}
		fmt.Printf("  %s [%s]: ", question, choices)
		if sc.Scan() {
			lower := strings.ToLower(strings.TrimSpace(sc.Text()))
			if lower != "" {
				return lower == "y" || lower == "yes"
			}
		}
		return def
	}

	// Per-server collector confirmation (replaces the old single proxy prompt).
	state.webCollectors = confirmWebServerCollectors(ask, askBool, state.webServers)

	// SSH monitoring
	if state.sshUnit != "" {
		state.monitorSSH = askBool(
			fmt.Sprintf("Monitor SSH via journald (unit: %s)?", state.sshUnit), true)
	}

	// Admin IPs for allowlist
	defaultAdmin := state.sshSourceIP
	if defaultAdmin == "" {
		defaultAdmin = state.publicIP
	}
	if rawAdmin := ask("Admin IP(s) to allowlist (space or comma separated)", defaultAdmin); rawAdmin != "" {
		state.adminIPs = splitIPs(rawAdmin)
	}

	// CDN detection + Cloudflare subflow — runs BEFORE AI so the loud-skip
	// warning fires before the operator commits to any downstream config.
	// See init_cdn.go for the flow and issue #43 for the design.
	state.cdn = &cdnStep{}
	runCDNStep(
		context.Background(),
		&wPrinter{w: os.Stdout},
		closurePrompter{askFn: ask, askBoolFn: askBool},
		state.cdn,
		cdnDeps{Yes: yes},
	)

	// AI
	state.enableAI = askBool("Enable AI analysis?", false)
	if state.enableAI {
		state.aiProvider = ask("AI provider (anthropic/openai/ollama)", "anthropic")
		// The env var NAME is fixed per provider (issue #13 §1) — we NEVER
		// prompt the operator for it. Anything not in the table (typo) falls
		// through to no key at all; the wizard warns instead of guessing.
		keyName, known := aiProviderKeyName[state.aiProvider]
		if !known {
			fmt.Printf("    unknown provider %q — supported: anthropic, openai, ollama; leaving AI key unset\n",
				state.aiProvider)
		}
		state.aiKeyEnvVar = keyName
		switch state.aiProvider {
		case "anthropic":
			state.aiModel = ask("Model", "claude-haiku-4-5-20251001")
		case "openai":
			state.aiModel = ask("Model", "gpt-4o-mini")
		case "ollama":
			state.aiModel = ask("Model", "llama3")
		}
		// Prompt for the token itself only when the provider actually uses
		// one (i.e. keyName is non-empty). Reading is masked and comes from
		// /dev/tty — never from the pipe stdin bufio.Scanner (issue #13 §2).
		// Non-TTY stdin, --yes, or a blank paste all fall through to the
		// placeholder path (§5). See readMaskedTokenFromTTY.
		if keyName != "" && !yes {
			tok, err := tokenReader(
				fmt.Sprintf("  Paste your %s API token (input hidden, ENTER to skip): ", state.aiProvider))
			switch {
			case err != nil:
				// Cannot read from /dev/tty (non-interactive, no tty) — fall
				// through silently to the placeholder path. We DO NOT print
				// err.Error() here because a broken tty error still shouldn't
				// look scary; the writeEnvFile path will print the placeholder
				// instructions in a moment.
				state.aiToken = ""
			default:
				state.aiToken = tok
			}
		}
	}

	// Dry-run vs armed
	state.armed = askBool("Start in armed mode? (no = dry-run, recommended for first run)", false)
}

// ── Config file generation ───────────────────────────────────────────────────

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
	if state.wpRulesPath != "" {
		fmt.Fprintf(&b, "rules_path: %s\n", state.wpRulesPath)
	}
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

	hasCF := state.cdn != nil && state.cdn.cfEnabled && state.cdn.cfCfg != nil
	if state.nftPath != "" || hasCF {
		b.WriteString("enforce:\n")
		if state.nftPath != "" {
			b.WriteString("  nftables:\n")
			fmt.Fprintf(&b, "    socket: %s\n", enforcerSockPath)
			b.WriteString("    table: inet ezyshield\n")
			b.WriteString("    set: blocked\n")
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

// buildAllowlist returns loopback + docker bridge range + server public IP.
func buildAllowlist(state *wizardState) []string {
	list := []string{
		"127.0.0.1/32",
		"::1/128",
		"172.16.0.0/12",
	}
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

// writeWordPressRules writes the embedded rules.yaml to path so operators can
// customize WordPress-specific detection (xmlrpc, wp-login, .env probing).
// The on-disk file is identical to the embedded defaults; rules_path in
// config.yaml activates it and allows site-specific edits without recompiling.
func writeWordPressRules(path string) error {
	data, err := configs.FS.ReadFile("rules.yaml")
	if err != nil {
		return fmt.Errorf("reading embedded rules.yaml: %w", err)
	}
	header := "# EzyShield rules — generated by 'ezyshield init' (WordPress mode)\n" +
		"# WordPress containers detected; this file enables xmlrpc, wp-login, and\n" +
		"# .env probing rules. Edit to add or tune rules without recompiling.\n\n"
	content := append([]byte(header), data...)
	//nolint:gosec // 0640: group-readable; rules contain no secrets
	if err := os.WriteFile(path, content, 0o640); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := applyDaemonOwnership(path, 0o640); err != nil {
		return fmt.Errorf("set ownership on %s: %w", path, err)
	}
	return nil
}
