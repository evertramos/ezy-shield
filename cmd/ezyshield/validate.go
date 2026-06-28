package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/config"
)

// Exit codes for the validate command (documented in --help).
const (
	validateExitOK       = 0
	validateExitError    = 1
	validateExitNotFound = 2
)

// Output markers.
const (
	markPass = "  ✓"
	markWarn = "  ⚠"
	markFail = "  ✗"
)

func newValidateCmd() *cobra.Command {
	var (
		configPath = defaultConfigDir + "/config.yaml"
		policyPath = defaultConfigDir + "/policy.yaml"
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate config.yaml and policy.yaml without starting the daemon",
		Long: `Validate the configuration files for correctness.

Reads config.yaml and policy.yaml, runs the strict loaders, and reports
errors and warnings. Does NOT start the daemon, open sockets, or touch
any state.

Exit codes:
  0  valid (may have warnings)
  1  errors found
  2  file not found / unreadable`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			code := runValidate(cmd.OutOrStdout(), configPath, policyPath)
			if code != validateExitOK {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", configPath, "path to config.yaml")
	cmd.Flags().StringVar(&policyPath, "policy", policyPath, "path to policy.yaml")
	return cmd
}

// runValidate validates configPath and policyPath, writing findings to w
// and returning the resulting exit code (0/1/2). It does not call os.Exit
// so it can be exercised from tests.
func runValidate(w io.Writer, configPath, policyPath string) int {
	var errs, warns int
	var notFound bool

	writef(w, "%s:\n", configPath)
	cfg, missing := checkConfigFile(w, configPath, &errs, &warns)
	if missing {
		notFound = true
	}

	writeln(w, "")
	writef(w, "%s:\n", policyPath)
	pol, missing := checkPolicyFile(w, policyPath, &errs, &warns)
	if missing {
		notFound = true
	}

	if cfg != nil && pol != nil {
		writeln(w, "")
		writeln(w, "cross-validation:")
		checkCross(w, cfg, pol, &errs, &warns)
	}

	writef(w, "\nResult: %d error(s), %d warning(s)\n", errs, warns)

	switch {
	case notFound:
		return validateExitNotFound
	case errs > 0:
		return validateExitError
	default:
		return validateExitOK
	}
}

// checkConfigFile runs all config checks. Returns (cfg, missing); cfg is nil
// when load failed and missing is true only when the file is absent/unreadable.
func checkConfigFile(w io.Writer, path string, errs, warns *int) (*config.Config, bool) {
	switch presence := statRegularFile(path); presence {
	case fileMissing:
		failLine(w, "file not found: "+path)
		*errs++
		return nil, true
	case fileUnreadable:
		failLine(w, "file not readable: "+path)
		*errs++
		return nil, true
	}

	cfg, err := config.LoadConfig(path)
	if err != nil {
		// The loader prefixes "parsing <name>" (YAML/strict decode) or
		// "validating <name>" (field constraint). Branch on the prefix so we
		// can report YAML syntax as PASS when only validation failed.
		if isParseError(err) {
			failLine(w, "YAML syntax: "+err.Error())
		} else {
			passLine(w, "YAML syntax")
			failLine(w, err.Error())
		}
		*errs++
		return nil, false
	}

	passLine(w, "YAML syntax")

	// Required fields not enforced by the loader.
	requiredOK := true
	if strings.TrimSpace(cfg.DataDir) == "" {
		failLine(w, "data_dir is required")
		*errs++
		requiredOK = false
	}
	if len(cfg.Collectors) == 0 {
		failLine(w, "at least one collector is required")
		*errs++
		requiredOK = false
	}
	if requiredOK {
		passLine(w, "Required fields")
	}

	writef(w, "%s Collectors (%d configured)\n", markPass, len(cfg.Collectors))

	// File-path warnings for file-kind collectors.
	for i, c := range cfg.Collectors {
		if c.Kind == "file" && c.Path != "" {
			if _, err := os.Stat(c.Path); err != nil {
				warnLine(w, fmt.Sprintf("collectors[%d].path %s not readable: %v",
					i, c.Path, err))
				*warns++
			}
		}
	}

	// Env var warnings — secret name only, never the resolved value.
	for _, ref := range collectSecretRefs(cfg) {
		name := envVarName(ref.value)
		if name == "" {
			continue
		}
		if _, ok := os.LookupEnv(name); !ok {
			warnLine(w, fmt.Sprintf("env var %s (referenced by %s) not set in current environment",
				name, ref.field))
			*warns++
		}
	}

	return cfg, false
}

// checkPolicyFile runs all policy checks. Returns (policy, missing).
func checkPolicyFile(w io.Writer, path string, errs, warns *int) (*config.Policy, bool) {
	switch presence := statRegularFile(path); presence {
	case fileMissing:
		failLine(w, "file not found: "+path)
		*errs++
		return nil, true
	case fileUnreadable:
		failLine(w, "file not readable: "+path)
		*errs++
		return nil, true
	}

	pol, err := config.LoadPolicy(path)
	if err != nil {
		if isParseError(err) {
			failLine(w, "YAML syntax: "+err.Error())
		} else {
			passLine(w, "YAML syntax")
			failLine(w, err.Error())
		}
		*errs++
		return nil, false
	}

	passLine(w, "YAML syntax")

	if err := checkStrikesMonotonic(pol); err != nil {
		failLine(w, "Strike table: "+err.Error())
		*errs++
	} else {
		writef(w, "%s Strike table (%d entries)\n", markPass, len(pol.Strikes))
	}

	// Allowlist validity is already enforced by LoadPolicy; surface as PASS.
	writef(w, "%s Allowlist CIDRs (%d entries)\n", markPass, len(pol.Allowlist))

	return pol, false
}

// checkCross runs the small set of cross-section sanity checks listed in #84.
// Most loader-level invariants are already enforced; this section surfaces
// reachability so an operator sees which integrations are wired up.
func checkCross(w io.Writer, cfg *config.Config, _ *config.Policy, errs, warns *int) {
	any := false
	if cfg.Enforce != nil && cfg.Enforce.Cloudflare != nil {
		passLine(w, "Cloudflare api_token referenced via env:")
		any = true
	}
	if cfg.Notify != nil && cfg.Notify.Telegram != nil {
		passLine(w, "Telegram bot_token + chat_ids present")
		any = true
	}
	if !any {
		passLine(w, "no integrations to cross-validate")
	}
	// Cross-check is informational only here — errs/warns are passed so future
	// checks can extend without re-threading.
	_ = errs
	_ = warns
}

// checkStrikesMonotonic verifies non-zero TTLs are strictly increasing and
// that the permanent entry (ttl: 0) only appears as the final step.
func checkStrikesMonotonic(p *config.Policy) error {
	var prev time.Duration
	last := len(p.Strikes) - 1
	for i, s := range p.Strikes {
		cur := s.TTL.AsDuration()
		if cur == 0 {
			if i != last {
				return fmt.Errorf("strikes[%d]: permanent entry (ttl: 0) must be last", i)
			}
			continue
		}
		if cur < 0 {
			return fmt.Errorf("strikes[%d]: negative TTL %s", i, cur)
		}
		if i > 0 && cur <= prev {
			return fmt.Errorf("strikes[%d]: TTL %s must be greater than previous %s", i, cur, prev)
		}
		prev = cur
	}
	return nil
}

// secretFieldRef captures a config field that holds an env: reference and its
// dotted name (e.g. "ai.api_key") for human-readable reporting.
type secretFieldRef struct {
	field string
	value config.SecretRef
}

func collectSecretRefs(cfg *config.Config) []secretFieldRef {
	var refs []secretFieldRef
	add := func(field string, val config.SecretRef) {
		if val.IsSet() {
			refs = append(refs, secretFieldRef{field: field, value: val})
		}
	}
	if cfg.AI != nil {
		add("ai.api_key", cfg.AI.APIKey)
		for i, p := range cfg.AI.Providers {
			add(fmt.Sprintf("ai.providers[%d].api_key", i), p.APIKey)
		}
	}
	if cfg.Enforce != nil && cfg.Enforce.Cloudflare != nil {
		add("enforce.cloudflare.api_token", cfg.Enforce.Cloudflare.APIToken)
	}
	if cfg.Notify != nil {
		if t := cfg.Notify.Telegram; t != nil {
			add("notify.telegram.bot_token", t.BotToken)
		}
		if e := cfg.Notify.Email; e != nil {
			add("notify.email.password", e.Password)
		}
		if s := cfg.Notify.Slack; s != nil {
			add("notify.slack.webhook_url", s.WebhookURL)
		}
		if d := cfg.Notify.Discord; d != nil {
			add("notify.discord.webhook_url", d.WebhookURL)
		}
		if wh := cfg.Notify.Webhook; wh != nil {
			add("notify.webhook.url", wh.URL)
		}
	}
	if cfg.Enrich != nil {
		add("enrich.license_key", cfg.Enrich.LicenseKey)
	}
	return refs
}

// envVarName extracts VARNAME from "env:VARNAME"; returns "" if the ref isn't
// the env: form (loader already rejects inline secrets, so this is defensive).
func envVarName(ref config.SecretRef) string {
	s := string(ref)
	const prefix = "env:"
	if !strings.HasPrefix(s, prefix) {
		return ""
	}
	return strings.TrimPrefix(s, prefix)
}

// filePresence classifies the result of stat for the validate flow.
type filePresence int

const (
	fileOK filePresence = iota
	fileMissing
	fileUnreadable
)

func statRegularFile(path string) filePresence {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileMissing
	}
	if err != nil {
		return fileUnreadable
	}
	if !info.Mode().IsRegular() {
		return fileUnreadable
	}
	return fileOK
}

// isParseError reports whether err originated in the strict YAML decode
// (vs. semantic Validate()), based on the prefix the loader applies.
func isParseError(err error) bool {
	return strings.HasPrefix(err.Error(), "parsing ")
}

func passLine(w io.Writer, msg string) {
	writeln(w, markPass+" "+msg)
}

func warnLine(w io.Writer, msg string) {
	writeln(w, markWarn+" WARN: "+msg)
}

func failLine(w io.Writer, msg string) {
	writeln(w, markFail+" ERROR: "+msg)
}

// writef writes a formatted line to w; the validate command targets stdout or
// an in-memory test buffer, so the Fprintf error is silently swallowed.
func writef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// writeln writes a line to w with the same rationale as writef.
func writeln(w io.Writer, s string) {
	_, _ = fmt.Fprintln(w, s)
}
