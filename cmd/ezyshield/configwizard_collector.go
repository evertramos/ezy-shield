package main

// Post-install collector wizards for `config collector <name>` (issue #103).
// Web-server names (nginx/apache/traefik/caddy) reuse the exact per-server
// prompt sub-flow the init wizard runs (confirmWebServerCollectors in
// init.go) plus the detection table in init_webdetect.go; the sshd name
// mirrors init's journald question. Collectors carry no secrets — every
// field lives in config.yaml, so there is no postSave/.env step here.

import (
	"context"
	"fmt"
	"strings"

	"github.com/evertramos/ezy-shield/internal/config"
)

// wizardCollectorSSH configures the journald SSH collector: confirm (same
// wording as init), then let the operator override the unit. Declining the
// confirm offers to remove an existing SSH entry — that is how a source is
// disabled, since the schema has no enabled flag.
func wizardCollectorSSH(_ context.Context, p *wPrinter, pr prompter, _ cdnDeps,
	cfg *config.Config, _ string) ([]string, func() error, error) {
	unit := detectSSHUnit()
	if !pr.askBool(fmt.Sprintf("Monitor SSH via journald (unit: %s)?", unit), true) {
		return removeCollectorIfConfirmed(p, pr, cfg, isSSHCollector, "sshd")
	}
	unit = pr.ask("systemd unit to follow", unit)
	entry := config.CollectorCfg{Kind: "journald", Unit: unit}
	verb := upsertCollector(cfg, isSSHCollector, entry)
	return []string{fmt.Sprintf("collectors — %s entry (%s)", verb, describeCollector(entry))}, nil, nil
}

// wizardCollectorWeb builds the wizard for one web-server collector name.
// The prompt logic for confirm + log path is shared with init via
// confirmWebServerCollectors; this wrapper only adds the file/docker source
// question (init infers it from detection, which a named post-install
// reconfigure cannot rely on) and the merge into the loaded Config.
func wizardCollectorWeb(kind string) componentWizard {
	return func(_ context.Context, p *wPrinter, pr prompter, _ cdnDeps,
		cfg *config.Config, _ string) ([]string, func() error, error) {
		spec, ok := specForKind(kind)
		if !ok {
			// Registry names come from webServerSpecs; reaching this is a bug.
			return nil, nil, fmt.Errorf("no web server spec for %q", kind)
		}

		source := strings.ToLower(strings.TrimSpace(
			pr.ask("Log source (file = host log file, docker = container stdout)", "file")))
		var ws detectedWebServer
		switch source {
		case "file":
			logPath, _ := resolveLocalLogPath(spec)
			ws = detectedWebServer{Kind: kind, Location: "local", Parser: spec.parser, LogPath: logPath}
		case "docker":
			container := pr.ask("Container name", "")
			if container == "" {
				p.println("  no container name given — aborting, nothing will be written.")
				return nil, nil, nil
			}
			ws = detectedWebServer{Kind: kind, Location: "docker", Parser: spec.parser, Container: container}
		default:
			return nil, nil, fmt.Errorf("invalid log source %q (must be file or docker)", source)
		}

		cols := confirmWebServerCollectors(pr.ask, pr.askBool, []detectedWebServer{ws})
		if len(cols) == 0 {
			// Operator declined the confirm prompt: offer removal instead.
			return removeCollectorIfConfirmed(p, pr, cfg, matchCollectorParser(spec.parser), kind)
		}
		entry := config.CollectorCfg{
			Kind:      cols[0].Kind,
			Path:      cols[0].Path,
			Container: cols[0].Container,
			Parser:    cols[0].Parser,
		}
		verb := upsertCollector(cfg, matchCollectorParser(spec.parser), entry)
		return []string{fmt.Sprintf("collectors — %s entry (%s)", verb, describeCollector(entry))}, nil, nil
	}
}

// isSSHCollector matches the journald entry the sshd wizard manages. Unit
// names come from detectSSHUnit ("ssh" on Debian/Ubuntu, "sshd" elsewhere);
// other journald units are someone else's collector and stay untouched.
func isSSHCollector(c config.CollectorCfg) bool {
	return c.Kind == "journald" && (c.Unit == "ssh" || c.Unit == "sshd")
}

// matchCollectorParser matches the first collector using parser — the wizard
// manages one entry per web server kind. Setups with several sources for the
// same parser (e.g. two nginx vhost logs) are edited in config.yaml directly.
func matchCollectorParser(parser string) func(config.CollectorCfg) bool {
	return func(c config.CollectorCfg) bool { return c.Parser == parser }
}

// upsertCollector replaces the first collector matched by match with entry,
// or appends entry when nothing matches. Returns the verb for the summary.
func upsertCollector(cfg *config.Config, match func(config.CollectorCfg) bool,
	entry config.CollectorCfg) string {
	for i := range cfg.Collectors {
		if match(cfg.Collectors[i]) {
			cfg.Collectors[i] = entry
			return "replaced"
		}
	}
	cfg.Collectors = append(cfg.Collectors, entry)
	return "added"
}

// removeCollectorIfConfirmed is the shared disable path: the operator
// declined to configure name, so if a matching entry exists offer to drop it
// (default no). Returning nil changed with nil err means nothing is written.
func removeCollectorIfConfirmed(p *wPrinter, pr prompter, cfg *config.Config,
	match func(config.CollectorCfg) bool, name string) ([]string, func() error, error) {
	idx := -1
	for i, c := range cfg.Collectors {
		if match(c) {
			idx = i
			break
		}
	}
	if idx < 0 {
		p.printf("  no %s collector is configured — nothing to do.\n", name)
		return nil, nil, nil
	}
	if !pr.askBool(fmt.Sprintf("Remove the existing %s collector from config.yaml?", name), false) {
		return nil, nil, nil
	}
	removed := cfg.Collectors[idx]
	cfg.Collectors = append(cfg.Collectors[:idx], cfg.Collectors[idx+1:]...)
	return []string{fmt.Sprintf("collectors — removed entry (%s)", describeCollector(removed))}, nil, nil
}

// describeCollector renders one entry for the changed-keys summary.
func describeCollector(c config.CollectorCfg) string {
	switch c.Kind {
	case "file":
		return fmt.Sprintf("kind=file, path=%s, parser=%s", c.Path, c.Parser)
	case "journald":
		return fmt.Sprintf("kind=journald, unit=%s", c.Unit)
	case "docker":
		return fmt.Sprintf("kind=docker, container=%s, parser=%s", c.Container, c.Parser)
	default:
		return "kind=" + c.Kind
	}
}
