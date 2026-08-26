package main

// Notifications step for `ezyshield init` (issue #290): configure zero or
// more channels during initial setup, in both modes. Issue #231's own
// acceptance criteria listed notifiers as part of the non-interactive
// surface; PR #288 shipped without them, and the interactive wizard never
// had the step either — this closes both gaps.
//
// Reuse, not duplication: the interactive step dispatches to the SAME
// per-channel prompt flows `config notifier <name>` runs
// (notifierChannelFlows in configwizard_notifier.go); the non-interactive
// path maps the answers schema onto config.NotifyCfg directly. Secret
// discipline is identical to the AI/Cloudflare handling: values only ever
// reach .env (or stay external), config.yaml carries env: references, and
// literal secrets in the answers file are rejected before any write.

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/evertramos/ezy-shield/internal/config"
)

// runNotifyStep is the interactive Notifications section of askQuestions.
// yes=true (unattended --yes run) skips the section entirely — channels
// need operator-specific values (chat IDs, addresses) that have no safe
// default.
func runNotifyStep(p *wPrinter, pr prompter, deps cdnDeps, state *wizardState,
	configDir string, yes bool) {
	if yes {
		return
	}
	if !pr.askBool("Configure notification channels now? (also available later: '"+
		progName+" config notifier <name>')", false) {
		return
	}
	scratch := &config.Config{}
	var hooks []func() error
	for _, name := range notifierChannelNames {
		if !pr.askBool(fmt.Sprintf("Add the %s channel?", name), false) {
			continue
		}
		changed, post, err := notifierChannelFlows[name](p, pr, deps, scratch, configDir)
		if err != nil {
			p.printf("  %s: %v — skipping this channel\n", name, err)
			continue
		}
		for _, c := range changed {
			p.println("  " + c)
		}
		if post != nil {
			hooks = append(hooks, post)
		}
	}
	state.notify = scratch.Notify
	state.notifyPostSave = chainPostSave(hooks...)
}

// renderNotifyYAML appends the notify: block to the generated config. The
// section is serialized from the SAME config.NotifyCfg shape both init modes
// build, so the two paths cannot drift (issue #290 AC: identical shape).
func renderNotifyYAML(b *strings.Builder, n *config.NotifyCfg) error {
	if n == nil {
		return nil
	}
	out, err := yaml.Marshal(struct {
		Notify *config.NotifyCfg `yaml:"notify"`
	}{n})
	if err != nil {
		return fmt.Errorf("render notify section: %w", err)
	}
	b.Write(out)
	return nil
}

// notifyEnvVars returns the env var NAMES the notify section references, for
// the non-interactive placeholder stubbing (interactive runs write .env via
// the channel post-save hooks instead).
func notifyEnvVars(n *config.NotifyCfg) []string {
	if n == nil {
		return nil
	}
	var names []string
	add := func(ref config.SecretRef) {
		if s := strings.TrimPrefix(string(ref), "env:"); s != "" && s != string(ref) {
			names = append(names, s)
		}
	}
	if n.Telegram != nil {
		add(n.Telegram.BotToken)
	}
	if n.Email != nil {
		add(n.Email.Password)
	}
	if n.Slack != nil {
		add(n.Slack.WebhookURL)
	}
	if n.Discord != nil {
		add(n.Discord.WebhookURL)
	}
	if n.Webhook != nil {
		add(n.Webhook.URL)
		for _, v := range n.Webhook.Headers {
			if s := strings.TrimPrefix(v, "env:"); s != v && s != "" {
				names = append(names, s)
			}
		}
	}
	return names
}
