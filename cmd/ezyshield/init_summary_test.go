package main

// Tests for the init Summary section (issue #102): summarizeChoices maps
// wizard answers to configured/skipped lines, renderInitSummary prints the
// final section, and — critically — the summary complements rather than
// replaces the loud Cloudflare abort banner from issue #93.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/cdndetect"
	"github.com/evertramos/ezy-shield/internal/config"
)

func TestSummarizeChoices_HappyPath(t *testing.T) {
	t.Parallel()

	state := &wizardState{
		sshUnit:    "ssh.service",
		monitorSSH: true,
		webCollectors: []webServerCollector{
			{Kind: "file", Parser: "nginx", Path: "/var/log/nginx/access.log"},
			{Kind: "docker", Parser: "nginx", Container: "proxy"},
		},
		nftPath:    "/usr/sbin/nft",
		adminIPs:   []string{"203.0.113.7"},
		enableAI:   true,
		aiProvider: "openai",
		aiModel:    "gpt-4o-mini",
		cdn: &cdnStep{
			cfEnabled:  true,
			cfAccounts: []cfAccountSetup{{cfg: config.CloudflareCfg{Mode: "lists", Action: "block"}}},
		},
	}
	sum := &initSummary{}
	summarizeChoices(state, sum, false)

	wantConfigured := []string{
		"collector: journald (SSH unit ssh.service)",
		"collector: nginx (/var/log/nginx/access.log)",
		"collector: nginx (container proxy)",
		"enforcer: nftables (/usr/sbin/nft)",
		"enforcer: cloudflare (mode lists, action block)",
		"AI analysis: openai (model gpt-4o-mini)",
		"allowlist: 1 admin IP(s)/CIDR(s)",
	}
	if got := strings.Join(sum.configured, "\n"); got != strings.Join(wantConfigured, "\n") {
		t.Errorf("configured =\n%s\nwant\n%s", got, strings.Join(wantConfigured, "\n"))
	}
	if len(sum.skipped) != 0 {
		t.Errorf("skipped = %q, want empty on the happy path", sum.skipped)
	}
}

func TestSummarizeChoices_SkippedPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state *wizardState
		yes   bool
		want  []string
	}{
		{
			name: "everything declined",
			state: &wizardState{
				sshUnit: "ssh.service", // detected but monitorSSH=false
				cdn: &cdnStep{
					detected: []cdndetect.Provider{{ID: "cloudflare", Name: "Cloudflare"}},
				},
			},
			want: []string{
				"SSH monitoring — declined at prompt",
				"nftables — not installed (dry-run and edge enforcement only)",
				"cloudflare enforcer — declined (CDN detected: bans will not reach real client IPs)",
				"AI analysis — disabled (rule engine only)",
			},
		},
		{
			name:  "--yes skips CDN detection",
			state: &wizardState{nftPath: "/usr/sbin/nft", cdn: &cdnStep{}},
			yes:   true,
			want: []string{
				"CDN detection — skipped (--yes mode)",
				"AI analysis — disabled (rule engine only)",
			},
		},
		{
			name: "aborted CF subflow survives into the summary",
			state: &wizardState{
				nftPath: "/usr/sbin/nft",
				cdn:     &cdnStep{cfAttempted: true},
			},
			want: []string{
				"cloudflare enforcer — setup did NOT complete (see the banner above)",
				"AI analysis — disabled (rule engine only)",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sum := &initSummary{}
			summarizeChoices(tc.state, sum, tc.yes)
			if got := strings.Join(sum.skipped, "\n"); got != strings.Join(tc.want, "\n") {
				t.Errorf("skipped =\n%s\nwant\n%s", got, strings.Join(tc.want, "\n"))
			}
		})
	}
}

// TestRenderInitSummary_HappyPath pins the full plain (non-TTY) rendering
// byte-for-byte: section header, configured/skipped/files blocks, dry-run
// reminder, detection count, and numbered next steps with the derived
// program name.
func TestRenderInitSummary_HappyPath(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &wPrinter{w: &buf}
	st := styler{color: false}
	state := &wizardState{armed: false}
	sum := &initSummary{
		configured: []string{"enforcer: nftables (/usr/sbin/nft)"},
		skipped:    []string{"AI analysis — disabled (rule engine only)"},
		files:      []string{"/etc/ezyshield/config.yaml"},
	}

	renderInitSummary(p, st, state, sum, 3, "/etc/ezyshield")
	if p.err != nil {
		t.Fatalf("printer error: %v", p.err)
	}

	want := "\n" +
		"Summary\n" +
		strings.Repeat("─", headerRuleWidth) + "\n" +
		"  Configured:\n" +
		"    ✓ enforcer: nftables (/usr/sbin/nft)\n" +
		"  Skipped:\n" +
		"    ! AI analysis — disabled (rule engine only)\n" +
		"  Files written:\n" +
		"    /etc/ezyshield/config.yaml\n" +
		"\n" +
		"  Mode: DRY-RUN (logging only, nothing blocked)\n" +
		"  Events: 3 dry-ban(s) detected in the first 15s\n" +
		"\n" +
		"  Next steps:\n" +
		fmt.Sprintf("    1. sudo %s doctor   — verify the configuration\n", progName) +
		fmt.Sprintf("    2. sudo %s status   — daemon and enforcer health\n", progName) +
		fmt.Sprintf("    3. sudo %s watch    — see detections live\n", progName) +
		"    4. set armed: true in /etc/ezyshield/policy.yaml when confident (after 24h+ of clean dry-run)\n"

	if got := buf.String(); got != want {
		t.Errorf("summary output:\n%q\nwant:\n%q", got, want)
	}
}

// TestRenderInitSummary_ConfigDirMode covers the --config-dir path
// (detections < 0): no services ran, so next steps must not say sudo and
// no Events line is printed.
func TestRenderInitSummary_ConfigDirMode(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &wPrinter{w: &buf}
	renderInitSummary(p, styler{color: false}, &wizardState{}, &initSummary{
		skipped: []string{"systemd units and services — skipped (non-default --config-dir)"},
	}, -1, "/tmp/dir")
	out := buf.String()

	if strings.Contains(out, "Events:") {
		t.Errorf("Events line printed in config-dir mode: %q", out)
	}
	if strings.Contains(out, "sudo") {
		t.Errorf("next steps mention sudo without installed services: %q", out)
	}
	if !strings.Contains(out, fmt.Sprintf("1. %s doctor", progName)) {
		t.Errorf("next steps missing doctor hint: %q", out)
	}
	if !strings.Contains(out, "systemd units and services — skipped") {
		t.Errorf("skipped services line missing: %q", out)
	}
}

// TestInitSummary_CFAbortBannerThenSummary is the issue #102 acceptance
// guard for the issue #93 interplay: when the Cloudflare subflow aborts,
// the loud banner still fires, and the summary ADDS a skipped line after
// it — it never replaces or hides the banner.
func TestInitSummary_CFAbortBannerThenSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &wPrinter{w: &buf}

	// Invalid mode answer → subflow aborts on its first prompt; the
	// deferred banner fires because cfEnabled stayed false.
	step := &cdnStep{}
	runCloudflareSubflow(context.Background(), p, &scriptedPrompter{strings: []string{"bogus"}}, step, cdnDeps{}, nil, cfSubflowOpts{})

	if step.cfEnabled {
		t.Fatal("cfEnabled=true after invalid mode")
	}
	if !step.cfAttempted {
		t.Fatal("cfAttempted=false after entering the subflow")
	}

	state := &wizardState{cdn: step}
	sum := &initSummary{}
	summarizeChoices(state, sum, false)
	renderInitSummary(p, styler{color: false}, state, sum, -1, "/tmp/dir")
	if p.err != nil {
		t.Fatalf("printer error: %v", p.err)
	}

	out := buf.String()
	banner := strings.Index(out, "Cloudflare enforcer setup did NOT complete")
	summary := strings.Index(out, "cloudflare enforcer — setup did NOT complete (see the banner above)")
	if banner < 0 {
		t.Fatalf("abort banner missing: %q", out)
	}
	if summary < 0 {
		t.Fatalf("summary skipped line missing: %q", out)
	}
	if summary < banner {
		t.Errorf("summary line printed before the banner (banner@%d, summary@%d)", banner, summary)
	}
}
