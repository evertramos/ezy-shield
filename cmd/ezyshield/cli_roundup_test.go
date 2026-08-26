// SPDX-License-Identifier: AGPL-3.0-only

package main

// Regression tests for the issue #356 CLI-consistency roundup.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestBan_ForIsAliasOfTTL: ban gained --for to match allow/arm; passing both
// spellings at once is ambiguous and must be refused before any RPC.
func TestBan_ForIsAliasOfTTL(t *testing.T) {
	_, _, err := execRoot(t, "ban", "192.0.2.7", "--ttl", "5m", "--for", "6m")
	if err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("passing both --ttl and --for must be refused, got: %v", err)
	}
}

// TestTestNotify_AllCoversSlackDiscordWebhook: slack, discord and webhook were
// configurable but not testable — `test notifier all` silently omitted them
// (issue #356). All three must now receive the synthetic alert.
func TestTestNotify_AllCoversSlackDiscordWebhook(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	t.Setenv("TEST_HOOK_URL", srv.URL)
	dir := t.TempDir()
	cfg := `notify:
  slack:
    webhook_url: env:TEST_HOOK_URL
  discord:
    webhook_url: env:TEST_HOOK_URL
  webhook:
    url: env:TEST_HOOK_URL
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := execRoot(t, "test", "notifier", "all", "--config-dir", dir)
	if err != nil {
		t.Fatalf("test notifier all: %v\n%s", err, out)
	}
	for _, want := range []string{"slack: OK", "discord: OK", "webhook: OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("expected 3 webhook deliveries (slack+discord+webhook), got %d", got)
	}
}

// TestTestNotify_SingleNewChannel: each new channel is addressable by name.
func TestTestNotify_SingleNewChannel(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	t.Setenv("TEST_HOOK_URL", srv.URL)
	dir := t.TempDir()
	cfg := `notify:
  discord:
    webhook_url: env:TEST_HOOK_URL
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := execRoot(t, "test", "notifier", "discord", "--config-dir", dir)
	if err != nil {
		t.Fatalf("test notifier discord: %v\n%s", err, out)
	}
	if hits.Load() != 1 {
		t.Errorf("expected 1 delivery, got %d", hits.Load())
	}
}

// TestRenderGeneratedPolicy_DerivesFromConfigDefaults: the generated
// policy.yaml must carry the config package's default constants, not
// re-declared literals that can drift (issue #356).
func TestRenderGeneratedPolicy_DerivesFromConfigDefaults(t *testing.T) {
	t.Parallel()
	body, err := renderGeneratedPolicy(&wizardState{})
	if err != nil {
		t.Fatalf("renderGeneratedPolicy: %v", err)
	}
	s := string(body)
	for _, want := range []string{
		"ban_threshold: 70",
		"observe_threshold: 40",
		"max_bans_per_minute: 30",
		"- ttl: 5m\n",
		"- ttl: 1h\n",
		"- ttl: 24h\n",
		"- ttl: 168h\n",
		"- ttl: 0\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("generated policy missing %q:\n%s", want, s)
		}
	}
}
