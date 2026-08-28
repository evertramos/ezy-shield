// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the bunny.net init subflow and doctor checks (issue #198).

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// bunnyHTTPFake stubs GET /pullzone/{id} for the given zone IDs.
func bunnyHTTPFake(okZones ...string) *httpFake {
	byPath := map[string]httpFakeResp{}
	for _, z := range okZones {
		byPath["/pullzone/"+z] = httpFakeResp{status: http.StatusOK, bodyJSON: `{"Id":` + z + `,"BlockedIps":[]}`}
	}
	return &httpFake{byPath: byPath}
}

func TestRunBunnySubflow_HappyPath(t *testing.T) {
	prompt := &scriptedPrompter{
		strings: []string{"101, 202"},
	}
	step := &cdnStep{}
	fake := bunnyHTTPFake("101", "202")
	out := captureStep(t, func(p *wPrinter) {
		runBunnySubflow(context.Background(), p, prompt, step, cdnDeps{
			HTTPClient:      fake,
			TokenReader:     seqTokenReader(t, "bunny-key-secret"),
			BunnyAPIBaseURL: "http://bunny.example",
		})
	})

	if !step.bunnyEnabled || step.bunny == nil {
		t.Fatalf("bunnyEnabled false; out=%q", out)
	}
	if got := step.bunny.cfg.PullZones; len(got) != 2 || got[0] != 101 || got[1] != 202 {
		t.Errorf("pull zones = %v, want [101 202]", got)
	}
	if step.bunny.cfg.APIKey != config.SecretRef("env:BUNNY_API_KEY") {
		t.Errorf("api_key ref = %q, want env:BUNNY_API_KEY", step.bunny.cfg.APIKey)
	}
	if step.bunny.keyEnvVar != "BUNNY_API_KEY" || step.bunny.key != "bunny-key-secret" {
		t.Errorf("env material = %q/%q", step.bunny.keyEnvVar, step.bunny.key)
	}
	// The key must never surface in wizard output or in String().
	if strings.Contains(out, "bunny-key-secret") {
		t.Errorf("key leaked into wizard output: %q", out)
	}
	if s := step.bunny.String(); strings.Contains(s, "bunny-key-secret") {
		t.Errorf("key leaked into String(): %q", s)
	}
	// Ownership warning must be shown before the operator commits.
	if !strings.Contains(out, "ownership") {
		t.Errorf("missing list-ownership warning; out=%q", out)
	}
	// Every configured zone was probed with the AccessKey header.
	if len(fake.requests) != 2 {
		t.Fatalf("probe requests = %d, want 2", len(fake.requests))
	}
	for _, r := range fake.requests {
		if r.Header.Get("AccessKey") != "bunny-key-secret" {
			t.Errorf("probe missing AccessKey header")
		}
	}
}

func TestRunBunnySubflow_RejectedKeyAborts(t *testing.T) {
	prompt := &scriptedPrompter{strings: []string{"101"}}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runBunnySubflow(context.Background(), p, prompt, step, cdnDeps{
			HTTPClient:      &httpFake{status: http.StatusUnauthorized, bodyJSON: `{}`},
			TokenReader:     seqTokenReader(t, "bad-key"),
			BunnyAPIBaseURL: "http://bunny.example",
		})
	})
	if step.bunnyEnabled || step.bunny != nil {
		t.Fatalf("bunnyEnabled must stay false on 401; out=%q", out)
	}
	if !step.bunnyAttempted {
		t.Error("bunnyAttempted must be recorded for the init summary")
	}
	for _, want := range []string{"rejected", "did NOT complete"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; out=%q", want, out)
		}
	}
}

func TestRunBunnySubflow_InvalidZonesAbort(t *testing.T) {
	for name, zones := range map[string]string{
		"empty":       "",
		"not-numeric": "my-zone",
		"negative":    "-5",
	} {
		t.Run(name, func(t *testing.T) {
			prompt := &scriptedPrompter{strings: []string{zones}}
			step := &cdnStep{}
			fake := bunnyHTTPFake()
			out := captureStep(t, func(p *wPrinter) {
				runBunnySubflow(context.Background(), p, prompt, step, cdnDeps{
					HTTPClient:      fake,
					TokenReader:     seqTokenReader(t, "unused"),
					BunnyAPIBaseURL: "http://bunny.example",
				})
			})
			if step.bunnyEnabled {
				t.Fatalf("bunnyEnabled true for zones=%q; out=%q", zones, out)
			}
			if len(fake.requests) != 0 {
				t.Errorf("API reached despite invalid zone input")
			}
		})
	}
}

func TestRunBunnySubflow_ZoneNotFoundAborts(t *testing.T) {
	prompt := &scriptedPrompter{strings: []string{"101, 999"}}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runBunnySubflow(context.Background(), p, prompt, step, cdnDeps{
			HTTPClient:      bunnyHTTPFake("101"), // 999 → 404
			TokenReader:     seqTokenReader(t, "key"),
			BunnyAPIBaseURL: "http://bunny.example",
		})
	})
	if step.bunnyEnabled {
		t.Fatalf("bunnyEnabled true with a missing zone; out=%q", out)
	}
	if !strings.Contains(out, "999") || !strings.Contains(out, "not found") {
		t.Errorf("output must name the missing zone; out=%q", out)
	}
}

// TestEmitBunnyYAML_RendersValidConfig pins that the emitted section loads
// and validates through the real config loader.
func TestEmitBunnyYAML_RendersValidConfig(t *testing.T) {
	step := &cdnStep{
		bunnyEnabled: true,
		bunny: &bunnySetup{
			cfg: config.BunnyCfg{
				APIKey:    config.SecretRef("env:BUNNY_API_KEY"),
				PullZones: []int64{101, 202},
			},
			keyEnvVar: "BUNNY_API_KEY",
		},
	}
	var b strings.Builder
	b.WriteString("data_dir: /var/lib/ezyshield\nenforce:\n")
	emitBunnyYAML(&b, step)

	dir := t.TempDir()
	path := dir + "/config.yaml"
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("emitted YAML failed to load: %v\n%s", err, b.String())
	}
	if cfg.Enforce == nil || cfg.Enforce.Bunny == nil {
		t.Fatalf("enforce.bunny missing after load:\n%s", b.String())
	}
	if got := cfg.Enforce.Bunny.PullZones; len(got) != 2 || got[0] != 101 || got[1] != 202 {
		t.Errorf("pull zones = %v", got)
	}
}
