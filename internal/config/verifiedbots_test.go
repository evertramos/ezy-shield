// SPDX-License-Identifier: AGPL-3.0-only

package config

// Tests for the verified_bots config section (issue #215).

import (
	"strings"
	"testing"
)

func TestValidateVerifiedBots(t *testing.T) {
	t.Parallel()
	ok := &VerifiedBotsCfg{Enabled: true, Providers: []VerifiedBotProviderCfg{
		{Name: "mybot", UAContains: []string{"mybot"}, Domains: []string{"crawl.example.com"}},
	}}
	if err := (&Config{VerifiedBots: ok}).Validate(); err != nil {
		t.Fatalf("valid section rejected: %v", err)
	}
	// Section with defaults only is fine.
	if err := (&Config{VerifiedBots: &VerifiedBotsCfg{Enabled: true}}).Validate(); err != nil {
		t.Fatalf("defaults-only section rejected: %v", err)
	}

	cases := []struct {
		name string
		p    VerifiedBotProviderCfg
		want string
	}{
		{"missing name", VerifiedBotProviderCfg{UAContains: []string{"x"}, Domains: []string{"a.example"}}, "name is required"},
		{"no ua", VerifiedBotProviderCfg{Name: "b", Domains: []string{"a.example"}}, "ua_contains"},
		{"no domains", VerifiedBotProviderCfg{Name: "b", UAContains: []string{"b"}}, "domains"},
		{"bad domain", VerifiedBotProviderCfg{Name: "b", UAContains: []string{"b"}, Domains: []string{"http://evil"}}, "not a valid domain"},
		{"dotless domain", VerifiedBotProviderCfg{Name: "b", UAContains: []string{"b"}, Domains: []string{"localhost"}}, "not a valid domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := (&Config{VerifiedBots: &VerifiedBotsCfg{Providers: []VerifiedBotProviderCfg{tc.p}}}).Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
