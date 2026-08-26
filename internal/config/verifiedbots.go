package config

// Verified-bots section (issue #215): opt-in FCrDNS protection for
// well-known crawlers. See internal/botverify for the mechanism; this file
// only carries configuration shape and validation.

import (
	"fmt"
	"strings"
)

// VerifiedBotsCfg is the `verified_bots:` section of config.yaml.
// Disabled (or absent) = no DNS lookups ever happen.
type VerifiedBotsCfg struct {
	// Enabled turns the guard on. The built-in provider table (Googlebot,
	// Bingbot, Applebot, YandexBot, Baiduspider, DuckDuckBot) applies by
	// default.
	Enabled bool `yaml:"enabled"`
	// Providers extends or overrides the built-in table, matched by name.
	Providers []VerifiedBotProviderCfg `yaml:"providers"`
}

// VerifiedBotProviderCfg declares one crawler operator.
type VerifiedBotProviderCfg struct {
	// Name identifies the provider in audits; overriding a built-in name
	// replaces that entry.
	Name string `yaml:"name"`
	// UAContains are case-insensitive User-Agent substrings that make an IP
	// a verification candidate.
	UAContains []string `yaml:"ua_contains"`
	// Domains are the DNS suffixes the PTR name must fall under.
	Domains []string `yaml:"domains"`
}

func validateVerifiedBots(v *VerifiedBotsCfg) error {
	for i, p := range v.Providers {
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("providers[%d]: name is required", i)
		}
		if len(p.UAContains) == 0 {
			return fmt.Errorf("provider %q: ua_contains must be non-empty", p.Name)
		}
		if len(p.Domains) == 0 {
			return fmt.Errorf("provider %q: domains must be non-empty", p.Name)
		}
		for _, d := range p.Domains {
			d = strings.TrimSpace(d)
			if d == "" || strings.ContainsAny(d, " /\\:@") || !strings.Contains(d, ".") ||
				strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
				return fmt.Errorf("provider %q: %q is not a valid domain suffix", p.Name, d)
			}
		}
	}
	return nil
}
