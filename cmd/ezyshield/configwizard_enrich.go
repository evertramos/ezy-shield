package main

// Post-install wizard for `config enrich maxmind` (issue #168). Enrichment
// was the only config section without a wizard: operators had no guided way
// to set up GeoIP/ASN — which MMDB files, where they come from, or that the
// daemon can download them itself. Built strictly on the shared primitives:
// the prompt closures (newAskFuncs), the registry + atomic write path
// (runConfigComponent), and the secret discipline of the notifier/AI wizards
// (the license key lands ONLY in .env; config.yaml carries the env:VARNAME
// reference — SECURITY-REVIEW §4).

import (
	"context"
	"fmt"

	"github.com/evertramos/ezy-shield/internal/config"
)

// enrichLicenseEnvVar fixes the default env var for the MaxMind license key,
// same single-source-of-truth idea as notifierSecretEnvVar.
const enrichLicenseEnvVar = "MAXMIND_LICENSE_KEY"

// Default MMDB locations. They live in the daemon's data dir so the
// auto-updater (which runs as the service user) can replace them.
const (
	defaultCountryDBPath = "/var/lib/ezyshield/GeoLite2-Country.mmdb"
	defaultASNDBPath     = "/var/lib/ezyshield/GeoLite2-ASN.mmdb"
)

// wizardEnrichMaxmind configures the enrich: section for MaxMind GeoLite2.
// With auto_update on, internal/enrich.Updater downloads both editions at
// daemon startup when the files are missing and refreshes them weekly — so
// the usual flow is: run this wizard, restart, done. With auto_update off
// the operator downloads the MMDB files themselves and no key is needed.
func wizardEnrichMaxmind(_ context.Context, p *wPrinter, pr prompter, deps cdnDeps,
	cfg *config.Config, configDir string) ([]string, func() error, error) {
	if !pr.askBool("Configure GeoIP/ASN enrichment (MaxMind GeoLite2)?", true) {
		return removeEnrichIfConfirmed(p, pr, cfg)
	}

	p.println("  Enrichment adds country/ASN to events — it powers block_countries /")
	p.println("  block_asns in policy.yaml and the country/ASN columns in list and report.")
	p.println("  GeoLite2 databases are free but need a MaxMind account and license key:")
	p.println("    https://www.maxmind.com/en/geolite2/signup")

	dbPath := pr.ask("Country database path", defaultCountryDBPath)
	asnPath := pr.ask("ASN database path", defaultASNDBPath)
	autoUpdate := pr.askBool(
		"Let the daemon download and refresh the databases weekly (needs the license key)?", true)

	var sec notifierSecret
	if autoUpdate {
		sec = askNotifierSecret(p, pr, deps.TokenReader, "MaxMind license key", enrichLicenseEnvVar)
	}

	verb := "added"
	if cfg.Enrich != nil {
		verb = "replaced"
	}
	cfg.Enrich = &config.EnrichCfg{
		DBPath:     dbPath,
		ASNPath:    asnPath,
		AutoUpdate: autoUpdate,
	}
	changed := []string{fmt.Sprintf(
		"enrich — %s section (db_path=%s, asn_path=%s, auto_update=%v)",
		verb, dbPath, asnPath, autoUpdate)}

	var postSave func() error
	if autoUpdate {
		cfg.Enrich.LicenseKey = config.SecretRef("env:" + sec.envVar)
		changed = append(changed, "enrich.license_key = env:"+sec.envVar)
		postSave = sec.envPostSave(p, configDir)
		p.println("  On the next daemon start the databases are downloaded automatically")
		p.println("  if missing, then refreshed weekly.")
	} else {
		p.println("  auto_update is off — download GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb")
		p.println("  from your MaxMind account and place them at the paths above. Missing")
		p.println("  files are not an error: the daemon runs with empty enrichment until")
		p.println("  they appear.")
	}
	return changed, postSave, nil
}

// removeEnrichIfConfirmed handles the "answered no" path: offer to drop an
// existing enrich: section, same shape as removeNotifierIfConfirmed.
func removeEnrichIfConfirmed(p *wPrinter, pr prompter, cfg *config.Config) ([]string, func() error, error) {
	if cfg.Enrich == nil {
		p.println("  no enrich section is configured — nothing to do.")
		return nil, nil, nil
	}
	if !pr.askBool("Remove the existing enrich section from config.yaml?", false) {
		return nil, nil, nil
	}
	cfg.Enrich = nil
	return []string{"enrich — removed section"}, nil, nil
}
