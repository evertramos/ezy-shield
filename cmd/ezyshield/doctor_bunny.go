package main

// bunny.net enforcer doctor checks (issue #198): the post-setup
// counterparts of the wizard's dry validation — key resolves, key is valid,
// every configured pull zone is reachable. All calls are read-only
// (GET /pullzone/{id}); the key never appears in any output.

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
)

// checkBunnyEnforcer runs the read-only checks for the configured bunny.net
// enforcer. Returns a single N/A result when none is configured (or the
// config cannot be loaded — the config checks report that separately).
func checkBunnyEnforcer(configDir string) []CheckResult {
	cfg, err := config.LoadConfig(filepath.Join(configDir, "config.yaml"))
	if err != nil || cfg.Enforce == nil || cfg.Enforce.Bunny == nil {
		return []CheckResult{{
			Name:   "bunny: enforcer",
			Status: statusNA,
			Hint:   "no bunny enforcer configured",
		}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 8 * time.Second}
	return checkOneBunny(ctx, client, "https://api.bunny.net", configDir, cfg.Enforce.Bunny)
}

// checkOneBunny runs the checks for the bunny enforcer entry. client and
// base are injectable for tests.
func checkOneBunny(ctx context.Context, client cfClient, base, configDir string, bcfg *config.BunnyCfg) []CheckResult {
	label := "bunny"
	if bcfg.Name != "" {
		label = "bunny(" + bcfg.Name + ")"
	}

	// 1. Key resolution — same env-file fallback as the cloudflare checks:
	// the doctor CLI usually runs without the daemon's EnvironmentFile.
	key, err := bcfg.APIKey.Resolve()
	if err != nil {
		envVar := strings.TrimPrefix(string(bcfg.APIKey), "env:")
		if v, ok := readEnvValue(filepath.Join(configDir, envFileName), envVar); ok &&
			v != "" && v != config.PlaceholderAPIKey {
			key = v
		} else {
			return []CheckResult{{
				Name:   label + ": key resolves",
				Status: statusFail,
				Hint: fmt.Sprintf("API key not found in environment or %s -- add %s there (mode 0600)",
					filepath.Join(configDir, envFileName), envVar),
			}}
		}
	}
	results := []CheckResult{{Name: label + ": key resolves", Status: statusPass}}

	// 2. Key validity + per-zone reachability: one read-only GET per zone.
	for _, zone := range bcfg.PullZones {
		name := label + ": pull zone " + strconv.FormatInt(zone, 10)
		status, err := doBunnyGet(ctx, client, base+"/pullzone/"+strconv.FormatInt(zone, 10), key)
		switch {
		case err != nil:
			results = append(results, CheckResult{
				Name:   name,
				Status: statusFail,
				Hint:   sanitizeErrorMessage(err.Error()),
			})
		case status == http.StatusUnauthorized:
			// A rejected key fails every zone identically; report once.
			results = append(results, CheckResult{
				Name:   label + ": key valid",
				Status: statusFail,
				Hint:   "the bunny API rejected the key (HTTP 401) -- rotate it in the bunny panel (Account -> API) and update .env",
			})
			return results
		case status == http.StatusNotFound:
			results = append(results, CheckResult{
				Name:   name,
				Status: statusFail,
				Hint:   "pull zone not found (HTTP 404) -- check the numeric ID in the bunny panel",
			})
		case status != http.StatusOK:
			results = append(results, CheckResult{
				Name:   name,
				Status: statusFail,
				Hint:   fmt.Sprintf("unexpected HTTP %d from the bunny API", status),
			})
		default:
			results = append(results, CheckResult{Name: name, Status: statusPass})
		}
	}
	return results
}

// doBunnyGet performs one read-only GET with the AccessKey header. The key
// never reaches the returned error.
func doBunnyGet(ctx context.Context, client cfClient, url, key string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("AccessKey", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ezyshield-doctor/bunny")
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("bunny API unreachable: %w", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}
