package main

// Doctor checks for the bunny.net enforcer (issue #198).

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

func bunnyDoctorCfg(zones ...int64) *config.BunnyCfg {
	return &config.BunnyCfg{
		APIKey:    config.SecretRef("env:BUNNY_DOCTOR_TEST_KEY"),
		PullZones: zones,
	}
}

func TestCheckOneBunny_AllZonesReachable(t *testing.T) {
	t.Setenv("BUNNY_DOCTOR_TEST_KEY", "doctor-key")
	fake := bunnyHTTPFake("101", "202")
	results := checkOneBunny(context.Background(), fake, "http://bunny.example",
		t.TempDir(), bunnyDoctorCfg(101, 202))

	if len(results) != 3 {
		t.Fatalf("results = %+v, want key + 2 zones", results)
	}
	for _, r := range results {
		if r.Status != statusPass {
			t.Errorf("%s = %s (%s), want pass", r.Name, r.Status, r.Hint)
		}
	}
}

func TestCheckOneBunny_KeyRejected(t *testing.T) {
	t.Setenv("BUNNY_DOCTOR_TEST_KEY", "rotated-away")
	fake := &httpFake{status: http.StatusUnauthorized, bodyJSON: `{}`}
	results := checkOneBunny(context.Background(), fake, "http://bunny.example",
		t.TempDir(), bunnyDoctorCfg(101, 202))

	// key resolves (pass) + one key-invalid failure; the second zone is not
	// probed (a rejected key fails every zone identically).
	if len(results) != 2 {
		t.Fatalf("results = %+v, want 2", results)
	}
	last := results[len(results)-1]
	if last.Status != statusFail || !strings.Contains(last.Hint, "401") {
		t.Errorf("want 401 failure, got %+v", last)
	}
	if strings.Contains(last.Hint, "rotated-away") {
		t.Errorf("key leaked into hint: %q", last.Hint)
	}
}

func TestCheckOneBunny_ZoneMissing(t *testing.T) {
	t.Setenv("BUNNY_DOCTOR_TEST_KEY", "doctor-key")
	fake := bunnyHTTPFake("101") // 999 → 404
	results := checkOneBunny(context.Background(), fake, "http://bunny.example",
		t.TempDir(), bunnyDoctorCfg(101, 999))

	var found bool
	for _, r := range results {
		if strings.Contains(r.Name, "999") {
			found = true
			if r.Status != statusFail || !strings.Contains(r.Hint, "not found") {
				t.Errorf("zone 999 = %+v, want 404 failure", r)
			}
		}
	}
	if !found {
		t.Fatalf("no result for the missing zone: %+v", results)
	}
}

func TestCheckOneBunny_KeyUnresolvable(t *testing.T) {
	// Env var absent and no .env fallback in the temp config dir.
	results := checkOneBunny(context.Background(), bunnyHTTPFake(), "http://bunny.example",
		t.TempDir(), &config.BunnyCfg{
			APIKey:    config.SecretRef("env:BUNNY_DOCTOR_TEST_MISSING"),
			PullZones: []int64{101},
		})
	if len(results) != 1 || results[0].Status != statusFail {
		t.Fatalf("want single key-resolution failure, got %+v", results)
	}
}
