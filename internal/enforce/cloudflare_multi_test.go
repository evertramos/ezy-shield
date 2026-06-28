package enforce_test

// Multi-account Cloudflare fan-out tests (issue #90). These exercise the
// real composition the daemon performs in cmd/ezyshield/watch.go: one
// CloudflareListsEnforcer per configured account, all wrapped in a
// MultiEnforcer. The mock CF Lists server is reused per account so each
// account ends up backed by its own isolated API surface.

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// newCFAccountMock returns a CF Lists mock keyed to accountID, plus its server.
func newCFAccountMock(t *testing.T, accountID string) (*cfListsMock, *httptest.Server) {
	t.Helper()
	m := newCFListsMock(accountID)
	ts := httptest.NewServer(m.handler())
	t.Cleanup(ts.Close)
	return m, ts
}

func TestMultiEnforcer_CloudflareFanOut_BanReachesAllAccounts(t *testing.T) {
	mockA, tsA := newCFAccountMock(t, "acct-a")
	mockB, tsB := newCFAccountMock(t, "acct-b")

	eA := enforce.NewCFListsEnforcerWithName("client_a", "tokA", tsA.URL, "acct-a", "ezyshield_blocked")
	eB := enforce.NewCFListsEnforcerWithName("client_b", "tokB", tsB.URL, "acct-b", "ezyshield_blocked")
	m := enforce.NewMulti(eA, eB)

	ip := netip.MustParseAddr("203.0.113.7")
	if err := m.Ban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	if !mockA.hasItem("ezyshield_blocked", "203.0.113.7") {
		t.Error("account A should have 203.0.113.7 in its list")
	}
	if !mockB.hasItem("ezyshield_blocked", "203.0.113.7") {
		t.Error("account B should have 203.0.113.7 in its list")
	}
}

func TestMultiEnforcer_CloudflareFanOut_UnbanReachesAllAccounts(t *testing.T) {
	mockA, tsA := newCFAccountMock(t, "acct-a")
	mockB, tsB := newCFAccountMock(t, "acct-b")

	eA := enforce.NewCFListsEnforcerWithName("client_a", "tokA", tsA.URL, "acct-a", "ezyshield_blocked")
	eB := enforce.NewCFListsEnforcerWithName("client_b", "tokB", tsB.URL, "acct-b", "ezyshield_blocked")
	m := enforce.NewMulti(eA, eB)

	ip := netip.MustParseAddr("198.51.100.4")
	if err := m.Ban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if err := m.Unban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Unban: %v", err)
	}

	if mockA.itemCount("ezyshield_blocked") != 0 {
		t.Errorf("account A should be empty after Unban, got %d items",
			mockA.itemCount("ezyshield_blocked"))
	}
	if mockB.itemCount("ezyshield_blocked") != 0 {
		t.Errorf("account B should be empty after Unban, got %d items",
			mockB.itemCount("ezyshield_blocked"))
	}
}

func TestMultiEnforcer_CloudflareFanOut_PartialFailureIsolated(t *testing.T) {
	// Account A points at an unroutable URL so its API calls always fail; B is healthy.
	// Acceptance criterion (issue #90): a failure in one account must not prevent
	// the ban from landing in the others, and the combined error must identify
	// which account failed.
	mockB, tsB := newCFAccountMock(t, "acct-b")

	eA := enforce.NewCFListsEnforcerWithName("client_a", "tokA", "http://127.0.0.1:1", "acct-a", "ezyshield_blocked")
	eB := enforce.NewCFListsEnforcerWithName("client_b", "tokB", tsB.URL, "acct-b", "ezyshield_blocked")
	m := enforce.NewMulti(eA, eB)

	ip := netip.MustParseAddr("192.0.2.9")
	err := m.Ban(context.Background(), sdk.Target{IP: ip})
	if err == nil {
		t.Fatal("expected combined error from failing account A")
	}
	if !strings.Contains(err.Error(), "cloudflare[client_a]") {
		t.Errorf("error should identify the failing account, got: %v", err)
	}
	if !mockB.hasItem("ezyshield_blocked", "192.0.2.9") {
		t.Error("account B should have received the ban even though A failed")
	}
}

func TestMultiEnforcer_CloudflareFanOut_NameDisambiguates(t *testing.T) {
	eA := enforce.NewCFListsEnforcerWithName("client_a", "tokA", "http://localhost", "acct-a", "ezyshield_blocked")
	eB := enforce.NewCFListsEnforcerWithName("client_b", "tokB", "http://localhost", "acct-b", "ezyshield_blocked")
	m := enforce.NewMulti(eA, eB)

	got := m.Name()
	if got != "cloudflare[client_a]+cloudflare[client_b]" {
		t.Errorf("MultiEnforcer.Name() = %q, want 'cloudflare[client_a]+cloudflare[client_b]'", got)
	}
}
