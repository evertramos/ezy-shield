// SPDX-License-Identifier: AGPL-3.0-only

package enforce

// Tests for the AWS WAFv2 IPSet enforcer (issue #200): SigV4 against the
// AWS-documented test vector, ban/unban/sync against a local mock of the
// wafv2 endpoint, lock-token conflict retry, capacity truncation, auth
// failure, the credential chain, and the secret-leak discipline. No real
// AWS is ever contacted.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// TestSignSigV4_AWSDocVector pins the signer to the official example from
// the AWS General Reference ("Signature Version 4 signing process",
// GET iam ListUsers): a wrong canonicalization or key derivation fails
// against AWS's own published signature.
func TestSignSigV4_AWSDocVector(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")
	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Host:   "iam.amazonaws.com",
		Header: http.Header{},
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	creds := awsCredentials{ //nolint:gosec // the PUBLIC example credentials from AWS's SigV4 documentation, not a real secret
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	at, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	signSigV4(req, nil, creds, "us-east-1", "iam", at)

	auth := req.Header.Get("Authorization")
	wantSig := "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if !strings.HasSuffix(auth, "Signature="+wantSig) {
		t.Errorf("signature mismatch against the AWS documented vector.\ngot:  %s\nwant suffix: Signature=%s", auth, wantSig)
	}
	if !strings.Contains(auth, "Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request") {
		t.Errorf("credential scope wrong: %s", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=content-type;host;x-amz-date") {
		t.Errorf("signed headers wrong: %s", auth)
	}
}

// mockWAF is a local stand-in for the wafv2 endpoint: one IPSet keyed by
// Name, optimistic lock tokens, scriptable failures.
type mockWAF struct {
	mu         sync.Mutex
	addresses  map[string]map[string]bool // name -> set of CIDRs
	lockToken  map[string]int
	conflicts  int // pending forced lock conflicts on UpdateIPSet
	authFail   bool
	updates    int
	lastAuthOK bool
}

func newMockWAF(names ...string) *mockWAF {
	m := &mockWAF{addresses: map[string]map[string]bool{}, lockToken: map[string]int{}}
	for _, n := range names {
		m.addresses[n] = map[string]bool{}
	}
	return m
}

func (m *mockWAF) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.lastAuthOK = strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=")
		if m.authFail {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","Message":"not authorized"}`))
			return
		}
		var req struct {
			Name      string   `json:"Name"`
			Addresses []string `json:"Addresses"`
			LockToken string   `json:"LockToken"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		set, ok := m.addresses[req.Name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"__type":"WAFNonexistentItemException","Message":"no such set"}`))
			return
		}
		switch r.Header.Get("X-Amz-Target") {
		case "AWSWAF_20190729.GetIPSet":
			list := make([]string, 0, len(set))
			for a := range set {
				list = append(list, a)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"IPSet":     map[string]any{"Addresses": list},
				"LockToken": tokenString(m.lockToken[req.Name]),
			})
		case "AWSWAF_20190729.UpdateIPSet":
			if m.conflicts > 0 {
				m.conflicts--
				m.lockToken[req.Name]++ // someone else won the race
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"__type":"WAFOptimisticLockException","Message":"stale token"}`))
				return
			}
			if req.LockToken != tokenString(m.lockToken[req.Name]) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"__type":"WAFOptimisticLockException","Message":"stale token"}`))
				return
			}
			next := map[string]bool{}
			for _, a := range req.Addresses {
				next[a] = true
			}
			m.addresses[req.Name] = next
			m.lockToken[req.Name]++
			m.updates++
			_ = json.NewEncoder(w).Encode(map[string]any{"NextLockToken": tokenString(m.lockToken[req.Name])})
		default:
			t.Errorf("unexpected X-Amz-Target %q", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func tokenString(n int) string { return fmt.Sprintf("tok-%d", n) }

func (m *mockWAF) has(name, cidr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addresses[name][cidr]
}

func (m *mockWAF) list(name string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.addresses[name]))
	for a := range m.addresses[name] {
		out = append(out, a)
	}
	return out
}

// newAWSEnforcerForTest wires the enforcer at a mock endpoint with static
// env-style credentials and no backoff waits.
func newAWSEnforcerForTest(t *testing.T, srv *httptest.Server, v4, v6 *AWSIPSetRef) *AWSWAFEnforcer {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key-value-do-not-leak")
	cfg := &AWSWAFConfig{Scope: "REGIONAL", Region: "eu-west-1", IPSetV4: v4, IPSetV6: v6}
	e, err := NewAWSWAFEnforcer(cfg, nil)
	if err != nil {
		t.Fatalf("NewAWSWAFEnforcer: %v", err)
	}
	e.endpoint = srv.URL
	e.retryDelays = nil
	e.limiter = newCFRateLimiter(10000)
	return e
}

func TestAWSWAF_BanUnban_NormalizesCIDR(t *testing.T) {
	mock := newMockWAF("ez-v4", "ez-v6")
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()
	e := newAWSEnforcerForTest(t, srv,
		&AWSIPSetRef{Name: "ez-v4", ID: "id4"}, &AWSIPSetRef{Name: "ez-v6", ID: "id6"})
	ctx := context.Background()

	if err := e.Ban(ctx, sdk.Target{IP: netip.MustParseAddr("203.0.113.7")}); err != nil {
		t.Fatalf("Ban v4: %v", err)
	}
	if !mock.has("ez-v4", "203.0.113.7/32") {
		t.Errorf("v4 address not normalized to /32: %v", mock.list("ez-v4"))
	}

	if err := e.Ban(ctx, sdk.Target{IP: netip.MustParseAddr("2001:db8::7")}); err != nil {
		t.Fatalf("Ban v6: %v", err)
	}
	if !mock.has("ez-v6", "2001:db8::7/128") {
		t.Errorf("v6 address not normalized to /128: %v", mock.list("ez-v6"))
	}

	// A prefix passes through masked; an IPv4-mapped v6 address lands in
	// the v4 set.
	if err := e.Ban(ctx, sdk.Target{Prefix: netip.MustParsePrefix("198.51.100.0/24")}); err != nil {
		t.Fatalf("Ban prefix: %v", err)
	}
	if !mock.has("ez-v4", "198.51.100.0/24") {
		t.Errorf("prefix missing: %v", mock.list("ez-v4"))
	}
	if err := e.Ban(ctx, sdk.Target{IP: netip.MustParseAddr("::ffff:203.0.113.9")}); err != nil {
		t.Fatalf("Ban mapped: %v", err)
	}
	if !mock.has("ez-v4", "203.0.113.9/32") {
		t.Errorf("mapped v4 must land in the v4 set: %v", mock.list("ez-v4"))
	}

	if err := e.Unban(ctx, sdk.Target{IP: netip.MustParseAddr("203.0.113.7")}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if mock.has("ez-v4", "203.0.113.7/32") {
		t.Errorf("unban did not remove the address")
	}
}

func TestAWSWAF_SyncReconciles(t *testing.T) {
	mock := newMockWAF("ez-v4")
	mock.addresses["ez-v4"]["192.0.2.99/32"] = true // stale remote entry
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()
	e := newAWSEnforcerForTest(t, srv, &AWSIPSetRef{Name: "ez-v4", ID: "id4"}, nil)

	want := []sdk.Target{
		{IP: netip.MustParseAddr("203.0.113.1")},
		{IP: netip.MustParseAddr("203.0.113.2")},
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got := mock.list("ez-v4")
	if len(got) != 2 || !mock.has("ez-v4", "203.0.113.1/32") || !mock.has("ez-v4", "203.0.113.2/32") {
		t.Errorf("reconcile wrong, got %v", got)
	}
	if mock.has("ez-v4", "192.0.2.99/32") {
		t.Errorf("stale entry survived the reconcile")
	}
}

func TestAWSWAF_LockConflictRetries(t *testing.T) {
	mock := newMockWAF("ez-v4")
	mock.conflicts = 2 // two writers win before us
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()
	e := newAWSEnforcerForTest(t, srv, &AWSIPSetRef{Name: "ez-v4", ID: "id4"}, nil)

	if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("203.0.113.3")}); err != nil {
		t.Fatalf("Ban should survive %d lock conflicts: %v", 2, err)
	}
	if !mock.has("ez-v4", "203.0.113.3/32") {
		t.Errorf("address missing after retried ban")
	}
}

func TestAWSWAF_LockConflictExhaustion(t *testing.T) {
	mock := newMockWAF("ez-v4")
	mock.conflicts = awsLockRetries + 5 // more conflicts than the budget
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()
	e := newAWSEnforcerForTest(t, srv, &AWSIPSetRef{Name: "ez-v4", ID: "id4"}, nil)

	err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("203.0.113.4")})
	if err == nil || !strings.Contains(err.Error(), "optimistic-lock retries exhausted") {
		t.Fatalf("expected lock-retry exhaustion, got %v", err)
	}
}

func TestAWSWAF_CapacityTruncation(t *testing.T) {
	mock := newMockWAF("ez-v4")
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()
	e := newAWSEnforcerForTest(t, srv, &AWSIPSetRef{Name: "ez-v4", ID: "id4"}, nil)
	e.setCap = 2

	// Sync above capacity keeps the NEWEST (tail of insertion order).
	want := []sdk.Target{
		{IP: netip.MustParseAddr("203.0.113.10")},
		{IP: netip.MustParseAddr("203.0.113.11")},
		{IP: netip.MustParseAddr("203.0.113.12")},
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if mock.has("ez-v4", "203.0.113.10/32") {
		t.Errorf("oldest entry must be dropped at capacity")
	}
	if !mock.has("ez-v4", "203.0.113.11/32") || !mock.has("ez-v4", "203.0.113.12/32") {
		t.Errorf("newest entries must be kept: %v", mock.list("ez-v4"))
	}

	// A ban at capacity evicts the oldest managed entry.
	if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("203.0.113.13")}); err != nil {
		t.Fatalf("Ban at capacity: %v", err)
	}
	if mock.has("ez-v4", "203.0.113.11/32") {
		t.Errorf("ban at capacity must evict the oldest")
	}
	if !mock.has("ez-v4", "203.0.113.13/32") {
		t.Errorf("new ban missing after eviction")
	}
}

func TestAWSWAF_AuthFailure_NoRetryAndNoSecretLeak(t *testing.T) {
	mock := newMockWAF("ez-v4")
	mock.authFail = true
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()
	e := newAWSEnforcerForTest(t, srv, &AWSIPSetRef{Name: "ez-v4", ID: "id4"}, nil)

	err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("203.0.113.5")})
	if err == nil {
		t.Fatalf("expected an auth error")
	}
	if !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Errorf("error should carry the API error type: %v", err)
	}
	if strings.Contains(err.Error(), "test-secret-key-value-do-not-leak") ||
		strings.Contains(err.Error(), "AKIDTEST") {
		t.Errorf("error leaks credentials: %v", err)
	}
}

func TestAWSWAF_AllowlistedRefusedWithoutAPICall(t *testing.T) {
	mock := newMockWAF("ez-v4")
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()
	e := newAWSEnforcerForTest(t, srv, &AWSIPSetRef{Name: "ez-v4", ID: "id4"}, nil)
	e.allowlist = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}

	err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("203.0.113.6")})
	if err == nil || !strings.Contains(err.Error(), "refusing to ban allowlisted") {
		t.Fatalf("expected an allowlist refusal, got %v", err)
	}
	if mock.updates != 0 {
		t.Errorf("allowlisted ban must never reach the API")
	}
}

func TestAWSWAF_NoFamilySetSkipsQuietly(t *testing.T) {
	mock := newMockWAF("ez-v4")
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()
	e := newAWSEnforcerForTest(t, srv, &AWSIPSetRef{Name: "ez-v4", ID: "id4"}, nil)

	// No v6 set designated: a v6 ban is skipped (warned), never an error —
	// the nftables enforcer still covers it locally.
	if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("2001:db8::1")}); err != nil {
		t.Fatalf("v6 ban with no v6 set must not error: %v", err)
	}
}

func TestNewAWSWAFEnforcer_Validation(t *testing.T) {
	t.Parallel()
	if _, err := NewAWSWAFEnforcer(&AWSWAFConfig{Scope: "REGIONAL", IPSetV4: &AWSIPSetRef{Name: "x", ID: "y"}}, nil); err == nil {
		t.Errorf("REGIONAL without region must fail")
	}
	if _, err := NewAWSWAFEnforcer(&AWSWAFConfig{Scope: "bogus", Region: "eu-west-1", IPSetV4: &AWSIPSetRef{Name: "x", ID: "y"}}, nil); err == nil {
		t.Errorf("unknown scope must fail")
	}
	if _, err := NewAWSWAFEnforcer(&AWSWAFConfig{Scope: "REGIONAL", Region: "eu-west-1"}, nil); err == nil {
		t.Errorf("no IPSet designated must fail")
	}
	e, err := NewAWSWAFEnforcer(&AWSWAFConfig{Scope: "CLOUDFRONT", IPSetV4: &AWSIPSetRef{Name: "x", ID: "y"}}, nil)
	if err != nil {
		t.Fatalf("CLOUDFRONT: %v", err)
	}
	if e.region != "us-east-1" {
		t.Errorf("CLOUDFRONT must pin us-east-1, got %s", e.region)
	}
}

// ── Credential chain ─────────────────────────────────────────────────────────

func TestAWSCreds_EnvWins(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
	t.Setenv("AWS_SESSION_TOKEN", "env-token")
	p := newAWSCredProvider()
	c, err := p.credentials(context.Background())
	if err != nil {
		t.Fatalf("credentials: %v", err)
	}
	if c.AccessKeyID != "AKIDENV" || c.SessionToken != "env-token" {
		t.Errorf("env credentials not used: %+v", c.AccessKeyID)
	}
}

func TestAWSCreds_SharedFileAndProfile(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	dir := t.TempDir()
	credFile := filepath.Join(dir, "credentials")
	content := "[default]\naws_access_key_id = AKIDDEFAULT\naws_secret_access_key = s1\n\n" +
		"[prod]\naws_access_key_id = AKIDPROD\naws_secret_access_key = s2\naws_session_token = tok\n"
	if err := os.WriteFile(credFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credFile)

	t.Setenv("AWS_PROFILE", "")
	p := newAWSCredProvider()
	c, err := p.credentials(context.Background())
	if err != nil {
		t.Fatalf("credentials: %v", err)
	}
	if c.AccessKeyID != "AKIDDEFAULT" {
		t.Errorf("default profile not used: %s", c.AccessKeyID)
	}

	t.Setenv("AWS_PROFILE", "prod")
	p2 := newAWSCredProvider()
	c2, err := p2.credentials(context.Background())
	if err != nil {
		t.Fatalf("credentials(prod): %v", err)
	}
	if c2.AccessKeyID != "AKIDPROD" || c2.SessionToken != "tok" {
		t.Errorf("AWS_PROFILE not honored: %s", c2.AccessKeyID)
	}
}

func TestAWSCreds_IMDSv2(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "absent"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				t.Errorf("IMDSv2 token request missing TTL header")
			}
			_, _ = w.Write([]byte("imds-token"))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			if r.Header.Get("X-aws-ec2-metadata-token") != "imds-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("my-role\n"))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/my-role":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Code": "Success", "AccessKeyId": "AKIDIMDS",
				"SecretAccessKey": "imds-secret", "Token": "imds-session",
				"Expiration": time.Now().Add(6 * time.Hour).UTC().Format(time.RFC3339),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", srv.URL)

	p := newAWSCredProvider()
	c, err := p.credentials(context.Background())
	if err != nil {
		t.Fatalf("credentials: %v", err)
	}
	if c.AccessKeyID != "AKIDIMDS" || c.SessionToken != "imds-session" || c.Expiration.IsZero() {
		t.Errorf("IMDS credentials wrong: %+v", c.AccessKeyID)
	}
}
