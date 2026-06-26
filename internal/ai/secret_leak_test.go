// Package ai — AI API-key secret-leak gate tests (SECURITY-REVIEW §4).
//
// The Anthropic API key is set in the Authorization-like header and must never
// appear in error messages, log output, or any other observable string returned
// to callers or written to structured logs.
package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const testAPIKey = "sk-ant-FAKEFAKEFAKEFAKE-SECRETSECRET" //nolint:gosec // G101: intentionally fake key for secret-leak testing

// makeProviderWithKey constructs a provider with the given API key instead of
// relying on config resolution, for direct secret-leak testing.
func makeProviderWithKey(t *testing.T, srv *httptest.Server, apiKey string) *AnthropicProvider {
	t.Helper()
	return &AnthropicProvider{
		apiKey:   apiKey,
		model:    defaultModel,
		endpoint: srv.URL,
		client:   srv.Client(),
	}
}

// TestSecretLeak_APIKey_NotInHTTPError verifies that when the server returns a
// non-200 status, the error string returned by Analyze does not contain the API key.
func TestSecretLeak_APIKey_NotInHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Fallback that captures whether it was called.
	fallbackCalled := false
	fallback := func(_ []sdk.Aggregate) []sdk.Verdict {
		fallbackCalled = true
		return nil
	}

	p := makeProviderWithKey(t, srv, testAPIKey)
	p.fallback = fallback

	agg := sampleAggregate("192.0.2.100")
	_, _, err := p.Analyze(context.Background(), []sdk.Aggregate{agg}, sdk.TokenBudget{Remaining: 10000, DailyLimit: 100000})

	// On HTTP error the provider falls back — no error returned to caller.
	if err != nil {
		// If somehow an error IS returned, it must not contain the key.
		if strings.Contains(err.Error(), testAPIKey) {
			t.Errorf("API key leaked in error: %q", err.Error())
		}
	}
	// Fallback is expected.
	if !fallbackCalled {
		t.Error("expected fallback to be called on HTTP 500")
	}
}

// TestSecretLeak_APIKey_NotInBadJSONError verifies that a malformed JSON response
// does not cause the error path to echo the API key.
func TestSecretLeak_APIKey_NotInBadJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a valid HTTP 200 but with a body that breaks the outer JSON decoder.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("NOT JSON {{{ " + testAPIKey))
	}))
	defer srv.Close()

	fallback := func(_ []sdk.Aggregate) []sdk.Verdict { return nil }
	p := makeProviderWithKey(t, srv, testAPIKey)
	p.fallback = fallback

	agg := sampleAggregate("192.0.2.101")
	_, _, err := p.Analyze(context.Background(), []sdk.Aggregate{agg}, sdk.TokenBudget{Remaining: 10000, DailyLimit: 100000})
	if err != nil && strings.Contains(err.Error(), testAPIKey) {
		t.Errorf("API key leaked in JSON decode error: %q", err.Error())
	}
}

// TestSecretLeak_APIKey_NotSentInRequestBody confirms the key is NOT in the
// request body (it must only be in the x-api-key header, never in the JSON payload).
func TestSecretLeak_APIKey_NotSentInRequestBody(t *testing.T) {
	var requestBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 16384)
		n, _ := r.Body.Read(buf)
		requestBody = string(buf[:n])

		w.Header().Set("Content-Type", "application/json")
		resp := `{"results":[{"ip":"192.0.2.102","score":10,"category":"legitimate","confidence":0.9,"reason":"ok","suggest_ttl_seconds":0}]}`
		_, _ = w.Write([]byte(anthropicResponse(resp, 50, 10)))
	}))
	defer srv.Close()

	p := makeProviderWithKey(t, srv, testAPIKey)
	agg := sampleAggregate("192.0.2.102")

	_, _, err := p.Analyze(context.Background(), []sdk.Aggregate{agg}, sdk.TokenBudget{Remaining: 10000, DailyLimit: 100000})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if strings.Contains(requestBody, testAPIKey) {
		t.Errorf("API key found in request body — must only be in header: %.300s", requestBody)
	}
}
