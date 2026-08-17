package enforce

// Internal unit tests for the throttle-classification and backoff helpers
// (issue #445). The end-to-end retry behaviour is covered from the outside in
// cloudflare_lists_test.go; these pin the pure helpers.

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"5", 5 * time.Second},
		{" 2 ", 2 * time.Second},
		{"0", 0},
		{"-3", 0},
		{"garbage", 0},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0}, // HTTP-date form: no hint
	}
	for _, tc := range cases {
		if got := parseRetryAfter(tc.in); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCFIsThrottle(t *testing.T) {
	cases := []struct {
		name   string
		status int
		errs   []cfAPIError
		want   bool
	}{
		{"http 429 no body", http.StatusTooManyRequests, nil, true},
		{"code 10040", http.StatusOK, []cfAPIError{{Code: 10040, Message: "ratelimited"}}, true},
		{"code 971", http.StatusOK, []cfAPIError{{Code: 971, Message: "throttle"}}, true},
		{"real failure", http.StatusOK, []cfAPIError{{Code: 1004, Message: "bad payload"}}, false},
		{"success shape", http.StatusOK, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfIsThrottle(tc.status, tc.errs); got != tc.want {
				t.Errorf("cfIsThrottle(%d, %v) = %v, want %v", tc.status, tc.errs, got, tc.want)
			}
		})
	}
}

func TestCFBackoffWait_CtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := cfBackoffWait(ctx, []time.Duration{time.Hour}, 0, 0)
	if err == nil {
		t.Fatal("cfBackoffWait with canceled ctx returned nil, want ctx error")
	}
}

func TestCFBackoffWait_AttemptClampsToSchedule(t *testing.T) {
	// An attempt index past the schedule must clamp to the last delay, not
	// panic. Delays are tiny so the test stays fast.
	if err := cfBackoffWait(context.Background(), []time.Duration{time.Millisecond}, 5, 0); err != nil {
		t.Fatalf("cfBackoffWait: %v", err)
	}
}
