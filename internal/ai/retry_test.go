package ai

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// TestMain shrinks the retry backoff base for the whole package: with the
// production 1s base, every test that exhausts a provider retry loop would
// sleep for real seconds (issue #313 made non-429 retries back off too).
func TestMain(m *testing.M) {
	aiBackoffBase = time.Millisecond
	os.Exit(m.Run())
}

// Regression tests for issue #313: uncapped server-controlled Retry-After,
// sleep after the final attempt, immediate (delay=0) retries, and usage
// lost across attempts.

func TestRetryDelay(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		attempt int
		want    time.Duration
	}{
		{"explicit small Retry-After honored", newRateLimitError("openai", "2"), 0, 2 * time.Second},
		{"hostile huge Retry-After capped", newRateLimitError("openai", "3600"), 0, aiRetryAfterCap},
		{"Retry-After zero means no sleep", newRateLimitError("openai", "0"), 0, 0},
		{"unparsable Retry-After falls back to backoff", newRateLimitError("openai", "soon"), 0, aiBackoffBase},
		{"negative Retry-After falls back to backoff", newRateLimitError("openai", "-5"), 1, aiBackoffBase * 2},
		{"non-429 error backs off exponentially", errors.New("boom"), 2, aiBackoffBase * 4},
		{"backoff itself is capped", errors.New("boom"), 60, aiRetryAfterCap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryDelay(tt.err, tt.attempt); got != tt.want {
				t.Errorf("retryDelay = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnalyzeWithRetry_AccumulatesUsageAcrossAttempts(t *testing.T) {
	calls := 0
	verdicts, usage, err := analyzeWithRetry(context.Background(), "test",
		func(context.Context) ([]sdk.Verdict, sdk.Usage, error) {
			calls++
			u := sdk.Usage{InputTokens: 10, OutputTokens: 5, CostUSD: 0.01}
			if calls < 3 {
				return nil, u, errors.New("transient")
			}
			return []sdk.Verdict{{Score: 1}}, u, nil
		})
	if err != nil {
		t.Fatalf("analyzeWithRetry: %v", err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("verdicts = %d, want 1", len(verdicts))
	}
	// Tokens burned by the two failed attempts must be charged too —
	// previously only the last attempt's usage reached the Budget.
	if usage.InputTokens != 30 || usage.OutputTokens != 15 {
		t.Errorf("usage = %+v, want the sum of all 3 attempts", usage)
	}
	if usage.CostUSD < 0.029 || usage.CostUSD > 0.031 {
		t.Errorf("cost = %v, want ~0.03", usage.CostUSD)
	}
}

func TestAnalyzeWithRetry_NoSleepAfterFinalAttempt(t *testing.T) {
	// Every attempt 429s with a (capped) explicit delay of 1s. Sleeps happen
	// only BETWEEN attempts: aiMaxRetries sleeps, not aiMaxRetries+1. With
	// the old loop shape the extra post-final sleep made this take ≥1s more.
	calls := 0
	start := time.Now()
	_, _, err := analyzeWithRetry(context.Background(), "test",
		func(context.Context) ([]sdk.Verdict, sdk.Usage, error) {
			calls++
			return nil, sdk.Usage{}, newRateLimitError("test", "0")
		})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want the final error after exhaustion")
	}
	if calls != aiMaxRetries+1 {
		t.Fatalf("calls = %d, want %d", calls, aiMaxRetries+1)
	}
	// Retry-After: 0 → all sleeps are zero; anything near a real backoff
	// means a sleep ran where none should.
	if elapsed > 500*time.Millisecond {
		t.Errorf("retry loop took %v — it must not sleep after the final attempt (or ignore Retry-After: 0)", elapsed)
	}
}

func TestAnalyzeWithRetry_ContextCancellationStopsRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	_, _, err := analyzeWithRetry(ctx, "test",
		func(context.Context) ([]sdk.Verdict, sdk.Usage, error) {
			calls++
			// Large explicit delay (capped at 30s) — cancellation must win.
			return nil, sdk.Usage{}, newRateLimitError("test", "30")
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (cancelled during the first backoff)", calls)
	}
}
