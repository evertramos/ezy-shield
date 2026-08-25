package ai

// retry.go — one retry policy for every AI provider (issue #313).
//
// Before this file each provider had its own loop with drifting semantics:
// OpenAI honored an UNCAPPED server-controlled Retry-After inside the
// daemon's synchronous event loop (a 429 with Retry-After: 3600 stalled all
// detection for an hour — §8: API responses are untrusted), slept even
// after the final attempt before falling back, and retried non-429
// failures with delay=0 (§10: never retry with delay=0); Anthropic had no
// 429 handling at all and retried immediately; and every provider reported
// only the LAST attempt's token usage, so tokens burned by failed attempts
// were never charged to the Budget.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	// aiMaxRetries is the number of retries after the first attempt, shared
	// by every provider (previously 3 for OpenAI, 1 for Anthropic/Ollama).
	aiMaxRetries = 3
	// aiRetryAfterCap bounds every inter-attempt delay — the exponential
	// backoff AND a server-controlled Retry-After. Analyze runs
	// synchronously on the daemon's event loop, so the cap is the maximum
	// time a misbehaving or hostile API can stall detection per attempt;
	// past it the rules fallback covers.
	aiRetryAfterCap = 30 * time.Second
)

// rateLimitError signals an HTTP 429 so the retry loop can back off.
// hasExplicitDelay distinguishes "Retry-After: 0" (no sleep) from an absent
// or unparsable header (exponential backoff).
type rateLimitError struct {
	provider         string
	retryAfter       time.Duration
	hasExplicitDelay bool
}

func (e *rateLimitError) Error() string {
	return fmt.Sprintf("%s: rate limited (retry after %v)", e.provider, e.retryAfter)
}

// newRateLimitError builds the 429 signal from a Retry-After header value.
// hasExplicitDelay is set only when the header parses to a non-negative
// integer (§10: never treat a merely-present header as a parsed delay).
func newRateLimitError(provider, retryAfterHeader string) *rateLimitError {
	rle := &rateLimitError{provider: provider}
	if retryAfterHeader != "" {
		if secs, err := strconv.Atoi(retryAfterHeader); err == nil && secs >= 0 {
			rle.hasExplicitDelay = true
			rle.retryAfter = time.Duration(secs) * time.Second
		}
	}
	return rle
}

// aiBackoffBase is the exponential-backoff base delay. A package-level var
// only so the test suite can shrink it (retry loops would otherwise sleep
// for real seconds); production code never mutates it.
var aiBackoffBase = time.Second

// retryDelay returns the bounded pause before the next attempt: a parsed
// Retry-After when the failure was a 429 with one, else exponential backoff
// from aiBackoffBase — both capped at aiRetryAfterCap.
func retryDelay(err error, attempt int) time.Duration {
	var rle *rateLimitError
	if errors.As(err, &rle) && rle.hasExplicitDelay {
		return min(rle.retryAfter, aiRetryAfterCap)
	}
	// Guard the shift against overflow: attempt is a small loop index in
	// production (≤ aiMaxRetries), but a duration gone negative through a
	// large shift would mean "no delay" — the exact bug class this file
	// exists to remove.
	d := aiBackoffBase << uint(min(attempt, 30)) //nolint:gosec // shift bounded to 30
	if d <= 0 || d > aiRetryAfterCap {
		return aiRetryAfterCap
	}
	return d
}

// analyzeWithRetry runs callOnce up to aiMaxRetries+1 times with bounded
// backoff and accumulates usage across ALL attempts, so tokens burned by
// failed calls are still charged to the Budget. It never sleeps after the
// final attempt (the caller's fallback should not be delayed), and returns
// the accumulated usage together with the last error on exhaustion.
func analyzeWithRetry(ctx context.Context, provider string,
	callOnce func(context.Context) ([]sdk.Verdict, sdk.Usage, error),
) ([]sdk.Verdict, sdk.Usage, error) {
	var (
		total   sdk.Usage
		callErr error
	)
	for attempt := 0; attempt <= aiMaxRetries; attempt++ {
		var (
			verdicts []sdk.Verdict
			u        sdk.Usage
		)
		verdicts, u, callErr = callOnce(ctx)
		total = addUsage(total, u)
		if callErr == nil {
			return verdicts, total, nil
		}
		if attempt == aiMaxRetries {
			break
		}
		delay := retryDelay(callErr, attempt)
		slog.WarnContext(ctx, "ai: attempt failed, backing off",
			"provider", provider, "attempt", attempt+1, "delay", delay, "err", callErr)
		select {
		case <-ctx.Done():
			return nil, total, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, total, callErr
}

// addUsage sums two usage reports.
func addUsage(a, b sdk.Usage) sdk.Usage {
	return sdk.Usage{
		InputTokens:  a.InputTokens + b.InputTokens,
		OutputTokens: a.OutputTokens + b.OutputTokens,
		CostUSD:      a.CostUSD + b.CostUSD,
	}
}
