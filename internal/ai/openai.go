package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	openaiEndpoint     = "https://api.openai.com/v1/chat/completions"
	openaiDefaultModel = "gpt-4o-mini"
	maxOpenAIRetries   = 3
	// gpt-4o-mini pricing in USD per token.
	openaiInputCostPerToken  = 1.5e-7 // $0.15 / 1M input tokens
	openaiOutputCostPerToken = 6e-7   // $0.60 / 1M output tokens
)

// openaiRateLimitError signals a 429 response so Analyze can apply backoff.
// hasExplicitDelay distinguishes "Retry-After: 0" (no sleep) from header absent (use backoff).
type openaiRateLimitError struct {
	retryAfter       time.Duration
	hasExplicitDelay bool
}

func (e *openaiRateLimitError) Error() string {
	return fmt.Sprintf("openai: rate limited (retry after %v)", e.retryAfter)
}

// OpenAIProvider implements sdk.AIProvider using the OpenAI Chat Completions API.
// The API key is resolved from config at construction time and never logged.
type OpenAIProvider struct {
	apiKey    string
	model     string
	endpoint  string // overridable in tests
	client    *http.Client
	allowlist []netip.Prefix
	maxTTL    time.Duration
	fallback  RulesFunc
}

// NewOpenAIProvider creates an OpenAIProvider from config.
// apiKey is resolved via SecretRef (env: only); allowlist and maxTTL enforce
// policy bounds on AI verdicts (Hard Rule §1, §5 from AGENTS.md).
func NewOpenAIProvider(
	cfg *config.AICfg,
	allowlist []netip.Prefix,
	maxTTL time.Duration,
	fallback RulesFunc,
) (*OpenAIProvider, error) {
	key, err := cfg.APIKey.Resolve()
	if err != nil {
		return nil, fmt.Errorf("ai: openai api_key: %w", err)
	}
	model := cfg.Model
	if model == "" {
		model = openaiDefaultModel
	}
	return &OpenAIProvider{
		apiKey:    key,
		model:     model,
		endpoint:  openaiEndpoint,
		client:    &http.Client{Timeout: 30 * time.Second},
		allowlist: allowlist,
		maxTTL:    maxTTL,
		fallback:  fallback,
	}, nil
}

// Name implements sdk.AIProvider.
func (p *OpenAIProvider) Name() string { return "openai" }

// Analyze implements sdk.AIProvider.
// Aggregates are serialised as JSON data and wrapped in a system prompt that
// instructs the model to treat log content as untrusted data, not instructions
// (§5 SECURITY-REVIEW.md). Non-conforming responses trigger retries; after
// exhausting retries the rules fallback runs and no error is surfaced to the caller.
// 429 responses receive exponential backoff before each retry.
func (p *OpenAIProvider) Analyze(
	ctx context.Context,
	batch []sdk.Aggregate,
	budget sdk.TokenBudget,
) ([]sdk.Verdict, sdk.Usage, error) {
	if len(batch) == 0 {
		return nil, sdk.Usage{}, nil
	}

	payload, err := buildPayload(batch)
	if err != nil {
		return nil, sdk.Usage{}, fmt.Errorf("ai: build payload: %w", err)
	}

	prompt := buildPrompt(payload, budget)

	var (
		verdicts []sdk.Verdict
		usage    sdk.Usage
		callErr  error
	)
	for attempt := 0; attempt <= maxOpenAIRetries; attempt++ {
		verdicts, usage, callErr = p.callOnce(ctx, prompt)
		if callErr == nil {
			break
		}

		var rle *openaiRateLimitError
		if errors.As(callErr, &rle) {
			delay := rle.retryAfter
			if !rle.hasExplicitDelay {
				delay = time.Duration(1<<uint(attempt)) * time.Second
			}
			slog.WarnContext(ctx, "ai: openai rate limited, backing off",
				"attempt", attempt+1, "delay", delay)
			select {
			case <-ctx.Done():
				return nil, usage, ctx.Err()
			case <-time.After(delay):
			}
			continue
		}

		slog.WarnContext(ctx, "ai: openai attempt failed",
			"attempt", attempt+1, "err", callErr)
	}

	if callErr != nil {
		if p.fallback != nil {
			slog.WarnContext(ctx, "ai: openai falling back to rules engine",
				"attempts", maxOpenAIRetries+1, "err", callErr)
			return p.fallback(batch), usage, nil
		}
		return nil, usage, fmt.Errorf("ai: openai: %w", callErr)
	}

	verdicts = p.clamp(ctx, verdicts)
	return verdicts, usage, nil
}

func (p *OpenAIProvider) callOnce(ctx context.Context, prompt string) ([]sdk.Verdict, sdk.Usage, error) {
	reqBody := map[string]any{
		"model":      p.model,
		"max_tokens": maxTokens,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, sdk.Usage{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, sdk.Usage{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, sdk.Usage{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only close

	if resp.StatusCode == http.StatusTooManyRequests {
		rle := &openaiRateLimitError{}
		if s := resp.Header.Get("Retry-After"); s != "" {
			if secs, parseErr := strconv.Atoi(s); parseErr == nil {
				rle.hasExplicitDelay = true
				rle.retryAfter = time.Duration(secs) * time.Second
			}
		}
		return nil, sdk.Usage{}, rle
	}

	if resp.StatusCode != http.StatusOK {
		return nil, sdk.Usage{}, fmt.Errorf("openai API returned status %d", resp.StatusCode)
	}

	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, sdk.Usage{}, fmt.Errorf("decode response: %w", err)
	}

	usage := sdk.Usage{
		InputTokens:  apiResp.Usage.PromptTokens,
		OutputTokens: apiResp.Usage.CompletionTokens,
		CostUSD: float64(apiResp.Usage.PromptTokens)*openaiInputCostPerToken +
			float64(apiResp.Usage.CompletionTokens)*openaiOutputCostPerToken,
	}

	if len(apiResp.Choices) == 0 || apiResp.Choices[0].Message.Content == "" {
		return nil, usage, fmt.Errorf("no content in response")
	}
	text := apiResp.Choices[0].Message.Content

	var schema verdictSchema
	if err := parseVerdictJSON(text, &schema); err != nil {
		return nil, usage, err
	}
	if len(schema.Results) == 0 {
		return nil, usage, fmt.Errorf("empty results in response")
	}

	verdicts := make([]sdk.Verdict, 0, len(schema.Results))
	for _, r := range schema.Results {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil {
			slog.WarnContext(ctx, "ai: skipping verdict with invalid IP", "ip", r.IP)
			continue
		}
		score := r.Score
		if score < 0 {
			score = 0
		} else if score > 100 {
			score = 100
		}
		verdicts = append(verdicts, sdk.Verdict{
			IP:         ip,
			Score:      score,
			Category:   r.Category,
			Confidence: r.Confidence,
			Reason:     r.Reason,
			Source:     "ai:openai",
			SuggestTTL: time.Duration(r.SuggestTTLSecs) * time.Second,
		})
	}
	return verdicts, usage, nil
}

// clamp enforces policy bounds on AI verdicts (Hard Rule §1, SECURITY-REVIEW §2, §5):
//   - Allowlisted IPs have score zeroed — the model can never cause a ban on them.
//   - SuggestTTL is capped at maxTTL when maxTTL > 0.
func (p *OpenAIProvider) clamp(ctx context.Context, verdicts []sdk.Verdict) []sdk.Verdict {
	out := make([]sdk.Verdict, 0, len(verdicts))
	for _, v := range verdicts {
		for _, pfx := range p.allowlist {
			if pfx.Contains(v.IP) {
				slog.WarnContext(ctx, "ai: clamping verdict for allowlisted IP",
					"ip", v.IP, "original_score", v.Score)
				v.Score = 0
				v.Reason = "clamped: allowlisted"
				v.SuggestTTL = 0
				break
			}
		}
		if p.maxTTL > 0 && v.SuggestTTL > p.maxTTL {
			v.SuggestTTL = p.maxTTL
		}
		out = append(out, v)
	}
	return out
}
