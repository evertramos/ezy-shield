package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	ollamaDefaultEndpoint = "http://localhost:11434"
	ollamaDefaultModel    = "llama3.1:8b"
	ollamaTimeout         = 60 * time.Second
	maxOllamaRetries      = 1
)

// OllamaProvider implements sdk.AIProvider using the Ollama /api/chat endpoint.
// No API key is required — Ollama runs locally and inference is free.
type OllamaProvider struct {
	model     string
	endpoint  string // full /api/chat URL; overridable in tests
	client    *http.Client
	allowlist []netip.Prefix
	maxTTL    time.Duration
	fallback  RulesFunc
}

// NewOllamaProvider creates an OllamaProvider from config.
// No API key is needed. allowlist and maxTTL enforce policy bounds on AI verdicts
// (Hard Rule §1, §5 from AGENTS.md).
func NewOllamaProvider(
	cfg *config.AICfg,
	allowlist []netip.Prefix,
	maxTTL time.Duration,
	fallback RulesFunc,
) (*OllamaProvider, error) {
	model := cfg.Model
	if model == "" {
		model = ollamaDefaultModel
	}
	base := cfg.Endpoint
	if base == "" {
		base = ollamaDefaultEndpoint
	}
	return &OllamaProvider{
		model:     model,
		endpoint:  base + "/api/chat",
		client:    &http.Client{Timeout: ollamaTimeout},
		allowlist: allowlist,
		maxTTL:    maxTTL,
		fallback:  fallback,
	}, nil
}

// Name implements sdk.AIProvider.
func (p *OllamaProvider) Name() string { return "ollama" }

// Analyze implements sdk.AIProvider.
// Aggregates are serialised as JSON data and wrapped in a prompt that instructs
// the model to treat log content as untrusted data, not instructions
// (§5 SECURITY-REVIEW.md). Non-conforming responses trigger one retry; after
// that the rules fallback runs and no error is surfaced to the caller.
func (p *OllamaProvider) Analyze(
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
	for attempt := 0; attempt <= maxOllamaRetries; attempt++ {
		verdicts, usage, callErr = p.callOnce(ctx, prompt)
		if callErr == nil {
			break
		}
		slog.WarnContext(ctx, "ai: ollama attempt failed",
			"attempt", attempt+1, "err", callErr)
	}

	if callErr != nil {
		if p.fallback != nil {
			slog.WarnContext(ctx, "ai: ollama falling back to rules engine",
				"attempts", maxOllamaRetries+1, "err", callErr)
			return p.fallback(batch), usage, nil
		}
		return nil, usage, fmt.Errorf("ai: ollama: %w", callErr)
	}

	verdicts = p.clamp(ctx, verdicts)
	return verdicts, usage, nil
}

func (p *OllamaProvider) callOnce(ctx context.Context, prompt string) ([]sdk.Verdict, sdk.Usage, error) {
	reqBody := map[string]any{
		"model":  p.model,
		"stream": false,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
		"options": map[string]any{
			"temperature": 0.1,
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

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, sdk.Usage{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only close

	if resp.StatusCode != http.StatusOK {
		return nil, sdk.Usage{}, fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var apiResp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		EvalCount       int `json:"eval_count"`
		PromptEvalCount int `json:"prompt_eval_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, sdk.Usage{}, fmt.Errorf("decode response: %w", err)
	}

	usage := sdk.Usage{
		InputTokens:  apiResp.PromptEvalCount,
		OutputTokens: apiResp.EvalCount,
		CostUSD:      0, // local inference — no billing cost
	}

	if apiResp.Message.Content == "" {
		return nil, usage, fmt.Errorf("no content in response")
	}

	var schema verdictSchema
	if err := json.Unmarshal([]byte(apiResp.Message.Content), &schema); err != nil {
		return nil, usage, fmt.Errorf("parse verdict JSON: %w", err)
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
			Source:     "ai:ollama",
			SuggestTTL: time.Duration(r.SuggestTTLSecs) * time.Second,
		})
	}
	return verdicts, usage, nil
}

// clamp enforces policy bounds on AI verdicts (Hard Rule §1, SECURITY-REVIEW §2, §5):
//   - Allowlisted IPs have score zeroed — the model can never cause a ban on them.
//   - SuggestTTL is capped at maxTTL when maxTTL > 0.
func (p *OllamaProvider) clamp(ctx context.Context, verdicts []sdk.Verdict) []sdk.Verdict {
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
