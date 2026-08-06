package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// ReasonAllowlistClamped is the operator-facing Reason every provider clamp
// stamps on a verdict whose score it zeroed because the target IP is
// allowlisted. It is display-only: Reason is copied from model JSON on every
// other path, so it must never be trusted as a clamp marker.
const ReasonAllowlistClamped = "clamped: allowlisted"

// AllowlistClampSourceSuffix marks a clamped verdict in Source. Source is
// assembled exclusively by provider code ("ai:anthropic", …) and never copied
// from model output, so — unlike Reason — the model cannot forge or suppress
// this marker (Strix finding on #414, CWE-345).
const AllowlistClampSourceSuffix = "+allowlist-clamp"

// IsAllowlistClamped reports whether v is an allowlist-clamped verdict: not a
// model judgment about the behavior, but a policy override tied to the one IP
// that happened to be allowlisted. Such verdicts must never enter the
// behavior-signature cache — the cache is keyed by traffic pattern, not IP, so
// a cached clamp would replay Score 0 onto every non-allowlisted IP sharing
// the signature for a full cache TTL (issue #402, SECURITY-REVIEW §5).
//
// Detection keys on the Source suffix, not Reason: Reason is model-controlled
// text, and matching it would let a prompt-injected response fake a clamp and
// bust the cache (repeat AI consultations for the same signature).
func IsAllowlistClamped(v sdk.Verdict) bool {
	return strings.HasSuffix(v.Source, AllowlistClampSourceSuffix)
}

// boundToBatch drops every verdict whose IP is not one of the analyzed batch
// aggregates' IPs (issue #312, Hard Rule 1, SECURITY-REVIEW §5).
//
// Policy clamps bound the score, TTL, and allowlist — but not the target: a
// hallucinating or compromised model could otherwise name an arbitrary,
// never-observed IP and the decision engine (which acts on best.IP) would ban
// it. Membership is representation-insensitive (IPv4-mapped IPv6 forms compare
// equal to their IPv4 address, cf. #314), and surviving verdicts are rewritten
// to the batch's canonical address so the engine's single-IP invariant holds.
func boundToBatch(ctx context.Context, verdicts []sdk.Verdict, batch []sdk.Aggregate, provider string) []sdk.Verdict {
	if len(verdicts) == 0 {
		return verdicts
	}
	observed := make(map[netip.Addr]netip.Addr, len(batch))
	for _, a := range batch {
		observed[a.IP.Unmap()] = a.IP
	}
	out := make([]sdk.Verdict, 0, len(verdicts))
	for _, v := range verdicts {
		canonical, ok := observed[v.IP.Unmap()]
		if !ok {
			slog.WarnContext(ctx, "ai: dropping verdict for IP not in analyzed batch",
				"provider", provider, "ip", v.IP, "score", v.Score)
			continue
		}
		v.IP = canonical
		out = append(out, v)
	}
	return out
}

// parseVerdictJSON unmarshals an AI provider's raw text response into dst.
//
// It transparently strips a leading Markdown code fence — Claude Haiku 4.5 (and
// several other modern chat models) frequently wrap JSON responses in
// ```json … ``` even when the prompt explicitly asks for raw JSON. Without
// this preprocessing json.Unmarshal fails with "invalid character '`' looking
// for beginning of value" and burns tokens for zero verdicts (see issue #21).
//
// Accepted shapes (case-insensitive on the language hint):
//
//	{"results": ...}
//	```json\n{"results": ...}\n```
//	```JSON\r\n{"results": ...}\r\n```
//	   ```   \n{"results": ...}\n```   (whitespace-tolerant on both ends)
//
// A malformed JSON body after strip still returns an error — the strip is
// intentionally forgiving of the wrapper, strict about the payload.
func parseVerdictJSON(text string, dst any) error {
	trimmed := strings.TrimSpace(text)
	body := stripCodeFence(trimmed)
	if err := json.Unmarshal([]byte(body), dst); err != nil {
		return fmt.Errorf("parse verdict JSON: %w", err)
	}
	return nil
}

// stripCodeFence removes a leading ```<lang>?\n and a trailing \n``` from s
// when both are present. If either fence is missing, s is returned as-is so
// callers that pass raw JSON keep working. The check is line-oriented so an
// unrelated backtick appearing inside the JSON body (e.g. inside a "reason"
// string) does not confuse the strip.
func stripCodeFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	// Drop everything up to and including the first newline of the opening
	// fence — that captures "```", "```json", "```JSON", "```  json  ", etc.
	openNL := strings.IndexByte(s, '\n')
	if openNL < 0 {
		// Single-line "```json{...}```" isn't a shape we've seen in practice
		// and would be ambiguous to parse safely, so leave it to Unmarshal to
		// reject with a normal JSON error.
		return s
	}
	body := s[openNL+1:]

	// Trim a trailing ``` (with optional whitespace / newlines around it).
	// Strip whitespace first so ``` at the very end matches regardless of a
	// stray trailing newline the model might emit.
	body = strings.TrimRight(body, " \t\r\n")
	if strings.HasSuffix(body, "```") {
		body = strings.TrimSuffix(body, "```")
		body = strings.TrimRight(body, " \t\r\n")
	}
	return body
}
