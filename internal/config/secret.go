package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const envPrefix = "env:"

// envVarNameRe matches a POSIX shell identifier: [A-Za-z_][A-Za-z0-9_]*.
// SecretRef "env:VARNAME" references and wizard prompts asking for a variable
// name must both match this. Anything else is almost certainly the operator
// pasting the secret itself into the wrong prompt (see issue #13).
var envVarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// knownSecretPrefixes lists prefixes of well-known API credentials. When the
// operator pastes a real key where an env-var NAME was expected, catching the
// prefix produces a much clearer rejection than the generic identifier check.
// This list is intentionally short — false positives (an env var literally
// starting with "sk-") are impossible because those aren't valid env-var names
// anyway (they contain "-"), but callers should always run the identifier
// check first regardless.
var knownSecretPrefixes = []string{
	"sk-",
	"sk-ant-",
	"sk_live_",
	"pk-",
	"xoxb-",
	"xoxp-",
	"ghp_",
	"gho_",
	"github_pat_",
}

// SecretRef is a config field that must hold an "env:VARNAME" reference.
// Inline secret values are rejected at load time — secrets must never appear
// in config files. An empty SecretRef is valid and means the field is unset.
type SecretRef string

// UnmarshalYAML rejects any value that is non-empty and lacks the "env:" prefix,
// or whose "env:VARNAME" portion is not a valid POSIX shell identifier. Error
// messages never echo the raw value — only a redacted fingerprint (see
// redactSecret) — so a hand-edited config that pastes the API key after "env:"
// cannot leak the secret into logs or the journal (issue #13).
func (s *SecretRef) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("line %d: %w", value.Line, err)
	}
	if raw == "" {
		*s = ""
		return nil
	}
	if !strings.HasPrefix(raw, envPrefix) {
		return fmt.Errorf(
			"line %d: secret field must use 'env:VARNAME' reference, not an inline value (got %s)",
			value.Line, redactSecret(raw))
	}
	varName := strings.TrimPrefix(raw, envPrefix)
	if err := validateEnvVarName(varName); err != nil {
		return fmt.Errorf("line %d: secret field 'env:' reference: %w", value.Line, err)
	}
	*s = SecretRef(raw)
	return nil
}

// IsSet reports whether the reference is non-empty (i.e., the field is configured).
func (s SecretRef) IsSet() bool {
	return string(s) != ""
}

// Resolve looks up the referenced environment variable and returns its value.
// Returns an error if the reference is empty, malformed, or the variable is not
// set. Malformed references — the classic issue #13 case where the operator
// pasted an API key where a var NAME was expected and it ended up in
// config.yaml as "api_key: env:sk-ant-..." — are rejected with a REDACTED
// error message so the key never reaches the journal.
//
// When the env var is set but empty or the literal placeholder written by the
// init wizard (§5 of issue #13), the returned error uses the operator-facing
// phrasing "AI API key missing — check /etc/ezyshield/.env" and never echoes
// the referenced variable name back into the message (defense-in-depth: even
// though the name isn't the secret, matching one specific string is easier
// than trying to filter journald ex-post).
func (s SecretRef) Resolve() (string, error) {
	if !s.IsSet() {
		return "", fmt.Errorf("secret reference is not configured")
	}
	if !strings.HasPrefix(string(s), envPrefix) {
		return "", fmt.Errorf(
			"secret reference is malformed: missing 'env:' prefix (got %s)",
			redactSecret(string(s)))
	}
	varName := strings.TrimPrefix(string(s), envPrefix)
	if err := validateEnvVarName(varName); err != nil {
		return "", fmt.Errorf("secret reference is malformed: %w", err)
	}
	v, ok := os.LookupEnv(varName)
	if !ok || v == "" || v == PlaceholderAPIKey {
		return "", ErrAPIKeyMissing
	}
	return v, nil
}

// PlaceholderAPIKey is the exact string written into /etc/ezyshield/.env by
// `ezyshield init` when the operator skips the token prompt (issue #13 §5).
// The loader treats this value as equivalent to "unset" so a stale placeholder
// never gets sent to a real AI provider.
const PlaceholderAPIKey = "YOUR_API_KEY_HERE" //nolint:gosec // G101: literal placeholder — deliberately public, treated as "unset" by Resolve so it can never be forwarded to a real AI provider (issue #13 §5).

// ErrAPIKeyMissing is the operator-facing error surfaced whenever an AI
// SecretRef fails to resolve to a real token. Deliberately generic — it
// points the operator at the .env file without echoing the referenced env
// var name, the previous value, or any part of the referenced string. This
// matches issue #13 §6 ("error is: 'AI API key missing — check
// /etc/ezyshield/.env' — no reference to what was there").
var ErrAPIKeyMissing = fmt.Errorf("AI API key missing — check /etc/ezyshield/.env")

// Secret wraps a resolved credential token in a type whose String()/GoString()/
// Format() methods return "<redacted>". Struct dumps (%+v, %v), log lines,
// json.Marshal, and error-wrapping all see the redacted form; callers that
// actually need the plaintext must go through Reveal(). This exists to satisfy
// issue #13 §6 ("Redact in any struct dump / %+v / test helper by implementing
// String() string on the secret type that returns \"<redacted>\"") and
// SECURITY-REVIEW.md §4 (secrets never in logs/errors).
type Secret struct {
	v string
}

// NewSecret wraps v in a Secret. The caller is responsible for having sourced
// v from an env var / systemd LoadCredential and NOT from an inline config
// value (SecretRef.UnmarshalYAML already rejects the latter).
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the raw token. Callers must use this ONLY to hand the token
// to the outbound HTTP request (Authorization header etc.) — never in a log
// message, error message, or format string. Grep the diff for Reveal() to
// audit call sites.
func (s Secret) Reveal() string { return s.v }

// IsSet reports whether the wrapped value is non-empty.
func (s Secret) IsSet() bool { return s.v != "" }

// String implements fmt.Stringer and is the format verb %s / %v receives.
// Always returns the fixed redaction marker; the raw token never appears.
func (s Secret) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer so `%#v` also redacts.
func (s Secret) GoString() string { return "<redacted>" }

// MarshalJSON keeps Secret out of JSON dumps. Emitting the redacted string
// rather than an empty object makes accidental Marshal calls visible in tests
// without leaking the token.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"<redacted>"`), nil
}

// ValidateEnvVarName is the exported form of validateEnvVarName so the init
// wizard (in cmd/ezyshield) can enforce the same rules at prompt time. Returns
// nil if name is a valid POSIX shell identifier and does NOT look like a
// well-known secret. All error messages are redacted — they never echo name
// verbatim.
func ValidateEnvVarName(name string) error {
	return validateEnvVarName(name)
}

// validateEnvVarName enforces two invariants on operator-supplied env-var
// names:
//  1. Must be a valid POSIX shell identifier: ^[A-Za-z_][A-Za-z0-9_]*$
//  2. Must not start with a well-known secret prefix (issue #13 catches
//     paste-mistakes where the operator pasted the key instead of the name).
//
// Errors are redacted so callers can safely log/echo them.
func validateEnvVarName(name string) error {
	if name == "" {
		return fmt.Errorf("env var name is empty")
	}
	for _, p := range knownSecretPrefixes {
		if strings.HasPrefix(name, p) {
			return fmt.Errorf(
				"input looks like an API key (%s), not an env var name — "+
					"type ONLY the variable NAME (e.g. ANTHROPIC_API_KEY), never the key itself",
				redactSecret(name))
		}
	}
	if !envVarNameRe.MatchString(name) {
		return fmt.Errorf(
			"env var name must match [A-Za-z_][A-Za-z0-9_]* (got %s)",
			redactSecret(name))
	}
	return nil
}

// RedactSecret is the exported form of redactSecret for use by other packages
// (notably the init wizard) that need to log an operator-supplied string that
// may or may not be a secret. See redactSecret for the format.
func RedactSecret(s string) string {
	return redactSecret(s)
}

// redactSecret produces a short, non-reversible fingerprint of s suitable for
// error messages. Format: "<first-4-chars>..(<total-len> chars)". Anything
// shorter than 5 characters shows only the length so we never leak a short
// literal. Empty input returns "<empty>".
//
// The point is that operators can still tell "yes that's roughly what I
// pasted" from the fingerprint without the raw value being recoverable from
// journald / stderr / a copied error string.
func redactSecret(s string) string {
	n := len(s)
	if n == 0 {
		return "<empty>"
	}
	if n < 5 {
		return fmt.Sprintf("..(%d chars)", n)
	}
	return fmt.Sprintf("%s..(%d chars)", s[:4], n)
}
