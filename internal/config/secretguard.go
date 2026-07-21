package config

// Misplaced-credential guard (issue #172). SecretRef fields already reject
// inline values at parse time, but nothing caught a credential pasted into a
// NON-secret field (provider, model, endpoint, ...): the config loaded and
// the value leaked verbatim through `config show` and validation errors —
// observed with a real API key in production. Validate() now scans every
// string leaf of the config for known credential shapes and fails closed,
// naming the field but never echoing the value beyond the same 4-char
// fingerprint SecretRef errors use (redactSecret, issue #13).

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// credentialPrefixes are well-known key formats. Matching is exact-prefix and
// requires the whole value to be at least credPrefixMinLen so short legit
// strings that merely start alike (a hypothetical model "sk-tiny") don't trip.
var credentialPrefixes = []string{
	"sk-",                                  // OpenAI / Anthropic (sk-ant-...)
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", // GitHub tokens
	"github_pat_",                      // GitHub fine-grained PAT
	"glpat-",                           // GitLab PAT
	"xoxb-", "xoxp-", "xoxa-", "xoxs-", // Slack tokens
	"AKIA", "ASIA", // AWS access key IDs
	"AIza", // Google API keys
}

const (
	credPrefixMinLen  = 16
	credGenericMinLen = 32
)

// looksLikeCredential reports whether s resembles a pasted secret. Two rules,
// both deliberately conservative — a false positive here blocks the daemon
// from starting, so legit values (model names, URLs, paths, hex IDs, unit
// names) must never match:
//
//   - a well-known key prefix on a value of credential-like length;
//   - a generic high-entropy shape: >= 32 chars drawn only from the
//     base64/token alphabet, mixing upper case, lower case, and digits.
//     Paths, URLs and model names contain '.', '/' or ':' or lack the case
//     mix (docker IDs and Cloudflare account IDs are lower-hex) and fall
//     through.
func looksLikeCredential(s string) bool {
	if strings.HasPrefix(s, envPrefix) {
		return false // env:VARNAME references are the one sanctioned shape
	}
	if len(s) >= credPrefixMinLen {
		for _, p := range credentialPrefixes {
			if strings.HasPrefix(s, p) {
				return true
			}
		}
	}
	if len(s) < credGenericMinLen {
		return false
	}
	var upper, lower, digit bool
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case r == '+' || r == '/' || r == '=' || r == '_' || r == '-':
			// token alphabet, keeps scanning
		default:
			return false // '.', ':', spaces, ... — not a bare token
		}
	}
	return upper && lower && digit
}

// webhookHeadersPath is the one subtree exempt from the scan: raw header
// values (e.g. an Authorization bearer token) are legal there by design and
// are already redacted in `config show` (see redact.go).
const webhookHeadersPath = "notify.webhook.headers"

// scanForMisplacedSecrets walks every string leaf of the config and returns
// an error for the first value that looks like a pasted credential. The walk
// runs over the YAML round-trip of the struct so any future field is covered
// automatically — adding a field can not silently reopen this hole.
func scanForMisplacedSecrets(c *Config) error {
	raw, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("secret scan: rendering config: %w", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return fmt.Errorf("secret scan: parsing config: %w", err)
	}
	return walkForSecrets(tree, "")
}

func walkForSecrets(node any, path string) error {
	switch v := node.(type) {
	case map[string]any:
		// Deterministic order so the same config always reports the same field.
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			if child == webhookHeadersPath {
				continue
			}
			if err := walkForSecrets(v[k], child); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if err := walkForSecrets(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case string:
		if looksLikeCredential(v) {
			return fmt.Errorf(
				"field %s appears to contain a credential (%s) — secrets never go in config.yaml; use an 'env:VARNAME' reference and put the value in the .env file",
				path, redactSecret(v))
		}
	}
	return nil
}

// enumValueForError renders an invalid enum-ish value for an error message.
// Values that look like credentials — or are simply too long to be a
// plausible enum typo — are fingerprinted instead of echoed, so a pasted key
// that slips past the scan's heuristics still cannot leak through the
// "unknown provider" class of errors.
func enumValueForError(s string) string {
	if looksLikeCredential(s) || len(s) > 40 {
		return redactSecret(s)
	}
	return fmt.Sprintf("%q", s)
}
