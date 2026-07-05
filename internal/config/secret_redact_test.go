package config_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// TestSecret_StringRedacts satisfies issue #13 §6: the Secret wrapper must
// render as "<redacted>" via every format verb the runtime might use — %s,
// %v, %+v, %#v — and via json.Marshal. Any struct that embeds a Secret then
// automatically inherits the redaction on any log line or error wrap.
func TestSecret_StringRedacts(t *testing.T) {
	t.Parallel()
	const raw = "sk-ant-VERY-SECRET-tail-part-9999" //nolint:gosec // G101: test fake
	s := config.NewSecret(raw)

	// Direct calls.
	if got := s.String(); got != "<redacted>" {
		t.Errorf("String() = %q, want <redacted>", got)
	}
	if got := s.GoString(); got != "<redacted>" {
		t.Errorf("GoString() = %q, want <redacted>", got)
	}

	// Format verbs.
	for _, verb := range []string{"%s", "%v", "%+v", "%#v"} {
		got := fmt.Sprintf(verb, s)
		if strings.Contains(got, raw) {
			t.Errorf("Sprintf(%q, secret) leaks raw token: %q", verb, got)
		}
		if !strings.Contains(got, "<redacted>") {
			t.Errorf("Sprintf(%q, secret) = %q, expected <redacted>", verb, got)
		}
	}

	// Nested in a struct dump — the most common leak path.
	type holder struct {
		Name  string
		Token config.Secret
	}
	h := holder{Name: "anthropic", Token: s}
	dump := fmt.Sprintf("%+v", h)
	if strings.Contains(dump, raw) {
		t.Errorf("struct dump leaks token: %q", dump)
	}
	if !strings.Contains(dump, "<redacted>") {
		t.Errorf("struct dump missing <redacted>: %q", dump)
	}

	// JSON — MarshalJSON must NOT expose the raw token.
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(b), raw) {
		t.Errorf("JSON leaks token: %s", string(b))
	}
	// json.Marshal HTML-escapes '<' and '>' by default (< / >),
	// so we test for the redacted marker in its escaped form OR the raw form.
	if !strings.Contains(string(b), "redacted") {
		t.Errorf("JSON missing 'redacted' marker: %s", string(b))
	}

	// Reveal is the ONLY path that returns the plaintext.
	if s.Reveal() != raw {
		t.Errorf("Reveal() = %q, want %q", s.Reveal(), raw)
	}
	if !s.IsSet() {
		t.Errorf("IsSet() = false, want true")
	}

	// Empty Secret still redacts (never returns a hint about "empty" vs "set").
	empty := config.NewSecret("")
	if empty.String() != "<redacted>" {
		t.Errorf("empty Secret String() = %q, want <redacted>", empty.String())
	}
	if empty.IsSet() {
		t.Errorf("empty Secret IsSet() = true, want false")
	}
}

// TestLoader_NoTokenInError covers issue #13 §6: when the env var referenced
// by a SecretRef is not set (or holds the placeholder), Resolve() returns
// ErrAPIKeyMissing without echoing any part of what was there.
//
// Subtests use t.Setenv, which is incompatible with t.Parallel — hence no
// t.Parallel on either the parent or the subtests.
func TestLoader_NoTokenInError(t *testing.T) {
	t.Run("env unset", func(t *testing.T) {
		ref := config.SecretRef("env:EZYSHIELD_TEST_UNSET_NOLEAK_XYZ")
		_, err := ref.Resolve()
		if err == nil {
			t.Fatal("expected error for unset var")
		}
		if err.Error() != config.ErrAPIKeyMissing.Error() {
			t.Errorf("Resolve() err = %q, want %q", err.Error(), config.ErrAPIKeyMissing.Error())
		}
	})

	t.Run("env set to placeholder", func(t *testing.T) {
		t.Setenv("EZYSHIELD_TEST_PLACEHOLDER_NOLEAK", config.PlaceholderAPIKey)
		ref := config.SecretRef("env:EZYSHIELD_TEST_PLACEHOLDER_NOLEAK")
		_, err := ref.Resolve()
		if err == nil {
			t.Fatal("expected error for placeholder value")
		}
		if err.Error() != config.ErrAPIKeyMissing.Error() {
			t.Errorf("Resolve() err = %q, want %q", err.Error(), config.ErrAPIKeyMissing.Error())
		}
		// And the fixed error text explicitly points at .env.
		if !strings.Contains(err.Error(), ".env") {
			t.Errorf("Resolve() err = %q — spec requires a pointer to .env", err.Error())
		}
	})

	t.Run("env set to empty string", func(t *testing.T) {
		t.Setenv("EZYSHIELD_TEST_EMPTY_NOLEAK", "")
		ref := config.SecretRef("env:EZYSHIELD_TEST_EMPTY_NOLEAK")
		_, err := ref.Resolve()
		if err == nil {
			t.Fatal("expected error for empty value")
		}
		if err.Error() != config.ErrAPIKeyMissing.Error() {
			t.Errorf("Resolve() err = %q, want %q", err.Error(), config.ErrAPIKeyMissing.Error())
		}
	})

	t.Run("env set to real token succeeds", func(t *testing.T) {
		const tok = "sk-ant-real-9999" //nolint:gosec // G101: test fake
		t.Setenv("EZYSHIELD_TEST_REAL_TOKEN", tok)
		ref := config.SecretRef("env:EZYSHIELD_TEST_REAL_TOKEN")
		got, err := ref.Resolve()
		if err != nil {
			t.Fatalf("Resolve() err = %v", err)
		}
		if got != tok {
			t.Errorf("Resolve() = %q, want %q", got, tok)
		}
	})
}
