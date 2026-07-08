package dashboard

import (
	"strings"
	"testing"
)

func TestHashPassword_RoundTrip(t *testing.T) {
	pw := "correct-horse-battery-staple"
	h, err := hashPassword(pw)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(h, pbkdf2Prefix+"$") {
		t.Errorf("hash missing algorithm prefix: %q", h)
	}
	if strings.Contains(h, pw) {
		t.Fatalf("hash must not contain plaintext password")
	}
	if !verifyPassword(h, pw) {
		t.Fatal("verifyPassword should accept the round-tripped password")
	}
	if verifyPassword(h, pw+"x") {
		t.Fatal("verifyPassword should reject a modified password")
	}
}

func TestHashPassword_SaltsDiffer(t *testing.T) {
	pw := "same-password"
	a, err := hashPassword(pw)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	b, err := hashPassword(pw)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
}

func TestVerifyPassword_MalformedHashRejects(t *testing.T) {
	cases := []string{
		"",
		"plain",
		"$$$$",
		"bcrypt$1$salt$key",                 // wrong algorithm
		pbkdf2Prefix + "$0$c2FsdA$aGFzaA",   // zero iterations
		pbkdf2Prefix + "$abc$c2FsdA$aGFzaA", // non-integer iterations
		pbkdf2Prefix + "$1000$***$aGFzaA",   // bad base64 salt
	}
	for _, c := range cases {
		if verifyPassword(c, "anything") {
			t.Errorf("verifyPassword should reject malformed hash %q", c)
		}
	}
}

func TestGeneratePassword_Entropy(t *testing.T) {
	seen := make(map[string]struct{}, 128)
	for i := 0; i < 128; i++ {
		pw, err := generatePassword()
		if err != nil {
			t.Fatalf("generatePassword: %v", err)
		}
		if len(pw) < 20 {
			t.Fatalf("generated password too short: %q (len=%d)", pw, len(pw))
		}
		if _, dup := seen[pw]; dup {
			t.Fatalf("generatePassword produced a duplicate at iteration %d", i)
		}
		seen[pw] = struct{}{}
	}
}
