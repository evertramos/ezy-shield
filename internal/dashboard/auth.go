package dashboard

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// pbkdf2Iterations follows the OWASP 2024 minimum for PBKDF2-SHA256.
// Bumping this requires no migration: verifyPassword reads the iteration
// count from the stored hash and re-derives at whatever value was written.
const (
	pbkdf2Iterations = 600_000
	pbkdf2KeyLen     = 32
	pbkdf2SaltLen    = 16
	pbkdf2Prefix     = "pbkdf2-sha256"

	// generatedPasswordBytes yields a 24-character URL-safe base64 password
	// (~144 bits of entropy) — long enough to resist online guessing at
	// dashboard timeouts, short enough to paste.
	generatedPasswordBytes = 18
)

// errAdminNotFound is returned when the requested admin username has no
// row in the auth store. It is a sentinel error so the login handler can
// distinguish "no such user" from a real database failure.
var errAdminNotFound = errors.New("dashboard: admin account not found")

// hashPassword returns a self-describing PBKDF2-SHA256 hash of password:
//
//	pbkdf2-sha256$<iter>$<salt-b64>$<key-b64>
//
// The iteration count is stored alongside the hash so future increases do
// not invalidate existing accounts.
func hashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s",
		pbkdf2Prefix,
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// verifyPassword compares password against a stored hash string.
//
// A malformed hash returns false rather than an error: login timing and
// operator-facing messaging must not distinguish "wrong password" from
// "corrupt row", so the caller sees a single "invalid credentials" path.
func verifyPassword(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != pbkdf2Prefix {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// generatePassword returns a URL-safe, base64-encoded random password.
// The characters are copy-paste-safe (no shell metacharacters) and the
// entropy source is crypto/rand.
func generatePassword() (string, error) {
	buf := make([]byte, generatedPasswordBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
