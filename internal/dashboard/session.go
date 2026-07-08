package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// sessionTokenBytes is the length of the raw random token before hex encoding.
// 32 bytes → 256 bits of entropy → 64 hex characters in the cookie.
const sessionTokenBytes = 32

// sessionStore is an in-memory map of opaque token → session entry. Sessions
// are intentionally not persisted: on daemon restart, operators re-log-in,
// and the smaller attack surface (no on-disk session cookies) is worth the
// mild UX cost.
type sessionStore struct {
	timeout time.Duration
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]*sessionEntry
}

type sessionEntry struct {
	username  string
	expiresAt time.Time
}

func newSessionStore(timeout time.Duration) *sessionStore {
	return &sessionStore{
		timeout: timeout,
		now:     time.Now,
		entries: make(map[string]*sessionEntry),
	}
}

// Create issues a new session token for username. The token is a hex-encoded
// 32-byte value from crypto/rand.
func (s *sessionStore) Create(username string) (string, error) {
	buf := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	tok := hex.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[tok] = &sessionEntry{
		username:  username,
		expiresAt: s.now().Add(s.timeout),
	}
	return tok, nil
}

// Get returns the username associated with tok if the session is valid and
// not expired. A successful lookup extends the expiry by the configured
// timeout so active operators are not logged out mid-flow.
func (s *sessionStore) Get(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[tok]
	if !ok {
		return "", false
	}
	now := s.now()
	if !now.Before(e.expiresAt) {
		delete(s.entries, tok)
		return "", false
	}
	e.expiresAt = now.Add(s.timeout)
	return e.username, true
}

// Delete drops the entry for tok, whether it exists or not.
func (s *sessionStore) Delete(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, tok)
}

// Len reports the current number of live entries; used only by tests.
func (s *sessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
