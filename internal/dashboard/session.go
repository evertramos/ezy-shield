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

// csrfTokenBytes matches the session token length. Same rationale — 256 bits
// of entropy — but the two secrets are independent so a leaked cookie cannot
// double as a CSRF bypass.
const csrfTokenBytes = 32

// maxSessionsPerUser caps how many concurrent sessions a single account can
// hold. When a new login pushes the account over the cap, the oldest session
// is evicted so a stolen cookie has a bounded useful life and an operator
// who forgets to sign out on a shared machine gets a hard limit.
const maxSessionsPerUser = 3

// sessionStore is an in-memory map of opaque token → session entry. Sessions
// are intentionally not persisted: on daemon restart, operators re-log-in,
// and the smaller attack surface (no on-disk session cookies) is worth the
// mild UX cost.
type sessionStore struct {
	timeout time.Duration
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]*sessionEntry
	// perUser tracks live tokens per username, ordered oldest-first, so
	// Create can evict the head when the account hits maxSessionsPerUser.
	perUser map[string][]string
}

type sessionEntry struct {
	username  string
	csrf      string
	createdAt time.Time
	expiresAt time.Time
}

// sessionInfo is the read-side projection of a live session, returned by
// Lookup. It hides the internal expiry/creation timestamps so callers don't
// accidentally build authorisation on data that only exists in memory.
type sessionInfo struct {
	Username string
	CSRF     string
}

func newSessionStore(timeout time.Duration) *sessionStore {
	return &sessionStore{
		timeout: timeout,
		now:     time.Now,
		entries: make(map[string]*sessionEntry),
		perUser: make(map[string][]string),
	}
}

// Create issues a new session token for username together with a fresh CSRF
// token. If the account already holds maxSessionsPerUser live sessions the
// oldest one is evicted before the new one is inserted, so a stolen cookie
// has a bounded useful life.
func (s *sessionStore) Create(username string) (token string, csrf string, err error) {
	buf := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("read random session: %w", err)
	}
	tok := hex.EncodeToString(buf)

	csrfBuf := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(csrfBuf); err != nil {
		return "", "", fmt.Errorf("read random csrf: %w", err)
	}
	csrfTok := hex.EncodeToString(csrfBuf)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.enforceCapLocked(username)
	s.entries[tok] = &sessionEntry{
		username:  username,
		csrf:      csrfTok,
		createdAt: now,
		expiresAt: now.Add(s.timeout),
	}
	s.perUser[username] = append(s.perUser[username], tok)
	return tok, csrfTok, nil
}

// enforceCapLocked drops the oldest sessions for username until the account
// holds strictly fewer than maxSessionsPerUser slots. Caller must hold s.mu.
func (s *sessionStore) enforceCapLocked(username string) {
	list := s.perUser[username]
	for len(list) >= maxSessionsPerUser {
		oldest := list[0]
		list = list[1:]
		delete(s.entries, oldest)
	}
	if len(list) == 0 {
		delete(s.perUser, username)
	} else {
		s.perUser[username] = list
	}
}

// Lookup resolves tok to the live sessionInfo (username + CSRF) if the
// session exists and is not expired, sliding the expiry forward on hit.
func (s *sessionStore) Lookup(tok string) (sessionInfo, bool) {
	if tok == "" {
		return sessionInfo{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[tok]
	if !ok {
		return sessionInfo{}, false
	}
	now := s.now()
	if !now.Before(e.expiresAt) {
		s.removeLocked(tok, e.username)
		return sessionInfo{}, false
	}
	e.expiresAt = now.Add(s.timeout)
	return sessionInfo{Username: e.username, CSRF: e.csrf}, true
}

// Get is the thin username-only projection kept for call sites that never
// touched CSRF. requireAuth uses Lookup so it can attach CSRF to the
// context; Get remains here for tests and future consumers.
func (s *sessionStore) Get(tok string) (string, bool) {
	info, ok := s.Lookup(tok)
	return info.Username, ok
}

// Delete drops the entry for tok, whether it exists or not.
func (s *sessionStore) Delete(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[tok]
	if !ok {
		return
	}
	s.removeLocked(tok, e.username)
}

// removeLocked drops tok from both entries and perUser. Caller holds s.mu.
func (s *sessionStore) removeLocked(tok, username string) {
	delete(s.entries, tok)
	list := s.perUser[username]
	for i, t := range list {
		if t == tok {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(s.perUser, username)
	} else {
		s.perUser[username] = list
	}
}

// Len reports the current number of live entries; used only by tests.
func (s *sessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// userLen reports how many live sessions the given account holds. Test-only.
func (s *sessionStore) userLen(username string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.perUser[username])
}
