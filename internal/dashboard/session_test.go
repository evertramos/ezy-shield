package dashboard

import (
	"testing"
	"time"
)

func TestSessionStore_CreateGet(t *testing.T) {
	s := newSessionStore(time.Hour)
	tok, _, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(tok) != sessionTokenBytes*2 {
		t.Errorf("token len = %d, want %d", len(tok), sessionTokenBytes*2)
	}
	u, ok := s.Get(tok)
	if !ok || u != "admin" {
		t.Errorf("Get = %q,%v; want admin,true", u, ok)
	}
	if _, ok := s.Get("bogus"); ok {
		t.Errorf("Get bogus should return false")
	}
	if _, ok := s.Get(""); ok {
		t.Errorf("Get empty should return false")
	}
}

func TestSessionStore_Expiry(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := newSessionStore(30 * time.Minute)
	s.now = func() time.Time { return now }

	tok, _, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Advance past expiry.
	now = now.Add(31 * time.Minute)
	if _, ok := s.Get(tok); ok {
		t.Fatalf("expired session should not resolve")
	}
	if s.Len() != 0 {
		t.Errorf("expired session should be evicted; Len=%d", s.Len())
	}
}

func TestSessionStore_SlidingRenewal(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	s := newSessionStore(30 * time.Minute)
	s.now = func() time.Time { return now }

	tok, _, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Advance 20 minutes — still valid, and expiry should slide forward.
	now = now.Add(20 * time.Minute)
	if _, ok := s.Get(tok); !ok {
		t.Fatalf("session should still be valid at 20m")
	}
	// Advance another 20 minutes; without renewal we'd be at 40m.
	// With renewal we're at 20m past the last touch, still valid.
	now = now.Add(20 * time.Minute)
	if _, ok := s.Get(tok); !ok {
		t.Fatalf("session should still be valid after sliding renewal")
	}
}

func TestSessionStore_Delete(t *testing.T) {
	s := newSessionStore(time.Hour)
	tok, _, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	s.Delete(tok)
	if _, ok := s.Get(tok); ok {
		t.Fatalf("deleted session should not resolve")
	}
	// Deleting an unknown token must not panic.
	s.Delete("nonexistent")
}
