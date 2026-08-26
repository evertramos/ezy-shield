// SPDX-License-Identifier: AGPL-3.0-only

package dashboard

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSessionStore_CreateGet(t *testing.T) {
	s := newSessionStore(time.Hour, nil)
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
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	now := time.Unix(1_000_000, 0)
	s := newSessionStore(30*time.Minute, logger)
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
	// Idle-timeout eviction is a different code path from the cap-exceeded
	// eviction and must stay silent — logging it would spam the log on
	// every normal idle-out.
	if buf.Len() != 0 {
		t.Errorf("expiry cleanup must not emit an eviction log, got: %q", buf.String())
	}
}

func TestSessionStore_SlidingRenewal(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	s := newSessionStore(30*time.Minute, nil)
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
	s := newSessionStore(time.Hour, nil)
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

func TestLogSafeUser(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "admin", "admin"},
		{"crlf injection", "admin\r\nFAKE ban 203.0.113.7", "adminFAKE ban 203.0.113.7"},
		{"ansi escape", "adm\x1b[31min\x1b[0m", "adm[31min[0m"},
		{"control chars and del", "a\x00b\x07c\x7fd", "abcd"},
		{"unicode kept", "usuário", "usuário"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := logSafeUser(tt.in); got != tt.want {
				t.Errorf("logSafeUser(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	t.Run("length cap rune-safe", func(t *testing.T) {
		long := strings.Repeat("é", 100) // 2 bytes per rune
		got := logSafeUser(long)
		if len(got) > maxLogUserLen {
			t.Errorf("len = %d, want <= %d", len(got), maxLogUserLen)
		}
		if !utf8.ValidString(got) {
			t.Errorf("truncation produced invalid UTF-8: %q", got)
		}
	})
}

func TestSessionStore_EvictionLogSanitized(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	s := newSessionStore(time.Hour, logger)
	hostile := "admin\r\nFORGED line"
	for range maxSessionsPerUser + 1 {
		if _, _, err := s.Create(hostile); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	out := buf.String()
	if out == "" {
		t.Fatalf("expected an eviction log line")
	}
	// The sanitizer removes CR/LF entirely, so neither a raw CR nor the
	// handler-escaped `\r` form may appear in the eviction line.
	if strings.Contains(out, "\r") || strings.Contains(out, `\r`) {
		t.Errorf("eviction log contains CR (raw or escaped): %q", out)
	}
}
