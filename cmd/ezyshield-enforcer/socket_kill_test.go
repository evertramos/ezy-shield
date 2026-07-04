package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// mockSsCalls records the args the ssRunner is invoked with. Optional errStub
// lets a test simulate ss failure without pulling in a real binary.
type mockSsCalls struct {
	calls   [][]string
	errStub error
}

func (m *mockSsCalls) runner() ssRunner {
	return func(_ context.Context, args []string) error {
		// copy to defeat aliasing by callers that reuse a slice
		cp := make([]string, len(args))
		copy(cp, args)
		m.calls = append(m.calls, cp)
		return m.errStub
	}
}

// TestKillSocketsForIP_v4 asserts the ssRunner is invoked with exactly
// `-K dst <ip>` for an IPv4 target.
func TestKillSocketsForIP_v4(t *testing.T) {
	mock := &mockSsCalls{}
	if err := killSocketsForIP(context.Background(), mock.runner(), "1.2.3.4"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected exactly 1 ss call, got %d", len(mock.calls))
	}
	want := []string{"-K", "dst", "1.2.3.4"}
	if !reflect.DeepEqual(mock.calls[0], want) {
		t.Errorf("ss args: got %v, want %v", mock.calls[0], want)
	}
}

// TestKillSocketsForIP_v6 asserts the same argv shape works for IPv6 targets:
// ss parses the address family from the token, so the wrapper does not need
// to branch on v4 vs v6.
func TestKillSocketsForIP_v6(t *testing.T) {
	mock := &mockSsCalls{}
	if err := killSocketsForIP(context.Background(), mock.runner(), "2001:db8::1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected exactly 1 ss call, got %d", len(mock.calls))
	}
	want := []string{"-K", "dst", "2001:db8::1"}
	if !reflect.DeepEqual(mock.calls[0], want) {
		t.Errorf("ss args: got %v, want %v", mock.calls[0], want)
	}
}

// TestKillSocketsForIP_BestEffort verifies the best-effort semantics from
// Hard Rule §1: a failing ss call must NOT propagate an error that could
// roll back a successful nft ban.
func TestKillSocketsForIP_BestEffort(t *testing.T) {
	mock := &mockSsCalls{errStub: errors.New("ss: exit 1: not permitted")}
	if err := killSocketsForIP(context.Background(), mock.runner(), "1.2.3.4"); err != nil {
		t.Errorf("killSocketsForIP must swallow ss errors, got: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected exactly 1 ss call, got %d", len(mock.calls))
	}
}
