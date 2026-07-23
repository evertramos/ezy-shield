package main

// Tests for gidToUint32, the guarded GID narrowing shared by the doctor
// ownership checks (CodeQL go/incorrect-integer-conversion, issue #260).

import (
	"math"
	"testing"
)

func TestGidToUint32(t *testing.T) {
	tests := []struct {
		name string
		gid  int
		want uint32
		ok   bool
	}{
		{"zero (root group)", 0, 0, true},
		{"typical daemon gid", 988, 988, true},
		{"max uint32", math.MaxUint32, math.MaxUint32, true},
		{"negative", -1, 0, false},
		{"just above uint32 range", math.MaxUint32 + 1, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := gidToUint32(tc.gid)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("gidToUint32(%d) = (%d, %v), want (%d, %v)", tc.gid, got, ok, tc.want, tc.ok)
			}
		})
	}
}
