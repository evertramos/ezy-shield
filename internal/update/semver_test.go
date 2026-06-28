package update

import "testing"

func TestCompareSemver(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want int
	}{
		{"v0.1.0", "v0.2.0", -1},
		{"v0.2.0", "v0.1.0", 1},
		{"v0.1.0", "v0.1.0", 0},
		{"0.1.0", "v0.1.0", 0},   // leading-v is optional
		{"v1.2.3", "v1.2.4", -1}, // patch
		{"v1.2.3", "v1.3.0", -1}, // minor
		{"v1.2.3", "v2.0.0", -1}, // major
		{"v1.2.3-rc.1", "v1.2.3", -1},
		{"v1.2.3", "v1.2.3-rc.1", 1},
		{"v1.2.3-rc.1", "v1.2.3-rc.2", -1},
		{"v1.2.3+build.1", "v1.2.3", 0}, // build metadata ignored
	}
	for _, tt := range tests {
		got, err := CompareSemver(tt.a, tt.b)
		if err != nil {
			t.Errorf("Compare(%q,%q): unexpected err %v", tt.a, tt.b, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCompareSemverInvalid(t *testing.T) {
	t.Parallel()
	cases := []string{"dev", "unknown", "", "v1", "1.2", "v1.2.x"}
	for _, c := range cases {
		if _, err := CompareSemver(c, "v1.0.0"); err == nil {
			t.Errorf("Compare(%q, v1.0.0) expected error, got nil", c)
		}
	}
}
