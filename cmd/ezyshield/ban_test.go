package main

import "testing"

func TestValidateTarget(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"1.2.3.4", false},
		{"203.0.113.0/24", false},
		{"10.0.0.0/8", false},
		{"2001:db8::1", false},
		{"2001:db8::/32", false},
		{"::1/128", false},
		{"", true},
		{"not-an-ip", true},
		{"1.2.3.4/40", true},
		{"1.2.3.999", true},
	}
	for _, tc := range cases {
		err := validateTarget(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateTarget(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
		}
	}
}
