package config

import (
	"strings"
	"testing"
)

func TestValidateWebshellWatch(t *testing.T) {
	cases := []struct {
		name    string
		cfg     WebshellWatchCfg
		wantErr string // "" = valid
	}{
		{
			name: "valid minimal",
			cfg:  WebshellWatchCfg{Enabled: true, Roots: []string{"/var/www/html"}},
		},
		{
			name: "disabled needs nothing",
			cfg:  WebshellWatchCfg{},
		},
		{
			name:    "enabled without roots",
			cfg:     WebshellWatchCfg{Enabled: true},
			wantErr: "roots",
		},
		{
			name:    "relative root",
			cfg:     WebshellWatchCfg{Enabled: true, Roots: []string{"www/html"}},
			wantErr: "absolute",
		},
		{
			name:    "extension without dot",
			cfg:     WebshellWatchCfg{Enabled: true, Roots: []string{"/srv/www"}, Extensions: []string{"php"}},
			wantErr: "dot",
		},
		{
			name:    "bad glob",
			cfg:     WebshellWatchCfg{Enabled: true, Roots: []string{"/srv/www"}, Ignore: []string{"[unclosed"}},
			wantErr: "invalid pattern",
		},
		{
			name:    "interval below floor",
			cfg:     WebshellWatchCfg{Enabled: true, Roots: []string{"/srv/www"}, IntervalSec: 1},
			wantErr: "floor",
		},
		{
			name: "valid full",
			cfg: WebshellWatchCfg{
				Enabled:     true,
				Roots:       []string{"/var/www/html", "/srv/www/wp"},
				Extensions:  []string{".php", ".phtml"},
				Ignore:      []string{"cache", "*.bak.php"},
				IntervalSec: 30,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWebshellWatch(&tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
