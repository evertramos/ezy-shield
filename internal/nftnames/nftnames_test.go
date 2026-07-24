package nftnames

import (
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		table   string
		set     string
		want    Names
		wantErr string // substring; empty = expect success
	}{
		{
			name: "empty means defaults",
			want: Names{Table: "inet ezyshield", Set4: "blocked", Set6: "blocked6", Allow4: "allowed", Allow6: "allowed6"},
		},
		{
			name:  "bare table name gets inet family",
			table: "mytable",
			want:  Names{Table: "inet mytable", Set4: "blocked", Set6: "blocked6", Allow4: "allowed", Allow6: "allowed6"},
		},
		{
			name:  "explicit inet family",
			table: "inet mytable",
			set:   "myblocked",
			want:  Names{Table: "inet mytable", Set4: "myblocked", Set6: "myblocked6", Allow4: "allowed", Allow6: "allowed6"},
		},
		{
			name:  "whitespace trimmed",
			table: "  inet mytable  ",
			want:  Names{Table: "inet mytable", Set4: "blocked", Set6: "blocked6", Allow4: "allowed", Allow6: "allowed6"},
		},
		{name: "non-inet family rejected", table: "ip mytable", wantErr: "family must be 'inet'"},
		{name: "ip6 family rejected", table: "ip6 mytable", wantErr: "family must be 'inet'"},
		{name: "three tokens rejected", table: "inet a b", wantErr: "must be '<name>' or 'inet <name>'"},
		{name: "nft syntax via semicolon", table: "x; flush ruleset", wantErr: "must be '<name>' or 'inet <name>'"},
		{name: "nft syntax via brace", table: "x{", wantErr: "letters, digits and underscore"},
		{name: "leading digit rejected", table: "1table", wantErr: "letters, digits and underscore"},
		{name: "dash rejected", set: "bad-name", wantErr: "letters, digits and underscore"},
		{name: "newline in set rejected", set: "a\nb", wantErr: "letters, digits and underscore"},
		{name: "reserved allowed", set: "allowed", wantErr: "reserved allowlist sets"},
		{name: "reserved allowed6", set: "allowed6", wantErr: "reserved allowlist sets"},
		{name: "table too long", table: strings.Repeat("a", 33), wantErr: "longer than 32"},
		{name: "set too long for v6 twin", set: strings.Repeat("a", 32), wantErr: "longer than 31"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.table, tc.set)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Resolve(%q,%q) err = %v, want containing %q", tc.table, tc.set, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q,%q): %v", tc.table, tc.set, err)
			}
			if got != tc.want {
				t.Errorf("Resolve(%q,%q) = %+v, want %+v", tc.table, tc.set, got, tc.want)
			}
		})
	}
}

func TestIsDefault(t *testing.T) {
	t.Parallel()
	d, err := Resolve("", "")
	if err != nil || !d.IsDefault() {
		t.Fatalf("defaults must be default (err=%v)", err)
	}
	// Explicitly spelling out the default values is still the default set.
	same, err := Resolve("inet ezyshield", "blocked")
	if err != nil || !same.IsDefault() {
		t.Fatalf("explicit default names must be IsDefault (err=%v)", err)
	}
	custom, err := Resolve("inet mytable", "")
	if err != nil || custom.IsDefault() {
		t.Fatalf("custom table must not be IsDefault (err=%v)", err)
	}
}
