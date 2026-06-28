package update

import (
	"strings"
	"testing"
)

func TestParseChecksumsValid(t *testing.T) {
	t.Parallel()
	input := `# release v0.2.0 checksums
` + strings.Repeat("a", 64) + `  ezyshield-linux-amd64
` + strings.Repeat("b", 64) + `  ezyshield-linux-arm64
` + strings.Repeat("c", 64) + ` *ezyshield-enforcer-linux-amd64
`
	got, err := ParseChecksums(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	want := map[string]string{
		"ezyshield-linux-amd64":          strings.Repeat("a", 64),
		"ezyshield-linux-arm64":          strings.Repeat("b", 64),
		"ezyshield-enforcer-linux-amd64": strings.Repeat("c", 64),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("entry %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseChecksumsMalformed(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"not enough fields":     "abcdef\n",
		"hash too short":        "deadbeef  file\n",
		"hash too long":         strings.Repeat("a", 65) + "  file\n",
		"hash contains non-hex": strings.Repeat("z", 64) + "  file\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseChecksums(strings.NewReader(input)); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseChecksumsDuplicate(t *testing.T) {
	t.Parallel()
	h := strings.Repeat("a", 64)
	input := h + "  file\n" + h + "  file\n"
	if _, err := ParseChecksums(strings.NewReader(input)); err == nil {
		t.Error("expected duplicate-name error, got nil")
	}
}
