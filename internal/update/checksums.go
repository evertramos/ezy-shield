package update

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// hexLine matches a single sha256sum line: 64 hex chars, whitespace, optional
// "*" (binary-mode marker), then the filename.
var hexLine = regexp.MustCompile(`^([0-9a-fA-F]{64})\s+\*?(\S+)$`)

// ParseChecksums parses sha256sum-format output: each line is
// "<64-hex>  <name>" or "<64-hex> *<name>". Comments (#) and blank lines are
// skipped. Returns a map of filename → lower-case hex digest. Duplicate names
// keep the first occurrence and an error is returned.
//
// Input is read with a bounded scanner buffer so a hostile checksums file can't
// drive the parser into unbounded memory.
func ParseChecksums(r io.Reader) (map[string]string, error) {
	sums := make(map[string]string)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := hexLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("malformed checksum line: %q", line)
		}
		hex := strings.ToLower(m[1])
		name := m[2]
		if _, dup := sums[name]; dup {
			return nil, fmt.Errorf("duplicate checksum entry: %q", name)
		}
		sums[name] = hex
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read checksums: %w", err)
	}
	return sums, nil
}
