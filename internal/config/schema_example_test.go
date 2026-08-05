package config

import (
	"os"
	"testing"
)

// TestSchemaExampleLoads keeps docs/internal/schemas/config/examples/full.yaml
// honest: the schema-regression fixture must also pass the real Go loader, so
// the schema and internal/config can't drift apart via the fixture itself
// (issue #325).
func TestSchemaExampleLoads(t *testing.T) {
	f, err := os.Open("../../docs/internal/schemas/config/examples/full.yaml")
	if err != nil {
		t.Fatalf("open schema example: %v", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	if _, err := LoadConfigReader(f, "full.yaml"); err != nil {
		t.Fatalf("schema example must pass Go validation: %v", err)
	}
}
