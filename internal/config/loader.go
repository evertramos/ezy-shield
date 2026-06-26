package config

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// decodeStrict decodes YAML from r into out, rejecting unknown fields.
// gopkg.in/yaml.v3 includes line numbers in error messages automatically.
func decodeStrict(r io.Reader, name string, out any) error {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("parsing %s: %w", name, err)
	}
	return nil
}
