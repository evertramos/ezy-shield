package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const envPrefix = "env:"

// SecretRef is a config field that must hold an "env:VARNAME" reference.
// Inline secret values are rejected at load time — secrets must never appear
// in config files. An empty SecretRef is valid and means the field is unset.
type SecretRef string

// UnmarshalYAML rejects any value that is non-empty and lacks the "env:" prefix.
func (s *SecretRef) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("line %d: %w", value.Line, err)
	}
	if raw != "" && !strings.HasPrefix(raw, envPrefix) {
		return fmt.Errorf(
			"line %d: secret field must use 'env:VARNAME' reference, not an inline value", value.Line)
	}
	*s = SecretRef(raw)
	return nil
}

// IsSet reports whether the reference is non-empty (i.e., the field is configured).
func (s SecretRef) IsSet() bool {
	return string(s) != ""
}

// Resolve looks up the referenced environment variable and returns its value.
// Returns an error if the reference is empty or the variable is not set.
func (s SecretRef) Resolve() (string, error) {
	if !s.IsSet() {
		return "", fmt.Errorf("secret reference is not configured")
	}
	varName := strings.TrimPrefix(string(s), envPrefix)
	v, ok := os.LookupEnv(varName)
	if !ok {
		return "", fmt.Errorf("environment variable %s is not set", varName)
	}
	return v, nil
}
