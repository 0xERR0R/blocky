package config

import (
	"fmt"
	"os"
	"strings"
)

// secretFilePrefix marks a Secret value that should be read from a file path.
const secretFilePrefix = "file:"

// Secret is a string config value that may be provided inline or, when prefixed
// with `file:`, read from the named file. Its String/MarshalText implementations
// redact the value so it can't leak through logging.
type Secret string

// Reveal returns the real secret value.
func (s Secret) Reveal() string {
	return string(s)
}

// String implements `fmt.Stringer`, redacting the value.
func (s Secret) String() string {
	return secretObfuscator
}

// MarshalText implements `encoding.TextMarshaler`, redacting the value.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(secretObfuscator), nil
}

// UnmarshalYAML implements YAML unmarshalling with `file:` support.
func (s *Secret) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}

	path, ok := strings.CutPrefix(raw, secretFilePrefix)
	if !ok {
		*s = Secret(raw)

		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read secret file %q: %w", path, err)
	}

	*s = Secret(trimSingleTrailingNewline(string(data)))

	return nil
}

// trimSingleTrailingNewline removes one trailing "\n" or "\r\n", leaving any
// other surrounding whitespace intact.
func trimSingleTrailingNewline(s string) string {
	after, found := strings.CutSuffix(s, "\n")
	if !found {
		return s
	}

	after, _ = strings.CutSuffix(after, "\r")

	return after
}
