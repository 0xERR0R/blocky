package config

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// ConditionalUpstream conditional upstream configuration
type ConditionalUpstream struct {
	RewriterConfig `yaml:",inline"`
	Mapping        ConditionalUpstreamMapping `yaml:"mapping"`
}

// ConditionalUpstreamMapping mapping for conditional configuration
type ConditionalUpstreamMapping struct {
	Upstreams map[string][]Upstream
}

// IsEnabled implements `config.Configurable`.
func (c *ConditionalUpstream) IsEnabled() bool {
	return len(c.Mapping.Upstreams) != 0
}

// LogConfig implements `config.Configurable`.
func (c *ConditionalUpstream) LogConfig(logger *logrus.Entry) {
	for key, val := range c.Mapping.Upstreams {
		logger.Infof("%s = %v", key, val)
	}
}

// UnmarshalYAML implements `yaml.Unmarshaler`.
func (c *ConditionalUpstreamMapping) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input map[string]string
	if err := unmarshal(&input); err != nil {
		return err
	}

	result := make(map[string][]Upstream, len(input))

	for k, v := range input {
		var upstreams []Upstream

		for _, part := range strings.Split(v, ",") {
			upstream, err := ParseUpstream(strings.TrimSpace(part))
			if err != nil {
				return fmt.Errorf("can't convert upstream '%s': %w", strings.TrimSpace(part), err)
			}

			upstreams = append(upstreams, upstream)
		}

		result[k] = upstreams
	}

	c.Upstreams = result

	return nil
}
