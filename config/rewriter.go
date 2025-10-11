package config

import (
	"strings"

	"github.com/sirupsen/logrus"
)

// RewriterConfig custom DNS configuration
type RewriterConfig struct {
	Rewrite          map[string]string `yaml:"rewrite"`
	FallbackUpstream bool              `default:"false" yaml:"fallbackUpstream"`
}

// NormalizeRewrites normalizes the rewrite keys to lowercase
func (c *RewriterConfig) NormalizeRewrites() {
	if len(c.Rewrite) > 0 {
		normalized := make(map[string]string, len(c.Rewrite))
		for k, v := range c.Rewrite {
			normalized[strings.ToLower(k)] = strings.ToLower(v)
		}
		c.Rewrite = normalized
	}
}

// IsEnabled implements `config.Configurable`.
func (c *RewriterConfig) IsEnabled() bool {
	return len(c.Rewrite) != 0
}

// LogConfig implements `config.Configurable`.
func (c *RewriterConfig) LogConfig(logger *logrus.Entry) {
	logger.Infof("fallbackUpstream = %t", c.FallbackUpstream)

	logger.Info("rules:")

	for key, val := range c.Rewrite {
		logger.Infof("  %s = %s", key, val)
	}
}
