package config

import (
	"fmt"
	"log/slog"
	"strings"
)

// RewriterConfig custom DNS configuration
type RewriterConfig struct {
	// Domain rewrite rules applied before resolution; keys are rewritten to their values.
	Rewrite map[string]string `yaml:"rewrite"`
	// If true, the original query is sent upstream when the mapped resolver returns an empty answer.
	FallbackUpstream bool `default:"false" yaml:"fallbackUpstream"`
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
func (c *RewriterConfig) LogConfig(logger *slog.Logger) {
	logger.Info(fmt.Sprintf("fallbackUpstream = %t", c.FallbackUpstream))

	logger.Info("rules:")

	for key, val := range c.Rewrite {
		logger.Info(fmt.Sprintf("  %s = %s", key, val))
	}
}
