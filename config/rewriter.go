package config

import (
	"github.com/sirupsen/logrus"
)

// RewriterConfig custom DNS configuration
type RewriterConfig struct {
	Rewrite          map[string]string `yaml:"rewrite"`
	FallbackUpstream bool              `yaml:"fallbackUpstream" default:"false"`
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
