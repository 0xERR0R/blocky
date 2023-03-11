package config

import (
	"github.com/sirupsen/logrus"
)

// RewriteConfig custom DNS configuration
type RewriteConfig struct {
	Rewrite          map[string]string `yaml:"rewrite"`
	FallbackUpstream bool              `yaml:"fallbackUpstream" default:"false"`
}

// IsEnabled implements `config.Configurable`.
func (c *RewriteConfig) IsEnabled() bool {
	return len(c.Rewrite) != 0
}

// LogConfig implements `config.Configurable`.
func (c *RewriteConfig) LogConfig(logger *logrus.Entry) {
	logger.Info("rewrite:")

	for key, val := range c.Rewrite {
		logger.Infof("  %s = %q", key, val)
	}
}
