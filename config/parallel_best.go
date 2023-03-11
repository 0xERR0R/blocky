package config

import (
	"github.com/sirupsen/logrus"
)

const UpstreamDefaultCfgName = "default"

// UpstreamConfig upstream server configuration
type UpstreamConfig struct {
	ExternalResolvers UpstreamMapping `yaml:",inline"`
}

type UpstreamMapping map[string][]Upstream

// IsEnabled implements `config.Configurable`.
func (c *UpstreamConfig) IsEnabled() bool {
	return len(c.ExternalResolvers) != 0
}

// LogConfig implements `config.Configurable`.
func (c *UpstreamConfig) LogConfig(logger *logrus.Entry) {
	logger.Info("upstream resolvers:")

	for name, upstreams := range c.ExternalResolvers {
		logger.Infof("  - %s", name)

		for _, upstream := range upstreams {
			logger.Infof("    - %s", upstream)
		}
	}
}
