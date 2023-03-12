package config

import (
	"github.com/sirupsen/logrus"
)

const UpstreamDefaultCfgName = "default"

// ParallelBestConfig upstream server configuration
type ParallelBestConfig struct {
	ExternalResolvers ParallelBestMapping `yaml:",inline"`
}

type ParallelBestMapping map[string][]Upstream

// IsEnabled implements `config.Configurable`.
func (c *ParallelBestConfig) IsEnabled() bool {
	return len(c.ExternalResolvers) != 0
}

// LogConfig implements `config.Configurable`.
func (c *ParallelBestConfig) LogConfig(logger *logrus.Entry) {
	logger.Info("upstream resolvers:")

	for name, upstreams := range c.ExternalResolvers {
		logger.Infof("  %s:", name)

		for _, upstream := range upstreams {
			logger.Infof("    - %s", upstream)
		}
	}
}
