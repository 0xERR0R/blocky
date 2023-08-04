package config

import (
	"github.com/sirupsen/logrus"
)

const UpstreamDefaultCfgName = "default"

// UpstreamsConfig upstream servers configuration
type UpstreamsConfig struct {
	Timeout  Duration         `yaml:"timeout" default:"2s"`
	Groups   UpstreamGroups   `yaml:"groups"`
	Strategy UpstreamStrategy `yaml:"strategy" default:"parallel_best"`
}

type UpstreamGroups map[string][]Upstream

// IsEnabled implements `config.Configurable`.
func (c *UpstreamsConfig) IsEnabled() bool {
	return len(c.Groups) != 0
}

// LogConfig implements `config.Configurable`.
func (c *UpstreamsConfig) LogConfig(logger *logrus.Entry) {
	logger.Info("timeout: ", c.Timeout)
	logger.Info("strategy: ", c.Strategy)
	logger.Info("groups:")

	for name, upstreams := range c.Groups {
		logger.Infof("  %s:", name)

		for _, upstream := range upstreams {
			logger.Infof("    - %s", upstream)
		}
	}
}
