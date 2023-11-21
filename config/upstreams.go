package config

import (
	"github.com/sirupsen/logrus"
)

const UpstreamDefaultCfgName = "default"

// Upstreams upstream servers configuration
type Upstreams struct {
	Timeout  Duration         `yaml:"timeout" default:"2s"`
	Groups   UpstreamGroups   `yaml:"groups"`
	Strategy UpstreamStrategy `yaml:"strategy" default:"parallel_best"`
}

type UpstreamGroups map[string][]Upstream

// IsEnabled implements `config.Configurable`.
func (c *Upstreams) IsEnabled() bool {
	return len(c.Groups) != 0
}

// LogConfig implements `config.Configurable`.
func (c *Upstreams) LogConfig(logger *logrus.Entry) {
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

// UpstreamGroup represents the config for one group (upstream branch)
type UpstreamGroup struct {
	Name      string
	Upstreams []Upstream
}

// IsEnabled implements `config.Configurable`.
func (c *UpstreamGroup) IsEnabled() bool {
	return len(c.Upstreams) != 0
}

// LogConfig implements `config.Configurable`.
func (c *UpstreamGroup) LogConfig(logger *logrus.Entry) {
	logger.Info("group: ", c.Name)
	logger.Info("upstreams:")

	for _, upstream := range c.Upstreams {
		logger.Infof("  - %s", upstream)
	}
}
